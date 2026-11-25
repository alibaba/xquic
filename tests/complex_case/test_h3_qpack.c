/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 *
 * Complex case for HTTP/3 QPACK over a real in-process client/server pair:
 * a request whose HEADERS is blocked behind a flow-control-throttled QPACK
 * encoder stream, is aborted by the client while blocked so the transport
 * stream closes underneath the surviving h3 stream, and is then rejected
 * for exceeding the field-section limit once the encoder instruction
 * finally arrives. The server must destroy the rejected h3 stream without
 * touching the dead transport stream, and the connection must stay usable.
 */
#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>
#include "complex_case_common.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/http3/xqc_h3_request.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_stream.h"

#define HQ_PAD_VALUE_LEN    200
#define HQ_THROTTLE_WINDOW  64
/*
 * RFC 9114 field-section accounting charges len(name)+len(value)+32 per
 * field: the four pseudo headers of a plain request total 175, adding the
 * x-pad header (237) pushes the rejected request to 412. 256 sits between
 * the two so only the padded request exceeds the limit.
 */
#define HQ_FIELD_LIMIT      256
/*
 * Wait loops are bounded by both a pass cap and a real-time deadline so a
 * heavily loaded CI machine cannot fail the case on wall-clock alone.
 */
#define HQ_WAIT_DEADLINE    (xqc_complex_case_now_us() + 5000000)

typedef struct {
    xqc_complex_case_engine_t   base;
    xqc_h3_conn_t              *h3;
    int                         server;
    int                         conn_closed;
    int                         req_headers;    /* server: request header sections */
    int                         resp_headers;   /* client: response header sections */
    xqc_int_t                   conn_error;
    int                         conn_error_app; /* an application error */
} hq_endpoint_t;

#define HQ_CHECK(expr)                                                    \
    do {                                                                 \
        if (!(expr)) {                                                   \
            fprintf(stderr, "line %d: %s\n", __LINE__, #expr);           \
            goto fail;                                                   \
        }                                                                \
    } while (0)

static char hq_pad_value[HQ_PAD_VALUE_LEN];

static int
hq_accept(xqc_engine_t *engine, xqc_connection_t *conn,
    const xqc_cid_t *cid, void *data)
{
    xqc_conn_set_transport_user_data(conn, data);
    return XQC_OK;
}

static int
hq_conn_create(xqc_h3_conn_t *h3, const xqc_cid_t *cid, void *data)
{
    ((hq_endpoint_t *) data)->h3 = h3;
    return XQC_OK;
}

static int
hq_conn_close(xqc_h3_conn_t *h3, const xqc_cid_t *cid, void *data)
{
    hq_endpoint_t *ep = data;
    ep->conn_error = xqc_conn_get_errno(h3->conn);
    ep->conn_error_app = XQC_CONN_ERR_IS_APPLICATION(h3->conn->conn_err);
    ep->conn_closed++;
    ep->h3 = NULL;
    return XQC_OK;
}

static int
hq_req_create(xqc_h3_request_t *request, void *data)
{
    xqc_h3_request_set_user_data(request,
                                 xqc_h3_get_conn_user_data_by_request(request));
    return XQC_OK;
}

static int
hq_req_read(xqc_h3_request_t *request, xqc_request_notify_flag_t flags,
    void *data)
{
    hq_endpoint_t *ep = data;
    uint8_t fin = 0;
    if (!(flags & XQC_REQ_NOTIFY_READ_HEADER)) {
        return XQC_OK;
    }
    if (xqc_h3_request_recv_headers(request, &fin) == NULL) {
        return -XQC_ESTATE;
    }
    if (ep->server) {
        ep->req_headers++;
        xqc_http_header_t field = {
            .name = {(void *)":status", 7}, .value = {(void *)"200", 3},
        };
        xqc_http_headers_t response = {.headers = &field, .count = 1};
        return xqc_h3_request_send_headers(request, &response, 1) < 0
            ? -XQC_ESTATE : XQC_OK;
    }
    ep->resp_headers++;
    return XQC_OK;
}

static void
hq_req_closing(xqc_h3_request_t *request, xqc_int_t error, void *data)
{
}

static int
hq_engine_init(hq_endpoint_t *ep, xqc_engine_type_t type)
{
    xqc_config_t config;
    xqc_engine_ssl_config_t ssl = {0};
    xqc_engine_callback_t engine_cbs;
    xqc_transport_callbacks_t transport_cbs;
    xqc_h3_callbacks_t h3;
    struct sockaddr_in addr = {0};

    ep->server = type == XQC_ENGINE_SERVER;
    ep->base.socket.fd = -1;
    ep->base.user_data = ep;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (xqc_complex_case_make_socket(&ep->base, (struct sockaddr *)&addr,
                                     sizeof(addr)) != 0)
    {
        perror("h3 qpack loopback socket");
        return -1;
    }
    xqc_engine_get_default_config(&config, type);
    config.cfg_log_level = XQC_LOG_ERROR;
    ssl.ciphers = XQC_TLS_CIPHERS;
    ssl.groups = XQC_TLS_GROUPS;
    if (type == XQC_ENGINE_SERVER) {
        ssl.private_key_file = "./server.key";
        ssl.cert_file = "./server.crt";
    }
    xqc_complex_case_init_engine_callbacks(&engine_cbs);
    xqc_complex_case_init_transport_callbacks(&transport_cbs);
    transport_cbs.server_accept = hq_accept;
    ep->base.engine = xqc_engine_create(type, &config, &ssl, &engine_cbs,
                                        &transport_cbs, ep);
    if (ep->base.engine == NULL) {
        return -1;
    }
    xqc_memzero(&h3, sizeof(h3));
    h3.h3c_cbs.h3_conn_create_notify = hq_conn_create;
    h3.h3c_cbs.h3_conn_close_notify = hq_conn_close;
    h3.h3r_cbs.h3_request_create_notify = hq_req_create;
    h3.h3r_cbs.h3_request_read_notify = hq_req_read;
    h3.h3r_cbs.h3_request_closing_notify = hq_req_closing;
    return xqc_h3_ctx_init(ep->base.engine, &h3) == XQC_OK ? 0 : -1;
}

static int
hq_server_blocked(hq_endpoint_t *server)
{
    return server->h3 != NULL
        && !xqc_list_empty(&server->h3->block_stream_head);
}

/*
 * Single pump pass: one receive/process/send step per engine. Unlike
 * xqc_complex_case_pump, which loops until its deadline expires, one pass
 * keeps every phase of the scenario observable between passes. While
 * `throttle` is not NULL the given send window is re-applied right before
 * the client's main logic, so a MAX_STREAM_DATA grant triggered by the
 * throttled encoder stream cannot silently restore the window mid-phase.
 */
static void
hq_pump_pass(hq_endpoint_t *client, hq_endpoint_t *server,
    xqc_stream_t *throttle, uint64_t window)
{
    unsigned char buf[65536];
    xqc_complex_case_engine_t *engines[] = {&client->base, &server->base};
    struct pollfd pfd[2];
    nfds_t nfd = 0;

    for (int i = 0; i < 2; i++) {
        if (engines[i]->engine == NULL) {
            continue;
        }
        pfd[nfd].fd = engines[i]->socket.fd;
        pfd[nfd].events = POLLIN;
        pfd[nfd].revents = 0;
        nfd++;
    }
    poll(pfd, nfd, 1);

    for (int i = 0; i < 2; i++) {
        xqc_complex_case_engine_t *ctx = engines[i];
        if (ctx->engine == NULL) {
            continue;
        }

        for (;;) {
            struct sockaddr_storage from;
            socklen_t fromlen = sizeof(from);
            ssize_t received = recvfrom(ctx->socket.fd, buf, sizeof(buf), 0,
                                        (struct sockaddr *)&from, &fromlen);
            if (received <= 0) {
                break;
            }
            xqc_engine_packet_process(ctx->engine, buf, (size_t) received,
                                      (struct sockaddr *)&ctx->local,
                                      ctx->locallen,
                                      (struct sockaddr *)&from, fromlen,
                                      xqc_complex_case_now_us(),
                                      ctx->user_data);
        }
        xqc_engine_finish_recv(ctx->engine);

        if (throttle != NULL && i == 0) {
            throttle->stream_flow_ctl.fc_max_stream_data_can_send = window;
        }
        xqc_engine_main_logic(ctx->engine);
    }
}

/*
 * QPACK error codes (RFC 9204 Section 6). The client writes raw bytes on
 * its QPACK encoder or decoder stream, or on a request stream. The server
 * accepts valid instructions, and closes the connection with the error
 * code that RFC 9204 gives each failure.
 */
enum {
    HQ_ERR_VALID,           /* valid instructions, then a request */
    HQ_ERR_CAPACITY,        /* a capacity above the server's maximum */
    HQ_ERR_SECTION_ACK,     /* an acknowledgment without a field section */
    HQ_ERR_STATIC_INDEX,    /* a field line with static index 99 */
    HQ_ERR_BLOCKED_INDEX,   /* the same, after its stream was blocked */
    HQ_ERR_BLOCKED_LIMIT,   /* a blocked stream, while the server allows 0 */
    HQ_ERR_CASES,
};

/* the error of an endpoint's connection is an application error */
static int
hq_conn_err_app(hq_endpoint_t *ep)
{
    if (ep->h3 == NULL) {
        return ep->conn_closed && ep->conn_error_app;
    }

    return XQC_CONN_ERR_IS_APPLICATION(ep->h3->conn->conn_err);
}

/* the error of an endpoint's connection, 0 while it has none */
static uint64_t
hq_conn_err(hq_endpoint_t *ep)
{
    if (ep->h3 == NULL) {
        return ep->conn_closed ? (uint64_t) ep->conn_error : 0;
    }

    return XQC_CONN_ERR_CODE(ep->h3->conn->conn_err);
}

/* send the raw bytes of a HEADERS frame on a new request stream */
static int
hq_send_raw_headers(hq_endpoint_t *client, const xqc_cid_t *cid,
    const unsigned char *frame, size_t len)
{
    unsigned char buf[16];
    xqc_h3_request_t *request;

    request = xqc_h3_request_create(client->base.engine, cid, NULL, client);
    if (request == NULL || len > sizeof(buf)) {
        return -1;
    }

    memcpy(buf, frame, len);
    return xqc_stream_send(request->h3_stream->stream, buf, len, 0)
           == (ssize_t) len ? 0 : -1;
}

static int
hq_qpack_error_case(int c)
{
    /*
     * HEADERS frames: Required Insert Count 0, or 1 (encoded as 2), Base
     * equal to it, then an Indexed Field Line with static index 99, which
     * does not exist, or with dynamic relative index 0
     */
    static const unsigned char static_99[] = {
        0x01, 0x04, 0x00, 0x00, 0xff, 0x24
    };
    static const unsigned char blocked_99[] = {
        0x01, 0x04, 0x02, 0x00, 0xff, 0x24
    };
    static const unsigned char blocked[] = { 0x01, 0x03, 0x02, 0x00, 0x80 };
    xqc_http_header_t fields[] = {
        {.name = {(void *)":method", 7}, .value = {(void *)"GET", 3}},
        {.name = {(void *)":scheme", 7}, .value = {(void *)"https", 5}},
        {.name = {(void *)":authority", 10},
         .value = {(void *)"localhost", 9}},
        {.name = {(void *)":path", 5}, .value = {(void *)"/", 1}},
    };
    xqc_http_headers_t headers = {.headers = fields,
        .count = sizeof(fields) / sizeof(fields[0])};
    hq_endpoint_t client, server;
    xqc_complex_case_engine_t *engines[] = {&client.base, &server.base};
    xqc_conn_ssl_config_t ssl = {0};
    xqc_h3_request_t *request;
    xqc_var_buf_t *ins;
    uint64_t max_cap, cap, expected = 0;
    xqc_usec_t dl;
    int rc = 1, app = 0;

    memset(&client, 0, sizeof(client));
    memset(&server, 0, sizeof(server));
    client.base.socket.fd = server.base.socket.fd = -1;
    HQ_CHECK(hq_engine_init(&server, XQC_ENGINE_SERVER) == 0);
    HQ_CHECK(hq_engine_init(&client, XQC_ENGINE_CLIENT) == 0);
    if (c == HQ_ERR_BLOCKED_LIMIT) {
        xqc_h3_engine_set_qpack_blocked_streams(server.base.engine, 0);
    }

    const xqc_cid_t *cid = xqc_h3_connect(client.base.engine,
        &client.base.engine->default_conn_settings, NULL, 0, "localhost", 0,
        &ssl, (struct sockaddr *)&server.base.local, server.base.locallen,
        &client);
    HQ_CHECK(cid != NULL);

    /* the client's encoder applied the server's SETTINGS */
    dl = HQ_WAIT_DEADLINE;
    while ((client.h3 == NULL || server.h3 == NULL
            || client.h3->peer_h3_conn_settings.qpack_dec_max_table_capacity
               == XQC_H3_SETTINGS_UNSET)
           && xqc_complex_case_now_us() < dl)
    {
        xqc_complex_case_pump(engines, 2, 10);
    }
    HQ_CHECK(client.h3 != NULL && server.h3 != NULL);
    HQ_CHECK(client.h3->peer_h3_conn_settings.qpack_dec_max_table_capacity
             != XQC_H3_SETTINGS_UNSET);
    max_cap = server.h3->local_h3_conn_settings.qpack_dec_max_table_capacity;

    switch (c) {
    case HQ_ERR_VALID:
        /*
         * the capacity that the client's encoder set already: the lower of
         * the server's maximum and its own, both 16384 by default
         */
        cap = client.h3->local_h3_conn_settings.qpack_enc_max_table_capacity;
        cap = cap < max_cap ? cap : max_cap;
        ins = xqc_h3_conn_get_ins_buf(XQC_INS_TYPE_ENCODER, client.h3);
        HQ_CHECK(ins != NULL);
        HQ_CHECK(xqc_ins_write_set_dtable_cap(ins, cap) == XQC_OK);
        HQ_CHECK(xqc_h3_conn_send_ins(XQC_INS_TYPE_ENCODER, ins,
                                      client.h3) >= 0);
        ins = xqc_h3_conn_get_ins_buf(XQC_INS_TYPE_DECODER, client.h3);
        HQ_CHECK(ins != NULL);
        HQ_CHECK(xqc_ins_write_stream_cancel(ins, 4) == XQC_OK);
        HQ_CHECK(xqc_h3_conn_send_ins(XQC_INS_TYPE_DECODER, ins,
                                      client.h3) >= 0);

        request = xqc_h3_request_create(client.base.engine, cid, NULL,
                                        &client);
        HQ_CHECK(request != NULL);
        HQ_CHECK(xqc_h3_request_send_headers(request, &headers, 1) >= 0);
        dl = HQ_WAIT_DEADLINE;
        while (!client.resp_headers && xqc_complex_case_now_us() < dl) {
            hq_pump_pass(&client, &server, NULL, 0);
        }
        HQ_CHECK(server.req_headers == 1 && client.resp_headers == 1);
        break;

    case HQ_ERR_CAPACITY:
        expected = QPACK_ENCODER_STREAM_ERROR;
        ins = xqc_h3_conn_get_ins_buf(XQC_INS_TYPE_ENCODER, client.h3);
        HQ_CHECK(ins != NULL);
        HQ_CHECK(xqc_ins_write_set_dtable_cap(ins, max_cap + 1) == XQC_OK);
        HQ_CHECK(xqc_h3_conn_send_ins(XQC_INS_TYPE_ENCODER, ins,
                                      client.h3) >= 0);
        break;

    case HQ_ERR_SECTION_ACK:
        expected = QPACK_DECODER_STREAM_ERROR;
        ins = xqc_h3_conn_get_ins_buf(XQC_INS_TYPE_DECODER, client.h3);
        HQ_CHECK(ins != NULL);
        HQ_CHECK(xqc_ins_write_section_ack(ins, 0) == XQC_OK);
        HQ_CHECK(xqc_h3_conn_send_ins(XQC_INS_TYPE_DECODER, ins,
                                      client.h3) >= 0);
        break;

    case HQ_ERR_STATIC_INDEX:
        expected = QPACK_DECOMPRESSION_FAILED;
        HQ_CHECK(hq_send_raw_headers(&client, cid, static_99,
                                     sizeof(static_99)) == 0);
        break;

    case HQ_ERR_BLOCKED_INDEX:
        expected = QPACK_DECOMPRESSION_FAILED;
        HQ_CHECK(hq_send_raw_headers(&client, cid, blocked_99,
                                     sizeof(blocked_99)) == 0);
        dl = HQ_WAIT_DEADLINE;
        while (!hq_server_blocked(&server)
               && xqc_complex_case_now_us() < dl)
        {
            hq_pump_pass(&client, &server, NULL, 0);
        }
        HQ_CHECK(hq_server_blocked(&server));

        /* the insertion unblocks the stream */
        ins = xqc_h3_conn_get_ins_buf(XQC_INS_TYPE_ENCODER, client.h3);
        HQ_CHECK(ins != NULL);
        HQ_CHECK(xqc_ins_write_insert_literal_name(ins,
                     (unsigned char *) "x-qpack", 7,
                     (unsigned char *) "1", 1) == XQC_OK);
        HQ_CHECK(xqc_h3_conn_send_ins(XQC_INS_TYPE_ENCODER, ins,
                                      client.h3) >= 0);
        break;

    default:
        expected = QPACK_DECOMPRESSION_FAILED;
        HQ_CHECK(server.h3->local_h3_conn_settings.qpack_blocked_streams
                 == 0);
        HQ_CHECK(hq_send_raw_headers(&client, cid, blocked,
                                     sizeof(blocked)) == 0);
        break;
    }

    if (expected != 0) {
        dl = HQ_WAIT_DEADLINE;
        while (hq_conn_err(&server) == 0 && xqc_complex_case_now_us() < dl) {
            hq_pump_pass(&client, &server, NULL, 0);
        }

        /*
         * the client's own encoder does not know the raw insertion: it may
         * reject the server's Insert Count Increment first
         */
        dl = HQ_WAIT_DEADLINE;
        while (c != HQ_ERR_BLOCKED_INDEX && hq_conn_err(&client) == 0
               && xqc_complex_case_now_us() < dl)
        {
            hq_pump_pass(&client, &server, NULL, 0);
        }
    }

    /* the server's connection is closing, or already closed */
    app = hq_conn_err_app(&server);
    printf("h3 qpack error case %d: server 0x%llx (%s), client 0x%llx\n",
           c, (unsigned long long) hq_conn_err(&server),
           hq_conn_err(&server) == 0 ? "none"
           : (app ? "application" : "transport"),
           (unsigned long long) hq_conn_err(&client));
    HQ_CHECK(hq_conn_err(&server) == expected);
    HQ_CHECK(expected == 0 || app);
    HQ_CHECK(c == HQ_ERR_BLOCKED_INDEX || hq_conn_err(&client) == expected);
    rc = 0;

fail:
    xqc_complex_case_engine_release(&client.base);
    xqc_complex_case_engine_release(&server.base);
    return rc;
}

static int
hq_qpack_error_codes(void)
{
    int rc = 0;

    for (int c = 0; c < HQ_ERR_CASES; c++) {
        if (hq_qpack_error_case(c) != 0) {
            fprintf(stderr, "qpack error case %d failed\n", c);
            rc = 1;
        }
    }

    return rc;
}

/*
 * RFC 9204 Section 2.1.2: a decoder that encounters more blocked streams
 * than its SETTINGS_QPACK_BLOCKED_STREAMS allows treats this as a
 * connection error of type QPACK_DECOMPRESSION_FAILED. The server
 * advertises HQ_LIMIT_BLOCKED. On one request stream after another, the
 * client writes the raw bytes of a HEADERS frame that refers to a dynamic
 * table entry it never inserts: the server blocks the first
 * HQ_LIMIT_BLOCKED streams, the last of them with its FIN, and closes the
 * connection on the next one, also sent with its FIN. Once both
 * connections are closed, every request that the server created must have
 * been closed. The h3 connection destroys a blocked stream that waits with
 * its FIN read from its list of blocked streams; a stream refused over the
 * limit is not in that list, and must be destroyed with its transport
 * stream.
 */
#define HQ_LIMIT_BLOCKED    2

static int hq_limit_created;
static int hq_limit_closed;

static int
hq_limit_req_create(xqc_h3_request_t *request, void *data)
{
    hq_limit_created++;
    return hq_req_create(request, data);
}

static int
hq_limit_req_close(xqc_h3_request_t *request, void *data)
{
    hq_limit_closed++;
    return XQC_OK;
}

static int
hq_blocked_limit(void)
{
    /* HEADERS: Required Insert Count 1, Base 1, dynamic index 0 */
    static const unsigned char blocked[] = { 0x01, 0x03, 0x02, 0x00, 0x80 };
    hq_endpoint_t client, server;
    xqc_complex_case_engine_t *engines[] = {&client.base, &server.base};
    xqc_conn_ssl_config_t ssl = {0};
    xqc_h3_request_t *request;
    unsigned char buf[sizeof(blocked)];
    xqc_usec_t dl;
    uint8_t fin;
    int rc = 1, app, i;

    memset(&client, 0, sizeof(client));
    memset(&server, 0, sizeof(server));
    client.base.socket.fd = server.base.socket.fd = -1;
    hq_limit_created = 0;
    hq_limit_closed = 0;
    HQ_CHECK(hq_engine_init(&server, XQC_ENGINE_SERVER) == 0);
    HQ_CHECK(hq_engine_init(&client, XQC_ENGINE_CLIENT) == 0);
    xqc_h3_engine_set_qpack_blocked_streams(server.base.engine,
                                            HQ_LIMIT_BLOCKED);

    const xqc_cid_t *cid = xqc_h3_connect(client.base.engine,
        &client.base.engine->default_conn_settings, NULL, 0, "localhost", 0,
        &ssl, (struct sockaddr *)&server.base.local, server.base.locallen,
        &client);
    HQ_CHECK(cid != NULL);

    /* the client received the limit in the server's SETTINGS */
    dl = HQ_WAIT_DEADLINE;
    while ((client.h3 == NULL || server.h3 == NULL
            || client.h3->peer_h3_conn_settings.qpack_blocked_streams
               != HQ_LIMIT_BLOCKED)
           && xqc_complex_case_now_us() < dl)
    {
        xqc_complex_case_pump(engines, 2, 10);
    }
    HQ_CHECK(client.h3 != NULL && server.h3 != NULL);
    HQ_CHECK(client.h3->peer_h3_conn_settings.qpack_blocked_streams
             == HQ_LIMIT_BLOCKED);

    /* count the requests that the server creates, and those it closes */
    server.h3->h3_request_callbacks.h3_request_create_notify =
        hq_limit_req_create;
    server.h3->h3_request_callbacks.h3_request_close_notify =
        hq_limit_req_close;

    for (i = 0; i <= HQ_LIMIT_BLOCKED; i++) {
        fin = i >= HQ_LIMIT_BLOCKED - 1;
        request = xqc_h3_request_create(client.base.engine, cid, NULL,
                                        &client);
        HQ_CHECK(request != NULL);
        memcpy(buf, blocked, sizeof(blocked));
        HQ_CHECK(xqc_stream_send(request->h3_stream->stream, buf,
                                 sizeof(buf), fin) == (ssize_t) sizeof(buf));

        /* the server blocks the stream, or closes the connection */
        dl = HQ_WAIT_DEADLINE;
        while (server.h3 != NULL && hq_conn_err(&server) == 0
               && server.h3->block_stream_count < (uint64_t) i + 1
               && xqc_complex_case_now_us() < dl)
        {
            xqc_complex_case_pump(engines, 2, 10);
        }
        HQ_CHECK(hq_limit_created == i + 1);
        if (i < HQ_LIMIT_BLOCKED) {
            HQ_CHECK(hq_conn_err(&server) == 0);
            HQ_CHECK(server.h3->block_stream_count == (uint64_t) i + 1);
        }
    }

    /* the server's connection is closing, or already closed */
    app = hq_conn_err_app(&server);
    dl = HQ_WAIT_DEADLINE;
    while ((!client.conn_closed || !server.conn_closed)
           && xqc_complex_case_now_us() < dl)
    {
        xqc_complex_case_pump(engines, 2, 10);
    }
    printf("h3 qpack blocked limit: server 0x%llx (%s), client 0x%llx, "
           "server requests created %d, closed %d\n",
           (unsigned long long) hq_conn_err(&server),
           app ? "application" : "transport or none",
           (unsigned long long) hq_conn_err(&client), hq_limit_created,
           hq_limit_closed);
    HQ_CHECK(hq_conn_err(&server) == QPACK_DECOMPRESSION_FAILED && app);
    HQ_CHECK(hq_conn_err(&client) == QPACK_DECOMPRESSION_FAILED);
    HQ_CHECK(client.conn_closed && server.conn_closed);
    HQ_CHECK(hq_limit_created == HQ_LIMIT_BLOCKED + 1);
    HQ_CHECK(hq_limit_closed == hq_limit_created);
    rc = 0;

fail:
    xqc_complex_case_engine_release(&client.base);
    xqc_complex_case_engine_release(&server.base);
    return rc;
}

static int
hq_blocked_reject_after_close(void)
{
    hq_endpoint_t client, server;
    xqc_complex_case_engine_t *engines[] = {&client.base, &server.base};
    xqc_conn_ssl_config_t ssl = {0};
    xqc_h3_stream_t *h3s;
    xqc_stream_t *enc, *ts, *svr_enc;
    uint64_t window, sid, svr_enc_window;
    xqc_usec_t dl;
    int rc = 1, i;

    memset(&client, 0, sizeof(client));
    memset(&server, 0, sizeof(server));
    memset(hq_pad_value, 'a', sizeof(hq_pad_value));
    client.base.socket.fd = server.base.socket.fd = -1;
    HQ_CHECK(hq_engine_init(&server, XQC_ENGINE_SERVER) == 0);
    HQ_CHECK(hq_engine_init(&client, XQC_ENGINE_CLIENT) == 0);

    const xqc_cid_t *cid = xqc_h3_connect(client.base.engine,
        &client.base.engine->default_conn_settings, NULL, 0, "localhost", 0,
        &ssl, (struct sockaddr *)&server.base.local, server.base.locallen,
        &client);
    HQ_CHECK(cid != NULL);
    dl = HQ_WAIT_DEADLINE;
    for (i = 0; (!client.h3 || !server.h3)
         && xqc_complex_case_now_us() < dl; i++) {
        xqc_complex_case_pump(engines, 2, 10);
    }
    HQ_CHECK(client.h3 && server.h3);

    /* wait until the client's encoder knows the peer's dynamic table capacity */
    dl = HQ_WAIT_DEADLINE;
    for (i = 0; client.h3->peer_h3_conn_settings
         .qpack_dec_max_table_capacity == XQC_H3_SETTINGS_UNSET
         && xqc_complex_case_now_us() < dl; i++)
    {
        xqc_complex_case_pump(engines, 2, 10);
    }
    HQ_CHECK(client.h3->peer_h3_conn_settings.qpack_dec_max_table_capacity
        != XQC_H3_SETTINGS_UNSET);

    /*
     * Enforce a small field-section limit at decode time only; the value
     * advertised in SETTINGS stays at the default so the client does not
     * refuse to send the oversized header section.
     */
    server.h3->local_h3_conn_settings.max_field_section_size = HQ_FIELD_LIMIT;

    /*
     * Throttle the client encoder stream as if the peer had advertised a
     * tiny initial_max_stream_data_uni: only the first HQ_THROTTLE_WINDOW
     * bytes (stream type prefix plus a partial insert instruction) go out
     * with the request; the rest is released after the request stream has
     * closed on the server.
     */
    enc = client.h3->qenc_stream->stream;
    window = enc->stream_flow_ctl.fc_max_stream_data_can_send;
    enc->stream_flow_ctl.fc_max_stream_data_can_send = HQ_THROTTLE_WINDOW;

    /*
     * Make the server refuse every MAX_STREAM_DATA grant for the encoder
     * stream: with a zero receive-window allowance the DATA_BLOCKED
     * handler can never raise the limit, so the throttle holds for the
     * whole lifetime of the blocked request. Clamping the client window
     * alone is not enough, because xqc_engine_packet_process may run the
     * main logic (and thus send) before the caller can re-apply it.
     */
    svr_enc = NULL;
    dl = HQ_WAIT_DEADLINE;
    for (i = 0; svr_enc == NULL && xqc_complex_case_now_us() < dl; i++) {
        svr_enc = xqc_find_stream_by_id(enc->stream_id,
                                        server.h3->conn->streams_hash);
        if (svr_enc == NULL) {
            hq_pump_pass(&client, &server, enc, HQ_THROTTLE_WINDOW);
        }
    }
    HQ_CHECK(svr_enc != NULL);
    svr_enc_window = svr_enc->stream_flow_ctl.fc_stream_recv_window_size;
    svr_enc->stream_flow_ctl.fc_stream_recv_window_size = 0;

    xqc_h3_request_t *request = xqc_h3_request_create(client.base.engine,
                                                    cid, NULL, &client);
    HQ_CHECK(request != NULL);
    xqc_http_header_t fields[] = {
        {.name = {(void *)":method", 7}, .value = {(void *)"GET", 3}},
        {.name = {(void *)":scheme", 7}, .value = {(void *)"https", 5}},
        {.name = {(void *)":authority", 10}, .value = {(void *)"localhost", 9}},
        {.name = {(void *)":path", 5}, .value = {(void *)"/", 1}},
        {.name = {(void *)"x-pad", 5},
         .value = {hq_pad_value, sizeof(hq_pad_value)}},
    };
    xqc_http_headers_t headers = {.headers = fields,
        .count = sizeof(fields) / sizeof(fields[0])};
    HQ_CHECK(xqc_h3_request_send_headers(request, &headers, 1) >= 0);

    /* the request HEADERS is blocked behind the throttled insert instruction */
    dl = HQ_WAIT_DEADLINE;
    for (i = 0; !hq_server_blocked(&server)
         && xqc_complex_case_now_us() < dl; i++) {
        hq_pump_pass(&client, &server, enc, HQ_THROTTLE_WINDOW);
    }
    HQ_CHECK(hq_server_blocked(&server) && server.req_headers == 0);

    /* the blocked h3 stream is still attached to its transport stream */
    sid = request->h3_stream->stream_id;
    ts = xqc_find_stream_by_id(sid, server.h3->conn->streams_hash);
    HQ_CHECK(ts != NULL);
    h3s = ts->user_data;
    HQ_CHECK(h3s != NULL && h3s->stream == ts);

    /*
     * The client aborts the blocked request; FIN was already consumed, so
     * the reset completes the server-side transport stream while the h3
     * stream stays alive for the delayed destroy.
     */
    HQ_CHECK(xqc_h3_request_close(request) == XQC_OK);

    /*
     * A terminally-closed transport stream is destroyed only after the
     * STREAM_CLOSE timer expires (3*PTO), so wait on a real-time deadline
     * instead of a pass count.
     */
    xqc_usec_t close_deadline = xqc_complex_case_now_us() + 5000000;
    while (h3s->stream != NULL
           && xqc_complex_case_now_us() < close_deadline)
    {
        hq_pump_pass(&client, &server, enc, HQ_THROTTLE_WINDOW);
    }
    if (h3s->stream != NULL) {
        ts = xqc_find_stream_by_id(sid, server.h3->conn->streams_hash);
        fprintf(stderr, "transport stream not closed: ts:%p sid:%lu blocked:%d "
                "flags:0x%lx c_closed:%d s_closed:%d c_err:%d s_err:%d\n",
                (void *)ts, (unsigned long)sid, hq_server_blocked(&server),
                (unsigned long)h3s->flags, client.conn_closed, server.conn_closed,
                client.conn_error, server.conn_error);
        if (ts != NULL) {
            fprintf(stderr, " send:%d recv:%d flag:0x%x",
                    ts->stream_state_send, ts->stream_state_recv,
                    ts->stream_flag);
        }
        fprintf(stderr, "\n");
    }
    HQ_CHECK(h3s->stream == NULL);
    HQ_CHECK(h3s->flags & XQC_HTTP3_STREAM_FLAG_CLOSED);
    HQ_CHECK(xqc_find_stream_by_id(sid, server.h3->conn->streams_hash) == NULL);
    HQ_CHECK(hq_server_blocked(&server));   /* h3s survives */
    HQ_CHECK(!client.conn_closed && !server.conn_closed);

    /* release the rest of the insert instruction */
    enc->stream_flow_ctl.fc_max_stream_data_can_send = window;
    enc->stream_flag &= ~XQC_STREAM_FLAG_DATA_BLOCKED;
    svr_enc->stream_flow_ctl.fc_stream_recv_window_size = svr_enc_window;
    /*
     * The connection went idle while the transport stream was being torn
     * down, so the engine no longer schedules its write loop on its own;
     * re-arm the encoder stream to put the connection back onto the
     * active queue, otherwise the buffered insert instruction never goes
     * out and the server stays blocked forever.
     */
    xqc_stream_ready_to_write(enc);
    dl = HQ_WAIT_DEADLINE;
    for (i = 0; hq_server_blocked(&server)
         && xqc_complex_case_now_us() < dl; i++) {
        hq_pump_pass(&client, &server, NULL, 0);
    }
    /* pre-fix the reject path dereferences the dead transport stream here */
    HQ_CHECK(!hq_server_blocked(&server));
    HQ_CHECK(server.h3->total_blocked_buf_size == 0);
    HQ_CHECK(server.req_headers == 0);
    HQ_CHECK(!client.conn_closed && !server.conn_closed);
    HQ_CHECK(!client.conn_error && !server.conn_error);

    /* the connection survives: a plain request still round-trips */
    request = xqc_h3_request_create(client.base.engine, cid, NULL, &client);
    HQ_CHECK(request != NULL);
    headers.count = 4;
    HQ_CHECK(xqc_h3_request_send_headers(request, &headers, 1) >= 0);
    dl = HQ_WAIT_DEADLINE;
    for (i = 0; !client.resp_headers && xqc_complex_case_now_us() < dl; i++) {
        hq_pump_pass(&client, &server, NULL, 0);
    }
    HQ_CHECK(server.req_headers == 1 && client.resp_headers == 1);
    rc = 0;

fail:
    xqc_complex_case_engine_release(&client.base);
    xqc_complex_case_engine_release(&server.base);
    return rc;
}

int
main(int argc, char **argv)
{
    int rc = 1;
    setbuf(stdout, NULL);
    if (argc == 2 && !strcmp(argv[1], "error-codes")) {
        rc = hq_qpack_error_codes();

    } else if (argc == 2 && !strcmp(argv[1], "blocked-limit")) {
        rc = hq_blocked_limit();

    } else if (argc == 2 && !strcmp(argv[1], "blocked-reject-after-close")) {
        rc = hq_blocked_reject_after_close();

    } else {
        fprintf(stderr, "usage: %s blocked-reject-after-close\n", argv[0]);
    }
    printf("h3 qpack %s: %s\n", argc == 2 ? argv[1] : "usage",
           rc == 0 ? "pass" : "fail");
    return rc;
}
