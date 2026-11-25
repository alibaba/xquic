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

/* bytes that the server's QPACK decoder stream wrote: sent or buffered */
static uint64_t
hq_section_dec_sent(hq_endpoint_t *server)
{
    xqc_h3_stream_t *h3s = server->h3->qdec_stream;
    uint64_t bytes = h3s->stream->stream_send_offset;
    xqc_list_head_t *pos;

    xqc_list_for_each(pos, &h3s->send_buf) {
        xqc_list_buf_t *lb = xqc_list_entry(pos, xqc_list_buf_t, list_head);
        bytes += lb->buf->data_len - lb->buf->consumed_len;
    }

    return bytes;
}

/* bytes of the server's QPACK decoder stream that the client received */
static uint64_t
hq_section_dec_rcvd(hq_endpoint_t *client, hq_endpoint_t *server)
{
    xqc_stream_t *stream;

    stream = xqc_find_stream_by_id(server->h3->qdec_stream->stream_id,
                                   client->h3->conn->streams_hash);
    return stream != NULL ? stream->stream_data_in.merged_offset_end : 0;
}

/* the error of an endpoint's connection is an application error */
static int
hq_section_err_app(hq_endpoint_t *ep)
{
    if (ep->h3 == NULL) {
        return ep->conn_closed && ep->conn_error_app;
    }

    return XQC_CONN_ERR_IS_APPLICATION(ep->h3->conn->conn_err);
}

/* the error of an endpoint's connection, 0 while it has none */
static uint64_t
hq_section_err(hq_endpoint_t *ep)
{
    if (ep->h3 == NULL) {
        return ep->conn_closed ? (uint64_t) ep->conn_error : 0;
    }

    return XQC_CONN_ERR_CODE(ep->h3->conn->conn_err);
}

/*
 * RFC 9204 Section 2.2.1: a stream becomes unblocked when the Insert Count
 * reaches the Required Insert Count of its field section, even when no
 * byte arrived after the one it blocked on. The client writes the bytes of
 * a request itself, with field sections that refer to entries its encoder
 * has not inserted yet. Then its encoder encodes, for the same stream, a
 * field section that inserts the next entry, which it does not send: the
 * server's Section Acknowledgments for that stream stay in step with the
 * field sections the encoder recorded.
 */
typedef struct {
    hq_endpoint_t               client;
    hq_endpoint_t               server;
    const xqc_cid_t            *cid;
} hq_resume_t;

static int hq_resume_init(hq_resume_t *r);
static int hq_resume_insert(hq_resume_t *r, xqc_h3_request_t *request,
    const char *name, uint64_t icnt);
static void hq_resume_uninit(hq_resume_t *r);

static int
hq_resume_init(hq_resume_t *r)
{
    xqc_complex_case_engine_t *engines[] = {&r->client.base, &r->server.base};
    xqc_conn_ssl_config_t ssl = {0};
    xqc_usec_t dl;

    memset(r, 0, sizeof(*r));
    r->client.base.socket.fd = r->server.base.socket.fd = -1;
    if (hq_engine_init(&r->server, XQC_ENGINE_SERVER) != 0
        || hq_engine_init(&r->client, XQC_ENGINE_CLIENT) != 0)
    {
        return -1;
    }

    r->cid = xqc_h3_connect(r->client.base.engine,
        &r->client.base.engine->default_conn_settings, NULL, 0, "localhost",
        0, &ssl, (struct sockaddr *)&r->server.base.local,
        r->server.base.locallen, &r->client);
    if (r->cid == NULL) {
        return -1;
    }

    /* the client's encoder applied the server's SETTINGS */
    dl = HQ_WAIT_DEADLINE;
    while ((r->client.h3 == NULL || r->server.h3 == NULL
            || r->client.h3->peer_h3_conn_settings.qpack_dec_max_table_capacity
               == XQC_H3_SETTINGS_UNSET)
           && xqc_complex_case_now_us() < dl)
    {
        xqc_complex_case_pump(engines, 2, 10);
    }

    return r->client.h3 != NULL && r->server.h3 != NULL
           && r->client.h3->peer_h3_conn_settings.qpack_dec_max_table_capacity
              != XQC_H3_SETTINGS_UNSET ? 0 : -1;
}

/*
 * the client's encoder inserts name: 1 for the request's stream, and the
 * server's decoder receives it, its Insert Count reaching icnt; or the
 * server's connection closes with an error
 */
static int
hq_resume_insert(hq_resume_t *r, xqc_h3_request_t *request,
    const char *name, uint64_t icnt)
{
    xqc_http_header_t field = {
        .name = {(void *) name, strlen(name)}, .value = {(void *) "1", 1},
    };
    xqc_http_headers_t headers = {.headers = &field, .count = 1};
    xqc_complex_case_engine_t *engines[] = {&r->client.base, &r->server.base};
    xqc_var_buf_t *efs = xqc_var_buf_create(64);
    xqc_usec_t dl;
    int ret;

    if (efs == NULL) {
        return -1;
    }

    ret = xqc_qpack_enc_headers(r->client.h3->qpack,
                                request->h3_stream->stream_id, &headers,
                                efs);
    xqc_var_buf_free(efs);
    if (ret != XQC_OK) {
        return -1;
    }

    dl = HQ_WAIT_DEADLINE;
    while (r->server.h3 != NULL && r->server.h3->conn->conn_err == 0
           && xqc_qpack_get_dec_insert_count(r->server.h3->qpack) < icnt
           && xqc_complex_case_now_us() < dl)
    {
        xqc_complex_case_pump(engines, 2, 10);
    }

    return r->server.h3 != NULL
           && xqc_qpack_get_dec_insert_count(r->server.h3->qpack) == icnt
           ? 0 : -1;
}

static void
hq_resume_uninit(hq_resume_t *r)
{
    xqc_complex_case_engine_release(&r->client.base);
    xqc_complex_case_engine_release(&r->server.base);
}

/*
 * The first bytes of the request's HEADERS frame end with the prefix of its
 * field section, which refers to an entry not inserted yet: the server
 * blocks with no byte to buffer. The insertion unblocks the stream; then
 * the field line arrives, and the server answers the request.
 */
static int
hq_blocked_resume(void)
{
    /* HEADERS: Required Insert Count 1 (encoded as 2), Base 1 ... */
    unsigned char prefix[] = { 0x01, 0x03, 0x02, 0x00 };
    /* ... Indexed Field Line, dynamic relative index 0 */
    unsigned char line[] = { 0x80 };
    hq_resume_t r;
    xqc_complex_case_engine_t *engines[] = {&r.client.base, &r.server.base};
    xqc_h3_request_t *request;
    xqc_stream_t *stream;
    int rc = 1, resumed = 0;
    xqc_usec_t dl;

    HQ_CHECK(hq_resume_init(&r) == 0);
    request = xqc_h3_request_create(r.client.base.engine, r.cid, NULL,
                                    &r.client);
    HQ_CHECK(request != NULL);
    stream = request->h3_stream->stream;

    HQ_CHECK(xqc_stream_send(stream, prefix, sizeof(prefix), 0)
             == (ssize_t) sizeof(prefix));
    dl = HQ_WAIT_DEADLINE;
    while (!hq_server_blocked(&r.server) && xqc_complex_case_now_us() < dl) {
        xqc_complex_case_pump(engines, 2, 10);
    }
    HQ_CHECK(hq_server_blocked(&r.server));

    HQ_CHECK(hq_resume_insert(&r, request, "x-resume", 1) == 0);
    resumed = !hq_server_blocked(&r.server);

    HQ_CHECK(xqc_stream_send(stream, line, sizeof(line), 1)
             == (ssize_t) sizeof(line));
    dl = HQ_WAIT_DEADLINE;
    while (r.client.resp_headers == 0 && !r.client.conn_closed
           && xqc_complex_case_now_us() < dl)
    {
        xqc_complex_case_pump(engines, 2, 10);
    }
    printf("h3 qpack blocked resume: unblocked by the insertion %d, server "
           "requests %d, client responses %d\n", resumed,
           r.server.req_headers, r.client.resp_headers);
    HQ_CHECK(resumed);
    HQ_CHECK(r.server.req_headers == 1 && r.client.resp_headers == 1);
    HQ_CHECK(!r.client.conn_closed && !r.server.conn_closed);
    HQ_CHECK(r.client.h3->conn->conn_err == 0
             && r.server.h3->conn->conn_err == 0);
    rc = 0;

fail:
    hq_resume_uninit(&r);
    return rc;
}

/*
 * The request is a HEADERS frame on entry 0, a DATA frame, and a trailer
 * HEADERS frame on entry 1, before either is inserted. The server blocks on
 * the prefix of the first section, and buffers the rest: its first buffer,
 * of 4096 bytes, ends with the prefix of the trailer section. The first
 * insertion unblocks the stream, and the trailer section blocks again on
 * the last byte of that buffer, which is no protocol error. The second
 * insertion unblocks the stream again, which decodes the trailer section.
 */
static int
hq_blocked_again(void)
{
    /* HEADERS: Required Insert Count 1, Base 1, dynamic relative index 0 */
    static const unsigned char header[] = { 0x01, 0x03, 0x02, 0x00, 0x80 };
    /* the same, Required Insert Count 2, Base 2: entry 1 */
    static const unsigned char trailer[] = { 0x01, 0x03, 0x03, 0x00, 0x80 };
    /* DATA, of 4096 bytes less those around it in the first buffer */
    enum { HQ_AGAIN_DATA = XQC_DATA_BUF_SIZE_4K - 1 - 3 - 4 };
    static unsigned char req[sizeof(header) + 3 + HQ_AGAIN_DATA
                             + sizeof(trailer)];
    hq_resume_t r;
    xqc_complex_case_engine_t *engines[] = {&r.client.base, &r.server.base};
    xqc_h3_request_t *request;
    xqc_stream_t *ts;
    xqc_h3_stream_t *h3s = NULL;
    uint64_t err = 0;
    int rc = 1, again = 0, blocked = 1;
    xqc_usec_t dl;

    memcpy(req, header, sizeof(header));
    req[sizeof(header)] = 0x00;
    req[sizeof(header) + 1] = 0x40 | (HQ_AGAIN_DATA >> 8);
    req[sizeof(header) + 2] = HQ_AGAIN_DATA & 0xff;
    memcpy(req + sizeof(req) - sizeof(trailer), trailer, sizeof(trailer));

    HQ_CHECK(hq_resume_init(&r) == 0);
    request = xqc_h3_request_create(r.client.base.engine, r.cid, NULL,
                                    &r.client);
    HQ_CHECK(request != NULL);
    HQ_CHECK(xqc_stream_send(request->h3_stream->stream, req, sizeof(req), 1)
             == (ssize_t) sizeof(req));

    /* the server buffered every byte after the first prefix */
    dl = HQ_WAIT_DEADLINE;
    while ((h3s == NULL || h3s->blocked_buf_size != sizeof(req) - 4)
           && xqc_complex_case_now_us() < dl)
    {
        xqc_complex_case_pump(engines, 2, 10);
        ts = xqc_find_stream_by_id(request->h3_stream->stream_id,
                                   r.server.h3->conn->streams_hash);
        h3s = ts != NULL && hq_server_blocked(&r.server) ? ts->user_data
                                                          : NULL;
    }
    HQ_CHECK(h3s != NULL && h3s->blocked_buf_size == sizeof(req) - 4);

    if (hq_resume_insert(&r, request, "x-resume", 1) == 0) {
        again = hq_server_blocked(&r.server);
        if (hq_resume_insert(&r, request, "x-again", 2) == 0) {
            blocked = hq_server_blocked(&r.server);
        }
    }
    err = r.server.h3 != NULL ? XQC_CONN_ERR_CODE(r.server.h3->conn->conn_err)
                              : (uint64_t) r.server.conn_error;
    printf("h3 qpack blocked again: blocked again %d after the first "
           "insertion, then blocked %d, server 0x%llx, server requests %d\n",
           again, blocked, (unsigned long long) err, r.server.req_headers);
    HQ_CHECK(again && !blocked && err == 0);
    HQ_CHECK(!r.client.conn_closed && !r.server.conn_closed);
    HQ_CHECK(r.server.h3->total_blocked_buf_size == 0);
    HQ_CHECK(r.server.req_headers == 1);
    HQ_CHECK(r.client.h3->conn->conn_err == 0);
    rc = 0;

fail:
    hq_resume_uninit(&r);
    return rc;
}

/*
 * RFC 9204 Sections 2.2.2.1 and 4.5.1: the server's decoder acknowledges
 * a field section that refers to its dynamic table once the HEADERS frame
 * that carries it ends, and the server closes the connection with
 * QPACK_DECOMPRESSION_FAILED when a HEADERS frame ends inside a field line.
 * The client sends one request twice: its encoder inserts the fields for
 * the first, and only refers to them in the second.
 */
static int
hq_section_end(void)
{
    /*
     * HEADERS: Required Insert Count 0, Base 0, then a Literal Field Line
     * With Name Reference to static :path, cut inside its 3-byte value
     */
    static const unsigned char cut[] = {
        0x01, 0x05, 0x00, 0x00, 0x51, 0x03, '/'
    };
    xqc_http_header_t fields[] = {
        {.name = {(void *)":method", 7}, .value = {(void *)"GET", 3}},
        {.name = {(void *)":scheme", 7}, .value = {(void *)"https", 5}},
        {.name = {(void *)":authority", 10},
         .value = {(void *)"localhost", 9}},
        {.name = {(void *)":path", 5}, .value = {(void *)"/", 1}},
        {.name = {(void *)"x-section", 9}, .value = {(void *)"end", 3}},
    };
    xqc_http_headers_t headers = {.headers = fields,
        .count = sizeof(fields) / sizeof(fields[0])};
    hq_endpoint_t client, server;
    xqc_complex_case_engine_t *engines[] = {&client.base, &server.base};
    xqc_conn_ssl_config_t ssl = {0};
    xqc_h3_request_t *request;
    unsigned char buf[sizeof(cut)];
    uint64_t sent[2];
    xqc_usec_t dl;
    int rc = 1, app = 0, i;

    memset(&client, 0, sizeof(client));
    memset(&server, 0, sizeof(server));
    client.base.socket.fd = server.base.socket.fd = -1;
    HQ_CHECK(hq_engine_init(&server, XQC_ENGINE_SERVER) == 0);
    HQ_CHECK(hq_engine_init(&client, XQC_ENGINE_CLIENT) == 0);

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

    for (i = 0; i < 2; i++) {
        request = xqc_h3_request_create(client.base.engine, cid, NULL,
                                        &client);
        HQ_CHECK(request != NULL);
        HQ_CHECK(xqc_h3_request_send_headers(request, &headers, 1) >= 0);
        dl = HQ_WAIT_DEADLINE;
        while (client.resp_headers == i && !client.conn_closed
               && xqc_complex_case_now_us() < dl)
        {
            xqc_complex_case_pump(engines, 2, 10);
        }
        HQ_CHECK(server.req_headers == i + 1
                 && client.resp_headers == i + 1);
        sent[i] = hq_section_dec_sent(&server);
    }

    /*
     * the second field section inserts nothing: the server's decoder
     * stream carries only its Section Acknowledgment, the byte 0x84 of
     * stream 4, which the client's encoder takes
     */
    dl = HQ_WAIT_DEADLINE;
    while (hq_section_dec_rcvd(&client, &server) < sent[1]
           && xqc_complex_case_now_us() < dl)
    {
        xqc_complex_case_pump(engines, 2, 10);
    }
    printf("h3 qpack section end: second request acknowledged with %llu "
           "byte(s), client received %llu of %llu\n",
           (unsigned long long) (sent[1] - sent[0]),
           (unsigned long long) hq_section_dec_rcvd(&client, &server),
           (unsigned long long) sent[1]);
    HQ_CHECK(sent[1] - sent[0] == 1);
    HQ_CHECK(hq_section_dec_rcvd(&client, &server) == sent[1]);
    HQ_CHECK(hq_section_err(&client) == 0 && hq_section_err(&server) == 0);

    /* a HEADERS frame that ends inside a field line */
    request = xqc_h3_request_create(client.base.engine, cid, NULL, &client);
    HQ_CHECK(request != NULL);
    memcpy(buf, cut, sizeof(cut));
    HQ_CHECK(xqc_stream_send(request->h3_stream->stream, buf, sizeof(buf), 0)
             == (ssize_t) sizeof(buf));
    dl = HQ_WAIT_DEADLINE;
    while (hq_section_err(&server) == 0 && xqc_complex_case_now_us() < dl) {
        xqc_complex_case_pump(engines, 2, 10);
    }

    /* the server's connection is closing, or already closed */
    app = hq_section_err_app(&server);
    dl = HQ_WAIT_DEADLINE;
    while (hq_section_err(&client) == 0 && xqc_complex_case_now_us() < dl) {
        xqc_complex_case_pump(engines, 2, 10);
    }
    printf("h3 qpack section end: cut HEADERS: server 0x%llx (%s), "
           "client 0x%llx, server requests %d\n",
           (unsigned long long) hq_section_err(&server),
           app ? "application" : "transport or none",
           (unsigned long long) hq_section_err(&client), server.req_headers);
    HQ_CHECK(hq_section_err(&server) == QPACK_DECOMPRESSION_FAILED && app);
    HQ_CHECK(hq_section_err(&client) == QPACK_DECOMPRESSION_FAILED);
    HQ_CHECK(server.req_headers == 2);
    rc = 0;

fail:
    xqc_complex_case_engine_release(&client.base);
    xqc_complex_case_engine_release(&server.base);
    return rc;
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
    if (argc == 2 && !strcmp(argv[1], "blocked-reject-after-close")) {
        rc = hq_blocked_reject_after_close();
    } else if (argc == 2 && !strcmp(argv[1], "blocked-resume")) {
        rc = hq_blocked_resume();
    } else if (argc == 2 && !strcmp(argv[1], "blocked-again")) {
        rc = hq_blocked_again();
    } else if (argc == 2 && !strcmp(argv[1], "section-end")) {
        rc = hq_section_end();

    } else {
        fprintf(stderr, "usage: %s blocked-reject-after-close\n", argv[0]);
    }
    printf("h3 qpack %s: %s\n", argc == 2 ? argv[1] : "usage",
           rc == 0 ? "pass" : "fail");
    return rc;
}
