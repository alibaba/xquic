/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 *
 * Fuzz target: a client engine and a server engine connected in memory.
 *
 * The first byte configures both endpoints: HTTP/3 or the transport ALPN,
 * multipath, DATAGRAM, RESET_STREAM_AT and ACK_EXTENDED, FEC, a Retry from
 * the server, and whether the handshake completes before the operations.
 * The rest is a series of operations, each a selector byte, most of them
 * followed by a chunk with a 16-bit length:
 *
 *   frames   the chunk is the payload of a packet that one endpoint
 *            protects with its own keys, at one encryption level and on one
 *            of its paths, and sends to the other: any frame sequence
 *            reaches the receiver's packet and frame processing
 *   raw      the chunk is a datagram sent as is to one endpoint, from the
 *            other endpoint's address or from a new one; a Retry gets a
 *            valid integrity tag on request
 *   deliver  the datagrams that the endpoints sent are delivered
 *   time     the virtual clock advances and both engines run their timers
 *   app      the client opens a stream or request and sends the chunk on
 *            it, sends a datagram, opens or closes a path, sends a PING,
 *            moves to a new address or closes the connection
 *
 * The server reads everything it is given and answers each request.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include "src/common/xqc_malloc.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/tls/xqc_tls.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_packet_parser.h"
#include "xqc_fuzz_common.h"

#define XQC_FUZZ_MAX_QUEUE      64
#define XQC_FUZZ_MAX_OPS        64
#define XQC_FUZZ_DELIVER_ROUNDS 8
#define XQC_FUZZ_HS_ROUNDS      16
#define XQC_FUZZ_SERVER_PORT    4433
#define XQC_FUZZ_CLIENT_PORT    50000

/* the configuration byte */
#define XQC_FUZZ_CFG_H3         0x01
#define XQC_FUZZ_CFG_HANDSHAKE  0x02
#define XQC_FUZZ_CFG_MP         0x04
#define XQC_FUZZ_CFG_DGRAM      0x08
#define XQC_FUZZ_CFG_EXT        0x10
#define XQC_FUZZ_CFG_FEC        0x20
#define XQC_FUZZ_CFG_RETRY      0x40
#define XQC_FUZZ_CFG_CID_NEG    0x80

/*
 * the longest Retry whose integrity tag a client checks: longer tokens or
 * connection IDs are refused first
 */
#define XQC_FUZZ_RETRY_MAX_LEN                                              \
    (7 + 2 * XQC_MAX_CID_LEN + XQC_MAX_TOKEN_LEN + XQC_RETRY_INTEGRITY_TAG_LEN)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* defined in src/transport/xqc_packet_parser.c */
xqc_int_t xqc_conn_gen_retry_integrity_tag(
    xqc_connection_t *conn, const uint8_t *odcid_buf, unsigned odcid_len,
    uint8_t *retry_buf, unsigned retry_len, uint8_t *tag_buf, size_t *tag_len);

typedef struct xqc_fuzz_dgram_s {
    unsigned char *buf;
    size_t len;
    struct sockaddr_in from;
    struct sockaddr_in to;
} xqc_fuzz_dgram_t;

typedef struct xqc_fuzz_endpoint_s {
    xqc_engine_t *engine;
    xqc_cid_t cid;
    xqc_bool_t has_cid;
    xqc_fuzz_dgram_t queue[XQC_FUZZ_MAX_QUEUE];
    size_t queued;
} xqc_fuzz_endpoint_t;

static xqc_fuzz_endpoint_t xqc_fuzz_cli;
static xqc_fuzz_endpoint_t xqc_fuzz_srv;
static uint8_t xqc_fuzz_cfg;
/* the client's port offset, moved by a NAT rebinding */
static uint16_t xqc_fuzz_cli_port;


static void
xqc_fuzz_addr(struct sockaddr_in *sa, uint8_t host, uint16_t port)
{
    memset(sa, 0, sizeof(*sa));
    sa->sin_family = AF_INET;
    sa->sin_addr.s_addr = htonl(0x0a000000 | host);
    sa->sin_port = htons(port);
}

/* the address of a client path: one host per path ID */
static void
xqc_fuzz_client_addr(struct sockaddr_in *sa, uint64_t path_id)
{
    xqc_fuzz_addr(sa, (uint8_t)(2 + path_id % 200),
                  (uint16_t)(XQC_FUZZ_CLIENT_PORT + xqc_fuzz_cli_port));
}

static void
xqc_fuzz_server_addr(struct sockaddr_in *sa)
{
    xqc_fuzz_addr(sa, 1, XQC_FUZZ_SERVER_PORT);
}

static void
xqc_fuzz_queue(xqc_fuzz_endpoint_t *ep, const unsigned char *buf, size_t size,
               const struct sockaddr_in *from, const struct sockaddr *to)
{
    xqc_fuzz_dgram_t *d;

    if (ep->queued == XQC_FUZZ_MAX_QUEUE || size == 0) {
        return;
    }

    d = &ep->queue[ep->queued];
    /* exactly the size of the datagram, so that ASan sees overreads */
    d->buf = malloc(size);
    if (d->buf == NULL) {
        return;
    }
    memcpy(d->buf, buf, size);
    d->len = size;
    d->from = *from;
    if (to != NULL && to->sa_family == AF_INET) {
        memcpy(&d->to, to, sizeof(d->to));

    } else {
        xqc_fuzz_server_addr(&d->to);
    }
    ep->queued++;
}

static void
xqc_fuzz_queue_free(xqc_fuzz_endpoint_t *ep)
{
    size_t i;

    for (i = 0; i < ep->queued; i++) {
        free(ep->queue[i].buf);
    }
    ep->queued = 0;
}

static xqc_connection_t *
xqc_fuzz_find_conn(xqc_fuzz_endpoint_t *ep)
{
    if (ep->engine == NULL || !ep->has_cid) {
        return NULL;
    }
    return xqc_engine_conns_hash_find(ep->engine, &ep->cid, 's');
}


/* ---- socket and transport callbacks ---- */

static ssize_t
xqc_fuzz_cli_write_ex(uint64_t path_id, const unsigned char *buf, size_t size,
                      const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                      void *user_data)
{
    struct sockaddr_in from;

    xqc_fuzz_client_addr(&from, path_id);
    xqc_fuzz_queue(&xqc_fuzz_cli, buf, size, &from, peer_addr);
    return (ssize_t)size;
}

static ssize_t
xqc_fuzz_cli_write(const unsigned char *buf, size_t size,
                   const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                   void *user_data)
{
    return xqc_fuzz_cli_write_ex(0, buf, size, peer_addr, peer_addrlen,
                                 user_data);
}

static ssize_t
xqc_fuzz_srv_write_ex(uint64_t path_id, const unsigned char *buf, size_t size,
                      const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                      void *user_data)
{
    struct sockaddr_in from;

    xqc_fuzz_server_addr(&from);
    xqc_fuzz_queue(&xqc_fuzz_srv, buf, size, &from, peer_addr);
    return (ssize_t)size;
}

static ssize_t
xqc_fuzz_srv_write(const unsigned char *buf, size_t size,
                   const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                   void *user_data)
{
    return xqc_fuzz_srv_write_ex(0, buf, size, peer_addr, peer_addrlen,
                                 user_data);
}

static ssize_t
xqc_fuzz_srv_reset(const unsigned char *buf, size_t size,
                   const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                   const struct sockaddr *local_addr, socklen_t local_addrlen,
                   void *user_data)
{
    return xqc_fuzz_srv_write(buf, size, peer_addr, peer_addrlen, user_data);
}

static int
xqc_fuzz_srv_accept(xqc_engine_t *engine, xqc_connection_t *conn,
                    const xqc_cid_t *cid, void *user_data)
{
    return 0;
}

static void
xqc_fuzz_srv_refuse(xqc_engine_t *engine, xqc_connection_t *conn,
                    const xqc_cid_t *cid, void *user_data)
{
}

static int
xqc_fuzz_srv_retry(xqc_engine_t *engine, xqc_connection_t *conn,
                   const xqc_cid_t *cid, void *user_data)
{
    return (xqc_fuzz_cfg & XQC_FUZZ_CFG_RETRY) ? XQC_TRUE : XQC_FALSE;
}

/* keep following the connection when its original CID is retired */
static void
xqc_fuzz_update_cid(xqc_fuzz_endpoint_t *ep, const xqc_cid_t *retire_cid,
                    const xqc_cid_t *new_cid)
{
    if (ep->has_cid && xqc_cid_is_equal(&ep->cid, retire_cid) == XQC_OK) {
        xqc_cid_copy(&ep->cid, (xqc_cid_t *)new_cid);
    }
}

static void
xqc_fuzz_cli_update_cid(xqc_connection_t *conn, const xqc_cid_t *retire_cid,
                        const xqc_cid_t *new_cid, void *user_data)
{
    xqc_fuzz_update_cid(&xqc_fuzz_cli, retire_cid, new_cid);
}

static void
xqc_fuzz_srv_update_cid(xqc_connection_t *conn, const xqc_cid_t *retire_cid,
                        const xqc_cid_t *new_cid, void *user_data)
{
    xqc_fuzz_update_cid(&xqc_fuzz_srv, retire_cid, new_cid);
}

static void
xqc_fuzz_save_string(const char *data, size_t data_len, void *user_data)
{
}

static void
xqc_fuzz_save_token(const unsigned char *token, uint32_t token_len,
                    void *user_data)
{
}

static int
xqc_fuzz_cert_verify(const unsigned char *certs[], const size_t cert_len[],
                     size_t certs_len, void *user_data)
{
    return 0;
}

static void
xqc_fuzz_ready_to_create_path(const xqc_cid_t *scid, void *user_data)
{
}

static int
xqc_fuzz_path_created(xqc_connection_t *conn, const xqc_cid_t *scid,
                      uint64_t path_id, void *user_data)
{
    return 0;
}

static void
xqc_fuzz_path_removed(const xqc_cid_t *scid, uint64_t path_id, void *user_data)
{
}


/* ---- the transport ALPN ---- */

static void
xqc_fuzz_stream_read_all(xqc_stream_t *stream, uint8_t *fin)
{
    unsigned char buf[4096];
    ssize_t n;

    *fin = 0;
    do {
        n = xqc_stream_recv(stream, buf, sizeof(buf), fin);
    } while (n > 0 && !*fin);
}

static xqc_int_t
xqc_fuzz_srv_stream_read(xqc_stream_t *stream, void *user_data)
{
    uint8_t fin;

    xqc_fuzz_stream_read_all(stream, &fin);
    if (fin) {
        /* answer the request */
        (void)xqc_stream_send(stream, (unsigned char *)"ok", 2, 1);
    }
    return 0;
}

static xqc_int_t
xqc_fuzz_cli_stream_read(xqc_stream_t *stream, void *user_data)
{
    uint8_t fin;

    xqc_fuzz_stream_read_all(stream, &fin);
    return 0;
}

static xqc_int_t
xqc_fuzz_stream_notify(xqc_stream_t *stream, void *user_data)
{
    return 0;
}

static void
xqc_fuzz_stream_closing(xqc_stream_t *stream, xqc_int_t err_code,
                        void *user_data)
{
}

static int
xqc_fuzz_srv_conn_create(xqc_connection_t *conn, const xqc_cid_t *cid,
                         void *user_data, void *proto_data)
{
    xqc_cid_copy(&xqc_fuzz_srv.cid, (xqc_cid_t *)cid);
    xqc_fuzz_srv.has_cid = XQC_TRUE;
    return 0;
}

static int
xqc_fuzz_conn_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
                     void *user_data, void *proto_data)
{
    return 0;
}

static void
xqc_fuzz_dgram_read(xqc_connection_t *conn, void *user_data, const void *data,
                    size_t data_len, uint64_t ts)
{
}


/* ---- HTTP/3 ---- */

static void
xqc_fuzz_h3_respond(xqc_h3_request_t *h3r)
{
    xqc_http_header_t field = {
        .name = {.iov_base = ":status", .iov_len = 7},
        .value = {.iov_base = "200", .iov_len = 3},
    };
    xqc_http_headers_t headers = {&field, 1, 1, 0};

    if (xqc_h3_request_send_headers(h3r, &headers, 0) >= 0) {
        (void)xqc_h3_request_send_body(h3r, (unsigned char *)"ok", 2, 1);
    }
}

static int
xqc_fuzz_h3_read(xqc_h3_request_t *h3r, xqc_request_notify_flag_t flag,
                 xqc_bool_t server)
{
    xqc_http_headers_t *headers;
    xqc_h3_priority_t prio;
    unsigned char buf[4096];
    uint8_t fin = 0;
    ssize_t n;
    size_t i;

    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        headers = xqc_h3_request_recv_headers(h3r, &fin);
        if (headers == NULL) {
            return 0;
        }

        /* an application that applies the client's priority (RFC 9218) */
        for (i = 0; server && i < headers->count; i++) {
            if (headers->headers[i].name.iov_len == 8
                && memcmp(headers->headers[i].name.iov_base, "priority", 8) == 0
                && xqc_parse_http_priority(&prio,
                                           headers->headers[i].value.iov_base,
                                           headers->headers[i].value.iov_len)
                       == XQC_OK)
            {
                (void)xqc_h3_request_set_priority(h3r, &prio);
            }
        }
    }

    if (flag & XQC_REQ_NOTIFY_READ_BODY) {
        do {
            n = xqc_h3_request_recv_body(h3r, buf, sizeof(buf), &fin);
        } while (n > 0 && !fin);
    }

    if (flag & XQC_REQ_NOTIFY_READ_EMPTY_FIN) {
        fin = 1;
    }

    if (server && fin) {
        xqc_fuzz_h3_respond(h3r);
    }

    return 0;
}

static int
xqc_fuzz_srv_h3_read(xqc_h3_request_t *h3r, xqc_request_notify_flag_t flag,
                     void *user_data)
{
    return xqc_fuzz_h3_read(h3r, flag, XQC_TRUE);
}

static int
xqc_fuzz_cli_h3_read(xqc_h3_request_t *h3r, xqc_request_notify_flag_t flag,
                     void *user_data)
{
    return xqc_fuzz_h3_read(h3r, flag, XQC_FALSE);
}

static int
xqc_fuzz_h3_request_notify(xqc_h3_request_t *h3r, void *user_data)
{
    return 0;
}

static int
xqc_fuzz_srv_h3_conn_create(xqc_h3_conn_t *h3c, const xqc_cid_t *cid,
                            void *user_data)
{
    xqc_cid_copy(&xqc_fuzz_srv.cid, (xqc_cid_t *)cid);
    xqc_fuzz_srv.has_cid = XQC_TRUE;
    return 0;
}

static int
xqc_fuzz_h3_conn_notify(xqc_h3_conn_t *h3c, const xqc_cid_t *cid,
                        void *user_data)
{
    return 0;
}

static void
xqc_fuzz_h3_handshake_finished(xqc_h3_conn_t *h3c, void *user_data)
{
}

static void
xqc_fuzz_h3_dgram_read(xqc_h3_conn_t *h3c, const void *data, size_t data_len,
                       void *user_data, uint64_t ts)
{
}

static int
xqc_fuzz_bs_notify(xqc_h3_ext_bytestream_t *bs, void *user_data)
{
    return 0;
}

static int
xqc_fuzz_bs_read(xqc_h3_ext_bytestream_t *bs, const void *data, size_t data_len,
                 uint8_t fin, void *user_data, uint64_t ts)
{
    return 0;
}


/* ---- engines ---- */

static void
xqc_fuzz_conn_settings(xqc_conn_settings_t *settings)
{
    memset(settings, 0, sizeof(*settings));
    settings->proto_version = XQC_VERSION_V1;
    settings->idle_time_out = 30000;
    settings->init_idle_time_out = 10000;
    settings->spurious_loss_detect_on = 1;

    if (xqc_fuzz_cfg & XQC_FUZZ_CFG_MP) {
        settings->enable_multipath = 1;
        settings->init_max_path_id = 4;
        settings->mp_ping_on = 1;
    }

    if (xqc_fuzz_cfg & XQC_FUZZ_CFG_DGRAM) {
        settings->max_datagram_frame_size = 1200;
    }

    if (xqc_fuzz_cfg & XQC_FUZZ_CFG_EXT) {
        settings->extended_ack_features = 2;
        settings->max_receive_timestamps_per_ack = 16;
        settings->receive_timestamps_exponent = 0;
        settings->enable_reset_stream_at = 1;
        settings->enable_pmtud = 1;
    }

#ifdef XQC_ENABLE_FEC
    if (xqc_fuzz_cfg & XQC_FUZZ_CFG_FEC) {
        settings->enable_encode_fec = 1;
        settings->enable_decode_fec = 1;
        settings->fec_params.fec_encoder_schemes[0] = XQC_XOR_CODE;
        settings->fec_params.fec_decoder_schemes[0] = XQC_XOR_CODE;
        settings->fec_params.fec_encoder_schemes[1] = XQC_REED_SOLOMON_CODE;
        settings->fec_params.fec_decoder_schemes[1] = XQC_REED_SOLOMON_CODE;
        settings->fec_params.fec_encoder_schemes_num = 2;
        settings->fec_params.fec_decoder_schemes_num = 2;
        settings->fec_params.fec_max_window_size = 8;
        settings->fec_params.fec_code_rate = 0.2;
        settings->fec_params.fec_max_symbol_num_per_block = 10;
    }
#endif
}

static xqc_engine_t *
xqc_fuzz_create_engine(xqc_engine_type_t type)
{
    xqc_engine_ssl_config_t ssl_config;
    xqc_engine_callback_t callbacks;
    xqc_transport_callbacks_t tcbs;
    xqc_app_proto_callbacks_t ap_cbs;
    xqc_h3_callbacks_t h3_cbs;
    xqc_conn_settings_t settings;
    xqc_config_t config;
    xqc_engine_t *engine;
    xqc_bool_t server = type == XQC_ENGINE_SERVER;

    xqc_fuzz_ssl_config(&ssl_config);
    xqc_fuzz_engine_callbacks(&callbacks);

    memset(&tcbs, 0, sizeof(tcbs));
    tcbs.save_token = xqc_fuzz_save_token;
    tcbs.save_session_cb = xqc_fuzz_save_string;
    tcbs.save_tp_cb = xqc_fuzz_save_string;
    tcbs.cert_verify_cb = xqc_fuzz_cert_verify;
    tcbs.ready_to_create_path_notify = xqc_fuzz_ready_to_create_path;
    tcbs.path_created_notify = xqc_fuzz_path_created;
    tcbs.path_removed_notify = xqc_fuzz_path_removed;
    if (server) {
        tcbs.server_accept = xqc_fuzz_srv_accept;
        tcbs.server_refuse = xqc_fuzz_srv_refuse;
        tcbs.stateless_reset = xqc_fuzz_srv_reset;
        tcbs.write_socket = xqc_fuzz_srv_write;
        tcbs.write_socket_ex = xqc_fuzz_srv_write_ex;
        tcbs.conn_send_packet_before_accept = xqc_fuzz_srv_write;
        tcbs.conn_update_cid_notify = xqc_fuzz_srv_update_cid;
        tcbs.conn_retry_packet_condition_check = xqc_fuzz_srv_retry;

    } else {
        tcbs.write_socket = xqc_fuzz_cli_write;
        tcbs.write_socket_ex = xqc_fuzz_cli_write_ex;
        tcbs.conn_update_cid_notify = xqc_fuzz_cli_update_cid;
    }

    xqc_fuzz_engine_config(&config, type);
    config.enable_h3_ext = 1;
    if (server && (xqc_fuzz_cfg & XQC_FUZZ_CFG_CID_NEG)) {
        config.cid_negotiate = 1;
        config.cid_len = XQC_MAX_CID_LEN;
    }

    engine = xqc_engine_create(type, &config, &ssl_config, &callbacks, &tcbs,
                               NULL);
    if (engine == NULL) {
        abort();
    }

    if (server) {
        xqc_fuzz_conn_settings(&settings);
        xqc_server_set_conn_settings(engine, &settings);
    }

    memset(&h3_cbs, 0, sizeof(h3_cbs));
    h3_cbs.h3c_cbs.h3_conn_create_notify = server ? xqc_fuzz_srv_h3_conn_create
                                                  : xqc_fuzz_h3_conn_notify;
    h3_cbs.h3c_cbs.h3_conn_close_notify = xqc_fuzz_h3_conn_notify;
    h3_cbs.h3c_cbs.h3_conn_handshake_finished = xqc_fuzz_h3_handshake_finished;
    h3_cbs.h3r_cbs.h3_request_create_notify = xqc_fuzz_h3_request_notify;
    h3_cbs.h3r_cbs.h3_request_close_notify = xqc_fuzz_h3_request_notify;
    h3_cbs.h3r_cbs.h3_request_write_notify = xqc_fuzz_h3_request_notify;
    h3_cbs.h3r_cbs.h3_request_read_notify = server ? xqc_fuzz_srv_h3_read
                                                   : xqc_fuzz_cli_h3_read;
    h3_cbs.h3_ext_dgram_cbs.dgram_read_notify = xqc_fuzz_h3_dgram_read;
    h3_cbs.h3_ext_bs_cbs.bs_create_notify = xqc_fuzz_bs_notify;
    h3_cbs.h3_ext_bs_cbs.bs_close_notify = xqc_fuzz_bs_notify;
    h3_cbs.h3_ext_bs_cbs.bs_write_notify = xqc_fuzz_bs_notify;
    h3_cbs.h3_ext_bs_cbs.bs_read_notify = xqc_fuzz_bs_read;
    if (xqc_h3_ctx_init(engine, &h3_cbs) != XQC_OK) {
        abort();
    }

    memset(&ap_cbs, 0, sizeof(ap_cbs));
    ap_cbs.conn_cbs.conn_create_notify = server ? xqc_fuzz_srv_conn_create
                                                : xqc_fuzz_conn_notify;
    ap_cbs.conn_cbs.conn_close_notify = xqc_fuzz_conn_notify;
    ap_cbs.stream_cbs.stream_read_notify = server ? xqc_fuzz_srv_stream_read
                                                  : xqc_fuzz_cli_stream_read;
    ap_cbs.stream_cbs.stream_write_notify = xqc_fuzz_stream_notify;
    ap_cbs.stream_cbs.stream_create_notify = xqc_fuzz_stream_notify;
    ap_cbs.stream_cbs.stream_close_notify = xqc_fuzz_stream_notify;
    ap_cbs.stream_cbs.stream_closing_notify = xqc_fuzz_stream_closing;
    ap_cbs.dgram_cbs.datagram_read_notify = xqc_fuzz_dgram_read;
    if (xqc_engine_register_alpn(engine, "transport", 9, &ap_cbs, NULL)
        != XQC_OK)
    {
        abort();
    }

    return engine;
}

static xqc_bool_t
xqc_fuzz_connect(void)
{
    xqc_conn_settings_t settings;
    xqc_conn_ssl_config_t ssl_config;
    struct sockaddr_in server;
    const xqc_cid_t *cid;

    xqc_fuzz_conn_settings(&settings);
    memset(&ssl_config, 0, sizeof(ssl_config));
    xqc_fuzz_server_addr(&server);

    if (xqc_fuzz_cfg & XQC_FUZZ_CFG_H3) {
        cid = xqc_h3_connect(xqc_fuzz_cli.engine, &settings, NULL, 0,
                             "test.xquic.com", 0, &ssl_config,
                             (struct sockaddr *)&server, sizeof(server), NULL);

    } else {
        cid = xqc_connect(xqc_fuzz_cli.engine, &settings, NULL, 0,
                          "test.xquic.com", 0, &ssl_config,
                          (struct sockaddr *)&server, sizeof(server),
                          "transport", NULL);
    }

    if (cid == NULL) {
        return XQC_FALSE;
    }

    xqc_cid_copy(&xqc_fuzz_cli.cid, (xqc_cid_t *)cid);
    xqc_fuzz_cli.has_cid = XQC_TRUE;
    return XQC_TRUE;
}


/* ---- operations ---- */

static void
xqc_fuzz_receive(xqc_fuzz_endpoint_t *dst, const unsigned char *buf, size_t len,
                 const struct sockaddr_in *from, const struct sockaddr_in *to)
{
    (void)xqc_engine_packet_process(dst->engine, buf, len,
                                    (const struct sockaddr *)to, sizeof(*to),
                                    (const struct sockaddr *)from,
                                    sizeof(*from), xqc_fuzz_now, NULL);
    xqc_engine_finish_recv(dst->engine);
}

/* deliver the datagrams sent so far, in both directions */
static void
xqc_fuzz_deliver(int rounds)
{
    xqc_fuzz_dgram_t dgrams[XQC_FUZZ_MAX_QUEUE];
    size_t n, i;
    int r, side;

    for (r = 0; r < rounds; r++) {
        if (xqc_fuzz_cli.queued == 0 && xqc_fuzz_srv.queued == 0) {
            return;
        }

        for (side = 0; side < 2; side++) {
            xqc_fuzz_endpoint_t *src = side ? &xqc_fuzz_srv : &xqc_fuzz_cli;
            xqc_fuzz_endpoint_t *dst = side ? &xqc_fuzz_cli : &xqc_fuzz_srv;

            n = src->queued;
            memcpy(dgrams, src->queue, n * sizeof(dgrams[0]));
            src->queued = 0;

            for (i = 0; i < n; i++) {
                xqc_fuzz_receive(dst, dgrams[i].buf, dgrams[i].len,
                                 &dgrams[i].from, &dgrams[i].to);
                free(dgrams[i].buf);
            }
        }
    }
}

static xqc_bool_t
xqc_fuzz_established(xqc_fuzz_endpoint_t *ep)
{
    xqc_connection_t *conn = xqc_fuzz_find_conn(ep);

    return conn != NULL && conn->conn_state == XQC_CONN_STATE_ESTABED;
}

static void
xqc_fuzz_handshake(void)
{
    int r;

    for (r = 0; r < XQC_FUZZ_HS_ROUNDS; r++) {
        if (xqc_fuzz_established(&xqc_fuzz_cli)
            && xqc_fuzz_established(&xqc_fuzz_srv))
        {
            break;
        }
        xqc_fuzz_deliver(1);
        xqc_fuzz_now += 1000;
    }

    /* let HANDSHAKE_DONE and the first ACKs through */
    xqc_fuzz_deliver(2);
}

/*
 * protect the chunk as the payload of a packet of the sender's own, at the
 * level and on the path that the selector picks, and send it to the peer
 */
static void
xqc_fuzz_send_frames(uint8_t sel, const uint8_t *payload, size_t len)
{
    static const xqc_pkt_type_t types[4] = {
        XQC_PTYPE_SHORT_HEADER,
        XQC_PTYPE_INIT,
        XQC_PTYPE_HSK,
        XQC_PTYPE_0RTT,
    };
    static const xqc_pkt_num_space_t spaces[4] = {
        XQC_PNS_APP_DATA,
        XQC_PNS_INIT,
        XQC_PNS_HSK,
        XQC_PNS_APP_DATA,
    };
    unsigned char enc[XQC_PACKET_OUT_BUF_CAP + 64];
    unsigned char *copy;
    xqc_fuzz_endpoint_t *src, *dst;
    xqc_connection_t *conn;
    xqc_path_ctx_t *path;
    xqc_packet_out_t *po;
    struct sockaddr_in from, to;
    size_t enc_len = 0, room;
    int level;

    src = (sel & 0x08) ? &xqc_fuzz_srv : &xqc_fuzz_cli;
    dst = (sel & 0x08) ? &xqc_fuzz_cli : &xqc_fuzz_srv;
    level = (sel >> 4) & 0x03;

    conn = xqc_fuzz_find_conn(src);
    if (conn == NULL || conn->conn_state >= XQC_CONN_STATE_CLOSING) {
        return;
    }

    /* a server does not send 0-RTT */
    if (types[level] == XQC_PTYPE_0RTT && src == &xqc_fuzz_srv) {
        return;
    }

    if (!xqc_tls_is_key_ready(conn->tls,
                              xqc_packet_type_to_enc_level(types[level]),
                              XQC_KEY_TYPE_TX_WRITE))
    {
        return;
    }

    path = xqc_conn_find_path_by_path_id(conn, (sel >> 6) & 0x03);
    if (path == NULL || types[level] != XQC_PTYPE_SHORT_HEADER) {
        path = conn->conn_initial_path;
    }
    if (path == NULL) {
        return;
    }

    po = xqc_packet_out_create(conn->pkt_out_size);
    if (po == NULL) {
        return;
    }
    po->po_pkt.pkt_type = types[level];
    po->po_pkt.pkt_pns = spaces[level];
    po->po_path_id = path->path_id;

    if (xqc_write_packet_header(conn, po) != XQC_OK) {
        goto end;
    }

    room = xqc_get_po_remained_size(po);
    if (len > room) {
        len = room;
    }
    if (len > 0) {
        memcpy(po->po_buf + po->po_used_size, payload, len);
        po->po_used_size += len;
    }

    if (xqc_conn_enc_packet(conn, path, po, (char *)enc, sizeof(enc), &enc_len,
                            xqc_fuzz_now)
        != XQC_OK)
    {
        goto end;
    }

    if (src == &xqc_fuzz_cli) {
        xqc_fuzz_client_addr(&from, path->path_id);
        xqc_fuzz_server_addr(&to);

    } else {
        xqc_fuzz_server_addr(&from);
        memcpy(&to, path->peer_addr, sizeof(to));
    }
    /* a heap copy of the exact size, so that ASan sees overreads */
    copy = malloc(enc_len);
    if (copy != NULL) {
        memcpy(copy, enc, enc_len);
        xqc_fuzz_receive(dst, copy, enc_len, &from, &to);
        free(copy);
    }

end:
    xqc_packet_out_destroy(po);
}

/*
 * a datagram as is: to the server from a client path or a new address, or
 * to the client from the server; a Retry gets a valid integrity tag
 */
static void
xqc_fuzz_send_raw(uint8_t sel, const uint8_t *data, size_t len)
{
    unsigned char *buf;
    xqc_connection_t *conn;
    struct sockaddr_in from, to;
    unsigned char tag[XQC_RETRY_INTEGRITY_TAG_LEN];
    size_t tag_len = 0;

    buf = malloc(len ? len : 1);
    if (buf == NULL) {
        return;
    }
    memcpy(buf, data, len);

    if (sel & 0x08) {
        /* server to client */
        conn = xqc_fuzz_find_conn(&xqc_fuzz_cli);
        if ((sel & 0x10) && conn != NULL && len > XQC_RETRY_INTEGRITY_TAG_LEN
            && len <= XQC_FUZZ_RETRY_MAX_LEN && (buf[0] & 0xf0) == 0xf0
            && xqc_conn_gen_retry_integrity_tag(
                   conn, conn->original_dcid.cid_buf,
                   conn->original_dcid.cid_len, buf,
                   len - XQC_RETRY_INTEGRITY_TAG_LEN, tag, &tag_len)
                   == XQC_OK
            && tag_len == XQC_RETRY_INTEGRITY_TAG_LEN)
        {
            memcpy(buf + len - XQC_RETRY_INTEGRITY_TAG_LEN, tag, tag_len);
        }
        xqc_fuzz_server_addr(&from);
        xqc_fuzz_client_addr(&to, 0);
        xqc_fuzz_receive(&xqc_fuzz_cli, buf, len, &from, &to);

    } else {
        /* client to server, from a path's address or a new port */
        xqc_fuzz_client_addr(&from, (sel >> 4) & 0x03);
        if (sel & 0x40) {
            from.sin_port = htons(XQC_FUZZ_CLIENT_PORT - 1 - (sel >> 7));
        }
        xqc_fuzz_server_addr(&to);
        xqc_fuzz_receive(&xqc_fuzz_srv, buf, len, &from, &to);
    }

    free(buf);
}

static void
xqc_fuzz_app(uint8_t sel, const uint8_t *data, size_t len)
{
    xqc_http_header_t fields[5] = {
        {.name = {":method", 7}, .value = {"POST", 4}},
        {.name = {":scheme", 7}, .value = {"https", 5}},
        {.name = {":path", 5}, .value = {"/", 1}},
        {.name = {":authority", 10}, .value = {"test.xquic.com", 14}},
        {.name = {"priority", 8}, .value = {"u=1, i", 6}},
    };
    xqc_http_headers_t headers = {fields, 5, 5, 0};
    xqc_connection_t *conn;
    xqc_h3_request_t *h3r;
    xqc_stream_t *stream;
    uint64_t id;
    uint8_t fin = (sel >> 7) & 1;

    conn = xqc_fuzz_find_conn(&xqc_fuzz_cli);
    if (conn == NULL) {
        return;
    }

    switch ((sel >> 3) & 0x0f) {
    case 0:
    case 1:
    case 2:
    case 3:
        if (xqc_fuzz_cfg & XQC_FUZZ_CFG_H3) {
            h3r = xqc_h3_request_create(xqc_fuzz_cli.engine, &xqc_fuzz_cli.cid,
                                        NULL, NULL);
            if (h3r == NULL) {
                break;
            }
            /* the chunk starts with the priority field value */
            if (len > 0) {
                fields[4].value.iov_len = data[0] % 16 < len ? data[0] % 16
                                                             : len - 1;
                fields[4].value.iov_base = (void *)(data + 1);
                data += 1 + fields[4].value.iov_len;
                len -= 1 + fields[4].value.iov_len;
            }
            if (xqc_h3_request_send_headers(h3r, &headers, len == 0 && fin) >= 0
                && len > 0)
            {
                (void)xqc_h3_request_send_body(h3r, (unsigned char *)data, len,
                                               fin);
            }

        } else {
            stream = xqc_stream_create(xqc_fuzz_cli.engine, &xqc_fuzz_cli.cid,
                                       NULL, NULL);
            if (stream != NULL) {
                (void)xqc_stream_send(stream, (unsigned char *)data, len, fin);
            }
        }
        break;

    case 4:
    case 5:
        (void)xqc_datagram_send(conn, (void *)data, len, &id,
                                XQC_DATA_QOS_HIGH);
        break;

    case 6:
        (void)xqc_conn_create_path(xqc_fuzz_cli.engine, &xqc_fuzz_cli.cid, &id,
                                   0);
        break;

    case 7:
        (void)xqc_conn_close_path(xqc_fuzz_cli.engine, &xqc_fuzz_cli.cid,
                                  1 + (sel & 0x03));
        break;

    case 8:
        (void)xqc_conn_mark_path_standby(xqc_fuzz_cli.engine, &xqc_fuzz_cli.cid,
                                         sel & 0x03);
        break;

    case 9:
        (void)xqc_conn_mark_path_available(xqc_fuzz_cli.engine,
                                           &xqc_fuzz_cli.cid, sel & 0x03);
        break;

    case 10:
    case 11:
        (void)xqc_conn_send_ping(xqc_fuzz_cli.engine, &xqc_fuzz_cli.cid, NULL);
        break;

    case 12:
        /* a NAT rebinding: the client's datagrams come from a new port */
        xqc_fuzz_cli_port++;
        break;

    case 13:
        (void)xqc_conn_continue_send(xqc_fuzz_cli.engine, &xqc_fuzz_cli.cid);
        break;

    default:
        (void)xqc_conn_close(xqc_fuzz_cli.engine, &xqc_fuzz_cli.cid);
        break;
    }

    xqc_engine_main_logic(xqc_fuzz_cli.engine);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    xqc_fuzz_input_t in = {data, size};
    const uint8_t *chunk;
    size_t len;
    uint8_t sel;
    int ops;

    memset(&xqc_fuzz_cli, 0, sizeof(xqc_fuzz_cli));
    memset(&xqc_fuzz_srv, 0, sizeof(xqc_fuzz_srv));
    xqc_fuzz_now = XQC_FUZZ_START_TIME;
    xqc_fuzz_cli_port = 0;
    xqc_fuzz_cfg = xqc_fuzz_u8(&in);

    xqc_fuzz_srv.engine = xqc_fuzz_create_engine(XQC_ENGINE_SERVER);
    xqc_fuzz_cli.engine = xqc_fuzz_create_engine(XQC_ENGINE_CLIENT);
    if (!xqc_fuzz_connect()) {
        goto end;
    }

    if (xqc_fuzz_cfg & XQC_FUZZ_CFG_HANDSHAKE) {
        xqc_fuzz_handshake();
    }

    for (ops = 0; ops < XQC_FUZZ_MAX_OPS && in.size > 0; ops++) {
        sel = xqc_fuzz_u8(&in);

        switch (sel & 0x07) {
        case 0:
        case 1:
        case 2:
            len = xqc_fuzz_chunk(&in, &chunk);
            xqc_fuzz_send_frames(sel, chunk, len);
            break;

        case 3:
            len = xqc_fuzz_chunk(&in, &chunk);
            xqc_fuzz_send_raw(sel, chunk, len);
            break;

        case 4:
            xqc_fuzz_deliver(1 + (sel >> 3) % XQC_FUZZ_DELIVER_ROUNDS);
            break;

        case 5:
            /* up to about 65 seconds, enough for the idle timeouts */
            xqc_fuzz_now += (xqc_usec_t)xqc_fuzz_u16(&in) * 1000 + (sel >> 3);
            xqc_engine_main_logic(xqc_fuzz_cli.engine);
            xqc_engine_main_logic(xqc_fuzz_srv.engine);
            break;

        default:
            len = xqc_fuzz_chunk(&in, &chunk);
            xqc_fuzz_app(sel, chunk, len);
            break;
        }
    }

    /* let the endpoints finish the exchange that the operations started */
    xqc_fuzz_deliver(XQC_FUZZ_DELIVER_ROUNDS);

end:
    xqc_engine_destroy(xqc_fuzz_cli.engine);
    xqc_engine_destroy(xqc_fuzz_srv.engine);
    xqc_fuzz_queue_free(&xqc_fuzz_cli);
    xqc_fuzz_queue_free(&xqc_fuzz_srv);
    return 0;
}
