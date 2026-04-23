/**
 * xqc_wt_py_api.c - Flat C wrapper for Python CFFI bindings
 *
 * Encapsulates all xquic complex structs (xqc_conn_settings_t,
 * xqc_engine_ssl_config_t, etc.) internally. Python only sees
 * opaque handles and basic types.
 */

#include "xqc_wt_py_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>
#include <xquic/xqc_webtransport.h>
#include "src/common/xqc_time.h"
#include "xqc_webtransport_session.h"
#include "xqc_webtransport_conn.h"
#include "xqc_webtransport_stream.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/http3/xqc_h3_ext_bytestream.h"
#include "src/transport/xqc_stream.h"
#include "xqc_webtransport_wire.h"


/* ===== Common types ===== */

/* Dynamic mappings via xqc_id_hash (no fixed-size array limits) */
#include "src/common/xqc_id_hash.h"
#include "src/common/xqc_malloc.h"

typedef void (*xqc_wt_py_log_cb)(int level, const char *msg, size_t len, void *user);

/* ===== Configurable defaults ===== */

/* Network defaults */
#define XQC_WT_PY_DEFAULT_PORT           4443
#define XQC_WT_PY_IDLE_TIMEOUT_MS        1800000  /* 30 minutes */
#define XQC_WT_PY_MAX_DGRAM_FRAME_SIZE   16383   /* RFC 9221 max */
#define XQC_WT_PY_UDP_RECV_BUF_SIZE      1500

/* HTTP status / reject */
#define XQC_WT_PY_REJECT_ERROR_CODE      404
#define XQC_WT_PY_REJECT_REASON          "Not Found"
#define XQC_WT_PY_REJECT_REASON_LEN      9

typedef struct {
    uint64_t                stream_id;
    xqc_h3_stream_t        *h3_stream;
    xqc_wt_bidistream_t    *bidi_stream;   /* for xqc_wt_bidistream_send */
} py_stream_entry_t;

typedef struct {
    uint64_t                 stream_id;
    xqc_wt_unistream_t     *unistream;
} py_uni_stream_entry_t;

typedef struct {
    uint64_t                 session_id;
    xqc_wt_session_t        *wt_session;
} py_session_entry_t;

typedef struct {
    uint64_t                 session_id;
    xqc_wt_session_t        *wt_session;
    char                     path[256];
} py_server_session_entry_t;


/* ===== Internal: Client struct ===== */

struct xqc_wt_py_client_s {
    xqc_engine_t           *engine;
    xqc_cid_t               cid;
    char                     host[256];
    int                      port;
    struct sockaddr_storage  peer_addr;
    socklen_t                peer_addrlen;
    struct sockaddr_storage  local_addr;
    socklen_t                local_addrlen;
    int                      connected;

    uint64_t                 idle_timeout_ms;
    int                      log_level;
    int                      cc_type;
    xqc_wt_py_log_cb         log_cb;

    xqc_id_hash_table_t     *sessions;      /* session_id → py_session_entry_t* */
    uint64_t                 next_session_id;

    xqc_id_hash_table_t     *streams;       /* stream_id → py_stream_entry_t* */
    xqc_id_hash_table_t     *uni_streams;   /* stream_id → py_uni_stream_entry_t* */

    /* Python callbacks */
    xqc_wt_py_send_cb       send_cb;
    xqc_wt_py_timer_cb       timer_cb;
    xqc_wt_py_session_cb     session_cb;
    xqc_wt_py_stream_cb      stream_cb;
    xqc_wt_py_stream_data_cb data_cb;
    xqc_wt_py_dgram_cb       dgram_cb;
    void                    *user_data;

    /* set by Python send_cb when sendto returns EAGAIN */
    volatile int             send_eagain;
};



/* ===== Internal: Server struct ===== */

struct xqc_wt_py_server_s {
    xqc_engine_t           *engine;
    char                     cert_file[512];
    char                     key_file[512];
    int                      current_fd;

    uint64_t                 idle_timeout_ms;
    int                      log_level;
    int                      cc_type;
    xqc_wt_py_log_cb         log_cb;

    xqc_id_hash_table_t     *streams;       /* stream_id → py_stream_entry_t* */
    xqc_id_hash_table_t     *sessions;     /* session_id → py_server_session_entry_t* */

    /* Python callbacks */
    xqc_wt_py_send_cb            send_cb;
    xqc_wt_py_timer_cb            timer_cb;
    xqc_wt_py_session_cb          session_cb;
    xqc_wt_py_stream_cb           stream_cb;
    xqc_wt_py_stream_data_cb      data_cb;
    xqc_wt_py_dgram_cb            dgram_cb;
    xqc_wt_py_session_request_cb  session_request_cb;
    void                         *user_data;

    volatile int             send_eagain;
};


/* ===== Callback routing helpers ===== */

/*
 * Engine-level callbacks (set_timer, log_write) receive eng_user_data
 * which is the py_client_t* or py_server_t* passed to xqc_engine_create().
 *
 * WT-layer callbacks (session/stream/datagram) receive h3c_user_data
 * which is wt_conn*.  We store a back-pointer wt_conn->py_handle to
 * reach the py_client_t* or py_server_t* without global state.
 *
 * Transport callbacks (write_socket) receive conn_user_data from
 * xqc_connect/xqc_webtransport_connect's last argument.  For client
 * this is py_client_t*; for server it is py_server_t* via server_accept.
 */

static inline xqc_wt_py_client_t *
py_client_from_wt_conn(void *h3c_user_data)
{
    xqc_wt_conn_t *wt_conn = (xqc_wt_conn_t *)h3c_user_data;
    return wt_conn ? (xqc_wt_py_client_t *)wt_conn->py_handle : NULL;
}

static inline xqc_wt_py_server_t *
py_server_from_wt_conn(void *h3c_user_data)
{
    xqc_wt_conn_t *wt_conn = (xqc_wt_conn_t *)h3c_user_data;
    return wt_conn ? (xqc_wt_py_server_t *)wt_conn->py_handle : NULL;
}


/* ===== Client: xquic transport callbacks ===== */

static void
py_client_set_timer(xqc_msec_t wake_after, void *eng_user_data)
{
    xqc_wt_py_client_t *c = (xqc_wt_py_client_t *)eng_user_data;
    if (c && c->timer_cb) {
        c->timer_cb((uint64_t)wake_after, c->user_data);
    }
}

static void
py_client_log_write(xqc_log_level_t lvl, const void *buf, size_t sz, void *eng_user_data)
{
    xqc_wt_py_client_t *c = (xqc_wt_py_client_t *)eng_user_data;
    if (c && c->log_cb) {
        c->log_cb((int)lvl, (const char *)buf, sz, c->user_data);
    }
}

static ssize_t
py_client_write_socket(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data)
{
    /* conn_user_data = wt_conn* (set by xqc_conn_set_transport_user_data in h3_conn_create) */
    xqc_wt_py_client_t *c = py_client_from_wt_conn(conn_user_data);
    if (c && c->send_cb) {
        c->send_eagain = 0;
        c->send_cb((const uint8_t *)buf, size, peer_addr, peer_addrlen, c->user_data);
        if (c->send_eagain) {
            return XQC_SOCKET_EAGAIN;
        }
        return (ssize_t)size;
    }
    return -1;
}

static ssize_t
py_client_write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data)
{
    return py_client_write_socket(buf, size, peer_addr, peer_addrlen, conn_user_data);
}

static void
py_client_save_token(const unsigned char *token, unsigned token_len, void *user_data)
{
    /* no-op for now */
}

static void
py_client_save_session(const char *data, size_t data_len, void *user_data)
{
    /* no-op for now */
}


/* ===== Client: session mapping helpers (hash-based) ===== */

static xqc_wt_session_t *
py_find_session_by_id(xqc_wt_py_client_t *c, uint64_t session_id)
{
    py_session_entry_t *e = xqc_id_hash_find(c->sessions, session_id);
    return e ? e->wt_session : NULL;
}

static uint64_t
py_find_session_id(xqc_wt_py_client_t *c, xqc_wt_session_t *wt_session)
{
    /* Reverse lookup — iterate hash table */
    for (int i = 0; i < c->sessions->count; i++) {
        xqc_id_hash_node_t *node = c->sessions->list[i];
        while (node) {
            py_session_entry_t *e = (py_session_entry_t *)node->element.value;
            if (e && e->wt_session == wt_session) return e->session_id;
            node = node->next;
        }
    }
    return 0;
}

static void
py_remove_session(xqc_wt_py_client_t *c, uint64_t session_id)
{
    py_session_entry_t *e = xqc_id_hash_find(c->sessions, session_id);
    if (e) {
        xqc_id_hash_delete(c->sessions, session_id);
        xqc_free(e);
    }
}

static void
py_add_session(xqc_wt_py_client_t *c, uint64_t session_id, xqc_wt_session_t *ws)
{
    py_session_entry_t *e = xqc_malloc(sizeof(py_session_entry_t));
    if (!e) {
        fprintf(stderr, "py_add_session: malloc failed\n");
        return;
    }
    e->session_id = session_id;
    e->wt_session = ws;
    xqc_id_hash_element_t el = { session_id, e };
    xqc_id_hash_add(c->sessions, el);
}


/* ===== Client: WT session callbacks ===== */

static int
py_client_session_create(xqc_webtransport_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *h3c_user_data)
{
    xqc_wt_py_client_t *c = py_client_from_wt_conn(h3c_user_data);
    if (!c || !headers) return 0;

    /* check for :status 200 */
    for (size_t i = 0; i < headers->count; i++) {
        size_t nlen = headers->headers[i].name.iov_len;
        size_t vlen = headers->headers[i].value.iov_len;
        char *n = (char *)headers->headers[i].name.iov_base;
        char *v = (char *)headers->headers[i].value.iov_base;
        if (n && v && nlen == 7 && memcmp(n, ":status", 7) == 0 &&
            vlen == 3 && memcmp(v, "200", 3) == 0) {
            /* assign unique session_id and store mapping */
            uint64_t sid = ++c->next_session_id;
            py_add_session(c, sid, session);
            if (c->session_cb) {
                c->session_cb(XQC_WT_PY_EVENT_CREATED, sid, c->user_data);
            }
            return 0;
        }
    }
    return 0;
}

static int
py_client_session_close(xqc_webtransport_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *h3c_user_data)
{
    xqc_wt_py_client_t *c = py_client_from_wt_conn(h3c_user_data);
    if (c && c->session_cb) {
        uint64_t sid = py_find_session_id(c, session);
        c->session_cb(XQC_WT_PY_EVENT_CLOSED, sid, c->user_data);
        py_remove_session(c, sid);
    }
    return 0;
}

static void
py_client_handshake_done(xqc_webtransport_session_t *session)
{
    /* C layer guarantees session is non-NULL (may be a temp shell with wt_conn set). */
    xqc_wt_py_client_t *c = (session && session->wt_conn)
        ? (xqc_wt_py_client_t *)session->wt_conn->py_handle : NULL;
    if (c && c->session_cb) {
        c->session_cb(XQC_WT_PY_EVENT_HANDSHAKE_DONE, 0, c->user_data);
    }
}


/* ===== Client: WT datagram callback ===== */

static void
py_client_dgram_read(xqc_webtransport_session_t *session,
    const void *data, size_t data_len, void *user_data, uint64_t data_recv_time)
{
    xqc_wt_py_client_t *c = session ? (xqc_wt_py_client_t *)
        (session->wt_conn ? session->wt_conn->py_handle : NULL) : NULL;
    if (c && c->dgram_cb && data_len > 0) {
        uint64_t sid = py_find_session_id(c, session);
        c->dgram_cb(sid, (const uint8_t *)data, data_len, c->user_data);
    }
}


/* ===== Client: WT stream callbacks ===== */

static xqc_int_t
py_client_uni_read(xqc_wt_unistream_t *stream, xqc_wt_session_t *session,
    void *data, size_t data_len, void *strm_user_data)
{
    xqc_wt_py_client_t *c = session ? (xqc_wt_py_client_t *)
        (session->wt_conn ? session->wt_conn->py_handle : NULL) : NULL;
    if (!c || !c->data_cb) return 0;

    uint64_t sess_id = py_find_session_id(c, session);
    uint64_t stream_id = 0;
    if (stream && stream->type == XQC_WT_STREAM_TYPE_RECV
        && stream->stream.recv_stream
        && stream->stream.recv_stream->stream) {
        stream_id = stream->stream.recv_stream->stream->stream_id;
    }
    int fin = (stream && stream->fin.recv_fin) ? 1 : 0;

    if (c->stream_cb) {
        c->stream_cb(0, sess_id, stream_id, 0, c->user_data);
    }
    if (data_len > 0 || fin) {
        c->data_cb(sess_id, stream_id,
            (const uint8_t *)data, data_len, fin, c->user_data);
    }
    return 0;
}

static xqc_int_t
py_client_bidi_read_ex(xqc_wt_bidistream_t *stream, xqc_wt_session_t *session,
    void *data, size_t data_len, void *strm_user_data)
{
    xqc_wt_py_client_t *c = session ? (xqc_wt_py_client_t *)
        (session->wt_conn ? session->wt_conn->py_handle : NULL) : NULL;
    if (!c || !c->data_cb) return 0;

    /* NOTE: strm_user_data is &processed (int*), NOT h3_stream pointer.
     * Get h3_stream from the bidistream object instead. */
    uint64_t sess_id = py_find_session_id(c, session);
    uint64_t stream_id = 0;
    if (stream && stream->h3_stream) {
        stream_id = stream->h3_stream->stream_id;
    }
    int fin = (stream && stream->recv_fin) ? 1 : 0;

    if (data_len > 0 || fin) {
        c->data_cb(sess_id, stream_id,
            (const uint8_t *)data, data_len, fin, c->user_data);
    }
    return 0;
}


/* ===== Client API implementation ===== */

xqc_wt_py_client_t *
xqc_wt_py_client_create(const char *host, int port, int no_verify_cert)
{
    xqc_wt_py_client_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;

    strncpy(c->host, host ? host : "127.0.0.1", sizeof(c->host) - 1);
    c->port = port > 0 ? port : XQC_WT_PY_DEFAULT_PORT;

    /* peer address — try IPv6 first, fall back to IPv4 */
    memset(&c->peer_addr, 0, sizeof(c->peer_addr));
    struct sockaddr_in6 *peer6 = (struct sockaddr_in6 *)&c->peer_addr;
    struct sockaddr_in  *peer4 = (struct sockaddr_in *)&c->peer_addr;
    if (inet_pton(AF_INET6, c->host, &peer6->sin6_addr) == 1) {
        peer6->sin6_family = AF_INET6;
        peer6->sin6_port = htons((uint16_t)c->port);
        c->peer_addrlen = sizeof(struct sockaddr_in6);
    } else {
        peer4->sin_family = AF_INET;
        peer4->sin_port = htons((uint16_t)c->port);
        inet_pton(AF_INET, c->host, &peer4->sin_addr);
        c->peer_addrlen = sizeof(struct sockaddr_in);
    }

    /* local address (any, matching peer family) */
    memset(&c->local_addr, 0, sizeof(c->local_addr));
    if (c->peer_addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *local6 = (struct sockaddr_in6 *)&c->local_addr;
        local6->sin6_family = AF_INET6;
        local6->sin6_addr = in6addr_any;
        c->local_addrlen = sizeof(struct sockaddr_in6);
    } else {
        struct sockaddr_in *local4 = (struct sockaddr_in *)&c->local_addr;
        local4->sin_family = AF_INET;
        local4->sin_addr.s_addr = htonl(INADDR_ANY);
        c->local_addrlen = sizeof(struct sockaddr_in);
    }

    c->idle_timeout_ms = XQC_WT_PY_IDLE_TIMEOUT_MS;
    c->log_level = XQC_LOG_WARN;
    c->cc_type = 0;  /* bbr */

    /* init hash tables */
    c->sessions = xqc_malloc(sizeof(xqc_id_hash_table_t));
    c->streams = xqc_malloc(sizeof(xqc_id_hash_table_t));
    c->uni_streams = xqc_malloc(sizeof(xqc_id_hash_table_t));
    if (!c->sessions || !c->streams || !c->uni_streams) {
        xqc_free(c->sessions); xqc_free(c->streams); xqc_free(c->uni_streams);
        free(c);
        return NULL;
    }
    xqc_id_hash_init(c->sessions, xqc_default_allocator, 16);
    xqc_id_hash_init(c->streams, xqc_default_allocator, 64);
    xqc_id_hash_init(c->uni_streams, xqc_default_allocator, 16);

    return c;
}

void
xqc_wt_py_client_set_config(xqc_wt_py_client_t *client,
    uint64_t idle_timeout_ms, int log_level, int cc_type)
{
    if (!client) return;
    if (idle_timeout_ms > 0) client->idle_timeout_ms = idle_timeout_ms;
    if (log_level >= 0)      client->log_level = log_level;
    if (cc_type >= 0)        client->cc_type = cc_type;
}

void
xqc_wt_py_client_set_log_cb(xqc_wt_py_client_t *client, xqc_wt_py_log_cb cb)
{
    if (client) client->log_cb = cb;
}

void
xqc_wt_py_client_set_callbacks(xqc_wt_py_client_t *client,
    xqc_wt_py_send_cb send_cb, xqc_wt_py_timer_cb timer_cb,
    xqc_wt_py_session_cb session_cb, xqc_wt_py_stream_cb stream_cb,
    xqc_wt_py_stream_data_cb data_cb, xqc_wt_py_dgram_cb dgram_cb,
    void *user_data)
{
    if (!client) return;
    client->send_cb = send_cb;
    client->timer_cb = timer_cb;
    client->session_cb = session_cb;
    client->stream_cb = stream_cb;
    client->data_cb = data_cb;
    client->dgram_cb = dgram_cb;
    client->user_data = user_data;
}

int
xqc_wt_py_client_connect(xqc_wt_py_client_t *client)
{
    if (!client) return -1;

    /* py_handle is set automatically via wt_conn->py_handle = engine->user_data */

    /* engine callbacks */
    xqc_engine_callback_t ecbs = {
        .set_event_timer = py_client_set_timer,
        .log_callbacks = {
            .xqc_log_write_err = py_client_log_write,
            .xqc_log_write_stat = py_client_log_write,
        },
    };

    xqc_transport_callbacks_t tcbs = {
        .write_socket = py_client_write_socket,
        .write_socket_ex = py_client_write_socket_ex,
        .save_token = py_client_save_token,
        .save_session_cb = py_client_save_session,
    };

    /* engine config with defaults */
    xqc_config_t cfg;
    if (xqc_engine_get_default_config(&cfg, XQC_ENGINE_CLIENT) < 0) {
        return -1;
    }
    cfg.cfg_log_level = client->log_level;
    cfg.enable_h3_ext = 1;

    /* SSL config */
    xqc_engine_ssl_config_t ssl = {0};
    ssl.ciphers = XQC_TLS_CIPHERS;
    ssl.groups = XQC_TLS_GROUPS;

    /* create engine */
    client->engine = xqc_engine_create(XQC_ENGINE_CLIENT, &cfg, &ssl,
        &ecbs, &tcbs, client);
    if (!client->engine) {
        return -1;
    }

    /* register WT callbacks (xqc_wt_ctx_init now does value-copy) */
    xqc_webtransport_dgram_callbacks_t dcbs = {
        .dgram_read_notify = py_client_dgram_read,
    };
    xqc_webtransport_session_callbacks_t scbs = {
        .webtransport_session_create_notify = py_client_session_create,
        .webtransport_session_close_notify = py_client_session_close,
        .webtransport_session_handshake_finished_notify = py_client_handshake_done,
    };
    xqc_webtransport_stream_callbacks_t stcbs = {
        .wt_bidistream_read_notify = py_client_bidi_read_ex,
        .wt_unistream_read_notify = py_client_uni_read,
    };
    if (xqc_wt_ctx_init(client->engine, &dcbs, &scbs, &stcbs, 0) != XQC_OK) {
        xqc_engine_destroy(client->engine);
        client->engine = NULL;
        return -1;
    }

    /* wt_ctx_init OK */

    /* QUIC connection settings with defaults */
    xqc_conn_settings_t cs = {0};
    cs.proto_version = XQC_VERSION_V1;
    cs.cong_ctrl_callback = client->cc_type == 1 ? xqc_cubic_cb : xqc_bbr_cb;
    cs.init_idle_time_out = client->idle_timeout_ms;
    cs.max_datagram_frame_size = XQC_WT_PY_MAX_DGRAM_FRAME_SIZE;

    xqc_conn_ssl_config_t cssl = {0};

    /* initiate QUIC connection */
    const xqc_cid_t *cid = xqc_webtransport_connect(client->engine, &cs,
        NULL, 0, client->host, 0, &cssl,
        (struct sockaddr *)&client->peer_addr, client->peer_addrlen, client);
    if (!cid) {
        xqc_engine_destroy(client->engine);
        client->engine = NULL;
        return -1;
    }
    memcpy(&client->cid, cid, sizeof(xqc_cid_t));
    client->connected = 1;

    /* drive engine to send initial handshake packets */
    xqc_engine_main_logic(client->engine);

    return 0;
}

int
xqc_wt_py_client_feed_packet(xqc_wt_py_client_t *client,
    const uint8_t *data, size_t len,
    const struct sockaddr *local_addr, socklen_t local_addrlen,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    uint64_t recv_time_us)
{
    if (!client || !client->engine) return -1;
    /* py_handle is set automatically via wt_conn->py_handle = engine->user_data */

    /* Client always uses the stored peer_addr for correct sockaddr alignment */
    xqc_int_t ret = xqc_engine_packet_process(client->engine,
        (const unsigned char *)data, len,
        (const struct sockaddr *)&client->local_addr, client->local_addrlen,
        (const struct sockaddr *)&client->peer_addr, client->peer_addrlen,
        (xqc_usec_t)recv_time_us, client);
    if (ret != 0) {
        printf("[C-feed] packet_process returned %d, len=%zu\n", ret, len);
    }
    return ret;
}

void
xqc_wt_py_client_finish_recv(xqc_wt_py_client_t *client)
{
    if (!client || !client->engine) return;
    /* py_handle is set automatically via wt_conn->py_handle = engine->user_data */
    xqc_engine_finish_recv(client->engine);
}

void
xqc_wt_py_client_process(xqc_wt_py_client_t *client)
{
    if (!client || !client->engine) return;
    /* py_handle is set automatically via wt_conn->py_handle = engine->user_data */
    xqc_engine_main_logic(client->engine);
}

int
xqc_wt_py_open_session(xqc_wt_py_client_t *client,
    const char *path, const char *authority)
{
    if (!client || !client->engine) return -1;
    /* py_handle is set automatically via wt_conn->py_handle = engine->user_data */

    const char *auth = authority ? authority : client->host;
    return xqc_wt_client_open_session(client->engine, &client->cid,
        path, auth, client);
}

ssize_t
xqc_wt_py_send_bidi(xqc_wt_py_client_t *client, uint64_t session_id,
    const uint8_t *data, size_t len, int fin)
{
    if (!client) return -1;
    xqc_wt_session_t *ws = py_find_session_by_id(client, session_id);
    if (!ws) return -1;
    /* py_handle is set automatically via wt_conn->py_handle = engine->user_data */

    ssize_t ret = xqc_wt_session_send_bidi(ws,
        (const void *)data, len, fin);

    /* drive engine to flush outgoing data */
    xqc_engine_main_logic(client->engine);

    return ret;
}

int
xqc_wt_py_send_bidi_batch(xqc_wt_py_client_t *client, uint64_t session_id,
    const uint8_t *data, const size_t *offsets, const size_t *lengths,
    int count)
{
    if (!client || !client->engine || count <= 0) return -1;
    xqc_wt_session_t *ws = py_find_session_by_id(client, session_id);
    if (!ws) return -1;

    int sent = 0;
    for (int i = 0; i < count; i++) {
        ssize_t ret = xqc_wt_session_send_bidi(ws,
            (const void *)(data + offsets[i]), lengths[i], 1);
        if (ret >= 0) sent++;
    }
    /* single engine flush for all streams */
    xqc_engine_main_logic(client->engine);
    return sent;
}

/* helper: record a stream mapping (hash-based) */
static int
py_record_stream_h(xqc_id_hash_table_t *ht,
    uint64_t stream_id, xqc_h3_stream_t *h3s, xqc_wt_bidistream_t *bidi)
{
    py_stream_entry_t *e = xqc_id_hash_find(ht, stream_id);
    if (e) {
        if (bidi) e->bidi_stream = bidi;
        return 0;
    }
    e = xqc_malloc(sizeof(py_stream_entry_t));
    if (!e) return -1;
    e->stream_id = stream_id;
    e->h3_stream = h3s;
    e->bidi_stream = bidi;
    xqc_id_hash_element_t el = { stream_id, e };
    return xqc_id_hash_add(ht, el);
}

/* helper: find stream entry by stream_id */
static py_stream_entry_t *
py_find_stream_entry(xqc_id_hash_table_t *ht, uint64_t stream_id)
{
    return (py_stream_entry_t *)xqc_id_hash_find(ht, stream_id);
}

/* helper: find h3_stream by stream_id */
static xqc_h3_stream_t *
py_find_stream_h(xqc_id_hash_table_t *ht, uint64_t stream_id)
{
    py_stream_entry_t *e = py_find_stream_entry(ht, stream_id);
    return e ? e->h3_stream : NULL;
}

/* helper: remove a stream mapping */
static void
py_remove_stream_h(xqc_id_hash_table_t *ht, uint64_t stream_id)
{
    py_stream_entry_t *e = xqc_id_hash_find(ht, stream_id);
    if (e) {
        xqc_id_hash_delete(ht, stream_id);
        xqc_free(e);
    }
}

int
xqc_wt_py_create_bidi_stream(xqc_wt_py_client_t *client, uint64_t session_id)
{
    if (!client || !client->engine) return -1;
    xqc_wt_session_t *ws = py_find_session_by_id(client, session_id);
    if (!ws) return -1;
    /* py_handle is set automatically via wt_conn->py_handle = engine->user_data */

    xqc_h3_conn_t *h3c = ws->wt_conn->h3_conn;
    if (!h3c) return -1;

    xqc_connection_t *conn = xqc_h3_conn_get_xqc_conn(h3c);
    xqc_stream_t *stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    if (!stream) return -1;

    /* create H3 stream + mark as WT type */
    xqc_h3_stream_t *h3s = (xqc_h3_stream_t *)stream->user_data;
    if (!h3s) {
        h3s = xqc_h3_stream_create(h3c, stream,
                                    XQC_H3_STREAM_TYPE_WT_BIDI, NULL);
        if (h3s) stream->user_data = h3s;
    } else {
        h3s->type = XQC_H3_STREAM_TYPE_WT_BIDI;
    }
    if (h3s && !h3s->h3_ext_bs) {
        h3s->h3_ext_bs = xqc_h3_ext_bytestream_create_passive(h3c, h3s, NULL);
    }

    /* send WT bidi stream header: varint(type) + varint(session_id) */
    uint8_t wt_hdr[16];
    unsigned char *p = wt_hdr;
    p = xqc_put_varint(p, XQC_WT_STREAM_TYPE_BIDIRECTIONAL);
    p = xqc_put_varint(p, ws->session_id);
    size_t hdr_len = p - wt_hdr;

    ssize_t sent = xqc_stream_send(stream, wt_hdr, hdr_len, 0);
    if (sent < 0) return (int)sent;

    uint64_t sid = h3s->stream_id;

    /* record for later stream_send */
    py_record_stream_h(client->streams, sid, h3s, NULL);

    /* notify Python via stream_cb */
    if (client->stream_cb) {
        client->stream_cb(0, session_id, sid, 1, client->user_data);
    }

    xqc_engine_main_logic(client->engine);
    return 0;
}

ssize_t
xqc_wt_py_stream_send(xqc_wt_py_client_t *client, uint64_t stream_id,
    const uint8_t *data, size_t len, int fin)
{
    if (!client || !client->engine) return -1;
    /* py_handle is set automatically via wt_conn->py_handle = engine->user_data */

    /* check bidi streams first */
    xqc_h3_stream_t *h3s = py_find_stream_h(client->streams, stream_id);
    if (h3s && h3s->stream) {
        ssize_t sent = xqc_stream_send(h3s->stream, (unsigned char *)data, len, fin);
        if (sent >= 0) {
            xqc_engine_main_logic(client->engine);
            if (fin) {
                py_remove_stream_h(client->streams, stream_id);
            }
        }
        return sent;
    }

    /* check uni streams */
    {
        py_uni_stream_entry_t *ue = xqc_id_hash_find(client->uni_streams, stream_id);
        if (ue) {
            xqc_int_t ret = xqc_wt_unistream_send(ue->unistream, (void *)data, (uint32_t)len, fin);
            if (ret >= 0) {
                xqc_engine_main_logic(client->engine);
                if (fin) {
                    xqc_wt_unistream_close(ue->unistream);
                    xqc_id_hash_delete(client->uni_streams, stream_id);
                    xqc_free(ue);
                }
            }
            return ret >= 0 ? (ssize_t)len : (ssize_t)ret;
        }
    }

    return -1;
}

int
xqc_wt_py_send_datagram(xqc_wt_py_client_t *client, uint64_t session_id,
    const uint8_t *data, size_t len)
{
    if (!client) return -1;
    xqc_wt_session_t *ws = py_find_session_by_id(client, session_id);
    if (!ws || !ws->wt_conn) return -1;
    /* py_handle is set automatically via wt_conn->py_handle = engine->user_data */

    int ret = xqc_webtransport_datagram_send(ws->wt_conn, (void *)data, (uint32_t)len);
    xqc_engine_main_logic(client->engine);
    return ret;
}

int
xqc_wt_py_create_uni_stream(xqc_wt_py_client_t *client, uint64_t session_id)
{
    if (!client || !client->engine) return -1;
    xqc_wt_session_t *ws = py_find_session_by_id(client, session_id);
    if (!ws) return -1;
    /* py_handle is set automatically via wt_conn->py_handle = engine->user_data */

    xqc_h3_stream_t *h3s = xqc_wt_session_get_h3_stream(ws);
    if (!h3s) return -1;

    xqc_wt_unistream_t *unis = xqc_wt_create_unistream(
        XQC_WT_STREAM_TYPE_SEND, ws, NULL, h3s);
    if (!unis) return -1;

    uint64_t sid = unis->stream.send_stream->stream->stream_id;

    {
        py_uni_stream_entry_t *ue = xqc_malloc(sizeof(py_uni_stream_entry_t));
        if (ue) {
            ue->stream_id = sid;
            ue->unistream = unis;
            xqc_id_hash_element_t el = { sid, ue };
            xqc_id_hash_add(client->uni_streams, el);
        }
    }

    if (client->stream_cb) {
        client->stream_cb(0, session_id, sid, 0, client->user_data);
    }

    xqc_engine_main_logic(client->engine);
    return 0;
}

ssize_t
xqc_wt_py_send_uni(xqc_wt_py_client_t *client, uint64_t session_id,
    const uint8_t *data, size_t len)
{
    if (!client || !client->engine) return -1;
    xqc_wt_session_t *ws = py_find_session_by_id(client, session_id);
    if (!ws) return -1;
    /* py_handle is set automatically via wt_conn->py_handle = engine->user_data */

    xqc_h3_stream_t *h3s = xqc_wt_session_get_h3_stream(ws);
    if (!h3s) return -1;

    xqc_wt_unistream_t *unis = xqc_wt_create_unistream(
        XQC_WT_STREAM_TYPE_SEND, ws, NULL, h3s);
    if (!unis) return -1;

    xqc_int_t ret = xqc_wt_unistream_send(unis, (void *)data, (uint32_t)len, 1);
    xqc_wt_unistream_close(unis);

    xqc_engine_main_logic(client->engine);
    return ret >= 0 ? (ssize_t)len : (ssize_t)ret;
}

void
xqc_wt_py_client_set_send_eagain(xqc_wt_py_client_t *client)
{
    if (client) client->send_eagain = 1;
}

void
xqc_wt_py_server_set_send_eagain(xqc_wt_py_server_t *server)
{
    if (server) server->send_eagain = 1;
}

int
xqc_wt_py_close_session(xqc_wt_py_client_t *client, uint64_t session_id)
{
    if (!client || !client->engine) return -1;
    xqc_wt_session_t *ws = py_find_session_by_id(client, session_id);
    if (!ws) return -1;
    /* py_handle is set automatically via wt_conn->py_handle = engine->user_data */

    /* remove from our mapping — the underlying WT session resources
     * will be freed when the QUIC connection closes */
    py_remove_session(client, session_id);

    /* notify Python */
    if (client->session_cb) {
        client->session_cb(XQC_WT_PY_EVENT_CLOSED, session_id, client->user_data);
    }

    xqc_engine_main_logic(client->engine);
    return 0;
}

int
xqc_wt_py_close_session_with_error(xqc_wt_py_client_t *client,
    uint64_t session_id, uint32_t error_code,
    const char *reason, size_t reason_len)
{
    if (!client || !client->engine) return -1;
    xqc_wt_session_t *ws = py_find_session_by_id(client, session_id);
    if (!ws) return -1;
    int ret = xqc_wt_session_close_with_error(ws, error_code, reason, reason_len);
    if (ret == XQC_OK) {
        xqc_engine_main_logic(client->engine);
    }
    return ret;
}

int
xqc_wt_py_stream_reset(xqc_wt_py_client_t *client,
    uint64_t stream_id, uint64_t error_code)
{
    if (!client || !client->engine) return -1;
    py_stream_entry_t *e = py_find_stream_entry(client->streams, stream_id);
    if (e && e->bidi_stream) {
        int ret = xqc_wt_bidistream_reset(e->bidi_stream, error_code);
        if (ret >= 0) xqc_engine_main_logic(client->engine);
        return ret;
    }
    return -1;
}

int
xqc_wt_py_stream_stop_sending(xqc_wt_py_client_t *client,
    uint64_t stream_id, uint64_t error_code)
{
    if (!client || !client->engine) return -1;
    py_stream_entry_t *e = py_find_stream_entry(client->streams, stream_id);
    if (e && e->bidi_stream) {
        int ret = xqc_wt_bidistream_stop_sending(e->bidi_stream, error_code);
        if (ret >= 0) xqc_engine_main_logic(client->engine);
        return ret;
    }
    return -1;
}

void
xqc_wt_py_client_close(xqc_wt_py_client_t *client)
{
    if (!client || !client->engine) return;
    /* py_handle is set automatically via wt_conn->py_handle = engine->user_data */
    xqc_h3_conn_close(client->engine, &client->cid);
    xqc_engine_main_logic(client->engine);
}

/* free all value pointers in a hash table, then release the table itself */
static void
py_hash_free_all(xqc_id_hash_table_t *ht)
{
    if (!ht) return;
    for (size_t i = 0; i < ht->count; i++) {
        xqc_id_hash_node_t *node = ht->list[i];
        while (node) {
            xqc_free(node->element.value);
            node->element.value = NULL;
            if (node->next == node) break;
            node = node->next;
        }
    }
    xqc_id_hash_release(ht);
    xqc_free(ht);
}

void
xqc_wt_py_client_destroy(xqc_wt_py_client_t *client)
{
    if (!client) return;
    if (client->engine) {
        xqc_engine_destroy(client->engine);
        client->engine = NULL;
    }
    py_hash_free_all(client->sessions);
    py_hash_free_all(client->streams);
    py_hash_free_all(client->uni_streams);
    free(client);
}


/* ===== Diagnostics API ===== */

uint64_t
xqc_wt_py_client_get_srtt(xqc_wt_py_client_t *client)
{
    if (!client || !client->engine) return 0;
    xqc_conn_stats_t stats = xqc_conn_get_stats(client->engine, &client->cid);
    return stats.srtt;
}

uint32_t
xqc_wt_py_client_get_send_count(xqc_wt_py_client_t *client)
{
    if (!client || !client->engine) return 0;
    xqc_conn_stats_t stats = xqc_conn_get_stats(client->engine, &client->cid);
    return stats.send_count;
}

uint32_t
xqc_wt_py_client_get_recv_count(xqc_wt_py_client_t *client)
{
    if (!client || !client->engine) return 0;
    xqc_conn_stats_t stats = xqc_conn_get_stats(client->engine, &client->cid);
    return stats.recv_count;
}

int
xqc_wt_py_client_get_session_count(xqc_wt_py_client_t *client)
{
    if (!client || !client->sessions) return 0;
    /* count entries in hash table */
    int count = 0;
    for (int i = 0; i < client->sessions->count; i++) {
        xqc_id_hash_node_t *node = client->sessions->list[i];
        while (node) { count++; node = node->next; }
    }
    return count;
}

uint64_t
xqc_wt_py_client_get_remote_dgram_size(xqc_wt_py_client_t *client)
{
    if (!client || !client->sessions) return 0;
    /* find first session */
    for (int i = 0; i < client->sessions->count; i++) {
        xqc_id_hash_node_t *node = client->sessions->list[i];
        if (node && node->element.value) {
            py_session_entry_t *e = (py_session_entry_t *)node->element.value;
            if (e->wt_session && e->wt_session->wt_conn && e->wt_session->wt_conn->h3_conn) {
                xqc_connection_t *conn = xqc_h3_conn_get_xqc_conn(e->wt_session->wt_conn->h3_conn);
                if (conn) return conn->remote_settings.max_datagram_frame_size;
            }
        }
    }
    return 0;
}


/* ================================================================
 * Server API implementation
 * ================================================================ */

static void
py_server_set_timer(xqc_msec_t wake_after, void *eng_user_data)
{
    xqc_wt_py_server_t *s = (xqc_wt_py_server_t *)eng_user_data;
    if (s && s->timer_cb) {
        s->timer_cb((uint64_t)wake_after, s->user_data);
    }
}

static void
py_server_log_write(xqc_log_level_t lvl, const void *buf, size_t sz, void *eng_user_data)
{
    xqc_wt_py_server_t *s = (xqc_wt_py_server_t *)eng_user_data;
    if (s && s->log_cb) {
        s->log_cb((int)lvl, (const char *)buf, sz, s->user_data);
    }
}

/* Fallback server handle for write_socket during TLS handshake.
 * Before wt_conn is established, conn_user_data is NULL, so we need
 * an alternative way to reach the server's send_cb. Set by server_create. */
static xqc_wt_py_server_t *s_active_server = NULL;

static ssize_t
py_server_write_socket(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data)
{
    xqc_wt_py_server_t *s = py_server_from_wt_conn(conn_user_data);
    if (!s) s = s_active_server;  /* fallback during handshake */
    if (s && s->send_cb) {
        s->send_eagain = 0;
        s->send_cb((const uint8_t *)buf, size, peer_addr, peer_addrlen, s->user_data);
        if (s->send_eagain) {
            return XQC_SOCKET_EAGAIN;
        }
        return (ssize_t)size;
    }
    return -1;
}

static ssize_t
py_server_write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data)
{
    return py_server_write_socket(buf, size, peer_addr, peer_addrlen, conn_user_data);
}

static int
py_server_accept(xqc_engine_t *engine, xqc_connection_t *conn,
    const xqc_cid_t *cid, void *user_data)
{
    return 0; /* accept all connections */
}

/* Server-side WT stream callback: bidi data → Python data_cb */
static xqc_int_t
py_server_bidi_read_ex(xqc_wt_bidistream_t *bidi_stream, xqc_wt_session_t *session,
    void *data, size_t data_len, void *strm_user_data)
{
    xqc_wt_py_server_t *s = session ? (xqc_wt_py_server_t *)
        (session->wt_conn ? session->wt_conn->py_handle : NULL) : NULL;
    if (!s) return 0;

    /* NOTE: strm_user_data here is &processed (int*), NOT h3_stream pointer.
     * Get h3_stream from the bidistream object instead. */
    xqc_h3_stream_t *h3s = (bidi_stream) ? bidi_stream->h3_stream : NULL;
    uint64_t stream_id = (h3s) ? h3s->stream_id : 0;
    uint64_t session_id = session ? session->session_id : 0;
    int fin = (bidi_stream && bidi_stream->recv_fin) ? 1 : 0;

    /* record stream mapping for later stream_send */
    if (h3s) {
        py_record_stream_h(s->streams, stream_id, h3s, bidi_stream);
    }

    if (s->data_cb && (data_len > 0 || fin)) {
        s->data_cb(session_id, stream_id,
            (const uint8_t *)data, data_len, fin, s->user_data);
    }

    return 0;
}

/* helper: store session mapping in server */
static void
py_server_store_session(xqc_wt_py_server_t *s, uint64_t session_id,
    xqc_wt_session_t *wt_session, const char *path)
{
    py_server_session_entry_t *e = xqc_malloc(sizeof(py_server_session_entry_t));
    if (!e) {
        fprintf(stderr, "py_server_store_session: malloc failed\n");
        return;
    }
    e->session_id = session_id;
    e->wt_session = wt_session;
    if (path) {
        strncpy(e->path, path, sizeof(e->path) - 1);
        e->path[sizeof(e->path) - 1] = '\0';
    } else {
        e->path[0] = '/'; e->path[1] = '\0';
    }
    xqc_id_hash_element_t el = { session_id, e };
    xqc_id_hash_add(s->sessions, el);
}

/* helper: find wt_session by session_id */
static xqc_wt_session_t *
py_server_find_wt_session(xqc_wt_py_server_t *s, uint64_t session_id)
{
    py_server_session_entry_t *e = xqc_id_hash_find(s->sessions, session_id);
    return e ? e->wt_session : NULL;
}

/* helper: get session path */
static const char *
py_server_get_session_path(xqc_wt_py_server_t *s, uint64_t session_id)
{
    py_server_session_entry_t *e = xqc_id_hash_find(s->sessions, session_id);
    return e ? e->path : "";
}

/* helper: remove session entry */
static void
py_server_remove_session(xqc_wt_py_server_t *s, uint64_t session_id)
{
    py_server_session_entry_t *e = xqc_id_hash_find(s->sessions, session_id);
    if (e) {
        xqc_id_hash_delete(s->sessions, session_id);
        xqc_free(e);
    }
}

/* Server-side session create → accept/reject via session_request_cb, then notify */
static int
py_server_session_create(xqc_webtransport_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *h3c_user_data)
{
    xqc_wt_py_server_t *s = py_server_from_wt_conn(h3c_user_data);
    if (!s || !session) return 0;

    /* extract :path and :authority from headers */
    const char *path = NULL, *authority = NULL;
    if (headers) {
        for (size_t i = 0; i < headers->count; i++) {
            char *n = (char *)headers->headers[i].name.iov_base;
            size_t nlen = headers->headers[i].name.iov_len;
            if (nlen == 5 && memcmp(n, ":path", 5) == 0)
                path = (const char *)headers->headers[i].value.iov_base;
            else if (nlen == 10 && memcmp(n, ":authority", 10) == 0)
                authority = (const char *)headers->headers[i].value.iov_base;
        }
    }

    /* if session_request_cb is set, let Python decide accept/reject */
    if (s->session_request_cb) {
        int accepted = s->session_request_cb(
            path ? path : "/", authority ? authority : "",
            session->session_id, s->user_data);
        if (!accepted) {
            xqc_wt_session_close_with_error(session,
                XQC_WT_PY_REJECT_ERROR_CODE, XQC_WT_PY_REJECT_REASON,
                XQC_WT_PY_REJECT_REASON_LEN);
            return 0;
        }
    }

    /* store session mapping for close/drain/path queries */
    py_server_store_session(s, session->session_id, session, path);

    /* notify Python */
    if (s->session_cb) {
        s->session_cb(XQC_WT_PY_EVENT_CREATED, session->session_id, s->user_data);
    }
    return 0;
}

static int
py_server_session_close(xqc_webtransport_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *h3c_user_data)
{
    xqc_wt_py_server_t *s = py_server_from_wt_conn(h3c_user_data);
    if (s && session) {
        if (s->session_cb) {
            s->session_cb(XQC_WT_PY_EVENT_CLOSED, session->session_id, s->user_data);
        }
        py_server_remove_session(s, session->session_id);
    }
    return 0;
}


xqc_wt_py_server_t *
xqc_wt_py_server_create(const char *cert_file, const char *key_file)
{
    if (!cert_file || !key_file) return NULL;

    xqc_wt_py_server_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;

    strncpy(s->cert_file, cert_file, sizeof(s->cert_file) - 1);
    strncpy(s->key_file, key_file, sizeof(s->key_file) - 1);

    /* init hash tables */
    s->streams = xqc_malloc(sizeof(xqc_id_hash_table_t));
    s->sessions = xqc_malloc(sizeof(xqc_id_hash_table_t));
    if (!s->streams || !s->sessions) {
        xqc_free(s->streams); xqc_free(s->sessions);
        free(s);
        return NULL;
    }
    xqc_id_hash_init(s->streams, xqc_default_allocator, 64);
    xqc_id_hash_init(s->sessions, xqc_default_allocator, 16);

    /* py_handle is set automatically via wt_conn->py_handle = engine->user_data */

    /* engine callbacks */
    xqc_engine_callback_t ecbs = {
        .set_event_timer = py_server_set_timer,
        .log_callbacks = {
            .xqc_log_write_err = py_server_log_write,
            .xqc_log_write_stat = py_server_log_write,
        },
    };

    xqc_transport_callbacks_t tcbs = {
        .server_accept = py_server_accept,
        .write_socket = py_server_write_socket,
        .write_socket_ex = py_server_write_socket_ex,
    };

    /* engine config */
    xqc_config_t cfg;
    if (xqc_engine_get_default_config(&cfg, XQC_ENGINE_SERVER) < 0) {
        py_hash_free_all(s->streams); py_hash_free_all(s->sessions);
        free(s);
        return NULL;
    }
    cfg.cfg_log_level = s->log_level ? s->log_level : XQC_LOG_WARN;
    cfg.enable_h3_ext = 1;
    cfg.cid_len = 12;

    /* SSL config */
    xqc_engine_ssl_config_t ssl = {0};
    ssl.private_key_file = s->key_file;
    ssl.cert_file = s->cert_file;
    ssl.ciphers = XQC_TLS_CIPHERS;
    ssl.groups = XQC_TLS_GROUPS;

    /* create engine */
    s->engine = xqc_engine_create(XQC_ENGINE_SERVER, &cfg, &ssl,
        &ecbs, &tcbs, s);
    if (!s->engine) {
        py_hash_free_all(s->streams); py_hash_free_all(s->sessions);
        free(s);
        return NULL;
    }

    /* connection settings */
    xqc_conn_settings_t conn_settings = {0};
    conn_settings.cong_ctrl_callback = s->cc_type == 1 ? xqc_cubic_cb : xqc_bbr_cb;
    conn_settings.init_idle_time_out = s->idle_timeout_ms ? s->idle_timeout_ms : XQC_WT_PY_IDLE_TIMEOUT_MS;
    conn_settings.max_datagram_frame_size = XQC_WT_PY_MAX_DGRAM_FRAME_SIZE;
    conn_settings.max_pkt_out_size = 1200;
    xqc_server_set_conn_settings(s->engine, &conn_settings);

    /* register WT callbacks (xqc_wt_ctx_init now does value-copy) */
    xqc_webtransport_session_callbacks_t scbs = {
        .webtransport_session_create_notify = py_server_session_create,
        .webtransport_session_close_notify = py_server_session_close,
    };
    xqc_webtransport_stream_callbacks_t stcbs = {
        .wt_bidistream_read_notify = py_server_bidi_read_ex,
    };
    if (xqc_wt_ctx_init(s->engine, NULL, &scbs, &stcbs, 0) != XQC_OK) {
        xqc_engine_destroy(s->engine);
        py_hash_free_all(s->streams); py_hash_free_all(s->sessions);
        free(s);
        return NULL;
    }

    s_active_server = s;
    return s;
}

void
xqc_wt_py_server_set_callbacks(xqc_wt_py_server_t *server,
    xqc_wt_py_send_cb send_cb, xqc_wt_py_timer_cb timer_cb,
    xqc_wt_py_session_cb session_cb, xqc_wt_py_stream_cb stream_cb,
    xqc_wt_py_stream_data_cb data_cb, xqc_wt_py_dgram_cb dgram_cb,
    void *user_data)
{
    if (!server) return;
    server->send_cb = send_cb;
    server->timer_cb = timer_cb;
    server->session_cb = session_cb;
    server->stream_cb = stream_cb;
    server->data_cb = data_cb;
    server->dgram_cb = dgram_cb;
    server->user_data = user_data;
}

int
xqc_wt_py_server_feed_packet(xqc_wt_py_server_t *server,
    const uint8_t *data, size_t len,
    const struct sockaddr *local_addr, socklen_t local_addrlen,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    uint64_t recv_time_us)
{
    if (!server || !server->engine) return -1;
    /* py_handle set via wt_conn->py_handle = engine->user_data */

    return xqc_engine_packet_process(server->engine,
        (const unsigned char *)data, len,
        local_addr, local_addrlen,
        peer_addr, peer_addrlen,
        (xqc_usec_t)recv_time_us, server);
}

void
xqc_wt_py_server_finish_recv(xqc_wt_py_server_t *server)
{
    if (!server || !server->engine) return;
    /* py_handle set via wt_conn->py_handle = engine->user_data */
    xqc_engine_finish_recv(server->engine);
}

void
xqc_wt_py_server_process(xqc_wt_py_server_t *server)
{
    if (!server || !server->engine) return;
    /* py_handle set via wt_conn->py_handle = engine->user_data */
    xqc_engine_main_logic(server->engine);
}

ssize_t
xqc_wt_py_server_stream_send(xqc_wt_py_server_t *server, uint64_t stream_id,
    const uint8_t *data, size_t len, int fin)
{
    if (!server || !server->engine) return -1;

    py_stream_entry_t *e = py_find_stream_entry(server->streams, stream_id);
    if (!e) return -1;

    if (e->bidi_stream) {
        xqc_int_t ret = xqc_wt_bidistream_send(
            e->bidi_stream, (void *)data, (uint32_t)len, fin);
        if (ret >= 0) {
            xqc_engine_main_logic(server->engine);
        }
        return (ssize_t)ret;
    }
    /* fallback: raw stream_send (for non-bidi streams) */
    if (e->h3_stream && e->h3_stream->stream) {
        ssize_t sent = xqc_stream_send(e->h3_stream->stream,
            (unsigned char *)data, len, fin);
        if (sent >= 0) {
            xqc_engine_main_logic(server->engine);
        }
        return sent;
    }
    return -1;
}

int
xqc_wt_py_server_send_datagram(xqc_wt_py_server_t *server, uint64_t session_id,
    const uint8_t *data, size_t len)
{
    if (server == NULL || server->engine == NULL) {
        return -1;
    }
    /* TODO: implement server datagram via session_id → wt_conn lookup.
     * Requires storing wt_conn references in py_server_t during session create. */
    (void)session_id;
    (void)data;
    (void)len;
    return -1;
}

void
xqc_wt_py_server_set_session_request_cb(xqc_wt_py_server_t *server,
    xqc_wt_py_session_request_cb cb)
{
    if (server) server->session_request_cb = cb;
}

int
xqc_wt_py_server_close_session(xqc_wt_py_server_t *server, uint64_t session_id,
    uint32_t error_code, const char *reason, size_t reason_len)
{
    if (!server) return -1;
    xqc_wt_session_t *session = py_server_find_wt_session(server, session_id);
    if (!session) return -1;
    int ret = xqc_wt_session_close_with_error(session, error_code, reason, reason_len);
    if (ret == XQC_OK) {
        xqc_engine_main_logic(server->engine);
    }
    return ret;
}

int
xqc_wt_py_server_drain_session(xqc_wt_py_server_t *server, uint64_t session_id)
{
    if (!server) return -1;
    xqc_wt_session_t *session = py_server_find_wt_session(server, session_id);
    if (!session) return -1;
    int ret = xqc_wt_session_drain(session);
    if (ret == XQC_OK) {
        xqc_engine_main_logic(server->engine);
    }
    return ret;
}

const char *
xqc_wt_py_server_get_session_path(xqc_wt_py_server_t *server,
    uint64_t session_id)
{
    if (!server) return "";
    return py_server_get_session_path(server, session_id);
}

void
xqc_wt_py_server_set_log_cb(xqc_wt_py_server_t *server,
    xqc_wt_py_log_cb cb)
{
    if (server) server->log_cb = cb;
}

void
xqc_wt_py_server_set_config(xqc_wt_py_server_t *server,
    uint64_t idle_timeout_ms, int log_level, int cc_type)
{
    if (!server || !server->engine) return;
    server->idle_timeout_ms = idle_timeout_ms;
    server->log_level = log_level;
    server->cc_type = cc_type;
    xqc_conn_settings_t cs = {0};
    cs.cong_ctrl_callback = cc_type == 1 ? xqc_cubic_cb : xqc_bbr_cb;
    cs.init_idle_time_out = idle_timeout_ms ? idle_timeout_ms : XQC_WT_PY_IDLE_TIMEOUT_MS;
    cs.max_datagram_frame_size = XQC_WT_PY_MAX_DGRAM_FRAME_SIZE;
    cs.max_pkt_out_size = 1200;
    xqc_server_set_conn_settings(server->engine, &cs);
}

void
xqc_wt_py_server_destroy(xqc_wt_py_server_t *server)
{
    if (!server) return;
    if (server->engine) {
        xqc_engine_destroy(server->engine);
        server->engine = NULL;
    }
    py_hash_free_all(server->streams);
    py_hash_free_all(server->sessions);
    free(server);
}
