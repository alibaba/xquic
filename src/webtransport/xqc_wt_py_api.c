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
#include "xqc_webtransport_dgram.h"
#include "xqc_webtransport_stream.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_ctx.h"
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
#define XQC_WT_PY_DEFAULT_MAX_PKT_SIZE   1200
#define XQC_WT_PY_MAX_PKT_SIZE_LIMIT     1420
#define XQC_WT_PY_SERVER_MAGIC           0x57545356u
#define XQC_WT_PY_SERVER_MAGIC2          0x50595754u

/* HTTP status / reject */
#define XQC_WT_PY_REJECT_ERROR_CODE      404
#define XQC_WT_PY_REJECT_REASON          "Not Found"
#define XQC_WT_PY_REJECT_REASON_LEN      9

typedef struct {
    uint64_t                stream_id;      /* Python-visible id for server, wire id for client */
    uint64_t                owner_session_id;
    uint64_t                wire_stream_id;
    xqc_h3_stream_t        *h3_stream;
    xqc_wt_bidistream_t    *bidi_stream;   /* for xqc_wt_bidistream_send */
} py_stream_entry_t;

typedef struct {
    uint64_t                 stream_id;
    xqc_wt_unistream_t     *unistream;
} py_uni_stream_entry_t;

static void py_remove_stream_h(xqc_id_hash_table_t *ht, uint64_t stream_id);

typedef struct {
    uint64_t                 session_id;
    xqc_wt_session_t        *wt_session;
} py_session_entry_t;

typedef struct {
    uint64_t                 session_id;       /* Python-visible server id */
    uint64_t                 wire_session_id;  /* CONNECT stream id scoped to one QUIC connection */
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
    size_t                   max_pkt_out_size;
    uint8_t                  enable_pmtud;
    uint32_t                 ack_frequency;
    uint64_t                 initial_rtt_us;
    int                      no_verify_cert;
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
    uint32_t                 magic;
    uint32_t                 magic2;
    xqc_engine_t           *engine;
    char                     cert_file[512];
    char                     key_file[512];
    int                      current_fd;

    uint64_t                 idle_timeout_ms;
    int                      log_level;
    int                      cc_type;
    size_t                   max_pkt_out_size;
    uint8_t                  enable_pmtud;
    uint32_t                 ack_frequency;
    uint64_t                 initial_rtt_us;
    xqc_wt_py_log_cb         log_cb;

    xqc_id_hash_table_t     *streams;       /* py_stream_id → py_stream_entry_t* */
    xqc_id_hash_table_t     *sessions;      /* py_session_id → py_server_session_entry_t* */
    uint64_t                 next_session_id;
    uint64_t                 next_stream_id;
    char                     allowed_origins[16][256];
    size_t                   allowed_origin_count;
    xqc_bool_t               allow_any_origin;

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

static size_t
py_normalize_max_pkt_size(size_t max_pkt_out_size)
{
    if (max_pkt_out_size == 0) {
        return XQC_WT_PY_DEFAULT_MAX_PKT_SIZE;
    }
    if (max_pkt_out_size < XQC_WT_PY_DEFAULT_MAX_PKT_SIZE) {
        return XQC_WT_PY_DEFAULT_MAX_PKT_SIZE;
    }
    if (max_pkt_out_size > XQC_WT_PY_MAX_PKT_SIZE_LIMIT) {
        return XQC_WT_PY_MAX_PKT_SIZE_LIMIT;
    }
    return max_pkt_out_size;
}

static void
py_fill_conn_settings(xqc_conn_settings_t *cs, int cc_type,
    uint64_t idle_timeout_ms, size_t max_pkt_out_size, uint8_t enable_pmtud,
    uint32_t ack_frequency, uint64_t initial_rtt_us)
{
    memset(cs, 0, sizeof(*cs));
    cs->cong_ctrl_callback = cc_type == 1 ? xqc_cubic_cb : xqc_bbr_cb;
    cs->init_idle_time_out = idle_timeout_ms ? idle_timeout_ms
                                             : XQC_WT_PY_IDLE_TIMEOUT_MS;
    cs->max_datagram_frame_size = XQC_WT_PY_MAX_DGRAM_FRAME_SIZE;
    cs->reset_stream_at = 1;
    cs->max_pkt_out_size = py_normalize_max_pkt_size(max_pkt_out_size);
    cs->enable_pmtud = enable_pmtud ? 3 : 0;
    if (ack_frequency > 0) {
        cs->ack_frequency = ack_frequency;
    }
    if (initial_rtt_us > 0) {
        cs->initial_rtt = initial_rtt_us;
    }
}

static void
py_server_apply_conn_settings(xqc_wt_py_server_t *server)
{
    if (server == NULL || server->engine == NULL) {
        return;
    }
    xqc_conn_settings_t cs;
    py_fill_conn_settings(&cs, server->cc_type, server->idle_timeout_ms,
        server->max_pkt_out_size, server->enable_pmtud,
        server->ack_frequency, server->initial_rtt_us);
    xqc_server_set_conn_settings(server->engine, &cs);
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

static xqc_h3_conn_t *
py_client_get_h3_conn(xqc_wt_py_client_t *c)
{
    if (!c || !c->engine || !c->connected) {
        return NULL;
    }
    xqc_connection_t *conn = xqc_engine_get_conn_by_scid(c->engine, &c->cid);
    if (!conn) {
        return NULL;
    }
    return (xqc_h3_conn_t *)conn->proto_data;
}

static int
py_h3_peer_wt_ready(xqc_h3_conn_t *h3c)
{
    if (!h3c) {
        return 0;
    }
    if (!(h3c->flags & XQC_H3_CONN_FLAG_SETTINGS_RECVED)) {
        return 0;
    }
    return h3c->peer_h3_conn_settings.enable_webtransport
        && h3c->peer_h3_conn_settings.enable_connect_protocol
        && h3c->peer_h3_conn_settings.h3_datagram;
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

    /* A 2xx CONNECT response establishes the session; non-2xx rejects it. */
    for (size_t i = 0; i < headers->count; i++) {
        size_t nlen = headers->headers[i].name.iov_len;
        size_t vlen = headers->headers[i].value.iov_len;
        char *n = (char *)headers->headers[i].name.iov_base;
        char *v = (char *)headers->headers[i].value.iov_base;
        if (n && v && nlen == 7 && memcmp(n, ":status", 7) == 0
            && vlen == 3 && v[0] >= '0' && v[0] <= '9'
            && v[1] >= '0' && v[1] <= '9'
            && v[2] >= '0' && v[2] <= '9')
        {
            int status_code = (v[0] - '0') * 100 + (v[1] - '0') * 10 + (v[2] - '0');
            if (status_code >= 200 && status_code < 300) {
                /* assign unique session_id and store mapping */
                uint64_t sid = ++c->next_session_id;
                py_add_session(c, sid, session);
                if (c->session_cb) {
                    c->session_cb(XQC_WT_PY_EVENT_CREATED, sid, c->user_data);
                }
            } else if (c->session_cb) {
                c->session_cb(XQC_WT_PY_EVENT_REJECTED,
                    (uint64_t)status_code, c->user_data);
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
        if (sid != 0) {
            c->session_cb(XQC_WT_PY_EVENT_CLOSED, sid, c->user_data);
            py_remove_session(c, sid);
        }
    }
    return 0;
}

static void
py_client_handshake_done(xqc_webtransport_conn_t *conn, void *user_data)
{
    xqc_wt_py_client_t *c = py_client_from_wt_conn(user_data);
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
        if (sid == 0) {
            return;
        }
        c->dgram_cb(sid, (const uint8_t *)data, data_len, c->user_data);
    }
}


/* ===== Client: WT stream callbacks ===== */

static xqc_int_t
py_client_uni_read(xqc_wt_unistream_t *stream, xqc_wt_session_t *session,
    void *data, size_t data_len, uint8_t fin, void *strm_user_data)
{
    xqc_wt_py_client_t *c = session ? (xqc_wt_py_client_t *)
        (session->wt_conn ? session->wt_conn->py_handle : NULL) : NULL;
    if (!c || !c->data_cb) return 0;

    uint64_t sess_id = py_find_session_id(c, session);
    if (sess_id == 0) {
        return 0;
    }
    uint64_t stream_id = 0;
    if (stream && stream->type == XQC_WT_STREAM_TYPE_RECV
        && stream->stream.recv_stream
        && stream->stream.recv_stream->stream) {
        stream_id = stream->stream.recv_stream->stream->stream_id;
    }
    int py_fin = fin ? 1 : 0;

    if (c->stream_cb) {
        c->stream_cb(0, sess_id, stream_id, 0, c->user_data);
    }
    if (data_len > 0 || py_fin) {
        c->data_cb(sess_id, stream_id,
            (const uint8_t *)data, data_len, py_fin, c->user_data);
    }
    return 0;
}

static xqc_int_t
py_client_bidi_read_ex(xqc_wt_bidistream_t *stream, xqc_wt_session_t *session,
    void *data, size_t data_len, uint8_t fin, void *strm_user_data)
{
    xqc_wt_py_client_t *c = session ? (xqc_wt_py_client_t *)
        (session->wt_conn ? session->wt_conn->py_handle : NULL) : NULL;
    if (!c || !c->data_cb) return 0;

    /* NOTE: strm_user_data is &processed (int*), NOT h3_stream pointer.
     * Get h3_stream from the bidistream object instead. */
    uint64_t sess_id = py_find_session_id(c, session);
    if (sess_id == 0) {
        return 0;
    }
    uint64_t stream_id = 0;
    if (stream && stream->h3_stream) {
        stream_id = stream->h3_stream->stream_id;
    }
    int py_fin = fin ? 1 : 0;

    if (data_len > 0 || py_fin) {
        c->data_cb(sess_id, stream_id,
            (const uint8_t *)data, data_len, py_fin, c->user_data);
    }
    return 0;
}

static void py_remove_stream_h(xqc_id_hash_table_t *ht, uint64_t stream_id);

static xqc_int_t
py_client_bidi_close(xqc_wt_bidistream_t *stream, xqc_wt_session_t *session,
    void *strm_user_data)
{
    xqc_wt_py_client_t *c = session ? (xqc_wt_py_client_t *)
        (session->wt_conn ? session->wt_conn->py_handle : NULL) : NULL;
    if (c && stream && stream->h3_stream) {
        py_remove_stream_h(c->streams, stream->h3_stream->stream_id);
    }
    (void)strm_user_data;
    return 0;
}

static xqc_int_t
py_client_uni_close(xqc_wt_unistream_t *stream, xqc_wt_session_t *session,
    void *strm_user_data)
{
    xqc_wt_py_client_t *c = session ? (xqc_wt_py_client_t *)
        (session->wt_conn ? session->wt_conn->py_handle : NULL) : NULL;
    uint64_t stream_id = 0;
    if (stream && stream->type == XQC_WT_STREAM_TYPE_SEND
        && stream->stream.send_stream && stream->stream.send_stream->stream)
    {
        stream_id = stream->stream.send_stream->stream->stream_id;
    } else if (stream && stream->type == XQC_WT_STREAM_TYPE_RECV
               && stream->stream.recv_stream && stream->stream.recv_stream->stream)
    {
        stream_id = stream->stream.recv_stream->stream->stream_id;
    }
    if (c && stream_id) {
        py_uni_stream_entry_t *ue = xqc_id_hash_find(c->uni_streams, stream_id);
        if (ue) {
            xqc_id_hash_delete(c->uni_streams, stream_id);
            xqc_free(ue);
        }
    }
    (void)strm_user_data;
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
    c->no_verify_cert = no_verify_cert ? 1 : 0;

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
    c->max_pkt_out_size = XQC_WT_PY_DEFAULT_MAX_PKT_SIZE;
    c->enable_pmtud = 0;
    c->ack_frequency = 2;

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
xqc_wt_py_client_set_transport_params(xqc_wt_py_client_t *client,
    size_t max_pkt_out_size, int enable_pmtud, uint32_t ack_frequency,
    uint64_t initial_rtt_us)
{
    if (!client) return;
    client->max_pkt_out_size = py_normalize_max_pkt_size(max_pkt_out_size);
    client->enable_pmtud = enable_pmtud ? 1 : 0;
    if (ack_frequency > 0) {
        client->ack_frequency = ack_frequency;
    }
    client->initial_rtt_us = initial_rtt_us;
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
    xqc_config_t cfg = {0};
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
        .webtransport_conn_handshake_finished_notify = py_client_handshake_done,
    };
    xqc_webtransport_stream_callbacks_t stcbs = {
        .wt_bidistream_read_notify = py_client_bidi_read_ex,
        .wt_bidistream_close_notify = py_client_bidi_close,
        .wt_unistream_read_notify = py_client_uni_read,
        .wt_unistream_close_notify = py_client_uni_close,
    };
    if (xqc_wt_ctx_init(client->engine, &dcbs, &scbs, &stcbs, 0) != XQC_OK) {
        xqc_engine_destroy(client->engine);
        client->engine = NULL;
        return -1;
    }

    /* wt_ctx_init OK */

    /* QUIC connection settings with defaults */
    xqc_conn_settings_t cs;
    py_fill_conn_settings(&cs, client->cc_type, client->idle_timeout_ms,
        client->max_pkt_out_size, client->enable_pmtud,
        client->ack_frequency, client->initial_rtt_us);
    cs.proto_version = XQC_VERSION_V1;

    xqc_conn_ssl_config_t cssl = {0};
    if (!client->no_verify_cert) {
        cssl.cert_verify_flag = XQC_TLS_CERT_FLAG_NEED_VERIFY;
    }

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
    /* py_handle is set automatically via wt_conn->py_handle = engine->user_data.
     *
     * Prefer the concrete socket addresses observed by Python.  The stored
     * client->local_addr is 0.0.0.0:0 before the UDP socket receives its
     * ephemeral port; feeding packets with that address can break cross-host
     * path validation even when localhost happens to work.
     */
    const struct sockaddr *local =
        (local_addr && local_addrlen > 0)
            ? local_addr
            : (const struct sockaddr *)&client->local_addr;
    socklen_t local_len =
        (local_addr && local_addrlen > 0) ? local_addrlen : client->local_addrlen;
    const struct sockaddr *peer =
        (peer_addr && peer_addrlen > 0)
            ? peer_addr
            : (const struct sockaddr *)&client->peer_addr;
    socklen_t peer_len =
        (peer_addr && peer_addrlen > 0) ? peer_addrlen : client->peer_addrlen;

    xqc_int_t ret = xqc_engine_packet_process(client->engine,
        (const unsigned char *)data, len,
        local, local_len,
        peer, peer_len,
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
    if (!py_h3_peer_wt_ready(py_client_get_h3_conn(client))) {
        return -XQC_ESTATE;
    }

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
    e->owner_session_id = 0;
    e->wire_stream_id = h3s ? h3s->stream_id : stream_id;
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

    xqc_wt_flow_reservation_t reservation = {0};
    xqc_int_t fc_ret = xqc_wt_session_reserve_outgoing(ws, XQC_TRUE,
        XQC_TRUE, 0, &reservation);
    if (fc_ret < 0) return fc_ret;

    xqc_connection_t *conn = xqc_h3_conn_get_xqc_conn(h3c);
    xqc_stream_t *stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    if (!stream) {
        xqc_wt_session_rollback_outgoing(ws, &reservation);
        return -1;
    }

    /* Use BYTESTEAM type + WT_BIDI flag — same path as xqc_wt_session_send_bidi */
    xqc_h3_stream_t *h3s = (xqc_h3_stream_t *)stream->user_data;
    if (!h3s) {
        h3s = xqc_h3_stream_create(h3c, stream,
                                    XQC_H3_STREAM_TYPE_BYTESTEAM, NULL);
        if (h3s) stream->user_data = h3s;
    } else if (h3s->type == XQC_H3_STREAM_TYPE_UNKNOWN) {
        h3s->type = XQC_H3_STREAM_TYPE_BYTESTEAM;
    }
    if (h3s) {
        h3s->flags |= XQC_HTTP3_STREAM_FLAG_WT_BIDI;
        if (!h3s->h3_ext_bs) {
            h3s->h3_ext_bs = xqc_h3_ext_bytestream_create_passive(h3c, h3s, NULL);
        }
    }

    xqc_wt_bidistream_t *bidi =
        xqc_wt_create_bidistream(h3s, ws, NULL, NULL, XQC_FALSE);
    if (!bidi) {
        xqc_destroy_stream(stream);
        xqc_wt_session_rollback_outgoing(ws, &reservation);
        return -1;
    }

    xqc_int_t add_ret = xqc_wt_session_add_pendingstream(ws, h3s, bidi,
        XQC_WT_PENDING_BIDISTREAM);
    if (add_ret < 0) {
        xqc_wt_bidistream_destroy(bidi);
        xqc_destroy_stream(stream);
        xqc_wt_session_rollback_outgoing(ws, &reservation);
        return add_ret;
    }

    uint64_t sid = h3s->stream_id;

    /* record for later stream_send */
    if (py_record_stream_h(client->streams, sid, h3s, bidi) < 0) {
        xqc_wt_pending_stream_t *ps =
            xqc_wt_session_pending_stream_find(ws, h3s);
        xqc_id_hash_delete(ws->pending_unistreams, sid);
        if (ps) {
            xqc_free(ps);
        }
        xqc_wt_bidistream_destroy(bidi);
        xqc_destroy_stream(stream);
        xqc_wt_session_rollback_outgoing(ws, &reservation);
        return -1;
    }
    if (xqc_wt_session_commit_outgoing(ws, &reservation) < 0) {
        py_remove_stream_h(client->streams, sid);
        xqc_wt_pending_stream_t *ps =
            xqc_wt_session_pending_stream_find(ws, h3s);
        xqc_id_hash_delete(ws->pending_unistreams, sid);
        if (ps) {
            xqc_free(ps);
        }
        xqc_wt_bidistream_destroy(bidi);
        xqc_destroy_stream(stream);
        return -1;
    }

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
    py_stream_entry_t *se = py_find_stream_entry(client->streams, stream_id);
    xqc_h3_stream_t *h3s = se ? se->h3_stream : NULL;
    if (se && se->bidi_stream) {
        ssize_t sent = xqc_wt_bidistream_send(se->bidi_stream,
            (void *)data, (uint32_t)len, fin);
        if (sent >= 0) {
            xqc_engine_main_logic(client->engine);
            if (fin && se->bidi_stream && se->bidi_stream->send_fin) {
                py_remove_stream_h(client->streams, stream_id);
            }
        }
        return sent;
    }
    if (h3s && h3s->stream) {
        return -1;
    }

    /* check uni streams */
    {
        py_uni_stream_entry_t *ue = xqc_id_hash_find(client->uni_streams, stream_id);
        if (ue) {
            xqc_int_t ret = xqc_wt_unistream_send(ue->unistream, (void *)data, (uint32_t)len, fin);
            if (ret >= 0) {
                xqc_engine_main_logic(client->engine);
                if (fin && ue->unistream && ue->unistream->fin.send_fin) {
                    xqc_wt_unistream_close(ue->unistream);
                    xqc_id_hash_delete(client->uni_streams, stream_id);
                    xqc_free(ue);
                }
            }
            return ret;
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

    int ret = xqc_wt_session_datagram_send(ws, (void *)data, (uint32_t)len);
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
    return ret;
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
    int ret = xqc_wt_session_close_with_error(ws, 0, NULL, 0);
    if (ret == XQC_OK) {
        xqc_engine_main_logic(client->engine);
    }
    return ret;
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

int
xqc_wt_py_client_peer_wt_ready(xqc_wt_py_client_t *client)
{
    return py_h3_peer_wt_ready(py_client_get_h3_conn(client));
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

int
xqc_wt_py_debug_set_session_peer_flow_limits(xqc_wt_py_client_t *client,
    uint64_t session_id, uint64_t max_streams_bidi, uint64_t max_data)
{
    if (!client) return -1;
    xqc_wt_session_t *ws = py_find_session_by_id(client, session_id);
    if (!ws) return -1;
    ws->flow_control_enabled = XQC_TRUE;
    ws->peer_max_streams_bidi = max_streams_bidi;
    ws->peer_max_data = max_data;
    ws->sent_streams_bidi = 0;
    ws->sent_data = 0;
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

static ssize_t
py_server_write_socket(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data)
{
    xqc_wt_py_server_t *s = NULL;
    if (conn_user_data) {
        xqc_wt_py_server_t *direct = (xqc_wt_py_server_t *)conn_user_data;
        if (direct->magic == XQC_WT_PY_SERVER_MAGIC
            && direct->magic2 == XQC_WT_PY_SERVER_MAGIC2)
        {
            s = direct;
        } else {
            s = py_server_from_wt_conn(conn_user_data);
        }
    }
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
    if (conn && user_data) {
        xqc_conn_set_transport_user_data(conn, user_data);
    }
    return 0; /* accept all connections */
}

static py_server_session_entry_t *
py_server_find_session_entry_by_wt(xqc_wt_py_server_t *s,
    xqc_wt_session_t *wt_session)
{
    if (!s || !s->sessions || !wt_session) return NULL;
    for (int i = 0; i < s->sessions->count; i++) {
        xqc_id_hash_node_t *node = s->sessions->list[i];
        while (node) {
            py_server_session_entry_t *e =
                (py_server_session_entry_t *)node->element.value;
            if (e && e->wt_session == wt_session) return e;
            node = node->next;
        }
    }
    return NULL;
}

static uint64_t
py_server_find_session_id(xqc_wt_py_server_t *s, xqc_wt_session_t *wt_session)
{
    py_server_session_entry_t *e =
        py_server_find_session_entry_by_wt(s, wt_session);
    return e ? e->session_id : 0;
}

static uint64_t
py_server_find_stream_id_by_h3(xqc_wt_py_server_t *s, uint64_t owner_session_id,
    xqc_h3_stream_t *h3s, xqc_wt_bidistream_t *bidi_stream)
{
    if (!s || !s->streams || (!h3s && !bidi_stream)) return 0;
    uint64_t wire_stream_id = h3s ? h3s->stream_id : 0;
    for (int i = 0; i < s->streams->count; i++) {
        xqc_id_hash_node_t *node = s->streams->list[i];
        while (node) {
            py_stream_entry_t *e = (py_stream_entry_t *)node->element.value;
            if (e && e->owner_session_id == owner_session_id
                && ((wire_stream_id && e->wire_stream_id == wire_stream_id)
                    || (!wire_stream_id && bidi_stream
                        && e->bidi_stream == bidi_stream)))
            {
                if (bidi_stream && !e->bidi_stream) {
                    e->bidi_stream = bidi_stream;
                }
                return e->stream_id;
            }
            node = node->next;
        }
    }
    return 0;
}

static uint64_t
py_server_get_or_create_stream_id(xqc_wt_py_server_t *s,
    uint64_t owner_session_id, xqc_h3_stream_t *h3s,
    xqc_wt_bidistream_t *bidi_stream)
{
    uint64_t stream_id = py_server_find_stream_id_by_h3(s, owner_session_id,
        h3s, bidi_stream);
    if (stream_id) return stream_id;

    stream_id = ++s->next_stream_id;
    if (py_record_stream_h(s->streams, stream_id, h3s, bidi_stream) < 0) {
        return 0;
    }
    py_stream_entry_t *e = py_find_stream_entry(s->streams, stream_id);
    if (e) {
        e->owner_session_id = owner_session_id;
        e->wire_stream_id = h3s ? h3s->stream_id : 0;
    }
    return stream_id;
}

static xqc_int_t
py_server_bidi_close(xqc_wt_bidistream_t *bidi_stream, xqc_wt_session_t *session,
    void *strm_user_data)
{
    xqc_wt_py_server_t *s = session ? (xqc_wt_py_server_t *)
        (session->wt_conn ? session->wt_conn->py_handle : NULL) : NULL;
    if (s && bidi_stream) {
        uint64_t session_id = py_server_find_session_id(s, session);
        uint64_t stream_id = py_server_find_stream_id_by_h3(s, session_id,
            bidi_stream->h3_stream, bidi_stream);
        if (stream_id) {
            py_remove_stream_h(s->streams, stream_id);
        }
    }
    (void)strm_user_data;
    return 0;
}

static void
py_server_dgram_read(xqc_webtransport_session_t *session,
    const void *data, size_t data_len, void *user_data, uint64_t data_recv_time)
{
    xqc_wt_py_server_t *s = session ? (xqc_wt_py_server_t *)
        (session->wt_conn ? session->wt_conn->py_handle : NULL) : NULL;
    uint64_t session_id = py_server_find_session_id(s, session);
    if (s && s->dgram_cb && session_id && data_len > 0) {
        s->dgram_cb(session_id, (const uint8_t *)data, data_len, s->user_data);
    }
}

/* Server-side WT stream callback: bidi data → Python data_cb */
static xqc_int_t
py_server_bidi_read_ex(xqc_wt_bidistream_t *bidi_stream, xqc_wt_session_t *session,
    void *data, size_t data_len, uint8_t fin, void *strm_user_data)
{
    xqc_wt_py_server_t *s = session ? (xqc_wt_py_server_t *)
        (session->wt_conn ? session->wt_conn->py_handle : NULL) : NULL;
    if (!s) return 0;

    /* NOTE: strm_user_data here is &processed (int*), NOT h3_stream pointer.
     * Get h3_stream from the bidistream object instead. */
    xqc_h3_stream_t *h3s = (bidi_stream) ? bidi_stream->h3_stream : NULL;
    uint64_t session_id = py_server_find_session_id(s, session);
    uint64_t stream_id = py_server_get_or_create_stream_id(s, session_id,
        h3s, bidi_stream);
    int py_fin = fin ? 1 : 0;

    if (s->data_cb && session_id && stream_id && (data_len > 0 || py_fin)) {
        s->data_cb(session_id, stream_id,
            (const uint8_t *)data, data_len, py_fin, s->user_data);
    }

    return 0;
}

/* helper: store session mapping in server */
static int
py_server_store_session(xqc_wt_py_server_t *s, uint64_t session_id,
    uint64_t wire_session_id, xqc_wt_session_t *wt_session, const char *path)
{
    py_server_session_entry_t *e = xqc_malloc(sizeof(py_server_session_entry_t));
    if (!e) {
        fprintf(stderr, "py_server_store_session: malloc failed\n");
        return -1;
    }
    e->session_id = session_id;
    e->wire_session_id = wire_session_id;
    e->wt_session = wt_session;
    if (path) {
        strncpy(e->path, path, sizeof(e->path) - 1);
        e->path[sizeof(e->path) - 1] = '\0';
    } else {
        e->path[0] = '/'; e->path[1] = '\0';
    }
    xqc_id_hash_element_t el = { session_id, e };
    if (xqc_id_hash_add(s->sessions, el) < 0) {
        xqc_free(e);
        return -1;
    }
    return 0;
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

static int
py_server_origin_allowed(xqc_wt_py_server_t *s, const char *origin)
{
    if (s == NULL || s->allowed_origin_count == 0 || s->allow_any_origin) {
        return 1;
    }
    if (origin == NULL || origin[0] == '\0') {
        return 0;
    }
    for (size_t i = 0; i < s->allowed_origin_count; i++) {
        if (strcmp(s->allowed_origins[i], origin) == 0) {
            return 1;
        }
    }
    return 0;
}

/* helper: remove Python-visible stream entries owned by a server session */
static void
py_server_remove_streams_by_session(xqc_wt_py_server_t *s, uint64_t session_id)
{
    if (!s || !s->streams || session_id == 0) return;

    for (int i = 0; i < s->streams->count; i++) {
        xqc_id_hash_node_t *node = s->streams->list[i];
        while (node) {
            xqc_id_hash_node_t *next = node->next;
            py_stream_entry_t *e = (py_stream_entry_t *)node->element.value;
            if (e && e->owner_session_id == session_id) {
                uint64_t stream_id = e->stream_id;
                xqc_id_hash_delete(s->streams, stream_id);
                xqc_free(e);
            }
            if (next == node) break;
            node = next;
        }
    }
}

/* helper: remove session entry */
static void
py_server_remove_session(xqc_wt_py_server_t *s, uint64_t session_id)
{
    py_server_remove_streams_by_session(s, session_id);
    py_server_session_entry_t *e = xqc_id_hash_find(s->sessions, session_id);
    if (e) {
        xqc_id_hash_delete(s->sessions, session_id);
        xqc_free(e);
    }
}

static uint64_t
py_server_remove_session_by_wt(xqc_wt_py_server_t *s, xqc_wt_session_t *wt_session)
{
    py_server_session_entry_t *e =
        py_server_find_session_entry_by_wt(s, wt_session);
    uint64_t session_id = e ? e->session_id : 0;
    if (session_id) {
        py_server_remove_session(s, session_id);
    }
    return session_id;
}

/* Server-side session create → accept/reject via session_request_cb, then notify */
static int
py_server_session_create(xqc_webtransport_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *h3c_user_data)
{
    xqc_wt_py_server_t *s = py_server_from_wt_conn(h3c_user_data);
    if (!s || !session) return 0;

    /* extract :path and :authority from iovec headers into NUL-terminated buffers */
    char path_buf[256] = "/";
    char authority_buf[256] = "";
    char origin_buf[256] = "";
    const char *path = path_buf;
    const char *authority = authority_buf;
    const char *origin = origin_buf;
    if (headers) {
        for (size_t i = 0; i < headers->count; i++) {
            char *n = (char *)headers->headers[i].name.iov_base;
            size_t nlen = headers->headers[i].name.iov_len;
            char *v = (char *)headers->headers[i].value.iov_base;
            size_t vlen = headers->headers[i].value.iov_len;
            if (!n || !v) continue;
            if (nlen == 5 && memcmp(n, ":path", 5) == 0) {
                size_t copy_len = vlen < sizeof(path_buf) - 1 ? vlen : sizeof(path_buf) - 1;
                memcpy(path_buf, v, copy_len);
                path_buf[copy_len] = '\0';
            } else if (nlen == 10 && memcmp(n, ":authority", 10) == 0) {
                size_t copy_len = vlen < sizeof(authority_buf) - 1 ? vlen : sizeof(authority_buf) - 1;
                memcpy(authority_buf, v, copy_len);
                authority_buf[copy_len] = '\0';
            } else if (nlen == 6 && memcmp(n, "origin", 6) == 0) {
                size_t copy_len = vlen < sizeof(origin_buf) - 1 ? vlen : sizeof(origin_buf) - 1;
                memcpy(origin_buf, v, copy_len);
                origin_buf[copy_len] = '\0';
            }
        }
    }

    if (!py_server_origin_allowed(s, origin)) {
        return 403;
    }

    uint64_t py_session_id = ++s->next_session_id;

    /* if session_request_cb is set, let Python decide accept/reject */
    if (s->session_request_cb) {
        int accepted = s->session_request_cb(
            path, authority,
            py_session_id, s->user_data);
        if (!accepted) {
            return 0;
        }
    }

    /* store session mapping for close/drain/path queries */
    if (py_server_store_session(s, py_session_id, session->session_id,
        session, path) < 0)
    {
        return 0;
    }

    /* notify Python */
    if (s->session_cb) {
        s->session_cb(XQC_WT_PY_EVENT_CREATED, py_session_id, s->user_data);
    }
    return 1;
}

static int
py_server_session_close(xqc_webtransport_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *h3c_user_data)
{
    xqc_wt_py_server_t *s = py_server_from_wt_conn(h3c_user_data);
    if (s && session) {
        uint64_t py_session_id = py_server_find_session_id(s, session);
        if (s->session_cb && py_session_id) {
            s->session_cb(XQC_WT_PY_EVENT_CLOSED, py_session_id, s->user_data);
        }
        py_server_remove_session_by_wt(s, session);
    }
    return 0;
}


xqc_wt_py_server_t *
xqc_wt_py_server_create(const char *cert_file, const char *key_file)
{
    if (!cert_file || !key_file) return NULL;

    xqc_wt_py_server_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->magic = XQC_WT_PY_SERVER_MAGIC;
    s->magic2 = XQC_WT_PY_SERVER_MAGIC2;
    s->idle_timeout_ms = XQC_WT_PY_IDLE_TIMEOUT_MS;
    s->cc_type = 0;
    s->max_pkt_out_size = XQC_WT_PY_DEFAULT_MAX_PKT_SIZE;
    s->enable_pmtud = 0;
    s->ack_frequency = 2;

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
    xqc_config_t cfg = {0};
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

    py_server_apply_conn_settings(s);

    /* register WT callbacks (xqc_wt_ctx_init now does value-copy) */
    xqc_webtransport_dgram_callbacks_t dcbs = {
        .dgram_read_notify = py_server_dgram_read,
    };
    xqc_webtransport_session_callbacks_t scbs = {
        .webtransport_session_create_notify = py_server_session_create,
        .webtransport_session_close_notify = py_server_session_close,
    };
    xqc_webtransport_stream_callbacks_t stcbs = {
        .wt_bidistream_read_notify = py_server_bidi_read_ex,
        .wt_bidistream_close_notify = py_server_bidi_close,
    };
    if (xqc_wt_ctx_init(s->engine, &dcbs, &scbs, &stcbs, 0) != XQC_OK) {
        xqc_engine_destroy(s->engine);
        py_hash_free_all(s->streams); py_hash_free_all(s->sessions);
        free(s);
        return NULL;
    }

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
    if (!server || !server->engine) return -1;
    xqc_wt_session_t *session = py_server_find_wt_session(server, session_id);
    if (!session || !session->wt_conn) return -1;

    int ret = xqc_wt_session_datagram_send(session, (void *)data, (uint32_t)len);
    xqc_engine_main_logic(server->engine);
    return ret;
}

void
xqc_wt_py_server_set_session_request_cb(xqc_wt_py_server_t *server,
    xqc_wt_py_session_request_cb cb)
{
    if (server) server->session_request_cb = cb;
}

int
xqc_wt_py_server_set_allowed_origins(xqc_wt_py_server_t *server,
    const char *origins_csv)
{
    if (server == NULL) {
        return -XQC_EPARAM;
    }

    server->allowed_origin_count = 0;
    server->allow_any_origin = XQC_FALSE;
    if (origins_csv == NULL || origins_csv[0] == '\0') {
        return XQC_OK;
    }

    const char *p = origins_csv;
    while (*p) {
        if (server->allowed_origin_count >= 16) {
            server->allowed_origin_count = 0;
            server->allow_any_origin = XQC_FALSE;
            return -XQC_ELIMIT;
        }
        while (*p == ',' || *p == ' ') {
            p++;
        }
        const char *end = p;
        while (*end && *end != ',') {
            end++;
        }
        size_t len = (size_t)(end - p);
        while (len > 0 && p[len - 1] == ' ') {
            len--;
        }
        if (len == 1 && p[0] == '*') {
            server->allow_any_origin = XQC_TRUE;
            server->allowed_origin_count = 1;
            return XQC_OK;
        }
        if (len > 0) {
            if (len >= sizeof(server->allowed_origins[0])) {
                server->allowed_origin_count = 0;
                server->allow_any_origin = XQC_FALSE;
                return -XQC_ELIMIT;
            }
            size_t copy_len = len;
            memcpy(server->allowed_origins[server->allowed_origin_count],
                p, copy_len);
            server->allowed_origins[server->allowed_origin_count][copy_len] = '\0';
            server->allowed_origin_count++;
        }
        p = end;
    }
    return XQC_OK;
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
    if (idle_timeout_ms > 0) server->idle_timeout_ms = idle_timeout_ms;
    server->log_level = log_level;
    server->cc_type = cc_type;
    py_server_apply_conn_settings(server);
}

void
xqc_wt_py_server_set_transport_params(xqc_wt_py_server_t *server,
    size_t max_pkt_out_size, int enable_pmtud, uint32_t ack_frequency,
    uint64_t initial_rtt_us)
{
    if (!server) return;
    server->max_pkt_out_size = py_normalize_max_pkt_size(max_pkt_out_size);
    server->enable_pmtud = enable_pmtud ? 1 : 0;
    if (ack_frequency > 0) {
        server->ack_frequency = ack_frequency;
    }
    server->initial_rtt_us = initial_rtt_us;
    py_server_apply_conn_settings(server);
}

void
xqc_wt_py_server_set_browser_legacy_mode(xqc_wt_py_server_t *server,
    int enabled)
{
    if (!server || !server->engine) return;

    const char *alpns[] = { XQC_ALPN_H3, XQC_ALPN_H3_29, XQC_ALPN_H3_EXT };
    for (int i = 0; i < 3; i++) {
        xqc_h3_ctx_t *h3_ctx = xqc_engine_get_alpn_ctx(server->engine,
            alpns[i], strlen(alpns[i]));
        if (h3_ctx) {
            h3_ctx->h3c_def_local_settings.webtransport_mode =
                enabled ? XQC_WT_MODE_BROWSER_LEGACY
                        : XQC_WT_MODE_DRAFT15_STRICT;
        }
    }
}

void
xqc_wt_py_server_set_browser_compat_mode(xqc_wt_py_server_t *server,
    int enabled)
{
    if (!server || !server->engine) return;

    const char *alpns[] = { XQC_ALPN_H3, XQC_ALPN_H3_29, XQC_ALPN_H3_EXT };
    for (int i = 0; i < 3; i++) {
        xqc_h3_ctx_t *h3_ctx = xqc_engine_get_alpn_ctx(server->engine,
            alpns[i], strlen(alpns[i]));
        if (h3_ctx) {
            h3_ctx->h3c_def_local_settings.webtransport_mode =
                enabled ? XQC_WT_MODE_BROWSER_COMPAT
                        : XQC_WT_MODE_DRAFT15_STRICT;
        }
    }
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
    server->magic = 0;
    free(server);
}
