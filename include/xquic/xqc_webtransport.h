/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 *
 * Native HTTP/3 WebTransport drafts 16 and 07. Register after ordinary HTTP/3
 * callbacks, before creating connections. The server acceptance callback
 * validates Origin/application policy and returns 1 to accept, 0 to reject.
 * Callback data is the HTTP/3 connection user data, or the stream user data
 * supplied at creation. A successful create callback returns XQC_OK.
 * Handles and borrowed strings expire at their final close notification.
 * See harness/spec/webtransport/spec.md for negotiation and lifetime rules.
 */
#ifndef XQC_WEBTRANSPORT_H
#define XQC_WEBTRANSPORT_H

#include "xquic.h"
#include "xqc_http3.h"

#ifdef XQC_ENABLE_WEBTRANSPORT

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    XQC_WEBTRANSPORT_DRAFT_VERSION_7 = 1,
    XQC_WEBTRANSPORT_DRAFT_VERSION_16 = 2,
} xqc_webtransport_draft_version_t;

#define XQC_WEBTRANSPORT_DEFAULT_PENDING_DGRAM_COUNT_MAX 64
#define XQC_WEBTRANSPORT_DEFAULT_PENDING_DGRAM_BYTES_MAX (64 * 1024)
#define XQC_WEBTRANSPORT_DEFAULT_UNKNOWN_SESSION_DGRAM_WINDOW 32

typedef struct xqc_webtransport_conn_settings_s {
    /* Simultaneous sessions: 1..1024 (implementation cap), default 1. */
    uint64_t                         max_sessions_count;
    /* Highest supported revision: 16 also advertises 07; 7 is 07-only. */
    xqc_webtransport_draft_version_t draft_version;
    /* At least max_sessions_count; at most 2^60 when pooling; default 128. */
    uint64_t                         max_bidi_streams;
    /* At least 3 H3/QPACK streams; at most 2^60 when pooling; default 128. */
    uint64_t                         max_uni_streams;
    /* Nonzero receive window in bytes, default 1 MiB. */
    uint32_t                         init_recv_window;
    /* Must be true: both revisions require Datagram support. */
    xqc_bool_t                       enable_datagram;
} xqc_webtransport_conn_settings_t;

typedef struct xqc_webtransport_conn_s xqc_webtransport_conn_t;
typedef xqc_webtransport_conn_t xqc_wt_conn_t;

typedef struct xqc_webtransport_session_s xqc_webtransport_session_t;
typedef xqc_webtransport_session_t xqc_wt_session_t;

typedef struct xqc_wt_unistream_s xqc_wt_unistream_t;

typedef struct xqc_wt_bidistream_s xqc_wt_bidistream_t;

typedef void (*xqc_webtransport_datagram_read_notify_pt)(
    xqc_webtransport_session_t *session, const void *data, size_t data_len,
    void *user_data, uint64_t data_recv_time);

typedef void (*xqc_webtransport_datagram_write_notify_pt)(
    xqc_webtransport_session_t *session, void *user_data);

/*
 * Loss may be followed by a late ACK; return XQC_DGRAM_RETX_ASKED_BY_APP
 * to request retransmission, otherwise return zero.
 */
typedef int (*xqc_webtransport_datagram_lost_notify_pt)(
    xqc_webtransport_session_t *session, uint64_t dgram_id, void *user_data);

typedef void (*xqc_webtransport_datagram_acked_notify_pt)(
    xqc_webtransport_session_t *session, uint64_t dgram_id, void *user_data);

typedef void (*xqc_webtransport_datagram_mss_updated_notify_pt)(
    xqc_webtransport_session_t *session, size_t mss, void *user_data);

typedef struct xqc_webtransport_dgram_callbacks_s {
    xqc_webtransport_datagram_read_notify_pt        dgram_read_notify;

    xqc_webtransport_datagram_write_notify_pt       dgram_write_notify;

    xqc_webtransport_datagram_acked_notify_pt       dgram_acked_notify;

    xqc_webtransport_datagram_lost_notify_pt        dgram_lost_notify;

    xqc_webtransport_datagram_mss_updated_notify_pt dgram_mss_updated_notify;

} xqc_webtransport_dgram_callbacks_t;

typedef int (*xqc_webtransport_session_notify_pt)(
    xqc_webtransport_session_t *session, xqc_http_headers_t *headers,
    const xqc_cid_t *cid, void *h3c_user_data);

typedef int (*xqc_webtransport_on_create_session_notify_pt)(
    xqc_http_headers_t *headers, xqc_http_headers_t *response,
    void *h3c_user_data);

typedef void (*xqc_webtransport_conn_handshake_finished_notify_pt)(
    xqc_h3_conn_t *h3_conn, void *h3c_user_data);

typedef void (*xqc_webtransport_session_drain_notify_pt)(
    xqc_wt_session_t *session, void *h3c_user_data);

typedef struct xqc_webtransport_session_callbacks_s {
    /* Required on servers; response headers are copied synchronously. */
    xqc_webtransport_on_create_session_notify_pt
        webtransport_will_create_session_notify;
    /* Successful CONNECT; return an error to close the session. */
    xqc_webtransport_session_notify_pt webtransport_session_create_notify;
    /* Final notification, including failed CONNECT; headers is NULL. */
    xqc_webtransport_session_notify_pt webtransport_session_close_notify;
    xqc_webtransport_conn_handshake_finished_notify_pt
        webtransport_conn_handshake_finished_notify;
    xqc_webtransport_session_drain_notify_pt
        webtransport_session_drain_notify;

} xqc_webtransport_session_callbacks_t;

typedef xqc_int_t (*xqc_webtransport_unistream_notify_pt)(
    xqc_wt_unistream_t *stream, xqc_wt_session_t *session,
    void *strm_user_data);

typedef xqc_int_t (*xqc_webtransport_bidistream_notify_pt)(
    xqc_wt_bidistream_t *stream, xqc_wt_session_t *session,
    void *strm_user_data);

typedef xqc_int_t (*xqc_webtransport_unistream_read_notify_pt)(
    xqc_wt_unistream_t *stream, xqc_wt_session_t *session, void *data,
    size_t data_len, void *strm_user_data);

typedef xqc_int_t (*xqc_webtransport_bidistream_read_notify_pt)(
    xqc_wt_bidistream_t *stream, xqc_wt_session_t *session, void *data,
    size_t data_len, void *strm_user_data);

/* webtransport stream callback functions */
typedef struct xqc_webtransport_stream_callbacks_s {
    xqc_webtransport_unistream_read_notify_pt  wt_unistream_read_notify;

    xqc_webtransport_unistream_notify_pt       wt_unistream_write_notify;

    xqc_webtransport_unistream_notify_pt       wt_unistream_create_notify;

    xqc_webtransport_unistream_notify_pt       wt_unistream_close_notify;

    xqc_webtransport_unistream_notify_pt       wt_unistream_closing_notify;

    xqc_webtransport_bidistream_read_notify_pt wt_bidistream_read_notify;

    xqc_webtransport_bidistream_notify_pt      wt_bidistream_write_notify;

    xqc_webtransport_bidistream_notify_pt      wt_bidistream_create_notify;

    xqc_webtransport_bidistream_notify_pt      wt_bidistream_close_notify;

    xqc_webtransport_bidistream_notify_pt      wt_bidistream_closing_notify;

} xqc_webtransport_stream_callbacks_t;

typedef struct xqc_webtransport_callbacks_s {
    xqc_webtransport_dgram_callbacks_t   dgram_cbs;
    xqc_webtransport_session_callbacks_t session_cbs;
    xqc_webtransport_stream_callbacks_t  stream_cbs;
} xqc_webtransport_callbacks_t;

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_wt_ctx_init(xqc_engine_t *engine,
    xqc_webtransport_dgram_callbacks_t *dgram_cbs,
    xqc_webtransport_session_callbacks_t *session_cbs,
    xqc_webtransport_stream_callbacks_t *stream_cbs);

XQC_EXPORT_PUBLIC_API
const xqc_cid_t *xqc_webtransport_connect(xqc_engine_t *engine,
    const xqc_conn_settings_t *conn_settings, const unsigned char *token,
    unsigned token_len, const char *server_host, int no_crypto_flag,
    const xqc_conn_ssl_config_t *conn_ssl_config,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user_data);

/*
 * Send returns accepted payload bytes (prefix excluded), or a negative error.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_wt_unistream_send(xqc_wt_unistream_t *wt_stream, const void *data,
    uint32_t len, int fin);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_wt_bidistream_send(xqc_wt_bidistream_t *wt_bidistream,
    const void *data, uint32_t len, int fin);

/* NULL selects draft-16/07 support with one simultaneous session. */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_wt_engine_set_default_settings(xqc_engine_t *engine,
    const xqc_webtransport_conn_settings_t *settings);

/* Copies request strings. Sends CONNECT after SETTINGS and the handshake. */
XQC_EXPORT_PUBLIC_API
xqc_wt_session_t *xqc_wt_client_open_session(xqc_h3_conn_t *h3_conn,
    const char *authority, const char *path, const char *origin, int *err);

/*
 * Copies protocols in preference order and requires a negotiated protocol
 * when protocol_count is nonzero. Each string is printable ASCII, at most
 * 1024 bytes; the encoded list is at most 4096 bytes. Zero preserves the
 * optional negotiation behavior of xqc_wt_client_open_session().
 * Nonzero protocol_count requires draft-16; a draft-07 result fails locally.
 */
XQC_EXPORT_PUBLIC_API
xqc_wt_session_t *xqc_wt_client_open_session_with_protocols(
    xqc_h3_conn_t *h3_conn, const char *authority, const char *path,
    const char *origin, const char *const *protocols, size_t protocol_count,
    int *err);

/*
 * Selects the first client-offered application protocol supported locally.
 * Repeated WT-Available-Protocols fields form one list, at most 4096 bytes.
 * Local strings use the same size/character limits as the client API above.
 * Returns 1 for a match, 0 for no offer/match, or a negative error. On 1,
 * *selected borrows an element of protocols; otherwise it is NULL. The
 * caller retains the strings and decides whether to accept the session.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_wt_select_application_protocol(const xqc_http_headers_t *headers,
    const char *const *protocols, size_t protocol_count, const char **selected);

/* Client-selected protocol, borrowed until close notification; else NULL. */
XQC_EXPORT_PUBLIC_API
const char *xqc_wt_session_get_application_protocol(xqc_wt_session_t *session);

/* Final status sent or received; zero means no final response is available. */
XQC_EXPORT_PUBLIC_API
unsigned xqc_wt_session_get_response_status(xqc_wt_session_t *session);

/* window counts future client-initiated bidirectional stream IDs / 4. */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_wt_ctx_set_pending_datagram_policy(xqc_engine_t *engine,
    uint64_t window, size_t count_max, size_t bytes_max);

XQC_EXPORT_PUBLIC_API
xqc_h3_conn_t *xqc_wt_session_get_h3_conn(xqc_wt_session_t *session);

/* reason is copied; getters borrow storage until the final close callback. */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_wt_session_close_with_error(xqc_wt_session_t *session,
    uint32_t error_code, const char *reason, size_t reason_len);

XQC_EXPORT_PUBLIC_API
uint32_t xqc_wt_session_get_close_error_code(xqc_wt_session_t *session);

XQC_EXPORT_PUBLIC_API
const char *xqc_wt_session_get_close_reason(xqc_wt_session_t *session);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_wt_session_drain(xqc_wt_session_t *session);

/*
 * One application datagram per call; zero means accepted, errors are negative.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_wt_session_datagram_send(xqc_wt_session_t *session,
    const void *data, size_t data_len, uint64_t *datagram_id);

XQC_EXPORT_PUBLIC_API
xqc_wt_unistream_t *xqc_wt_session_create_uni_stream(
    xqc_wt_session_t *session, void *user_data, int *err);

XQC_EXPORT_PUBLIC_API
xqc_wt_bidistream_t *xqc_wt_session_create_bidi_stream(
    xqc_wt_session_t *session, void *user_data, int *err);

XQC_EXPORT_PUBLIC_API
xqc_stream_id_t xqc_wt_bidistream_id(xqc_wt_bidistream_t *stream);
XQC_EXPORT_PUBLIC_API
xqc_stream_id_t xqc_wt_unistream_id(xqc_wt_unistream_t *stream);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_wt_bidistream_reset(xqc_wt_bidistream_t *stream,
    uint32_t error_code);
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_wt_unistream_reset(xqc_wt_unistream_t *stream,
    uint32_t error_code);
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_wt_bidistream_stop_sending(xqc_wt_bidistream_t *stream,
    uint32_t error_code);
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_wt_unistream_stop_sending(xqc_wt_unistream_t *stream,
    uint32_t error_code);

/* Read callbacks return XQC_OK for full consumption or -XQC_EAGAIN for none. */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_wt_bidistream_set_read_paused(xqc_wt_bidistream_t *stream,
    xqc_bool_t paused);
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_wt_unistream_set_read_paused(xqc_wt_unistream_t *stream,
    xqc_bool_t paused);

XQC_EXPORT_PUBLIC_API
xqc_bool_t xqc_wt_bidistream_closing_is_stop_sending(
    xqc_wt_bidistream_t *stream);
XQC_EXPORT_PUBLIC_API
xqc_bool_t xqc_wt_unistream_closing_is_stop_sending(
    xqc_wt_unistream_t *stream);

/* Inside a closing callback, returns false when no application code exists. */
XQC_EXPORT_PUBLIC_API
xqc_bool_t xqc_wt_bidistream_get_recv_error_code(
    xqc_wt_bidistream_t *stream, uint32_t *error_code);
XQC_EXPORT_PUBLIC_API
xqc_bool_t xqc_wt_unistream_get_recv_error_code(
    xqc_wt_unistream_t *stream, uint32_t *error_code);

/* A zero-length read callback can carry FIN; these getters disambiguate it. */
XQC_EXPORT_PUBLIC_API
xqc_bool_t xqc_wt_bidistream_get_recv_fin(xqc_wt_bidistream_t *stream);
XQC_EXPORT_PUBLIC_API
xqc_bool_t xqc_wt_unistream_get_recv_fin(xqc_wt_unistream_t *stream);

#ifdef __cplusplus
}
#endif

#endif /* XQC_ENABLE_WEBTRANSPORT */

#endif
