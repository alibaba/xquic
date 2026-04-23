/**
 * xqc_wt_py_api.h - Flat C API for Python CFFI bindings
 *
 * This header does NOT include any xquic headers.
 * All complex xquic types (xqc_conn_settings_t, xqc_engine_ssl_config_t, etc.)
 * are handled internally in xqc_wt_py_api.c.
 *
 * Python side only sees opaque handles and basic C types.
 */

#ifndef XQC_WT_PY_API_H
#define XQC_WT_PY_API_H

#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ===== Opaque handles ===== */
typedef struct xqc_wt_py_client_s xqc_wt_py_client_t;
typedef struct xqc_wt_py_server_s xqc_wt_py_server_t;

/* ===== Callback types (C → Python) ===== */

/**
 * Called when C needs to send a UDP packet.
 * Python should call sock.sendto(data, addr) synchronously in this callback.
 * For server: parse peer to get the correct destination address per client.
 */
typedef void (*xqc_wt_py_send_cb)(
    const uint8_t *data, size_t len,
    const struct sockaddr *peer, socklen_t peer_len,
    void *user);

/**
 * Called when C needs a timer. Python should call asyncio.call_later().
 * @param wake_after_us  microseconds until the timer should fire
 */
typedef void (*xqc_wt_py_timer_cb)(
    uint64_t wake_after_us, void *user);

/**
 * Session lifecycle event.
 * @param event  0=created (server responded 200), 1=closed, 2=handshake_done
 * @param session_id  unique session identifier
 */
typedef void (*xqc_wt_py_session_cb)(
    int event, uint64_t session_id, void *user);

/**
 * Stream lifecycle event.
 * @param event  0=created (incoming stream), 1=closed
 * @param session_id  which session this stream belongs to
 * @param stream_id  unique stream identifier
 * @param is_bidi  1 for bidirectional, 0 for unidirectional
 */
typedef void (*xqc_wt_py_stream_cb)(
    int event, uint64_t session_id, uint64_t stream_id,
    int is_bidi, void *user);

/**
 * Stream data received.
 * @param session_id  which session
 * @param stream_id  which stream
 * @param data  received bytes
 * @param len  length of data
 * @param fin  1 if stream is finished (no more data)
 */
typedef void (*xqc_wt_py_stream_data_cb)(
    uint64_t session_id, uint64_t stream_id,
    const uint8_t *data, size_t len, int fin,
    void *user);

/**
 * Datagram received.
 * @param session_id  which session
 * @param data  received bytes
 * @param len  length of data
 */
typedef void (*xqc_wt_py_dgram_cb)(
    uint64_t session_id,
    const uint8_t *data, size_t len,
    void *user);

/**
 * Session request — server decides accept or reject before notifying Python.
 * Called from C thread context (CFFI callback).
 * @param path       the :path from Extended CONNECT (e.g. "/echo")
 * @param authority  the :authority header (e.g. "localhost:4443")
 * @param session_id assigned session id
 * @return 1 to accept (session_cb CREATED will follow), 0 to reject (CLOSE capsule sent)
 */
typedef int (*xqc_wt_py_session_request_cb)(
    const char *path, const char *authority,
    uint64_t session_id, void *user);

/* ===== Session/Stream event constants ===== */
#define XQC_WT_PY_EVENT_CREATED        0
#define XQC_WT_PY_EVENT_CLOSED         1
#define XQC_WT_PY_EVENT_HANDSHAKE_DONE 2

/* ===== Client API ===== */

/**
 * Create a WebTransport client.
 * Internally creates xquic engine (CLIENT mode) with sensible defaults.
 * Does NOT create any socket — Python manages the UDP socket.
 *
 * @param host  server hostname (e.g. "127.0.0.1")
 * @param port  server port (e.g. 4443)
 * @param no_verify_cert  1 to skip TLS certificate verification
 * @return opaque client handle, or NULL on failure
 */
xqc_wt_py_client_t *xqc_wt_py_client_create(
    const char *host, int port, int no_verify_cert);

/**
 * Register all callbacks. Must be called before connect.
 * Python MUST hold references to all callback objects to prevent GC.
 */
void xqc_wt_py_client_set_callbacks(
    xqc_wt_py_client_t *client,
    xqc_wt_py_send_cb       send_cb,
    xqc_wt_py_timer_cb       timer_cb,
    xqc_wt_py_session_cb     session_cb,
    xqc_wt_py_stream_cb      stream_cb,
    xqc_wt_py_stream_data_cb data_cb,
    xqc_wt_py_dgram_cb       dgram_cb,
    void *user_data);

/**
 * Feed a received UDP packet to the QUIC engine.
 * Call this from Python's asyncio add_reader callback after recvfrom().
 *
 * @param recv_time_us  packet receive time in microseconds
 *                      (Python: int(time.monotonic() * 1_000_000))
 *                      Used for RTT estimation and congestion control.
 * @return 0 on success, <0 on error
 */
int xqc_wt_py_client_feed_packet(
    xqc_wt_py_client_t *client,
    const uint8_t *data, size_t len,
    const struct sockaddr *local_addr, socklen_t local_addrlen,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    uint64_t recv_time_us);

/**
 * Notify engine that a batch of packets has been fed.
 * Call after the recvfrom loop ends, before process().
 */
void xqc_wt_py_client_finish_recv(xqc_wt_py_client_t *client);

/**
 * Drive the engine state machine (xqc_engine_main_logic).
 * Call after finish_recv(), or from timer callback.
 * Timer callback should call process() only (no finish_recv).
 */
void xqc_wt_py_client_process(xqc_wt_py_client_t *client);

/**
 * Initiate QUIC connection + TLS handshake.
 * Asynchronous — session_cb(HANDSHAKE_DONE) fires when ready.
 * @return 0 on success, <0 on error
 */
int xqc_wt_py_client_connect(xqc_wt_py_client_t *client);

/**
 * Open a WebTransport session (send Extended CONNECT).
 * Call after handshake is done (session_cb(HANDSHAKE_DONE)).
 * Asynchronous — session_cb(CREATED, session_id) fires when server responds 200.
 *
 * @param path  the WT endpoint path (e.g. "/echo")
 * @param authority  the authority (e.g. "localhost")
 * @return 0 on success (request sent), <0 on error
 */
int xqc_wt_py_open_session(
    xqc_wt_py_client_t *client,
    const char *path, const char *authority);

/**
 * Convenience API: create bidi stream + send data + optional FIN in one call.
 * @return bytes sent (== len on success), <0 on error
 */
ssize_t xqc_wt_py_send_bidi(
    xqc_wt_py_client_t *client, uint64_t session_id,
    const uint8_t *data, size_t len, int fin);

/**
 * Create a bidirectional stream on a session.
 * Asynchronous — stream_cb(CREATED, session_id, stream_id, 1) fires.
 * @return 0 on success, <0 on error
 */
int xqc_wt_py_create_bidi_stream(
    xqc_wt_py_client_t *client, uint64_t session_id);

/**
 * Send data on an existing stream (supports multiple sends before FIN).
 * @return actual bytes sent (may be < len if flow control blocks), <0 on error
 */
ssize_t xqc_wt_py_stream_send(
    xqc_wt_py_client_t *client, uint64_t stream_id,
    const uint8_t *data, size_t len, int fin);

/**
 * Create a unidirectional stream (client→server) on a session.
 * stream_cb(CREATED, session_id, stream_id, is_bidi=0) fires.
 * Use xqc_wt_py_stream_send() to write data on the stream.
 * @return 0 on success, <0 on error
 */
int xqc_wt_py_create_uni_stream(
    xqc_wt_py_client_t *client, uint64_t session_id);

/**
 * Convenience: create uni stream + send data + FIN in one call.
 * @return bytes sent (== len on success), <0 on error
 */
ssize_t xqc_wt_py_send_uni(
    xqc_wt_py_client_t *client, uint64_t session_id,
    const uint8_t *data, size_t len);

/**
 * Send an unreliable datagram on a session.
 * @return 0 on success, <0 on error
 */
int xqc_wt_py_send_datagram(
    xqc_wt_py_client_t *client, uint64_t session_id,
    const uint8_t *data, size_t len);

/** Signal to C that the last sendto failed with EAGAIN.
 *  Call from within the send_cb callback when sendto returns EAGAIN.
 *  C will return XQC_SOCKET_EAGAIN to xquic, triggering PTO retransmit. */
void xqc_wt_py_client_set_send_eagain(xqc_wt_py_client_t *client);
void xqc_wt_py_server_set_send_eagain(xqc_wt_py_server_t *server);

/**
 * Close a single WebTransport session without closing the QUIC connection.
 * session_cb(CLOSED, session_id) fires after the session is closed.
 * @return 0 on success, <0 on error
 */
int xqc_wt_py_close_session(
    xqc_wt_py_client_t *client, uint64_t session_id);

/** Close a session with error code and reason (sends CLOSE capsule). */
int xqc_wt_py_close_session_with_error(
    xqc_wt_py_client_t *client, uint64_t session_id,
    uint32_t error_code, const char *reason, size_t reason_len);

/** Send RESET_STREAM on a bidi stream. */
int xqc_wt_py_stream_reset(
    xqc_wt_py_client_t *client, uint64_t stream_id, uint64_t error_code);

/** Send STOP_SENDING on a bidi stream. */
int xqc_wt_py_stream_stop_sending(
    xqc_wt_py_client_t *client, uint64_t stream_id, uint64_t error_code);

/** Configure client before connect. cc_type: 0=bbr, 1=cubic. */
void xqc_wt_py_client_set_config(
    xqc_wt_py_client_t *client,
    uint64_t idle_timeout_ms, int log_level, int cc_type);

/** Close the QUIC connection gracefully. */
void xqc_wt_py_client_close(xqc_wt_py_client_t *client);

/** Destroy and free the client handle. */
void xqc_wt_py_client_destroy(xqc_wt_py_client_t *client);

/* ===== Diagnostics API ===== */

/** Get smoothed RTT in microseconds. Returns 0 if not available. */
uint64_t xqc_wt_py_client_get_srtt(xqc_wt_py_client_t *client);

/** Get number of packets sent. */
uint32_t xqc_wt_py_client_get_send_count(xqc_wt_py_client_t *client);

/** Get number of packets received. */
uint32_t xqc_wt_py_client_get_recv_count(xqc_wt_py_client_t *client);

/** Get number of sessions currently open. */
int xqc_wt_py_client_get_session_count(xqc_wt_py_client_t *client);


/* ===== Server API ===== */

/**
 * Create a WebTransport server.
 * Internally creates xquic engine (SERVER mode) with WT support.
 * Does NOT create any socket — Python manages the UDP socket.
 *
 * @param cert_file  path to TLS certificate PEM file
 * @param key_file   path to TLS private key PEM file
 * @return opaque server handle, or NULL on failure
 */
xqc_wt_py_server_t *xqc_wt_py_server_create(
    const char *cert_file, const char *key_file);

/** Register all callbacks. Same semantics as client. */
void xqc_wt_py_server_set_callbacks(
    xqc_wt_py_server_t *server,
    xqc_wt_py_send_cb       send_cb,
    xqc_wt_py_timer_cb       timer_cb,
    xqc_wt_py_session_cb     session_cb,
    xqc_wt_py_stream_cb      stream_cb,
    xqc_wt_py_stream_data_cb data_cb,
    xqc_wt_py_dgram_cb       dgram_cb,
    void *user_data);

/** Feed a received UDP packet. Same semantics as client. */
int xqc_wt_py_server_feed_packet(
    xqc_wt_py_server_t *server,
    const uint8_t *data, size_t len,
    const struct sockaddr *local_addr, socklen_t local_addrlen,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    uint64_t recv_time_us);

/** Notify engine that a batch of packets has been fed. */
void xqc_wt_py_server_finish_recv(xqc_wt_py_server_t *server);

/** Drive the engine state machine. */
void xqc_wt_py_server_process(xqc_wt_py_server_t *server);

/**
 * Send data on a stream (server-side, e.g. echo response).
 * Stream identified by stream_id (unique across all sessions).
 * @return actual bytes sent, <0 on error
 */
ssize_t xqc_wt_py_server_stream_send(
    xqc_wt_py_server_t *server, uint64_t stream_id,
    const uint8_t *data, size_t len, int fin);

/**
 * Send an unreliable datagram on a session (server-side).
 * @return 0 on success, <0 on error
 */
int xqc_wt_py_server_send_datagram(
    xqc_wt_py_server_t *server, uint64_t session_id,
    const uint8_t *data, size_t len);

/** Register session request callback for accept/reject + path routing. */
void xqc_wt_py_server_set_session_request_cb(
    xqc_wt_py_server_t *server,
    xqc_wt_py_session_request_cb cb);

/**
 * Close a session with error code and reason (sends CLOSE capsule, RFC 9297).
 * @param error_code  application error code (0 for clean close)
 * @param reason      UTF-8 reason phrase (can be NULL)
 * @param reason_len  length of reason
 * @return 0 on success, <0 on error
 */
int xqc_wt_py_server_close_session(
    xqc_wt_py_server_t *server, uint64_t session_id,
    uint32_t error_code, const char *reason, size_t reason_len);

/**
 * Send DRAIN capsule for graceful session shutdown (RFC 9297).
 * Peer should stop opening new streams after receiving DRAIN.
 * @return 0 on success, <0 on error
 */
int xqc_wt_py_server_drain_session(
    xqc_wt_py_server_t *server, uint64_t session_id);

/** Get the :path for a session. Returns "" if not found. */
const char *xqc_wt_py_server_get_session_path(
    xqc_wt_py_server_t *server, uint64_t session_id);

/** Configure server. Must be called AFTER create, BEFORE first packet. */
void xqc_wt_py_server_set_config(
    xqc_wt_py_server_t *server,
    uint64_t idle_timeout_ms, int log_level, int cc_type);

/** Destroy and free the server handle. */
void xqc_wt_py_server_destroy(xqc_wt_py_server_t *server);

#ifdef __cplusplus
}
#endif

#endif /* XQC_WT_PY_API_H */
