"""
CFFI declarations for xqc_wt_py_api.h (ABI mode — dlopen).

The C API is deliberately flat: no complex structs, only opaque handles
and basic types. This makes ABI mode safe — no struct layout mismatch risk.
"""

import os
import ctypes.util
from cffi import FFI

ffi = FFI()

ffi.cdef("""
    /* Opaque handles */
    typedef struct xqc_wt_py_client_s xqc_wt_py_client_t;
    typedef struct xqc_wt_py_server_s xqc_wt_py_server_t;

    /* Callback types — use void* for sockaddr pointers (ABI mode safe) */
    typedef void (*xqc_wt_py_send_cb)(
        const uint8_t *data, size_t len,
        const void *peer, unsigned int peer_len,
        void *user);
    typedef void (*xqc_wt_py_timer_cb)(
        uint64_t wake_after_us, void *user);
    typedef void (*xqc_wt_py_session_cb)(
        int event, uint64_t session_id, void *user);
    typedef void (*xqc_wt_py_stream_cb)(
        int event, uint64_t session_id, uint64_t stream_id,
        int is_bidi, void *user);
    typedef void (*xqc_wt_py_stream_data_cb)(
        uint64_t session_id, uint64_t stream_id,
        const uint8_t *data, size_t len, int fin,
        void *user);
    typedef void (*xqc_wt_py_dgram_cb)(
        uint64_t session_id,
        const uint8_t *data, size_t len,
        void *user);

    /* Client API */
    xqc_wt_py_client_t *xqc_wt_py_client_create(
        const char *host, int port, int no_verify_cert);
    void xqc_wt_py_client_set_callbacks(
        xqc_wt_py_client_t *client,
        xqc_wt_py_send_cb send_cb,
        xqc_wt_py_timer_cb timer_cb,
        xqc_wt_py_session_cb session_cb,
        xqc_wt_py_stream_cb stream_cb,
        xqc_wt_py_stream_data_cb data_cb,
        xqc_wt_py_dgram_cb dgram_cb,
        void *user_data);
    int xqc_wt_py_client_connect(xqc_wt_py_client_t *client);
    int xqc_wt_py_client_feed_packet(
        xqc_wt_py_client_t *client,
        const uint8_t *data, size_t len,
        const void *local_addr, unsigned int local_addrlen,
        const void *peer_addr, unsigned int peer_addrlen,
        uint64_t recv_time_us);
    void xqc_wt_py_client_finish_recv(xqc_wt_py_client_t *client);
    void xqc_wt_py_client_process(xqc_wt_py_client_t *client);
    int xqc_wt_py_open_session(
        xqc_wt_py_client_t *client,
        const char *path, const char *authority);
    long long xqc_wt_py_send_bidi(
        xqc_wt_py_client_t *client, uint64_t session_id,
        const uint8_t *data, size_t len, int fin);
    int xqc_wt_py_create_bidi_stream(
        xqc_wt_py_client_t *client, uint64_t session_id);
    long long xqc_wt_py_stream_send(
        xqc_wt_py_client_t *client, uint64_t stream_id,
        const uint8_t *data, size_t len, int fin);
    int xqc_wt_py_create_uni_stream(
        xqc_wt_py_client_t *client, uint64_t session_id);
    long long xqc_wt_py_send_uni(
        xqc_wt_py_client_t *client, uint64_t session_id,
        const uint8_t *data, size_t len);
    int xqc_wt_py_send_bidi_batch(
        xqc_wt_py_client_t *client, uint64_t session_id,
        const uint8_t *data, const size_t *offsets, const size_t *lengths,
        int count);
    int xqc_wt_py_send_datagram(
        xqc_wt_py_client_t *client, uint64_t session_id,
        const uint8_t *data, size_t len);
    int xqc_wt_py_close_session(
        xqc_wt_py_client_t *client, uint64_t session_id);
    int xqc_wt_py_close_session_with_error(
        xqc_wt_py_client_t *client, uint64_t session_id,
        uint32_t error_code, const char *reason, size_t reason_len);
    int xqc_wt_py_stream_reset(
        xqc_wt_py_client_t *client, uint64_t stream_id, uint64_t error_code);
    int xqc_wt_py_stream_stop_sending(
        xqc_wt_py_client_t *client, uint64_t stream_id, uint64_t error_code);
    void xqc_wt_py_client_set_config(
        xqc_wt_py_client_t *client,
        uint64_t idle_timeout_ms, int log_level, int cc_type);
    void xqc_wt_py_client_set_send_eagain(xqc_wt_py_client_t *client);
    void xqc_wt_py_server_set_send_eagain(xqc_wt_py_server_t *server);
    void xqc_wt_py_client_close(xqc_wt_py_client_t *client);
    void xqc_wt_py_client_destroy(xqc_wt_py_client_t *client);

    /* Diagnostics */
    uint64_t xqc_wt_py_client_get_srtt(xqc_wt_py_client_t *client);
    uint32_t xqc_wt_py_client_get_send_count(xqc_wt_py_client_t *client);
    uint32_t xqc_wt_py_client_get_recv_count(xqc_wt_py_client_t *client);
    int xqc_wt_py_client_get_session_count(xqc_wt_py_client_t *client);
    uint64_t xqc_wt_py_client_get_remote_dgram_size(xqc_wt_py_client_t *client);

    /* Server API */
    xqc_wt_py_server_t *xqc_wt_py_server_create(
        const char *cert_file, const char *key_file);
    void xqc_wt_py_server_set_callbacks(
        xqc_wt_py_server_t *server,
        xqc_wt_py_send_cb send_cb,
        xqc_wt_py_timer_cb timer_cb,
        xqc_wt_py_session_cb session_cb,
        xqc_wt_py_stream_cb stream_cb,
        xqc_wt_py_stream_data_cb data_cb,
        xqc_wt_py_dgram_cb dgram_cb,
        void *user_data);
    int xqc_wt_py_server_feed_packet(
        xqc_wt_py_server_t *server,
        const uint8_t *data, size_t len,
        const void *local_addr, unsigned int local_addrlen,
        const void *peer_addr, unsigned int peer_addrlen,
        uint64_t recv_time_us);
    void xqc_wt_py_server_finish_recv(xqc_wt_py_server_t *server);
    void xqc_wt_py_server_process(xqc_wt_py_server_t *server);
    long long xqc_wt_py_server_stream_send(
        xqc_wt_py_server_t *server, uint64_t stream_id,
        const uint8_t *data, size_t len, int fin);
    int xqc_wt_py_server_send_datagram(
        xqc_wt_py_server_t *server, uint64_t session_id,
        const uint8_t *data, size_t len);

    /* Session request callback (accept/reject + path routing) */
    typedef int (*xqc_wt_py_session_request_cb)(
        const char *path, const char *authority,
        uint64_t session_id, void *user);
    void xqc_wt_py_server_set_session_request_cb(
        xqc_wt_py_server_t *server,
        xqc_wt_py_session_request_cb cb);

    /* Session close with error code + reason (CLOSE capsule) */
    int xqc_wt_py_server_close_session(
        xqc_wt_py_server_t *server, uint64_t session_id,
        uint32_t error_code, const char *reason, size_t reason_len);

    /* Session drain (DRAIN capsule) */
    int xqc_wt_py_server_drain_session(
        xqc_wt_py_server_t *server, uint64_t session_id);

    /* Get session path */
    const char *xqc_wt_py_server_get_session_path(
        xqc_wt_py_server_t *server, uint64_t session_id);

    typedef void (*xqc_wt_py_log_cb)(int level, const char *msg, size_t len, void *user);
    void xqc_wt_py_client_set_log_cb(xqc_wt_py_client_t *client, xqc_wt_py_log_cb cb);
    void xqc_wt_py_server_set_log_cb(xqc_wt_py_server_t *server, xqc_wt_py_log_cb cb);

    void xqc_wt_py_server_set_config(
        xqc_wt_py_server_t *server,
        uint64_t idle_timeout_ms, int log_level, int cc_type);
    void xqc_wt_py_server_destroy(xqc_wt_py_server_t *server);

    /* Wire protocol (for testing) */
    size_t xqc_wt_encode_session_id(uint64_t session_id, uint8_t *buf, size_t buf_len);
    long long xqc_wt_decode_session_id(const uint8_t *buf, size_t buf_len, uint64_t *session_id);
    size_t xqc_wt_encode_close_session_capsule(uint32_t error_code,
        const char *reason, size_t reason_len, uint8_t *buf, size_t buf_len);
    long long xqc_wt_decode_close_session_capsule(const uint8_t *payload, size_t payload_len,
        uint32_t *error_code, const uint8_t **reason, size_t *reason_len);
    size_t xqc_wt_encode_drain_session_capsule(uint8_t *buf, size_t buf_len);
    long long xqc_wt_decode_capsule_header(const uint8_t *buf, size_t buf_len,
        uint64_t *type, uint64_t *payload_len);
""")


def _find_lib():
    """Search for libxquic_wt_py in common locations."""
    # 1. Environment variable
    env_path = os.environ.get("XQUIC_LIB_PATH")
    if env_path:
        for name in ("libxquic_wt_py.dylib", "libxquic_wt_py.so"):
            candidate = os.path.join(env_path, name)
            if os.path.isfile(candidate):
                return candidate
        # also check subdirectories
        for sub in ("src/webtransport",):
            for name in ("libxquic_wt_py.dylib", "libxquic_wt_py.so"):
                candidate = os.path.join(env_path, sub, name)
                if os.path.isfile(candidate):
                    return candidate

    # 2. Package directory
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    for name in ("libxquic_wt_py.dylib", "libxquic_wt_py.so"):
        candidate = os.path.join(pkg_dir, name)
        if os.path.isfile(candidate):
            return candidate

    # 3. Relative to package (development layout)
    dev_paths = [
        os.path.join(pkg_dir, "..", "..", "..", "build_wt", "src", "webtransport"),
        os.path.join(pkg_dir, "..", "..", "..", "build", "src", "webtransport"),
    ]
    for dp in dev_paths:
        for name in ("libxquic_wt_py.dylib", "libxquic_wt_py.so"):
            candidate = os.path.join(dp, name)
            if os.path.isfile(candidate):
                return os.path.abspath(candidate)

    # 4. System library path
    lib = ctypes.util.find_library("xquic_wt_py")
    if lib:
        return lib

    return None


_lib_path = _find_lib()
if _lib_path:
    lib = ffi.dlopen(_lib_path)
else:
    lib = None
