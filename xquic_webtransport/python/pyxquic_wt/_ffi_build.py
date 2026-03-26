"""
CFFI build script for pyxquic-wt.

Defines the C API surface that Python will bind to.
This is used by both ABI mode (dlopen) and API mode (compiled extension).
"""

import cffi

ffi = cffi.FFI()

# Minimal C declarations for the xquic WebTransport API.
# These are simplified from include/xquic/xqc_webtransport.h
# and will be expanded as needed.
ffi.cdef("""
    /* opaque types */
    typedef struct xqc_engine_s xqc_engine_t;
    typedef struct xqc_connection_s xqc_connection_t;
    typedef struct xqc_h3_conn_s xqc_h3_conn_t;
    typedef struct xqc_h3_stream_s xqc_h3_stream_t;
    typedef struct xqc_h3_request_s xqc_h3_request_t;

    typedef struct xqc_webtransport_conn_s xqc_wt_conn_t;
    typedef struct xqc_webtransport_session_s xqc_wt_session_t;
    typedef struct xqc_wt_unistream_s xqc_wt_unistream_t;
    typedef struct xqc_wt_bidistream_s xqc_wt_bidistream_t;

    typedef int xqc_int_t;
    typedef int xqc_bool_t;
    typedef uint64_t xqc_stream_id_t;

    /* cid */
    typedef struct {
        uint8_t cid_buf[20];
        uint8_t cid_len;
        uint64_t cid_seq_num;
        ...;
    } xqc_cid_t;

    /* http headers */
    typedef struct {
        struct {
            void *iov_base;
            size_t iov_len;
        } name;
        struct {
            void *iov_base;
            size_t iov_len;
        } value;
        uint8_t flags;
    } xqc_http_header_t;

    typedef struct {
        xqc_http_header_t *headers;
        size_t count;
        ...;
    } xqc_http_headers_t;

    /* WebTransport context init */
    xqc_int_t xqc_wt_ctx_init(
        xqc_engine_t *engine,
        void *dgram_cbs,
        void *session_cbs,
        void *stream_cbs
    );

    /* WebTransport session */
    xqc_wt_session_t *xqc_wt_session_init(
        uint64_t sessionID,
        xqc_wt_conn_t *wt_conn,
        xqc_h3_stream_t *h3_stream
    );

    /* WebTransport unistream */
    xqc_int_t xqc_wt_unistream_send(
        xqc_wt_unistream_t *wt_stream,
        void *data,
        uint32_t len,
        int fin
    );

    xqc_int_t xqc_wt_unistream_close(xqc_wt_unistream_t *wt_stream);

    /* WebTransport bidistream */
    xqc_int_t xqc_wt_bidistream_send(
        xqc_wt_bidistream_t *wt_bidistream,
        void *data,
        uint32_t len,
        int fin
    );

    /* WebTransport datagram */
    xqc_int_t xqc_webtransport_datagram_send(
        xqc_wt_conn_t *wt_conn,
        void *data,
        uint32_t size
    );

    /* connection helpers */
    xqc_connection_t *xqc_wt_session_get_conn(xqc_wt_session_t *wt_session);
    void xqc_wt_conn_set_dgram_mss(xqc_wt_conn_t *conn, size_t mss);
    xqc_int_t xqc_wt_conn_close(xqc_wt_conn_t *conn);
""")

ffi.set_source(
    "pyxquic_wt._pyxquic_wt_cffi",
    """
    #include <stdint.h>
    #include <stddef.h>
    /* Will link against libxquic at runtime via dlopen */
    """,
)

if __name__ == "__main__":
    ffi.compile(verbose=True)
