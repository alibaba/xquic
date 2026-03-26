"""
Low-level CFFI loader for libxquic.

Loads the xquic shared library and provides the FFI handle
for use by higher-level Python wrappers.
"""

import os
import sys
import ctypes.util
from cffi import FFI

ffi = FFI()

# Minimal cdef for ABI mode (dlopen).
# Keep in sync with _ffi_build.py declarations.
ffi.cdef("""
    typedef int xqc_int_t;
    typedef int xqc_bool_t;

    typedef struct xqc_engine_s xqc_engine_t;
    typedef struct xqc_connection_s xqc_connection_t;
    typedef struct xqc_webtransport_conn_s xqc_wt_conn_t;
    typedef struct xqc_webtransport_session_s xqc_wt_session_t;
    typedef struct xqc_wt_unistream_s xqc_wt_unistream_t;
    typedef struct xqc_wt_bidistream_s xqc_wt_bidistream_t;

    xqc_int_t xqc_wt_unistream_send(
        xqc_wt_unistream_t *wt_stream, void *data, uint32_t len, int fin);
    xqc_int_t xqc_wt_unistream_close(xqc_wt_unistream_t *wt_stream);
    xqc_int_t xqc_wt_bidistream_send(
        xqc_wt_bidistream_t *wt_bidistream, void *data, uint32_t len, int fin);
    xqc_int_t xqc_webtransport_datagram_send(
        xqc_wt_conn_t *wt_conn, void *data, uint32_t size);
    void xqc_wt_conn_set_dgram_mss(xqc_wt_conn_t *conn, size_t mss);
    xqc_int_t xqc_wt_conn_close(xqc_wt_conn_t *conn);
""")


def _find_libxquic():
    """Search for libxquic in common locations."""
    # 1. Environment variable
    env_path = os.environ.get("XQUIC_LIB_PATH")
    if env_path:
        for name in ("libxquic.so", "libxquic.dylib", "xquic.dll"):
            candidate = os.path.join(env_path, name)
            if os.path.isfile(candidate):
                return candidate

    # 2. Package directory (wheel ships the lib here)
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    for name in ("libxquic.so", "libxquic.dylib", "xquic.dll"):
        candidate = os.path.join(pkg_dir, name)
        if os.path.isfile(candidate):
            return candidate

    # 3. System library path
    lib = ctypes.util.find_library("xquic")
    if lib:
        return lib

    return None


_lib_path = _find_libxquic()
if _lib_path:
    lib = ffi.dlopen(_lib_path)
else:
    lib = None
