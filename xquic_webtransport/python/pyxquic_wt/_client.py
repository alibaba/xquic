"""
WebTransport client convenience API.

Provides two entry points:

    # Simple: connect to URL, get a session directly
    async with connect("https://host:4443/echo") as session:
        await session.send_bidi(b"Hello!")
        data = await session.recv()

    # Advanced: manage connection and sessions separately
    async with open_connection("https://host:4443") as conn:
        s1 = await conn.open_session("/echo")
        s2 = await conn.open_session("/chat")
        await s1.send_bidi(b"Hello echo!")
        await s2.send_bidi(b"Hello chat!")
"""

import logging

from contextlib import asynccontextmanager
from urllib.parse import urlparse

from pyxquic_wt._cffi_defs import ffi, lib
from pyxquic_wt._connection import WebTransportConnection
from pyxquic_wt._defaults import DEFAULT_PORT
from pyxquic_wt._session import WebTransportSession

logger = logging.getLogger("pyxquic_wt")

_XQC_LOG_MAP = {0: logging.ERROR, 1: logging.WARNING,
                2: logging.INFO, 3: logging.DEBUG}


@asynccontextmanager
async def open_connection(
    url: str,
    *,
    idle_timeout: float = 30.0,
    congestion: str = "bbr",
    log_level: int = 0,
):
    """Open a QUIC connection to a WebTransport server.

    Use ``conn.open_session(path)`` to create sessions.

    Usage::

        async with open_connection("https://host:4443") as conn:
            session = await conn.open_session("/echo")
            await session.send_bidi(b"Hello!")
    """
    if lib is None:
        raise RuntimeError(
            "libxquic_wt_py not found. Set XQUIC_LIB_PATH or build xquic first.")

    parsed = urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or DEFAULT_PORT

    handle = lib.xqc_wt_py_client_create(host.encode(), port, 1)
    if handle == ffi.NULL:
        raise RuntimeError("Failed to create WT client")

    cc_type = 1 if congestion == "cubic" else 0
    lib.xqc_wt_py_client_set_config(
        handle, int(idle_timeout * 1000), log_level, cc_type)

    _log_cbs = []
    if log_level > 0:
        @ffi.callback("xqc_wt_py_log_cb")
        def _on_log(level, msg, length, user):
            py_level = _XQC_LOG_MAP.get(level, logging.DEBUG)
            if logger.isEnabledFor(py_level):
                logger.log(py_level, ffi.string(msg, length).decode("utf-8", errors="replace").rstrip())
        _log_cbs.append(_on_log)
        lib.xqc_wt_py_client_set_log_cb(handle, _on_log)

    conn = WebTransportConnection(handle, host, port)
    try:
        await conn._establish()
        yield conn
    finally:
        await conn.close()


@asynccontextmanager
async def connect(
    url: str,
    *,
    cert_hash: str = None,
    idle_timeout: float = 30.0,
    congestion: str = "bbr",
    log_level: int = 0,
):
    """Connect to a WebTransport server and open a session.

    Convenience wrapper: creates connection + opens session in one step.

    Usage::

        async with connect("https://host:4443/echo") as session:
            await session.send_bidi(b"Hello!")
            data = await session.recv()

    Args:
        url: WebTransport URL (https://host:port/path)
        cert_hash: ignored for now (TLS verification is off)
        idle_timeout: connection idle timeout in seconds (default 30)
        congestion: congestion control algorithm ("bbr" or "cubic")
        log_level: C engine log level (0=error, 1=warn, 2=info, 3=debug)
    """
    parsed = urlparse(url)
    path = parsed.path or "/"
    # Remove path from url for connection
    base_url = f"https://{parsed.hostname or '127.0.0.1'}:{parsed.port or DEFAULT_PORT}"

    async with open_connection(base_url, idle_timeout=idle_timeout,
                               congestion=congestion, log_level=log_level) as conn:
        session = await conn.open_session(path)
        try:
            yield session
        finally:
            await session.close()
