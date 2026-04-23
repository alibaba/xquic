"""
WebTransport server: serve() async context manager with session routing.
"""
from __future__ import annotations

import asyncio
import logging
import signal
import socket
import struct
import sys
import time
from contextlib import asynccontextmanager
from typing import Callable, Optional

logger = logging.getLogger("pyxquic_wt")

from pyxquic_wt._cffi_defs import ffi, lib
from pyxquic_wt._defaults import (
    DEFAULT_PORT, DEFAULT_CERT_FILE, DEFAULT_KEY_FILE,
    POLL_INTERVAL_SEC, POLL_IDLE_INTERVAL_SEC, UDP_RECV_BUF_SIZE,
)
from pyxquic_wt._server_session import ServerSession
from pyxquic_wt._server_stream import ServerBidiStream


_EVENT_CREATED = 0
_EVENT_CLOSED = 1


class WebTransportServer:
    """Async WebTransport server powered by xquic."""

    def __init__(self, handle, host, port, handler, routes):
        self._handle = handle
        self._host = host
        self._port = port
        self._handler = handler
        self._routes = routes or {}
        self._closed = False
        self._destroyed = False

        self._loop = asyncio.get_running_loop()
        af = socket.AF_INET6 if ":" in host else socket.AF_INET
        self._sock = socket.socket(af, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.setblocking(False)
        self._sock.bind((host, port))

        self._local_addr = self._sock.getsockname()
        self._sessions: dict[int, ServerSession] = {}
        self._session_handlers: dict[int, Callable] = {}
        self._session_paths: dict[int, str] = {}
        self._session_id_counter = 0
        self._timer_handle = None
        self._poll_handle = None

        # CFFI callbacks — hold references
        self._c_send_cb = ffi.callback("xqc_wt_py_send_cb", self._on_send)
        self._c_timer_cb = ffi.callback("xqc_wt_py_timer_cb", self._on_timer)
        self._c_session_cb = ffi.callback("xqc_wt_py_session_cb", self._on_session)
        self._c_stream_cb = ffi.callback("xqc_wt_py_stream_cb", self._on_stream)
        self._c_data_cb = ffi.callback("xqc_wt_py_stream_data_cb", self._on_data)
        self._c_dgram_cb = ffi.callback("xqc_wt_py_dgram_cb", self._on_dgram)
        self._c_session_request_cb = ffi.callback(
            "xqc_wt_py_session_request_cb", self._on_session_request)

        lib.xqc_wt_py_server_set_callbacks(
            self._handle,
            self._c_send_cb, self._c_timer_cb,
            self._c_session_cb, self._c_stream_cb,
            self._c_data_cb, self._c_dgram_cb,
            ffi.NULL)

        if self._routes:
            lib.xqc_wt_py_server_set_session_request_cb(
                self._handle, self._c_session_request_cb)

    def _on_session_request(self, path_ptr, authority_ptr, session_id, user):
        path = ffi.string(path_ptr).decode("utf-8") if path_ptr else "/"
        authority = ffi.string(authority_ptr).decode("utf-8") if authority_ptr else ""

        if self._routes:
            handler = self._routes.get(path)
            if handler is None:
                return 0
            self._session_handlers[session_id] = handler

        self._session_paths[session_id] = path
        return 1

    def _on_send(self, data, length, peer, peer_len, user):
        buf = ffi.buffer(data, length)[:]
        try:
            raw = ffi.buffer(peer, peer_len)[:]
            port = struct.unpack("!H", raw[2:4])[0]
            addr = socket.inet_ntoa(raw[4:8])
            self._sock.sendto(buf, (addr, port))
        except BlockingIOError:
            lib.xqc_wt_py_server_set_send_eagain(self._handle)
        except (OSError, struct.error):
            lib.xqc_wt_py_server_set_send_eagain(self._handle)

    def _on_timer(self, wake_after_us, user):
        if self._timer_handle:
            self._timer_handle.cancel()
        delay = wake_after_us / 1_000_000
        self._timer_handle = self._loop.call_later(delay, self._process)

    def _on_session(self, event, session_id, user):
        if event == _EVENT_CREATED:
            self._session_id_counter += 1
            path = self._session_paths.pop(session_id, "/")
            session = ServerSession(session_id, self._handle, path=path)
            self._sessions[self._session_id_counter] = session
            self._sessions[session_id] = session
            handler = self._session_handlers.pop(session_id, self._handler)
            asyncio.ensure_future(self._run_handler(handler, session))
        elif event == _EVENT_CLOSED:
            session = self._sessions.pop(session_id, None)
            if session:
                session._closed = True
            self._session_handlers.pop(session_id, None)
            self._session_paths.pop(session_id, None)

    def _on_stream(self, event, session_id, stream_id, is_bidi, user):
        pass

    def _on_data(self, session_id, stream_id, data, length, fin, user):
        buf = bytes(ffi.buffer(data, length))
        session = self._sessions.get(session_id)
        if session:
            session._on_stream_data(stream_id, buf, bool(fin))

    def _on_dgram(self, session_id, data, length, user):
        buf = bytes(ffi.buffer(data, length))
        session = self._sessions.get(session_id)
        if session:
            session._on_datagram(buf)

    async def _run_handler(self, handler, session):
        try:
            await handler(session)
        except Exception:
            import traceback
            traceback.print_exc()

    @staticmethod
    def _build_sockaddr_in(host_str, port_int):
        ip_bytes = socket.inet_aton(host_str)
        port_n = struct.pack("!H", port_int)
        _is_bsd = sys.platform.startswith(("darwin", "freebsd", "openbsd", "netbsd"))
        if _is_bsd:
            return struct.pack("BB", 16, socket.AF_INET) + port_n + ip_bytes + b'\x00' * 8
        else:
            return struct.pack("H", socket.AF_INET) + port_n + ip_bytes + b'\x00' * 8

    def _on_readable(self):
        if self._destroyed:
            return
        local_sa = self._build_sockaddr_in(self._local_addr[0], self._local_addr[1])

        while True:
            try:
                data, addr = self._sock.recvfrom(UDP_RECV_BUF_SIZE)
            except (BlockingIOError, OSError):
                break

            recv_time_us = int(time.time() * 1_000_000)
            peer_sa = self._build_sockaddr_in(addr[0], addr[1])

            lib.xqc_wt_py_server_feed_packet(
                self._handle, data, len(data),
                local_sa, len(local_sa),
                peer_sa, len(peer_sa),
                recv_time_us)

        lib.xqc_wt_py_server_finish_recv(self._handle)
        lib.xqc_wt_py_server_process(self._handle)

    def _process(self):
        if self._destroyed:
            return
        lib.xqc_wt_py_server_process(self._handle)

    @property
    def _has_active_streams(self):
        return any(
            len(s._streams) > 0
            for s in self._sessions.values()
        )

    def _poll_tick(self):
        if self._destroyed:
            return
        self._on_readable()
        lib.xqc_wt_py_server_process(self._handle)
        if not self._closed and not self._destroyed:
            interval = POLL_INTERVAL_SEC if self._has_active_streams else POLL_IDLE_INTERVAL_SEC
            self._poll_handle = self._loop.call_later(interval, self._poll_tick)

    def _start(self):
        self._loop.add_reader(self._sock.fileno(), self._on_readable)
        self._poll_handle = self._loop.call_later(POLL_INTERVAL_SEC, self._poll_tick)

    async def close(self):
        if self._destroyed:
            return
        self._closed = True
        self._destroyed = True
        if self._timer_handle:
            self._timer_handle.cancel()
        if self._poll_handle:
            self._poll_handle.cancel()
        try:
            self._loop.remove_reader(self._sock.fileno())
        except (ValueError, OSError):
            pass
        if self._handle:
            lib.xqc_wt_py_server_destroy(self._handle)
            self._handle = None
        self._sock.close()


@asynccontextmanager
async def serve(
    handler: Optional[Callable] = None,
    *,
    routes: Optional[dict] = None,
    host: str = "0.0.0.0",
    port: int = DEFAULT_PORT,
    cert_file: str = DEFAULT_CERT_FILE,
    key_file: str = DEFAULT_KEY_FILE,
    idle_timeout: float = 30.0,
    congestion: str = "bbr",
):
    """
    Start a WebTransport server.

    Two modes:

    1. Single handler (backward compatible)::

        async def handler(session):
            async for stream in session.incoming_bidirectional_streams():
                data = await stream.read_all()
                await stream.write_all(data, end_stream=True)

        async with serve(handler, port=4443):
            await asyncio.Future()  # run forever

    2. Path-based routing::

        async with serve(routes={"/echo": echo_handler, "/chat": chat_handler}):
            await asyncio.Future()

        Sessions to unregistered paths are rejected (CLOSE capsule with 404).
    """
    if lib is None:
        raise RuntimeError("libxquic_wt_py not found.")

    if handler is None and not routes:
        raise ValueError("Either handler or routes must be provided")

    handle = lib.xqc_wt_py_server_create(
        cert_file.encode(), key_file.encode())
    if handle == ffi.NULL:
        raise RuntimeError(
            f"Failed to create WT server (check cert_file={cert_file}, key_file={key_file})")

    cc_type = 1 if congestion == "cubic" else 0
    lib.xqc_wt_py_server_set_config(
        handle, int(idle_timeout * 1000), 0, cc_type)

    _XQC_LOG_MAP = {0: logging.ERROR, 1: logging.WARNING,
                    2: logging.INFO, 3: logging.DEBUG}
    _log_cbs = []

    @ffi.callback("xqc_wt_py_log_cb")
    def _on_log(level, msg, length, user):
        py_level = _XQC_LOG_MAP.get(level, logging.DEBUG)
        if logger.isEnabledFor(py_level):
            logger.log(py_level, ffi.string(msg, length).decode("utf-8", errors="replace").rstrip())

    _log_cbs.append(_on_log)
    lib.xqc_wt_py_server_set_log_cb(handle, _on_log)

    server = WebTransportServer(handle, host, port, handler, routes)
    server._start()

    loop = asyncio.get_running_loop()
    shutdown = loop.create_future()

    def _signal_handler():
        if not shutdown.done():
            shutdown.set_result(True)

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            pass

    try:
        yield server
    finally:
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.remove_signal_handler(sig)
            except NotImplementedError:
                pass
        for session in list(server._sessions.values()):
            try:
                await session.drain()
            except Exception:
                pass
        await server.close()
