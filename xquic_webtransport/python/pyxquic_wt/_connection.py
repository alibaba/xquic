"""
WebTransportConnection — manages a single QUIC connection to a server.
"""

from __future__ import annotations

import asyncio
import socket
import struct
import sys
import time

from pyxquic_wt._cffi_defs import ffi, lib
from pyxquic_wt._defaults import (
    HANDSHAKE_TIMEOUT, SESSION_OPEN_TIMEOUT,
    POLL_INTERVAL_SEC, POLL_IDLE_INTERVAL_SEC, UDP_RECV_BUF_SIZE,
)
from pyxquic_wt._exceptions import QuicConnectionError
from pyxquic_wt._session import WebTransportSession


_EVENT_CREATED = 0
_EVENT_CLOSED = 1
_EVENT_HANDSHAKE_DONE = 2


class WebTransportConnection:
    """A QUIC connection to a WebTransport server.

    Owns the UDP socket, CFFI callbacks, and event loop integration.
    Use ``open_session(path)`` to create independent session objects.
    """

    def __init__(self, handle, host: str, port: int):
        self._handle = handle
        self._host = host
        self._port = port
        self._destroyed = False

        self._loop = asyncio.get_running_loop()
        # Detect address family from host
        af = socket.AF_INET6 if ":" in host else socket.AF_INET
        self._sock = socket.socket(af, socket.SOCK_DGRAM)
        self._sock.setblocking(False)

        self._handshake_done = self._loop.create_future()
        self._session_queue = asyncio.Queue()

        # session_id -> WebTransportSession
        self._sessions: dict[int, WebTransportSession] = {}

        # temp storage for create_uni_stream → SendStream id
        self._last_send_stream_id: int | None = None

        self._timer_handle = None
        self._poll_handle = None

        # CFFI callbacks — prevent GC
        self._c_send_cb = ffi.callback("xqc_wt_py_send_cb", self._on_send)
        self._c_timer_cb = ffi.callback("xqc_wt_py_timer_cb", self._on_timer)
        self._c_session_cb = ffi.callback("xqc_wt_py_session_cb", self._on_session)
        self._c_stream_cb = ffi.callback("xqc_wt_py_stream_cb", self._on_stream)
        self._c_data_cb = ffi.callback("xqc_wt_py_stream_data_cb", self._on_data)
        self._c_dgram_cb = ffi.callback("xqc_wt_py_dgram_cb", self._on_dgram)

        lib.xqc_wt_py_client_set_callbacks(
            self._handle,
            self._c_send_cb, self._c_timer_cb,
            self._c_session_cb, self._c_stream_cb,
            self._c_data_cb, self._c_dgram_cb,
            ffi.NULL)

    # ---- properties (Phase 3: diagnostics) ----

    @property
    def is_connected(self) -> bool:
        return self._handle is not None and not self._destroyed

    @property
    def srtt_us(self) -> int:
        """Smoothed RTT in microseconds."""
        if not self._handle:
            return 0
        return lib.xqc_wt_py_client_get_srtt(self._handle)

    @property
    def srtt_ms(self) -> float:
        """Smoothed RTT in milliseconds."""
        return self.srtt_us / 1000.0

    @property
    def send_count(self) -> int:
        """Number of packets sent."""
        if not self._handle:
            return 0
        return lib.xqc_wt_py_client_get_send_count(self._handle)

    @property
    def recv_count(self) -> int:
        """Number of packets received."""
        if not self._handle:
            return 0
        return lib.xqc_wt_py_client_get_recv_count(self._handle)

    @property
    def session_count(self) -> int:
        """Number of active sessions."""
        if not self._handle:
            return 0
        return lib.xqc_wt_py_client_get_session_count(self._handle)

    # ---- session management ----

    async def open_session(self, path: str) -> WebTransportSession:
        """Open a WebTransport session on this connection.

        Args:
            path: The WT endpoint path (e.g. "/echo")

        Returns:
            An independent WebTransportSession object.
        """
        if self._destroyed:
            raise RuntimeError("Connection is closed")
        ret = lib.xqc_wt_py_open_session(
            self._handle, path.encode(), self._host.encode())
        if ret < 0:
            raise QuicConnectionError(f"open_session failed: {ret}")

        session_id = await asyncio.wait_for(
            self._session_queue.get(), timeout=SESSION_OPEN_TIMEOUT)
        session = WebTransportSession(self, session_id)
        self._sessions[session_id] = session
        return session

    def _pop_last_send_stream_id(self) -> int | None:
        sid = self._last_send_stream_id
        self._last_send_stream_id = None
        return sid

    # ---- CFFI callbacks ----

    def _on_send(self, data, length, peer, peer_len, user):
        buf = ffi.buffer(data, length)[:]
        try:
            self._sock.sendto(buf, (self._host, self._port))
        except (BlockingIOError, OSError):
            lib.xqc_wt_py_client_set_send_eagain(self._handle)

    def _on_timer(self, wake_after_us, user):
        if self._timer_handle:
            self._timer_handle.cancel()
        delay = wake_after_us / 1_000_000
        self._timer_handle = self._loop.call_later(delay, self._process)

    def _on_session(self, event, session_id, user):
        if event == _EVENT_HANDSHAKE_DONE:
            if not self._handshake_done.done():
                self._handshake_done.set_result(True)
        elif event == _EVENT_CREATED:
            self._session_queue.put_nowait(session_id)
        elif event == _EVENT_CLOSED:
            session = self._sessions.get(session_id)
            if session:
                session._closed = True

    def _on_stream(self, event, session_id, stream_id, is_bidi, user):
        if event == _EVENT_CREATED:
            session = self._sessions.get(session_id)
            if session:
                if is_bidi:
                    session._on_stream_created(stream_id, True)
                else:
                    session._on_stream_created(stream_id, False)
            if not is_bidi:
                # store for create_unidirectional_stream() to pick up
                self._last_send_stream_id = stream_id

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

    # ---- network I/O ----

    @staticmethod
    def _build_sockaddr_in(host_str, port_int):
        ip_bytes = socket.inet_aton(host_str)
        port_n = struct.pack("!H", port_int)
        # BSD variants (macOS, FreeBSD, OpenBSD) use sin_len + sin_family (1+1 bytes)
        # Linux uses sa_family (2 bytes, little-endian)
        _is_bsd = sys.platform.startswith(("darwin", "freebsd", "openbsd", "netbsd"))
        if _is_bsd:
            return struct.pack("BB", 16, socket.AF_INET) + port_n + ip_bytes + b'\x00' * 8
        else:
            return struct.pack("H", socket.AF_INET) + port_n + ip_bytes + b'\x00' * 8

    def _on_readable(self):
        if self._destroyed:
            return
        local_sa = self._build_sockaddr_in("0.0.0.0", 0)
        while True:
            try:
                data, addr = self._sock.recvfrom(UDP_RECV_BUF_SIZE)
            except (BlockingIOError, OSError):
                break
            recv_time_us = int(time.time() * 1_000_000)
            peer_sa = self._build_sockaddr_in(addr[0], addr[1])
            lib.xqc_wt_py_client_feed_packet(
                self._handle, data, len(data),
                local_sa, len(local_sa),
                peer_sa, len(peer_sa),
                recv_time_us)
        lib.xqc_wt_py_client_finish_recv(self._handle)
        lib.xqc_wt_py_client_process(self._handle)

    def _process(self):
        if self._destroyed:
            return
        lib.xqc_wt_py_client_process(self._handle)

    @property
    def _has_active_streams(self):
        return any(
            len(s._streams) > 0 or len(s._recv_streams) > 0
            for s in self._sessions.values()
        )

    def _poll_tick(self):
        if self._destroyed:
            return
        self._on_readable()
        lib.xqc_wt_py_client_process(self._handle)
        if not self._destroyed:
            interval = POLL_INTERVAL_SEC if self._has_active_streams else POLL_IDLE_INTERVAL_SEC
            self._poll_handle = self._loop.call_later(interval, self._poll_tick)

    # ---- lifecycle ----

    async def _establish(self):
        """Internal: start I/O and complete QUIC handshake."""
        self._loop.add_reader(self._sock.fileno(), self._on_readable)
        self._poll_handle = self._loop.call_later(POLL_INTERVAL_SEC, self._poll_tick)

        ret = lib.xqc_wt_py_client_connect(self._handle)
        if ret < 0:
            raise QuicConnectionError(f"QUIC connect failed: {ret}")

        await asyncio.wait_for(self._handshake_done, timeout=HANDSHAKE_TIMEOUT)

    async def close(self):
        """Close the QUIC connection and all sessions."""
        if self._destroyed:
            return
        self._destroyed = True
        for session in self._sessions.values():
            session._closed = True
        if self._timer_handle:
            self._timer_handle.cancel()
            self._timer_handle = None
        if self._poll_handle:
            self._poll_handle.cancel()
            self._poll_handle = None
        try:
            self._loop.remove_reader(self._sock.fileno())
        except (ValueError, OSError):
            pass
        if self._handle:
            lib.xqc_wt_py_client_close(self._handle)
            lib.xqc_wt_py_client_destroy(self._handle)
            self._handle = None
        self._sock.close()
