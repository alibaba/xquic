"""
asyncio <-> xquic event loop bridge.

Integrates xquic's callback-driven model with Python's asyncio event loop:
- UDP socket readability -> xqc_engine_packet_process()
- xquic timer callbacks  -> asyncio.call_later()
- xquic data callbacks   -> asyncio.Future.set_result()
"""

import asyncio
import socket
from typing import Optional, Callable


class XquicEventLoop:
    """Bridges xquic's event model to asyncio."""

    def __init__(self, loop: Optional[asyncio.AbstractEventLoop] = None):
        self._loop = loop or asyncio.get_event_loop()
        self._udp_sock: Optional[socket.socket] = None
        self._timer_handle: Optional[asyncio.TimerHandle] = None

    def create_udp_socket(self, host: str, port: int, is_server: bool = False) -> socket.socket:
        """Create and bind/connect a UDP socket, register with asyncio."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if is_server:
            sock.bind((host, port))
        # Client sockets are not bound; they connect on first send.

        self._udp_sock = sock
        return sock

    def register_reader(self, fd: int, callback: Callable):
        """Register a file descriptor for read readiness."""
        self._loop.add_reader(fd, callback)

    def unregister_reader(self, fd: int):
        """Unregister a file descriptor."""
        self._loop.remove_reader(fd)

    def schedule_timer(self, delay_ms: float, callback: Callable):
        """Schedule a timer callback (replaces any pending timer)."""
        if self._timer_handle:
            self._timer_handle.cancel()
        self._timer_handle = self._loop.call_later(delay_ms / 1000.0, callback)

    def close(self):
        """Clean up resources."""
        if self._timer_handle:
            self._timer_handle.cancel()
            self._timer_handle = None
        if self._udp_sock:
            fd = self._udp_sock.fileno()
            if fd >= 0:
                try:
                    self._loop.remove_reader(fd)
                except (ValueError, OSError):
                    pass
            self._udp_sock.close()
            self._udp_sock = None
