"""
WebTransport datagram (unreliable) transport.
"""

import asyncio
from typing import Optional


class DatagramManager:
    """Manages WebTransport datagram send/receive for a session."""

    def __init__(self, session=None):
        self._session = session
        self._recv_queue: asyncio.Queue[bytes] = asyncio.Queue()

    async def send(self, data: bytes) -> None:
        """Send an unreliable datagram."""
        # TODO: call xqc_webtransport_datagram_send via CFFI
        raise NotImplementedError("Will be implemented with CFFI bridge")

    async def recv(self) -> bytes:
        """Receive a datagram."""
        return await self._recv_queue.get()

    def _on_datagram_received(self, data: bytes):
        """Called by the event loop bridge when a datagram arrives."""
        self._recv_queue.put_nowait(data)
