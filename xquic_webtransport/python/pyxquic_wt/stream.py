"""
WebTransport stream abstractions: BidiStream and UniStream.
"""

import asyncio
from typing import Optional


class BidiStream:
    """A bidirectional WebTransport stream."""

    def __init__(self, stream_handle=None, session=None):
        self._handle = stream_handle
        self._session = session
        self._recv_buffer = bytearray()
        self._recv_event = asyncio.Event()
        self._closed = False

    async def send(self, data: bytes, fin: bool = False) -> None:
        """Send data on this bidirectional stream."""
        if self._closed:
            raise RuntimeError("Stream is closed")
        # TODO: call xqc_wt_bidistream_send via CFFI
        raise NotImplementedError("Will be implemented with CFFI bridge")

    async def recv(self, max_bytes: int = 65536) -> bytes:
        """Receive data from this bidirectional stream."""
        if not self._recv_buffer and not self._closed:
            self._recv_event.clear()
            await self._recv_event.wait()

        data = bytes(self._recv_buffer[:max_bytes])
        del self._recv_buffer[:max_bytes]
        return data

    async def close(self) -> None:
        """Close this stream."""
        self._closed = True

    def _on_data_received(self, data: bytes):
        """Called by the event loop bridge when data arrives."""
        self._recv_buffer.extend(data)
        self._recv_event.set()


class UniStream:
    """A unidirectional WebTransport stream (send-only or recv-only)."""

    def __init__(self, stream_handle=None, session=None, direction: str = "send"):
        self._handle = stream_handle
        self._session = session
        self._direction = direction
        self._recv_buffer = bytearray()
        self._recv_event = asyncio.Event()
        self._closed = False

    async def send(self, data: bytes, fin: bool = False) -> None:
        """Send data on this unidirectional stream (send direction only)."""
        if self._direction != "send":
            raise RuntimeError("Cannot send on a receive-only stream")
        if self._closed:
            raise RuntimeError("Stream is closed")
        # TODO: call xqc_wt_unistream_send via CFFI
        raise NotImplementedError("Will be implemented with CFFI bridge")

    async def recv(self, max_bytes: int = 65536) -> bytes:
        """Receive data from this unidirectional stream (recv direction only)."""
        if self._direction != "recv":
            raise RuntimeError("Cannot recv on a send-only stream")

        if not self._recv_buffer and not self._closed:
            self._recv_event.clear()
            await self._recv_event.wait()

        data = bytes(self._recv_buffer[:max_bytes])
        del self._recv_buffer[:max_bytes]
        return data

    async def close(self) -> None:
        """Close this stream."""
        self._closed = True

    def _on_data_received(self, data: bytes):
        """Called by the event loop bridge when data arrives."""
        self._recv_buffer.extend(data)
        self._recv_event.set()
