"""
WebTransport session abstraction.
"""

import asyncio
from typing import Optional, AsyncIterator

from pyxquic_wt.stream import BidiStream, UniStream


class WebTransportSession:
    """Represents a WebTransport session (one per Extended CONNECT request)."""

    def __init__(self, session_handle=None, path: str = "/", remote_addr: str = ""):
        self._handle = session_handle
        self.path = path
        self.remote_addr = remote_addr
        self._bidi_queue: asyncio.Queue[BidiStream] = asyncio.Queue()
        self._uni_queue: asyncio.Queue[UniStream] = asyncio.Queue()
        self._closed = False

    async def create_bidi_stream(self) -> BidiStream:
        """Create a new bidirectional stream on this session."""
        # TODO: call xqc_wt_create_bidistream via CFFI
        stream = BidiStream(session=self)
        return stream

    async def create_uni_stream(self) -> UniStream:
        """Create a new unidirectional (send) stream on this session."""
        # TODO: call xqc_wt_create_unistream via CFFI
        stream = UniStream(session=self, direction="send")
        return stream

    async def incoming_bidi_streams(self) -> AsyncIterator[BidiStream]:
        """Async iterator over incoming bidirectional streams."""
        while not self._closed:
            try:
                stream = await asyncio.wait_for(self._bidi_queue.get(), timeout=1.0)
                yield stream
            except asyncio.TimeoutError:
                continue

    async def incoming_uni_streams(self) -> AsyncIterator[UniStream]:
        """Async iterator over incoming unidirectional streams."""
        while not self._closed:
            try:
                stream = await asyncio.wait_for(self._uni_queue.get(), timeout=1.0)
                yield stream
            except asyncio.TimeoutError:
                continue

    async def send_datagram(self, data: bytes) -> None:
        """Send an unreliable datagram on this session."""
        # TODO: call xqc_webtransport_datagram_send via CFFI
        raise NotImplementedError("Will be implemented with CFFI bridge")

    async def close(self) -> None:
        """Close this session."""
        self._closed = True

    def _on_bidi_stream_created(self, stream: BidiStream):
        """Called when a remote peer creates a bidi stream."""
        self._bidi_queue.put_nowait(stream)

    def _on_uni_stream_created(self, stream: UniStream):
        """Called when a remote peer creates a uni stream."""
        self._uni_queue.put_nowait(stream)
