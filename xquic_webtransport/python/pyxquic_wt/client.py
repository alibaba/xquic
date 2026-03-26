"""
WebTransport client.
"""

import asyncio
from typing import Optional, AsyncIterator
from urllib.parse import urlparse

from pyxquic_wt.session import WebTransportSession
from pyxquic_wt.stream import BidiStream, UniStream


class WebTransportClient:
    """
    Async WebTransport client powered by xquic.

    Usage:
        async with WebTransportClient("https://localhost:4443/echo") as client:
            stream = await client.create_bidi_stream()
            await stream.send(b"Hello!")
            data = await stream.recv()
    """

    def __init__(
        self,
        url: str,
        *,
        verify_cert: bool = True,
        cert_hash: Optional[str] = None,
    ):
        parsed = urlparse(url)
        self._host = parsed.hostname or "localhost"
        self._port = parsed.port or 443
        self._path = parsed.path or "/"
        self._scheme = parsed.scheme or "https"
        self._verify_cert = verify_cert
        self._cert_hash = cert_hash

        self._session: Optional[WebTransportSession] = None
        self._connected = False

    async def connect(self) -> "WebTransportClient":
        """Establish the WebTransport connection."""
        # TODO: Initialize xquic engine, create UDP socket,
        # call xqc_webtransport_connect(), and wait for session setup.
        self._session = WebTransportSession(path=self._path)
        self._connected = True
        return self

    async def close(self) -> None:
        """Close the connection."""
        if self._session:
            await self._session.close()
        self._connected = False

    async def create_bidi_stream(self) -> BidiStream:
        """Create a bidirectional stream."""
        if not self._session:
            raise RuntimeError("Not connected")
        return await self._session.create_bidi_stream()

    async def create_uni_stream(self) -> UniStream:
        """Create a unidirectional (send) stream."""
        if not self._session:
            raise RuntimeError("Not connected")
        return await self._session.create_uni_stream()

    async def incoming_bidi_streams(self) -> AsyncIterator[BidiStream]:
        """Iterate over incoming bidirectional streams."""
        if not self._session:
            raise RuntimeError("Not connected")
        async for stream in self._session.incoming_bidi_streams():
            yield stream

    async def incoming_uni_streams(self) -> AsyncIterator[UniStream]:
        """Iterate over incoming unidirectional streams."""
        if not self._session:
            raise RuntimeError("Not connected")
        async for stream in self._session.incoming_uni_streams():
            yield stream

    async def send_datagram(self, data: bytes) -> None:
        """Send an unreliable datagram."""
        if not self._session:
            raise RuntimeError("Not connected")
        await self._session.send_datagram(data)

    async def __aenter__(self) -> "WebTransportClient":
        return await self.connect()

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()
