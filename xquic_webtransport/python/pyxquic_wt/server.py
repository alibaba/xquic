"""
WebTransport server.
"""

import asyncio
from typing import Optional, Callable, Awaitable

from pyxquic_wt.session import WebTransportSession


class WebTransportServer:
    """
    Async WebTransport server powered by xquic.

    Usage:
        async def handle_session(session):
            async for stream in session.incoming_bidi_streams():
                data = await stream.recv()
                await stream.send(data)  # echo

        server = WebTransportServer(
            host="0.0.0.0", port=4443,
            cert_file="certs/localhost.crt",
            key_file="certs/localhost.key",
        )
        server.on_session = handle_session
        await server.serve_forever()
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 4443,
        cert_file: str = "",
        key_file: str = "",
    ):
        self._host = host
        self._port = port
        self._cert_file = cert_file
        self._key_file = key_file
        self._running = False

        self.on_session: Optional[Callable[[WebTransportSession], Awaitable[None]]] = None

    async def serve_forever(self) -> None:
        """Start serving and block until cancelled."""
        if not self._cert_file or not self._key_file:
            raise ValueError("cert_file and key_file are required")

        # TODO: Initialize xquic engine with WT callbacks,
        # create UDP socket, bind, and enter event loop.
        self._running = True

        try:
            while self._running:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass
        finally:
            await self.close()

    async def close(self) -> None:
        """Stop the server."""
        self._running = False

    async def _handle_new_session(self, session: WebTransportSession) -> None:
        """Called when a new WebTransport session is established."""
        if self.on_session:
            asyncio.create_task(self.on_session(session))
