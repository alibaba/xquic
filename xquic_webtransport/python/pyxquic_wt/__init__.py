"""
pyxquic-wt: WebTransport client/server powered by xquic QUIC/HTTP3 stack.

Usage (client):
    from pyxquic_wt import connect
    async with connect("https://host:4443/echo") as session:
        await session.send_bidi(b"Hello!")

Usage (server):
    from pyxquic_wt import serve
    async with serve(handler, port=4443, cert_file="cert.pem", key_file="key.pem"):
        await asyncio.Future()
"""

from pyxquic_wt._client import connect, open_connection
from pyxquic_wt._server import serve
from pyxquic_wt._exceptions import (
    WebTransportError,
    QuicConnectionError,
    SessionClosedError,
    StreamResetError,
    StreamStopError,
    HandshakeError,
    SessionRejectedError,
)

__version__ = "0.1.0"
__all__ = [
    "connect", "open_connection", "serve",
    "WebTransportError", "QuicConnectionError", "SessionClosedError",
    "StreamResetError", "StreamStopError", "HandshakeError",
    "SessionRejectedError",
]
