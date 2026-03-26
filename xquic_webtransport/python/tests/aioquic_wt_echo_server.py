"""
aioquic-based WebTransport echo server for interop testing.

Accepts WebTransport sessions, echoes back data on bidi/uni streams.
"""

import asyncio
import logging
import os
import sys
from typing import Dict, Optional

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.asyncio.server import QuicServer
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import (
    H3Event,
    HeadersReceived,
    WebTransportStreamDataReceived,
    DatagramReceived,
)
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, ProtocolNegotiated, StreamReset

logger = logging.getLogger("wt-echo-server")


class WebTransportEchoServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._h3: Optional[H3Connection] = None
        self._session_ids: set = set()

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ProtocolNegotiated):
            self._h3 = H3Connection(self._quic, enable_webtransport=True)

        if self._h3 is not None:
            for h3_event in self._h3.handle_event(event):
                self._h3_event_received(h3_event)

    def _h3_event_received(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived):
            headers = dict(event.headers)
            if headers.get(b":method") == b"CONNECT" and headers.get(b":protocol") == b"webtransport":
                self._session_ids.add(event.stream_id)
                self._h3.send_headers(
                    stream_id=event.stream_id,
                    headers=[(b":status", b"200")],
                )
                path = headers.get(b":path", b"/").decode()
                logger.info(f"WebTransport session established: stream_id={event.stream_id} path={path}")
                self.transmit()

        elif isinstance(event, WebTransportStreamDataReceived):
            # Echo the data back directly on the QUIC stream (no H3 DATA framing for WT)
            self._quic.send_stream_data(
                event.stream_id,
                event.data,
                end_stream=event.stream_ended,
            )
            if event.data:
                logger.info(f"Echo bidi/uni: {len(event.data)} bytes, fin={event.stream_ended}")
            self.transmit()

        elif isinstance(event, DatagramReceived):
            # Echo datagram back
            self._h3.send_datagram(
                stream_id=event.stream_id,
                data=event.data,
            )
            logger.info(f"Echo datagram: {len(event.data)} bytes on stream {event.stream_id}")
            self.transmit()


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

    cert_dir = os.path.join(os.path.dirname(__file__), "..", "..", "certs")
    cert_file = os.path.join(cert_dir, "localhost.crt")
    key_file = os.path.join(cert_dir, "localhost.key")

    if not os.path.exists(cert_file):
        logger.error(f"Certificate not found: {cert_file}")
        sys.exit(1)

    configuration = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=False,
        max_datagram_frame_size=65536,
    )
    configuration.load_cert_chain(cert_file, key_file)

    host = "127.0.0.1"
    port = 4433

    server = await serve(
        host, port,
        configuration=configuration,
        create_protocol=WebTransportEchoServerProtocol,
    )

    logger.info(f"aioquic WebTransport echo server listening on {host}:{port}")

    try:
        await asyncio.Future()  # run forever
    except KeyboardInterrupt:
        pass
    finally:
        server.close()


if __name__ == "__main__":
    asyncio.run(main())
