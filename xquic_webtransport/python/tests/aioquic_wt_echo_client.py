"""
aioquic-based WebTransport echo client for interop testing.

Connects to a WebTransport server, sends data on bidi stream,
receives echo, and reports result.
"""

import asyncio
import logging
import os
import sys
import time
from typing import Optional

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import (
    H3Event,
    HeadersReceived,
    WebTransportStreamDataReceived,
    DatagramReceived,
)
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, ProtocolNegotiated

logger = logging.getLogger("wt-echo-client")


class WebTransportEchoClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._h3: Optional[H3Connection] = None
        self._session_id: Optional[int] = None
        self._session_ready = asyncio.Event()
        self._received_data: dict = {}  # stream_id -> bytearray
        self._stream_done: dict = {}    # stream_id -> asyncio.Event
        self._datagram_received = asyncio.Queue()

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ProtocolNegotiated):
            self._h3 = H3Connection(self._quic, enable_webtransport=True)

        if self._h3 is not None:
            for h3_event in self._h3.handle_event(event):
                self._h3_event_received(h3_event)

    def _h3_event_received(self, event: H3Event) -> None:
        logger.debug(f"H3 event: {type(event).__name__}")

        if isinstance(event, HeadersReceived):
            headers = dict(event.headers)
            status = headers.get(b":status", b"")
            if status == b"200":
                self._session_id = event.stream_id
                self._session_ready.set()
                logger.info(f"WebTransport session ready: stream_id={event.stream_id}")

        elif isinstance(event, WebTransportStreamDataReceived):
            sid = event.stream_id
            if sid not in self._received_data:
                self._received_data[sid] = bytearray()
            self._received_data[sid].extend(event.data)
            if event.stream_ended:
                if sid in self._stream_done:
                    self._stream_done[sid].set()
                logger.info(f"Stream {sid} received: {len(self._received_data[sid])} bytes total, fin={event.stream_ended}")
            else:
                logger.debug(f"Stream {sid} chunk: {len(event.data)} bytes")

        elif isinstance(event, DatagramReceived):
            self._datagram_received.put_nowait(event.data)
            logger.info(f"Datagram received: {len(event.data)} bytes")
        else:
            logger.debug(f"Unhandled H3 event: {event}")

    async def connect_webtransport(self, path: str = "/") -> int:
        """Send Extended CONNECT to establish WebTransport session."""
        assert self._h3 is not None
        stream_id = self._quic.get_next_available_stream_id()
        self._h3.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"CONNECT"),
                (b":protocol", b"webtransport"),
                (b":scheme", b"https"),
                (b":authority", b"localhost"),
                (b":path", path.encode()),
            ],
        )
        self.transmit()

        await asyncio.wait_for(self._session_ready.wait(), timeout=5.0)
        return self._session_id

    async def send_bidi_and_recv(self, session_id: int, data: bytes) -> bytes:
        """Open a WebTransport bidi stream, send data, and receive the echo."""
        assert self._h3 is not None

        from aioquic.h3.connection import FrameType

        # create_webtransport_stream writes the WT stream header (frame type + session_id)
        stream_id = self._h3.create_webtransport_stream(
            session_id=session_id, is_unidirectional=False
        )

        # Mark the internal H3 stream so that incoming data is recognized as WT
        with self._h3._get_or_create_stream(stream_id) as stream:
            stream.frame_type = FrameType.WEBTRANSPORT_STREAM
            stream.session_id = session_id

        done_event = asyncio.Event()
        self._stream_done[stream_id] = done_event
        self._received_data[stream_id] = bytearray()

        # WT stream data goes directly on the QUIC stream (no H3 DATA framing)
        self._quic.send_stream_data(stream_id, data, end_stream=True)
        self.transmit()
        logger.info(f"Sent {len(data)} bytes on WT bidi stream {stream_id}")

        await asyncio.wait_for(done_event.wait(), timeout=5.0)
        return bytes(self._received_data[stream_id])


async def run_test(host: str, port: int, verify_cert: bool = False):
    """Run the echo interop test."""
    cert_dir = os.path.join(os.path.dirname(__file__), "..", "..", "certs")
    ca_cert = os.path.join(cert_dir, "localhost.crt")

    configuration = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=True,
        max_datagram_frame_size=65535,
    )

    if not verify_cert:
        configuration.verify_mode = False
    elif os.path.exists(ca_cert):
        configuration.load_verify_locations(ca_cert)

    results = []
    start = time.time()

    async with connect(host, port, configuration=configuration,
                       create_protocol=WebTransportEchoClientProtocol) as protocol:

        # Test 1: WebTransport session establishment
        test_name = "session-setup"
        try:
            session_id = await protocol.connect_webtransport("/echo")
            results.append((test_name, "PASS", f"session_id={session_id}"))
        except Exception as e:
            results.append((test_name, "FAIL", str(e)))
            return results

        # Test 2: Bidi stream echo - short message
        test_name = "bidi-echo-short"
        try:
            msg = b"Hello WebTransport!"
            echo = await protocol.send_bidi_and_recv(session_id, msg)
            if echo == msg:
                results.append((test_name, "PASS", f"{len(msg)} bytes"))
            else:
                results.append((test_name, "FAIL", f"expected {msg!r}, got {echo!r}"))
        except Exception as e:
            results.append((test_name, "FAIL", str(e)))

        # Test 3: Bidi stream echo - larger message
        test_name = "bidi-echo-1kb"
        try:
            msg = b"X" * 1024
            echo = await protocol.send_bidi_and_recv(session_id, msg)
            if echo == msg:
                results.append((test_name, "PASS", f"{len(msg)} bytes"))
            else:
                results.append((test_name, "FAIL", f"length mismatch: sent {len(msg)}, got {len(echo)}"))
        except Exception as e:
            results.append((test_name, "FAIL", str(e)))

        # Test 4: Bidi stream echo - 64KB
        test_name = "bidi-echo-64kb"
        try:
            msg = os.urandom(64 * 1024)
            echo = await protocol.send_bidi_and_recv(session_id, msg)
            if echo == msg:
                results.append((test_name, "PASS", f"{len(msg)} bytes"))
            else:
                results.append((test_name, "FAIL", f"length mismatch: sent {len(msg)}, got {len(echo)}"))
        except Exception as e:
            results.append((test_name, "FAIL", str(e)))

        # Test 5: Datagram echo
        test_name = "datagram-echo"
        try:
            dgram_msg = b"Datagram test payload"
            protocol._h3.send_datagram(stream_id=session_id, data=dgram_msg)
            protocol.transmit()
            logger.info(f"Sent datagram: {len(dgram_msg)} bytes")

            dgram_echo = await asyncio.wait_for(
                protocol._datagram_received.get(), timeout=3.0
            )
            if dgram_echo == dgram_msg:
                results.append((test_name, "PASS", f"{len(dgram_msg)} bytes"))
            else:
                results.append((test_name, "FAIL", f"expected {dgram_msg!r}, got {dgram_echo!r}"))
        except asyncio.TimeoutError:
            results.append((test_name, "FAIL", "timeout waiting for datagram echo"))
        except Exception as e:
            results.append((test_name, "FAIL", str(e)))

        # Test 6: Multiple concurrent bidi streams
        test_name = "multi-bidi-concurrent"
        try:
            msgs = [os.urandom(256) for _ in range(5)]
            tasks = [protocol.send_bidi_and_recv(session_id, m) for m in msgs]
            echoes = await asyncio.wait_for(asyncio.gather(*tasks), timeout=10.0)
            all_ok = all(e == m for e, m in zip(echoes, msgs))
            if all_ok:
                results.append((test_name, "PASS", f"5 streams, {sum(len(m) for m in msgs)} bytes"))
            else:
                results.append((test_name, "FAIL", "data mismatch in concurrent streams"))
        except Exception as e:
            results.append((test_name, "FAIL", str(e)))

    elapsed = time.time() - start

    # Print results
    print(f"\n{'='*60}")
    print(f"WebTransport Interop Test Results ({host}:{port})")
    print(f"{'='*60}")
    passed = sum(1 for _, s, _ in results if s == "PASS")
    total = len(results)
    for name, status, detail in results:
        icon = "OK" if status == "PASS" else "FAIL"
        print(f"  [{icon}] {name}: {detail}")
    print(f"\n  {passed}/{total} passed in {elapsed:.1f}s")
    print(f"{'='*60}\n")

    return results


async def main():
    import argparse
    parser = argparse.ArgumentParser(description="WebTransport echo client interop test")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4433)
    parser.add_argument("--verify-cert", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

    results = await run_test(args.host, args.port, args.verify_cert)
    failed = sum(1 for _, s, _ in results if s != "PASS")
    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    asyncio.run(main())
