"""
Extended WebTransport interop tests: large payload, binary data, zero-length, FIN separation.
Run against xquic wt_test_server (port 4443).
"""
import asyncio
import os
import ssl
import sys
import time

from aioquic.asyncio import connect
from aioquic.h3.connection import H3_ALPN, H3Connection, FrameType
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, ProtocolNegotiated
from aioquic.h3.events import (
    H3Event, HeadersReceived, WebTransportStreamDataReceived, DatagramReceived,
)

import logging
logger = logging.getLogger("wt-ext-test")


class WTClientProtocol(connect.__class__.__mro__[1] if False else object):
    pass

# reuse from echo client
sys.path.insert(0, os.path.dirname(__file__))
from aioquic_wt_echo_client import WebTransportEchoClientProtocol


async def run_extended_tests(host, port):
    cfg = QuicConfiguration(alpn_protocols=H3_ALPN, is_client=True,
                            max_datagram_frame_size=65535)
    cfg.verify_mode = ssl.CERT_NONE

    results = []
    start = time.time()

    async with connect(host, port, configuration=cfg,
                       create_protocol=WebTransportEchoClientProtocol) as protocol:

        # Setup session
        try:
            sid = await protocol.connect_webtransport("/echo")
            results.append(("session-setup", "PASS", f"sid={sid}"))
        except Exception as e:
            results.append(("session-setup", "FAIL", str(e)))
            return results

        # Test 1: Large payload (64KB)
        test = "bidi-echo-64kb"
        try:
            msg = os.urandom(64 * 1024)
            echo = await protocol.send_bidi_and_recv(sid, msg)
            if echo == msg:
                results.append((test, "PASS", f"{len(msg)} bytes"))
            else:
                results.append((test, "FAIL", f"mismatch: sent {len(msg)}, got {len(echo)}"))
        except Exception as e:
            results.append((test, "FAIL", str(e)))

        # Test 2: Binary data with null bytes
        test = "bidi-echo-binary"
        try:
            msg = bytes(range(256)) * 4  # 1024 bytes, all byte values including \x00
            echo = await protocol.send_bidi_and_recv(sid, msg)
            if echo == msg:
                results.append((test, "PASS", f"{len(msg)} bytes with \\x00"))
            else:
                results.append((test, "FAIL", f"mismatch"))
        except Exception as e:
            results.append((test, "FAIL", str(e)))

        # Test 3: Zero-length payload with FIN
        test = "bidi-echo-empty"
        try:
            msg = b""
            echo = await protocol.send_bidi_and_recv(sid, msg)
            if echo == msg:
                results.append((test, "PASS", "0 bytes"))
            else:
                results.append((test, "FAIL", f"got {len(echo)} bytes"))
        except asyncio.TimeoutError:
            results.append((test, "FAIL", "timeout (empty stream may not echo)"))
        except Exception as e:
            results.append((test, "FAIL", str(e)))

        # Test 4: Datagram echo
        test = "datagram-echo"
        try:
            dgram = b"datagram-test-payload-\x00\xff"
            protocol._h3.send_datagram(stream_id=sid, data=dgram)
            protocol.transmit()
            echo = await asyncio.wait_for(protocol._datagram_received.get(), timeout=3.0)
            if echo == dgram:
                results.append((test, "PASS", f"{len(dgram)} bytes"))
            else:
                results.append((test, "FAIL", f"mismatch: sent {dgram!r}, got {echo!r}"))
        except asyncio.TimeoutError:
            results.append((test, "FAIL", "timeout"))
        except Exception as e:
            results.append((test, "FAIL", str(e)))

        # Test 5: Multiple concurrent bidi streams
        test = "multi-bidi-5x"
        try:
            msgs = [os.urandom(512) for _ in range(5)]
            tasks = [protocol.send_bidi_and_recv(sid, m) for m in msgs]
            echoes = await asyncio.wait_for(asyncio.gather(*tasks), timeout=10.0)
            if all(e == m for e, m in zip(echoes, msgs)):
                results.append((test, "PASS", f"5 streams, {sum(len(m) for m in msgs)} bytes"))
            else:
                results.append((test, "FAIL", "data mismatch"))
        except Exception as e:
            results.append((test, "FAIL", str(e)))

        # Test 6: Large payload 256KB
        test = "bidi-echo-256kb"
        try:
            msg = os.urandom(256 * 1024)
            echo = await protocol.send_bidi_and_recv(sid, msg)
            if echo == msg:
                results.append((test, "PASS", f"{len(msg)} bytes"))
            else:
                results.append((test, "FAIL", f"mismatch: sent {len(msg)}, got {len(echo)}"))
        except Exception as e:
            results.append((test, "FAIL", str(e)))

    elapsed = time.time() - start
    print(f"\n{'='*60}")
    print(f"Extended WebTransport Tests ({host}:{port})")
    print(f"{'='*60}")
    passed = sum(1 for _, s, _ in results if s == "PASS")
    for name, status, detail in results:
        icon = "OK" if status == "PASS" else "FAIL"
        print(f"  [{icon}] {name}: {detail}")
    print(f"\n  {passed}/{len(results)} passed in {elapsed:.1f}s")
    print(f"{'='*60}\n")
    return results


async def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4443)
    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING)
    results = await run_extended_tests(args.host, args.port)
    failed = sum(1 for _, s, _ in results if s != "PASS")
    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    asyncio.run(main())
