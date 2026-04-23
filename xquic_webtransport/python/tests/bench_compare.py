"""
Performance benchmark: pyxquic-wt vs pywebtransport

Tests:
  1. Handshake latency
  2. Bidi echo (128B small messages)
  3. Bidi echo (64KB large messages)
  4. Concurrent streams (10x parallel send/recv)

Usage:
    python3.9 bench_compare.py
"""
from __future__ import annotations

import asyncio
import os
import ssl
import statistics
import sys
import time

HOST = "127.0.0.1"
BASE_PORT = 24400
CERT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "certs")
CERT_FILE = os.path.join(CERT_DIR, "localhost.crt")
KEY_FILE = os.path.join(CERT_DIR, "localhost.key")
WARMUP = 3
ITERATIONS = 30
LARGE_PAYLOAD = os.urandom(64 * 1024)
SMALL_PAYLOAD = b"x" * 128
STREAM_COUNT = 10

results: dict = {}


def record(lib, test, values):
    if test not in results:
        results[test] = {}
    avg = statistics.mean(values)
    results[test][lib] = avg
    p50 = statistics.median(values)
    p99 = sorted(values)[min(int(len(values) * 0.99), len(values) - 1)]
    print(f"  {lib:20s}  avg={avg*1000:8.2f}ms  p50={p50*1000:8.2f}ms  p99={p99*1000:8.2f}ms  (n={len(values)})")


# ===================================================================
# pyxquic-wt
# ===================================================================

async def xq_handshake(port):
    from pyxquic_wt import connect, serve
    async def noop(session):
        await asyncio.sleep(999)
    times = []
    async with serve(noop, host=HOST, port=port,
                     cert_file=CERT_FILE, key_file=KEY_FILE):
        await asyncio.sleep(0.3)
        for i in range(WARMUP + ITERATIONS):
            t0 = time.monotonic()
            async with connect(f"https://{HOST}:{port}/") as s:
                elapsed = time.monotonic() - t0
                if i >= WARMUP:
                    times.append(elapsed)
    record("pyxquic-wt", "handshake", times)


async def xq_echo_small(port):
    from pyxquic_wt import connect, serve
    async def echo(session):
        async for stream in session.incoming_bidirectional_streams():
            data = await stream.read_all(timeout=5)
            await stream.write_all(data, end_stream=True)
    times = []
    async with serve(echo, host=HOST, port=port,
                     cert_file=CERT_FILE, key_file=KEY_FILE):
        await asyncio.sleep(0.3)
        async with connect(f"https://{HOST}:{port}/echo") as session:
            for i in range(WARMUP + ITERATIONS):
                t0 = time.monotonic()
                await session.send_bidi(SMALL_PAYLOAD, fin=True)
                data = await session.recv(timeout=5)
                elapsed = time.monotonic() - t0
                if i >= WARMUP:
                    times.append(elapsed)
    record("pyxquic-wt", "echo_small_128B", times)


async def xq_echo_large(port):
    from pyxquic_wt import connect, serve
    async def echo(session):
        async for stream in session.incoming_bidirectional_streams():
            data = await stream.read_all(timeout=10)
            await stream.write_all(data, end_stream=True)
    times = []
    async with serve(echo, host=HOST, port=port,
                     cert_file=CERT_FILE, key_file=KEY_FILE):
        await asyncio.sleep(0.3)
        async with connect(f"https://{HOST}:{port}/echo") as session:
            for i in range(WARMUP + ITERATIONS):
                t0 = time.monotonic()
                await session.send_bidi(LARGE_PAYLOAD, fin=True)
                data = await session.recv(timeout=10)
                elapsed = time.monotonic() - t0
                if i >= WARMUP:
                    times.append(elapsed)
    record("pyxquic-wt", "echo_large_64KB", times)


async def xq_concurrent(port):
    from pyxquic_wt import connect, serve
    async def echo(session):
        async for stream in session.incoming_bidirectional_streams():
            data = await stream.read_all(timeout=5)
            await stream.write_all(data, end_stream=True)

    async def sr(session):
        await session.send_bidi(SMALL_PAYLOAD, fin=True)
        await session.recv(timeout=5)

    times = []
    async with serve(echo, host=HOST, port=port,
                     cert_file=CERT_FILE, key_file=KEY_FILE):
        await asyncio.sleep(0.3)
        async with connect(f"https://{HOST}:{port}/echo") as session:
            for i in range(WARMUP + ITERATIONS):
                t0 = time.monotonic()
                await asyncio.gather(*[sr(session) for _ in range(STREAM_COUNT)])
                elapsed = time.monotonic() - t0
                if i >= WARMUP:
                    times.append(elapsed)
    record("pyxquic-wt", f"concurrent_{STREAM_COUNT}_streams", times)


# ===================================================================
# pywebtransport
# ===================================================================

async def pwt_handshake(port):
    from pywebtransport import ServerApp, WebTransportClient
    from pywebtransport.config import ServerConfig, ClientConfig

    app = ServerApp(config=ServerConfig(
        bind_host=HOST, bind_port=port,
        certfile=CERT_FILE, keyfile=KEY_FILE,
    ))

    @app.route("/")
    async def handler(session):
        await asyncio.sleep(999)

    await app.startup()
    await asyncio.sleep(0.3)
    times = []
    try:
        for i in range(WARMUP + ITERATIONS):
            t0 = time.monotonic()
            client = WebTransportClient(config=ClientConfig(
                verify_mode=ssl.VerifyMode.CERT_NONE,
                check_hostname=False,
            ))
            await client.connect(f"https://{HOST}:{port}/")
            elapsed = time.monotonic() - t0
            if i >= WARMUP:
                times.append(elapsed)
            await client.close()
    finally:
        app.shutdown()
    record("pywebtransport", "handshake", times)


async def pwt_echo_small(port):
    from pywebtransport import ServerApp, WebTransportClient
    from pywebtransport.config import ServerConfig, ClientConfig

    app = ServerApp(config=ServerConfig(
        bind_host=HOST, bind_port=port,
        certfile=CERT_FILE, keyfile=KEY_FILE,
    ))

    @app.route("/echo")
    async def handler(session):
        async for stream in session.incoming_bidirectional_streams():
            data = await stream.read()
            await stream.write(data)
            await stream.close()

    await app.startup()
    await asyncio.sleep(0.3)
    times = []
    try:
        client = WebTransportClient(config=ClientConfig(
            verify_mode=ssl.VerifyMode.CERT_NONE,
            check_hostname=False,
        ))
        await client.connect(f"https://{HOST}:{port}/echo")

        for i in range(WARMUP + ITERATIONS):
            t0 = time.monotonic()
            stream = await client.create_bidirectional_stream()
            await stream.write(SMALL_PAYLOAD)
            await stream.close()
            data = await stream.read()
            elapsed = time.monotonic() - t0
            if i >= WARMUP:
                times.append(elapsed)

        await client.close()
    except Exception as e:
        print(f"  pywebtransport echo_small error: {e}")
        if not times:
            times = [float('inf')]
    finally:
        app.shutdown()
    record("pywebtransport", "echo_small_128B", times)


async def pwt_echo_large(port):
    from pywebtransport import ServerApp, WebTransportClient
    from pywebtransport.config import ServerConfig, ClientConfig

    app = ServerApp(config=ServerConfig(
        bind_host=HOST, bind_port=port,
        certfile=CERT_FILE, keyfile=KEY_FILE,
    ))

    @app.route("/echo")
    async def handler(session):
        async for stream in session.incoming_bidirectional_streams():
            data = await stream.read()
            await stream.write(data)
            await stream.close()

    await app.startup()
    await asyncio.sleep(0.3)
    times = []
    try:
        client = WebTransportClient(config=ClientConfig(
            verify_mode=ssl.VerifyMode.CERT_NONE,
            check_hostname=False,
        ))
        await client.connect(f"https://{HOST}:{port}/echo")

        for i in range(WARMUP + ITERATIONS):
            t0 = time.monotonic()
            stream = await client.create_bidirectional_stream()
            await stream.write(LARGE_PAYLOAD)
            await stream.close()
            data = await stream.read()
            elapsed = time.monotonic() - t0
            if i >= WARMUP:
                times.append(elapsed)

        await client.close()
    except Exception as e:
        print(f"  pywebtransport echo_large error: {e}")
        if not times:
            times = [float('inf')]
    finally:
        app.shutdown()
    record("pywebtransport", "echo_large_64KB", times)


async def pwt_concurrent(port):
    from pywebtransport import ServerApp, WebTransportClient
    from pywebtransport.config import ServerConfig, ClientConfig

    app = ServerApp(config=ServerConfig(
        bind_host=HOST, bind_port=port,
        certfile=CERT_FILE, keyfile=KEY_FILE,
    ))

    @app.route("/echo")
    async def handler(session):
        async for stream in session.incoming_bidirectional_streams():
            data = await stream.read()
            await stream.write(data)
            await stream.close()

    await app.startup()
    await asyncio.sleep(0.3)
    times = []

    async def sr(client):
        stream = await client.create_bidirectional_stream()
        await stream.write(SMALL_PAYLOAD)
        await stream.close()
        await stream.read()

    try:
        client = WebTransportClient(config=ClientConfig(
            verify_mode=ssl.VerifyMode.CERT_NONE,
            check_hostname=False,
        ))
        await client.connect(f"https://{HOST}:{port}/echo")

        for i in range(WARMUP + ITERATIONS):
            t0 = time.monotonic()
            await asyncio.gather(*[sr(client) for _ in range(STREAM_COUNT)])
            elapsed = time.monotonic() - t0
            if i >= WARMUP:
                times.append(elapsed)

        await client.close()
    except Exception as e:
        print(f"  pywebtransport concurrent error: {e}")
        if not times:
            times = [float('inf')]
    finally:
        app.shutdown()
    record("pywebtransport", f"concurrent_{STREAM_COUNT}_streams", times)


# ===================================================================
# Main
# ===================================================================

async def main():
    print("=" * 72)
    print("Performance Benchmark: pyxquic-wt vs pywebtransport")
    print(f"  Host: {HOST}, Small: {len(SMALL_PAYLOAD)}B, Large: {len(LARGE_PAYLOAD)//1024}KB")
    print(f"  Warmup: {WARMUP}, Iterations: {ITERATIONS}, Concurrent: {STREAM_COUNT}")
    print("=" * 72)

    port = BASE_PORT
    tests = [
        ("Handshake Latency",        xq_handshake,   pwt_handshake),
        ("Echo Small (128B)",        xq_echo_small,  pwt_echo_small),
        ("Echo Large (64KB)",        xq_echo_large,  pwt_echo_large),
        (f"Concurrent ({STREAM_COUNT}x)", xq_concurrent, pwt_concurrent),
    ]

    for idx, (name, xq_fn, pwt_fn) in enumerate(tests, 1):
        print(f"\n[{idx}] {name}")
        for fn, lib in [(xq_fn, "pyxquic-wt"), (pwt_fn, "pywebtransport")]:
            try:
                await fn(port)
            except Exception as e:
                print(f"  {lib} FAILED: {e}")
            port += 1

    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"{'Test':32s}  {'pyxquic-wt':>12s}  {'pywebtransport':>14s}  {'ratio':>8s}")
    print("-" * 72)
    for test, libs in results.items():
        xq = libs.get("pyxquic-wt", 0)
        pw = libs.get("pywebtransport", 0)
        if pw > 0 and pw < float('inf'):
            ratio = f"{xq/pw:.2f}x"
        else:
            ratio = "N/A"
        xq_s = f"{xq*1000:.2f}ms" if xq < float('inf') else "FAIL"
        pw_s = f"{pw*1000:.2f}ms" if pw < float('inf') else "FAIL"
        print(f"{test:32s}  {xq_s:>12s}  {pw_s:>14s}  {ratio:>8s}")
    print("=" * 72)
    print("ratio < 1.0 = pyxquic-wt is faster")


if __name__ == "__main__":
    asyncio.run(main())
