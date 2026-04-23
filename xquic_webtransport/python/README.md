# pyxquic-wt

WebTransport client/server for Python, powered by the [xquic](https://github.com/alibaba/xquic) QUIC/HTTP3 C engine.

## Features

- **Full RFC 9297 WebTransport** — bidirectional streams, unidirectional streams, datagrams
- **Browser-compatible** — tested with Chrome 146+ and Safari 26+
- **Async/await API** — built on Python asyncio
- **Path-based routing** — `serve(routes={"/echo": handler, "/chat": chat})`
- **Session management** — accept/reject, close with error code, drain
- **High performance** — C-based QUIC engine, 2x-7x faster than aioquic (see [BENCHMARK.md](BENCHMARK.md))
- **Type annotations** — complete `.pyi` stubs for IDE support

## Architecture

```
User Code (async with connect / serve)
    |
    v
Entry Layer       _client.py / _server.py          asynccontextmanager
    |
    v
Connection Layer  _connection.py / WebTransportServer
    |               UDP socket + event loop
    v               CFFI callback registration
Session Layer     _session.py / _server_session.py
    |               stream/datagram routing
    v               per-session Queue
Stream Layer      _stream.py / _server_stream.py
    |               BidiStream / SendStream / ReceiveStream
    v
FFI Bridge        _cffi_defs.py                    ABI mode (dlopen)
    |               ~60 C function declarations
    v
C Flat API        xqc_wt_py_api.c                  opaque handles, no struct exposure
    |               ~1500 lines
    v
xquic Engine      QUIC + HTTP/3 + WebTransport     BoringSSL / BabaSSL
```

## Project Structure

```
xquic/
  src/webtransport/
    xqc_wt_py_api.c/h       # flat C API for Python (opaque handles)
    xqc_webtransport_ctx.c   # WT protocol core
    xqc_webtransport_session.c/h
    xqc_webtransport_stream.c/h
    xqc_webtransport_conn.c/h
    xqc_webtransport_wire.c/h  # capsule encode/decode
  scripts/
    build_wt_py.sh           # one-command build (BabaSSL or BoringSSL)
  .github/workflows/
    pyxquic-wt.yml           # test CI (multi-Python, multi-OS, multi-SSL)
    build-wheels.yml         # cibuildwheel + PyPI publish

  xquic_webtransport/python/           # pip-installable package
    pyproject.toml / setup.py          # packaging
    MANIFEST.in
    pyxquic_wt/                        # Python package
      __init__.py                      # public API: connect, serve, exceptions
      _client.py                       # connect() / open_connection()
      _connection.py                   # WebTransportConnection (UDP I/O + event loop)
      _session.py                      # WebTransportSession (stream/datagram API)
      _stream.py                       # BidiStream, SendStream, ReceiveStream
      _server.py                       # WebTransportServer + serve()
      _server_session.py               # ServerSession
      _server_stream.py                # ServerBidiStream
      _cffi_defs.py                    # CFFI ABI declarations (dlopen)
      _exceptions.py                   # exception hierarchy
      _defaults.py                     # configurable constants
      cli.py                           # pyxquic-wt gen-cert
      *.pyi                            # type stubs (8 files)
      py.typed                         # PEP 561 marker
    tests/
      test_wire.py                     # wire protocol unit tests (13)
      test_e2e_lowlevel.py             # C-layer E2E tests (7)
      test_stream_unit.py              # stream API unit tests (16)
      test_echo.py                     # basic import/smoke tests (4)
      test_e2e.py                      # high-level E2E tests (4)
      bench_compare.py                 # performance benchmark
    examples/
      echo_client.py
      echo_server.py
    BENCHMARK.md                       # performance comparison vs aioquic
    RELEASING.md                       # release/publish guide
```

## Installation

### From source

```bash
# Clone xquic with submodules
git clone --recursive https://github.com/alibaba/xquic.git
cd xquic

# Build the native library (default: BabaSSL)
bash scripts/build_wt_py.sh

# Or with BoringSSL (for public CI / PyPI)
SSL_BACKEND=boringssl bash scripts/build_wt_py.sh

# Install Python package
cd xquic_webtransport/python
pip install -e ".[cert]"
```

### Verify

```bash
python -c "from pyxquic_wt import serve; print('OK')"
```

## Quick Start

### 1. Generate certificates

```bash
# For Chrome (self-signed + serverCertificateHashes)
pyxquic-wt gen-cert

# For Safari (CA-signed + system trust)
pyxquic-wt gen-cert --ca --trust
```

### 2. Echo server

```python
import asyncio
from pyxquic_wt import serve

async def echo_handler(session):
    async for stream in session.incoming_bidirectional_streams():
        data = await stream.read_all()
        await stream.write_all(data, end_stream=True)

async def main():
    async with serve(echo_handler, port=4443,
                     cert_file="certs/server.crt",
                     key_file="certs/server.key"):
        print("Listening on :4443")
        await asyncio.Future()

asyncio.run(main())
```

### 3. Echo client

```python
import asyncio
from pyxquic_wt import connect

async def main():
    async with connect("https://localhost:4443/echo") as session:
        await session.send_bidi(b"Hello, WebTransport!")
        response = await session.recv()
        print(f"Echo: {response}")

asyncio.run(main())
```

## API Reference

### Server

```python
from pyxquic_wt import serve

# Single handler
async with serve(handler, port=4443, cert_file="cert.pem", key_file="key.pem"):
    await asyncio.Future()

# Path-based routing
async with serve(routes={"/echo": echo, "/chat": chat}, port=4443, ...):
    await asyncio.Future()

# Configuration
async with serve(handler,
    idle_timeout=30.0,    # seconds
    congestion="bbr",     # "bbr" or "cubic"
):
    ...
```

### Session (server-side)

```python
async def handler(session):
    session.path           # request path
    session.session_id     # unique ID

    # Bidi streams
    async for stream in session.incoming_bidirectional_streams():
        data = await stream.read_all()
        await stream.write_all(data, end_stream=True)

    # Incremental read
    chunk = await stream.read(max_bytes=1024)

    # Datagrams
    await session.send_datagram(b"unreliable")
    dgram = await session.recv_datagram()

    # Close / drain
    await session.close(error_code=42, reason="done")
    await session.drain()
```

### Client

```python
from pyxquic_wt import connect, open_connection

# Simple (one-shot bidi)
async with connect("https://host:4443/echo") as session:
    await session.send_bidi(b"data")
    echo = await session.recv()

# Batch send (optimized, single engine flush)
async with connect("https://host:4443/echo") as session:
    await session.send_bidi_batch([b"msg1", b"msg2", b"msg3"])
    for _ in range(3):
        data = await session.recv()

# Advanced (multi-stream)
async with open_connection("https://host:4443",
        idle_timeout=60, congestion="cubic", log_level=3) as conn:
    session = await conn.open_session("/echo")
    stream = await session.create_bidirectional_stream()
    await stream.write_all(b"hello", end_stream=True)
    data = await stream.read_all()

# Uni streams & datagrams
async with connect("https://host:4443/ep") as session:
    await session.send_uni(b"fire-and-forget")
    await session.send_datagram(b"low-latency")
    dgram = await session.recv_datagram(timeout=5.0)
```

### Stream

```python
# Read all until FIN
data = await stream.read_all(timeout=10.0)

# Incremental read
chunk = await stream.read(max_bytes=4096)

# Write
await stream.write_all(b"part1", end_stream=False)
await stream.write_all(b"part2", end_stream=True)

# Reset / stop
stream.reset(error_code=0)
stream.stop_sending(error_code=0)

# Async iterator
async for chunk in stream:
    process(chunk)
```

### Exceptions

```python
from pyxquic_wt import (
    WebTransportError,       # base
    QuicConnectionError,     # QUIC connection failed
    SessionClosedError,      # session closed (has .error_code, .reason)
    StreamResetError,        # RESET_STREAM (has .error_code)
    StreamStopError,         # STOP_SENDING (has .error_code)
    HandshakeError,          # TLS handshake failed
    SessionRejectedError,    # server rejected session (has .status_code)
)
```

## Browser Configuration

### Chrome

1. Open `chrome://flags/#webtransport-developer-mode` → **Enabled**
2. Relaunch Chrome
3. Use self-signed cert with `serverCertificateHashes`

### Safari

Safari requires a CA-signed certificate trusted by the system:

```bash
pyxquic-wt gen-cert --ca --trust
```

## Performance

Benchmark against aioquic 1.2.0 (pywebtransport core) on localhost:

| Test | pyxquic-wt | aioquic | |
|------|-----------|---------|--|
| Handshake | **3.95 ms** | 9.02 ms | 2.3x faster |
| Echo 128B | **0.51 ms** | 0.63 ms | 1.2x faster |
| Echo 64KB | **3.67 ms** | 27.40 ms | 7.5x faster |
| 10x Concurrent | 3.87 ms | 2.41 ms | 1.5x slower |

See [BENCHMARK.md](BENCHMARK.md) for full details.

## Testing

```bash
cd xquic_webtransport/python

# Run all tests (40 tests)
python -m pytest tests/test_wire.py tests/test_e2e_lowlevel.py \
    tests/test_echo.py tests/test_stream_unit.py -v

# Performance benchmark
python tests/bench_compare.py
```

## Requirements

- Python >= 3.9
- cffi >= 1.15
- cryptography >= 3.0 (optional, for `gen-cert` command)
- libxquic (built from source via `scripts/build_wt_py.sh`)

## License

Apache-2.0
