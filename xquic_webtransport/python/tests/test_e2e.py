"""
End-to-end tests: xquic WT server + client (bidi echo, uni stream, datagram).

Requires:
  - libxquic_wt_py.{so,dylib} built and discoverable (XQUIC_LIB_PATH or LD_LIBRARY_PATH)
  - TLS cert/key pair at certs/localhost.{crt,key}  (self-signed is fine)

Run with:
    pytest tests/test_e2e.py -v
"""

import asyncio
import os
import pathlib
import sys

import pytest

# ---- availability guard --------------------------------------------------- #
_LIB_AVAILABLE = False
try:
    from pyxquic_wt._cffi_defs import lib
    if lib is not None:
        _LIB_AVAILABLE = True
except Exception:
    pass

_CERT_DIR = pathlib.Path(__file__).resolve().parent.parent.parent / "certs"
_CERT_FILE = _CERT_DIR / "localhost.crt"
_KEY_FILE = _CERT_DIR / "localhost.key"
_CERTS_EXIST = _CERT_FILE.exists() and _KEY_FILE.exists()

skip_no_lib = pytest.mark.skipif(
    not _LIB_AVAILABLE, reason="libxquic_wt_py not available")
skip_no_certs = pytest.mark.skipif(
    not _CERTS_EXIST, reason="certs/localhost.{crt,key} not found")

_PORT = int(os.environ.get("WT_TEST_PORT", "14443"))

# ---- helpers --------------------------------------------------------------- #

async def _echo_handler(session):
    """Echo handler: read from each bidi stream, echo back with FIN."""
    async for stream in session.incoming_bidirectional_streams():
        data = await stream.read_all(timeout=5.0)
        await stream.write_all(data, end_stream=True)


# ---- tests ----------------------------------------------------------------- #

@skip_no_lib
@skip_no_certs
@pytest.mark.asyncio
async def test_bidi_echo():
    """Client opens bidi stream, sends payload, server echoes it back."""
    from pyxquic_wt import connect, serve

    async with serve(
        _echo_handler,
        host="127.0.0.1", port=_PORT,
        cert_file=str(_CERT_FILE), key_file=str(_KEY_FILE),
    ):
        await asyncio.sleep(0.2)  # let server bind

        async with connect(f"https://127.0.0.1:{_PORT}/echo") as session:
            stream = await session.create_bidirectional_stream()
            await stream.write_all(b"Hello, WebTransport!", end_stream=True)
            echo = await stream.read_all(timeout=5.0)
            assert echo == b"Hello, WebTransport!"


@skip_no_lib
@skip_no_certs
@pytest.mark.asyncio
async def test_bidi_large_payload():
    """Echo a 64 KB payload over bidi stream."""
    from pyxquic_wt import connect, serve

    payload = os.urandom(65536)

    async with serve(
        _echo_handler,
        host="127.0.0.1", port=_PORT + 1,
        cert_file=str(_CERT_FILE), key_file=str(_KEY_FILE),
    ):
        await asyncio.sleep(0.2)

        async with connect(f"https://127.0.0.1:{_PORT + 1}/echo") as session:
            stream = await session.create_bidirectional_stream()
            await stream.write_all(payload, end_stream=True)
            echo = await stream.read_all(timeout=10.0)
            assert echo == payload


@skip_no_lib
@skip_no_certs
@pytest.mark.asyncio
async def test_multiple_bidi_streams():
    """Open 3 bidi streams concurrently and verify each echoes correctly."""
    from pyxquic_wt import connect, serve

    async with serve(
        _echo_handler,
        host="127.0.0.1", port=_PORT + 2,
        cert_file=str(_CERT_FILE), key_file=str(_KEY_FILE),
    ):
        await asyncio.sleep(0.2)

        async with connect(f"https://127.0.0.1:{_PORT + 2}/echo") as session:
            results = []
            for i in range(3):
                msg = f"stream-{i}".encode()
                stream = await session.create_bidirectional_stream()
                await stream.write_all(msg, end_stream=True)
                echo = await stream.read_all(timeout=5.0)
                results.append((msg, echo))

            for sent, received in results:
                assert sent == received


@skip_no_lib
@skip_no_certs
@pytest.mark.asyncio
async def test_session_close():
    """Verify session can be closed without error."""
    from pyxquic_wt import connect, serve

    async with serve(
        _echo_handler,
        host="127.0.0.1", port=_PORT + 3,
        cert_file=str(_CERT_FILE), key_file=str(_KEY_FILE),
    ):
        await asyncio.sleep(0.2)

        async with connect(f"https://127.0.0.1:{_PORT + 3}/echo") as session:
            stream = await session.create_bidirectional_stream()
            await stream.write_all(b"bye", end_stream=True)
            await stream.read_all(timeout=3.0)
        # session is closed by context manager — should not raise
