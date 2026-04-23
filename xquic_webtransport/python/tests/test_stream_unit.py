"""
Unit tests for stream types — no C library required.
Tests the async iterator protocol, queue semantics, and state management.
"""

import asyncio
import pytest

from pyxquic_wt._stream import BidiStream, ReceiveStream
from pyxquic_wt._server_stream import ServerBidiStream


class FakeConn:
    """Stub connection for testing stream without a real C handle."""
    _destroyed = False


@pytest.fixture
def bidi():
    return BidiStream(FakeConn(), stream_id=42)


@pytest.fixture
def recv_stream():
    return ReceiveStream(FakeConn(), stream_id=99)


# --- BidiStream ---

@pytest.mark.asyncio
async def test_bidi_read_all_with_fin(bidi):
    bidi._on_data(b"hello ", False)
    bidi._on_data(b"world", True)
    result = await bidi.read_all(timeout=1.0)
    assert result == b"hello world"


@pytest.mark.asyncio
async def test_bidi_read_all_timeout(bidi):
    bidi._on_data(b"partial", False)
    result = await bidi.read_all(timeout=0.1)
    assert result == b"partial"


@pytest.mark.asyncio
async def test_bidi_read_all_empty_fin(bidi):
    bidi._on_data(b"", True)
    result = await bidi.read_all(timeout=1.0)
    assert result == b""
    assert bidi._fin_received


@pytest.mark.asyncio
async def test_bidi_async_iterator(bidi):
    bidi._on_data(b"chunk1", False)
    bidi._on_data(b"chunk2", False)
    bidi._on_data(b"", True)

    chunks = []
    async for chunk in bidi:
        chunks.append(chunk)
        if bidi._fin_received:
            break
    assert b"chunk1" in chunks
    assert b"chunk2" in chunks


@pytest.mark.asyncio
async def test_bidi_aiter_protocol():
    """__aiter__ must return self (not a coroutine)."""
    stream = BidiStream(FakeConn(), stream_id=1)
    it = stream.__aiter__()
    assert it is stream
    assert not asyncio.iscoroutine(it)


# --- ReceiveStream ---

@pytest.mark.asyncio
async def test_recv_read_all_with_fin(recv_stream):
    recv_stream._on_data(b"data", True)
    result = await recv_stream.read_all(timeout=1.0)
    assert result == b"data"
    assert recv_stream._fin_received


@pytest.mark.asyncio
async def test_recv_read_all_multiple_chunks(recv_stream):
    recv_stream._on_data(b"a", False)
    recv_stream._on_data(b"b", False)
    recv_stream._on_data(b"c", True)
    result = await recv_stream.read_all(timeout=1.0)
    assert result == b"abc"


@pytest.mark.asyncio
async def test_recv_async_iterator(recv_stream):
    recv_stream._on_data(b"x", False)
    recv_stream._on_data(b"y", True)

    chunks = []
    async for chunk in recv_stream:
        chunks.append(chunk)
        if recv_stream._fin_received:
            break
    assert b"x" in chunks


@pytest.mark.asyncio
async def test_recv_aiter_protocol():
    """__aiter__ must return self (not a coroutine)."""
    stream = ReceiveStream(FakeConn(), stream_id=2)
    it = stream.__aiter__()
    assert it is stream
    assert not asyncio.iscoroutine(it)


@pytest.mark.asyncio
async def test_recv_context_manager():
    """ReceiveStream context manager should be a no-op on exit."""
    stream = ReceiveStream(FakeConn(), stream_id=3)
    async with stream as s:
        assert s is stream


# --- incremental read() ---

@pytest.mark.asyncio
async def test_bidi_read_max_bytes(bidi):
    """read(n) returns at most n bytes, buffers the rest."""
    bidi._on_data(b"hello world", False)
    chunk1 = await bidi.read(5, timeout=1.0)
    assert chunk1 == b"hello"
    chunk2 = await bidi.read(6, timeout=1.0)
    assert chunk2 == b" world"


@pytest.mark.asyncio
async def test_bidi_read_no_limit(bidi):
    """read() without max_bytes returns the full chunk."""
    bidi._on_data(b"all at once", True)
    data = await bidi.read(timeout=1.0)
    assert data == b"all at once"
    assert bidi._fin_received


@pytest.mark.asyncio
async def test_bidi_read_empty_after_fin(bidi):
    """read() returns b'' once FIN received and buffer drained."""
    bidi._on_data(b"x", True)
    await bidi.read(timeout=1.0)
    data = await bidi.read(timeout=0.05)
    assert data == b""


@pytest.mark.asyncio
async def test_recv_read_max_bytes(recv_stream):
    """ReceiveStream.read(n) returns at most n bytes."""
    recv_stream._on_data(b"abcdefgh", False)
    chunk = await recv_stream.read(3, timeout=1.0)
    assert chunk == b"abc"
    rest = await recv_stream.read(timeout=1.0)
    assert rest == b"defgh"


@pytest.mark.asyncio
async def test_bidi_read_across_chunks(bidi):
    """read(n) works when n spans multiple internal chunks."""
    bidi._on_data(b"aa", False)
    bidi._on_data(b"bb", True)
    # first read gets from first chunk only (one queue.get per call)
    chunk1 = await bidi.read(4, timeout=1.0)
    assert chunk1 == b"aa"
    chunk2 = await bidi.read(4, timeout=1.0)
    assert chunk2 == b"bb"


@pytest.mark.asyncio
async def test_server_bidi_read_max_bytes():
    """ServerBidiStream.read(n) returns at most n bytes."""
    stream = ServerBidiStream(None, session_id=1, stream_id=10)
    stream._on_data(b"server data", False)
    chunk = await stream.read(6, timeout=1.0)
    assert chunk == b"server"
    rest = await stream.read(timeout=1.0)
    assert rest == b" data"
