"""
WebTransportSession — an independent session object bound to a connection.
"""
from __future__ import annotations

import asyncio
from collections import deque

from pyxquic_wt._cffi_defs import ffi, lib
from pyxquic_wt._defaults import STREAM_READ_TIMEOUT, INCOMING_STREAM_TIMEOUT
from pyxquic_wt._exceptions import SessionClosedError, WebTransportError
from pyxquic_wt._stream import BidiStream, SendStream, ReceiveStream


class WebTransportSession:
    """A single WebTransport session on a QUIC connection.

    Each session has its own session_id and independent stream/datagram queues.
    Created by ``WebTransportConnection.open_session(path)``.
    """

    def __init__(self, connection, session_id: int):
        self._conn = connection
        self._session_id = session_id
        self._closed = False

        # per-session stream queues
        self._streams: dict[int, BidiStream] = {}
        self._recv_streams: dict[int, ReceiveStream] = {}
        self._incoming_bidi_queue = asyncio.Queue()
        self._incoming_uni_queue = asyncio.Queue()
        self._dgram_queue = asyncio.Queue()
        # queue for stream_ids created by create_bidirectional_stream()
        self._created_bidi_queue = asyncio.Queue()
        # fast-path: pending recv waiters for send_bidi + recv pattern
        self._pending_recv_waiters: deque[asyncio.Future] = deque()

    @property
    def session_id(self) -> int:
        return self._session_id

    @property
    def is_closed(self) -> bool:
        return self._closed

    # ---- bidi stream API ----

    async def send_bidi(self, data: bytes, fin: bool = True) -> int:
        """Convenience: create bidi stream + send data + optional FIN."""
        self._check_open()
        ret = lib.xqc_wt_py_send_bidi(
            self._conn._handle, self._session_id,
            data, len(data), 1 if fin else 0)
        return ret

    async def send_bidi_batch(self, payloads: list[bytes]) -> int:
        """Send multiple bidi streams in one batch (single C engine flush)."""
        self._check_open()
        if not payloads:
            return 0
        # pack all payloads into one contiguous buffer with offset/length arrays
        buf = b"".join(payloads)
        offsets = []
        lengths = []
        pos = 0
        for p in payloads:
            offsets.append(pos)
            lengths.append(len(p))
            pos += len(p)
        c_offsets = ffi.new("size_t[]", offsets)
        c_lengths = ffi.new("size_t[]", lengths)
        ret = lib.xqc_wt_py_send_bidi_batch(
            self._conn._handle, self._session_id,
            buf, c_offsets, c_lengths, len(payloads))
        return ret

    async def recv(self, timeout: float = STREAM_READ_TIMEOUT) -> bytes:
        """Receive all data from the next incoming bidi stream until FIN."""
        # fast-path: register a Future so _on_stream_data can resolve directly
        waiter = asyncio.get_running_loop().create_future()
        self._pending_recv_waiters.append(waiter)
        try:
            return await asyncio.wait_for(waiter, timeout=timeout)
        except asyncio.TimeoutError:
            # fall through — waiter might not have been consumed
            raise
        finally:
            # clean up if waiter wasn't consumed (timeout or cancel)
            if waiter in self._pending_recv_waiters:
                self._pending_recv_waiters.remove(waiter)

    async def create_bidirectional_stream(self) -> BidiStream:
        """Create a new bidirectional stream for multi-send/recv."""
        self._check_open()
        ret = lib.xqc_wt_py_create_bidi_stream(
            self._conn._handle, self._session_id)
        if ret < 0:
            raise RuntimeError(f"create_bidi_stream failed: {ret}")
        # stream_cb pushes the new stream_id to _created_bidi_queue
        stream_id = self._created_bidi_queue.get_nowait()
        return self._streams[stream_id]

    async def incoming_bidirectional_streams(self):
        """Async iterator over incoming bidi streams."""
        while not self._closed:
            try:
                stream = await asyncio.wait_for(
                    self._incoming_bidi_queue.get(), timeout=INCOMING_STREAM_TIMEOUT)
                yield stream
            except asyncio.TimeoutError:
                continue

    # ---- uni stream API ----

    async def send_uni(self, data: bytes) -> int:
        """Convenience: create uni stream + send data + FIN in one call."""
        self._check_open()
        ret = lib.xqc_wt_py_send_uni(
            self._conn._handle, self._session_id, data, len(data))
        return ret

    async def recv_uni(self, timeout: float = STREAM_READ_TIMEOUT) -> bytes:
        """Receive data from the next incoming uni stream."""
        stream = await asyncio.wait_for(
            self._incoming_uni_queue.get(), timeout=timeout)
        return await stream.read_all(timeout=timeout)

    async def create_unidirectional_stream(self) -> SendStream:
        """Create a client->server unidirectional stream."""
        self._check_open()
        ret = lib.xqc_wt_py_create_uni_stream(
            self._conn._handle, self._session_id)
        if ret < 0:
            raise RuntimeError(f"create_uni_stream failed: {ret}")
        # stream_cb fires with is_bidi=0; connection routes it here
        # find the SendStream just created (stored in _conn temporarily)
        sid = self._conn._pop_last_send_stream_id()
        if sid is None:
            raise RuntimeError("stream_cb not fired for uni stream")
        return SendStream(self._conn, sid)

    async def incoming_unidirectional_streams(self):
        """Async iterator over incoming uni receive streams."""
        while not self._closed:
            try:
                stream = await asyncio.wait_for(
                    self._incoming_uni_queue.get(), timeout=INCOMING_STREAM_TIMEOUT)
                yield stream
            except asyncio.TimeoutError:
                continue

    # ---- datagram API ----

    async def send_datagram(self, data: bytes):
        """Send an unreliable datagram."""
        self._check_open()
        ret = lib.xqc_wt_py_send_datagram(
            self._conn._handle, self._session_id, data, len(data))
        return ret

    async def recv_datagram(self, timeout: float = STREAM_READ_TIMEOUT) -> bytes:
        """Receive a datagram."""
        return await asyncio.wait_for(
            self._dgram_queue.get(), timeout=timeout)

    # ---- lifecycle ----

    async def close(self, error_code: int = 0, reason: str = ""):
        """Close this session with optional error code and reason."""
        if self._closed:
            return
        self._closed = True
        if self._conn._handle and self._session_id:
            if error_code or reason:
                reason_bytes = reason.encode("utf-8") if reason else b""
                lib.xqc_wt_py_close_session_with_error(
                    self._conn._handle, self._session_id,
                    error_code, reason_bytes, len(reason_bytes))
            else:
                lib.xqc_wt_py_close_session(
                    self._conn._handle, self._session_id)

    def _check_open(self):
        if self._closed:
            raise SessionClosedError()
        if self._conn._destroyed:
            raise WebTransportError("connection is closed")

    # ---- internal: called by Connection to route data ----

    def _on_stream_created(self, stream_id: int, is_bidi: bool):
        if is_bidi:
            if stream_id not in self._streams:
                stream = BidiStream(self._conn, stream_id)
                self._streams[stream_id] = stream
                # notify create_bidirectional_stream() waiters
                self._created_bidi_queue.put_nowait(stream_id)
        else:
            if stream_id not in self._recv_streams:
                stream = ReceiveStream(self._conn, stream_id)
                self._recv_streams[stream_id] = stream

    def _on_stream_data(self, stream_id: int, data: bytes, fin: bool):
        # bidi already known?
        stream = self._streams.get(stream_id)
        if stream:
            stream._on_data(data, fin)
            return
        # uni recv?
        recv = self._recv_streams.get(stream_id)
        if recv:
            recv._on_data(data, fin)
            if not recv._enqueued:
                recv._enqueued = True
                self._incoming_uni_queue.put_nowait(recv)
            return
        # unknown incoming bidi — fast-path: if there's a pending recv waiter
        # and data arrives with FIN (complete message), resolve directly
        if self._pending_recv_waiters:
            # accumulate into a new stream to handle multi-chunk case
            stream = BidiStream(self._conn, stream_id)
            self._streams[stream_id] = stream
            stream._on_data(data, fin)
            if fin:
                waiter = self._pending_recv_waiters.popleft()
                if not waiter.done():
                    waiter.set_result(data)
                    return
            # not FIN yet — need to go through queue for read_all
            self._incoming_bidi_queue.put_nowait(stream)
            return
        # no waiter — normal path
        stream = BidiStream(self._conn, stream_id)
        self._streams[stream_id] = stream
        stream._on_data(data, fin)
        self._incoming_bidi_queue.put_nowait(stream)

    def _on_datagram(self, data: bytes):
        self._dgram_queue.put_nowait(data)
