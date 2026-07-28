"""
WebTransport stream types: BidiStream, SendStream, ReceiveStream.
"""

import asyncio
import time

from pyxquic_wt._cffi_defs import ffi, lib
from pyxquic_wt._defaults import STREAM_READ_TIMEOUT, STREAM_ITER_TIMEOUT
from pyxquic_wt._exceptions import WebTransportError


class BidiStream:
    """A bidirectional WebTransport stream."""

    def __init__(self, connection, stream_id):
        self._conn = connection
        self.stream_id = stream_id
        self._queue = asyncio.Queue()
        self._fin_received = False
        self._read_buf = bytearray()

    async def read(self, max_bytes: int = -1, timeout: float = STREAM_READ_TIMEOUT) -> bytes:
        """Read up to *max_bytes* bytes (or one chunk if max_bytes < 0).

        Returns ``b""`` when FIN has been received and the buffer is empty.
        """
        if not self._read_buf and not self._fin_received:
            try:
                chunk, fin = await asyncio.wait_for(
                    self._queue.get(), timeout=timeout)
                self._read_buf.extend(chunk)
                if fin:
                    self._fin_received = True
            except asyncio.TimeoutError:
                pass
        if max_bytes < 0 or max_bytes >= len(self._read_buf):
            out = bytes(self._read_buf)
            self._read_buf.clear()
            return out
        out = bytes(self._read_buf[:max_bytes])
        del self._read_buf[:max_bytes]
        return out

    async def read_all(self, timeout: float = STREAM_READ_TIMEOUT) -> bytes:
        """Read all data until FIN or timeout."""
        result = bytearray()
        deadline = time.time() + timeout
        while not self._fin_received:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            try:
                chunk, fin = await asyncio.wait_for(
                    self._queue.get(), timeout=remaining)
                result.extend(chunk)
                if fin:
                    self._fin_received = True
                    break
            except asyncio.TimeoutError:
                break
        return bytes(result)

    recv = read_all

    async def write_all(self, data: bytes, end_stream: bool = False):
        """Write data on this stream. Set end_stream=True to send FIN."""
        if self._conn._destroyed:
            raise WebTransportError("connection is closed")
        ret = lib.xqc_wt_py_stream_send(
            self._conn._handle, self.stream_id,
            data, len(data), 1 if end_stream else 0)
        return ret

    def reset(self, error_code: int = 0):
        """Send RESET_STREAM to abort sending."""
        lib.xqc_wt_py_stream_reset(
            self._conn._handle, self.stream_id, error_code)

    def stop_sending(self, error_code: int = 0):
        """Send STOP_SENDING to tell peer to stop."""
        lib.xqc_wt_py_stream_stop_sending(
            self._conn._handle, self.stream_id, error_code)

    def _on_data(self, data: bytes, fin: bool):
        self._queue.put_nowait((data, fin))

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if not self._fin_received:
            await self.write_all(b"", end_stream=True)

    def __aiter__(self):
        return self

    async def __anext__(self) -> bytes:
        if self._fin_received:
            raise StopAsyncIteration
        try:
            chunk, fin = await asyncio.wait_for(self._queue.get(), timeout=STREAM_ITER_TIMEOUT)
            if fin:
                self._fin_received = True
            if chunk:
                return chunk
            if self._fin_received:
                raise StopAsyncIteration
            return b""
        except asyncio.TimeoutError:
            if self._fin_received:
                raise StopAsyncIteration
            return b""


class SendStream:
    """A unidirectional send stream (client -> server)."""

    def __init__(self, connection, stream_id):
        self._conn = connection
        self.stream_id = stream_id

    async def write(self, data: bytes, end_stream: bool = False):
        """Write data. Set end_stream=True to send FIN."""
        if self._conn._destroyed:
            raise WebTransportError("connection is closed")
        ret = lib.xqc_wt_py_stream_send(
            self._conn._handle, self.stream_id,
            data, len(data), 1 if end_stream else 0)
        return ret

    async def close(self):
        """Send FIN (empty write with end_stream=True)."""
        await self.write(b"", end_stream=True)


class ReceiveStream:
    """A unidirectional receive stream (server -> client)."""

    def __init__(self, connection, stream_id):
        self._conn = connection
        self.stream_id = stream_id
        self._queue = asyncio.Queue()
        self._fin_received = False
        self._enqueued = False  # True once pushed to incoming_uni_queue
        self._read_buf = bytearray()

    async def read(self, max_bytes: int = -1, timeout: float = STREAM_READ_TIMEOUT) -> bytes:
        """Read up to *max_bytes* bytes (or one chunk if max_bytes < 0).

        Returns ``b""`` when FIN has been received and the buffer is empty.
        """
        if not self._read_buf and not self._fin_received:
            try:
                chunk, fin = await asyncio.wait_for(
                    self._queue.get(), timeout=timeout)
                self._read_buf.extend(chunk)
                if fin:
                    self._fin_received = True
            except asyncio.TimeoutError:
                pass
        if max_bytes < 0 or max_bytes >= len(self._read_buf):
            out = bytes(self._read_buf)
            self._read_buf.clear()
            return out
        out = bytes(self._read_buf[:max_bytes])
        del self._read_buf[:max_bytes]
        return out

    async def read_all(self, timeout: float = STREAM_READ_TIMEOUT) -> bytes:
        """Read all data until FIN or timeout."""
        result = bytearray()
        deadline = time.time() + timeout
        while not self._fin_received:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            try:
                chunk, fin = await asyncio.wait_for(
                    self._queue.get(), timeout=remaining)
                result.extend(chunk)
                if fin:
                    self._fin_received = True
                    break
            except asyncio.TimeoutError:
                break
        return bytes(result)

    recv = read_all

    def _on_data(self, data: bytes, fin: bool):
        self._queue.put_nowait((data, fin))

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

    def __aiter__(self):
        return self

    async def __anext__(self) -> bytes:
        if self._fin_received:
            raise StopAsyncIteration
        try:
            chunk, fin = await asyncio.wait_for(self._queue.get(), timeout=STREAM_ITER_TIMEOUT)
            if fin:
                self._fin_received = True
            if chunk:
                return chunk
            if self._fin_received:
                raise StopAsyncIteration
            return b""
        except asyncio.TimeoutError:
            if self._fin_received:
                raise StopAsyncIteration
            return b""
