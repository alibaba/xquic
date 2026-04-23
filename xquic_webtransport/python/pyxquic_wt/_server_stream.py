"""Server-side WebTransport stream types."""

import asyncio
import time

from pyxquic_wt._cffi_defs import lib
from pyxquic_wt._defaults import SERVER_READ_TIMEOUT


class ServerBidiStream:
    """A server-side bidirectional WebTransport stream."""

    def __init__(self, server_handle, session_id, stream_id):
        self._server = server_handle
        self.session_id = session_id
        self.stream_id = stream_id
        self._queue = asyncio.Queue()
        self._fin_received = False
        self._read_buf = bytearray()

    async def read(self, max_bytes: int = -1, timeout: float = SERVER_READ_TIMEOUT) -> bytes:
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

    async def read_all(self, timeout: float = SERVER_READ_TIMEOUT) -> bytes:
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
            except asyncio.TimeoutError:
                break
        return bytes(result)

    async def write_all(self, data: bytes, end_stream: bool = False):
        """Write data to the stream. Set end_stream=True to send FIN."""
        ret = lib.xqc_wt_py_server_stream_send(
            self._server, self.stream_id,
            data, len(data), 1 if end_stream else 0)
        await asyncio.sleep(0)
        return ret

    def _on_data(self, data: bytes, fin: bool):
        self._queue.put_nowait((data, fin))
