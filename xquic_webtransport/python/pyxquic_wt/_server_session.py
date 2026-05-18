"""Server-side WebTransport session."""
from __future__ import annotations

import asyncio

from pyxquic_wt._cffi_defs import lib
from pyxquic_wt._defaults import SERVER_READ_TIMEOUT, INCOMING_STREAM_TIMEOUT
from pyxquic_wt._server_stream import ServerBidiStream


class ServerSession:
    """A server-side WebTransport session."""

    def __init__(self, session_id, server_handle, path: str = "/"):
        self.session_id = session_id
        self.path = path
        self._server = server_handle
        self._stream_queue = asyncio.Queue()
        self._streams: dict[int, ServerBidiStream] = {}
        self._closed = False

    async def incoming_bidirectional_streams(self):
        """Async iterator over incoming bidi streams."""
        while not self._closed:
            try:
                stream = await asyncio.wait_for(
                    self._stream_queue.get(), timeout=INCOMING_STREAM_TIMEOUT)
                yield stream
            except asyncio.TimeoutError:
                continue

    async def close(self, error_code: int = 0, reason: str = ""):
        """Close this session with an error code and reason (sends CLOSE capsule)."""
        if self._closed:
            return
        reason_bytes = reason.encode("utf-8") if reason else b""
        lib.xqc_wt_py_server_close_session(
            self._server, self.session_id,
            error_code, reason_bytes, len(reason_bytes))
        lib.xqc_wt_py_server_process(self._server)

    async def drain(self):
        """Send DRAIN capsule — peer should stop opening new streams."""
        lib.xqc_wt_py_server_drain_session(
            self._server, self.session_id)
        lib.xqc_wt_py_server_process(self._server)

    def _on_stream_data(self, stream_id, data, fin):
        stream = self._streams.get(stream_id)
        if not stream:
            stream = ServerBidiStream(self._server, self.session_id, stream_id)
            self._streams[stream_id] = stream
            self._stream_queue.put_nowait(stream)
        stream._on_data(data, fin)
