from contextlib import AbstractAsyncContextManager
from typing import AsyncIterator, Callable, Optional

class ServerBidiStream:
    session_id: int
    stream_id: int

    async def read(self, max_bytes: int = -1, timeout: float = ...) -> bytes: ...
    async def read_all(self, timeout: float = ...) -> bytes: ...
    async def write_all(self, data: bytes, end_stream: bool = False) -> int: ...

class ServerSession:
    session_id: int
    path: str

    async def send_datagram(self, data: bytes) -> int: ...
    async def recv_datagram(self, timeout: float = ...) -> bytes: ...
    async def incoming_bidirectional_streams(self) -> AsyncIterator[ServerBidiStream]: ...
    async def close(self, error_code: int = 0, reason: str = "") -> None: ...
    async def drain(self) -> None: ...

class WebTransportServer:
    async def close(self) -> None: ...

def serve(
    handler: Optional[Callable] = None,
    *,
    routes: Optional[dict[str, Callable]] = None,
    host: str = "0.0.0.0",
    port: int = 4443,
    cert_file: str = ...,
    key_file: str = ...,
    idle_timeout: float = 30.0,
    congestion: str = "bbr",
) -> AbstractAsyncContextManager[WebTransportServer]: ...
