from contextlib import AbstractAsyncContextManager

from pyxquic_wt._connection import WebTransportConnection
from pyxquic_wt._session import WebTransportSession

def open_connection(
    url: str,
    *,
    idle_timeout: float = 30.0,
    congestion: str = "bbr",
    log_level: int = 0,
) -> AbstractAsyncContextManager[WebTransportConnection]: ...

def connect(
    url: str,
    *,
    cert_hash: str | None = None,
    idle_timeout: float = 30.0,
    congestion: str = "bbr",
    log_level: int = 0,
) -> AbstractAsyncContextManager[WebTransportSession]: ...
