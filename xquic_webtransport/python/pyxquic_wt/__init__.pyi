from contextlib import AbstractAsyncContextManager
from typing import Callable, Optional

from pyxquic_wt._client import connect as connect
from pyxquic_wt._client import open_connection as open_connection
from pyxquic_wt._server import serve as serve
from pyxquic_wt._exceptions import (
    WebTransportError as WebTransportError,
    QuicConnectionError as QuicConnectionError,
    SessionClosedError as SessionClosedError,
    StreamResetError as StreamResetError,
    StreamStopError as StreamStopError,
    HandshakeError as HandshakeError,
    SessionRejectedError as SessionRejectedError,
)

__version__: str
__all__: list[str]
