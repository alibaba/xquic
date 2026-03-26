"""
pyxquic-wt: WebTransport client/server powered by xquic QUIC/HTTP3 stack.

Usage:
    from pyxquic_wt import WebTransportClient, WebTransportServer
"""

from pyxquic_wt.client import WebTransportClient
from pyxquic_wt.server import WebTransportServer

__version__ = "0.1.0"
__all__ = ["WebTransportClient", "WebTransportServer"]
