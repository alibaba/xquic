"""
Basic echo test for pyxquic-wt.
"""

import pytest
import asyncio


def test_import():
    """Verify the package can be imported."""
    from pyxquic_wt import WebTransportClient, WebTransportServer
    assert WebTransportClient is not None
    assert WebTransportServer is not None


def test_client_init():
    """Verify client can be instantiated."""
    from pyxquic_wt import WebTransportClient
    client = WebTransportClient("https://localhost:4443/echo")
    assert client._host == "localhost"
    assert client._port == 4443
    assert client._path == "/echo"


def test_server_init():
    """Verify server can be instantiated."""
    from pyxquic_wt import WebTransportServer
    server = WebTransportServer(
        host="0.0.0.0",
        port=4443,
        cert_file="test.crt",
        key_file="test.key",
    )
    assert server._port == 4443


if __name__ == "__main__":
    test_import()
    test_client_init()
    test_server_init()
    print("All basic tests passed!")
