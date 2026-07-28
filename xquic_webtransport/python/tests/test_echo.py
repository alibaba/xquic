"""
Basic tests for pyxquic-wt.
"""

import pytest


def test_import():
    """Verify the package can be imported."""
    from pyxquic_wt import connect, serve, open_connection
    assert connect is not None
    assert serve is not None
    assert open_connection is not None


def test_version():
    """Verify version string."""
    import pyxquic_wt
    assert pyxquic_wt.__version__ == "0.1.0"


def test_stream_types():
    """Verify stream types can be imported."""
    from pyxquic_wt._stream import BidiStream, SendStream, ReceiveStream
    assert BidiStream is not None
    assert SendStream is not None
    assert ReceiveStream is not None


def test_cffi_defs_loaded():
    """Verify CFFI definitions are parsed (lib may be None if .so not found)."""
    from pyxquic_wt._cffi_defs import ffi
    assert ffi is not None


if __name__ == "__main__":
    test_import()
    test_version()
    test_stream_types()
    test_cffi_defs_loaded()
    print("All basic tests passed!")
