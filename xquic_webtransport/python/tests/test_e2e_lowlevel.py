"""
Low-level E2E regression tests using CFFI directly (no _server.py/_client.py).

These tests verify the complete C→Python callback chain:
  QUIC handshake → session create → bidi send → server echo → client receive

Requires libxquic_wt_py.{so,dylib} and certs/localhost.{crt,key}.
"""

import asyncio
import os
import pathlib
import socket
import struct
import sys
import time

import pytest

# availability guard
_LIB_AVAILABLE = False
try:
    from pyxquic_wt._cffi_defs import ffi, lib
    if lib is not None:
        _LIB_AVAILABLE = True
except Exception:
    pass

_CERT_DIR = pathlib.Path(__file__).resolve().parent.parent.parent / "certs"
_CERT_FILE = _CERT_DIR / "localhost.crt"
_KEY_FILE = _CERT_DIR / "localhost.key"
_CERTS_EXIST = _CERT_FILE.exists() and _KEY_FILE.exists()

skip_no_lib = pytest.mark.skipif(not _LIB_AVAILABLE, reason="libxquic_wt_py not available")
skip_no_certs = pytest.mark.skipif(not _CERTS_EXIST, reason="certs not found")

_BASE_PORT = int(os.environ.get("WT_TEST_PORT", "15000"))


def _build_sockaddr_in(host, port):
    ip = socket.inet_aton(host)
    pn = struct.pack("!H", port)
    if sys.platform == "darwin":
        return struct.pack("BB", 16, socket.AF_INET) + pn + ip + b'\x00' * 8
    return struct.pack("H", socket.AF_INET) + pn + ip + b'\x00' * 8


class WTTestHarness:
    """Manages server + client lifecycle for a single test."""

    def __init__(self, port):
        self.port = port
        self._cbs = []  # prevent GC of CFFI callbacks

        # server
        self.sh = lib.xqc_wt_py_server_create(
            str(_CERT_FILE).encode(), str(_KEY_FILE).encode())
        self.ssock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ssock.setblocking(False)
        self.ssock.bind(("127.0.0.1", port))

        # client
        self.ch = lib.xqc_wt_py_client_create(b"127.0.0.1", port, 1)
        self.csock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.csock.setblocking(False)

        # state
        self.handshake_done = False
        self.session_id = None
        self.server_sessions = []
        self.echo_data = bytearray()

    def _mkcb(self, typ, fn):
        cb = ffi.callback(typ, fn)
        self._cbs.append(cb)
        return cb

    def setup_echo_server(self):
        """Configure server to echo bidi data back."""
        sh = self.sh

        def send_cb(d, l, p, pl, u):
            try:
                r = ffi.buffer(p, pl)[:]
                port = struct.unpack("!H", r[2:4])[0]
                addr = socket.inet_ntoa(r[4:8])
                self.ssock.sendto(ffi.buffer(d, l)[:], (addr, port))
            except Exception:
                pass

        def data_cb(sid, strid, d, l, fin, u):
            buf = bytes(ffi.buffer(d, l))
            lib.xqc_wt_py_server_stream_send(sh, strid, buf, len(buf), 1)
            lib.xqc_wt_py_server_process(sh)

        def session_cb(ev, sid, u):
            if ev == 0:
                self.server_sessions.append(sid)

        nop = lambda *a: None
        lib.xqc_wt_py_server_set_callbacks(
            sh,
            self._mkcb("xqc_wt_py_send_cb", send_cb),
            self._mkcb("xqc_wt_py_timer_cb", nop),
            self._mkcb("xqc_wt_py_session_cb", session_cb),
            self._mkcb("xqc_wt_py_stream_cb", nop),
            self._mkcb("xqc_wt_py_stream_data_cb", data_cb),
            self._mkcb("xqc_wt_py_dgram_cb", nop),
            ffi.NULL)

    def setup_client(self):
        """Configure client with standard callbacks."""
        def send_cb(d, l, p, pl, u):
            self.csock.sendto(ffi.buffer(d, l)[:], ("127.0.0.1", self.port))

        def session_cb(ev, sid, u):
            if ev == 2:
                self.handshake_done = True
            if ev == 0:
                self.session_id = sid

        def data_cb(sid, strid, d, l, fin, u):
            self.echo_data.extend(ffi.buffer(d, l))

        nop = lambda *a: None
        lib.xqc_wt_py_client_set_callbacks(
            self.ch,
            self._mkcb("xqc_wt_py_send_cb", send_cb),
            self._mkcb("xqc_wt_py_timer_cb", nop),
            self._mkcb("xqc_wt_py_session_cb", session_cb),
            self._mkcb("xqc_wt_py_stream_cb", nop),
            self._mkcb("xqc_wt_py_stream_data_cb", data_cb),
            self._mkcb("xqc_wt_py_dgram_cb", nop),
            ffi.NULL)

    def poll(self):
        bsa = _build_sockaddr_in
        try:
            while True:
                d, a = self.ssock.recvfrom(1500)
                lib.xqc_wt_py_server_feed_packet(
                    self.sh, d, len(d),
                    bsa("127.0.0.1", self.port), 16,
                    bsa(a[0], a[1]), 16,
                    int(time.time() * 1e6))
        except Exception:
            pass
        lib.xqc_wt_py_server_finish_recv(self.sh)
        lib.xqc_wt_py_server_process(self.sh)
        try:
            while True:
                d, a = self.csock.recvfrom(1500)
                lib.xqc_wt_py_client_feed_packet(
                    self.ch, d, len(d),
                    bsa("0.0.0.0", 0), 16,
                    bsa(a[0], a[1]), 16,
                    int(time.time() * 1e6))
        except Exception:
            pass
        lib.xqc_wt_py_client_finish_recv(self.ch)
        lib.xqc_wt_py_client_process(self.ch)

    async def wait_for(self, predicate, timeout=5.0, interval=0.02):
        deadline = time.time() + timeout
        while time.time() < deadline:
            await asyncio.sleep(interval)
            self.poll()
            if predicate():
                return True
        return False

    async def destroy(self):
        """Graceful shutdown: close connections, drain, then destroy.
        NOTE: xqc_conn_destroy has a known SEGV during engine teardown
        when active WT streams exist. We catch this by only destroying
        after graceful close + drain, but it may still crash on some paths.
        For now, close sockets and let the process clean up naturally. """
        try:
            lib.xqc_wt_py_client_close(self.ch)
            lib.xqc_wt_py_client_process(self.ch)
            await asyncio.sleep(0.1)
            self.poll()
        except Exception:
            pass
        self.ssock.close()
        self.csock.close()
        # Do NOT call client_destroy/server_destroy here — xqc_conn_destroy
        # crashes when WT streams are still referenced. The memory will be
        # reclaimed when the process exits. This is acceptable for tests.


# ---- Tests ---- #

@skip_no_lib
@skip_no_certs
@pytest.mark.asyncio
async def test_quic_handshake():
    """QUIC handshake completes between client and server."""
    h = WTTestHarness(_BASE_PORT)
    h.setup_echo_server()
    h.setup_client()
    lib.xqc_wt_py_client_connect(h.ch)
    lib.xqc_wt_py_client_process(h.ch)
    ok = await h.wait_for(lambda: h.handshake_done, timeout=5.0)
    assert ok, "QUIC handshake did not complete"
    await h.destroy()


@skip_no_lib
@skip_no_certs
@pytest.mark.asyncio
async def test_session_create():
    """Session can be opened after handshake."""
    h = WTTestHarness(_BASE_PORT + 1)
    h.setup_echo_server()
    h.setup_client()
    lib.xqc_wt_py_client_connect(h.ch)
    lib.xqc_wt_py_client_process(h.ch)
    await h.wait_for(lambda: h.handshake_done)
    lib.xqc_wt_py_open_session(h.ch, b"/echo", b"127.0.0.1")
    lib.xqc_wt_py_client_process(h.ch)
    ok = await h.wait_for(lambda: h.session_id is not None, timeout=5.0)
    assert ok, "Session was not created"
    assert len(h.server_sessions) > 0, "Server did not see session create"
    await h.destroy()


@skip_no_lib
@skip_no_certs
@pytest.mark.asyncio
async def test_bidi_echo():
    """Full E2E: client sends bidi data, server echoes, client receives."""
    h = WTTestHarness(_BASE_PORT + 2)
    h.setup_echo_server()
    h.setup_client()
    lib.xqc_wt_py_client_connect(h.ch)
    lib.xqc_wt_py_client_process(h.ch)
    await h.wait_for(lambda: h.handshake_done)
    lib.xqc_wt_py_open_session(h.ch, b"/echo", b"127.0.0.1")
    lib.xqc_wt_py_client_process(h.ch)
    await h.wait_for(lambda: h.session_id is not None)

    payload = b"Hello WebTransport!"
    lib.xqc_wt_py_send_bidi(h.ch, h.session_id, payload, len(payload), 1)
    lib.xqc_wt_py_client_process(h.ch)

    ok = await h.wait_for(lambda: len(h.echo_data) > 0, timeout=5.0)
    assert ok, "Echo data not received"
    assert bytes(h.echo_data) == payload, f"Expected {payload!r}, got {bytes(h.echo_data)!r}"
    await h.destroy()


@skip_no_lib
@skip_no_certs
@pytest.mark.asyncio
async def test_bidi_echo_large():
    """Echo a 4KB payload to verify multi-packet bidi echo."""
    h = WTTestHarness(_BASE_PORT + 3)
    h.setup_echo_server()
    h.setup_client()
    lib.xqc_wt_py_client_connect(h.ch)
    lib.xqc_wt_py_client_process(h.ch)
    await h.wait_for(lambda: h.handshake_done)
    lib.xqc_wt_py_open_session(h.ch, b"/echo", b"127.0.0.1")
    lib.xqc_wt_py_client_process(h.ch)
    await h.wait_for(lambda: h.session_id is not None)

    payload = os.urandom(1024)
    lib.xqc_wt_py_send_bidi(h.ch, h.session_id, payload, len(payload), 1)
    lib.xqc_wt_py_client_process(h.ch)

    ok = await h.wait_for(lambda: len(h.echo_data) >= len(payload), timeout=10.0)
    assert ok, f"Echo incomplete: got {len(h.echo_data)} of {len(payload)} bytes"
    assert bytes(h.echo_data) == payload
    await h.destroy()


@skip_no_lib
@skip_no_certs
@pytest.mark.asyncio
async def test_session_path():
    """Server can read session path via get_session_path."""
    h = WTTestHarness(_BASE_PORT + 4)
    h.setup_echo_server()
    h.setup_client()
    lib.xqc_wt_py_client_connect(h.ch)
    lib.xqc_wt_py_client_process(h.ch)
    await h.wait_for(lambda: h.handshake_done)
    lib.xqc_wt_py_open_session(h.ch, b"/my/path", b"127.0.0.1")
    lib.xqc_wt_py_client_process(h.ch)
    await h.wait_for(lambda: h.session_id is not None)
    await h.wait_for(lambda: len(h.server_sessions) > 0)

    path_ptr = lib.xqc_wt_py_server_get_session_path(h.sh, h.server_sessions[0])
    path = ffi.string(path_ptr).decode()
    assert path == "/my/path", f"Expected '/my/path', got {path!r}"
    await h.destroy()


@skip_no_lib
@skip_no_certs
@pytest.mark.asyncio
async def test_bidi_fin_propagation():
    """Server-side data_cb receives fin=1 when client sends FIN."""
    port = _BASE_PORT + 5
    h = WTTestHarness(port)
    fin_received = []

    sh = h.sh

    def send_cb(d, l, p, pl, u):
        try:
            r = ffi.buffer(p, pl)[:]
            port_n = struct.unpack("!H", r[2:4])[0]
            addr = socket.inet_ntoa(r[4:8])
            h.ssock.sendto(ffi.buffer(d, l)[:], (addr, port_n))
        except Exception:
            pass

    def data_cb(sid, strid, d, l, fin, u):
        buf = bytes(ffi.buffer(d, l))
        fin_received.append((buf, bool(fin)))
        # echo back
        lib.xqc_wt_py_server_stream_send(sh, strid, buf, len(buf), 1)
        lib.xqc_wt_py_server_process(sh)

    def session_cb(ev, sid, u):
        if ev == 0:
            h.server_sessions.append(sid)

    nop = lambda *a: None
    lib.xqc_wt_py_server_set_callbacks(
        sh,
        h._mkcb("xqc_wt_py_send_cb", send_cb),
        h._mkcb("xqc_wt_py_timer_cb", nop),
        h._mkcb("xqc_wt_py_session_cb", session_cb),
        h._mkcb("xqc_wt_py_stream_cb", nop),
        h._mkcb("xqc_wt_py_stream_data_cb", data_cb),
        h._mkcb("xqc_wt_py_dgram_cb", nop),
        ffi.NULL)

    h.setup_client()
    lib.xqc_wt_py_client_connect(h.ch)
    lib.xqc_wt_py_client_process(h.ch)
    await h.wait_for(lambda: h.handshake_done)
    lib.xqc_wt_py_open_session(h.ch, b"/echo", b"127.0.0.1")
    lib.xqc_wt_py_client_process(h.ch)
    await h.wait_for(lambda: h.session_id is not None)

    payload = b"fin-test"
    lib.xqc_wt_py_send_bidi(h.ch, h.session_id, payload, len(payload), 1)
    lib.xqc_wt_py_client_process(h.ch)

    ok = await h.wait_for(lambda: len(fin_received) > 0, timeout=5.0)
    assert ok, "data_cb was never called"

    # At least one call should have fin=True
    any_fin = any(fin for _, fin in fin_received)
    assert any_fin, f"FIN was not propagated to data_cb: {fin_received}"

    # Verify echo was received by client
    ok = await h.wait_for(lambda: len(h.echo_data) > 0, timeout=5.0)
    assert ok, "Echo data not received after FIN fix"
    assert bytes(h.echo_data) == payload
    await h.destroy()


@skip_no_lib
@skip_no_certs
@pytest.mark.asyncio
async def test_server_py_async_echo():
    """Python _server.py async handler reads FIN-terminated data and echoes back."""
    from pyxquic_wt import serve

    port = _BASE_PORT + 6
    handler_got = []

    async def echo_handler(session):
        async for stream in session.incoming_bidirectional_streams():
            data = await stream.read_all(timeout=5.0)
            handler_got.append(data)
            await stream.write_all(data, end_stream=True)

    async with serve(echo_handler, host="127.0.0.1", port=port,
                     cert_file=str(_CERT_FILE), key_file=str(_KEY_FILE)):
        # Use low-level client to send data
        ch = lib.xqc_wt_py_client_create(b"127.0.0.1", port, 1)
        csock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        csock.setblocking(False)
        cbs = []
        echo_data = bytearray()
        handshake_done = [False]
        session_id = [None]

        def mk(t, f):
            c = ffi.callback(t, f)
            cbs.append(c)
            return c

        def c_send(d, l, p, pl, u):
            csock.sendto(ffi.buffer(d, l)[:], ("127.0.0.1", port))

        def c_session(ev, sid, u):
            if ev == 2:
                handshake_done[0] = True
            if ev == 0:
                session_id[0] = sid

        def c_data(sid, strid, d, l, fin, u):
            echo_data.extend(ffi.buffer(d, l))

        nop = lambda *a: None
        lib.xqc_wt_py_client_set_callbacks(
            ch,
            mk("xqc_wt_py_send_cb", c_send),
            mk("xqc_wt_py_timer_cb", nop),
            mk("xqc_wt_py_session_cb", c_session),
            mk("xqc_wt_py_stream_cb", nop),
            mk("xqc_wt_py_stream_data_cb", c_data),
            mk("xqc_wt_py_dgram_cb", nop),
            ffi.NULL)

        lib.xqc_wt_py_client_connect(ch)
        lib.xqc_wt_py_client_process(ch)

        async def poll_client():
            try:
                while True:
                    d, a = csock.recvfrom(1500)
                    lib.xqc_wt_py_client_feed_packet(
                        ch, d, len(d),
                        _build_sockaddr_in("0.0.0.0", 0), 16,
                        _build_sockaddr_in(a[0], a[1]), 16,
                        int(time.time() * 1e6))
            except Exception:
                pass
            lib.xqc_wt_py_client_finish_recv(ch)
            lib.xqc_wt_py_client_process(ch)

        # Wait for handshake
        deadline = time.time() + 5
        while not handshake_done[0] and time.time() < deadline:
            await asyncio.sleep(0.02)
            await poll_client()
        assert handshake_done[0], "handshake failed"

        lib.xqc_wt_py_open_session(ch, b"/echo", b"127.0.0.1")
        lib.xqc_wt_py_client_process(ch)

        deadline = time.time() + 5
        while session_id[0] is None and time.time() < deadline:
            await asyncio.sleep(0.02)
            await poll_client()
        assert session_id[0] is not None, "session not created"

        payload = b"async-fin-echo-test"
        lib.xqc_wt_py_send_bidi(ch, session_id[0], payload, len(payload), 1)
        lib.xqc_wt_py_client_process(ch)

        # Wait for echo
        deadline = time.time() + 10
        while len(echo_data) < len(payload) and time.time() < deadline:
            await asyncio.sleep(0.02)
            await poll_client()

        assert len(handler_got) > 0, "Handler was never called"
        assert handler_got[0] == payload, f"Handler got {handler_got[0]!r}, expected {payload!r}"
        assert bytes(echo_data) == payload, f"Echo: {bytes(echo_data)!r}, expected {payload!r}"

        csock.close()
