"""Wire protocol unit tests — capsule encode/decode, session_id varint."""

import pathlib

import pytest

_LIB_AVAILABLE = False
try:
    from pyxquic_wt._cffi_defs import ffi, lib
    if lib is not None:
        _LIB_AVAILABLE = True
except Exception:
    pass

skip_no_lib = pytest.mark.skipif(not _LIB_AVAILABLE, reason="libxquic_wt_py not available")


# --- session_id varint ---

@skip_no_lib
@pytest.mark.parametrize("sid", [0, 1, 63, 64, 16383, 16384, 2**30 - 1, 2**30])
def test_session_id_roundtrip(sid):
    buf = ffi.new("uint8_t[16]")
    written = lib.xqc_wt_encode_session_id(sid, buf, 16)
    assert written > 0

    out = ffi.new("uint64_t *")
    consumed = lib.xqc_wt_decode_session_id(buf, written, out)
    assert consumed == written
    assert out[0] == sid


@skip_no_lib
def test_session_id_buffer_too_small():
    buf = ffi.new("uint8_t[1]")
    # Large session_id needs more than 1 byte
    written = lib.xqc_wt_encode_session_id(2**30, buf, 1)
    assert written == 0


# --- HTTP Datagram session demux ---

@skip_no_lib
def test_h3_datagram_session_id_uses_quarter_stream_id():
    """HTTP Datagrams carry Quarter Stream ID, not raw WT session_id."""
    buf = ffi.new("uint8_t[16]")
    written = lib.xqc_wt_encode_h3_datagram_session_id(4, buf, 16)
    assert written == 1
    assert bytes(ffi.buffer(buf, written)) == b"\x01"

    out = ffi.new("uint64_t *")
    consumed = lib.xqc_wt_decode_h3_datagram_session_id(buf, written, out)
    assert consumed == written
    assert out[0] == 4


@skip_no_lib
def test_h3_datagram_session_id_rejects_non_client_bidi_stream_id():
    buf = ffi.new("uint8_t[16]")
    assert lib.xqc_wt_encode_h3_datagram_session_id(5, buf, 16) == 0


# --- CLOSE_WEBTRANSPORT_SESSION capsule ---

@skip_no_lib
def test_close_capsule_roundtrip():
    buf = ffi.new("uint8_t[512]")
    reason = b"test reason"
    written = lib.xqc_wt_encode_close_session_capsule(
        42, reason, len(reason), buf, 512)
    assert written > 0

    # Decode capsule header first
    cap_type = ffi.new("uint64_t *")
    payload_len = ffi.new("uint64_t *")
    hdr_len = lib.xqc_wt_decode_capsule_header(buf, written, cap_type, payload_len)
    assert hdr_len > 0
    assert cap_type[0] == 0x2843  # XQC_WT_CAPSULE_CLOSE_SESSION

    # Decode payload
    err_code = ffi.new("uint32_t *")
    reason_ptr = ffi.new("const uint8_t **")
    reason_len = ffi.new("size_t *")
    payload_start = hdr_len
    consumed = lib.xqc_wt_decode_close_session_capsule(
        buf + payload_start, payload_len[0],
        err_code, reason_ptr, reason_len)
    assert consumed > 0
    assert err_code[0] == 42
    assert reason_len[0] == len(reason)
    assert bytes(ffi.buffer(reason_ptr[0], reason_len[0])) == reason


@skip_no_lib
def test_close_capsule_no_reason():
    buf = ffi.new("uint8_t[512]")
    written = lib.xqc_wt_encode_close_session_capsule(0, ffi.NULL, 0, buf, 512)
    assert written > 0

    cap_type = ffi.new("uint64_t *")
    payload_len = ffi.new("uint64_t *")
    hdr_len = lib.xqc_wt_decode_capsule_header(buf, written, cap_type, payload_len)
    assert cap_type[0] == 0x2843

    err_code = ffi.new("uint32_t *")
    reason_ptr = ffi.new("const uint8_t **")
    reason_len = ffi.new("size_t *")
    lib.xqc_wt_decode_close_session_capsule(
        buf + hdr_len, payload_len[0], err_code, reason_ptr, reason_len)
    assert err_code[0] == 0
    assert reason_len[0] == 0


# --- DRAIN_WEBTRANSPORT_SESSION capsule ---

@skip_no_lib
def test_drain_capsule():
    buf = ffi.new("uint8_t[64]")
    written = lib.xqc_wt_encode_drain_session_capsule(buf, 64)
    assert written > 0

    cap_type = ffi.new("uint64_t *")
    payload_len = ffi.new("uint64_t *")
    hdr_len = lib.xqc_wt_decode_capsule_header(buf, written, cap_type, payload_len)
    assert hdr_len > 0
    assert cap_type[0] == 0x78ae  # XQC_WT_CAPSULE_DRAIN_SESSION (draft-15)
    assert payload_len[0] == 0  # empty payload


# --- Flow-control capsules ---

@skip_no_lib
def test_flow_control_capsule_roundtrip():
    buf = ffi.new("uint8_t[64]")
    cap_type = ffi.new("uint64_t *")
    payload_len = ffi.new("uint64_t *")
    value = ffi.new("uint64_t *")

    written = lib.xqc_wt_encode_flow_control_capsule(
        0x190B4D3D, 65536, buf, 64)
    assert written > 0

    hdr_len = lib.xqc_wt_decode_capsule_header(buf, written, cap_type, payload_len)
    assert hdr_len > 0
    assert cap_type[0] == 0x190B4D3D

    consumed = lib.xqc_wt_decode_flow_control_capsule_value(
        buf + hdr_len, payload_len[0], value)
    assert consumed == payload_len[0]
    assert value[0] == 65536


@skip_no_lib
def test_flow_control_capsule_constants_from_draft15():
    root = pathlib.Path(__file__).resolve().parents[3]
    source = (root / "src/webtransport/xqc_webtransport_wire.h").read_text()

    assert "#define XQC_WT_CAPSULE_MAX_STREAMS_BIDI 0x190B4D3F" in source
    assert "#define XQC_WT_CAPSULE_MAX_STREAMS_UNI  0x190B4D40" in source
    assert "#define XQC_WT_CAPSULE_DATA_BLOCKED     0x190B4D41" in source
    assert "#define XQC_WT_CAPSULE_STREAMS_BLOCKED_BIDI 0x190B4D43" in source
    assert "#define XQC_WT_CAPSULE_STREAMS_BLOCKED_UNI  0x190B4D44" in source
    assert "#define XQC_WT_ERROR_FLOW_CONTROL      0x045d4487" in source


# --- SETTINGS IDs ---

@skip_no_lib
def test_settings_constants():
    """Verify draft-15 WebTransport SETTINGS IDs are in source."""
    root = pathlib.Path(__file__).resolve().parents[3]
    defs = (root / "src/http3/xqc_h3_defs.h").read_text()
    frame = (root / "src/http3/frame/xqc_h3_frame.c").read_text()

    assert "XQC_H3_SETTINGS_WT_ENABLED" in defs
    assert "0x2c7cf000" in defs
    assert "XQC_H3_SETTINGS_WT_INITIAL_MAX_STREAMS_UNI" in defs
    assert "0x2b64" in defs
    assert "XQC_H3_SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI" in defs
    assert "0x2b65" in defs
    assert "XQC_H3_SETTINGS_WT_INITIAL_MAX_DATA" in defs
    assert "0x2b61" in defs
    assert "XQC_H3_SETTINGS_WEBTRANSPORT_MAX_SESSIONS" not in frame
