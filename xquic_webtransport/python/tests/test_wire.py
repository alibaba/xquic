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


@skip_no_lib
def test_close_capsule_reason_limit_is_1024_bytes():
    buf = ffi.new("uint8_t[1100]")
    reason = b"x" * 1024
    written = lib.xqc_wt_encode_close_session_capsule(
        7, reason, len(reason), buf, 1100)
    assert written > 0

    too_long = b"x" * 1025
    assert lib.xqc_wt_encode_close_session_capsule(
        7, too_long, len(too_long), buf, 1100) == 0


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


# --- WebTransport application error code mapping ---

@skip_no_lib
def test_application_error_code_maps_to_h3_reserved_range():
    # draft-15 maps app code N into the H3 reserved range, skipping grease values.
    assert lib.xqc_wt_app_error_to_h3(0) == 0x52E4A40FA8DB
    assert lib.xqc_wt_app_error_to_h3(29) == 0x52E4A40FA8F8
    assert lib.xqc_wt_app_error_to_h3(30) == 0x52E4A40FA8FA

    app = ffi.new("uint32_t *")
    assert lib.xqc_wt_h3_error_to_app(0x52E4A40FA8DB, app) == 1
    assert app[0] == 0
    assert lib.xqc_wt_h3_error_to_app(0x52E4A40FA8FA, app) == 1
    assert app[0] == 30


@skip_no_lib
def test_application_error_code_mapping_rejects_non_wt_h3_codes():
    app = ffi.new("uint32_t *")
    assert lib.xqc_wt_h3_error_to_app(0x100, app) == 0
    assert lib.xqc_wt_h3_error_to_app(0x52E4A40FA8F9, app) == 0


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
    assert "webtransport_mode" in frame
    assert "XQC_H3_SETTINGS_ENABLE_WEBTRANSPORT" in frame
    assert "XQC_H3_SETTINGS_WEBTRANSPORT_MAX_SESSIONS" in frame


def test_legacy_browser_webtransport_protocol_token_is_accepted():
    """Safari may still use the legacy Extended CONNECT :protocol token."""
    root = pathlib.Path(__file__).resolve().parents[3]
    ctx = (root / "src/webtransport/xqc_webtransport_ctx.c").read_text()

    assert 'check_str_equal(request_name, "webtransport-h3")' in ctx
    assert 'check_str_equal(request_name, "webtransport")' in ctx


def test_safari_legacy_mode_is_explicit_server_option():
    """Safari 26.4 requires legacy WT SETTINGS without draft-15 WT_INITIAL_*."""
    root = pathlib.Path(__file__).resolve().parents[3]
    py_server = (root / "xquic_webtransport/python/pyxquic_wt/_server.py").read_text()
    cffi_defs = (root / "xquic_webtransport/python/pyxquic_wt/_cffi_defs.py").read_text()

    assert 'webtransport_mode: str = "draft15"' in py_server
    assert '"compat"' in py_server
    assert 'webtransport_mode == "legacy"' in py_server
    assert "xqc_wt_py_server_set_browser_legacy_mode" in cffi_defs
    assert "xqc_wt_py_server_set_browser_compat_mode" in cffi_defs


def test_webtransport_mode_is_enum_not_bool_pair():
    """WT SETTINGS/FC behavior should be selected by one explicit mode."""
    root = pathlib.Path(__file__).resolve().parents[3]
    h = (root / "include/xquic/xqc_http3.h").read_text()
    frame = (root / "src/http3/frame/xqc_h3_frame.c").read_text()
    session = (root / "src/webtransport/xqc_webtransport_session.c").read_text()

    assert "typedef enum xqc_wt_mode_e" in h
    assert "XQC_WT_MODE_DRAFT15_STRICT" in h
    assert "XQC_WT_MODE_BROWSER_LEGACY" in h
    assert "XQC_WT_MODE_BROWSER_COMPAT" in h
    assert "webtransport_mode" in h
    assert "webtransport_legacy_compat" not in h
    assert "webtransport_browser_compat" not in h
    assert "webtransport_mode != XQC_WT_MODE_BROWSER_LEGACY" in frame
    assert "XQC_WT_MODE_DRAFT15_STRICT" in session


def test_reset_stream_at_preserves_reliable_prefix_in_transport():
    """RESET_STREAM_AT must not degrade to ordinary RESET_STREAM receive behavior."""
    root = pathlib.Path(__file__).resolve().parents[3]
    stream_h = (root / "src/transport/xqc_stream.h").read_text()
    frame_c = (root / "src/transport/xqc_frame.c").read_text()
    stream_c = (root / "src/transport/xqc_stream.c").read_text()

    assert "reset_at_reliable_size" in stream_h
    assert "xqc_stream_data_keep_reliable_prefix" in frame_c
    reset_at_body = frame_c.split("xqc_process_reset_stream_at_frame", 1)[1]
    reset_at_body = reset_at_body.split("xqc_process_stop_sending_frame", 1)[0]
    assert "xqc_destroy_frame_list(&stream->stream_data_in.frames_tailq)" not in reset_at_body
    assert "reliable_reset" in stream_c


def test_datagram_invalid_session_id_is_strict_error_path():
    """Malformed or unknown datagram session ids must close with H3_ID_ERROR."""
    root = pathlib.Path(__file__).resolve().parents[3]
    ctx = (root / "src/webtransport/xqc_webtransport_ctx.c").read_text()

    assert "xqc_wt_close_invalid_dgram_conn" in ctx
    assert "xqc_conn_close_with_error(conn, H3_ID_ERROR)" in ctx
    assert "wt_session == NULL" in ctx
    assert "xqc_wt_buffer_pending_dgram(wt_conn, session_id" in ctx


def test_wt_send_eagain_is_not_reported_as_zero_after_partial_send():
    """WT stream send wrappers must not hide EAGAIN/partial state as success=0."""
    root = pathlib.Path(__file__).resolve().parents[3]
    stream_c = (root / "src/webtransport/xqc_webtransport_stream.c").read_text()
    stream_h = (root / "src/webtransport/xqc_webtransport_stream.h").read_text()
    assert "if (ret == -XQC_EAGAIN)" not in stream_c
    assert "return 0;" not in stream_c.split("xqc_wt_bidistream_send_inner", 1)[1].split(
        "xqc_wt_bidistream_send(", 1)[0]
    assert "send_header_sent" in stream_h
    assert "send_header_len" in stream_h
    assert "xqc_wt_send_stream_send_with_header" in stream_c


def test_python_stream_mapping_removed_only_after_fin_is_sent():
    """A partial payload write with fin=True must keep the C stream mapping for retry."""
    root = pathlib.Path(__file__).resolve().parents[3]
    api_c = (root / "src/webtransport/xqc_wt_py_api.c").read_text()
    stream_send_body = api_c.split("xqc_wt_py_stream_send", 1)[1].split(
        "int\nxqc_wt_py_send_datagram", 1)[0]

    assert "fin && se->bidi_stream && se->bidi_stream->send_fin" in stream_send_body
    assert "fin && ue->unistream && ue->unistream->fin.send_fin" in stream_send_body
    assert "if (fin) {\n                py_remove_stream_h" not in stream_send_body
    assert "if (fin) {\n                    xqc_wt_unistream_close" not in stream_send_body


def test_server_stream_mapping_uses_session_and_wire_stream_id():
    """Server Python stream ids must not be recovered from stale reused C pointers."""
    root = pathlib.Path(__file__).resolve().parents[3]
    api_c = (root / "src/webtransport/xqc_wt_py_api.c").read_text()
    find_body = api_c.split("py_server_find_stream_id_by_h3", 1)[1].split(
        "static uint64_t\npy_server_get_or_create_stream_id", 1)[0]

    assert "owner_session_id" in find_body
    assert "wire_stream_id" in find_body
    assert "e->owner_session_id == owner_session_id" in find_body
    assert "e->wire_stream_id == wire_stream_id" in find_body
    assert "e->h3_stream == h3s" not in find_body


def test_bytestream_close_finds_owner_session_before_freeing_wt_stream():
    """A QUIC connection can carry multiple WT sessions; close routing must be per session."""
    root = pathlib.Path(__file__).resolve().parents[3]
    ctx_c = (root / "src/webtransport/xqc_webtransport_ctx.c").read_text()
    helper_body = ctx_c.split("xqc_wt_conn_find_pending_stream", 1)[1].split(
        "/* bytestream callbacks", 1)[0]
    close_body = ctx_c.split("wt_bs_close_notify", 1)[1].split(
        "static int\nwt_bs_read_notify", 1)[0]

    assert "wt_conn->sessions" in helper_body
    assert "session->pending_unistreams" in helper_body
    assert "owner_session" in helper_body
    assert "xqc_wt_conn_find_pending_stream(wt_conn, stream_id, &wt_session)" in close_body
    assert "xqc_id_hash_delete(wt_session->pending_unistreams, stream_id)" in close_body
    assert "wt_conn->wt_session->pending_unistreams" not in close_body


def test_unistream_create_callback_waits_for_decoded_session_id():
    """WT uni streams carry session id in stream data; create callback must use that owner."""
    root = pathlib.Path(__file__).resolve().parents[3]
    ctx_c = (root / "src/webtransport/xqc_webtransport_ctx.c").read_text()
    create_body = ctx_c.split("xqc_wt_unknown_unistream_notify", 1)[1].split(
        "int\nxqc_wt_unknown_unistream_recvdata_notify", 1)[0]
    recv_body = ctx_c.split("xqc_wt_unknown_unistream_recvdata_notify", 1)[1].split(
        "/* public wrappers called from H3 layer", 1)[0]

    assert "wt_unistream_create_notify" not in create_body
    assert "xqc_wt_conn_find_session(wt_conn, session_id)" in recv_body
    assert "xqc_wt_conn_move_pending_stream(owner_session, wt_session" in recv_body
    assert "first_parse && wt_ctx && wt_ctx->stream_cbs.wt_unistream_create_notify" in recv_body
    assert "wt_unistream_create_notify(wt_unistream, wt_session" in recv_body


def test_wt_stream_frame_type_is_rejected_outside_first_bytes():
    """draft-15: WT_STREAM 0x41 is not a normal H3 frame outside stream prefix."""
    root = pathlib.Path(__file__).resolve().parents[3]
    h3_stream = (root / "src/http3/xqc_h3_stream.c").read_text()

    assert "xqc_h3_stream_is_forbidden_wt_stream_frame" in h3_stream
    assert "pctx->frame.type == (xqc_h3_frm_type_t)XQC_H3_STREAM_TYPE_WT_BIDI" in h3_stream
    assert "return -H3_FRAME_ERROR" in h3_stream


def test_pending_datagram_overflow_is_drop_not_session_close():
    """draft-15 says excessive buffered datagrams SHALL be dropped."""
    root = pathlib.Path(__file__).resolve().parents[3]
    ctx = (root / "src/webtransport/xqc_webtransport_ctx.c").read_text()

    assert "xqc_wt_drop_buffer_overflow_dgram" in ctx
    assert "optimistic datagram buffer exceeded" not in ctx
    assert "xqc_wt_close_buffer_overflow_session" not in ctx


def test_no_flow_control_rejects_multiple_simultaneous_sessions():
    """draft-15 forbids multiple simultaneous sessions when WT FC is not enabled."""
    root = pathlib.Path(__file__).resolve().parents[3]
    conn_h = (root / "src/webtransport/xqc_webtransport_conn.h").read_text()
    conn_c = (root / "src/webtransport/xqc_webtransport_conn.c").read_text()
    ctx = (root / "src/webtransport/xqc_webtransport_ctx.c").read_text()

    assert "active_session_count" in conn_h
    assert "xqc_wt_conn_has_active_session_without_fc" in conn_c
    assert "H3_REQUEST_REJECTED" in ctx
    assert "xqc_wt_conn_has_active_session_without_fc(wt_conn, session)" in ctx


def test_closed_session_id_is_not_treated_as_h3_id_error():
    """draft-15: session IDs for closed sessions are valid and must not close H3."""
    root = pathlib.Path(__file__).resolve().parents[3]
    conn_h = (root / "src/webtransport/xqc_webtransport_conn.h").read_text()
    conn_c = (root / "src/webtransport/xqc_webtransport_conn.c").read_text()
    ctx = (root / "src/webtransport/xqc_webtransport_ctx.c").read_text()

    assert "closed_sessions" in conn_h
    assert "xqc_wt_conn_mark_session_closed" in conn_c
    assert "xqc_wt_conn_is_closed_session(wt_conn, session_id)" in ctx
    assert "xqc_wt_abort_closed_session_stream" in ctx


def test_wt_abort_helpers_do_not_write_during_conn_teardown():
    """Session teardown from conn_destroy must not emit RESET/STOP on closing conn."""
    root = pathlib.Path(__file__).resolve().parents[3]
    stream_c = (root / "src/webtransport/xqc_webtransport_stream.c").read_text()

    assert "xqc_wt_conn_can_send_abort" in stream_c
    assert "conn->conn_state < XQC_CONN_STATE_CLOSING" in stream_c
    assert stream_c.count("!xqc_wt_conn_can_send_abort(conn)") >= 4


def test_wt_active_bidi_creation_cleans_transport_stream_on_mid_failure():
    """If WT wrapper registration fails after QUIC stream creation, the stream is destroyed."""
    root = pathlib.Path(__file__).resolve().parents[3]
    ctx = (root / "src/webtransport/xqc_webtransport_ctx.c").read_text()
    py_api = (root / "src/webtransport/xqc_wt_py_api.c").read_text()

    send_bidi_body = ctx.split("xqc_wt_session_send_bidi", 1)[1].split(
        "const xqc_cid_t *", 1)[0]
    create_bidi_body = py_api.split("xqc_wt_py_create_bidi_stream", 1)[1].split(
        "ssize_t\nxqc_wt_py_stream_send", 1)[0]
    assert "xqc_destroy_stream(stream)" in send_bidi_body
    assert "xqc_destroy_stream(stream)" in create_bidi_body


def test_wt_reservation_api_requires_non_null_reservation():
    """Reservation API must not mutate global reserved counters without a token."""
    root = pathlib.Path(__file__).resolve().parents[3]
    session_c = (root / "src/webtransport/xqc_webtransport_session.c").read_text()
    reserve_body = session_c.split("xqc_wt_session_reserve_outgoing", 1)[1].split(
        "void\nxqc_wt_session_rollback_outgoing", 1)[0]

    assert "session == NULL || reservation == NULL" in reserve_body
    assert "memset(reservation, 0, sizeof(*reservation));" in reserve_body


def test_allowed_origins_api_rejects_truncation():
    """Origin allowlist setup must fail instead of silently truncating entries."""
    root = pathlib.Path(__file__).resolve().parents[3]
    api_c = (root / "src/webtransport/xqc_wt_py_api.c").read_text()
    api_h = (root / "src/webtransport/xqc_wt_py_api.h").read_text()
    cffi_defs = (root / "xquic_webtransport/python/pyxquic_wt/_cffi_defs.py").read_text()
    py_server = (root / "xquic_webtransport/python/pyxquic_wt/_server.py").read_text()

    assert "int xqc_wt_py_server_set_allowed_origins" in api_h
    assert "int xqc_wt_py_server_set_allowed_origins" in cffi_defs
    assert "len >= sizeof(server->allowed_origins[0])" in api_c
    assert "return -XQC_ELIMIT" in api_c
    assert "allowed_origins entries must be shorter than 256 bytes" in py_server


def test_python_c_callbacks_match_webtransport_api():
    root = pathlib.Path(__file__).resolve().parents[3]
    api_c = (root / "src/webtransport/xqc_wt_py_api.c").read_text()

    assert "py_client_handshake_done(xqc_webtransport_conn_t *conn, void *user_data)" in api_c
    assert ".webtransport_conn_handshake_finished_notify = py_client_handshake_done" in api_c
    assert "webtransport_session_handshake_finished_notify" not in api_c
    assert "py_client_uni_read(xqc_wt_unistream_t *stream, xqc_wt_session_t *session,\n    void *data, size_t data_len, uint8_t fin, void *strm_user_data)" in api_c
    assert "py_client_bidi_read_ex(xqc_wt_bidistream_t *stream, xqc_wt_session_t *session,\n    void *data, size_t data_len, uint8_t fin, void *strm_user_data)" in api_c
    assert "py_server_bidi_read_ex(xqc_wt_bidistream_t *bidi_stream, xqc_wt_session_t *session,\n    void *data, size_t data_len, uint8_t fin, void *strm_user_data)" in api_c


def test_wt_test_client_is_parameterized_for_sessions_and_streams():
    root = pathlib.Path(__file__).resolve().parents[3]
    client_c = (root / "src/webtransport/wt_test_client.c").read_text()

    assert "xqc_webtransport_session_t *sessions[32]" not in client_c
    assert "wt_stream_read_state_t stream_reads[8]" not in client_c
    assert "--sessions" in client_c
    assert "--streams" in client_c
    assert "--size" in client_c
    assert "--count" in client_c
    assert "--timeout" in client_c
    assert "ctx_s.target_sessions = 2;" not in client_c
    assert "ctx_s.sessions = calloc" in client_c
    assert "ctx_s.stream_reads = calloc" in client_c
