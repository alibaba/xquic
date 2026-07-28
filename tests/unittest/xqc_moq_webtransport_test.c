/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include <string.h>

#include "moq/moq_media/xqc_moq_container_loc.h"
#include "moq/moq_media/xqc_moq_datachannel.h"
#include "moq/moq_media/xqc_moq_media_track.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_transport/xqc_moq_stream_webtransport.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/transport/xqc_conn.h"
#include "src/webtransport/xqc_webtransport_conn.h"
#include "src/webtransport/xqc_webtransport_stream.h"
#include "xqc_common_test.h"
#include "xqc_moq_webtransport_test.h"

typedef struct {
    size_t calls;
} xqc_moq_short_write_state_t;

static int
xqc_test_moq_wt_session_create_notify(xqc_webtransport_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *h3c_user_data)
{
    return XQC_OK;
}

static ssize_t
xqc_test_moq_short_write(void *trans_stream, uint8_t *data, size_t data_len,
    uint8_t fin)
{
    xqc_moq_short_write_state_t *state =
        (xqc_moq_short_write_state_t *)trans_stream;
    state->calls++;
    if (state->calls == 1) {
        return 3;
    }
    return -XQC_EAGAIN;
}

void
xqc_test_moq_stream_retries_after_short_write(void)
{
    uint8_t write_buf[8] = {0};
    xqc_moq_short_write_state_t state = {0};
    xqc_moq_stream_t stream;
    memset(&stream, 0, sizeof(stream));
    stream.trans_stream = &state;
    stream.trans_ops.write = xqc_test_moq_short_write;
    stream.write_buf = write_buf;
    stream.write_buf_len = sizeof(write_buf);
    stream.write_stream_fin = 1;

    xqc_int_t ret = xqc_moq_stream_write(&stream);

    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(state.calls, 2);
    CU_ASSERT_EQUAL(stream.write_buf_processed, 3);
}

void
xqc_test_moq_session_destroy_clears_user_session(void)
{
    xqc_moq_user_session_t user_session;
    xqc_log_t log;
    memset(&user_session, 0, sizeof(user_session));
    memset(&log, 0, sizeof(log));

    xqc_moq_session_t *session = xqc_calloc(1, sizeof(*session));
    CU_ASSERT_PTR_NOT_NULL_FATAL(session);
    session->user_session = &user_session;
    session->log = &log;
    session->closing = XQC_TRUE;
    user_session.session = session;
    xqc_init_list_head(&session->local_subscribe_list);
    xqc_init_list_head(&session->peer_subscribe_list);
    xqc_init_list_head(&session->track_list_for_pub);
    xqc_init_list_head(&session->track_list_for_sub);
    xqc_init_list_head(&session->wt_stream_list);

    xqc_moq_session_destroy(session);

    CU_ASSERT_PTR_NULL(user_session.session);
}

void
xqc_test_moq_wt_rejects_duplicate_control_stream(void)
{
    xqc_moq_user_session_t user_session;
    xqc_log_t log;
    memset(&user_session, 0, sizeof(user_session));
    memset(&log, 0, sizeof(log));

    xqc_connection_t conn;
    memset(&conn, 0, sizeof(conn));
    conn.log = &log;
    conn.conn_type = XQC_CONN_TYPE_SERVER;
    conn.user_data = &user_session;

    xqc_h3_conn_t h3_conn;
    memset(&h3_conn, 0, sizeof(h3_conn));
    h3_conn.conn = &conn;
    h3_conn.log = &log;

    xqc_wt_conn_t wt_conn;
    memset(&wt_conn, 0, sizeof(wt_conn));
    wt_conn.h3_conn = &h3_conn;

    xqc_wt_session_t wt_session;
    memset(&wt_session, 0, sizeof(wt_session));
    wt_session.wt_conn = &wt_conn;
    wt_session.session_id = 4;

    xqc_moq_session_t moq_session;
    memset(&moq_session, 0, sizeof(moq_session));
    moq_session.log = &log;
    moq_session.user_session = &user_session;
    moq_session.transport_type = XQC_MOQ_TRANSPORT_WEBTRANSPORT;
    moq_session.trans_conn = &wt_session;
    user_session.session = &moq_session;
    xqc_init_list_head(&moq_session.local_subscribe_list);
    xqc_init_list_head(&moq_session.peer_subscribe_list);
    xqc_init_list_head(&moq_session.track_list_for_pub);
    xqc_init_list_head(&moq_session.track_list_for_sub);
    xqc_init_list_head(&moq_session.wt_stream_list);

    xqc_stream_t stream;
    memset(&stream, 0, sizeof(stream));
    stream.stream_id = 0;
    stream.stream_conn = &conn;

    xqc_h3_stream_t h3_stream;
    memset(&h3_stream, 0, sizeof(h3_stream));
    h3_stream.h3c = &h3_conn;
    h3_stream.log = &log;
    h3_stream.stream = &stream;
    h3_stream.stream_id = stream.stream_id;

    xqc_wt_bidistream_t *bidi = xqc_wt_create_bidistream(&h3_stream,
        &wt_session, NULL, NULL, XQC_TRUE);
    CU_ASSERT_PTR_NOT_NULL_FATAL(bidi);

    xqc_int_t ret =
        xqc_moq_wt_stream_callbacks.wt_bidistream_create_notify(
            bidi, &wt_session, NULL);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    xqc_moq_stream_t *control = moq_session.ctl_stream;
    CU_ASSERT_PTR_NOT_NULL_FATAL(control);

    ret =
        xqc_moq_wt_stream_callbacks.wt_bidistream_create_notify(
            bidi, &wt_session, NULL);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_PTR_EQUAL(moq_session.ctl_stream, control);

    xqc_stream_t duplicate_stream;
    memset(&duplicate_stream, 0, sizeof(duplicate_stream));
    duplicate_stream.stream_id = 4;
    duplicate_stream.stream_conn = &conn;

    xqc_h3_stream_t duplicate_h3_stream;
    memset(&duplicate_h3_stream, 0, sizeof(duplicate_h3_stream));
    duplicate_h3_stream.h3c = &h3_conn;
    duplicate_h3_stream.log = &log;
    duplicate_h3_stream.stream = &duplicate_stream;
    duplicate_h3_stream.stream_id = duplicate_stream.stream_id;

    xqc_wt_bidistream_t *duplicate_bidi = xqc_wt_create_bidistream(
        &duplicate_h3_stream, &wt_session, NULL, NULL, XQC_TRUE);
    CU_ASSERT_PTR_NOT_NULL_FATAL(duplicate_bidi);

    ret =
        xqc_moq_wt_stream_callbacks.wt_bidistream_create_notify(
            duplicate_bidi, &wt_session, NULL);
    CU_ASSERT_EQUAL(ret, -XQC_EPROTO);
    CU_ASSERT_PTR_EQUAL(moq_session.ctl_stream, control);

    moq_session.closing = XQC_TRUE;
    xqc_moq_wt_cleanup_stream_list(&moq_session);
    xqc_wt_bidistream_destroy(bidi);
    xqc_wt_bidistream_destroy(duplicate_bidi);
}

void
xqc_test_moq_legacy_wt_init_requires_session_callbacks(void)
{
    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);

    xqc_int_t ret = xqc_moq_init_alpn(engine, NULL,
        XQC_MOQ_TRANSPORT_WEBTRANSPORT);
    CU_ASSERT_EQUAL(ret, -XQC_EPARAM);

    xqc_engine_destroy(engine);
}

void
xqc_test_moq_wt_init_requires_session_create_notify(void)
{
    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);

    xqc_webtransport_session_callbacks_t session_cbs;
    memset(&session_cbs, 0, sizeof(session_cbs));
    xqc_int_t ret = xqc_moq_init_webtransport(engine, NULL, &session_cbs);
    CU_ASSERT_EQUAL(ret, -XQC_EPARAM);
    xqc_engine_destroy(engine);

    engine = test_create_engine();
    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);
    session_cbs.webtransport_session_create_notify =
        xqc_test_moq_wt_session_create_notify;
    ret = xqc_moq_init_webtransport(engine, NULL, &session_cbs);
    CU_ASSERT_EQUAL(ret, XQC_OK);

    xqc_engine_destroy(engine);
}

void
xqc_test_moq_wt_uni_retries_after_stream_credit(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    xqc_engine_t *engine = conn->engine;

    xqc_h3_conn_t h3_conn;
    memset(&h3_conn, 0, sizeof(h3_conn));
    h3_conn.conn = conn;
    h3_conn.log = engine->log;

    xqc_wt_conn_t *wt_conn = xqc_wt_conn_create(&h3_conn);
    CU_ASSERT_PTR_NOT_NULL_FATAL(wt_conn);
    h3_conn.wt_conn = wt_conn;

    xqc_wt_session_t *wt_session = xqc_wt_session_init(4, wt_conn, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(wt_session);
    CU_ASSERT_EQUAL(xqc_wt_session_mark_established(wt_session), XQC_OK);
    wt_session->flow_control_enabled = XQC_TRUE;
    wt_session->peer_max_streams_uni = 0;
    wt_session->peer_max_data = 1024;

    xqc_moq_session_t moq_session;
    memset(&moq_session, 0, sizeof(moq_session));
    moq_session.transport_type = XQC_MOQ_TRANSPORT_WEBTRANSPORT;
    moq_session.trans_conn = wt_session;
    moq_session.quic_conn = conn;
    moq_session.engine = engine;
    moq_session.log = engine->log;
    moq_session.timer_manager = &conn->conn_timer_manager;
    moq_session.enable_fec = XQC_TRUE;
    moq_session.fec_code_rate = 0.5;
    xqc_init_list_head(&moq_session.local_subscribe_list);
    xqc_init_list_head(&moq_session.peer_subscribe_list);
    xqc_init_list_head(&moq_session.track_list_for_pub);
    xqc_init_list_head(&moq_session.track_list_for_sub);
    xqc_init_list_head(&moq_session.wt_stream_list);

    xqc_moq_media_track_t media_track;
    memset(&media_track, 0, sizeof(media_track));
    media_track.track.session = &moq_session;
    media_track.track.track_alias = 1;
    media_track.track.track_info.track_name = "test";
    media_track.track.track_info.track_type = XQC_MOQ_TRACK_VIDEO;
    media_track.container_ops = xqc_moq_loc_ops;
    xqc_init_list_head(&media_track.write_stream_list);

    uint8_t payload = 0x42;
    xqc_moq_video_frame_t frame = {
        .type = XQC_MOQ_VIDEO_KEY,
        .seq_num = 1,
        .timestamp_us = 1,
        .video_data = &payload,
        .video_len = 1,
    };
    xqc_int_t ret = xqc_moq_write_video_frame(&moq_session, 1,
        &media_track.track, &frame);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_PTR_NOT_EQUAL(media_track.write_stream_list.next,
        &media_track.write_stream_list);

    xqc_moq_stream_t *stream = xqc_list_entry(
        media_track.write_stream_list.next, xqc_moq_stream_t, list_member);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream->write_buf);
    CU_ASSERT(stream->write_buf_len > 0);
    CU_ASSERT_EQUAL(stream->write_buf_processed, 0);
    CU_ASSERT_PTR_NULL(stream->trans_ops.quic_stream(stream->trans_stream));

    wt_session->peer_max_streams_uni = 1;
    xqc_timer_expire(moq_session.timer_manager,
        xqc_monotonic_timestamp() + 100 * 1000);
    xqc_stream_t *quic_stream =
        stream->trans_ops.quic_stream(stream->trans_stream);
    CU_ASSERT_PTR_NOT_NULL_FATAL(quic_stream);
    CU_ASSERT_EQUAL(wt_session->sent_streams_uni, 1);
    CU_ASSERT_EQUAL(quic_stream->stream_fec_ctl.enable_fec, 1);
    CU_ASSERT_DOUBLE_EQUAL(quic_stream->stream_fec_ctl.fec_code_rate,
        moq_session.fec_code_rate, 0.0001);

    xqc_moq_track_t datachannel_track;
    memset(&datachannel_track, 0, sizeof(datachannel_track));
    datachannel_track.session = &moq_session;
    datachannel_track.track_alias = 2;
    moq_session.datachannel.ready = 1;
    moq_session.datachannel.peer_subscribe_id = 2;
    moq_session.datachannel.track_for_pub = &datachannel_track;

    ret = xqc_moq_write_datachannel(&moq_session, &payload, sizeof(payload));
    CU_ASSERT_EQUAL(ret, XQC_OK);
    xqc_moq_stream_t *datachannel_stream =
        moq_session.datachannel.ordered_stream;
    CU_ASSERT_PTR_NOT_NULL_FATAL(datachannel_stream);
    CU_ASSERT_PTR_NULL(datachannel_stream->trans_ops.quic_stream(
        datachannel_stream->trans_stream));

    wt_session->peer_max_streams_uni = 2;
    xqc_timer_expire(moq_session.timer_manager,
        xqc_monotonic_timestamp() + 100 * 1000);
    quic_stream = datachannel_stream->trans_ops.quic_stream(
        datachannel_stream->trans_stream);
    CU_ASSERT_PTR_NOT_NULL_FATAL(quic_stream);
    CU_ASSERT_EQUAL(quic_stream->stream_priority, XQC_STREAM_PRI_HIGH);

    moq_session.closing = XQC_TRUE;
    xqc_moq_wt_cleanup_stream_list(&moq_session);
    xqc_wt_conn_close(wt_conn);
    h3_conn.wt_conn = NULL;
    xqc_engine_destroy(engine);
}

void
xqc_test_moq_wt_uni_reset_waits_for_final_close(void)
{
    xqc_moq_user_session_t user_session;
    xqc_log_t log;
    memset(&user_session, 0, sizeof(user_session));
    memset(&log, 0, sizeof(log));

    xqc_connection_t conn;
    memset(&conn, 0, sizeof(conn));
    conn.log = &log;
    conn.conn_type = XQC_CONN_TYPE_SERVER;
    conn.user_data = &user_session;

    xqc_h3_conn_t h3_conn;
    memset(&h3_conn, 0, sizeof(h3_conn));
    h3_conn.conn = &conn;
    h3_conn.log = &log;

    xqc_wt_conn_t wt_conn;
    memset(&wt_conn, 0, sizeof(wt_conn));
    wt_conn.h3_conn = &h3_conn;

    xqc_wt_session_t wt_session;
    memset(&wt_session, 0, sizeof(wt_session));
    wt_session.wt_conn = &wt_conn;
    wt_session.session_id = 4;

    xqc_moq_session_t moq_session;
    memset(&moq_session, 0, sizeof(moq_session));
    moq_session.log = &log;
    moq_session.user_session = &user_session;
    moq_session.transport_type = XQC_MOQ_TRANSPORT_WEBTRANSPORT;
    moq_session.trans_conn = &wt_session;
    user_session.session = &moq_session;
    xqc_init_list_head(&moq_session.local_subscribe_list);
    xqc_init_list_head(&moq_session.peer_subscribe_list);
    xqc_init_list_head(&moq_session.track_list_for_pub);
    xqc_init_list_head(&moq_session.track_list_for_sub);
    xqc_init_list_head(&moq_session.wt_stream_list);

    xqc_stream_t stream;
    memset(&stream, 0, sizeof(stream));
    stream.stream_id = 2;
    stream.stream_conn = &conn;

    xqc_h3_stream_t h3_stream;
    memset(&h3_stream, 0, sizeof(h3_stream));
    h3_stream.h3c = &h3_conn;
    h3_stream.log = &log;
    h3_stream.stream = &stream;
    h3_stream.stream_id = stream.stream_id;

    xqc_wt_unistream_t *uni = xqc_wt_create_unistream(
        XQC_WT_STREAM_TYPE_RECV, &wt_session, NULL, &h3_stream);
    CU_ASSERT_PTR_NOT_NULL_FATAL(uni);

    xqc_int_t ret =
        xqc_moq_wt_stream_callbacks.wt_unistream_create_notify(
            uni, &wt_session, NULL);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_PTR_NOT_EQUAL(moq_session.wt_stream_list.next,
        &moq_session.wt_stream_list);

    ret = xqc_moq_wt_stream_callbacks.wt_unistream_closing_notify(
        uni, &wt_session, NULL);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_PTR_NOT_EQUAL(moq_session.wt_stream_list.next,
        &moq_session.wt_stream_list);

    ret = xqc_moq_wt_stream_callbacks.wt_unistream_close_notify(
        uni, &wt_session, NULL);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_PTR_EQUAL(moq_session.wt_stream_list.next,
        &moq_session.wt_stream_list);

    xqc_wt_unistream_destroy(uni);
}
