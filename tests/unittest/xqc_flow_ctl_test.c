/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_flow_ctl_test.h"
#include <CUnit/CUnit.h>
#include <stdint.h>
#include <string.h>
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_stream.h"
#include "xqc_common_test.h"

/*
 * Place the receive limit less than one window below the bound so a single
 * growth step has to cross it.
 */
#define XQC_TEST_FC_NEAR_LIMIT (XQC_MAX_FLOW_CONTROL_WINDOW - 100)


/**
 * Test: xqc_clamp_to_max_flow_ctl bounds every input at the RFC 9000
 * variable-length integer maximum and leaves smaller values untouched.
 */
void
xqc_test_flow_ctl_clamp_boundary(void)
{
    CU_ASSERT_EQUAL(XQC_MAX_FLOW_CONTROL_WINDOW, ((uint64_t)1 << 62) - 1);

    /* below the bound passes through unchanged */
    CU_ASSERT_EQUAL(xqc_clamp_to_max_flow_ctl(0), 0);
    CU_ASSERT_EQUAL(xqc_clamp_to_max_flow_ctl(XQC_MAX_RECV_WINDOW), XQC_MAX_RECV_WINDOW);
    CU_ASSERT_EQUAL(xqc_clamp_to_max_flow_ctl(XQC_MAX_FLOW_CONTROL_WINDOW - 1),
                    XQC_MAX_FLOW_CONTROL_WINDOW - 1);

    /* exactly at the bound passes through unchanged */
    CU_ASSERT_EQUAL(xqc_clamp_to_max_flow_ctl(XQC_MAX_FLOW_CONTROL_WINDOW),
                    XQC_MAX_FLOW_CONTROL_WINDOW);

    /* one above the bound, and far above it, are clamped */
    CU_ASSERT_EQUAL(xqc_clamp_to_max_flow_ctl(XQC_MAX_FLOW_CONTROL_WINDOW + 1),
                    XQC_MAX_FLOW_CONTROL_WINDOW);
    CU_ASSERT_EQUAL(xqc_clamp_to_max_flow_ctl(UINT64_MAX), XQC_MAX_FLOW_CONTROL_WINDOW);
}


/**
 * Test: the stream-level growth path in xqc_stream_do_recv_flow_ctl stops at
 * the variable-length integer maximum instead of advertising a larger
 * MAX_STREAM_DATA value.
 */
void
xqc_test_stream_flow_ctl_clamp(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    xqc_stream_t *stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);

    /* keep the window-sizing branches deterministic */
    stream->recv_rate_bytes_per_sec = 0;
    stream->stream_flow_ctl.fc_last_window_update_time = 0;

    /* the whole window has been consumed, so growth is due */
    stream->stream_flow_ctl.fc_max_stream_data_can_recv = XQC_TEST_FC_NEAR_LIMIT;
    stream->stream_data_in.next_read_offset = XQC_TEST_FC_NEAR_LIMIT;
    stream->stream_flow_ctl.fc_stream_recv_window_size = XQC_MAX_RECV_WINDOW;

    CU_ASSERT_EQUAL(xqc_stream_do_recv_flow_ctl(stream), XQC_OK);

    CU_ASSERT_EQUAL(stream->stream_flow_ctl.fc_max_stream_data_can_recv,
                    XQC_MAX_FLOW_CONTROL_WINDOW);

    xqc_engine_destroy(conn->engine);
}


/**
 * Test: the connection-level growth path in xqc_stream_do_recv_flow_ctl stops
 * at the variable-length integer maximum instead of advertising a larger
 * MAX_DATA value.
 */
void
xqc_test_conn_flow_ctl_clamp(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    xqc_stream_t *stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);

    /* leave the stream window fully free so only the connection level grows */
    stream->recv_rate_bytes_per_sec = 0;
    stream->stream_flow_ctl.fc_stream_recv_window_size = XQC_MAX_RECV_WINDOW;
    stream->stream_flow_ctl.fc_max_stream_data_can_recv = XQC_MAX_RECV_WINDOW;
    stream->stream_data_in.next_read_offset = 0;

    conn->conn_settings.recv_rate_bytes_per_sec = 0;
    conn->conn_flow_ctl.fc_last_window_update_time = 0;
    conn->conn_flow_ctl.fc_max_data_can_recv = XQC_TEST_FC_NEAR_LIMIT;
    conn->conn_flow_ctl.fc_data_read = XQC_TEST_FC_NEAR_LIMIT;
    conn->conn_flow_ctl.fc_recv_windows_size = XQC_MAX_RECV_WINDOW;

    CU_ASSERT_EQUAL(xqc_stream_do_recv_flow_ctl(stream), XQC_OK);

    /* the stream level stayed put, so the assertion below observes the
       connection-level clamp on its own */
    CU_ASSERT_EQUAL(stream->stream_flow_ctl.fc_max_stream_data_can_recv, XQC_MAX_RECV_WINDOW);
    CU_ASSERT_EQUAL(conn->conn_flow_ctl.fc_max_data_can_recv, XQC_MAX_FLOW_CONTROL_WINDOW);

    xqc_engine_destroy(conn->engine);
}


/**
 * Control test: a limit far below the bound still grows by the full window, so
 * the assertions above observe the clamp rather than a saturated no-op.
 */
void
xqc_test_flow_ctl_normal_no_clamp(void)
{
    uint64_t expected;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    xqc_stream_t *stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);

    stream->recv_rate_bytes_per_sec = 0;
    stream->stream_flow_ctl.fc_last_window_update_time = 0;

    stream->stream_flow_ctl.fc_max_stream_data_can_recv = 1024 * 1024;
    stream->stream_data_in.next_read_offset = 1024 * 1024;
    stream->stream_flow_ctl.fc_stream_recv_window_size = XQC_MAX_RECV_WINDOW;

    expected = stream->stream_flow_ctl.fc_max_stream_data_can_recv + XQC_MAX_RECV_WINDOW;

    CU_ASSERT_EQUAL(xqc_stream_do_recv_flow_ctl(stream), XQC_OK);

    CU_ASSERT_EQUAL(stream->stream_flow_ctl.fc_max_stream_data_can_recv, expected);
    CU_ASSERT(stream->stream_flow_ctl.fc_max_stream_data_can_recv < XQC_MAX_FLOW_CONTROL_WINDOW);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_uni_stream_credit_exhausted(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    conn->local_settings.max_streams_uni = 4;
    conn->conn_flow_ctl.fc_max_streams_uni_can_recv = 4;
    conn->conn_flow_ctl.fc_max_streams_uni_recv_wind = 4;
    conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT;

    /* RFC 9000 Section 4.6: replenish credit without STREAMS_BLOCKED. */
    for (unsigned batch = 0; batch < 3; ++batch) {
        xqc_stream_t *streams[4];
        uint64_t limit = 4 * (batch + 1);
        for (unsigned i = 0; i < 4; ++i) {
            xqc_stream_id_t id = 4 * (4 * batch + i) + XQC_SVR_UNI;
            streams[i] = xqc_passive_create_stream(conn, id, NULL);
            CU_ASSERT_PTR_NOT_NULL_FATAL(streams[i]);
        }
        CU_ASSERT_EQUAL(conn->max_stream_id_uni_remote + 1, limit);
        CU_ASSERT_EQUAL(conn->conn_flow_ctl.fc_max_streams_uni_can_recv,
                        limit);

        /* Exhaust the limit before any stream is destroyed. */
        xqc_destroy_stream(streams[0]);
        CU_ASSERT_EQUAL(conn->conn_flow_ctl.fc_max_streams_uni_can_recv,
                        limit + 1);
        for (unsigned i = 1; i < 4; ++i) {
            xqc_destroy_stream(streams[i]);
        }
        CU_ASSERT_EQUAL(conn->conn_flow_ctl.fc_max_streams_uni_recv_wind,
                        limit + 4);
        if (conn->conn_flow_ctl.fc_max_streams_uni_can_recv != limit + 1) {
            break;
        }
    }

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_uni_stream_credit_not_exhausted(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    conn->local_settings.max_streams_uni = 4;
    conn->conn_flow_ctl.fc_max_streams_uni_can_recv = 4;
    conn->conn_flow_ctl.fc_max_streams_uni_recv_wind = 4;

    xqc_stream_id_t stream_id = (0ULL << 2) | XQC_SVR_UNI;
    xqc_stream_t *stream = xqc_passive_create_stream(conn, stream_id, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
    xqc_destroy_stream(stream);
    CU_ASSERT_EQUAL(conn->conn_flow_ctl.fc_max_streams_uni_recv_wind, 5);
    CU_ASSERT_EQUAL(conn->conn_flow_ctl.fc_max_streams_uni_can_recv, 4);

    xqc_engine_destroy(conn->engine);
}


/* the number of queued or sent packets of pkt_type (any for XQC_PTYPE_NUM)
   that carry frame_bit */
static int
xqc_test_fc_count_frames(xqc_connection_t *conn,
    xqc_frame_type_bit_t frame_bit, xqc_pkt_type_t pkt_type)
{
    xqc_send_queue_t   *sndq = conn->conn_send_queue;
    xqc_list_head_t    *lists[5 + XQC_PNS_N];
    xqc_list_head_t    *pos;
    xqc_packet_out_t   *packet_out;
    int                 count = 0;
    int                 i;

    lists[0] = &sndq->sndq_send_packets;
    lists[1] = &sndq->sndq_send_packets_high_pri;
    lists[2] = &sndq->sndq_buff_1rtt_packets;
    lists[3] = &sndq->sndq_lost_packets;
    lists[4] = &sndq->sndq_pto_probe_packets;
    for (i = 0; i < XQC_PNS_N; i++) {
        lists[5 + i] = &sndq->sndq_unacked_packets[i];
    }

    for (i = 0; i < 5 + XQC_PNS_N; i++) {
        xqc_list_for_each(pos, lists[i]) {
            packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            if ((packet_out->po_frame_types & frame_bit)
                && (pkt_type == XQC_PTYPE_NUM
                    || packet_out->po_pkt.pkt_type == pkt_type))
            {
                count++;
            }
        }
    }

    return count;
}


static xqc_int_t
xqc_test_fc_write_notify(xqc_stream_t *stream, void *user_data)
{
    (*(int *) user_data)++;
    return XQC_OK;
}


/* feed one MAX_STREAMS (bidirectional) frame with a one-byte value */
static xqc_int_t
xqc_test_fc_recv_max_streams_bidi(xqc_connection_t *conn, uint8_t limit)
{
    unsigned char       frame[2] = {0x12, limit};
    xqc_packet_in_t     packet_in;

    memset(&packet_in, 0, sizeof(packet_in));
    packet_in.pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    packet_in.pos = frame;
    packet_in.last = frame + sizeof(frame);
    return xqc_process_frames(conn, &packet_in);
}


/*
 * RFC 9000 Section 4.6: three bidirectional streams are created before the
 * handshake, against the local limit, and the peer's transport parameters
 * then allow one. The two streams beyond the limit send nothing and are not
 * notified, and one STREAMS_BLOCKED reports the limit in a 1-RTT packet,
 * until a MAX_STREAMS frame covers them.
 */
void
xqc_test_stream_limit_holds_early_streams(void)
{
    static xqc_stream_callbacks_t cbs = {
        .stream_write_notify = xqc_test_fc_write_notify,
    };
    static unsigned char req[] = "GET /\r\n";
    xqc_stream_t *streams[3];
    int notified[3] = {0};
    unsigned i;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    /* as inside a callback: sends do not run the connection */
    conn->engine->eng_flag |= XQC_ENG_FLAG_RUNNING;

    for (i = 0; i < 3; i++) {
        streams[i] = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI,
                                                      &notified[i]);
        CU_ASSERT_PTR_NOT_NULL_FATAL(streams[i]);
        streams[i]->stream_if = &cbs;
    }

    /* as the peer's transport parameters set it, then 1-RTT is ready */
    conn->conn_flow_ctl.fc_max_streams_bidi_can_send = 1;
    conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT;
    conn->conn_state = XQC_CONN_STATE_ESTABED;

    CU_ASSERT(!xqc_stream_beyond_peer_limit(streams[0]));
    CU_ASSERT(xqc_stream_beyond_peer_limit(streams[1]));
    CU_ASSERT(xqc_stream_beyond_peer_limit(streams[2]));

    CU_ASSERT_EQUAL(xqc_stream_send(streams[2], req, sizeof(req) - 1, 1),
                    -XQC_EAGAIN);
    CU_ASSERT_EQUAL(streams[2]->stream_send_offset, 0);
    CU_ASSERT_EQUAL(streams[2]->stream_state_send, XQC_SEND_STREAM_ST_READY);

    xqc_process_write_streams(conn);
    xqc_process_write_streams(conn);
    CU_ASSERT_EQUAL(notified[0], 2);
    CU_ASSERT_EQUAL(notified[1], 0);
    CU_ASSERT_EQUAL(notified[2], 0);
    CU_ASSERT_EQUAL(xqc_test_fc_count_frames(conn,
                    XQC_FRAME_BIT_STREAMS_BLOCKED, XQC_PTYPE_NUM), 1);
    CU_ASSERT_EQUAL(xqc_test_fc_count_frames(conn,
                    XQC_FRAME_BIT_STREAMS_BLOCKED, XQC_PTYPE_SHORT_HEADER), 1);

    /* a credit of 2 releases stream 4 only */
    CU_ASSERT_EQUAL(xqc_test_fc_recv_max_streams_bidi(conn, 2), XQC_OK);
    xqc_process_write_streams(conn);
    CU_ASSERT_EQUAL(notified[1], 1);
    CU_ASSERT_EQUAL(notified[2], 0);
    CU_ASSERT_EQUAL(xqc_test_fc_count_frames(conn,
                    XQC_FRAME_BIT_STREAMS_BLOCKED, XQC_PTYPE_SHORT_HEADER), 2);

    CU_ASSERT_EQUAL(xqc_test_fc_recv_max_streams_bidi(conn, 3), XQC_OK);
    CU_ASSERT(!xqc_stream_beyond_peer_limit(streams[2]));
    xqc_process_write_streams(conn);
    CU_ASSERT_EQUAL(notified[2], 1);
    CU_ASSERT_EQUAL(xqc_stream_send(streams[2], req, sizeof(req) - 1, 1),
                    (ssize_t) (sizeof(req) - 1));
    CU_ASSERT_EQUAL(streams[2]->stream_send_offset, sizeof(req) - 1);
    CU_ASSERT_EQUAL(xqc_test_fc_count_frames(conn,
                    XQC_FRAME_BIT_STREAMS_BLOCKED, XQC_PTYPE_NUM), 2);

    conn->engine->eng_flag &= ~XQC_ENG_FLAG_RUNNING;
    xqc_engine_destroy(conn->engine);
}


/*
 * Only the limit for the stream's own type and direction applies, an index
 * equal to the limit is already beyond it, and peer-initiated streams are
 * never held. A creation refused before the handshake sends no
 * STREAMS_BLOCKED (RFC 9000 Section 12.4: 0-RTT and 1-RTT only), and one
 * refused after it reports each limit once (Section 19.14).
 */
void
xqc_test_stream_limit_boundaries(void)
{
    xqc_stream_t *bidi[3], *uni[2], *peer;
    unsigned i;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    for (i = 0; i < 3; i++) {
        bidi[i] = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI,
                                                   NULL);
        CU_ASSERT_PTR_NOT_NULL_FATAL(bidi[i]);
    }
    for (i = 0; i < 2; i++) {
        uni[i] = xqc_stream_create_with_direction(conn, XQC_STREAM_UNI, NULL);
        CU_ASSERT_PTR_NOT_NULL_FATAL(uni[i]);
    }
    peer = xqc_passive_create_stream(conn, (5 << 2) | XQC_SVR_BID, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(peer);

    conn->conn_flow_ctl.fc_max_streams_bidi_can_send = 2;
    conn->conn_flow_ctl.fc_max_streams_uni_can_send = 1;

    CU_ASSERT(!xqc_stream_beyond_peer_limit(bidi[1]));
    CU_ASSERT(xqc_stream_beyond_peer_limit(bidi[2]));
    CU_ASSERT(!xqc_stream_beyond_peer_limit(uni[0]));
    CU_ASSERT(xqc_stream_beyond_peer_limit(uni[1]));
    CU_ASSERT(!xqc_stream_beyond_peer_limit(peer));

    /* still in the handshake: the refusal is not reported */
    CU_ASSERT_PTR_NULL(xqc_stream_create_with_direction(conn,
                       XQC_STREAM_BIDI, NULL));
    CU_ASSERT_EQUAL(xqc_test_fc_count_frames(conn,
                    XQC_FRAME_BIT_STREAMS_BLOCKED, XQC_PTYPE_NUM), 0);

    conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT;
    conn->conn_state = XQC_CONN_STATE_ESTABED;
    for (i = 0; i < 2; i++) {
        CU_ASSERT_PTR_NULL(xqc_stream_create_with_direction(conn,
                           XQC_STREAM_BIDI, NULL));
        CU_ASSERT_PTR_NULL(xqc_stream_create_with_direction(conn,
                           XQC_STREAM_UNI, NULL));
    }
    CU_ASSERT_EQUAL(xqc_test_fc_count_frames(conn,
                    XQC_FRAME_BIT_STREAMS_BLOCKED, XQC_PTYPE_SHORT_HEADER), 2);

    xqc_engine_destroy(conn->engine);
}


/*
 * RFC 9000 Sections 3.1 and 4.6: RESET_STREAM and STOP_SENDING carry the
 * stream ID, so closing or resetting a stream that waits beyond the peer's
 * limit sends nothing until MAX_STREAMS covers the stream; then the close
 * is applied instead of a write notification.
 */
void
xqc_test_stream_limit_defers_close(void)
{
    static xqc_stream_callbacks_t cbs = {
        .stream_write_notify = xqc_test_fc_write_notify,
    };
    static unsigned char req[] = "GET /\r\n";
    xqc_stream_t *streams[3];
    int notified[3] = {0};
    unsigned i;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    conn->engine->eng_flag |= XQC_ENG_FLAG_RUNNING;

    for (i = 0; i < 3; i++) {
        streams[i] = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI,
                                                      &notified[i]);
        CU_ASSERT_PTR_NOT_NULL_FATAL(streams[i]);
        streams[i]->stream_if = &cbs;
    }

    conn->conn_flow_ctl.fc_max_streams_bidi_can_send = 1;
    conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT;
    conn->conn_state = XQC_CONN_STATE_ESTABED;

    CU_ASSERT_EQUAL(xqc_stream_reset(streams[2], 9), -XQC_EAGAIN);
    CU_ASSERT_EQUAL(xqc_stream_close(streams[1]), XQC_OK);
    CU_ASSERT(streams[1]->stream_flag & XQC_STREAM_FLAG_CLOSE_DEFERRED);
    CU_ASSERT_EQUAL(streams[1]->stream_state_send, XQC_SEND_STREAM_ST_READY);
    CU_ASSERT_EQUAL(xqc_stream_send(streams[1], req, sizeof(req) - 1, 1),
                    -XQC_ESTREAM_RESET);

    xqc_process_write_streams(conn);
    CU_ASSERT_EQUAL(xqc_test_fc_count_frames(conn,
                    XQC_FRAME_BIT_RESET_STREAM, XQC_PTYPE_NUM), 0);
    CU_ASSERT_EQUAL(xqc_test_fc_count_frames(conn,
                    XQC_FRAME_BIT_STOP_SENDING, XQC_PTYPE_NUM), 0);

    CU_ASSERT_EQUAL(xqc_test_fc_recv_max_streams_bidi(conn, 3), XQC_OK);
    xqc_process_write_streams(conn);
    CU_ASSERT_EQUAL(notified[1], 0);
    CU_ASSERT_FALSE(streams[1]->stream_flag & XQC_STREAM_FLAG_CLOSE_DEFERRED);
    CU_ASSERT_EQUAL(streams[1]->stream_state_send,
                    XQC_SEND_STREAM_ST_RESET_SENT);
    CU_ASSERT_EQUAL(xqc_test_fc_count_frames(conn,
                    XQC_FRAME_BIT_RESET_STREAM, XQC_PTYPE_SHORT_HEADER), 1);
    CU_ASSERT_EQUAL(xqc_test_fc_count_frames(conn,
                    XQC_FRAME_BIT_STOP_SENDING, XQC_PTYPE_SHORT_HEADER), 1);
    CU_ASSERT_EQUAL(xqc_stream_reset(streams[2], 9), XQC_OK);

    conn->engine->eng_flag &= ~XQC_ENG_FLAG_RUNNING;
    xqc_engine_destroy(conn->engine);
}


/* the number of packets in one send queue list that carry frame_bit */
static int
xqc_test_fc_count_in_list(xqc_list_head_t *head,
    xqc_frame_type_bit_t frame_bit)
{
    xqc_list_head_t    *pos;
    xqc_packet_out_t   *packet_out;
    int                 count = 0;

    xqc_list_for_each(pos, head) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_frame_types & frame_bit) {
            count++;
        }
    }

    return count;
}


/*
 * RFC 9000 Sections 3.1 and 4.6: before the handshake, closing a stream
 * buffers its RESET_STREAM and STOP_SENDING until 1-RTT keys exist. When the
 * peer's transport parameters put the stream beyond its limit, those
 * packets stay buffered until MAX_STREAMS covers it; a buffered reset of a
 * stream within the limit is released with the keys.
 */
void
xqc_test_stream_limit_holds_early_reset(void)
{
    xqc_stream_t *streams[3];
    xqc_send_queue_t *sndq;
    unsigned i;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    conn->engine->eng_flag |= XQC_ENG_FLAG_RUNNING;
    sndq = conn->conn_send_queue;

    for (i = 0; i < 3; i++) {
        streams[i] = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI,
                                                      NULL);
        CU_ASSERT_PTR_NOT_NULL_FATAL(streams[i]);
    }

    /* no 1-RTT keys yet: both resets are buffered */
    CU_ASSERT_EQUAL(xqc_stream_close(streams[0]), XQC_OK);
    CU_ASSERT_EQUAL(xqc_stream_close(streams[2]), XQC_OK);
    CU_ASSERT_EQUAL(xqc_test_fc_count_in_list(&sndq->sndq_buff_1rtt_packets,
                    XQC_FRAME_BIT_RESET_STREAM), 2);
    CU_ASSERT_EQUAL(xqc_test_fc_count_in_list(&sndq->sndq_buff_1rtt_packets,
                    XQC_FRAME_BIT_STOP_SENDING), 2);

    /* the peer's transport parameters allow one stream, then 1-RTT */
    conn->conn_flow_ctl.fc_max_streams_bidi_can_send = 1;
    conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT;
    conn->conn_state = XQC_CONN_STATE_ESTABED;

    xqc_conn_write_buffed_1rtt_packets(conn);
    CU_ASSERT_EQUAL(xqc_test_fc_count_in_list(&sndq->sndq_send_packets,
                    XQC_FRAME_BIT_RESET_STREAM), 1);
    CU_ASSERT_EQUAL(xqc_test_fc_count_in_list(&sndq->sndq_send_packets,
                    XQC_FRAME_BIT_STOP_SENDING), 1);
    CU_ASSERT_EQUAL(xqc_test_fc_count_in_list(&sndq->sndq_buff_1rtt_packets,
                    XQC_FRAME_BIT_RESET_STREAM), 1);
    CU_ASSERT_EQUAL(xqc_test_fc_count_in_list(&sndq->sndq_buff_1rtt_packets,
                    XQC_FRAME_BIT_STOP_SENDING), 1);

    /* a credit of 2 does not cover stream 8 yet, 3 does */
    CU_ASSERT_EQUAL(xqc_test_fc_recv_max_streams_bidi(conn, 2), XQC_OK);
    xqc_conn_write_buffed_1rtt_packets(conn);
    CU_ASSERT_EQUAL(xqc_test_fc_count_in_list(&sndq->sndq_buff_1rtt_packets,
                    XQC_FRAME_BIT_RESET_STREAM), 1);

    CU_ASSERT_EQUAL(xqc_test_fc_recv_max_streams_bidi(conn, 3), XQC_OK);
    xqc_conn_write_buffed_1rtt_packets(conn);
    CU_ASSERT(xqc_list_empty(&sndq->sndq_buff_1rtt_packets));
    CU_ASSERT_EQUAL(xqc_test_fc_count_in_list(&sndq->sndq_send_packets,
                    XQC_FRAME_BIT_RESET_STREAM), 2);
    CU_ASSERT_EQUAL(xqc_test_fc_count_in_list(&sndq->sndq_send_packets,
                    XQC_FRAME_BIT_STOP_SENDING), 2);

    conn->engine->eng_flag &= ~XQC_ENG_FLAG_RUNNING;
    xqc_engine_destroy(conn->engine);
}


/* feed one MAX_DATA frame carrying 1048576 */
static xqc_int_t
xqc_test_fc_recv_max_data_1m(xqc_connection_t *conn)
{
    unsigned char       frame[5] = {0x10, 0x80, 0x10, 0x00, 0x00};
    xqc_packet_in_t     packet_in;

    memset(&packet_in, 0, sizeof(packet_in));
    packet_in.pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    packet_in.pos = frame;
    packet_in.last = frame + sizeof(frame);
    return xqc_process_frames(conn, &packet_in);
}


/*
 * RFC 9000 Section 7.4.1 and RFC 9001 Section 4.6.2: when the server
 * rejects 0-RTT, the client sends the 0-RTT data again in 1-RTT, within the
 * limits of the server's new transport parameters, which can be lower than
 * the remembered ones: stream 0 within a limit of one stream goes at once,
 * streams 4 and 8 once MAX_STREAMS covers them, and new data on a stream
 * waits behind its rejected data. A connection that MAX_DATA blocks sends
 * the data once MAX_DATA allows it.
 */
void
xqc_test_stream_limit_0rtt_replay(void)
{
    static unsigned char req[100];
    xqc_stream_t *streams[3];
    unsigned i;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    conn->engine->eng_flag |= XQC_ENG_FLAG_RUNNING;

    for (i = 0; i < 3; i++) {
        streams[i] = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI,
                                                      NULL);
        CU_ASSERT_PTR_NOT_NULL_FATAL(streams[i]);
        /* as a 0-RTT send of the whole request leaves it */
        CU_ASSERT_EQUAL(xqc_stream_buff_data(streams[i], req, sizeof(req), 1),
                        (ssize_t) sizeof(req));
        streams[i]->stream_flag |= XQC_STREAM_FLAG_HAS_0RTT;
        xqc_stream_shutdown_write(streams[i]);
    }

    /* handshake done, 0-RTT rejected, the new limit is one stream */
    conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT | XQC_CONN_FLAG_HAS_0RTT;
    conn->conn_state = XQC_CONN_STATE_ESTABED;
    conn->conn_flow_ctl.fc_max_streams_bidi_can_send = 1;
    CU_ASSERT_EQUAL(xqc_conn_early_data_reject(conn), XQC_OK);

    CU_ASSERT_EQUAL(streams[0]->stream_send_offset, sizeof(req));
    CU_ASSERT(xqc_list_empty(
        &streams[0]->stream_write_buff_list.write_buff_list));
    for (i = 1; i < 3; i++) {
        CU_ASSERT_EQUAL(streams[i]->stream_send_offset, 0);
        CU_ASSERT(streams[i]->stream_flag & XQC_STREAM_FLAG_READY_TO_WRITE);
    }
    CU_ASSERT_EQUAL(xqc_stream_send(streams[1], req, sizeof(req), 0),
                    -XQC_EAGAIN);

    CU_ASSERT_EQUAL(xqc_test_fc_recv_max_streams_bidi(conn, 3), XQC_OK);
    xqc_process_write_streams(conn);
    for (i = 1; i < 3; i++) {
        CU_ASSERT_EQUAL(streams[i]->stream_send_offset, sizeof(req));
        CU_ASSERT(xqc_list_empty(
            &streams[i]->stream_write_buff_list.write_buff_list));
        CU_ASSERT_FALSE(streams[i]->stream_flag
                        & XQC_STREAM_FLAG_READY_TO_WRITE);
    }

    conn->engine->eng_flag &= ~XQC_ENG_FLAG_RUNNING;
    xqc_engine_destroy(conn->engine);

    /* connection flow control: nothing goes before MAX_DATA */
    conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    conn->engine->eng_flag |= XQC_ENG_FLAG_RUNNING;

    streams[0] = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI,
                                                  NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(streams[0]);
    CU_ASSERT_EQUAL(xqc_stream_buff_data(streams[0], req, sizeof(req), 1),
                    (ssize_t) sizeof(req));
    streams[0]->stream_flag |= XQC_STREAM_FLAG_HAS_0RTT;
    xqc_stream_shutdown_write(streams[0]);

    conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT | XQC_CONN_FLAG_HAS_0RTT;
    conn->conn_state = XQC_CONN_STATE_ESTABED;
    conn->conn_flow_ctl.fc_max_data_can_send = 0;
    CU_ASSERT_EQUAL(xqc_conn_early_data_reject(conn), XQC_OK);
    CU_ASSERT_EQUAL(streams[0]->stream_send_offset, 0);
    CU_ASSERT(conn->conn_flag & XQC_CONN_FLAG_DATA_BLOCKED);

    xqc_process_write_streams(conn);
    CU_ASSERT_EQUAL(streams[0]->stream_send_offset, 0);

    CU_ASSERT_EQUAL(xqc_test_fc_recv_max_data_1m(conn), XQC_OK);
    xqc_process_write_streams(conn);
    CU_ASSERT_EQUAL(streams[0]->stream_send_offset, sizeof(req));
    CU_ASSERT(xqc_list_empty(
        &streams[0]->stream_write_buff_list.write_buff_list));

    conn->engine->eng_flag &= ~XQC_ENG_FLAG_RUNNING;
    xqc_engine_destroy(conn->engine);
}
