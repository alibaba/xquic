/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include <CUnit/CUnit.h>
#include "xqc_reliable_reset_test.h"
#include "xqc_common_test.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_transport_params.h"

static xqc_connection_t *xqc_reset_test_conn(void);
static xqc_int_t xqc_reset_test_input(xqc_connection_t *conn,
    unsigned char *data, size_t length);
static unsigned xqc_reset_test_packet_count(xqc_connection_t *conn,
    xqc_frame_type_bit_t type);

typedef struct {
    unsigned stop_count;
    unsigned closing_count;
    uint64_t stop_error;
    uint64_t offset_at_stop;
    xqc_bool_t reset_at_stop;
} xqc_reset_test_notifications_t;

static void
xqc_reset_test_stop_notify(xqc_stream_t *stream, uint64_t error,
    void *user_data)
{
    xqc_reset_test_notifications_t *notifications = user_data;
    notifications->stop_count++;
    notifications->stop_error = error;
    notifications->offset_at_stop = stream->stream_send_offset;
    notifications->reset_at_stop = stream->reset_stream_at_sent;
}

static void
xqc_reset_test_closing_notify(xqc_stream_t *stream, xqc_int_t error,
    void *user_data)
{
    xqc_reset_test_notifications_t *notifications = user_data;
    notifications->closing_count++;
}

static xqc_connection_t *
xqc_reset_test_conn(void)
{
    xqc_connection_t *conn = test_engine_connect();
    if (conn != NULL) {
        conn->conn_err = 0;
        conn->local_settings.reset_stream_at = XQC_TRUE;
        conn->remote_settings.reset_stream_at = XQC_TRUE;
        conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT
                          | XQC_CONN_FLAG_TLS_HSK_COMPLETED;
    }
    return conn;
}

static xqc_int_t
xqc_reset_test_input(xqc_connection_t *conn, unsigned char *data,
    size_t length)
{
    xqc_packet_in_t packet = {0};
    packet.pos = data;
    packet.last = data + length;
    packet.pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    return xqc_process_frames(conn, &packet);
}

static unsigned
xqc_reset_test_packet_count(xqc_connection_t *conn, xqc_frame_type_bit_t type)
{
    unsigned count = 0;
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &conn->conn_send_queue->sndq_send_packets) {
        xqc_packet_out_t *packet = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        count += !!(packet->po_frame_types & type);
    }
    return count;
}

void
xqc_test_reliable_reset_transport_params(void)
{
    /* reliable-stream-reset-09 Section 3: empty, remembered capability. */
    unsigned char buffer[512], empty[] = {0x1d, 0}, nonempty[] = {0x1d, 1, 0};
    unsigned char duplicate[] = {0x1d, 0, 0x1d, 0};
    xqc_transport_params_t params, decoded;
    size_t length;
    xqc_init_transport_params(&params);
    CU_ASSERT(params.reset_stream_at == XQC_FALSE);
    params.reset_stream_at = XQC_TRUE;
    CU_ASSERT(xqc_encode_transport_params(&params, XQC_TP_TYPE_CLIENT_HELLO,
        buffer, sizeof(buffer), &length) == XQC_OK);
    CU_ASSERT(xqc_decode_transport_params(&decoded, XQC_TP_TYPE_CLIENT_HELLO,
        buffer, length) == XQC_OK);
    CU_ASSERT(decoded.reset_stream_at == XQC_TRUE);
    CU_ASSERT(xqc_decode_transport_params(&decoded, XQC_TP_TYPE_CLIENT_HELLO,
        empty, sizeof(empty)) == XQC_OK);
    CU_ASSERT(xqc_decode_transport_params(&decoded, XQC_TP_TYPE_CLIENT_HELLO,
        nonempty, sizeof(nonempty)) < 0);
    CU_ASSERT(xqc_decode_transport_params(&decoded, XQC_TP_TYPE_CLIENT_HELLO,
        duplicate, sizeof(duplicate)) < 0);
    char stored[512];
    xqc_init_transport_params(&decoded);
    int n = xqc_write_transport_params(stored, sizeof(stored), &params);
    CU_ASSERT_FATAL(n > 0 && n < sizeof(stored));
    CU_ASSERT(xqc_read_transport_params(stored, n, &decoded) == XQC_OK);
    CU_ASSERT(decoded.reset_stream_at == XQC_TRUE);
    xqc_connection_t *conn = xqc_reset_test_conn();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT(xqc_conn_set_early_remote_transport_params(conn, &decoded)
        == XQC_OK);
    CU_ASSERT(conn->remote_settings.reset_stream_at == XQC_TRUE);
    xqc_engine_destroy(conn->engine);
}

void
xqc_test_reliable_reset_receive_order(void)
{
    /* Sections 5 and 5.3: reset may precede every reliable STREAM byte. */
    xqc_connection_t *conn = xqc_reset_test_conn();
    CU_ASSERT_FATAL(conn != NULL);
    unsigned char reset[] = {0x24, 3, 9, 8, 3};
    unsigned char tail[] = {0x0e, 3, 1, 2, 'b', 'c'};
    unsigned char head[] = {0x0e, 3, 0, 1, 'a'};
    unsigned char result[16], fin = 0;
    CU_ASSERT(xqc_reset_test_input(conn, reset, sizeof(reset)) == XQC_OK);
    xqc_stream_t *stream = xqc_find_stream_by_id(3, conn->streams_hash);
    CU_ASSERT_FATAL(stream != NULL);
    CU_ASSERT(stream->stream_state_recv == XQC_RECV_STREAM_ST_SIZE_KNOWN);
    CU_ASSERT(!stream->recv_reset_reported);
    CU_ASSERT(xqc_stream_recv(stream, result, sizeof(result), &fin)
        == -XQC_EAGAIN);
    CU_ASSERT(xqc_reset_test_input(conn, tail, sizeof(tail)) == XQC_OK);
    CU_ASSERT(xqc_stream_recv(stream, result, sizeof(result), &fin)
        == -XQC_EAGAIN);
    CU_ASSERT(xqc_reset_test_input(conn, head, sizeof(head)) == XQC_OK);
    CU_ASSERT(xqc_stream_recv(stream, result, sizeof(result), &fin) == 3);
    CU_ASSERT(memcmp(result, "abc", 3) == 0 && fin == 0);
    CU_ASSERT(!stream->recv_reset_reported);
    CU_ASSERT(xqc_stream_recv(stream, result, sizeof(result), &fin)
        == -XQC_ESTREAM_RESET);
    CU_ASSERT(stream->stream_err == 9);
    CU_ASSERT(conn->conn_flow_ctl.fc_data_recved == 8);
    CU_ASSERT(conn->conn_flow_ctl.fc_data_read == 8);
    CU_ASSERT(xqc_stream_recv(stream, result, sizeof(result), &fin)
        == -XQC_ESTREAM_RESET);
    CU_ASSERT(conn->conn_flow_ctl.fc_data_read == 8);
    xqc_engine_destroy(conn->engine);

    conn = xqc_reset_test_conn();
    CU_ASSERT_FATAL(conn != NULL);
    reset[4] = 0;
    CU_ASSERT(xqc_reset_test_input(conn, reset, sizeof(reset)) == XQC_OK);
    stream = xqc_find_stream_by_id(3, conn->streams_hash);
    CU_ASSERT_FATAL(stream != NULL);
    CU_ASSERT(xqc_stream_recv(stream, result, sizeof(result), &fin)
        == -XQC_ESTREAM_RESET);
    CU_ASSERT(conn->conn_flow_ctl.fc_data_read == 8);
    xqc_engine_destroy(conn->engine);
}

void
xqc_test_reliable_reset_receive_errors(void)
{
    unsigned char cases[][5] = {
        {0x24, 3, 9, 2, 3}, {0x24, 2, 9, 3, 3},
        {0x24, 3, 9, 3, 3}, {0x24, 3, 9, 3, 3},
        {0x24, 3, 9, 3, 3}, {0x24, 3, 9, 3, 3}
    };
    uint64_t errors[] = {TRA_FRAME_ENCODING_ERROR, TRA_STREAM_STATE_ERROR,
        TRA_PROTOCOL_VIOLATION, TRA_FLOW_CONTROL_ERROR, TRA_FLOW_CONTROL_ERROR,
        TRA_FRAME_ENCODING_ERROR};
    for (int i = 0; i < 6; i++) {
        xqc_connection_t *conn = xqc_reset_test_conn();
        CU_ASSERT_FATAL(conn != NULL);
        if (i == 2) {
            conn->local_settings.reset_stream_at = XQC_FALSE;
        }
        if (i == 3) {
            conn->conn_flow_ctl.fc_max_data_can_recv = 2;
        }
        if (i == 4) {
            xqc_stream_t *stream = xqc_passive_create_stream(conn, 3, NULL);
            CU_ASSERT_FATAL(stream != NULL);
            stream->stream_flow_ctl.fc_max_stream_data_can_recv = 2;
        }
        CU_ASSERT(xqc_reset_test_input(conn, cases[i], i == 5 ? 4 : 5) < 0);
        CU_ASSERT(conn->conn_err == errors[i]);
        xqc_engine_destroy(conn->engine);
    }
    for (int change = 0; change < 2; change++) {
        xqc_connection_t *conn = xqc_reset_test_conn();
        CU_ASSERT_FATAL(conn != NULL);
        unsigned char reset[] = {0x24, 3, 9, 8, 4};
        CU_ASSERT(xqc_reset_test_input(conn, reset, 5) == XQC_OK);
        reset[4] = 2;
        CU_ASSERT(xqc_reset_test_input(conn, reset, 5) == XQC_OK);
        reset[4] = 3;
        CU_ASSERT(xqc_reset_test_input(conn, reset, 5) == XQC_OK);
        xqc_stream_t *stream = xqc_find_stream_by_id(3, conn->streams_hash);
        CU_ASSERT_FATAL(stream != NULL);
        CU_ASSERT(stream->recv_reliable_size == 2);
        reset[change ? 3 : 2]++;
        CU_ASSERT(xqc_reset_test_input(conn, reset, 5) < 0);
        CU_ASSERT(conn->conn_err == (change ? TRA_FINAL_SIZE_ERROR
                                            : TRA_STREAM_STATE_ERROR));
        xqc_engine_destroy(conn->engine);
    }
}

void
xqc_test_reliable_reset_ack_order(void)
{
    xqc_connection_t *conn = xqc_reset_test_conn();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_stream_t *stream = xqc_stream_create_with_direction(conn,
        XQC_STREAM_UNI, NULL);
    CU_ASSERT_FATAL(stream != NULL);
    stream->stream_flag |= XQC_STREAM_FLAG_HAS_H3;
    CU_ASSERT(xqc_stream_set_reliable_size(stream, 3) == XQC_OK);
    unsigned char prefix[] = "abc";
    CU_ASSERT(xqc_stream_send(stream, prefix, 3, 0) == 3);
    unsigned before = xqc_reset_test_packet_count(conn, XQC_FRAME_BIT_STREAM);
    CU_ASSERT(before > 0);
    CU_ASSERT(xqc_stream_reset(stream, 9) == XQC_OK);
    CU_ASSERT(xqc_reset_test_packet_count(conn, XQC_FRAME_BIT_STREAM) == before);
    CU_ASSERT(xqc_reset_test_packet_count(conn, XQC_FRAME_BIT_RESET_STREAM_AT)
        == 1);
    xqc_packet_out_t ack = {0};
    ack.po_frame_types = XQC_FRAME_BIT_RESET_STREAM_AT;
    ack.po_stream_frames_idx = 1;
    ack.po_stream_frames[0].ps_is_used = 1;
    ack.po_stream_frames[0].ps_stream_id = stream->stream_id;
    ack.po_stream_frames[0].ps_is_reset_at = 1;
    ack.po_stream_frames[0].ps_reliable_size = 3;
    xqc_send_ctl_on_packet_acked(conn->conn_initial_path->path_send_ctl,
        &ack, xqc_monotonic_timestamp(), 0);
    CU_ASSERT(stream->reset_stream_at_acked);
    CU_ASSERT(stream->stream_state_send == XQC_SEND_STREAM_ST_DATA_SENT);

    /* The prefix is lost after the reset ACK; recovery must retain it. */
    xqc_packet_out_t *head_packet = NULL;
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &conn->conn_send_queue->sndq_send_packets) {
        xqc_packet_out_t *packet = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet->po_frame_types & XQC_FRAME_BIT_STREAM) {
            head_packet = packet;
            break;
        }
    }
    CU_ASSERT_FATAL(head_packet != NULL);
    xqc_send_queue_remove_send(&head_packet->po_list);
    head_packet->po_pkt.pkt_num = 1;
    head_packet->po_pkt.pkt_pns = XQC_PNS_APP_DATA;
    head_packet->po_path_id = conn->conn_initial_path->path_id;
    head_packet->po_sent_time = 1;
    xqc_send_ctl_increase_inflight(conn, head_packet);
    xqc_conn_increase_unacked_stream_ref(conn, head_packet);
    xqc_send_queue_insert_unacked(head_packet,
        &conn->conn_send_queue->sndq_unacked_packets[XQC_PNS_APP_DATA],
        conn->conn_send_queue);
    xqc_send_ctl_t *ctl = conn->conn_initial_path->path_send_ctl;
    ctl->ctl_srtt = 1000;
    ctl->ctl_latest_rtt = 1000;
    ctl->ctl_largest_acked[XQC_PNS_APP_DATA] = 4;
    xqc_send_ctl_detect_lost(ctl, conn->conn_send_queue, XQC_PNS_APP_DATA,
        100000);
    CU_ASSERT_FATAL(!xqc_list_empty(&conn->conn_send_queue->sndq_lost_packets));
    xqc_packet_out_t *retry = xqc_list_entry(
        conn->conn_send_queue->sndq_lost_packets.next, xqc_packet_out_t, po_list);
    CU_ASSERT(retry->po_frame_types & XQC_FRAME_BIT_STREAM);
    CU_ASSERT(retry->po_stream_frames[0].ps_offset == 0);
    CU_ASSERT(retry->po_stream_frames[0].ps_length == 3);
    CU_ASSERT(stream->stream_state_send == XQC_SEND_STREAM_ST_DATA_SENT);
    xqc_stream_ack_reliable(stream, 1, 2, XQC_FALSE);
    CU_ASSERT(stream->reliable_acked_offset == 0);
    CU_ASSERT(stream->stream_state_send == XQC_SEND_STREAM_ST_DATA_SENT);
    xqc_send_ctl_on_packet_acked(ctl, retry, xqc_monotonic_timestamp(), 0);
    CU_ASSERT(stream->reliable_acked_offset == 3);
    CU_ASSERT(stream->stream_state_send == XQC_SEND_STREAM_ST_DATA_RECVD);
    CU_ASSERT(stream->stream_flag & XQC_STREAM_FLAG_NEED_CLOSE);
    xqc_engine_destroy(conn->engine);
}

void
xqc_test_reliable_reset_stop_sending(void)
{
    /* Section 5.4: preserve the prefix before reporting STOP_SENDING. */
    xqc_connection_t *conn = xqc_reset_test_conn();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_reset_test_notifications_t notifications = {0};
    xqc_stream_callbacks_t callbacks = {
        .stream_closing_notify = xqc_reset_test_closing_notify,
        .stream_stop_sending_notify = xqc_reset_test_stop_notify,
    };
    xqc_stream_t *stream = xqc_stream_create_with_direction(conn,
        XQC_STREAM_UNI, &notifications);
    CU_ASSERT_FATAL(stream != NULL && stream->stream_id < 64);
    stream->stream_if = &callbacks;
    stream->stream_flag |= XQC_STREAM_FLAG_HAS_H3;
    CU_ASSERT(xqc_stream_set_reliable_size(stream, 3) == XQC_OK);
    unsigned char stop[] = {0x05, (unsigned char)stream->stream_id, 9};
    CU_ASSERT(xqc_reset_test_input(conn, stop, sizeof(stop)) == XQC_OK);
    CU_ASSERT(stream->reset_stream_at_pending);
    CU_ASSERT(!stream->reset_stream_at_sent);
    CU_ASSERT(notifications.stop_count == 0);
    stop[2] = 10;
    CU_ASSERT(xqc_reset_test_input(conn, stop, sizeof(stop)) == XQC_OK);
    CU_ASSERT(stream->reset_stream_at_error == 9);
    unsigned char prefix[] = "abc";
    CU_ASSERT(xqc_stream_send(stream, prefix, 1, 0) == 1);
    CU_ASSERT(notifications.stop_count == 0);
    CU_ASSERT(xqc_stream_send(stream, prefix + 1, 2, 0) == 2);
    CU_ASSERT(stream->reset_stream_at_sent);
    CU_ASSERT(!stream->reset_stream_at_pending);
    CU_ASSERT(stream->reset_stream_at_error == 9);
    CU_ASSERT(notifications.stop_count == 1);
    CU_ASSERT(notifications.stop_error == 9);
    CU_ASSERT(notifications.offset_at_stop == 3);
    CU_ASSERT(notifications.reset_at_stop);
    CU_ASSERT(notifications.closing_count == 0);
    CU_ASSERT(xqc_reset_test_input(conn, stop, sizeof(stop)) == XQC_OK);
    CU_ASSERT(stream->reset_stream_at_error == 9);
    CU_ASSERT(notifications.stop_count == 1);
    CU_ASSERT(xqc_reset_test_packet_count(conn, XQC_FRAME_BIT_RESET_STREAM_AT)
        == 1);
    CU_ASSERT(xqc_reset_test_packet_count(conn, XQC_FRAME_BIT_STREAM) > 0);
    CU_ASSERT(xqc_stream_send(stream, prefix, 3, 0) == -XQC_ESTREAM_RESET);
    xqc_engine_destroy(conn->engine);

    /* The optional callback also preserves non-reliable 62-bit errors. */
    conn = xqc_reset_test_conn();
    CU_ASSERT_FATAL(conn != NULL);
    memset(&notifications, 0, sizeof(notifications));
    stream = xqc_stream_create_with_direction(conn, XQC_STREAM_UNI,
        &notifications);
    CU_ASSERT_FATAL(stream != NULL && stream->stream_id < 64);
    stream->stream_if = &callbacks;
    unsigned char wide_stop[] = {0x05, (unsigned char)stream->stream_id,
                                0xc0, 0, 0, 1, 0, 0, 0, 9};
    CU_ASSERT(xqc_reset_test_input(conn, wide_stop, sizeof(wide_stop))
        == XQC_OK);
    CU_ASSERT(notifications.stop_count == 1);
    CU_ASSERT(notifications.stop_error == UINT64_C(0x100000009));
    CU_ASSERT(notifications.closing_count == 0);
    xqc_stream_closing(stream, 11);
    CU_ASSERT(notifications.closing_count == 1);
    CU_ASSERT(notifications.stop_count == 1);
    xqc_engine_destroy(conn->engine);
}

void
xqc_test_reliable_reset_send_errors(void)
{
    xqc_connection_t *conn = xqc_reset_test_conn();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_stream_t *stream = xqc_stream_create_with_direction(conn,
        XQC_STREAM_UNI, NULL);
    CU_ASSERT_FATAL(stream != NULL);
    /* A remembered TP must not authorize resets before this handshake. */
    conn->conn_flag &= ~XQC_CONN_FLAG_TLS_HSK_COMPLETED;
    CU_ASSERT(xqc_stream_set_reliable_size(stream, 3) == -XQC_ESTATE);
    CU_ASSERT(!stream->reliable_size_set);
    CU_ASSERT(!stream->reset_stream_at_pending);
    conn->conn_flag |= XQC_CONN_FLAG_TLS_HSK_COMPLETED;
    conn->remote_settings.reset_stream_at = XQC_FALSE;
    CU_ASSERT(xqc_stream_set_reliable_size(stream, 3) == -XQC_ESTATE);
    conn->remote_settings.reset_stream_at = XQC_TRUE;
    CU_ASSERT(xqc_stream_set_reliable_size(stream, 3) == XQC_OK);
    CU_ASSERT(xqc_stream_reset(stream, 9) == -XQC_EAGAIN);
    CU_ASSERT(!stream->reset_stream_at_sent);
    xqc_stream_t *recv_only = xqc_passive_create_stream(conn, 3, NULL);
    CU_ASSERT_FATAL(recv_only != NULL);
    CU_ASSERT(xqc_stream_reset(recv_only, 9) == -XQC_EPARAM);
    CU_ASSERT(xqc_stream_set_reliable_size(recv_only, 3) == -XQC_EPARAM);
    xqc_stream_t *empty = xqc_stream_create_with_direction(conn,
        XQC_STREAM_UNI, NULL);
    CU_ASSERT_FATAL(empty != NULL);
    CU_ASSERT(xqc_stream_set_reliable_size(empty, 0) == XQC_OK);
    CU_ASSERT(xqc_stream_reset(empty, 9) == XQC_OK);
    CU_ASSERT(empty->reset_stream_at_sent);
    CU_ASSERT(xqc_stream_reset(empty, 9) == XQC_OK);
    CU_ASSERT(xqc_stream_reset(empty, 10) == -XQC_ESTATE);
    CU_ASSERT(xqc_reset_test_packet_count(conn, XQC_FRAME_BIT_RESET_STREAM_AT)
        == 1);
    xqc_stream_ack_reliable(empty, 0, 0, XQC_TRUE);
    CU_ASSERT(empty->stream_state_send == XQC_SEND_STREAM_ST_DATA_RECVD);
    unsigned char buf[64];
    xqc_packet_out_t packet = {0};
    packet.po_buf = buf;
    packet.po_buf_size = sizeof(buf);
    CU_ASSERT(xqc_gen_reset_stream_at_frame(&packet, 2, 9, 2, 3)
        == -XQC_EPARAM);
    packet.po_buf_size = 1;
    CU_ASSERT(xqc_gen_reset_stream_at_frame(&packet, 2, 9, 3, 3) < 0);
    xqc_engine_destroy(conn->engine);

    conn = xqc_reset_test_conn();
    CU_ASSERT_FATAL(conn != NULL);
    unsigned char invalid_stop[] = {0x05, 3, 9};
    CU_ASSERT(xqc_reset_test_input(conn, invalid_stop, sizeof(invalid_stop))
        == -XQC_EPROTO);
    CU_ASSERT(conn->conn_err == TRA_STREAM_STATE_ERROR);
    xqc_engine_destroy(conn->engine);
}
