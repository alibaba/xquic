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
static xqc_packet_out_t *xqc_reset_test_queued_packet(xqc_stream_t *stream,
    xqc_frame_type_bit_t type, uint64_t offset);
static void xqc_reset_test_packet_sent(xqc_connection_t *conn,
    xqc_packet_out_t *packet, xqc_packet_number_t number);

typedef struct {
    unsigned stop_count;
    unsigned closing_count;
    uint64_t stop_error;
    uint64_t offset_at_stop;
    xqc_bool_t reset_at_stop;
    xqc_bool_t reenter_read;
    ssize_t reenter_result;
} xqc_reset_test_notifications_t;

static void
xqc_reset_test_stop_notify(xqc_stream_t *stream, uint64_t error,
    void *user_data)
{
    xqc_reset_test_notifications_t *notifications = user_data;
    notifications->stop_count++;
    notifications->stop_error = error;
    notifications->offset_at_stop = stream->stream_send_offset;
    notifications->reset_at_stop =
        stream->reset_at.send_state == XQC_RESET_AT_SENT;
}

static void
xqc_reset_test_closing_notify(xqc_stream_t *stream, xqc_int_t error,
    void *user_data)
{
    xqc_reset_test_notifications_t *notifications = user_data;
    notifications->closing_count++;
    if (notifications->reenter_read && notifications->closing_count == 1) {
        unsigned char data[8], fin;
        CU_ASSERT(stream->stream_state_recv >= XQC_RECV_STREAM_ST_RESET_RECVD);
        notifications->reenter_result =
            xqc_stream_recv(stream, data, sizeof(data), &fin);
        CU_ASSERT(fin == 0);
    }
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

static xqc_packet_out_t *
xqc_reset_test_queued_packet(xqc_stream_t *stream,
    xqc_frame_type_bit_t type, uint64_t offset)
{
    xqc_list_head_t *pos;
    xqc_list_for_each(pos,
        &stream->stream_conn->conn_send_queue->sndq_send_packets)
    {
        xqc_packet_out_t *packet = xqc_list_entry(pos, xqc_packet_out_t,
                                                po_list);
        if (!(packet->po_frame_types & type)) {
            continue;
        }
        for (unsigned i = 0; i < packet->po_stream_frames_idx; i++) {
            xqc_po_stream_frame_t *frame = &packet->po_stream_frames[i];
            if (frame->ps_is_used && frame->ps_stream_id == stream->stream_id
                && (frame->ps_is_reset_at || frame->ps_offset == offset))
            {
                return packet;
            }
        }
    }
    return NULL;
}

static void
xqc_reset_test_packet_sent(xqc_connection_t *conn, xqc_packet_out_t *packet,
    xqc_packet_number_t number)
{
    if (packet->po_flag & XQC_POF_IN_PATH_BUF_LIST) {
        xqc_path_send_buffer_remove(conn->conn_initial_path, packet);

    } else {
        xqc_send_queue_remove_send(&packet->po_list);
    }
    packet->po_pkt.pkt_num = number;
    packet->po_pkt.pkt_pns = XQC_PNS_APP_DATA;
    packet->po_path_id = conn->conn_initial_path->path_id;
    packet->po_sent_time = 1;
    xqc_send_ctl_increase_inflight(conn, packet);
    xqc_conn_increase_unacked_stream_ref(conn, packet);
    xqc_send_queue_insert_unacked(packet,
        &conn->conn_send_queue->sndq_unacked_packets[XQC_PNS_APP_DATA],
        conn->conn_send_queue);
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
    CU_ASSERT(stream->stream_state_recv < XQC_RECV_STREAM_ST_RESET_RECVD);
    CU_ASSERT(xqc_stream_recv(stream, result, sizeof(result), &fin)
        == -XQC_EAGAIN);
    CU_ASSERT(xqc_reset_test_input(conn, tail, sizeof(tail)) == XQC_OK);
    CU_ASSERT(xqc_stream_recv(stream, result, sizeof(result), &fin)
        == -XQC_EAGAIN);
    CU_ASSERT(xqc_reset_test_input(conn, head, sizeof(head)) == XQC_OK);
    CU_ASSERT(xqc_stream_recv(stream, result, sizeof(result), &fin) == 3);
    CU_ASSERT(memcmp(result, "abc", 3) == 0 && fin == 0);
    CU_ASSERT(stream->stream_state_recv < XQC_RECV_STREAM_ST_RESET_RECVD);
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

    /*
     * RFC 9000 Section 3.1 and reliable-stream-reset-09 Section 5.3:
     * the two directions retain independent errors; receive reentry must
     * neither repeat the callback nor account for the final size twice.
     */
    for (unsigned receive_first = 0; receive_first < 2; receive_first++) {
        conn = xqc_reset_test_conn();
        CU_ASSERT_FATAL(conn != NULL);
        xqc_reset_test_notifications_t notifications = {0};
        notifications.reenter_read = XQC_TRUE;
        xqc_stream_callbacks_t callbacks = {
            .stream_closing_notify = xqc_reset_test_closing_notify,
        };
        stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI,
            &notifications);
        CU_ASSERT_FATAL(stream != NULL && stream->stream_id < 64);
        stream->stream_if = &callbacks;
        stream->stream_flag |= XQC_STREAM_FLAG_HAS_H3;
        CU_ASSERT(xqc_stream_set_reliable_size(stream, 3) == XQC_OK);
        CU_ASSERT(xqc_stream_send(stream, (unsigned char *)"snd", 3, 0) == 3);
        if (!receive_first) {
            CU_ASSERT(xqc_stream_reset(stream, 17) == XQC_OK);
        }
        unsigned char peer_reset[] = {
            0x24, (unsigned char)stream->stream_id, 9, 8, 3,
        };
        unsigned char peer_data[] = {
            0x0e, (unsigned char)stream->stream_id, 0, 3, 'r', 'c', 'v',
        };
        CU_ASSERT(xqc_reset_test_input(conn, peer_reset, sizeof(peer_reset))
            == XQC_OK);
        CU_ASSERT(xqc_reset_test_input(conn, peer_data, sizeof(peer_data))
            == XQC_OK);
        CU_ASSERT(xqc_stream_recv(stream, result, sizeof(result), &fin) == 3);
        CU_ASSERT(memcmp(result, "rcv", 3) == 0 && fin == 0);
        CU_ASSERT(notifications.closing_count == 0);
        CU_ASSERT(xqc_stream_recv(stream, result, sizeof(result), &fin)
            == -XQC_ESTREAM_RESET);
        CU_ASSERT(notifications.closing_count == 1);
        CU_ASSERT(notifications.reenter_result == -XQC_ESTREAM_RESET);
        if (receive_first) {
            CU_ASSERT(xqc_stream_reset(stream, 17) == XQC_OK);
        }
        CU_ASSERT(stream->reset_at.send_error == 17);
        CU_ASSERT(stream->reset_at.recv_error == 9);
        CU_ASSERT(stream->reset_at.send_size == 3);
        CU_ASSERT(stream->reset_at.recv_size == 3);
        CU_ASSERT(stream->reset_at.send_state == XQC_RESET_AT_SENT);
        CU_ASSERT(stream->reset_at.recv_state == XQC_RESET_AT_RELIABLE);
        CU_ASSERT(xqc_stream_recv(stream, result, sizeof(result), &fin)
            == -XQC_ESTREAM_RESET);
        CU_ASSERT(notifications.closing_count == 1);
        CU_ASSERT(conn->conn_flow_ctl.fc_data_read == 8);
        peer_reset[2] = 10;
        CU_ASSERT(xqc_reset_test_input(conn, peer_reset, sizeof(peer_reset))
            == -XQC_EPROTO);
        CU_ASSERT(conn->conn_err == TRA_STREAM_STATE_ERROR);
        CU_ASSERT(stream->reset_at.send_error == 17);
        CU_ASSERT(stream->reset_at.recv_error == 9);
        xqc_engine_destroy(conn->engine);
    }
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
        CU_ASSERT(stream->reset_at.recv_size == 2);
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
    /* Section 5.3: ACK the actual reset and every reliable prefix packet. */
    for (unsigned ack_copy = 0; ack_copy < 2; ack_copy++) {
        xqc_connection_t *conn = xqc_reset_test_conn();
        CU_ASSERT_FATAL(conn != NULL);
        xqc_send_queue_t *queue = conn->conn_send_queue;
        xqc_send_ctl_t *ctl = conn->conn_initial_path->path_send_ctl;
        xqc_stream_t *stream = xqc_stream_create_with_direction(conn,
            XQC_STREAM_UNI, NULL);
        CU_ASSERT_FATAL(stream != NULL);
        stream->stream_flag |= XQC_STREAM_FLAG_HAS_H3;
        CU_ASSERT(xqc_stream_set_reliable_size(stream, 3) == XQC_OK);
        unsigned char prefix[] = "abc";
        CU_ASSERT(xqc_stream_send(stream, prefix, 1, 0) == 1);
        xqc_packet_out_t *head = xqc_reset_test_queued_packet(stream,
            XQC_FRAME_BIT_STREAM, 0);
        CU_ASSERT_PTR_NOT_NULL_FATAL(head);
        if (ack_copy) {
            xqc_path_ctx_t *path = conn->conn_initial_path;
            xqc_path_send_buffer_append(path, head,
                &path->path_schedule_buf[XQC_SEND_TYPE_NORMAL]);

        } else {
            xqc_send_queue_move_to_high_pri(&head->po_list, queue);
        }
        CU_ASSERT(xqc_stream_send(stream, prefix + 1, 2, 0) == 2);
        xqc_packet_out_t *tail = xqc_reset_test_queued_packet(stream,
            XQC_FRAME_BIT_STREAM, 1);
        CU_ASSERT_PTR_NOT_NULL_FATAL(tail);
        CU_ASSERT(xqc_stream_reset(stream, 9) == XQC_OK);
        xqc_packet_out_t *reset = xqc_reset_test_queued_packet(stream,
            XQC_FRAME_BIT_RESET_STREAM_AT, 0);
        CU_ASSERT_PTR_NOT_NULL_FATAL(reset);

        /* Reset ACK cannot finish a prefix still waiting in the send queue. */
        xqc_reset_test_packet_sent(conn, reset, 1);
        xqc_send_ctl_on_packet_acked(ctl, reset, xqc_monotonic_timestamp(), 0);
        CU_ASSERT(reset->po_acked && !head->po_acked && !tail->po_acked);
        CU_ASSERT(stream->stream_state_send == XQC_SEND_STREAM_ST_DATA_SENT);
        xqc_reset_test_packet_sent(conn, tail, 2);
        xqc_send_ctl_on_packet_acked(ctl, tail, xqc_monotonic_timestamp(), 0);
        CU_ASSERT(tail->po_acked && !head->po_acked);
        CU_ASSERT(stream->stream_state_send == XQC_SEND_STREAM_ST_DATA_SENT);

        /* A missing first prefix byte survives loss after the later ACKs. */
        xqc_reset_test_packet_sent(conn, head, 3);
        ctl->ctl_srtt = 1000;
        ctl->ctl_latest_rtt = 1000;
        ctl->ctl_largest_acked[XQC_PNS_APP_DATA] = 6;
        xqc_send_ctl_detect_lost(ctl, queue, XQC_PNS_APP_DATA, 100000);
        CU_ASSERT_FATAL(!xqc_list_empty(&queue->sndq_lost_packets));
        xqc_packet_out_t *retry = xqc_list_entry(
            queue->sndq_lost_packets.next, xqc_packet_out_t, po_list);
        CU_ASSERT_PTR_EQUAL(retry->po_origin, head);
        CU_ASSERT(retry->po_stream_frames[0].ps_offset == 0);
        CU_ASSERT(retry->po_stream_frames[0].ps_length == 1);
        CU_ASSERT(stream->stream_state_send == XQC_SEND_STREAM_ST_DATA_SENT);
        xqc_send_queue_copy_to_probe(head, queue, conn->conn_initial_path);
        CU_ASSERT_FATAL(!xqc_list_empty(&queue->sndq_pto_probe_packets));
        xqc_packet_out_t *probe = xqc_list_entry(
            queue->sndq_pto_probe_packets.next, xqc_packet_out_t, po_list);
        CU_ASSERT_PTR_EQUAL(probe->po_origin, head);
        if (ack_copy) {
            xqc_reset_test_packet_sent(conn, retry, 4);
        }
        xqc_send_ctl_on_packet_acked(ctl, ack_copy ? retry : head,
            xqc_monotonic_timestamp(), 0);
        CU_ASSERT(head->po_acked);
        CU_ASSERT(!probe->po_acked);
        CU_ASSERT(stream->stream_state_send == XQC_SEND_STREAM_ST_DATA_RECVD);
        CU_ASSERT(stream->stream_flag & XQC_STREAM_FLAG_NEED_CLOSE);

        /* Queued copies of an ACKed origin must not reopen or retain it. */
        if (!ack_copy) {
            xqc_reset_test_packet_sent(conn, retry, 4);
        }
        xqc_send_ctl_on_packet_acked(ctl, retry, xqc_monotonic_timestamp(), 0);
        xqc_send_ctl_on_packet_acked(ctl, head, xqc_monotonic_timestamp(), 0);
        CU_ASSERT(stream->stream_state_send == XQC_SEND_STREAM_ST_DATA_RECVD);
        CU_ASSERT(stream->stream_unacked_pkt == 0);
        xqc_engine_destroy(conn->engine);
    }

    /* Prefix ACK still waits for a lost reset, including its retransmit. */
    xqc_connection_t *conn = xqc_reset_test_conn();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_send_queue_t *queue = conn->conn_send_queue;
    xqc_send_ctl_t *ctl = conn->conn_initial_path->path_send_ctl;
    xqc_stream_t *stream = xqc_stream_create_with_direction(conn,
        XQC_STREAM_UNI, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
    stream->stream_flag |= XQC_STREAM_FLAG_HAS_H3;
    CU_ASSERT(xqc_stream_set_reliable_size(stream, 1) == XQC_OK);
    CU_ASSERT(xqc_stream_send(stream, (unsigned char *)"a", 1, 0) == 1);
    xqc_packet_out_t *prefix = xqc_reset_test_queued_packet(stream,
        XQC_FRAME_BIT_STREAM, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(prefix);
    CU_ASSERT(xqc_stream_reset(stream, 9) == XQC_OK);
    xqc_packet_out_t *reset = xqc_reset_test_queued_packet(stream,
        XQC_FRAME_BIT_RESET_STREAM_AT, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(reset);
    xqc_reset_test_packet_sent(conn, prefix, 1);
    xqc_send_ctl_on_packet_acked(ctl, prefix, xqc_monotonic_timestamp(), 0);
    CU_ASSERT(stream->stream_state_send == XQC_SEND_STREAM_ST_DATA_SENT);
    xqc_reset_test_packet_sent(conn, reset, 2);
    ctl->ctl_srtt = 1000;
    ctl->ctl_latest_rtt = 1000;
    ctl->ctl_largest_acked[XQC_PNS_APP_DATA] = 5;
    xqc_send_ctl_detect_lost(ctl, queue, XQC_PNS_APP_DATA, 100000);
    CU_ASSERT_FATAL(!xqc_list_empty(&queue->sndq_lost_packets));
    xqc_packet_out_t *retry = xqc_list_entry(queue->sndq_lost_packets.next,
        xqc_packet_out_t, po_list);
    CU_ASSERT_PTR_EQUAL(retry->po_origin, reset);
    CU_ASSERT((retry->po_frame_types & XQC_FRAME_BIT_RESET_STREAM_AT) != 0);
    CU_ASSERT(stream->stream_state_send == XQC_SEND_STREAM_ST_DATA_SENT);
    xqc_reset_test_packet_sent(conn, retry, 3);
    xqc_send_ctl_on_packet_acked(ctl, retry, xqc_monotonic_timestamp(), 0);
    CU_ASSERT(reset->po_acked);
    CU_ASSERT(stream->stream_state_send == XQC_SEND_STREAM_ST_DATA_RECVD);
    CU_ASSERT(stream->stream_unacked_pkt == 0);
    xqc_engine_destroy(conn->engine);
}

void
xqc_test_reliable_reset_stop_sending(void)
{
    /* Section 5.4: STOP reports immediately; the reset waits for its prefix. */
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
    CU_ASSERT(stream->reset_at.send_state == XQC_RESET_AT_PENDING);
    CU_ASSERT(stream->reset_at.send_state != XQC_RESET_AT_SENT);
    CU_ASSERT(notifications.stop_count == 1);
    CU_ASSERT(notifications.stop_error == 9);
    CU_ASSERT(notifications.offset_at_stop == 0);
    CU_ASSERT(!notifications.reset_at_stop);
    stop[2] = 10;
    CU_ASSERT(xqc_reset_test_input(conn, stop, sizeof(stop)) == XQC_OK);
    CU_ASSERT(stream->reset_at.send_error == 9);
    CU_ASSERT(notifications.stop_count == 2);
    CU_ASSERT(notifications.stop_error == 10);
    unsigned char prefix[] = "abc";
    CU_ASSERT(xqc_stream_send(stream, prefix, 1, 0) == 1);
    CU_ASSERT(notifications.stop_count == 2);
    CU_ASSERT(xqc_stream_send(stream, prefix + 1, 2, 0) == 2);
    CU_ASSERT(stream->reset_at.send_state == XQC_RESET_AT_SENT);
    CU_ASSERT(stream->reset_at.send_state != XQC_RESET_AT_PENDING);
    CU_ASSERT(stream->reset_at.send_error == 9);
    CU_ASSERT(notifications.stop_count == 2);
    CU_ASSERT(notifications.stop_error == 10);
    CU_ASSERT(notifications.offset_at_stop == 0);
    CU_ASSERT(!notifications.reset_at_stop);
    CU_ASSERT(notifications.closing_count == 0);
    CU_ASSERT(xqc_reset_test_input(conn, stop, sizeof(stop)) == XQC_OK);
    CU_ASSERT(stream->reset_at.send_error == 9);
    CU_ASSERT(notifications.stop_count == 3);
    CU_ASSERT(notifications.offset_at_stop == 3);
    CU_ASSERT(notifications.reset_at_stop);
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
                                0xff, 0xff, 0xff, 0xff,
                                0xff, 0xff, 0xff, 0xff};
    CU_ASSERT(xqc_reset_test_input(conn, wide_stop, sizeof(wide_stop))
        == XQC_OK);
    CU_ASSERT(notifications.stop_count == 1);
    CU_ASSERT(notifications.stop_error == (UINT64_C(1) << 62) - 1);
    CU_ASSERT(xqc_reset_test_input(conn, wide_stop, sizeof(wide_stop))
        == XQC_OK);
    CU_ASSERT(notifications.stop_count == 2);
    CU_ASSERT(notifications.stop_error == (UINT64_C(1) << 62) - 1);
    CU_ASSERT(notifications.closing_count == 0);
    xqc_stream_closing(stream, 11);
    CU_ASSERT(notifications.closing_count == 1);
    CU_ASSERT(notifications.stop_count == 2);
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
    CU_ASSERT(stream->reset_at.send_state == XQC_RESET_AT_NONE);
    CU_ASSERT(stream->reset_at.send_state != XQC_RESET_AT_PENDING);
    conn->conn_flag |= XQC_CONN_FLAG_TLS_HSK_COMPLETED;
    conn->remote_settings.reset_stream_at = XQC_FALSE;
    CU_ASSERT(xqc_stream_set_reliable_size(stream, 3) == -XQC_ESTATE);
    conn->remote_settings.reset_stream_at = XQC_TRUE;
    CU_ASSERT(xqc_stream_set_reliable_size(stream, 3) == XQC_OK);
    CU_ASSERT(stream->reset_at.send_state == XQC_RESET_AT_READY);
    CU_ASSERT(xqc_stream_reset(stream, 9) == -XQC_EAGAIN);
    CU_ASSERT(stream->reset_at.send_state == XQC_RESET_AT_PENDING);
    CU_ASSERT(xqc_stream_set_reliable_size(stream, 3) == XQC_OK);
    CU_ASSERT(stream->reset_at.send_state == XQC_RESET_AT_PENDING);
    CU_ASSERT(stream->reset_at.send_error == 9);
    xqc_stream_t *recv_only = xqc_passive_create_stream(conn, 3, NULL);
    CU_ASSERT_FATAL(recv_only != NULL);
    CU_ASSERT(xqc_stream_reset(recv_only, 9) == -XQC_EPARAM);
    CU_ASSERT(xqc_stream_set_reliable_size(recv_only, 3) == -XQC_EPARAM);
    xqc_stream_t *empty = xqc_stream_create_with_direction(conn,
        XQC_STREAM_UNI, NULL);
    CU_ASSERT_FATAL(empty != NULL);
    CU_ASSERT(xqc_stream_set_reliable_size(empty, 0) == XQC_OK);
    CU_ASSERT(xqc_stream_reset(empty, 9) == XQC_OK);
    CU_ASSERT(empty->reset_at.send_state == XQC_RESET_AT_SENT);
    CU_ASSERT(xqc_stream_reset(empty, 9) == XQC_OK);
    CU_ASSERT(xqc_stream_reset(empty, 10) == -XQC_ESTATE);
    CU_ASSERT(xqc_reset_test_packet_count(conn, XQC_FRAME_BIT_RESET_STREAM_AT)
        == 1);
    xqc_packet_out_t *reset = xqc_reset_test_queued_packet(empty,
        XQC_FRAME_BIT_RESET_STREAM_AT, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(reset);
    xqc_reset_test_packet_sent(conn, reset, 1);
    xqc_send_ctl_on_packet_acked(conn->conn_initial_path->path_send_ctl,
        reset, xqc_monotonic_timestamp(), 0);
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
