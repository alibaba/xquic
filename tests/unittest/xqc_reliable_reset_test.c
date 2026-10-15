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
static xqc_packet_out_t *xqc_reset_test_queued_reset_at(
    xqc_stream_t *stream, uint64_t reliable_size);
static xqc_bool_t xqc_reset_test_list_has_data_from(xqc_list_head_t *head,
    xqc_stream_id_t stream_id, uint64_t offset);
static void xqc_reset_test_packet_sent(xqc_connection_t *conn,
    xqc_packet_out_t *packet, xqc_packet_number_t number);

typedef struct {
    unsigned stop_count;
    unsigned closing_count;
    uint64_t stop_error;
    uint64_t offset_at_stop;
    xqc_bool_t reset_at_stop;
    xqc_bool_t reenter_read;
    xqc_bool_t destroy_stream;
    ssize_t reenter_result;
    xqc_bool_t reenter_write;
    ssize_t reenter_fin_result;
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
    if (notifications->reenter_write) {
        notifications->reenter_result =
            xqc_stream_send(stream, (unsigned char *)"x", 1, 0);
        notifications->reenter_fin_result =
            xqc_stream_send(stream, (unsigned char *)"", 0, 1);
    }
    if (notifications->reenter_read && notifications->closing_count == 1) {
        unsigned char data[8], fin;
        CU_ASSERT(stream->stream_state_recv >= XQC_RECV_STREAM_ST_RESET_RECVD);
        notifications->reenter_result =
            xqc_stream_recv(stream, data, sizeof(data), &fin);
        CU_ASSERT(fin == 0);
    }
    if (notifications->destroy_stream) {
        xqc_destroy_stream(stream);
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
    xqc_packet_in_t packet;
    memset(&packet, 0, sizeof(packet));
    packet.pos = data;
    packet.last = data + length;
    packet.pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    return xqc_process_frames(conn, &packet);
}

static unsigned
xqc_reset_test_packet_count(xqc_connection_t *conn, xqc_frame_type_bit_t type)
{
    unsigned count = 0;
    xqc_list_head_t *heads[] = {
        &conn->conn_send_queue->sndq_send_packets,
        &conn->conn_send_queue->sndq_send_packets_high_pri,
    };
    for (size_t i = 0; i < sizeof(heads) / sizeof(heads[0]); i++) {
        xqc_list_head_t *pos;
        xqc_list_for_each(pos, heads[i]) {
            xqc_packet_out_t *packet = xqc_list_entry(pos,
                xqc_packet_out_t, po_list);
            count += !!(packet->po_frame_types & type);
        }
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

static xqc_packet_out_t *
xqc_reset_test_queued_reset_at(xqc_stream_t *stream, uint64_t reliable_size)
{
    xqc_list_head_t *pos;
    xqc_list_for_each(pos,
        &stream->stream_conn->conn_send_queue->sndq_send_packets)
    {
        xqc_packet_out_t *packet = xqc_list_entry(pos, xqc_packet_out_t,
                                                  po_list);
        for (unsigned i = 0; i < packet->po_stream_frames_idx; i++) {
            xqc_po_stream_frame_t *frame = &packet->po_stream_frames[i];
            if (frame->ps_is_used && frame->ps_is_reset_at
                && frame->ps_stream_id == stream->stream_id
                && frame->ps_reset_at_size == reliable_size)
            {
                return packet;
            }
        }
    }
    return NULL;
}

static xqc_bool_t
xqc_reset_test_list_has_data_from(xqc_list_head_t *head,
    xqc_stream_id_t stream_id, uint64_t offset)
{
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, head) {
        xqc_packet_out_t *packet = xqc_list_entry(pos, xqc_packet_out_t,
                                                  po_list);
        for (unsigned i = 0; i < packet->po_stream_frames_idx; i++) {
            xqc_po_stream_frame_t *frame = &packet->po_stream_frames[i];
            if (frame->ps_is_used && !frame->ps_is_reset
                && !frame->ps_is_reset_at
                && frame->ps_stream_id == stream_id && frame->ps_length > 0
                && frame->ps_offset >= offset)
            {
                return XQC_TRUE;
            }
        }
    }
    return XQC_FALSE;
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
    xqc_conn_update_stream_stats_on_sent(conn,
        conn->conn_initial_path->path_send_ctl, packet,
        packet->po_sent_time);
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
    CU_ASSERT(strstr(stored, "reset_stream_at=1\n") != NULL);
    CU_ASSERT(xqc_read_transport_params(stored, n, &decoded) == XQC_OK);
    CU_ASSERT(decoded.reset_stream_at == XQC_TRUE);
    xqc_connection_t *conn = xqc_reset_test_conn();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT(xqc_conn_set_early_remote_transport_params(conn, &decoded)
        == XQC_OK);
    CU_ASSERT(conn->remote_settings.reset_stream_at == XQC_TRUE);
    xqc_engine_destroy(conn->engine);

    params.reset_stream_at = XQC_FALSE;
    n = xqc_write_transport_params(stored, sizeof(stored), &params);
    CU_ASSERT_FATAL(n > 0 && n < sizeof(stored));
    CU_ASSERT(strstr(stored, "reset_stream_at=") == NULL);
    int appended = snprintf(stored + n, sizeof(stored) - n,
                            "reset_stream_at=0\n");
    CU_ASSERT_FATAL(appended > 0 && appended < sizeof(stored) - n);
    xqc_init_transport_params(&decoded);
    CU_ASSERT(xqc_read_transport_params(stored, n + appended, &decoded)
        == XQC_OK);
    CU_ASSERT(decoded.reset_stream_at == XQC_FALSE);
    char *reset_value = strstr(stored, "reset_stream_at=0\n");
    CU_ASSERT_FATAL(reset_value != NULL);
    reset_value[xqc_lengthof("reset_stream_at=")] = '2';
    CU_ASSERT(xqc_read_transport_params(stored, n + appended, &decoded) < 0);

    /* Match the internal decimal parser and reset-only cache validation. */
    const char *valid_reset = "reset_stream_at=0001\n";
    strcpy(stored + n, valid_reset);
    CU_ASSERT(xqc_read_transport_params(stored, n + strlen(valid_reset),
                                       &decoded) == XQC_OK);
    CU_ASSERT(decoded.reset_stream_at == XQC_TRUE);
    CU_ASSERT(xqc_read_transport_params(stored, n, &decoded) == XQC_OK);
    CU_ASSERT(decoded.reset_stream_at == XQC_FALSE);

    const char *invalid_reset[] = {
        "reset_stream_at=2\n", "reset_stream_at=\n",
        "reset_stream_at=1x\n", "reset_stream_at=-1\n",
        "reset_stream_at=4611686018427387904\n",
        "reset_stream_at=1\nreset_stream_at=0\n",
    };
    for (size_t i = 0; i < sizeof(invalid_reset) / sizeof(invalid_reset[0]);
         i++)
    {
        strcpy(stored + n, invalid_reset[i]);
        CU_ASSERT(xqc_read_transport_params(stored,
            n + strlen(invalid_reset[i]), &decoded)
            == -XQC_TLS_MALFORMED_TRANSPORT_PARAM);
    }
}

void
xqc_test_reliable_reset_receive_order(void)
{
    /* Sections 5 and 5.3: reset may precede every reliable STREAM byte. */
    xqc_connection_t *conn = xqc_reset_test_conn();
    CU_ASSERT_FATAL(conn != NULL);
    conn->conn_flow_ctl.fc_max_data_can_recv = 8;
    conn->conn_flow_ctl.fc_recv_windows_size = 8;
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
    CU_ASSERT(conn->conn_flow_ctl.fc_max_data_can_recv > 8);
    CU_ASSERT(xqc_reset_test_packet_count(conn, XQC_FRAME_BIT_MAX_DATA) > 0);
    CU_ASSERT(xqc_reset_test_packet_count(conn,
        XQC_FRAME_BIT_MAX_STREAM_DATA) == 0);
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
    CU_ASSERT(stream->reset_at.recv_state == XQC_RESET_AT_RECV_NONE);
    CU_ASSERT(!stream->stream_data_in.stream_determined);
    CU_ASSERT(conn->conn_flow_ctl.fc_data_read == 8);
    unsigned char zero_late_fin[] = {0x0f, 3, 8, 1, 'x'};
    CU_ASSERT(xqc_reset_test_input(conn, zero_late_fin,
                                   sizeof(zero_late_fin)) == -XQC_EPROTO);
    CU_ASSERT(conn->conn_err == TRA_FINAL_SIZE_ERROR);
    xqc_engine_destroy(conn->engine);

    /* Ordinary reset is K=0: a later AT is validated but not re-accounted. */
    conn = xqc_reset_test_conn();
    CU_ASSERT_FATAL(conn != NULL);
    unsigned char ordinary[] = {0x04, 3, 9, 8};
    unsigned char later_at[] = {0x24, 3, 9, 8, 3};
    unsigned char late_fin[] = {0x0f, 3, 7, 1, 'x'};
    CU_ASSERT(xqc_reset_test_input(conn, ordinary, sizeof(ordinary))
        == XQC_OK);
    stream = xqc_find_stream_by_id(3, conn->streams_hash);
    CU_ASSERT_FATAL(stream != NULL);
    CU_ASSERT(stream->reset_at.recv_state == XQC_RESET_AT_RECV_NONE);
    CU_ASSERT(conn->conn_flow_ctl.fc_data_recved == 8);
    CU_ASSERT(xqc_reset_test_input(conn, later_at, sizeof(later_at))
        == XQC_OK);
    CU_ASSERT(conn->conn_flow_ctl.fc_data_recved == 8);
    CU_ASSERT(stream->reset_at.recv_state == XQC_RESET_AT_RECV_NONE);
    CU_ASSERT(xqc_reset_test_input(conn, late_fin, sizeof(late_fin))
        == XQC_OK);
    CU_ASSERT(conn->conn_err == 0);
    later_at[2] = 10;
    CU_ASSERT(xqc_reset_test_input(conn, later_at, sizeof(later_at))
        == -XQC_EPROTO);
    CU_ASSERT(conn->conn_err == TRA_STREAM_STATE_ERROR);
    xqc_engine_destroy(conn->engine);

    /* Data Read stays terminal for both reset frame kinds. */
    conn = xqc_reset_test_conn();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_reset_test_notifications_t terminal_notifications = {0};
    xqc_stream_callbacks_t terminal_callbacks = {
        .stream_closing_notify = xqc_reset_test_closing_notify,
    };
    stream = xqc_passive_create_stream(conn, 3, &terminal_notifications);
    CU_ASSERT_FATAL(stream != NULL);
    stream->stream_if = &terminal_callbacks;
    unsigned char complete[] = {0x0f, 3, 0, 3, 'a', 'b', 'c'};
    CU_ASSERT(xqc_reset_test_input(conn, complete, sizeof(complete))
        == XQC_OK);
    CU_ASSERT(xqc_stream_recv(stream, result, sizeof(result), &fin) == 3);
    CU_ASSERT(fin == 1);
    CU_ASSERT(stream->stream_state_recv == XQC_RECV_STREAM_ST_DATA_READ);
    unsigned char terminal_at[] = {0x24, 3, 9, 3, 2};
    CU_ASSERT(xqc_reset_test_input(conn, terminal_at, sizeof(terminal_at))
        == XQC_OK);
    CU_ASSERT(stream->stream_state_recv == XQC_RECV_STREAM_ST_DATA_READ);
    CU_ASSERT(stream->reset_at.recv_state == XQC_RESET_AT_RECV_NONE);
    unsigned char terminal_reset[] = {0x04, 3, 9, 3};
    CU_ASSERT(xqc_reset_test_input(conn, terminal_reset,
                                  sizeof(terminal_reset)) == XQC_OK);
    CU_ASSERT(stream->stream_state_recv == XQC_RECV_STREAM_ST_DATA_READ);
    CU_ASSERT(terminal_notifications.closing_count == 0);
    xqc_engine_destroy(conn->engine);

    /* Lowering K below bytes already read completes the reset immediately. */
    conn = xqc_reset_test_conn();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_reset_test_notifications_t lower_notifications = {0};
    xqc_stream_callbacks_t lower_callbacks = {
        .stream_closing_notify = xqc_reset_test_closing_notify,
    };
    unsigned char reset_four[] = {0x24, 3, 9, 8, 4};
    unsigned char first_three[] = {
        0x0e, 3, 0, 3, 'a', 'b', 'c',
    };
    CU_ASSERT(xqc_reset_test_input(conn, reset_four, sizeof(reset_four))
        == XQC_OK);
    stream = xqc_find_stream_by_id(3, conn->streams_hash);
    CU_ASSERT_FATAL(stream != NULL);
    stream->stream_if = &lower_callbacks;
    stream->user_data = &lower_notifications;
    CU_ASSERT(xqc_reset_test_input(conn, first_three, sizeof(first_three))
        == XQC_OK);
    CU_ASSERT(xqc_stream_recv(stream, result, sizeof(result), &fin) == 3);
    reset_four[4] = 2;
    CU_ASSERT(xqc_reset_test_input(conn, reset_four, sizeof(reset_four))
        == XQC_OK);
    CU_ASSERT(stream->stream_state_recv == XQC_RECV_STREAM_ST_RESET_RECVD);
    CU_ASSERT(stream->reset_at.recv_size == 2);
    CU_ASSERT(lower_notifications.closing_count == 1);
    CU_ASSERT(xqc_stream_recv(stream, result, sizeof(result), &fin)
        == -XQC_ESTREAM_RESET);
    xqc_engine_destroy(conn->engine);

    /* A reliable completion callback may destroy the stream. */
    conn = xqc_reset_test_conn();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_reset_test_notifications_t destroy_notifications = {
        .destroy_stream = XQC_TRUE,
    };
    xqc_stream_callbacks_t destroy_callbacks = {
        .stream_closing_notify = xqc_reset_test_closing_notify,
    };
    stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI,
        &destroy_notifications);
    CU_ASSERT_FATAL(stream != NULL && stream->stream_id < 64);
    stream->stream_if = &destroy_callbacks;
    xqc_stream_id_t destroyed_id = stream->stream_id;
    unsigned char destroy_reset[] = {
        0x24, (unsigned char)destroyed_id, 9, 8, 3,
    };
    unsigned char destroy_data[] = {
        0x0e, (unsigned char)destroyed_id, 0, 3, 'a', 'b', 'c',
    };
    CU_ASSERT(xqc_reset_test_input(conn, destroy_reset,
                                  sizeof(destroy_reset)) == XQC_OK);
    CU_ASSERT(xqc_reset_test_input(conn, destroy_data,
                                  sizeof(destroy_data)) == XQC_OK);
    CU_ASSERT(xqc_stream_recv(stream, result, sizeof(result), &fin) == 3);
    CU_ASSERT(xqc_stream_recv(stream, result, sizeof(result), &fin)
        == -XQC_ESTREAM_RESET);
    CU_ASSERT(destroy_notifications.closing_count == 1);
    CU_ASSERT_PTR_NULL(xqc_find_stream_by_id(destroyed_id,
                                             conn->streams_hash));
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

static void
xqc_reset_test_at_frame_codec(void)
{
    /* RFC 9000 Section 16; reliable-stream-reset-09 Section 4. */
    unsigned char wire[] = {
        0x24, 0x40, 0x40, 0x80, 0x00, 0x40, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
    };
    unsigned char buf[32], untouched[32];
    memset(untouched, 0xa5, sizeof(untouched));
    size_t length = sizeof(wire);
    xqc_frame_type_bit_t bit = XQC_FRAME_BIT_RESET_STREAM_AT;
    xqc_packet_out_t out;
    memset(&out, 0, sizeof(out));
    out.po_buf = buf;
    out.po_used_size = 3;
    out.po_frame_types = XQC_FRAME_BIT_PING;
    memcpy(buf, untouched, sizeof(buf));

    /* A short buffer must not commit even the frame type. */
    out.po_buf_size = out.po_used_size + length - 1;
    ssize_t n = xqc_gen_reset_stream_at_frame(&out, 64, 16384, XQC_VINT_MAX,
                                              1073741824);
    CU_ASSERT(n == -XQC_ENOBUF);
    CU_ASSERT(memcmp(buf, untouched, sizeof(buf)) == 0);
    CU_ASSERT(out.po_frame_types == XQC_FRAME_BIT_PING);

    out.po_buf_size++;
    n = xqc_gen_reset_stream_at_frame(&out, 64, 16384, XQC_VINT_MAX,
                                      1073741824);
    CU_ASSERT(n == length);
    CU_ASSERT(memcmp(buf + out.po_used_size, wire, length) == 0);
    CU_ASSERT(out.po_used_size == 3);
    CU_ASSERT(buf[2] == 0xa5 && buf[3 + length] == 0xa5);
    CU_ASSERT(out.po_frame_types == (XQC_FRAME_BIT_PING | bit));

    /* Every truncated field must leave the input cursor uncommitted. */
    for (size_t size = 0; size <= length; size++) {
        xqc_packet_in_t in;
        memset(&in, 0, sizeof(in));
        in.pos = wire;
        in.last = wire + size;
        in.pi_frame_types = XQC_FRAME_BIT_PING;
        uint64_t id = 0, error = 0, final = 0, prefix = 0;
        xqc_int_t ret = xqc_parse_reset_stream_at_frame(&in, &id, &error,
                                                        &final, &prefix);
        if (size < length) {
            CU_ASSERT(ret == -XQC_EVINTREAD);
            CU_ASSERT(in.pos == wire);
            CU_ASSERT(in.pi_frame_types == XQC_FRAME_BIT_PING);

        } else {
            CU_ASSERT(ret == XQC_OK);
            CU_ASSERT(id == 64 && error == 16384 && final == XQC_VINT_MAX);
            CU_ASSERT(prefix == 1073741824);
            CU_ASSERT(in.pos == wire + length);
            CU_ASSERT(in.pi_frame_types == (XQC_FRAME_BIT_PING | bit));
        }
    }

    /* RESET_STREAM_AT rejects out-of-range fields before writing. */
    for (int field = 0; field < 4; field++) {
        uint64_t values[] = {64, 16384, XQC_VINT_MAX, 1073741824};
        values[field] = XQC_VINT_MAX + 1;
        out.po_frame_types = XQC_FRAME_BIT_PING;
        memcpy(buf, untouched, sizeof(buf));
        n = xqc_gen_reset_stream_at_frame(&out, values[0], values[1],
                                          values[2], values[3]);
        CU_ASSERT(n == -XQC_EPARAM);
        CU_ASSERT(memcmp(buf, untouched, sizeof(buf)) == 0);
        CU_ASSERT(out.po_frame_types == XQC_FRAME_BIT_PING);
        CU_ASSERT(out.po_used_size == 3);
    }
}

void
xqc_test_reliable_reset_receive_errors(void)
{
    xqc_reset_test_at_frame_codec();
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

    /* -09 Section 5.2: ordinary resets preserve reliable reset fields. */
    for (int change = 0; change < 4; change++) {
        xqc_connection_t *conn = xqc_reset_test_conn();
        CU_ASSERT_FATAL(conn != NULL);
        unsigned char reliable[] = {0x24, 3, 9, 8, 4};
        unsigned char ordinary[] = {0x04, 3, 9, 8};
        CU_ASSERT(xqc_reset_test_input(conn, reliable, sizeof(reliable))
            == XQC_OK);
        if (change == 1) {
            ordinary[2]++;

        } else if (change == 2) {
            ordinary[3]--;

        } else if (change == 3) {
            ordinary[3]++;
        }
        CU_ASSERT(xqc_reset_test_input(conn, ordinary, sizeof(ordinary))
            == (change ? -XQC_EPROTO : XQC_OK));
        CU_ASSERT(conn->conn_err == (change == 0 ? 0
            : change == 1 ? TRA_STREAM_STATE_ERROR : TRA_FINAL_SIZE_ERROR));
        CU_ASSERT(conn->conn_flow_ctl.fc_data_recved == 8);
        CU_ASSERT(conn->conn_flow_ctl.fc_data_read == (change ? 0 : 8));
        xqc_engine_destroy(conn->engine);
    }

    /* RFC 9000 Section 4.1 and reliable-stream-reset-09 Section 4. */
    const struct {
        uint64_t received;
        unsigned char final_size;
        xqc_bool_t accepted;
    } flow_cases[] = {
        {99, 8, XQC_TRUE}, {99, 9, XQC_TRUE}, {99, 10, XQC_FALSE},
        {100, 8, XQC_TRUE}, {100, 9, XQC_FALSE},
        {101, 8, XQC_FALSE}, {101, 9, XQC_FALSE},
    };
    for (int reset_at = 0; reset_at < 2; reset_at++) {
        for (size_t i = 0; i < sizeof(flow_cases) / sizeof(flow_cases[0]);
             i++)
        {
            xqc_connection_t *conn = xqc_reset_test_conn();
            CU_ASSERT_FATAL(conn != NULL);
            unsigned char data[] = {
                0x0e, 3, 0, 8, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
            };
            CU_ASSERT(xqc_reset_test_input(conn, data, sizeof(data))
                == XQC_OK);
            xqc_stream_t *stream = xqc_find_stream_by_id(3, conn->streams_hash);
            CU_ASSERT_FATAL(stream != NULL);
            /* Seed the already-exceeded state as well as legal boundaries. */
            conn->conn_flow_ctl.fc_data_recved = flow_cases[i].received;
            conn->conn_flow_ctl.fc_max_data_can_recv = 100;
            unsigned char reset[] = {
                reset_at ? 0x24 : 0x04, 3, 9, flow_cases[i].final_size, 4,
            };
            xqc_bool_t accepted = flow_cases[i].accepted;
            CU_ASSERT(xqc_reset_test_input(conn, reset, reset_at ? 5 : 4)
                == (accepted ? XQC_OK : -XQC_EPROTO));
            CU_ASSERT(conn->conn_err
                == (accepted ? 0 : TRA_FLOW_CONTROL_ERROR));
            CU_ASSERT(conn->conn_flow_ctl.fc_data_recved
                == flow_cases[i].received
                    + (accepted ? flow_cases[i].final_size - 8 : 0));
            CU_ASSERT(stream->stream_max_recv_offset
                == (accepted ? flow_cases[i].final_size : 8));
            CU_ASSERT(conn->conn_flow_ctl.fc_data_read
                == (accepted && !reset_at ? flow_cases[i].final_size : 0));
            xqc_engine_destroy(conn->engine);
        }
    }
}

static void
xqc_reset_test_ack_capability(void)
{
    for (unsigned local = 0; local < 2; local++) {
        for (unsigned remote = 0; remote < 2; remote++) {
            xqc_connection_t *conn = xqc_reset_test_conn();
            CU_ASSERT_FATAL(conn != NULL);
            conn->local_settings.reset_stream_at = local;
            conn->remote_settings.reset_stream_at = remote;
            xqc_send_ctl_t *ctl = conn->conn_initial_path->path_send_ctl;
            xqc_stream_t *stream = xqc_stream_create_with_direction(conn,
                XQC_STREAM_UNI, NULL);
            CU_ASSERT_FATAL(stream != NULL);
            stream->stream_flag |= XQC_STREAM_FLAG_HAS_H3;
            CU_ASSERT(xqc_stream_send(stream, (unsigned char *)"ab", 2, 0)
                == 2);
            xqc_packet_out_t *head = xqc_reset_test_queued_packet(stream,
                XQC_FRAME_BIT_STREAM, 0);
            CU_ASSERT_PTR_NOT_NULL_FATAL(head);
            xqc_reset_test_packet_sent(conn, head, 1);
            CU_ASSERT(xqc_stream_send(stream, (unsigned char *)"cd", 2, 0)
                == 2);
            xqc_packet_out_t *tail = xqc_reset_test_queued_packet(stream,
                XQC_FRAME_BIT_STREAM, 2);
            CU_ASSERT_PTR_NOT_NULL_FATAL(tail);
            xqc_reset_test_packet_sent(conn, tail, 2);

            /* Peer parameters can be known before handshake completion. */
            conn->conn_flag &= ~XQC_CONN_FLAG_TLS_HSK_COMPLETED;
            xqc_send_ctl_on_packet_acked(ctl, tail,
                xqc_monotonic_timestamp(), 0);
            CU_ASSERT(stream->stream_acked_offset == 0);
            CU_ASSERT(xqc_list_empty(&stream->stream_acked_ranges) == !remote);
            xqc_send_ctl_on_packet_acked(ctl, head,
                xqc_monotonic_timestamp(), 0);
            CU_ASSERT(stream->stream_acked_offset == (remote ? 4 : 0));
            CU_ASSERT(xqc_list_empty(&stream->stream_acked_ranges));
            CU_ASSERT(stream->reset_at.send_state == XQC_RESET_AT_NONE);
            conn->conn_flag |= XQC_CONN_FLAG_TLS_HSK_COMPLETED;

            /* -09 Section 5.3: retain ACKs from before the reset API call. */
            if (remote) {
                CU_ASSERT(xqc_stream_set_reliable_size(stream, 4) == XQC_OK);
                CU_ASSERT(xqc_stream_reset(stream, 9) == XQC_OK);
                xqc_packet_out_t *reset = xqc_reset_test_queued_reset_at(
                    stream, 4);
                CU_ASSERT_PTR_NOT_NULL_FATAL(reset);
                xqc_reset_test_packet_sent(conn, reset, 3);
                xqc_send_ctl_on_packet_acked(ctl, reset,
                    xqc_monotonic_timestamp(), 0);
                CU_ASSERT(stream->stream_state_send
                    == XQC_SEND_STREAM_ST_DATA_RECVD);

            } else {
                CU_ASSERT(xqc_stream_set_reliable_size(stream, 4)
                    == -XQC_ESTATE);
            }
            CU_ASSERT(conn->conn_err == 0);
            xqc_engine_destroy(conn->engine);
        }
    }
}

void
xqc_test_reliable_reset_ack_order(void)
{
    xqc_reset_test_ack_capability();

    /* Section 5.3: merge later ACK ranges and wait for the leading gap. */
    xqc_connection_t *conn = xqc_reset_test_conn();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_send_ctl_t *ctl = conn->conn_initial_path->path_send_ctl;
    xqc_stream_t *stream = xqc_stream_create_with_direction(conn,
        XQC_STREAM_UNI, NULL);
    CU_ASSERT_FATAL(stream != NULL);
    stream->stream_flag |= XQC_STREAM_FLAG_HAS_H3;
    CU_ASSERT(xqc_stream_set_reliable_size(stream, 6) == XQC_OK);
    CU_ASSERT(xqc_stream_send(stream, (unsigned char *)"ab", 2, 0) == 2);
    xqc_packet_out_t *head = xqc_reset_test_queued_packet(stream,
        XQC_FRAME_BIT_STREAM, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(head);
    xqc_send_queue_move_to_high_pri(&head->po_list, conn->conn_send_queue);
    CU_ASSERT(xqc_stream_send(stream, (unsigned char *)"cd", 2, 0) == 2);
    xqc_packet_out_t *middle = xqc_reset_test_queued_packet(stream,
        XQC_FRAME_BIT_STREAM, 2);
    CU_ASSERT_PTR_NOT_NULL_FATAL(middle);
    xqc_send_queue_move_to_high_pri(&middle->po_list, conn->conn_send_queue);
    CU_ASSERT(xqc_stream_send(stream, (unsigned char *)"ef", 2, 0) == 2);
    xqc_packet_out_t *tail = xqc_reset_test_queued_packet(stream,
        XQC_FRAME_BIT_STREAM, 4);
    CU_ASSERT_PTR_NOT_NULL_FATAL(tail);
    CU_ASSERT(xqc_stream_reset(stream, 9) == XQC_OK);
    xqc_packet_out_t *reset = xqc_reset_test_queued_reset_at(stream, 6);
    CU_ASSERT_PTR_NOT_NULL_FATAL(reset);
    CU_ASSERT(stream->stream_stats.app_reset_time != 0);
    CU_ASSERT(stream->stream_stats.local_reset_time == 0);

    xqc_reset_test_packet_sent(conn, reset, 1);
    CU_ASSERT(stream->stream_stats.local_reset_time == 1);
    xqc_send_ctl_on_packet_acked(ctl, reset, xqc_monotonic_timestamp(), 0);
    CU_ASSERT(stream->reset_at.send_reset_acked);
    CU_ASSERT(stream->stream_state_send == XQC_SEND_STREAM_ST_DATA_SENT);

    xqc_reset_test_packet_sent(conn, middle, 2);
    xqc_send_ctl_on_packet_acked(ctl, middle, xqc_monotonic_timestamp(), 0);
    xqc_reset_test_packet_sent(conn, tail, 3);
    xqc_send_ctl_on_packet_acked(ctl, tail, xqc_monotonic_timestamp(), 0);
    CU_ASSERT(stream->stream_acked_offset == 0);
    CU_ASSERT(!xqc_list_empty(&stream->stream_acked_ranges));
    CU_ASSERT(xqc_stream_on_data_acked(stream, 2, 4) == XQC_OK);
    CU_ASSERT(stream->stream_acked_offset == 0);
    CU_ASSERT(stream->stream_state_send == XQC_SEND_STREAM_ST_DATA_SENT);

    xqc_reset_test_packet_sent(conn, head, 4);
    xqc_send_ctl_on_packet_acked(ctl, head, xqc_monotonic_timestamp(), 0);
    CU_ASSERT(stream->stream_acked_offset == 6);
    CU_ASSERT(xqc_list_empty(&stream->stream_acked_ranges));
    CU_ASSERT(stream->stream_state_send == XQC_SEND_STREAM_ST_DATA_RECVD);
    CU_ASSERT(xqc_stream_set_reliable_size(stream, 6) == XQC_OK);
    CU_ASSERT(xqc_stream_set_reliable_size(stream, 5) == -XQC_ESTATE);
    CU_ASSERT(xqc_stream_reset(stream, 9) == XQC_OK);
    CU_ASSERT(xqc_stream_reset(stream, 10) == -XQC_ESTATE);
    xqc_engine_destroy(conn->engine);

    /* Send and receive errors remain independent on a bidirectional stream. */
    conn = xqc_reset_test_conn();
    CU_ASSERT_FATAL(conn != NULL);
    stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    CU_ASSERT_FATAL(stream != NULL && stream->stream_id < 64);
    CU_ASSERT(xqc_stream_reset(stream, 17) == XQC_OK);
    unsigned char peer_zero_reset[] = {
        XQC_FRAME_TYPE_RESET_STREAM_AT, (unsigned char)stream->stream_id,
        9, 0, 0,
    };
    CU_ASSERT(xqc_reset_test_input(conn, peer_zero_reset,
                                   sizeof(peer_zero_reset)) == XQC_OK);
    CU_ASSERT(stream->stream_err == 9);
    CU_ASSERT(stream->reset_at.send_error == 17);
    CU_ASSERT(xqc_stream_reset(stream, 17) == XQC_OK);
    CU_ASSERT(xqc_stream_reset(stream, 9) == -XQC_ESTATE);
    xqc_engine_destroy(conn->engine);

    /* Only the control frame carrying the current, lowered K can finish. */
    conn = xqc_reset_test_conn();
    CU_ASSERT_FATAL(conn != NULL);
    ctl = conn->conn_initial_path->path_send_ctl;
    stream = xqc_stream_create_with_direction(conn, XQC_STREAM_UNI, NULL);
    CU_ASSERT_FATAL(stream != NULL);
    stream->stream_flag |= XQC_STREAM_FLAG_HAS_H3;
    CU_ASSERT(xqc_stream_set_reliable_size(stream, 5) == XQC_OK);
    CU_ASSERT(xqc_stream_send(stream, (unsigned char *)"abcde", 5, 0) == 5);
    xqc_packet_out_t *data = xqc_reset_test_queued_packet(stream,
        XQC_FRAME_BIT_STREAM, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(data);
    CU_ASSERT(xqc_stream_reset(stream, 9) == XQC_OK);
    xqc_packet_out_t *reset_five = xqc_reset_test_queued_reset_at(stream, 5);
    CU_ASSERT_PTR_NOT_NULL_FATAL(reset_five);
    CU_ASSERT(xqc_stream_set_reliable_size(stream, 3) == XQC_OK);
    CU_ASSERT(stream->reset_at.send_update_pending);
    CU_ASSERT(xqc_stream_set_reliable_size(stream, 4) == -XQC_ESTATE);
    CU_ASSERT(xqc_stream_reset(stream, 10) == -XQC_ESTATE);
    CU_ASSERT(xqc_stream_reset(stream, 9) == XQC_OK);
    xqc_packet_out_t *reset_three = xqc_reset_test_queued_reset_at(stream, 3);
    CU_ASSERT_PTR_NOT_NULL_FATAL(reset_three);

    xqc_reset_test_packet_sent(conn, data, 1);
    xqc_send_ctl_on_packet_acked(ctl, data, xqc_monotonic_timestamp(), 0);
    CU_ASSERT(stream->stream_acked_offset == 5);
    xqc_reset_test_packet_sent(conn, reset_five, 2);
    xqc_send_ctl_on_packet_acked(ctl, reset_five,
                                 xqc_monotonic_timestamp(), 0);
    CU_ASSERT(!stream->reset_at.send_reset_acked);
    CU_ASSERT(stream->stream_state_send == XQC_SEND_STREAM_ST_DATA_SENT);
    xqc_reset_test_packet_sent(conn, reset_three, 3);
    xqc_send_ctl_on_packet_acked(ctl, reset_three,
                                 xqc_monotonic_timestamp(), 0);
    CU_ASSERT(stream->reset_at.send_reset_acked);
    CU_ASSERT(stream->stream_state_send == XQC_SEND_STREAM_ST_DATA_RECVD);
    xqc_engine_destroy(conn->engine);

    /* ACK state is per stream and duplicate range insertion is idempotent. */
    conn = xqc_reset_test_conn();
    CU_ASSERT_FATAL(conn != NULL);
    stream = xqc_stream_create_with_direction(conn, XQC_STREAM_UNI, NULL);
    xqc_stream_t *other = xqc_stream_create_with_direction(conn,
        XQC_STREAM_UNI, NULL);
    CU_ASSERT_FATAL(stream != NULL && other != NULL);
    CU_ASSERT(xqc_stream_on_data_acked(stream, 4, 2) == XQC_OK);
    CU_ASSERT(xqc_stream_on_data_acked(stream, 2, 2) == XQC_OK);
    CU_ASSERT(xqc_stream_on_data_acked(stream, 2, 4) == XQC_OK);
    CU_ASSERT(stream->stream_acked_offset == 0);
    CU_ASSERT(other->stream_acked_offset == 0);
    CU_ASSERT(xqc_stream_on_data_acked(stream, 0, 2) == XQC_OK);
    CU_ASSERT(stream->stream_acked_offset == 6);
    CU_ASSERT(xqc_list_empty(&stream->stream_acked_ranges));
    CU_ASSERT(other->stream_acked_offset == 0);
    xqc_engine_destroy(conn->engine);

    /* Reset cleanup removes the unreliable suffix from every send queue. */
    conn = xqc_reset_test_conn();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_send_queue_t *queue = conn->conn_send_queue;
    xqc_path_ctx_t *path = conn->conn_initial_path;
    stream = xqc_stream_create_with_direction(conn, XQC_STREAM_UNI, NULL);
    CU_ASSERT_FATAL(stream != NULL);
    stream->stream_flag |= XQC_STREAM_FLAG_HAS_H3;
    CU_ASSERT(xqc_stream_set_reliable_size(stream, 1) == XQC_OK);

    for (uint64_t offset = 0; offset < 9; offset++) {
        CU_ASSERT(xqc_stream_send(stream, (unsigned char *)"x", 1, 0) == 1);
        xqc_packet_out_t *packet = xqc_reset_test_queued_packet(stream,
            XQC_FRAME_BIT_STREAM, offset);
        CU_ASSERT_PTR_NOT_NULL_FATAL(packet);
        switch (offset) {
        case 0:
        case 1:
            xqc_send_queue_move_to_high_pri(&packet->po_list, queue);
            break;
        case 2:
            xqc_send_queue_remove_send(&packet->po_list);
            xqc_send_queue_insert_buff(&packet->po_list,
                                       &queue->sndq_buff_1rtt_packets);
            break;
        case 3:
            xqc_path_send_buffer_append(path, packet,
                &path->path_schedule_buf[XQC_SEND_TYPE_NORMAL_HIGH_PRI]);
            break;
        case 4:
            xqc_send_queue_remove_send(&packet->po_list);
            xqc_send_queue_insert_lost(&packet->po_list,
                                       &queue->sndq_lost_packets);
            break;
        case 5:
            xqc_send_queue_remove_send(&packet->po_list);
            xqc_send_queue_insert_probe(&packet->po_list,
                                        &queue->sndq_pto_probe_packets);
            break;
        case 6:
            xqc_path_send_buffer_append(path, packet,
                                        &path->path_reinj_tmp_buf);
            break;
        case 7:
            xqc_reset_test_packet_sent(conn, packet, 1);
            xqc_send_queue_copy_to_lost(packet, queue, XQC_FALSE);
            xqc_send_queue_copy_to_probe(packet, queue, path);
            CU_ASSERT(packet->po_origin_ref_cnt == 2);
            break;
        default:
            break;
        }
    }

    CU_ASSERT(xqc_stream_reset(stream, 9) == XQC_OK);
    CU_ASSERT(xqc_reset_test_list_has_data_from(
        &queue->sndq_send_packets_high_pri, stream->stream_id, 0));
    CU_ASSERT(!xqc_reset_test_list_has_data_from(
        &queue->sndq_send_packets_high_pri, stream->stream_id, 1));
    CU_ASSERT(!xqc_reset_test_list_has_data_from(
        &queue->sndq_send_packets, stream->stream_id, 1));
    CU_ASSERT(!xqc_reset_test_list_has_data_from(
        &queue->sndq_buff_1rtt_packets, stream->stream_id, 1));
    CU_ASSERT(!xqc_reset_test_list_has_data_from(
        &queue->sndq_unacked_packets[XQC_PNS_APP_DATA],
        stream->stream_id, 1));
    CU_ASSERT(!xqc_reset_test_list_has_data_from(
        &queue->sndq_lost_packets, stream->stream_id, 1));
    CU_ASSERT(!xqc_reset_test_list_has_data_from(
        &queue->sndq_pto_probe_packets, stream->stream_id, 1));
    for (int type = 0; type < XQC_SEND_TYPE_N; type++) {
        CU_ASSERT(!xqc_reset_test_list_has_data_from(
            &path->path_schedule_buf[type], stream->stream_id, 1));
    }
    CU_ASSERT(!xqc_reset_test_list_has_data_from(&path->path_reinj_tmp_buf,
                                                 stream->stream_id, 1));
    CU_ASSERT(stream->stream_unacked_pkt == 0);
    xqc_engine_destroy(conn->engine);
}

void
xqc_test_reliable_reset_stop_sending(void)
{
    /* Section 5.4: STOP never obligates the application to fill a prefix. */
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
    CU_ASSERT(stream->reset_at.send_state != XQC_RESET_AT_SENT);
    CU_ASSERT(stream->stream_state_send == XQC_SEND_STREAM_ST_RESET_SENT);
    CU_ASSERT(notifications.stop_count == 1);
    CU_ASSERT(notifications.stop_error == 9);
    CU_ASSERT(notifications.offset_at_stop == 0);
    CU_ASSERT(!notifications.reset_at_stop);
    CU_ASSERT(xqc_reset_test_packet_count(conn, XQC_FRAME_BIT_RESET_STREAM)
        == 1);
    CU_ASSERT(xqc_reset_test_packet_count(conn,
        XQC_FRAME_BIT_RESET_STREAM_AT) == 0);
    CU_ASSERT(xqc_stream_send(stream, (unsigned char *)"abc", 3, 0)
        == -XQC_ESTREAM_RESET);
    stop[2] = 10;
    CU_ASSERT(xqc_reset_test_input(conn, stop, sizeof(stop)) == XQC_OK);
    CU_ASSERT(notifications.stop_count == 2);
    CU_ASSERT(notifications.stop_error == 10);
    CU_ASSERT(notifications.offset_at_stop == 0);
    CU_ASSERT(!notifications.reset_at_stop);
    CU_ASSERT(notifications.closing_count == 0);
    CU_ASSERT(xqc_reset_test_input(conn, stop, sizeof(stop)) == XQC_OK);
    CU_ASSERT(notifications.stop_count == 3);
    CU_ASSERT(notifications.offset_at_stop == 0);
    CU_ASSERT(!notifications.reset_at_stop);
    CU_ASSERT(xqc_reset_test_packet_count(conn, XQC_FRAME_BIT_RESET_STREAM)
        == 1);
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
    const unsigned indices[] = {
        0, XQC_MAX_STREAM_FRAME_IN_PO - 1,
        XQC_MAX_STREAM_FRAME_IN_PO, XQC_MAX_STREAM_FRAME_IN_PO + 1,
    };
    for (int reset_at = 0; reset_at < 2; reset_at++) {
        for (size_t i = 0; i < sizeof(indices) / sizeof(indices[0]); i++) {
            xqc_packet_out_t packet, before;
            xqc_stream_t stream;
            memset(&packet, 0, sizeof(packet));
            memset(&stream, 0, sizeof(stream));
            stream.stream_id = 2;
            packet.po_stream_frames_idx = indices[i];
            memcpy(&before, &packet, sizeof(before));
            xqc_bool_t full = indices[i] >= XQC_MAX_STREAM_FRAME_IN_PO;
            CU_ASSERT(xqc_record_reset_frame(&packet, &stream, reset_at, 4)
                == (full ? -XQC_ENOBUF : XQC_OK));
            if (full) {
                CU_ASSERT(memcmp(&packet, &before, sizeof(packet)) == 0);
                CU_ASSERT(stream.stream_stats.app_reset_time == 0);
                continue;
            }
            CU_ASSERT(packet.po_stream_frames_idx == indices[i] + 1);
            xqc_po_stream_frame_t *frame =
                &packet.po_stream_frames[indices[i]];
            CU_ASSERT(frame->ps_is_used);
            CU_ASSERT(frame->ps_stream_id == 2);
            CU_ASSERT(frame->ps_is_reset == !reset_at);
            CU_ASSERT(frame->ps_is_reset_at == reset_at);
            CU_ASSERT(frame->ps_reset_at_size == 4);
            CU_ASSERT(stream.stream_stats.app_reset_time != 0);
            CU_ASSERT(memcmp(packet.po_stream_frames, before.po_stream_frames,
                indices[i] * sizeof(*frame)) == 0);
        }
    }

    xqc_connection_t *conn = xqc_reset_test_conn();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_stream_t *stream = xqc_stream_create_with_direction(conn,
        XQC_STREAM_UNI, NULL);
    CU_ASSERT_FATAL(stream != NULL);
    /* A remembered TP must not authorize resets before this handshake. */
    stream->stream_flag |= XQC_STREAM_FLAG_HAS_H3;
    conn->conn_flag &= ~XQC_CONN_FLAG_TLS_HSK_COMPLETED;
    CU_ASSERT(xqc_stream_set_reliable_size(stream, 3) == -XQC_ESTATE);
    CU_ASSERT(stream->reset_at.send_state == XQC_RESET_AT_NONE);
    CU_ASSERT(xqc_stream_set_reliable_size(stream, 0) == XQC_OK);
    CU_ASSERT(stream->reset_at.send_state == XQC_RESET_AT_READY);
    conn->conn_flag |= XQC_CONN_FLAG_TLS_HSK_COMPLETED;
    conn->remote_settings.reset_stream_at = XQC_FALSE;
    CU_ASSERT(xqc_stream_set_reliable_size(stream, 3) == -XQC_ESTATE);
    conn->remote_settings.reset_stream_at = XQC_TRUE;
    CU_ASSERT(xqc_stream_set_reliable_size(stream, 3) == XQC_OK);
    CU_ASSERT(stream->reset_at.send_state == XQC_RESET_AT_READY);
    CU_ASSERT(xqc_stream_reset(stream, 9) == -XQC_EAGAIN);
    CU_ASSERT(stream->reset_at.send_state == XQC_RESET_AT_READY);
    CU_ASSERT(stream->reset_at.send_error == 0);
    CU_ASSERT(xqc_reset_test_packet_count(conn,
        XQC_FRAME_BIT_RESET_STREAM_AT) == 0);
    CU_ASSERT(xqc_stream_send(stream, (unsigned char *)"abc", 3, 0) == 3);
    CU_ASSERT(xqc_stream_set_reliable_size(stream, 3) == XQC_OK);
    CU_ASSERT(stream->reset_at.send_state == XQC_RESET_AT_READY);
    CU_ASSERT(xqc_stream_reset(stream, 9) == XQC_OK);
    CU_ASSERT(stream->reset_at.send_state == XQC_RESET_AT_SENT);
    CU_ASSERT(stream->reset_at.send_error == 9);
    CU_ASSERT(xqc_stream_send(stream, (unsigned char *)"d", 1, 0)
        == -XQC_ESTREAM_RESET);
    xqc_stream_t *recv_only = xqc_passive_create_stream(conn, 3, NULL);
    CU_ASSERT_FATAL(recv_only != NULL);
    CU_ASSERT(xqc_stream_reset(recv_only, 9) == -XQC_EPARAM);
    CU_ASSERT(xqc_stream_set_reliable_size(recv_only, 3) == -XQC_EPARAM);

    xqc_stream_t *finished = xqc_stream_create_with_direction(conn,
        XQC_STREAM_UNI, NULL);
    CU_ASSERT_FATAL(finished != NULL);
    xqc_stream_send_state_update(finished, XQC_SEND_STREAM_ST_DATA_RECVD);
    CU_ASSERT(xqc_stream_set_reliable_size(finished, 0) == -XQC_ESTATE);
    CU_ASSERT(xqc_stream_reset(finished, 9) == -XQC_ESTATE);
    CU_ASSERT(finished->stream_state_send == XQC_SEND_STREAM_ST_DATA_RECVD);
    size_t reset_count = xqc_reset_test_packet_count(
        conn, XQC_FRAME_BIT_RESET_STREAM);
    unsigned char finished_stop[] = {
        0x05, (unsigned char)finished->stream_id, 9,
    };
    CU_ASSERT(xqc_reset_test_input(conn, finished_stop,
                                   sizeof(finished_stop)) == XQC_OK);
    CU_ASSERT(finished->stream_state_send == XQC_SEND_STREAM_ST_DATA_RECVD);
    CU_ASSERT(xqc_reset_test_packet_count(conn, XQC_FRAME_BIT_RESET_STREAM)
              == reset_count);

    xqc_stream_t *empty = xqc_stream_create_with_direction(conn,
        XQC_STREAM_UNI, NULL);
    CU_ASSERT_FATAL(empty != NULL);
    CU_ASSERT(xqc_stream_set_reliable_size(empty, 0) == XQC_OK);
    CU_ASSERT(xqc_stream_reset(empty, 9) == XQC_OK);
    CU_ASSERT(empty->reset_at.send_state == XQC_RESET_AT_READY);
    CU_ASSERT(empty->stream_state_send == XQC_SEND_STREAM_ST_RESET_SENT);
    CU_ASSERT(xqc_stream_reset(empty, 9) == XQC_OK);
    CU_ASSERT(xqc_stream_reset(empty, 10) == -XQC_ESTATE);
    CU_ASSERT(xqc_reset_test_packet_count(conn, XQC_FRAME_BIT_RESET_STREAM_AT)
        == 1);
    xqc_packet_out_t *reset = xqc_reset_test_queued_packet(empty,
        XQC_FRAME_BIT_RESET_STREAM, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(reset);
    xqc_reset_test_packet_sent(conn, reset, 1);
    xqc_send_ctl_on_packet_acked(conn->conn_initial_path->path_send_ctl,
        reset, xqc_monotonic_timestamp(), 0);
    CU_ASSERT(empty->stream_state_send == XQC_SEND_STREAM_ST_RESET_RECVD);

    xqc_stream_t *lower_zero = xqc_stream_create_with_direction(conn,
        XQC_STREAM_UNI, NULL);
    CU_ASSERT_FATAL(lower_zero != NULL);
    lower_zero->stream_flag |= XQC_STREAM_FLAG_HAS_H3;
    CU_ASSERT(xqc_stream_set_reliable_size(lower_zero, 1) == XQC_OK);
    CU_ASSERT(xqc_stream_send(lower_zero, (unsigned char *)"a", 1, 0) == 1);
    CU_ASSERT(xqc_stream_reset(lower_zero, 11) == XQC_OK);
    CU_ASSERT(xqc_stream_set_reliable_size(lower_zero, 0) == XQC_OK);
    CU_ASSERT(lower_zero->reset_at.send_update_pending);
    CU_ASSERT(xqc_stream_reset(lower_zero, 11) == XQC_OK);
    CU_ASSERT(lower_zero->reset_at.send_state == XQC_RESET_AT_NONE);
    CU_ASSERT(lower_zero->stream_state_send == XQC_SEND_STREAM_ST_RESET_SENT);
    CU_ASSERT_PTR_NOT_NULL(xqc_reset_test_queued_packet(lower_zero,
        XQC_FRAME_BIT_RESET_STREAM, 0));

    unsigned char buf[64];
    xqc_packet_out_t packet;
    memset(&packet, 0, sizeof(packet));
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

void
xqc_test_reliable_reset_close(void)
{
    for (int data_read = 0; data_read < 2; data_read++) {
        xqc_connection_t *conn = xqc_reset_test_conn();
        CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
        xqc_stream_t *stream = xqc_stream_create_with_direction(conn,
            XQC_STREAM_BIDI, NULL);
        CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
        stream->stream_flag |= XQC_STREAM_FLAG_HAS_H3;
        xqc_stream_send_state_update(stream, XQC_SEND_STREAM_ST_DATA_RECVD);
        if (data_read) {
            xqc_stream_recv_state_update(stream,
                XQC_RECV_STREAM_ST_DATA_READ);
        }
        CU_ASSERT(xqc_stream_close_with_error(stream, 270) == XQC_OK);
        CU_ASSERT(stream->stream_err == 270);
        CU_ASSERT(stream->stream_state_send == XQC_SEND_STREAM_ST_DATA_RECVD);
        CU_ASSERT(conn->conn_err == 0);
        CU_ASSERT(xqc_reset_test_packet_count(conn,
            XQC_FRAME_BIT_RESET_STREAM) == 0);
        CU_ASSERT(!!(stream->stream_flag & XQC_STREAM_FLAG_STOP_SENDING_SENT)
            == !data_read);
        xqc_engine_destroy(conn->engine);
    }

    /* -09 Section 5.2: closing the receiver cannot change the send error. */
    for (int completed = 0; completed < 2; completed++) {
        xqc_connection_t *conn = xqc_reset_test_conn();
        CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
        xqc_stream_t *stream = xqc_stream_create_with_direction(conn,
            XQC_STREAM_BIDI, NULL);
        CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
        stream->stream_flag |= XQC_STREAM_FLAG_HAS_H3;
        CU_ASSERT(xqc_stream_set_reliable_size(stream, 3) == XQC_OK);
        CU_ASSERT(xqc_stream_send(stream, (unsigned char *)"abc", 3, 0) == 3);
        CU_ASSERT(xqc_stream_reset(stream, 9) == XQC_OK);
        if (completed) {
            CU_ASSERT(xqc_stream_on_data_acked(stream, 0, 3) == XQC_OK);
            xqc_stream_on_reset_at_acked(stream, 3);
        }
        CU_ASSERT(xqc_stream_reset(stream, 10) == -XQC_ESTATE);
        CU_ASSERT(xqc_stream_close(stream) == XQC_OK);
        CU_ASSERT(conn->conn_err == 0);
        CU_ASSERT(stream->reset_at.send_error == 9);
        CU_ASSERT(stream->stream_err == 9);
        CU_ASSERT(stream->reset_at.send_final_size == 3);
        CU_ASSERT(stream->stream_flag & XQC_STREAM_FLAG_STOP_SENDING_SENT);
        CU_ASSERT(stream->stream_state_send == (completed
            ? XQC_SEND_STREAM_ST_DATA_RECVD : XQC_SEND_STREAM_ST_DATA_SENT));
        xqc_engine_destroy(conn->engine);
    }
}

void
xqc_test_reliable_reset_late_ack(void)
{
    /* -09 Section 5.3: loss does not invalidate a later control ACK. */
    for (int lowered = 0; lowered < 2; lowered++) {
        xqc_connection_t *conn = xqc_reset_test_conn();
        CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
        xqc_stream_t *stream = xqc_stream_create_with_direction(conn,
            XQC_STREAM_UNI, NULL);
        CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
        stream->stream_flag |= XQC_STREAM_FLAG_HAS_H3;
        CU_ASSERT(xqc_stream_set_reliable_size(stream, 3) == XQC_OK);
        CU_ASSERT(xqc_stream_send(stream, (unsigned char *)"abc", 3, 0) == 3);
        xqc_packet_out_t *data = xqc_reset_test_queued_packet(stream,
            XQC_FRAME_BIT_STREAM, 0);
        CU_ASSERT_PTR_NOT_NULL_FATAL(data);
        CU_ASSERT(xqc_stream_reset(stream, 9) == XQC_OK);
        xqc_packet_out_t *reset = xqc_reset_test_queued_reset_at(stream, 3);
        CU_ASSERT_PTR_NOT_NULL_FATAL(reset);
        xqc_send_ctl_t *ctl = conn->conn_initial_path->path_send_ctl;
        xqc_reset_test_packet_sent(conn, data, 1);
        xqc_send_ctl_on_packet_acked(ctl, data, xqc_monotonic_timestamp(), 0);
        xqc_reset_test_packet_sent(conn, reset, 2);
        xqc_send_ctl_decrease_inflight(conn, reset);
        xqc_send_queue_copy_to_lost(reset, conn->conn_send_queue, XQC_TRUE);
        if (lowered) {
            CU_ASSERT(xqc_stream_set_reliable_size(stream, 2) == XQC_OK);
            CU_ASSERT(xqc_stream_reset(stream, 9) == XQC_OK);
        }
        CU_ASSERT(!(reset->po_flag & XQC_POF_IN_FLIGHT));
        xqc_send_ctl_on_packet_acked(ctl, reset, xqc_monotonic_timestamp(), 0);
        CU_ASSERT(stream->reset_at.send_reset_acked == !lowered);
        CU_ASSERT(stream->stream_state_send == (lowered
            ? XQC_SEND_STREAM_ST_DATA_SENT : XQC_SEND_STREAM_ST_DATA_RECVD));
        xqc_list_head_t *lost = &conn->conn_send_queue->sndq_lost_packets;
        if (!lowered) {
            CU_ASSERT(!xqc_list_empty(lost));
            xqc_packet_out_t *copy = xqc_list_entry(lost->next,
                xqc_packet_out_t, po_list);
            CU_ASSERT(xqc_send_ctl_indirectly_ack_or_drop_po(conn, copy));
            CU_ASSERT(stream->reset_at.send_reset_acked);
        } else {
            reset = xqc_reset_test_queued_reset_at(stream, 2);
            CU_ASSERT_PTR_NOT_NULL_FATAL(reset);
            xqc_reset_test_packet_sent(conn, reset, 3);
            xqc_send_ctl_on_packet_acked(ctl, reset,
                xqc_monotonic_timestamp(), 0);
            CU_ASSERT(stream->stream_state_send
                == XQC_SEND_STREAM_ST_DATA_RECVD);
        }
        xqc_engine_destroy(conn->engine);
    }
}

void
xqc_test_reliable_reset_retry(void)
{
    /* -09 Sections 5 and 5.3: Retry preserves prefix data and its ACKs. */
    for (int retry = 0; retry < 2; retry++) {
        for (int ack_first = 0; ack_first < 2; ack_first++) {
            xqc_connection_t *conn = xqc_reset_test_conn();
            CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
            conn->conn_flag &= ~(XQC_CONN_FLAG_CAN_SEND_1RTT
                                | XQC_CONN_FLAG_TLS_HSK_COMPLETED);
            xqc_stream_t *stream = xqc_stream_create_with_direction(conn,
                XQC_STREAM_UNI, NULL);
            CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
            stream->stream_flag |= XQC_STREAM_FLAG_HAS_H3;
            size_t written = 0;
            CU_ASSERT(xqc_write_stream_frame_to_packet(conn, stream,
                XQC_PTYPE_0RTT, 0, (unsigned char *)"abc", 3, &written)
                == XQC_OK);
            CU_ASSERT(written == 3);
            if (retry) {
                xqc_cid_t scid = conn->conn_initial_path->path_dcid;
                scid.cid_buf[0] ^= 1;
                CU_ASSERT(xqc_conn_on_recv_retry(conn, &scid) == XQC_OK);
            }
            xqc_packet_out_t *data = xqc_reset_test_queued_packet(stream,
                XQC_FRAME_BIT_STREAM, 0);
            CU_ASSERT_PTR_NOT_NULL_FATAL(data);
            CU_ASSERT(data->po_stream_frames_idx == 1);
            CU_ASSERT(data->po_stream_frames[0].ps_length == 3);
            conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT
                              | XQC_CONN_FLAG_TLS_HSK_COMPLETED;
            xqc_send_ctl_t *ctl = conn->conn_initial_path->path_send_ctl;
            if (ack_first) {
                xqc_reset_test_packet_sent(conn, data, 1);
                xqc_send_ctl_on_packet_acked(ctl, data,
                    xqc_monotonic_timestamp(), 0);
                CU_ASSERT(stream->stream_acked_offset == 3);
            }
            CU_ASSERT(xqc_stream_set_reliable_size(stream, 3) == XQC_OK);
            CU_ASSERT(xqc_stream_reset(stream, 9) == XQC_OK);
            CU_ASSERT(stream->stream_state_send
                == XQC_SEND_STREAM_ST_DATA_SENT);
            if (!ack_first) {
                CU_ASSERT(xqc_reset_test_queued_packet(stream,
                    XQC_FRAME_BIT_STREAM, 0) == data);
            }
            xqc_packet_out_t *reset = xqc_reset_test_queued_reset_at(stream, 3);
            CU_ASSERT_PTR_NOT_NULL_FATAL(reset);
            xqc_reset_test_packet_sent(conn, reset, 2);
            xqc_send_ctl_on_packet_acked(ctl, reset,
                xqc_monotonic_timestamp(), 0);
            if (!ack_first) {
                CU_ASSERT(stream->stream_state_send
                    == XQC_SEND_STREAM_ST_DATA_SENT);
                xqc_reset_test_packet_sent(conn, data, 3);
                xqc_send_ctl_on_packet_acked(ctl, data,
                    xqc_monotonic_timestamp(), 0);
            }
            CU_ASSERT(stream->stream_acked_offset == 3);
            CU_ASSERT(stream->stream_state_send
                == XQC_SEND_STREAM_ST_DATA_RECVD);
            CU_ASSERT(conn->conn_err == 0);
            xqc_engine_destroy(conn->engine);
        }
    }
}

void
xqc_test_reliable_reset_zero_validation(void)
{
    /* -09 Section 5.2 covers duplicate ordinary resets as well as AT(0). */
    for (int scenario = 0; scenario < 9; scenario++) {
        int enabled = scenario >= 3;
        int first_at = scenario >= 3 && scenario < 6;
        int changed = scenario % 3;
        xqc_connection_t *conn = xqc_reset_test_conn();
        CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
        conn->local_settings.reset_stream_at = enabled;
        unsigned char reset_at[] = {0x24, 3, 9, 5, 0};
        unsigned char reset[] = {0x04, 3, 9, 5};
        /* Without the extension, keep ordinary duplicate-reset behavior. */
        CU_ASSERT(xqc_reset_test_input(conn, first_at ? reset_at : reset,
            first_at ? sizeof(reset_at) : sizeof(reset))
            == XQC_OK);
        xqc_stream_t *stream = xqc_find_stream_by_id(3, conn->streams_hash);
        CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
        CU_ASSERT(stream->reset_at.recv_state == XQC_RESET_AT_RECV_NONE);
        CU_ASSERT(conn->conn_flow_ctl.fc_data_recved == 5);
        xqc_reset_test_notifications_t notifications = {0};
        xqc_stream_callbacks_t callbacks = {
            .stream_closing_notify = xqc_reset_test_closing_notify,
        };
        stream->stream_if = &callbacks;
        stream->user_data = &notifications;
        if (changed) {
            reset[changed == 1 ? 2 : 3]++;
        }
        CU_ASSERT(xqc_reset_test_input(conn, reset, sizeof(reset))
            == (enabled && changed ? -XQC_EPROTO : XQC_OK));
        CU_ASSERT(conn->conn_err == (!enabled ? 0
            : changed == 1 ? TRA_STREAM_STATE_ERROR
            : changed == 2 ? TRA_FINAL_SIZE_ERROR : 0));
        CU_ASSERT(conn->conn_flow_ctl.fc_data_recved == 5);
        CU_ASSERT(conn->conn_flow_ctl.fc_data_read == 5);
        CU_ASSERT(notifications.closing_count == !(enabled && changed));
        if (enabled) {
            CU_ASSERT(stream->reset_at.recv_error == 9);
            CU_ASSERT(stream->stream_err == 9);
        }
        xqc_engine_destroy(conn->engine);
    }
}

void
xqc_test_reliable_reset_direction_error(void)
{
    /* RFC 9000 Section 2.4: opposite directions have independent errors. */
    for (int ordinary = 0; ordinary < 2; ordinary++) {
        for (int receive_first = 0; receive_first < 2; receive_first++) {
            xqc_connection_t *conn = xqc_reset_test_conn();
            CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
            xqc_stream_t *stream = xqc_stream_create_with_direction(conn,
                XQC_STREAM_BIDI, NULL);
            CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
            stream->stream_flag |= XQC_STREAM_FLAG_HAS_H3;
            CU_ASSERT(xqc_stream_set_reliable_size(stream, 1) == XQC_OK);
            CU_ASSERT(xqc_stream_send(stream, (unsigned char *)"a", 1, 0)
                == 1);
            CU_ASSERT(xqc_stream_reset(stream, 17) == XQC_OK);
            unsigned char peer[] = {0x24, stream->stream_id, 9, 0, 0};
            unsigned char first[] = {0x04, stream->stream_id, 9, 0};
            if (receive_first) {
                CU_ASSERT(xqc_reset_test_input(conn,
                    ordinary ? first : peer,
                    ordinary ? sizeof(first) : sizeof(peer)) == XQC_OK);
            }
            CU_ASSERT(xqc_stream_set_reliable_size(stream, 0) == XQC_OK);
            CU_ASSERT(xqc_stream_reset(stream, 17) == XQC_OK);
            if (!receive_first) {
                CU_ASSERT(xqc_reset_test_input(conn,
                    ordinary ? first : peer,
                    ordinary ? sizeof(first) : sizeof(peer)) == XQC_OK);
            }
            CU_ASSERT(xqc_reset_test_input(conn, peer, sizeof(peer))
                == XQC_OK);
            CU_ASSERT(conn->conn_err == 0);
            CU_ASSERT(stream->reset_at.send_error == 17);
            CU_ASSERT(stream->reset_at.recv_error == 9);
            /* -09 Section 5.2 still rejects a changed peer error. */
            peer[2] = 10;
            CU_ASSERT(xqc_reset_test_input(conn, peer, sizeof(peer))
                == -XQC_EPROTO);
            CU_ASSERT(conn->conn_err == TRA_STREAM_STATE_ERROR);
            xqc_engine_destroy(conn->engine);
        }
    }
}

void
xqc_test_reliable_reset_peer_reset_send(void)
{
    /* -09 Sections 3/5.2: receive capability cannot alter a sent reset. */
    for (int local = 0; local < 2; local++) {
        for (int acked = 0; acked < 2; acked++) {
            xqc_connection_t *conn = xqc_reset_test_conn();
            CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
            conn->local_settings.reset_stream_at = local;
            xqc_stream_t *stream = xqc_stream_create_with_direction(conn,
                XQC_STREAM_BIDI, NULL);
            CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
            stream->stream_flag |= XQC_STREAM_FLAG_HAS_H3;
            CU_ASSERT(xqc_stream_set_reliable_size(stream, 3) == XQC_OK);
            CU_ASSERT(xqc_stream_send(stream, (unsigned char *)"abc", 3, 0)
                == 3);
            CU_ASSERT(xqc_stream_reset(stream, 17) == XQC_OK);
            if (acked) {
                CU_ASSERT(xqc_stream_on_data_acked(stream, 0, 3) == XQC_OK);
                xqc_stream_on_reset_at_acked(stream, 3);
            }
            xqc_send_stream_state_t send_state = stream->stream_state_send;
            unsigned char reset[] = {0x04, stream->stream_id, 9, 0};
            CU_ASSERT(xqc_reset_test_input(conn, reset, sizeof(reset))
                == XQC_OK);
            CU_ASSERT(conn->conn_err == 0);
            CU_ASSERT(stream->stream_state_send == send_state);
            CU_ASSERT(stream->reset_at.send_error == 17);
            CU_ASSERT(stream->reset_at.send_final_size == 3);
            CU_ASSERT(stream->reset_at.send_size == 3);
            CU_ASSERT(xqc_reset_test_packet_count(conn,
                XQC_FRAME_BIT_RESET_STREAM) == 0);
            if (!acked) {
                CU_ASSERT_PTR_NOT_NULL(xqc_reset_test_queued_packet(stream,
                    XQC_FRAME_BIT_STREAM, 0));
            }
            CU_ASSERT(xqc_stream_reset(stream, 18) == -XQC_ESTATE);
            CU_ASSERT(xqc_stream_send(stream, (unsigned char *)"x", 1, 0)
                == -XQC_ESTREAM_RESET);
            xqc_engine_destroy(conn->engine);
        }
    }
}

void
xqc_test_reliable_reset_peer_reset_terminal(void)
{
    /* RFC 9000 Section 3.2: Data Read is terminal, Data Recvd is not. */
    for (int local = 0; local < 2; local++) {
        for (int consumed = 0; consumed < 2; consumed++) {
            xqc_connection_t *conn = xqc_reset_test_conn();
            CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
            conn->local_settings.reset_stream_at = local;
            xqc_reset_test_notifications_t notifications = {0};
            xqc_stream_callbacks_t callbacks = {
                .stream_closing_notify = xqc_reset_test_closing_notify,
            };
            xqc_stream_t *stream = xqc_stream_create_with_direction(conn,
                XQC_STREAM_BIDI, &notifications);
            CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
            stream->stream_if = &callbacks;
            unsigned char data[] = {
                0x0f, stream->stream_id, 0, 3, 'a', 'b', 'c',
            };
            unsigned char buf[8], fin;
            CU_ASSERT(xqc_reset_test_input(conn, data, sizeof(data))
                == XQC_OK);
            if (consumed) {
                CU_ASSERT(xqc_stream_recv(stream, buf, sizeof(buf), &fin)
                    == 3);
                CU_ASSERT(fin == 1);
            }
            unsigned char reset[] = {0x04, stream->stream_id, 9, 3};
            CU_ASSERT(xqc_reset_test_input(conn, reset, sizeof(reset))
                == XQC_OK);
            CU_ASSERT(stream->stream_state_recv == (consumed
                ? XQC_RECV_STREAM_ST_DATA_READ
                : XQC_RECV_STREAM_ST_RESET_RECVD));
            CU_ASSERT(notifications.closing_count == !consumed);
            CU_ASSERT(!!(stream->stream_flag & XQC_STREAM_FLAG_READY_TO_READ)
                == !consumed);
            CU_ASSERT(conn->conn_flow_ctl.fc_data_recved == 3);
            CU_ASSERT(conn->conn_flow_ctl.fc_data_read == 3);
            CU_ASSERT(xqc_stream_recv(stream, buf, sizeof(buf), &fin)
                == (consumed ? 0 : -XQC_ESTREAM_RESET));
            CU_ASSERT(fin == consumed);
            xqc_engine_destroy(conn->engine);
        }
    }
}

void
xqc_test_reliable_reset_peer_reset_pending(void)
{
    /* An implicit reverse reset must finish before the closing callback. */
    for (int sent = 0; sent < 2; sent++) {
        for (int write_error = 0; write_error < 2; write_error++) {
            xqc_connection_t *conn = xqc_reset_test_conn();
            CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
            xqc_reset_test_notifications_t notifications = {
                .reenter_write = XQC_TRUE,
            };
            xqc_stream_callbacks_t callbacks = {
                .stream_closing_notify = xqc_reset_test_closing_notify,
            };
            xqc_stream_t *stream = xqc_stream_create_with_direction(conn,
                XQC_STREAM_BIDI, &notifications);
            CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
            stream->stream_if = &callbacks;
            stream->stream_flag |= XQC_STREAM_FLAG_HAS_H3;
            CU_ASSERT(xqc_stream_set_reliable_size(stream, 3) == XQC_OK);
            if (sent) {
                CU_ASSERT(xqc_stream_send(stream, (unsigned char *)"abc",
                    3, 0) == 3);
            }
            unsigned pkt_out_size = conn->pkt_out_size;
            if (write_error) {
                /* Fail packet header construction without allocating less. */
                conn->pkt_out_size = 0;
            }
            unsigned char reset[] = {0x04, stream->stream_id, 9, 0};
            CU_ASSERT(xqc_reset_test_input(conn, reset, sizeof(reset))
                == (write_error ? -XQC_EWRITE_PKT : XQC_OK));
            conn->pkt_out_size = pkt_out_size;
            CU_ASSERT(notifications.closing_count == !write_error);
            if (write_error) {
                CU_ASSERT(stream->stream_state_recv
                    == XQC_RECV_STREAM_ST_RECV);
                CU_ASSERT(xqc_reset_test_input(conn, reset, sizeof(reset))
                    == XQC_OK);
            }
            CU_ASSERT(notifications.reenter_result == -XQC_ESTREAM_RESET);
            CU_ASSERT(notifications.reenter_fin_result == -XQC_ESTREAM_RESET);
            CU_ASSERT(!(stream->stream_flag & XQC_STREAM_FLAG_READY_TO_WRITE));
            CU_ASSERT(stream->stream_send_offset == (sent ? 3 : 0));
            CU_ASSERT(xqc_reset_test_packet_count(conn, sent
                ? XQC_FRAME_BIT_RESET_STREAM_AT : XQC_FRAME_BIT_RESET_STREAM)
                == 1);
            CU_ASSERT(conn->conn_err == 0);
            xqc_engine_destroy(conn->engine);
        }
    }
}

void
xqc_test_reliable_reset_zero_fin(void)
{
    /* reliable-stream-reset-09 Section 5.2 includes subsequent STREAM FIN. */
    for (int ordinary = 0; ordinary < 2; ordinary++) {
        for (int end = 7; end <= 9; end++) {
            xqc_connection_t *conn = xqc_reset_test_conn();
            CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
            unsigned char reset[] = {0x24, 3, 9, 8, 0};
            unsigned char first[] = {0x04, 3, 9, 8};
            unsigned char fin[] = {0x0f, 3, end, 0};
            if (ordinary) {
                CU_ASSERT(xqc_reset_test_input(conn, first, sizeof(first))
                    == XQC_OK);
                reset[4] = 3;
            }
            CU_ASSERT(xqc_reset_test_input(conn, reset, sizeof(reset))
                == XQC_OK);
            CU_ASSERT(xqc_reset_test_input(conn, fin, sizeof(fin))
                == (end == 8 ? XQC_OK : -XQC_EPROTO));
            CU_ASSERT(conn->conn_err
                == (end == 8 ? 0 : TRA_FINAL_SIZE_ERROR));
            xqc_engine_destroy(conn->engine);
        }
    }
    /* Without extension provenance, retain the legacy ordinary path. */
    xqc_connection_t *conn = xqc_reset_test_conn();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    conn->local_settings.reset_stream_at = XQC_FALSE;
    unsigned char frames[] = {0x04, 3, 9, 8, 0x0f, 3, 9, 0};
    CU_ASSERT(xqc_reset_test_input(conn, frames, sizeof(frames)) == XQC_OK);
    CU_ASSERT(conn->conn_err == 0);
    xqc_engine_destroy(conn->engine);
}

void
xqc_test_reliable_reset_zero_close(void)
{
    /* Public close terminates both directions, even after a send reset. */
    for (int mode = 0; mode < 3; mode++) {
        xqc_connection_t *conn = xqc_reset_test_conn();
        CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
        xqc_stream_t *stream = xqc_stream_create_with_direction(conn,
            XQC_STREAM_BIDI, NULL);
        CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
        stream->stream_flag |= XQC_STREAM_FLAG_HAS_H3;
        if (mode != 0) {
            CU_ASSERT(xqc_stream_set_reliable_size(stream, mode == 2)
                == XQC_OK);
        }
        CU_ASSERT(xqc_stream_send(stream, (unsigned char *)"a", 1, 0) == 1);
        CU_ASSERT(xqc_stream_reset(stream, 9) == XQC_OK);
        if (mode == 2) {
            CU_ASSERT(xqc_stream_set_reliable_size(stream, 0) == XQC_OK);
            CU_ASSERT(xqc_stream_reset(stream, 9) == XQC_OK);
        }
        CU_ASSERT(xqc_stream_reset(stream, 10) == -XQC_ESTATE);
        CU_ASSERT(xqc_stream_close(stream) == XQC_OK);
        CU_ASSERT(stream->stream_flag & XQC_STREAM_FLAG_STOP_SENDING_SENT);
        CU_ASSERT(stream->reset_at.send_error == 9);
        unsigned stops = xqc_reset_test_packet_count(conn,
            XQC_FRAME_BIT_STOP_SENDING);
        CU_ASSERT(stops == 1);
        CU_ASSERT(xqc_stream_close(stream) == XQC_OK);
        CU_ASSERT(xqc_reset_test_packet_count(conn,
            XQC_FRAME_BIT_STOP_SENDING) == stops);
        CU_ASSERT(conn->conn_err == 0);
        xqc_engine_destroy(conn->engine);
    }
}
