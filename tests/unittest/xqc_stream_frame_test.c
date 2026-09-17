/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_stream_frame_test.h"
#include <CUnit/CUnit.h>
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_defs.h"
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_send_queue.h"
#include "xqc_common_test.h"

void
xqc_test_stream_frame()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    xqc_stream_t *stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    CU_ASSERT(stream != NULL);

    char payload[100];
    xqc_stream_frame_t *frame[10];
    memset(frame, 0, sizeof(frame));

    for (int i = 0; i < 10; i++) {
        frame[i] = xqc_malloc(sizeof(xqc_stream_frame_t));
        memset(frame[i], 0, sizeof(*frame[i]));
        frame[i]->data_length = 10;
        frame[i]->data_offset = i * 10;
        memset(payload + i * 10, i, 10);
        frame[i]->data = xqc_malloc(10);
        memcpy(frame[i]->data, payload + i * 10, 10);
    }

    ret = xqc_insert_stream_frame(conn, stream, frame[1]);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_data_in.merged_offset_end == 0);

    ret = xqc_insert_stream_frame(conn, stream, frame[2]);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_data_in.merged_offset_end == 0);

    ret = xqc_insert_stream_frame(conn, stream, frame[0]);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_data_in.merged_offset_end == 30);

    ret = xqc_insert_stream_frame(conn, stream, frame[3]);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_data_in.merged_offset_end == 40);

    xqc_list_head_t *pos;
    xqc_stream_frame_t *pframe;
    uint64_t offset = 0;
    xqc_list_for_each(pos, &stream->stream_data_in.frames_tailq) {
        pframe = xqc_list_entry(pos, xqc_stream_frame_t, sf_list);
        CU_ASSERT(pframe->data_offset == offset);
        offset += 10;
    }

    char recv_buf[16];
    unsigned recv_buf_size = 16;
    unsigned char fin;
    offset = 0;
    do {
        ret = xqc_stream_recv(stream, recv_buf, recv_buf_size, &fin);
        CU_ASSERT(ret >= 0 || ret == -XQC_EAGAIN);
        if (ret > 0) {
            CU_ASSERT(memcmp(payload + offset, recv_buf, ret) == 0);
        }
        offset += ret;
    } while (ret > 0);

    for (int i = 4; i < 10; i++) {
        xqc_destroy_stream_frame(frame[i]);
    }

    xqc_engine_destroy(conn->engine);
}


/**
 * Test buffered_frame_count limit (CWE-770 mitigation for stream fragmentation attack)
 */
void
xqc_test_stream_frame_buffered_limit()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);
    if (conn == NULL) return;

    xqc_stream_t *stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    CU_ASSERT(stream != NULL);
    if (stream == NULL) { xqc_engine_destroy(conn->engine); return; }

    xqc_stream_frame_t *frame1 = xqc_malloc(sizeof(xqc_stream_frame_t));
    memset(frame1, 0, sizeof(*frame1));
    frame1->data_length = 1;
    frame1->data_offset = 99999;  /* out-of-order offset */
    frame1->data = xqc_malloc(1);
    frame1->data[0] = 'A';

    /* Simulate count at limit: should reject */
    stream->stream_data_in.buffered_frame_count = XQC_MAX_STREAM_FRAME_BUFFERED_COUNT;
    ret = xqc_insert_stream_frame(conn, stream, frame1);
    CU_ASSERT(ret == -XQC_ELIMIT);

    /* Simulate count at limit - 1: should accept */
    stream->stream_data_in.buffered_frame_count = XQC_MAX_STREAM_FRAME_BUFFERED_COUNT - 1;
    ret = xqc_insert_stream_frame(conn, stream, frame1);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_data_in.buffered_frame_count == XQC_MAX_STREAM_FRAME_BUFFERED_COUNT);

    /* Next insert should be rejected (count == limit now) */
    xqc_stream_frame_t *frame2 = xqc_malloc(sizeof(xqc_stream_frame_t));
    memset(frame2, 0, sizeof(*frame2));
    frame2->data_length = 1;
    frame2->data_offset = 199999;
    frame2->data = xqc_malloc(1);
    frame2->data[0] = 'B';

    ret = xqc_insert_stream_frame(conn, stream, frame2);
    CU_ASSERT(ret == -XQC_ELIMIT);

    /* cleanup: frame2 was rejected so we free it manually */
    xqc_free(frame2->data);
    xqc_free(frame2);

    xqc_engine_destroy(conn->engine);
}


/* Count packets carrying a STREAM frame for stream_id. */
static int
test_ss_count_stream_packets(xqc_connection_t *conn, xqc_stream_id_t sid)
{
    xqc_send_queue_t *sq = conn->conn_send_queue;
    xqc_list_head_t  *queues[4];
    xqc_list_head_t  *pos, *next;
    xqc_packet_out_t *po;
    int               n = 0;
    int               q, i;

    queues[0] = &sq->sndq_send_packets;
    queues[1] = &sq->sndq_unacked_packets[XQC_PNS_APP_DATA];
    queues[2] = &sq->sndq_lost_packets;
    queues[3] = &sq->sndq_pto_probe_packets;

    for (q = 0; q < 4; q++) {
        xqc_list_for_each_safe(pos, next, queues[q]) {
            po = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            if (!(po->po_frame_types & XQC_FRAME_BIT_STREAM)) {
                continue;
            }
            for (i = 0; i < XQC_MAX_STREAM_FRAME_IN_PO; i++) {
                if (po->po_stream_frames[i].ps_is_used == 0) {
                    break;
                }
                if (po->po_stream_frames[i].ps_stream_id == sid
                    && !po->po_stream_frames[i].ps_is_reset)
                {
                    n++;
                    break;
                }
            }
        }
    }

    return n;
}

/* Count packets carrying a RESET_STREAM frame for stream_id. */
static int
test_ss_count_reset_packets(xqc_connection_t *conn, xqc_stream_id_t sid)
{
    xqc_send_queue_t *sq = conn->conn_send_queue;
    xqc_list_head_t  *queues[4];
    xqc_list_head_t  *pos, *next;
    xqc_packet_out_t *po;
    int               n = 0;
    int               q, i;

    queues[0] = &sq->sndq_send_packets;
    queues[1] = &sq->sndq_unacked_packets[XQC_PNS_APP_DATA];
    queues[2] = &sq->sndq_lost_packets;
    queues[3] = &sq->sndq_pto_probe_packets;

    for (q = 0; q < 4; q++) {
        xqc_list_for_each_safe(pos, next, queues[q]) {
            po = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            if (!(po->po_frame_types & XQC_FRAME_BIT_RESET_STREAM)) {
                continue;
            }
            for (i = 0; i < XQC_MAX_STREAM_FRAME_IN_PO; i++) {
                if (po->po_stream_frames[i].ps_is_used == 0) {
                    break;
                }
                if (po->po_stream_frames[i].ps_stream_id == sid
                    && po->po_stream_frames[i].ps_is_reset)
                {
                    n++;
                    break;
                }
            }
        }
    }

    return n;
}

/* Build one STOP_SENDING frame: type 0x05, stream id, error code. */
static size_t
test_ss_put_stop_sending(unsigned char *out, uint64_t stream_id, uint64_t err)
{
    out[0] = 0x05;
    out[1] = (unsigned char) stream_id;
    out[2] = (unsigned char) err;
    return 3;
}

void
xqc_test_stop_sending_drops_queued_stream_packets()
{
    xqc_connection_t *conn = test_engine_connect();
    xqc_stream_t     *stream;
    xqc_packet_in_t   pi;
    unsigned char     frame[8];
    unsigned char     payload[1024];
    size_t            written = 0;
    int               queued_before, i, ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
    /* the frame below encodes the stream id as a one-byte varint */
    CU_ASSERT_FATAL(stream->stream_id < 64);

    /* enough credit that flow control is not what stops the writes */
    stream->stream_flow_ctl.fc_max_stream_data_can_send = 1024 * 1024;
    conn->conn_flow_ctl.fc_max_data_can_send = 8 * 1024 * 1024;
    /* without this the RESET_STREAM goes to sndq_buff_1rtt_packets */
    conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT;

    memset(payload, 'z', sizeof(payload));
    for (i = 0; i < 8; i++) {
        written = 0;
        ret = xqc_write_stream_frame_to_packet(conn, stream,
                                               XQC_PTYPE_SHORT_HEADER, 0,
                                               payload, sizeof(payload),
                                               &written);
        if (ret < 0) {
            break;
        }
    }

    queued_before = test_ss_count_stream_packets(conn, stream->stream_id);
    CU_ASSERT_FATAL(queued_before > 0);
    CU_ASSERT_EQUAL(test_ss_count_reset_packets(conn, stream->stream_id), 0);
    CU_ASSERT(stream->stream_state_send < XQC_SEND_STREAM_ST_RESET_SENT);

    /* the peer asks us to stop */
    memset(&pi, 0, sizeof(pi));
    pi.pos = frame;
    pi.last = frame + test_ss_put_stop_sending(frame, stream->stream_id, 0x02);

    CU_ASSERT_EQUAL(xqc_process_stop_sending_frame(conn, &pi), XQC_OK);

    /* RESET_STREAM is written */
    CU_ASSERT(test_ss_count_reset_packets(conn, stream->stream_id) > 0);

    /* and the queued STREAM packets for that stream are gone */
    CU_ASSERT_EQUAL(test_ss_count_stream_packets(conn, stream->stream_id), 0);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_stop_sending_spares_other_streams()
{
    xqc_connection_t *conn = test_engine_connect();
    xqc_stream_t     *victim, *bystander;
    xqc_packet_in_t   pi;
    unsigned char     frame[8];
    unsigned char     payload[1024];
    size_t            written = 0;
    int               bystander_before, i, ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    victim = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    bystander = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(victim);
    CU_ASSERT_PTR_NOT_NULL_FATAL(bystander);
    CU_ASSERT_FATAL(victim->stream_id < 64);

    victim->stream_flow_ctl.fc_max_stream_data_can_send = 1024 * 1024;
    bystander->stream_flow_ctl.fc_max_stream_data_can_send = 1024 * 1024;
    conn->conn_flow_ctl.fc_max_data_can_send = 8 * 1024 * 1024;
    conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT;

    memset(payload, 'z', sizeof(payload));
    for (i = 0; i < 6; i++) {
        written = 0;
        ret = xqc_write_stream_frame_to_packet(conn, victim,
                                               XQC_PTYPE_SHORT_HEADER, 0,
                                               payload, sizeof(payload),
                                               &written);
        if (ret < 0) {
            break;
        }
        written = 0;
        ret = xqc_write_stream_frame_to_packet(conn, bystander,
                                               XQC_PTYPE_SHORT_HEADER, 0,
                                               payload, sizeof(payload),
                                               &written);
        if (ret < 0) {
            break;
        }
    }

    bystander_before = test_ss_count_stream_packets(conn,
                                                    bystander->stream_id);
    CU_ASSERT_FATAL(bystander_before > 0);
    CU_ASSERT_FATAL(test_ss_count_stream_packets(conn, victim->stream_id) > 0);

    memset(&pi, 0, sizeof(pi));
    pi.pos = frame;
    pi.last = frame + test_ss_put_stop_sending(frame, victim->stream_id, 0x02);
    CU_ASSERT_EQUAL(xqc_process_stop_sending_frame(conn, &pi), XQC_OK);

    CU_ASSERT_EQUAL(test_ss_count_stream_packets(conn, victim->stream_id), 0);
    /* the bystander keeps every one of its packets */
    CU_ASSERT_EQUAL(test_ss_count_stream_packets(conn, bystander->stream_id),
                    bystander_before);

    xqc_engine_destroy(conn->engine);
}
