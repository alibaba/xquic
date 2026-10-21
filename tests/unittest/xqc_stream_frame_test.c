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
#include "src/transport/xqc_packet.h"
#include <xquic/xqc_errno.h>
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_send_queue.h"
#include "xqc_common_test.h"

static xqc_stream_frame_t *test_mk_frame(uint64_t offset, unsigned length);

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

    /* a frame beyond the hole never takes the reserved prefix slot */
    xqc_stream_frame_t *frame1 = test_mk_frame(99999, 1);

    /* count at limit: reject */
    stream->stream_data_in.buffered_frame_count = XQC_MAX_STREAM_FRAME_BUFFERED_COUNT;
    ret = xqc_insert_stream_frame(conn, stream, frame1);
    CU_ASSERT(ret == -XQC_ELIMIT);

    /* count at limit - 1: the last slot is reserved, reject */
    stream->stream_data_in.buffered_frame_count = XQC_MAX_STREAM_FRAME_BUFFERED_COUNT - 1;
    ret = xqc_insert_stream_frame(conn, stream, frame1);
    CU_ASSERT(ret == -XQC_ELIMIT);

    /* count at limit - 2: accept, count becomes limit - 1 */
    stream->stream_data_in.buffered_frame_count = XQC_MAX_STREAM_FRAME_BUFFERED_COUNT - 2;
    ret = xqc_insert_stream_frame(conn, stream, frame1);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_data_in.buffered_frame_count == XQC_MAX_STREAM_FRAME_BUFFERED_COUNT - 1);

    /* next beyond-hole insert is rejected again */
    xqc_stream_frame_t *frame2 = test_mk_frame(199999, 1);
    ret = xqc_insert_stream_frame(conn, stream, frame2);
    CU_ASSERT(ret == -XQC_ELIMIT);

    /* cleanup: frame2 was rejected so we free it manually */
    xqc_free(frame2->data);
    xqc_free(frame2);

    xqc_engine_destroy(conn->engine);
}


/* Allocate a STREAM frame node filled with 'x'. */
static xqc_stream_frame_t *
test_mk_frame(uint64_t offset, unsigned length)
{
    xqc_stream_frame_t *f = xqc_calloc(1, sizeof(xqc_stream_frame_t));
    f->data_offset = offset;
    f->data_length = length;
    f->data = xqc_malloc(length ? length : 1);
    memset(f->data, 'x', length);
    return f;
}

/* Free a frame that xqc_insert_stream_frame did not take ownership of. */
static void
test_free_rejected(xqc_stream_frame_t *f, xqc_int_t ret)
{
    if (ret != XQC_OK) {
        xqc_free(f->data);
        xqc_free(f);
    }
}

/* Run one wire-encoded STREAM frame through xqc_process_stream_frame. */
static xqc_int_t
test_process_stream_bytes(xqc_connection_t *conn, const unsigned char *buf,
    size_t len, xqc_pkt_type_t pkt_type)
{
    xqc_packet_in_t packet_in;
    memset(&packet_in, 0, sizeof(packet_in));
    packet_in.buf = buf;
    packet_in.buf_size = len;
    packet_in.pos = (unsigned char *)buf;
    packet_in.last = (unsigned char *)buf + len;
    packet_in.pi_pkt.pkt_type = pkt_type;
    return xqc_process_stream_frame(conn, &packet_in);
}

static xqc_stream_t *
test_stream_with_fc(xqc_connection_t *conn, uint64_t stream_fc, uint64_t conn_fc)
{
    xqc_stream_t *stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    if (stream == NULL) {
        return NULL;
    }
    stream->stream_flow_ctl.fc_max_stream_data_can_recv = stream_fc;
    conn->conn_flow_ctl.fc_max_data_can_recv = conn_fc;
    return stream;
}

/**
 * At the cap a frame that extends the contiguous prefix is still admitted
 * into the reserved slot, and the node count never exceeds the cap.
 */
void
xqc_test_stream_frame_cap_reserved_slot()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);
    if (conn == NULL) return;

    xqc_stream_t *stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    CU_ASSERT(stream != NULL);
    if (stream == NULL) { xqc_engine_destroy(conn->engine); return; }

    /* one real beyond-hole node at [20,30), hole at [0,20) */
    xqc_stream_frame_t *seed = test_mk_frame(20, 10);
    ret = xqc_insert_stream_frame(conn, stream, seed);
    CU_ASSERT(ret == XQC_OK);
    test_free_rejected(seed, ret);

    stream->stream_data_in.buffered_frame_count = XQC_MAX_STREAM_FRAME_BUFFERED_COUNT - 1;

    /* beyond-hole frame: rejected, the reserved slot is not for it */
    xqc_stream_frame_t *bh = test_mk_frame(100, 10);
    ret = xqc_insert_stream_frame(conn, stream, bh);
    CU_ASSERT(ret == -XQC_ELIMIT);
    test_free_rejected(bh, ret);

    /* prefix-extending frame [0,10): admitted into the reserved slot */
    xqc_stream_frame_t *pf = test_mk_frame(0, 10);
    ret = xqc_insert_stream_frame(conn, stream, pf);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_data_in.merged_offset_end == 10);
    CU_ASSERT(stream->stream_data_in.buffered_frame_count == XQC_MAX_STREAM_FRAME_BUFFERED_COUNT);
    test_free_rejected(pf, ret);

    /* at the hard bound even a prefix-extending frame waits for a drain */
    xqc_stream_frame_t *pf2 = test_mk_frame(10, 5);
    ret = xqc_insert_stream_frame(conn, stream, pf2);
    CU_ASSERT(ret == -XQC_ELIMIT);
    test_free_rejected(pf2, ret);

    /* one node drained: prefix admission resumes */
    stream->stream_data_in.buffered_frame_count = XQC_MAX_STREAM_FRAME_BUFFERED_COUNT - 1;
    xqc_stream_frame_t *pf3 = test_mk_frame(10, 5);
    ret = xqc_insert_stream_frame(conn, stream, pf3);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_data_in.merged_offset_end == 15);
    test_free_rejected(pf3, ret);

    xqc_engine_destroy(conn->engine);
}

/**
 * Retransmitted FIN-only frames of a stream whose final size is known must
 * not accumulate zero-length nodes; they consume no flow-control credit.
 */
void
xqc_test_stream_frame_fin_only_no_accumulation()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);
    if (conn == NULL) return;

    xqc_stream_t *stream = test_stream_with_fc(conn, 1 << 20, 1 << 20);
    CU_ASSERT(stream != NULL);
    if (stream == NULL) { xqc_engine_destroy(conn->engine); return; }
    CU_ASSERT(stream->stream_id < 64); /* 1-byte varint below */

    /* STREAM frame, LEN|FIN, no OFF: offset 0, length 0, fin */
    unsigned char fin_only[3] = { 0x0b, (unsigned char)stream->stream_id, 0x00 };

    for (int i = 0; i < 5; i++) {
        ret = test_process_stream_bytes(conn, fin_only, sizeof(fin_only), XQC_PTYPE_SHORT_HEADER);
        CU_ASSERT(ret == XQC_OK);
    }

    CU_ASSERT(stream->stream_data_in.stream_determined == XQC_TRUE);
    CU_ASSERT(stream->stream_state_recv == XQC_RECV_STREAM_ST_DATA_RECVD);
    CU_ASSERT(stream->stream_data_in.buffered_frame_count == 1);

    xqc_engine_destroy(conn->engine);
}

/**
 * A beyond-hole frame rejected by the cap is a tolerant whole-packet drop
 * (-XQC_EIGNORE_PKT, packet never acknowledged) for a short header packet
 * and not a connection error. A long header packet keeps the error path.
 */
void
xqc_test_stream_frame_cap_tolerant_drop()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);
    if (conn == NULL) return;

    xqc_stream_t *stream = test_stream_with_fc(conn, 1 << 20, 1 << 20);
    CU_ASSERT(stream != NULL);
    if (stream == NULL) { xqc_engine_destroy(conn->engine); return; }
    CU_ASSERT(stream->stream_id < 64);

    stream->stream_data_in.buffered_frame_count = XQC_MAX_STREAM_FRAME_BUFFERED_COUNT;

    /* STREAM frame, OFF|LEN: offset 200 (beyond the hole), length 10 */
    unsigned char beyond[15] = { 0x0e, (unsigned char)stream->stream_id, 0x40, 0xc8, 0x0a,
                                 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x' };

    ret = test_process_stream_bytes(conn, beyond, sizeof(beyond), XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT(ret == -XQC_EIGNORE_PKT);
    CU_ASSERT(conn->conn_err == 0);
    CU_ASSERT(stream->stream_data_in.buffered_frame_count == XQC_MAX_STREAM_FRAME_BUFFERED_COUNT);
    CU_ASSERT(stream->stream_max_recv_offset == 0);

    ret = test_process_stream_bytes(conn, beyond, sizeof(beyond), XQC_PTYPE_0RTT);
    CU_ASSERT(ret == -XQC_ELIMIT);
    CU_ASSERT(conn->conn_err == 0);

    xqc_engine_destroy(conn->engine);
}

/**
 * Flow control is validated before the cap: a frame past the advertised
 * stream or connection limit is a FLOW_CONTROL_ERROR even while the
 * reassembly buffer is full, and is not masked by the tolerant drop.
 */
void
xqc_test_stream_frame_fc_before_cap()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);
    if (conn == NULL) return;

    xqc_stream_t *stream = test_stream_with_fc(conn, 100, 1 << 20);
    CU_ASSERT(stream != NULL);
    if (stream == NULL) { xqc_engine_destroy(conn->engine); return; }
    CU_ASSERT(stream->stream_id < 64);

    stream->stream_data_in.buffered_frame_count = XQC_MAX_STREAM_FRAME_BUFFERED_COUNT;

    /* STREAM frame, OFF|LEN: offset 96, length 10 -> end 106 > limit 100 */
    unsigned char violating[15] = { 0x0e, (unsigned char)stream->stream_id, 0x40, 0x60, 0x0a,
                                    'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x' };

    ret = test_process_stream_bytes(conn, violating, sizeof(violating), XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT(ret == -XQC_EPROTO);
    CU_ASSERT(conn->conn_err == TRA_FLOW_CONTROL_ERROR);

    /* connection-level limit is enforced the same way */
    conn->conn_err = 0;
    stream->stream_flow_ctl.fc_max_stream_data_can_recv = 1 << 20;
    conn->conn_flow_ctl.fc_max_data_can_recv = 100;

    ret = test_process_stream_bytes(conn, violating, sizeof(violating), XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT(ret == -XQC_EPROTO);
    CU_ASSERT(conn->conn_err == TRA_FLOW_CONTROL_ERROR);

    xqc_engine_destroy(conn->engine);
}

/**
 * A FIN whose packet is dropped at the cap leaves no final-size state
 * behind, so its retransmission is processed afresh and completes the
 * stream once a slot is free.
 */
void
xqc_test_stream_frame_fin_dropped_then_retransmitted()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);
    if (conn == NULL) return;

    xqc_stream_t *stream = test_stream_with_fc(conn, 1 << 20, 1 << 20);
    CU_ASSERT(stream != NULL);
    if (stream == NULL) { xqc_engine_destroy(conn->engine); return; }
    CU_ASSERT(stream->stream_id < 64);

    /* deliver [0,10): STREAM frame, LEN only */
    unsigned char data10[13] = { 0x0a, (unsigned char)stream->stream_id, 0x0a,
                                 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd' };
    ret = test_process_stream_bytes(conn, data10, sizeof(data10), XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_data_in.merged_offset_end == 10);

    /* FIN-only frame at offset 10 (OFF|LEN|FIN) while the buffer is full */
    stream->stream_data_in.buffered_frame_count = XQC_MAX_STREAM_FRAME_BUFFERED_COUNT;
    unsigned char fin_at_10[4] = { 0x0f, (unsigned char)stream->stream_id, 0x0a, 0x00 };
    ret = test_process_stream_bytes(conn, fin_at_10, sizeof(fin_at_10), XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT(ret == -XQC_EIGNORE_PKT);
    CU_ASSERT(stream->stream_data_in.stream_determined == XQC_FALSE);
    CU_ASSERT(stream->stream_state_recv == XQC_RECV_STREAM_ST_RECV);

    /* buffer drained; the peer retransmits the unacknowledged FIN */
    stream->stream_data_in.buffered_frame_count = 1;
    ret = test_process_stream_bytes(conn, fin_at_10, sizeof(fin_at_10), XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_data_in.stream_determined == XQC_TRUE);
    CU_ASSERT(stream->stream_state_recv == XQC_RECV_STREAM_ST_DATA_RECVD);

    char buf[64];
    unsigned char fin = 0;
    ret = xqc_stream_recv(stream, buf, sizeof(buf), &fin);
    CU_ASSERT(ret == 10);
    CU_ASSERT(fin == 1);

    xqc_engine_destroy(conn->engine);
}

/**
 * conn_settings.max_stream_frame_buffered_cnt overrides the built-in cap;
 * the reserved slot follows the override.
 */
void
xqc_test_stream_frame_cap_setting()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);
    if (conn == NULL) return;

    xqc_stream_t *stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    CU_ASSERT(stream != NULL);
    if (stream == NULL) { xqc_engine_destroy(conn->engine); return; }

    conn->conn_settings.max_stream_frame_buffered_cnt = 16;

    /* beyond-hole frames stop at cap - 1 = 15 */
    xqc_stream_frame_t *fa = test_mk_frame(1000, 1);
    stream->stream_data_in.buffered_frame_count = 15;
    ret = xqc_insert_stream_frame(conn, stream, fa);
    CU_ASSERT(ret == -XQC_ELIMIT);
    test_free_rejected(fa, ret);

    xqc_stream_frame_t *fb = test_mk_frame(1000, 1);
    stream->stream_data_in.buffered_frame_count = 14;
    ret = xqc_insert_stream_frame(conn, stream, fb);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_data_in.buffered_frame_count == 15);
    test_free_rejected(fb, ret);

    /* a prefix-extending frame may take the reserved slot up to the cap */
    xqc_stream_frame_t *pf = test_mk_frame(0, 10);
    ret = xqc_insert_stream_frame(conn, stream, pf);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_data_in.buffered_frame_count == 16);
    test_free_rejected(pf, ret);

    xqc_stream_frame_t *pf2 = test_mk_frame(10, 5);
    ret = xqc_insert_stream_frame(conn, stream, pf2);
    CU_ASSERT(ret == -XQC_ELIMIT);
    test_free_rejected(pf2, ret);

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
