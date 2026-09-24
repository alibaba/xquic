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
#include "src/common/utils/vint/xqc_variable_len_int.h"
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


/* the byte a test stream carries at `offset`, so a read-back proves order */
static unsigned char
test_sf_byte(uint64_t offset)
{
    return (unsigned char) (offset * 31 + 7);
}

static xqc_stream_frame_t *
test_sf_new(uint64_t offset, unsigned len)
{
    xqc_stream_frame_t *f = xqc_calloc(1, sizeof(xqc_stream_frame_t));
    unsigned            i;

    f->data_offset = offset;
    f->data_length = len;
    f->data = xqc_malloc(len);
    for (i = 0; i < len; i++) {
        f->data[i] = test_sf_byte(offset + i);
    }
    return f;
}

/* insert a new frame; the frame is freed here when the stream refuses it */
static xqc_int_t
test_sf_insert(xqc_connection_t *conn, xqc_stream_t *stream, uint64_t offset,
    unsigned len)
{
    xqc_stream_frame_t *f = test_sf_new(offset, len);
    xqc_int_t           ret = xqc_insert_stream_frame(conn, stream, f);

    if (ret != XQC_OK) {
        xqc_destroy_stream_frame(f);
    }
    return ret;
}

/* read everything readable; returns the byte count, or -1 on a mismatch */
static int64_t
test_sf_read_back(xqc_stream_t *stream, uint64_t from)
{
    unsigned char buf[4096];
    uint8_t       fin = 0;
    ssize_t       n, i;
    int64_t       total = 0;

    for ( ;; ) {
        n = xqc_stream_recv(stream, buf, sizeof(buf), &fin);
        if (n <= 0) {
            break;
        }
        for (i = 0; i < n; i++) {
            if (buf[i] != test_sf_byte(from + total + i)) {
                return -1;
            }
        }
        total += n;
    }
    return total;
}

static uint64_t
test_sf_max_node_len(xqc_stream_t *stream)
{
    xqc_list_head_t    *pos;
    xqc_stream_frame_t *f;
    uint64_t            max = 0;

    xqc_list_for_each(pos, &stream->stream_data_in.frames_tailq) {
        f = xqc_list_entry(pos, xqc_stream_frame_t, sf_list);
        max = xqc_max(max, f->data_length);
    }
    return max;
}


/*
 * A reader that takes nothing while the peer fills the credit it was given
 * in order: 20,000 frames, well past XQC_MAX_STREAM_FRAME_BUFFERED_COUNT,
 * are all accepted, the nodes stay a few past the coalescing threshold, and
 * every byte reads back in order.
 */
void
xqc_test_stream_frame_coalesce_contiguous()
{
    xqc_connection_t *conn = test_engine_connect();
    xqc_stream_t     *stream;
    const unsigned    len = 7;
    uint64_t          off = 0;
    int               i, ret, refused = 0;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);

    for (i = 0; i < 20000; i++) {
        ret = test_sf_insert(conn, stream, off, len);
        if (ret != XQC_OK) {
            refused++;
            break;
        }
        off += len;
    }

    CU_ASSERT_EQUAL(refused, 0);
    CU_ASSERT_EQUAL(stream->stream_data_in.merged_offset_end, off);
    CU_ASSERT(stream->stream_data_in.buffered_frame_count
              <= XQC_STREAM_FRAME_COALESCE_THRESHOLD
                 + off / XQC_STREAM_FRAME_COALESCE_MAX_LEN + 1);
    CU_ASSERT(test_sf_max_node_len(stream)
              <= XQC_STREAM_FRAME_COALESCE_MAX_LEN);

    CU_ASSERT_EQUAL(test_sf_read_back(stream, 0), (int64_t) off);
    CU_ASSERT_EQUAL(stream->stream_data_in.buffered_frame_count, 0);

    xqc_engine_destroy(conn->engine);
}


/*
 * What coalescing does not change: below the threshold each frame keeps its
 * own node; a frame that leaves a gap still costs a node, and is still
 * refused at the cap; a duplicate inside a merged node is still a duplicate.
 */
void
xqc_test_stream_frame_coalesce_bounds()
{
    xqc_connection_t *conn = test_engine_connect();
    xqc_stream_t     *stream;
    const unsigned    len = 7;
    uint64_t          off = 0, gap_off, tail_end;
    int               i;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);

    for (i = 0; i < XQC_STREAM_FRAME_COALESCE_THRESHOLD; i++) {
        CU_ASSERT_EQUAL_FATAL(test_sf_insert(conn, stream, off, len), XQC_OK);
        off += len;
        CU_ASSERT_EQUAL(stream->stream_data_in.buffered_frame_count,
                        (uint64_t) i + 1);
    }
    CU_ASSERT_EQUAL(test_sf_max_node_len(stream), len);

    /* past the threshold, a frame after a gap is a node of its own */
    gap_off = off + 100;
    CU_ASSERT_EQUAL(test_sf_insert(conn, stream, gap_off, len), XQC_OK);
    CU_ASSERT_EQUAL(stream->stream_data_in.buffered_frame_count,
                    (uint64_t) XQC_STREAM_FRAME_COALESCE_THRESHOLD + 1);

    /* adjacent to it, merged: no node, and the gap still bounds the prefix */
    CU_ASSERT_EQUAL(test_sf_insert(conn, stream, gap_off + len, len), XQC_OK);
    tail_end = gap_off + 2 * len;
    CU_ASSERT_EQUAL_FATAL(stream->stream_data_in.buffered_frame_count,
                          (uint64_t) XQC_STREAM_FRAME_COALESCE_THRESHOLD + 1);
    CU_ASSERT_EQUAL(stream->stream_data_in.merged_offset_end, off);

    /* bytes inside the merged node are a duplicate */
    CU_ASSERT_EQUAL(test_sf_insert(conn, stream, gap_off + 2, len),
                    -XQC_EDUP_FRAME);

    /* at the cap: a gap is refused, a continuation is still taken */
    stream->stream_data_in.buffered_frame_count =
        XQC_MAX_STREAM_FRAME_BUFFERED_COUNT;
    CU_ASSERT_EQUAL(test_sf_insert(conn, stream, tail_end + 100, len),
                    -XQC_ELIMIT);
    CU_ASSERT_EQUAL(test_sf_insert(conn, stream, tail_end, len), XQC_OK);
    tail_end += len;
    CU_ASSERT_EQUAL(stream->stream_data_in.buffered_frame_count,
                    (uint64_t) XQC_MAX_STREAM_FRAME_BUFFERED_COUNT);
    stream->stream_data_in.buffered_frame_count =
        XQC_STREAM_FRAME_COALESCE_THRESHOLD + 1;

    /* filling the gap joins the prefix to the merged node's end */
    CU_ASSERT_EQUAL(test_sf_insert(conn, stream, off, 100), XQC_OK);
    CU_ASSERT_EQUAL(stream->stream_data_in.merged_offset_end, tail_end);
    CU_ASSERT_EQUAL(test_sf_read_back(stream, 0), (int64_t) tail_end);

    xqc_engine_destroy(conn->engine);
}


/*
 * Two paths: the even frames arrive first and each odd frame 200 frames
 * late, so every odd frame fills a gap between two nodes. The fill joins
 * them, the node count stays near the threshold plus the late path's
 * frames in flight, and all 20,000 frames are accepted and read in order.
 */
void
xqc_test_stream_frame_coalesce_reordered()
{
    xqc_connection_t *conn = test_engine_connect();
    xqc_stream_t     *stream;
    const unsigned    len = 7;
    const int         n = 10000, lag = 200;
    uint64_t          max_nodes = 0, end = (uint64_t) 2 * n * len;
    int               t, refused = 0;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);

    for (t = 0; t < n + lag; t++) {
        if (t < n && test_sf_insert(conn, stream, (uint64_t) 2 * t * len,
                                    len) != XQC_OK)
        {
            refused++;
        }
        if (t >= lag
            && test_sf_insert(conn, stream,
                              (uint64_t) (2 * (t - lag) + 1) * len,
                              len) != XQC_OK)
        {
            refused++;
        }
        max_nodes = xqc_max(max_nodes,
                            stream->stream_data_in.buffered_frame_count);
    }

    CU_ASSERT_EQUAL(refused, 0);
    CU_ASSERT(max_nodes <= XQC_STREAM_FRAME_COALESCE_THRESHOLD + 2 * lag);
    CU_ASSERT_EQUAL(stream->stream_data_in.merged_offset_end, end);
    CU_ASSERT_EQUAL(test_sf_read_back(stream, 0), (int64_t) end);
    CU_ASSERT_EQUAL(stream->stream_data_in.buffered_frame_count, 0);

    xqc_engine_destroy(conn->engine);
}


/* A FIN-only frame that continues a node is taken without a node. */
void
xqc_test_stream_frame_coalesce_fin_only()
{
    xqc_connection_t   *conn = test_engine_connect();
    xqc_stream_t       *stream;
    xqc_stream_frame_t *fin_frame, *tail;
    const unsigned      len = 7;
    uint64_t            off = 0;
    int                 i;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);

    for (i = 0; i < XQC_STREAM_FRAME_COALESCE_THRESHOLD; i++) {
        CU_ASSERT_EQUAL_FATAL(test_sf_insert(conn, stream, off, len), XQC_OK);
        off += len;
    }

    /* at the cap */
    stream->stream_data_in.buffered_frame_count =
        XQC_MAX_STREAM_FRAME_BUFFERED_COUNT;
    fin_frame = xqc_calloc(1, sizeof(xqc_stream_frame_t));
    fin_frame->data_offset = off;
    fin_frame->fin = 1;
    CU_ASSERT_EQUAL(xqc_insert_stream_frame(conn, stream, fin_frame), XQC_OK);
    CU_ASSERT_EQUAL(stream->stream_data_in.buffered_frame_count,
                    (uint64_t) XQC_MAX_STREAM_FRAME_BUFFERED_COUNT);

    tail = xqc_list_entry(stream->stream_data_in.frames_tailq.prev,
                          xqc_stream_frame_t, sf_list);
    CU_ASSERT(tail->fin);
    CU_ASSERT_EQUAL(tail->data_offset + tail->data_length, off);

    stream->stream_data_in.buffered_frame_count =
        XQC_STREAM_FRAME_COALESCE_THRESHOLD;
    xqc_engine_destroy(conn->engine);
}


/* one STREAM frame on the wire: OFF and LEN bits, 8-byte offset */
static size_t
test_sf_put_stream_frame(unsigned char *out, xqc_stream_id_t sid,
    uint64_t offset, unsigned len)
{
    unsigned char *p = out;
    unsigned       i;

    *p++ = 0x0e;
    p = xqc_put_varint(p, sid);
    *p++ = (unsigned char) (0xc0 | (offset >> 56));
    for (i = 1; i < 8; i++) {
        *p++ = (unsigned char) (offset >> (56 - 8 * i));
    }
    p = xqc_put_varint(p, len);
    for (i = 0; i < len; i++) {
        *p++ = test_sf_byte(offset + i);
    }
    return p - out;
}


/*
 * The same flood through the STREAM frame handler, which reads the frame's
 * fields after the insert for flow control: 20,000 frames, no connection
 * error, and the flow-control accounting equal to the bytes sent.
 */
void
xqc_test_stream_frame_coalesce_through_handler()
{
    xqc_connection_t *conn = test_engine_connect();
    xqc_stream_t     *stream;
    xqc_packet_in_t   pi;
    unsigned char     wire[64];
    const unsigned    len = 7;
    uint64_t          off = 0;
    int               i, failed = 0;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
    stream->stream_flow_ctl.fc_max_stream_data_can_recv = 1024 * 1024;
    conn->conn_flow_ctl.fc_max_data_can_recv = 1024 * 1024;

    for (i = 0; i < 20000; i++) {
        memset(&pi, 0, sizeof(pi));
        pi.pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
        pi.pos = wire;
        pi.last = wire + test_sf_put_stream_frame(wire, stream->stream_id,
                                                  off, len);
        if (xqc_process_stream_frame(conn, &pi) != XQC_OK) {
            failed++;
            break;
        }
        off += len;
    }

    CU_ASSERT_EQUAL(failed, 0);
    CU_ASSERT_EQUAL(conn->conn_err, 0);
    CU_ASSERT_EQUAL(stream->stream_max_recv_offset, off);
    CU_ASSERT_EQUAL(conn->conn_flow_ctl.fc_data_recved, off);
    CU_ASSERT(stream->stream_data_in.buffered_frame_count
              < XQC_MAX_STREAM_FRAME_BUFFERED_COUNT);
    CU_ASSERT_EQUAL(test_sf_read_back(stream, 0), (int64_t) off);

    xqc_engine_destroy(conn->engine);
}
