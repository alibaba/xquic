/*
 * Frame layer of draft-ietf-quic-multipath-19/21 (multipath_version
 * XQC_MULTIPATH_3E): wire formats, Section 4 receive rules and the
 * PATHS_BLOCKED / PATH_CIDS_BLOCKED report on path creation.
 */

#include "xqc_multipath_frame_test.h"
#include "xqc_common_test.h"
#include <CUnit/CUnit.h>
#include <xquic/xquic.h>
#include <xquic/xqc_errno.h>
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_cid.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_send_queue.h"

/* a connection that negotiated multipath draft-19 with path IDs 0..8 */
static xqc_connection_t *
test_mp3e_conn(void)
{
    xqc_connection_t *conn = test_engine_connect();
    if (conn == NULL) {
        return NULL;
    }
    conn->enable_multipath = XQC_CONN_MP_ENABLED;
    conn->conn_settings.multipath_version = XQC_MULTIPATH_3E;
    conn->local_settings.init_max_path_id = 8;
    conn->remote_settings.init_max_path_id = 8;
    conn->local_max_path_id = 8;
    conn->remote_max_path_id = 8;
    conn->curr_max_path_id = 8;
    return conn;
}

static void
test_mp3e_packet_in(xqc_packet_in_t *packet_in, const unsigned char *buf, size_t len)
{
    memset(packet_in, 0, sizeof(*packet_in));
    packet_in->pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    packet_in->buf = buf;
    packet_in->buf_size = len;
    packet_in->pos = (unsigned char *)buf;
    packet_in->last = (unsigned char *)buf + len;
}

static xqc_int_t
test_mp3e_process_in(xqc_connection_t *conn, const unsigned char *buf, size_t len,
    xqc_pkt_type_t pkt_type)
{
    xqc_packet_in_t packet_in;
    test_mp3e_packet_in(&packet_in, buf, len);
    packet_in.pi_pkt.pkt_type = pkt_type;
    return xqc_process_frames(conn, &packet_in);
}

static xqc_int_t
test_mp3e_process(xqc_connection_t *conn, const unsigned char *buf, size_t len)
{
    return test_mp3e_process_in(conn, buf, len, XQC_PTYPE_SHORT_HEADER);
}

static int
test_mp3e_count_queued(xqc_connection_t *conn, xqc_frame_type_bit_t bit)
{
    xqc_list_head_t *pos;
    xqc_packet_out_t *po;
    int count = 0;

    xqc_list_for_each(pos, &conn->conn_send_queue->sndq_send_packets_high_pri) {
        po = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (po->po_frame_types & bit) {
            count++;
        }
    }
    return count;
}

/* draft-21 Section 4.2: PATH_ABANDON has no Reason Phrase; draft-10 MP_ABANDON still has one */
void
xqc_test_mp3e_path_abandon_frame(void)
{
    xqc_connection_t *conn = test_mp3e_conn();
    xqc_packet_out_t *po;
    xqc_packet_in_t packet_in;
    unsigned char *start;
    uint64_t path_id, error_code;
    ssize_t n;
    xqc_int_t ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    po = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT_PTR_NOT_NULL_FATAL(po);
    start = po->po_buf + po->po_used_size;
    n = xqc_gen_path_abandon_frame(conn, po, 3, APPLICATION_ABANDON_PATH);
    /* Type 0x3e75 (2 bytes), Path Identifier 3, Error Code 0x3e */
    CU_ASSERT(n == 4);
    CU_ASSERT((po->po_frame_types & XQC_FRAME_BIT_PATH_ABANDON) != 0);

    /* a byte after the frame belongs to the next frame and is left alone */
    start[n] = 0x01;
    test_mp3e_packet_in(&packet_in, start, n + 1);
    ret = xqc_parse_path_abandon_frame(&packet_in, &path_id, &error_code, conn);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(path_id == 3);
    CU_ASSERT(error_code == APPLICATION_ABANDON_PATH);
    CU_ASSERT(packet_in.pos == start + n);
    CU_ASSERT((packet_in.pi_frame_types & XQC_FRAME_BIT_PATH_ABANDON) != 0);

    /* draft-10: 4-byte type and a zero Reason Phrase Length on the wire */
    conn->conn_settings.multipath_version = XQC_MULTIPATH_10;
    po = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT_PTR_NOT_NULL_FATAL(po);
    start = po->po_buf + po->po_used_size;
    n = xqc_gen_path_abandon_frame(conn, po, 3, 0);
    CU_ASSERT(n == 7);
    CU_ASSERT(start[n - 1] == 0);

    test_mp3e_packet_in(&packet_in, start, n);
    ret = xqc_parse_path_abandon_frame(&packet_in, &path_id, &error_code, conn);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(path_id == 3);
    CU_ASSERT(packet_in.pos == start + n);

    /* a Reason Phrase Length past the end of the frame is rejected */
    start[n - 1] = 0x05;
    test_mp3e_packet_in(&packet_in, start, n);
    ret = xqc_parse_path_abandon_frame(&packet_in, &path_id, &error_code, conn);
    CU_ASSERT(ret == -XQC_EVINTREAD);

    xqc_engine_destroy(conn->engine);
}

/* draft-21 Section 4.3: PATH_STATUS_BACKUP 0x3e76 and PATH_STATUS_AVAILABLE 0x3e77 */
void
xqc_test_mp3e_path_status_parse(void)
{
    static const unsigned char backup[] = { 0x7e, 0x76, 0x01, 0x07 };
    static const unsigned char available[] = { 0x7e, 0x77, 0x01, 0x08 };
    xqc_connection_t *conn = test_mp3e_conn();
    xqc_packet_in_t packet_in;
    uint64_t path_id, seq, status;
    xqc_int_t ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    test_mp3e_packet_in(&packet_in, backup, sizeof(backup));
    ret = xqc_parse_path_status_frame(&packet_in, &path_id, &seq, &status);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(path_id == 1);
    CU_ASSERT(seq == 7);
    CU_ASSERT(status == XQC_APP_PATH_STATUS_STANDBY);
    CU_ASSERT((packet_in.pi_frame_types & XQC_FRAME_BIT_PATH_STANDBY) != 0);
    CU_ASSERT(packet_in.pos == packet_in.last);

    test_mp3e_packet_in(&packet_in, available, sizeof(available));
    ret = xqc_parse_path_status_frame(&packet_in, &path_id, &seq, &status);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(seq == 8);
    CU_ASSERT(status == XQC_APP_PATH_STATUS_AVAILABLE);
    CU_ASSERT((packet_in.pi_frame_types & XQC_FRAME_BIT_PATH_AVAILABLE) != 0);

    /* through the dispatcher: a status for an unknown path is ignored, not an error */
    ret = test_mp3e_process(conn, backup, sizeof(backup));
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(conn->conn_err == 0);

    xqc_engine_destroy(conn->engine);
}

/* draft-21 Section 4.1: the 0x3f type carries three ECN counts after the ranges */
void
xqc_test_mp3e_path_ack_ecn_counts(void)
{
    /* Path Identifier 0, Largest 5, ACK Delay 0, Range Count 0, First Range 0 */
    static const unsigned char path_ack_ecn[] = { 0x3f, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03 };
    static const unsigned char path_ack[] = { 0x3e, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01 };
    static const unsigned char mp_ack1[] = { 0x95, 0x22, 0x8c, 0x01, 0x00, 0x05, 0x00, 0x00, 0x00,
                                             0x01, 0x02, 0x03 };
    static const unsigned char path_ack_ecn_short[] = { 0x3f, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01 };
    xqc_connection_t *conn = test_mp3e_conn();
    xqc_packet_in_t packet_in;
    xqc_ack_info_t ack_info;
    uint64_t path_id;
    xqc_int_t ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    test_mp3e_packet_in(&packet_in, path_ack_ecn, sizeof(path_ack_ecn));
    ret = xqc_parse_ack_mp_frame(&packet_in, conn, &path_id, &ack_info);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(path_id == 0);
    CU_ASSERT(ack_info.ranges[0].high == 5);
    CU_ASSERT(packet_in.pos == packet_in.last);

    /* PATH_ACK has no counts: the trailing byte is the next frame */
    test_mp3e_packet_in(&packet_in, path_ack, sizeof(path_ack));
    ret = xqc_parse_ack_mp_frame(&packet_in, conn, &path_id, &ack_info);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(packet_in.pos == packet_in.last - 1);

    /* draft-10 ACK_MP with ECN (0x15228c01) is handled the same way */
    test_mp3e_packet_in(&packet_in, mp_ack1, sizeof(mp_ack1));
    ret = xqc_parse_ack_mp_frame(&packet_in, conn, &path_id, &ack_info);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(packet_in.pos == packet_in.last);

    /* truncated counts are a parse error */
    test_mp3e_packet_in(&packet_in, path_ack_ecn_short, sizeof(path_ack_ecn_short));
    ret = xqc_parse_ack_mp_frame(&packet_in, conn, &path_id, &ack_info);
    CU_ASSERT(ret == -XQC_EVINTREAD);

    xqc_engine_destroy(conn->engine);
}

/* draft-21 Section 4.7: PATHS_BLOCKED and PATH_CIDS_BLOCKED generate and parse back */
void
xqc_test_mp3e_blocked_frames_roundtrip(void)
{
    xqc_connection_t *conn = test_mp3e_conn();
    xqc_packet_out_t *po;
    xqc_packet_in_t packet_in;
    unsigned char *start;
    uint64_t max_path_id, path_id, next_seq;
    ssize_t n;
    xqc_int_t ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    po = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT_PTR_NOT_NULL_FATAL(po);
    start = po->po_buf + po->po_used_size;
    n = xqc_gen_paths_blocked_frame(po, 8);
    CU_ASSERT(n == 3);
    CU_ASSERT((po->po_frame_types & XQC_FRAME_BIT_PATHS_BLOCKED) != 0);
    test_mp3e_packet_in(&packet_in, start, n);
    ret = xqc_parse_paths_blocked_frame(&packet_in, &max_path_id);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(max_path_id == 8);
    CU_ASSERT(packet_in.pos == packet_in.last);
    CU_ASSERT((packet_in.pi_frame_types & XQC_FRAME_BIT_PATHS_BLOCKED) != 0);

    po = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT_PTR_NOT_NULL_FATAL(po);
    start = po->po_buf + po->po_used_size;
    n = xqc_gen_path_cids_blocked_frame(po, 5, 2);
    CU_ASSERT(n == 4);
    CU_ASSERT((po->po_frame_types & XQC_FRAME_BIT_PATH_CIDS_BLOCKED) != 0);
    test_mp3e_packet_in(&packet_in, start, n);
    ret = xqc_parse_path_cids_blocked_frame(&packet_in, &path_id, &next_seq);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(path_id == 5);
    CU_ASSERT(next_seq == 2);
    CU_ASSERT(packet_in.pos == packet_in.last);
    CU_ASSERT((packet_in.pi_frame_types & XQC_FRAME_BIT_PATH_CIDS_BLOCKED) != 0);

    /* both are ack-eliciting */
    CU_ASSERT(XQC_IS_ACK_ELICITING(XQC_FRAME_BIT_PATHS_BLOCKED) != 0);
    CU_ASSERT(XQC_IS_ACK_ELICITING(XQC_FRAME_BIT_PATH_CIDS_BLOCKED) != 0);

    xqc_engine_destroy(conn->engine);
}

/* draft-21 Section 4.7: a Maximum Path Identifier above our limit is PROTOCOL_VIOLATION */
void
xqc_test_mp3e_paths_blocked_limit(void)
{
    static const unsigned char at_limit[] = { 0x7e, 0x7b, 0x08 };
    static const unsigned char above_limit[] = { 0x7e, 0x7b, 0x09 };
    xqc_connection_t *conn = test_mp3e_conn();
    xqc_int_t ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    ret = test_mp3e_process(conn, at_limit, sizeof(at_limit));
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(conn->conn_err == 0);

    ret = test_mp3e_process(conn, above_limit, sizeof(above_limit));
    CU_ASSERT(ret == -XQC_EILLEGAL_FRAME);
    CU_ASSERT(conn->conn_err == TRA_PROTOCOL_VIOLATION);

    xqc_engine_destroy(conn->engine);

    /* draft-10 keeps its own error code */
    conn = test_mp3e_conn();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    conn->conn_settings.multipath_version = XQC_MULTIPATH_10;
    xqc_conn_mp_protocol_violation(conn);
    CU_ASSERT(conn->conn_err == TRA_MP_PROTOCOL_VIOLATION);
    xqc_engine_destroy(conn->engine);
}

/* draft-21 Section 4.7: Path Identifier and Next Sequence Number bounds */
void
xqc_test_mp3e_path_cids_blocked_limit(void)
{
    static const unsigned char seq0[] = { 0x7e, 0x7c, 0x02, 0x00 };
    static const unsigned char seq1[] = { 0x7e, 0x7c, 0x02, 0x01 };
    static const unsigned char seq2[] = { 0x7e, 0x7c, 0x02, 0x02 };
    static const unsigned char path9[] = { 0x7e, 0x7c, 0x09, 0x00 };
    xqc_connection_t *conn = test_mp3e_conn();
    xqc_int_t ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    ret = xqc_conn_add_path_cid_sets(conn, 1, 8);
    CU_ASSERT(ret == XQC_OK);

    /* nothing issued for path 2 yet: the first connection ID will be sequence 0 */
    ret = test_mp3e_process(conn, seq0, sizeof(seq0));
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(conn->conn_err == 0);
    ret = test_mp3e_process(conn, seq1, sizeof(seq1));
    CU_ASSERT(ret == -XQC_EILLEGAL_FRAME);
    CU_ASSERT(conn->conn_err == TRA_PROTOCOL_VIOLATION);
    xqc_engine_destroy(conn->engine);

    /* sequence 0 issued for path 2: the peer may expect 1, not 2 */
    conn = test_mp3e_conn();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    ret = xqc_conn_add_path_cid_sets(conn, 1, 8);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_write_mp_new_conn_id_frame_to_packet(conn, 0, 2);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(xqc_get_path_cid_set(&conn->scid_set, 2)->largest_scid_seq_num == 0);
    ret = test_mp3e_process(conn, seq1, sizeof(seq1));
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(conn->conn_err == 0);
    ret = test_mp3e_process(conn, seq2, sizeof(seq2));
    CU_ASSERT(ret == -XQC_EILLEGAL_FRAME);
    CU_ASSERT(conn->conn_err == TRA_PROTOCOL_VIOLATION);
    xqc_engine_destroy(conn->engine);

    conn = test_mp3e_conn();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    ret = test_mp3e_process(conn, path9, sizeof(path9));
    CU_ASSERT(ret == -XQC_EILLEGAL_FRAME);
    CU_ASSERT(conn->conn_err == TRA_PROTOCOL_VIOLATION);
    xqc_engine_destroy(conn->engine);
}

/* draft-21 Section 4.6: MAX_PATH_ID bounds, and smaller values are ignored */
void
xqc_test_mp3e_max_path_id_validation(void)
{
    static const unsigned char stale[] = { 0x7e, 0x7a, 0x08 };
    static const unsigned char grow[] = { 0x7e, 0x7a, 0x0a };
    static const unsigned char below_initial[] = { 0x7e, 0x7a, 0x07 };
    /* 2^32 as an 8-byte varint */
    static const unsigned char too_large[] = { 0x7e, 0x7a, 0xc0, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };
    xqc_connection_t *conn = test_mp3e_conn();
    xqc_int_t ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    ret = test_mp3e_process(conn, stale, sizeof(stale));
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(conn->remote_max_path_id == 8);

    ret = test_mp3e_process(conn, grow, sizeof(grow));
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(conn->remote_max_path_id == 10);
    /* our own limit still bounds the usable path IDs */
    CU_ASSERT(conn->curr_max_path_id == 8);

    ret = test_mp3e_process(conn, below_initial, sizeof(below_initial));
    CU_ASSERT(ret == -XQC_EILLEGAL_FRAME);
    CU_ASSERT(conn->conn_err == TRA_PROTOCOL_VIOLATION);
    xqc_engine_destroy(conn->engine);

    conn = test_mp3e_conn();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    ret = test_mp3e_process(conn, too_large, sizeof(too_large));
    CU_ASSERT(ret == -XQC_EILLEGAL_FRAME);
    CU_ASSERT(conn->conn_err == TRA_PROTOCOL_VIOLATION);
    xqc_engine_destroy(conn->engine);
}

/* draft-21 Section 4: multipath frames are only accepted in 1-RTT packets */
void
xqc_test_mp3e_frames_require_1rtt(void)
{
    static const unsigned char paths_blocked[] = { 0x7e, 0x7b, 0x08 };
    static const unsigned char path_ack[] = { 0x3e, 0x00, 0x05, 0x00, 0x00, 0x00 };
    static const unsigned char ping[] = { 0x01 };
    xqc_connection_t *conn = test_mp3e_conn();
    xqc_int_t ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    /* a non-multipath frame in 0-RTT is fine */
    ret = test_mp3e_process_in(conn, ping, sizeof(ping), XQC_PTYPE_0RTT);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(conn->conn_err == 0);

    ret = test_mp3e_process_in(conn, paths_blocked, sizeof(paths_blocked), XQC_PTYPE_0RTT);
    CU_ASSERT(ret == -XQC_EILLEGAL_FRAME);
    CU_ASSERT(conn->conn_err == TRA_PROTOCOL_VIOLATION);
    xqc_engine_destroy(conn->engine);

    conn = test_mp3e_conn();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    ret = test_mp3e_process_in(conn, path_ack, sizeof(path_ack), XQC_PTYPE_HSK);
    CU_ASSERT(ret == -XQC_EILLEGAL_FRAME);
    CU_ASSERT(conn->conn_err == TRA_PROTOCOL_VIOLATION);
    xqc_engine_destroy(conn->engine);

    /* draft-10 frames keep their current handling */
    conn = test_mp3e_conn();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    conn->conn_settings.multipath_version = XQC_MULTIPATH_10;
    ret = test_mp3e_process_in(conn, paths_blocked, sizeof(paths_blocked), XQC_PTYPE_0RTT);
    CU_ASSERT(ret == -XQC_EMP_INVALID_MP_VERTION);
    CU_ASSERT(conn->conn_err == 0);
    xqc_engine_destroy(conn->engine);
}

/* draft-10 Section 7.7 has the same MAX_PATH_ID lower bound; its error code stays MP_PROTOCOL_VIOLATION */
void
xqc_test_mp10_max_path_id_lower_bound(void)
{
    static const unsigned char grow[] = { 0x95, 0x22, 0x8c, 0x0c, 0x0a };
    static const unsigned char below_initial[] = { 0x95, 0x22, 0x8c, 0x0c, 0x07 };
    xqc_connection_t *conn = test_mp3e_conn();
    xqc_int_t ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    conn->conn_settings.multipath_version = XQC_MULTIPATH_10;

    ret = test_mp3e_process(conn, grow, sizeof(grow));
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(conn->remote_max_path_id == 10);

    ret = test_mp3e_process(conn, below_initial, sizeof(below_initial));
    CU_ASSERT(ret == -XQC_EILLEGAL_FRAME);
    CU_ASSERT(conn->conn_err == TRA_MP_PROTOCOL_VIOLATION);
    xqc_engine_destroy(conn->engine);
}

/* PATHS_BLOCKED / PATH_CIDS_BLOCKED codec bounds: buffer space, long varints, truncation */
void
xqc_test_mp3e_blocked_frames_bounds(void)
{
    static const unsigned char no_value[] = { 0x7e, 0x7b };
    static const unsigned char cut_varint[] = { 0x7e, 0x7b, 0xc0, 0x00 };
    static const unsigned char no_seq[] = { 0x7e, 0x7c, 0x02 };
    static const unsigned char then_ping[] = { 0x7e, 0x7b, 0x08, 0x01 };
    xqc_connection_t *conn = test_mp3e_conn();
    xqc_packet_out_t *po;
    xqc_packet_in_t packet_in;
    unsigned char *start;
    size_t room;
    uint64_t max_path_id, path_id, next_seq;
    ssize_t n;
    xqc_int_t ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    po = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT_PTR_NOT_NULL_FATAL(po);
    room = xqc_get_po_remained_size(po);
    po->po_used_size += room - 2;
    CU_ASSERT(xqc_gen_paths_blocked_frame(po, 8) == -XQC_ENOBUF);
    CU_ASSERT(xqc_gen_path_cids_blocked_frame(po, 2, 1) == -XQC_ENOBUF);
    po->po_used_size -= room - 2;

    /* 2^32-1 takes an 8-byte varint */
    start = po->po_buf + po->po_used_size;
    n = xqc_gen_paths_blocked_frame(po, XQC_PATH_ID_MAX_VALUE);
    CU_ASSERT(n == 10);
    test_mp3e_packet_in(&packet_in, start, n);
    ret = xqc_parse_paths_blocked_frame(&packet_in, &max_path_id);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(max_path_id == XQC_PATH_ID_MAX_VALUE);
    CU_ASSERT(packet_in.pos == packet_in.last);

    start = po->po_buf + po->po_used_size;
    n = xqc_gen_path_cids_blocked_frame(po, 0x3fff, 0x40000000);
    CU_ASSERT(n == 12);
    test_mp3e_packet_in(&packet_in, start, n);
    ret = xqc_parse_path_cids_blocked_frame(&packet_in, &path_id, &next_seq);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(path_id == 0x3fff);
    CU_ASSERT(next_seq == 0x40000000);
    CU_ASSERT(packet_in.pos == packet_in.last);

    test_mp3e_packet_in(&packet_in, no_value, sizeof(no_value));
    CU_ASSERT(xqc_parse_paths_blocked_frame(&packet_in, &max_path_id) == -XQC_EVINTREAD);
    test_mp3e_packet_in(&packet_in, cut_varint, sizeof(cut_varint));
    CU_ASSERT(xqc_parse_paths_blocked_frame(&packet_in, &max_path_id) == -XQC_EVINTREAD);
    test_mp3e_packet_in(&packet_in, no_seq, sizeof(no_seq));
    CU_ASSERT(xqc_parse_path_cids_blocked_frame(&packet_in, &path_id, &next_seq) == -XQC_EVINTREAD);

    /* the following frame is left for the dispatcher */
    test_mp3e_packet_in(&packet_in, then_ping, sizeof(then_ping));
    ret = xqc_parse_paths_blocked_frame(&packet_in, &max_path_id);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(packet_in.pos == packet_in.last - 1);

    xqc_engine_destroy(conn->engine);
}

/* draft-21 Section 2: no multipath frame is accepted before both sides negotiated it */
void
xqc_test_mp3e_frames_require_negotiation(void)
{
    static const struct { unsigned char len; unsigned char buf[2]; } frames[] = {
        { 1, { 0x3e } },        /* PATH_ACK */
        { 1, { 0x3f } },        /* PATH_ACK_ECN */
        { 2, { 0x7e, 0x75 } },  /* PATH_ABANDON */
        { 2, { 0x7e, 0x76 } },  /* PATH_STATUS_BACKUP */
        { 2, { 0x7e, 0x77 } },  /* PATH_STATUS_AVAILABLE */
        { 2, { 0x7e, 0x78 } },  /* PATH_NEW_CONNECTION_ID */
        { 2, { 0x7e, 0x79 } },  /* PATH_RETIRE_CONNECTION_ID */
        { 2, { 0x7e, 0x7a } },  /* MAX_PATH_ID */
        { 2, { 0x7e, 0x7b } },  /* PATHS_BLOCKED */
        { 2, { 0x7e, 0x7c } },  /* PATH_CIDS_BLOCKED */
    };
    xqc_connection_t *conn = test_mp3e_conn();
    xqc_int_t ret;
    size_t i;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    conn->enable_multipath = XQC_CONN_MP_DISABLED;

    for (i = 0; i < sizeof(frames) / sizeof(frames[0]); i++) {
        ret = test_mp3e_process(conn, frames[i].buf, frames[i].len);
        CU_ASSERT_EQUAL(ret, -XQC_EMP_INVALID_MP_VERTION);
    }

    xqc_engine_destroy(conn->engine);
}

/* draft-21 Section 3.2.1: a failed path creation reports why, at most once per PTO */
void
xqc_test_mp3e_report_path_blocked(void)
{
    xqc_connection_t *conn = test_mp3e_conn();
    uint64_t new_path_id = 0;
    uint64_t pid;
    xqc_int_t ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    /* every path ID under the limit is in use */
    ret = xqc_conn_add_path_cid_sets(conn, 1, 8);
    CU_ASSERT(ret == XQC_OK);
    for (pid = 0; pid <= 8; pid++) {
        xqc_cid_set_update_state(&conn->scid_set, pid, XQC_CID_SET_USED);
    }

    /* an idle connection: nothing else would make the frame leave */
    xqc_engine_remove_active_queue(conn->engine, conn);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_TICKING) == 0);

    ret = xqc_conn_create_path(conn->engine, &conn->scid_set.user_scid, &new_path_id,
                               XQC_APP_PATH_STATUS_AVAILABLE);
    CU_ASSERT(ret == -XQC_EMP_NO_AVAIL_PATH_ID);
    CU_ASSERT(test_mp3e_count_queued(conn, XQC_FRAME_BIT_PATHS_BLOCKED) == 1);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_TICKING) != 0);

    /* a retry within one PTO sends nothing more */
    ret = xqc_conn_create_path(conn->engine, &conn->scid_set.user_scid, &new_path_id,
                               XQC_APP_PATH_STATUS_AVAILABLE);
    CU_ASSERT(ret == -XQC_EMP_NO_AVAIL_PATH_ID);
    CU_ASSERT(test_mp3e_count_queued(conn, XQC_FRAME_BIT_PATHS_BLOCKED) == 1);

    /* path 9 becomes allowed but the peer has issued no connection ID for it */
    conn->local_max_path_id = 9;
    conn->remote_max_path_id = 9;
    conn->curr_max_path_id = 9;
    ret = xqc_conn_add_path_cid_sets(conn, 9, 9);
    CU_ASSERT(ret == XQC_OK);
    conn->last_path_blocked_sent_time = 0;

    ret = xqc_conn_create_path(conn->engine, &conn->scid_set.user_scid, &new_path_id,
                               XQC_APP_PATH_STATUS_AVAILABLE);
    CU_ASSERT(ret == -XQC_EMP_NO_AVAIL_PATH_ID);
    CU_ASSERT(test_mp3e_count_queued(conn, XQC_FRAME_BIT_PATH_CIDS_BLOCKED) == 1);
    CU_ASSERT(test_mp3e_count_queued(conn, XQC_FRAME_BIT_PATHS_BLOCKED) == 1);

    /* draft-10 has neither frame */
    conn->conn_settings.multipath_version = XQC_MULTIPATH_10;
    conn->last_path_blocked_sent_time = 0;
    ret = xqc_conn_create_path(conn->engine, &conn->scid_set.user_scid, &new_path_id,
                               XQC_APP_PATH_STATUS_AVAILABLE);
    CU_ASSERT(ret == -XQC_EMP_NO_AVAIL_PATH_ID);
    CU_ASSERT(test_mp3e_count_queued(conn, XQC_FRAME_BIT_PATH_CIDS_BLOCKED) == 1);

    xqc_engine_destroy(conn->engine);
}
