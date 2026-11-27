/*
 * CBMC harnesses for src/transport/xqc_frame_parser.c (xqc_parse_*_frame).
 *
 * Each harness_<frame>() calls one parser on a packet_in whose payload is an
 * unconstrained buffer of 1..MAXLEN bytes, like xqc_process_frames() does
 * after it has read the frame type.  Besides the memory-safety, overflow and
 * UB checks that cbmc adds, every harness asserts the contract that
 * xqc_process_frames() relies on: a parser that returns XQC_OK has moved
 * packet_in->pos forward and not past packet_in->last.
 */
#include "common.h"

#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_recv_record.h"
#include "src/transport/xqc_recv_timestamps_info.h"
#include "src/transport/xqc_defs.h"
#include "src/transport/xqc_transport_params.h"

static unsigned char *g_first;   /* first byte given to the parser */

/*
 * A packet_in over a fresh buffer.  Fields other than pos/last keep the
 * nondeterministic values of a stack object, except the ones parsers read:
 * pi_frame_types (or-ed into) and pi_flag/decode_payload_len (FEC).
 */
static void
mk_packet(xqc_packet_in_t *pi, size_t minlen)
{
    size_t len;
    unsigned char *buf = cbmc_buf(minlen, &len);
    pi->pos = buf;
    pi->last = buf + len;
    pi->pi_frame_types = 0;
    g_first = buf;
}

/*
 * A connection object with unconstrained contents, except for the
 * invariants that the transport parameter decoder establishes before any
 * frame can be parsed (checked separately by the transport parameter
 * harness): ack_delay_exponent <= 20.
 */
static xqc_connection_t *
mk_conn(void)
{
    xqc_connection_t *conn = malloc(sizeof(xqc_connection_t));
    __CPROVER_assume(conn != NULL);
    __CPROVER_assume(conn->remote_settings.ack_delay_exponent <= 20);
    /* XQC_CONN_ERR() reads these */
    conn->conn_err = 0;
    conn->conn_close_msg = NULL;
    return conn;
}

/* the contract of xqc_process_frames() on a successful parse */
static void
check_ok(const xqc_packet_in_t *pi, xqc_int_t ret, const unsigned char *last)
{
    if (ret == XQC_OK) {
        __CPROVER_assert(pi->pos > g_first, "parser advanced pos");
        __CPROVER_assert(pi->pos <= last, "parser stayed within the packet");
    }
}

static void
release(xqc_packet_in_t *pi, xqc_connection_t *conn)
{
    free(g_first);
    free(conn);
}

/* ---- RFC 9000 frames ------------------------------------------------- */

void
harness_padding(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    __CPROVER_assume(pi.pos[0] == 0x00);
    xqc_connection_t *conn = mk_conn();
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_padding_frame(&pi, conn);
    check_ok(&pi, ret, last);
    release(&pi, conn);
}

void
harness_ping(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    __CPROVER_assume(pi.pos[0] == 0x01);
    xqc_connection_t *conn = mk_conn();
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_ping_frame(&pi, conn);
    check_ok(&pi, ret, last);
    release(&pi, conn);
}

void
harness_handshake_done(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    __CPROVER_assume(pi.pos[0] == 0x1e);
    xqc_connection_t *conn = mk_conn();
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_handshake_done_frame(&pi, conn);
    check_ok(&pi, ret, last);
    release(&pi, conn);
}

void
harness_ack(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    /* ACK (0x02) or ACK_ECN (0x03) */
    __CPROVER_assume(pi.pos[0] == 0x02 || pi.pos[0] == 0x03);
    xqc_connection_t *conn = mk_conn();
    xqc_ack_info_t *ack_info = malloc(sizeof(*ack_info));
    __CPROVER_assume(ack_info != NULL);
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_ack_frame(&pi, conn, ack_info);
    check_ok(&pi, ret, last);
    if (ret == XQC_OK) {
        /* what xqc_send_ctl_on_ack_received() relies on */
        __CPROVER_assert(ack_info->n_ranges >= 1
                             && ack_info->n_ranges <= XQC_MAX_ACK_RANGE_CNT,
                         "ACK: n_ranges in 1..XQC_MAX_ACK_RANGE_CNT");
        for (unsigned i = 0;
             i < ack_info->n_ranges && i < XQC_MAX_ACK_RANGE_CNT; i++)
        {
            __CPROVER_assert(ack_info->ranges[i].low
                                 <= ack_info->ranges[i].high,
                             "ACK: every range has low <= high");
            if (i > 0) {
                __CPROVER_assert(ack_info->ranges[i].high + 1
                                     < ack_info->ranges[i - 1].low,
                                 "ACK: ranges descend with a gap");
            }
        }
    }
    free(ack_info);
    release(&pi, conn);
}

void
harness_ack_ext(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    xqc_connection_t *conn = mk_conn();
    xqc_ack_info_t *ack_info = malloc(sizeof(*ack_info));
    __CPROVER_assume(ack_info != NULL);
    xqc_ack_timestamp_info_t *ts = malloc(sizeof(*ts));
    __CPROVER_assume(ts != NULL);
    ts->report_num = 0;              /* as xqc_process_ack_ext_frame() does */
#ifdef TS_LOCAL_MAX
    /* the local setting; the API does not bound it */
    __CPROVER_assume(conn->local_settings.max_receive_timestamps_per_ack
                     <= TS_LOCAL_MAX);
#else
    /* the largest value that the peer's decoder accepts (63) */
    __CPROVER_assume(conn->local_settings.max_receive_timestamps_per_ack <= 63);
#endif
    __CPROVER_assume(conn->local_settings.receive_timestamps_exponent <= 20);
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_ack_ext_frame(&pi, conn, ack_info, ts);
    check_ok(&pi, ret, last);
    free(ts);
    free(ack_info);
    release(&pi, conn);
}

void
harness_reset_stream(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    __CPROVER_assume(pi.pos[0] == XQC_FRAME_TYPE_RESET_STREAM);
    xqc_connection_t *conn = mk_conn();
    xqc_stream_id_t sid;
    uint64_t err, final_size;
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_reset_stream_frame(&pi, &sid, &err, &final_size,
                                                 conn);
    check_ok(&pi, ret, last);
    release(&pi, conn);
}

void
harness_reset_stream_at(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    xqc_connection_t *conn = mk_conn();
    xqc_stream_id_t sid;
    uint64_t err, final_size, reliable_size;
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_reset_stream_at_frame(&pi, &sid, &err,
                                                    &final_size,
                                                    &reliable_size);
    check_ok(&pi, ret, last);
    if (ret == XQC_OK) {
        __CPROVER_assert(reliable_size <= final_size,
                         "RESET_STREAM_AT: reliable <= final");
    }
    release(&pi, conn);
}

void
harness_stop_sending(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    __CPROVER_assume(pi.pos[0] == 0x05);
    xqc_connection_t *conn = mk_conn();
    xqc_stream_id_t sid;
    uint64_t err;
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_stop_sending_frame(&pi, &sid, &err, conn);
    check_ok(&pi, ret, last);
    release(&pi, conn);
}

void
harness_crypto(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    __CPROVER_assume(pi.pos[0] == 0x06);
    xqc_connection_t *conn = mk_conn();
    xqc_stream_frame_t frame;
    memset(&frame, 0, sizeof(frame));     /* xqc_calloc() in the caller */
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_crypto_frame(&pi, conn, &frame);
    check_ok(&pi, ret, last);
    if (ret == XQC_OK) {
        __CPROVER_assert(frame.data_length <= (size_t)(last - g_first),
                         "CRYPTO: data_length within the packet");
    }
    free(frame.data);                    /* the caller frees on both paths */
    release(&pi, conn);
}

void
harness_new_token(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    __CPROVER_assume(pi.pos[0] == 0x07);
    xqc_connection_t *conn = mk_conn();
    /* xqc_process_new_token_frame(): conn->conn_token, XQC_MAX_TOKEN_LEN */
    unsigned char *token = malloc(XQC_MAX_TOKEN_LEN);
    __CPROVER_assume(token != NULL);
    unsigned token_len = XQC_MAX_TOKEN_LEN;
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_new_token_frame(&pi, token, &token_len, conn);
    check_ok(&pi, ret, last);
    if (ret == XQC_OK) {
        __CPROVER_assert(token_len >= 1 && token_len <= XQC_MAX_TOKEN_LEN,
                         "NEW_TOKEN: token_len in 1..XQC_MAX_TOKEN_LEN");
    }
    free(token);
    release(&pi, conn);
}

void
harness_stream(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    __CPROVER_assume(pi.pos[0] >= 0x08 && pi.pos[0] <= 0x0f);
    xqc_connection_t *conn = mk_conn();
    xqc_stream_frame_t frame;
    memset(&frame, 0, sizeof(frame)); /* xqc_calloc() in the caller */
    xqc_stream_id_t sid;
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_stream_frame(&pi, conn, &frame, &sid);
    check_ok(&pi, ret, last);
    if (ret == XQC_OK) {
        __CPROVER_assert(frame.data_length <= (size_t)(last - g_first),
                         "STREAM: data_length within the packet");
        __CPROVER_assert(frame.data_offset + frame.data_length <= XQC_VINT_MAX,
                         "STREAM: offset + length <= 2^62 - 1");
    }
    free(frame.data);
    release(&pi, conn);
}

void
harness_max_data(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    __CPROVER_assume(pi.pos[0] == 0x10);
    xqc_connection_t *conn = mk_conn();
    uint64_t v;
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_max_data_frame(&pi, &v, conn);
    check_ok(&pi, ret, last);
    release(&pi, conn);
}

void
harness_max_stream_data(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    __CPROVER_assume(pi.pos[0] == 0x11);
    xqc_connection_t *conn = mk_conn();
    xqc_stream_id_t sid;
    uint64_t v;
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_max_stream_data_frame(&pi, &sid, &v, conn);
    check_ok(&pi, ret, last);
    release(&pi, conn);
}

void
harness_max_streams(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    __CPROVER_assume(pi.pos[0] == 0x12 || pi.pos[0] == 0x13);
    xqc_connection_t *conn = mk_conn();
    uint64_t v;
    int bidi;
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_max_streams_frame(&pi, &v, &bidi, conn);
    check_ok(&pi, ret, last);
    release(&pi, conn);
}

void
harness_data_blocked(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    __CPROVER_assume(pi.pos[0] == 0x14);
    xqc_connection_t *conn = mk_conn();
    uint64_t v;
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_data_blocked_frame(&pi, &v, conn);
    check_ok(&pi, ret, last);
    release(&pi, conn);
}

void
harness_stream_data_blocked(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    __CPROVER_assume(pi.pos[0] == 0x15);
    xqc_connection_t *conn = mk_conn();
    xqc_stream_id_t sid;
    uint64_t v;
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_stream_data_blocked_frame(&pi, &sid, &v, conn);
    check_ok(&pi, ret, last);
    release(&pi, conn);
}

void
harness_streams_blocked(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    __CPROVER_assume(pi.pos[0] == 0x16 || pi.pos[0] == 0x17);
    xqc_connection_t *conn = mk_conn();
    uint64_t v;
    int bidi;
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_streams_blocked_frame(&pi, &v, &bidi, conn);
    check_ok(&pi, ret, last);
    release(&pi, conn);
}

void
harness_new_conn_id(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    __CPROVER_assume(pi.pos[0] == 0x18);
    xqc_connection_t *conn = mk_conn();
    xqc_cid_t cid;
    uint64_t rpt;
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_new_conn_id_frame(&pi, &cid, &rpt, conn);
    check_ok(&pi, ret, last);
    if (ret == XQC_OK) {
        __CPROVER_assert(cid.cid_len >= 1 && cid.cid_len <= XQC_MAX_CID_LEN,
                         "NEW_CONNECTION_ID: cid_len in 1..20");
    }
    release(&pi, conn);
}

void
harness_retire_conn_id(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    __CPROVER_assume(pi.pos[0] == 0x19);
    xqc_connection_t *conn = mk_conn();
    uint64_t seq;
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_retire_conn_id_frame(&pi, &seq);
    check_ok(&pi, ret, last);
    release(&pi, conn);
}

void
harness_path_challenge(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    __CPROVER_assume(pi.pos[0] == 0x1a);
    xqc_connection_t *conn = mk_conn();
    unsigned char data[XQC_PATH_CHALLENGE_DATA_LEN];
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_path_challenge_frame(&pi, data);
    check_ok(&pi, ret, last);
    release(&pi, conn);
}

void
harness_path_response(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    __CPROVER_assume(pi.pos[0] == 0x1b);
    xqc_connection_t *conn = mk_conn();
    unsigned char data[XQC_PATH_CHALLENGE_DATA_LEN];
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_path_response_frame(&pi, data);
    check_ok(&pi, ret, last);
    release(&pi, conn);
}

void
harness_conn_close(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    __CPROVER_assume(pi.pos[0] == 0x1c || pi.pos[0] == 0x1d);
    xqc_connection_t *conn = mk_conn();
    uint64_t err;
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_conn_close_frame(&pi, &err, conn);
    check_ok(&pi, ret, last);
    release(&pi, conn);
}

void
harness_datagram(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    __CPROVER_assume(pi.pos[0] == 0x30 || pi.pos[0] == 0x31);
    xqc_connection_t *conn = mk_conn();
    unsigned char *data = NULL;
    size_t size = 0;
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_datagram_frame(&pi, conn, &data, &size);
    check_ok(&pi, ret, last);
    if (ret == XQC_OK) {
        __CPROVER_assert(data >= g_first && data + size <= last,
                         "DATAGRAM: payload within the packet");
    }
    release(&pi, conn);
}

/* ---- multipath (draft-ietf-quic-multipath) frames ------------------------ */

void
harness_ack_mp(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    xqc_connection_t *conn = mk_conn();
    xqc_ack_info_t *ack_info = malloc(sizeof(*ack_info));
    __CPROVER_assume(ack_info != NULL);
    uint64_t path_id;
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_ack_mp_frame(&pi, conn, &path_id, ack_info);
    check_ok(&pi, ret, last);
    if (ret == XQC_OK) {
        __CPROVER_assert(ack_info->n_ranges >= 1
                             && ack_info->n_ranges <= XQC_MAX_ACK_RANGE_CNT,
                         "ACK_MP: n_ranges in 1..XQC_MAX_ACK_RANGE_CNT");
        for (unsigned i = 0;
             i < ack_info->n_ranges && i < XQC_MAX_ACK_RANGE_CNT; i++)
        {
            __CPROVER_assert(ack_info->ranges[i].low
                                 <= ack_info->ranges[i].high,
                             "ACK_MP: every range has low <= high");
            if (i > 0) {
                __CPROVER_assert(ack_info->ranges[i].high + 1
                                     < ack_info->ranges[i - 1].low,
                                 "ACK_MP: ranges descend with a gap");
            }
        }
    }
    free(ack_info);
    release(&pi, conn);
}

void
harness_path_abandon(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    xqc_connection_t *conn = mk_conn();
    uint64_t path_id, err;
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_path_abandon_frame(&pi, &path_id, &err);
    check_ok(&pi, ret, last);
    release(&pi, conn);
}

void
harness_path_status(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    xqc_connection_t *conn = mk_conn();
    uint64_t path_id, seq, status;
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_path_status_frame(&pi, &path_id, &seq, &status);
    check_ok(&pi, ret, last);
    release(&pi, conn);
}

void
harness_mp_new_conn_id(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    xqc_connection_t *conn = mk_conn();
    xqc_cid_t cid;
    uint64_t rpt, path_id;
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_mp_new_conn_id_frame(&pi, &cid, &rpt, &path_id,
                                                   conn);
    check_ok(&pi, ret, last);
    if (ret == XQC_OK) {
        __CPROVER_assert(cid.cid_len >= 1 && cid.cid_len <= XQC_MAX_CID_LEN,
                         "PATH_NEW_CONNECTION_ID: cid_len in 1..20");
    }
    release(&pi, conn);
}

void
harness_mp_retire_conn_id(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    xqc_connection_t *conn = mk_conn();
    uint64_t seq, path_id;
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_mp_retire_conn_id_frame(&pi, &seq, &path_id);
    check_ok(&pi, ret, last);
    release(&pi, conn);
}

void
harness_max_path_id(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    xqc_connection_t *conn = mk_conn();
    uint64_t max_path_id;
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_max_path_id_frame(&pi, &max_path_id);
    check_ok(&pi, ret, last);
    release(&pi, conn);
}

/* ---- FEC frames (XQC_ENABLE_FEC) ---------------------------------------- */
#ifdef XQC_ENABLE_FEC
void
harness_sid(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    xqc_connection_t *conn = mk_conn();
    uint64_t src_payload_id;
    xqc_int_t symbol_size;
    /* the decrypted payload holds this frame */
    __CPROVER_assume(pi.decode_payload_len >= (size_t)(pi.last - pi.pos)
                     && pi.decode_payload_len <= 1500);
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_sid_frame(conn, &pi, &src_payload_id,
                                        &symbol_size);
    check_ok(&pi, ret, last);
    release(&pi, conn);
}

void
harness_repair(void)
{
    xqc_packet_in_t pi;
    mk_packet(&pi, 1);
    xqc_connection_t *conn = mk_conn();
    xqc_fec_rpr_syb_t syb;
    memset(&syb, 0, sizeof(syb)); /* as xqc_process_repair_frame() */
    unsigned char *last = pi.last;
    xqc_int_t ret = xqc_parse_repair_frame(conn, &pi, &syb);
    check_ok(&pi, ret, last);
    if (ret == XQC_OK) {
        /* xqc_process_rpr_symbol() copies these two ranges */
        __CPROVER_assert(syb.repair_key >= g_first
                             && syb.repair_key_size
                                    <= (size_t)(last - syb.repair_key),
                         "REPAIR: repair key within the packet");
        __CPROVER_assert(syb.payload >= g_first
                             && syb.payload_size
                                    <= (size_t)(last - syb.payload),
                         "REPAIR: repair symbol within the packet");
    }
    release(&pi, conn);
}
#endif

/* ---- xqc_vint_read() and the contract the frame parsers rely on ---------- */

/*
 * For any position p in [buf, end] of any buffer: a successful read
 * returns 1, 2, 4 or 8, stays within [p, end) and yields a value below
 * 2^(8 * len - 2) <= 2^62.  stubs/vint_contract.c abstracts xqc_vint_read()
 * to exactly this contract for the harnesses that would otherwise be too
 * large (VINT_CONTRACT builds).
 */
void
harness_vint_read(void)
{
    size_t len;
    unsigned char *buf = cbmc_buf(0, &len);
    size_t off = nondet_size_t();
    __CPROVER_assume(off <= len);
    uint64_t v;
    int r = xqc_vint_read(buf + off, buf + len, &v);
    __CPROVER_assert(r == -1 || r == 1 || r == 2 || r == 4 || r == 8,
                     "vint: result is -1, 1, 2, 4 or 8");
    if (r > 0) {
        __CPROVER_assert(off + (size_t)r <= len,
                         "vint: read within the buffer");
        __CPROVER_assert(v < ((uint64_t)1 << (8 * r - 2)),
                         "vint: value fits its length");
        __CPROVER_assert(r == (1 << (buf[off] >> 6)),
                         "vint: length from the first byte");
    } else {
        __CPROVER_assert(off == len
                             || (size_t)(1 << (buf[off] >> 6)) > len - off,
                         "vint: fails only when the value does not fit");
    }
    free(buf);
}
