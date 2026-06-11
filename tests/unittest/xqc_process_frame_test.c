/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xqc_process_frame_test.h"
#include "xqc_common_test.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_packet_in.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/transport/xqc_conn.h"
#include "xquic/xqc_errno.h"

char XQC_TEST_ILL_FRAME_1[] = {0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
char XQC_TEST_ZERO_LEN_NEW_TOKEN_FRAME[] = {0x07, 0x00};
char XQC_TEST_STREAM_FRAME[] = {0x0a, 0x00, 0x01, 0x00};


static xqc_int_t
xqc_test_parse_stream_frame_inner(unsigned char *frame_buf,
    size_t frame_buf_len,
    xqc_stream_frame_t *frame, xqc_stream_id_t *stream_id,
    xqc_connection_t **conn)
{
    xqc_packet_in_t pi;

    *conn = test_engine_connect();
    CU_ASSERT(*conn != NULL);
    if (*conn == NULL) {
        return XQC_ERROR;
    }

    memset(&pi, 0, sizeof(pi));
    memset(frame, 0, sizeof(*frame));
    pi.pos = frame_buf;
    pi.last = frame_buf + frame_buf_len;

    return xqc_parse_stream_frame(&pi, *conn, frame, stream_id);
}


void
xqc_test_process_frame()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    xqc_packet_in_t packet_in;
    packet_in.pos = XQC_TEST_ILL_FRAME_1;
    packet_in.last = packet_in.pos + sizeof(XQC_TEST_ILL_FRAME_1);
    int ret = xqc_process_frames(conn, &packet_in);
    CU_ASSERT(ret == -XQC_EIGNORE_PKT);

    packet_in.pos = XQC_TEST_ZERO_LEN_NEW_TOKEN_FRAME;
    packet_in.last = packet_in.pos + sizeof(XQC_TEST_ZERO_LEN_NEW_TOKEN_FRAME);
    ret = xqc_process_frames(conn, &packet_in);
    CU_ASSERT(ret == -XQC_EPROTO);

    xqc_packet_in_t pi_stream_init;
    memset(&pi_stream_init, 0, sizeof(xqc_packet_in_t));
    pi_stream_init.pi_pkt.pkt_type = XQC_PTYPE_INIT;
    pi_stream_init.pos = XQC_TEST_STREAM_FRAME;
    pi_stream_init.last = pi_stream_init.pos + sizeof(XQC_TEST_STREAM_FRAME);
    ret = xqc_process_frames(conn, &pi_stream_init);
    CU_ASSERT(ret == -XQC_EPROTO);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_parse_padding_frame()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    char XQC_PURE_PADDING_FRAME[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    xqc_packet_in_t pi_padding;
    memset(&pi_padding, 0, sizeof(xqc_packet_in_t));
    pi_padding.pos = XQC_PURE_PADDING_FRAME;
    pi_padding.last = pi_padding.pos + sizeof(XQC_PURE_PADDING_FRAME);
    int ret = xqc_process_frames(conn, &pi_padding);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(pi_padding.pi_frame_types == XQC_FRAME_BIT_PADDING);

    /* MAX_DATA frame after PADDING frame */
    char XQC_MIXED_PADDING_FRAME[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x3F};
    xqc_packet_in_t pi_padding_mix;
    memset(&pi_padding_mix, 0, sizeof(xqc_packet_in_t));
    pi_padding_mix.pos = XQC_MIXED_PADDING_FRAME;
    pi_padding_mix.last = pi_padding_mix.pos + sizeof(XQC_MIXED_PADDING_FRAME);
    ret = xqc_process_frames(conn, &pi_padding_mix);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(pi_padding_mix.pi_frame_types == (XQC_FRAME_BIT_PADDING | XQC_FRAME_BIT_MAX_DATA));

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_large_ack_frame()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);
    char XQC_ACK_FRAME[] = {0x02,       /* type */ 
                            0x40, 0xFF, /* Largest Acknowledged, 256 */
                            0x00,       /* ACK Delay */
                            0x40, 0x7F, /* ACK range count, 127 */
                            0x00,       /* first ack range */
                            0x00, 0x00, /* gap: 0, range: 0 */
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    xqc_packet_in_t pi_ack;
    memset(&pi_ack, 0, sizeof(xqc_packet_in_t));
    pi_ack.pos = XQC_ACK_FRAME;
    pi_ack.last = pi_ack.pos + sizeof(XQC_ACK_FRAME);

    int ret = xqc_process_frames(conn, &pi_ack);
    CU_ASSERT(pi_ack.pi_frame_types == XQC_FRAME_BIT_ACK);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_stream_frame_offset_overflow()
{
    xqc_connection_t *conn;
    xqc_stream_frame_t frame;
    xqc_stream_id_t stream_id;
    int ret;

    /*
     * STREAM frame: first_byte=0x0e (OFF=1, LEN=1, FIN=0)
     * stream_id=0 (1-byte varint: 0x00)
     * offset = 8-byte varint
     * length = 1-byte varint
     * data = 1 byte (0x00)
     *
     * 8-byte varint: high 2 bits = 0xC0, remaining 62 bits = value
     * (1 << 62) - 1 is encoded as 0xFF FF FF FF FF FF FF FF
     * (1 << 62) - 2 is encoded as 0xFF FF FF FF FF FF FF FE
     */

    /* Case 1: offset=(1 << 62) - 1, length=1 exceeds 2^62 - 1. */
    unsigned char frame_overflow[] = {
        0x0e,                                           /* STREAM + OFF + LEN */
        0x00,                                           /* stream_id = 0 */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* offset = (1<<62)-1 */
        0x01,                                           /* length = 1 */
        0x00                                            /* 1 byte data */
    };
    ret = xqc_test_parse_stream_frame_inner(frame_overflow,
                                            sizeof(frame_overflow), &frame,
                                            &stream_id, &conn);
    CU_ASSERT(ret == -XQC_EILLEGAL_FRAME);
    CU_ASSERT(conn->conn_err == TRA_FRAME_ENCODING_ERROR);
    xqc_engine_destroy(conn->engine);

    /* Case 2: offset=(1 << 62) - 2, length=1 reaches the boundary. */
    unsigned char frame_boundary[] = {
        0x0e,
        0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, /* offset = (1<<62)-2 */
        0x01,                                           /* length = 1 */
        0x00                                            /* 1 byte data */
    };
    ret = xqc_test_parse_stream_frame_inner(frame_boundary,
                                            sizeof(frame_boundary), &frame,
                                            &stream_id, &conn);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream_id == 0);
    CU_ASSERT(frame.data_offset == ((UINT64_C(1) << 62) - 2));
    CU_ASSERT(frame.data_length == 1);
    CU_ASSERT(conn->conn_err == 0);
    xqc_free(frame.data);
    xqc_engine_destroy(conn->engine);

    /* Case 3: offset=(1 << 62) - 1, length=0 reaches the boundary. */
    unsigned char frame_zero_len[] = {
        0x0e,
        0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x00,                                           /* length = 0 */
    };
    ret = xqc_test_parse_stream_frame_inner(frame_zero_len,
                                            sizeof(frame_zero_len), &frame,
                                            &stream_id, &conn);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream_id == 0);
    CU_ASSERT(frame.data_offset == ((UINT64_C(1) << 62) - 1));
    CU_ASSERT(frame.data_length == 0);
    CU_ASSERT(conn->conn_err == 0);
    xqc_engine_destroy(conn->engine);

    /* Case 4: implicit length can also reach the boundary. */
    unsigned char frame_implicit_boundary[] = {
        0x0c,                                           /* STREAM + OFF */
        0x00,                                           /* stream_id = 0 */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0x00                                            /* 1 byte data */
    };
    ret = xqc_test_parse_stream_frame_inner(frame_implicit_boundary,
                                            sizeof(frame_implicit_boundary),
                                            &frame, &stream_id, &conn);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream_id == 0);
    CU_ASSERT(frame.data_offset == ((UINT64_C(1) << 62) - 2));
    CU_ASSERT(frame.data_length == 1);
    CU_ASSERT(conn->conn_err == 0);
    xqc_free(frame.data);
    xqc_engine_destroy(conn->engine);

    /* Case 5: implicit length, offset=(1 << 62) - 1, 1 byte data. */
    unsigned char frame_implicit_overflow[] = {
        0x0c,                                           /* STREAM + OFF */
        0x00,                                           /* stream_id = 0 */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x00                                            /* 1 byte data */
    };
    ret = xqc_test_parse_stream_frame_inner(frame_implicit_overflow,
                                            sizeof(frame_implicit_overflow),
                                            &frame, &stream_id, &conn);
    CU_ASSERT(ret == -XQC_EILLEGAL_FRAME);
    CU_ASSERT(conn->conn_err == TRA_FRAME_ENCODING_ERROR);
    xqc_engine_destroy(conn->engine);
}


/*
 * Helpers for the RFC 9001 8.3 CRYPTO-in-0-RTT regression tests.
 *
 * Each helper builds a fresh connection plus a packet_in that carries a
 * minimal but parseable CRYPTO frame body. The CRYPTO body is laid out so
 * that, when the new packet-type guard is bypassed (i.e. for INIT / HSK /
 * 1-RTT), xqc_parse_crypto_frame succeeds and any subsequent failures stem
 * from missing handshake state rather than from frame validation. That lets
 * us assert "guard not taken" without depending on full crypto-stream setup.
 *
 * CRYPTO frame layout (RFC 9000 19.6): type=0x06, offset=0, length=0.
 */
static unsigned char XQC_TEST_CRYPTO_FRAME_EMPTY[] = {0x06, 0x00, 0x00};


static void
xqc_test_crypto_frame_setup(xqc_connection_t **conn, xqc_packet_in_t *pi,
    xqc_pkt_type_t pkt_type)
{
    *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(*conn);

    memset(pi, 0, sizeof(*pi));
    pi->pi_pkt.pkt_type = pkt_type;
    pi->pos = XQC_TEST_CRYPTO_FRAME_EMPTY;
    pi->last = pi->pos + sizeof(XQC_TEST_CRYPTO_FRAME_EMPTY);
}


void
xqc_test_crypto_frame_in_0rtt_rejected()
{
    xqc_connection_t *conn;
    xqc_packet_in_t pi;
    xqc_int_t ret;

    xqc_test_crypto_frame_setup(&conn, &pi, XQC_PTYPE_0RTT);

    ret = xqc_process_crypto_frame(conn, &pi);

    /* RFC 9001 8.3: PROTOCOL_VIOLATION on CRYPTO in 0-RTT. */
    CU_ASSERT(ret == -XQC_EPROTO);
    CU_ASSERT(conn->conn_err == TRA_PROTOCOL_VIOLATION);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);

    /*
     * The guard MUST run before the frame-type bit is recorded, otherwise
     * a malformed 0-RTT packet could leave residual state behind.
     */
    CU_ASSERT((pi.pi_frame_types & XQC_FRAME_BIT_CRYPTO) == 0);

    /* Parser must not have advanced; the buffer is untouched. */
    CU_ASSERT(pi.pos == XQC_TEST_CRYPTO_FRAME_EMPTY);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_crypto_frame_in_initial_accepted()
{
    xqc_connection_t *conn;
    xqc_packet_in_t pi;
    xqc_int_t ret;

    xqc_test_crypto_frame_setup(&conn, &pi, XQC_PTYPE_INIT);

    ret = xqc_process_crypto_frame(conn, &pi);

    /*
     * The guard must not fire for Initial packets. Whatever the rest of
     * xqc_process_crypto_frame does in unit-test isolation, it must NOT
     * short-circuit with PROTOCOL_VIOLATION and must NOT set FLAG_ERROR.
     */
    CU_ASSERT(ret != -XQC_EPROTO);
    CU_ASSERT(conn->conn_err != TRA_PROTOCOL_VIOLATION);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) == 0);

    /* The post-guard line that records the frame bit must have executed. */
    CU_ASSERT((pi.pi_frame_types & XQC_FRAME_BIT_CRYPTO) != 0);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_crypto_frame_in_handshake_accepted()
{
    xqc_connection_t *conn;
    xqc_packet_in_t pi;
    xqc_int_t ret;

    xqc_test_crypto_frame_setup(&conn, &pi, XQC_PTYPE_HSK);

    ret = xqc_process_crypto_frame(conn, &pi);

    CU_ASSERT(ret != -XQC_EPROTO);
    CU_ASSERT(conn->conn_err != TRA_PROTOCOL_VIOLATION);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) == 0);
    CU_ASSERT((pi.pi_frame_types & XQC_FRAME_BIT_CRYPTO) != 0);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_crypto_frame_in_short_header_accepted()
{
    xqc_connection_t *conn;
    xqc_packet_in_t pi;
    xqc_int_t ret;

    /*
     * RFC 9001 4.1.3 explicitly permits CRYPTO frames in 1-RTT packets for
     * post-handshake key updates and NEW_SESSION_TICKET delivery. The guard
     * must therefore not fire for XQC_PTYPE_SHORT_HEADER.
     */
    xqc_test_crypto_frame_setup(&conn, &pi, XQC_PTYPE_SHORT_HEADER);

    ret = xqc_process_crypto_frame(conn, &pi);

    CU_ASSERT(ret != -XQC_EPROTO);
    CU_ASSERT(conn->conn_err != TRA_PROTOCOL_VIOLATION);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) == 0);
    CU_ASSERT((pi.pi_frame_types & XQC_FRAME_BIT_CRYPTO) != 0);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_crypto_frame_dispatched_via_xqc_process_frame()
{
    xqc_connection_t *conn;
    xqc_packet_in_t pi;
    xqc_int_t ret;

    /*
     * End-to-end check that the dispatcher path (xqc_process_frames ->
     * frame_type 0x06 case) also rejects, not just direct calls to
     * xqc_process_crypto_frame.
     */
    xqc_test_crypto_frame_setup(&conn, &pi, XQC_PTYPE_0RTT);

    ret = xqc_process_frames(conn, &pi);

    CU_ASSERT(ret == -XQC_EPROTO);
    CU_ASSERT(conn->conn_err == TRA_PROTOCOL_VIOLATION);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);
    CU_ASSERT((pi.pi_frame_types & XQC_FRAME_BIT_CRYPTO) == 0);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_crypto_in_0rtt_emits_connection_close()
{
    xqc_connection_t *conn;
    xqc_packet_in_t pi;
    xqc_int_t ret;

    xqc_test_crypto_frame_setup(&conn, &pi, XQC_PTYPE_0RTT);

    ret = xqc_process_crypto_frame(conn, &pi);
    CU_ASSERT(ret == -XQC_EPROTO);

    /*
     * XQC_CONN_ERR is the canonical entry point for emitting CONNECTION_CLOSE
     * with a transport error. It must have:
     *   1. recorded conn_err = TRA_PROTOCOL_VIOLATION (0x0a)
     *   2. set XQC_CONN_FLAG_ERROR so the connection enters the immediate
     *      close path (XQC_CONN_IMMEDIATE_CLOSE_FLAGS includes FLAG_ERROR)
     *   3. driven the connection out of the normal (non-closing) state via
     *      xqc_conn_closing()
     *
     * That triple is the contract under which the engine emits a
     * CONNECTION_CLOSE frame on the next write opportunity.
     */
    CU_ASSERT(conn->conn_err == TRA_PROTOCOL_VIOLATION);
    CU_ASSERT((uint64_t)conn->conn_err == 0x0a);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);
    CU_ASSERT((conn->conn_flag & XQC_CONN_IMMEDIATE_CLOSE_FLAGS) != 0);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_CLOSING_NOTIFY) != 0);

    xqc_engine_destroy(conn->engine);
}


/*
 * ACK_ECN frame parsing tests for issue #632.
 *
 * RFC 9000 Section 19.3 defines ACK_ECN (type=0x03) as an ACK frame
 * followed by three additional varint fields: ECT(0) Count, ECT(1)
 * Count, and ECN-CE Count.  Before the fix, xqc_parse_ack_frame did
 * not consume these fields, so packet_in->pos pointed into the ECN
 * data rather than past it, corrupting subsequent frame parsing.
 *
 * All buffers below are hand-crafted byte sequences.  Single-byte
 * varints (value 0-63) are used everywhere for simplicity; the
 * varint encoding is already tested elsewhere.
 *
 * Minimal ACK / ACK_ECN layout used in these tests:
 *   type           : 1 byte  (0x02 or 0x03)
 *   largest_acked  : 1 byte  varint
 *   ack_delay      : 1 byte  varint
 *   ack_range_count: 1 byte  varint (0 = no additional ranges)
 *   first_ack_range: 1 byte  varint
 *   --- ACK_ECN only ---
 *   ect0_count     : 1 byte  varint
 *   ect1_count     : 1 byte  varint
 *   ecnce_count    : 1 byte  varint
 */


/*
 * Test A: ACK_ECN (type=0x03) with valid ECN fields parses correctly
 * and consumes the entire frame including the three ECN count fields.
 */
void
xqc_test_ack_ecn_normal_parse()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    /*
     * ACK_ECN frame:
     *   0x03  type = ACK_ECN
     *   0x0A  largest_acked = 10
     *   0x00  ack_delay = 0
     *   0x00  ack_range_count = 0
     *   0x05  first_ack_range = 5  (acks 10..5)
     *   0x03  ECT(0) count = 3
     *   0x02  ECT(1) count = 2
     *   0x01  ECN-CE count = 1
     */
    unsigned char buf[] = {
        0x03,
        0x0A, 0x00, 0x00, 0x05,
        0x03, 0x02, 0x01
    };

    xqc_packet_in_t pi;
    memset(&pi, 0, sizeof(pi));
    pi.pos = buf;
    pi.last = buf + sizeof(buf);

    xqc_ack_info_t ack_info;
    memset(&ack_info, 0, sizeof(ack_info));

    xqc_int_t ret = xqc_parse_ack_frame(&pi, conn, &ack_info);
    CU_ASSERT(ret == XQC_OK);

    /* parser must have consumed the entire buffer */
    CU_ASSERT(pi.pos == buf + sizeof(buf));

    /* verify ACK semantics are correct */
    CU_ASSERT(ack_info.n_ranges == 1);
    CU_ASSERT(ack_info.largest_acked == 10);
    CU_ASSERT(ack_info.ranges[0].high == 10);
    CU_ASSERT(ack_info.ranges[0].low == 5);

    /* frame type bit must be recorded */
    CU_ASSERT((pi.pi_frame_types & XQC_FRAME_BIT_ACK) != 0);

    xqc_engine_destroy(conn->engine);
}


/*
 * Test B: Plain ACK (type=0x02) must not read ECN fields -- regression.
 *
 * We append garbage bytes after the ACK body.  If the parser
 * incorrectly tried to read ECN fields for type 0x02, pos would
 * advance into the garbage and the consumed length would be wrong.
 */
void
xqc_test_ack_plain_regression()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    /*
     * ACK frame (type=0x02):
     *   0x02  type = ACK
     *   0x0A  largest_acked = 10
     *   0x00  ack_delay = 0
     *   0x00  ack_range_count = 0
     *   0x05  first_ack_range = 5
     * Followed by 3 bytes of trailing data (simulating a next frame).
     */
    unsigned char buf[] = {
        0x02,
        0x0A, 0x00, 0x00, 0x05,
        0xAA, 0xBB, 0xCC   /* trailing -- must NOT be consumed */
    };

    xqc_packet_in_t pi;
    memset(&pi, 0, sizeof(pi));
    pi.pos = buf;
    pi.last = buf + sizeof(buf);

    xqc_ack_info_t ack_info;
    memset(&ack_info, 0, sizeof(ack_info));

    xqc_int_t ret = xqc_parse_ack_frame(&pi, conn, &ack_info);
    CU_ASSERT(ret == XQC_OK);

    /* parser must stop right after the ACK body (5 bytes), not touch trailing */
    CU_ASSERT(pi.pos == buf + 5);

    CU_ASSERT(ack_info.n_ranges == 1);
    CU_ASSERT(ack_info.largest_acked == 10);
    CU_ASSERT((pi.pi_frame_types & XQC_FRAME_BIT_ACK) != 0);

    xqc_engine_destroy(conn->engine);
}


/*
 * Test C: ACK_ECN with truncated ECN fields must return error.
 *
 * Buffer holds a valid ACK body for type=0x03 but cuts off before
 * all three ECN count fields can be read.
 */
void
xqc_test_ack_ecn_truncated()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    /*
     * ACK_ECN frame, but only 1 of 3 ECN fields present:
     *   0x03  type = ACK_ECN
     *   0x0A  largest_acked = 10
     *   0x00  ack_delay = 0
     *   0x00  ack_range_count = 0
     *   0x05  first_ack_range = 5
     *   0x03  ECT(0) count = 3  -- present
     *          ECT(1) -- MISSING
     *          ECN-CE -- MISSING
     */
    unsigned char buf[] = {
        0x03,
        0x0A, 0x00, 0x00, 0x05,
        0x03
    };

    xqc_packet_in_t pi;
    memset(&pi, 0, sizeof(pi));
    pi.pos = buf;
    pi.last = buf + sizeof(buf);

    xqc_ack_info_t ack_info;
    memset(&ack_info, 0, sizeof(ack_info));

    xqc_int_t ret = xqc_parse_ack_frame(&pi, conn, &ack_info);
    CU_ASSERT(ret == -XQC_EVINTREAD);

    xqc_engine_destroy(conn->engine);
}


/*
 * Test D: ACK_ECN followed by a PING frame -- the core issue scenario.
 *
 * Before the fix, xqc_parse_ack_frame left pos pointing at the ECN
 * fields.  When xqc_process_frames continued to read the "next frame",
 * it would interpret ECN data as a frame type, resulting in garbage
 * parsing.  After the fix, pos must land exactly on the PING byte.
 */
void
xqc_test_ack_ecn_followed_by_ping()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    /*
     * ACK_ECN frame + PING frame:
     *   0x03  type = ACK_ECN
     *   0x0A  largest_acked = 10
     *   0x00  ack_delay = 0
     *   0x00  ack_range_count = 0
     *   0x05  first_ack_range = 5
     *   0x03  ECT(0) count = 3
     *   0x02  ECT(1) count = 2
     *   0x01  ECN-CE count = 1
     *   0x01  PING frame (type=0x01)
     */
    unsigned char buf[] = {
        0x03,
        0x0A, 0x00, 0x00, 0x05,
        0x03, 0x02, 0x01,
        0x01   /* PING */
    };

    xqc_packet_in_t pi;
    memset(&pi, 0, sizeof(pi));
    pi.pos = buf;
    pi.last = buf + sizeof(buf);

    xqc_ack_info_t ack_info;
    memset(&ack_info, 0, sizeof(ack_info));

    xqc_int_t ret = xqc_parse_ack_frame(&pi, conn, &ack_info);
    CU_ASSERT(ret == XQC_OK);

    /* pos must point at the PING byte, i.e. buf + 8 */
    CU_ASSERT(pi.pos == buf + 8);

    /* verify the byte at pos is indeed PING type */
    CU_ASSERT(*pi.pos == 0x01);

    /* parse the remaining buffer via xqc_process_frames for full E2E check */
    int ret2 = xqc_process_frames(conn, &pi);
    CU_ASSERT(ret2 == XQC_OK);
    CU_ASSERT((pi.pi_frame_types & XQC_FRAME_BIT_ACK) != 0);
    CU_ASSERT((pi.pi_frame_types & XQC_FRAME_BIT_PING) != 0);

    /* pos must now be at the very end */
    CU_ASSERT(pi.pos == buf + sizeof(buf));

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_new_conn_id_zero_len_cid(void)
{
    /*
     * RFC 9000 §19.15: CID Length < 1 or > 20 MUST trigger
     * FRAME_ENCODING_ERROR.  Build a NEW_CONNECTION_ID frame
     * with Length = 0 and verify the parser rejects it.
     *
     * Frame layout:
     *   Type       = 0x18 (1 byte)
     *   SeqNum     = 0x01 (1 byte varint)
     *   RetirePT   = 0x00 (1 byte varint)
     *   Length     = 0x00 (1 byte — invalid!)
     *   CID        = (none, 0 bytes)
     *   SR Token   = 16 bytes of 0xAA
     */
    unsigned char frame_buf[64];
    unsigned char *p = frame_buf;
    *p++ = 0x18;  /* type */
    *p++ = 0x01;  /* sequence number = 1 */
    *p++ = 0x00;  /* retire prior to = 0 */
    *p++ = 0x00;  /* length = 0 (invalid) */
    /* no CID bytes */
    memset(p, 0xAA, 16);  /* stateless reset token */
    p += 16;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);
    if (conn == NULL) {
        return;
    }

    xqc_packet_in_t pi;
    memset(&pi, 0, sizeof(pi));
    pi.pos = frame_buf + 1;  /* skip type byte, parser starts after type */
    pi.last = p;
    pi.pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;

    xqc_cid_t new_cid;
    uint64_t retire_prior_to = 0;
    xqc_int_t ret = xqc_parse_new_conn_id_frame(&pi, &new_cid, &retire_prior_to, conn);
    CU_ASSERT(ret != XQC_OK);
    CU_ASSERT(conn->conn_err == TRA_FRAME_ENCODING_ERROR);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_stream_frame_on_send_only_stream(void)
{
    /*
     * RFC 9000 §19.8: receiving a STREAM frame on a send-only stream
     * must trigger STREAM_STATE_ERROR.
     *
     * test_engine_connect() creates a CLIENT connection.
     * stream_id=2 → XQC_CLI_UNI → client's send-only unidirectional stream.
     * Frame bytes (after type byte): 0x02 (stream_id=2), 0x01 (len=1), 0x00 (data).
     * Type byte 0x0a = STREAM|LEN, consumed by xqc_process_frames before dispatch.
     */
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);
    if (conn == NULL) {
        return;
    }

    conn->conn_err = 0;

    /* build packet_in with STREAM frame type 0x0a, stream_id=2 */
    char frame_buf[] = {0x0a, 0x02, 0x01, 0x00};
    xqc_packet_in_t pi;
    memset(&pi, 0, sizeof(pi));
    pi.pos = frame_buf;
    pi.last = frame_buf + sizeof(frame_buf);
    pi.pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;

    /* call xqc_process_stream_frame directly; it expects pos at the type byte */
    xqc_int_t ret = xqc_process_stream_frame(conn, &pi);
    CU_ASSERT(ret == -XQC_EPROTO);
    CU_ASSERT(conn->conn_err == TRA_STREAM_STATE_ERROR);

    xqc_engine_destroy(conn->engine);
}
