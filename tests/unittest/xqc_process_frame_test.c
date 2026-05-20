/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xqc_process_frame_test.h"
#include "xqc_common_test.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_packet_in.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/transport/xqc_conn.h"

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
