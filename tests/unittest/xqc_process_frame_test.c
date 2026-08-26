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
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_stream.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/transport/xqc_conn.h"
#include "xquic/xqc_errno.h"

char XQC_TEST_ILL_FRAME_1[] = {0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
char XQC_TEST_ZERO_LEN_NEW_TOKEN_FRAME[] = {0x07, 0x00};
char XQC_TEST_STREAM_FRAME[] = {0x0a, 0x00, 0x01, 0x00};

static void xqc_test_conn_close_error_type(unsigned char *frame,
    size_t frame_len, xqc_conn_err_type_t expected_type);
static void xqc_test_conn_close_frame_accepted(unsigned char *frame,
    size_t frame_len, xqc_pkt_type_t pkt_type, xqc_conn_type_t conn_type,
    xqc_conn_err_type_t expected_type);
static void xqc_test_conn_close_app_error_rejected(xqc_pkt_type_t pkt_type);
static void xqc_test_ack_range_rejected(unsigned char *frame,
    size_t frame_len);


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


#ifdef XQC_PING_ATTACK_PROTECT
static xqc_connection_t *xqc_test_server_initial_connection(void);


static xqc_connection_t *
xqc_test_server_initial_connection(void)
{
    xqc_connection_t *conn = test_engine_connect();

    CU_ASSERT(conn != NULL);
    if (conn == NULL) {
        return NULL;
    }

    conn->conn_type = XQC_CONN_TYPE_SERVER;
    conn->conn_state = XQC_CONN_STATE_SERVER_INIT;
    conn->conn_flag &= ~XQC_CONN_FLAG_INIT_RECVD;

    return conn;
}


void
xqc_test_initial_ping_before_crypto_accepted(void)
{
    unsigned char frames[] = {
        0x00,                   /* PADDING */
        0x01,                   /* PING */
        0x00,                   /* PADDING */
        0x06, 0x00, 0x00       /* CRYPTO, offset 0, length 0 */
    };
    xqc_connection_t *conn;
    xqc_packet_in_t packet_in;
    xqc_int_t ret;

    conn = xqc_test_server_initial_connection();
    if (conn == NULL) {
        return;
    }

    memset(&packet_in, 0, sizeof(packet_in));
    packet_in.pi_pkt.pkt_type = XQC_PTYPE_INIT;
    packet_in.pos = frames;
    packet_in.last = frames + sizeof(frames);

    ret = xqc_process_frames(conn, &packet_in);

    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(packet_in.pos == packet_in.last);
    CU_ASSERT((packet_in.pi_frame_types & XQC_FRAME_BIT_PING) != 0);
    CU_ASSERT((packet_in.pi_frame_types & XQC_FRAME_BIT_CRYPTO) != 0);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_INIT_RECVD) != 0);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_initial_ping_without_crypto_rejected(void)
{
    unsigned char frames[] = {
        0x00,                   /* PADDING */
        0x01,                   /* PING */
        0x00                    /* PADDING */
    };
    xqc_connection_t *conn;
    xqc_packet_in_t packet_in;
    xqc_int_t ret;

    conn = xqc_test_server_initial_connection();
    if (conn == NULL) {
        return;
    }

    memset(&packet_in, 0, sizeof(packet_in));
    packet_in.pi_pkt.pkt_type = XQC_PTYPE_INIT;
    packet_in.pos = frames;
    packet_in.last = frames + sizeof(frames);

    ret = xqc_process_frames(conn, &packet_in);

    CU_ASSERT(ret == XQC_ERROR);
    CU_ASSERT(packet_in.pos == packet_in.last);
    CU_ASSERT((packet_in.pi_frame_types & XQC_FRAME_BIT_PING) != 0);
    CU_ASSERT((packet_in.pi_frame_types & XQC_FRAME_BIT_CRYPTO) == 0);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_INIT_RECVD) == 0);

    xqc_engine_destroy(conn->engine);
}
#endif

static void
xqc_test_conn_close_error_type(unsigned char *frame, size_t frame_len,
    xqc_conn_err_type_t expected_type)
{
    unsigned char application_frame[] = {
        0x1d, 0x41, 0x02, 0x00
    };
    unsigned char transport_frame[] = {
        0x1c, 0x41, 0x02, 0x01, 0x00
    };
    xqc_connection_t *conn;
    xqc_packet_in_t packet_in;
    unsigned char *second_frame;
    size_t second_frame_len;
    uint64_t err_code;
    xqc_int_t ret;

    conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    memset(&packet_in, 0, sizeof(packet_in));
    packet_in.pos = frame;
    packet_in.last = frame + frame_len;

    CU_ASSERT(xqc_conn_get_err_type(conn) == XQC_CONN_ERR_TYPE_UNKNOWN);

    ret = xqc_parse_conn_close_frame(&packet_in, &err_code, conn);

    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(err_code == H3_INTERNAL_ERROR);
    CU_ASSERT(packet_in.pos == packet_in.last);
    CU_ASSERT(xqc_conn_get_err_type(conn) == expected_type);

    /*
     * CONNECTION_CLOSE can be retransmitted. Preserve the namespace of the
     * first received frame so it remains aligned with first-write-wins error
     * reporting.
     */
    if (expected_type == XQC_CONN_ERR_TYPE_APPLICATION) {
        second_frame = transport_frame;
        second_frame_len = sizeof(transport_frame);

    } else {
        second_frame = application_frame;
        second_frame_len = sizeof(application_frame);
    }

    memset(&packet_in, 0, sizeof(packet_in));
    packet_in.pos = second_frame;
    packet_in.last = second_frame + second_frame_len;
    ret = xqc_parse_conn_close_frame(&packet_in, &err_code, conn);

    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(packet_in.pos == packet_in.last);
    CU_ASSERT(xqc_conn_get_err_type(conn) == expected_type);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_conn_close_application_error_type(void)
{
    unsigned char frame[] = {
        0x1d, 0x41, 0x02, 0x00
    };

    xqc_test_conn_close_error_type(frame, sizeof(frame),
                                   XQC_CONN_ERR_TYPE_APPLICATION);
}

void
xqc_test_conn_close_transport_error_type_overlap(void)
{
    unsigned char frame[] = {
        0x1c, 0x41, 0x02, 0x01, 0x00
    };

    /*
     * 0x102 is both a transport CRYPTO_ERROR value and
     * H3_INTERNAL_ERROR. The 0x1c frame type is the only reliable
     * discriminator.
     */
    xqc_test_conn_close_error_type(frame, sizeof(frame),
                                   XQC_CONN_ERR_TYPE_TRANSPORT);
}


static void
xqc_test_conn_close_frame_accepted(unsigned char *frame, size_t frame_len,
    xqc_pkt_type_t pkt_type, xqc_conn_type_t conn_type,
    xqc_conn_err_type_t expected_type)
{
    xqc_connection_t *conn;
    xqc_packet_in_t packet_in;
    xqc_int_t ret;

    conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    conn->conn_type = conn_type;

    memset(&packet_in, 0, sizeof(packet_in));
    packet_in.pi_pkt.pkt_type = pkt_type;
    packet_in.pos = frame;
    packet_in.last = frame + frame_len;

    ret = xqc_process_frames(conn, &packet_in);

    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT(packet_in.pos == packet_in.last);
    CU_ASSERT_EQUAL(packet_in.pi_frame_types,
                    XQC_FRAME_BIT_CONNECTION_CLOSE);
    CU_ASSERT_EQUAL(xqc_conn_get_err_type(conn), expected_type);
    CU_ASSERT_EQUAL(conn->conn_state, XQC_CONN_STATE_DRAINING);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_conn_close_valid_packet_types(void)
{
    unsigned char transport_frame[] = {0x1c, 0x00, 0x00, 0x00};
    unsigned char application_frame[] = {0x1d, 0x00, 0x00};

    xqc_test_conn_close_frame_accepted(transport_frame,
        sizeof(transport_frame), XQC_PTYPE_INIT, XQC_CONN_TYPE_CLIENT,
        XQC_CONN_ERR_TYPE_TRANSPORT);
    xqc_test_conn_close_frame_accepted(transport_frame,
        sizeof(transport_frame), XQC_PTYPE_HSK, XQC_CONN_TYPE_CLIENT,
        XQC_CONN_ERR_TYPE_TRANSPORT);
    xqc_test_conn_close_frame_accepted(application_frame,
        sizeof(application_frame), XQC_PTYPE_0RTT, XQC_CONN_TYPE_SERVER,
        XQC_CONN_ERR_TYPE_APPLICATION);
    xqc_test_conn_close_frame_accepted(application_frame,
        sizeof(application_frame), XQC_PTYPE_SHORT_HEADER,
        XQC_CONN_TYPE_CLIENT, XQC_CONN_ERR_TYPE_APPLICATION);
}


static void
xqc_test_conn_close_app_error_rejected(xqc_pkt_type_t pkt_type)
{
    unsigned char frame[] = {0x1d, 0x00, 0x00};
    xqc_connection_t *conn;
    xqc_packet_in_t packet_in;
    xqc_int_t ret;

    conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    memset(&packet_in, 0, sizeof(packet_in));
    packet_in.pi_pkt.pkt_type = pkt_type;
    packet_in.pos = frame;
    packet_in.last = frame + sizeof(frame);

    ret = xqc_process_frames(conn, &packet_in);

    CU_ASSERT_EQUAL(ret, -XQC_EPROTO);
    CU_ASSERT_EQUAL(conn->conn_err, TRA_PROTOCOL_VIOLATION);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);
    CU_ASSERT_EQUAL(xqc_conn_get_err_type(conn), XQC_CONN_ERR_TYPE_UNKNOWN);
    CU_ASSERT_EQUAL(packet_in.pi_frame_types, 0);
    CU_ASSERT(packet_in.pos == frame);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_conn_close_app_error_in_handshake_rejected(void)
{
    xqc_test_conn_close_app_error_rejected(XQC_PTYPE_INIT);
    xqc_test_conn_close_app_error_rejected(XQC_PTYPE_HSK);
}


void
xqc_test_peer_key_update_error_not_0rtt(void)
{
    unsigned char frame[] = {
        0x1c, 0x0e, 0x00, 0x00
    };
    xqc_connection_t *conn;
    xqc_packet_in_t packet_in;
    xqc_int_t ret;

    conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    memset(&packet_in, 0, sizeof(packet_in));
    packet_in.pos = frame;
    packet_in.last = frame + sizeof(frame);

    ret = xqc_process_conn_close_frame(conn, &packet_in);

    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(conn->conn_err, TRA_KEY_UPDATE_ERROR);
    CU_ASSERT_EQUAL(xqc_conn_get_err_type(conn),
                    XQC_CONN_ERR_TYPE_TRANSPORT);
    CU_ASSERT_FALSE(xqc_conn_should_clear_0rtt_ticket(conn->conn_err));

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
xqc_test_ack_range_zero_boundary()
{
    unsigned char frame[] = {
        0x02,       /* ACK */
        0x0a,       /* largest acknowledged = 10 */
        0x00,       /* ACK delay */
        0x02,       /* ACK range count = 2 */
        0x02,       /* first ACK range: 10..8 */
        0x01, 0x02, /* gap = 1, ACK range: 5..3 */
        0x01, 0x00  /* gap = 1, ACK range: 0..0 */
    };
    xqc_connection_t *conn;
    xqc_packet_in_t packet_in;
    xqc_ack_info_t ack_info;
    xqc_int_t ret;

    conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    memset(&packet_in, 0, sizeof(packet_in));
    memset(&ack_info, 0, sizeof(ack_info));
    packet_in.pos = frame;
    packet_in.last = frame + sizeof(frame);

    ret = xqc_parse_ack_frame(&packet_in, conn, &ack_info);

    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(ack_info.n_ranges, 3);
    CU_ASSERT_EQUAL(ack_info.ranges[0].high, 10);
    CU_ASSERT_EQUAL(ack_info.ranges[0].low, 8);
    CU_ASSERT_EQUAL(ack_info.ranges[1].high, 5);
    CU_ASSERT_EQUAL(ack_info.ranges[1].low, 3);
    CU_ASSERT_EQUAL(ack_info.ranges[2].high, 0);
    CU_ASSERT_EQUAL(ack_info.ranges[2].low, 0);
    CU_ASSERT(packet_in.pos == packet_in.last);
    CU_ASSERT((packet_in.pi_frame_types & XQC_FRAME_BIT_ACK) != 0);

    xqc_engine_destroy(conn->engine);
}


static void
xqc_test_ack_range_rejected(unsigned char *frame, size_t frame_len)
{
    xqc_connection_t *conn;
    xqc_packet_in_t packet_in;
    xqc_ack_info_t ack_info;
    xqc_int_t ret;

    conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    memset(&packet_in, 0, sizeof(packet_in));
    memset(&ack_info, 0, sizeof(ack_info));
    packet_in.pos = frame;
    packet_in.last = frame + frame_len;

    ret = xqc_parse_ack_frame(&packet_in, conn, &ack_info);

    CU_ASSERT_EQUAL(ret, -XQC_EILLEGAL_FRAME);
    CU_ASSERT_EQUAL(conn->conn_err, TRA_FRAME_ENCODING_ERROR);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);
    CU_ASSERT_EQUAL(packet_in.pi_frame_types & XQC_FRAME_BIT_ACK, 0);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_ack_range_negative_rejected()
{
    unsigned char first_range[] = {
        0x02, 0x00, 0x00, 0x00, 0x01
    };
    unsigned char gap[] = {
        0x02, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00
    };
    unsigned char range[] = {
        0x02, 0x03, 0x00, 0x01, 0x00, 0x00, 0x02
    };
    unsigned char after_storage_limit[135];
    unsigned char *p;

    xqc_test_ack_range_rejected(first_range, sizeof(first_range));
    xqc_test_ack_range_rejected(gap, sizeof(gap));
    xqc_test_ack_range_rejected(range, sizeof(range));

    p = after_storage_limit;
    *p++ = 0x02;       /* ACK */
    *p++ = 0x40;
    *p++ = 0x7f;       /* largest acknowledged = 127 */
    *p++ = 0x00;       /* ACK delay */
    *p++ = 0x40;
    *p++ = 0x40;       /* ACK range count = 64 */
    *p++ = 0x00;       /* first ACK range */
    for (int i = 0; i < 64; ++i) {
        *p++ = 0x00;   /* gap */
        *p++ = 0x00;   /* ACK range length */
    }

    CU_ASSERT_EQUAL(p - after_storage_limit,
                    sizeof(after_storage_limit));
    xqc_test_ack_range_rejected(after_storage_limit,
                                sizeof(after_storage_limit));
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
xqc_test_gen_new_conn_id_frame_min_cid(void)
{
    xqc_packet_out_t *packet_out;
    xqc_cid_t cid;
    uint8_t sr_token[XQC_STATELESS_RESET_TOKENLEN] = {0};
    ssize_t ret;

    packet_out = xqc_packet_out_create(XQC_QUIC_MAX_MSS);
    CU_ASSERT(packet_out != NULL);
    if (packet_out == NULL) {
        return;
    }

    memset(&cid, 0, sizeof(cid));
    cid.cid_len = 1;
    cid.cid_seq_num = 1;
    cid.cid_buf[0] = 0xa5;

    ret = xqc_gen_new_conn_id_frame(packet_out, &cid, 0, sr_token);

    CU_ASSERT(ret == 5 + XQC_STATELESS_RESET_TOKENLEN);
    CU_ASSERT(packet_out->po_buf[0] == 0x18);
    CU_ASSERT(packet_out->po_buf[1] == 0x01);
    CU_ASSERT(packet_out->po_buf[2] == 0x00);
    CU_ASSERT(packet_out->po_buf[3] == 0x01);
    CU_ASSERT(packet_out->po_buf[4] == 0xa5);
    CU_ASSERT(packet_out->po_frame_types
              == XQC_FRAME_BIT_NEW_CONNECTION_ID);

    xqc_packet_out_destroy(packet_out);
}


void
xqc_test_gen_new_conn_id_frame_zero_cid(void)
{
    xqc_packet_out_t *packet_out;
    xqc_cid_t cid;
    uint8_t sr_token[XQC_STATELESS_RESET_TOKENLEN] = {0};
    ssize_t ret;

    packet_out = xqc_packet_out_create(XQC_QUIC_MAX_MSS);
    CU_ASSERT(packet_out != NULL);
    if (packet_out == NULL) {
        return;
    }

    memset(&cid, 0, sizeof(cid));
    packet_out->po_buf[0] = 0xa5;
    packet_out->po_frame_types = XQC_FRAME_BIT_PING;

    ret = xqc_gen_new_conn_id_frame(packet_out, &cid, 0, sr_token);

    CU_ASSERT(ret == -XQC_EPARAM);
    CU_ASSERT(packet_out->po_buf[0] == 0xa5);
    CU_ASSERT(packet_out->po_frame_types == XQC_FRAME_BIT_PING);

    xqc_packet_out_destroy(packet_out);
}

static size_t
xqc_test_build_new_conn_id_frame(unsigned char *frame_buf, uint64_t seq_num)
{
    unsigned char *p = frame_buf;
    int i;

    *p++ = 0x18;                  /* NEW_CONNECTION_ID */
    *p++ = (unsigned char)seq_num; /* sequence number, 1-byte varint */
    *p++ = 0x00;                  /* retire prior to */
    *p++ = XQC_DEFAULT_CID_LEN;   /* cid length */

    for (i = 0; i < XQC_DEFAULT_CID_LEN; i++) {
        *p++ = (unsigned char)(0xA0 + seq_num + i);
    }

    for (i = 0; i < XQC_STATELESS_RESET_TOKENLEN; i++) {
        *p++ = (unsigned char)(0xC0 + seq_num + i);
    }

    return p - frame_buf;
}

static xqc_int_t
xqc_test_process_new_conn_id_frame_one(xqc_connection_t *conn,
    uint64_t seq_num)
{
    unsigned char frame_buf[64];
    size_t frame_len = xqc_test_build_new_conn_id_frame(frame_buf, seq_num);
    xqc_packet_in_t pi;

    memset(&pi, 0, sizeof(pi));
    pi.pos = frame_buf;
    pi.last = frame_buf + frame_len;
    pi.pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;

    return xqc_process_frames(conn, &pi);
}

void
xqc_test_new_conn_id_active_limit_accept(void)
{
    xqc_connection_t *conn = test_engine_connect();
    xqc_cid_set_inner_t *inner_set;
    xqc_int_t ret;

    CU_ASSERT(conn != NULL);
    if (conn == NULL) {
        return;
    }

    conn->local_settings.active_connection_id_limit = 2;

    ret = xqc_test_process_new_conn_id_frame_one(conn, 1);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(conn->conn_err == 0);

    inner_set = xqc_get_path_cid_set(&conn->dcid_set, XQC_INITIAL_PATH_ID);
    CU_ASSERT(inner_set != NULL);
    if (inner_set != NULL) {
        CU_ASSERT(xqc_cid_set_countable_cnt(inner_set) == 1);
    }

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_new_conn_id_active_limit_exceeded(void)
{
    xqc_connection_t *conn = test_engine_connect();
    xqc_cid_set_inner_t *inner_set;
    xqc_int_t ret;

    CU_ASSERT(conn != NULL);
    if (conn == NULL) {
        return;
    }

    conn->local_settings.active_connection_id_limit = 2;

    ret = xqc_test_process_new_conn_id_frame_one(conn, 1);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(conn->conn_err == 0);

    ret = xqc_test_process_new_conn_id_frame_one(conn, 2);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(conn->conn_err == 0);

    ret = xqc_test_process_new_conn_id_frame_one(conn, 3);
    CU_ASSERT(ret == -XQC_EPROTO);
    CU_ASSERT(conn->conn_err == TRA_CONNECTION_ID_LIMIT_ERROR);

    inner_set = xqc_get_path_cid_set(&conn->dcid_set, XQC_INITIAL_PATH_ID);
    CU_ASSERT(inner_set != NULL);
    if (inner_set != NULL) {
        CU_ASSERT(xqc_cid_set_countable_cnt(inner_set) == 2);
    }

    xqc_engine_destroy(conn->engine);
}


/* ---- RFC 9000 stream directionality checks (issues #565 / #566 / #567) ----
 *
 * RFC 9000 section 2.1: the two low bits of a stream ID carry the initiator and
 * the directionality, so with test_engine_connect() building a CLIENT
 * connection:
 *   stream_id 0 -> XQC_CLI_BID  client initiated, bidirectional
 *   stream_id 2 -> XQC_CLI_UNI  client initiated, unidirectional: send-only
 *                               for the client, recv-only for the server
 *   stream_id 3 -> XQC_SVR_UNI  server initiated, unidirectional: send-only
 *                               for the server, recv-only for the client
 *
 * The parser only reads conn->conn_type, so the server side of each check is
 * exercised by flipping that field rather than by building a server engine.
 */

static xqc_connection_t *
xqc_test_dir_make_conn(xqc_conn_type_t conn_type)
{
    xqc_connection_t *conn = test_engine_connect();
    if (conn == NULL) {
        return NULL;
    }

    conn->conn_type = conn_type;
    conn->conn_err = 0;
    return conn;
}

static void
xqc_test_dir_init_pi(xqc_packet_in_t *pi, unsigned char *buf, size_t len)
{
    memset(pi, 0, sizeof(*pi));
    pi->pos = buf;
    pi->last = buf + len;
    pi->pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
}


/* ---- issue #566: RESET_STREAM on a send-only stream ---- */

void
xqc_test_reset_stream_on_send_only_stream(void)
{
    /* client + CLI_UNI: the client is the sender, so RESET_STREAM is illegal */
    xqc_connection_t *conn = xqc_test_dir_make_conn(XQC_CONN_TYPE_CLIENT);
    CU_ASSERT_FATAL(conn != NULL);

    /* type(0x04) + stream_id(2) + err_code(0) + final_size(0) */
    unsigned char frame_buf[] = {0x04, 0x02, 0x00, 0x00};
    xqc_stream_id_t stream_id;
    uint64_t err_code, final_size;
    xqc_packet_in_t pi;
    xqc_test_dir_init_pi(&pi, frame_buf, sizeof(frame_buf));

    xqc_int_t ret = xqc_parse_reset_stream_frame(&pi, &stream_id, &err_code, &final_size, conn);
    CU_ASSERT(ret == -XQC_EPROTO);
    CU_ASSERT(conn->conn_err == TRA_STREAM_STATE_ERROR);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_reset_stream_on_send_only_stream_server(void)
{
    /* server + SVR_UNI: the server is the sender, so RESET_STREAM is illegal */
    xqc_connection_t *conn = xqc_test_dir_make_conn(XQC_CONN_TYPE_SERVER);
    CU_ASSERT_FATAL(conn != NULL);

    unsigned char frame_buf[] = {0x04, 0x03, 0x00, 0x00};
    xqc_stream_id_t stream_id;
    uint64_t err_code, final_size;
    xqc_packet_in_t pi;
    xqc_test_dir_init_pi(&pi, frame_buf, sizeof(frame_buf));

    xqc_int_t ret = xqc_parse_reset_stream_frame(&pi, &stream_id, &err_code, &final_size, conn);
    CU_ASSERT(ret == -XQC_EPROTO);
    CU_ASSERT(conn->conn_err == TRA_STREAM_STATE_ERROR);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_reset_stream_on_recv_only_stream_accepted(void)
{
    /*
     * Control case: client + SVR_UNI is recv-only for the client, so the peer
     * resetting its own sending side is legal and MUST still be accepted.
     * Without this a check that rejected every unidirectional stream
     * regardless of conn_type would go unnoticed.
     */
    xqc_connection_t *conn = xqc_test_dir_make_conn(XQC_CONN_TYPE_CLIENT);
    CU_ASSERT_FATAL(conn != NULL);

    /* err_code 10 and final_size 5 so the parsed values can be asserted */
    unsigned char frame_buf[] = {0x04, 0x03, 0x0a, 0x05};
    xqc_stream_id_t stream_id;
    uint64_t err_code, final_size;
    xqc_packet_in_t pi;
    xqc_test_dir_init_pi(&pi, frame_buf, sizeof(frame_buf));

    xqc_int_t ret = xqc_parse_reset_stream_frame(&pi, &stream_id, &err_code, &final_size, conn);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(conn->conn_err == 0);
    CU_ASSERT(stream_id == 3);
    CU_ASSERT(err_code == 10);
    CU_ASSERT(final_size == 5);
    CU_ASSERT(pi.pi_frame_types & XQC_FRAME_BIT_RESET_STREAM);
    CU_ASSERT(pi.pos == frame_buf + sizeof(frame_buf));

    xqc_engine_destroy(conn->engine);
}


static void
xqc_test_process_reset_stream_direction(xqc_stream_id_t stream_id,
    xqc_bool_t expect_local_reset)
{
    unsigned char frame_buf[] = {0x04, (unsigned char)stream_id, 0x00, 0x00};
    xqc_packet_in_t pi;
    xqc_connection_t *conn;
    xqc_stream_t *stream;
    uint64_t packets_used;
    xqc_int_t ret;

    conn = xqc_test_dir_make_conn(XQC_CONN_TYPE_CLIENT);
    CU_ASSERT_FATAL(conn != NULL);

    packets_used = conn->conn_send_queue->sndq_packets_used;
    xqc_test_dir_init_pi(&pi, frame_buf, sizeof(frame_buf));

    ret = xqc_process_reset_stream_frame(conn, &pi);
    CU_ASSERT(ret == XQC_OK);

    stream = xqc_find_stream_by_id(stream_id, conn->streams_hash);
    CU_ASSERT_FATAL(stream != NULL);
    CU_ASSERT(stream->stream_state_recv == XQC_RECV_STREAM_ST_RESET_RECVD);

    if (expect_local_reset) {
        CU_ASSERT(conn->conn_send_queue->sndq_packets_used
                  == packets_used + 1);
        CU_ASSERT(stream->stream_state_send == XQC_SEND_STREAM_ST_RESET_SENT);

    } else {
        CU_ASSERT(conn->conn_send_queue->sndq_packets_used == packets_used);
        CU_ASSERT(stream->stream_state_send == XQC_SEND_STREAM_ST_READY);
    }

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_process_reset_stream_on_bidirectional_stream(void)
{
    /* Server-initiated bidirectional stream: the client has a sending part. */
    xqc_test_process_reset_stream_direction(1, XQC_TRUE);
}

void
xqc_test_process_reset_stream_on_recv_only_stream(void)
{
    /* RFC 9000 Section 3.3: the receiver cannot send RESET_STREAM. */
    xqc_test_process_reset_stream_direction(3, XQC_FALSE);
}


/* ---- issue #567: STOP_SENDING on a recv-only stream ---- */

void
xqc_test_stop_sending_on_recv_only_stream(void)
{
    /* client + SVR_UNI: the client only receives, so STOP_SENDING is illegal */
    xqc_connection_t *conn = xqc_test_dir_make_conn(XQC_CONN_TYPE_CLIENT);
    CU_ASSERT_FATAL(conn != NULL);

    /* type(0x05) + stream_id(3) + err_code(0) */
    unsigned char frame_buf[] = {0x05, 0x03, 0x00};
    xqc_stream_id_t stream_id;
    uint64_t err_code;
    xqc_packet_in_t pi;
    xqc_test_dir_init_pi(&pi, frame_buf, sizeof(frame_buf));

    xqc_int_t ret = xqc_parse_stop_sending_frame(&pi, &stream_id, &err_code, conn);
    CU_ASSERT(ret == -XQC_EPROTO);
    CU_ASSERT(conn->conn_err == TRA_STREAM_STATE_ERROR);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_stop_sending_on_recv_only_stream_server(void)
{
    /* server + CLI_UNI: the server only receives, so STOP_SENDING is illegal */
    xqc_connection_t *conn = xqc_test_dir_make_conn(XQC_CONN_TYPE_SERVER);
    CU_ASSERT_FATAL(conn != NULL);

    unsigned char frame_buf[] = {0x05, 0x02, 0x00};
    xqc_stream_id_t stream_id;
    uint64_t err_code;
    xqc_packet_in_t pi;
    xqc_test_dir_init_pi(&pi, frame_buf, sizeof(frame_buf));

    xqc_int_t ret = xqc_parse_stop_sending_frame(&pi, &stream_id, &err_code, conn);
    CU_ASSERT(ret == -XQC_EPROTO);
    CU_ASSERT(conn->conn_err == TRA_STREAM_STATE_ERROR);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_stop_sending_on_send_only_stream_accepted(void)
{
    /*
     * Control case: client + CLI_UNI is send-only for the client, so the peer
     * asking it to stop sending is legal and MUST still be accepted.  This is
     * the normal case for an HTTP/3 client control stream.
     */
    xqc_connection_t *conn = xqc_test_dir_make_conn(XQC_CONN_TYPE_CLIENT);
    CU_ASSERT_FATAL(conn != NULL);

    /* err_code 7 so the parsed value can be asserted */
    unsigned char frame_buf[] = {0x05, 0x02, 0x07};
    xqc_stream_id_t stream_id;
    uint64_t err_code;
    xqc_packet_in_t pi;
    xqc_test_dir_init_pi(&pi, frame_buf, sizeof(frame_buf));

    xqc_int_t ret = xqc_parse_stop_sending_frame(&pi, &stream_id, &err_code, conn);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(conn->conn_err == 0);
    CU_ASSERT(stream_id == 2);
    CU_ASSERT(err_code == 7);
    CU_ASSERT(pi.pi_frame_types & XQC_FRAME_BIT_STOP_SENDING);
    CU_ASSERT(pi.pos == frame_buf + sizeof(frame_buf));

    xqc_engine_destroy(conn->engine);
}


/* ---- RFC 9000 Section 19.10 MAX_STREAM_DATA direction ---- */

void
xqc_test_max_stream_data_on_recv_only_stream(void)
{
    /* client + SVR_UNI: the client has no sending side on stream 3 */
    xqc_connection_t *conn = xqc_test_dir_make_conn(XQC_CONN_TYPE_CLIENT);
    CU_ASSERT_FATAL(conn != NULL);

    unsigned char frame_buf[] = {0x11, 0x03, 0x10};
    xqc_packet_in_t pi;
    xqc_test_dir_init_pi(&pi, frame_buf, sizeof(frame_buf));

    xqc_int_t ret = xqc_process_max_stream_data_frame(conn, &pi);
    CU_ASSERT(ret == -XQC_EPROTO);
    CU_ASSERT(conn->conn_err == TRA_STREAM_STATE_ERROR);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_max_stream_data_on_recv_only_stream_server(void)
{
    /* server + CLI_UNI: the server has no sending side on stream 2 */
    xqc_connection_t *conn = xqc_test_dir_make_conn(XQC_CONN_TYPE_SERVER);
    CU_ASSERT_FATAL(conn != NULL);

    unsigned char frame_buf[] = {0x11, 0x02, 0x10};
    xqc_packet_in_t pi;
    xqc_test_dir_init_pi(&pi, frame_buf, sizeof(frame_buf));

    xqc_int_t ret = xqc_process_max_stream_data_frame(conn, &pi);
    CU_ASSERT(ret == -XQC_EPROTO);
    CU_ASSERT(conn->conn_err == TRA_STREAM_STATE_ERROR);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_max_stream_data_on_send_only_stream(void)
{
    xqc_connection_t *conn = xqc_test_dir_make_conn(XQC_CONN_TYPE_CLIENT);
    CU_ASSERT_FATAL(conn != NULL);

    xqc_stream_t *stream = xqc_stream_create_with_direction(
        conn, XQC_STREAM_UNI, NULL);
    CU_ASSERT_FATAL(stream != NULL);
    CU_ASSERT(stream->stream_id == 2);

    stream->stream_flow_ctl.fc_max_stream_data_can_send = 0;
    stream->stream_flag |= XQC_STREAM_FLAG_DATA_BLOCKED;

    unsigned char frame_buf[] = {0x11, 0x02, 0x10};
    xqc_packet_in_t pi;
    xqc_test_dir_init_pi(&pi, frame_buf, sizeof(frame_buf));

    xqc_int_t ret = xqc_process_max_stream_data_frame(conn, &pi);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(conn->conn_err == 0);
    CU_ASSERT(stream->stream_flow_ctl.fc_max_stream_data_can_send == 16);
    CU_ASSERT(!(stream->stream_flag & XQC_STREAM_FLAG_DATA_BLOCKED));
    CU_ASSERT(pi.pi_frame_types & XQC_FRAME_BIT_MAX_STREAM_DATA);
    CU_ASSERT(pi.pos == frame_buf + sizeof(frame_buf));

    xqc_engine_destroy(conn->engine);
}


/* ---- issue #565: STREAM frame direction and locally initiated stream ---- */

void
xqc_test_stream_frame_on_send_only_stream(void)
{
    /*
     * RFC 9000 section 19.8 first MUST: client + CLI_UNI is send-only for the
     * client, so carrying stream data towards it is illegal.
     * xqc_process_stream_frame() expects pos at the type byte.
     */
    xqc_connection_t *conn = xqc_test_dir_make_conn(XQC_CONN_TYPE_CLIENT);
    CU_ASSERT_FATAL(conn != NULL);

    /* type(0x0a = STREAM|LEN) + stream_id(2) + len(1) + data */
    unsigned char frame_buf[] = {0x0a, 0x02, 0x01, 0x00};
    xqc_packet_in_t pi;
    xqc_test_dir_init_pi(&pi, frame_buf, sizeof(frame_buf));

    xqc_int_t ret = xqc_process_stream_frame(conn, &pi);
    CU_ASSERT(ret == -XQC_EPROTO);
    CU_ASSERT(conn->conn_err == TRA_STREAM_STATE_ERROR);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_stream_frame_on_send_only_stream_server(void)
{
    /* server + SVR_UNI is send-only for the server */
    xqc_connection_t *conn = xqc_test_dir_make_conn(XQC_CONN_TYPE_SERVER);
    CU_ASSERT_FATAL(conn != NULL);

    unsigned char frame_buf[] = {0x0a, 0x03, 0x01, 0x00};
    xqc_packet_in_t pi;
    xqc_test_dir_init_pi(&pi, frame_buf, sizeof(frame_buf));

    xqc_int_t ret = xqc_process_stream_frame(conn, &pi);
    CU_ASSERT(ret == -XQC_EPROTO);
    CU_ASSERT(conn->conn_err == TRA_STREAM_STATE_ERROR);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_stream_frame_on_recv_only_stream_accepted(void)
{
    /*
     * Control case: client + SVR_UNI is recv-only for the client, so stream
     * data on it is legal.  The stream does not exist yet, so it must be
     * created passively rather than rejected.
     */
    xqc_connection_t *conn = xqc_test_dir_make_conn(XQC_CONN_TYPE_CLIENT);
    CU_ASSERT_FATAL(conn != NULL);

    unsigned char frame_buf[] = {0x0a, 0x03, 0x01, 0x00};
    xqc_packet_in_t pi;
    xqc_test_dir_init_pi(&pi, frame_buf, sizeof(frame_buf));

    xqc_int_t ret = xqc_process_stream_frame(conn, &pi);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(conn->conn_err == 0);
    CU_ASSERT(xqc_find_stream_by_id(3, conn->streams_hash) != NULL);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_stream_frame_on_local_uncreated_stream(void)
{
    /*
     * RFC 9000 section 19.8 second MUST: a STREAM frame for a locally
     * initiated stream that has not yet been created must be rejected.
     *
     * client + CLI_BID stream_id 4 -> index 1.  With the local counter at 1 no
     * stream of index 1 has ever been created, so the frame is illegal.
     */
    xqc_connection_t *conn = xqc_test_dir_make_conn(XQC_CONN_TYPE_CLIENT);
    CU_ASSERT_FATAL(conn != NULL);

    conn->cur_stream_id_bidi_local = 1;

    unsigned char frame_buf[] = {0x0a, 0x04, 0x01, 0x00};
    xqc_packet_in_t pi;
    xqc_test_dir_init_pi(&pi, frame_buf, sizeof(frame_buf));

    xqc_int_t ret = xqc_process_stream_frame(conn, &pi);
    CU_ASSERT(ret == -XQC_EPROTO);
    CU_ASSERT(conn->conn_err == TRA_STREAM_STATE_ERROR);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_stream_frame_on_local_closed_stream_tolerated(void)
{
    /*
     * Control case for the above: same frame, same stream id, only the local
     * counter differs.  With the counter at 2 index 1 was created earlier and
     * has since been closed, so this is a retransmission and must still be
     * tolerated instead of killing the connection.
     */
    xqc_connection_t *conn = xqc_test_dir_make_conn(XQC_CONN_TYPE_CLIENT);
    CU_ASSERT_FATAL(conn != NULL);

    conn->cur_stream_id_bidi_local = 2;

    unsigned char frame_buf[] = {0x0a, 0x04, 0x01, 0x00};
    xqc_packet_in_t pi;
    xqc_test_dir_init_pi(&pi, frame_buf, sizeof(frame_buf));

    xqc_int_t ret = xqc_process_stream_frame(conn, &pi);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(conn->conn_err == 0);

    xqc_engine_destroy(conn->engine);
}
