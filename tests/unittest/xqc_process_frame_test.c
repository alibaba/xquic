/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xqc_process_frame_test.h"
#include "xqc_common_test.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_send_queue.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/transport/xqc_conn.h"

char XQC_TEST_ILL_FRAME_1[] = {0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
char XQC_TEST_ZERO_LEN_NEW_TOKEN_FRAME[] = {0x07, 0x00};
char XQC_TEST_STREAM_FRAME[] = {0x0a, 0x00, 0x01, 0x00};
char XQC_TEST_APP_CONN_CLOSE_FRAME[] = {0x1d, 0x00, 0x00};


static void
xqc_test_1rtt_only_frame_buffered(xqc_connection_t *conn)
{
    CU_ASSERT(xqc_list_empty(&conn->conn_send_queue->sndq_send_packets_high_pri));
    CU_ASSERT(!xqc_list_empty(&conn->conn_send_queue->sndq_buff_1rtt_packets));
}


static xqc_packet_out_t *
xqc_test_first_high_pri_packet(xqc_connection_t *conn)
{
    if (xqc_list_empty(&conn->conn_send_queue->sndq_send_packets_high_pri)) {
        return NULL;
    }

    return xqc_list_entry(conn->conn_send_queue->sndq_send_packets_high_pri.next,
                          xqc_packet_out_t, po_list);
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

    conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    xqc_packet_in_t pi_app_conn_close_init;
    memset(&pi_app_conn_close_init, 0, sizeof(xqc_packet_in_t));
    pi_app_conn_close_init.pi_pkt.pkt_type = XQC_PTYPE_INIT;
    pi_app_conn_close_init.pos = XQC_TEST_APP_CONN_CLOSE_FRAME;
    pi_app_conn_close_init.last = pi_app_conn_close_init.pos + sizeof(XQC_TEST_APP_CONN_CLOSE_FRAME);
    ret = xqc_process_frames(conn, &pi_app_conn_close_init);
    CU_ASSERT(ret == -XQC_EPROTO);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_handshake_app_conn_close_is_converted()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    int ret = xqc_write_conn_close_to_packet(conn, H3_NO_ERROR);
    CU_ASSERT(ret == XQC_OK);

    xqc_packet_out_t *packet_out = xqc_test_first_high_pri_packet(conn);
    CU_ASSERT(packet_out != NULL);
    CU_ASSERT(packet_out->po_pkt.pkt_type == XQC_PTYPE_INIT);
    CU_ASSERT(packet_out->po_payload < packet_out->po_buf + packet_out->po_used_size);
    CU_ASSERT(*packet_out->po_payload == 0x1c);

    uint64_t err_code = 0;
    ssize_t vlen = xqc_vint_read(packet_out->po_payload + 1,
                                 packet_out->po_buf + packet_out->po_used_size,
                                 &err_code);
    CU_ASSERT(vlen > 0);
    CU_ASSERT(err_code == TRA_APPLICATION_ERROR);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_1rtt_only_flow_control_frames_are_buffered()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    int ret = xqc_write_data_blocked_to_packet(conn, 1);
    CU_ASSERT(ret == XQC_OK);
    xqc_test_1rtt_only_frame_buffered(conn);
    xqc_engine_destroy(conn->engine);

    conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    ret = xqc_write_stream_data_blocked_to_packet(conn, 0, 1);
    CU_ASSERT(ret == XQC_OK);
    xqc_test_1rtt_only_frame_buffered(conn);
    xqc_engine_destroy(conn->engine);

    conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    ret = xqc_write_max_data_to_packet(conn, 1);
    CU_ASSERT(ret == XQC_OK);
    xqc_test_1rtt_only_frame_buffered(conn);
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
    pi_padding_mix.pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
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
