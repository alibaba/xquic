/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_datagram_test.h"
#include <CUnit/CUnit.h>
#include <string.h>
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_datagram.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_packet_in.h"
#include "xqc_common_test.h"

static void xqc_test_init_dgram_packet(xqc_packet_in_t *packet_in,
    xqc_packet_out_t *packet_out, xqc_pkt_type_t pkt_type);

static void
xqc_test_init_dgram_packet(xqc_packet_in_t *packet_in,
    xqc_packet_out_t *packet_out, xqc_pkt_type_t pkt_type)
{
    memset(packet_in, 0, sizeof(*packet_in));
    packet_in->pos = packet_out->po_payload;
    packet_in->last = packet_out->po_buf + packet_out->po_used_size;
    packet_in->pi_pkt.pkt_type = pkt_type;
}

void
xqc_test_receive_invalid_dgram()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    const unsigned char payload[100] = {0};

    xqc_packet_out_t *packet_out;
    packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT(packet_out != NULL);

    ret = xqc_gen_datagram_frame(packet_out, payload, (size_t)100);
    CU_ASSERT(ret == XQC_OK);

    xqc_packet_in_t pkt_in;
    xqc_test_init_dgram_packet(&pkt_in, packet_out,
                               XQC_PTYPE_SHORT_HEADER);
    conn->local_settings.max_datagram_frame_size = 0;

    ret = xqc_process_datagram_frame(conn, &pkt_in);
    CU_ASSERT(ret == -XQC_EPROTO);

    conn->local_settings.max_datagram_frame_size = 50;
    ret = xqc_process_datagram_frame(conn, &pkt_in);
    CU_ASSERT(ret == -XQC_EPROTO);

    conn->local_settings.max_datagram_frame_size = 120;
    ret = xqc_process_datagram_frame(conn, &pkt_in);
    CU_ASSERT(ret == XQC_OK);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_receive_dgram_at_valid_encryption_level()
{
    const xqc_pkt_type_t pkt_types[] = {
        XQC_PTYPE_0RTT, XQC_PTYPE_SHORT_HEADER
    };
    const unsigned char payload[1] = {0};
    xqc_connection_t   *conn;
    xqc_packet_out_t   *packet_out;
    xqc_packet_in_t     packet_in;
    xqc_int_t           ret;

    conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    conn->local_settings.max_datagram_frame_size = 64;

    packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT_PTR_NOT_NULL_FATAL(packet_out);
    ret = xqc_gen_datagram_frame(packet_out, payload, sizeof(payload));
    CU_ASSERT_EQUAL_FATAL(ret, XQC_OK);

    for (size_t i = 0; i < sizeof(pkt_types) / sizeof(pkt_types[0]); i++) {
        xqc_test_init_dgram_packet(&packet_in, packet_out, pkt_types[i]);

        ret = xqc_process_datagram_frame(conn, &packet_in);

        CU_ASSERT_EQUAL(ret, XQC_OK);
        CU_ASSERT(packet_in.pi_frame_types & XQC_FRAME_BIT_DATAGRAM);
        CU_ASSERT(packet_in.pos == packet_in.last);
    }

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_reject_dgram_at_invalid_encryption_level()
{
    const xqc_pkt_type_t pkt_types[] = {
        XQC_PTYPE_INIT, XQC_PTYPE_HSK
    };
    const unsigned char payload[1] = {0};

    for (size_t i = 0; i < sizeof(pkt_types) / sizeof(pkt_types[0]); i++) {
        xqc_connection_t *conn = test_engine_connect();
        CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
        conn->local_settings.max_datagram_frame_size = 64;

        xqc_packet_out_t *packet_out =
            xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
        CU_ASSERT_PTR_NOT_NULL_FATAL(packet_out);
        xqc_int_t ret = xqc_gen_datagram_frame(packet_out, payload,
                                               sizeof(payload));
        CU_ASSERT_EQUAL_FATAL(ret, XQC_OK);

        xqc_packet_in_t packet_in;
        xqc_test_init_dgram_packet(&packet_in, packet_out, pkt_types[i]);
        unsigned char *frame_start = packet_in.pos;

        ret = xqc_process_datagram_frame(conn, &packet_in);

        CU_ASSERT_EQUAL(ret, -XQC_EPROTO);
        CU_ASSERT_EQUAL(conn->conn_err, TRA_PROTOCOL_VIOLATION);
        CU_ASSERT(packet_in.pos == frame_start);
        CU_ASSERT_FALSE(packet_in.pi_frame_types & XQC_FRAME_BIT_DATAGRAM);

        xqc_engine_destroy(conn->engine);
    }
}

static int      xqc_test_mss_notify_cnt;
static size_t   xqc_test_mss_notified;

static void
xqc_test_dgram_mss_updated(xqc_connection_t *conn, size_t mss,
    void *user_data)
{
    xqc_test_mss_notify_cnt++;
    xqc_test_mss_notified = mss;
}

static void
xqc_test_record_mss_times(xqc_connection_t *conn, int times)
{
    for (int i = 0; i < times; i++) {
        xqc_datagram_record_mss(conn);
    }
}

/*
 * An MSS of zero tells the application that the peer takes no DATAGRAM
 * frames. It is reported once, however often the MSS is computed again,
 * e.g. on a connection ID or path MTU change, and once more after an MSS
 * above zero.
 */
void
xqc_test_dgram_mss_zero_notified_once()
{
    int dgram_data = 0;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    conn->app_proto_cbs.dgram_cbs.datagram_mss_updated_notify =
        xqc_test_dgram_mss_updated;
    conn->dgram_data = &dgram_data;
    conn->conn_flag |= XQC_CONN_FLAG_UPPER_CONN_EXIST
                       | XQC_CONN_FLAG_CAN_SEND_1RTT;
    conn->remote_settings.max_udp_payload_size = XQC_CONN_MAX_UDP_PAYLOAD_SIZE;
    xqc_test_mss_notify_cnt = 0;
    xqc_test_mss_notified = 0;

    /* the peer takes no DATAGRAM frames */
    conn->remote_settings.max_datagram_frame_size = 0;
    xqc_test_record_mss_times(conn, 3);
    CU_ASSERT_EQUAL(xqc_test_mss_notify_cnt, 1);
    CU_ASSERT_EQUAL(xqc_test_mss_notified, 0);
    CU_ASSERT_EQUAL(xqc_datagram_get_mss(conn), 0);

    /* an MSS above zero is reported */
    conn->remote_settings.max_datagram_frame_size = 1000;
    xqc_test_record_mss_times(conn, 3);
    CU_ASSERT_EQUAL(xqc_test_mss_notify_cnt, 2);
    CU_ASSERT(xqc_test_mss_notified > 0);
    CU_ASSERT_EQUAL(xqc_test_mss_notified, xqc_datagram_get_mss(conn));

    /* and a later MSS of zero once more */
    conn->remote_settings.max_datagram_frame_size = 0;
    xqc_test_record_mss_times(conn, 3);
    CU_ASSERT_EQUAL(xqc_test_mss_notify_cnt, 3);
    CU_ASSERT_EQUAL(xqc_test_mss_notified, 0);

    xqc_engine_destroy(conn->engine);
}
