/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_datagram_test.h"
#include <CUnit/CUnit.h>
#include <string.h>
#include "src/transport/xqc_conn.h"
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
