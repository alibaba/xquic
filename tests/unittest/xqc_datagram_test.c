/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_datagram_test.h"
#include <CUnit/CUnit.h>
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_packet_in.h"
#include "xqc_common_test.h"

void
xqc_test_receive_invalid_dgram()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    const unsigned char payload[100];

    xqc_packet_out_t *packet_out;
    packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT(packet_out != NULL);

    ret = xqc_gen_datagram_frame(packet_out, payload, (size_t)100);
    CU_ASSERT(ret == XQC_OK);

    xqc_packet_in_t pkt_in;
    pkt_in.pos = packet_out->po_payload;
    pkt_in.last = packet_out->po_buf + packet_out->po_used_size;
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