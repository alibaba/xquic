/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xquic/xquic.h"
#include "src/transport/xqc_packet.h"
#include "src/common/xqc_log.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_cid.h"
#include "xquic/xquic_typedef.h"
#include "src/common/xqc_str.h"
#include "src/common/xqc_timer.h"
#include "src/transport/xqc_conn.h"
#include "src/congestion_control/xqc_new_reno.h"
#include "src/transport/xqc_packet_parser.h"
#include "xqc_common_test.h"


void
xqc_test_engine_create()
{
    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT(engine != NULL);
    xqc_engine_destroy(engine);
    engine = NULL;
}


#define XQC_TEST_SHORT_HEADER_PACKET_A "\x40\xAB\x3f\x12\x0a\xcd\xef\x00\x89"
#define XQC_TEST_LONG_HEADER_PACKET_B "\xC0\xFF\x00\x00\x1D\x08\xAB\x3f\x12\x0a\xcd\xef\x00\x89\x08\xAB\x3f\x12\x0a\xcd\xef\x00\x89"

#define XQC_TEST_CHECK_CID "ab3f120acdef0089"


void
xqc_test_engine_packet_process()
{
    struct sockaddr local_addr;
    socklen_t local_addrlen = 0;
    struct sockaddr peer_addr;
    socklen_t peer_addrlen = 0;

    xqc_engine_t *engine = test_create_engine_server();
    CU_ASSERT(engine != NULL);

    xqc_msec_t recv_time = xqc_monotonic_timestamp();

    xqc_int_t rc = xqc_engine_packet_process(engine, XQC_TEST_LONG_HEADER_PACKET_B,
                                             sizeof(XQC_TEST_LONG_HEADER_PACKET_B) - 1,
                                             (struct sockaddr *)(&local_addr), local_addrlen,
                                             (struct sockaddr *)(&peer_addr), peer_addrlen,
                                             recv_time, NULL);
    //CU_ASSERT(rc == XQC_OK);

    /* get connection */
    xqc_cid_t dcid, scid;
    xqc_cid_init_zero(&dcid);
    xqc_cid_init_zero(&scid);

    rc = xqc_packet_parse_cid(&scid, &dcid, engine->config->cid_len, XQC_TEST_LONG_HEADER_PACKET_B,
                              sizeof(XQC_TEST_LONG_HEADER_PACKET_B) - 1);
    CU_ASSERT(rc == XQC_OK);

    xqc_connection_t *conn = xqc_engine_conns_hash_find(engine, &scid, 's');
    CU_ASSERT(conn != NULL);

    /* set handshake completed */
    conn->conn_flag |= XQC_CONN_FLAG_HANDSHAKE_COMPLETED;

    recv_time = xqc_monotonic_timestamp();
    rc = xqc_engine_packet_process(engine, XQC_TEST_SHORT_HEADER_PACKET_A,
                                   sizeof(XQC_TEST_SHORT_HEADER_PACKET_A) - 1,
                                   (struct sockaddr *)&local_addr, local_addrlen,
                                   (struct sockaddr *)&peer_addr, peer_addrlen, recv_time, NULL);
    //CU_ASSERT(rc == XQC_OK);

    xqc_engine_destroy(engine);
}

