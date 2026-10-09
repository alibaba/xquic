/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xquic/xquic.h"
#include "src/transport/xqc_packet.h"
#include "src/common/xqc_log.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_cid.h"
#include "src/transport/xqc_multipath.h"
#include "xquic/xquic_typedef.h"
#include "src/common/xqc_str.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_timer.h"
#include "src/congestion_control/xqc_new_reno.h"
#include "src/transport/xqc_packet_parser.h"
#include "xqc_common_test.h"

xqc_int_t xqc_need_padding(xqc_connection_t *conn, xqc_packet_out_t *packet_out);


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
xqc_test_rebinding_candidate_budget_limit()
{
    xqc_connection_t *conn = test_engine_connect();
    xqc_path_ctx_t *path;
    struct sockaddr_in addr;
    xqc_int_t ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    path = conn->conn_initial_path;
    CU_ASSERT_PTR_NOT_NULL_FATAL(path);
    conn->conn_type = XQC_CONN_TYPE_SERVER;
    conn->conn_flag &= ~XQC_CONN_FLAG_HANDSHAKE_CONFIRMED;
    xqc_memzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;

    ret = xqc_path_rebinding_on_authenticated_datagram(conn, path,
        (struct sockaddr *)&addr, sizeof(addr), 399, xqc_monotonic_timestamp());
    CU_ASSERT_EQUAL(ret, -XQC_EAGAIN);
    CU_ASSERT_EQUAL(path->rebinding.state, XQC_REBINDING_ADDRESS_VALIDATING);
    CU_ASSERT_EQUAL(path->rebinding.recv_bytes, 399);
    CU_ASSERT_EQUAL(path->rebinding.sent_bytes, 0);

    ret = xqc_path_rebinding_on_authenticated_datagram(conn, path,
        (struct sockaddr *)&addr, sizeof(addr), 1, xqc_monotonic_timestamp());
    CU_ASSERT_EQUAL(ret, -XQC_EAGAIN);
    CU_ASSERT_EQUAL(path->rebinding.recv_bytes, 400);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_rebinding_no_padding_flag()
{
    xqc_connection_t conn;
    xqc_engine_t engine;
    xqc_packet_out_t packet_out;

    xqc_memzero(&conn, sizeof(conn));
    xqc_memzero(&engine, sizeof(engine));
    xqc_memzero(&packet_out, sizeof(packet_out));

    conn.engine = &engine;
    engine.eng_type = XQC_ENGINE_SERVER;
    packet_out.po_pkt.pkt_pns = XQC_PNS_APP_DATA;
    packet_out.po_frame_types = XQC_FRAME_BIT_PATH_CHALLENGE;

    CU_ASSERT_TRUE(xqc_need_padding(&conn, &packet_out));

    packet_out.po_flag |= XQC_POF_NO_PATH_PADDING;
    CU_ASSERT_FALSE(xqc_need_padding(&conn, &packet_out));

    packet_out.po_flag &= ~XQC_POF_NO_PATH_PADDING;
    packet_out.po_flag |= XQC_POF_PATH_MIN_PADDING;
    CU_ASSERT_TRUE(xqc_need_padding(&conn, &packet_out));
}


void
xqc_test_rebinding_min_padding_flag()
{
    xqc_connection_t conn;
    xqc_packet_out_t packet_out;
    unsigned char buf[1500];

    xqc_memzero(&conn, sizeof(conn));
    xqc_memzero(&packet_out, sizeof(packet_out));
    xqc_memzero(buf, sizeof(buf));

    conn.enable_pmtud = 1;
    packet_out.po_buf = buf;
    packet_out.po_buf_size = 1300;
    packet_out.po_used_size = 20;
    packet_out.po_frame_types = XQC_FRAME_BIT_PATH_CHALLENGE;
    packet_out.po_flag = XQC_POF_PATH_MIN_PADDING;

    xqc_gen_padding_frame(&conn, &packet_out);
    CU_ASSERT_EQUAL(packet_out.po_used_size,
                    XQC_PACKET_INITIAL_MIN_LENGTH - XQC_TLS_AEAD_OVERHEAD_MAX_LEN);
}


void
xqc_test_rebinding_response_state_transition()
{
    xqc_connection_t *conn = test_engine_connect();
    xqc_path_ctx_t *path;
    struct sockaddr_in addr;
    unsigned char response_data[XQC_PATH_CHALLENGE_DATA_LEN];
    xqc_int_t ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    path = conn->conn_initial_path;
    CU_ASSERT_PTR_NOT_NULL_FATAL(path);
    conn->conn_type = XQC_CONN_TYPE_SERVER;
    conn->conn_flag &= ~XQC_CONN_FLAG_HANDSHAKE_CONFIRMED;
    xqc_memzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4433);
    CU_ASSERT_EQUAL(xqc_memcpy_with_cap(path->rebinding.addr,
                                        sizeof(path->rebinding.addr), &addr,
                                        sizeof(addr)), XQC_OK);
    path->rebinding.addrlen = sizeof(addr);
    path->rebinding.state = XQC_REBINDING_ADDRESS_VALIDATING;
    path->rebinding.initial_challenge_padded = XQC_FALSE;
    memset(path->rebinding.challenge_data, 0x5a,
           sizeof(path->rebinding.challenge_data));

    ret = xqc_path_rebinding_on_response(conn, path,
                                         path->rebinding.challenge_data,
                                         xqc_monotonic_timestamp());
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(path->rebinding.state, XQC_REBINDING_MTU_VALIDATING);
    CU_ASSERT_EQUAL(path->rebinding.valid, 1);
    CU_ASSERT_TRUE(xqc_is_same_addr((struct sockaddr *)&addr,
                                    (struct sockaddr *)path->peer_addr));

    xqc_memcpy(response_data, path->rebinding.challenge_data, sizeof(response_data));
    ret = xqc_path_rebinding_on_response(conn, path, response_data,
                                         xqc_monotonic_timestamp());
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(path->rebinding.state, XQC_REBINDING_IDLE);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_rebinding_clear()
{
    xqc_path_ctx_t path;

    xqc_memzero(&path, sizeof(path));
    path.rebinding.addrlen = sizeof(struct sockaddr_in);
    path.rebinding.recv_bytes = 1200;
    path.rebinding.sent_bytes = 1200;
    path.rebinding.state = XQC_REBINDING_MTU_VALIDATING;
    path.rebinding.initial_challenge_padded = XQC_TRUE;
    path.rebinding.mtu_probe_retries = 2;
    path.rebinding.count = 3;
    path.rebinding.valid = 2;

    xqc_path_rebinding_clear(&path);
    CU_ASSERT_EQUAL(path.rebinding.addrlen, 0);
    CU_ASSERT_EQUAL(path.rebinding.recv_bytes, 0);
    CU_ASSERT_EQUAL(path.rebinding.sent_bytes, 0);
    CU_ASSERT_EQUAL(path.rebinding.state, XQC_REBINDING_IDLE);
    CU_ASSERT_FALSE(path.rebinding.initial_challenge_padded);
    CU_ASSERT_EQUAL(path.rebinding.mtu_probe_retries, 0);
    CU_ASSERT_EQUAL(path.rebinding.count, 3);
    CU_ASSERT_EQUAL(path.rebinding.valid, 2);
}


void
xqc_test_rebinding_ignores_unauthenticated_packet()
{
    xqc_connection_t *conn = test_engine_connect();
    unsigned char packet[] = {0};
    uint32_t authenticated_before;
    xqc_int_t ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    authenticated_before = conn->rcv_pkt_stats.conn_authenticated_pkts;
    ret = xqc_conn_process_packet(conn, packet, sizeof(packet),
                                  xqc_monotonic_timestamp());
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(conn->rcv_pkt_stats.conn_authenticated_pkts,
                    authenticated_before);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_rebinding_path_challenge_requires_confirmed()
{
    xqc_connection_t *conn = test_engine_connect();
    struct sockaddr_in addr;
    xqc_int_t ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn->conn_initial_path);

    conn->conn_type = XQC_CONN_TYPE_SERVER;
    conn->conn_flag &= ~XQC_CONN_FLAG_HANDSHAKE_CONFIRMED;
    xqc_memzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;

    ret = xqc_path_rebinding_on_authenticated_datagram(conn, conn->conn_initial_path,
        (struct sockaddr *)&addr, sizeof(addr), 1200, xqc_monotonic_timestamp());
    CU_ASSERT_EQUAL(ret, -XQC_EAGAIN);
    CU_ASSERT_EQUAL(conn->conn_initial_path->rebinding.state,
                    XQC_REBINDING_ADDRESS_VALIDATING);
    CU_ASSERT_EQUAL(conn->conn_initial_path->rebinding.sent_bytes, 0);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_rebinding_timeout_retry_limit()
{
    xqc_connection_t *conn = test_engine_connect();
    xqc_path_ctx_t *path;
    struct sockaddr_in addr;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    path = conn->conn_initial_path;
    CU_ASSERT_PTR_NOT_NULL_FATAL(path);

    conn->conn_type = XQC_CONN_TYPE_SERVER;
    conn->conn_flag &= ~XQC_CONN_FLAG_HANDSHAKE_CONFIRMED;
    xqc_memzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    CU_ASSERT_EQUAL(xqc_memcpy_with_cap(path->rebinding.addr,
                                        sizeof(path->rebinding.addr), &addr,
                                        sizeof(addr)), XQC_OK);
    path->rebinding.addrlen = sizeof(addr);
    path->rebinding.recv_bytes = 400;
    path->rebinding.state = XQC_REBINDING_MTU_VALIDATING;
    path->rebinding.mtu_probe_retries = XQC_REBINDING_MAX_MTU_PROBE_RETRIES - 1;

    xqc_path_rebinding_on_timeout(conn, path, xqc_monotonic_timestamp());
    CU_ASSERT_EQUAL(path->rebinding.state, XQC_REBINDING_MTU_VALIDATING);
    CU_ASSERT_EQUAL(path->rebinding.mtu_probe_retries,
                    XQC_REBINDING_MAX_MTU_PROBE_RETRIES);
    CU_ASSERT_TRUE(xqc_timer_is_set(&path->path_send_ctl->path_timer_manager,
                                    XQC_TIMER_NAT_REBINDING));

    xqc_path_rebinding_on_timeout(conn, path, xqc_monotonic_timestamp());
    CU_ASSERT_EQUAL(path->rebinding.state, XQC_REBINDING_IDLE);
    CU_ASSERT_EQUAL(path->rebinding.addrlen, 0);
    CU_ASSERT_EQUAL(path->rebinding.mtu_probe_retries, 0);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_rebinding_response_mismatch_preserves_state()
{
    xqc_connection_t *conn = test_engine_connect();
    xqc_path_ctx_t *path;
    unsigned char mismatch_data[XQC_PATH_CHALLENGE_DATA_LEN] = {0};
    xqc_usec_t now;
    xqc_int_t ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    path = conn->conn_initial_path;
    CU_ASSERT_PTR_NOT_NULL_FATAL(path);

    path->rebinding.state = XQC_REBINDING_ADDRESS_VALIDATING;
    path->rebinding.recv_bytes = 400;
    path->rebinding.sent_bytes = 100;
    path->rebinding.valid = 2;
    memset(path->rebinding.challenge_data, 0x5a,
           sizeof(path->rebinding.challenge_data));
    now = xqc_monotonic_timestamp();
    xqc_timer_set(&path->path_send_ctl->path_timer_manager, XQC_TIMER_NAT_REBINDING,
                  now, 1);

    ret = xqc_path_rebinding_on_response(conn, path, mismatch_data, now);
    CU_ASSERT_EQUAL(ret, XQC_ERROR);
    CU_ASSERT_EQUAL(path->rebinding.state, XQC_REBINDING_ADDRESS_VALIDATING);
    CU_ASSERT_EQUAL(path->rebinding.recv_bytes, 400);
    CU_ASSERT_EQUAL(path->rebinding.sent_bytes, 100);
    CU_ASSERT_EQUAL(path->rebinding.valid, 2);
    CU_ASSERT_EQUAL(memcmp(path->rebinding.challenge_data, mismatch_data,
                           sizeof(mismatch_data)) != 0, XQC_TRUE);
    CU_ASSERT_TRUE(xqc_timer_is_set(&path->path_send_ctl->path_timer_manager,
                                    XQC_TIMER_NAT_REBINDING));

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_rebinding_sender_error_clears_candidate()
{
    xqc_connection_t *conn = test_engine_connect();
    xqc_path_ctx_t *path;
    struct sockaddr_in addr;
    xqc_int_t ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    path = conn->conn_initial_path;
    CU_ASSERT_PTR_NOT_NULL_FATAL(path);

    xqc_memzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    conn->transport_cbs.write_socket_ex = NULL;
    ret = xqc_path_rebinding_on_authenticated_datagram(conn, path,
        (struct sockaddr *)&addr, sizeof(addr), 400, xqc_monotonic_timestamp());
    CU_ASSERT_EQUAL(ret, XQC_ERROR);
    CU_ASSERT_EQUAL(path->rebinding.state, XQC_REBINDING_IDLE);
    CU_ASSERT_EQUAL(path->rebinding.addrlen, 0);
    CU_ASSERT_EQUAL(path->rebinding.recv_bytes, 0);
    CU_ASSERT_EQUAL(path->rebinding.sent_bytes, 0);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_engine_packet_process()
{
    struct sockaddr local_addr;
    socklen_t local_addrlen = 0;
    struct sockaddr peer_addr;
    socklen_t peer_addrlen = 0;

    xqc_engine_t *engine = test_create_engine_server();
    CU_ASSERT(engine != NULL);
    if (engine == NULL) {
        return;
    }

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

    /*
     * This packet is synthetic and does not complete a TLS handshake.  Do not
     * force 1-RTT short-header processing without installed packet keys.
     */
    xqc_engine_destroy(engine);
}
