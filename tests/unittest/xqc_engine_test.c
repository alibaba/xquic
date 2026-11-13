/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xquic/xquic.h"
#include "src/transport/xqc_packet.h"
#include "src/common/xqc_log.h"
#include "src/common/xqc_priority_q.h"
#include "src/common/xqc_time.h"
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
#include "xqc_alloc_wrap.h"

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
#define XQC_TEST_INITIAL_FIRST_BYTE 0xC0
#define XQC_TEST_0RTT_FIRST_BYTE 0xD0

#define XQC_TEST_CHECK_CID "ab3f120acdef0089"


static void
xqc_test_build_long_header(unsigned char *packet, size_t packet_size,
    unsigned char first_byte)
{
    static const unsigned char cid[] = {0xAB, 0x3F, 0x12, 0x0A, 0xCD, 0xEF, 0x00, 0x89};

    xqc_memzero(packet, packet_size);
    packet[0] = first_byte;
    packet[4] = XQC_VERSION_V1;
    packet[5] = sizeof(cid);
    xqc_memcpy(packet + 6, cid, sizeof(cid));
    packet[14] = sizeof(cid);
    xqc_memcpy(packet + 15, cid, sizeof(cid));
}


static xqc_connection_t *
xqc_test_find_packet_conn(xqc_engine_t *engine, const unsigned char *packet,
    size_t packet_size)
{
    xqc_cid_t dcid, scid;

    xqc_cid_init_zero(&dcid);
    xqc_cid_init_zero(&scid);
    if (xqc_packet_parse_cid(&scid, &dcid, engine->config->cid_len,
                             packet, packet_size) != XQC_OK)
    {
        return NULL;
    }

    return xqc_engine_conns_hash_find(engine, &scid, 's');
}


/*
 * test_create_engine_server() (in xqc_common_test.c) loads server.key /
 * server.crt from disk and is unusable in environments without those
 * fixtures. The pre-connection drop gate under test only depends on
 * engine->eng_type and packet parsing, not on a real TLS handshake, so we
 * intentionally reuse the certificate-free client engine helper and
 * override eng_type to XQC_ENGINE_SERVER to exercise the server code path.
 */
static xqc_engine_t *
xqc_test_create_server_role_engine()
{
    xqc_engine_t *engine = test_create_engine();

    if (engine != NULL) {
        engine->eng_type = XQC_ENGINE_SERVER;
    }

    return engine;
}


static void
xqc_test_engine_small_new_conn_packet(unsigned char first_byte)
{
    unsigned char packet[XQC_PACKET_INITIAL_MIN_LENGTH];
    struct sockaddr local_addr = {0};
    struct sockaddr peer_addr = {0};
    xqc_engine_t *engine = xqc_test_create_server_role_engine();

    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);
    xqc_test_build_long_header(packet, sizeof(packet), first_byte);

    xqc_int_t ret = xqc_engine_packet_process(engine, packet,
        XQC_PACKET_INITIAL_MIN_LENGTH - 1,
        &local_addr, sizeof(local_addr), &peer_addr, sizeof(peer_addr),
        xqc_monotonic_timestamp(), NULL);

    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT_PTR_NULL(xqc_test_find_packet_conn(engine, packet,
                                                 sizeof(packet) - 1));
    xqc_engine_destroy(engine);
}


void
xqc_test_engine_drop_small_initial()
{
    xqc_test_engine_small_new_conn_packet(XQC_TEST_INITIAL_FIRST_BYTE);
}


void
xqc_test_engine_drop_small_unknown_0rtt()
{
    xqc_test_engine_small_new_conn_packet(XQC_TEST_0RTT_FIRST_BYTE);
}


void
xqc_test_engine_min_initial_not_pre_dropped()
{
    unsigned char packet[XQC_PACKET_INITIAL_MIN_LENGTH];
    struct sockaddr local_addr = {0};
    struct sockaddr peer_addr = {0};
    xqc_engine_t *engine = xqc_test_create_server_role_engine();

    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);
    xqc_test_build_long_header(packet, sizeof(packet), XQC_TEST_INITIAL_FIRST_BYTE);

    xqc_engine_packet_process(engine, packet, sizeof(packet),
        &local_addr, sizeof(local_addr), &peer_addr, sizeof(peer_addr),
        xqc_monotonic_timestamp(), NULL);

    CU_ASSERT_PTR_NOT_NULL(xqc_test_find_packet_conn(engine, packet,
                                                     sizeof(packet)));
    xqc_engine_destroy(engine);
}


void
xqc_test_engine_min_unknown_0rtt_not_pre_dropped()
{
    unsigned char packet[XQC_PACKET_INITIAL_MIN_LENGTH];
    struct sockaddr local_addr = {0};
    struct sockaddr peer_addr = {0};
    xqc_engine_t *engine = xqc_test_create_server_role_engine();

    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);
    xqc_test_build_long_header(packet, sizeof(packet), XQC_TEST_0RTT_FIRST_BYTE);

    xqc_engine_packet_process(engine, packet, sizeof(packet),
        &local_addr, sizeof(local_addr), &peer_addr, sizeof(peer_addr),
        xqc_monotonic_timestamp(), NULL);

    CU_ASSERT_PTR_NOT_NULL(xqc_test_find_packet_conn(engine, packet,
                                                     sizeof(packet)));
    xqc_engine_destroy(engine);
}


/*
 * Every encrypted length of a load balancer CID: 16 bytes take one AES
 * pass, the others the four-pass cipher, whose truncations shift by more
 * than a byte for the long lengths. Each CID is encrypted into a buffer of
 * exactly its length, followed by a guard byte that must stay intact.
 * Encryption is deterministic and keeps the first octet; lengths and keys
 * out of range are refused.
 */
void
xqc_test_engine_lb_cid_encryption()
{
    uint8_t key[XQC_LB_CID_KEY_LEN];
    uint8_t in[XQC_MAX_CID_LEN];
    uint8_t out1[XQC_MAX_CID_LEN + 1], out2[XQC_MAX_CID_LEN + 1];
    xqc_engine_t *engine = test_create_engine();

    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);
    for (size_t i = 0; i < sizeof(key); i++) {
        key[i] = (uint8_t) (0x30 + i);
    }
    for (size_t i = 0; i < sizeof(in); i++) {
        in[i] = (uint8_t) (0x11 * i + 7);
    }

    for (size_t len = 1; len < XQC_MAX_CID_LEN; len++) {
        memcpy(out1, in, len + 1);
        memcpy(out2, in, len + 1);
        out1[len + 1] = 0xa5;
        out2[len + 1] = 0xa5;
        CU_ASSERT(xqc_lb_cid_encryption(in, len, out1, len + 1,
                                        key, sizeof(key), engine) == XQC_OK);
        CU_ASSERT(xqc_lb_cid_encryption(in, len, out2, len + 1,
                                        key, sizeof(key), engine) == XQC_OK);
        CU_ASSERT(memcmp(out1, out2, len + 1) == 0);
        CU_ASSERT(out1[0] == in[0]);
        CU_ASSERT(out1[len + 1] == 0xa5);
    }

    /* abnormal: too long, a short output buffer, a wrong key length */
    CU_ASSERT(xqc_lb_cid_encryption(in, XQC_MAX_CID_LEN, out1, sizeof(out1),
                                    key, sizeof(key), engine) == -XQC_EPARAM);
    CU_ASSERT(xqc_lb_cid_encryption(in, 8, out1, 8, key, sizeof(key),
                                    engine) == -XQC_EPARAM);
    CU_ASSERT(xqc_lb_cid_encryption(in, 8, out1, sizeof(out1), key,
                                    sizeof(key) - 1, engine) == -XQC_EPARAM);

    xqc_engine_destroy(engine);
}


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


static void *
xqc_test_engine_no_growth(void *opaque, size_t size)
{
    return NULL;
}

/*
 * A client engine whose active queue holds one connection, with two
 * connections, a and b, waiting in its wakeup queue.
 */
static xqc_engine_t *
xqc_test_engine_two_waiting(xqc_connection_t **a, xqc_connection_t **b)
{
    xqc_config_t        config;
    xqc_engine_t       *engine;
    const xqc_cid_t    *cid;

    CU_ASSERT_FATAL(xqc_engine_get_default_config(&config, XQC_ENGINE_CLIENT)
                    == XQC_OK);
    config.conns_active_pq_capacity = 1;
    engine = test_create_engine_with_config(&config);
    CU_ASSERT_FATAL(engine != NULL);

    cid = test_cid_connect(engine);
    CU_ASSERT_FATAL(cid != NULL);
    *a = xqc_engine_conns_hash_find(engine, cid, 's');
    cid = test_cid_connect(engine);
    CU_ASSERT_FATAL(cid != NULL);
    *b = xqc_engine_conns_hash_find(engine, cid, 's');
    CU_ASSERT_FATAL(*a != NULL && *b != NULL);

    CU_ASSERT((*a)->conn_flag & XQC_CONN_FLAG_WAIT_WAKEUP);
    CU_ASSERT((*b)->conn_flag & XQC_CONN_FLAG_WAIT_WAKEUP);
    return engine;
}

/*
 * An API call such as xqc_conn_close() moves its connection from the
 * wakeup queue to the active queue, for the engine to process it. When the
 * active queue cannot grow, the connection must not be left in neither
 * queue, where nothing would process or destroy it again: it waits in the
 * wakeup queue, due at once, and the next run processes it.
 */
void
xqc_test_engine_active_queue_full(void)
{
    uint32_t            sent;
    xqc_engine_t       *engine;
    xqc_connection_t   *a, *b;
    xqc_malloc_wrap_t   pq_malloc;

    engine = xqc_test_engine_two_waiting(&a, &b);

    /*
     * as from a callback of the engine, which processes the connections of
     * its active queue once the callback returns
     */
    engine->eng_flag |= XQC_ENG_FLAG_RUNNING;
    CU_ASSERT(xqc_conn_close(engine, &a->scid_set.user_scid) == XQC_OK);
    CU_ASSERT(a->conn_flag & XQC_CONN_FLAG_TICKING);

    pq_malloc = engine->conns_active_pq->a.malloc;
    engine->conns_active_pq->a.malloc = xqc_test_engine_no_growth;
    CU_ASSERT(xqc_conn_close(engine, &b->scid_set.user_scid) == XQC_OK);
    engine->conns_active_pq->a.malloc = pq_malloc;
    engine->eng_flag &= ~XQC_ENG_FLAG_RUNNING;

    CU_ASSERT(!(b->conn_flag & XQC_CONN_FLAG_TICKING));
    CU_ASSERT(b->conn_flag & XQC_CONN_FLAG_WAIT_WAKEUP);
    CU_ASSERT(b->next_tick_time <= xqc_monotonic_timestamp());

    /* the next run sends the CONNECTION_CLOSE of b too */
    sent = b->snd_pkt_stats.conn_sent_pkts;
    xqc_engine_main_logic(engine);
    CU_ASSERT(b->conn_state == XQC_CONN_STATE_CLOSING);
    CU_ASSERT(b->snd_pkt_stats.conn_sent_pkts > sent);

    xqc_engine_destroy(engine);
}

/*
 * xqc_engine_main_logic() moves the connections due from the wakeup queue
 * to the active queue. One that the active queue cannot take waits in the
 * wakeup queue, with no error, and the next run processes it.
 */
void
xqc_test_engine_main_logic_active_queue_full(void)
{
    xqc_usec_t          ticked;
    xqc_engine_t       *engine;
    xqc_connection_t   *a, *b;
    xqc_malloc_wrap_t   pq_malloc;

    engine = xqc_test_engine_two_waiting(&a, &b);

    /* both due, a first */
    xqc_engine_remove_wakeup_queue(engine, a);
    xqc_engine_remove_wakeup_queue(engine, b);
    a->next_tick_time = 1;
    b->next_tick_time = 2;
    CU_ASSERT(xqc_engine_add_wakeup_queue(engine, a) == XQC_OK);
    CU_ASSERT(xqc_engine_add_wakeup_queue(engine, b) == XQC_OK);
    ticked = b->last_ticked_time;

    pq_malloc = engine->conns_active_pq->a.malloc;
    engine->conns_active_pq->a.malloc = xqc_test_engine_no_growth;
    xqc_engine_main_logic(engine);
    engine->conns_active_pq->a.malloc = pq_malloc;

    CU_ASSERT(b->conn_err == 0);
    CU_ASSERT(b->conn_flag & XQC_CONN_FLAG_WAIT_WAKEUP);
    CU_ASSERT(b->last_ticked_time == ticked);
    CU_ASSERT(b->next_tick_time <= xqc_monotonic_timestamp());

    xqc_engine_main_logic(engine);
    CU_ASSERT(b->last_ticked_time > ticked);
    CU_ASSERT(b->conn_err == 0);

    xqc_engine_destroy(engine);
}


/*
 * Connections that the active queue cannot take when they are new, and
 * that their caller destroys: xqc_engine_add_active_queue() puts them in
 * the wakeup queue, or leaves them in neither queue when that one cannot
 * grow either, and the destroyed engine must hold no reference to them
 * and leave nothing allocated (xqc_alloc_wrap.h).
 *
 * At a server, a client's first packet creates a connection, pushed on
 * the active queue at the end of xqc_engine_packet_process(), which
 * destroys it when the push fails. At a client, xqc_connect() destroys a
 * connection that it cannot queue, here with both queues full.
 */
void
xqc_test_engine_new_conn_active_queue_full(void)
{
    int                 ret;
    xqc_config_t        config;
    xqc_engine_t       *engine;
    xqc_connection_t   *a, *b, *w;
    const xqc_cid_t    *cid;
    xqc_malloc_wrap_t   active_malloc, wakeup_malloc;
    unsigned char       pkt_a[XQC_PACKET_INITIAL_MIN_LENGTH];
    unsigned char       pkt_b[XQC_PACKET_INITIAL_MIN_LENGTH];
    struct sockaddr     local_addr = {0};
    struct sockaddr     peer_addr = {0};

    CU_ASSERT_FATAL(xqc_engine_get_default_config(&config, XQC_ENGINE_CLIENT)
                    == XQC_OK);
    config.conns_active_pq_capacity = 1;
    config.conns_wakeup_pq_capacity = 1;

    /* the allocations made once per process */
    engine = test_create_engine_with_config(&config);
    CU_ASSERT_FATAL(engine != NULL);
    CU_ASSERT_FATAL(test_cid_connect(engine) != NULL);
    xqc_engine_destroy(engine);

#ifdef XQC_TEST_ALLOC_WRAP
    xqc_test_alloc_live = 0;
    xqc_test_alloc_tracking = 1;
#endif

    /* server: a takes the active queue, b cannot be queued */
    engine = test_create_engine_with_config(&config);
    CU_ASSERT_FATAL(engine != NULL);
    engine->eng_type = XQC_ENGINE_SERVER;
    xqc_test_build_long_header(pkt_a, sizeof(pkt_a),
                               XQC_TEST_INITIAL_FIRST_BYTE);
    xqc_memcpy(pkt_b, pkt_a, sizeof(pkt_b));
    pkt_b[6] ^= 0xFF;   /* another destination connection ID */

    engine->eng_flag |= XQC_ENG_FLAG_RUNNING;
    xqc_engine_packet_process(engine, pkt_a, sizeof(pkt_a),
                              &local_addr, sizeof(local_addr),
                              &peer_addr, sizeof(peer_addr),
                              xqc_monotonic_timestamp(), NULL);
    a = xqc_test_find_packet_conn(engine, pkt_a, sizeof(pkt_a));
    CU_ASSERT_FATAL(a != NULL);
    CU_ASSERT(a->conn_flag & XQC_CONN_FLAG_TICKING);

    active_malloc = engine->conns_active_pq->a.malloc;
    engine->conns_active_pq->a.malloc = xqc_test_engine_no_growth;
    ret = xqc_engine_packet_process(engine, pkt_b, sizeof(pkt_b),
                                    &local_addr, sizeof(local_addr),
                                    &peer_addr, sizeof(peer_addr),
                                    xqc_monotonic_timestamp(), NULL);
    engine->conns_active_pq->a.malloc = active_malloc;
    engine->eng_flag &= ~XQC_ENG_FLAG_RUNNING;

    CU_ASSERT(ret == -XQC_EFATAL);
    CU_ASSERT(xqc_test_find_packet_conn(engine, pkt_b, sizeof(pkt_b)) == NULL);
    CU_ASSERT(xqc_test_find_packet_conn(engine, pkt_a, sizeof(pkt_a)) == a);
    CU_ASSERT(engine->conns_active_pq->count == 1);
    CU_ASSERT(engine->conns_wait_wakeup_pq->count == 0);
    xqc_engine_destroy(engine);

    /* client: w waits in the wakeup queue, a is in the active queue */
    engine = test_create_engine_with_config(&config);
    CU_ASSERT_FATAL(engine != NULL);
    cid = test_cid_connect(engine);
    CU_ASSERT_FATAL(cid != NULL);
    w = xqc_engine_conns_hash_find(engine, cid, 's');
    CU_ASSERT_FATAL(w != NULL);
    CU_ASSERT(w->conn_flag & XQC_CONN_FLAG_WAIT_WAKEUP);

    engine->eng_flag |= XQC_ENG_FLAG_RUNNING;
    cid = test_cid_connect(engine);
    CU_ASSERT_FATAL(cid != NULL);
    a = xqc_engine_conns_hash_find(engine, cid, 's');
    CU_ASSERT_FATAL(a != NULL);
    CU_ASSERT(a->conn_flag & XQC_CONN_FLAG_TICKING);

    active_malloc = engine->conns_active_pq->a.malloc;
    wakeup_malloc = engine->conns_wait_wakeup_pq->a.malloc;
    engine->conns_active_pq->a.malloc = xqc_test_engine_no_growth;
    engine->conns_wait_wakeup_pq->a.malloc = xqc_test_engine_no_growth;
    CU_ASSERT(test_cid_connect(engine) == NULL);
    engine->conns_active_pq->a.malloc = active_malloc;
    engine->conns_wait_wakeup_pq->a.malloc = wakeup_malloc;
    engine->eng_flag &= ~XQC_ENG_FLAG_RUNNING;

    CU_ASSERT(engine->conns_active_pq->count == 1);
    CU_ASSERT(engine->conns_wait_wakeup_pq->count == 1);
    CU_ASSERT(a->conn_flag & XQC_CONN_FLAG_TICKING);
    CU_ASSERT(w->conn_flag & XQC_CONN_FLAG_WAIT_WAKEUP);
    xqc_engine_destroy(engine);

#ifdef XQC_TEST_ALLOC_WRAP
    xqc_test_alloc_tracking = 0;
    CU_ASSERT(xqc_test_alloc_live == 0);
#endif
}
