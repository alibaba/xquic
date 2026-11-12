/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include <string.h>

#include "xqc_preferred_addr_test.h"
#include "xqc_common_test.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_utils.h"
#include "src/transport/xqc_packet_parser.h"
#include "src/transport/xqc_transport_params.h"

#define XQC_TEST_PA_SERVER_PORT     443
#define XQC_TEST_PA_PREFERRED_PORT  4433


static void
xqc_test_pa_set_ipv4(unsigned char *addr, socklen_t *addrlen,
    uint8_t last_byte, uint16_t port)
{
    struct sockaddr_in *sin = (struct sockaddr_in *)addr;

    memset(addr, 0, sizeof(struct sockaddr_in6));
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    sin->sin_addr.s_addr = htonl(0x7f000000u | last_byte);
    *addrlen = sizeof(struct sockaddr_in);
}


/* a client connection with migration on, to 127.0.0.1:443 */
static xqc_connection_t *
xqc_test_pa_conn(void)
{
    xqc_connection_t   *conn = test_engine_connect();
    xqc_path_ctx_t     *path;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    path = conn->conn_initial_path;
    xqc_test_pa_set_ipv4(conn->peer_addr, &conn->peer_addrlen, 1,
                         XQC_TEST_PA_SERVER_PORT);
    memcpy(path->peer_addr, conn->peer_addr, sizeof(path->peer_addr));
    path->peer_addrlen = conn->peer_addrlen;
    conn->conn_settings.enable_preferred_address_migration = XQC_TRUE;
    return conn;
}


/* a preferred address on 127.0.0.<last_byte>:port, IPv4 only */
static void
xqc_test_pa_params(xqc_connection_t *conn, xqc_preferred_addr_t *preferred,
    uint8_t last_byte, uint16_t port)
{
    memset(preferred, 0, sizeof(*preferred));
    preferred->ipv4[0] = 127;
    preferred->ipv4[3] = last_byte;
    preferred->ipv4_port = port;
    preferred->cid.cid_len = conn->dcid_set.current_dcid.cid_len;
    memset(preferred->cid.cid_buf, 0x5a, preferred->cid.cid_len);
    memset(preferred->stateless_reset_token, 0xa5,
           XQC_STATELESS_RESET_TOKENLEN);
}


static xqc_cid_inner_t *
xqc_test_pa_inner_cid(xqc_connection_t *conn, uint64_t seq_num)
{
    return xqc_get_inner_cid_by_seq(&conn->dcid_set, seq_num,
                                    XQC_INITIAL_PATH_ID);
}


/* the packets queued with a frame of type_bit */
static int
xqc_test_pa_queued(xqc_connection_t *conn, xqc_frame_type_bit_t type_bit)
{
    int                 n = 0;
    xqc_list_head_t    *pos;
    xqc_packet_out_t   *packet_out;
    xqc_send_queue_t   *send_queue = conn->conn_send_queue;
    xqc_list_head_t    *heads[] = {
        &send_queue->sndq_send_packets,
        &send_queue->sndq_send_packets_high_pri,
    };

    for (size_t i = 0; i < sizeof(heads) / sizeof(heads[0]); i++) {
        xqc_list_for_each(pos, heads[i]) {
            packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            n += (packet_out->po_frame_types & type_bit) != 0;
        }
    }
    return n;
}


/*
 * process a packet of one or two PATH_CHALLENGE (0x1a) or PATH_RESPONSE
 * (0x1b) frames; type2 0 for one
 */
static xqc_int_t
xqc_test_pa_recv_frames(xqc_connection_t *conn, uint64_t type,
    const unsigned char *data, uint64_t type2, const unsigned char *data2)
{
    unsigned char       frame[32];
    unsigned char      *p = frame;
    xqc_packet_in_t     packet_in;

    p = xqc_put_varint(p, type);
    memcpy(p, data, XQC_PATH_CHALLENGE_DATA_LEN);
    p += XQC_PATH_CHALLENGE_DATA_LEN;
    if (type2 != 0) {
        p = xqc_put_varint(p, type2);
        memcpy(p, data2, XQC_PATH_CHALLENGE_DATA_LEN);
        p += XQC_PATH_CHALLENGE_DATA_LEN;
    }

    memset(&packet_in, 0, sizeof(packet_in));
    packet_in.pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    packet_in.pos = frame;
    packet_in.last = p;
    return xqc_process_frames(conn, &packet_in);
}


static xqc_int_t
xqc_test_pa_recv_frame(xqc_connection_t *conn, uint64_t type,
    const unsigned char *data)
{
    return xqc_test_pa_recv_frames(conn, type, data, 0, NULL);
}


/* the server acknowledges a NEW_CONNECTION_ID frame, issued and sent now */
static void
xqc_test_pa_ack_new_cid(xqc_connection_t *conn, xqc_usec_t now)
{
    xqc_send_queue_t   *send_queue = conn->conn_send_queue;
    xqc_packet_out_t   *packet_out = NULL;
    xqc_list_head_t    *pos;

    CU_ASSERT_FATAL(xqc_write_new_conn_id_frame_to_packet(conn, 0)
                    == XQC_OK);
    xqc_list_for_each(pos, &send_queue->sndq_send_packets_high_pri) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_frame_types & XQC_FRAME_BIT_NEW_CONNECTION_ID) {
            break;
        }
        packet_out = NULL;
    }
    CU_ASSERT_PTR_NOT_NULL_FATAL(packet_out);

    xqc_send_queue_remove_send(&packet_out->po_list);
    packet_out->po_path_id = conn->conn_initial_path->path_id;
    packet_out->po_sent_time = now;
    xqc_send_ctl_increase_inflight(conn, packet_out);
    xqc_send_queue_insert_unacked(packet_out,
        &send_queue->sndq_unacked_packets[packet_out->po_pkt.pkt_pns],
        send_queue);
    xqc_send_ctl_on_packet_acked(conn->conn_initial_path->path_send_ctl,
                                 packet_out, now, 0);
}


/* the preferred address and its connection ID, offered to the client */
static xqc_connection_t *
xqc_test_pa_offer(uint8_t last_byte, uint16_t port)
{
    xqc_connection_t       *conn = xqc_test_pa_conn();
    xqc_preferred_addr_t    preferred;

    xqc_test_pa_params(conn, &preferred, last_byte, port);
    CU_ASSERT(xqc_conn_on_preferred_address(conn, &preferred) == XQC_OK);
    CU_ASSERT(conn->preferred_addr.state == XQC_PREFERRED_ADDR_OFFERED);
    return conn;
}


/* ready to be validated: the server has an unused client connection ID */
static xqc_connection_t *
xqc_test_pa_offered_conn(uint8_t last_byte, uint16_t port)
{
    xqc_connection_t *conn = xqc_test_pa_offer(last_byte, port);

    xqc_test_pa_ack_new_cid(conn, xqc_monotonic_timestamp());
    return conn;
}


/*
 * RFC 9000 Section 18.2: the connection ID of preferred_address has
 * sequence number 1, and comes with its stateless reset token; the client
 * keeps the address of the family in use.
 */
void
xqc_test_preferred_addr_store()
{
    xqc_connection_t       *conn = xqc_test_pa_offer(2, 4433);
    xqc_preferred_addr_ctx_t *pa = &conn->preferred_addr;
    struct sockaddr_in     *sin = (struct sockaddr_in *)pa->addr;
    xqc_cid_inner_t        *inner_cid;

    inner_cid = xqc_test_pa_inner_cid(conn, 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(inner_cid);
    CU_ASSERT(inner_cid->state == XQC_CID_UNUSED);
    CU_ASSERT(inner_cid->cid.sr_token[0] == 0xa5);
    CU_ASSERT(xqc_find_conns_hash(conn->engine->conns_hash_sr_token, conn,
                                  inner_cid->cid.sr_token,
                                  XQC_STATELESS_RESET_TOKENLEN) == conn);
    CU_ASSERT(pa->addrlen == sizeof(struct sockaddr_in));
    CU_ASSERT(sin->sin_family == AF_INET);
    CU_ASSERT(sin->sin_port == htons(4433));
    CU_ASSERT(sin->sin_addr.s_addr == htonl(0x7f000002));

    xqc_engine_destroy(conn->engine);
}


/* over IPv6, the IPv6 preferred address is taken (RFC 9000 Section 9.6.3) */
void
xqc_test_preferred_addr_ipv6()
{
    xqc_connection_t       *conn = xqc_test_pa_conn();
    xqc_preferred_addr_t    preferred;
    struct sockaddr_in6    *peer = (struct sockaddr_in6 *)conn->peer_addr;
    struct sockaddr_in6    *sin6;

    memset(conn->peer_addr, 0, sizeof(conn->peer_addr));
    peer->sin6_family = AF_INET6;
    peer->sin6_port = htons(XQC_TEST_PA_SERVER_PORT);
    peer->sin6_addr.s6_addr[15] = 1;
    conn->peer_addrlen = sizeof(*peer);

    xqc_test_pa_params(conn, &preferred, 2, 4433);
    preferred.ipv6[15] = 1;
    preferred.ipv6_port = 4443;
    CU_ASSERT(xqc_conn_on_preferred_address(conn, &preferred) == XQC_OK);
    CU_ASSERT(conn->preferred_addr.state == XQC_PREFERRED_ADDR_OFFERED);
    CU_ASSERT(conn->preferred_addr.addrlen == sizeof(struct sockaddr_in6));
    sin6 = (struct sockaddr_in6 *)conn->preferred_addr.addr;
    CU_ASSERT(sin6->sin6_family == AF_INET6);
    CU_ASSERT(sin6->sin6_port == htons(4443));
    CU_ASSERT(memcmp(&sin6->sin6_addr, preferred.ipv6, 16) == 0);

    xqc_engine_destroy(conn->engine);
}


/*
 * An all-zero address stands for none (RFC 9000 Section 18.2), and the
 * client does not move to the other address family: the connection ID is
 * kept, but there is nothing to validate.
 */
void
xqc_test_preferred_addr_none_usable()
{
    xqc_connection_t       *conn = xqc_test_pa_conn();
    xqc_preferred_addr_t    preferred;

    xqc_test_pa_params(conn, &preferred, 2, 4433);
    memset(preferred.ipv4, 0, sizeof(preferred.ipv4));
    preferred.ipv6[15] = 1;
    preferred.ipv6_port = 4433;
    CU_ASSERT(xqc_conn_on_preferred_address(conn, &preferred) == XQC_OK);
    CU_ASSERT(conn->preferred_addr.state == XQC_PREFERRED_ADDR_NONE);
    CU_ASSERT_PTR_NOT_NULL(xqc_test_pa_inner_cid(conn, 1));

    xqc_conn_preferred_addr_start(conn, xqc_monotonic_timestamp());
    CU_ASSERT(conn->preferred_addr.state == XQC_PREFERRED_ADDR_NONE);
    CU_ASSERT(xqc_test_pa_inner_cid(conn, 1)->state == XQC_CID_UNUSED);

    xqc_engine_destroy(conn->engine);
}


/* a preferred address with the connection ID in use is not taken */
void
xqc_test_preferred_addr_cid_in_use()
{
    xqc_connection_t       *conn = xqc_test_pa_conn();
    xqc_preferred_addr_t    preferred;

    xqc_test_pa_params(conn, &preferred, 2, 4433);
    preferred.cid = conn->dcid_set.current_dcid;
    CU_ASSERT(xqc_conn_on_preferred_address(conn, &preferred) == XQC_OK);
    CU_ASSERT(conn->preferred_addr.state == XQC_PREFERRED_ADDR_NONE);
    CU_ASSERT_PTR_NULL(xqc_test_pa_inner_cid(conn, 1));

    xqc_engine_destroy(conn->engine);
}


/*
 * RFC 9000 Section 9.6.1: once the handshake is confirmed, the client
 * challenges the preferred address with the unused connection ID, then
 * sends there with it once the response comes, and retires the one it
 * used. A port change only keeps the RTT estimate (Section 9.4).
 */
void
xqc_test_preferred_addr_migrate()
{
    xqc_connection_t       *conn = xqc_test_pa_offered_conn(1, 4433);
    xqc_preferred_addr_ctx_t *pa = &conn->preferred_addr;
    xqc_path_ctx_t         *path = conn->conn_initial_path;
    xqc_send_ctl_t         *send_ctl = path->path_send_ctl;
    uint64_t                old_seq = path->path_dcid.cid_seq_num;

    send_ctl->ctl_srtt = 1234;
    xqc_conn_preferred_addr_start(conn, xqc_monotonic_timestamp());
    CU_ASSERT(pa->state == XQC_PREFERRED_ADDR_VALIDATING);
    CU_ASSERT(pa->challenge_cnt == 1);
    CU_ASSERT(pa->dcid.cid_seq_num == 1);
    CU_ASSERT(xqc_test_pa_inner_cid(conn, 1)->state == XQC_CID_USED);
    CU_ASSERT(xqc_timer_is_set(&conn->conn_timer_manager,
                               XQC_TIMER_PREFERRED_ADDR));
    /* nothing is sent to the preferred address before it is validated */
    CU_ASSERT(path->path_dcid.cid_seq_num == old_seq);
    CU_ASSERT(xqc_is_same_addr((struct sockaddr *)path->peer_addr,
                               (struct sockaddr *)conn->peer_addr));

    CU_ASSERT(xqc_test_pa_recv_frame(conn, 0x1b, pa->challenge_data[0])
              == XQC_OK);
    CU_ASSERT(pa->state == XQC_PREFERRED_ADDR_MIGRATED);
    CU_ASSERT(!xqc_timer_is_set(&conn->conn_timer_manager,
                                XQC_TIMER_PREFERRED_ADDR));
    CU_ASSERT(xqc_is_same_addr((struct sockaddr *)path->peer_addr,
                               (struct sockaddr *)pa->addr));
    CU_ASSERT(xqc_is_same_addr((struct sockaddr *)conn->peer_addr,
                               (struct sockaddr *)pa->addr));
    CU_ASSERT(path->path_dcid.cid_seq_num == 1);
    CU_ASSERT(conn->dcid_set.current_dcid.cid_seq_num == 1);
    CU_ASSERT(xqc_test_pa_inner_cid(conn, old_seq)->state == XQC_CID_RETIRED);
    CU_ASSERT(xqc_test_pa_queued(conn, XQC_FRAME_BIT_RETIRE_CONNECTION_ID)
              == 1);
    CU_ASSERT(send_ctl->ctl_srtt == 1234);

    /* the response again, as to a second challenge: nothing changes */
    CU_ASSERT(xqc_test_pa_recv_frame(conn, 0x1b, pa->challenge_data[0])
              == XQC_OK);
    CU_ASSERT(pa->state == XQC_PREFERRED_ADDR_MIGRATED);
    CU_ASSERT(xqc_test_pa_queued(conn, XQC_FRAME_BIT_RETIRE_CONNECTION_ID)
              == 1);
    CU_ASSERT(conn->conn_err == 0);

    xqc_engine_destroy(conn->engine);
}


/*
 * RFC 9000 Section 9.4: a new IP address restarts the RTT estimator and the
 * congestion controller, and the packets sent before count in neither
 * (xqc_send_ctl_reset_for_new_path())
 */
void
xqc_test_preferred_addr_migrate_new_ip()
{
    xqc_connection_t       *conn = xqc_test_pa_offered_conn(2, 443);
    xqc_send_ctl_t         *send_ctl = conn->conn_initial_path->path_send_ctl;

    send_ctl->ctl_srtt = 1234;
    send_ctl->ctl_minrtt = 1000;
    CU_ASSERT(send_ctl->ctl_cc_reset_time == 0);
    xqc_conn_preferred_addr_start(conn, xqc_monotonic_timestamp());
    CU_ASSERT(xqc_test_pa_recv_frame(conn, 0x1b,
                                     conn->preferred_addr.challenge_data[0])
              == XQC_OK);
    CU_ASSERT(conn->preferred_addr.state == XQC_PREFERRED_ADDR_MIGRATED);
    CU_ASSERT(send_ctl->ctl_srtt == conn->conn_settings.initial_rtt);
    CU_ASSERT(send_ctl->ctl_minrtt == XQC_MAX_UINT32_VALUE);
    CU_ASSERT(send_ctl->ctl_cc_reset_time > 0);

    xqc_engine_destroy(conn->engine);
}


/* a PATH_RESPONSE that answers no challenge changes nothing */
void
xqc_test_preferred_addr_wrong_response()
{
    xqc_connection_t       *conn = xqc_test_pa_offered_conn(2, 4433);
    xqc_path_ctx_t         *path = conn->conn_initial_path;
    uint64_t                old_seq = path->path_dcid.cid_seq_num;
    unsigned char           data[XQC_PATH_CHALLENGE_DATA_LEN];

    xqc_conn_preferred_addr_start(conn, xqc_monotonic_timestamp());
    memcpy(data, conn->preferred_addr.challenge_data[0], sizeof(data));
    data[0] ^= 0xff;
    CU_ASSERT(xqc_test_pa_recv_frame(conn, 0x1b, data) == XQC_OK);
    CU_ASSERT(conn->preferred_addr.state == XQC_PREFERRED_ADDR_VALIDATING);
    CU_ASSERT(path->path_dcid.cid_seq_num == old_seq);
    CU_ASSERT(xqc_is_same_addr((struct sockaddr *)path->peer_addr,
                               (struct sockaddr *)conn->peer_addr));
    CU_ASSERT(conn->conn_err == 0);

    xqc_engine_destroy(conn->engine);
}


/*
 * RFC 9000 Sections 8.2.4 and 9.6.1: without a response, the client
 * challenges again, then abandons the validation, keeps sending to the
 * original address, and retires the connection ID of the challenges.
 */
void
xqc_test_preferred_addr_timeout()
{
    xqc_connection_t       *conn = xqc_test_pa_offered_conn(2, 4433);
    xqc_preferred_addr_ctx_t *pa = &conn->preferred_addr;
    xqc_path_ctx_t         *path = conn->conn_initial_path;
    uint64_t                old_seq = path->path_dcid.cid_seq_num;
    xqc_usec_t              now = xqc_monotonic_timestamp();
    int                     rounds = 0;

    xqc_conn_preferred_addr_start(conn, now);
    CU_ASSERT(pa->deadline > now);
    while (pa->state == XQC_PREFERRED_ADDR_VALIDATING && rounds++ < 10) {
        now = conn->conn_timer_manager.timer[XQC_TIMER_PREFERRED_ADDR]
                  .expire_time;
        xqc_conn_preferred_addr_on_timeout(conn, now);
    }

    CU_ASSERT(pa->state == XQC_PREFERRED_ADDR_FAILED);
    CU_ASSERT(pa->challenge_cnt >= 2
              && pa->challenge_cnt <= XQC_PREFERRED_ADDR_MAX_CHALLENGES);
    CU_ASSERT(now >= pa->deadline);
    CU_ASSERT(path->path_dcid.cid_seq_num == old_seq);
    CU_ASSERT(xqc_is_same_addr((struct sockaddr *)path->peer_addr,
                               (struct sockaddr *)conn->peer_addr));
    CU_ASSERT(xqc_test_pa_inner_cid(conn, 1)->state == XQC_CID_RETIRED);
    CU_ASSERT(xqc_test_pa_queued(conn, XQC_FRAME_BIT_RETIRE_CONNECTION_ID)
              == 1);

    /* a response after the validation was abandoned changes nothing */
    CU_ASSERT(xqc_test_pa_recv_frame(conn, 0x1b, pa->challenge_data[0])
              == XQC_OK);
    CU_ASSERT(pa->state == XQC_PREFERRED_ADDR_FAILED);
    CU_ASSERT(path->path_dcid.cid_seq_num == old_seq);

    xqc_engine_destroy(conn->engine);
}


/*
 * RFC 9000 Section 9.5: the server answers from its preferred address with
 * a connection ID of the client's that it has not used yet. The client
 * challenges once the server acknowledges one, or after a PTO without.
 */
void
xqc_test_preferred_addr_wait_for_cid()
{
    xqc_connection_t       *conn = xqc_test_pa_offer(2, 4433);
    xqc_preferred_addr_ctx_t *pa = &conn->preferred_addr;
    xqc_timer_t            *timer;
    xqc_usec_t              now = xqc_monotonic_timestamp();

    timer = &conn->conn_timer_manager.timer[XQC_TIMER_PREFERRED_ADDR];
    xqc_conn_preferred_addr_start(conn, now);
    CU_ASSERT(pa->state == XQC_PREFERRED_ADDR_VALIDATING);
    CU_ASSERT(pa->challenge_cnt == 0);
    CU_ASSERT(xqc_test_pa_inner_cid(conn, 1)->state == XQC_CID_USED);
    CU_ASSERT(timer->timer_is_set && timer->expire_time > now);

    /* the acknowledgment brings the first challenge forward */
    now += 1000;
    xqc_test_pa_ack_new_cid(conn, now);
    CU_ASSERT(xqc_get_path_cid_set(&conn->scid_set, XQC_INITIAL_PATH_ID)
              ->acked_unused == 1);
    CU_ASSERT(pa->challenge_cnt == 0);
    CU_ASSERT(timer->timer_is_set && timer->expire_time == now);
    xqc_conn_preferred_addr_on_timeout(conn, now);
    CU_ASSERT(pa->state == XQC_PREFERRED_ADDR_VALIDATING);
    CU_ASSERT(pa->challenge_cnt == 1);
    CU_ASSERT(pa->deadline > now);
    CU_ASSERT(timer->timer_is_set && timer->expire_time > now);

    /* later acknowledgments do not bring the next challenge forward */
    xqc_conn_preferred_addr_on_cid_acked(conn, now + 1000);
    CU_ASSERT(timer->expire_time > now + 1000);
    xqc_engine_destroy(conn->engine);

    /* without an acknowledgment, the client challenges after a PTO */
    conn = xqc_test_pa_offer(2, 4433);
    pa = &conn->preferred_addr;
    timer = &conn->conn_timer_manager.timer[XQC_TIMER_PREFERRED_ADDR];
    now = xqc_monotonic_timestamp();
    xqc_conn_preferred_addr_start(conn, now);
    CU_ASSERT(pa->challenge_cnt == 0);
    now = timer->expire_time;
    xqc_conn_preferred_addr_on_timeout(conn, now);
    CU_ASSERT(pa->state == XQC_PREFERRED_ADDR_VALIDATING);
    CU_ASSERT(pa->challenge_cnt == 1);
    CU_ASSERT(pa->deadline > now);
    xqc_engine_destroy(conn->engine);
}


/* off by default, and not with multipath */
void
xqc_test_preferred_addr_disabled()
{
    xqc_connection_t       *conn = xqc_test_pa_offered_conn(2, 4433);

    conn->conn_settings.enable_preferred_address_migration = XQC_FALSE;
    xqc_conn_preferred_addr_start(conn, xqc_monotonic_timestamp());
    CU_ASSERT(conn->preferred_addr.state == XQC_PREFERRED_ADDR_NONE);
    CU_ASSERT(xqc_test_pa_inner_cid(conn, 1)->state == XQC_CID_UNUSED);
    xqc_engine_destroy(conn->engine);

    conn = xqc_test_pa_offered_conn(2, 4433);
    conn->enable_multipath = XQC_CONN_MP_ENABLED;
    xqc_conn_preferred_addr_start(conn, xqc_monotonic_timestamp());
    CU_ASSERT(conn->preferred_addr.state == XQC_PREFERRED_ADDR_NONE);
    CU_ASSERT(xqc_test_pa_inner_cid(conn, 1)->state == XQC_CID_UNUSED);
    conn->enable_multipath = XQC_CONN_MP_DISABLED;
    xqc_engine_destroy(conn->engine);
}


/*
 * RFC 9000 Section 8.2.2: a PATH_CHALLENGE from the preferred address under
 * validation is answered there, one from the original address on the
 * original path.
 */
void
xqc_test_preferred_addr_challenge_path()
{
    xqc_connection_t       *conn = xqc_test_pa_offered_conn(2, 4433);
    unsigned char           data[XQC_PATH_CHALLENGE_DATA_LEN];

    memset(data, 0x3c, sizeof(data));
    xqc_conn_preferred_addr_start(conn, xqc_monotonic_timestamp());

    xqc_conn_preferred_addr_on_datagram(conn,
        (struct sockaddr *)conn->preferred_addr.addr);
    CU_ASSERT(conn->preferred_addr.recv_from_addr);
    CU_ASSERT(xqc_test_pa_recv_frame(conn, 0x1a, data) == XQC_OK);
    CU_ASSERT(xqc_test_pa_queued(conn, XQC_FRAME_BIT_PATH_RESPONSE) == 0);

    xqc_conn_preferred_addr_on_datagram(conn,
        (struct sockaddr *)conn->peer_addr);
    CU_ASSERT(!conn->preferred_addr.recv_from_addr);
    CU_ASSERT(xqc_test_pa_recv_frame(conn, 0x1a, data) == XQC_OK);
    CU_ASSERT(xqc_test_pa_queued(conn, XQC_FRAME_BIT_PATH_RESPONSE) == 1);
    CU_ASSERT(conn->preferred_addr.state == XQC_PREFERRED_ADDR_VALIDATING);

    xqc_engine_destroy(conn->engine);
}


/*
 * A server can challenge the client's path in the packet of its
 * PATH_RESPONSE (picoquic does): in either order of the frames, the client
 * migrates and answers on the path to the preferred address.
 */
void
xqc_test_preferred_addr_response_and_challenge()
{
    xqc_connection_t       *conn;
    xqc_preferred_addr_ctx_t *pa;
    xqc_path_ctx_t         *path;
    unsigned char           data[XQC_PATH_CHALLENGE_DATA_LEN];
    int                     challenge_first;

    memset(data, 0x3c, sizeof(data));
    for (challenge_first = 0; challenge_first <= 1; challenge_first++) {
        conn = xqc_test_pa_offered_conn(2, 4433);
        pa = &conn->preferred_addr;
        path = conn->conn_initial_path;
        xqc_conn_preferred_addr_start(conn, xqc_monotonic_timestamp());
        CU_ASSERT_FATAL(pa->challenge_cnt == 1);

        xqc_conn_preferred_addr_on_datagram(conn, (struct sockaddr *)pa->addr);
        if (challenge_first) {
            CU_ASSERT(xqc_test_pa_recv_frames(conn, 0x1a, data, 0x1b,
                                              pa->challenge_data[0])
                      == XQC_OK);
            /* answered at once, outside the send queue */
            CU_ASSERT(xqc_test_pa_queued(conn, XQC_FRAME_BIT_PATH_RESPONSE)
                      == 0);

        } else {
            CU_ASSERT(xqc_test_pa_recv_frames(conn, 0x1b,
                                              pa->challenge_data[0], 0x1a,
                                              data)
                      == XQC_OK);
            /* on the migrated path */
            CU_ASSERT(xqc_test_pa_queued(conn, XQC_FRAME_BIT_PATH_RESPONSE)
                      == 1);
        }
        CU_ASSERT(pa->state == XQC_PREFERRED_ADDR_MIGRATED);
        CU_ASSERT(xqc_is_same_addr((struct sockaddr *)path->peer_addr,
                                   (struct sockaddr *)pa->addr));
        CU_ASSERT(conn->conn_err == 0);
        xqc_engine_destroy(conn->engine);
    }
}


/*
 * RFC 9000 Section 18.2: only a server sends preferred_address, and a
 * server with a zero-length connection ID MUST NOT.
 */
void
xqc_test_preferred_addr_transport_params()
{
    xqc_connection_t       *conn = xqc_test_pa_conn();
    xqc_transport_params_t  params;

    xqc_test_pa_params(conn, &conn->local_settings.preferred_address, 2,
                       4433);
    memset(&params, 0, sizeof(params));
    CU_ASSERT(xqc_conn_get_local_transport_params(conn, &params) == XQC_OK);
    CU_ASSERT(params.preferred_address_present == 0);

    conn->conn_type = XQC_CONN_TYPE_SERVER;
    memset(&params, 0, sizeof(params));
    CU_ASSERT(xqc_conn_get_local_transport_params(conn, &params) == XQC_OK);
    CU_ASSERT(params.preferred_address_present == 1);
    CU_ASSERT(params.preferred_address.ipv4_port == 4433);
    conn->conn_type = XQC_CONN_TYPE_CLIENT;

    /* the server's transport parameters, with a zero-length connection ID */
    memset(&params, 0, sizeof(params));
    xqc_test_pa_params(conn, &params.preferred_address, 2, 4433);
    conn->dcid_set.current_dcid.cid_len = 0;
    params.initial_source_connection_id_present = 1;
    params.original_dest_connection_id_present = 1;
    params.original_dest_connection_id = conn->original_dcid;
    CU_ASSERT(xqc_conn_check_transport_params(conn, &params) == XQC_OK);

    params.preferred_address_present = 1;
    CU_ASSERT(xqc_conn_check_transport_params(conn, &params)
              == -XQC_TLS_TRANSPORT_PARAM);

    xqc_engine_destroy(conn->engine);
}


/*
 * A server's preferred address, RFC 9000 Section 9.6.2: a server
 * connection from 127.0.0.1:5000 to 127.0.0.1:443 that offers
 * 127.0.0.1:port, and [::1]:port6 unless port6 is 0
 */
#define XQC_TEST_SPA_CLIENT_PORT    5000

static void
xqc_test_spa_set_sin(struct sockaddr_in *sin, uint8_t last_byte,
    uint16_t port)
{
    memset(sin, 0, sizeof(*sin));
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    sin->sin_addr.s_addr = htonl(0x7f000000u | last_byte);
}


static xqc_connection_t *
xqc_test_spa_conn(uint16_t port, uint16_t port6)
{
    xqc_engine_t           *engine = test_create_engine_server();
    xqc_conn_settings_t     settings;
    struct sockaddr_in      local, peer;
    xqc_cid_t               dcid, scid;
    xqc_connection_t       *conn;

    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);
    settings = engine->default_conn_settings;
    xqc_test_spa_set_sin(&settings.preferred_address.ipv4, 1, port);
    if (port6 != 0) {
        settings.preferred_address.ipv6.sin6_family = AF_INET6;
        settings.preferred_address.ipv6.sin6_port = htons(port6);
        settings.preferred_address.ipv6.sin6_addr.s6_addr[15] = 1;
    }

    xqc_test_spa_set_sin(&local, 1, XQC_TEST_PA_SERVER_PORT);
    xqc_test_spa_set_sin(&peer, 1, XQC_TEST_SPA_CLIENT_PORT);
    memset(&dcid, 0, sizeof(dcid));
    memset(&scid, 0, sizeof(scid));
    dcid.cid_len = XQC_DEFAULT_CID_LEN;
    scid.cid_len = engine->config->cid_len;
    memset(dcid.cid_buf, 0x11, dcid.cid_len);
    memset(scid.cid_buf, 0x22, scid.cid_len);

    conn = xqc_conn_server_create(engine, (struct sockaddr *)&local,
                                  sizeof(local), (struct sockaddr *)&peer,
                                  sizeof(peer), &dcid, &scid, &settings,
                                  NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    return conn;
}


/* the server connection is in no queue of the engine: destroyed first */
static void
xqc_test_spa_destroy(xqc_connection_t *conn)
{
    xqc_engine_t *engine = conn->engine;

    xqc_conn_destroy(conn);
    xqc_engine_destroy(engine);
}


/* the server's local transport parameters, as encoded */
static void
xqc_test_spa_local_tp(xqc_connection_t *conn, xqc_transport_params_t *params)
{
    uint8_t     buf[XQC_MAX_TRANSPORT_PARAM_BUF_LEN];
    size_t      len = 0;

    memset(params, 0, sizeof(*params));
    CU_ASSERT_FATAL(xqc_conn_encode_local_tp(conn, buf, sizeof(buf), &len)
                    == XQC_OK);
    CU_ASSERT_FATAL(xqc_decode_transport_params(params,
                        XQC_TP_TYPE_ENCRYPTED_EXTENSIONS, buf, len)
                    == XQC_OK);
}


/*
 * RFC 9000 Sections 5.1.1 and 18.2: the server offers the addresses with a
 * connection ID of sequence number 1, which reaches the connection, and the
 * stateless reset token of that connection ID; NEW_CONNECTION_ID frames go
 * on from sequence number 2
 */
void
xqc_test_server_preferred_addr_offer()
{
    xqc_connection_t       *conn = xqc_test_spa_conn(4433, 4443);
    xqc_transport_params_t  params;
    xqc_cid_inner_t        *inner;
    uint8_t                 token[XQC_STATELESS_RESET_TOKENLEN];
    uint8_t                 ipv4[4] = {127, 0, 0, 1};
    uint8_t                 ipv6[16] = {0};

    ipv6[15] = 1;
    inner = xqc_get_inner_cid_by_seq(&conn->scid_set, 1, XQC_INITIAL_PATH_ID);
    CU_ASSERT_PTR_NOT_NULL_FATAL(inner);
    CU_ASSERT(inner->state == XQC_CID_UNUSED);
    CU_ASSERT(xqc_engine_conns_hash_find(conn->engine, &inner->cid, 's')
              == conn);
    CU_ASSERT(xqc_cid_set_get_largest_seq_or_rpt(&conn->scid_set,
                                                 XQC_INITIAL_PATH_ID) == 1);

    xqc_test_spa_local_tp(conn, &params);
    CU_ASSERT(params.preferred_address_present == 1);
    CU_ASSERT(memcmp(params.preferred_address.ipv4, ipv4, 4) == 0);
    CU_ASSERT(params.preferred_address.ipv4_port == 4433);
    CU_ASSERT(memcmp(params.preferred_address.ipv6, ipv6, 16) == 0);
    CU_ASSERT(params.preferred_address.ipv6_port == 4443);
    CU_ASSERT(xqc_cid_is_equal(&params.preferred_address.cid, &inner->cid)
              == XQC_OK);
    xqc_gen_reset_token(&inner->cid, token, XQC_STATELESS_RESET_TOKENLEN,
                        conn->engine->config->reset_token_key,
                        conn->engine->config->reset_token_keylen);
    CU_ASSERT(memcmp(params.preferred_address.stateless_reset_token, token,
                     XQC_STATELESS_RESET_TOKENLEN) == 0);

    conn->remote_settings.active_connection_id_limit = 8;
    CU_ASSERT(xqc_write_new_conn_id_frame_to_packet(conn, 0) == XQC_OK);
    CU_ASSERT_PTR_NOT_NULL(xqc_get_inner_cid_by_seq(&conn->scid_set, 2,
                                                    XQC_INITIAL_PATH_ID));

    xqc_test_spa_destroy(conn);
}


/*
 * An address without a port offers nothing, and RFC 9000 Section 18.2: "A
 * server that chooses a zero-length connection ID MUST NOT provide a
 * preferred address."
 */
void
xqc_test_server_preferred_addr_not_offered()
{
    xqc_connection_t       *conn = xqc_test_spa_conn(0, 0);
    xqc_transport_params_t  params;
    uint8_t                 cid_len;

    CU_ASSERT_PTR_NULL(xqc_get_inner_cid_by_seq(&conn->scid_set, 1,
                                                XQC_INITIAL_PATH_ID));
    xqc_test_spa_local_tp(conn, &params);
    CU_ASSERT(params.preferred_address_present == 0);
    CU_ASSERT(conn->server_preferred_addr.state == XQC_PREFERRED_ADDR_NONE);
    xqc_test_spa_destroy(conn);

    conn = xqc_test_spa_conn(4433, 0);
    memset(&conn->local_settings.preferred_address, 0,
           sizeof(conn->local_settings.preferred_address));
    conn->server_preferred_addr.state = XQC_PREFERRED_ADDR_NONE;
    cid_len = conn->scid_set.user_scid.cid_len;
    conn->scid_set.user_scid.cid_len = 0;
    CU_ASSERT(xqc_conn_server_preferred_addr_init(conn) == XQC_OK);
    CU_ASSERT(conn->server_preferred_addr.state == XQC_PREFERRED_ADDR_NONE);
    CU_ASSERT(conn->local_settings.preferred_address.cid.cid_len == 0);
    conn->scid_set.user_scid.cid_len = cid_len;
    xqc_test_spa_destroy(conn);
}


/* the handshake is confirmed, and a connection ID of the client's unused */
static void
xqc_test_spa_ready(xqc_connection_t *conn)
{
    xqc_cid_t   cid;

    conn->conn_flag |= XQC_CONN_FLAG_HANDSHAKE_COMPLETED
                       | XQC_CONN_FLAG_HANDSHAKE_CONFIRMED;
    memset(&cid, 0, sizeof(cid));
    cid.cid_len = conn->dcid_set.current_dcid.cid_len;
    memset(cid.cid_buf, 0x61, cid.cid_len);
    cid.cid_seq_num = 1;
    CU_ASSERT_FATAL(xqc_cid_set_insert_cid(&conn->dcid_set, &cid,
                                           XQC_CID_UNUSED, 8,
                                           XQC_INITIAL_PATH_ID) == XQC_OK);
}


/* a datagram of size bytes from 127.0.0.<peer>:5000 reaches 127.0.0.1:port */
static void
xqc_test_spa_datagram_size(xqc_connection_t *conn, uint16_t port,
    uint8_t peer, size_t size)
{
    struct sockaddr_in  local, from;

    xqc_test_spa_set_sin(&local, 1, port);
    xqc_test_spa_set_sin(&from, peer, XQC_TEST_SPA_CLIENT_PORT);
    xqc_conn_server_preferred_addr_on_datagram(conn,
        (struct sockaddr *)&local, (struct sockaddr *)&from, sizeof(from),
        size);
}


static void
xqc_test_spa_datagram(xqc_connection_t *conn, uint16_t port, uint8_t peer)
{
    xqc_test_spa_datagram_size(conn, port, peer,
                               XQC_PACKET_INITIAL_MIN_LENGTH);
}


/* the datagram held an authenticated 1-RTT packet with frame_types */
static void
xqc_test_spa_packet(xqc_connection_t *conn, xqc_packet_number_t pn,
    xqc_frame_type_bit_t frame_types)
{
    xqc_packet_in_t     packet_in;
    xqc_pn_ctl_t       *pn_ctl = xqc_get_pn_ctl(conn, conn->conn_initial_path);

    memset(&packet_in, 0, sizeof(packet_in));
    packet_in.pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    packet_in.pi_pkt.pkt_pns = XQC_PNS_APP_DATA;
    packet_in.pi_pkt.pkt_num = pn;
    packet_in.pi_frame_types = frame_types;
    xqc_conn_server_preferred_addr_on_packet(conn, &packet_in);
    xqc_recv_record_add(&pn_ctl->ctl_recv_record[XQC_PNS_APP_DATA], pn);
    conn->rcv_pkt_stats.conn_authenticated_pkts++;
}


/* the end of the datagram */
static void
xqc_test_spa_processed(xqc_connection_t *conn, xqc_usec_t now)
{
    xqc_conn_server_preferred_addr_on_processed(conn, now);
    conn->server_preferred_addr.recv_at_addr = XQC_FALSE;
}


/*
 * RFC 9000 Section 9.6.2: the server answers there a PATH_CHALLENGE that
 * reached its preferred address, with a connection ID of the client's not
 * used yet (Section 9.5) and a PATH_CHALLENGE of its own, and moves there
 * once that path is validated and a non-probing packet came there; the
 * original connection ID is retired, and a new port keeps the RTT
 */
void
xqc_test_server_preferred_addr_migrate()
{
    xqc_connection_t                *conn = xqc_test_spa_conn(4433, 0);
    xqc_server_preferred_addr_ctx_t *spa = &conn->server_preferred_addr;
    xqc_path_ctx_t                  *path = conn->conn_initial_path;
    xqc_send_ctl_t                  *send_ctl = path->path_send_ctl;
    struct sockaddr_in               preferred, local;
    socklen_t                        local_len = 0;
    unsigned char                    data[XQC_PATH_CHALLENGE_DATA_LEN];
    uint64_t                         old_seq = path->path_dcid.cid_seq_num;

    xqc_test_spa_ready(conn);
    xqc_test_spa_set_sin(&preferred, 1, 4433);
    send_ctl->ctl_srtt = 1234;
    memset(data, 0x3c, sizeof(data));

    xqc_test_spa_datagram(conn, 4433, 1);
    CU_ASSERT(spa->recv_at_addr);
    CU_ASSERT(xqc_test_pa_recv_frame(conn, 0x1a, data) == XQC_OK);
    xqc_test_spa_packet(conn, 10, XQC_FRAME_BIT_PATH_CHALLENGE
                                  | XQC_FRAME_BIT_PADDING);
    xqc_test_spa_processed(conn, xqc_monotonic_timestamp());
    CU_ASSERT(spa->state == XQC_PREFERRED_ADDR_VALIDATING);
    CU_ASSERT(spa->challenge_cnt == 1);
    CU_ASSERT(spa->dcid.cid_seq_num == 1);
    CU_ASSERT(xqc_test_pa_inner_cid(conn, 1)->state == XQC_CID_USED);
    /* not answered from the original address (Section 8.2.2) */
    CU_ASSERT(xqc_test_pa_queued(conn, XQC_FRAME_BIT_PATH_RESPONSE) == 0);
    CU_ASSERT(!spa->non_probing_recvd);

    /* the response, from the original address, validates the path */
    xqc_test_spa_datagram(conn, XQC_TEST_PA_SERVER_PORT, 1);
    CU_ASSERT(!spa->recv_at_addr);
    CU_ASSERT(xqc_test_pa_recv_frame(conn, 0x1b, spa->challenge_data[0])
              == XQC_OK);
    xqc_test_spa_packet(conn, 11, XQC_FRAME_BIT_PATH_RESPONSE
                                  | XQC_FRAME_BIT_ACK);
    xqc_test_spa_processed(conn, xqc_monotonic_timestamp());
    CU_ASSERT(spa->validated);
    CU_ASSERT(spa->state == XQC_PREFERRED_ADDR_VALIDATING);
    CU_ASSERT(xqc_conn_get_local_addr(conn, (struct sockaddr *)&local,
                                      sizeof(local), &local_len) == XQC_OK);
    CU_ASSERT(local.sin_port == htons(XQC_TEST_PA_SERVER_PORT));

    /* a non-probing packet with a new largest packet number there */
    xqc_test_spa_datagram(conn, 4433, 1);
    xqc_test_spa_packet(conn, 12, XQC_FRAME_BIT_STREAM);
    CU_ASSERT(spa->non_probing_recvd);
    xqc_test_spa_processed(conn, xqc_monotonic_timestamp());
    CU_ASSERT(spa->state == XQC_PREFERRED_ADDR_MIGRATED);
    CU_ASSERT(xqc_conn_get_local_addr(conn, (struct sockaddr *)&local,
                                      sizeof(local), &local_len) == XQC_OK);
    CU_ASSERT(local_len == sizeof(preferred)
              && memcmp(&local, &preferred, sizeof(preferred)) == 0);
    CU_ASSERT(xqc_path_get_local_addr(conn, XQC_INITIAL_PATH_ID,
                                      (struct sockaddr *)&local,
                                      sizeof(local), &local_len) == XQC_OK);
    CU_ASSERT(memcmp(&local, &preferred, sizeof(preferred)) == 0);
    CU_ASSERT(path->path_dcid.cid_seq_num == 1);
    CU_ASSERT(conn->dcid_set.current_dcid.cid_seq_num == 1);
    CU_ASSERT(xqc_test_pa_inner_cid(conn, old_seq)->state == XQC_CID_RETIRED);
    CU_ASSERT(xqc_test_pa_queued(conn, XQC_FRAME_BIT_RETIRE_CONNECTION_ID)
              == 1);
    CU_ASSERT(send_ctl->ctl_srtt == 1234);

    /* a late response to the challenge changes nothing */
    CU_ASSERT(xqc_test_pa_recv_frame(conn, 0x1b, spa->challenge_data[0])
              == XQC_OK);
    CU_ASSERT(spa->state == XQC_PREFERRED_ADDR_MIGRATED);
    CU_ASSERT(conn->conn_err == 0);

    xqc_test_spa_destroy(conn);
}


/*
 * RFC 9000 Section 9.6.2: no move before the path is validated and a
 * non-probing packet with a new largest packet number came there; probing
 * packets, older packets and packets to the original address do not count
 */
void
xqc_test_server_preferred_addr_order()
{
    xqc_connection_t                *conn = xqc_test_spa_conn(4433, 0);
    xqc_server_preferred_addr_ctx_t *spa = &conn->server_preferred_addr;
    unsigned char                    data[XQC_PATH_CHALLENGE_DATA_LEN];
    xqc_usec_t                       now = xqc_monotonic_timestamp();

    xqc_test_spa_ready(conn);
    memset(data, 0x3c, sizeof(data));

    /* non-probing before the validation */
    xqc_test_spa_datagram(conn, 4433, 1);
    CU_ASSERT(xqc_test_pa_recv_frame(conn, 0x1a, data) == XQC_OK);
    xqc_test_spa_packet(conn, 20, XQC_FRAME_BIT_PATH_CHALLENGE
                                  | XQC_FRAME_BIT_STREAM);
    xqc_test_spa_processed(conn, now);
    CU_ASSERT(spa->non_probing_recvd);
    CU_ASSERT(!spa->validated);
    CU_ASSERT(spa->state == XQC_PREFERRED_ADDR_VALIDATING);

    /* validated, but the non-probing packet came before: still needed */
    xqc_test_spa_datagram(conn, XQC_TEST_PA_SERVER_PORT, 1);
    spa->non_probing_recvd = XQC_FALSE;
    CU_ASSERT(xqc_test_pa_recv_frame(conn, 0x1b, spa->challenge_data[0])
              == XQC_OK);
    xqc_test_spa_packet(conn, 21, XQC_FRAME_BIT_PATH_RESPONSE
                                  | XQC_FRAME_BIT_STREAM);
    xqc_test_spa_processed(conn, now);
    CU_ASSERT(spa->validated);
    CU_ASSERT(spa->state == XQC_PREFERRED_ADDR_VALIDATING);

    /* a probing packet, then an older one, reach the preferred address */
    xqc_test_spa_datagram(conn, 4433, 1);
    xqc_test_spa_packet(conn, 22, XQC_FRAME_BIT_PATH_CHALLENGE
                                  | XQC_FRAME_BIT_NEW_CONNECTION_ID
                                  | XQC_FRAME_BIT_PADDING);
    xqc_test_spa_processed(conn, now);
    xqc_test_spa_datagram(conn, 4433, 1);
    xqc_test_spa_packet(conn, 19, XQC_FRAME_BIT_STREAM);
    xqc_test_spa_processed(conn, now);
    CU_ASSERT(!spa->non_probing_recvd);
    CU_ASSERT(spa->state == XQC_PREFERRED_ADDR_VALIDATING);

    /* then a new one */
    xqc_test_spa_datagram(conn, 4433, 1);
    xqc_test_spa_packet(conn, 23, XQC_FRAME_BIT_ACK);
    xqc_test_spa_processed(conn, now);
    CU_ASSERT(spa->state == XQC_PREFERRED_ADDR_MIGRATED);

    xqc_test_spa_destroy(conn);
}


/*
 * RFC 9000 Section 9.5: without a connection ID of the client's not used
 * yet, a PATH_CHALLENGE at the preferred address is dropped rather than
 * answered from the original address (Section 8.2.2)
 */
void
xqc_test_server_preferred_addr_no_cid()
{
    xqc_connection_t                *conn = xqc_test_spa_conn(4433, 0);
    xqc_server_preferred_addr_ctx_t *spa = &conn->server_preferred_addr;
    unsigned char                    data[XQC_PATH_CHALLENGE_DATA_LEN];

    conn->conn_flag |= XQC_CONN_FLAG_HANDSHAKE_COMPLETED
                       | XQC_CONN_FLAG_HANDSHAKE_CONFIRMED;
    memset(data, 0x3c, sizeof(data));
    xqc_test_spa_datagram(conn, 4433, 1);
    CU_ASSERT(xqc_test_pa_recv_frame(conn, 0x1a, data) == XQC_OK);
    xqc_test_spa_packet(conn, 30, XQC_FRAME_BIT_PATH_CHALLENGE);
    xqc_test_spa_processed(conn, xqc_monotonic_timestamp());
    CU_ASSERT(spa->state == XQC_PREFERRED_ADDR_OFFERED);
    CU_ASSERT(spa->challenge_cnt == 0);
    CU_ASSERT(xqc_test_pa_queued(conn, XQC_FRAME_BIT_PATH_RESPONSE) == 0);

    xqc_test_spa_destroy(conn);
}


/*
 * RFC 9000 Sections 8.2.4 and 9.4: without a response, the server
 * challenges again no sooner than a PTO, then gives up after three times
 * the larger of the PTO and the initial one, stays, and retires the
 * connection ID of the probes (Section 9.5)
 */
void
xqc_test_server_preferred_addr_give_up()
{
    xqc_connection_t                *conn = xqc_test_spa_conn(4433, 0);
    xqc_server_preferred_addr_ctx_t *spa = &conn->server_preferred_addr;
    unsigned char                    data[XQC_PATH_CHALLENGE_DATA_LEN];
    xqc_usec_t                       now, pto;

    xqc_test_spa_ready(conn);
    memset(data, 0x3c, sizeof(data));
    xqc_test_spa_datagram(conn, 4433, 1);
    CU_ASSERT(xqc_test_pa_recv_frame(conn, 0x1a, data) == XQC_OK);
    xqc_test_spa_packet(conn, 40, XQC_FRAME_BIT_PATH_CHALLENGE);
    now = spa->challenge_time;
    xqc_test_spa_processed(conn, now);
    CU_ASSERT_FATAL(spa->challenge_cnt == 1);
    pto = xqc_conn_get_max_pto(conn);
    CU_ASSERT(spa->deadline >= now + 3 * pto);

    /* the client moved there, but did not answer */
    xqc_test_spa_datagram(conn, 4433, 1);
    xqc_test_spa_packet(conn, 41, XQC_FRAME_BIT_STREAM);
    xqc_test_spa_processed(conn, now + pto - 1);
    CU_ASSERT(spa->challenge_cnt == 1);
    xqc_test_spa_datagram(conn, 4433, 1);
    xqc_test_spa_packet(conn, 42, XQC_FRAME_BIT_ACK);
    xqc_test_spa_processed(conn, now + pto);
    CU_ASSERT(spa->challenge_cnt == 2);
    CU_ASSERT(spa->state == XQC_PREFERRED_ADDR_VALIDATING);

    xqc_test_spa_datagram(conn, 4433, 1);
    xqc_test_spa_packet(conn, 43, XQC_FRAME_BIT_ACK);
    xqc_test_spa_processed(conn, spa->deadline);
    CU_ASSERT(spa->state == XQC_PREFERRED_ADDR_FAILED);
    CU_ASSERT(xqc_test_pa_inner_cid(conn, 1)->state == XQC_CID_RETIRED);
    CU_ASSERT(xqc_test_pa_queued(conn, XQC_FRAME_BIT_RETIRE_CONNECTION_ID)
              == 1);

    /* a late response does not move it, nor is an error */
    CU_ASSERT(xqc_test_pa_recv_frame(conn, 0x1b, spa->challenge_data[0])
              == XQC_OK);
    xqc_test_spa_datagram(conn, 4433, 1);
    xqc_test_spa_packet(conn, 44, XQC_FRAME_BIT_STREAM);
    xqc_test_spa_processed(conn, spa->deadline + 1);
    CU_ASSERT(spa->state == XQC_PREFERRED_ADDR_FAILED);
    CU_ASSERT(conn->local_addrlen == sizeof(struct sockaddr_in)
              && ((struct sockaddr_in *)conn->local_addr)->sin_port
                 == htons(XQC_TEST_PA_SERVER_PORT));
    CU_ASSERT(conn->conn_err == 0);

    xqc_test_spa_destroy(conn);
}


static int xqc_test_spa_peer_changes;

static void
xqc_test_spa_peer_addr_changed(xqc_connection_t *conn, void *user_data)
{
    xqc_test_spa_peer_changes++;
}


/*
 * RFC 9000 Section 9.6.3: a new client address at the preferred address is
 * validated there, and the server moves to it as well; its new IP address
 * restarts the congestion controller and the RTT estimator (Section 9.4)
 */
void
xqc_test_server_preferred_addr_new_client_addr()
{
    xqc_connection_t                *conn = xqc_test_spa_conn(4433, 0);
    xqc_server_preferred_addr_ctx_t *spa = &conn->server_preferred_addr;
    xqc_send_ctl_t                  *send_ctl;
    unsigned char                    data[XQC_PATH_CHALLENGE_DATA_LEN];
    struct sockaddr_in              *peer;

    xqc_test_spa_ready(conn);
    send_ctl = conn->conn_initial_path->path_send_ctl;
    send_ctl->ctl_srtt = 1234;
    xqc_test_spa_peer_changes = 0;
    conn->transport_cbs.conn_peer_addr_changed_notify =
        xqc_test_spa_peer_addr_changed;
    memset(data, 0x3c, sizeof(data));

    xqc_test_spa_datagram(conn, 4433, 2);
    CU_ASSERT(xqc_test_pa_recv_frame(conn, 0x1a, data) == XQC_OK);
    CU_ASSERT(spa->recv_bytes == XQC_PACKET_INITIAL_MIN_LENGTH);
    CU_ASSERT(xqc_test_pa_recv_frame(conn, 0x1b, spa->challenge_data[0])
              == XQC_OK);
    xqc_test_spa_packet(conn, 50, XQC_FRAME_BIT_STREAM);
    xqc_test_spa_processed(conn, xqc_monotonic_timestamp());

    CU_ASSERT(spa->state == XQC_PREFERRED_ADDR_MIGRATED);
    peer = (struct sockaddr_in *)conn->conn_initial_path->peer_addr;
    CU_ASSERT(peer->sin_addr.s_addr == htonl(0x7f000002));
    peer = (struct sockaddr_in *)conn->peer_addr;
    CU_ASSERT(peer->sin_addr.s_addr == htonl(0x7f000002));
    CU_ASSERT(xqc_test_spa_peer_changes == 1);
    CU_ASSERT(send_ctl->ctl_srtt == conn->conn_settings.initial_rtt);

    xqc_test_spa_destroy(conn);
}


/*
 * RFC 9000 Section 9.3.2: a datagram that reaches the preferred address
 * from another address, without an authenticated packet, changes nothing:
 * the server moves with the client address it validated
 */
void
xqc_test_server_preferred_addr_spoofed()
{
    xqc_connection_t                *conn = xqc_test_spa_conn(4433, 0);
    xqc_server_preferred_addr_ctx_t *spa = &conn->server_preferred_addr;
    unsigned char                    data[XQC_PATH_CHALLENGE_DATA_LEN];
    xqc_usec_t                       now = xqc_monotonic_timestamp();
    struct sockaddr_in              *peer;

    xqc_test_spa_ready(conn);
    memset(data, 0x3c, sizeof(data));
    xqc_test_spa_datagram(conn, 4433, 1);
    CU_ASSERT(xqc_test_pa_recv_frame(conn, 0x1a, data) == XQC_OK);
    CU_ASSERT(xqc_test_pa_recv_frame(conn, 0x1b, spa->challenge_data[0])
              == XQC_OK);
    xqc_test_spa_packet(conn, 60, XQC_FRAME_BIT_PATH_CHALLENGE
                                  | XQC_FRAME_BIT_PATH_RESPONSE);
    xqc_test_spa_processed(conn, now);
    CU_ASSERT_FATAL(spa->validated);

    xqc_test_spa_datagram(conn, 4433, 3);
    xqc_test_spa_processed(conn, now);
    peer = (struct sockaddr_in *)spa->peer_addr;
    CU_ASSERT(spa->validated);
    CU_ASSERT(peer->sin_addr.s_addr == htonl(0x7f000001));
    CU_ASSERT(spa->recv_bytes == XQC_PACKET_INITIAL_MIN_LENGTH);
    CU_ASSERT(spa->challenge_cnt == 1);

    xqc_test_spa_datagram(conn, 4433, 1);
    xqc_test_spa_packet(conn, 61, XQC_FRAME_BIT_STREAM);
    xqc_test_spa_processed(conn, now);
    CU_ASSERT(spa->state == XQC_PREFERRED_ADDR_MIGRATED);
    peer = (struct sockaddr_in *)conn->conn_initial_path->peer_addr;
    CU_ASSERT(peer->sin_addr.s_addr == htonl(0x7f000001));

    xqc_test_spa_destroy(conn);
}


/*
 * RFC 9000 Section 8.2.1: toward a new client address, the server's
 * PATH_CHALLENGE waits until the anti-amplification limit permits a
 * datagram of 1200 bytes, so that the path MTU is validated with the path;
 * the PATH_RESPONSE goes meanwhile, within the limit (Section 8.2.2)
 */
void
xqc_test_server_preferred_addr_padding()
{
    xqc_connection_t                *conn = xqc_test_spa_conn(4433, 0);
    xqc_server_preferred_addr_ctx_t *spa = &conn->server_preferred_addr;
    unsigned char                    data[XQC_PATH_CHALLENGE_DATA_LEN];
    xqc_usec_t                       now = xqc_monotonic_timestamp();

    xqc_test_spa_ready(conn);
    memset(data, 0x3c, sizeof(data));

    /* 100 bytes from a new client address: 300 bytes may go there */
    xqc_test_spa_datagram_size(conn, 4433, 2, 100);
    CU_ASSERT(xqc_test_pa_recv_frame(conn, 0x1a, data) == XQC_OK);
    xqc_test_spa_packet(conn, 70, XQC_FRAME_BIT_PATH_CHALLENGE);
    xqc_test_spa_processed(conn, now);
    CU_ASSERT(spa->recv_bytes == 100);
    CU_ASSERT(spa->challenge_cnt == 0);
    CU_ASSERT(spa->state == XQC_PREFERRED_ADDR_OFFERED);
    CU_ASSERT(xqc_test_pa_queued(conn, XQC_FRAME_BIT_PATH_RESPONSE) == 0);

    /* 300 more: 1200 bytes may go there */
    xqc_test_spa_datagram_size(conn, 4433, 2, 300);
    xqc_test_spa_packet(conn, 71, XQC_FRAME_BIT_ACK);
    xqc_test_spa_processed(conn, now);
    CU_ASSERT(spa->recv_bytes == 400);
    CU_ASSERT(spa->challenge_cnt == 1);
    CU_ASSERT(spa->state == XQC_PREFERRED_ADDR_VALIDATING);

    xqc_test_spa_destroy(conn);
}


/* not with multipath: what reaches the preferred address is not apart */
void
xqc_test_server_preferred_addr_multipath()
{
    xqc_connection_t   *conn = xqc_test_spa_conn(4433, 0);
    unsigned char       data[XQC_PATH_CHALLENGE_DATA_LEN];

    xqc_test_spa_ready(conn);
    conn->enable_multipath = XQC_CONN_MP_ENABLED;
    memset(data, 0x3c, sizeof(data));
    xqc_test_spa_datagram(conn, 4433, 1);
    CU_ASSERT(!conn->server_preferred_addr.recv_at_addr);
    CU_ASSERT(!xqc_conn_server_preferred_addr_on_challenge(conn, data));
    CU_ASSERT(conn->server_preferred_addr.state
              == XQC_PREFERRED_ADDR_OFFERED);
    conn->enable_multipath = XQC_CONN_MP_DISABLED;

    xqc_test_spa_destroy(conn);
}
