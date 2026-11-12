/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <string.h>
#include <CUnit/CUnit.h>

#include "xqc_ecn_test.h"
#include "xqc_common_test.h"

#include "src/common/xqc_time.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_recv_record.h"
#include "src/transport/xqc_recv_timestamps_info.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_transport_params.h"
#include "src/common/xqc_malloc.h"

/* not exposed in a header */
void xqc_conn_record_single(xqc_connection_t *c, xqc_packet_in_t *packet_in);
ssize_t xqc_send_burst(xqc_connection_t *conn, xqc_path_ctx_t *path,
    struct iovec *iov, int cnt);
void xqc_on_packets_send_burst(xqc_connection_t *conn, xqc_path_ctx_t *path,
    ssize_t sent, xqc_usec_t now, xqc_send_type_t send_type);
ssize_t xqc_send(xqc_connection_t *conn, xqc_path_ctx_t *path,
    unsigned char *data, unsigned int len);


/* record a received ack-eliciting 1-RTT packet that came with ecn */
static void
xqc_test_ecn_recv(xqc_connection_t *conn, xqc_packet_number_t pkt_num,
    uint8_t ecn)
{
    xqc_packet_in_t pi;

    memset(&pi, 0, sizeof(pi));
    pi.pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    pi.pi_pkt.pkt_pns = XQC_PNS_APP_DATA;
    pi.pi_pkt.pkt_num = pkt_num;
    pi.pi_frame_types = XQC_FRAME_BIT_PING;
    pi.pi_path_id = conn->conn_initial_path->path_id;
    pi.pkt_recv_time = xqc_monotonic_timestamp();
    pi.pi_ecn = ecn;
    xqc_conn_record_single(conn, &pi);
}


static xqc_bool_t
xqc_test_ecn_should_ack(xqc_connection_t *conn)
{
    return (conn->conn_initial_path->path_flag
            & (XQC_PATH_FLAG_SHOULD_ACK_INIT << XQC_PNS_APP_DATA)) != 0;
}


static void
xqc_test_ecn_clear_ack(xqc_connection_t *conn)
{
    conn->conn_initial_path->path_flag &=
        ~(XQC_PATH_FLAG_SHOULD_ACK_INIT << XQC_PNS_APP_DATA);
    conn->conn_initial_path->path_send_ctl->ctl_ack_eliciting_pkt[
        XQC_PNS_APP_DATA] = 0;
}


/*
 * RFC 9000 Section 13.4.1: count the codepoint of each packet that is not a
 * duplicate, per packet number space. Section 13.2.1: acknowledge a packet
 * marked CE immediately.
 */
void
xqc_test_ecn_recv_counts(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT;
    xqc_pn_ctl_t *pn_ctl = xqc_get_pn_ctl(conn, conn->conn_initial_path);
    xqc_ecn_counts_t *cnt = &pn_ctl->ctl_ecn_recv[XQC_PNS_APP_DATA];

    xqc_test_ecn_recv(conn, 1, XQC_ECN_ECT_0);
    xqc_test_ecn_recv(conn, 2, XQC_ECN_ECT_0);
    xqc_test_ecn_recv(conn, 3, XQC_ECN_ECT_1);
    xqc_test_ecn_recv(conn, 4, XQC_ECN_NOT_ECT);
    CU_ASSERT_EQUAL(cnt->ect0, 2);
    CU_ASSERT_EQUAL(cnt->ect1, 1);
    CU_ASSERT_EQUAL(cnt->ce, 0);

    /* a duplicate is not counted */
    xqc_test_ecn_recv(conn, 2, XQC_ECN_ECT_0);
    CU_ASSERT_EQUAL(cnt->ect0, 2);

    /* one in-order packet does not trigger an ACK by itself */
    xqc_test_ecn_clear_ack(conn);
    xqc_test_ecn_recv(conn, 5, XQC_ECN_ECT_0);
    CU_ASSERT_EQUAL(cnt->ect0, 3);
    CU_ASSERT(!xqc_test_ecn_should_ack(conn));

    /* the same with CE does */
    xqc_test_ecn_clear_ack(conn);
    xqc_test_ecn_recv(conn, 6, XQC_ECN_CE);
    CU_ASSERT_EQUAL(cnt->ce, 1);
    CU_ASSERT(xqc_test_ecn_should_ack(conn));

    /* other spaces keep their own counts */
    CU_ASSERT_EQUAL(pn_ctl->ctl_ecn_recv[XQC_PNS_INIT].ect0, 0);
    CU_ASSERT_EQUAL(pn_ctl->ctl_ecn_recv[XQC_PNS_HSK].ect0, 0);

    xqc_engine_destroy(conn->engine);
}


/* write an ACK frame of the 1-RTT space and parse it back */
static void
xqc_test_ecn_ack_roundtrip(xqc_connection_t *conn,
    const xqc_ecn_counts_t *counts, uint8_t expect_type,
    xqc_ack_info_t *ack_info)
{
    xqc_pn_ctl_t *pn_ctl = xqc_get_pn_ctl(conn, conn->conn_initial_path);
    xqc_packet_out_t *po = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT_FATAL(po != NULL);

    int has_gap = 0;
    xqc_packet_number_t largest_ack = 0;
    xqc_usec_t now = xqc_monotonic_timestamp();
    size_t off = po->po_used_size;
    ssize_t len = xqc_gen_ack_frame(conn, po, now, 3,
                                    &pn_ctl->ctl_recv_record[XQC_PNS_APP_DATA],
                                    counts, now, &has_gap, &largest_ack);
    CU_ASSERT_FATAL(len > 0);
    CU_ASSERT_EQUAL(po->po_buf[off], expect_type);

    xqc_packet_in_t pi;
    memset(&pi, 0, sizeof(pi));
    pi.pi_pkt.pkt_pns = XQC_PNS_APP_DATA;
    pi.pos = po->po_buf + off;
    pi.last = pi.pos + len;
    memset(ack_info, 0xff, sizeof(*ack_info));
    CU_ASSERT_EQUAL(xqc_parse_ack_frame(&pi, conn, ack_info), XQC_OK);
    CU_ASSERT(pi.pos == pi.last);
    CU_ASSERT_EQUAL(ack_info->largest_acked, 9);
}


/* RFC 9000 Section 19.3.2: ACK frames of type 0x03 carry the counts */
void
xqc_test_ecn_ack_frame_counts(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_pn_ctl_t *pn_ctl = xqc_get_pn_ctl(conn, conn->conn_initial_path);
    xqc_recv_record_add(&pn_ctl->ctl_recv_record[XQC_PNS_APP_DATA], 9);

    /* counts that need two-byte and one-byte variable-length integers */
    xqc_ecn_counts_t counts = {.ect0 = 300, .ect1 = 0, .ce = 2};
    xqc_ack_info_t ack_info;
    xqc_test_ecn_ack_roundtrip(conn, &counts, 0x03, &ack_info);
    CU_ASSERT(ack_info.ecn_present);
    CU_ASSERT_EQUAL(ack_info.ecn.ect0, 300);
    CU_ASSERT_EQUAL(ack_info.ecn.ect1, 0);
    CU_ASSERT_EQUAL(ack_info.ecn.ce, 2);

    /* no codepoint received yet, or none known: a plain ACK frame */
    memset(&counts, 0, sizeof(counts));
    xqc_test_ecn_ack_roundtrip(conn, &counts, 0x02, &ack_info);
    CU_ASSERT(!ack_info.ecn_present);
    xqc_test_ecn_ack_roundtrip(conn, NULL, 0x02, &ack_info);
    CU_ASSERT(!ack_info.ecn_present);

    xqc_engine_destroy(conn->engine);
}


/*
 * draft-ietf-quic-multipath-10 Section 7.1: an ACK_MP frame with ECN Counts
 * has the type 0x15228c01
 */
void
xqc_test_ecn_ack_mp_frame_counts(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    conn->conn_settings.multipath_version = XQC_MULTIPATH_10;
    xqc_pn_ctl_t *pn_ctl = xqc_get_pn_ctl(conn, conn->conn_initial_path);
    xqc_recv_record_add(&pn_ctl->ctl_recv_record[XQC_PNS_APP_DATA], 9);

    const xqc_ecn_counts_t counts = {.ect0 = 70, .ect1 = 0, .ce = 1};
    for (int with_ecn = 0; with_ecn <= 1; with_ecn++) {
        xqc_packet_out_t *po = xqc_write_new_packet(conn,
                                                    XQC_PTYPE_SHORT_HEADER);
        CU_ASSERT_FATAL(po != NULL);
        int has_gap = 0;
        xqc_packet_number_t largest_ack = 0;
        xqc_usec_t now = xqc_monotonic_timestamp();
        size_t off = po->po_used_size;
        ssize_t len = xqc_gen_ack_mp_frame(conn, 2, po, now, 3,
            &pn_ctl->ctl_recv_record[XQC_PNS_APP_DATA],
            with_ecn ? &counts : NULL, now, &has_gap, &largest_ack);
        CU_ASSERT_FATAL(len > 0);

        uint64_t type = 0;
        CU_ASSERT(xqc_vint_read(po->po_buf + off, po->po_buf + off + len,
                                &type) > 0);
        CU_ASSERT_EQUAL(type, with_ecn ? XQC_TRANS_FRAME_TYPE_MP_ACK1
                                       : XQC_TRANS_FRAME_TYPE_MP_ACK0);

        xqc_packet_in_t pi;
        xqc_ack_info_t ack_info;
        uint64_t path_id = 0;
        memset(&pi, 0, sizeof(pi));
        pi.pi_pkt.pkt_pns = XQC_PNS_APP_DATA;
        pi.pos = po->po_buf + off;
        pi.last = pi.pos + len;
        CU_ASSERT_EQUAL(xqc_parse_ack_mp_frame(&pi, conn, &path_id,
                                               &ack_info), XQC_OK);
        CU_ASSERT(pi.pos == pi.last);
        CU_ASSERT_EQUAL(path_id, 2);
        CU_ASSERT_EQUAL(ack_info.largest_acked, 9);
        CU_ASSERT_EQUAL(ack_info.ecn_present, with_ecn);
        if (with_ecn) {
            CU_ASSERT_EQUAL(ack_info.ecn.ect0, 70);
            CU_ASSERT_EQUAL(ack_info.ecn.ect1, 0);
            CU_ASSERT_EQUAL(ack_info.ecn.ce, 1);
        }
    }

    xqc_engine_destroy(conn->engine);
}


static int                  g_ecn_write_calls;
static xqc_ecn_codepoint_t  g_ecn_written;

static ssize_t
xqc_test_ecn_write_cb(uint64_t path_id, const unsigned char *buf,
    size_t size, const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    xqc_ecn_codepoint_t ecn, void *conn_user_data)
{
    g_ecn_write_calls++;
    g_ecn_written = ecn;
    return size;
}


/* a 1-RTT packet sent on the initial path after the last write */
static xqc_packet_out_t *
xqc_test_ecn_send(xqc_connection_t *conn, xqc_packet_number_t pkt_num)
{
    xqc_send_queue_t *sq = conn->conn_send_queue;
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    xqc_packet_out_t *po = xqc_packet_out_get(sq);
    if (po == NULL) {
        return NULL;
    }

    po->po_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    po->po_pkt.pkt_pns = XQC_PNS_APP_DATA;
    po->po_pkt.pkt_num = pkt_num;
    po->po_path_id = send_ctl->ctl_path->path_id;
    po->po_frame_types = XQC_FRAME_BIT_PING;
    po->po_flag = XQC_POF_IN_FLIGHT;
    po->po_sent_time = xqc_monotonic_timestamp();
    xqc_send_ctl_on_packet_sent(send_ctl,
                                xqc_get_pn_ctl(conn, conn->conn_initial_path),
                                po, po->po_sent_time);
    xqc_send_queue_insert_unacked(po,
        &sq->sndq_unacked_packets[XQC_PNS_APP_DATA], sq);
    return po;
}


/*
 * RFC 9000 Section 13.4.2 and Appendix A.4: mark the first packets of a
 * path ECT(0), stop until they are acknowledged, mark again once ECN is
 * validated, and stop for good when the validation fails.
 */
void
xqc_test_ecn_marking(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    xqc_packet_out_t *po;
    xqc_packet_number_t pn = 0;

    /* a datagram not written with write_socket_ecn */
    send_ctl->ctl_ecn_last_write = XQC_ECN_NOT_ECT;
    po = xqc_test_ecn_send(conn, ++pn);
    CU_ASSERT_FATAL(po != NULL);
    CU_ASSERT((po->po_flag & XQC_POF_ECN_ECT0) == 0);
    CU_ASSERT_EQUAL(send_ctl->ctl_ecn_state, XQC_ECN_STATE_NONE);

    /* testing: the first datagrams are marked */
    for (int i = 0; i < XQC_ECN_TESTING_PACKETS; i++) {
        CU_ASSERT_EQUAL(xqc_send_ctl_ecn_on_write(send_ctl), XQC_ECN_ECT_0);
        CU_ASSERT_EQUAL(send_ctl->ctl_ecn_state, XQC_ECN_STATE_TESTING);
        po = xqc_test_ecn_send(conn, ++pn);
        CU_ASSERT_FATAL(po != NULL);
        CU_ASSERT((po->po_flag & XQC_POF_ECN_ECT0) != 0);
    }
    CU_ASSERT_EQUAL(send_ctl->ctl_ecn_state, XQC_ECN_STATE_UNKNOWN);

    /* unknown: not marked until they are acknowledged */
    CU_ASSERT_EQUAL(xqc_send_ctl_ecn_on_write(send_ctl), XQC_ECN_NOT_ECT);
    po = xqc_test_ecn_send(conn, ++pn);
    CU_ASSERT_FATAL(po != NULL);
    CU_ASSERT((po->po_flag & XQC_POF_ECN_ECT0) == 0);

    /* validated: marked again */
    send_ctl->ctl_ecn_state = XQC_ECN_STATE_CAPABLE;
    CU_ASSERT_EQUAL(xqc_send_ctl_ecn_on_write(send_ctl), XQC_ECN_ECT_0);
    po = xqc_test_ecn_send(conn, ++pn);
    CU_ASSERT_FATAL(po != NULL);
    CU_ASSERT((po->po_flag & XQC_POF_ECN_ECT0) != 0);

    /* failed: not marked any more */
    send_ctl->ctl_ecn_state = XQC_ECN_STATE_FAILED;
    CU_ASSERT_EQUAL(xqc_send_ctl_ecn_on_write(send_ctl), XQC_ECN_NOT_ECT);
    po = xqc_test_ecn_send(conn, ++pn);
    CU_ASSERT_FATAL(po != NULL);
    CU_ASSERT((po->po_flag & XQC_POF_ECN_ECT0) == 0);
    CU_ASSERT_EQUAL(send_ctl->ctl_ecn_state, XQC_ECN_STATE_FAILED);

    xqc_engine_destroy(conn->engine);
}


/* only connections with enable_ecn write with write_socket_ecn */
void
xqc_test_ecn_write_socket(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_path_ctx_t *path = conn->conn_initial_path;
    unsigned char dgram[32] = {0};

    g_ecn_write_calls = 0;
    conn->transport_cbs.write_socket_ecn = xqc_test_ecn_write_cb;

    /* not enabled: the other callbacks write it, unmarked */
    conn->conn_settings.enable_ecn = 0;
    CU_ASSERT_EQUAL(xqc_send(conn, path, dgram, sizeof(dgram)),
                    sizeof(dgram));
    CU_ASSERT_EQUAL(g_ecn_write_calls, 0);
    CU_ASSERT_EQUAL(path->path_send_ctl->ctl_ecn_last_write,
                    XQC_ECN_NOT_ECT);
    CU_ASSERT_EQUAL(path->path_send_ctl->ctl_ecn_state, XQC_ECN_STATE_NONE);

    /* enabled: written with its codepoint */
    conn->conn_settings.enable_ecn = 1;
    CU_ASSERT_EQUAL(xqc_send(conn, path, dgram, sizeof(dgram)),
                    sizeof(dgram));
    CU_ASSERT_EQUAL(g_ecn_write_calls, 1);
    CU_ASSERT_EQUAL(g_ecn_written, XQC_ECN_ECT_0);
    CU_ASSERT_EQUAL(path->path_send_ctl->ctl_ecn_last_write, XQC_ECN_ECT_0);
    CU_ASSERT_EQUAL(path->path_send_ctl->ctl_ecn_state,
                    XQC_ECN_STATE_TESTING);

    path->path_send_ctl->ctl_ecn_state = XQC_ECN_STATE_FAILED;
    CU_ASSERT_EQUAL(xqc_send(conn, path, dgram, sizeof(dgram)),
                    sizeof(dgram));
    CU_ASSERT_EQUAL(g_ecn_write_calls, 2);
    CU_ASSERT_EQUAL(g_ecn_written, XQC_ECN_NOT_ECT);

    xqc_engine_destroy(conn->engine);
}


/* validate an ACK frame of the 1-RTT space on a fresh path */
static xqc_ecn_state_t
xqc_test_ecn_validate(xqc_ecn_state_t state, xqc_ecn_counts_t last,
    xqc_bool_t present, xqc_ecn_counts_t counts, uint64_t acked_ect0,
    xqc_bool_t increased)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    xqc_ack_info_t ack_info;

    memset(&ack_info, 0, sizeof(ack_info));
    ack_info.pns = XQC_PNS_APP_DATA;
    ack_info.ecn_present = present;
    ack_info.ecn = counts;
    send_ctl->ctl_ecn_state = state;
    send_ctl->ctl_ecn_acked[XQC_PNS_APP_DATA] = last;
    xqc_send_ctl_ecn_on_ack(send_ctl, &ack_info, acked_ect0, increased);

    xqc_ecn_state_t result = send_ctl->ctl_ecn_state;
    if (result != XQC_ECN_STATE_FAILED && present && increased
        && state != XQC_ECN_STATE_NONE && state != XQC_ECN_STATE_FAILED)
    {
        /* the counts of a valid frame are the base of the next one */
        CU_ASSERT_EQUAL(send_ctl->ctl_ecn_acked[XQC_PNS_APP_DATA].ect0,
                        counts.ect0);
        CU_ASSERT_EQUAL(send_ctl->ctl_ecn_acked[XQC_PNS_APP_DATA].ce,
                        counts.ce);
    }

    xqc_engine_destroy(conn->engine);
    return result;
}


/* RFC 9000 Section 13.4.2.1 */
void
xqc_test_ecn_validation(void)
{
    const xqc_ecn_counts_t zero = {0, 0, 0};
    const xqc_ecn_counts_t five = {5, 0, 0};

    /* the marks of the packets acknowledged are reported */
    CU_ASSERT_EQUAL(xqc_test_ecn_validate(XQC_ECN_STATE_TESTING, zero,
                    XQC_TRUE, (xqc_ecn_counts_t){3, 0, 0}, 3, XQC_TRUE),
                    XQC_ECN_STATE_CAPABLE);
    CU_ASSERT_EQUAL(xqc_test_ecn_validate(XQC_ECN_STATE_UNKNOWN, zero,
                    XQC_TRUE, (xqc_ecn_counts_t){10, 0, 0}, 10, XQC_TRUE),
                    XQC_ECN_STATE_CAPABLE);

    /* CE counts as a mark, and counts may exceed the packets acked */
    CU_ASSERT_EQUAL(xqc_test_ecn_validate(XQC_ECN_STATE_CAPABLE, five,
                    XQC_TRUE, (xqc_ecn_counts_t){7, 0, 1}, 3, XQC_TRUE),
                    XQC_ECN_STATE_CAPABLE);

    /* no ECT(0) packet acknowledged yet: not validated, not failed */
    CU_ASSERT_EQUAL(xqc_test_ecn_validate(XQC_ECN_STATE_TESTING, zero,
                    XQC_FALSE, zero, 0, XQC_TRUE),
                    XQC_ECN_STATE_TESTING);
    CU_ASSERT_EQUAL(xqc_test_ecn_validate(XQC_ECN_STATE_TESTING, zero,
                    XQC_TRUE, zero, 0, XQC_TRUE),
                    XQC_ECN_STATE_TESTING);

    /* the counts are missing */
    CU_ASSERT_EQUAL(xqc_test_ecn_validate(XQC_ECN_STATE_CAPABLE, five,
                    XQC_FALSE, zero, 1, XQC_TRUE),
                    XQC_ECN_STATE_FAILED);

    /* fewer marks than packets acknowledged: bleached or remarked */
    CU_ASSERT_EQUAL(xqc_test_ecn_validate(XQC_ECN_STATE_TESTING, zero,
                    XQC_TRUE, (xqc_ecn_counts_t){1, 0, 0}, 2, XQC_TRUE),
                    XQC_ECN_STATE_FAILED);

    /* a count decreased */
    CU_ASSERT_EQUAL(xqc_test_ecn_validate(XQC_ECN_STATE_CAPABLE, five,
                    XQC_TRUE, (xqc_ecn_counts_t){4, 0, 2}, 1, XQC_TRUE),
                    XQC_ECN_STATE_FAILED);

    /* ECT(1), which is never sent */
    CU_ASSERT_EQUAL(xqc_test_ecn_validate(XQC_ECN_STATE_CAPABLE, five,
                    XQC_TRUE, (xqc_ecn_counts_t){6, 1, 0}, 1, XQC_TRUE),
                    XQC_ECN_STATE_FAILED);

    /* an ACK frame that does not increase the largest acknowledged */
    CU_ASSERT_EQUAL(xqc_test_ecn_validate(XQC_ECN_STATE_CAPABLE, five,
                    XQC_FALSE, zero, 1, XQC_FALSE),
                    XQC_ECN_STATE_CAPABLE);

    /* ECN not used, or already failed */
    CU_ASSERT_EQUAL(xqc_test_ecn_validate(XQC_ECN_STATE_NONE, zero,
                    XQC_FALSE, zero, 1, XQC_TRUE),
                    XQC_ECN_STATE_NONE);
    CU_ASSERT_EQUAL(xqc_test_ecn_validate(XQC_ECN_STATE_FAILED, zero,
                    XQC_TRUE, (xqc_ecn_counts_t){1, 0, 0}, 1, XQC_TRUE),
                    XQC_ECN_STATE_FAILED);
}


/* acknowledge packets 1 to 3 of the 1-RTT space, all sent with ECT(0) */
static xqc_ecn_state_t
xqc_test_ecn_ack_three(xqc_bool_t present, uint64_t ect0)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    xqc_pn_ctl_t *pn_ctl = xqc_get_pn_ctl(conn, conn->conn_initial_path);

    conn->conn_settings.disable_pn_skipping = 1;
    for (xqc_packet_number_t pn = 1; pn <= 3; pn++) {
        CU_ASSERT_EQUAL(xqc_send_ctl_ecn_on_write(send_ctl), XQC_ECN_ECT_0);
        CU_ASSERT_FATAL(xqc_test_ecn_send(conn, pn) != NULL);
    }
    CU_ASSERT_EQUAL(send_ctl->ctl_ecn_state, XQC_ECN_STATE_TESTING);

    xqc_ack_info_t ack_info;
    memset(&ack_info, 0, sizeof(ack_info));
    ack_info.pns = XQC_PNS_APP_DATA;
    ack_info.n_ranges = 1;
    ack_info.ranges[0].low = 1;
    ack_info.ranges[0].high = 3;
    ack_info.largest_acked = 3;
    ack_info.ecn_present = present;
    ack_info.ecn.ect0 = ect0;
    CU_ASSERT_EQUAL(xqc_send_ctl_on_ack_received(send_ctl, pn_ctl,
                    conn->conn_send_queue, &ack_info,
                    xqc_monotonic_timestamp(), XQC_TRUE), XQC_OK);

    xqc_ecn_state_t state = send_ctl->ctl_ecn_state;
    xqc_engine_destroy(conn->engine);
    return state;
}


/* the packets newly acknowledged by an ACK frame are checked */
void
xqc_test_ecn_validation_on_ack(void)
{
    CU_ASSERT_EQUAL(xqc_test_ecn_ack_three(XQC_TRUE, 3),
                    XQC_ECN_STATE_CAPABLE);
    CU_ASSERT_EQUAL(xqc_test_ecn_ack_three(XQC_TRUE, 2),
                    XQC_ECN_STATE_FAILED);
    CU_ASSERT_EQUAL(xqc_test_ecn_ack_three(XQC_FALSE, 0),
                    XQC_ECN_STATE_FAILED);
}


/* RFC 9002 Section 7.1: new CE marks are a congestion event */
void
xqc_test_ecn_ce_congestion_event(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    CU_ASSERT_FATAL(send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd
                    != NULL);
    xqc_ack_info_t ack_info;
    memset(&ack_info, 0, sizeof(ack_info));
    ack_info.pns = XQC_PNS_APP_DATA;
    ack_info.ecn_present = XQC_TRUE;

    send_ctl->ctl_ecn_state = XQC_ECN_STATE_CAPABLE;
    send_ctl->ctl_largest_acked_sent_time[XQC_PNS_APP_DATA] =
        xqc_monotonic_timestamp();
    uint64_t cwnd = send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(
        send_ctl->ctl_cong);

    /* no new CE mark */
    ack_info.ecn.ect0 = 2;
    xqc_send_ctl_ecn_on_ack(send_ctl, &ack_info, 2, XQC_TRUE);
    CU_ASSERT_EQUAL(send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(
                    send_ctl->ctl_cong), cwnd);

    /* a new CE mark reduces the window */
    ack_info.ecn.ect0 = 3;
    ack_info.ecn.ce = 1;
    xqc_send_ctl_ecn_on_ack(send_ctl, &ack_info, 2, XQC_TRUE);
    CU_ASSERT(send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(
              send_ctl->ctl_cong) < cwnd);
    CU_ASSERT_EQUAL(send_ctl->ctl_ecn_state, XQC_ECN_STATE_CAPABLE);
    CU_ASSERT_EQUAL(send_ctl->ctl_ecn_acked[XQC_PNS_APP_DATA].ce, 1);

    xqc_engine_destroy(conn->engine);
}


static int                  g_ecn_mmsg_calls;
static int                  g_ecn_mmsg_ex_calls;
static unsigned int         g_ecn_mmsg_vlen[2];
static xqc_ecn_codepoint_t  g_ecn_mmsg_ecn[2];
static unsigned int         g_ecn_mmsg_accept;

static ssize_t
xqc_test_ecn_mmsg_cb(uint64_t path_id, const struct iovec *msg_iov,
    unsigned int vlen, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, xqc_ecn_codepoint_t ecn, void *conn_user_data)
{
    if (g_ecn_mmsg_calls < 2) {
        g_ecn_mmsg_vlen[g_ecn_mmsg_calls] = vlen;
        g_ecn_mmsg_ecn[g_ecn_mmsg_calls] = ecn;
    }
    g_ecn_mmsg_calls++;
    return vlen < g_ecn_mmsg_accept ? vlen : g_ecn_mmsg_accept;
}

static ssize_t
xqc_test_ecn_mmsg_ex_cb(uint64_t path_id, const struct iovec *msg_iov,
    unsigned int vlen, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *conn_user_data)
{
    g_ecn_mmsg_ex_calls++;
    return vlen;
}

/* write a burst of 5 datagrams on the path */
static ssize_t
xqc_test_ecn_burst(xqc_connection_t *conn, xqc_ecn_state_t state,
    uint32_t testing_sent)
{
    static unsigned char dgrams[5][32];
    struct iovec iov[5];
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;

    for (int i = 0; i < 5; i++) {
        iov[i].iov_base = dgrams[i];
        iov[i].iov_len = sizeof(dgrams[i]);
    }

    send_ctl->ctl_ecn_state = state;
    send_ctl->ctl_ecn_testing_sent = testing_sent;
    g_ecn_mmsg_calls = 0;
    g_ecn_mmsg_ex_calls = 0;
    memset(g_ecn_mmsg_vlen, 0, sizeof(g_ecn_mmsg_vlen));
    return xqc_send_burst(conn, conn->conn_initial_path, iov, 5);
}


/*
 * RFC 9000 Section 13.4.2 and Appendix A.4: with write_mmsg_ecn, a burst is
 * written in one call per codepoint, the datagrams to mark first.
 */
void
xqc_test_ecn_write_mmsg(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;

    conn->transport_cbs.write_mmsg_ecn = xqc_test_ecn_mmsg_cb;
    conn->transport_cbs.write_mmsg_ex = xqc_test_ecn_mmsg_ex_cb;
    g_ecn_mmsg_accept = 64;

    /* not enabled: write_mmsg_ex writes it, unmarked */
    conn->conn_settings.enable_ecn = 0;
    CU_ASSERT_EQUAL(xqc_test_ecn_burst(conn, XQC_ECN_STATE_NONE, 0), 5);
    CU_ASSERT_EQUAL(g_ecn_mmsg_calls, 0);
    CU_ASSERT_EQUAL(g_ecn_mmsg_ex_calls, 1);
    CU_ASSERT_EQUAL(send_ctl->ctl_ecn_burst_marked, 0);

    /* testing, two datagrams left to mark: 2 ECT(0), then 3 Not-ECT */
    conn->conn_settings.enable_ecn = 1;
    CU_ASSERT_EQUAL(xqc_test_ecn_burst(conn, XQC_ECN_STATE_TESTING,
                    XQC_ECN_TESTING_PACKETS - 2), 5);
    CU_ASSERT_EQUAL(g_ecn_mmsg_ex_calls, 0);
    CU_ASSERT_EQUAL(g_ecn_mmsg_calls, 2);
    CU_ASSERT(g_ecn_mmsg_vlen[0] == 2 && g_ecn_mmsg_ecn[0] == XQC_ECN_ECT_0);
    CU_ASSERT(g_ecn_mmsg_vlen[1] == 3
              && g_ecn_mmsg_ecn[1] == XQC_ECN_NOT_ECT);
    CU_ASSERT_EQUAL(send_ctl->ctl_ecn_burst_marked, 2);

    /* the first call writes 1 of 2: the burst stops there */
    g_ecn_mmsg_accept = 1;
    CU_ASSERT_EQUAL(xqc_test_ecn_burst(conn, XQC_ECN_STATE_TESTING,
                    XQC_ECN_TESTING_PACKETS - 2), 1);
    CU_ASSERT_EQUAL(g_ecn_mmsg_calls, 1);
    CU_ASSERT_EQUAL(send_ctl->ctl_ecn_burst_marked, 1);
    g_ecn_mmsg_accept = 64;

    /* validated: one call, all marked */
    CU_ASSERT_EQUAL(xqc_test_ecn_burst(conn, XQC_ECN_STATE_CAPABLE, 0), 5);
    CU_ASSERT_EQUAL(g_ecn_mmsg_calls, 1);
    CU_ASSERT(g_ecn_mmsg_vlen[0] == 5 && g_ecn_mmsg_ecn[0] == XQC_ECN_ECT_0);
    CU_ASSERT_EQUAL(send_ctl->ctl_ecn_burst_marked, 5);

    /* waiting for the ACKs of the testing packets, or failed: unmarked */
    CU_ASSERT_EQUAL(xqc_test_ecn_burst(conn, XQC_ECN_STATE_UNKNOWN, 10), 5);
    CU_ASSERT(g_ecn_mmsg_calls == 1 && g_ecn_mmsg_vlen[0] == 5
              && g_ecn_mmsg_ecn[0] == XQC_ECN_NOT_ECT);
    CU_ASSERT_EQUAL(xqc_test_ecn_burst(conn, XQC_ECN_STATE_FAILED, 10), 5);
    CU_ASSERT(g_ecn_mmsg_calls == 1 && g_ecn_mmsg_ecn[0] == XQC_ECN_NOT_ECT);
    CU_ASSERT_EQUAL(send_ctl->ctl_ecn_burst_marked, 0);

    xqc_engine_destroy(conn->engine);
}


/* each packet of a burst carries the codepoint of its datagram */
void
xqc_test_ecn_burst_flags(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_path_ctx_t *path = conn->conn_initial_path;
    xqc_send_ctl_t *send_ctl = path->path_send_ctl;
    xqc_packet_out_t *po[4];

    for (int i = 0; i < 4; i++) {
        po[i] = xqc_packet_out_get(conn->conn_send_queue);
        CU_ASSERT_FATAL(po[i] != NULL);
        po[i]->po_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
        po[i]->po_pkt.pkt_pns = XQC_PNS_APP_DATA;
        po[i]->po_pkt.pkt_num = i + 1;
        po[i]->po_frame_types = XQC_FRAME_BIT_PING;
        po[i]->po_used_size = 32;
        xqc_init_list_head(&po[i]->po_list);
        xqc_path_send_buffer_append(path, po[i],
            &path->path_schedule_buf[XQC_SEND_TYPE_NORMAL]);
    }

    /* two testing packets left: the first two of the burst were marked */
    send_ctl->ctl_ecn_state = XQC_ECN_STATE_TESTING;
    send_ctl->ctl_ecn_testing_sent = XQC_ECN_TESTING_PACKETS - 2;
    send_ctl->ctl_ecn_burst_marked = 2;
    xqc_on_packets_send_burst(conn, path, 4, xqc_monotonic_timestamp(),
                              XQC_SEND_TYPE_NORMAL);
    CU_ASSERT((po[0]->po_flag & XQC_POF_ECN_ECT0) != 0);
    CU_ASSERT((po[1]->po_flag & XQC_POF_ECN_ECT0) != 0);
    CU_ASSERT((po[2]->po_flag & XQC_POF_ECN_ECT0) == 0);
    CU_ASSERT((po[3]->po_flag & XQC_POF_ECN_ECT0) == 0);
    CU_ASSERT_EQUAL(send_ctl->ctl_ecn_testing_sent, XQC_ECN_TESTING_PACKETS);
    CU_ASSERT_EQUAL(send_ctl->ctl_ecn_state, XQC_ECN_STATE_UNKNOWN);

    xqc_engine_destroy(conn->engine);
}


/*
 * RFC 9000 Section 13.4.2: "If all packets marked with non-zero ECN
 * codepoints are subsequently lost, it can disable marking."
 */
void
xqc_test_ecn_testing_lost(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    xqc_pn_ctl_t *pn_ctl = xqc_get_pn_ctl(conn, conn->conn_initial_path);
    xqc_packet_number_t pn;

    /* the testing packets are sent, then three unmarked ones */
    conn->conn_settings.disable_pn_skipping = 1;
    for (pn = 1; pn <= XQC_ECN_TESTING_PACKETS; pn++) {
        CU_ASSERT_EQUAL(xqc_send_ctl_ecn_on_write(send_ctl), XQC_ECN_ECT_0);
        CU_ASSERT_FATAL(xqc_test_ecn_send(conn, pn) != NULL);
    }
    CU_ASSERT_EQUAL(send_ctl->ctl_ecn_state, XQC_ECN_STATE_UNKNOWN);
    for (; pn <= XQC_ECN_TESTING_PACKETS + 3; pn++) {
        CU_ASSERT_EQUAL(xqc_send_ctl_ecn_on_write(send_ctl),
                        XQC_ECN_NOT_ECT);
        CU_ASSERT_FATAL(xqc_test_ecn_send(conn, pn) != NULL);
    }

    /* an ACK of the unmarked ones makes the testing packets lost */
    xqc_ack_info_t ack_info;
    memset(&ack_info, 0, sizeof(ack_info));
    ack_info.pns = XQC_PNS_APP_DATA;
    ack_info.n_ranges = 1;
    ack_info.ranges[0].low = XQC_ECN_TESTING_PACKETS + 1;
    ack_info.ranges[0].high = XQC_ECN_TESTING_PACKETS + 3;
    ack_info.largest_acked = XQC_ECN_TESTING_PACKETS + 3;
    CU_ASSERT_EQUAL(xqc_send_ctl_on_ack_received(send_ctl, pn_ctl,
                    conn->conn_send_queue, &ack_info,
                    xqc_monotonic_timestamp(), XQC_TRUE), XQC_OK);
    CU_ASSERT_EQUAL(send_ctl->ctl_ecn_testing_lost, XQC_ECN_TESTING_PACKETS);
    CU_ASSERT_EQUAL(send_ctl->ctl_ecn_state, XQC_ECN_STATE_FAILED);
    CU_ASSERT_EQUAL(xqc_send_ctl_ecn_on_write(send_ctl), XQC_ECN_NOT_ECT);

    /* one fewer lost: still waiting; once validated, losses do not count */
    send_ctl->ctl_ecn_state = XQC_ECN_STATE_UNKNOWN;
    send_ctl->ctl_ecn_testing_lost = 0;
    for (int i = 0; i < XQC_ECN_TESTING_PACKETS - 1; i++) {
        xqc_send_ctl_ecn_on_lost(send_ctl);
    }
    CU_ASSERT_EQUAL(send_ctl->ctl_ecn_state, XQC_ECN_STATE_UNKNOWN);
    send_ctl->ctl_ecn_state = XQC_ECN_STATE_CAPABLE;
    xqc_send_ctl_ecn_on_lost(send_ctl);
    CU_ASSERT_EQUAL(send_ctl->ctl_ecn_state, XQC_ECN_STATE_CAPABLE);

    xqc_engine_destroy(conn->engine);
}


/* a client connection with ACK_EXTENDED frames and ECN as given */
static xqc_connection_t *
xqc_test_ecn_connect_ack_ext(xqc_engine_t *engine, uint8_t enable_ecn)
{
    xqc_conn_settings_t settings;
    xqc_conn_ssl_config_t ssl_config;

    memset(&settings, 0, sizeof(settings));
    settings.proto_version = XQC_VERSION_V1;
    settings.extended_ack_features = XQC_ACK_EXT_FEATURE_BIT_RECV_TS;
    settings.max_receive_timestamps_per_ack = 30;
    settings.enable_ecn = enable_ecn;
    memset(&ssl_config, 0, sizeof(ssl_config));
    const xqc_cid_t *cid = xqc_connect(engine, &settings, NULL, 0, "", 0,
        &ssl_config, NULL, 0, "transport", NULL);
    return cid != NULL ? xqc_engine_conns_hash_find(engine, cid, 's') : NULL;
}

/* the server's transport parameters, with its extended_ack_features */
static void
xqc_test_ecn_server_tp(xqc_connection_t *conn, uint64_t features)
{
    xqc_transport_params_t params;
    uint8_t buf[XQC_MAX_TRANSPORT_PARAM_BUF_LEN];
    size_t len = 0;

    xqc_init_transport_params(&params);
    params.original_dest_connection_id_present = 1;
    xqc_cid_copy(&params.original_dest_connection_id, &conn->original_dcid);
    params.initial_source_connection_id_present = 1;
    xqc_cid_copy(&params.initial_source_connection_id,
                 &conn->dcid_set.current_dcid);
    params.extended_ack_features = features;
    params.max_receive_timestamps_per_ack = 30;
    CU_ASSERT_EQUAL_FATAL(xqc_encode_transport_params(&params,
                          XQC_TP_TYPE_ENCRYPTED_EXTENSIONS, buf, sizeof(buf),
                          &len), XQC_OK);
    xqc_conn_tls_cbs.tp_cb(buf, len, conn);
}


/*
 * draft-smith-quic-receive-ts-01 Section 6: an endpoint with ECN enabled
 * accepts the ECN Counts in ACK_EXTENDED frames, and writes them only to a
 * peer that accepts them.
 */
void
xqc_test_ecn_ack_ext_negotiation(void)
{
    for (uint8_t ecn = 0; ecn <= 1; ecn++) {
        for (uint64_t peer = 2; peer <= 3; peer++) {
            xqc_engine_t *engine = test_create_engine();
            CU_ASSERT_FATAL(engine != NULL);
            xqc_connection_t *conn = xqc_test_ecn_connect_ack_ext(engine, ecn);
            CU_ASSERT_FATAL(conn != NULL);

            CU_ASSERT_EQUAL(conn->local_settings.extended_ack_features,
                            ecn ? 3 : 2);
            xqc_test_ecn_server_tp(conn, peer);
            CU_ASSERT_EQUAL(conn->conn_err, 0);
            CU_ASSERT_EQUAL(conn->conn_settings.extended_ack_features, peer);

            xqc_engine_destroy(engine);
        }
    }
}


/*
 * draft-smith-quic-receive-ts-01 Section 5: the ECN Counts of the space go
 * in an ACK_EXTENDED frame before its Receive Timestamps, when the peer
 * accepts them.
 */
void
xqc_test_ecn_ack_ext_frame_counts(void)
{
    for (int accepts = 0; accepts <= 1; accepts++) {
        xqc_packet_out_t *po = xqc_packet_out_create(XQC_QUIC_MAX_MSS);
        xqc_connection_t *conn = test_engine_connect();
        CU_ASSERT_FATAL(po != NULL && conn != NULL);
        xqc_path_ctx_t *initial = conn->conn_initial_path;
        xqc_path_ctx_t *path = xqc_calloc(1, sizeof(xqc_path_ctx_t));
        path->path_pn_ctl = xqc_calloc(1, sizeof(xqc_pn_ctl_t));
        path->path_send_ctl = xqc_calloc(1, sizeof(xqc_send_ctl_t));
        path->path_send_ctl->ctl_largest_recv_time[XQC_PNS_APP_DATA] = 3000;
        xqc_recv_record_t *record =
            &path->path_pn_ctl->ctl_recv_record[XQC_PNS_APP_DATA];
        xqc_init_list_head(&record->list_head);
        path->recv_ts_info = xqc_recv_timestamps_info_create();
        for (xqc_packet_number_t pn = 1; pn <= 3; pn++) {
            xqc_recv_timestamps_info_add_pkt(path->recv_ts_info, pn,
                                             pn * 1000);
            xqc_recv_record_add(record, pn);
        }
        path->path_pn_ctl->ctl_ecn_recv[XQC_PNS_APP_DATA] =
            (xqc_ecn_counts_t){2, 0, 1};

        conn->conn_settings.extended_ack_features =
            XQC_ACK_EXT_FEATURE_BIT_RECV_TS
            | (accepts ? XQC_ACK_EXT_FEATURE_BIT_ENC_COUNT : 0);
        conn->conn_settings.max_receive_timestamps_per_ack = 30;
        conn->remote_settings.extended_ack_features =
            conn->conn_settings.extended_ack_features;
        conn->remote_settings.max_receive_timestamps_per_ack = 30;
        conn->local_settings.max_receive_timestamps_per_ack = 30;
        conn->conn_create_time = 0;
        conn->conn_initial_path = path;
        po->po_used_size = 0;
        CU_ASSERT_EQUAL(xqc_write_ack_ext_to_one_packet(conn, po,
                        XQC_PNS_APP_DATA, 1), XQC_OK);

        xqc_packet_in_t packet_in;
        xqc_ack_info_t ack_info;
        xqc_ack_timestamp_info_t ack_ts;
        memset(&packet_in, 0, sizeof(packet_in));
        packet_in.buf = po->po_buf;
        packet_in.pos = po->po_buf;
        packet_in.last = po->po_buf + po->po_used_size;
        ack_ts.report_num = 0;
        CU_ASSERT_EQUAL(xqc_parse_ack_ext_frame(&packet_in, conn, &ack_info,
                        &ack_ts), XQC_OK);
        CU_ASSERT_EQUAL(ack_info.ecn_present, accepts);
        CU_ASSERT(!accepts || (ack_info.ecn.ect0 == 2 && ack_info.ecn.ect1 == 0
                               && ack_info.ecn.ce == 1));
        CU_ASSERT_EQUAL(ack_ts.report_num, 3);
        CU_ASSERT_EQUAL(ack_info.largest_acked, 3);

        conn->conn_initial_path = initial;
        xqc_engine_destroy(conn->engine);
        xqc_packet_out_destroy(po);
        xqc_recv_record_destroy(record);
        xqc_recv_timestamps_info_destroy(path->recv_ts_info);
        xqc_free(path->path_pn_ctl);
        xqc_free(path->path_send_ctl);
        xqc_free(path);
    }
}
