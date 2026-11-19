#include <CUnit/CUnit.h>
#include <xquic/xquic_typedef.h>
#include "xqc_cid_test.h"
#include "xqc_common_test.h"
#include "src/common/xqc_malloc.h"
#include "src/transport/xqc_recv_timestamps_info.h"
#include "src/transport/xqc_packet_parser.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_frame.h"

#define test_pkt_num 13

void
xqc_test_ack_with_timestamp_normal()
{
    xqc_packet_out_t* packet_out = xqc_packet_out_create(XQC_QUIC_MAX_MSS);
    xqc_connection_t *conn = test_engine_connect();
    xqc_path_ctx_t *path = xqc_calloc(1, sizeof(xqc_path_ctx_t));
    path->path_pn_ctl = xqc_calloc(1, sizeof(xqc_pn_ctl_t));
    // path->path_send_ctl->ctl_largest_recv_time[pns]
    path->path_send_ctl = xqc_calloc(1, sizeof(xqc_send_ctl_t));
    path->path_send_ctl->ctl_largest_recv_time[XQC_PNS_APP_DATA] = 15000;
    xqc_init_list_head(&path->path_pn_ctl->ctl_recv_record[XQC_PNS_APP_DATA].list_head);
    packet_out->po_used_size = 0;
    xqc_recv_timestamps_info_t *recv_timestamp_info = xqc_recv_timestamps_info_create();
    xqc_packet_number_t pkt_num_test_list[test_pkt_num] = {1, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15};
    xqc_usec_t recv_time_test_list[test_pkt_num] = {1000, 3000, 4000, 5000, 6000, 7000, 9000, 10000, 11000, 12000, 13000, 14000, 15000};
    for (int i = 0; i < test_pkt_num; i++) {
        xqc_recv_timestamps_info_add_pkt(recv_timestamp_info, pkt_num_test_list[i], recv_time_test_list[i]);
        xqc_recv_record_add(&path->path_pn_ctl->ctl_recv_record[XQC_PNS_APP_DATA], pkt_num_test_list[i]);
    }
    CU_ASSERT(conn != NULL);
    conn->conn_settings.extended_ack_features = 2;
    conn->conn_settings.max_receive_timestamps_per_ack = 30;
    conn->conn_settings.receive_timestamps_exponent = 0;

    conn->remote_settings.extended_ack_features = 2;
    conn->remote_settings.max_receive_timestamps_per_ack = 30;
    conn->remote_settings.receive_timestamps_exponent = 0;
    conn->local_settings.extended_ack_features = 2;
    conn->local_settings.max_receive_timestamps_per_ack = 30;
    conn->conn_create_time = 0;

    packet_out->po_largest_ack = 15;
    conn->conn_create_time = 0;
    
    path->recv_ts_info = recv_timestamp_info;
    conn->conn_initial_path = path;

    int ret = xqc_write_ack_ext_to_one_packet(conn, packet_out, XQC_PNS_APP_DATA, 1);
    CU_ASSERT(ret == XQC_OK);
    packet_out->po_used_size += ret;

    xqc_packet_in_t* packet_in = xqc_calloc(1, sizeof(xqc_packet_in_t));
    packet_in->buf = packet_out->po_buf;
    packet_in->pos = packet_out->po_buf;
    packet_in->last = packet_out->po_buf + packet_out->po_used_size;
    xqc_ack_timestamp_info_t ack_timestamp;
    ack_timestamp.report_num = 0;
    xqc_ack_info_t ack_info;
    ret = xqc_parse_ack_ext_frame(packet_in, conn, &ack_info, &ack_timestamp);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(ack_timestamp.report_num == test_pkt_num);
    for (int i = 0; i < ack_timestamp.report_num; i++) {
        // printf("pkt_num:%lu, recv_ts:%lu\n", ack_timestamp.pkt_nums[i], ack_timestamp.recv_ts[i]);
        CU_ASSERT(ack_timestamp.recv_ts[i] == recv_time_test_list[test_pkt_num - 1 - i]/1000);
    }
    xqc_engine_destroy(conn->engine);
    xqc_packet_out_destroy(packet_out);
    xqc_recv_record_destroy(
        &path->path_pn_ctl->ctl_recv_record[XQC_PNS_APP_DATA]);
    xqc_recv_timestamps_info_destroy(recv_timestamp_info);
    xqc_free(packet_in);
    xqc_free(path->path_pn_ctl);
    xqc_free(path->path_send_ctl);
    xqc_free(path);
}

void
xqc_test_ack_with_timestamp_no_buf_space()
{
    xqc_packet_out_t* packet_out = xqc_packet_out_create(XQC_QUIC_MAX_MSS);
    xqc_connection_t *conn = test_engine_connect();
    xqc_path_ctx_t *path = xqc_calloc(1, sizeof(xqc_path_ctx_t));
    path->path_pn_ctl = xqc_calloc(1, sizeof(xqc_pn_ctl_t));
    // path->path_send_ctl->ctl_largest_recv_time[pns]
    path->path_send_ctl = xqc_calloc(1, sizeof(xqc_send_ctl_t));
    path->path_send_ctl->ctl_largest_recv_time[XQC_PNS_APP_DATA] = 15000;
    xqc_init_list_head(&path->path_pn_ctl->ctl_recv_record[XQC_PNS_APP_DATA].list_head);
    packet_out->po_used_size = 0;
    xqc_recv_timestamps_info_t *recv_timestamp_info = xqc_recv_timestamps_info_create();
    xqc_packet_number_t pkt_num_test_list[test_pkt_num] = {1, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15};
    xqc_usec_t recv_time_test_list[test_pkt_num] = {1000, 3000, 4000, 5000, 6000, 7000, 9000, 10000, 11000, 12000, 13000, 14000, 15000};
    for (int i = 0; i < test_pkt_num; i++) {
        xqc_recv_timestamps_info_add_pkt(recv_timestamp_info, pkt_num_test_list[i], recv_time_test_list[i]);
        xqc_recv_record_add(&path->path_pn_ctl->ctl_recv_record[XQC_PNS_APP_DATA], pkt_num_test_list[i]);
    }
    CU_ASSERT(conn != NULL);
    conn->conn_settings.extended_ack_features = 2;
    conn->conn_settings.max_receive_timestamps_per_ack = 30;
    conn->conn_settings.receive_timestamps_exponent = 0;

    conn->remote_settings.extended_ack_features = 2;
    conn->remote_settings.max_receive_timestamps_per_ack = 30;
    conn->remote_settings.receive_timestamps_exponent = 0;
    conn->local_settings.extended_ack_features = 2;
    conn->local_settings.max_receive_timestamps_per_ack = 30;
    conn->conn_create_time = 0;

    packet_out->po_largest_ack = 15;
    conn->conn_create_time = 0;
    
    path->recv_ts_info = recv_timestamp_info;
    conn->conn_initial_path = path;
    packet_out->po_used_size = 1400;

    ssize_t ret;
    int has_gap;
    xqc_packet_number_t largest_ack;
    xqc_usec_t now = xqc_monotonic_timestamp();

    xqc_pn_ctl_t *pn_ctl = xqc_get_pn_ctl(conn, path);

    ret = xqc_gen_ack_ext_frame(conn, packet_out, now, conn->local_settings.ack_delay_exponent,
                            &pn_ctl->ctl_recv_record[XQC_PNS_APP_DATA], path->path_send_ctl->ctl_largest_recv_time[XQC_PNS_APP_DATA],
                            &has_gap, &largest_ack, path->recv_ts_info);

    CU_ASSERT(ret == -XQC_ENOBUF);
    xqc_engine_destroy(conn->engine);
    xqc_packet_out_destroy(packet_out);
    xqc_recv_record_destroy(
        &path->path_pn_ctl->ctl_recv_record[XQC_PNS_APP_DATA]);
    xqc_recv_timestamps_info_destroy(recv_timestamp_info);
    xqc_free(path->path_pn_ctl);
    xqc_free(path->path_send_ctl);
    xqc_free(path);
}


void
xqc_test_ack_with_timestamp_partial_writing()
{
    xqc_packet_out_t* packet_out = xqc_packet_out_create(XQC_QUIC_MAX_MSS);
    xqc_connection_t *conn = test_engine_connect();
    xqc_path_ctx_t *path = xqc_calloc(1, sizeof(xqc_path_ctx_t));
    path->path_pn_ctl = xqc_calloc(1, sizeof(xqc_pn_ctl_t));
    // path->path_send_ctl->ctl_largest_recv_time[pns]
    path->path_send_ctl = xqc_calloc(1, sizeof(xqc_send_ctl_t));
    path->path_send_ctl->ctl_largest_recv_time[XQC_PNS_APP_DATA] = 15000;
    xqc_init_list_head(&path->path_pn_ctl->ctl_recv_record[XQC_PNS_APP_DATA].list_head);
    packet_out->po_used_size = 0;
    xqc_recv_timestamps_info_t *recv_timestamp_info = xqc_recv_timestamps_info_create();
    xqc_packet_number_t pkt_num_test_list[test_pkt_num] = {1, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15};
    xqc_usec_t recv_time_test_list[test_pkt_num] = {1000, 3000, 4000, 5000, 6000, 7000, 9000, 10000, 11000, 12000, 13000, 14000, 15000};
    for (int i = 0; i < test_pkt_num; i++) {
        xqc_recv_timestamps_info_add_pkt(recv_timestamp_info, pkt_num_test_list[i], recv_time_test_list[i]);
        xqc_recv_record_add(&path->path_pn_ctl->ctl_recv_record[XQC_PNS_APP_DATA], pkt_num_test_list[i]);
    }
    CU_ASSERT(conn != NULL);
    conn->conn_settings.extended_ack_features = 2;
    conn->conn_settings.max_receive_timestamps_per_ack = 30;
    conn->conn_settings.receive_timestamps_exponent = 0;

    conn->remote_settings.extended_ack_features = 2;
    conn->remote_settings.max_receive_timestamps_per_ack = 30;
    conn->remote_settings.receive_timestamps_exponent = 0;
    conn->local_settings.extended_ack_features = 2;
    conn->local_settings.max_receive_timestamps_per_ack = 30;
    conn->conn_create_time = 0;

    packet_out->po_largest_ack = 15;
    conn->conn_create_time = 0;
    
    path->recv_ts_info = recv_timestamp_info;
    conn->conn_initial_path = path;
    int used_size = 1398;
    packet_out->po_used_size = used_size;

    int ret;
    int has_gap;
    xqc_packet_number_t largest_ack;
    xqc_usec_t now = xqc_monotonic_timestamp();

    xqc_pn_ctl_t *pn_ctl = xqc_get_pn_ctl(conn, path);

    ret = xqc_write_ack_ext_to_one_packet(conn, packet_out, XQC_PNS_APP_DATA, 1);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(recv_timestamp_info->nobuf_for_ts_in_last_ext_ack == 1);
    packet_out->po_used_size += ret;

    xqc_packet_in_t* packet_in = xqc_calloc(1, sizeof(xqc_packet_in_t));
    packet_in->buf = packet_out->po_buf;
    packet_in->pos = packet_out->po_buf + used_size;
    packet_in->last = packet_out->po_buf + packet_out->po_used_size;
    xqc_ack_timestamp_info_t ack_timestamp;
    ack_timestamp.report_num = 0;
    xqc_ack_info_t ack_info;
    ret = xqc_parse_ack_ext_frame(packet_in, conn, &ack_info, &ack_timestamp);
    CU_ASSERT(ack_info.n_ranges == 3);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(ack_timestamp.report_num == 0);
    xqc_engine_destroy(conn->engine);
    xqc_packet_out_destroy(packet_out);
    xqc_recv_record_destroy(
        &path->path_pn_ctl->ctl_recv_record[XQC_PNS_APP_DATA]);
    xqc_recv_timestamps_info_destroy(recv_timestamp_info);
    xqc_free(packet_in);
    xqc_free(path->path_pn_ctl);
    xqc_free(path->path_send_ctl);
    xqc_free(path);
}


void
xqc_test_ack_with_timestamp()
{
    xqc_test_ack_with_timestamp_normal();
    xqc_test_ack_with_timestamp_no_buf_space();
    xqc_test_ack_with_timestamp_partial_writing();
}


/*
 * ACK_EXTENDED frames (draft-smith-quic-receive-ts-01 Section 5) that
 * acknowledge packets 3 to 5: type, Largest Acknowledged 5, ACK Delay 0,
 * no ACK Range, First ACK Range 2, then Extended Ack Features and the
 * fields its bits announce.
 */

/* features 2: Receive Timestamps, one range of one timestamp */
static const unsigned char xqc_test_ack_ext_ts[] = {
    0x40, 0xb1, 0x05, 0x00, 0x00, 0x02, 0x02,
    0x01, 0x00, 0x01, 0x0a,
};

/* features 3: ECN Counts 1, 0, 0, then the Receive Timestamps */
static const unsigned char xqc_test_ack_ext_ecn_ts[] = {
    0x40, 0xb1, 0x05, 0x00, 0x00, 0x02, 0x03,
    0x01, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x0a,
};

/* features 0: the fields of an ACK frame only */
static const unsigned char xqc_test_ack_ext_none[] = {
    0x40, 0xb1, 0x05, 0x00, 0x00, 0x02, 0x00,
};

/* features 4: a bit that no feature is defined for */
static const unsigned char xqc_test_ack_ext_unknown[] = {
    0x40, 0xb1, 0x05, 0x00, 0x00, 0x02, 0x04,
};

static xqc_connection_t *
xqc_test_ack_ext_conn(uint64_t advertised)
{
    xqc_connection_t *conn = test_engine_connect();

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    /* the features this endpoint sent in extended_ack_features */
    conn->local_settings.extended_ack_features = advertised;
    conn->local_settings.max_receive_timestamps_per_ack = 30;
    conn->local_settings.receive_timestamps_exponent = 0;
    return conn;
}

static xqc_int_t
xqc_test_ack_ext_parse(xqc_connection_t *conn, const unsigned char *frame,
    size_t len, xqc_ack_timestamp_info_t *ts)
{
    unsigned char buf[32];
    xqc_packet_in_t pi;
    xqc_ack_info_t ack_info;
    xqc_int_t ret;

    CU_ASSERT_FATAL(len <= sizeof(buf));
    memcpy(buf, frame, len);
    memset(&pi, 0, sizeof(pi));
    pi.pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    pi.pi_pkt.pkt_pns = XQC_PNS_APP_DATA;
    pi.buf = buf;
    pi.pos = buf;
    pi.last = buf + len;
    memset(&ack_info, 0, sizeof(ack_info));
    ts->report_num = 0;

    ret = xqc_parse_ack_ext_frame(&pi, conn, &ack_info, ts);
    if (ret == XQC_OK) {
        CU_ASSERT_PTR_EQUAL(pi.pos, buf + len);
        CU_ASSERT_EQUAL(ack_info.n_ranges, 1);
        CU_ASSERT_EQUAL(ack_info.ranges[0].high, 5);
        CU_ASSERT_EQUAL(ack_info.ranges[0].low, 3);
    }
    return ret;
}

/*
 * draft-smith-quic-receive-ts-01 Section 6: an endpoint accepts the
 * ACK_EXTENDED features it included in its extended_ack_features
 * transport parameter, and a frame that announces no feature.
 */
void
xqc_test_ack_ext_advertised_features(void)
{
    xqc_connection_t *conn;
    xqc_ack_timestamp_info_t ts;

    /* Receive Timestamps, advertised */
    conn = xqc_test_ack_ext_conn(XQC_ACK_EXT_FEATURE_BIT_RECV_TS);
    CU_ASSERT_EQUAL(xqc_test_ack_ext_parse(conn, xqc_test_ack_ext_ts,
                                           sizeof(xqc_test_ack_ext_ts), &ts),
                    XQC_OK);
    CU_ASSERT_EQUAL(ts.report_num, 1);
    CU_ASSERT_EQUAL(ts.pkt_nums[0], 5);
    CU_ASSERT_EQUAL(conn->conn_err, 0);

    /* no feature, with Receive Timestamps advertised */
    CU_ASSERT_EQUAL(xqc_test_ack_ext_parse(conn, xqc_test_ack_ext_none,
                                           sizeof(xqc_test_ack_ext_none), &ts),
                    XQC_OK);
    CU_ASSERT_EQUAL(ts.report_num, 0);
    CU_ASSERT_EQUAL(conn->conn_err, 0);
    xqc_engine_destroy(conn->engine);

    /* no feature, with nothing advertised */
    conn = xqc_test_ack_ext_conn(0);
    CU_ASSERT_EQUAL(xqc_test_ack_ext_parse(conn, xqc_test_ack_ext_none,
                                           sizeof(xqc_test_ack_ext_none), &ts),
                    XQC_OK);
    CU_ASSERT_EQUAL(conn->conn_err, 0);
    xqc_engine_destroy(conn->engine);
}

/*
 * draft-smith-quic-receive-ts-01 Section 6: "An endpoint receiving an
 * ACK_EXTENDED frame with features it did not include in the transport
 * parameter should terminate the connection with a PROTOCOL_VIOLATION
 * violation error." The fields of such a feature are not parsed.
 */
void
xqc_test_ack_ext_unadvertised_features(void)
{
    static const struct {
        uint64_t             advertised;
        const unsigned char *frame;
        size_t               len;
    } cases[] = {
        /* ECN Counts, not advertised */
        { XQC_ACK_EXT_FEATURE_BIT_RECV_TS,
          xqc_test_ack_ext_ecn_ts, sizeof(xqc_test_ack_ext_ecn_ts) },
        /* Receive Timestamps, with no feature advertised */
        { 0, xqc_test_ack_ext_ts, sizeof(xqc_test_ack_ext_ts) },
        /* a bit that no feature is defined for */
        { XQC_ACK_EXT_FEATURE_BIT_RECV_TS,
          xqc_test_ack_ext_unknown, sizeof(xqc_test_ack_ext_unknown) },
    };
    xqc_connection_t *conn;
    xqc_ack_timestamp_info_t ts;
    xqc_packet_in_t pi;
    unsigned char buf[32];
    size_t i, len;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        conn = xqc_test_ack_ext_conn(cases[i].advertised);
        CU_ASSERT_EQUAL(xqc_test_ack_ext_parse(conn, cases[i].frame,
                                               cases[i].len, &ts),
                        -XQC_EPROTO);
        CU_ASSERT_EQUAL(ts.report_num, 0);
        CU_ASSERT_EQUAL(conn->conn_err, TRA_PROTOCOL_VIOLATION);
        CU_ASSERT(conn->conn_flag & XQC_CONN_FLAG_ERROR);
        xqc_engine_destroy(conn->engine);
    }

    /* in a 1-RTT packet, followed by a PING */
    conn = xqc_test_ack_ext_conn(XQC_ACK_EXT_FEATURE_BIT_RECV_TS);
    len = sizeof(xqc_test_ack_ext_ecn_ts);
    memcpy(buf, xqc_test_ack_ext_ecn_ts, len);
    buf[len++] = 0x01;
    memset(&pi, 0, sizeof(pi));
    pi.pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    pi.pi_pkt.pkt_pns = XQC_PNS_APP_DATA;
    pi.buf = buf;
    pi.pos = buf;
    pi.last = buf + len;

    CU_ASSERT_EQUAL(xqc_process_frames(conn, &pi), -XQC_EPROTO);
    CU_ASSERT_EQUAL(conn->conn_err, TRA_PROTOCOL_VIOLATION);
    CU_ASSERT(conn->conn_flag & XQC_CONN_FLAG_ERROR);
    xqc_engine_destroy(conn->engine);
}
