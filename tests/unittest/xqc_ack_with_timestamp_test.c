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

/*
 * An ACK_EXTENDED frame with Timestamp Ranges of 63 and n Timestamp Deltas
 * (64 or 65 timestamps in all), parsed with a max_receive_timestamps_per_ack
 * setting above the 64 entries of xqc_ack_timestamp_info_t.
 */
static xqc_int_t
xqc_test_ack_with_timestamp_parse_count(xqc_connection_t *conn,
    int second_range, xqc_ack_timestamp_info_t *ack_ts)
{
    unsigned char frame[128];
    size_t n = 0;
    frame[n++] = 0x40;          /* Type: 0xb1 */
    frame[n++] = 0xb1;
    frame[n++] = 0x40;          /* Largest Acknowledged: 200 */
    frame[n++] = 0xc8;
    frame[n++] = 0x00;          /* ACK Delay */
    frame[n++] = 0x00;          /* ACK Range Count */
    frame[n++] = 0x40;          /* First ACK Range: 199 */
    frame[n++] = 0xc7;
    frame[n++] = 0x02;          /* Extended Ack Features: timestamps */
    frame[n++] = 0x02;          /* Timestamp Range Count */
    frame[n++] = 0x00;          /* Gap */
    frame[n++] = 0x3f;          /* Timestamp Delta Count: 63 */
    for (int i = 0; i < 63; i++) {
        frame[n++] = 0x01;
    }
    frame[n++] = 0x00;          /* Gap */
    frame[n++] = (unsigned char) second_range;
    for (int i = 0; i < second_range; i++) {
        frame[n++] = 0x01;
    }

    xqc_packet_in_t packet_in;
    memset(&packet_in, 0, sizeof(packet_in));
    packet_in.buf = frame;
    packet_in.pos = frame;
    packet_in.last = frame + n;
    packet_in.pi_pkt.pkt_pns = XQC_PNS_APP_DATA;

    xqc_ack_info_t ack_info;
    ack_ts->report_num = 0;
    return xqc_parse_ack_ext_frame(&packet_in, conn, &ack_info, ack_ts);
}

void
xqc_test_ack_with_timestamp_count_limit()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    conn->local_settings.extended_ack_features = 2;
    conn->local_settings.max_receive_timestamps_per_ack = 100;
    conn->local_settings.receive_timestamps_exponent = 0;
    conn->conn_create_time = 0;

    /* allocated with its exact size: a sanitizer sees a write past it */
    xqc_ack_timestamp_info_t *ack_ts =
        xqc_calloc(1, sizeof(xqc_ack_timestamp_info_t));
    CU_ASSERT_FATAL(ack_ts != NULL);

    /* 64 timestamps fill the arrays */
    xqc_int_t ret = xqc_test_ack_with_timestamp_parse_count(conn, 1, ack_ts);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(ack_ts->report_num == XQC_RECV_TIMESTAMPS_INFO_MAX_LENGTH);

    /* a 65th does not fit */
    ret = xqc_test_ack_with_timestamp_parse_count(conn, 2, ack_ts);
    CU_ASSERT(ret == -XQC_EACK_EXT_ABN_VAL);
    CU_ASSERT(ack_ts->report_num <= XQC_RECV_TIMESTAMPS_INFO_MAX_LENGTH);

    xqc_free(ack_ts);
    xqc_engine_destroy(conn->engine);
}


void
xqc_test_ack_with_timestamp()
{
    xqc_test_ack_with_timestamp_normal();
    xqc_test_ack_with_timestamp_no_buf_space();
    xqc_test_ack_with_timestamp_partial_writing();
    xqc_test_ack_with_timestamp_count_limit();
}