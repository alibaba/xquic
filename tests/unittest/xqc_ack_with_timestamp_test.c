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
 * max_receive_timestamps_per_ack bounds the timestamps in a frame: the
 * ranges that gaps open do not use it up. Packets 1, 2, 4, 5, 7, 8 and 10
 * with a limit of 5 report the newest 5: 10, 8, 7, 5 and 4.
 */
static void
xqc_test_ack_with_timestamp_gaps_budget()
{
    const xqc_packet_number_t pkt_nums[] = {1, 2, 4, 5, 7, 8, 10};
    const xqc_packet_number_t reported[] = {10, 8, 7, 5, 4};
    const int npkts = sizeof(pkt_nums) / sizeof(pkt_nums[0]);
    const int nreported = sizeof(reported) / sizeof(reported[0]);

    xqc_packet_out_t *packet_out = xqc_packet_out_create(XQC_QUIC_MAX_MSS);
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_recv_record_t record;
    memset(&record, 0, sizeof(record));
    xqc_init_list_head(&record.list_head);
    xqc_recv_timestamps_info_t *ts_info = xqc_recv_timestamps_info_create();
    for (int i = 0; i < npkts; i++) {
        xqc_recv_record_add(&record, pkt_nums[i]);
        xqc_recv_timestamps_info_add_pkt(ts_info, pkt_nums[i], 1000 * pkt_nums[i]);
    }
    conn->conn_settings.extended_ack_features = 2;
    conn->conn_settings.max_receive_timestamps_per_ack = nreported;
    conn->conn_settings.receive_timestamps_exponent = 0;
    conn->local_settings.extended_ack_features = 2;
    conn->local_settings.max_receive_timestamps_per_ack = nreported;
    conn->local_settings.receive_timestamps_exponent = 0;
    conn->conn_create_time = 0;

    int has_gap;
    xqc_packet_number_t largest_ack;
    packet_out->po_used_size = 0;
    ssize_t len = xqc_gen_ack_ext_frame(conn, packet_out, 10000, 0, &record, 10000,
                                        &has_gap, &largest_ack, ts_info);
    CU_ASSERT_FATAL(len > 0);

    xqc_packet_in_t packet_in;
    memset(&packet_in, 0, sizeof(packet_in));
    packet_in.buf = packet_out->po_buf;
    packet_in.pos = packet_out->po_buf;
    packet_in.last = packet_out->po_buf + len;
    packet_in.pi_pkt.pkt_pns = XQC_PNS_APP_DATA;
    xqc_ack_info_t ack_info;
    xqc_ack_timestamp_info_t ack_ts;
    ack_ts.report_num = 0;
    CU_ASSERT(xqc_parse_ack_ext_frame(&packet_in, conn, &ack_info, &ack_ts) == XQC_OK);
    CU_ASSERT(ack_ts.report_num == nreported);
    for (int i = 0; i < nreported && i < ack_ts.report_num; i++) {
        CU_ASSERT(ack_ts.pkt_nums[i] == reported[i]);
    }

    xqc_engine_destroy(conn->engine);
    xqc_packet_out_destroy(packet_out);
    xqc_recv_record_destroy(&record);
    xqc_recv_timestamps_info_destroy(ts_info);
}


void
xqc_test_ack_with_timestamp()
{
    xqc_test_ack_with_timestamp_normal();
    xqc_test_ack_with_timestamp_no_buf_space();
    xqc_test_ack_with_timestamp_partial_writing();
    xqc_test_ack_with_timestamp_gaps_budget();
}