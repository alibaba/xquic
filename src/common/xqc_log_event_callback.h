/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQUIC_XQC_LOG_EVENT_CALLBACK_H
#define XQUIC_XQC_LOG_EVENT_CALLBACK_H

#include "src/common/xqc_log.h"

void xqc_log_CON_SERVER_LISTENING_callback(xqc_log_t *log, const char *func, const struct sockaddr *peer_addr, 
    socklen_t peer_addrlen);

void xqc_log_CON_CONNECTION_STARTED_callback(xqc_log_t *log, const char *func,
    xqc_connection_t *conn, xqc_int_t local);

void xqc_log_CON_CONNECTION_CLOSED_callback(xqc_log_t *log, const char *func,
    xqc_connection_t *conn);

void xqc_log_CON_CONNECTION_ID_UPDATED_callback(xqc_log_t *log, const char *func,
    xqc_connection_t *conn);

void xqc_log_CON_CONNECTION_STATE_UPDATED_callback(xqc_log_t *log, const char *func,
    xqc_connection_t *conn);

void xqc_log_CON_PATH_ASSIGNED_callback(xqc_log_t *log, const char *func,
    xqc_path_ctx_t *path, xqc_connection_t *conn);

void xqc_log_CON_MTU_UPDATED_callback(xqc_log_t *log, const char *func,
    xqc_connection_t *conn, int32_t is_done);

void xqc_log_SEC_KEY_UPDATED_callback(xqc_log_t *log, const char *func,
    xqc_engine_ssl_config_t ssl_config, xqc_int_t local);

void xqc_log_TRA_VERSION_INFORMATION_callback(xqc_log_t *log, const char *func,
    uint32_t local_count, uint32_t *local_version, uint32_t remote_count,
    uint32_t *remote_version, uint32_t choose);

void xqc_log_TRA_ALPN_INFORMATION_callback(xqc_log_t *log, const char *func, const unsigned char * server_alpn_list, 
    unsigned int server_alpn_list_len, const unsigned char *client_alpn_list, unsigned int client_alpn_list_len,
    const char *selected_alpn, size_t selected_alpn_len);

void xqc_log_TRA_PARAMETERS_SET_callback(xqc_log_t *log, const char *func, xqc_connection_t *conn,
    xqc_int_t local);

void xqc_log_TRA_PACKET_DROPPED_callback(xqc_log_t *log, const char *func, const char *trigger, xqc_int_t ret,
    const char * pi_pkt_type, xqc_packet_number_t pi_pkt_num);

void xqc_log_TRA_PACKET_RECEIVED_callback(xqc_log_t *log, const char *func,
    xqc_packet_in_t *packet_in);

void xqc_log_TRA_PACKET_SENT_callback(xqc_log_t *log, const char *func, xqc_connection_t *conn,
    xqc_packet_out_t *packet_out, xqc_path_ctx_t *path, xqc_usec_t send_time, ssize_t sent, xqc_bool_t with_pn);

void xqc_log_TRA_PACKET_BUFFERED_callback(xqc_log_t *log, const char *func,
    xqc_packet_in_t *packet_in);

void xqc_log_TRA_PACKETS_ACKED_callback(xqc_log_t *log, const char *func,
    xqc_packet_in_t *packet_in, xqc_packet_number_t high, xqc_packet_number_t low, uint64_t path_id);

void xqc_log_TRA_DATAGRAMS_SENT_callback(xqc_log_t *log, const char *func, ssize_t size, uint64_t path_id);

void xqc_log_TRA_DATAGRAMS_RECEIVED_callback(xqc_log_t *log, const char *func, ssize_t size, uint64_t path_id);

void xqc_log_TRA_STREAM_STATE_UPDATED_callback(xqc_log_t *log, const char *func,
    xqc_stream_t *stream, xqc_int_t stream_type, xqc_int_t state);

void xqc_log_TRA_FRAMES_PROCESSED_callback(xqc_log_t *log, const char *func, ...);

void xqc_log_TRA_STREAM_DATA_MOVED_callback(xqc_log_t *log, const char *func, xqc_stream_t *stream,
    xqc_bool_t is_recv, size_t read_or_write_size, size_t recv_buf_size, uint8_t fin, int ret, 
    int pkt_type, int buff_1rtt, size_t offset);

void xqc_log_TRA_DATAGRAM_DATA_MOVED_callback(xqc_log_t *log, const char *func, xqc_stream_t *stream,
    size_t moved_data_len, const char *from, const char *to);

void xqc_log_TRA_STATELESS_RESET_callback(xqc_log_t *log, const char *func, xqc_connection_t *c);

void xqc_log_REC_PARAMETERS_SET_callback(xqc_log_t *log, const char *func, xqc_send_ctl_t *send_ctl,
    uint8_t timer_granularity, xqc_cc_params_t cc_params);

void xqc_log_REC_METRICS_UPDATED_callback(xqc_log_t *log, const char *func, xqc_send_ctl_t *send_ctl);

void xqc_log_REC_CONGESTION_STATE_UPDATED_callback(xqc_log_t *log, const char *func,
    char *new_state);

void xqc_log_REC_LOSS_TIMER_UPDATED_callback(xqc_log_t *log, const char *func,
    xqc_timer_manager_t *timer_manager, xqc_usec_t inter_time, xqc_int_t type, xqc_int_t event);

void xqc_log_REC_PACKET_LOST_callback(xqc_log_t *log, const char *func, xqc_packet_out_t *packet_out, 
    xqc_packet_number_t lost_pn, xqc_usec_t lost_send_time, xqc_usec_t loss_delay);

void xqc_log_HTTP_PARAMETERS_SET_callback(xqc_log_t *log, const char *func, xqc_h3_conn_t *h3_conn,
    xqc_int_t local);

void xqc_log_HTTP_PARAMETERS_RESTORED_callback(xqc_log_t *log, const char *func,
    xqc_h3_conn_t *h3_conn);

void xqc_log_HTTP_STREAM_TYPE_SET_callback(xqc_log_t *log, const char *func,
    xqc_h3_stream_t *h3_stream, xqc_int_t local);

void xqc_log_HTTP_FRAME_CREATED_callback(xqc_log_t *log, const char *func, ...);

void xqc_log_HTTP_FRAME_PARSED_callback(xqc_log_t *log, const char *func,
    xqc_h3_stream_t *h3_stream);

void
xqc_log_HTTP_PRIORITY_UPDATED_callback(xqc_log_t *log, const char *func, xqc_h3_priority_t *prio, xqc_h3_stream_t *h3s);

void xqc_log_QPACK_STATE_UPDATED_callback(xqc_log_t *log, const char *func, ...);

void xqc_log_QPACK_STREAM_STATE_UPDATED_callback(xqc_log_t *log, const char *func,
    xqc_h3_stream_t *h3_stream);

void xqc_log_QPACK_DYNAMIC_TABLE_UPDATED_callback(xqc_log_t *log, const char *func, ...);

void xqc_log_QPACK_HEADERS_ENCODED_callback(xqc_log_t *log, const char *func, ...);

void xqc_log_QPACK_HEADERS_DECODED_callback(xqc_log_t *log, const char *func, ...);

void xqc_log_QPACK_INSTRUCTION_CREATED_callback(xqc_log_t *log, const char *func, ...);

void xqc_log_QPACK_INSTRUCTION_PARSED_callback(xqc_log_t *log, const char *func, ...);

#endif /* XQUIC_XQC_LOG_EVENT_CALLBACK_H */
