/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQUIC_XQC_LOG_EVENT_CALLBACK_H
#define XQUIC_XQC_LOG_EVENT_CALLBACK_H

#include "src/common/xqc_log.h"


void xqc_log_CON_CONNECTION_STARTED_callback(xqc_log_t *log, const char *func,
    xqc_connection_t *conn, xqc_int_t local);

void xqc_log_CON_CONNECTION_CLOSED_callback(xqc_log_t *log, const char *func,
    xqc_connection_t *conn);

void xqc_log_CON_CONNECTION_ID_UPDATED_callback(xqc_log_t *log, const char *func,
    xqc_connection_t *conn);

void xqc_log_CON_CONNECTION_STATE_UPDATED_callback(xqc_log_t *log, const char *func,
    xqc_connection_t *conn);

void xqc_log_SEC_KEY_UPDATED_callback(xqc_log_t *log, const char *func,
    xqc_engine_ssl_config_t ssl_config, xqc_int_t local);

void xqc_log_TRA_VERSION_INFORMATION_callback(xqc_log_t *log, const char *func,
    uint32_t local_count, uint32_t *local_version, uint32_t remote_count,
    uint32_t *remote_version, uint32_t choose);

void xqc_log_TRA_ALPN_INFORMATION_callback(xqc_log_t *log, const char *func, size_t local_count,
    uint8_t *local_alpn, size_t remote_count, const uint8_t *remote_alpn, size_t alpn_len,
    const unsigned char *alpn);

void xqc_log_TRA_PARAMETERS_SET_callback(xqc_log_t *log, const char *func, xqc_connection_t *conn,
    xqc_int_t local);

void xqc_log_TRA_PACKET_RECEIVED_callback(xqc_log_t *log, const char *func,
    xqc_packet_in_t *packet_in);

void xqc_log_TRA_PACKET_SENT_callback(xqc_log_t *log, const char *func,
    xqc_packet_out_t *packet_out);

void xqc_log_TRA_PACKET_BUFFERED_callback(xqc_log_t *log, const char *func,
    xqc_packet_in_t *packet_in);

void xqc_log_TRA_PACKETS_ACKED_callback(xqc_log_t *log, const char *func,
    xqc_packet_in_t *packet_in, xqc_packet_number_t high, xqc_packet_number_t low);

void xqc_log_TRA_DATAGRAMS_SENT_callback(xqc_log_t *log, const char *func, ssize_t size);

void xqc_log_TRA_DATAGRAMS_RECEIVED_callback(xqc_log_t *log, const char *func, ssize_t size);

void xqc_log_TRA_STREAM_STATE_UPDATED_callback(xqc_log_t *log, const char *func,
    xqc_stream_t *stream, xqc_int_t stream_type, xqc_int_t state);

void xqc_log_TRA_FRAMES_PROCESSED_callback(xqc_log_t *log, const char *func, ...);

void xqc_log_REC_PARAMETERS_SET_callback(xqc_log_t *log, const char *func, xqc_send_ctl_t *ctl);

void xqc_log_REC_METRICS_UPDATED_callback(xqc_log_t *log, const char *func, xqc_send_ctl_t *ctl);

void xqc_log_REC_CONGESTION_STATE_UPDATED_callback(xqc_log_t *log, const char *func,
    char *new_state);

void xqc_log_REC_LOSS_TIMER_UPDATED_callback(xqc_log_t *log, const char *func, xqc_send_ctl_t *ctl,
    xqc_usec_t inter_time, xqc_int_t type, xqc_int_t event);

void xqc_log_REC_PACKET_LOST_callback(xqc_log_t *log, const char *func,
    xqc_packet_out_t *packet_out);

void xqc_log_HTTP_PARAMETERS_SET_callback(xqc_log_t *log, const char *func, xqc_h3_conn_t *h3_conn,
    xqc_int_t local);

void xqc_log_HTTP_PARAMETERS_RESTORED_callback(xqc_log_t *log, const char *func,
    xqc_h3_conn_t *h3_conn);

void xqc_log_HTTP_STREAM_TYPE_SET_callback(xqc_log_t *log, const char *func,
    xqc_h3_stream_t *h3_stream, xqc_int_t local);

void xqc_log_HTTP_FRAME_CREATED_callback(xqc_log_t *log, const char *func, ...);

void xqc_log_HTTP_FRAME_PARSED_callback(xqc_log_t *log, const char *func,
    xqc_h3_stream_t *h3_stream);

void xqc_log_HTTP_SETTING_PARSED_callback(xqc_log_t *log, const char *func, uint64_t identifier,
    uint64_t value);

void xqc_log_QPACK_STATE_UPDATED_callback(xqc_log_t *log, const char *func, ...);

void xqc_log_QPACK_STREAM_STATE_UPDATED_callback(xqc_log_t *log, const char *func,
    xqc_h3_stream_t *h3_stream);

void xqc_log_QPACK_DYNAMIC_TABLE_UPDATED_callback(xqc_log_t *log, const char *func, ...);

void xqc_log_QPACK_HEADERS_ENCODED_callback(xqc_log_t *log, const char *func, ...);

void xqc_log_QPACK_HEADERS_DECODED_callback(xqc_log_t *log, const char *func, ...);

void xqc_log_QPACK_INSTRUCTION_CREATED_callback(xqc_log_t *log, const char *func, ...);

void xqc_log_QPACK_INSTRUCTION_PARSED_callback(xqc_log_t *log, const char *func, ...);

#endif /* XQUIC_XQC_LOG_EVENT_CALLBACK_H */
