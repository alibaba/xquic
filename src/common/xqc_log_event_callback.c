/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_log_event_callback.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/congestion_control/xqc_bbr_common.h"
#include "src/http3/xqc_h3_conn.h"

void
xqc_log_CON_CONNECTION_STARTED_callback(xqc_log_t *log, const char *func, xqc_connection_t *conn, xqc_int_t local)
{
    if (local == XQC_LOG_LOCAL_EVENT) {
        struct sockaddr_in *sa_local = (struct sockaddr_in *)conn->local_addr;
        xqc_log_implement(log, CON_CONNECTION_STARTED, func,
                          "|local|src_ip:%s|src_port:%d|",
                          xqc_conn_local_addr_str((struct sockaddr*)sa_local,
                                                  conn->local_addrlen), ntohs(sa_local->sin_port));

    } else {
        struct sockaddr_in *sa_peer = (struct sockaddr_in *)conn->peer_addr;
        xqc_log_implement(log, CON_CONNECTION_STARTED, func,
                          "|remote|dst_ip:%s|dst_port:%d|scid:%s|dcid:%s|",
                          xqc_conn_peer_addr_str((struct sockaddr*)sa_peer, conn->peer_addrlen),
                          ntohs(sa_peer->sin_port), log->scid, xqc_dcid_str(&conn->dcid_set.current_dcid));
    }
}

void
xqc_log_CON_CONNECTION_CLOSED_callback(xqc_log_t *log, const char *func, xqc_connection_t *conn)
{
    xqc_log_implement(log, CON_CONNECTION_CLOSED, func,
                      "|err_code:%d|", conn->conn_err);
}

void
xqc_log_CON_CONNECTION_ID_UPDATED_callback(xqc_log_t *log, const char *func, xqc_connection_t *conn)
{
    unsigned char  scid_str[XQC_MAX_CID_LEN * 2 + 1];
    xqc_hex_dump(scid_str, conn->scid_set.user_scid.cid_buf, conn->scid_set.user_scid.cid_len);
    scid_str[conn->scid_set.user_scid.cid_len * 2] = '\0';
    xqc_log_implement(log, CON_CONNECTION_ID_UPDATED, func,
                      "|scid:%s|dcid:%s|", scid_str, conn->dcid_set.current_dcid_str);
}

void
xqc_log_CON_CONNECTION_STATE_UPDATED_callback(xqc_log_t *log, const char *func, xqc_connection_t *conn)
{
    xqc_log_implement(log, CON_CONNECTION_STATE_UPDATED, func,
                      "|state:%d|", conn->conn_state);
}

void
xqc_log_SEC_KEY_UPDATED_callback(xqc_log_t *log, const char *func, xqc_engine_ssl_config_t ssl_config, xqc_int_t local)
{
    if (local == XQC_LOG_LOCAL_EVENT) {
        xqc_log_implement(log, SEC_KEY_UPDATED, func,
                          "|local|ciphers:%s|", ssl_config.ciphers);

    } else {
        xqc_log_implement(log, SEC_KEY_UPDATED, func,
                          "|remote|ciphers:%s|", ssl_config.ciphers);
    }
}

void
xqc_log_TRA_VERSION_INFORMATION_callback(xqc_log_t *log, const char *func, uint32_t local_count,
    uint32_t *local_version, uint32_t remote_count, uint32_t *remote_version, uint32_t choose)
{
    unsigned char log_buf[XQC_MAX_LOG_LEN];
    unsigned char *p = log_buf;
    unsigned char *last = log_buf + sizeof(log_buf);

    p = xqc_sprintf(p, last, "local_version:");
    for (uint32_t i = 0; i < local_count; ++i) {
        p = xqc_sprintf(p, last, " %d", local_version[i]);
    }

    p = xqc_sprintf(p, last, "|remote_version:");
    for (uint32_t i = 0; i < remote_count; ++i) {
        p = xqc_sprintf(p, last, " %d", remote_version[i]);
    }

    if (p != last) {
        *p = '\0';
    }

    xqc_log_implement(log, TRA_VERSION_INFORMATION, func,
                      "|%s|choose:%d|", log_buf, choose);
}

void
xqc_log_TRA_ALPN_INFORMATION_callback(xqc_log_t *log, const char *func, size_t local_count, uint8_t *local_alpn,
    size_t remote_count, const uint8_t *remote_alpn, size_t alpn_len, const unsigned char *alpn)
{
    unsigned char log_buf[XQC_MAX_LOG_LEN];
    unsigned char *p = log_buf;
    unsigned char *last = log_buf + sizeof(log_buf);

    p = xqc_sprintf(p, last, "local_alpn:");
    for (size_t i = 0; i < local_count; ++i) {
        p = xqc_sprintf(p, last, " %d", local_alpn[i]);
    }

    p = xqc_sprintf(p, last, "|remote_alpn:");
    for (size_t i = 0; i < remote_count; ++i) {
        p = xqc_sprintf(p, last, " %d", remote_alpn[i]);
    }

    if (p != last) {
        *p = '\0';
    }

    xqc_log_implement(log, TRA_ALPN_INFORMATION, func,
                      "|%s|choose:%*s|", log_buf, alpn_len, alpn);
}

void
xqc_log_TRA_PARAMETERS_SET_callback(xqc_log_t *log, const char *func, xqc_connection_t *conn, xqc_int_t local)
{
    xqc_trans_settings_t *setting;
    if (local == XQC_LOG_LOCAL_EVENT) {
        setting = &conn->local_settings;

    } else {
        setting = &conn->remote_settings;
    }

    xqc_log_implement(log, TRA_PARAMETERS_SET, func,
                      "|%s|migration:%d|max_idle_timeout:%d|max_udp_payload_size:%d|"
                      "active_connection_id_limit:%d|max_data:%d|",
                      local == XQC_LOG_LOCAL_EVENT ? "local" : "remote", setting->disable_active_migration,
                      setting->max_idle_timeout, setting->max_udp_payload_size,
                      setting->active_connection_id_limit, setting->max_data);
}

void
xqc_log_TRA_PACKET_RECEIVED_callback(xqc_log_t *log, const char *func, xqc_packet_in_t *packet_in)
{
    xqc_log_implement(log, TRA_PACKET_RECEIVED, func,
                      "|pkt_pns:%d|pkt_type:%d|pkt_num:%d|len:%d|frame_flag:%s|",
                      packet_in->pi_pkt.pkt_pns, packet_in->pi_pkt.pkt_type, packet_in->pi_pkt.pkt_num,
                      packet_in->buf_size, xqc_frame_type_2_str(packet_in->pi_frame_types));
}

void
xqc_log_TRA_PACKET_SENT_callback(xqc_log_t *log, const char *func, xqc_packet_out_t *packet_out)
{
    xqc_log_implement(log, TRA_PACKET_SENT, func,
                      "|pkt_pns:%d|pkt_type:%d|pkt_num:%d|size:%d|frame_flag:%s|",
                      packet_out->po_pkt.pkt_pns, packet_out->po_pkt.pkt_type, packet_out->po_pkt.pkt_num,
                      packet_out->po_used_size, xqc_frame_type_2_str(packet_out->po_frame_types));
}

void
xqc_log_TRA_PACKET_BUFFERED_callback(xqc_log_t *log, const char *func, xqc_packet_in_t *packet_in)
{
    xqc_log_implement(log, TRA_PACKET_BUFFERED, func,
                      "|pkt_pns:%d|pkt_type:%d|len:%d|",
                      packet_in->pi_pkt.pkt_pns, packet_in->pi_pkt.pkt_type, packet_in->buf_size);
}

void
xqc_log_TRA_PACKETS_ACKED_callback(xqc_log_t *log, const char *func, xqc_packet_in_t *packet_in,
    xqc_packet_number_t high, xqc_packet_number_t low)
{
    xqc_log_implement(log, TRA_PACKETS_ACKED, func,
                      "|pkt_space:%d|high:%d|low:%d|",
                      packet_in->pi_pkt.pkt_pns, high, low);
}

void
xqc_log_TRA_DATAGRAMS_SENT_callback(xqc_log_t *log, const char *func, ssize_t size)
{
    xqc_log_implement(log, TRA_DATAGRAMS_SENT, func,
                      "|size:%d|", size);
}

void
xqc_log_TRA_DATAGRAMS_RECEIVED_callback(xqc_log_t *log, const char *func, ssize_t size)
{
    xqc_log_implement(log, TRA_DATAGRAMS_RECEIVED, func,
                      "|size:%d|", size);
}

void
xqc_log_TRA_STREAM_STATE_UPDATED_callback(xqc_log_t *log, const char *func, xqc_stream_t *stream,
    xqc_int_t stream_type, xqc_int_t state)
{
    if (stream_type == XQC_LOG_STREAM_SEND) {
        xqc_log_implement(log, TRA_STREAM_STATE_UPDATED, func,
                          "|stream_id:%d|send_stream|old:%d|new:%d|",
                          stream->stream_id, stream->stream_state_send, state);
    } else {
        xqc_log_implement(log, TRA_STREAM_STATE_UPDATED, func,
                          "|stream_id:%d|recv_stream|old:%d|new:%d|",
                          stream->stream_id, stream->stream_state_recv, state);
    }
}

void
xqc_log_TRA_FRAMES_PROCESSED_callback(xqc_log_t *log, const char *func, ...)
{
    va_list args;
    va_start(args, func);
    xqc_frame_type_t frame_type = va_arg(args, xqc_frame_type_t);
    switch (frame_type) {
    case XQC_FRAME_PADDING: {
        uint32_t length = va_arg(args, uint32_t);
        xqc_log_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|length:%ui|", frame_type, length);
        break;
    }

    case XQC_FRAME_PING:
        xqc_log_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|", frame_type);
        break;

    case XQC_FRAME_ACK: {
        xqc_ack_info_t *ack_info = va_arg(args, xqc_ack_info_t*);
        unsigned char buf[1024];
        unsigned char *p = buf;
        unsigned char *last = buf + sizeof(buf);

        for (int i = 0; i < ack_info->n_ranges; i++) {
            if (i == 0) {
                p = xqc_sprintf(p, last, "{%ui - %ui", ack_info->ranges[i].low, ack_info->ranges[i].high);

            } else {
                p = xqc_sprintf(p, last, ", %ui - %ui", ack_info->ranges[i].low, ack_info->ranges[i].high);
            }
        }

        p = xqc_sprintf(p, last, "}");
        if (p != last) {
            *p = '\0';
        }

        xqc_log_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|ack_delay:%ui|ack_range:%s|",
                          frame_type, ack_info->ack_delay, buf);
        break;
    }

    case XQC_FRAME_RESET_STREAM: {
        xqc_stream_id_t stream_id = va_arg(args, xqc_stream_id_t);
        uint64_t err_code = va_arg(args, uint64_t);
        uint64_t final_size = va_arg(args, uint64_t);
        xqc_log_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|stream_id:%ui|err_code:%ui|final_size:%ui|",
                          frame_type, stream_id, err_code, final_size);
        break;
    }

    case XQC_FRAME_STOP_SENDING: {
        xqc_stream_id_t stream_id = va_arg(args, xqc_stream_id_t);
        uint64_t err_code = va_arg(args, uint64_t);
        xqc_log_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|stream_id:%ui|err_code:%ui|", frame_type, stream_id, err_code);
        break;
    }

    case XQC_FRAME_CRYPTO: {
        uint64_t offset = va_arg(args, uint64_t);
        uint64_t length = va_arg(args, uint64_t);
        xqc_log_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|offset:%ui|length:%ui|", frame_type, offset, length);
        break;
    }

    case XQC_FRAME_NEW_TOKEN: {
        uint64_t length = va_arg(args, uint64_t);
        unsigned char* token = va_arg(args, unsigned char*);
        xqc_log_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|token_length:%ui|token:%s|", frame_type, length, token);
        break;
    }

    case XQC_FRAME_STREAM: {
        xqc_stream_frame_t *frame = va_arg(args, xqc_stream_frame_t*);
        xqc_log_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|data_offset:%ui|data_length:%d|fin:%d|",
                          frame_type, frame->data_offset, frame->data_length, frame->fin);
        break;
    }

    case XQC_FRAME_MAX_DATA: {
        uint64_t max_data = va_arg(args, uint64_t);
        xqc_log_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|max_data:%ui|", frame_type, max_data);
        break;
    }

    case XQC_FRAME_MAX_STREAM_DATA: {
        xqc_stream_id_t stream_id = va_arg(args, xqc_stream_id_t);
        uint64_t max_stream_data = va_arg(args, uint64_t);
        xqc_log_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|stream_id:%ui|max_stream_data:%ui|",
                          frame_type, stream_id, max_stream_data);
        break;
    }
    case XQC_FRAME_MAX_STREAMS: {
        int bidirectional = va_arg(args, int);
        uint64_t max_streams = va_arg(args, uint64_t);
        if (bidirectional) {
            xqc_log_implement(log, TRA_FRAMES_PROCESSED, func,
                              "|type:%d|bidirectional|max_stream_data:%ui|",
                              frame_type, max_streams);

        } else {
            xqc_log_implement(log, TRA_FRAMES_PROCESSED, func,
                              "|type:%d|unidirectional|max_stream_data:%ui|",
                              frame_type, max_streams);
        }
        break;
    }

    case XQC_FRAME_DATA_BLOCKED: {
        uint64_t *data_limit = va_arg(args, uint64_t*);
        xqc_log_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|bidirectional|data_limit:%ui|",
                          frame_type, *data_limit);
        break;
    }

    case XQC_FRAME_STREAM_DATA_BLOCKED: {
        xqc_stream_id_t stream_id = va_arg(args, xqc_stream_id_t);
        uint64_t stream_data_limit = va_arg(args, uint64_t);
        xqc_log_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|bidirectional|stream_id:%ui|stream_data_limit:%ui|",
                          frame_type, stream_id, stream_data_limit);
        break;
    }

    case XQC_FRAME_STREAMS_BLOCKED: {
        int bidirectional = va_arg(args, int);
        uint64_t stream_limit = va_arg(args, uint64_t);
        if (bidirectional) {
            xqc_log_implement(log, TRA_FRAMES_PROCESSED, func,
                              "|type:%d|bidirectional|stream_limit:%ui|",
                              frame_type, stream_limit);

        } else {
            xqc_log_implement(log, TRA_FRAMES_PROCESSED, func,
                              "|type:%d|unidirectional|stream_limit:%ui|",
                              frame_type, stream_limit);
        }
        break;
    }

    case XQC_FRAME_NEW_CONNECTION_ID: {
        xqc_cid_t *new_cid = va_arg(args, xqc_cid_t*);
        uint64_t retire_prior_to = va_arg(args, uint64_t);
        unsigned char scid_str[XQC_MAX_CID_LEN * 2 + 1];
        xqc_hex_dump(scid_str, new_cid->cid_buf, new_cid->cid_len);
        scid_str[new_cid->cid_len * 2] = '\0';
        xqc_log_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|seq_num:%ui|retire_prior_to:%ui|cid_len:%d|cid:%s|",
                          frame_type, new_cid->cid_seq_num, retire_prior_to, new_cid->cid_len, scid_str);
        break;
    }

    case XQC_FRAME_CONNECTION_CLOSE: {
        uint64_t err_code = va_arg(args, uint64_t);
        xqc_log_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|err_code:%ui|", frame_type, err_code);
        break;
    }

    case XQC_FRAME_HANDSHAKE_DONE:
        xqc_log_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|", frame_type);
        break;

    case XQC_FRAME_RETIRE_CONNECTION_ID:
    case XQC_FRAME_PATH_CHALLENGE:
    case XQC_FRAME_PATH_RESPONSE:
    case XQC_FRAME_PATH_STATUS:
    case XQC_FRAME_ACK_MP:
    case XQC_FRAME_QOE_CONTROL_SIGNAL:
    case XQC_FRAME_Extension:
        break;

    default:
        break;
    }
    va_end(args);
}

void
xqc_log_REC_PARAMETERS_SET_callback(xqc_log_t *log, const char *func, xqc_send_ctl_t *ctl)
{
    xqc_log_implement(log, REC_PARAMETERS_SET, func,
                      "|reordering_packet_threshold:%d|reordering_time_threshold_shift:%d|",
                      ctl->ctl_reordering_packet_threshold, ctl->ctl_reordering_time_threshold_shift);
}

void
xqc_log_REC_METRICS_UPDATED_callback(xqc_log_t *log, const char *func, xqc_send_ctl_t *ctl)
{
    uint64_t cwnd = ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(ctl->ctl_cong);
    int64_t bw = 0;
    uint64_t pacing_rate = 0;
    int mode = 0;
    xqc_usec_t min_rtt = 0;

    if (ctl->ctl_cong_callback->xqc_cong_ctl_init_bbr) {
        bw = ctl->ctl_cong_callback->
                xqc_cong_ctl_get_bandwidth_estimate(ctl->ctl_cong);
        pacing_rate = ctl->ctl_cong_callback->
                xqc_cong_ctl_get_pacing_rate(ctl->ctl_cong);
        mode = ctl->ctl_cong_callback->xqc_cong_ctl_info_cb->mode(ctl->ctl_cong);
        min_rtt = ctl->ctl_cong_callback-> xqc_cong_ctl_info_cb->min_rtt(ctl->ctl_cong);
        xqc_log_implement(log, REC_METRICS_UPDATED, func,
                          "|cwnd:%ui|inflight:%ud|mode:%ud|applimit:%ud|pacing_rate:%ui|bw:%ui|srtt:%ui|"
                          "latest_rtt:%ui|ctl_rttvar:%ui|pto_count:%ud|min_rtt:%ui|send:%ud|lost:%ud|tlp:%ud|recv:%ud|",
                          cwnd, ctl->ctl_bytes_in_flight, mode, ctl->ctl_app_limited, pacing_rate, bw, ctl->ctl_srtt,
                          ctl->ctl_latest_rtt, ctl->ctl_pto_count, min_rtt, ctl->ctl_send_count, ctl->ctl_lost_count,
                          ctl->ctl_tlp_count, ctl->ctl_recv_count);

    } else {
        xqc_log_implement(log, REC_METRICS_UPDATED, func,
                          "|cwnd:%ui|inflight:%ud|applimit:%ud|srtt:%ui|latest_rtt:%ui|pto_count:%ud|"
                          "send:%ud|lost:%ud|tlp:%ud|recv:%ud|",
                          cwnd, ctl->ctl_bytes_in_flight, ctl->ctl_app_limited, ctl->ctl_srtt, ctl->ctl_latest_rtt, ctl->ctl_pto_count,
                          ctl->ctl_send_count, ctl->ctl_lost_count, ctl->ctl_tlp_count, ctl->ctl_recv_count);
    }
}

void
xqc_log_REC_CONGESTION_STATE_UPDATED_callback(xqc_log_t *log, const char *func, char *new_state)
{
    xqc_log_implement(log, REC_CONGESTION_STATE_UPDATED, func,
                      "|new_state:%s|", new_state);
}

void
xqc_log_REC_LOSS_TIMER_UPDATED_callback(xqc_log_t *log, const char *func, xqc_send_ctl_t *ctl,
                                        xqc_usec_t inter_time, xqc_int_t type, xqc_int_t event)
{
    if (event == XQC_LOG_TIMER_SET) {
        xqc_log_implement(log, REC_LOSS_TIMER_UPDATED, func,
                          "|set|type:%s|expire:%ui|interv:%ui|",
                          xqc_timer_type_2_str(type), ctl->ctl_timer[type].ctl_expire_time, inter_time);

    } else if (event == XQC_LOG_TIMER_EXPIRE) {
        xqc_log_implement(log, REC_LOSS_TIMER_UPDATED, func,
                          "|expired|type:%s|expire_time:%ui|",
                          xqc_timer_type_2_str(type), ctl->ctl_timer[type].ctl_expire_time);

    } else if (event == XQC_LOG_TIMER_CANCEL) {
        xqc_log_implement(log, REC_LOSS_TIMER_UPDATED, func,
                          "|cancel|type:%s|", xqc_timer_type_2_str(type));
    }
}

void
xqc_log_REC_PACKET_LOST_callback(xqc_log_t *log, const char *func, xqc_packet_out_t *packet_out)
{
    xqc_log_implement(log, REC_PACKET_LOST, func,
                      "|pkt_pns:%d|pkt_type:%d|pkt_num:%d|",
                      packet_out->po_pkt.pkt_pns, packet_out->po_pkt.pkt_type, packet_out->po_pkt.pkt_num);
}

void
xqc_log_HTTP_PARAMETERS_SET_callback(xqc_log_t *log, const char *func, xqc_h3_conn_t *h3_conn, xqc_int_t local)
{
    xqc_h3_conn_settings_t *setting;
    if (local == XQC_LOG_LOCAL_EVENT) {
        setting = &h3_conn->local_h3_conn_settings;

    } else {
        setting = &h3_conn->peer_h3_conn_settings;
    }
    xqc_log_implement(log, HTTP_PARAMETERS_SET, func,
                      "|%s|max_field_section_size:%ui|qpack_max_table_capacity:%ui|qpack_blocked_streams:%ui|",
                      local == XQC_LOG_LOCAL_EVENT ? "local" : "remote", setting->max_field_section_size,
                      setting->qpack_max_table_capacity, setting->qpack_blocked_streams);
}

void
xqc_log_HTTP_PARAMETERS_RESTORED_callback(xqc_log_t *log, const char *func, xqc_h3_conn_t *h3_conn)
{
    xqc_h3_conn_settings_t *setting = &h3_conn->local_h3_conn_settings;
    xqc_log_implement(log, HTTP_PARAMETERS_RESTORED, func,
                      "|max_field_section_size:%ui|qpack_max_table_capacity:%ui|qpack_blocked_streams:%ui|",
                      setting->max_field_section_size,
                      setting->qpack_max_table_capacity, setting->qpack_blocked_streams);
}

void
xqc_log_HTTP_STREAM_TYPE_SET_callback(xqc_log_t *log, const char *func, xqc_h3_stream_t *h3_stream, xqc_int_t local)
{
    xqc_log_implement(log, HTTP_STREAM_TYPE_SET, func,
                      "|%s|stream_id:%ui|stream_type:%d|",
                      local == XQC_LOG_LOCAL_EVENT ? "local" : "remote", h3_stream->stream->stream_id, h3_stream->type);
}

void
xqc_log_HTTP_FRAME_CREATED_callback(xqc_log_t *log, const char *func, ...)
{
    unsigned char log_buf[XQC_MAX_LOG_LEN];
    va_list args;
    va_start(args, func);
    xqc_h3_stream_t *h3_stream = va_arg(args, xqc_h3_stream_t*);
    xqc_stream_id_t stream_id = h3_stream->stream->stream_id;
    xqc_h3_frm_type_t type = va_arg(args, xqc_h3_frm_type_t);
    switch (type) {
    case XQC_H3_FRM_DATA: {
        uint64_t size = va_arg(args, uint64_t);
        xqc_log_implement(log, HTTP_FRAME_CREATED, func,
                          "|stream_id:%ui|type:%d|size:%ui|", stream_id, type, size);
        break;
    }
    case XQC_H3_FRM_HEADERS: {
        xqc_http_headers_t *headers = va_arg(args, xqc_http_headers_t*);
        unsigned char *p = log_buf;
        unsigned char *last = log_buf + sizeof(log_buf);
        for (uint32_t i = 0; i < headers->count; ++i) {
            xqc_http_header_t *header = &headers->headers[i];
            if (header->value.iov_len > 0) {
                p = xqc_sprintf(p, last, "{name:%*s} {value:%*s}|", (size_t) header->name.iov_len, header->name.iov_base,
                                (size_t) header->value.iov_len, header->value.iov_base);
            } else {
                p = xqc_sprintf(p, last, "{name:%*s}|", (size_t) header->name.iov_len, header->name.iov_base);
            }
        }
        xqc_log_implement(log, HTTP_FRAME_CREATED, func,
                          "|stream_id:%ui|type:%d|%s", stream_id, type, log_buf);
        break;
    }
    case XQC_H3_FRM_CANCEL_PUSH:
    case XQC_H3_FRM_GOAWAY:
    case XQC_H3_FRM_MAX_PUSH_ID: {
        uint64_t push_id = va_arg(args, uint64_t);
        xqc_log_implement(log, HTTP_FRAME_CREATED, func,
                          "|stream_id:%ui|type:%d|push_id:%ui|", stream_id, type, push_id);
        break;
    }
    case XQC_H3_FRM_SETTINGS: {
        xqc_h3_conn_settings_t *settings = va_arg(args, xqc_h3_conn_settings_t*);
        xqc_log_implement(log, HTTP_FRAME_CREATED, func,
                          "|stream_id:%ui|type:%d|max_field_section_size:%ui|max_pushes:%ui|"
                          "|qpack_max_table_capacity:%ui|qpack_blocked_streams:%ui|",
                          stream_id, type, settings->max_field_section_size, settings->max_pushes,
                          settings->qpack_max_table_capacity, settings->qpack_blocked_streams);
        break;
    }
    case XQC_H3_FRM_PUSH_PROMISE: {
        uint64_t push_id = va_arg(args, uint64_t);
        xqc_http_headers_t *headers = va_arg(args, xqc_http_headers_t*);
        xqc_log_implement(log, HTTP_FRAME_CREATED, func,
                          "|stream_id:%ui|type:%d|push_id:%ui|", stream_id, type, push_id);
        break;
    }
    default:
        break;
    }
    va_end(args);
}

void
xqc_log_HTTP_FRAME_PARSED_callback(xqc_log_t *log, const char *func, xqc_h3_stream_t *h3_stream)
{
    xqc_h3_frame_t *frame = &h3_stream->pctx.frame_pctx.frame;
    xqc_stream_id_t stream_id = h3_stream->stream->stream_id;
    switch (frame->type) {
    case XQC_H3_FRM_DATA:
    case XQC_H3_FRM_HEADERS:
    case XQC_H3_FRM_SETTINGS:
        xqc_log_implement(log, HTTP_FRAME_PARSED, func,
                          "|stream_id:%ui|type:%d|length:%ui|", stream_id, frame->type, frame->len);
        break;
    case XQC_H3_FRM_CANCEL_PUSH: {
        xqc_log_implement(log, HTTP_FRAME_PARSED, func,
                          "|stream_id:%ui|type:%d|length:%ui|push_id:%ui|",
                          stream_id, frame->type, frame->len, frame->frame_payload.cancel_push.push_id.vi);
        break;
    }
    case XQC_H3_FRM_PUSH_PROMISE: {
        xqc_log_implement(log, HTTP_FRAME_PARSED, func,
                          "|stream_id:%ui|type:%d|length:%ui|push_id:%ui|",
                          stream_id, frame->type, frame->len, frame->frame_payload.push_promise.push_id.vi);
        break;
    }
    case XQC_H3_FRM_GOAWAY: {
        xqc_log_implement(log, HTTP_FRAME_PARSED, func,
                          "|stream_id:%ui|type:%d|length:%ui|push_id:%ui|",
                          stream_id, frame->type, frame->len, frame->frame_payload.goaway.stream_id.vi);
        break;
    }
    case XQC_H3_FRM_MAX_PUSH_ID: {
        xqc_log_implement(log, HTTP_FRAME_PARSED, func,
                          "|stream_id:%ui|type:%d|length:%ui|push_id:%ui|",
                          stream_id, frame->type, frame->len, frame->frame_payload.max_push_id.push_id.vi);
        break;
    }
    default:
        break;
    }
}

void
xqc_log_HTTP_SETTING_PARSED_callback(xqc_log_t *log, const char *func, uint64_t identifier, uint64_t value)
{
    xqc_log_implement(log, HTTP_SETTING_PARSED, func, "|id:%ui|value:%d|", identifier, value);
}

void
xqc_log_QPACK_STREAM_STATE_UPDATED_callback(xqc_log_t *log, const char *func, xqc_h3_stream_t *h3_stream)
{
    xqc_log_implement(log, QPACK_STREAM_STATE_UPDATED, func,
                      "|stream_id:%ui|%s|", h3_stream->stream->stream_id,
                      h3_stream->flags & XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED ? "blocked" : "unblocked");
}

void
xqc_log_QPACK_DYNAMIC_TABLE_UPDATED_callback(xqc_log_t *log, const char *func, ...)
{
    va_list args;
    va_start(args, func);
    xqc_int_t type = va_arg(args, xqc_int_t);
    uint64_t index = va_arg(args, uint64_t);
    if (type == XQC_LOG_DTABLE_EVICTED) {
        xqc_log_implement(log, QPACK_DYNAMIC_TABLE_UPDATED, func,
                          "|evicted|index:%ui|", index);

    } else {
        uint64_t nlen = va_arg(args, uint64_t);
        char *name = va_arg(args, char*);
        uint64_t vlen = va_arg(args, uint64_t);
        char *value = va_arg(args, char*);
        xqc_log_implement(log, QPACK_DYNAMIC_TABLE_UPDATED, func,
                          "|inserted|index:%ui|name:%*s|value:%*s|", index, (size_t) nlen, name, (size_t) vlen, value);
    }
    va_end(args);
}

void
xqc_log_QPACK_INSTRUCTION_CREATED_callback(xqc_log_t *log, const char *func, ...)
{
    va_list args;
    va_start(args, func);
    xqc_int_t coder_type = va_arg(args, xqc_int_t);
    if (coder_type == XQC_LOG_ENCODER_EVENT) {
        xqc_ins_enc_type_t type = va_arg(args, xqc_ins_enc_type_t);
        switch (type) {
        case XQC_INS_TYPE_ENC_SET_DTABLE_CAP: {
            uint64_t cap = va_arg(args, uint64_t);
            xqc_log_implement(log, QPACK_INSTRUCTION_CREATED, func,
                              "|set_dynamic_table_capacity|capacity:%ui|", cap);
            break;
        }
        case XQC_INS_TYPE_ENC_INSERT_NAME_REF: {
            xqc_int_t table_type = va_arg(args, xqc_int_t);
            uint64_t name_index = va_arg(args, uint64_t);
            uint64_t value_len = va_arg(args, uint64_t);
            char *value = va_arg(args, char*);
            xqc_log_implement(log, QPACK_INSTRUCTION_CREATED, func,
                              "|insert_with_name_reference|%s|name_index:%ui|value:%*s|",
                              table_type == XQC_DTABLE_FLAG ? "dtable" : "stable", name_index, (size_t) value_len, value);
            break;
        }
        case XQC_INS_TYPE_ENC_INSERT_LITERAL: {
            uint64_t name_len = va_arg(args, uint64_t);
            char *name = va_arg(args, char*);
            uint64_t value_len = va_arg(args, uint64_t);
            char *value = va_arg(args, char*);
            xqc_log_implement(log, QPACK_INSTRUCTION_CREATED, func,
                              "|insert_without_name_reference|name:%*s|value:%*s|",
                              (size_t) name_len, name, (size_t) value_len, value);
            break;
        }
        case XQC_INS_TYPE_ENC_DUP: {
            uint64_t index = va_arg(args, uint64_t);
            xqc_log_implement(log, QPACK_INSTRUCTION_CREATED, func,
                              "|duplicate|index:%ui|", index);
            break;
        }
        default:
            break;
        }

    } else {
        xqc_ins_dec_type_t type = va_arg(args, xqc_ins_dec_type_t);
        switch (type) {
        case XQC_INS_TYPE_DEC_SECTION_ACK: {
            uint64_t stream_id = va_arg(args, uint64_t);
            xqc_log_implement(log, QPACK_INSTRUCTION_CREATED, func,
                              "|header_acknowledgement|stream_id:%ui|", stream_id);
            break;
        }
        case XQC_INS_TYPE_DEC_STREAM_CANCEL: {
            uint64_t stream_id = va_arg(args, uint64_t);
            xqc_log_implement(log, QPACK_INSTRUCTION_CREATED, func,
                              "|stream_cancellation|stream_id:%ui|", stream_id);
            break;
        }
        case XQC_INS_TYPE_DEC_INSERT_CNT_INC: {
            uint64_t increment = va_arg(args, uint64_t);
            xqc_log_implement(log, QPACK_INSTRUCTION_CREATED, func,
                              "|insert_count_increment|increment:%ui|", increment);
            break;
        }
        default:
            break;
        }
    }
    va_end(args);
}

void
xqc_log_QPACK_INSTRUCTION_PARSED_callback(xqc_log_t *log, const char *func, ...)
{
    va_list args;
    va_start(args, func);
    xqc_int_t coder_type = va_arg(args, xqc_int_t);
    if (coder_type == XQC_LOG_ENCODER_EVENT) {
        xqc_ins_enc_ctx_t *ctx = va_arg(args, xqc_ins_enc_ctx_t*);
        switch (ctx->type) {
        case XQC_INS_TYPE_ENC_SET_DTABLE_CAP:
            xqc_log_implement(log, QPACK_INSTRUCTION_PARSED, func,
                              "|set_dynamic_table_capacity|capacity:%ui|", ctx->capacity.value);
            break;
        case XQC_INS_TYPE_ENC_INSERT_NAME_REF:
            xqc_log_implement(log, QPACK_INSTRUCTION_PARSED, func,
                              "|insert_with_name_reference|name_index:%ui|value:%*s|",
                              ctx->name_index.value, (size_t) ctx->value->value->data_len, ctx->value->value->data);
            break;
        case XQC_INS_TYPE_ENC_INSERT_LITERAL:
            xqc_log_implement(log, QPACK_INSTRUCTION_PARSED, func,
                              "|insert_without_name_reference|name:%*s|value:%*s|",
                              (size_t) ctx->name->value->data_len, ctx->name->value->data,
                              (size_t) ctx->value->value->data_len, ctx->value->value->data);
            break;
        case XQC_INS_TYPE_ENC_DUP:
            xqc_log_implement(log, QPACK_INSTRUCTION_PARSED, func,
                              "|duplicate|index:%ui|", ctx->name_index.value);
            break;
        }

    } else {
        xqc_ins_dec_ctx_t *ctx = va_arg(args, xqc_ins_dec_ctx_t*);
        switch (ctx->type) {
        case XQC_INS_TYPE_DEC_SECTION_ACK:
            xqc_log_implement(log, QPACK_INSTRUCTION_PARSED, func,
                              "|header_acknowledgement|stream_id:%ui|", ctx->stream_id.value);
            break;
        case XQC_INS_TYPE_DEC_STREAM_CANCEL:
            xqc_log_implement(log, QPACK_INSTRUCTION_PARSED, func,
                              "|stream_cancellation|stream_id:%ui|", ctx->stream_id.value);
            break;
        case XQC_INS_TYPE_DEC_INSERT_CNT_INC:
            xqc_log_implement(log, QPACK_INSTRUCTION_PARSED, func,
                              "|insert_count_increment|increment:%ui|", ctx->increment.value);
            break;
        }
    }
    va_end(args);
}
