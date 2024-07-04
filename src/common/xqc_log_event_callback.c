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
xqc_log_CON_SERVER_LISTENING_callback(xqc_log_t *log, const char *func, const struct sockaddr *peer_addr, 
    socklen_t peer_addrlen)
{
    struct sockaddr_in *sa_peer = (struct sockaddr_in *)peer_addr;
    if(peer_addr->sa_family ==  AF_INET){
        xqc_qlog_implement(log, CON_SERVER_LISTENING, func,
                          "|ip_v4:%s|port_v4:%d|",
                          xqc_peer_addr_str(log->engine, (struct sockaddr*)sa_peer, peer_addrlen),
                          ntohs(sa_peer->sin_port));
    }
    else{
        xqc_qlog_implement(log, CON_SERVER_LISTENING, func,
                          "|ip_v6:%s|port_v6:%d|",
                          xqc_peer_addr_str(log->engine, (struct sockaddr*)sa_peer, peer_addrlen),
                          ntohs(sa_peer->sin_port));
    }
}

void
xqc_log_CON_CONNECTION_STARTED_callback(xqc_log_t *log, const char *func, xqc_connection_t *conn, xqc_int_t local)
{
    if (local == XQC_LOG_LOCAL_EVENT) {
        struct sockaddr_in *sa_local = (struct sockaddr_in *)conn->local_addr;
        xqc_qlog_implement(log, CON_CONNECTION_STARTED, func,
                          "|local|src_ip:%s|src_port:%d|",
                          xqc_local_addr_str(conn->engine, (struct sockaddr*)sa_local, conn->local_addrlen),
                          ntohs(sa_local->sin_port));

    } else {
        struct sockaddr_in *sa_peer = (struct sockaddr_in *)conn->peer_addr;
        xqc_qlog_implement(log, CON_CONNECTION_STARTED, func,
                          "|remote|dst_ip:%s|dst_port:%d|scid:%s|dcid:%s|",
                          xqc_peer_addr_str(conn->engine, (struct sockaddr*)sa_peer, conn->peer_addrlen),
                          ntohs(sa_peer->sin_port), log->scid, xqc_dcid_str(conn->engine, &conn->dcid_set.current_dcid));
    }
}

void
xqc_log_CON_CONNECTION_CLOSED_callback(xqc_log_t *log, const char *func, xqc_connection_t *conn)
{
    if (conn->conn_err != 0){
        xqc_list_head_t *pos, *next;
        xqc_path_ctx_t *path = NULL;
        unsigned char log_buf[500];
        unsigned char *p = log_buf;
        unsigned char *last = log_buf + sizeof(log_buf);
        xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
            path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
            uint8_t idx = path->path_send_ctl->ctl_cwndlim_update_idx;
            p = xqc_sprintf(p, last, "<path:%ui, (%ui,%ui,%ui)>",
            path->path_id,
            xqc_calc_delay(path->path_send_ctl->ctl_recent_cwnd_limitation_time[idx], conn->conn_create_time) / 1000,
            xqc_calc_delay(path->path_send_ctl->ctl_recent_cwnd_limitation_time[(idx + 1) % 3], conn->conn_create_time) / 1000,
            xqc_calc_delay(path->path_send_ctl->ctl_recent_cwnd_limitation_time[(idx + 2) % 3], conn->conn_create_time) / 1000
            );
            if (p != last) {
                *p = '\0';
            }
        }
        xqc_qlog_implement(log, CON_CONNECTION_CLOSED, func,
                            "|err_code:%d|mtu_updatad_count:%d|pkt_dropped:%d|recent_congestion:%s|", 
                            conn->conn_err, conn->MTU_updated_count, conn->packet_dropped_count, log_buf);
    }
    else{
        xqc_qlog_implement(log, CON_CONNECTION_CLOSED, func,
                            "|err_code:%d|mtu_updatad_count:%d|pkt_dropped:%d|", 
                            conn->conn_err, conn->MTU_updated_count, conn->packet_dropped_count);
    }
}

void
xqc_log_CON_CONNECTION_ID_UPDATED_callback(xqc_log_t *log, const char *func, xqc_connection_t *conn)
{
    unsigned char  scid_str[XQC_MAX_CID_LEN * 2 + 1];
    xqc_hex_dump(scid_str, conn->scid_set.user_scid.cid_buf, conn->scid_set.user_scid.cid_len);
    scid_str[conn->scid_set.user_scid.cid_len * 2] = '\0';
    xqc_qlog_implement(log, CON_CONNECTION_ID_UPDATED, func,
                      "|scid:%s|dcid:%s|", scid_str, conn->dcid_set.current_dcid_str);
}

void
xqc_log_CON_CONNECTION_STATE_UPDATED_callback(xqc_log_t *log, const char *func, xqc_connection_t *conn)
{
    xqc_qlog_implement(log, CON_CONNECTION_STATE_UPDATED, func,
                      "|new:%s|", xqc_conn_state_2_str(conn->conn_state));
}

void 
xqc_log_CON_PATH_ASSIGNED_callback(xqc_log_t *log, const char *func,
    xqc_path_ctx_t *path, xqc_connection_t *conn)
{
    xqc_qlog_implement(log, CON_PATH_ASSIGNED, func,
                      "|path_id:%ui|local_addr:%s|peer_addr:%s|dcid:%s|scid:%s|",
                     path->path_id,  xqc_conn_addr_str(conn), xqc_path_addr_str(path),
                     xqc_dcid_str(log->engine, &path->path_dcid), xqc_scid_str(log->engine, &path->path_scid));
}

void 
xqc_log_CON_MTU_UPDATED_callback(xqc_log_t *log, const char *func, xqc_connection_t *conn, int32_t is_done)
{
    xqc_qlog_implement(log, CON_MTU_UPDATED, func,
                      "|new:%uz|done:%d|max:%uz|", conn->pkt_out_size, is_done, conn->max_pkt_out_size);
}

void
xqc_log_SEC_KEY_UPDATED_callback(xqc_log_t *log, const char *func, xqc_engine_ssl_config_t ssl_config, xqc_int_t local)
{
    if (local == XQC_LOG_LOCAL_EVENT) {
        xqc_qlog_implement(log, SEC_KEY_UPDATED, func,
                          "|local|ciphers:%s|", ssl_config.ciphers);

    } else {
        xqc_qlog_implement(log, SEC_KEY_UPDATED, func,
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

    xqc_qlog_implement(log, TRA_VERSION_INFORMATION, func,
                      "|%s|choose:%d|", log_buf, choose);
}

void
xqc_log_TRA_ALPN_INFORMATION_callback(xqc_log_t *log, const char *func, const unsigned char * server_alpn_list, 
    unsigned int server_alpn_list_len, const unsigned char *client_alpn_list, unsigned int client_alpn_list_len,
    const char *selected_alpn, size_t selected_alpn_len)
{
    unsigned char log_buf[XQC_MAX_LOG_LEN];
    unsigned char *p = log_buf;
    unsigned char *last = log_buf + sizeof(log_buf);
    p = xqc_sprintf(p, last, "client_alpn:");

    uint8_t alpn_len;
    size_t alpn_write_len; 

    for (unsigned i = 0; i < client_alpn_list_len;) {
        alpn_len = client_alpn_list[i];
        alpn_write_len = alpn_len;
        p = xqc_sprintf(p, last, "%*s ", alpn_write_len, &client_alpn_list[i + 1]);
        i += alpn_len;
        i++;
    }
    p = xqc_sprintf(p, last, "|server_alpn:");

    for (unsigned i = 0; i < server_alpn_list_len;) {
        alpn_len = server_alpn_list[i];
        alpn_write_len = alpn_len;
        p = xqc_sprintf(p, last, "%*s ", alpn_write_len, &server_alpn_list[i + 1]);
        i += alpn_len;
        i++;
    }
    xqc_qlog_implement(log, TRA_ALPN_INFORMATION, func,
                      "|%s|selected_alpn:%*s|", log_buf, selected_alpn_len, selected_alpn);
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

    xqc_qlog_implement(log, TRA_PARAMETERS_SET, func,
                      "|%s|migration:%d|max_idle_timeout:%d|max_udp_payload_size:%d|"
                      "active_connection_id_limit:%d|max_data:%d|",
                      local == XQC_LOG_LOCAL_EVENT ? "local" : "remote", setting->disable_active_migration,
                      setting->max_idle_timeout, setting->max_udp_payload_size,
                      setting->active_connection_id_limit, setting->max_data);
}

void
xqc_log_TRA_PACKET_RECEIVED_callback(xqc_log_t *log, const char *func, xqc_packet_in_t *packet_in)
{
    xqc_qlog_implement(log, TRA_PACKET_RECEIVED, func,
                      "|pkt_pns:%d|pkt_type:%s|pkt_num:%ui|len:%uz|frame_flag:%s|path_id:%ui|",
                      packet_in->pi_pkt.pkt_pns, xqc_pkt_type_2_str(packet_in->pi_pkt.pkt_type), packet_in->pi_pkt.pkt_num,
                      packet_in->buf_size, xqc_frame_type_2_str(log->engine, packet_in->pi_frame_types), packet_in->pi_path_id);
}

void
xqc_log_TRA_PACKET_DROPPED_callback(xqc_log_t *log, const char *func, const char *trigger, xqc_int_t ret,
    const char* pi_pkt_type, xqc_packet_number_t pi_pkt_num)
{
    xqc_qlog_implement(log, TRA_PACKET_DROPPED, func,
                    "|trigger:%s|ret:%d|pkt_type:%s|pkt_num:%ui|",
                    trigger, ret, pi_pkt_type, pi_pkt_num);
}

void
xqc_log_TRA_PACKET_SENT_callback(xqc_log_t *log, const char *func, xqc_connection_t *conn,
    xqc_packet_out_t *packet_out, xqc_path_ctx_t *path, xqc_usec_t send_time, ssize_t sent, xqc_bool_t with_pn)
{
    if (with_pn) {
        xqc_qlog_implement(log, TRA_PACKET_SENT, func,
                        "|<==|conn:%p|path_id:%ui|pkt_pns:%d|pkt_type:%s|pkt_num:%ui|size:%d|frame_flag:%s|"
                        "sent:%z|inflight:%ud|now:%ui|stream_id:%ui|stream_offset:%ui|",
                        conn, path->path_id, packet_out->po_pkt.pkt_pns, 
                        xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type), packet_out->po_pkt.pkt_num,
                        packet_out->po_used_size, xqc_frame_type_2_str(log->engine, packet_out->po_frame_types),
                        sent, path->path_send_ctl->ctl_bytes_in_flight, send_time, 
                        packet_out->po_stream_id, packet_out->po_stream_offset);
    } else {
        xqc_qlog_implement(log, TRA_PACKET_SENT, func,
                       "|<==|conn:%p|path_id:%ui|pkt_type:%s|pkt_pns:%d|frame_flag:%s|size:%ud|sent:%z|",
                       conn, path->path_id, xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type), packet_out->po_pkt.pkt_pns, 
                       xqc_frame_type_2_str(log->engine, packet_out->po_frame_types), packet_out->po_used_size, sent);
    }
}

void
xqc_log_TRA_PACKET_BUFFERED_callback(xqc_log_t *log, const char *func, xqc_packet_in_t *packet_in)
{
    xqc_qlog_implement(log, TRA_PACKET_BUFFERED, func,
                      "|pkt_num:%ui|pkt_pns:%d|pkt_type:%d|len:%d|",
                      packet_in->pi_pkt.pkt_num, packet_in->pi_pkt.pkt_pns, packet_in->pi_pkt.pkt_type, packet_in->buf_size);
}

void
xqc_log_TRA_PACKETS_ACKED_callback(xqc_log_t *log, const char *func, xqc_packet_in_t *packet_in,
    xqc_packet_number_t high, xqc_packet_number_t low, uint64_t path_id)
{
    xqc_qlog_implement(log, TRA_PACKETS_ACKED, func,
                      "|pkt_space:%d|high:%d|low:%d|path_id:%ui|",
                      packet_in->pi_pkt.pkt_pns, high, low, path_id);
}

void
xqc_log_TRA_DATAGRAMS_SENT_callback(xqc_log_t *log, const char *func, ssize_t size, uint64_t path_id)
{
    xqc_qlog_implement(log, TRA_DATAGRAMS_SENT, func,
                      "|size:%z|path_id:%ui|", size, path_id);
}

void
xqc_log_TRA_DATAGRAMS_RECEIVED_callback(xqc_log_t *log, const char *func, ssize_t size, uint64_t path_id)
{
    xqc_qlog_implement(log, TRA_DATAGRAMS_RECEIVED, func,
                      "|size:%d|path_id:%ui|", size, path_id);
}

void
xqc_log_TRA_STREAM_STATE_UPDATED_callback(xqc_log_t *log, const char *func, xqc_stream_t *stream,
    xqc_int_t stream_type, xqc_int_t state)
{
    if (stream_type == XQC_LOG_STREAM_SEND) {
        xqc_qlog_implement(log, TRA_STREAM_STATE_UPDATED, func,
                          "|stream_id:%d|send_stream|old:%d|new:%d|",
                          stream->stream_id, stream->stream_state_send, state);
    } else {
        xqc_qlog_implement(log, TRA_STREAM_STATE_UPDATED, func,
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
        xqc_qlog_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|length:%ui|", frame_type, length);
        break;
    }

    case XQC_FRAME_PING:
        xqc_qlog_implement(log, TRA_FRAMES_PROCESSED, func,
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

        xqc_qlog_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|ack_delay:%ui|ack_range:%s|",
                          frame_type, ack_info->ack_delay, buf);
        break;
    }

    case XQC_FRAME_RESET_STREAM: {
        xqc_stream_id_t stream_id = va_arg(args, xqc_stream_id_t);
        uint64_t err_code = va_arg(args, uint64_t);
        uint64_t final_size = va_arg(args, uint64_t);
        xqc_qlog_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|stream_id:%ui|err_code:%ui|final_size:%ui|",
                          frame_type, stream_id, err_code, final_size);
        break;
    }

    case XQC_FRAME_STOP_SENDING: {
        xqc_stream_id_t stream_id = va_arg(args, xqc_stream_id_t);
        uint64_t err_code = va_arg(args, uint64_t);
        xqc_qlog_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|stream_id:%ui|err_code:%ui|", frame_type, stream_id, err_code);
        break;
    }

    case XQC_FRAME_CRYPTO: {
        uint64_t offset = va_arg(args, uint64_t);
        uint64_t length = va_arg(args, uint64_t);
        xqc_qlog_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|offset:%ui|length:%ui|", frame_type, offset, length);
        break;
    }

    case XQC_FRAME_NEW_TOKEN: {
        uint64_t length = va_arg(args, uint64_t);
        unsigned char *token = va_arg(args, unsigned char *);
        xqc_qlog_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|token_length:%ui|token:%s|", frame_type, length, token);
        break;
    }

    case XQC_FRAME_STREAM: {
        xqc_stream_frame_t *frame = va_arg(args, xqc_stream_frame_t*);
        xqc_qlog_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|data_offset:%ui|data_length:%d|fin:%d|",
                          frame_type, frame->data_offset, frame->data_length, frame->fin);
        break;
    }

    case XQC_FRAME_DATAGRAM: {
        uint64_t length = va_arg(args, uint64_t);
        xqc_qlog_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|data_length:%ui|", frame_type, length);
        break;
    }

    case XQC_FRAME_MAX_DATA: {
        uint64_t max_data = va_arg(args, uint64_t);
        xqc_qlog_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|max_data:%ui|", frame_type, max_data);
        break;
    }

    case XQC_FRAME_MAX_STREAM_DATA: {
        xqc_stream_id_t stream_id = va_arg(args, xqc_stream_id_t);
        uint64_t max_stream_data = va_arg(args, uint64_t);
        xqc_qlog_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|stream_id:%ui|max_stream_data:%ui|",
                          frame_type, stream_id, max_stream_data);
        break;
    }
    case XQC_FRAME_MAX_STREAMS: {
        int bidirectional = va_arg(args, int);
        uint64_t max_streams = va_arg(args, uint64_t);
        if (bidirectional) {
            xqc_qlog_implement(log, TRA_FRAMES_PROCESSED, func,
                              "|type:%d|stream_type:bidirectional|maximum:%ui|",
                              frame_type, max_streams);

        } else {
            xqc_qlog_implement(log, TRA_FRAMES_PROCESSED, func,
                              "|type:%d|stream_type:unidirectional|maximum:%ui|",
                              frame_type, max_streams);
        }
        break;
    }

    case XQC_FRAME_DATA_BLOCKED: {
        uint64_t data_limit = va_arg(args, uint64_t);
        xqc_qlog_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|bidirectional|limit:%ui|",
                          frame_type, data_limit);
        break;
    }

    case XQC_FRAME_STREAM_DATA_BLOCKED: {
        xqc_stream_id_t stream_id = va_arg(args, xqc_stream_id_t);
        uint64_t stream_data_limit = va_arg(args, uint64_t);
        xqc_qlog_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|bidirectional|stream_id:%ui|limit:%ui|",
                          frame_type, stream_id, stream_data_limit);
        break;
    }

    case XQC_FRAME_STREAMS_BLOCKED: {
        int bidirectional = va_arg(args, int);
        uint64_t stream_limit = va_arg(args, uint64_t);
        if (bidirectional) {
            xqc_qlog_implement(log, TRA_FRAMES_PROCESSED, func,
                              "|type:%d|stream_type:bidirectional|limit:%ui|",
                              frame_type, stream_limit);

        } else {
            xqc_qlog_implement(log, TRA_FRAMES_PROCESSED, func,
                              "|type:%d|stream_type:unidirectional|limit:%ui|",
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
        xqc_qlog_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|sequence_number:%ui|retire_prior_to:%ui|connection_id_length:%d|connection_id:%s|",
                          frame_type, new_cid->cid_seq_num, retire_prior_to, new_cid->cid_len, scid_str);
        break;
    }

    case XQC_FRAME_CONNECTION_CLOSE: {
        uint64_t err_code = va_arg(args, uint64_t);
        xqc_qlog_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|err_code:%ui|", frame_type, err_code);
        break;
    }

    case XQC_FRAME_HANDSHAKE_DONE:
        xqc_qlog_implement(log, TRA_FRAMES_PROCESSED, func,
                          "|type:%d|", frame_type);
        break;

    /* TODO: add log */
    case XQC_FRAME_RETIRE_CONNECTION_ID:
    case XQC_FRAME_PATH_CHALLENGE:
    case XQC_FRAME_PATH_RESPONSE:
    case XQC_FRAME_ACK_MP:
    case XQC_FRAME_PATH_ABANDON:
    case XQC_FRAME_PATH_STATUS:
    case XQC_FRAME_Extension:
        break;

    default:
        break;
    }
    va_end(args);
}


void 
xqc_log_TRA_STREAM_DATA_MOVED_callback(xqc_log_t *log, const char *func, xqc_stream_t *stream,
                                        xqc_bool_t is_recv, size_t read_or_write_size, size_t recv_buf_size,
                                        uint8_t fin, int ret, int pkt_type, int buff_1rtt, size_t offset)
{
    if (is_recv) {
        xqc_qlog_implement(log, TRA_STREAM_DATA_MOVED, func,
                          "|stream_id:%ui|read:%uz|recv_buf_size:%uz|fin:%d|stream_length:%ui|next_read_offset:%ui|conn:%p"
                          "|from:transport|to:application|",
                          stream->stream_id, read_or_write_size, recv_buf_size, fin,
                          stream->stream_data_in.stream_length, stream->stream_data_in.next_read_offset,
                          stream->stream_conn);
    }
    else{
        xqc_connection_t *conn = stream->stream_conn;
        xqc_qlog_implement(log, TRA_STREAM_DATA_MOVED, func,
                          "|ret:%d|stream_id:%ui|stream_send_offset:%ui|pkt_type:%s|buff_1rtt:%d"
                          "|send_data_size:%uz|offset:%uz|fin:%d|stream_flag:%d|conn:%p|conn_state:%s|flag:%s"
                          "|from:application|to:transport|",
                          ret, stream->stream_id, stream->stream_send_offset, xqc_pkt_type_2_str(pkt_type),
                          buff_1rtt, read_or_write_size, offset, fin, stream->stream_flag, conn,
                          xqc_conn_state_2_str(conn->conn_state), xqc_conn_flag_2_str(conn, conn->conn_flag));
    }
}

void 
xqc_log_TRA_DATAGRAM_DATA_MOVED_callback(xqc_log_t *log, const char *func, xqc_stream_t *stream,
                                        size_t moved_data_len, const char *from, const char *to)
{
    xqc_qlog_implement(log, TRA_STREAM_DATA_MOVED, func,
                          "|stream_id:%ui|length:%uz|from:%s|to:%s|",
                          stream->stream_id, moved_data_len, from, to);
}

void
xqc_log_TRA_STATELESS_RESET_callback(xqc_log_t *log, const char *func, xqc_connection_t *conn)
{
    xqc_qlog_implement(log, TRA_STATELESS_RESET, func, "|stateless reset|cid:%s|",
                      log->scid);
}

void
xqc_log_REC_PARAMETERS_SET_callback(xqc_log_t *log, const char *func, xqc_send_ctl_t *send_ctl, uint8_t timer_granularity,
                                    xqc_cc_params_t cc_params)
{
    xqc_qlog_implement(log, REC_PARAMETERS_SET, func,
                      "|reordering_threshold:%ui|time_threshold:%d|timer_granularity:%d|initial_rtt:%ui|"
                      "initial_congestion_window:%d|minimum_congestion_window:%d|",
                      send_ctl->ctl_reordering_packet_threshold, send_ctl->ctl_reordering_time_threshold_shift, timer_granularity, send_ctl->ctl_srtt / 1000,
                      cc_params.init_cwnd, cc_params.min_cwnd);
}

void
xqc_log_REC_METRICS_UPDATED_callback(xqc_log_t *log, const char *func, xqc_send_ctl_t *send_ctl)
{
    uint64_t cwnd = send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(send_ctl->ctl_cong);
    int64_t bw = 0;
    uint64_t pacing_rate = 0;
    int mode = 0;
    xqc_usec_t min_rtt = 0;

    if (send_ctl->ctl_cong_callback->xqc_cong_ctl_init_bbr) {
        bw = send_ctl->ctl_cong_callback->
                xqc_cong_ctl_get_bandwidth_estimate(send_ctl->ctl_cong);
        pacing_rate = send_ctl->ctl_cong_callback->
                xqc_cong_ctl_get_pacing_rate(send_ctl->ctl_cong);
        mode = send_ctl->ctl_cong_callback->xqc_cong_ctl_info_cb->mode(send_ctl->ctl_cong);
        min_rtt = send_ctl->ctl_cong_callback-> xqc_cong_ctl_info_cb->min_rtt(send_ctl->ctl_cong);
        xqc_qlog_implement(log, REC_METRICS_UPDATED, func,
                          "|cwnd:%ui|inflight:%ud|mode:%ud|applimit:%ud|pacing_rate:%ui|bw:%ui|srtt:%ui|"
                          "latest_rtt:%ui|ctl_rttvar:%ui|pto_count:%ud|min_rtt:%ui|send:%ud|lost:%ud|tlp:%ud|recv:%ud|",
                          cwnd, send_ctl->ctl_bytes_in_flight, mode, send_ctl->ctl_app_limited, pacing_rate, bw, send_ctl->ctl_srtt,
                          send_ctl->ctl_latest_rtt, send_ctl->ctl_pto_count, min_rtt, send_ctl->ctl_send_count, send_ctl->ctl_lost_count,
                          send_ctl->ctl_tlp_count, send_ctl->ctl_recv_count);

    } else {
        xqc_qlog_implement(log, REC_METRICS_UPDATED, func,
                          "|cwnd:%ui|inflight:%ud|applimit:%ud|srtt:%ui|latest_rtt:%ui|pto_count:%ud|"
                          "send:%ud|lost:%ud|tlp:%ud|recv:%ud|",
                          cwnd, send_ctl->ctl_bytes_in_flight, send_ctl->ctl_app_limited, send_ctl->ctl_srtt, send_ctl->ctl_latest_rtt, send_ctl->ctl_pto_count,
                          send_ctl->ctl_send_count, send_ctl->ctl_lost_count, send_ctl->ctl_tlp_count, send_ctl->ctl_recv_count);
    }
}

void
xqc_log_REC_CONGESTION_STATE_UPDATED_callback(xqc_log_t *log, const char *func, char *new_state)
{
    xqc_qlog_implement(log, REC_CONGESTION_STATE_UPDATED, func,
                      "|new_state:%s|", new_state);
}

void
xqc_log_REC_LOSS_TIMER_UPDATED_callback(xqc_log_t *log, const char *func,
    xqc_timer_manager_t *timer_manager, xqc_usec_t inter_time, xqc_int_t type, xqc_int_t event)
{
    if (type != XQC_TIMER_LOSS_DETECTION){
        return ;
    }
    if (event == XQC_LOG_TIMER_SET) {
        xqc_qlog_implement(log, REC_LOSS_TIMER_UPDATED, func,
                          "|event_type:set|type:%s|expire:%ui|interv:%ui|",
                          xqc_timer_type_2_str(type), timer_manager->timer[type].expire_time, inter_time);

    } else if (event == XQC_LOG_TIMER_EXPIRE) {
        xqc_qlog_implement(log, REC_LOSS_TIMER_UPDATED, func,
                          "|event_type:expired|type:%s|expire_time:%ui|",
                          xqc_timer_type_2_str(type), timer_manager->timer[type].expire_time);

    } else if (event == XQC_LOG_TIMER_CANCEL) {
        xqc_qlog_implement(log, REC_LOSS_TIMER_UPDATED, func,
                          "|event_type:cancel|type:%s|", xqc_timer_type_2_str(type));
    }
}

void
xqc_log_REC_PACKET_LOST_callback(xqc_log_t *log, const char *func, xqc_packet_out_t *packet_out, 
                                xqc_packet_number_t lost_pn, xqc_usec_t lost_send_time, xqc_usec_t loss_delay)
{
    xqc_qlog_implement(log, REC_PACKET_LOST, func,
                      "|pkt_pns:%d|pkt_type:%d|pkt_num:%d|lost_pn:%ui|po_sent_time:%ui|"
                      "lost_send_time:%ui|loss_delay:%ui|frame:%s|repair:%d|path_id:%ui|",
                      packet_out->po_pkt.pkt_pns, packet_out->po_pkt.pkt_type, packet_out->po_pkt.pkt_num,
                      lost_pn, packet_out->po_sent_time, lost_send_time, loss_delay,
                      xqc_frame_type_2_str(log->engine, packet_out->po_frame_types), XQC_NEED_REPAIR(packet_out->po_frame_types),
                      packet_out->po_path_id);
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
    xqc_qlog_implement(log, HTTP_PARAMETERS_SET, func,
                      "|owner:%s|max_field_section_size:%ui|qpack_max_table_capacity:%ui|qpack_blocked_streams:%ui|",
                      local == XQC_LOG_LOCAL_EVENT ? "local" : "remote", setting->max_field_section_size,
                      setting->qpack_dec_max_table_capacity, setting->qpack_blocked_streams);
}

void
xqc_log_HTTP_PARAMETERS_RESTORED_callback(xqc_log_t *log, const char *func, xqc_h3_conn_t *h3_conn)
{
    xqc_h3_conn_settings_t *setting = &h3_conn->local_h3_conn_settings;
    xqc_qlog_implement(log, HTTP_PARAMETERS_RESTORED, func,
                      "|max_field_section_size:%ui|qpack_max_table_capacity:%ui|qpack_blocked_streams:%ui|",
                      setting->max_field_section_size,
                      setting->qpack_dec_max_table_capacity, setting->qpack_blocked_streams);
}

void
xqc_log_HTTP_STREAM_TYPE_SET_callback(xqc_log_t *log, const char *func, xqc_h3_stream_t *h3_stream, xqc_int_t local)
{
    xqc_qlog_implement(log, HTTP_STREAM_TYPE_SET, func,
                      "|%s|stream_id:%ui|stream_type:%d|",
                      local == XQC_LOG_LOCAL_EVENT ? "local" : "remote", h3_stream->stream_id, h3_stream->type);
}

void
xqc_log_HTTP_FRAME_CREATED_callback(xqc_log_t *log, const char *func, ...)
{
    unsigned char log_buf[XQC_MAX_LOG_LEN];
    va_list args;
    va_start(args, func);
    xqc_h3_stream_t *h3_stream = va_arg(args, xqc_h3_stream_t*);
    xqc_stream_id_t stream_id = h3_stream->stream_id;
    xqc_h3_frm_type_t type = va_arg(args, xqc_h3_frm_type_t);
    switch (type) {
    case XQC_H3_FRM_DATA: {
        uint64_t size = va_arg(args, uint64_t);
        xqc_qlog_implement(log, HTTP_FRAME_CREATED, func,
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
        xqc_qlog_implement(log, HTTP_FRAME_CREATED, func,
                          "|stream_id:%ui|type:%d|%s", stream_id, type, log_buf);
        break;
    }
    case XQC_H3_FRM_CANCEL_PUSH:
    case XQC_H3_FRM_GOAWAY:
    case XQC_H3_FRM_MAX_PUSH_ID: {
        uint64_t push_id = va_arg(args, uint64_t);
        xqc_qlog_implement(log, HTTP_FRAME_CREATED, func,
                          "|stream_id:%ui|type:%d|push_id:%ui|", stream_id, type, push_id);
        break;
    }
    case XQC_H3_FRM_SETTINGS: {
        xqc_h3_conn_settings_t *settings = va_arg(args, xqc_h3_conn_settings_t*);
        xqc_qlog_implement(log, HTTP_FRAME_CREATED, func,
                          "|stream_id:%ui|type:%d|max_field_section_size:%ui|max_pushes:%ui|"
                          "|qpack_max_table_capacity:%ui|qpack_blocked_streams:%ui|",
                          stream_id, type, settings->max_field_section_size, settings->max_pushes,
                          settings->qpack_dec_max_table_capacity, settings->qpack_blocked_streams);
        break;
    }
    case XQC_H3_FRM_PUSH_PROMISE: {
        uint64_t push_id = va_arg(args, uint64_t);
        xqc_http_headers_t *headers = va_arg(args, xqc_http_headers_t*);
        xqc_qlog_implement(log, HTTP_FRAME_CREATED, func,
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
    xqc_stream_id_t stream_id = h3_stream->stream_id;
    switch (frame->type) {
    case XQC_H3_FRM_DATA:
    case XQC_H3_FRM_HEADERS:
    case XQC_H3_FRM_SETTINGS:
        xqc_qlog_implement(log, HTTP_FRAME_PARSED, func,
                          "|stream_id:%ui|type:%d|length:%ui|", stream_id, frame->type, frame->len);
        break;
    case XQC_H3_FRM_CANCEL_PUSH: {
        xqc_qlog_implement(log, HTTP_FRAME_PARSED, func,
                          "|stream_id:%ui|type:%d|length:%ui|push_id:%ui|",
                          stream_id, frame->type, frame->len, frame->frame_payload.cancel_push.push_id.vi);
        break;
    }
    case XQC_H3_FRM_PUSH_PROMISE: {
        xqc_qlog_implement(log, HTTP_FRAME_PARSED, func,
                          "|stream_id:%ui|type:%d|length:%ui|push_id:%ui|",
                          stream_id, frame->type, frame->len, frame->frame_payload.push_promise.push_id.vi);
        break;
    }
    case XQC_H3_FRM_GOAWAY: {
        xqc_qlog_implement(log, HTTP_FRAME_PARSED, func,
                          "|stream_id:%ui|type:%d|length:%ui|push_id:%ui|",
                          stream_id, frame->type, frame->len, frame->frame_payload.goaway.stream_id.vi);
        break;
    }
    case XQC_H3_FRM_MAX_PUSH_ID: {
        xqc_qlog_implement(log, HTTP_FRAME_PARSED, func,
                          "|stream_id:%ui|type:%d|length:%ui|push_id:%ui|",
                          stream_id, frame->type, frame->len, frame->frame_payload.max_push_id.push_id.vi);
        break;
    }
    default:
        break;
    }
}

void
xqc_log_HTTP_PRIORITY_UPDATED_callback(xqc_log_t *log, const char *func, xqc_h3_priority_t *prio, xqc_h3_stream_t *h3s)
{
    xqc_qlog_implement(log, HTTP_PRIORITY_UPDATED, func, "|urgency:%ui|incremental:%ui|schedule:%ui|reinject:%ui|"
            "stream_id:%ui|conn:%p|",
            prio->urgency, prio->incremental, prio->schedule, prio->reinject,
            h3s->stream_id, h3s->h3c->conn);
}

void
xqc_log_QPACK_STREAM_STATE_UPDATED_callback(xqc_log_t *log, const char *func, xqc_h3_stream_t *h3_stream)
{
    xqc_qlog_implement(log, QPACK_STREAM_STATE_UPDATED, func,
                      "|stream_id:%ui|%s|", h3_stream->stream_id,
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
        xqc_qlog_implement(log, QPACK_DYNAMIC_TABLE_UPDATED, func,
                          "|evicted|index:%ui|", index);

    } else {
        uint64_t nlen = va_arg(args, uint64_t);
        char *name = va_arg(args, char *);
        uint64_t vlen = va_arg(args, uint64_t);
        char *value = va_arg(args, char *);
        xqc_qlog_implement(log, QPACK_DYNAMIC_TABLE_UPDATED, func,
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
            xqc_qlog_implement(log, QPACK_INSTRUCTION_CREATED, func,
                              "|set_dynamic_table_capacity|capacity:%ui|", cap);
            break;
        }
        case XQC_INS_TYPE_ENC_INSERT_NAME_REF: {
            xqc_flag_t  table_type  = va_arg(args, xqc_flag_t);
            uint64_t    name_index  = va_arg(args, uint64_t);
            size_t      value_len   = va_arg(args, size_t);
            char       *value       = va_arg(args, char *);
            xqc_qlog_implement(log, QPACK_INSTRUCTION_CREATED, func,
                              "|insert_with_name_reference|%s|name_index:%ui|value:%*s|",
                              table_type == XQC_DTABLE_FLAG ? "dtable" : "stable",
                              name_index, (size_t) value_len, value);
            break;
        }
        case XQC_INS_TYPE_ENC_INSERT_LITERAL: {
            size_t  name_len    = va_arg(args, size_t);
            char   *name        = va_arg(args, char *);
            size_t  value_len   = va_arg(args, size_t);
            char   *value       = va_arg(args, char *);
            xqc_qlog_implement(log, QPACK_INSTRUCTION_CREATED, func,
                              "|insert_without_name_reference|name:%*s|value:%*s|",
                              (size_t) name_len, name, (size_t) value_len, value);
            break;
        }
        case XQC_INS_TYPE_ENC_DUP: {
            uint64_t index = va_arg(args, uint64_t);
            xqc_qlog_implement(log, QPACK_INSTRUCTION_CREATED, func,
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
            xqc_qlog_implement(log, QPACK_INSTRUCTION_CREATED, func,
                              "|header_acknowledgement|stream_id:%ui|", stream_id);
            break;
        }
        case XQC_INS_TYPE_DEC_STREAM_CANCEL: {
            uint64_t stream_id = va_arg(args, uint64_t);
            xqc_qlog_implement(log, QPACK_INSTRUCTION_CREATED, func,
                              "|stream_cancellation|stream_id:%ui|", stream_id);
            break;
        }
        case XQC_INS_TYPE_DEC_INSERT_CNT_INC: {
            uint64_t increment = va_arg(args, uint64_t);
            xqc_qlog_implement(log, QPACK_INSTRUCTION_CREATED, func,
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
            xqc_qlog_implement(log, QPACK_INSTRUCTION_PARSED, func,
                              "|set_dynamic_table_capacity|capacity:%ui|", ctx->capacity.value);
            break;
        case XQC_INS_TYPE_ENC_INSERT_NAME_REF:
            xqc_qlog_implement(log, QPACK_INSTRUCTION_PARSED, func,
                              "|insert_with_name_reference|name_index:%ui|value:%*s|",
                              ctx->name_index.value, (size_t) ctx->value->value->data_len, ctx->value->value->data);
            break;
        case XQC_INS_TYPE_ENC_INSERT_LITERAL:
            xqc_qlog_implement(log, QPACK_INSTRUCTION_PARSED, func,
                              "|insert_without_name_reference|name:%*s|value:%*s|",
                              (size_t) ctx->name->value->data_len, ctx->name->value->data,
                              (size_t) ctx->value->value->data_len, ctx->value->value->data);
            break;
        case XQC_INS_TYPE_ENC_DUP:
            xqc_qlog_implement(log, QPACK_INSTRUCTION_PARSED, func,
                              "|duplicate|index:%ui|", ctx->name_index.value);
            break;
        }

    } else {
        xqc_ins_dec_ctx_t *ctx = va_arg(args, xqc_ins_dec_ctx_t*);
        switch (ctx->type) {
        case XQC_INS_TYPE_DEC_SECTION_ACK:
            xqc_qlog_implement(log, QPACK_INSTRUCTION_PARSED, func,
                              "|header_acknowledgement|stream_id:%ui|", ctx->stream_id.value);
            break;
        case XQC_INS_TYPE_DEC_STREAM_CANCEL:
            xqc_qlog_implement(log, QPACK_INSTRUCTION_PARSED, func,
                              "|stream_cancellation|stream_id:%ui|", ctx->stream_id.value);
            break;
        case XQC_INS_TYPE_DEC_INSERT_CNT_INC:
            xqc_qlog_implement(log, QPACK_INSTRUCTION_PARSED, func,
                              "|insert_count_increment|increment:%ui|", ctx->increment.value);
            break;
        }
    }
    va_end(args);
}
