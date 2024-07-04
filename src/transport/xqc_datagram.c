/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/transport/xqc_datagram.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_packet_parser.h"
#include "src/common/xqc_log.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_utils.h"
#include "src/transport/xqc_engine.h"


xqc_datagram_0rtt_buffer_t* 
xqc_datagram_create_0rtt_buffer(void *data, size_t data_len, 
    uint64_t dgram_id, xqc_data_qos_level_t qos_level)
{
    xqc_datagram_0rtt_buffer_t *buffer = xqc_malloc(sizeof(xqc_datagram_0rtt_buffer_t));
    if (buffer == NULL) {
        return NULL;
    }

    buffer->iov.iov_base = NULL;

    if (data_len > 0) {
        buffer->iov.iov_base = xqc_malloc(data_len);
        if (buffer->iov.iov_base == NULL) {
            xqc_free(buffer);
            return NULL;
        }
        xqc_memcpy(buffer->iov.iov_base, data, data_len);
    }

    buffer->iov.iov_len = data_len;
    buffer->dgram_id = dgram_id;
    buffer->qos_level = qos_level;
    xqc_init_list_head(&buffer->list);
    return buffer;
}

void 
xqc_datagram_destroy_0rtt_buffer(xqc_datagram_0rtt_buffer_t* buffer)
{
    if (buffer) {
        if (buffer->iov.iov_base) {
            xqc_free(buffer->iov.iov_base);
        }
        xqc_free(buffer);
    }
}

void 
xqc_datagram_record_mss(xqc_connection_t *conn)
{
    size_t udp_payload_limit = 0, dgram_frame_limit = 0, mtu_limit = 0;
    size_t quic_header_size, headroom;
    size_t old_mss = conn->dgram_mss;

    if (conn->conn_flag & XQC_CONN_FLAG_CAN_SEND_1RTT) {
        quic_header_size = xqc_short_packet_header_size(conn->dcid_set.current_dcid.cid_len, XQC_PKTNO_BITS);

    } else {
        if (conn->conn_type == XQC_CONN_TYPE_CLIENT) {
            quic_header_size = xqc_long_packet_header_size(conn->dcid_set.current_dcid.cid_len, conn->scid_set.user_scid.cid_len, 0, XQC_PKTNO_BITS, XQC_PTYPE_0RTT);

        } else {
            conn->dgram_mss = 0;
            goto end;
        }
    }

    headroom = XQC_ACK_SPACE + XQC_TLS_AEAD_OVERHEAD_MAX_LEN + quic_header_size + XQC_DATAGRAM_HEADER_BYTES;
    
    if (conn->conn_settings.fec_params.fec_encoder_scheme) {
        headroom += XQC_FEC_SPACE;
    }

    if (conn->remote_settings.max_udp_payload_size >= headroom) {
        udp_payload_limit = conn->remote_settings.max_udp_payload_size - headroom;

    } else {
        udp_payload_limit = 0;
    }

    headroom = quic_header_size + XQC_DATAGRAM_HEADER_BYTES;
    if (conn->conn_settings.fec_params.fec_encoder_scheme) {
        headroom += XQC_FEC_SPACE;
    }
    if (conn->pkt_out_size >= headroom) {
        mtu_limit = conn->pkt_out_size - headroom;

    } else {
        mtu_limit = 0;
    }

    dgram_frame_limit = conn->remote_settings.max_datagram_frame_size >= XQC_DATAGRAM_HEADER_BYTES ?
                        conn->remote_settings.max_datagram_frame_size - XQC_DATAGRAM_HEADER_BYTES : 
                        0;
    
    conn->dgram_mss = xqc_min(xqc_min(dgram_frame_limit, udp_payload_limit), mtu_limit);
end:
    if (conn->dgram_mss > old_mss) {
        conn->conn_flag |= XQC_CONN_FLAG_DGRAM_MSS_NOTIFY;

    } else {
        if ((conn->conn_flag & XQC_CONN_FLAG_CAN_SEND_1RTT)
            && (conn->dgram_mss == 0)
            && ~(conn->conn_flag & XQC_CONN_FLAG_NO_DGRAM_NOTIFIED)) 
        {
            conn->conn_flag |= XQC_CONN_FLAG_DGRAM_MSS_NOTIFY;
            conn->conn_flag |= XQC_CONN_FLAG_NO_DGRAM_NOTIFIED;
        }
    }

    if ((conn->conn_flag & XQC_CONN_FLAG_DGRAM_MSS_NOTIFY) 
        && conn->app_proto_cbs.dgram_cbs.datagram_mss_updated_notify
        && (conn->conn_flag & XQC_CONN_FLAG_UPPER_CONN_EXIST)
        && conn->dgram_data) 
    {
        conn->conn_flag &= ~XQC_CONN_FLAG_DGRAM_MSS_NOTIFY;
        conn->app_proto_cbs.dgram_cbs.datagram_mss_updated_notify(conn, conn->dgram_mss, conn->dgram_data);
    }
}


/*
 * @brief the API to get the max length of the data that can be sent 
 *        via a single call of xqc_datagram_send
 * 
 * @param conn the connection handle 
 * @return 0 = the peer does not support datagram, >0 = the max length
 */
size_t 
xqc_datagram_get_mss(xqc_connection_t *conn)
{
    return conn->dgram_mss;
}

/*
 * @brief the API to send a datagram over the QUIC connection
 * 
 * @param conn the connection handle 
 * @param data the data to be sent
 * @param data_len the length of the data
 * @param *dgram_id the pointer to return the id the datagram
 * @return <0 = error (-XQC_EAGAIN, -XQC_CLOSING, -XQC_EDGRAM_TOO_LARGE, ...), 
 *         0 success
 */
xqc_int_t xqc_datagram_send(xqc_connection_t *conn, void *data, 
	size_t data_len, uint64_t *dgram_id, xqc_data_qos_level_t qos_level)
{
    if (conn == NULL) {
        return -XQC_EPARAM;
    }

    if (data == NULL && data_len != 0) {
        return -XQC_EPARAM;
    }

    if (conn->conn_state >= XQC_CONN_STATE_CLOSING) {
        xqc_conn_log(conn, XQC_LOG_INFO, "|conn closing, cannot send datagram|size:%ud|", data_len);
        return -XQC_CLOSING;
    }

    if (conn->remote_settings.max_datagram_frame_size == 0) {
        if (conn->conn_flag & XQC_CONN_FLAG_CAN_SEND_1RTT) {
            xqc_conn_log(conn, XQC_LOG_INFO, "|does not support datagram|size:%ud|", data_len);
            return -XQC_EDGRAM_NOT_SUPPORTED;
        } else {
            /*may receive max_datagram_frame_size later */
            xqc_log(conn->log, XQC_LOG_DEBUG, "|waiting_for_max_datagram_frame_size_from_peer|");
            conn->conn_flag |= XQC_CONN_FLAG_DGRAM_WAIT_FOR_1RTT;
            return -XQC_EAGAIN;
        }
    }

    if (conn->dgram_mss < data_len) {
        xqc_log(conn->log, XQC_LOG_INFO, "|datagram_is_too_large|data_len:%ud|",
                data_len);
        return -XQC_EDGRAM_TOO_LARGE;
    }

    /* max_datagram_frame_size > 0 */

    int ret;
    xqc_pkt_type_t pkt_type = XQC_PTYPE_SHORT_HEADER;
    int support_0rtt = xqc_conn_is_ready_to_send_early_data(conn);
    uint64_t dg_id;

    if (!(conn->conn_flag & XQC_CONN_FLAG_CAN_SEND_1RTT)) {
        if ((conn->conn_type == XQC_CONN_TYPE_CLIENT) 
            && (conn->conn_state == XQC_CONN_STATE_CLIENT_INITIAL_SENT) 
            && support_0rtt)
        {
            pkt_type = XQC_PTYPE_0RTT;
            conn->conn_flag |= XQC_CONN_FLAG_HAS_0RTT;

        } else {
            xqc_log(conn->log, XQC_LOG_DEBUG, "|does_not_support_0rtt_when_sending_datagram|");
            conn->conn_flag |= XQC_CONN_FLAG_DGRAM_WAIT_FOR_1RTT;
            return -XQC_EAGAIN;
        }
    }

    if (!xqc_send_queue_can_write(conn->conn_send_queue)) {
        conn->conn_send_queue->sndq_full = XQC_TRUE;
        xqc_log(conn->log, XQC_LOG_DEBUG, "|too many packets used|ctl_packets_used:%ud|", conn->conn_send_queue->sndq_packets_used);
        return -XQC_EAGAIN;
    }

    if (pkt_type == XQC_PTYPE_0RTT && conn->zero_rtt_count >= XQC_PACKET_0RTT_MAX_COUNT) {
        conn->conn_flag |= XQC_CONN_FLAG_DGRAM_WAIT_FOR_1RTT;
        xqc_log(conn->log, XQC_LOG_DEBUG, "|too many 0rtt packets|zero_rtt_count:%ud|", conn->zero_rtt_count);
        return -XQC_EAGAIN;
    }

    xqc_conn_check_app_limit(conn);

    ret = xqc_write_datagram_frame_to_packet(conn, pkt_type, data, data_len, &dg_id, XQC_FALSE, qos_level);

    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|write_datagram_frame_to_packet_error|");
        XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
        return ret;
    }

    /* 0RTT failure requires fallback to 1RTT, save the original send data */
    if (pkt_type == XQC_PTYPE_0RTT) {
        /* buffer 0RTT packet */
        ret = xqc_conn_buff_0rtt_datagram(conn, data, data_len, dg_id, qos_level);
        if (ret < 0) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|unable_to_buffer_0rtt_datagram_data_error|");
            XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
            return ret;
        }
    }

    if (dgram_id) {
        *dgram_id = dg_id;
    }

    if (!(conn->conn_flag & XQC_CONN_FLAG_TICKING)) {
        if (0 == xqc_conns_pq_push(conn->engine->conns_active_pq, conn, conn->last_ticked_time)) {
            conn->conn_flag |= XQC_CONN_FLAG_TICKING;
        }
    }

    if (conn->conn_settings.datagram_redundant_probe
        && conn->dgram_probe_timer >= 0
        && qos_level <= XQC_DATA_QOS_NORMAL
        && conn->last_dgram
        && data_len <= conn->last_dgram->buf_len)
    {
        xqc_var_buf_clear(conn->last_dgram);
        xqc_var_buf_save_data(conn->last_dgram, data, data_len);
        xqc_conn_gp_timer_set(conn, conn->dgram_probe_timer, xqc_monotonic_timestamp() + conn->conn_settings.datagram_redundant_probe);
        xqc_log(conn->log, XQC_LOG_DEBUG, "|start_dgram_probe_timer|data_len:%z|", data_len);
    }

    /* call main logic to send packets out */
    xqc_engine_main_logic_internal(conn->engine);

    return XQC_OK;
}

/*
 * @brief the API to send a datagram over the QUIC connection
 * 
 * @param conn the connection handle 
 * @param iov multiple data buffers need to be sent 
 * @param *dgram_id the pointer to return the list of dgram_id 
 * @param iov_size the size of iov list 
 * @param *sent_cnt the number of successfully sent datagrams
 * @param *sent_bytes the total bytes of successfully sent datagrams
 * @return <0 = error (-XQC_EAGAIN, -XQC_CLOSING, -XQC_EDGRAM_NOT_SUPPORTED, -XQC_EDGRAM_TOO_LARGE, ...), 
 *         0 success
 */
xqc_int_t 
xqc_datagram_send_multiple(xqc_connection_t *conn, 
    struct iovec *iov, uint64_t *dgram_id_list, size_t iov_size, 
    size_t *sent_cnt, size_t *sent_bytes, xqc_data_qos_level_t qos_level)
{
    return xqc_datagram_send_multiple_internal(conn, iov, dgram_id_list, iov_size, sent_cnt, sent_bytes, qos_level, XQC_FALSE);
}

xqc_int_t 
xqc_datagram_send_multiple_internal(xqc_connection_t *conn, 
    struct iovec *iov, uint64_t *dgram_id_list, size_t iov_size, 
    size_t *sent_cnt, size_t *sent_bytes, xqc_data_qos_level_t qos_level, 
    xqc_bool_t use_supplied_dgram_id)
{
    if (sent_cnt) {
        *sent_cnt = 0;
    }

    if (sent_bytes) {
        *sent_bytes = 0;
    }

    if (conn == NULL || iov == NULL || iov_size == 0 || sent_cnt == NULL || sent_bytes == NULL) {
        return -XQC_EPARAM;
    }

    if (use_supplied_dgram_id && dgram_id_list == NULL) {
        return -XQC_EPARAM;
    }

    if (conn->conn_state >= XQC_CONN_STATE_CLOSING) {
        xqc_conn_log(conn, XQC_LOG_INFO, "|conn closing, cannot send datagram|");
        return -XQC_CLOSING;
    }

    if (conn->remote_settings.max_datagram_frame_size == 0) {
        if (conn->conn_flag & XQC_CONN_FLAG_CAN_SEND_1RTT) {
            xqc_conn_log(conn, XQC_LOG_INFO, "|does not support datagram|");
            return -XQC_EDGRAM_NOT_SUPPORTED;
        } else {
            /*may receive max_datagram_frame_size later */
            conn->conn_flag |= XQC_CONN_FLAG_DGRAM_WAIT_FOR_1RTT;
            xqc_log(conn->log, XQC_LOG_DEBUG, "|waiting_for_max_datagram_frame_size_from_peer|");
            return -XQC_EAGAIN;
        }
    }

    int ret = XQC_OK;
    xqc_pkt_type_t pkt_type = XQC_PTYPE_SHORT_HEADER;
    int support_0rtt = xqc_conn_is_ready_to_send_early_data(conn);

    if (!(conn->conn_flag & XQC_CONN_FLAG_CAN_SEND_1RTT)) {
        if ((conn->conn_type == XQC_CONN_TYPE_CLIENT) 
            && (conn->conn_state == XQC_CONN_STATE_CLIENT_INITIAL_SENT) 
            && support_0rtt)
        {
            pkt_type = XQC_PTYPE_0RTT;
            conn->conn_flag |= XQC_CONN_FLAG_HAS_0RTT;

        } else {
            conn->conn_flag |= XQC_CONN_FLAG_DGRAM_WAIT_FOR_1RTT;
            xqc_log(conn->log, XQC_LOG_DEBUG, "|does_not_support_0rtt_when_sending_datagram|");
            return -XQC_EAGAIN;
        }
    }

    int i;
    void *data;
    size_t data_len;
    uint8_t check_applimit = 1;
    uint64_t dgram_id;

    for (i = 0; i < iov_size; *sent_cnt = ++i) {
        data = iov[i].iov_base;
        data_len = iov[i].iov_len;

        if (data == NULL && data_len != 0) {
            ret = -XQC_EPARAM;
            break;
        }

        if (conn->dgram_mss < data_len) {
            xqc_log(conn->log, XQC_LOG_INFO, "|datagram_is_too_large|data_len:%ud|",
                    data_len);
            return -XQC_EDGRAM_TOO_LARGE;
        }

        if (!xqc_send_queue_can_write(conn->conn_send_queue)) {
            conn->conn_send_queue->sndq_full = XQC_TRUE;
            xqc_log(conn->log, XQC_LOG_DEBUG, "|too many packets used|ctl_packets_used:%ud|", conn->conn_send_queue->sndq_packets_used);
            ret =  -XQC_EAGAIN;
            break;
        }

        if (pkt_type == XQC_PTYPE_0RTT && conn->zero_rtt_count >= XQC_PACKET_0RTT_MAX_COUNT) {
            conn->conn_flag |= XQC_CONN_FLAG_DGRAM_WAIT_FOR_1RTT;
            xqc_log(conn->log, XQC_LOG_DEBUG, "|too many 0rtt packets|zero_rtt_count:%ud|", conn->zero_rtt_count);
            ret = -XQC_EAGAIN;
            break;
        }

        if (check_applimit) {
            xqc_conn_check_app_limit(conn);
            check_applimit = 0;
        }

        if (use_supplied_dgram_id) {
            dgram_id = dgram_id_list[i];
        }

        ret = xqc_write_datagram_frame_to_packet(conn, pkt_type, data, data_len, 
                                                 &dgram_id, use_supplied_dgram_id, 
                                                 qos_level);

        if (ret < 0) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|write_datagram_frame_to_packet_error|");
            XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
            return ret;
        }

        /* 0RTT failure requires fallback to 1RTT, save the original send data */
        if (pkt_type == XQC_PTYPE_0RTT) {
            /* buffer 0RTT packet */
            ret = xqc_conn_buff_0rtt_datagram(conn, data, data_len, dgram_id, qos_level);
            if (ret < 0) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|unable_to_buffer_0rtt_datagram_data_error|");
                XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
                return ret;
            }
        }

        if (dgram_id_list) {
            dgram_id_list[i] = dgram_id;
        }

        *sent_bytes += data_len;
    }

    if (*sent_cnt > 0) {
        if (!(conn->conn_flag & XQC_CONN_FLAG_TICKING)) {
            if (0 == xqc_conns_pq_push(conn->engine->conns_active_pq, conn, conn->last_ticked_time)) {
                conn->conn_flag |= XQC_CONN_FLAG_TICKING;
            }
        }

        data = iov[*sent_cnt - 1].iov_base;
        data_len = iov[*sent_cnt - 1].iov_len;

        if (conn->conn_settings.datagram_redundant_probe
            && conn->dgram_probe_timer >= 0
            && qos_level <= XQC_DATA_QOS_NORMAL
            && conn->last_dgram
            && data_len <= conn->last_dgram->buf_len)
        {
            xqc_var_buf_clear(conn->last_dgram);
            xqc_var_buf_save_data(conn->last_dgram, data, data_len);
            xqc_conn_gp_timer_set(conn, conn->dgram_probe_timer, xqc_monotonic_timestamp() + conn->conn_settings.datagram_redundant_probe);
            xqc_log(conn->log, XQC_LOG_DEBUG, "|start_dgram_probe_timer|data_len:%z|", data_len);
        }

        /* call main logic to send packets out */
        xqc_engine_main_logic_internal(conn->engine);
    }

    return ret < 0 ? ret : XQC_OK;
}
void 
xqc_datagram_set_user_data(xqc_connection_t *conn, void *dgram_data)
{
    conn->dgram_data = dgram_data;
    /* notify to the upper layer */
    xqc_datagram_record_mss(conn);
}

void *
xqc_datagram_get_user_data(xqc_connection_t *conn)
{
    return conn->dgram_data;
}

void 
xqc_datagram_notify_write(xqc_connection_t *conn)
{
    if (conn->remote_settings.max_datagram_frame_size > 0
        && (conn->conn_flag & XQC_CONN_FLAG_UPPER_CONN_EXIST))
    {
        if (conn->app_proto_cbs.dgram_cbs.datagram_write_notify) {
            conn->app_proto_cbs.dgram_cbs.datagram_write_notify(conn, conn->dgram_data);
        }
    }
}

xqc_int_t 
xqc_datagram_notify_loss(xqc_connection_t *conn, xqc_packet_out_t *po)
{
    if (conn->app_proto_cbs.dgram_cbs.datagram_lost_notify
        && (conn->conn_flag & XQC_CONN_FLAG_UPPER_CONN_EXIST))
    {
        return conn->app_proto_cbs.dgram_cbs.datagram_lost_notify(conn, po->po_dgram_id, conn->dgram_data);
    }
    return 0;
}

void
xqc_datagram_notify_ack(xqc_connection_t *conn, xqc_packet_out_t *po)
{
    /* if it is already acked, do not notify */
    if (po->po_acked 
        || (po->po_origin && po->po_origin->po_acked))
    {
        xqc_log(conn->log, XQC_LOG_DEBUG, 
                "|datagram already notified|dgram_id:%ui|", po->po_dgram_id);
        return;
    }
    if (conn->app_proto_cbs.dgram_cbs.datagram_acked_notify
        && (conn->conn_flag & XQC_CONN_FLAG_UPPER_CONN_EXIST))
    {
        xqc_log(conn->log, XQC_LOG_DEBUG, 
                "|notify datagram acked to app|dgram_id:%ui|", po->po_dgram_id);
        conn->app_proto_cbs.dgram_cbs.datagram_acked_notify(conn, po->po_dgram_id, conn->dgram_data);
    }
}