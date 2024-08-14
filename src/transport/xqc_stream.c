/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/common/xqc_memory_pool.h"
#include "src/common/xqc_id_hash.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_packet_parser.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_utils.h"
#include "src/transport/xqc_pacing.h"
#include "src/tls/xqc_tls.h"


static xqc_stream_id_t
xqc_gen_stream_id(xqc_connection_t *conn, xqc_stream_type_t type)
{
    xqc_stream_id_t sid = 0;
    if (type == XQC_CLI_BID || type == XQC_SVR_BID) {
        sid = conn->cur_stream_id_bidi_local++;

    } else if (type == XQC_CLI_UNI || type == XQC_SVR_UNI) {
        sid = conn->cur_stream_id_uni_local++;
    }

    sid = sid << 2 | type;
    return sid;
}

void
xqc_stream_ready_to_write(xqc_stream_t *stream)
{
    if (!(stream->stream_flag & XQC_STREAM_FLAG_READY_TO_WRITE)) {
        if (stream->stream_encrypt_level == XQC_ENC_LEV_1RTT) {
            xqc_list_add_tail(&stream->write_stream_list, &stream->stream_conn->conn_write_streams);
        }
        stream->stream_flag |= XQC_STREAM_FLAG_READY_TO_WRITE;
    }

    if (!(stream->stream_conn->conn_flag & XQC_CONN_FLAG_TICKING)) {
        if (xqc_conns_pq_push(stream->stream_conn->engine->conns_active_pq,
                          stream->stream_conn, stream->stream_conn->last_ticked_time) != 0) {
            return;
        }

        stream->stream_conn->conn_flag |= XQC_CONN_FLAG_TICKING;
    }
}

void
xqc_stream_shutdown_write(xqc_stream_t *stream)
{
    if (stream->stream_flag & XQC_STREAM_FLAG_READY_TO_WRITE) {
        if (stream->stream_encrypt_level == XQC_ENC_LEV_1RTT) {
            xqc_list_del_init(&stream->write_stream_list);
        }
        stream->stream_flag &= ~XQC_STREAM_FLAG_READY_TO_WRITE;
    }
}

void
xqc_stream_ready_to_read(xqc_stream_t *stream)
{
    if (!(stream->stream_flag & XQC_STREAM_FLAG_READY_TO_READ)) {
        if (stream->stream_encrypt_level == XQC_ENC_LEV_1RTT) {
            xqc_list_add_tail(&stream->read_stream_list, &stream->stream_conn->conn_read_streams);
        }
        stream->stream_flag |= XQC_STREAM_FLAG_READY_TO_READ;
    }

    if (!(stream->stream_conn->conn_flag & XQC_CONN_FLAG_TICKING)) {
        if (xqc_conns_pq_push(stream->stream_conn->engine->conns_active_pq,
                              stream->stream_conn, stream->stream_conn->last_ticked_time) != 0) {
            return;
        }

        stream->stream_conn->conn_flag |= XQC_CONN_FLAG_TICKING;
    }
}

void
xqc_stream_shutdown_read(xqc_stream_t *stream)
{
    if (stream->stream_flag & XQC_STREAM_FLAG_READY_TO_READ) {
        if (stream->stream_encrypt_level == XQC_ENC_LEV_1RTT) {
            xqc_list_del_init(&stream->read_stream_list);
        }
        stream->stream_flag &= ~XQC_STREAM_FLAG_READY_TO_READ;
    }
}

void
xqc_stream_maybe_need_close(xqc_stream_t *stream)
{
    if (stream->stream_flag & XQC_STREAM_FLAG_NEED_CLOSE) {
        return;
    }

    if (stream->stream_state_send == XQC_SEND_STREAM_ST_DATA_RECVD
        && stream->stream_stats.all_data_acked_time == 0)
    {
        stream->stream_stats.all_data_acked_time = xqc_monotonic_timestamp();
    }

    if (stream->stream_state_send == XQC_SEND_STREAM_ST_DATA_RECVD 
        || stream->stream_state_send == XQC_SEND_STREAM_ST_RESET_RECVD)
    {
        xqc_stream_record_trans_state(stream, XQC_FALSE);
    }

    if ((stream->stream_state_send == XQC_SEND_STREAM_ST_DATA_RECVD || stream->stream_state_send == XQC_SEND_STREAM_ST_RESET_RECVD)
        && (stream->stream_state_recv == XQC_RECV_STREAM_ST_DATA_READ || stream->stream_state_recv == XQC_RECV_STREAM_ST_RESET_READ))
    {
        xqc_log(stream->stream_conn->log, XQC_LOG_DEBUG, "|stream_id:%ui|stream_type:%d|", stream->stream_id, stream->stream_type);
        stream->stream_flag |= XQC_STREAM_FLAG_NEED_CLOSE;
        xqc_usec_t now = xqc_monotonic_timestamp();
        if (stream->stream_stats.close_time == 0) {
            stream->stream_stats.close_time = now;
        }

        xqc_timer_manager_t *timer_manager = &stream->stream_conn->conn_timer_manager;
        xqc_usec_t pto = xqc_conn_get_max_pto(stream->stream_conn);
        xqc_usec_t new_expire = now + 3 * pto;
        if ((timer_manager->timer[XQC_TIMER_STREAM_CLOSE].timer_is_set 
            && new_expire < timer_manager->timer[XQC_TIMER_STREAM_CLOSE].expire_time) 
            || !timer_manager->timer[XQC_TIMER_STREAM_CLOSE].timer_is_set)
        {
            xqc_timer_set(timer_manager, XQC_TIMER_STREAM_CLOSE, now, 3 * pto);
        }
        stream->stream_close_time = new_expire;
        xqc_list_add_tail(&stream->closing_stream_list, &stream->stream_conn->conn_closing_streams);
        xqc_stream_shutdown_read(stream);
        xqc_stream_shutdown_write(stream);
    }
}

void
xqc_stream_close_discarded_stream(xqc_stream_t *stream)
{
    xqc_timer_manager_t    *timer_manager;
    xqc_usec_t              now;
    xqc_usec_t              pto;
    xqc_usec_t              new_expire;

    if (stream->stream_flag & XQC_STREAM_FLAG_NEED_CLOSE) {
        return;
    }

    xqc_log(stream->stream_conn->log, XQC_LOG_DEBUG, 
            "|stream_id:%ui|stream_type:%d|",
            stream->stream_id, stream->stream_type);

    stream->stream_flag |= XQC_STREAM_FLAG_NEED_CLOSE;

    now = xqc_monotonic_timestamp();
    pto = xqc_conn_get_max_pto(stream->stream_conn);
    new_expire = now + 3 * pto;

    timer_manager = &stream->stream_conn->conn_timer_manager;

    if ((timer_manager->timer[XQC_TIMER_STREAM_CLOSE].timer_is_set 
        && new_expire < timer_manager->timer[XQC_TIMER_STREAM_CLOSE].expire_time) 
        || !timer_manager->timer[XQC_TIMER_STREAM_CLOSE].timer_is_set)
    {
        xqc_timer_set(timer_manager, XQC_TIMER_STREAM_CLOSE, now, 3 * pto);
    }

    stream->stream_close_time = new_expire;

    xqc_list_add_tail(&stream->closing_stream_list, &stream->stream_conn->conn_closing_streams);
    xqc_stream_shutdown_read(stream);
    xqc_stream_shutdown_write(stream);
}

xqc_stream_t *
xqc_find_stream_by_id(xqc_stream_id_t stream_id, xqc_id_hash_table_t *streams_hash)
{
    xqc_stream_t *stream = xqc_id_hash_find(streams_hash, stream_id);
    return stream;
}

void
xqc_stream_set_flow_ctl(xqc_stream_t *stream)
{
    xqc_trans_settings_t *local_settings = &stream->stream_conn->local_settings;
    xqc_trans_settings_t *remote_settings = &stream->stream_conn->remote_settings;
    xqc_connection_t *conn = stream->stream_conn;

    if ((remote_settings->max_stream_data_bidi_remote
         && remote_settings->max_stream_data_bidi_local
         && remote_settings->max_stream_data_uni) == XQC_FALSE)
    {
        remote_settings = &stream->stream_conn->local_settings;
    }
    /*
     * initial_max_stream_data_bidi_local (0x0005):  This parameter is an
     * integer value specifying the initial flow control limit for
     * locally-initiated bidirectional streams.  This limit applies to
     * newly created bidirectional streams opened by the endpoint that
     * sends the transport parameter.  In client transport parameters,
     * this applies to streams with an identifier with the least
     * significant two bits set to 0x0; in server transport parameters,
     * this applies to streams with the least significant two bits set to
     * 0x1.
     *
     *  initial_max_stream_data_bidi_remote (0x0006):  This parameter is an
     * integer value specifying the initial flow control limit for peer-
     * initiated bidirectional streams.  This limit applies to newly
     * created bidirectional streams opened by the endpoint that receives
     * the transport parameter.  In client transport parameters, this
     * applies to streams with an identifier with the least significant
     * two bits set to 0x1; in server transport parameters, this applies
     * to streams with the least significant two bits set to 0x0.
     */
    if (conn->conn_type == XQC_CONN_TYPE_CLIENT) {
        if (stream->stream_type == XQC_CLI_BID) {
            stream->stream_flow_ctl.fc_max_stream_data_can_send = remote_settings->max_stream_data_bidi_remote;
            stream->stream_flow_ctl.fc_max_stream_data_can_recv = local_settings->max_stream_data_bidi_local;
            stream->stream_flow_ctl.fc_stream_recv_window_size = local_settings->max_stream_data_bidi_local;

        } else if (stream->stream_type == XQC_SVR_BID) {
            /* 
             * in server transport parameters,
             * this applies to streams with the least significant two bits set to 0x1
             */
            stream->stream_flow_ctl.fc_max_stream_data_can_send = remote_settings->max_stream_data_bidi_local;
            stream->stream_flow_ctl.fc_max_stream_data_can_recv = local_settings->max_stream_data_bidi_remote;
            stream->stream_flow_ctl.fc_stream_recv_window_size = local_settings->max_stream_data_bidi_remote;

        } else {
            stream->stream_flow_ctl.fc_max_stream_data_can_send = remote_settings->max_stream_data_uni;
            stream->stream_flow_ctl.fc_max_stream_data_can_recv = local_settings->max_stream_data_uni;
            stream->stream_flow_ctl.fc_stream_recv_window_size = local_settings->max_stream_data_uni;
        }

    } else { /* conn->conn_type == XQC_CONN_TYPE_SERVER */
        if (stream->stream_type == XQC_CLI_BID) {
            stream->stream_flow_ctl.fc_max_stream_data_can_send = remote_settings->max_stream_data_bidi_local;
            stream->stream_flow_ctl.fc_max_stream_data_can_recv = local_settings->max_stream_data_bidi_remote;
            stream->stream_flow_ctl.fc_stream_recv_window_size = local_settings->max_stream_data_bidi_remote;

        } else if (stream->stream_type == XQC_SVR_BID) {
            stream->stream_flow_ctl.fc_max_stream_data_can_send = remote_settings->max_stream_data_bidi_remote;
            stream->stream_flow_ctl.fc_max_stream_data_can_recv = local_settings->max_stream_data_bidi_local;
            stream->stream_flow_ctl.fc_stream_recv_window_size = local_settings->max_stream_data_bidi_local;

        } else {
            stream->stream_flow_ctl.fc_max_stream_data_can_send = remote_settings->max_stream_data_uni;
            stream->stream_flow_ctl.fc_max_stream_data_can_recv = local_settings->max_stream_data_uni;
            stream->stream_flow_ctl.fc_stream_recv_window_size = local_settings->max_stream_data_uni;
        }
    }
}


void
xqc_stream_update_flow_ctl(xqc_stream_t *stream)
{
    xqc_trans_settings_t *remote_settings = &stream->stream_conn->remote_settings;
    xqc_connection_t *conn = stream->stream_conn;

    if (conn->conn_type == XQC_CONN_TYPE_CLIENT) {
        if (stream->stream_type == XQC_CLI_BID) {
            stream->stream_flow_ctl.fc_max_stream_data_can_send = remote_settings->max_stream_data_bidi_remote;

        } else if (stream->stream_type == XQC_SVR_BID) {
            /* 
             * in server transport parameters,
             * this applies to streams with the least significant two bits set to 0x1
             */
            stream->stream_flow_ctl.fc_max_stream_data_can_send = remote_settings->max_stream_data_bidi_local;

        } else {
            stream->stream_flow_ctl.fc_max_stream_data_can_send = remote_settings->max_stream_data_uni;
        }

    } else { /* conn->conn_type == XQC_CONN_TYPE_SERVER */
        if (stream->stream_type == XQC_CLI_BID) {
            stream->stream_flow_ctl.fc_max_stream_data_can_send = remote_settings->max_stream_data_bidi_local;

        } else if (stream->stream_type == XQC_SVR_BID) {
            stream->stream_flow_ctl.fc_max_stream_data_can_send = remote_settings->max_stream_data_bidi_remote;

        } else {
            stream->stream_flow_ctl.fc_max_stream_data_can_send = remote_settings->max_stream_data_uni;
        }
    }
}


uint64_t
xqc_stream_get_init_max_stream_data(xqc_stream_t *stream)
{
    xqc_connection_t *conn = stream->stream_conn;
    if (stream->stream_type == XQC_SVR_BID) {
        if (conn->conn_type == XQC_CONN_TYPE_SERVER) {
            return conn->local_settings.max_stream_data_bidi_local;

        } else {
            return conn->local_settings.max_stream_data_bidi_remote;
        }

    } else if (stream->stream_type == XQC_CLI_BID) {
        if (conn->conn_type == XQC_CONN_TYPE_SERVER) {
            return conn->local_settings.max_stream_data_bidi_remote;

        } else {
            return conn->local_settings.max_stream_data_bidi_local;
        }

    } else {
        return conn->local_settings.max_stream_data_uni;
    }
}

int
xqc_stream_do_send_flow_ctl(xqc_stream_t *stream)
{
    int ret = XQC_OK;

    xqc_log(stream->stream_conn->log, XQC_LOG_DEBUG, "|conn_flow_ctl|window:%ui|",
                stream->stream_conn->conn_flow_ctl.fc_max_data_can_send - stream->stream_conn->conn_flow_ctl.fc_data_sent);

    /* connection level */
    if (stream->stream_conn->conn_flow_ctl.fc_data_sent + stream->stream_conn->pkt_out_size > stream->stream_conn->conn_flow_ctl.fc_max_data_can_send) {
        xqc_log(stream->stream_conn->log, XQC_LOG_INFO, "|xqc_stream_send|exceed max_data:%ui|",
                stream->stream_conn->conn_flow_ctl.fc_max_data_can_send);

        stream->stream_conn->conn_flag |= XQC_CONN_FLAG_DATA_BLOCKED;
        xqc_write_data_blocked_to_packet(stream->stream_conn, stream->stream_conn->conn_flow_ctl.fc_max_data_can_send);
        ret = -XQC_ECONN_BLOCKED;
    }

    /* stream level */
    if (stream->stream_send_offset + stream->stream_conn->pkt_out_size > stream->stream_flow_ctl.fc_max_stream_data_can_send) {
        xqc_log(stream->stream_conn->log, XQC_LOG_INFO, "|xqc_stream_send|exceed max_stream_data:%ui|",
                stream->stream_flow_ctl.fc_max_stream_data_can_send);

        stream->stream_flag |= XQC_STREAM_FLAG_DATA_BLOCKED;
        xqc_write_stream_data_blocked_to_packet(stream->stream_conn, stream->stream_id,
                                                stream->stream_flow_ctl.fc_max_stream_data_can_send);
        ret = -XQC_ESTREAM_BLOCKED;
    }
    return ret;
}

int
xqc_stream_do_recv_flow_ctl(xqc_stream_t *stream)
{
    xqc_connection_t *conn = stream->stream_conn;
    xqc_usec_t now = xqc_monotonic_timestamp();

    /* increase recv window */
    xqc_usec_t min_srtt = xqc_conn_get_min_srtt(conn, 0);
    xqc_usec_t max_srtt = 0;
    uint64_t old_fc_win = 0;

    /* stream level */
    uint64_t available_window = stream->stream_flow_ctl.fc_max_stream_data_can_recv - stream->stream_data_in.next_read_offset;

    if (available_window < stream->stream_flow_ctl.fc_stream_recv_window_size / 2) {
        
        if (!stream->recv_rate_bytes_per_sec) {
            if (stream->stream_flow_ctl.fc_last_window_update_time
                && (now - stream->stream_flow_ctl.fc_last_window_update_time < 2 * min_srtt)) 
            {
                stream->stream_flow_ctl.fc_stream_recv_window_size
                        = xqc_min(stream->stream_flow_ctl.fc_stream_recv_window_size * 2, XQC_MAX_RECV_WINDOW);
            }

        } else {

            if (!max_srtt) {
                max_srtt = xqc_conn_get_max_srtt(conn);
            }

            old_fc_win = stream->stream_flow_ctl.fc_stream_recv_window_size;
            stream->stream_flow_ctl.fc_stream_recv_window_size = stream->recv_rate_bytes_per_sec * max_srtt / 1000000;
            stream->stream_flow_ctl.fc_stream_recv_window_size = xqc_max(conn->conn_settings.init_recv_window, stream->stream_flow_ctl.fc_stream_recv_window_size);
            stream->stream_flow_ctl.fc_stream_recv_window_size = xqc_min(XQC_MAX_RECV_WINDOW, stream->stream_flow_ctl.fc_stream_recv_window_size);
            xqc_log(conn->log, XQC_LOG_DEBUG, 
                    "|stream_level|fc_win_update|old_fc_win:%ui|fc_win:%ui|", 
                    old_fc_win, stream->stream_flow_ctl.fc_stream_recv_window_size);
        }

        stream->stream_flow_ctl.fc_last_window_update_time = now;

        if (stream->stream_flow_ctl.fc_stream_recv_window_size > available_window) {        
            stream->stream_flow_ctl.fc_max_stream_data_can_recv += (stream->stream_flow_ctl.fc_stream_recv_window_size - available_window);
            xqc_log(conn->log, XQC_LOG_DEBUG,
                    "|xqc_write_max_stream_data_to_packet|new_max_data:%ui|stream_max_recv_offset:%ui|next_read_offset:%ui|window_size:%ui|",
                    stream->stream_flow_ctl.fc_max_stream_data_can_recv, stream->stream_max_recv_offset,
                    stream->stream_data_in.next_read_offset, stream->stream_flow_ctl.fc_stream_recv_window_size);
            xqc_write_max_stream_data_to_packet(conn, stream->stream_id, stream->stream_flow_ctl.fc_max_stream_data_can_recv, XQC_PTYPE_SHORT_HEADER);
        }
    }

    /* connection level */
    available_window = conn->conn_flow_ctl.fc_max_data_can_recv - conn->conn_flow_ctl.fc_data_read;

    if (available_window < conn->conn_flow_ctl.fc_recv_windows_size / 2) {

        if (!conn->conn_settings.recv_rate_bytes_per_sec) {

            if (conn->conn_flow_ctl.fc_last_window_update_time
                && (now - conn->conn_flow_ctl.fc_last_window_update_time < 2 * min_srtt))
            {
                conn->conn_flow_ctl.fc_recv_windows_size
                        = xqc_min(conn->conn_flow_ctl.fc_recv_windows_size * 2, XQC_MAX_RECV_WINDOW);
            }

            if (conn->conn_flow_ctl.fc_recv_windows_size < 1.5 * stream->stream_flow_ctl.fc_stream_recv_window_size) {
                conn->conn_flow_ctl.fc_recv_windows_size = (uint64_t)(1.5 * stream->stream_flow_ctl.fc_stream_recv_window_size);
            }

        } else {

            if (!max_srtt) {
                max_srtt = xqc_conn_get_max_srtt(conn);
            }

            old_fc_win = conn->conn_flow_ctl.fc_recv_windows_size;
            conn->conn_flow_ctl.fc_recv_windows_size = conn->conn_settings.recv_rate_bytes_per_sec * max_srtt / 1000000;
            conn->conn_flow_ctl.fc_recv_windows_size = xqc_max(XQC_MIN_RECV_WINDOW, conn->conn_flow_ctl.fc_recv_windows_size);
            conn->conn_flow_ctl.fc_recv_windows_size = xqc_min(XQC_MAX_RECV_WINDOW, conn->conn_flow_ctl.fc_recv_windows_size);
            xqc_log(conn->log, XQC_LOG_DEBUG, 
                    "|conn_level|fc_win_update|old_fc_win:%ui|fc_win:%ui|", 
                    old_fc_win, conn->conn_flow_ctl.fc_recv_windows_size);

        }

        conn->conn_flow_ctl.fc_last_window_update_time = now;

        if (conn->conn_flow_ctl.fc_recv_windows_size > available_window) {
            conn->conn_flow_ctl.fc_max_data_can_recv += (conn->conn_flow_ctl.fc_recv_windows_size - available_window);
            xqc_log(conn->log, XQC_LOG_DEBUG,
                    "|xqc_write_max_data_to_packet|new_max_data:%ui|fc_data_recved:%ui|fc_data_read:%ui|window_size:%ui|",
                    conn->conn_flow_ctl.fc_max_data_can_recv, conn->conn_flow_ctl.fc_data_recved,
                    conn->conn_flow_ctl.fc_data_read, conn->conn_flow_ctl.fc_recv_windows_size);
            xqc_write_max_data_to_packet(conn, conn->conn_flow_ctl.fc_max_data_can_recv);
        }
    }

    return XQC_OK;
}

int
xqc_stream_do_create_flow_ctl(xqc_connection_t *conn, xqc_stream_id_t stream_id, xqc_stream_type_t stream_type)
{
    if (stream_id == XQC_UNDEFINE_STREAM_ID) { /* sending part */
        if (stream_type == XQC_CLI_BID || stream_type == XQC_SVR_BID) {
            if (conn->cur_stream_id_bidi_local >= conn->conn_flow_ctl.fc_max_streams_bidi_can_send) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|exceed max_streams_bidi_can_send:%ui|",
                        conn->conn_flow_ctl.fc_max_streams_bidi_can_send);
                xqc_write_streams_blocked_to_packet(conn, conn->conn_flow_ctl.fc_max_streams_bidi_can_send, 1);
                return -XQC_EPROTO;
            }

        } else {
            if (conn->cur_stream_id_uni_local >= conn->conn_flow_ctl.fc_max_streams_uni_can_send) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|exceed max_streams_uni_can_send:%ui|",
                        conn->conn_flow_ctl.fc_max_streams_uni_can_send);
                xqc_write_streams_blocked_to_packet(conn, conn->conn_flow_ctl.fc_max_streams_uni_can_send, 0);
                return -XQC_EPROTO;
            }
        }

    } else { /* receiving part */
        stream_type = xqc_get_stream_type(stream_id);
        if (stream_type == XQC_CLI_BID || stream_type == XQC_SVR_BID) {
            if (stream_id >= 4 * conn->conn_flow_ctl.fc_max_streams_bidi_can_recv + stream_type) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|exceed max_streams_bidi_can_recv:%ui|",
                        conn->conn_flow_ctl.fc_max_streams_bidi_can_recv);
                XQC_CONN_ERR(conn, TRA_STREAM_LIMIT_ERROR);
                return -XQC_EPROTO;
            }
            /* increase max streams */
            if ((stream_id >> 2) >= conn->conn_flow_ctl.fc_max_streams_bidi_can_recv / 2) {
                conn->conn_flow_ctl.fc_max_streams_bidi_can_recv += conn->local_settings.max_streams_bidi;
                xqc_write_max_streams_to_packet(conn, conn->conn_flow_ctl.fc_max_streams_bidi_can_recv, 1);
            }

        } else {
            if (stream_id >= 4 * conn->conn_flow_ctl.fc_max_streams_uni_can_recv + stream_type) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|exceed max_streams_uni_can_recv:%ui|",
                        conn->conn_flow_ctl.fc_max_streams_uni_can_recv);
                XQC_CONN_ERR(conn, TRA_STREAM_LIMIT_ERROR);
                return -XQC_EPROTO;
            }
            /* increase max streams */
            if ((stream_id >> 2) >= conn->conn_flow_ctl.fc_max_streams_uni_can_recv / 2) {
                conn->conn_flow_ctl.fc_max_streams_uni_can_recv += conn->local_settings.max_streams_uni;
                xqc_write_max_streams_to_packet(conn, conn->conn_flow_ctl.fc_max_streams_uni_can_recv, 0);
            }
        }
    }
    return XQC_OK;
}

xqc_stream_t *
xqc_stream_create(xqc_engine_t *engine, const xqc_cid_t *cid, xqc_stream_settings_t *settings, 
    void *user_data)
{
    xqc_connection_t *conn;
    xqc_stream_t *stream;

    conn = xqc_engine_conns_hash_find(engine, cid, 's');
    if (!conn) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|can not find connection|cid:%s",
                xqc_scid_str(engine, cid));
        return NULL;
    }

    stream = xqc_create_stream_with_conn(conn, XQC_UNDEFINE_STREAM_ID, XQC_CLI_BID, settings, user_data);
    if (!stream) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|xqc_create_stream_with_conn error|");
        return NULL;
    }

    conn->cli_bidi_streams++;

    return stream;
}

xqc_stream_t *
xqc_stream_create_with_direction(xqc_connection_t *conn,
    xqc_stream_direction_t dir, void *user_data)
{
    xqc_stream_type_t type;

    /* get stream type */
    if (XQC_CONN_TYPE_CLIENT == xqc_conn_get_type(conn)) {
        if (XQC_STREAM_BIDI == dir) {
            type = XQC_CLI_BID;

        } else {
            type = XQC_CLI_UNI;
        }

    } else {
        if (XQC_STREAM_BIDI == dir) {
            type = XQC_SVR_BID;

        } else {
            type = XQC_SVR_UNI;
        }
    }

    /* create stream */
    return xqc_create_stream_with_conn(conn, XQC_UNDEFINE_STREAM_ID, type,
                                       NULL, user_data);
}


xqc_stream_t *
xqc_create_stream_with_conn(xqc_connection_t *conn, xqc_stream_id_t stream_id,
    xqc_stream_type_t stream_type, xqc_stream_settings_t *settings, void *user_data)
{
    xqc_int_t   ret;

    if (conn->conn_state >= XQC_CONN_STATE_CLOSING) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|conn closing, cannot create stream|type:%d|state:%d|flag:%s|",
                conn->conn_type, conn->conn_state, xqc_conn_flag_2_str(conn, conn->conn_flag));
        return NULL;
    }

    if (xqc_stream_do_create_flow_ctl(conn, stream_id, stream_type)) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_stream_do_create_flow_ctl error|");
        return NULL;
    }

    xqc_stream_t *stream = xqc_calloc(1, sizeof(xqc_stream_t));
    if (stream == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_calloc error|");
        return NULL;
    }
    xqc_list_add_tail(&stream->all_stream_list, &conn->conn_all_streams);

    stream->stream_encrypt_level = XQC_ENC_LEV_1RTT;

    stream->stream_conn = conn;
    stream->stream_if = &conn->app_proto_cbs.stream_cbs;
    stream->user_data = user_data;
    stream->stream_state_send = XQC_SEND_STREAM_ST_READY;
    stream->stream_state_recv = XQC_RECV_STREAM_ST_RECV;

    stream->stream_refcnt = 0;
    xqc_memset(&stream->stream_stats, 0, sizeof(stream->stream_stats));
    stream->stream_stats.create_time = xqc_monotonic_timestamp();

    xqc_memset(&stream->paths_info, 0, sizeof(stream->paths_info));
    for (int i = 0; i < XQC_MAX_PATHS_COUNT; ++i) {
        stream->paths_info[i].path_id = XQC_MAX_UINT64_VALUE;
    }

    xqc_stream_set_flow_ctl(stream);

    xqc_init_list_head(&stream->stream_data_in.frames_tailq);

    xqc_init_list_head(&stream->stream_write_buff_list.write_buff_list);

    if (stream_id == XQC_UNDEFINE_STREAM_ID) {
        stream->stream_type = stream_type;
        stream->stream_id = xqc_gen_stream_id(conn, stream->stream_type);

    } else {
        stream->stream_id = stream_id;
        stream->stream_type = xqc_get_stream_type(stream_id);
    }

    xqc_id_hash_element_t e = {stream->stream_id, stream};
    if (xqc_id_hash_add(conn->streams_hash, e)) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_id_hash_add error|");
        goto error;
    }

    /* newly initiated stream is writable */
    if (stream_id == XQC_UNDEFINE_STREAM_ID) {
        xqc_stream_ready_to_write(stream);
    }

    stream->recv_rate_bytes_per_sec = 0;

    if (settings) {
        if (conn->conn_settings.enable_stream_rate_limit
            && stream->stream_type == XQC_CLI_BID)
        {
            stream->recv_rate_bytes_per_sec = settings->recv_rate_bytes_per_sec;
        }
    }

    if (stream->stream_if->stream_create_notify) {
        ret = stream->stream_if->stream_create_notify(stream, stream->user_data);
        if (XQC_OK != ret) {
            xqc_log(conn->log, XQC_LOG_WARN, "|stream create notify error|"
                    "|stream_id:%ui", stream->stream_id);
            stream->stream_flag |= XQC_STREAM_FLAG_DISCARDED;
        }
    }

    return stream;

error:

    xqc_destroy_stream(stream);
    return NULL;
}

void
xqc_stream_set_user_data(xqc_stream_t *stream, void *user_data)
{
    stream->user_data = user_data;
}

void *
xqc_get_conn_user_data_by_stream(xqc_stream_t *stream)
{
    return stream->stream_conn->user_data;
}

void *
xqc_get_conn_alp_user_data_by_stream(xqc_stream_t *stream)
{
    return stream->stream_conn->proto_data;
}

xqc_stream_id_t
xqc_stream_id(xqc_stream_t *stream)
{
    return stream->stream_id;
}

void
xqc_destroy_stream(xqc_stream_t *stream)
{
    xqc_log(stream->stream_conn->log, XQC_LOG_DEBUG, "|send_state:%d|recv_state:%d|stream_id:%ui|stream_type:%d|",
            stream->stream_state_send, stream->stream_state_recv, stream->stream_id, stream->stream_type);

    if ((stream->stream_state_send == XQC_SEND_STREAM_ST_DATA_RECVD)
        && (stream->stream_state_recv == XQC_RECV_STREAM_ST_DATA_READ))
    {
        if(stream->stream_conn) {
            stream->stream_conn->finished_streams++;
        }
    }

    xqc_stream_record_trans_state(stream, XQC_FALSE);

    if (stream->stream_if->stream_close_notify
        && !(stream->stream_flag & XQC_STREAM_FLAG_DISCARDED))
    {
        stream->stream_if->stream_close_notify(stream, stream->user_data);
    }

    xqc_list_del_init(&stream->all_stream_list);

    xqc_destroy_frame_list(&stream->stream_data_in.frames_tailq);

    xqc_destroy_write_buff_list(&stream->stream_write_buff_list.write_buff_list);

    int ret = xqc_id_hash_delete(stream->stream_conn->streams_hash, stream->stream_id);
    if (ret != XQC_OK) {
        xqc_log(stream->stream_conn->log, XQC_LOG_ERROR, "|delete stream error|conn:%p|stream_id:%ui|ret:%d|",
                stream->stream_conn, stream->stream_id, ret);
    }

    if (xqc_id_hash_delete(stream->stream_conn->passive_streams_hash, stream->stream_id) == XQC_ID_HASH_LOOP) {
        xqc_id_hash_table_t* hash_tab = stream->stream_conn->passive_streams_hash;
        xqc_id_hash_node_t* node = hash_tab->list[stream->stream_id % hash_tab->count];
        xqc_log(stream->stream_conn->log, XQC_LOG_ERROR, "|stream_id:%ui|hash:%ui|value:%p|node:%p|next:%p|",
                stream->stream_id, node->element.hash, node->element.value, node, node->next);
    }

    xqc_stream_shutdown_write(stream);
    xqc_stream_shutdown_read(stream);

    stream->stream_flag |= XQC_STREAM_FLAG_CLOSED;

#define __calc_delay(a, b) (a? (a) - (b) : 0)

    char path_info_buff[200 * XQC_MAX_PATHS_COUNT] = {'\0'};
    xqc_stream_path_metrics_print(stream->stream_conn, stream, path_info_buff, 50 * XQC_MAX_PATHS_COUNT);

    xqc_log(stream->stream_conn->log, XQC_LOG_STATS,
            "|err:0x%xi|close_msg:%s|enable_multipath:%d|"
            "send_state:%d|recv_state:%d|stream_id:%ui|stream_type:%d|"
            "send_bytes:%ui|read_bytes:%ui|recv_bytes:%ui|stream_len:%ui|"
            "create_time:%ui|wrt_delay:%ui|"
            "snd_delay:%ui|finwrt_delay:%ui|finsnd_delay:%ui|"
            "finrcv_delay:%ui|finread_delay:%ui|all_acked_delay:%ui|"
            "firstfinack_dely:%ui|close_delay:%ui|"
            "apprst_delay:%ui|rstsnd_delay:%ui|rstrcv_delay:%ui|%s|"
            "path_info:%s|",
            stream->stream_err, stream->stream_close_msg ? stream->stream_close_msg : "",
            stream->stream_conn->enable_multipath ? 1:0,
            stream->stream_state_send, stream->stream_state_recv, 
            stream->stream_id, stream->stream_type,
            stream->stream_send_offset,
            stream->stream_data_in.next_read_offset,
            stream->stream_data_in.merged_offset_end,
            stream->stream_data_in.stream_length,
            stream->stream_stats.create_time,
            __calc_delay(stream->stream_stats.first_write_time, stream->stream_stats.create_time),
            __calc_delay(stream->stream_stats.first_snd_time, stream->stream_stats.create_time),
            __calc_delay(stream->stream_stats.local_fin_write_time, stream->stream_stats.create_time),
            __calc_delay(stream->stream_stats.local_fin_snd_time, stream->stream_stats.create_time),
            __calc_delay(stream->stream_stats.peer_fin_rcv_time, stream->stream_stats.create_time),
            __calc_delay(stream->stream_stats.peer_fin_read_time, stream->stream_stats.create_time),
            __calc_delay(stream->stream_stats.all_data_acked_time, stream->stream_stats.create_time),
            __calc_delay(stream->stream_stats.first_fin_ack_time, stream->stream_stats.create_time),
            __calc_delay(stream->stream_stats.close_time, stream->stream_stats.create_time),
            __calc_delay(stream->stream_stats.app_reset_time, stream->stream_stats.create_time),
            __calc_delay(stream->stream_stats.local_reset_time, stream->stream_stats.create_time),
            __calc_delay(stream->stream_stats.peer_reset_time, stream->stream_stats.create_time),
            xqc_conn_addr_str(stream->stream_conn),
            path_info_buff);
#undef __calc_delay

    xqc_free(stream);
}

void 
xqc_stream_record_trans_state(xqc_stream_t *stream, xqc_bool_t begin)
{
    xqc_connection_t *conn = stream->stream_conn;

    if (begin && stream->begin_trans_state[0] == 0) {
        xqc_conn_encode_transport_state(conn, stream->begin_trans_state, XQC_STREAM_TRANSPORT_STATE_SZ);
    }

    if (!begin && stream->end_trans_state[0] == 0) {
        xqc_conn_encode_transport_state(conn, stream->end_trans_state, XQC_STREAM_TRANSPORT_STATE_SZ);
    }
}

xqc_int_t
xqc_stream_close(xqc_stream_t *stream)
{
    xqc_int_t ret;
    xqc_connection_t *conn = stream->stream_conn;
    xqc_log(conn->log, XQC_LOG_DEBUG, "|stream_id:%ui|stream_state_send:%d|stream_state_recv:%d|conn:%p|conn_state:%s|",
            stream->stream_id, stream->stream_state_send, stream->stream_state_recv, conn, xqc_conn_state_2_str(conn->conn_state));

    XQC_STREAM_CLOSE_MSG(stream, "local reset");

    if (stream->stream_state_send >= XQC_SEND_STREAM_ST_RESET_SENT) {
        return XQC_OK;
    }
    if (conn->conn_state >= XQC_CONN_STATE_CLOSING) {
        return XQC_OK;
    }

    xqc_send_queue_drop_stream_frame_packets(conn, stream->stream_id);
    ret = xqc_write_reset_stream_to_packet(conn, stream, H3_REQUEST_CANCELLED, stream->stream_send_offset);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_reset_stream_to_packet error|%d|", ret);
        XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
    }

    /* A STOP_SENDING frame can be sent for streams in the "Recv" or "Size
       Known" states */
    if (stream->stream_state_recv == XQC_RECV_STREAM_ST_RECV
        || stream->stream_state_recv == XQC_RECV_STREAM_ST_SIZE_KNOWN)
    {
        ret = xqc_write_stop_sending_to_packet(conn, stream, H3_REQUEST_CANCELLED);
        if (ret < 0) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_stop_sending_to_packet error|%d|", ret);
            XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
        }
    }

    if (!(conn->conn_flag & XQC_CONN_FLAG_TICKING)) {
        if (0 == xqc_conns_pq_push(conn->engine->conns_active_pq, conn, conn->last_ticked_time)) {
            conn->conn_flag |= XQC_CONN_FLAG_TICKING;
        }
    }
    xqc_stream_shutdown_write(stream);
    xqc_engine_main_logic_internal(conn->engine);
    return XQC_OK;
}

xqc_int_t
xqc_insert_passive_stream_hash(xqc_connection_t *conn, int64_t cur_max_sid, xqc_stream_id_t stream_id)
{
    xqc_stream_type_t type = xqc_get_stream_type(stream_id);
    for (int64_t sid = cur_max_sid + 1; sid <= (stream_id >> 2u); ++sid) {
        xqc_id_hash_element_t e = {(uint64_t)sid << 2u | type, conn};
        if (xqc_id_hash_add(conn->passive_streams_hash, e)) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_id_hash_add error|stream_id:%ui|", stream_id);
            XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
        }
    }
    return XQC_OK;
}

xqc_stream_t *
xqc_passive_create_stream(xqc_connection_t *conn, xqc_stream_id_t stream_id, void *user_data)
{
    if (xqc_stream_do_create_flow_ctl(conn, stream_id, xqc_get_stream_type(stream_id)) != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_stream_do_create_flow_ctl error|");
        return NULL;
    }

    int64_t sid = stream_id >> 2u;
    if (xqc_stream_is_bidi(stream_id) && sid > conn->max_stream_id_bidi_remote) {
        xqc_insert_passive_stream_hash(conn, conn->max_stream_id_bidi_remote, stream_id);
        conn->max_stream_id_bidi_remote = sid;

    } else if (!xqc_stream_is_bidi(stream_id) && sid > conn->max_stream_id_uni_remote) {
        xqc_insert_passive_stream_hash(conn, conn->max_stream_id_uni_remote, stream_id);
        conn->max_stream_id_uni_remote = sid;

    } else {
        if (!xqc_id_hash_find(conn->passive_streams_hash, stream_id)) {
            /* already closed */
            xqc_log(conn->log, XQC_LOG_DEBUG, "|stream already closed|stream_id:%ui|", stream_id);
            return NULL;
        }
    }

    xqc_stream_t *stream = xqc_create_stream_with_conn(conn, stream_id, 0, NULL, user_data);
    if (stream == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_create_stream_with_conn error|stream_id:%ui|", stream_id);
        XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
        return NULL;
    }

    xqc_stream_type_t stream_type;
    stream_type = xqc_get_stream_type(stream_id);

    if (stream_type == XQC_CLI_BID) {
        conn->cli_bidi_streams++;
        
    } else if (stream_type == XQC_SVR_BID) {
        conn->svr_bidi_streams++;
    }

    return stream;
}


xqc_int_t 
xqc_stream_update_settings(xqc_stream_t *stream, 
    xqc_stream_settings_t *settings)
{
    xqc_connection_t *conn = NULL;
    xqc_usec_t max_srtt = 0;
    uint64_t old_fc_win = 0, new_offset = 0;
    
    if (stream && settings 
        && settings->recv_rate_bytes_per_sec)
    {
        conn = stream->stream_conn;
        if (conn->conn_settings.enable_stream_rate_limit) {
            stream->recv_rate_bytes_per_sec = settings->recv_rate_bytes_per_sec;
            max_srtt = xqc_conn_get_max_srtt(conn);
            old_fc_win = stream->stream_flow_ctl.fc_stream_recv_window_size;
            stream->stream_flow_ctl.fc_stream_recv_window_size = stream->recv_rate_bytes_per_sec * max_srtt / 1000000;
            stream->stream_flow_ctl.fc_stream_recv_window_size = xqc_max(conn->conn_settings.init_recv_window, stream->stream_flow_ctl.fc_stream_recv_window_size);
            stream->stream_flow_ctl.fc_stream_recv_window_size = xqc_min(XQC_MAX_RECV_WINDOW, stream->stream_flow_ctl.fc_stream_recv_window_size);
            xqc_log(conn->log, XQC_LOG_DEBUG, 
                    "|fc_win_update|old_fc_win:%ui|fc_win:%ui|", 
                    old_fc_win, stream->stream_flow_ctl.fc_stream_recv_window_size);
            new_offset = stream->stream_data_in.next_read_offset + stream->stream_flow_ctl.fc_stream_recv_window_size;

            if(new_offset > stream->stream_flow_ctl.fc_max_stream_data_can_recv) {
                stream->stream_flow_ctl.fc_max_stream_data_can_recv = new_offset;
                xqc_log(conn->log, XQC_LOG_DEBUG,
                        "|new_max_data:%ui|stream_max_recv_offset:%ui|next_read_offset:%ui|window_size:%ui|",
                        stream->stream_flow_ctl.fc_max_stream_data_can_recv, stream->stream_max_recv_offset,
                        stream->stream_data_in.next_read_offset, stream->stream_flow_ctl.fc_stream_recv_window_size);
                xqc_write_max_stream_data_to_packet(conn, stream->stream_id, stream->stream_flow_ctl.fc_max_stream_data_can_recv, XQC_PTYPE_NUM);
            }
            return XQC_OK;
        }        
    }

    return -XQC_EPARAM;
}

xqc_int_t 
xqc_read_crypto_stream(xqc_stream_t *stream)
{
    xqc_stream_frame_t *stream_frame = NULL;
    xqc_connection_t *conn = stream->stream_conn;

    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &stream->stream_data_in.frames_tailq) {
        stream_frame = xqc_list_entry(pos, xqc_stream_frame_t, sf_list);

        if (stream->stream_data_in.next_read_offset < stream_frame->data_offset) {
            break;
        }

        if (stream->stream_data_in.next_read_offset >= stream_frame->data_offset + stream_frame->data_length) {
            xqc_list_del(pos);
            xqc_destroy_stream_frame(stream_frame);
            continue;
        }

        size_t data_len = stream_frame->data_offset + stream_frame->data_length - stream->stream_data_in.next_read_offset;
        unsigned char *data_start = stream_frame->data + (stream->stream_data_in.next_read_offset - stream_frame->data_offset);

        stream->stream_data_in.next_read_offset = stream->stream_data_in.next_read_offset + data_len;

        xqc_int_t ret = xqc_tls_process_crypto_data(conn->tls, stream->stream_encrypt_level, data_start, data_len);

        xqc_list_del(pos);
        xqc_destroy_stream_frame(stream_frame);

        if (ret != XQC_OK) {
            xqc_log(stream->stream_conn->log, XQC_LOG_ERROR, "|xqc_tls_process_crypto_data error: %d|", ret);
            return -XQC_EILLEGAL_FRAME;
        }
    }

    return XQC_OK;
}

int 
xqc_crypto_stream_on_read(xqc_stream_t *stream, void *user_data)
{
    XQC_DEBUG_PRINT
    xqc_encrypt_level_t encrypt_level = stream->stream_encrypt_level;
    xqc_conn_state_t cur_state = stream->stream_conn->conn_state;
    xqc_conn_state_t next_state;

    xqc_connection_t * conn = stream->stream_conn;

    if (encrypt_level == XQC_ENC_LEV_INIT) {
        switch (cur_state) {
        case XQC_CONN_STATE_CLIENT_INITIAL_SENT:
            next_state = XQC_CONN_STATE_CLIENT_INITIAL_RECVD;
            break;
        case XQC_CONN_STATE_SERVER_INIT:
            xqc_stream_ready_to_write(stream);
            next_state = XQC_CONN_STATE_SERVER_INITIAL_RECVD;
            break;
        default:
            next_state = cur_state;
        }

    } else if (encrypt_level == XQC_ENC_LEV_HSK) {
        switch (cur_state) {
        case XQC_CONN_STATE_CLIENT_INITIAL_SENT:
        case XQC_CONN_STATE_CLIENT_INITIAL_RECVD:
        case XQC_CONN_STATE_CLIENT_HANDSHAKE_RECVD:
            xqc_stream_ready_to_write(stream);
            next_state = XQC_CONN_STATE_CLIENT_HANDSHAKE_RECVD;
            break;
        case XQC_CONN_STATE_SERVER_INITIAL_RECVD:
        case XQC_CONN_STATE_SERVER_INITIAL_SENT:
            xqc_stream_ready_to_write(stream);
            next_state = XQC_CONN_STATE_SERVER_HANDSHAKE_RECVD;
            break;
        case XQC_CONN_STATE_SERVER_HANDSHAKE_SENT:
            next_state = XQC_CONN_STATE_ESTABED;
            if (conn->crypto_stream[XQC_ENC_LEV_1RTT] != NULL) {
                xqc_stream_ready_to_write(conn->crypto_stream[XQC_ENC_LEV_1RTT]);
            }
            break;
        default:
            next_state = cur_state;
        }

    } else if (encrypt_level == XQC_ENC_LEV_1RTT) {
        switch (cur_state) {
        case XQC_CONN_STATE_ESTABED:
            next_state = XQC_CONN_STATE_ESTABED;
            break;

        default:
            xqc_log(stream->stream_conn->log, XQC_LOG_ERROR, "|illegal encrypt_level:%d|",
                    encrypt_level);
            return -XQC_ELEVEL;
        }

    }else {
        xqc_log(stream->stream_conn->log, XQC_LOG_ERROR, "|illegal encrypt_level:%d|",
                encrypt_level);
        return -XQC_ELEVEL;
    }
    conn->conn_state = next_state;
    xqc_log_event(conn->log, CON_CONNECTION_STATE_UPDATED, conn);
    int ret = xqc_conn_check_handshake_complete(conn);
    if (ret < 0) {
        return ret;
    }

    xqc_stream_shutdown_read(stream);

    xqc_log(stream->stream_conn->log, XQC_LOG_DEBUG,
            "|encrypt_level:%d|cur_state:%s|next_state:%s|",
            encrypt_level, xqc_conn_state_2_str(cur_state), xqc_conn_state_2_str(next_state));
    return 0;
}

#define MIN_CRYPTO_FRAME_SIZE 8

int 
xqc_crypto_stream_send(xqc_stream_t *stream, 
    xqc_list_head_t *crypto_data_list, xqc_pkt_type_t pkt_type)
{
    size_t send_data_written = 0;
    ssize_t n_written = 0;
    xqc_packet_out_t *packet_out;
    xqc_connection_t *c = stream->stream_conn;

    xqc_list_head_t *head = crypto_data_list;
    xqc_list_head_t *pos, *next;
    xqc_hs_buffer_t *buf = NULL;

    xqc_list_for_each_safe(pos, next, head) {
        buf = xqc_list_entry(pos, xqc_hs_buffer_t, list_head);
        if (buf->data_len > 0) {
            uint64_t send_data_num = stream->stream_send_offset + buf->data_len;
            size_t offset = 0;
            while (stream->stream_send_offset < send_data_num) {
                unsigned int header_size = xqc_crypto_frame_header_size(stream->stream_send_offset,
                                                                        buf->data_len - offset);
                packet_out = xqc_write_new_packet(c, pkt_type);
                if (packet_out == NULL) {
                    return -XQC_EWRITE_PKT;
                }
                n_written = xqc_gen_crypto_frame(packet_out,
                                                 stream->stream_send_offset,
                                                 buf->data + offset,
                                                 buf->data_len - offset,
                                                 &send_data_written);
                if (n_written < 0) {
                    xqc_maybe_recycle_packet_out(packet_out, stream->stream_conn);
                    return n_written;
                }

                offset += send_data_written;
                stream->stream_send_offset += send_data_written;
                packet_out->po_used_size += n_written;

                xqc_usec_t now = xqc_monotonic_timestamp();
                packet_out->po_sent_time = now;
                xqc_long_packet_update_length(packet_out);
                xqc_log(stream->stream_conn->log, XQC_LOG_INFO,
                        "|crypto send data|pkt_num:%ui|size:%ud|sent:%d|pkt_type:%s|frame:%s|now:%ui|",
                        packet_out->po_pkt.pkt_num, packet_out->po_used_size, n_written,
                        xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type),
                        xqc_frame_type_2_str(stream->stream_conn->engine, packet_out->po_frame_types), now);

                xqc_send_queue_move_to_high_pri(&packet_out->po_list, stream->stream_conn->conn_send_queue);
            }
        }

        xqc_list_del(pos);
        xqc_free(buf);
    }

    return 0;

}

xqc_int_t
xqc_crypto_stream_on_write(xqc_stream_t *stream, void *user_data)
{
    XQC_DEBUG_PRINT
    xqc_int_t ret;

    xqc_pkt_num_space_t pns;
    xqc_pkt_type_t pkt_type;
    xqc_encrypt_level_t encrypt_level = stream->stream_encrypt_level;
    xqc_conn_state_t cur_state = stream->stream_conn->conn_state;
    xqc_conn_state_t next_state;

    xqc_connection_t *conn = stream->stream_conn;
    xqc_list_head_t *crypto_data_list = NULL;

    xqc_log(conn->log, XQC_LOG_DEBUG, "|enc_level|%d|", encrypt_level);

    if (encrypt_level == XQC_ENC_LEV_INIT) {
        pns = XQC_PNS_INIT;
        pkt_type = XQC_PTYPE_INIT;

        switch (cur_state) {
        case XQC_CONN_STATE_CLIENT_INIT:
            crypto_data_list = &conn->initial_crypto_data_list;
            next_state = XQC_CONN_STATE_CLIENT_INITIAL_SENT;
            break;

        case XQC_CONN_STATE_SERVER_INIT:
        case XQC_CONN_STATE_SERVER_INITIAL_RECVD:

            xqc_log(stream->stream_conn->log, XQC_LOG_DEBUG, "|cur_state:%d|switch|", cur_state);
            /* haven't recved enough data for client hello */
            if (conn->conn_type == XQC_CONN_TYPE_SERVER && !(conn->conn_flag & XQC_CONN_FLAG_TLS_CH_RECVD)) {
                return XQC_OK;
            }

            crypto_data_list = &conn->initial_crypto_data_list;
            if (conn->crypto_stream[XQC_ENC_LEV_HSK] != NULL) {
                xqc_stream_ready_to_write(conn->crypto_stream[XQC_ENC_LEV_HSK]);
            }
            next_state = XQC_CONN_STATE_SERVER_INITIAL_SENT;
            break;

        default:
            next_state = cur_state;
        }

    } else if (encrypt_level == XQC_ENC_LEV_HSK) {
        pns = XQC_PNS_HSK;
        pkt_type = XQC_PTYPE_HSK;

        switch (cur_state) {
        case XQC_CONN_STATE_CLIENT_HANDSHAKE_RECVD:
            crypto_data_list = &conn->hsk_crypto_data_list;
            if (conn->conn_flag & XQC_CONN_FLAG_TLS_HSK_COMPLETED) {
                next_state = XQC_CONN_STATE_ESTABED;

            } else {
                next_state = cur_state;
            }
            break;

        case XQC_CONN_STATE_SERVER_INITIAL_SENT:
        case XQC_CONN_STATE_SERVER_INITIAL_RECVD:
            crypto_data_list = &conn->hsk_crypto_data_list;
            next_state = XQC_CONN_STATE_SERVER_HANDSHAKE_SENT;
            break;
        default:
            next_state = cur_state;
        }

    } else if (encrypt_level == XQC_ENC_LEV_1RTT) {
        pkt_type = XQC_PTYPE_SHORT_HEADER;
        switch (cur_state) {

        case XQC_CONN_STATE_ESTABED:
            crypto_data_list = &conn->application_crypto_data_list;
            next_state = cur_state;
            break;
        default:
            xqc_log(stream->stream_conn->log, XQC_LOG_ERROR, "|illegal encrypt_level:%d|",
                    encrypt_level);
            return -XQC_ELEVEL;
        }

    } else {
        xqc_log(stream->stream_conn->log, XQC_LOG_ERROR, "|illegal encrypt_level:%d|",
                encrypt_level);
        return -XQC_ELEVEL;
    }

    if (crypto_data_list != NULL) {
        int ret = xqc_crypto_stream_send(stream, crypto_data_list, pkt_type);
        if (ret < 0) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_crypto_stream_send error|");
            return ret;
        }
    }


    xqc_stream_shutdown_write(stream);

    conn->conn_state = next_state;
    xqc_log_event(conn->log, CON_CONNECTION_STATE_UPDATED, conn);
    
    ret = xqc_conn_check_handshake_complete(conn);
    if (ret < 0) {
        return ret;
    }

    xqc_log(stream->stream_conn->log, XQC_LOG_DEBUG,
            "|encrypt_level:%d|cur_state:%s|next_state:%s|",
            encrypt_level, xqc_conn_state_2_str(cur_state), xqc_conn_state_2_str(next_state));
    return 0;
}

xqc_stream_callbacks_t crypto_stream_callback = {
    .stream_read_notify = xqc_crypto_stream_on_read,
    .stream_write_notify = xqc_crypto_stream_on_write,
};

xqc_stream_t *
xqc_create_crypto_stream(xqc_connection_t *conn, xqc_encrypt_level_t encrypt_level, void *user_data)
{
    xqc_log(conn->log, XQC_LOG_DEBUG, "|encrypt_level:%d|cur_state:%s|",
            encrypt_level, xqc_conn_state_2_str(conn->conn_state));

    xqc_stream_t *stream = xqc_pcalloc(conn->conn_pool, sizeof(xqc_stream_t));
    if (stream == NULL) {
        return NULL;
    }

    memset(stream, 0, sizeof(xqc_stream_t));

    stream->stream_type = conn->conn_type == XQC_CONN_TYPE_CLIENT ? XQC_CLI_BID : XQC_SVR_BID;
    stream->stream_encrypt_level = encrypt_level;
    stream->stream_conn = conn;
    stream->stream_if = &crypto_stream_callback;
    stream->user_data = user_data;

    xqc_init_list_head(&stream->stream_data_in.frames_tailq);
    xqc_init_list_head(&stream->stream_write_buff_list.write_buff_list);

    if (!(conn->conn_type == XQC_CONN_TYPE_SERVER)) {
        xqc_stream_ready_to_write(stream);
    }

    return stream;
}

void
xqc_destroy_crypto_stream(xqc_connection_t *conn, xqc_stream_t *stream)
{
    xqc_log(conn->log, XQC_LOG_DEBUG, "|destroy crypto stream|encrypt_level:%d"
            "|cur_state:%s|", stream->stream_encrypt_level,
            xqc_conn_state_2_str(conn->conn_state));

    xqc_destroy_frame_list(&stream->stream_data_in.frames_tailq);
    xqc_destroy_write_buff_list(&stream->stream_write_buff_list.write_buff_list);

    /* TODO: pfree is needed */
}

ssize_t 
xqc_stream_recv(xqc_stream_t *stream, unsigned char *recv_buf, size_t recv_buf_size, uint8_t *fin)
{
    xqc_list_head_t *pos, *next;
    xqc_stream_frame_t *stream_frame = NULL;
    size_t read = 0;
    size_t frame_left;
    *fin = 0;

    if (stream->stream_state_recv >= XQC_RECV_STREAM_ST_RESET_RECVD) {
        stream->stream_state_recv = XQC_RECV_STREAM_ST_RESET_READ;
        xqc_stream_shutdown_read(stream);
        xqc_stream_maybe_need_close(stream);
        return -XQC_ESTREAM_RESET;
    }

    xqc_list_for_each_safe(pos, next, &stream->stream_data_in.frames_tailq) {
        stream_frame = xqc_list_entry(pos, xqc_stream_frame_t, sf_list);

        if (stream_frame->data_offset > stream->stream_data_in.merged_offset_end) {
            break;
        }

        if (read >= recv_buf_size) {
            break;
        }
        /*
         *     |------------------------|
         *        |----------|
         */

        /* already read */
        if (stream_frame->data_offset + stream_frame->data_length < stream->stream_data_in.next_read_offset) {
            /* free frame */
            xqc_list_del_init(&stream_frame->sf_list);
            xqc_free(stream_frame->data);
            xqc_free(stream_frame);
            continue;
        }

        /*
         *        |----------|
         *             |-------|
         */
        if (stream_frame->data_offset < stream->stream_data_in.next_read_offset) {
            uint64_t offset = stream->stream_data_in.next_read_offset - stream_frame->data_offset;
            stream_frame->next_read_offset = xqc_max(stream_frame->next_read_offset, offset);
        }

        frame_left = stream_frame->data_length - stream_frame->next_read_offset;

        if (read + frame_left <= recv_buf_size) {
            memcpy(recv_buf + read, stream_frame->data + stream_frame->next_read_offset, frame_left);
            stream->stream_data_in.next_read_offset += frame_left;
            stream_frame->next_read_offset = stream_frame->data_length;
            read += frame_left;
            /* free frame */
            xqc_list_del_init(&stream_frame->sf_list);
            xqc_free(stream_frame->data);
            xqc_free(stream_frame);

        } else {
            memcpy(recv_buf + read, stream_frame->data + stream_frame->next_read_offset, recv_buf_size - read);
            stream_frame->next_read_offset += recv_buf_size - read;
            stream->stream_data_in.next_read_offset += recv_buf_size - read;
            read = recv_buf_size;
            break;
        }

    }

    if (stream->stream_data_in.stream_determined
        && stream->stream_data_in.next_read_offset == stream->stream_data_in.stream_length) 
    {
        *fin = 1;
        stream->stream_stats.peer_fin_read_time = xqc_monotonic_timestamp();
        if (stream->stream_state_recv == XQC_RECV_STREAM_ST_DATA_RECVD) {
            xqc_stream_recv_state_update(stream, XQC_RECV_STREAM_ST_DATA_READ);
            xqc_stream_maybe_need_close(stream);
        }
    }

    stream->stream_conn->conn_flow_ctl.fc_data_read += read;

    xqc_log_event(stream->stream_conn->log, TRA_STREAM_DATA_MOVED, stream, 1, read,
                  recv_buf_size, *fin, 0, 0, 0, 0);
    xqc_stream_shutdown_read(stream);

    int ret = xqc_stream_do_recv_flow_ctl(stream);
    if (ret) {
        xqc_log(stream->stream_conn->log, XQC_LOG_ERROR, "|xqc_stream_do_recv_flow_ctl error|stream_id:%ui|", stream->stream_id);
        return ret;
    }

    return (read == 0 && *fin == 0) ? -XQC_EAGAIN : read;
}


ssize_t
xqc_stream_send(xqc_stream_t *stream, unsigned char *send_data, size_t send_data_size, uint8_t fin)
{
    xqc_connection_t *conn = stream->stream_conn;
    if (conn->conn_state >= XQC_CONN_STATE_CLOSING) {
        xqc_conn_log(conn, XQC_LOG_INFO, "|conn closing, cannot send|stream_id:%ui|", stream->stream_id);
        xqc_stream_shutdown_write(stream);
        return -XQC_CLOSING;
    }
    if (stream->stream_state_send >= XQC_SEND_STREAM_ST_RESET_SENT) {
        xqc_conn_log(conn, XQC_LOG_INFO, "|stream reset sent, cannot send|stream_id:%ui|", stream->stream_id);
        xqc_stream_shutdown_write(stream);
        return -XQC_ESTREAM_RESET;
    }
    if (stream->stream_flag & XQC_STREAM_FLAG_FIN_WRITE) {
        xqc_conn_log(conn, XQC_LOG_WARN, "|fin write, cannot send|stream_id:%ui|", stream->stream_id);
        xqc_stream_shutdown_write(stream);
        return 0;
    }
    int ret;
    xqc_stream_ready_to_write(stream);
    size_t send_data_written = 0;
    size_t offset = 0; /* the written offset in send_data */
    uint8_t fin_only = fin && !send_data_size;
    uint8_t fin_only_done = 0;
    xqc_pkt_type_t pkt_type = XQC_PTYPE_SHORT_HEADER;
    int support_0rtt = xqc_conn_is_ready_to_send_early_data(conn);
    int buff_1rtt = 0;
    int check_app_limit = 1;


    if (!(conn->conn_flag & XQC_CONN_FLAG_CAN_SEND_1RTT)) {
        if ((conn->conn_type == XQC_CONN_TYPE_CLIENT) && support_0rtt
            && xqc_conn_is_ready_to_send_early_data(conn))
        {
            pkt_type = XQC_PTYPE_0RTT;
            conn->conn_flag |= XQC_CONN_FLAG_HAS_0RTT;
            stream->stream_flag |= XQC_STREAM_FLAG_HAS_0RTT;

        } else {
            xqc_log(conn->log, XQC_LOG_DEBUG, "|blocked by no 0RTT support|");
            ret = -XQC_EAGAIN;
            goto do_buff;
        }
    }

    while (offset < send_data_size || fin_only) {

        if (pkt_type == XQC_PTYPE_SHORT_HEADER) {
            ret = xqc_stream_do_send_flow_ctl(stream);
            if (ret) {
                ret = -XQC_EAGAIN;
                goto do_buff;
            }
        }

        if (!xqc_send_queue_can_write(conn->conn_send_queue)) {
            conn->conn_send_queue->sndq_full = XQC_TRUE;
            xqc_log(conn->log, XQC_LOG_DEBUG, "|too many packets used|sndq_packets_used:%ud|", conn->conn_send_queue->sndq_packets_used);
            ret = -XQC_EAGAIN;
            goto do_buff;
        }


        if (pkt_type == XQC_PTYPE_0RTT && conn->zero_rtt_count >= XQC_PACKET_0RTT_MAX_COUNT) {
            xqc_log(conn->log, XQC_LOG_DEBUG, "|too many 0rtt packets|zero_rtt_count:%ud|", conn->zero_rtt_count);
            ret = -XQC_EAGAIN;
            goto do_buff;
        }

        if (check_app_limit) {
            xqc_conn_check_app_limit(conn);
            check_app_limit = 0;
        }

        ret = xqc_write_stream_frame_to_packet(conn, stream, pkt_type,
                                               fin,
                                               send_data + offset,
                                               send_data_size - offset,
                                               &send_data_written);
        if (ret) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_stream_frame_to_packet error|");
            XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
            return ret;
        }

        offset += send_data_written;
        if (fin_only) {
            fin_only_done = 1;
            break;
        }
    }

    xqc_stream_shutdown_write(stream);

do_buff:
    /* 0RTT failure requires fallback to 1RTT, save the original send data */
    if (pkt_type == XQC_PTYPE_0RTT) {
        /* fin not yet written to packet */
        if (offset != send_data_size && fin) {
            fin = 0;
        }

        /* if no data or fin is written, no buff required */
        if (offset > 0 || fin_only) {
            xqc_stream_buff_data(stream, send_data, offset, fin);
        }
    }

    if ((!conn->first_data_send_time) && ((stream->stream_type == XQC_CLI_BID) || (stream->stream_type == XQC_SVR_BID))) {
        conn->first_data_send_time = xqc_monotonic_timestamp();
    }


    xqc_log(conn->log, XQC_LOG_INFO, "|ret:%d|stream_id:%ui|stream_send_offset:%ui|pkt_type:%s|buff_1rtt:%d|"
                                      "send_data_size:%uz|offset:%uz|fin:%d|stream_flag:%d|conn:%p|conn_state:%s|flag:%s|",
            ret, stream->stream_id, stream->stream_send_offset, xqc_pkt_type_2_str(pkt_type), buff_1rtt,
            send_data_size, offset, fin, stream->stream_flag, conn, xqc_conn_state_2_str(conn->conn_state),
            xqc_conn_flag_2_str(conn, conn->conn_flag));
    xqc_log_event(conn->log, TRA_STREAM_DATA_MOVED, stream, 0, send_data_size, 0, fin, ret, pkt_type,
                  buff_1rtt, offset);

    if (!(conn->conn_flag & XQC_CONN_FLAG_TICKING)) {
        if (0 == xqc_conns_pq_push(conn->engine->conns_active_pq, conn, conn->last_ticked_time)) {
            conn->conn_flag |= XQC_CONN_FLAG_TICKING;
        }
    }

    xqc_stream_record_trans_state(stream, XQC_TRUE);

    /* application layer call the main logic */
    if (!(stream->stream_flag & XQC_STREAM_FLAG_HAS_H3)) {
        xqc_engine_main_logic_internal(conn->engine);
    }

    if (offset == 0 && !fin_only_done) {
        if (ret == -XQC_EAGAIN) {
            return -XQC_EAGAIN; /* -XQC_EAGAIN not means error */
        } else {
            XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
            return ret;
        }
    }
    return offset;
}

ssize_t
xqc_stream_buff_data(xqc_stream_t *stream, unsigned char *send_data, size_t send_data_size, uint8_t fin)
{
    xqc_connection_t *conn = stream->stream_conn;
    xqc_stream_write_buff_list_t *buff_list = &stream->stream_write_buff_list;
    xqc_stream_write_buff_t *write_buff = xqc_calloc(1, sizeof(xqc_stream_write_buff_t));
    if (!write_buff) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_calloc error|");
        return -XQC_EMALLOC;
    }

    write_buff->sw_data = xqc_malloc(send_data_size);
    if (write_buff->sw_data == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_calloc sw_data error|");
        xqc_free(write_buff);
        return -XQC_EMALLOC;
    }
    memcpy(write_buff->sw_data, send_data, send_data_size);
    write_buff->data_length = send_data_size;
    write_buff->data_offset += buff_list->total_len;
    write_buff->next_write_offset = 0;
    write_buff->fin = fin;

    buff_list->total_len += send_data_size;
    xqc_list_add_tail(&write_buff->sw_list, &buff_list->write_buff_list);

    xqc_log(conn->log, XQC_LOG_DEBUG, "|size:%uz|", send_data_size);
    return send_data_size;
}

int
xqc_stream_write_buffed_data_to_packets(xqc_stream_t *stream)
{
    xqc_connection_t *conn = stream->stream_conn;
    xqc_pkt_type_t pkt_type = XQC_PTYPE_SHORT_HEADER;
    xqc_stream_write_buff_list_t *buff_list = &stream->stream_write_buff_list;
    xqc_stream_write_buff_t *write_buff;
    xqc_list_head_t *pos, *next;
    unsigned char *send_data;
    size_t send_data_size;
    size_t offset;
    size_t send_data_written;
    int ret;
    unsigned char fin;

    xqc_list_for_each_safe(pos, next, &buff_list->write_buff_list) {
        write_buff = xqc_list_entry(pos, xqc_stream_write_buff_t, sw_list);
        send_data_size = write_buff->data_length;
        offset = 0;
        fin = write_buff->fin;
        send_data = write_buff->sw_data;
        uint8_t fin_only = fin && send_data_size == 0;

        while (offset < send_data_size || fin_only) {

            ret = xqc_write_stream_frame_to_packet(conn, stream, pkt_type,
                                                    fin,
                                                    send_data + offset,
                                                    send_data_size - offset,
                                                    &send_data_written);
            if (ret) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_stream_frame_to_packet error|");
                return ret;
            }
            offset += send_data_written;
            xqc_log(conn->log, XQC_LOG_DEBUG, 
                    "|resend 1RTT stream packets|stream_id:%ui|offset:%uz|fin:%d|",
                    stream->stream_id, offset, fin);
            if (fin_only) {
                break;
            }
        }

        xqc_list_del_init(&write_buff->sw_list);
        xqc_destroy_write_buff(write_buff);
    }
    xqc_log(conn->log, XQC_LOG_DEBUG, "|write 1RTT packets|");
    return XQC_OK;
}

void
xqc_process_write_streams(xqc_connection_t *conn)
{
    XQC_DEBUG_PRINT
    xqc_int_t ret;
    xqc_stream_t *stream;
    xqc_list_head_t *pos, *next;
    int cnt = 0;

    xqc_list_for_each_safe(pos, next, &conn->conn_write_streams) {
        stream = xqc_list_entry(pos, xqc_stream_t, write_stream_list);
        if (stream->stream_flag & XQC_STREAM_FLAG_DATA_BLOCKED
            || conn->conn_flag & XQC_CONN_FLAG_DATA_BLOCKED) 
        {
            xqc_log(conn->log, XQC_LOG_DEBUG, "|DATA_BLOCKED|stream_id:%ui|conn:%p|",
                    stream->stream_id, stream->stream_conn);
            continue;
        }
        xqc_log(conn->log, XQC_LOG_DEBUG, "|stream_write_notify|flag:%d|stream_id:%ui|conn:%p|cnt:%d|",
                stream->stream_flag, stream->stream_id, stream->stream_conn, cnt++);
        if (stream->stream_if->stream_write_notify == NULL) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|stream_write_notify is NULL|flag:%d|stream_id:%ui|conn:%p|",
                    stream->stream_flag, stream->stream_id, stream->stream_conn);
            XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
            return;
        }
        ret = stream->stream_if->stream_write_notify(stream, stream->user_data);
        if (ret < 0) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|stream_write_notify err:%d|flag:%d|stream_id:%ui|conn:%p|",
                    ret, stream->stream_flag, stream->stream_id, stream->stream_conn);
            XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
        }
    }
}

void
xqc_process_read_streams(xqc_connection_t *conn)
{
    XQC_DEBUG_PRINT
    xqc_int_t ret;
    xqc_stream_t *stream;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &conn->conn_read_streams) {
        if (pos->next == pos) {
            xqc_log(conn->log, XQC_LOG_FATAL, "|pos:%p|conn:%p|",
                     pos, conn);
            XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
            return;
        }
        stream = xqc_list_entry(pos, xqc_stream_t, read_stream_list);
        xqc_log(conn->log, XQC_LOG_DEBUG, "|stream_read_notify|flag:%d|stream_id:%ui|conn:%p|",
                stream->stream_flag, stream->stream_id, stream->stream_conn);
        if (stream->stream_if->stream_read_notify == NULL) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|stream_read_notify is NULL|flag:%d|stream_id:%ui|conn:%p|",
                    stream->stream_flag, stream->stream_id, stream->stream_conn);
            XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
            return;
        }
        ret = stream->stream_if->stream_read_notify(stream, stream->user_data);
        if (ret < 0) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|stream_read_notify err:%d|flag:%d|stream_id:%ui|conn:%p|",
                    ret, stream->stream_flag, stream->stream_id, stream->stream_conn);
            XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
        }
    }
}

void
xqc_process_crypto_write_streams(xqc_connection_t *conn)
{
    XQC_DEBUG_PRINT
    xqc_int_t ret;
    xqc_stream_t *stream;
    for (int i = XQC_ENC_LEV_INIT; i < XQC_ENC_LEV_MAX; i++) {
        stream = conn->crypto_stream[i];
        if (stream && (stream->stream_flag & XQC_STREAM_FLAG_READY_TO_WRITE)) {
            xqc_log(conn->log, XQC_LOG_DEBUG, "|");
            ret = stream->stream_if->stream_write_notify(stream, stream->user_data);
            if (ret < 0) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|stream_write_notify crypto err:%d|", ret);
                XQC_CONN_ERR(conn, TRA_CRYPTO_ERROR);
            }
        }
    }
}

void
xqc_process_crypto_read_streams(xqc_connection_t *conn)
{
    XQC_DEBUG_PRINT
    xqc_int_t ret;
    xqc_stream_t *stream;
    for (int i = XQC_ENC_LEV_INIT; i < XQC_ENC_LEV_MAX; i++) {
        stream = conn->crypto_stream[i];
        if (stream && (stream->stream_flag & XQC_STREAM_FLAG_READY_TO_READ)) {
            ret = stream->stream_if->stream_read_notify(stream, stream->user_data);
            if (ret < 0) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|stream_read_notify crypto err:%d|", ret);
                XQC_CONN_ERR(conn, TRA_CRYPTO_ERROR);
            }
        }
    }
}

void
xqc_destroy_stream_frame(xqc_stream_frame_t *stream_frame)
{
    if (stream_frame) {
        if (stream_frame->data) {
            xqc_free(stream_frame->data);
        }

        xqc_free(stream_frame);
    }
}

void
xqc_destroy_write_buff(xqc_stream_write_buff_t *write_buff)
{
    xqc_free(write_buff->sw_data);
    xqc_free(write_buff);
}

void
xqc_destroy_frame_list(xqc_list_head_t *head)
{
    xqc_list_head_t *pos, *next;
    xqc_stream_frame_t *stream_frame;
    xqc_list_for_each_safe(pos, next, head) {
        stream_frame = xqc_list_entry(pos, xqc_stream_frame_t, sf_list);
        xqc_list_del_init(pos);
        xqc_destroy_stream_frame(stream_frame);
    }
}

void
xqc_destroy_write_buff_list(xqc_list_head_t *head)
{
    xqc_list_head_t *pos, *next;
    xqc_stream_write_buff_t *write_buff;
    xqc_list_for_each_safe(pos, next, head) {
        write_buff = xqc_list_entry(pos, xqc_stream_write_buff_t, sw_list);
        xqc_list_del_init(pos);
        xqc_destroy_write_buff(write_buff);
    }
}


/* used to count reference */
void
xqc_stream_refcnt_add(xqc_stream_t *stream)
{
    stream->stream_refcnt++;
}

void
xqc_stream_refcnt_del(xqc_stream_t *stream)
{
    stream->stream_refcnt--;
}


void
xqc_stream_send_state_update(xqc_stream_t *stream, xqc_send_stream_state_t state)
{
    xqc_log_event(stream->stream_conn->log, TRA_STREAM_STATE_UPDATED, stream, XQC_LOG_STREAM_SEND, state);
    stream->stream_state_send = state;
}

void
xqc_stream_recv_state_update(xqc_stream_t *stream, xqc_recv_stream_state_t state)
{
    xqc_log_event(stream->stream_conn->log, TRA_STREAM_STATE_UPDATED, stream, XQC_LOG_STREAM_RECV, state);
    stream->stream_state_recv = state;
}

xqc_stream_direction_t
xqc_stream_get_direction(xqc_stream_t *strm)
{
    return xqc_stream_is_uni(strm->stream_id)
        ? XQC_STREAM_UNI : XQC_STREAM_BIDI;
}

void
xqc_stream_set_multipath_usage(xqc_stream_t *stream, uint8_t schedule, uint8_t reinject)
{
    stream->stream_mp_usage_schedule = schedule;
    stream->stream_mp_usage_reinject = reinject;
}

void
xqc_stream_closing(xqc_stream_t *stream, xqc_int_t err)
{
    if (stream->stream_if->stream_closing_notify) {
        stream->stream_if->stream_closing_notify(stream, err,
                                                 stream->user_data);
    }
}
