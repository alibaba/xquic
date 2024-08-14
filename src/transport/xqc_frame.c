/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <xquic/xquic_typedef.h>
#include "src/http3/xqc_h3_conn.h"
#include "src/common/xqc_log.h"
#include "src/transport/xqc_frame.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/transport/xqc_engine.h"
#include "src/common/xqc_log.h"
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_defs.h"
#include "src/transport/xqc_utils.h"
#include "src/tls/xqc_tls.h"



static const char * const frame_type_2_str[XQC_FRAME_NUM] = {
    [XQC_FRAME_PADDING]              = "PADDING",
    [XQC_FRAME_PING]                 = "PING",
    [XQC_FRAME_ACK]                  = "ACK",
    [XQC_FRAME_RESET_STREAM]         = "RESET_STREAM",
    [XQC_FRAME_STOP_SENDING]         = "STOP_SENDING",
    [XQC_FRAME_CRYPTO]               = "CRYPTO",
    [XQC_FRAME_NEW_TOKEN]            = "NEW_TOKEN",
    [XQC_FRAME_STREAM]               = "STREAM",
    [XQC_FRAME_MAX_DATA]             = "MAX_DATA",
    [XQC_FRAME_MAX_STREAM_DATA]      = "MAX_STREAM_DATA",
    [XQC_FRAME_MAX_STREAMS]          = "MAX_STREAMS",
    [XQC_FRAME_DATA_BLOCKED]         = "DATA_BLOCKED",
    [XQC_FRAME_STREAM_DATA_BLOCKED]  = "STREAM_DATA_BLOCKED",
    [XQC_FRAME_STREAMS_BLOCKED]      = "STREAMS_BLOCKED",
    [XQC_FRAME_NEW_CONNECTION_ID]    = "NEW_CONNECTION_ID",
    [XQC_FRAME_RETIRE_CONNECTION_ID] = "RETIRE_CONNECTION_ID",
    [XQC_FRAME_PATH_CHALLENGE]       = "PATH_CHALLENGE",
    [XQC_FRAME_PATH_RESPONSE]        = "PATH_RESPONSE",
    [XQC_FRAME_CONNECTION_CLOSE]     = "CONNECTION_CLOSE",
    [XQC_FRAME_HANDSHAKE_DONE]       = "HANDSHAKE_DONE",
    [XQC_FRAME_ACK_MP]               = "ACK_MP",
    [XQC_FRAME_PATH_ABANDON]         = "PATH_ABANDON",
    [XQC_FRAME_PATH_STATUS]          = "PATH_STATUS",
    [XQC_FRAME_DATAGRAM]             = "DATAGRAM",
    [XQC_FRAME_Extension]            = "Extension",
};

const char *
xqc_frame_type_2_str(xqc_engine_t *engine, xqc_frame_type_bit_t type_bit)
{
    engine->frame_type_buf[0] = '\0';
    size_t pos = 0;
    int wsize;
    for (int i = 0; i < XQC_FRAME_NUM; i++) {
        if (type_bit & 1 << i) {
            wsize = snprintf(engine->frame_type_buf + pos, sizeof(engine->frame_type_buf) - pos, "%s ",
                             frame_type_2_str[i]);
            if (wsize < 0 || wsize >= sizeof(engine->frame_type_buf) - pos) {
                break;
            }
            pos += wsize;
        }
    }
    return engine->frame_type_buf;
}

unsigned int
xqc_stream_frame_header_size(xqc_stream_id_t stream_id, uint64_t offset, size_t length)
{
    return 1 + xqc_vint_len_by_val(stream_id) +
            offset ? xqc_vint_len_by_val(offset) : 0 +
            xqc_vint_len_by_val(length);
}

unsigned int
xqc_crypto_frame_header_size(uint64_t offset, size_t length)
{
    return 1 +
           xqc_vint_len_by_val(offset) +
           xqc_vint_len_by_val(length);

}

xqc_int_t
xqc_insert_stream_frame(xqc_connection_t *conn, xqc_stream_t *stream, xqc_stream_frame_t *new_frame)
{

    /* insert xqc_stream_frame_t into stream->stream_data_in.frames_tailq in order of offset */
    unsigned char inserted = 0;
    xqc_list_head_t *pos;
    xqc_stream_frame_t *frame;

    xqc_list_for_each_reverse(pos, &stream->stream_data_in.frames_tailq) {
        frame = xqc_list_entry(pos, xqc_stream_frame_t, sf_list);

        if (xqc_max(frame->data_offset, new_frame->data_offset) <
            xqc_min(frame->data_offset + frame->data_length, new_frame->data_offset + new_frame->data_length))
        {
            /*
             * overlap
             *      |-----------|   frame
             * |-----------|        new_frame
             *        |------------|new_frame
             *        |----|        new_frame  do not insert
             * |-------------------|new_frame
             */
            xqc_log(conn->log, XQC_LOG_INFO, "|is overlap|offset:%ui|new_offset:%ui|len:%ud|new_len:%ud|",
                    frame->data_offset, new_frame->data_offset, frame->data_length, new_frame->data_length);
        }

        if (new_frame->data_offset >= frame->data_offset && new_frame->data_length > 0
            && new_frame->data_offset + new_frame->data_length <= frame->data_offset + frame->data_length)
        {
            xqc_log(conn->log, XQC_LOG_INFO, "|already recvd|offset:%ui|new_offset:%ui|len:%ud|new_len:%ud|",
                    frame->data_offset, new_frame->data_offset, frame->data_length, new_frame->data_length);
            return -XQC_EDUP_FRAME;
        }

        if (new_frame->data_offset >= frame->data_offset) {
            xqc_list_add(&new_frame->sf_list, pos);
            inserted = 1;
            break;
        }
    }

    if (!inserted) {
        xqc_list_add(&new_frame->sf_list, &stream->stream_data_in.frames_tailq);
    }

    /*
     * can merge
     * |--------------|merged_offset_end
     *          |----------|
     *                |--------|
     */
    /* merge */
    if (stream->stream_data_in.merged_offset_end >= new_frame->data_offset
        && stream->stream_data_in.merged_offset_end < new_frame->data_offset + new_frame->data_length)
    {
        stream->stream_data_in.merged_offset_end = new_frame->data_offset + new_frame->data_length;
        xqc_log(conn->log, XQC_LOG_DEBUG, "|merge left|merged_offset_end:%ui|new_offset:%ui|new_len:%ud|",
                stream->stream_data_in.merged_offset_end, new_frame->data_offset, new_frame->data_length);

        pos = new_frame->sf_list.next;
        xqc_list_for_each_from(pos, &stream->stream_data_in.frames_tailq) {
            frame = xqc_list_entry(pos, xqc_stream_frame_t, sf_list);
            if (stream->stream_data_in.merged_offset_end >= frame->data_offset) {
                stream->stream_data_in.merged_offset_end = xqc_max(frame->data_offset + frame->data_length, 
                                                                   stream->stream_data_in.merged_offset_end);
                xqc_log(conn->log, XQC_LOG_DEBUG, "|merge right|merged_offset_end:%ui|offset:%ui|len:%ud|",
                        stream->stream_data_in.merged_offset_end, frame->data_offset, frame->data_length);
            } else {
                /* There is a hole, break */
                break;
            }
        }
    }

    return XQC_OK;
}


xqc_int_t
xqc_process_frames(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret;
    unsigned char *last_pos = NULL;

    while (packet_in->pos < packet_in->last) {
        last_pos = packet_in->pos;

        unsigned char *pos = packet_in->pos;
        unsigned char *end = packet_in->last;
        ssize_t frame_type_len;
        uint64_t frame_type = 0;
        frame_type_len = xqc_vint_read(pos, end, &frame_type);
        if (frame_type_len < 0) {
            return -XQC_EVINTREAD;
        }

        if (conn->conn_state == XQC_CONN_STATE_CLOSING) {
            xqc_log(conn->log, XQC_LOG_DEBUG, "|closing state|frame_type:%ui|",
                    frame_type);
            /* respond connection close when recv any packet */
            if (frame_type != 0x1c && frame_type != 0x1d) {
                xqc_conn_immediate_close(conn);
                packet_in->pos = packet_in->last;
                return XQC_OK;
            }

        } else if (conn->conn_state >= XQC_CONN_STATE_DRAINING) {
            xqc_log(conn->log, XQC_LOG_DEBUG, "|draining state, skip|");
            /* do not respond any packet */
            packet_in->pos = packet_in->last;
            return XQC_OK;
        }

        xqc_log(conn->log, XQC_LOG_DEBUG, "|frame_type:%ui|", frame_type);

        switch (frame_type) {

        case 0x00:
            ret = xqc_process_padding_frame(conn, packet_in);
            break;
        case 0x01:
            ret = xqc_process_ping_frame(conn, packet_in);
            break;
        case 0x02:
        case 0x03:
            ret = xqc_process_ack_frame(conn, packet_in);
            break;
        case 0x04:
            ret = xqc_process_reset_stream_frame(conn, packet_in);
            break;
        case 0x05:
            ret = xqc_process_stop_sending_frame(conn, packet_in);
            break;
        case 0x06:
            ret = xqc_process_crypto_frame(conn, packet_in);
            break;
        case 0x07:
            ret = xqc_process_new_token_frame(conn, packet_in);
            break;
        case 0x08:
        case 0x09:
        case 0x0a:
        case 0x0b:
        case 0x0c:
        case 0x0d:
        case 0x0e:
        case 0x0f:
            ret = xqc_process_stream_frame(conn, packet_in);
            break;
        case 0x10:
            ret = xqc_process_max_data_frame(conn, packet_in);
            break;
        case 0x11:
            ret = xqc_process_max_stream_data_frame(conn, packet_in);
            break;
        case 0x12:
        case 0x13:
            ret = xqc_process_max_streams_frame(conn, packet_in);
            break;
        case 0x14:
            ret = xqc_process_data_blocked_frame(conn, packet_in);
            break;
        case 0x15:
            ret = xqc_process_stream_data_blocked_frame(conn, packet_in);
            break;
        case 0x16: 
        case 0x17:
            ret = xqc_process_streams_blocked_frame(conn, packet_in);
            break;
        case 0x18:
            ret = xqc_process_new_conn_id_frame(conn, packet_in);
            break;
        case 0x19:
            ret = xqc_process_retire_conn_id_frame(conn, packet_in);
            break;
        case 0x1a:
            ret = xqc_process_path_challenge_frame(conn, packet_in);
            break;
        case 0x1b:
            ret = xqc_process_path_response_frame(conn, packet_in);
            break;
        case 0x1c:
        case 0x1d:
            ret = xqc_process_conn_close_frame(conn, packet_in);
            break;
        case 0x1e:
            ret = xqc_process_handshake_done_frame(conn, packet_in);
            break;
        case 0x30:
        case 0x31:
            ret = xqc_process_datagram_frame(conn, packet_in);
            break;
        case 0xbaba00:
        case 0xbaba01:
            if (conn->conn_settings.multipath_version == XQC_MULTIPATH_04) {
                ret = xqc_process_ack_mp_frame(conn, packet_in);
            } else {
                xqc_log(conn->log, XQC_LOG_ERROR, "|receive wrong mp version mp_ack frame or cannot process frame in mp version 04|");
                ret = -XQC_EMP_INVALID_MP_VERTION;
            }
            break;
        case 0x15228c00:
        case 0x15228c01:
            if (conn->conn_settings.multipath_version >= XQC_MULTIPATH_05) {
                ret = xqc_process_ack_mp_frame(conn, packet_in);

            } else {
                xqc_log(conn->log, XQC_LOG_ERROR, "|receive wrong mp version mp_ack frame or cannot process frame in mp version 05|");
                ret = -XQC_EMP_INVALID_MP_VERTION;
            }
            break;
        case 0xbaba05:
            if (conn->conn_settings.multipath_version == XQC_MULTIPATH_04) {
                ret = xqc_process_path_abandon_frame(conn, packet_in);
            } else {
                xqc_log(conn->log, XQC_LOG_ERROR, "|receive wrong mp version path_abandon frame or cannot process frame in mp version 04|");
                ret = -XQC_EMP_INVALID_MP_VERTION;
            }
            break;
        case 0x15228c05:
            if (conn->conn_settings.multipath_version >= XQC_MULTIPATH_05) {
                ret = xqc_process_path_abandon_frame(conn, packet_in);

            } else {
                xqc_log(conn->log, XQC_LOG_ERROR, "|receive wrong mp version path_abandon frame or cannot process frame in mp version 05|");
                ret = -XQC_EMP_INVALID_MP_VERTION;
            }
            break;
        case 0xbaba06:
            if (conn->conn_settings.multipath_version == XQC_MULTIPATH_04) {
                ret = xqc_process_path_status_frame(conn, packet_in);
            } else {
                xqc_log(conn->log, XQC_LOG_ERROR, "|receive wrong mp version path_status frame or cannot process frame in mp version 04|");
                ret = -XQC_EMP_INVALID_MP_VERTION;
            }
            break;
        case 0x15228c06:
            if (conn->conn_settings.multipath_version == XQC_MULTIPATH_05) {
                ret = xqc_process_path_status_frame(conn, packet_in);
                
            } else {
                xqc_log(conn->log, XQC_LOG_ERROR, "|receive wrong mp version path_status frame or cannot process frame in mp version 05|");
                ret = -XQC_EMP_INVALID_MP_VERTION;
            }
            break;
        case 0x15228c07:
            if (conn->conn_settings.multipath_version == XQC_MULTIPATH_06) {
                ret = xqc_process_path_standby_frame(conn, packet_in);

            } else {
                xqc_log(conn->log, XQC_LOG_ERROR, "|receive wrong mp version path_status frame or cannot process frame in mp version 06|");
                ret = -XQC_EMP_INVALID_MP_VERTION;
            }
            break;
        case 0x15228c08:
            if (conn->conn_settings.multipath_version == XQC_MULTIPATH_06) {
                ret = xqc_process_path_available_frame(conn, packet_in);

            } else {
                xqc_log(conn->log, XQC_LOG_ERROR, "|receive wrong mp version path_status frame or cannot process frame in mp version 06|");
                ret = -XQC_EMP_INVALID_MP_VERTION;
            }
            break;

#ifdef XQC_ENABLE_FEC
        case 0xfec5:
            if (conn->conn_settings.enable_decode_fec
                && conn->conn_settings.fec_params.fec_decoder_scheme != 0)
            {
                ret = xqc_process_sid_frame(conn, packet_in);
            
            } else {
                xqc_log(conn->log, XQC_LOG_ERROR, "|fec negotiation failed but still received fec packet.");
                ret = -XQC_EFEC_NOT_SUPPORT_FEC;
            }
            break;

        case 0xfec6:
            if (conn->conn_settings.enable_decode_fec
                && conn->conn_settings.fec_params.fec_decoder_scheme != 0)
            {
                ret = xqc_process_repair_frame(conn, packet_in);

            } else {
                xqc_log(conn->log, XQC_LOG_ERROR, "|fec negotiation failed but still received fec packet.");
                ret = -XQC_EFEC_NOT_SUPPORT_FEC;
            }
            break;
#endif
        default:
            xqc_log(conn->log, XQC_LOG_ERROR, "|unknown frame type|");
            return -XQC_EIGNORE_PKT;
        }

        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|process frame error|%d|", ret);
            return ret;
        }

        if (last_pos == packet_in->pos) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|pos not update|");
            return -XQC_ESYS;
        }
    }

    /*
     * An endpoint MUST treat receipt of a packet containing no frames as a
     * connection error of type PROTOCOL_VIOLATION
     */
    if (packet_in->pi_frame_types == 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|receive packet with no frame, close"
                "with PROTOCOL_VIOLATION|");
        XQC_CONN_ERR(conn, TRA_PROTOCOL_VIOLATION);
    }

    xqc_path_ctx_t *path = xqc_conn_find_path_by_path_id(conn, packet_in->pi_path_id);
    if (path != NULL 
        && (packet_in->pi_frame_types & XQC_FRAME_BIT_DATAGRAM)) 
    {
        path->path_send_ctl->ctl_dgram_recv_count++;
        if (packet_in->pi_flag & XQC_PIF_REINJECTED_REPLICA) {
            path->path_send_ctl->ctl_reinj_dgram_recv_count++;
        }
    }

    return XQC_OK;
}

xqc_int_t
xqc_process_padding_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret;

    xqc_log(conn->log, XQC_LOG_DEBUG, "|process padding|");
    ret = xqc_parse_padding_frame(packet_in, conn);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_parse_padding_frame error|");
        return ret;
    }

    return XQC_OK;
}


xqc_int_t
xqc_process_stream_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t            ret;
    xqc_stream_id_t      stream_id;
    xqc_stream_type_t    stream_type;
    xqc_stream_t        *stream = NULL;
    xqc_stream_frame_t  *stream_frame;

    stream_frame = xqc_calloc(1, sizeof(xqc_stream_frame_t));
    if (stream_frame == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_calloc error|");
        return -XQC_EMALLOC;
    }

    ret = xqc_parse_stream_frame(packet_in, conn, stream_frame, &stream_id);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_parse_stream_frame error|ret:%d|stream_id:%ui|", ret, stream_id);
        goto error;
    }

    stream_type = xqc_get_stream_type(stream_id);

    xqc_log(conn->log, XQC_LOG_DEBUG, "|offset:%ui|data_length:%ud|fin:%ud|stream_id:%ui|path:%ui|",
            stream_frame->data_offset, stream_frame->data_length, stream_frame->fin, stream_id, packet_in->pi_path_id);

    /* TODOfec: which step should be skip considering current packet is fec recovered？ */
    stream = xqc_find_stream_by_id(stream_id, conn->streams_hash);
    if (!stream) {
        if ((conn->conn_type == XQC_CONN_TYPE_SERVER && (stream_type == XQC_CLI_BID || stream_type == XQC_CLI_UNI))
            || (conn->conn_type == XQC_CONN_TYPE_CLIENT && (stream_type == XQC_SVR_BID || stream_type == XQC_SVR_UNI)))
        {
            stream = xqc_passive_create_stream(conn, stream_id, NULL);
            if (!stream) {
                goto free;
            }

        } else {
            xqc_log(conn->log, XQC_LOG_WARN, "|cannot find stream|stream_id:%ui|", stream_id);
            ret = XQC_OK; /* STREAM frame retransmitted after stream is closed. Ignore it. */
            goto error;
        }
    }

    if (!stream->stream_stats.first_rcv_time) {
        stream->stream_stats.first_rcv_time = xqc_monotonic_timestamp();
    }

    conn->stream_stats.recv_bytes += stream_frame->data_length;

    if (!(packet_in->pi_flag & XQC_PIF_FEC_RECOVERED)) {
        xqc_stream_path_metrics_on_recv(conn, stream, packet_in);
        if (packet_in->pi_path_id < XQC_MAX_PATHS_COUNT) {
            stream->paths_info[packet_in->pi_path_id].path_recv_bytes += stream_frame->data_length;
        }
    }

    if (stream->stream_state_recv >= XQC_RECV_STREAM_ST_RESET_RECVD) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|RESET_RECVD return|stream_id:%ui|", stream_id);
        ret = XQC_OK;
        goto free;
    }

    if (stream_frame->data_offset + stream_frame->data_length <= stream->stream_data_in.merged_offset_end) {
        if (!(stream_frame->fin && stream_frame->data_length == 0 && stream->stream_data_in.stream_length == 0)) {
            xqc_log(conn->log, XQC_LOG_DEBUG, "|already recvd|data_offset:%ui|data_length:%ud|merged_offset_end:%ui|",
                    stream_frame->data_offset, stream_frame->data_length, stream->stream_data_in.merged_offset_end);
            goto free;
        }
    }

    if (stream_frame->fin) {
        if (stream->stream_data_in.stream_determined
            && stream->stream_data_in.stream_length != stream_frame->data_offset + stream_frame->data_length) 
        {
            xqc_log(conn->log, XQC_LOG_ERROR, "|final size changed|stream_id:%ui|", stream_id);
            XQC_CONN_ERR(conn, TRA_FINAL_SIZE_ERROR);
            ret = -XQC_EPROTO;
            goto error;
        }

        if (!stream->stream_stats.peer_fin_rcv_time) {
            stream->stream_stats.peer_fin_rcv_time = xqc_monotonic_timestamp();
        }

        stream->stream_data_in.stream_length = stream_frame->data_offset + stream_frame->data_length;
        stream->stream_data_in.stream_determined = XQC_TRUE;

        if (stream->stream_state_recv == XQC_RECV_STREAM_ST_RECV) {
            xqc_stream_recv_state_update(stream, XQC_RECV_STREAM_ST_SIZE_KNOWN);
        }
    }

    if (stream->stream_data_in.stream_determined
        && stream_frame->data_offset + stream_frame->data_length > stream->stream_data_in.stream_length)
    {
        xqc_log(conn->log, XQC_LOG_ERROR, "|exceed final size|stream_id:%ui|", stream_id);
        XQC_CONN_ERR(conn, TRA_FINAL_SIZE_ERROR);
        ret = -XQC_EPROTO;
        goto error;
    }

    /* if stream is discarded, drop all data */
    if (stream->stream_flag & XQC_STREAM_FLAG_DISCARDED) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|stream[%ui] data discarded|"
                "offset:%ui|len:%ui", stream->stream_id,
                stream_frame->data_offset,
                stream_frame->data_length);

        /* if all data is discarded, try to close the stream */
        if (stream_frame->fin) {
            xqc_stream_close_discarded_stream(stream);
        }

        goto free;
    }

    ret = xqc_insert_stream_frame(conn, stream, stream_frame);
    if (ret == -XQC_EDUP_FRAME) {
        ret = XQC_OK;
        goto free;

    } else if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_insert_stream_frame error|stream_id:%ui|", stream_id);
        goto error;
    }

    /* receiver flow control */
    if (stream->stream_max_recv_offset < stream_frame->data_offset + stream_frame->data_length) {
        conn->conn_flow_ctl.fc_data_recved += stream_frame->data_offset + stream_frame->data_length - stream->stream_max_recv_offset;
        stream->stream_max_recv_offset = stream_frame->data_offset + stream_frame->data_length;
    }

    if (conn->conn_flow_ctl.fc_data_recved > conn->conn_flow_ctl.fc_max_data_can_recv) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|exceed conn flow control|fc_data_recved:%ui|fc_max_data_can_recv:%ui|",
                conn->conn_flow_ctl.fc_data_recved, conn->conn_flow_ctl.fc_max_data_can_recv);
        XQC_CONN_ERR(conn, TRA_FLOW_CONTROL_ERROR);
        return -XQC_EPROTO;
    }

    if (stream->stream_max_recv_offset > stream->stream_flow_ctl.fc_max_stream_data_can_recv) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|exceed stream flow control|stream_max_recv_offset:%ui|fc_max_stream_data_can_recv:%ui|",
                stream->stream_max_recv_offset, stream->stream_flow_ctl.fc_max_stream_data_can_recv);
        XQC_CONN_ERR(conn, TRA_FLOW_CONTROL_ERROR);
        return -XQC_EPROTO;
    }

    if (stream->stream_data_in.stream_determined
        && stream->stream_data_in.stream_length == stream->stream_data_in.merged_offset_end) 
    {
        if (stream->stream_state_recv == XQC_RECV_STREAM_ST_SIZE_KNOWN) {
            xqc_stream_recv_state_update(stream, XQC_RECV_STREAM_ST_DATA_RECVD);
        }
        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_stream_ready_to_read all recvd|");
        xqc_stream_ready_to_read(stream);
    }

    else if (stream->stream_data_in.next_read_offset < stream->stream_data_in.merged_offset_end) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_stream_ready_to_read part recvd|");
        xqc_stream_ready_to_read(stream);
    }

    if (!(packet_in->pi_flag & XQC_PIF_FEC_RECOVERED)
        && packet_in->pi_path_id < XQC_MAX_PATHS_COUNT)
    {
        stream->paths_info[packet_in->pi_path_id].path_recv_effective_bytes += stream_frame->data_length;
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|stream_length:%ui|merged_offset_end:%ui|stream_id:%ui|",
            stream->stream_data_in.stream_length, stream->stream_data_in.merged_offset_end, stream_id);

    return XQC_OK;

error:
free:
    xqc_free(stream_frame->data);
    xqc_free(stream_frame);
    return ret;
}


xqc_int_t
xqc_insert_crypto_frame(xqc_connection_t *conn, xqc_stream_t *stream, xqc_stream_frame_t *stream_frame)
{
    unsigned char inserted = 0;
    xqc_list_head_t *pos;
    xqc_stream_frame_t *frame;
    xqc_list_for_each_reverse(pos, &stream->stream_data_in.frames_tailq) {
        frame = xqc_list_entry(pos, xqc_stream_frame_t, sf_list);

        if (stream_frame->data_offset >= frame->data_offset ) {
            xqc_list_add(&stream_frame->sf_list, pos);
            inserted = 1;
            break;
        }
    }

    if (!inserted) {
        xqc_list_add(&stream_frame->sf_list, &stream->stream_data_in.frames_tailq);
    }

    return XQC_OK;
}


xqc_int_t
xqc_process_crypto_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret;

    /* ack even if the token check fail */
    packet_in->pi_frame_types |= XQC_FRAME_BIT_CRYPTO;

    /* check token, only validate token with Initial/CRYPTO packet, but not with Initial/ACK */
    if (!(conn->conn_flag & XQC_CONN_FLAG_TOKEN_OK)
        && conn->conn_type == XQC_CONN_TYPE_SERVER
        && packet_in->pi_pkt.pkt_type == XQC_PTYPE_INIT)
    {
        if (xqc_conn_check_token(conn, conn->conn_token, conn->conn_token_len) == XQC_OK) {
            conn->conn_flag |= XQC_CONN_FLAG_TOKEN_OK;

        } else {
            xqc_log(conn->log, XQC_LOG_INFO, "|check_token fail|conn:%p|%s|", conn, xqc_conn_addr_str(conn));
        }
    }

    xqc_stream_frame_t *stream_frame = xqc_calloc(1, sizeof(xqc_stream_frame_t));
    if (stream_frame == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_calloc error|");
        return -XQC_EMALLOC;
    }

    ret = xqc_parse_crypto_frame(packet_in, conn, stream_frame);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_parse_crypto_frame error|");
        xqc_destroy_stream_frame(stream_frame);
        return ret;
    }


    xqc_encrypt_level_t encrypt_level = xqc_packet_type_to_enc_level(packet_in->pi_pkt.pkt_type);
    if (conn->crypto_stream[encrypt_level] == NULL) {
        conn->crypto_stream[encrypt_level] = xqc_create_crypto_stream(conn, encrypt_level, NULL);
        if (conn->crypto_stream[encrypt_level] == NULL) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_create_crypto_stream error|");
            xqc_destroy_stream_frame(stream_frame);
            return -XQC_EMALLOC;
        }
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|level:%d|", encrypt_level);

    xqc_stream_t *stream = conn->crypto_stream[encrypt_level];

    ret = xqc_insert_crypto_frame(conn, stream, stream_frame);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_insert_crypto_frame error|");
        xqc_destroy_stream_frame(stream_frame);
        return -1;
    }

    ret = xqc_read_crypto_stream(stream);
    if (ret < 0) {
        return ret;
    }
    xqc_stream_ready_to_read(stream);


    if (conn->conn_type == XQC_CONN_TYPE_SERVER
        && encrypt_level == XQC_ENC_LEV_INIT && conn->crypto_stream[XQC_ENC_LEV_HSK] == NULL)
    {
        conn->crypto_stream[XQC_ENC_LEV_HSK] = xqc_create_crypto_stream(conn, XQC_ENC_LEV_HSK, NULL);
        xqc_log(conn->log, XQC_LOG_DEBUG, "|server create hsk stream|");
    }

    if (conn->conn_type == XQC_CONN_TYPE_SERVER
        && encrypt_level == XQC_ENC_LEV_HSK && conn->crypto_stream[XQC_ENC_LEV_1RTT] == NULL)
    {
        conn->crypto_stream[XQC_ENC_LEV_1RTT] = xqc_create_crypto_stream(conn, XQC_ENC_LEV_1RTT, NULL);
        xqc_log(conn->log, XQC_LOG_DEBUG, "|server create 1RTT stream|");
    }

    return XQC_OK;
}

xqc_int_t
xqc_process_ack_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret;

    xqc_ack_info_t ack_info;
    ret = xqc_parse_ack_frame(packet_in, conn, &ack_info);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_parse_ack_frame error|");
        return ret;
    }
    if ((packet_in->pi_flag & XQC_PIF_FEC_RECOVERED) != 0) {
        return XQC_OK;
    }

    for (int i = 0; i < ack_info.n_ranges; i++) {
        xqc_log_event(conn->log, TRA_PACKETS_ACKED, packet_in, ack_info.ranges[i].high,
            ack_info.ranges[i].low, packet_in->pi_path_id);
    }

    /* 对端还不支持MP，或还未握手确认时，使用 initial path */
    xqc_path_ctx_t *path = conn->conn_initial_path;
    xqc_pn_ctl_t *pn_ctl = xqc_get_pn_ctl(conn, path);
    ret = xqc_send_ctl_on_ack_received(path->path_send_ctl, pn_ctl, conn->conn_send_queue,
                                       &ack_info, packet_in->pkt_recv_time, 1);

    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_send_ctl_on_ack_received error|");
        return ret;
    }

    return XQC_OK;
}

xqc_int_t
xqc_process_ping_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret;

    ret = xqc_parse_ping_frame(packet_in, conn);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_parse_ping_frame error|");
        return ret;
    }

    return XQC_OK;
}


xqc_int_t
xqc_process_new_conn_id_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t        ret = XQC_ERROR;
    xqc_cid_t        new_conn_cid;
    uint64_t         retire_prior_to;
    uint64_t         largest_retire_prior_to;
    uint64_t         cid_limit;


    /* the initial cid limit */
    cid_limit = conn->local_settings.active_connection_id_limit;

    ret = xqc_parse_new_conn_id_frame(packet_in, &new_conn_cid, &retire_prior_to, conn);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_parse_new_conn_id_frame error|");
        return ret;
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|new_conn_id|%s|sr_token:%s",
            xqc_scid_str(conn->engine, &new_conn_cid), xqc_sr_token_str(conn->engine, new_conn_cid.sr_token));

    if (retire_prior_to > new_conn_cid.cid_seq_num) {
        /*
         * The Retire Prior To field MUST be less than or equal to the Sequence Number field.
         * Receiving a value greater than the Sequence Number MUST be treated as a connection
         * error of type FRAME_ENCODING_ERROR.
         */
        xqc_log(conn->log, XQC_LOG_ERROR, "|retire_prior_to:%ui greater than seq_num:%ui|",
                retire_prior_to, new_conn_cid.cid_seq_num);
        XQC_CONN_ERR(conn, TRA_FRAME_ENCODING_ERROR);
        return -XQC_EPROTO;
    }

    /* TODO: write_retire_conn_id_frame 可能涉及到 替换 path.dcid (当前无 retire_prior_to 因此不涉及) */

    /* the current cid was retired and is needed no more */
    if (new_conn_cid.cid_seq_num < conn->dcid_set.largest_retire_prior_to) {
        /*
         * An endpoint that receives a NEW_CONNECTION_ID frame with a sequence number smaller
         * than the Retire Prior To field of a previously received NEW_CONNECTION_ID frame
         * MUST send a corresponding RETIRE_CONNECTION_ID frame that retires the newly received
         * connection ID, unless it has already done so for that sequence number.
         */
        xqc_log(conn->log, XQC_LOG_DEBUG, "|seq_num:%ui smaller than largest_retire_prior_to:%ui|",
                new_conn_cid.cid_seq_num, conn->dcid_set.largest_retire_prior_to);

        ret = xqc_write_retire_conn_id_frame_to_packet(conn, new_conn_cid.cid_seq_num);
        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_retire_conn_id_frame_to_packet error|");
            return ret;
        }

        return XQC_OK;
    }

    /* store dcid & add unused_dcid_count */
    if (xqc_cid_in_cid_set(&conn->dcid_set.cid_set, &new_conn_cid) != NULL) {
        return XQC_OK;
    }

    /* check if insertion of the new conneciton id will violate the cid limit */
    largest_retire_prior_to = xqc_max(retire_prior_to,
                                      conn->dcid_set.largest_retire_prior_to);
    if (!xqc_cid_set_validate_new_cid_limit(&conn->dcid_set.cid_set,
            largest_retire_prior_to, &cid_limit))
    {
        xqc_log(conn->log, XQC_LOG_ERROR, "|retire_prior_to:%ui greater than seq_num:%ui|",
                retire_prior_to, new_conn_cid.cid_seq_num);
        XQC_CONN_ERR(conn, TRA_PROTOCOL_VIOLATION);
        return -XQC_EPROTO;
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|nci allow to be inserted|seq:%ui|dcid_cnt:%ui|cid_limit:%ui",
            new_conn_cid.cid_seq_num, xqc_cid_set_cnt(&conn->dcid_set.cid_set), cid_limit);

    /* insert into dcid-connection hash, for processing the deprecated stateless
       reset packet */
    ret = xqc_insert_conns_hash(conn->engine->conns_hash_dcid, conn, 
                                new_conn_cid.cid_buf, new_conn_cid.cid_len);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|insert new_cid into conns_hash_dcid failed|");
        return ret;
    }

    /* insert into sr_token-connection hash, for processing stateless reset
       packet */
    ret = xqc_insert_conns_hash(conn->engine->conns_hash_sr_token, conn,
                                new_conn_cid.sr_token,
                                XQC_STATELESS_RESET_TOKENLEN);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|insert new_cid into conns_hash_sr_token failed|");
        return ret;
    }

    /* An endpoint MAY send connection IDs that temporarily exceed a peer's 
     * limit if the NEW_CONNECTION_ID frame also requires the retirement of any
     * excess, by including a sufficiently large value in the Retire Prior To
     * field. Hence it is not reasonable to consider it as an error */
    ret = xqc_cid_set_insert_cid(&conn->dcid_set.cid_set, &new_conn_cid,
                                 XQC_CID_UNUSED, cid_limit);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_cid_set_insert_cid error"
                "|local_limit:%ui|largest_limit:%ui|retire_prior_to:%ui|"
                "unused:%ui|used:%ui|",
                conn->local_settings.active_connection_id_limit,
                cid_limit, retire_prior_to, conn->dcid_set.cid_set.unused_cnt,
                conn->dcid_set.cid_set.used_cnt);
        return ret;
    }

    /*
     * Upon receipt of an increased Retire Prior To field, the peer MUST stop
     * using the corresponding connection IDs and retire them with
     * RETIRE_CONNECTION_ID frames before adding the newly provided connection
     * ID to the set of active connection IDs.
     */
    if (retire_prior_to > conn->dcid_set.largest_retire_prior_to) {
        xqc_conn_retire_dcid_prior_to(conn, retire_prior_to);
    }

    return XQC_OK;
}

xqc_int_t
xqc_process_retire_conn_id_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret = XQC_ERROR;
    uint64_t seq_num;

    ret = xqc_parse_retire_conn_id_frame(packet_in, &seq_num);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_parse_retire_conn_id_frame error|");
        return ret;
    }
    
    if ((packet_in->pi_flag & XQC_PIF_FEC_RECOVERED) != 0) {
        return XQC_OK;
    }

    if (seq_num > conn->scid_set.largest_scid_seq_num) {
        /* 
         * Receipt of a RETIRE_CONNECTION_ID frame containing a sequence number
         * greater than any previously sent to the peer MUST be treated as a
         * connection error of type PROTOCOL_VIOLATION.
         */
        xqc_log(conn->log, XQC_LOG_ERROR, "|no match seq_num|");
        XQC_CONN_ERR(conn, TRA_PROTOCOL_VIOLATION);
        return -XQC_EPROTO;
    }

    xqc_cid_inner_t *inner_cid = xqc_get_inner_cid_by_seq(&conn->scid_set.cid_set, seq_num);
    if (inner_cid == NULL) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|can't find scid with seq_num:%ui|", seq_num);
        return XQC_OK;
    }

    /* skip if cid not available anymore */
    if (!xqc_validate_retire_cid_frame(&conn->scid_set.cid_set, inner_cid)) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|cid not valid any more|seq_num:%ui",
                seq_num);
        return XQC_OK;
    }

    if (XQC_OK == xqc_cid_is_equal(&inner_cid->cid, &packet_in->pi_pkt.pkt_dcid)) {
        /* 
         * The sequence number specified in a RETIRE_CONNECTION_ID frame MUST NOT refer to
         * the Destination Connection ID field of the packet in which the frame is contained.
         * The peer MAY treat this as a connection error of type PROTOCOL_VIOLATION.
         */
        xqc_log(conn->log, XQC_LOG_ERROR, "|seq_num refer to pkt_dcid|");
        XQC_CONN_ERR(conn, TRA_PROTOCOL_VIOLATION);
        return -XQC_EPROTO;
    }

    ret = xqc_conn_set_cid_retired_ts(conn, inner_cid);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_set_cid_retired_ts error|");
        return ret;
    }

    /* update SCID */
    if (XQC_OK == xqc_cid_is_equal(&conn->scid_set.user_scid, &inner_cid->cid)) {
        ret = xqc_conn_update_user_scid(conn, &conn->scid_set);
        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|conn don't have other used scid, can't retire user_scid|");
            return ret;
        }

        xqc_log(conn->log, XQC_LOG_DEBUG, "|switch scid to %ui|", conn->scid_set.user_scid.cid_seq_num);
    }

    /* TODO: 如果对应 “Active” Path 则需要替换 CID */
    // xqc_path_ctx_t *path = xqc_conn_find_path_by_scid(conn, &inner_cid->cid);
    // if (path != NULL) {
    //     xqc_log(conn->log, XQC_LOG_DEBUG, "|path:%ui|state:%d|", path->path_id, path->path_state);
    // }

    return XQC_OK;
}


xqc_int_t
xqc_process_conn_close_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret;
    uint64_t err_code;

    ret = xqc_parse_conn_close_frame(packet_in, &err_code, conn);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_parse_conn_close_frame error|");
        return ret;
    }

    if (conn->conn_close_recv_time == 0) {
        conn->conn_close_recv_time = xqc_monotonic_timestamp();
    }

    if (err_code) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|with err:0x%xi|", err_code);
        XQC_CONN_CLOSE_MSG(conn, "remote error");
        XQC_CONN_ERR(conn, err_code);
    } else {
        XQC_CONN_CLOSE_MSG(conn, "remote close");
    }

    if (conn->conn_state < XQC_CONN_STATE_CLOSING) {
        ret = xqc_conn_immediate_close(conn);
        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR,
                    "|xqc_conn_immediate_close error|");
        }
    }
    conn->conn_state = XQC_CONN_STATE_DRAINING;
    xqc_log_event(conn->log, CON_CONNECTION_STATE_UPDATED, conn);
    xqc_conn_closing(conn);

    return XQC_OK;
}

xqc_int_t
xqc_process_reset_stream_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret;
    uint64_t err_code;
    xqc_stream_id_t stream_id;
    uint64_t final_size;
    xqc_stream_t *stream;

    ret = xqc_parse_reset_stream_frame(packet_in, &stream_id, &err_code, &final_size, conn);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_parse_reset_stream_frame error|");
        return ret;
    }
    xqc_stream_type_t stream_type = xqc_get_stream_type(stream_id);

    stream = xqc_find_stream_by_id(stream_id, conn->streams_hash);
    if (!stream) {
        if ((conn->conn_type == XQC_CONN_TYPE_SERVER && (stream_type == XQC_CLI_BID || stream_type == XQC_CLI_UNI))
            || (conn->conn_type == XQC_CONN_TYPE_CLIENT && (stream_type == XQC_SVR_BID || stream_type == XQC_SVR_UNI)))
        {
            stream = xqc_passive_create_stream(conn, stream_id, NULL);
            if (!stream) {
                return XQC_OK;
            }

        } else {
            xqc_log(conn->log, XQC_LOG_WARN, "|cannot find stream|stream_id:%ui|", stream_id);
            /* Packet retransmitted after stream is closed */
            return XQC_OK;
        }
    }
    stream->stream_err = err_code;

    XQC_STREAM_CLOSE_MSG(stream, "remote reset");

    xqc_log(conn->log, XQC_LOG_DEBUG, "|stream_id:%ui|stream_state_recv:%d|stream_state_send:%d|",
            stream->stream_id, stream->stream_state_recv, stream->stream_state_send);

    xqc_stream_closing(stream, err_code);

    if (stream->stream_state_send < XQC_SEND_STREAM_ST_RESET_SENT) {
        xqc_send_queue_drop_stream_frame_packets(conn, stream_id);
        xqc_write_reset_stream_to_packet(conn, stream, err_code, stream->stream_send_offset);
    }

    if (stream->stream_state_recv < XQC_RECV_STREAM_ST_RESET_RECVD) {
        xqc_stream_recv_state_update(stream, XQC_RECV_STREAM_ST_RESET_RECVD);
        if (stream->stream_stats.peer_reset_time == 0) {
            stream->stream_stats.peer_reset_time = xqc_monotonic_timestamp(); 
        }
        conn->conn_flow_ctl.fc_data_recved += (int64_t)final_size - (int64_t)stream->stream_max_recv_offset;
        conn->conn_flow_ctl.fc_data_read += (int64_t)final_size - (int64_t)stream->stream_data_in.next_read_offset;
        xqc_destroy_frame_list(&stream->stream_data_in.frames_tailq);
        xqc_stream_ready_to_read(stream);
    }
    return XQC_OK;
}

xqc_int_t
xqc_process_stop_sending_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret;
    uint64_t err_code;
    xqc_stream_id_t stream_id;
    xqc_stream_t *stream;

    ret = xqc_parse_stop_sending_frame(packet_in, &stream_id, &err_code, conn);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_parse_stop_sending_frame error|");
        return ret;
    }

    xqc_stream_type_t stream_type = xqc_get_stream_type(stream_id);

    stream = xqc_find_stream_by_id(stream_id, conn->streams_hash);
    if (!stream) {
        if ((conn->conn_type == XQC_CONN_TYPE_SERVER && (stream_type == XQC_CLI_BID || stream_type == XQC_CLI_UNI))
            || (conn->conn_type == XQC_CONN_TYPE_CLIENT && (stream_type == XQC_SVR_BID || stream_type == XQC_SVR_UNI)))
        {
            stream = xqc_passive_create_stream(conn, stream_id, NULL);
            if (!stream) {
                return XQC_OK;
            }

        } else {
            xqc_log(conn->log, XQC_LOG_WARN, "|cannot find stream|stream_id:%ui|", stream_id);
            /* Packet retransmitted after stream is closed */
            return XQC_OK;
        }
    }

    /*
     * An endpoint that receives a STOP_SENDING frame
     * MUST send a RESET_STREAM frame if the stream is in the Ready or Send
     * state.
     */
    if (stream->stream_state_send < XQC_SEND_STREAM_ST_RESET_SENT) {
        xqc_write_reset_stream_to_packet(conn, stream, H3_REQUEST_CANCELLED, stream->stream_send_offset);
    }

    return XQC_OK;
}


xqc_int_t
xqc_process_data_blocked_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret;
    uint64_t data_limit;

    ret = xqc_parse_data_blocked_frame(packet_in, &data_limit, conn);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_parse_data_blocked_frame error|");
        return ret;
    }

    if (conn->conn_flow_ctl.fc_data_read + conn->conn_flow_ctl.fc_recv_windows_size <= data_limit) {
        xqc_log(conn->log, XQC_LOG_INFO, "|cannot increase data_limit now|fc_max_data_can_recv:%ui|data_limit:%ui|fc_data_read:%ui|",
                conn->conn_flow_ctl.fc_max_data_can_recv, data_limit, conn->conn_flow_ctl.fc_data_read);
        return XQC_OK;
    }

    conn->conn_flow_ctl.fc_max_data_can_recv = conn->conn_flow_ctl.fc_data_read + conn->conn_flow_ctl.fc_recv_windows_size;

    ret = xqc_write_max_data_to_packet(conn, conn->conn_flow_ctl.fc_max_data_can_recv);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_max_data_to_packet error|");
        return ret;
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|data_limit:%ui|new_limit:%ui|",
            data_limit, conn->conn_flow_ctl.fc_max_data_can_recv);
    return XQC_OK;
}

xqc_int_t
xqc_process_stream_data_blocked_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret;
    uint64_t stream_data_limit;
    xqc_stream_id_t stream_id;
    xqc_stream_t *stream;

    ret = xqc_parse_stream_data_blocked_frame(packet_in, &stream_id, &stream_data_limit, conn);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_parse_stream_data_blocked_frame error|");
        return ret;
    }

    xqc_stream_type_t stream_type = xqc_get_stream_type(stream_id);

    stream = xqc_find_stream_by_id(stream_id, conn->streams_hash);
    if (!stream) {
        if ((conn->conn_type == XQC_CONN_TYPE_SERVER && (stream_type == XQC_CLI_BID || stream_type == XQC_CLI_UNI))
            || (conn->conn_type == XQC_CONN_TYPE_CLIENT && (stream_type == XQC_SVR_BID || stream_type == XQC_SVR_UNI)))
        {
            stream = xqc_passive_create_stream(conn, stream_id, NULL);
            if (!stream) {
                return XQC_OK;
            }

        } else {
            xqc_log(conn->log, XQC_LOG_WARN, "|cannot find stream|stream_id:%ui|", stream_id);
            /* Packet retransmitted after stream is closed */
            return XQC_OK;
        }
    }

    if (stream->stream_data_in.next_read_offset + stream->stream_flow_ctl.fc_stream_recv_window_size <= stream_data_limit) {
        xqc_log(conn->log, XQC_LOG_INFO, "|cannot increase data_limit now|fc_max_stream_data_can_recv:%ui|stream_data_limit:%ui|next_read_offset:%ui|stream_max_recv_offset:%ui|",
                stream->stream_flow_ctl.fc_max_stream_data_can_recv, stream_data_limit, stream->stream_data_in.next_read_offset, stream->stream_max_recv_offset);
        return XQC_OK;
    }

    stream->stream_flow_ctl.fc_max_stream_data_can_recv = stream->stream_data_in.next_read_offset + stream->stream_flow_ctl.fc_stream_recv_window_size;

    ret = xqc_write_max_stream_data_to_packet(conn, stream_id, stream->stream_flow_ctl.fc_max_stream_data_can_recv, XQC_PTYPE_SHORT_HEADER);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_max_stream_data_to_packet error|");
        return ret;
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|stream_data_limit:%ui|new_limit:%ui|",
            stream_data_limit, stream->stream_flow_ctl.fc_max_stream_data_can_recv);
    return XQC_OK;
}

xqc_int_t
xqc_process_streams_blocked_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret;
    uint64_t stream_limit;
    int bidirectional;

    ret = xqc_parse_streams_blocked_frame(packet_in, &stream_limit, &bidirectional, conn);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_parse_streams_blocked_frame error|");
        return ret;
    }

    uint64_t new_max_streams;
    if (bidirectional) {
        /* there is no need to increase MAX_STREAMS */
        if (stream_limit < conn->conn_flow_ctl.fc_max_streams_bidi_can_recv) {
            return XQC_OK;
        }

        new_max_streams = xqc_min(stream_limit + conn->local_settings.max_streams_bidi,
            conn->conn_flow_ctl.fc_max_streams_bidi_can_recv + conn->local_settings.max_streams_bidi);
        conn->conn_flow_ctl.fc_max_streams_bidi_can_recv = new_max_streams;

    } else {
        /* there is no need to increase MAX_STREAMS */
        if (stream_limit < conn->conn_flow_ctl.fc_max_streams_uni_can_recv) {
            return XQC_OK;
        }

        new_max_streams = xqc_min(stream_limit + conn->local_settings.max_streams_uni,
            conn->conn_flow_ctl.fc_max_streams_uni_can_recv + conn->local_settings.max_streams_uni);
        conn->conn_flow_ctl.fc_max_streams_uni_can_recv = new_max_streams;
    }

    if (stream_limit < XQC_MAX_STREAMS && (new_max_streams > XQC_MAX_STREAMS)) {
        new_max_streams = XQC_MAX_STREAMS;
    }

    ret = xqc_write_max_streams_to_packet(conn, new_max_streams, bidirectional);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_write_max_streams_to_packet error|");
        return ret;
    }

    return XQC_OK;
}

xqc_int_t
xqc_process_max_data_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret;
    uint64_t max_data;

    ret = xqc_parse_max_data_frame(packet_in, &max_data, conn);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_parse_max_data_frame error|");
        return ret;
    }

    if (max_data > conn->conn_flow_ctl.fc_max_data_can_send) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|max_data:%ui|max_data_old:%ui|",
                max_data, conn->conn_flow_ctl.fc_max_data_can_send);
        conn->conn_flow_ctl.fc_max_data_can_send = max_data;
        conn->conn_flag &= ~XQC_CONN_FLAG_DATA_BLOCKED;

    } else {
        xqc_log(conn->log, XQC_LOG_INFO, "|max_data too small|max_data:%ui|max_data_old:%ui|",
                max_data, conn->conn_flow_ctl.fc_max_data_can_send);
    }

    return XQC_OK;
}

xqc_int_t
xqc_process_max_stream_data_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret = XQC_ERROR;
    uint64_t max_stream_data;
    xqc_stream_id_t stream_id;
    xqc_stream_t *stream;

    ret = xqc_parse_max_stream_data_frame(packet_in, &stream_id, &max_stream_data, conn);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_parse_max_stream_data_frame error|");
        return ret;
    }

    xqc_stream_type_t stream_type = xqc_get_stream_type(stream_id);

    stream = xqc_find_stream_by_id(stream_id, conn->streams_hash);
    if (!stream) {
        if ((conn->conn_type == XQC_CONN_TYPE_SERVER && (stream_type == XQC_CLI_BID || stream_type == XQC_CLI_UNI))
            || (conn->conn_type == XQC_CONN_TYPE_CLIENT && (stream_type == XQC_SVR_BID || stream_type == XQC_SVR_UNI)))
        {
            stream = xqc_passive_create_stream(conn, stream_id, NULL);
            if (!stream) {
                return XQC_OK;
            }

        } else {
            xqc_log(conn->log, XQC_LOG_WARN, "|cannot find stream|stream_id:%ui|", stream_id);
            /* Packet retransmitted after stream is closed */
            return XQC_OK;
        }
    }

    if (max_stream_data > stream->stream_flow_ctl.fc_max_stream_data_can_send) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|max_stream_data=%ui|max_stream_data_old=%ui|",
                max_stream_data, stream->stream_flow_ctl.fc_max_stream_data_can_send);
        stream->stream_flow_ctl.fc_max_stream_data_can_send = max_stream_data;
        stream->stream_flag &= ~XQC_STREAM_FLAG_DATA_BLOCKED;

    } else {
        xqc_log(conn->log, XQC_LOG_INFO, "|max_stream_data too small|max_stream_data=%ui|max_stream_data_old=%ui|",
                max_stream_data, stream->stream_flow_ctl.fc_max_stream_data_can_send);
    }
    return XQC_OK;
}

xqc_int_t
xqc_process_max_streams_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret = XQC_ERROR;
    uint64_t max_streams;
    int bidirectional;

    ret = xqc_parse_max_streams_frame(packet_in, &max_streams, &bidirectional, conn);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_parse_max_streams_frame error|");
        return ret;
    }

    if (max_streams > XQC_MAX_STREAMS) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_max_streams_frame error|receive max_streams:%ui|", max_streams);
        return -XQC_EPROTO;
    }

    if (bidirectional) {
        if (max_streams > conn->conn_flow_ctl.fc_max_streams_bidi_can_send) {
            conn->conn_flow_ctl.fc_max_streams_bidi_can_send = max_streams;
        }

    } else {
        if (max_streams > conn->conn_flow_ctl.fc_max_streams_uni_can_send) {
            conn->conn_flow_ctl.fc_max_streams_uni_can_send = max_streams;
        }
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|fc_max_streams_bidi_can_send:%ui|fc_max_streams_uni_can_send:%ui|bidirectional:%d|max_streams:%ui|",
            conn->conn_flow_ctl.fc_max_streams_bidi_can_send, conn->conn_flow_ctl.fc_max_streams_uni_can_send, bidirectional, max_streams);
    return XQC_OK;
}

xqc_int_t
xqc_process_new_token_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret;
    if (XQC_CONN_TYPE_SERVER == conn->conn_type) {
        return -XQC_EPROTO;
    }

    conn->conn_token_len = XQC_MAX_TOKEN_LEN;
    ret = xqc_parse_new_token_frame(packet_in, conn->conn_token, &conn->conn_token_len, conn);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_parse_new_token_frame error|");
        return ret;
    }

    conn->transport_cbs.save_token(conn->conn_token, conn->conn_token_len,
                                   xqc_conn_get_user_data(conn));

    return XQC_OK;
}

xqc_int_t
xqc_process_datagram_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    /* does not support datagram */
    if (conn->local_settings.max_datagram_frame_size == 0) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|the endpoint does not support datagram but receives a DATAGRAM frame|");
        XQC_CONN_ERR(conn, TRA_PROTOCOL_VIOLATION);
        return -XQC_EPROTO;
    }

    unsigned char *data_buffer = NULL;
    size_t data_len = 0;

    xqc_int_t ret = xqc_parse_datagram_frame(packet_in, conn, &data_buffer, &data_len);
    if (ret == -XQC_EPROTO) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|the endpoint receives a DATAGRAM frame larger than max_datagram_frame_size|"
                "max_datagram_frame_size:%ud|frame_size:%ud|",
                conn->local_settings.max_datagram_frame_size,
                data_len + XQC_DATAGRAM_HEADER_BYTES);
        XQC_CONN_ERR(conn, TRA_PROTOCOL_VIOLATION);
        return ret;
    }
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_parse_datagram_frame error|");
        return ret;
    }

    /* @TODO: datagram read callback */
    if (data_len > 0) {
        if (conn->app_proto_cbs.dgram_cbs.datagram_read_notify
            && (conn->conn_flag & XQC_CONN_FLAG_UPPER_CONN_EXIST))
        {
            conn->app_proto_cbs.dgram_cbs.datagram_read_notify(conn, conn->dgram_data, data_buffer, data_len, xqc_monotonic_timestamp() - packet_in->pkt_recv_time);
            xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_datagram_read|data_len:%z|", data_len);
        }
    }

    return ret;
}



xqc_int_t
xqc_process_handshake_done_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    if (XQC_CONN_TYPE_SERVER == conn->conn_type) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_process_handshake_done_frame error, server recv HANDSHAKE_DONE|");
        XQC_CONN_ERR(conn, TRA_PROTOCOL_VIOLATION);
        return -XQC_EPROTO;
    }

    xqc_int_t ret = xqc_parse_handshake_done_frame(packet_in, conn);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_process_handshake_done_frame error|");
        return ret;
    }

    conn->conn_flag |= XQC_CONN_FLAG_HANDSHAKE_DONE_RECVD;

    return ret;
}


xqc_int_t
xqc_process_path_challenge_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret = XQC_ERROR;
    unsigned char path_challenge_data[XQC_PATH_CHALLENGE_DATA_LEN];

    ret = xqc_parse_path_challenge_frame(packet_in, path_challenge_data);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_parse_path_challenge_frame error|");
        return ret;
    }

    if ((packet_in->pi_flag & XQC_PIF_FEC_RECOVERED) != 0) {
        return XQC_OK;
    }

    //TODO: MPQUIC fix migration
    xqc_path_ctx_t *path = NULL;
    if (conn->enable_multipath) {
        path = xqc_conn_find_path_by_scid(conn, &packet_in->pi_pkt.pkt_dcid);

    } else {
        path = conn->conn_initial_path;
    }
    
    if (path == NULL) {
        if (conn->conn_type == XQC_CONN_TYPE_SERVER) {
            /* try to create new path */
            path = xqc_conn_create_path_inner(conn, &packet_in->pi_pkt.pkt_dcid, NULL, XQC_APP_PATH_STATUS_AVAILABLE);
            if (path == NULL) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_create_path_inner err|");
                return -XQC_EMP_CREATE_PATH;
            }
            packet_in->pi_path_id = path->path_id;
            conn->validating_path_id = path->path_id;
            conn->conn_flag |= XQC_CONN_FLAG_RECV_NEW_PATH;

        } else {
            xqc_log(conn->log, XQC_LOG_ERROR, 
                    "|no path to challenge|dcid:%s|path_id:%ui|", 
                    xqc_dcid_str(conn->engine, &packet_in->pi_pkt.pkt_dcid),
                    packet_in->pi_path_id);
            return XQC_OK;
        }
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, 
            "|path:%ui|state:%d|RECV path_challenge_data:%s|cid:%s|",
            path->path_id, path->path_state, 
            path_challenge_data, xqc_dcid_str(conn->engine, &packet_in->pi_pkt.pkt_dcid));

    ret = xqc_write_path_response_frame_to_packet(conn, path, path_challenge_data);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_path_response_frame_to_packet error|%d|", ret);
        return ret;
    }

    return XQC_OK;
}


xqc_int_t
xqc_process_path_response_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret = XQC_ERROR;
    unsigned char path_response_data[XQC_PATH_CHALLENGE_DATA_LEN];

    ret = xqc_parse_path_response_frame(packet_in, path_response_data);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_parse_path_response_frame error|");
        return ret;
    }

    if ((packet_in->pi_flag & XQC_PIF_FEC_RECOVERED) != 0) {
        return XQC_OK;
    }

    //TODO: MPQUIC fix migration
    xqc_path_ctx_t *path = NULL;
    if (conn->enable_multipath) {
        path = xqc_conn_find_path_by_scid(conn, &packet_in->pi_pkt.pkt_dcid);
        if (path == NULL) {
            xqc_log(conn->log, XQC_LOG_ERROR, 
                    "|ingnore path response|pkt_dcid:%s|path_id:%ui|", 
                    xqc_scid_str(conn->engine, &packet_in->pi_pkt.pkt_dcid),
                    packet_in->pi_path_id);
            return XQC_OK;
        }

    } else {
        path = conn->conn_initial_path;
    }
    
    xqc_log(conn->log, XQC_LOG_DEBUG, "|path:%ui|state:%d|RECV path_response_data:%s|",
            path->path_id, path->path_state, path_response_data);

    /* 
     * If the content of a PATH_RESPONSE frame does not match the content of
     * a PATH_CHALLENGE frame previously sent by the endpoint, the endpoint
     * MAY generate a connection error of type PROTOCOL_VIOLATION.
     */

    if (memcmp(path->path_challenge_data, path_response_data, XQC_PATH_CHALLENGE_DATA_LEN) != 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|path:%ui|ignore|no match path challenge data|", path->path_id);
        return XQC_OK;
    }

    xqc_path_validate(path);

    if (conn->conn_type == XQC_CONN_TYPE_SERVER
        && (path->rebinding_addrlen != 0)
        && (path->rebinding_check_response == 1))
    {
        /* successfully validate rebinding addr */
        xqc_memcpy(path->peer_addr, path->rebinding_addr, path->rebinding_addrlen);
        path->peer_addrlen = path->rebinding_addrlen;
        path->addr_str_len = 0;
        xqc_log(conn->log, XQC_LOG_INFO, "|path:%ui|REBINDING|validate NAT rebinding addr|path:%s|", path->path_id, xqc_path_addr_str(path));

        if (conn->enable_multipath
            && (path->path_id != XQC_INITIAL_PATH_ID))
        {
            if (conn->transport_cbs.path_peer_addr_changed_notify) {
                conn->transport_cbs.path_peer_addr_changed_notify(conn, path->path_id, xqc_conn_get_user_data(conn));
            }

        } else {
            xqc_memcpy(conn->peer_addr, path->rebinding_addr, path->rebinding_addrlen);
            conn->peer_addrlen = path->rebinding_addrlen;
            conn->addr_str_len = 0;
            xqc_log(conn->log, XQC_LOG_INFO, "|path:%ui|REBINDING|validate NAT rebinding addr|conn:%s|", path->path_id, xqc_conn_addr_str(conn));

            if (conn->transport_cbs.conn_peer_addr_changed_notify) {
                conn->transport_cbs.conn_peer_addr_changed_notify(conn, xqc_conn_get_user_data(conn));
            }
        }

        path->rebinding_valid++;
        path->rebinding_addrlen = 0;
        path->rebinding_check_response = 0;
        xqc_timer_unset(&path->path_send_ctl->path_timer_manager, XQC_TIMER_NAT_REBINDING);
    }

    return XQC_OK;
}


xqc_int_t
xqc_process_ack_mp_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret;

    xqc_ack_info_t ack_info;
    uint64_t dcid_seq_num;
    ret = xqc_parse_ack_mp_frame(packet_in, conn, &dcid_seq_num, &ack_info);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_parse_ack_mp_frame error|");
        return ret;
    }

    if ((packet_in->pi_flag & XQC_PIF_FEC_RECOVERED) != 0) {
        return XQC_OK;
    }

    xqc_path_ctx_t *path_to_be_acked = xqc_conn_find_path_by_dcid_seq(conn, dcid_seq_num);
    if (path_to_be_acked == NULL) {
        xqc_log(conn->log, XQC_LOG_INFO, "|ignore unknown path|dcid_seq:%ui|", dcid_seq_num);
        return XQC_OK;
    }

    if (path_to_be_acked->path_id != packet_in->pi_path_id) {
        xqc_log(conn->log, XQC_LOG_DEBUG, 
                "|ACK_MP received on a different path|ack_path_id:%ui|recv_path_id:%ui|",
                path_to_be_acked->path_id,
                packet_in->pi_path_id);
    }

    for (int i = 0; i < ack_info.n_ranges; i++) {
        xqc_log_event(conn->log, TRA_PACKETS_ACKED, packet_in, ack_info.ranges[i].high, 
            ack_info.ranges[i].low, path_to_be_acked->path_id);
    }

    xqc_pn_ctl_t *pn_ctl = xqc_get_pn_ctl(conn, path_to_be_acked);

    ret = xqc_send_ctl_on_ack_received(path_to_be_acked->path_send_ctl, pn_ctl, conn->conn_send_queue,
                                       &ack_info, packet_in->pkt_recv_time, 
                                       path_to_be_acked->path_id == packet_in->pi_path_id);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_send_ctl_on_ack_received error|");
        return ret;
    }

    return XQC_OK;
}

xqc_int_t
xqc_process_path_abandon_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret = XQC_ERROR;

    uint64_t dcid_seq_num;
    uint64_t error_code;

    ret = xqc_parse_path_abandon_frame(packet_in, &dcid_seq_num, &error_code);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_parse_path_abandon_frame error|");
        return ret;
    }

    xqc_path_ctx_t *path = xqc_conn_find_path_by_dcid_seq(conn, dcid_seq_num);

    if (path == NULL) {
        xqc_log(conn->log, XQC_LOG_WARN,
                "|invalid path|dcid_seq_num:%ui|path_id:%ui|",
                dcid_seq_num, packet_in->pi_path_id);
        return XQC_OK; /* ignore */
    }

    /* 
     * If a PATH_ABANDON frame is received for the only active path of a
     * QUIC connection, the receiving peer SHOULD send a CONNECTION_CLOSE
     * frame and enters the closing state.
     */
    if (conn->active_path_count < 2 && path->path_state == XQC_PATH_STATE_ACTIVE) {
        xqc_log(conn->log, XQC_LOG_WARN, "|abandon the only active path, close connection|");
        xqc_conn_immediate_close(conn);
        return XQC_OK;
    }

    if (path->path_state < XQC_PATH_STATE_CLOSING) {
        ret = xqc_path_immediate_close(path);
        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_path_immediate_close error|ret:%d|", ret);
        }
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|path:%ui|state:%d|err_code:%ui|", path->path_id, path->path_state, error_code);

    return XQC_OK;
}

xqc_int_t
xqc_process_path_status_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret = XQC_ERROR;

    uint64_t dcid_seq_num;
    uint64_t path_status_seq_num;
    uint64_t path_status;

    ret = xqc_parse_path_status_frame(packet_in, &dcid_seq_num, &path_status_seq_num, &path_status);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_parse_path_status_frame error|");
        return ret;
    }

    xqc_path_ctx_t *path = xqc_conn_find_path_by_dcid_seq(conn, dcid_seq_num);

    if (path == NULL) {
        xqc_log(conn->log, XQC_LOG_WARN,
                "|invalid path|dcid_seq_num:%ui|pi_path_id:%ui|",
                dcid_seq_num, packet_in->pi_path_id);
        return XQC_OK; /* ignore */
    }

    if (path_status_seq_num > path->app_path_status_recv_seq_num) {
        path->app_path_status_recv_seq_num = path_status_seq_num;
        path->next_app_path_state = path_status;
        
        if (path->path_state < XQC_PATH_STATE_ACTIVE) {
            path->path_flag |= XQC_PATH_FLAG_RECV_STATUS;

        } else {
            xqc_set_application_path_status(path, path->next_app_path_state, XQC_FALSE);
        }
    }

    return XQC_OK;
}

xqc_int_t
xqc_process_path_standby_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret = XQC_ERROR;

    uint64_t dcid_seq_num;
    uint64_t path_status_seq_num;
    uint64_t path_status;

    ret = xqc_parse_path_standby_frame(packet_in, &dcid_seq_num, &path_status_seq_num, &path_status);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_parse_path_status_frame error|");
        return ret;
    }

    xqc_path_ctx_t *path = xqc_conn_find_path_by_dcid_seq(conn, dcid_seq_num);

    if (path == NULL) {
        xqc_log(conn->log, XQC_LOG_WARN,
                "|invalid path|dcid_seq_num:%ui|pi_path_id:%ui|",
                dcid_seq_num, packet_in->pi_path_id);
        return XQC_OK; /* ignore */
    }

    if (path_status_seq_num > path->app_path_status_recv_seq_num) {
        path->app_path_status_recv_seq_num = path_status_seq_num;
        path->next_app_path_state = path_status;

        if (path->path_state < XQC_PATH_STATE_ACTIVE) {
            path->path_flag |= XQC_PATH_FLAG_RECV_STATUS;

        } else {
            xqc_set_application_path_status(path, path->next_app_path_state, XQC_FALSE);
        }
    }

    return XQC_OK;
}


xqc_int_t
xqc_process_path_available_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret = XQC_ERROR;

    uint64_t dcid_seq_num;
    uint64_t path_status_seq_num;
    uint64_t path_status;

    ret = xqc_parse_path_available_frame(packet_in, &dcid_seq_num, &path_status_seq_num, &path_status);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_parse_path_status_frame error|");
        return ret;
    }

    xqc_path_ctx_t *path = xqc_conn_find_path_by_dcid_seq(conn, dcid_seq_num);

    if (path == NULL) {
        xqc_log(conn->log, XQC_LOG_WARN,
                "|invalid path|dcid_seq_num:%ui|pi_path_id:%ui|",
                dcid_seq_num, packet_in->pi_path_id);
        return XQC_OK; /* ignore */
    }

    if (path_status_seq_num > path->app_path_status_recv_seq_num) {
        path->app_path_status_recv_seq_num = path_status_seq_num;
        path->next_app_path_state = path_status;

        if (path->path_state < XQC_PATH_STATE_ACTIVE) {
            path->path_flag |= XQC_PATH_FLAG_RECV_STATUS;

        } else {
            xqc_set_application_path_status(path, path->next_app_path_state, XQC_FALSE);
        }
    }

    return XQC_OK;
}

#ifdef XQC_ENABLE_FEC
xqc_int_t
xqc_process_sid_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret;

    ret = xqc_parse_sid_frame(conn, packet_in);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_parse_sid_frame err|ret:%d|", ret);
    }
    if (ret == -XQC_EVINTREAD) {
        return ret;
    }
    /* if there's error, just ignore fec module */
    return XQC_OK;
}

xqc_int_t
xqc_process_repair_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret;
    
    ret = xqc_parse_repair_frame(conn, packet_in);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_parse_repair_frame err|ret:%d|", ret);
    }
    if (ret == -XQC_EVINTREAD) {
        return ret;
    }
    /* if there's error, just ignore fec module */
    return XQC_OK;
}
#endif