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
#include "src/transport/xqc_defs.h"
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
    [XQC_FRAME_MAX_STREAM_DATA]      = "MAX_STREAM_DAT",
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
    [XQC_FRAME_Extension]            = "Extension",
};

static char g_frame_type_buf[128];

const char*
xqc_frame_type_2_str(xqc_frame_type_bit_t type_bit)
{
    g_frame_type_buf[0] = '\0';
    size_t pos = 0;
    int wsize;
    for (int i = 0; i < XQC_FRAME_NUM; i++) {
        if (type_bit & 1 << i) {
            wsize = snprintf(g_frame_type_buf + pos, sizeof(g_frame_type_buf) - pos, "%s ",
                             frame_type_2_str[i]);
            if (wsize < 0 || wsize >= sizeof(g_frame_type_buf) - pos) {
                break;
            }
            pos += wsize;
        }
    }
    return g_frame_type_buf;
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
            if (stream->stream_data_in.merged_offset_end >= frame->data_offset
                && stream->stream_data_in.merged_offset_end < frame->data_offset + frame->data_length)
            {
                stream->stream_data_in.merged_offset_end = frame->data_offset + frame->data_length;
                xqc_log(conn->log, XQC_LOG_DEBUG, "|merge right|merged_offset_end:%ui|offset:%ui|len:%ud|",
                        stream->stream_data_in.merged_offset_end, frame->data_offset, frame->data_length);
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
        case 0x02 ... 0x03:
            ret = xqc_process_ack_frame(conn, packet_in);
            break;
        case 0x04:
            ret = xqc_process_reset_stream_frame(conn, packet_in);
            break;
        case 0x05:
            ret = xqc_process_stop_sending_frame(conn, packet_in);
            break;
        case 0x06:            ret = xqc_process_crypto_frame(conn, packet_in);
            break;
        case 0x07:
            ret = xqc_process_new_token_frame(conn, packet_in);
            break;
        case 0x08 ... 0x0f:
            ret = xqc_process_stream_frame(conn, packet_in);
            break;
        case 0x10:
            ret = xqc_process_max_data_frame(conn, packet_in);
            break;
        case 0x11:
            ret = xqc_process_max_stream_data_frame(conn, packet_in);
            break;
        case 0x12 ... 0x13:
            ret = xqc_process_max_streams_frame(conn, packet_in);
            break;
        case 0x14:
            ret = xqc_process_data_blocked_frame(conn, packet_in);
            break;
        case 0x15:
            ret = xqc_process_stream_data_blocked_frame(conn, packet_in);
            break;
        case 0x16 ... 0x17:
            ret = xqc_process_streams_blocked_frame(conn, packet_in);
            break;
        case 0x18:
            ret = xqc_process_new_conn_id_frame(conn, packet_in);
            break;
        case 0x19:
            ret = xqc_process_retire_conn_id_frame(conn, packet_in);
            break;
        case 0x1c ... 0x1d:
            ret = xqc_process_conn_close_frame(conn, packet_in);
            break;
        case 0x1e:
            ret = xqc_process_handshake_done_frame(conn, packet_in);
            break;
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
    xqc_int_t ret = 0;

    xqc_stream_id_t stream_id;
    xqc_stream_type_t stream_type;
    xqc_stream_t *stream = NULL;
    xqc_stream_frame_t *stream_frame = xqc_calloc(1, sizeof(xqc_stream_frame_t));
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

    xqc_log(conn->log, XQC_LOG_DEBUG, "|offset:%ui|data_length:%ud|fin:%ud|",
            stream_frame->data_offset, stream_frame->data_length, stream_frame->fin);

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
        if (stream->stream_data_in.stream_length > 0
                && stream->stream_data_in.stream_length != stream_frame->data_offset + stream_frame->data_length) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|final size changed|stream_id:%ui|", stream_id);
            XQC_CONN_ERR(conn, TRA_FINAL_SIZE_ERROR);
            ret = -XQC_EPROTO;
            goto error;
        }

        if (!stream->stream_stats.peer_fin_rcv_time) {
            stream->stream_stats.peer_fin_rcv_time = xqc_monotonic_timestamp();
        }

        stream->stream_data_in.stream_length = stream_frame->data_offset + stream_frame->data_length;

        if (stream->stream_state_recv == XQC_RECV_STREAM_ST_RECV) {
            xqc_stream_recv_state_update(stream, XQC_RECV_STREAM_ST_SIZE_KNOWN);
        }
    }

    if (stream->stream_data_in.stream_length > 0
        && stream_frame->data_offset + stream_frame->data_length > stream->stream_data_in.stream_length)
    {
        xqc_log(conn->log, XQC_LOG_ERROR, "|exceed final size|stream_id:%ui|", stream_id);
        XQC_CONN_ERR(conn, TRA_FINAL_SIZE_ERROR);
        ret = -XQC_EPROTO;
        goto error;
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

    if (stream->stream_data_in.stream_length == stream->stream_data_in.merged_offset_end
        && stream->stream_data_in.stream_length > 0)
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
        xqc_free(stream_frame);
        return ret;
    }

    xqc_encrypt_level_t encrypt_level = xqc_packet_type_to_enc_level(packet_in->pi_pkt.pkt_type);
    if (conn->crypto_stream[encrypt_level] == NULL) {
        conn->crypto_stream[encrypt_level] = xqc_create_crypto_stream(conn, encrypt_level, NULL);
        if (conn->crypto_stream[encrypt_level] == NULL) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_create_crypto_stream error|");
            xqc_free(stream_frame);
            return -XQC_EMALLOC;
        }
    }

    xqc_stream_t *stream = conn->crypto_stream[encrypt_level];

    ret = xqc_insert_crypto_frame(conn, stream, stream_frame);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_insert_crypto_frame error|");
        xqc_free(stream_frame);
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

    for (int i = 0; i < ack_info.n_ranges; i++) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|high:%ui|low:%ui|pkt_pns:%d|",
                ack_info.ranges[i].high, ack_info.ranges[i].low, packet_in->pi_pkt.pkt_pns);
        xqc_log_event(conn->log, TRA_PACKETS_ACKED, packet_in, ack_info.ranges[i].high, ack_info.ranges[i].low);
    }

    ret = xqc_send_ctl_on_ack_received(conn->conn_send_ctl, &ack_info, packet_in->pkt_recv_time);
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
    xqc_int_t ret = XQC_ERROR;
    xqc_cid_t new_conn_cid;
    uint64_t retire_prior_to;

    xqc_cid_inner_t *inner_cid;
    xqc_list_head_t *pos, *next;

    ret = xqc_parse_new_conn_id_frame(packet_in, &new_conn_cid, &retire_prior_to, conn);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_parse_new_conn_id_frame error|");
        return ret;
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|new_conn_id|%s|", xqc_scid_str(&new_conn_cid));

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

    if (retire_prior_to > conn->dcid_set.largest_retire_prior_to) {
        /*
         * Upon receipt of an increased Retire Prior To field, the peer MUST stop using the
         * corresponding connection IDs and retire them with RETIRE_CONNECTION_ID frames before
         * adding the newly provided connection ID to the set of active connection IDs.
         */

        xqc_list_for_each_safe(pos, next, &conn->dcid_set.cid_set.list_head) {
            inner_cid = xqc_list_entry(pos, xqc_cid_inner_t, list);
            uint64_t seq_num = inner_cid->cid.cid_seq_num;
            if ((inner_cid->state == XQC_CID_UNUSED || inner_cid->state == XQC_CID_USED)
                 && (seq_num >= conn->dcid_set.largest_retire_prior_to && seq_num < retire_prior_to))
            {
                ret = xqc_write_retire_conn_id_frame_to_packet(conn, seq_num);
                if (ret != XQC_OK) {
                    xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_retire_conn_id_frame_to_packet error|");
                    return ret;
                }
            }
        }

        conn->dcid_set.largest_retire_prior_to = retire_prior_to;
        xqc_log(conn->log, XQC_LOG_DEBUG, "|retire_prior_to|%ui|increase to|%ui|",
                conn->dcid_set.largest_retire_prior_to, retire_prior_to);
    }

    /* store dcid & add unused_dcid_count */
    if (xqc_cid_in_cid_set(&conn->dcid_set.cid_set, &new_conn_cid) != NULL) {
        return XQC_OK;
    }

    ret = xqc_cid_set_insert_cid(&conn->dcid_set.cid_set, &new_conn_cid, XQC_CID_UNUSED, conn->local_settings.active_connection_id_limit);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_cid_set_insert_cid error|limit:%ui|unused:%ui|used:%ui|",
                conn->local_settings.active_connection_id_limit, conn->dcid_set.cid_set.unused_cnt, conn->dcid_set.cid_set.used_cnt);
        return ret;
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

    if (seq_num >= conn->scid_set.largest_scid_seq_num) {
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
        xqc_log(conn->log, XQC_LOG_DEBUG, "|can't find scid with seq_number|%ui|", seq_num);
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

    if (err_code) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|with err:0x%xi|", err_code);
        XQC_CONN_ERR(conn, err_code);
    }

    if (conn->conn_state < XQC_CONN_STATE_CLOSING) {
        ret = xqc_conn_immediate_close(conn);
        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR,
                    "|xqc_conn_immediate_close error|");
        }
    }
    conn->conn_state = XQC_CONN_STATE_DRAINING;

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

    xqc_log(conn->log, XQC_LOG_DEBUG, "|stream_id:%ui|stream_state_recv:%d|stream_state_send:%d|",
            stream->stream_id, stream->stream_state_recv, stream->stream_state_send);

    if (stream->stream_state_send < XQC_SEND_STREAM_ST_RESET_SENT) {
        xqc_send_ctl_drop_stream_frame_packets(conn->conn_send_ctl, stream_id);
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

    ret = xqc_write_max_stream_data_to_packet(conn, stream_id, stream->stream_flow_ctl.fc_max_stream_data_can_recv);
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

        new_max_streams = stream_limit + conn->local_settings.max_streams_bidi;
        conn->conn_flow_ctl.fc_max_streams_bidi_can_recv = new_max_streams;

    } else {
        /* there is no need to increase MAX_STREAMS */
        if (stream_limit < conn->conn_flow_ctl.fc_max_streams_uni_can_recv) {
            return XQC_OK;
        }

        new_max_streams = stream_limit + conn->local_settings.max_streams_uni;
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

