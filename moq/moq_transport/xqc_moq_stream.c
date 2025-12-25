#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_conn.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_stream_quic.h"
#include "moq/moq_transport/xqc_moq_stream_webtransport.h"

xqc_moq_stream_t *
xqc_moq_stream_create(xqc_moq_session_t *session)
{
    xqc_moq_stream_t *stream = xqc_calloc(1, sizeof(*stream));
    switch (session->transport_type) {
        case XQC_MOQ_TRANSPORT_QUIC: {
            stream->trans_ops = xqc_moq_quic_stream_ops;
            break;
        }
        /*case XQC_MOQ_TRANSPORT_WEBTRANSPORT: {
            //TODO: WEBTRANSPORT
            stream->trans_ops = xqc_moq_wt_stream_ops;
            break;
        }*/
        default: {
            xqc_log(session->log, XQC_LOG_ERROR, "|transport_type error|");
            goto error;
        }
    }

    stream->session = session;
    xqc_init_list_head(&stream->list_member);

    return stream;

error:
    xqc_free(stream);
    return NULL;
}

void
xqc_moq_stream_destroy(xqc_moq_stream_t *stream)
{
    xqc_moq_session_t *session = stream->session;
    xqc_stream_t *quic_stream = stream->trans_ops.quic_stream(stream->trans_stream);
    xqc_usec_t now = xqc_monotonic_timestamp();
    
    if (stream == stream->session->ctl_stream) {
        stream->session->ctl_stream = NULL;
        /* The control stream MUST NOT be abruptly closed at the underlying transport layer.
         * Doing so results in the session being closed as a 'Protocol Violation'. */
        if (quic_stream->stream_conn->conn_state <= XQC_CONN_STATE_ESTABED) {
            xqc_log(session->log, XQC_LOG_ERROR, "|control stream closed|");
            xqc_moq_session_error(session, MOQ_PROTOCOL_VIOLATION, "control stream closed");
        }
    }
    
    if (stream == session->datachannel.ordered_stream) {
        session->datachannel.ordered_stream = NULL;
        if (quic_stream->stream_conn->conn_state <= XQC_CONN_STATE_ESTABED) {
            xqc_log(session->log, XQC_LOG_ERROR, "|datachannel stream closed|");
            xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "datachannel stream closed");
        }
    }
    
    if (quic_stream && quic_stream->stream_stats.all_data_acked_time
        && stream->track && stream->track->track_info.track_type == XQC_MOQ_TRACK_VIDEO)
    {
        xqc_usec_t latest_delay = quic_stream->stream_stats.all_data_acked_time - quic_stream->stream_stats.create_time;
        xqc_moq_track_t *track = stream->track;
        xqc_moq_track_info_t *track_info = track ? &track->track_info : NULL;
        xqc_moq_bitrate_alloc_on_frame_acked(session, track, track_info, latest_delay, 
                                             quic_stream->stream_stats.create_time, now, 
                                             quic_stream->stream_send_offset, stream->seq_num);
    }

    // if stream finished && stream is fec protected type (video or audio)
    if (quic_stream && xqc_is_stream_finished(quic_stream) 
        && (stream->moq_frame_type & (1 << MOQ_VIDEO_FRAME)))
    {
        // calculate current stream close delay and average session close delay
        xqc_record_stream_state(quic_stream);
    }

    if (stream->track && stream->track->subgroup_stream == stream) {
        stream->track->subgroup_stream = NULL;
    }

    xqc_free(stream->read_buf);
    stream->read_buf = NULL;

    xqc_free(stream->write_buf);
    stream->write_buf = NULL;

    xqc_moq_stream_free_cur_decode_msg(stream);

    xqc_list_del_init(&stream->list_member);

    xqc_free(stream);
}

xqc_moq_stream_t *
xqc_moq_stream_create_with_transport(xqc_moq_session_t *session, xqc_stream_direction_t direction)
{
    xqc_moq_stream_t *moq_stream;
    moq_stream = xqc_moq_stream_create(session);
    if (moq_stream == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|create moq stream error|");
        return NULL;
    }

    moq_stream->trans_stream = moq_stream->trans_ops.create(session->trans_conn, direction, moq_stream);
    if (moq_stream->trans_stream == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|create transport stream error|direction:%d|", direction);
        goto error;
    }

    return moq_stream;

error:
    xqc_moq_stream_destroy(moq_stream);
    return NULL;
}

xqc_int_t
xqc_moq_stream_close(xqc_moq_stream_t *moq_stream)
{
    return moq_stream->trans_ops.close(moq_stream->trans_stream);
}

xqc_int_t
xqc_moq_stream_write(xqc_moq_stream_t *moq_stream)
{
    xqc_int_t   ret;
    
    ret = 0;

    // FEC initiation
    if (moq_stream->enable_fec) {
        xqc_init_quic_fec(moq_stream);
    }

    ret = moq_stream->trans_ops.write(moq_stream->trans_stream,
                                      moq_stream->write_buf + moq_stream->write_buf_processed,
                                      moq_stream->write_buf_len - moq_stream->write_buf_processed,
                                      moq_stream->write_stream_fin);
    if (ret == -XQC_EAGAIN) {
        return XQC_OK;
    } else if (ret < 0) {
        return ret;
    } else {
        moq_stream->write_buf_processed += ret;
    }
    return XQC_OK;
}

void
xqc_moq_stream_on_track_write(xqc_moq_stream_t *moq_stream, xqc_moq_track_t *track,
    uint64_t group_id, uint64_t object_id, uint64_t seq_num)
{
    moq_stream->track = track;
    moq_stream->group_id = group_id;
    moq_stream->object_id = object_id;
    moq_stream->seq_num = seq_num;
}

void *
xqc_moq_stream_get_or_alloc_cur_decode_msg(xqc_moq_stream_t *moq_stream)
{
    if (moq_stream->decode_msg_ctx.cur_decode_msg) {
        return moq_stream->decode_msg_ctx.cur_decode_msg;
    }

    xqc_moq_msg_type_t type = moq_stream->decode_msg_ctx.cur_msg_type;
    // on non-control streams, SUBGROUP_HEADER types (0x10-0x1D) map to the internal SUBGROUP message type
    if (moq_stream->session && moq_stream != moq_stream->session->ctl_stream
        && type >= 0x10 && type <= 0x1D) {
        type = XQC_MOQ_MSG_SUBGROUP;
    } else if (type == XQC_MOQ_MSG_SUBGROUP_STREAM_OBJECT) {
        type = XQC_MOQ_MSG_SUBGROUP;
    }

    void *msg = xqc_moq_msg_create(type);
    if (msg == NULL) {
        return NULL;
    }

    moq_stream->decode_msg_ctx.cur_decode_msg = msg;
    return msg;
}

void
xqc_moq_stream_free_cur_decode_msg(xqc_moq_stream_t *moq_stream)
{
    xqc_moq_msg_type_t type = moq_stream->decode_msg_ctx.cur_msg_type;
    if (moq_stream->session && moq_stream != moq_stream->session->ctl_stream
        && type >= 0x10 && type <= 0x1D) {
        type = XQC_MOQ_MSG_SUBGROUP;
    } else if (type == XQC_MOQ_MSG_SUBGROUP_STREAM_OBJECT) {
        type = XQC_MOQ_MSG_SUBGROUP;
    }
    xqc_moq_msg_free(type, moq_stream->decode_msg_ctx.cur_decode_msg);
    moq_stream->decode_msg_ctx.cur_decode_msg = NULL;
}

void
xqc_moq_stream_clean_decode_msg_ctx(xqc_moq_stream_t *moq_stream)
{
    xqc_moq_stream_free_cur_decode_msg(moq_stream);
    xqc_moq_decode_msg_ctx_reset(&moq_stream->decode_msg_ctx);
}

//return processed or error
xqc_int_t
xqc_moq_stream_process(xqc_moq_stream_t *moq_stream, uint8_t *buf, size_t buf_len, uint8_t fin)
{
    xqc_int_t stop = 0;
    xqc_moq_msg_type_t msg_type = 0xFF;
    xqc_int_t remained = moq_stream->remain_read_buf_len;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_int_t msg_finish = 0;
    xqc_int_t wait_more_data = 0;
    if (moq_stream->remain_read_buf_len + buf_len > moq_stream->read_buf_cap) {
        moq_stream->read_buf_cap = moq_stream->remain_read_buf_len + buf_len;
        moq_stream->read_buf = xqc_realloc(moq_stream->read_buf, moq_stream->read_buf_cap);
    }
    if (moq_stream->remain_read_buf_len > 0) {
        moq_stream->read_buf_len = moq_stream->remain_read_buf_len + buf_len;
        xqc_memcpy(moq_stream->read_buf, moq_stream->remain_read_buf, moq_stream->remain_read_buf_len);
        xqc_memcpy(moq_stream->read_buf + moq_stream->remain_read_buf_len, buf, buf_len);
        moq_stream->remain_read_buf_len = 0;
    } else {
        moq_stream->read_buf_len = buf_len;
        xqc_memcpy(moq_stream->read_buf, buf, buf_len);
    }
    moq_stream->read_buf_processed = 0;

    do {
        switch (moq_stream->decode_msg_ctx.cur_decode_state) {
            case XQC_MOQ_DECODE_MSG_TYPE:
                ret = xqc_moq_msg_decode_type(moq_stream->read_buf + moq_stream->read_buf_processed,
                                              moq_stream->read_buf_len - moq_stream->read_buf_processed,
                                              &msg_type, &wait_more_data);
                if (ret < 0) {
                    xqc_log(moq_stream->session->log, XQC_LOG_ERROR,
                            "|decode message type error|ret:%d|", ret);
                    return ret;
                }
                moq_stream->read_buf_processed += ret;
                processed += ret;

                xqc_log(moq_stream->session->log, XQC_LOG_DEBUG,
                        "|decode message type|ret:%d|msg_type:0x%xi|wait_more_data:%d|processed:%d|",
                        ret, msg_type, wait_more_data, processed);

                if (wait_more_data == 1) {
                    stop = 1;
                    break;
                }

                DEBUG_PRINTF(">>>msg_type:0x%x\n",msg_type);

                moq_stream->decode_msg_ctx.cur_msg_type = msg_type;
                moq_stream->decode_msg_ctx.cur_decode_state = XQC_MOQ_DECODE_MSG;
                break;
            case XQC_MOQ_DECODE_MSG:
                ret = xqc_moq_stream_process_msg(moq_stream, fin, &msg_finish, &wait_more_data);
                if (ret < 0 || (ret == 0 && wait_more_data == 0)) {
                    xqc_log(moq_stream->session->log, XQC_LOG_ERROR,
                            "|decode message error|ret:%d|msg_type:0x%xi|cur_field_idx:%d|",
                            ret, moq_stream->decode_msg_ctx.cur_msg_type, moq_stream->decode_msg_ctx.cur_field_idx);
                    xqc_moq_stream_clean_decode_msg_ctx(moq_stream);
                    return -XQC_EILLEGAL_FRAME;
                }
                processed += ret;

                xqc_log(moq_stream->session->log, XQC_LOG_DEBUG,
                        "|decode message|ret:%d|msg_type:0x%xi|msg_finish:%d|wait_more_data:%d|processed:%d|",
                        ret, moq_stream->decode_msg_ctx.cur_msg_type, msg_finish, wait_more_data, processed);

                if (wait_more_data == 1) {
                    stop = 1;
                    break;
                }
                if (msg_finish == 1) {
                    DEBUG_PRINTF(">>>msg decode finish\n");
                    xqc_moq_decode_state_t next_state = XQC_MOQ_DECODE_MSG_TYPE;
                    xqc_moq_msg_type_t cur_msg_type = moq_stream->decode_msg_ctx.cur_msg_type;
                    xqc_moq_msg_type_t next_msg_type = 0xFF;
                    if (cur_msg_type == XQC_MOQ_MSG_STREAM_HEADER_TRACK
                        || cur_msg_type == XQC_MOQ_MSG_TRACK_STREAM_OBJECT) {
                        next_state = XQC_MOQ_DECODE_MSG;
                        next_msg_type = XQC_MOQ_MSG_TRACK_STREAM_OBJECT;
                    } else if (cur_msg_type == XQC_MOQ_MSG_STREAM_HEADER_GROUP
                               || cur_msg_type == XQC_MOQ_MSG_GROUP_STREAM_OBJECT) {
                        next_state = XQC_MOQ_DECODE_MSG;
                        next_msg_type = XQC_MOQ_MSG_GROUP_STREAM_OBJECT;
                    } else if (moq_stream->session && moq_stream != moq_stream->session->ctl_stream
                               && cur_msg_type >= 0x10 && cur_msg_type <= 0x1D) {
                        next_state = XQC_MOQ_DECODE_MSG;
                        next_msg_type = XQC_MOQ_MSG_SUBGROUP_STREAM_OBJECT;
                    } else if (cur_msg_type == XQC_MOQ_MSG_SUBGROUP_STREAM_OBJECT) {
                        next_state = XQC_MOQ_DECODE_MSG;
                        next_msg_type = XQC_MOQ_MSG_SUBGROUP_STREAM_OBJECT;
                    }
                    xqc_moq_stream_clean_decode_msg_ctx(moq_stream);
                    moq_stream->decode_msg_ctx.cur_decode_state = next_state;
                    moq_stream->decode_msg_ctx.cur_msg_type = next_msg_type;
                    break;
                }
                break;
            default:
                xqc_log(moq_stream->session->log, XQC_LOG_ERROR,
                        "|decode state error|state:%d|", moq_stream->decode_msg_ctx.cur_decode_state);
                return -XQC_EILLEGAL_FRAME;
        }
    } while (stop == 0);

    moq_stream->remain_read_buf_len = moq_stream->read_buf_len - moq_stream->read_buf_processed;
    if (moq_stream->remain_read_buf_len >= 8) {
        xqc_log(moq_stream->session->log, XQC_LOG_ERROR,
                "|remain_read_buf_len error|remain_read_buf_len:%uz|", moq_stream->remain_read_buf_len);
        return -XQC_EILLEGAL_FRAME;
    } else if (moq_stream->remain_read_buf_len > 0) {
        xqc_memcpy(moq_stream->remain_read_buf, moq_stream->read_buf + moq_stream->read_buf_processed,
                   moq_stream->remain_read_buf_len);
        processed += moq_stream->remain_read_buf_len;
    }

    processed -= remained;
    if (processed != buf_len) {
        xqc_log(moq_stream->session->log, XQC_LOG_ERROR,
                "|input buf not processed completely|");
        return -XQC_EILLEGAL_FRAME;
    }
    return processed;
}


//return processed or error
xqc_int_t
xqc_moq_stream_process_msg(xqc_moq_stream_t *moq_stream, uint8_t stream_fin, xqc_int_t *msg_finish, xqc_int_t *wait_more_data)
{
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    *msg_finish = 0;
    *wait_more_data = 0;

    xqc_moq_msg_base_t *msg_base = xqc_moq_stream_get_or_alloc_cur_decode_msg(moq_stream);
    if (msg_base == NULL) {
        xqc_log(moq_stream->session->log, XQC_LOG_ERROR, "|unkonwn message type|msg_type:0x%xi|",
                moq_stream->decode_msg_ctx.cur_msg_type);
        return ret;
    }

    if (moq_stream->decode_msg_ctx.cur_msg_type == XQC_MOQ_MSG_SUBGROUP_STREAM_OBJECT) {
        if (!moq_stream->subgroup_header_valid) {
            xqc_log(moq_stream->session->log, XQC_LOG_ERROR,
                    "|subgroup stream object without header|");
            return -XQC_EILLEGAL_FRAME;
        }
        xqc_moq_subgroup_msg_t *subgroup = (xqc_moq_subgroup_msg_t *)msg_base;
        subgroup->track_alias = moq_stream->subgroup_header.track_alias;
        subgroup->group_id = moq_stream->subgroup_header.group_id;
        subgroup->subgroup_id = moq_stream->subgroup_header.subgroup_id;
        subgroup->subgroup_type = moq_stream->subgroup_header.subgroup_type;
        subgroup->subgroup_priority = moq_stream->subgroup_header.subgroup_priority;
        if (moq_stream->decode_msg_ctx.cur_field_idx < 4) {
            moq_stream->decode_msg_ctx.cur_field_idx = 4; // start decoding from object_delta
        }
    }
    ret = msg_base->decode(moq_stream->read_buf + moq_stream->read_buf_processed,
                           moq_stream->read_buf_len - moq_stream->read_buf_processed,
                           stream_fin,
                           &moq_stream->decode_msg_ctx,
                           msg_base,
                           msg_finish, wait_more_data);
    if (ret < 0) {
        return ret;
    }
    moq_stream->read_buf_processed += ret;
    processed += ret;

    if (*wait_more_data == 1) {
        return processed;
    }
    if (*msg_finish == 1) {
        msg_base->on_msg(moq_stream->session, moq_stream, msg_base);
    }

    return processed;
}

