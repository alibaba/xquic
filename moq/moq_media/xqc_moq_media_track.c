#include "moq/moq_media/xqc_moq_media_track.h"
#include "moq/moq_media/xqc_moq_container_loc.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_transport/xqc_moq_message.h"
#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/xqc_moq_subscribe.h"
#include "moq/moq_media/xqc_moq_av_frame_ext.h"
#include "moq/moq_media/dejitter/xqc_moq_av_dejitter.h"
#include "moq/xqc_moq.h"
#include "src/common/xqc_log.h"
#include "src/transport/xqc_stream.h"

#define XQC_MOQ_MEDIA_MAX_SEND_DELAY 500000 /* 500ms */

static void xqc_moq_media_on_create(xqc_moq_track_t *track);
static void xqc_moq_media_on_destroy(xqc_moq_track_t *track);
static void xqc_moq_media_on_subscribe_v05(xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_subscribe_msg_t_v05 *msg);
static void xqc_moq_media_on_subscribe_v13(xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_subscribe_msg_t_v13 *msg);
static void xqc_moq_media_on_subscribe_update_v05(xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_subscribe_update_msg_t_v05 *update);
// static void xqc_moq_media_on_subscribe_update_v13(xqc_moq_session_t *session, uint64_t subscribe_id,
//     xqc_moq_track_t *track, xqc_moq_subscribe_update_msg_t_v13 *update);
static void xqc_moq_media_on_subscribe_ok(xqc_moq_session_t *session, xqc_moq_track_t *track,
    xqc_moq_subscribe_ok_msg_t *subscribe_ok);
static void xqc_moq_media_on_subscribe_error(xqc_moq_session_t *session, xqc_moq_track_t *track,
    xqc_moq_subscribe_error_msg_t *subscribe_error);
static void xqc_moq_media_on_object(xqc_moq_session_t *session, xqc_moq_track_t *track, xqc_moq_object_t *object);

const xqc_moq_track_ops_t xqc_moq_media_track_ops = {
    .on_create           = xqc_moq_media_on_create,
    .on_destroy          = xqc_moq_media_on_destroy,
    .on_subscribe_v05    = xqc_moq_media_on_subscribe_v05,
    .on_subscribe_v13    = xqc_moq_media_on_subscribe_v13,
    .on_subscribe_update_v05 = xqc_moq_media_on_subscribe_update_v05,
    .on_subscribe_update_v13 = NULL, // TODO add v13 support
    .on_subscribe_ok     = xqc_moq_media_on_subscribe_ok,
    .on_subscribe_error  = xqc_moq_media_on_subscribe_error,
    .on_object           = xqc_moq_media_on_object,
};

static void xqc_moq_media_cancel_write(xqc_moq_session_t *session, xqc_moq_track_t *track);
static xqc_bool_t xqc_moq_media_maybe_cancel_write(xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_video_frame_t *video_frame);

xqc_int_t
xqc_moq_write_video_frame_v11(xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_video_frame_t *video_frame)
{
    xqc_int_t ret = 0;
    xqc_int_t encoded_len;
    xqc_moq_stream_t *stream;
    xqc_moq_subgroup_msg_t *subgroup;
    xqc_moq_subgroup_object_msg_t subgroup_object;
    xqc_moq_media_track_t *media_track = (xqc_moq_media_track_t*)track;
    
    if (xqc_moq_media_maybe_cancel_write(session, subscribe_id, track, video_frame)) {
        xqc_log(session->log, XQC_LOG_INFO, "|drop video frame|track_name:%s|subscribe_id:%ui|seq:%ui|type:%d|",
                track->track_info.track_name, subscribe_id, video_frame->seq_num, video_frame->type);
        return XQC_OK;
    }
    
    size_t buf_cap = video_frame->video_len + XQC_MOQ_MAX_CONTAINER_OVERHEAD;
    uint8_t *buf = xqc_malloc(buf_cap);
    ret = media_track->container_ops.encode_video(video_frame, buf, buf_cap, &encoded_len);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|encode video container error|ret:%d|", ret);
        goto error;
    }
    // stream = xqc_moq_stream_create_with_transport(session, XQC_STREAM_UNI);
    // if (stream == NULL) {
    //     xqc_log(session->log, XQC_LOG_ERROR, "|create moq stream error|");
    //     ret = -XQC_ECREATE_STREAM;
    //     goto error;
    // }

    
    // if (video_frame->type == XQC_MOQ_VIDEO_KEY) {
    //     // TODO remove last stream
    //     if(track->cur_group_id > 0){
            
    //         // stream = xqc_moq_find_stream_by_group_id(track, track->cur_group_id);
    //         stream = media_track->send_stream;
    //         if (stream == NULL) {
    //             xqc_log(session->log, XQC_LOG_ERROR, "|find stream by group_id error|group_id:%ui|", track->cur_group_id);
    //             ret = -XQC_ECREATE_STREAM;
    //             goto error;
    //         }
    //         subgroup_object.subgroup_header = stream->subgroup_header;
    //         subgroup_object.object_id = track->cur_object_id++;
    //         subgroup_object.payload = NULL;
    //         subgroup_object.payload_len = 0;
    //         subgroup_object.object_status = XQC_MOQ_OBJ_STATUS_NORMAL;
    //         stream->write_stream_fin = 1;
    //         ret = xqc_moq_write_subgroup_object_msg(session, stream, &subgroup_object);
    //         if (ret < 0) {
    //             xqc_log(session->log, XQC_LOG_ERROR, "|write_subgroup_object_msg error|ret:%d|", ret);
    //             goto error;
    //         }
    //         // TODO remove last stream
    //     }

    //     stream = xqc_moq_stream_create_with_transport(session, XQC_STREAM_UNI);
    //     if (stream == NULL) {
    //         xqc_log(session->log, XQC_LOG_ERROR, "|create moq stream error|");
    //         ret = -XQC_ECREATE_STREAM;
    //         goto error;
    //     }
    //     stream->group_id = track->cur_group_id+1;
    //     xqc_list_add_tail(&stream->list_member, &media_track->write_stream_list);
    //     media_track->send_stream = stream;
    //     subgroup = xqc_calloc(1, sizeof(xqc_moq_subgroup_msg_t));
    //     subgroup->track_alias = track->track_alias;
    //     subgroup->group_id = ++track->cur_group_id;
    //     subgroup->subgroup_id = 0;
    //     subgroup->publish_priority = 0;
    //     if(media_track->subgroup_header == NULL){
    //         // TODO free subgroup
    //     }
    //     media_track->subgroup_header = subgroup;
    //     stream->write_stream_fin = 0;
    //     ret = xqc_moq_write_subgroup_msg(session, stream, subgroup);
    //     xqc_moq_stream_on_track_write(stream, track, subgroup->group_id, subgroup_object.object_id, video_frame->seq_num);
    //     if (ret < 0) {
    //         xqc_log(session->log, XQC_LOG_ERROR, "|write_subgroup_msg error|ret:%d|", ret);
    //         goto error;
    //     }

    //     subgroup_object.subgroup_header = subgroup;
    //     // subgroup_object.object_id = track->cur_object_id++;
    //     subgroup_object.object_id = 0;
    //     subgroup_object.payload = buf;
    //     subgroup_object.payload_len = encoded_len;

    //     track->cur_object_id = 0;
    //     stream->write_stream_fin = 0;
    // } else {
    //     stream = media_track->send_stream;
    //     // media_track->send_stream = stream;
    //     // stream = xqc_moq_find_stream_by_group_id(track, track->cur_group_id);
        // if (stream == NULL) {
        //     xqc_log(session->log, XQC_LOG_ERROR, "|find stream by group_id error|group_id:%ui|", track->cur_group_id);
        //     ret = -XQC_ECREATE_STREAM;
        //     goto error;
        // }
    //     subgroup_object.subgroup_header = media_track->subgroup_header;
    //     subgroup_object.object_id = track->cur_object_id++;
    //     // subgroup_object.object_id = 0;
    //     subgroup_object.payload = buf;
    //     subgroup_object.payload_len = encoded_len;

    //     subgroup = subgroup_object.subgroup_header;
    //     stream->write_stream_fin = 0;
    // }

    //test

    stream = xqc_moq_stream_create_with_transport(session, XQC_STREAM_UNI);
    if(stream == NULL){
        xqc_log(session->log, XQC_LOG_ERROR, "|create moq stream error|");
        ret = -XQC_ECREATE_STREAM;
        goto error;
    }
    subgroup = xqc_calloc(1, sizeof(xqc_moq_subgroup_msg_t));
    printf("subgroup->track_alias will be set to track->track_alias:%llu\n", track->track_alias);
    subgroup->track_alias = track->track_alias;
    subgroup->subgroup_id = 0;
    subgroup->publish_priority = 128; /* Use recommended default per draft-ietf-moq-transport */

    if(video_frame->type == XQC_MOQ_VIDEO_KEY){

        subgroup->group_id = track->cur_group_id++;
        subgroup->subgroup_id = track->cur_object_id++;
        // subgroup_object.object_id = track->cur_object_id++;
        subgroup_object.object_id = 0;
        subgroup_object.payload = buf;
        subgroup_object.payload_len = encoded_len;

        track->cur_object_id = 0;
    }
    else {
        subgroup->group_id = track->cur_group_id;
        subgroup->subgroup_id = track->cur_object_id++;
        subgroup_object.subgroup_header = media_track->subgroup_header;
        subgroup_object.object_id = 0;
        subgroup_object.payload = buf;
        subgroup_object.payload_len = encoded_len;

        subgroup = subgroup_object.subgroup_header;
    }


    if(media_track->subgroup_header == NULL){
        // TODO free subgroup
    }
    media_track->subgroup_header = subgroup;

    subgroup_object.subgroup_header = subgroup;
    subgroup_object.object_id = 0;
    subgroup_object.payload = buf;
    subgroup_object.payload_len = encoded_len;

    stream->write_stream_fin = 0;
    xqc_moq_stream_on_track_write(stream, track, subgroup->group_id, subgroup_object.object_id, video_frame->seq_num);
    ret = xqc_moq_write_subgroup_msg(session, stream, subgroup);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|write_subgroup_msg error|ret:%d|", ret);
        goto error;
    }


    stream->write_stream_fin = 1;
    ret = xqc_moq_write_subgroup_object_msg(session, stream, &subgroup_object);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|write_object_stream_msg error|ret:%d|", ret);
        goto error;
    }

    xqc_usec_t now = xqc_monotonic_timestamp();
    xqc_moq_fps_counter_insert(&media_track->fps_counter, now);
    xqc_int_t write_fps = xqc_moq_fps_counter_get(&media_track->fps_counter, now, 1000000);

    xqc_stream_t *quic_stream = stream->trans_ops.quic_stream(stream->trans_stream);
    
    xqc_free(buf);
    xqc_log(session->log, XQC_LOG_INFO,
            "|write video frame success|track_name:%s|subscribe_id:%ui|seq:%ui|"
            "group_id:%ui|object_id:%ui|stream_id:%ui|video_len:%ui|type:%d|fps:%d|",
            track->track_info.track_name, subscribe_id, video_frame->seq_num, 
            subgroup->group_id, subgroup_object.object_id, quic_stream->stream_id, video_frame->video_len, 
            video_frame->type, write_fps);
    return XQC_OK;

error:
    xqc_free(buf);
    return ret;
}

xqc_int_t
xqc_moq_write_video_frame(xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_video_frame_t *video_frame)
{
    if(session->version >= XQC_MOQ_VERSION_DRAFT_11) {
        return xqc_moq_write_video_frame_v11(session, subscribe_id, track, video_frame);
    }
    xqc_int_t ret = 0;
    xqc_int_t encoded_len;
    xqc_moq_stream_t *stream;
    xqc_moq_object_stream_msg_t object;
    xqc_moq_media_track_t *media_track = (xqc_moq_media_track_t*)track;
    
    if (xqc_moq_media_maybe_cancel_write(session, subscribe_id, track, video_frame)) {
        xqc_log(session->log, XQC_LOG_INFO, "|drop video frame|track_name:%s|subscribe_id:%ui|seq:%ui|type:%d|",
                track->track_info.track_name, subscribe_id, video_frame->seq_num, video_frame->type);
        return XQC_OK;
    }
    
    size_t buf_cap = video_frame->video_len + XQC_MOQ_MAX_CONTAINER_OVERHEAD;
    uint8_t *buf = xqc_malloc(buf_cap);
    ret = media_track->container_ops.encode_video(video_frame, buf, buf_cap, &encoded_len);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|encode video container error|ret:%d|", ret);
        goto error;
    }

    stream = xqc_moq_stream_create_with_transport(session, XQC_STREAM_UNI);
    if (stream == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|create moq stream error|");
        ret = -XQC_ECREATE_STREAM;
        goto error;
    }
    stream->write_stream_fin = 1;
    stream->enable_fec = session->enable_fec;
    stream->fec_code_rate = session->fec_code_rate;
    stream->moq_frame_type |= (1 << MOQ_VIDEO_FRAME);

    object.subscribe_id = subscribe_id;
    object.track_alias = track->track_alias;
    object.send_order = 0; //TODO
    object.status = XQC_MOQ_OBJ_STATUS_NORMAL;
    object.payload = buf;
    object.payload_len = encoded_len;
    if (video_frame->type == XQC_MOQ_VIDEO_KEY) {
        object.group_id = ++track->cur_group_id;
        track->cur_object_id = 0;
        object.object_id = track->cur_object_id++;
    } else {
        object.group_id = track->cur_group_id;
        object.object_id = track->cur_object_id++;
    }

    xqc_moq_stream_on_track_write(stream, track, object.group_id, object.object_id, video_frame->seq_num);
    xqc_list_add_tail(&stream->list_member, &media_track->write_stream_list);

    ret = xqc_moq_write_object_stream_msg(session, stream, &object);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|write_object_stream_msg error|ret:%d|", ret);
        goto error;
    }

    xqc_usec_t now = xqc_monotonic_timestamp();
    xqc_moq_fps_counter_insert(&media_track->fps_counter, now);
    xqc_int_t write_fps = xqc_moq_fps_counter_get(&media_track->fps_counter, now, 1000000);

    xqc_stream_t *quic_stream = stream->trans_ops.quic_stream(stream->trans_stream);
    
    xqc_free(buf);
    xqc_log(session->log, XQC_LOG_INFO,
            "|write video frame success|track_name:%s|subscribe_id:%ui|seq:%ui|"
            "group_id:%ui|object_id:%ui|stream_id:%ui|video_len:%ui|type:%d|fps:%d|",
            track->track_info.track_name, subscribe_id, video_frame->seq_num, 
            object.group_id, object.object_id, quic_stream->stream_id, video_frame->video_len, 
            video_frame->type, write_fps);
    return XQC_OK;

error:
    xqc_free(buf);
    return ret;
}

xqc_int_t
xqc_moq_write_audio_frame_v11(xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_audio_frame_t *audio_frame)
{
    xqc_int_t ret = 0;
    xqc_int_t encoded_len;
    xqc_moq_stream_t *stream;
    xqc_moq_subgroup_msg_t subgroup;
    xqc_moq_subgroup_object_msg_t object;
    xqc_moq_media_track_t *media_track = (xqc_moq_media_track_t*)track;
    size_t buf_cap = audio_frame->audio_len + XQC_MOQ_MAX_CONTAINER_OVERHEAD;
    uint8_t *buf = xqc_malloc(buf_cap);
    ret = media_track->container_ops.encode_audio(audio_frame, buf, buf_cap, &encoded_len);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|encode audio container error|ret:%d|", ret);
        goto error;
    }

    stream = xqc_moq_stream_create_with_transport(session, XQC_STREAM_UNI);
    if (stream == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|create moq stream error|");
        ret = -XQC_ECREATE_STREAM;
        goto error;
    }
    stream->write_stream_fin = 1;
    subgroup.track_alias = track->track_alias;
    subgroup.group_id = track->cur_group_id;
    subgroup.subgroup_id = 0;
    subgroup.publish_priority = 0;
    stream->write_stream_fin = 0;
    ret = xqc_moq_write_subgroup_msg(session, stream, &subgroup);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|write_subgroup_msg error|ret:%d|", ret);
        goto error;
    }
    
    object.subgroup_header = &subgroup;
    object.object_id = 0;
    object.payload = buf;
    object.payload_len = encoded_len;

    xqc_moq_stream_on_track_write(stream, track, subgroup.group_id, object.object_id, audio_frame->seq_num);
    xqc_list_add_tail(&stream->list_member, &media_track->write_stream_list);

    stream->write_stream_fin = 1;
    ret = xqc_moq_write_subgroup_object_msg(session, stream, &object);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|write_object_stream_msg error|ret:%d|", ret);
        goto error;
    }

    
    xqc_stream_t *quic_stream = stream->trans_ops.quic_stream(stream->trans_stream);

    xqc_free(buf);
    xqc_log(session->log, XQC_LOG_INFO,
            "|write audio frame success|track_name:%s|subscribe_id:%ui|seq:%ui|"
            "group_id:%ui|subgroup_id:%ui|stream_id:%ui|audio_len:%ui|",
            track->track_info.track_name, subscribe_id, audio_frame->seq_num, 
            subgroup.group_id, object.object_id, quic_stream->stream_id, audio_frame->audio_len);
    return XQC_OK;

error:
    xqc_free(buf);
    return ret;
}

xqc_int_t
xqc_moq_write_audio_frame(xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_audio_frame_t *audio_frame)
{
    if(session->version >= XQC_MOQ_VERSION_DRAFT_11) {
        return xqc_moq_write_audio_frame_v11(session, subscribe_id, track, audio_frame);
    }
    xqc_int_t ret = 0;
    xqc_int_t encoded_len;
    xqc_moq_stream_t *stream;
    xqc_moq_object_stream_msg_t object;
    xqc_moq_media_track_t *media_track = (xqc_moq_media_track_t*)track;
    size_t buf_cap = audio_frame->audio_len + XQC_MOQ_MAX_CONTAINER_OVERHEAD;
    uint8_t *buf = xqc_malloc(buf_cap);
    ret = media_track->container_ops.encode_audio(audio_frame, buf, buf_cap, &encoded_len);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|encode audio container error|ret:%d|", ret);
        goto error;
    }

    stream = xqc_moq_stream_create_with_transport(session, XQC_STREAM_UNI);
    if (stream == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|create moq stream error|");
        ret = -XQC_ECREATE_STREAM;
        goto error;
    }
    stream->write_stream_fin = 1;

    object.subscribe_id = subscribe_id;
    object.track_alias = track->track_alias;
    object.send_order = 0; //TODO
    object.status = XQC_MOQ_OBJ_STATUS_NORMAL;
    object.payload = buf;
    object.payload_len = encoded_len;
    object.group_id = track->cur_group_id;
    object.object_id = track->cur_object_id++;

    xqc_moq_stream_on_track_write(stream, track, object.group_id, object.object_id, audio_frame->seq_num);
    xqc_list_add_tail(&stream->list_member, &media_track->write_stream_list);

    ret = xqc_moq_write_object_stream_msg(session, stream, &object);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|write_object_stream_msg error|ret:%d|", ret);
        goto error;
    }
    
    xqc_stream_t *quic_stream = stream->trans_ops.quic_stream(stream->trans_stream);

    xqc_free(buf);
    xqc_log(session->log, XQC_LOG_INFO,
            "|write audio frame success|track_name:%s|subscribe_id:%ui|seq:%ui|"
            "group_id:%ui|object_id:%ui|stream_id:%ui|audio_len:%ui|",
            track->track_info.track_name, subscribe_id, audio_frame->seq_num, 
            object.group_id, object.object_id, quic_stream->stream_id, audio_frame->audio_len);
    return XQC_OK;

error:
    xqc_free(buf);
    return ret;
}

static void
xqc_moq_media_cancel_write(xqc_moq_session_t *session, xqc_moq_track_t *track)
{
    xqc_list_head_t *pos, *next;
    xqc_moq_stream_t *stream;
    xqc_stream_t *quic_stream;
    xqc_moq_media_track_t *media_track = (xqc_moq_media_track_t*)track;
    uint64_t group_id = media_track->drop_group_id_before;
    uint64_t object_id = media_track->drop_object_id_before;

    xqc_log(session->log, XQC_LOG_INFO, "|cancel stream before|track_name:%s|subscribe_id:%ui|group_id:%ui|object_id:%ui|",
            track->track_info.track_name, track->subscribe_id, group_id, object_id);

search_from_head:
    xqc_list_for_each_safe(pos, next, &media_track->write_stream_list) {
        stream = xqc_list_entry(pos, xqc_moq_stream_t, list_member);
        quic_stream = stream->trans_ops.quic_stream(stream->trans_stream);
        if (stream->group_id < group_id
            || (stream->group_id == group_id && stream->object_id < object_id)) {
            xqc_log(session->log, XQC_LOG_INFO, "|do cancel stream|group_id:%ui|object_id:%ui|send_state:%d|",
                    stream->group_id, stream->object_id, quic_stream->stream_state_send);
            xqc_list_del_init(&stream->list_member); /* Delete here or on moq stream destroy */
            xqc_moq_stream_close(stream);
            
            /* If the next node is deleted in xqc_moq_stream_close, search from head */
            if (next->next == next) {
                xqc_log(session->log, XQC_LOG_WARN, "|next node deleted|group_id:%ui|object_id:%ui|send_state:%d|",
                        stream->group_id, stream->object_id, quic_stream->stream_state_send);
                goto search_from_head;
            }
        } else {
            break;
        }
    }
}

static xqc_bool_t 
xqc_moq_media_maybe_cancel_write(xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_video_frame_t *video_frame)
{
    xqc_list_head_t *pos, *next;
    xqc_moq_stream_t *stream;
    xqc_stream_t *quic_stream;
    xqc_usec_t create_time;
    xqc_usec_t now = xqc_monotonic_timestamp();
    xqc_int_t need_request_keyframe = 0;
    xqc_moq_media_track_t *media_track = (xqc_moq_media_track_t*)track;
    
    xqc_list_for_each_safe(pos, next, &media_track->write_stream_list) {
        stream = xqc_list_entry(pos, xqc_moq_stream_t, list_member);
        quic_stream = stream->trans_ops.quic_stream(stream->trans_stream);
        create_time = quic_stream->stream_stats.create_time;
        if (now - create_time < XQC_MOQ_MEDIA_MAX_SEND_DELAY) {
            break;
        }
        if (quic_stream->stream_state_send < XQC_SEND_STREAM_ST_DATA_RECVD) {
            xqc_log(session->log, XQC_LOG_INFO, "|video frame timeout|seq:%ui|group_id:%ui|object_id:%ui|",
                    video_frame->seq_num, stream->group_id, stream->object_id);
            
            media_track->drop_group_id_before = xqc_max(stream->group_id + 1, media_track->drop_group_id_before);
            media_track->drop_object_id_before = 0;
            need_request_keyframe = 1;
        }
    }
    
    if (need_request_keyframe) {
        xqc_moq_media_cancel_write(session, track);
    }
    
    if (video_frame->type == XQC_MOQ_VIDEO_KEY) {
        return XQC_FALSE;
    } else {
        if (need_request_keyframe) {
            xqc_log(session->log, XQC_LOG_INFO, "|on_request_keyframe|track_name:%s|", track->track_info.track_name);
            session->session_callbacks.on_request_keyframe(session->user_session, subscribe_id, track);
        }
        if (track->cur_group_id < media_track->drop_group_id_before) {
            return XQC_TRUE;
        } else {
            return XQC_FALSE;
        }
    }
}

static uint64_t
xqc_moq_media_track_get_largest_video_group_id(xqc_moq_track_t *track)
{
    xqc_moq_media_track_t *media_track = (xqc_moq_media_track_t *)track;
    if (media_track->dejitter == NULL) {
        xqc_log(media_track->track.session->log, XQC_LOG_ERROR,
                "|media_track dejitter is NULL|");
        return 0;
    }
    return xqc_moq_av_dejitter_get_largest_video_group_id(media_track->dejitter);
}

xqc_int_t
xqc_moq_request_keyframe(xqc_moq_session_t *session, uint64_t subscribe_id)
{
    xqc_int_t ret;
    xqc_moq_subscribe_t *subscribe;
    xqc_moq_track_t *track = NULL;
    uint64_t track_alias;

    subscribe = xqc_moq_find_subscribe(session, subscribe_id, 1);
    if (subscribe == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|subscribe not exist|subscribe_id:%ui|", subscribe_id);
        return -XQC_EPARAM;
    }

    /* For draft-11 and later */
    if (session->version >= XQC_MOQ_VERSION_DRAFT_11) {
        track = xqc_moq_find_track_by_subscribe_id(session, subscribe_id, XQC_MOQ_TRACK_FOR_SUB);
        if (track == NULL) {
            xqc_log(session->log, XQC_LOG_ERROR, "|track not found by subscribe_id|subscribe_id:%ui|", subscribe_id);
            return -XQC_EPARAM;
        }

        uint64_t largest_group_id = xqc_moq_media_track_get_largest_video_group_id(track);
        xqc_moq_subscribe_update_msg_t_v13 subscribe_update;
        xqc_memset(&subscribe_update, 0, sizeof(subscribe_update));
        subscribe_update.subscribe_id = subscribe_id;
        subscribe_update.start_group_id = largest_group_id + 1;
        subscribe_update.start_object_id = 0;
        subscribe_update.end_group = 0;
        subscribe_update.subscriber_priority = 0;
        subscribe_update.forward = 0;
        subscribe_update.params_num = 0;
        ret = xqc_moq_write_subscribe_update_v13(session, &subscribe_update);
        if (ret < 0) {
            xqc_log(session->log, XQC_LOG_ERROR,
                    "|xqc_moq_write_subscribe_update_v13 error|ret:%d|track_name:%s|subscribe_id:%ui|",
                    ret, track->track_info.track_name, subscribe_id);
            return ret;
        }
        xqc_log(session->log, XQC_LOG_INFO,
                "|request keyframe v13 success|track_name:%s|subscribe_id:%ui|start_group_id:%ui|",
                track->track_info.track_name, subscribe_id, subscribe_update.start_group_id);
        return XQC_OK;

    } else {
        /* For draft-05 */
        if (subscribe->subscribe_msg_v05 == NULL) {
            xqc_log(session->log, XQC_LOG_ERROR, "|subscribe v05 msg is NULL|subscribe_id:%ui|", subscribe_id);
            return -XQC_EPARAM;
        }
        track = xqc_moq_find_track_by_alias(session, subscribe->subscribe_msg_v05->track_alias, XQC_MOQ_TRACK_FOR_SUB);
        if (track == NULL) {
            xqc_log(session->log, XQC_LOG_ERROR, "|track not found|subscribe_id:%ui|", subscribe_id);
            return -XQC_EPARAM;
        }

        uint64_t largest_group_id = xqc_moq_media_track_get_largest_video_group_id(track);
        xqc_moq_subscribe_update_msg_t_v05 update;
        xqc_memset(&update, 0, sizeof(xqc_moq_subscribe_update_msg_t_v05));
        update.subscribe_id = subscribe_id;
        update.start_group_id = largest_group_id + 1;
        update.start_object_id = 0;
        update.end_group_id = 0;
        update.end_object_id = 0;
        update.params_num = 0;
        ret = xqc_moq_write_subscribe_update_v05(session, &update);
        if (ret < 0) {
            xqc_log(session->log, XQC_LOG_ERROR,
                    "|xqc_moq_write_subscribe_update error|ret:%d|track_name:%s|subscribe_id:%ui|",
                    ret, track->track_info.track_name, subscribe_id);
            return ret;
        }
        xqc_log(session->log, XQC_LOG_INFO, "|request keyframe success|track_name:%s|subscribe_id:%ui|start_group_id:%ui|",
                track->track_info.track_name, subscribe_id, update.start_group_id);
        return XQC_OK;
    }
}

static void
xqc_moq_on_decodable_video_frame_callback(xqc_moq_video_frame_ext_t *video_frame_ext, void *track_user_date)
{
    xqc_moq_media_track_t *media_track = (xqc_moq_media_track_t*)track_user_date;
    xqc_moq_video_frame_t *video_frame = &video_frame_ext->video_frame;
    xqc_moq_session_t *session = media_track->track.session;
    xqc_moq_track_t *track = &media_track->track;

    xqc_usec_t now = xqc_monotonic_timestamp();
    xqc_moq_fps_counter_insert(&media_track->fps_counter, now);
    xqc_int_t fps = xqc_moq_fps_counter_get(&media_track->fps_counter, now, 1000000);

    xqc_log(session->log, XQC_LOG_INFO,
            "|on_video|track_name:%s|track_alias:%ui|seq:%ui|group_id:%ui|object_id:%ui|fps:%d|",
            track->track_info.track_name, track->track_alias, video_frame->seq_num,
            video_frame_ext->group_id, video_frame_ext->object_id, fps);
    session->session_callbacks.on_video(session->user_session, track->subscribe_id, video_frame);
}

static void
xqc_moq_request_keyframe_callback(void *track_user_date)
{
    xqc_moq_media_track_t *media_track = (xqc_moq_media_track_t*)track_user_date;
    uint64_t subscribe_id = media_track->track.subscribe_id;
    xqc_moq_session_t *session = media_track->track.session;
    xqc_moq_request_keyframe(session, subscribe_id);
}

static void
xqc_moq_on_dejitter_output_audio(xqc_moq_session_t *session, xqc_moq_track_t *track,
    xqc_moq_audio_frame_ext_t *audio_frame_ext)
{
    xqc_moq_media_track_t *media_track = (xqc_moq_media_track_t*)track;
    xqc_moq_audio_frame_t *audio_frame = &audio_frame_ext->audio_frame;
    xqc_log(session->log, XQC_LOG_INFO,
            "|on_audio|track_name:%s|track_alias:%ui|seq:%ui|group_id:%ui|object_id:%ui|",
            track->track_info.track_name, track->track_alias, audio_frame->seq_num,
            audio_frame_ext->group_id, audio_frame_ext->object_id);
    session->session_callbacks.on_audio(session->user_session, track->subscribe_id, audio_frame);
}
 
/**
 * Media track ops
 */

static void
xqc_moq_media_on_create(xqc_moq_track_t *track)
{
    xqc_moq_media_track_t *media_track = (xqc_moq_media_track_t*)track;
    xqc_moq_session_t *session = track->session;
    xqc_moq_track_type_t track_type = track->track_info.track_type;

    switch (track->container_format) {
        case XQC_MOQ_CONTAINER_LOC:
            media_track->container_ops = xqc_moq_loc_ops;
            break;
        /*case XQC_MOQ_CONTAINER_CMAF:
            //TODO: CMAF
            media_track->container_ops = xqc_moq_cmaf_ops;
            break;*/
        default:
            media_track->container_ops = xqc_moq_loc_ops;
            break;
    }

    xqc_init_list_head(&media_track->write_stream_list);

    /* 
    * if subscribed track, add dejitter module add init
    */
    if (track->track_role == XQC_MOQ_TRACK_FOR_SUB) {
        xqc_bool_t is_video_track = (track_type == XQC_MOQ_TRACK_VIDEO);
        xqc_int_t audio_samplerate = track->track_info.selection_params.samplerate;
        media_track->dejitter = xqc_moq_av_dejitter_create(
                                    is_video_track, session->timer_manager,
                                    audio_samplerate, session->log, media_track);
        if (is_video_track) {
            media_track->dejitter->on_decodable_video_frame = 
                xqc_moq_on_decodable_video_frame_callback;
            media_track->dejitter->request_keyframe =
                xqc_moq_request_keyframe_callback;
        } else {
            // media_track->dejitter->decodable_audio_frame_callback = 
            //     xqc_moq_decodable_audio_frame_callback;
        }
    }
}

static void
xqc_moq_media_on_destroy(xqc_moq_track_t *track)
{
    xqc_moq_media_track_t *media_track = (xqc_moq_media_track_t*)track;
    if (media_track->dejitter != NULL) {
        xqc_moq_av_dejitter_destroy(media_track->dejitter);
    }
}

static void
xqc_moq_media_on_subscribe_v05(xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_subscribe_msg_t_v05 *msg)
{
    session->session_callbacks.on_subscribe_v05(session->user_session, subscribe_id, track, msg);
}

static void
xqc_moq_media_on_subscribe_v13(xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_subscribe_msg_t_v13 *msg)
{
    session->session_callbacks.on_subscribe_v13(session->user_session, subscribe_id, track, msg);
}

static void
xqc_moq_media_on_subscribe_update_v05(xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_subscribe_update_msg_t_v05 *update)
{
    xqc_moq_media_track_t *media_track = (xqc_moq_media_track_t*)track;
    media_track->drop_group_id_before = xqc_max(update->start_group_id, media_track->drop_group_id_before);
    media_track->drop_object_id_before = 0;
    xqc_moq_media_cancel_write(session, track);

    if (track->track_info.track_type == XQC_MOQ_TRACK_VIDEO) {
        xqc_log(session->log, XQC_LOG_INFO, "|on_request_keyframe|track_name:%s|", track->track_info.track_name);
        session->session_callbacks.on_request_keyframe(session->user_session, subscribe_id, track);
    }
}

static void
xqc_moq_media_on_subscribe_ok(xqc_moq_session_t *session, xqc_moq_track_t *track,
    xqc_moq_subscribe_ok_msg_t *subscribe_ok)
{
    session->session_callbacks.on_subscribe_ok(session->user_session, subscribe_ok);
}

static void
xqc_moq_media_on_subscribe_error(xqc_moq_session_t *session, xqc_moq_track_t *track,
    xqc_moq_subscribe_error_msg_t *subscribe_error)
{
    session->session_callbacks.on_subscribe_error(session->user_session, subscribe_error);
}

static void
xqc_moq_media_on_object(xqc_moq_session_t *session, xqc_moq_track_t *track, xqc_moq_object_t *object)
{
    xqc_int_t ret;
    xqc_moq_media_track_t *media_track = (xqc_moq_media_track_t*)track;
    switch (track->track_info.track_type) {
        case XQC_MOQ_TRACK_VIDEO: {
            xqc_moq_video_frame_ext_t video_frame_ext;
            video_frame_ext.group_id = object->group_id;
            video_frame_ext.object_id = object->object_id;

            xqc_moq_video_frame_t *video_frame = &video_frame_ext.video_frame;
            ret = media_track->container_ops.decode_video(object->payload,
                                            object->payload_len, video_frame);
            if (ret < 0) {
                xqc_log(session->log, XQC_LOG_ERROR, "|decode_video_container error|ret:%d|", ret);
                return;
            }
            xqc_moq_av_dejitter_on_video(media_track->dejitter, &video_frame_ext);
            break;
        }
        case XQC_MOQ_TRACK_AUDIO: {
            xqc_moq_audio_frame_ext_t audio_frame_ext;
            audio_frame_ext.group_id = object->group_id;
            audio_frame_ext.object_id = object->object_id;

            xqc_moq_audio_frame_t *audio_frame = &audio_frame_ext.audio_frame;
            ret = media_track->container_ops.decode_audio(object->payload, object->payload_len, audio_frame);
            if (ret < 0) {
                xqc_log(session->log, XQC_LOG_ERROR, "|decode_audio_container error|ret:%d|", ret);
                return;
            }

            xqc_moq_on_dejitter_output_audio(session, track, &audio_frame_ext);
            break;
        }
        default: {
            return;
        }
    }
}

