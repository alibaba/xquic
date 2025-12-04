#include "moq/moq_media/xqc_moq_media_track.h"
#include "moq/moq_media/xqc_moq_container_loc.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_transport/xqc_moq_message.h"
#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/xqc_moq_subscribe.h"
#include "moq/moq_media/xqc_moq_av_frame_ext.h"
#include "moq/moq_media/dejitter/xqc_moq_av_dejitter.h"
#include "src/transport/xqc_stream.h"

#define XQC_MOQ_MEDIA_MAX_SEND_DELAY 500000 /* 500ms */
static void xqc_moq_media_on_create(xqc_moq_track_t *track);
static void xqc_moq_media_on_destroy(xqc_moq_track_t *track);
static void xqc_moq_media_on_subscribe(xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_subscribe_msg_t *msg);
static void xqc_moq_media_on_subscribe_update(xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_subscribe_update_msg_t *update);
static void xqc_moq_media_on_subscribe_ok(xqc_moq_session_t *session, xqc_moq_track_t *track,
    xqc_moq_subscribe_ok_msg_t *subscribe_ok);
static void xqc_moq_media_on_subscribe_error(xqc_moq_session_t *session, xqc_moq_track_t *track,
    xqc_moq_subscribe_error_msg_t *subscribe_error);
static void xqc_moq_media_on_object(xqc_moq_session_t *session, xqc_moq_track_t *track, xqc_moq_object_t *object);

const xqc_moq_track_ops_t xqc_moq_media_track_ops = {
    .on_create           = xqc_moq_media_on_create,
    .on_destroy          = xqc_moq_media_on_destroy,
    .on_subscribe        = xqc_moq_media_on_subscribe,
    .on_subscribe_update = xqc_moq_media_on_subscribe_update,
    .on_subscribe_ok     = xqc_moq_media_on_subscribe_ok,
    .on_subscribe_error  = xqc_moq_media_on_subscribe_error,
    .on_object           = xqc_moq_media_on_object,
};

static void xqc_moq_media_cancel_write(xqc_moq_session_t *session, xqc_moq_track_t *track);
static xqc_bool_t xqc_moq_media_maybe_cancel_write(xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_video_frame_t *video_frame);

static xqc_int_t
xqc_moq_media_write_subgroup_stream(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, xqc_moq_object_stream_msg_t *object)
{
    return xqc_moq_write_subgroup_msg(session, stream, object);
}

xqc_int_t
xqc_moq_write_video_frame(xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_video_frame_t *video_frame)
{
    xqc_int_t ret = 0;
    xqc_int_t encoded_len;
    xqc_moq_stream_t *stream;
    xqc_moq_object_stream_msg_t object;
    xqc_moq_media_track_t *media_track = (xqc_moq_media_track_t*)track;
    uint8_t *buf = NULL;
    xqc_int_t need_free = 0;
    
    if (xqc_moq_media_maybe_cancel_write(session, subscribe_id, track, video_frame)) {
        xqc_log(session->log, XQC_LOG_INFO, "|drop video frame|track_name:%s|subscribe_id:%ui|seq:%ui|type:%d|",
                track->track_info.track_name, subscribe_id, video_frame->seq_num, video_frame->type);
        return XQC_OK;
    }
    
    if (track->container_format == XQC_MOQ_CONTAINER_NONE) {
        buf = video_frame->video_data;
        encoded_len = (xqc_int_t)video_frame->video_len;
    } else {
        size_t buf_cap = video_frame->video_len + XQC_MOQ_MAX_CONTAINER_OVERHEAD;
        buf = xqc_malloc(buf_cap);
        need_free = 1;
        ret = media_track->container_ops->encode_video(video_frame, buf, buf_cap, &encoded_len);
        if (ret < 0) {
            xqc_log(session->log, XQC_LOG_ERROR, "|encode video container error|ret:%d|", ret);
            goto error;
        }
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
    /* Use the alias bound to this subscribe_id on the subscription,
     * so that SUBGROUP always carries the subscriber's view of alias. */
    uint64_t track_alias = track->track_alias;
    xqc_moq_subscribe_t *subscribe = xqc_moq_find_subscribe(session, subscribe_id, 0);
    if (subscribe && subscribe->subscribe_msg) {
        track_alias = subscribe->subscribe_msg->track_alias;
    } else {
        subscribe = xqc_moq_find_subscribe(session, subscribe_id, 1);
        if (subscribe && subscribe->subscribe_msg) {
            track_alias = subscribe->subscribe_msg->track_alias;
        }
    }
    object.track_alias = track_alias;
    object.send_order = 0; //TODO
    object.status = XQC_MOQ_OBJ_STATUS_NORMAL;
    object.payload = buf;
    object.payload_len = encoded_len;
    if (video_frame->type == XQC_MOQ_VIDEO_KEY) {
        object.group_id = ++track->cur_group_id;
        track->cur_object_id = 0;
    } else {
        object.group_id = track->cur_group_id;
    }
    object.object_id = track->cur_object_id++;
    object.subgroup_id = xqc_moq_track_next_subgroup_id(track, object.group_id);
    object.subgroup_type = XQC_MOQ_SUBGROUP_TYPE_WITH_ID;
    object.subgroup_priority = XQC_MOQ_DEFAULT_SUBGROUP_PRIORITY;
    object.object_id_delta = object.object_id;
    xqc_moq_message_parameter_t ext_headers[4];
    xqc_memzero(ext_headers, sizeof(ext_headers));
    uint64_t ext_num = 0;

    /* Optional Capture Timestamp. */
    if (video_frame->timestamp_us != 0) {
        ext_headers[ext_num].type = XQC_MOQ_LOC_HDR_CAPTURE_TIMESTAMP;
        ext_headers[ext_num].is_integer = 1;
        ext_headers[ext_num].int_value = video_frame->timestamp_us;
        ext_headers[ext_num].length = 0;
        ext_headers[ext_num].value = NULL;
        ext_num++;
    }

    if (video_frame->has_video_config && video_frame->video_config && video_frame->video_config_len > 0)
    {
        ext_headers[ext_num].type = XQC_MOQ_LOC_HDR_VIDEO_CONFIG;
        ext_headers[ext_num].is_integer = 0;
        ext_headers[ext_num].int_value = 0;
        ext_headers[ext_num].length = video_frame->video_config_len;
        ext_headers[ext_num].value = video_frame->video_config;
        ext_num++;
    }

    /* Optional Video Frame Marking (integer varint). */
    if (video_frame->has_video_frame_marking) {
        ext_headers[ext_num].type = XQC_MOQ_LOC_HDR_VIDEO_FRAME_MARKING;
        ext_headers[ext_num].is_integer = 1;
        ext_headers[ext_num].int_value = video_frame->video_frame_marking;
        ext_headers[ext_num].length = 0;
        ext_headers[ext_num].value = NULL;
        ext_num++;
    }

    /* Optional Bizinfo (bytes). */
    if (video_frame->has_bizinfo && video_frame->bizinfo && video_frame->bizinfo_len > 0)
    {
        ext_headers[ext_num].type = XQC_MOQ_LOC_HDR_BIZINFO;
        ext_headers[ext_num].is_integer = 0;
        ext_headers[ext_num].int_value = 0;
        ext_headers[ext_num].length = video_frame->bizinfo_len;
        ext_headers[ext_num].value = video_frame->bizinfo;
        ext_num++;
    }

    object.ext_params = ext_headers;
    object.ext_params_num = ext_num;

    xqc_moq_stream_on_track_write(stream, track, object.group_id, object.object_id, video_frame->seq_num);
    xqc_list_add_tail(&stream->list_member, &media_track->write_stream_list);

    ret = xqc_moq_media_write_subgroup_stream(session, stream, &object);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|write_subgroup_stream error|ret:%d|", ret);
        goto error;
    }

    xqc_usec_t now = xqc_monotonic_timestamp();
    xqc_moq_fps_counter_insert(&media_track->fps_counter, now);
    xqc_int_t write_fps = xqc_moq_fps_counter_get(&media_track->fps_counter, now, 1000000);

    xqc_stream_t *quic_stream = stream->trans_ops.quic_stream(stream->trans_stream);
    
    if (need_free) {
        xqc_free(buf);
    }
    xqc_log(session->log, XQC_LOG_INFO,
            "|write video frame success|track_name:%s|subscribe_id:%ui|seq:%ui|"
            "group_id:%ui|object_id:%ui|stream_id:%ui|video_len:%ui|type:%d|fps:%d|"
            "track_alias:%ui|object_alias:%ui|",
            track->track_info.track_name, subscribe_id, video_frame->seq_num, 
            object.group_id, object.object_id, quic_stream->stream_id, video_frame->video_len, 
            video_frame->type, write_fps, track->track_alias, object.track_alias);
    return XQC_OK;

error:
    if (need_free && buf) {
        xqc_free(buf);
    }
    return ret;
}

xqc_int_t
xqc_moq_write_audio_frame(xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_audio_frame_t *audio_frame)
{
    xqc_int_t ret = 0;
    xqc_int_t encoded_len;
    xqc_moq_stream_t *stream;
    xqc_moq_object_stream_msg_t object;
    xqc_moq_media_track_t *media_track = (xqc_moq_media_track_t*)track;
    uint8_t *buf = NULL;
    xqc_int_t need_free = 0;

    if (track->container_format == XQC_MOQ_CONTAINER_NONE) {
        // raw object mode
        buf = audio_frame->audio_data;
        encoded_len = (xqc_int_t)audio_frame->audio_len;
    } else {
        size_t buf_cap = audio_frame->audio_len + XQC_MOQ_MAX_CONTAINER_OVERHEAD;
        buf = xqc_malloc(buf_cap);
        need_free = 1;
        ret = media_track->container_ops->encode_audio(audio_frame, buf, buf_cap, &encoded_len);
        if (ret < 0) {
            xqc_log(session->log, XQC_LOG_ERROR, "|encode audio container error|ret:%d|", ret);
            goto error;
        }
    }

    stream = xqc_moq_stream_create_with_transport(session, XQC_STREAM_UNI);
    if (stream == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|create moq stream error|");
        ret = -XQC_ECREATE_STREAM;
        goto error;
    }
    stream->write_stream_fin = 1;

    object.subscribe_id = subscribe_id;
    /* Same as video: derive alias from subscription to keep it stable. */
    uint64_t track_alias = track->track_alias;
    xqc_moq_subscribe_t *subscribe = xqc_moq_find_subscribe(session, subscribe_id, 0);
    if (subscribe && subscribe->subscribe_msg) {
        track_alias = subscribe->subscribe_msg->track_alias;
    } else {
        subscribe = xqc_moq_find_subscribe(session, subscribe_id, 1);
        if (subscribe && subscribe->subscribe_msg) {
            track_alias = subscribe->subscribe_msg->track_alias;
        }
    }
    object.track_alias = track_alias;
    object.send_order = 0; //TODO
    object.status = XQC_MOQ_OBJ_STATUS_NORMAL;
    object.payload = buf;
    object.payload_len = encoded_len;
    object.group_id = ++track->cur_group_id;
    track->cur_object_id = 0;
    object.object_id = track->cur_object_id;
    object.subgroup_id = xqc_moq_track_next_subgroup_id(track, object.group_id);
    object.subgroup_type = XQC_MOQ_SUBGROUP_TYPE_WITH_ID;
    object.subgroup_priority = XQC_MOQ_DEFAULT_SUBGROUP_PRIORITY;
    object.object_id_delta = object.object_id;
    xqc_moq_message_parameter_t ext_headers[3];
    xqc_memzero(ext_headers, sizeof(ext_headers));
    uint64_t ext_num = 0;

    /* Optional Capture Timestamp. */
    if (audio_frame->timestamp_us != 0) {
        ext_headers[ext_num].type = XQC_MOQ_LOC_HDR_CAPTURE_TIMESTAMP;
        ext_headers[ext_num].is_integer = 1;
        ext_headers[ext_num].int_value = audio_frame->timestamp_us;
        ext_headers[ext_num].length = 0;
        ext_headers[ext_num].value = NULL;
        ext_num++;
    }

    /* Optional Audio Level (integer varint, we use full value). */
    if (audio_frame->has_audio_level) {
        ext_headers[ext_num].type = XQC_MOQ_LOC_HDR_AUDIO_LEVEL;
        ext_headers[ext_num].is_integer = 1;
        ext_headers[ext_num].int_value = audio_frame->audio_level;
        ext_headers[ext_num].length = 0;
        ext_headers[ext_num].value = NULL;
        ext_num++;
    }

    /* Optional Bizinfo (bytes). */
    if (audio_frame->has_bizinfo && audio_frame->bizinfo && audio_frame->bizinfo_len > 0)
    {
        ext_headers[ext_num].type = XQC_MOQ_LOC_HDR_BIZINFO;
        ext_headers[ext_num].is_integer = 0;
        ext_headers[ext_num].int_value = 0;
        ext_headers[ext_num].length = audio_frame->bizinfo_len;
        ext_headers[ext_num].value = audio_frame->bizinfo;
        ext_num++;
    }

    object.ext_params = ext_headers;
    object.ext_params_num = ext_num;

    xqc_moq_stream_on_track_write(stream, track, object.group_id, object.object_id, audio_frame->seq_num);
    xqc_list_add_tail(&stream->list_member, &media_track->write_stream_list);

    ret = xqc_moq_media_write_subgroup_stream(session, stream, &object);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|write_subgroup_stream error|ret:%d|", ret);
        goto error;
    }
    
    xqc_stream_t *quic_stream = stream->trans_ops.quic_stream(stream->trans_stream);

    if (need_free) {
        xqc_free(buf);
    }
    xqc_log(session->log, XQC_LOG_INFO,
            "|write audio frame success|track_name:%s|subscribe_id:%ui|seq:%ui|"
            "group_id:%ui|object_id:%ui|stream_id:%ui|audio_len:%ui|"
            "track_alias:%ui|object_alias:%ui|",
            track->track_info.track_name, subscribe_id, audio_frame->seq_num, 
            object.group_id, object.object_id, quic_stream->stream_id, audio_frame->audio_len,
            track->track_alias, object.track_alias);
    return XQC_OK;

error:
    if (need_free && buf) {
        xqc_free(buf);
    }
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
    xqc_moq_track_t *track;
    uint64_t track_alias;
    xqc_moq_subscribe_update_msg_t update;

    subscribe = xqc_moq_find_subscribe(session, subscribe_id, 1);
    if (subscribe == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|subscribe not exist|subscribe_id:%ui|", subscribe_id);
        return -XQC_EPARAM;
    }
    track_alias = subscribe->subscribe_msg->track_alias;

    track = xqc_moq_find_track_by_alias(session, track_alias, XQC_MOQ_TRACK_FOR_SUB);
    if (track == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|track not found|track_alias:%ui|", track_alias);
        return -XQC_EPARAM;
    }

    uint64_t largest_group_id = xqc_moq_media_track_get_largest_video_group_id(track);
    xqc_memset(&update, 0, sizeof(xqc_moq_subscribe_update_msg_t));
    update.subscribe_id = subscribe_id;
    update.start_group_id = largest_group_id + 1;
    update.start_object_id = 0;
    update.end_group_id = 0;
    update.end_object_id = 0;
    update.params_num = 0;
    ret = xqc_moq_write_subscribe_update(session, &update);
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
            media_track->container_ops = &xqc_moq_loc_ops;
            break;
        /*case XQC_MOQ_CONTAINER_CMAF:
            //TODO: CMAF
            media_track->container_ops = xqc_moq_cmaf_ops;
            break;*/
        default:
            media_track->container_ops = &xqc_moq_loc_ops;
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
xqc_moq_media_on_subscribe(xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_subscribe_msg_t *msg)
{
    session->session_callbacks.on_subscribe(session->user_session, subscribe_id, track, msg);
}

static void
xqc_moq_media_on_subscribe_update(xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_subscribe_update_msg_t *update)
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
    session->session_callbacks.on_subscribe_ok(session->user_session, track,
        &track->track_info, subscribe_ok);
}

static void
xqc_moq_media_on_subscribe_error(xqc_moq_session_t *session, xqc_moq_track_t *track,
    xqc_moq_subscribe_error_msg_t *subscribe_error)
{
    session->session_callbacks.on_subscribe_error(session->user_session, track,
        &track->track_info, subscribe_error);
}

static void
xqc_moq_media_on_object(xqc_moq_session_t *session, xqc_moq_track_t *track, xqc_moq_object_t *object)
{
    xqc_int_t ret;
    xqc_moq_media_track_t *media_track = (xqc_moq_media_track_t*)track;
    switch (track->track_info.track_type) {
        case XQC_MOQ_TRACK_VIDEO: {
            xqc_moq_video_frame_ext_t video_frame_ext;
            xqc_memzero(&video_frame_ext, sizeof(video_frame_ext));
            video_frame_ext.group_id = object->group_id;
            video_frame_ext.object_id = object->object_id;

            xqc_moq_video_frame_t *video_frame = &video_frame_ext.video_frame;
            xqc_log(session->log, XQC_LOG_INFO,
                    "|decode video frame|track:%s/%s|alias:%ui|subscribe_id:%ui|payload_len:%ui|container:%d|codec:%s|mime:%s|",
                    track->track_info.track_namespace, track->track_info.track_name,
                    track->track_alias, track->subscribe_id, object->payload_len,
                    track->container_format,
                    track->track_info.selection_params.codec ?
                        track->track_info.selection_params.codec : "null",
                    track->track_info.selection_params.mime_type ?
                        track->track_info.selection_params.mime_type : "null");
            ret = media_track->container_ops->decode_video(object->payload,
                                            object->payload_len, video_frame);
            if (ret < 0) {
                xqc_log(session->log, XQC_LOG_ERROR, "|decode_video_container error|ret:%d|", ret);
                if (object->ext_params && object->ext_params_num > 0) {
                    for (uint64_t i = 0; i < object->ext_params_num; i++) {
                        xqc_moq_message_parameter_t *p = &object->ext_params[i];
                        xqc_log(session->log, XQC_LOG_ERROR,
                                "|decode_video_container ext_param|idx:%ui|type:%ui|is_int:%d|len:%ui|",
                                i, p->type, p->is_integer, p->length);
                    }
                }
                return;
            }
            if (object->ext_params && object->ext_params_num > 0) {
                for (uint64_t i = 0; i < object->ext_params_num; i++) {
                    xqc_moq_message_parameter_t *p = &object->ext_params[i];
                    if (p->type == XQC_MOQ_LOC_HDR_CAPTURE_TIMESTAMP && p->is_integer) {
                        video_frame->timestamp_us = p->int_value;
                    } else if (p->type == XQC_MOQ_LOC_HDR_VIDEO_FRAME_MARKING && p->is_integer) {
                        video_frame->video_frame_marking = p->int_value;
                        video_frame->has_video_frame_marking = 1;
                    } else if (p->type == XQC_MOQ_LOC_HDR_VIDEO_CONFIG
                               && p->length > 0 && p->value != NULL)
                    {
                        video_frame->video_config = p->value;
                        video_frame->video_config_len = p->length;
                        video_frame->has_video_config = 1;
                    } else if (p->type == XQC_MOQ_LOC_HDR_BIZINFO
                               && p->length > 0 && p->value != NULL)
                    {
                        video_frame->bizinfo = p->value;
                        video_frame->bizinfo_len = p->length;
                        video_frame->has_bizinfo = 1;
                    }
                }
            }
            xqc_moq_av_dejitter_on_video(media_track->dejitter, &video_frame_ext);
            break;
        }
        case XQC_MOQ_TRACK_AUDIO: {
            xqc_moq_audio_frame_ext_t audio_frame_ext;
            xqc_memzero(&audio_frame_ext, sizeof(audio_frame_ext));
            audio_frame_ext.group_id = object->group_id;
            audio_frame_ext.object_id = object->object_id;

            xqc_moq_audio_frame_t *audio_frame = &audio_frame_ext.audio_frame;
            ret = media_track->container_ops->decode_audio(object->payload, object->payload_len, audio_frame);
            if (ret < 0) {
                xqc_log(session->log, XQC_LOG_ERROR, "|decode_audio_container error|ret:%d|", ret);
                if (object->ext_params && object->ext_params_num > 0) {
                    for (uint64_t i = 0; i < object->ext_params_num; i++) {
                        xqc_moq_message_parameter_t *p = &object->ext_params[i];
                        xqc_log(session->log, XQC_LOG_ERROR,
                                "|decode_audio_container ext_param|idx:%ui|type:%ui|is_int:%d|len:%ui|",
                                i, p->type, p->is_integer, p->length);
                    }
                }
                return;
            }

            if (object->ext_params && object->ext_params_num > 0) {
                for (uint64_t i = 0; i < object->ext_params_num; i++) {
                    xqc_moq_message_parameter_t *p = &object->ext_params[i];
                    if (p->type == XQC_MOQ_LOC_HDR_CAPTURE_TIMESTAMP && p->is_integer) {
                        audio_frame->timestamp_us = p->int_value;
                    } else if (p->type == XQC_MOQ_LOC_HDR_AUDIO_LEVEL && p->is_integer) {
                        audio_frame->audio_level = p->int_value;
                        audio_frame->has_audio_level = 1;
                    } else if (p->type == XQC_MOQ_LOC_HDR_BIZINFO
                               && p->length > 0 && p->value != NULL)
                    {
                        audio_frame->bizinfo = p->value;
                        audio_frame->bizinfo_len = p->length;
                        audio_frame->has_bizinfo = 1;
                    }
                }
            }

            xqc_moq_on_dejitter_output_audio(session, track, &audio_frame_ext);
            break;
        }
        default: {
            return;
        }
    }
}
