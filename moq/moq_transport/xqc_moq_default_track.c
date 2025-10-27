#include "moq/moq_transport/xqc_moq_default_track.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/xqc_moq_message.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_stream.h"

static void
xqc_moq_default_track_on_create(xqc_moq_track_t *track)
{
    xqc_moq_default_track_t *default_track = (xqc_moq_default_track_t *)track;
    default_track->next_group_id = 0;
    default_track->next_object_id = 0;
    default_track->user_data = NULL;
}

static void
xqc_moq_default_track_on_destroy(xqc_moq_track_t *track)
{
    xqc_moq_default_track_t *default_track = (xqc_moq_default_track_t *)track;
    default_track->user_data = NULL;
}

static void
xqc_moq_default_track_on_subscribe_v05(xqc_moq_session_t *session, uint64_t subscribe_id,
                             xqc_moq_track_t *track, xqc_moq_subscribe_msg_t_v05 *msg)
{
    xqc_log(session->log, XQC_LOG_DEBUG, "|default track on subscribe v05|track_name:%s|subscribe_id:%llu|", 
            track->track_info.track_name, subscribe_id);
}

static void
xqc_moq_default_track_on_subscribe_v13(xqc_moq_session_t *session, uint64_t subscribe_id,
                             xqc_moq_track_t *track, xqc_moq_subscribe_msg_t_v13 *msg)
{
    xqc_log(session->log, XQC_LOG_DEBUG, "|default track on subscribe v13|track_name:%s|subscribe_id:%llu|", 
            track->track_info.track_name, subscribe_id);
    if(session->session_callbacks.on_subscribe_v13 != NULL) {
        session->session_callbacks.on_subscribe_v13(session->user_session, subscribe_id, track, msg);
    }
    else {
        xqc_log(session->log, XQC_LOG_WARN, "|on_subscribe_v13 callback not set|");
    }
}

static void
xqc_moq_default_track_on_subscribe_ok(xqc_moq_session_t *session, xqc_moq_track_t *track,
                            xqc_moq_subscribe_ok_msg_t *subscribe_ok)
{
    printf("default track on subscribe ok\n");
    xqc_log(session->log, XQC_LOG_DEBUG, "|default track on subscribe ok|track_name:%s|subscribe_id:%llu|", 
            track->track_info.track_name, subscribe_ok->subscribe_id);
    if(session->session_callbacks.on_subscribe_ok != NULL) {
        session->session_callbacks.on_subscribe_ok(session->user_session, subscribe_ok);
    }
    else {
        xqc_log(session->log, XQC_LOG_WARN, "|on_subscribe_ok callback not set|");
    }
}

static void
xqc_moq_default_track_on_subscribe_error(xqc_moq_session_t *session, xqc_moq_track_t *track,
                               xqc_moq_subscribe_error_msg_t *subscribe_error)
{
    xqc_log(session->log, XQC_LOG_DEBUG, "|default track on subscribe error|track_name:%s|subscribe_id:%llu|", 
            track->track_info.track_name, subscribe_error->subscribe_id);
    if(session->session_callbacks.on_subscribe_error != NULL) {
        session->session_callbacks.on_subscribe_error(session->user_session, subscribe_error);
    }
    else {
        xqc_log(session->log, XQC_LOG_WARN, "|on_subscribe_error callback not set|");
    }
}

static void
xqc_moq_default_track_on_object(xqc_moq_session_t *session, xqc_moq_track_t *track,
                      xqc_moq_object_t *object)
{
    xqc_log(session->log, XQC_LOG_DEBUG, 
            "|default track on object|track_name:%s|group_id:%llu|object_id:%llu|", 
            track->track_info.track_name, object->group_id, object->object_id);
}

static void
xqc_moq_default_track_on_subscribe_done(xqc_moq_session_t *session, xqc_moq_track_t *track,
                xqc_moq_subscribe_done_msg_t *subscribe_done)
{
    xqc_log(session->log, XQC_LOG_DEBUG, "|default track on subscribe done|track_name:%s|", 
            track->track_info.track_name);
}

static void
xqc_moq_default_track_on_announce(xqc_moq_session_t *session, xqc_moq_track_t *track,
                        xqc_moq_announce_msg_t *announce)
{
    xqc_log(session->log, XQC_LOG_DEBUG, "|default track on announce|track_name:%s|", 
            track->track_info.track_name);
}

static void
xqc_moq_default_track_on_announce_ok(xqc_moq_session_t *session, xqc_moq_track_t *track,
                           xqc_moq_announce_ok_msg_t *announce_ok)
{
    xqc_log(session->log, XQC_LOG_DEBUG, "|default track on announce ok|track_name:%s|", 
            track->track_info.track_name);
}

static void
xqc_moq_default_track_on_announce_error(xqc_moq_session_t *session, xqc_moq_track_t *track,
                              xqc_moq_announce_error_msg_t *announce_error)
{
    xqc_log(session->log, XQC_LOG_DEBUG, "|default track on announce error|track_name:%s|", 
            track->track_info.track_name);
}

static void
xqc_moq_default_track_on_goaway(xqc_moq_session_t *session, xqc_moq_track_t *track,
                      xqc_moq_goaway_msg_t *goaway)
{
    xqc_log(session->log, XQC_LOG_DEBUG, "|default track on goaway|track_name:%s|", 
            track->track_info.track_name);
}

static void
xqc_moq_default_track_on_max_request_id(xqc_moq_session_t *session, xqc_moq_track_t *track,
                                xqc_moq_max_request_id_msg_t *max_request_id)
{
    xqc_log(session->log, XQC_LOG_DEBUG, "|default track on max request id|track_name:%s|", 
            track->track_info.track_name);
}

static void
xqc_moq_default_track_on_publish(xqc_moq_session_t *session, xqc_moq_track_t *track,
                                xqc_moq_publish_msg_t *publish)
{
    printf("default track on publish\n");
    xqc_log(session->log, XQC_LOG_DEBUG, "|default track on publish|track_name:%s|", 
            track->track_info.track_name);
}

static void
xqc_moq_default_track_on_subscribe_update_v05(xqc_moq_session_t *session, uint64_t subscribe_id,
                             xqc_moq_track_t *track, xqc_moq_subscribe_update_msg_t_v05 *msg)
{
    xqc_log(session->log, XQC_LOG_DEBUG, "|default track on subscribe update v05|track_name:%s|subscribe_id:%llu|", 
            track->track_info.track_name, subscribe_id);
}

static void
xqc_moq_default_track_on_subscribe_update_v13(xqc_moq_session_t *session, uint64_t subscribe_id,
                             xqc_moq_track_t *track, xqc_moq_subscribe_update_msg_t_v13 *msg)
{
    xqc_log(session->log, XQC_LOG_DEBUG, "|default track on subscribe update v13|track_name:%s|subscribe_id:%llu|", 
            track->track_info.track_name, subscribe_id);
}

xqc_moq_track_ops_t xqc_moq_default_track_ops = {
    .on_create = xqc_moq_default_track_on_create,
    .on_destroy = xqc_moq_default_track_on_destroy,
    .on_subscribe_v05 = xqc_moq_default_track_on_subscribe_v05,
    .on_subscribe_v13 = xqc_moq_default_track_on_subscribe_v13,
    .on_subscribe_update_v05 = xqc_moq_default_track_on_subscribe_update_v05,
    .on_subscribe_update_v13 = xqc_moq_default_track_on_subscribe_update_v13,
    .on_subscribe_ok = xqc_moq_default_track_on_subscribe_ok,
    .on_subscribe_error = xqc_moq_default_track_on_subscribe_error,
    .on_object = xqc_moq_default_track_on_object,
    .on_subscribe_done = xqc_moq_default_track_on_subscribe_done,
    .on_announce = xqc_moq_default_track_on_announce,
    .on_announce_ok = xqc_moq_default_track_on_announce_ok,
    .on_announce_error = xqc_moq_default_track_on_announce_error,
    .on_goaway = xqc_moq_default_track_on_goaway,
    .on_max_request_id = xqc_moq_default_track_on_max_request_id,
    .on_publish = xqc_moq_default_track_on_publish,
};

void
xqc_moq_default_track_init(xqc_moq_track_t *track)
{
    track->track_ops = xqc_moq_default_track_ops;
}

xqc_moq_track_t *
xqc_moq_default_track_create(xqc_moq_session_t *session, char *track_namespace, char *track_name, 
                           xqc_moq_selection_params_t *params, xqc_moq_track_role_t role)
{
    return xqc_moq_track_create(session, track_namespace, track_name, 
                               XQC_MOQ_TRACK_DEFAULT, params, XQC_MOQ_CONTAINER_NONE, role);
}

void
xqc_moq_default_track_destroy(xqc_moq_track_t *track)
{
    xqc_moq_track_destroy(track);
}

/**
 * @brief 在指定stream上发送subgroup object（传输层核心功能）
 */
xqc_moq_stream_t *
xqc_moq_default_track_send_on_stream(
    xqc_moq_track_t *track,
    xqc_moq_stream_t *stream,
    uint64_t subgroup_id,
    uint8_t *data,
    size_t data_len,
    xqc_bool_t is_first)
{
    xqc_moq_session_t *session = track->session;
    xqc_moq_default_track_t *default_track = (xqc_moq_default_track_t *)track;
    
    if (track->track_alias == -1) {
        xqc_log(session->log, XQC_LOG_ERROR, "|track not announced|");
        return NULL;
    }
    
    if (default_track->next_group_id == XQC_MOQ_INVALID_ID) {
        default_track->next_group_id = 0;
    }
    
    uint64_t group_id = default_track->next_group_id;
    uint64_t object_id = default_track->next_object_id++;
    
    xqc_int_t ret = XQC_OK;
    
    /* 如果没有提供stream，创建新的 */
    if (stream == NULL) {
        stream = xqc_moq_stream_create_with_transport(session, XQC_STREAM_UNI);
        if (stream == NULL) {
            xqc_log(session->log, XQC_LOG_ERROR, "|create stream error|");
            return NULL;
        }
        stream->write_stream_fin = 0;
        
        xqc_log(session->log, XQC_LOG_DEBUG, "|new stream for subgroup|group:%llu|subgroup:%llu|",
                (unsigned long long)group_id, (unsigned long long)subgroup_id);
    }
    
    /* 如果是第一个object，发送SUBGROUP_HEADER */
    if (is_first) {
        xqc_moq_subgroup_msg_t *subgroup_msg = xqc_calloc(1, sizeof(xqc_moq_subgroup_msg_t));
        if (subgroup_msg == NULL) {
            xqc_log(session->log, XQC_LOG_ERROR, "|alloc subgroup_msg error|");
            return NULL;
        }
        subgroup_msg->track_alias = track->track_alias;
        subgroup_msg->group_id = group_id;
        subgroup_msg->subgroup_id = subgroup_id;
        subgroup_msg->publish_priority = 128;
        
        ret = xqc_moq_write_subgroup_msg(session, stream, subgroup_msg);
        xqc_free(subgroup_msg);
        
        if (ret < 0) {
            xqc_log(session->log, XQC_LOG_ERROR, "|write subgroup header error|ret:%d|", ret);
            return NULL;
        }
        
    }
    
    /* 发送Object */
    xqc_moq_subgroup_object_msg_t *subgroup_object = xqc_calloc(1, sizeof(xqc_moq_subgroup_object_msg_t));
    if (subgroup_object == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|alloc subgroup_object error|");
        return NULL;
    }
    subgroup_object->subgroup_header = NULL;
    subgroup_object->object_id = object_id;
    subgroup_object->payload_len = data_len;
    subgroup_object->payload = data;
    subgroup_object->object_status = 0;
    
    ret = xqc_moq_write_subgroup_object_msg(session, stream, subgroup_object);
    xqc_free(subgroup_object);
    
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|write subgroup object error|ret:%d|", ret);
        return NULL;
    }
    
    return stream;
}

/**
 * @brief 简单发送模式（每次创建新stream，subgroup_id=0）
 */
xqc_int_t
xqc_moq_default_track_send(xqc_moq_track_t *track, uint8_t *data, size_t data_len)
{
    xqc_moq_stream_t *stream = xqc_moq_default_track_send_on_stream(
        track, NULL, 0, data, data_len, XQC_TRUE
    );
    return stream ? XQC_OK : -XQC_ERROR;
}

void
xqc_moq_default_track_set_user_data(xqc_moq_track_t *track, void *user_data)
{
    xqc_moq_default_track_t *default_track = (xqc_moq_default_track_t *)track;
    default_track->user_data = user_data;
}

void *
xqc_moq_default_track_get_user_data(xqc_moq_track_t *track)
{
    xqc_moq_default_track_t *default_track = (xqc_moq_default_track_t *)track;
    return default_track->user_data;
} 