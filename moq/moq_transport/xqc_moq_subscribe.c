#include "moq/moq_transport/xqc_moq_subscribe.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/xqc_moq_namespace.h"
#include "moq/moq_transport/xqc_moq_track.h"

xqc_moq_subscribe_t *
xqc_moq_subscribe_create_with_namespace_tuple(xqc_moq_session_t *session, uint64_t subscribe_id,
    uint64_t track_alias, const xqc_moq_track_ns_field_t *track_namespace_tuple, uint64_t track_namespace_num,
    const char *track_name, size_t track_name_len, xqc_moq_filter_type_t filter_type,
    uint64_t start_group_id, uint64_t start_object_id, uint64_t end_group_id, uint64_t end_object_id,
    char *authinfo, xqc_int_t is_local)
{
    xqc_moq_subscribe_t *subscribe;
    xqc_moq_subscribe_msg_t *msg;

    if (session == NULL || track_namespace_tuple == NULL || track_namespace_num == 0
        || track_name == NULL || track_name_len == 0)
    {
        return NULL;
    }

    if (track_name_len > XQC_MOQ_MAX_NAME_LEN) {
        xqc_log(session->log, XQC_LOG_ERROR, "|illegal track name|");
        return NULL;
    }

    if (track_namespace_num > XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS) {
        xqc_log(session->log, XQC_LOG_ERROR, "|illegal track namespace tuple size|");
        return NULL;
    }

    size_t track_namespace_len = 0;
    for (uint64_t i = 0; i < track_namespace_num; i++) {
        if (track_namespace_tuple[i].len > XQC_MOQ_MAX_NAME_LEN) {
            xqc_log(session->log, XQC_LOG_ERROR, "|illegal track namespace tuple elem len|");
            return NULL;
        }
        if (track_namespace_len > XQC_MOQ_MAX_FULL_TRACK_NAME_LEN - track_namespace_tuple[i].len) {
            xqc_log(session->log, XQC_LOG_ERROR, "|track namespace too long|");
            return NULL;
        }
        track_namespace_len += track_namespace_tuple[i].len;
    }

    if (track_namespace_len > XQC_MOQ_MAX_FULL_TRACK_NAME_LEN - track_name_len) {
        xqc_log(session->log, XQC_LOG_ERROR, "|full track name too long|");
        return NULL;
    }

    size_t authinfo_len;
    if (authinfo == NULL) {
        authinfo_len = 0;
    } else {
        authinfo_len = strlen(authinfo);
    }
    if (authinfo_len > XQC_MOQ_MAX_AUTH_LEN) {
        xqc_log(session->log, XQC_LOG_ERROR, "|authinfo too long|");
        return NULL;
    }

    msg = xqc_calloc(1, sizeof(xqc_moq_subscribe_msg_t));
    if (msg == NULL) {
        return NULL;
    }

    msg->subscribe_id = subscribe_id;
    msg->track_alias = track_alias;
    msg->track_namespace_num = track_namespace_num;
    msg->track_namespace_tuple = xqc_moq_namespace_tuple_copy(track_namespace_tuple, track_namespace_num);
    if (msg->track_namespace_tuple == NULL) {
        xqc_free(msg);
        return NULL;
    }
    msg->track_namespace_len = track_namespace_len;

    msg->track_name_len = track_name_len;
    msg->track_name = xqc_calloc(1, track_name_len + 1);
    if (msg->track_name == NULL) {
        xqc_moq_msg_free_subscribe(msg);
        return NULL;
    }
    xqc_memcpy(msg->track_name, track_name, track_name_len);

    msg->subscriber_priority = 0;
    msg->group_order = 0x1;
    msg->forward = 0;
    msg->filter_type = filter_type;
    msg->start_group_id = start_group_id;
    msg->start_object_id = start_object_id;
    msg->end_group_id = end_group_id;
    msg->end_object_id = end_object_id;

    if (authinfo_len > 0) {
        msg->params_num = 1;
        msg->params = xqc_calloc(msg->params_num, sizeof(xqc_moq_message_parameter_t));
        if (msg->params == NULL) {
            xqc_moq_msg_free_subscribe(msg);
            return NULL;
        }
        msg->params[0].type = XQC_MOQ_PARAM_AUTH;
        msg->params[0].length = authinfo_len;
        msg->params[0].value = xqc_calloc(1, authinfo_len + 1);
        if (msg->params[0].value == NULL) {
            xqc_moq_msg_free_subscribe(msg);
            return NULL;
        }
        xqc_memcpy(msg->params[0].value, authinfo, authinfo_len);
    } else {
        msg->params_num = 0;
    }

    subscribe = xqc_calloc(1, sizeof(xqc_moq_subscribe_t));
    if (subscribe == NULL) {
        xqc_moq_msg_free_subscribe(msg);
        return NULL;
    }
    subscribe->subscribe_msg = msg;

    xqc_init_list_head(&subscribe->list_member);
    if (is_local) {
        xqc_list_add_tail(&subscribe->list_member, &session->local_subscribe_list);
    } else {
        xqc_list_add_tail(&subscribe->list_member, &session->peer_subscribe_list);
    }

    return subscribe;
}

void
xqc_moq_subscribe_destroy(xqc_moq_subscribe_t *subscribe)
{
    xqc_moq_msg_free_subscribe(subscribe->subscribe_msg);
    subscribe->subscribe_msg = NULL;

    xqc_free(subscribe);
}

void
xqc_moq_subscribe_update_msg(xqc_moq_subscribe_t *subscribe, xqc_moq_subscribe_update_msg_t *update)
{
    xqc_moq_subscribe_msg_t *msg = subscribe->subscribe_msg;
    msg->start_group_id = update->start_group_id;
    msg->start_object_id = update->start_object_id;
    msg->end_group_id = update->end_group_id;
    msg->subscriber_priority = update->subscriber_priority;
    msg->forward = update->forward;
}

xqc_int_t
xqc_moq_subscribe_with_namespace_tuple(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *track_namespace_tuple, uint64_t track_namespace_num,
    const char *track_name,
    xqc_moq_filter_type_t filter_type,
    uint64_t start_group_id, uint64_t start_object_id,
    uint64_t end_group_id, uint64_t end_object_id,
    char *authinfo)
{
    if (session == NULL || track_namespace_tuple == NULL || track_namespace_num == 0 || track_name == NULL) {
        return -XQC_EPARAM;
    }

    xqc_moq_track_t *track = xqc_moq_find_track_by_track_namespace_tuple(session,
        track_namespace_tuple, track_namespace_num, track_name, XQC_MOQ_TRACK_FOR_SUB);
    if (track == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|track not found|");
        return -XQC_ENULLPTR;
    }

    if (track->track_alias != XQC_MOQ_INVALID_ID || track->subscribe_id != XQC_MOQ_INVALID_ID) {
        xqc_log(session->log, XQC_LOG_ERROR, "|track already subscribed|");
        return -MOQ_PROTOCOL_VIOLATION;
    }

    uint64_t subscribe_id = xqc_moq_session_alloc_subscribe_id(session);
    uint64_t track_alias = xqc_moq_session_alloc_track_alias(session);
    xqc_moq_track_set_subscribe_id(track, subscribe_id);
    xqc_moq_track_set_alias(track, track_alias);

    size_t track_name_len = strlen(track_name);
    xqc_moq_subscribe_t *subscribe = xqc_moq_subscribe_create_with_namespace_tuple(session, subscribe_id, track_alias,
        track_namespace_tuple, track_namespace_num, track_name, track_name_len,
        filter_type, start_group_id, start_object_id, end_group_id, end_object_id,
        authinfo, 1);
    if (subscribe == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|create subscribe error|");
        xqc_moq_track_set_subscribe_id(track, XQC_MOQ_INVALID_ID);
        xqc_moq_track_set_alias(track, XQC_MOQ_INVALID_ID);
        return -XQC_ENULLPTR;
    }

    xqc_moq_subscribe_msg_t *msg = subscribe->subscribe_msg;

    xqc_int_t ret = xqc_moq_write_subscribe(session, msg);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|write subscribe error|");
        xqc_list_del(&subscribe->list_member);
        xqc_moq_subscribe_destroy(subscribe);
        xqc_moq_track_set_subscribe_id(track, XQC_MOQ_INVALID_ID);
        xqc_moq_track_set_alias(track, XQC_MOQ_INVALID_ID);
        return ret;
    }

    xqc_log(session->log, XQC_LOG_INFO, "|subscribe_with_tuple success|track_name:%s|track_alias:%ui|subscribe_id:%ui|",
            track_name, track_alias, subscribe_id);

    return subscribe_id;
}

xqc_int_t
xqc_moq_subscribe(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *track_namespace_tuple, uint64_t track_namespace_num,
    const char *track_name,
    xqc_moq_filter_type_t filter_type, uint64_t start_group_id, uint64_t start_object_id,
    uint64_t end_group_id, uint64_t end_object_id, char *authinfo)
{
    return xqc_moq_subscribe_with_namespace_tuple(session,
        track_namespace_tuple, track_namespace_num, track_name, filter_type,
        start_group_id, start_object_id, end_group_id, end_object_id, authinfo);
}

xqc_int_t
xqc_moq_subscribe_latest(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *track_namespace_tuple, uint64_t track_namespace_num,
    const char *track_name)
{
    return xqc_moq_subscribe(session, track_namespace_tuple, track_namespace_num, track_name,
        XQC_MOQ_FILTER_LAST_GROUP, 0, 0, 0, 0, NULL);
}

xqc_int_t
xqc_moq_subscribe_latest_with_namespace_tuple(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *track_namespace_tuple, uint64_t track_namespace_num,
    const char *track_name)
{
    return xqc_moq_subscribe_with_namespace_tuple(session,
        track_namespace_tuple, track_namespace_num, track_name,
        XQC_MOQ_FILTER_LAST_GROUP, 0, 0, 0, 0, NULL);
}

xqc_int_t
xqc_moq_unsubscribe(xqc_moq_session_t *session, uint64_t subscribe_id)
{
    xqc_moq_subscribe_t *subscribe = xqc_moq_find_subscribe(session, subscribe_id, 1);
    if (subscribe == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|unsubscribe target not found|subscribe_id:%ui|", subscribe_id);
        return -XQC_ENULLPTR;
    }

    xqc_moq_unsubscribe_msg_t unsubscribe_msg;
    xqc_memzero(&unsubscribe_msg, sizeof(unsubscribe_msg));
    xqc_moq_msg_unsubscribe_init_handler(&unsubscribe_msg.msg_base);
    unsubscribe_msg.subscribe_id = subscribe_id;

    xqc_int_t ret = xqc_moq_write_unsubscribe(session, &unsubscribe_msg);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|write unsubscribe error|ret:%d|subscribe_id:%ui|", ret, subscribe_id);
        return ret;
    }

    xqc_moq_track_t *track = xqc_moq_find_track_by_alias(session, subscribe->subscribe_msg->track_alias,
                                                         XQC_MOQ_TRACK_FOR_SUB);
    if (track) {
        xqc_moq_track_set_subscribe_id(track, XQC_MOQ_INVALID_ID);
        xqc_moq_track_set_alias(track, XQC_MOQ_INVALID_ID);
    }

    xqc_list_del(&subscribe->list_member);
    xqc_moq_subscribe_destroy(subscribe);

    xqc_log(session->log, XQC_LOG_INFO, "|unsubscribe success|subscribe_id:%ui|", subscribe_id);

    return XQC_OK;
}

xqc_int_t
xqc_moq_publish(xqc_moq_session_t *session, xqc_moq_publish_msg_t *publish)
{
    xqc_moq_track_t *track;
    xqc_moq_subscribe_t *subscribe;
    xqc_int_t ret;
    uint64_t subscribe_id;

    if (session == NULL || publish == NULL || publish->track_name == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|publish invalid argument|");
        return -XQC_EPARAM;
    }

    if (publish->track_namespace_tuple == NULL || publish->track_namespace_num == 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|publish missing namespace tuple|");
        return -XQC_EPARAM;
    }
    track = xqc_moq_find_track_by_track_namespace_tuple(session,
        publish->track_namespace_tuple, publish->track_namespace_num,
        publish->track_name, XQC_MOQ_TRACK_FOR_PUB);
    if (track == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|publish track not found|track_name:%s|", publish->track_name);
        return -XQC_ENULLPTR;
    }

    if (track->track_alias == XQC_MOQ_INVALID_ID) {
        xqc_moq_track_set_alias(track, xqc_moq_session_alloc_track_alias(session));
    }
    publish->track_alias = track->track_alias;

    if (track->subscribe_id != XQC_MOQ_INVALID_ID) {
        xqc_log(session->log, XQC_LOG_ERROR, "|publish track already has subscriber|track_name:%s|",
                publish->track_name);
        return -MOQ_PROTOCOL_VIOLATION;
    }

    subscribe_id = publish->subscribe_id;
    if (subscribe_id == 0) {
        subscribe_id = xqc_moq_session_alloc_subscribe_id(session);
    }
    xqc_moq_track_set_subscribe_id(track, subscribe_id);
    publish->subscribe_id = subscribe_id;

    if (publish->track_name_len == 0) {
        publish->track_name_len = strlen(publish->track_name);
    }
    if (publish->group_order == 0) {
        publish->group_order = 0x1;
    }

    subscribe = xqc_moq_subscribe_create_with_namespace_tuple(session, subscribe_id, track->track_alias,
        publish->track_namespace_tuple, publish->track_namespace_num,
        publish->track_name, publish->track_name_len,
        XQC_MOQ_FILTER_LAST_GROUP, 0, 0, 0, 0, NULL, 0);
    if (subscribe == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|publish create subscribe error|");
        xqc_moq_track_set_subscribe_id(track, XQC_MOQ_INVALID_ID);
        return -XQC_ENULLPTR;
    }

    if (publish->forward != 0) {
        publish->forward = 1;
    }

    ret = xqc_moq_write_publish(session, publish);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_write_publish error|ret:%d|", ret);
        xqc_list_del(&subscribe->list_member);
        xqc_moq_subscribe_destroy(subscribe);
        xqc_moq_track_set_subscribe_id(track, XQC_MOQ_INVALID_ID);
        xqc_moq_track_set_alias(track, XQC_MOQ_INVALID_ID);
        return ret;
    }

    xqc_log(session->log, XQC_LOG_INFO, "|publish send success|track_name:%s|track_alias:%ui|subscribe_id:%ui|",
            publish->track_name, track->track_alias, subscribe_id);

    return subscribe_id;
}

xqc_int_t
xqc_moq_create_datachannel(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *track_namespace_tuple, uint64_t track_namespace_num,
    const char *track_name, xqc_moq_track_t **track, uint64_t *subscribe_id, xqc_int_t raw_object)
{
    return xqc_moq_create_datachannel_with_namespace_tuple(session,
        track_namespace_tuple, track_namespace_num, track_name,
        track, subscribe_id, raw_object);
}

xqc_int_t
xqc_moq_create_datachannel_with_namespace_tuple(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *track_namespace_tuple, uint64_t track_namespace_num,
    const char *track_name,
    xqc_moq_track_t **track, uint64_t *subscribe_id, xqc_int_t raw_object)
{
    xqc_moq_track_t *dc_track;
    xqc_moq_publish_msg_t publish_msg;
    xqc_int_t ret;

    if (session == NULL || track_namespace_tuple == NULL || track_namespace_num == 0 || track_name == NULL) {
        return -XQC_EPARAM;
    }

    dc_track = xqc_moq_track_create_with_namespace_tuple(session,track_namespace_num, track_namespace_tuple, 
        (char *)track_name, XQC_MOQ_TRACK_DATACHANNEL, NULL, XQC_MOQ_CONTAINER_NONE, XQC_MOQ_TRACK_FOR_PUB);
    if (dc_track == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|create datachannel track error|track:%s|",
                xqc_moq_track_get_full_name(dc_track));
        return -XQC_ENULLPTR;
    }
    dc_track->raw_object = raw_object ? 1 : 0;
    xqc_log(session->log, XQC_LOG_INFO,
            "|create_datachannel_track|track:%s|track_type:%d|raw_object:%d|",
            xqc_moq_track_get_full_name(dc_track), dc_track->track_info.track_type, dc_track->raw_object);

    xqc_memzero(&publish_msg, sizeof(publish_msg));
    publish_msg.track_namespace_num = dc_track->track_info.track_namespace_num;
    publish_msg.track_namespace_tuple = dc_track->track_info.track_namespace_tuple;
    publish_msg.track_namespace_len = 0;
    publish_msg.track_name = dc_track->track_info.track_name;
    publish_msg.track_name_len = strlen(dc_track->track_info.track_name);
    publish_msg.group_order = 0;
    publish_msg.content_exist = 0;
    publish_msg.largest_group_id = 0;
    publish_msg.largest_object_id = 0;
    publish_msg.forward = 1;
    publish_msg.params_num = 0;
    publish_msg.params = NULL;

    xqc_moq_message_parameter_t auth_param;
    int auth_param_valid = 0;
    ret = xqc_moq_build_catalog_param_from_track(dc_track, &auth_param);
    if (ret == XQC_OK) {
        publish_msg.params = &auth_param;
        publish_msg.params_num = 1;
        auth_param_valid = 1;
        xqc_log(session->log, XQC_LOG_INFO,
                "|create_datachannel_build_catalog_ok|track:%s|",
                xqc_moq_track_get_full_name(dc_track));
    } else {
        xqc_log(session->log, XQC_LOG_ERROR,
                "|create_datachannel_build_catalog_fail|ret:%d|track:%s|",
                ret, xqc_moq_track_get_full_name(dc_track));
    }

    ret = xqc_moq_publish(session, &publish_msg);
    if (auth_param_valid) {
        xqc_moq_free_catalog_param(&auth_param);
    }
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_create_datachannel publish error|ret:%d|track:%s|",
                ret, xqc_moq_track_get_full_name(dc_track));
        xqc_list_del(&dc_track->list_member);
        xqc_moq_track_destroy(dc_track);
        return ret;
    }

    if (track) {
        *track = dc_track;
    }
    if (subscribe_id) {
        *subscribe_id = publish_msg.subscribe_id;
    }

    return ret;
}
