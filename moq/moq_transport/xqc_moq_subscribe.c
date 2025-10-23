
#include "moq/moq_transport/xqc_moq_subscribe.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_message_writer.h"

xqc_moq_subscribe_t *
xqc_moq_subscribe_create(xqc_moq_session_t *session, uint64_t subscribe_id,
    uint64_t track_alias, const char *track_namespace, const char *track_name, xqc_moq_filter_type_t filter_type,
    uint64_t start_group_id, uint64_t start_object_id, uint64_t end_group_id, uint64_t end_object_id,
    char *authinfo, xqc_int_t is_local)
{
    xqc_moq_subscribe_t *subscribe;
    xqc_moq_subscribe_msg_t *msg;

    size_t track_namespace_len = strlen(track_namespace);
    size_t track_name_len = strlen(track_name);
    if (track_namespace_len > XQC_MOQ_MAX_NAME_LEN || track_name_len > XQC_MOQ_MAX_NAME_LEN
        || track_namespace_len == 0 || track_name_len == 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|illegal track namespace or name|");
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
    msg->subscribe_id = subscribe_id;
    msg->track_alias = track_alias;
    msg->track_namespace_len = track_namespace_len;
    msg->track_namespace = xqc_calloc(1, track_namespace_len + 1);
    xqc_memcpy(msg->track_namespace, track_namespace, track_namespace_len);
    msg->track_name_len = track_name_len;
    msg->track_name = xqc_calloc(1, track_name_len + 1);
    xqc_memcpy(msg->track_name, track_name, track_name_len);
    msg->filter_type = filter_type;
    msg->start_group_id = start_group_id;
    msg->start_object_id = start_object_id;
    msg->end_group_id = end_group_id;
    msg->end_object_id = end_object_id;
    if (authinfo_len > 0) {
        msg->params_num = 1;
        msg->params = xqc_calloc(msg->params_num, sizeof(xqc_moq_message_parameter_t));
        msg->params[0].type = XQC_MOQ_PARAM_AUTH;
        msg->params[0].length = authinfo_len;
        msg->params[0].value = xqc_calloc(1, authinfo_len + 1);
        xqc_memcpy(msg->params[0].value, authinfo, authinfo_len);
    } else {
        msg->params_num = 0;
    }

    subscribe = xqc_calloc(1, sizeof(xqc_moq_subscribe_t));
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
    msg->end_object_id = update->end_object_id;
}

xqc_int_t
xqc_moq_subscribe(xqc_moq_session_t *session, const char *track_namespace, const char *track_name,
    xqc_moq_filter_type_t filter_type, uint64_t start_group_id, uint64_t start_object_id,
    uint64_t end_group_id, uint64_t end_object_id, char *authinfo)
{
    xqc_moq_subscribe_t *subscribe;
    xqc_moq_track_t *track;
    xqc_int_t ret;
    track = xqc_moq_find_track_by_name(session, track_namespace, track_name, XQC_MOQ_TRACK_FOR_SUB);
    if (track == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|track not found|");
        return -XQC_ENULLPTR;
    }

    if (track->track_alias != -1 || track->subscribe_id != -1) {
        xqc_log(session->log, XQC_LOG_ERROR, "|track already subscribed|");
        return -MOQ_PROTOCOL_VIOLATION;
    }

    uint64_t subscribe_id = xqc_moq_session_alloc_subscribe_id(session);
    uint64_t track_alias = xqc_moq_session_alloc_track_alias(session);
    xqc_moq_track_set_subscribe_id(track, subscribe_id);
    xqc_moq_track_set_alias(track, track_alias);

    subscribe = xqc_moq_subscribe_create(session, subscribe_id, track->track_alias, track_namespace, track_name,
                                         filter_type, start_group_id, start_object_id, end_group_id, end_object_id,
                                         authinfo, 1);
    if (subscribe == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|create subscribe error|");
        return -XQC_ENULLPTR;
    }

    ret = xqc_moq_write_subscribe(session, subscribe->subscribe_msg);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|write subscribe error|");
        return ret;
    }

    xqc_log(session->log, XQC_LOG_INFO, "|subscribe success|track_name:%s|track_alias:%ui|subscribe_id:%ui|",
            track_name, track_alias, subscribe_id);

    return subscribe_id;
}

xqc_int_t
xqc_moq_subscribe_latest(xqc_moq_session_t *session, const char *track_namespace, const char *track_name)
{
    return xqc_moq_subscribe(session, track_namespace, track_name,
                             XQC_MOQ_FILTER_LAST_GROUP, 0, 0, 0, 0, NULL);
}

