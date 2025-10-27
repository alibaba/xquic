
#include "moq/moq_transport/xqc_moq_subscribe.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/xqc_moq_message.h"
#include "moq/xqc_moq.h"

// xqc_moq_subscribe_t *
// xqc_moq_subscribe_create(xqc_moq_session_t *session, uint64_t subscribe_id,
//     uint64_t track_alias, const char *track_namespace, const char *track_name, xqc_moq_filter_type_t filter_type,
//     uint64_t start_group_id, uint64_t start_object_id, uint64_t end_group_id, uint64_t end_object_id,
//     char *authinfo, xqc_int_t is_local)
// {
//     xqc_moq_subscribe_t *subscribe;
//     xqc_moq_subscribe_msg_t *msg;

//     size_t track_namespace_len = strlen(track_namespace);
//     size_t track_name_len = strlen(track_name);
//     if (track_namespace_len > XQC_MOQ_MAX_NAME_LEN || track_name_len > XQC_MOQ_MAX_NAME_LEN
//         || track_namespace_len == 0 || track_name_len == 0) {
//         xqc_log(session->log, XQC_LOG_ERROR, "|illegal track namespace or name|");
//         return NULL;
//     }

//     size_t authinfo_len;
//     if (authinfo == NULL) {
//         authinfo_len = 0;
//     } else {
//         authinfo_len = strlen(authinfo);
//     }
//     if (authinfo_len > XQC_MOQ_MAX_AUTH_LEN) {
//         xqc_log(session->log, XQC_LOG_ERROR, "|authinfo too long|");
//         return NULL;
//     }

//     msg = xqc_calloc(1, sizeof(xqc_moq_subscribe_msg_t));
//     msg->request_id = subscribe_id;
//     // msg->track_alias = track_alias;
//     msg->track_namespace = xqc_calloc(1, sizeof(xqc_moq_msg_track_namespace_t));
//     msg->track_namespace->track_namespace_num = 1;
//     msg->track_namespace->track_namespace_len = xqc_calloc(1, sizeof(uint64_t));
//     msg->track_namespace->track_namespace = xqc_calloc(1, sizeof(char *));
//     msg->track_namespace->track_namespace_len[0] = track_namespace_len;
//     msg->track_namespace->track_namespace[0] = xqc_calloc(1, track_namespace_len + 1);
//     xqc_memcpy(msg->track_namespace->track_namespace[0], track_namespace, track_namespace_len);
//     msg->track_name_len = track_name_len;
//     msg->track_name = xqc_calloc(1, track_name_len + 1);
//     xqc_memcpy(msg->track_name, track_name, track_name_len);
//     msg->filter_type = filter_type;
//     msg->start_group_id = start_group_id;
//     msg->start_object_id = start_object_id;
//     msg->end_group_id = end_group_id;
//     msg->end_object_id = end_object_id;
//     if (authinfo_len > 0) {
//         msg->params_num = 1;
//         msg->params = xqc_calloc(msg->params_num, sizeof(xqc_moq_message_parameter_t));
//         msg->params[0].type = XQC_MOQ_VERSION_SPE_PARAM_AUTH;
//         msg->params[0].length = authinfo_len;
//         msg->params[0].value = xqc_calloc(1, authinfo_len + 1);
//         xqc_memcpy(msg->params[0].value, authinfo, authinfo_len);
//     } else {
//         msg->params_num = 0;
//     }

//     subscribe = xqc_calloc(1, sizeof(xqc_moq_subscribe_t));
//     subscribe->subscribe_msg = msg;

//     xqc_init_list_head(&subscribe->list_member);
//     if (is_local) {
//         xqc_list_add_tail(&subscribe->list_member, &session->local_subscribe_list);
//     } else {
//         xqc_list_add_tail(&subscribe->list_member, &session->peer_subscribe_list);
//     }

//     return subscribe;
// }

xqc_moq_subscribe_t *
xqc_moq_subscribe_create_v05(xqc_moq_session_t *session, uint64_t subscribe_id,
    uint64_t track_alias, const char *track_namespace, const char *track_name, xqc_moq_filter_type_t filter_type,
    uint64_t start_group_id, uint64_t start_object_id, uint64_t end_group_id, uint64_t end_object_id,
    char *authinfo, xqc_int_t is_local)
{
    xqc_moq_subscribe_t *subscribe;
    xqc_moq_subscribe_msg_t_v05 *msg;

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

    msg = xqc_calloc(1, sizeof(xqc_moq_subscribe_msg_t_v05));
    msg->subscribe_id = subscribe_id;
    msg->track_alias = track_alias;
    msg->track_namespace = xqc_calloc(1, sizeof(xqc_moq_msg_track_namespace_t));
    msg->track_namespace->track_namespace_num = 1;
    msg->track_namespace->track_namespace_len = xqc_calloc(1, sizeof(uint64_t));
    msg->track_namespace->track_namespace = xqc_calloc(1, sizeof(char *));
    msg->track_namespace->track_namespace_len[0] = track_namespace_len;
    msg->track_namespace->track_namespace[0] = xqc_calloc(1, track_namespace_len + 1);
    xqc_memcpy(msg->track_namespace->track_namespace[0], track_namespace, track_namespace_len);
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
        msg->params[0].type = XQC_MOQ_VERSION_SPE_PARAM_AUTH;
        msg->params[0].length = authinfo_len;
        msg->params[0].value = xqc_calloc(1, authinfo_len + 1);
        xqc_memcpy(msg->params[0].value, authinfo, authinfo_len);
    } else {
        msg->params_num = 0;
    }

    subscribe = xqc_calloc(1, sizeof(xqc_moq_subscribe_t));
    subscribe->subscribe_msg_v05 = msg;
    subscribe->is_v05 = 1;

    xqc_init_list_head(&subscribe->list_member);
    if (is_local) {
        xqc_list_add_tail(&subscribe->list_member, &session->local_subscribe_list);
    } else {
        xqc_list_add_tail(&subscribe->list_member, &session->peer_subscribe_list);
    }

    return subscribe;
}


xqc_moq_subscribe_t *
xqc_moq_subscribe_create_v13(xqc_moq_session_t *session, uint64_t subscribe_id,
    const char *track_namespace, const char *track_name, xqc_moq_filter_type_t filter_type,
    uint64_t start_group_id, uint64_t start_object_id, uint64_t end_group_id, uint64_t end_object_id,
    char *authinfo, xqc_int_t is_local)
{
    xqc_moq_subscribe_t *subscribe;
    xqc_moq_subscribe_msg_t_v13 *msg;

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

    msg = xqc_calloc(1, sizeof(xqc_moq_subscribe_msg_t_v13));
    msg->request_id = subscribe_id;
    // msg->track_alias = track_alias;
    msg->track_namespace = xqc_calloc(1, sizeof(xqc_moq_msg_track_namespace_t));
    msg->track_namespace->track_namespace_num = 1;
    msg->track_namespace->track_namespace_len = xqc_calloc(1, sizeof(uint64_t));
    msg->track_namespace->track_namespace = xqc_calloc(1, sizeof(char *));
    msg->track_namespace->track_namespace_len[0] = track_namespace_len;
    msg->track_namespace->track_namespace[0] = xqc_calloc(1, track_namespace_len + 1);
    xqc_memcpy(msg->track_namespace->track_namespace[0], track_namespace, track_namespace_len);
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
        msg->params[0].type = XQC_MOQ_VERSION_SPE_PARAM_AUTH;
        msg->params[0].length = authinfo_len;
        msg->params[0].value = xqc_calloc(1, authinfo_len + 1);
        xqc_memcpy(msg->params[0].value, authinfo, authinfo_len);
    } else {
        msg->params_num = 0;
    }

    subscribe = xqc_calloc(1, sizeof(xqc_moq_subscribe_t));
    subscribe->subscribe_msg_v13 = msg;
    subscribe->is_v05 = 0;

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
    if (subscribe->is_v05) {
        xqc_moq_msg_free_subscribe_v05(subscribe->subscribe_msg_v05);
        subscribe->subscribe_msg_v05 = NULL;
    } else {
        xqc_moq_msg_free_subscribe_v13(subscribe->subscribe_msg_v13);
        subscribe->subscribe_msg_v13 = NULL;
    }

    xqc_free(subscribe);
}

void
xqc_moq_subscribe_update_msg(xqc_moq_subscribe_t *subscribe, xqc_moq_subscribe_update_msg_t_v05 *update)
{
    if (subscribe->is_v05) {
        xqc_moq_subscribe_msg_t_v05 *msg = subscribe->subscribe_msg_v05;
        msg->start_group_id = update->start_group_id;
        msg->start_object_id = update->start_object_id;
        msg->end_group_id = update->end_group_id;
        msg->end_object_id = update->end_object_id;
    } else {
        // TODO check it later for adding v13 support
        xqc_moq_subscribe_msg_t_v13 *msg = subscribe->subscribe_msg_v13;
        msg->start_group_id = update->start_group_id;
        msg->start_object_id = update->start_object_id;
        msg->end_group_id = update->end_group_id;
        msg->end_object_id = update->end_object_id;
    }
}

// xqc_int_t
// xqc_moq_subscribe(xqc_moq_session_t *session, const char *track_namespace, const char *track_name,
//     xqc_moq_filter_type_t filter_type, uint64_t start_group_id, uint64_t start_object_id,
//     uint64_t end_group_id, uint64_t end_object_id, char *authinfo)
// {
//     xqc_moq_subscribe_t *subscribe;
//     xqc_moq_track_t *track;
//     xqc_int_t ret;
//     track = xqc_moq_find_track_by_name(session, track_namespace, track_name, XQC_MOQ_TRACK_FOR_SUB);
//     if (track == NULL) {
//         xqc_log(session->log, XQC_LOG_ERROR, "|track not found|");
//         return -XQC_ENULLPTR;
//     }

//     if (track->track_alias != -1 || track->subscribe_id != -1) {
//         xqc_log(session->log, XQC_LOG_ERROR, "|track already subscribed|");
//         return -MOQ_PROTOCOL_VIOLATION;
//     }

//     uint64_t subscribe_id = xqc_moq_session_alloc_subscribe_id(session);
//     uint64_t track_alias = xqc_moq_session_alloc_track_alias(session);
//     xqc_moq_track_set_subscribe_id(track, subscribe_id);
//     xqc_moq_track_set_alias(track, track_alias);

//     subscribe = xqc_moq_subscribe_create(session, subscribe_id, track->track_alias, track_namespace, track_name,
//                                          filter_type, start_group_id, start_object_id, end_group_id, end_object_id,
//                                          authinfo, 1);
//     if (subscribe == NULL) {
//         xqc_log(session->log, XQC_LOG_ERROR, "|create subscribe error|");
//         return -XQC_ENULLPTR;
//     }

//     // ret = xqc_moq_write_subscribe(session, subscribe->subscribe_msg);
//     if (session->version == XQC_MOQ_SUPPORTED_VERSION_05) {
//         ret = xqc_moq_write_subscribe_v05(session, subscribe->subscribe_msg_v05);
//     } else {
//         ret = xqc_moq_write_subscribe_v13(session, subscribe->subscribe_msg_v13);
//     }
//     if (ret < 0) {
//         xqc_log(session->log, XQC_LOG_ERROR, "|write subscribe error|");
//         return ret;
//     }

//     xqc_log(session->log, XQC_LOG_INFO, "|subscribe success|track_name:%s|track_alias:%ui|subscribe_id:%ui|",
//             track_name, track_alias, subscribe_id);

//     return subscribe_id;
// }

xqc_int_t
xqc_moq_subscribe_v05(xqc_moq_session_t *session, const char *track_namespace, const char *track_name,
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

    subscribe = xqc_moq_subscribe_create_v05(session, subscribe_id, track->track_alias, track_namespace, track_name,
                                         filter_type, start_group_id, start_object_id, end_group_id, end_object_id,
                                         authinfo, 1);
    if (subscribe == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|create subscribe error|");
        return -XQC_ENULLPTR;
    }

    ret = xqc_moq_write_subscribe_v05(session, subscribe->subscribe_msg_v05);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|write subscribe error|");
        return ret;
    }

    xqc_log(session->log, XQC_LOG_INFO, "|subscribe success|track_name:%s|track_alias:%ui|subscribe_id:%ui|",
            track_name, track_alias, subscribe_id);

    return subscribe_id;
}

xqc_int_t
xqc_moq_subscribe_v13(xqc_moq_session_t *session, const char *track_namespace, const char *track_name,
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

    // if (track->track_alias != -1 || track->subscribe_id != -1) {
    //     xqc_log(session->log, XQC_LOG_ERROR, "|track already subscribed|");
    //     return -MOQ_PROTOCOL_VIOLATION;
    // }

    uint64_t subscribe_id = xqc_moq_session_alloc_subscribe_id(session);
    // uint64_t track_alias = xqc_moq_session_alloc_track_alias(session);
    xqc_moq_track_set_subscribe_id(track, subscribe_id);
    // find track by subscribe_id
    // xqc_moq_track_set_alias(track, track_alias);


    subscribe = xqc_moq_subscribe_create_v13(session, subscribe_id, track_namespace, track_name,
                                         filter_type, start_group_id, start_object_id, end_group_id, end_object_id,
                                         authinfo, 1);
    if (subscribe == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|create subscribe error|");
        return -XQC_ENULLPTR;
    }

    // ret = xqc_moq_write_subscribe(session, subscribe->subscribe_msg);
    ret = xqc_moq_write_subscribe_v13(session, subscribe->subscribe_msg_v13);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|write subscribe error|");
        return ret;
    }

    xqc_log(session->log, XQC_LOG_INFO, "|subscribe success|track_name:%s|subscribe_id:%ui|",
            track_name, subscribe_id);

    return subscribe_id;
}



xqc_int_t
xqc_moq_subscribe_latest(xqc_moq_session_t *session, const char *track_namespace, const char *track_name)
{
    if (session->version == XQC_MOQ_SUPPORTED_VERSION_05) {
        return xqc_moq_subscribe_v05(session, track_namespace, track_name,
                                     XQC_MOQ_FILTER_LAST_GROUP, 0, 0, 0, 0, NULL);
    } else {
        return xqc_moq_subscribe_v13(session, track_namespace, track_name,
                                     XQC_MOQ_FILTER_LAST_GROUP, 0, 0, 0, 0, NULL);
    }
    // set FILTER_LAST_OBJECT for xquic interop
}

xqc_moq_unsubscribe_t *
xqc_moq_unsubscribe_create(xqc_moq_session_t *session, uint64_t subscribe_id)
{
    xqc_moq_unsubscribe_t *unsubscribe;
    xqc_moq_unsubscribe_msg_t *msg;

    msg = xqc_calloc(1, sizeof(xqc_moq_unsubscribe_msg_t));
    msg->subscribe_id = subscribe_id;

    unsubscribe = xqc_calloc(1, sizeof(xqc_moq_unsubscribe_t));
    unsubscribe->unsubscribe_msg = msg;


    return unsubscribe;
}

xqc_int_t 
xqc_moq_unsubscribe(xqc_moq_session_t *session, uint64_t request_id)
{
    xqc_int_t ret = 0;
    xqc_moq_unsubscribe_t *unsubscribe = xqc_moq_unsubscribe_create(session, 2);
    ret = xqc_moq_write_unsubscribe(session, unsubscribe->unsubscribe_msg);
    if (ret < 0) {
        xqc_moq_msg_free_unsubscribe(unsubscribe);
        xqc_log(session->log, XQC_LOG_ERROR, "|write unsubscribe error|");
        return ret;
    }
    else {
        xqc_log(session->log, XQC_LOG_INFO, "|unsubscribe success|");
    }


    return 0;
}

xqc_int_t
xqc_moq_publish(xqc_moq_session_t *session, xqc_moq_publish_msg_t *publish)
{
    xqc_int_t ret;

    ret = xqc_moq_write_publish_msg(session, publish);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|write publish error|");
        return ret;
    }
    xqc_log(session->log, XQC_LOG_INFO, "|publish success|track_name:%s|track_alias:%ui|",
            publish->track_name, publish->track_alias);

    return 0;
}

xqc_int_t
xqc_moq_subscribe_done(xqc_moq_session_t *session, uint64_t subscribe_id, xqc_moq_subscribe_done_status_t status_code,
     uint64_t stream_count, char *reason, size_t reason_len)
{
    xqc_moq_subscribe_done_msg_t *subscribe_done;
    xqc_int_t ret;

    subscribe_done = xqc_calloc(1, sizeof(xqc_moq_subscribe_done_msg_t));
    subscribe_done->subscribe_id = subscribe_id;
    subscribe_done->status_code = status_code;
    subscribe_done->stream_count = stream_count;
    subscribe_done->reason_len = reason_len;
    subscribe_done->reason = xqc_calloc(1, reason_len + 1);
    xqc_memcpy(subscribe_done->reason, reason, reason_len);

    ret = xqc_moq_write_subscribe_done_msg(session, session->ctl_stream, subscribe_done);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|write subscribe done error|");
        return ret;
    }

    return XQC_OK;
}