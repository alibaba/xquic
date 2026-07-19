
#include "moq/moq_transport/xqc_moq_message_handler.h"
#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/xqc_moq_subscribe.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_transport/xqc_moq_track.h"
#include "moq/moq_transport/xqc_moq_namespace.h"
#include "moq/moq_media/xqc_moq_catalog.h"

#define XQC_MOQ_ALIAS_TYPE_DELETE      0x0
#define XQC_MOQ_ALIAS_TYPE_REGISTER    0x1
#define XQC_MOQ_ALIAS_TYPE_USE_ALIAS   0x2
#define XQC_MOQ_ALIAS_TYPE_USE_VALUE   0x3

static uint8_t xqc_moq_param_read_u8(const xqc_moq_message_parameter_t *param);

void
xqc_moq_on_client_setup(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t ret = 0;
    xqc_int_t role_found = 0;
    uint32_t version = 0;
    char *extdata = NULL;
    xqc_moq_client_setup_msg_t *client_setup = (xqc_moq_client_setup_msg_t*)msg_base;

    if (session->session_setup_done) {
        return;
    }

    for (int i = 0; i < client_setup->versions_num; i++) {
        if (/*client_setup->versions[i] == XQC_MOQ_VERSION ||*/ client_setup->versions[i] == XQC_MOQ_VERSION_5) {
            version = client_setup->versions[i];
            break;
        }
    }

    if (version) {
        session->version = version;
    } else {
        xqc_log(session->log, XQC_LOG_ERROR, "|version is not support|");
        goto error;
    }

    for (int i = 0; i < client_setup->params_num; i++) {
        xqc_moq_message_parameter_t *param = &client_setup->params[i];
        switch (param->type) {
            case XQC_MOQ_PARAM_ROLE:
                role_found = 1;
                session->peer_role = xqc_moq_param_read_u8(param);
                if (session->peer_role > XQC_MOQ_PUBSUB) {
                    xqc_log(session->log, XQC_LOG_ERROR, "|illegal role|", param->type);
                    goto error;
                }
                break;
            case XQC_MOQ_PARAM_PATH:
                //TODO: WEBTRANSPORT get path must close session
                break;
            case XQC_MOQ_PARAM_EXTDATA:
                if (param->value != NULL && param->length > 0) {
                    extdata = (char *)param->value;
                }
                break;
            default:
                xqc_log(session->log, XQC_LOG_ERROR, "|except param type:0x%xi|", param->type);
                goto error;
        }
    }

    if (role_found == 0) {
        session->peer_role = XQC_MOQ_PUBSUB;
        xqc_log(session->log, XQC_LOG_WARN, "|role not found, default to subscriber|");
    }

    xqc_moq_message_parameter_t params[] = {
            {XQC_MOQ_PARAM_ROLE, 1, (uint8_t * ) & session->role, 1, (uint64_t)session->role},
    };
    xqc_moq_server_setup_msg_t server_setup;
    server_setup.version = version;
    server_setup.params_num = sizeof(params) / sizeof(params[0]);
    server_setup.params = params;
    ret = xqc_moq_write_server_setup(session, &server_setup);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_write_server_setup error|ret:%d|", ret);
        goto error;
    }

    if (session->enable_datachannel) {
        ret = xqc_moq_subscribe_datachannel(session);
        if (ret < 0) {
            xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_subscribe_datachannel error|ret:%d|", ret);
            goto error;
        }
    }

    if (session->enable_catalog) {
        ret = xqc_moq_subscribe_catalog(session);
        if (ret < 0) {
            xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_subscribe_catalog error|ret:%d|", ret);
            goto error;
        }
    }

    session->session_setup_done = 1;

    xqc_moq_session_on_setup(session, extdata, client_setup->params, client_setup->params_num);

    return;

error:
    xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "on client setup");
}

void
xqc_moq_on_client_setup_v14(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t ret = 0;
    xqc_int_t role_found = 0;
    char *extdata = NULL;
    xqc_moq_client_setup_v14_msg_t *client_setup = (xqc_moq_client_setup_v14_msg_t*)msg_base;

    if (session->session_setup_done) {
        return;
    }

    uint32_t version = 0;
    for (int i = 0; i < client_setup->versions_num; i++) {
        if (client_setup->versions[i] == XQC_MOQ_VERSION_14) {
            version = client_setup->versions[i];
            break;
        }
    }
    if (version == 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|unsupported version in client_setup_v14|");
        goto error;
    }
    session->version = version;
    xqc_log(session->log, XQC_LOG_INFO, "|client_setup_v14|versions_num:%ui|params_num:%ui|selected_version:%ui|",
            client_setup->versions_num, client_setup->params_num, version);

    for (int i = 0; i < client_setup->params_num; i++) {
        xqc_moq_message_parameter_t *param = &client_setup->params[i];
        switch (param->type) {
            case XQC_MOQ_PARAM_ROLE:
                role_found = 1;
                session->peer_role = xqc_moq_param_read_u8(param);
                xqc_log(session->log, XQC_LOG_INFO, "|client_setup_v14_role|peer_role:%u|", session->peer_role);
                if (session->peer_role > XQC_MOQ_PUBSUB) {
                    xqc_log(session->log, XQC_LOG_ERROR, "|illegal role|");
                    goto error;
                }
                break;
            case XQC_MOQ_PARAM_PATH:
                break;
            case XQC_MOQ_PARAM_EXTDATA:
                if (param->value != NULL && param->length > 0) {
                    extdata = (char *)param->value;
                }
                break;
            default:
                xqc_log(session->log, XQC_LOG_DEBUG, "|ignore unknown param|type:0x%xi|", param->type);
                break;
        }
    }

    if (role_found == 0) {
        session->peer_role = XQC_MOQ_PUBSUB;
        xqc_log(session->log, XQC_LOG_WARN, "|role not found, default to subscriber|");
    }

    xqc_moq_message_parameter_t params[] = {
        {XQC_MOQ_PARAM_ROLE, 1, (uint8_t *)&session->role, 1, (uint64_t)session->role},
    };
    xqc_moq_server_setup_v14_msg_t server_setup;
    memset(&server_setup, 0, sizeof(server_setup));
    server_setup.selected_version = version;
    ret = xqc_moq_write_server_setup_v14(session, &server_setup);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_write_server_setup_v14 error|ret:%d|", ret);
        goto error;
    }
    xqc_log(session->log, XQC_LOG_INFO, "|client_setup_v14_complete|local_role:%u|", session->role);

    if (session->enable_datachannel) {
        ret = xqc_moq_subscribe_datachannel(session);
        if (ret < 0) {
            xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_subscribe_datachannel error|ret:%d|", ret);
            goto error;
        }
    }

    if (session->enable_catalog) {
        ret = xqc_moq_subscribe_catalog(session);
        if (ret < 0) {
            xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_subscribe_catalog error|ret:%d|", ret);
            goto error;
        }
    }

    session->session_setup_done = 1;

    xqc_moq_session_on_setup(session, extdata, client_setup->params, client_setup->params_num);
    return;

error:
    xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "on client setup v14");
}

void
xqc_moq_on_server_setup(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t ret = 0;
    xqc_int_t role_found = 0;
    xqc_moq_server_setup_msg_t *server_setup = (xqc_moq_server_setup_msg_t*)msg_base;

    if (session->session_setup_done) {
        return;
    }

    if (/*server_setup->version == XQC_MOQ_VERSION ||*/ server_setup->version == XQC_MOQ_VERSION_5) {
        session->version = server_setup->version;
    } else {
        xqc_log(session->log, XQC_LOG_ERROR, "|illegal version:%ui|", server_setup->version);
        goto error;
    }

    for (int i = 0; i < server_setup->params_num; i++) {
        xqc_moq_message_parameter_t *param = &server_setup->params[i];
        switch (param->type) {
            case XQC_MOQ_PARAM_ROLE:
                role_found = 1;
                session->peer_role = xqc_moq_param_read_u8(param);
                if (session->peer_role > XQC_MOQ_PUBSUB) {
                    xqc_log(session->log, XQC_LOG_ERROR, "|illegal role:0x%xi|", param->type);
                    goto error;
                }
                break;
            default:
                xqc_log(session->log, XQC_LOG_ERROR, "|except param type:0x%xi|", param->type);
                goto error;
        }
    }

    if (role_found == 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|role not found|");
        goto error;
    }

    if (session->enable_datachannel) {
        ret = xqc_moq_subscribe_datachannel(session);
        if (ret < 0) {
            xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_subscribe_datachannel error|ret:%d|", ret);
            goto error;
        }
    }

    if (session->enable_catalog) {
        ret = xqc_moq_subscribe_catalog(session);
        if (ret < 0) {
            xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_subscribe_catalog error|ret:%d|", ret);
            goto error;
        }
    }

    session->session_setup_done = 1;

    xqc_moq_session_on_setup(session, NULL, server_setup->params, server_setup->params_num);

    return;

error:
    xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "on server setup");
}

void
xqc_moq_on_server_setup_v14(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t ret = 0;
    xqc_int_t role_found = 0;
    xqc_moq_server_setup_v14_msg_t *server_setup = (xqc_moq_server_setup_v14_msg_t*)msg_base;

    if (session->session_setup_done) {
        return;
    }

    session->version = XQC_MOQ_VERSION_14;
    xqc_log(session->log, XQC_LOG_INFO, "|server_setup_v14|params_num:%ui|", server_setup->params_num);

    for (int i = 0; i < server_setup->params_num; i++) {
        xqc_moq_message_parameter_t *param = &server_setup->params[i];
        switch (param->type) {
            case XQC_MOQ_PARAM_ROLE:
                role_found = 1;
                session->peer_role = xqc_moq_param_read_u8(param);
                xqc_log(session->log, XQC_LOG_INFO, "|server_setup_v14_role|peer_role:%u|", session->peer_role);
                if (session->peer_role > XQC_MOQ_PUBSUB) {
                    xqc_log(session->log, XQC_LOG_ERROR, "|illegal role:0x%xi|", param->type);
                    goto error;
                }
                break;
            default:
                xqc_log(session->log, XQC_LOG_DEBUG, "|ignore unknown param|type:0x%xi|", param->type);
                break;
        }
    }

    if (session->enable_datachannel) {
        ret = xqc_moq_subscribe_datachannel(session);
        if (ret < 0) {
            xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_subscribe_datachannel error|ret:%d|", ret);
            goto error;
        }
    }

    if (session->enable_catalog) {
        ret = xqc_moq_subscribe_catalog(session);
        if (ret < 0) {
            xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_subscribe_catalog error|ret:%d|", ret);
            goto error;
        }
    }

    session->session_setup_done = 1;
    xqc_log(session->log, XQC_LOG_INFO, "|server_setup_v14_complete|");

    xqc_moq_session_on_setup(session, NULL, server_setup->params, server_setup->params_num);
    return;

error:
    xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "on server setup v14");
}

void
xqc_moq_on_setup(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream,
    xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_setup_msg_t *setup = (xqc_moq_setup_msg_t *)msg_base;
    if (!session->use_unified_setup || session->session_setup_done
        || (session->peer_ctl_stream && session->peer_ctl_stream != moq_stream))
    {
        xqc_moq_session_error(session, MOQ_PROTOCOL_VIOLATION, "invalid draft-18 SETUP");
        return;
    }

    session->peer_ctl_stream = moq_stream;
    session->version = XQC_MOQ_VERSION_18;
    session->session_setup_done = 1;
    xqc_log(session->log, XQC_LOG_INFO, "|setup_complete|options_len:%ui|",
            setup->options_len);
    xqc_moq_session_on_setup(session, NULL, NULL, 0);
}

void
xqc_moq_on_subscribe(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_subscribe_t *subscribe;
    xqc_moq_track_t *track;
    xqc_int_t ret;
    xqc_moq_subscribe_msg_t *subscribe_msg = (xqc_moq_subscribe_msg_t*)msg_base;

    track = xqc_moq_find_track_by_ns_tuple(session, subscribe_msg->track_namespace_tuple,
                subscribe_msg->track_namespace_num, subscribe_msg->track_name, XQC_MOQ_TRACK_FOR_PUB);
    if (track == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|track not found|track_alias:%ui|", subscribe_msg->track_alias);
        goto error;
    }

    if (track->subscribe_id != XQC_MOQ_INVALID_ID) {
        xqc_log(session->log, XQC_LOG_ERROR, "|track already subscribed|");
        goto error;
    }

    if (track->track_alias == XQC_MOQ_INVALID_ID) {
        xqc_moq_track_set_alias(track, xqc_moq_session_alloc_track_alias(session));
    }
    subscribe_msg->track_alias = track->track_alias;

    subscribe = xqc_moq_find_subscribe(session, subscribe_msg->subscribe_id, 0);
    if (subscribe) {
        xqc_log(session->log, XQC_LOG_ERROR, "|subscribe already exist|subscribe_id:%ui|", subscribe_msg->subscribe_id);
        goto error;
    }

    xqc_moq_track_set_subscribe_id(track, subscribe_msg->subscribe_id);
    xqc_moq_track_set_alias(track, subscribe_msg->track_alias);

    subscribe = xqc_moq_subscribe_create_with_ns_tuple(session, subscribe_msg->subscribe_id,
                     subscribe_msg->track_alias,
                     subscribe_msg->track_namespace_tuple, subscribe_msg->track_namespace_num,
                     subscribe_msg->track_name,
                     subscribe_msg->filter_type, subscribe_msg->start_group_id, subscribe_msg->start_object_id,
                     subscribe_msg->end_group_id, subscribe_msg->end_object_id, NULL, 0);
    if (subscribe == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|create subscribe error|");
        goto error;
    }

    xqc_log(session->log, XQC_LOG_INFO, "|on_subscribe|subscribe_id:%ui|track_name:%s|track_alias:%ui|filter_type:%ui|",
            subscribe_msg->subscribe_id, subscribe_msg->track_name,
            subscribe_msg->track_alias, subscribe_msg->filter_type);

    track->track_ops.on_subscribe(session, subscribe_msg->subscribe_id, track, subscribe_msg);
    return;

error:
    xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "on subscribe");
}

void
xqc_moq_on_subscribe_update(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_subscribe_t *subscribe;
    xqc_moq_track_t *track;
    uint64_t track_alias;
    xqc_moq_err_code_t err = MOQ_INTERNAL_ERROR;
    xqc_moq_subscribe_update_msg_t *update = (xqc_moq_subscribe_update_msg_t*)msg_base;
    subscribe = xqc_moq_find_subscribe(session, update->subscribe_id, 0);
    if (subscribe == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|subscribe not exist|subscribe_id:%ui|", update->subscribe_id);
        goto error;
    }
    if (!xqc_moq_subscribe_update_is_valid(subscribe->subscribe_msg,
                                           update->start_group_id,
                                           update->start_object_id,
                                           update->end_group_id))
    {
        xqc_log(session->log, XQC_LOG_ERROR,
                "|invalid subscribe update|subscribe_id:%ui|old_start:%ui/%ui|old_end:%ui|new_start:%ui/%ui|new_end:%ui|",
                update->subscribe_id, subscribe->subscribe_msg->start_group_id,
                subscribe->subscribe_msg->start_object_id, subscribe->subscribe_msg->end_group_id,
                update->start_group_id, update->start_object_id, update->end_group_id);
        err = MOQ_PROTOCOL_VIOLATION;
        goto error;
    }
    track_alias = subscribe->subscribe_msg->track_alias;

    track = xqc_moq_find_track_by_alias(session, track_alias, XQC_MOQ_TRACK_FOR_PUB);
    if (track == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|track not found|track_alias:%ui|", track_alias);
        goto error;
    }

    xqc_moq_subscribe_update_msg(subscribe, update);

    if (track->track_ops.on_subscribe_update) {
        track->track_ops.on_subscribe_update(session, update->subscribe_id, track, update);
    } else {
        xqc_log(session->log, XQC_LOG_ERROR, "|subscribe update is not supported now|track_type:%d|",
                track->track_info.track_type);
    }

    if (session->session_callbacks.on_subscribe_update) {
        xqc_moq_subscribe_update_info_t update_info;
        xqc_memzero(&update_info, sizeof(update_info));
        update_info.request_id = update->request_id;
        update_info.start_group_id = update->start_group_id;
        update_info.start_object_id = update->start_object_id;
        update_info.end_group_id = update->end_group_id;
        update_info.subscriber_priority = update->subscriber_priority;
        update_info.forward = update->forward;
        session->session_callbacks.on_subscribe_update(session->user_session,
            update->subscribe_id, track, &update_info);
    }
    return;

error:
    xqc_moq_session_error(session, err, "on subscribe update");
}

void
xqc_moq_on_subscribe_ok(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_subscribe_ok_msg_t *subscribe_ok = (xqc_moq_subscribe_ok_msg_t*)msg_base;

    xqc_moq_subscribe_t *subscribe;
    subscribe = xqc_moq_find_subscribe(session, subscribe_ok->subscribe_id, 1);
    if (subscribe == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|subscribe not found|subscribe_id:%ui|", subscribe_ok->subscribe_id);
        goto error;
    }
    xqc_moq_track_t *track;
    track = xqc_moq_find_track_by_subscribe_id(session, subscribe_ok->subscribe_id, XQC_MOQ_TRACK_FOR_SUB);
    if (track == NULL) {
        track = xqc_moq_find_track_by_alias(session, subscribe->subscribe_msg->track_alias, XQC_MOQ_TRACK_FOR_SUB);
    }
    if (track == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|track not found|subscribe_id:%ui|track_alias:%ui|",
                subscribe_ok->subscribe_id, subscribe->subscribe_msg->track_alias);
        goto error;
    }

    if (subscribe_ok->track_alias != XQC_MOQ_INVALID_ID) {
        xqc_moq_track_set_alias(track, subscribe_ok->track_alias);
        subscribe->subscribe_msg->track_alias = subscribe_ok->track_alias;
    }

    xqc_log(session->log, XQC_LOG_INFO, "|on_subscribe_ok|track_name:%s|track_alias:%ui|subscribe_id:%ui|",
            track->track_info.track_name, track->track_alias, subscribe_ok->subscribe_id);

    xqc_int_t apply_ret = xqc_moq_apply_catalog_param_to_track(track,
        subscribe_ok->params, subscribe_ok->params_num);
    if (apply_ret == XQC_OK) {
        xqc_log(session->log, XQC_LOG_INFO,
                "|on_subscribe_ok catalog param applied|track_name:%s|codec:%s|",
                track->track_info.track_name,
                track->track_info.selection_params.codec ?
                    track->track_info.selection_params.codec : "null");
    } else if (apply_ret == XQC_MOQ_CATALOG_PARAM_DECODE_ERR
               || apply_ret == XQC_MOQ_CATALOG_PARAM_NO_MATCH) {
        xqc_log(session->log, XQC_LOG_WARN,
                "|on_subscribe_ok catalog param present but not applied|track_name:%s|reason:%d|",
                track->track_info.track_name, apply_ret);
    }

    track->track_ops.on_subscribe_ok(session, track, subscribe_ok);
    return;

error:
    xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "on subscribe ok");
}

void
xqc_moq_on_subscribe_error(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_subscribe_error_msg_t *subscribe_error = (xqc_moq_subscribe_error_msg_t*)msg_base;

    xqc_moq_subscribe_t *subscribe;
    subscribe = xqc_moq_find_subscribe(session, subscribe_error->subscribe_id, 1);
    if (subscribe == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|subscribe not found|subscribe_id:%ui|", subscribe_error->subscribe_id);
        goto error;
    }
    xqc_moq_track_t *track;
    track = xqc_moq_find_track_by_alias(session, subscribe->subscribe_msg->track_alias, XQC_MOQ_TRACK_FOR_SUB);
    if (track == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|track not found|track_alias:%ui|", subscribe->subscribe_msg->track_alias);
        goto error;
    }

    xqc_log(session->log, XQC_LOG_INFO, "|on_subscribe_error|track_name:%s|track_alias:%ui|",
            track->track_info.track_name, track->track_alias);
    track->track_ops.on_subscribe_error(session, track, subscribe_error);

    xqc_moq_track_set_subscribe_id(track, XQC_MOQ_INVALID_ID);
    xqc_moq_track_set_alias(track, XQC_MOQ_INVALID_ID);
    xqc_list_del(&subscribe->list_member);
    xqc_moq_subscribe_destroy(subscribe);
    xqc_moq_session_check_drain_complete(session);
    return;

error:
    xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "on subscribe error");
}

static void
xqc_moq_publish_send_error(xqc_moq_session_t *session, xqc_moq_track_t *track,
    uint64_t subscribe_id, uint64_t error_code, const char *reason)
{
    xqc_moq_publish_error_msg_t publish_error;
    xqc_memzero(&publish_error, sizeof(publish_error));
    xqc_moq_msg_publish_error_init_handler(&publish_error.msg_base);
    publish_error.subscribe_id = subscribe_id;
    publish_error.error_code = error_code;
    if (reason) {
        publish_error.reason_phrase = (char *)reason;
        publish_error.reason_phrase_len = strlen(reason);
    }
    xqc_moq_write_publish_error(session, &publish_error);

    if (session->session_callbacks.on_publish_error) {
        xqc_moq_track_info_t *track_info = track ? &track->track_info : NULL;
        session->session_callbacks.on_publish_error(session->user_session, track, track_info, &publish_error);
    }
}

void
xqc_moq_on_publish_namespace(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_publish_namespace_msg_t *msg = (xqc_moq_publish_namespace_msg_t*)msg_base;
    if (session == NULL || msg == NULL) {
        return;
    }

    uint64_t sender_parity = xqc_moq_session_is_server(session) ? 0 : 1;
    if ((msg->request_id & 1) != sender_parity) {
        xqc_log(session->log, XQC_LOG_ERROR,
                "|publish_namespace wrong request_id parity|request_id:%ui|expected_parity:%ui|",
                msg->request_id, sender_parity);
        xqc_moq_session_error(session, MOQ_PROTOCOL_VIOLATION, "wrong publish_namespace request_id parity");
        return;
    }

    if (xqc_moq_session_find_request_id(session, msg->request_id)) {
        xqc_log(session->log, XQC_LOG_ERROR,
                "|publish_namespace duplicate request_id|request_id:%ui|", msg->request_id);
        xqc_moq_session_error(session, MOQ_PROTOCOL_VIOLATION,
                              "duplicate publish_namespace request_id");
        return;
    }
    session->max_peer_ns_request_id = msg->request_id;
    session->peer_ns_request_id_seen = 1;

    xqc_int_t ret = xqc_moq_session_add_advertised_namespace(session, 0,
        msg->track_namespace_tuple, msg->track_namespace_num);
    if (ret != XQC_OK) {
        xqc_log(session->log, XQC_LOG_ERROR, "|add peer publish_namespace failed|ret:%d|", ret);
        xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "on publish namespace");
        return;
    }

    char *ns = xqc_moq_namespace_tuple_join(msg->track_namespace_tuple, msg->track_namespace_num);
    xqc_log(session->log, XQC_LOG_INFO,
            "|publish_namespace|request_id:%ui|namespace_num:%ui|namespace:%s|",
            msg->request_id, msg->track_namespace_num, ns ? ns : "");
    xqc_free(ns);
}

void
xqc_moq_on_request_ok(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream,
    xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_request_ok_msg_t *msg = (xqc_moq_request_ok_msg_t *)msg_base;
    if (session == NULL || moq_stream == NULL || msg == NULL) {
        return;
    }

    if (!moq_stream->local_request || moq_stream->response_received) {
        xqc_log(session->log, XQC_LOG_ERROR,
                "|request_ok on invalid request stream|local:%d|received:%d|",
                moq_stream->local_request, moq_stream->response_received);
        xqc_moq_session_error(session, MOQ_PROTOCOL_VIOLATION,
                              "REQUEST_OK on invalid request stream");
        return;
    }
    if (moq_stream->request_type == XQC_MOQ_MSG_PUBLISH_NAMESPACE
        && msg->params_num != 0)
    {
        xqc_moq_session_error(session, MOQ_PROTOCOL_VIOLATION,
                              "PUBLISH_NAMESPACE_OK has parameters");
        return;
    }

    moq_stream->response_received = 1;
    xqc_log(session->log, XQC_LOG_INFO,
            "|request_ok|request_id:%ui|request_type:0x%xi|params_num:%ui|",
            moq_stream->request_id, moq_stream->request_type, msg->params_num);
    if (session->session_callbacks.on_request_ok) {
        session->session_callbacks.on_request_ok(session->user_session,
            moq_stream->request_id, moq_stream->request_type, msg);
    }
}

void
xqc_moq_on_publish_namespace_done(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_publish_namespace_done_msg_t *msg = (xqc_moq_publish_namespace_done_msg_t*)msg_base;
    if (session == NULL || msg == NULL) {
        return;
    }

    xqc_moq_session_remove_advertised_namespace(session, 0,
        msg->track_namespace_tuple, msg->track_namespace_num);

    char *ns = xqc_moq_namespace_tuple_join(msg->track_namespace_tuple, msg->track_namespace_num);
    xqc_log(session->log, XQC_LOG_INFO,
            "|publish_namespace_done|namespace_num:%ui|namespace:%s|",
            msg->track_namespace_num, ns ? ns : "");
    xqc_free(ns);
}

void
xqc_moq_on_publish(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_publish_msg_t *publish = (xqc_moq_publish_msg_t*)msg_base;
    xqc_moq_track_t *track = NULL;
    xqc_moq_subscribe_t *subscribe;
    xqc_moq_track_type_t track_type = XQC_MOQ_TRACK_AUDIO; // Default track type
    xqc_moq_selection_params_t catalog_params;
    xqc_int_t have_catalog_params = 0;
    xqc_int_t has_catalog = 0;
    xqc_int_t track_created = 0;
    char *pub_ns_joined = xqc_moq_namespace_tuple_join(publish->track_namespace_tuple, publish->track_namespace_num);
    xqc_memzero(&catalog_params, sizeof(catalog_params));

    /* TODO: kept separate from xqc_moq_apply_catalog_param_to_track on purpose.
     * This loop also has to *create* the track when it does not yet exist and
     * wire the right track_ops, which the helper does not do. Do not collapse
     * the two without first unifying the track-create path. */
    xqc_moq_message_parameter_t *params = publish->params;
    for (int i = 0; i < publish->params_num; i++) {
        xqc_moq_message_parameter_t *param = &params[i];
        if ((param->type != XQC_MOQ_PARAM_CATALOG
             && param->type != XQC_MOQ_PARAM_AUTHORIZATION_TOKEN)
            || param->value == NULL || param->length == 0) {
            continue;
        }

        xqc_moq_catalog_t catalog;
        xqc_moq_catalog_init(&catalog);
        xqc_int_t cat_ret = xqc_moq_catalog_decode(&catalog, param->value, (size_t)param->length);
        if (cat_ret < 0) {
            xqc_log(session->log, XQC_LOG_ERROR, "|decode catalog param error|ret:%d|subscribe_id:%ui|",
                    cat_ret, publish->subscribe_id);
            xqc_moq_catalog_free_fields(&catalog);
            continue;
        }

        xqc_moq_track_t *catalog_track = NULL;
        if (!xqc_list_empty(&catalog.track_list_for_sub)) {
            catalog_track = xqc_list_entry(catalog.track_list_for_sub.next, xqc_moq_track_t, list_member);
        }

        if (catalog_track != NULL) {
            has_catalog = 1;
            if (catalog_track->track_info.track_type == XQC_MOQ_TRACK_VIDEO
                || catalog_track->track_info.track_type == XQC_MOQ_TRACK_AUDIO) {

                track_type = catalog_track->track_info.track_type;

                if (!have_catalog_params) {
                    xqc_moq_track_copy_params(&catalog_params,
                                              &catalog_track->track_info.selection_params);
                    have_catalog_params = 1;
                }
                xqc_moq_track_info_t *track_info_array[1];
                track_info_array[0] = &catalog_track->track_info;
                session->session_callbacks.on_catalog(session->user_session, track_info_array, 1);
                track = xqc_moq_find_track_by_ns_tuple(session, publish->track_namespace_tuple,
                            publish->track_namespace_num, publish->track_name, XQC_MOQ_TRACK_FOR_SUB);
                if (track) {
                    xqc_moq_track_set_params(track, &catalog_track->track_info.selection_params);
                } else {
                    xqc_log(session->log, XQC_LOG_INFO,
                            "|on_publish catalog params pending track create|track:%s/%s|",
                            pub_ns_joined, publish->track_name);
                }
            } else if (catalog_track->track_info.track_type == XQC_MOQ_TRACK_DATACHANNEL) {
                track_type = XQC_MOQ_TRACK_DATACHANNEL;
                char *cat_ns = xqc_moq_namespace_tuple_join(catalog_track->track_info.track_namespace_tuple,
                                                            catalog_track->track_info.track_namespace_num);
                xqc_log(session->log, XQC_LOG_INFO,
                        "|on_publish_catalog_datatrack|subscribe_id:%ui|track:%s/%s|",
                        publish->subscribe_id,
                        cat_ns ? cat_ns : "null",
                        catalog_track->track_info.track_name ?
                            catalog_track->track_info.track_name : "null");
                xqc_free(cat_ns);
            }
        }

        xqc_moq_catalog_free_fields(&catalog);
        break;
    }

    track = xqc_moq_find_track_by_ns_tuple(session, publish->track_namespace_tuple,
                publish->track_namespace_num, publish->track_name, XQC_MOQ_TRACK_FOR_SUB);
    if (track == NULL) {
        xqc_moq_selection_params_t *params = NULL;
        xqc_moq_container_t container = XQC_MOQ_CONTAINER_LOC;

        if (have_catalog_params) {
            params = &catalog_params;
        }

        if (track_type == XQC_MOQ_TRACK_VIDEO || track_type == XQC_MOQ_TRACK_AUDIO) {
            if (!has_catalog) {
                container = XQC_MOQ_CONTAINER_NONE;
            }
        } else if (track_type == XQC_MOQ_TRACK_DATACHANNEL) {
            params = NULL;
            container = XQC_MOQ_CONTAINER_NONE;
        }

        track = xqc_moq_track_create_with_ns_tuple(session,
                                     publish->track_namespace_tuple, publish->track_namespace_num,
                                     publish->track_name, track_type, params, container,
                                     XQC_MOQ_TRACK_FOR_SUB);
        if (track == NULL) {
            xqc_log(session->log, XQC_LOG_ERROR, "|on_publish track not found|track_name:%s|", publish->track_name);
            xqc_moq_publish_send_error(session, NULL, publish->subscribe_id,
                                      XQC_MOQ_PUBLISH_ERR_TRACK_NOT_FOUND, "track not found");
            goto clean_up;
        }
        track_created = 1;

        if (!has_catalog && (track->track_info.track_type == XQC_MOQ_TRACK_VIDEO ||
                track->track_info.track_type == XQC_MOQ_TRACK_AUDIO)) {
            xqc_moq_track_set_raw_object(track, 1);
        }

        xqc_log(session->log, XQC_LOG_INFO,
                "|on_publish_track_created|subscribe_id:%ui|track:%s/%s|track_type:%d|container:%d|",
                publish->subscribe_id,
                pub_ns_joined ? pub_ns_joined : "null",
                track->track_info.track_name ? track->track_info.track_name : "null",
                track->track_info.track_type, track->container_format);
    } else {
        xqc_log(session->log, XQC_LOG_INFO,
                "|on_publish_track_found|subscribe_id:%ui|track:%s/%s|track_type:%d|",
                publish->subscribe_id,
                pub_ns_joined ? pub_ns_joined : "null",
                track->track_info.track_name ? track->track_info.track_name : "null",
                track->track_info.track_type);
    }

    if (track->subscribe_id != XQC_MOQ_INVALID_ID && track->subscribe_id != publish->subscribe_id) {
        xqc_log(session->log, XQC_LOG_INFO,
                "|on_publish_discovery_duplicate|track_name:%s|existing_id:%ui|publish_id:%ui|",
                track->track_info.track_name, track->subscribe_id, publish->subscribe_id);

        if (have_catalog_params) {
            xqc_moq_track_set_params(track, &catalog_params);
        }
        if (session->session_callbacks.on_publish) {
            session->session_callbacks.on_publish(session->user_session, track, publish);
        }
        goto clean_up;
    }

    xqc_log(session->log, XQC_LOG_INFO,
            "|on_publish|subscribe_id:%ui|track:%s/%s|track_alias:%ui|forward:%u|",
            publish->subscribe_id, pub_ns_joined, publish->track_name,
            publish->track_alias, publish->forward);

    xqc_moq_publish_selected_params_t selected_params;
    memset(&selected_params, 0, sizeof(selected_params));
    selected_params.forward = 1;
    selected_params.group_order = publish->group_order;
    selected_params.filter_type = XQC_MOQ_FILTER_LAST_GROUP;

    if (session->session_callbacks.on_publish_accept) {
        session->session_callbacks.on_publish_accept(session->user_session, track, publish, &selected_params);
    }
    xqc_log(session->log, XQC_LOG_DEBUG,
            "|publish_selection|subscribe_id:%ui|filter:%ui|start_group:%ui|start_object:%ui|end_group:%ui|end_object:%ui|forward:%u|group_order:%u|",
            publish->subscribe_id, selected_params.filter_type, selected_params.start_group_id,
            selected_params.start_object_id, selected_params.end_group_id, selected_params.end_object_id,
            selected_params.forward, selected_params.group_order);

    subscribe = xqc_moq_find_subscribe(session, publish->subscribe_id, 1);
    if (subscribe == NULL) {
        subscribe = xqc_moq_subscribe_create_with_ns_tuple(session, publish->subscribe_id,
                                             publish->track_alias,
                                             publish->track_namespace_tuple, publish->track_namespace_num,
                                             publish->track_name, selected_params.filter_type,
                                             selected_params.start_group_id, selected_params.start_object_id,
                                             selected_params.end_group_id, selected_params.end_object_id, NULL, 1);
        if (subscribe == NULL) {
            xqc_log(session->log, XQC_LOG_ERROR, "|on_publish create subscribe error|");
            xqc_moq_publish_send_error(session, track, publish->subscribe_id,
                                      XQC_MOQ_PUBLISH_ERR_INTERNAL, "internal error");
            goto clean_up;
        }
    }

    xqc_moq_track_set_alias(track, publish->track_alias);
    xqc_moq_track_set_subscribe_id(track, publish->subscribe_id);

    subscribe->subscribe_msg->filter_type = selected_params.filter_type;
    subscribe->subscribe_msg->start_group_id = selected_params.start_group_id;
    subscribe->subscribe_msg->start_object_id = selected_params.start_object_id;
    subscribe->subscribe_msg->end_group_id = selected_params.end_group_id;
    subscribe->subscribe_msg->end_object_id = selected_params.end_object_id;
    subscribe->subscribe_msg->forward = selected_params.forward;
    subscribe->subscribe_msg->group_order = selected_params.group_order;

    if (session->session_callbacks.on_publish) {
        session->session_callbacks.on_publish(session->user_session, track, publish);
    }
    goto clean_up;

clean_up:
    xqc_free(pub_ns_joined);
    if (track_created && track != NULL && track->subscribe_id == XQC_MOQ_INVALID_ID) {
        xqc_list_del(&track->list_member);
        xqc_moq_track_destroy(track);
        track = NULL;
    }
    if (have_catalog_params) {
        xqc_moq_track_free_params(&catalog_params);
    }
}

void
xqc_moq_on_publish_ok(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_publish_ok_msg_t *publish_ok = (xqc_moq_publish_ok_msg_t*)msg_base;
    xqc_moq_subscribe_t *subscribe;
    xqc_moq_track_t *track;

    subscribe = xqc_moq_find_subscribe(session, publish_ok->subscribe_id, 0);
    if (subscribe == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|publish_ok subscribe not found|subscribe_id:%ui|",
                publish_ok->subscribe_id);
        goto error;
    }

    track = xqc_moq_find_track_by_alias(session, subscribe->subscribe_msg->track_alias, XQC_MOQ_TRACK_FOR_PUB);
    if (track == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|publish_ok track not found|track_alias:%ui|",
                subscribe->subscribe_msg->track_alias);
        goto error;
    }

    xqc_moq_track_set_alias(track, subscribe->subscribe_msg->track_alias);
    xqc_moq_track_set_subscribe_id(track, publish_ok->subscribe_id);

    if (session->session_callbacks.on_publish_ok) {
        session->session_callbacks.on_publish_ok(session->user_session, track, publish_ok);
    }
    return;

error:
    xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "on publish ok");
}

void
xqc_moq_on_publish_error(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_publish_error_msg_t *publish_error = (xqc_moq_publish_error_msg_t*)msg_base;
    xqc_moq_subscribe_t *subscribe;
    xqc_moq_track_t *track;

    subscribe = xqc_moq_find_subscribe(session, publish_error->subscribe_id, 0);
    if (subscribe == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|publish_error subscribe not found|subscribe_id:%ui|",
                publish_error->subscribe_id);
        return;
    }

    track = xqc_moq_find_track_by_alias(session, subscribe->subscribe_msg->track_alias, XQC_MOQ_TRACK_FOR_PUB);
    if (track) {
        char *err_ns = xqc_moq_namespace_tuple_join(track->track_info.track_namespace_tuple, track->track_info.track_namespace_num);
        xqc_log(session->log, XQC_LOG_INFO,
                "|on_publish_error|subscribe_id:%ui|track:%s/%s|reason:%s|",
                publish_error->subscribe_id,
                err_ns ? err_ns : "null", track->track_info.track_name,
                publish_error->reason_phrase ? publish_error->reason_phrase : "null");
        xqc_free(err_ns);
        xqc_moq_track_set_alias(track, XQC_MOQ_INVALID_ID);
        xqc_moq_track_set_subscribe_id(track, XQC_MOQ_INVALID_ID);
        if (session->session_callbacks.on_publish_error) {
            xqc_moq_track_info_t *track_info = &track->track_info;
            session->session_callbacks.on_publish_error(session->user_session, track, track_info, publish_error);
        }
    } else {
        xqc_log(session->log, XQC_LOG_INFO,
                "|on_publish_error no track|subscribe_id:%ui|reason:%s|",
                publish_error->subscribe_id,
                publish_error->reason_phrase ? publish_error->reason_phrase : "null");
    }

    xqc_list_del(&subscribe->list_member);
    xqc_moq_subscribe_destroy(subscribe);
    xqc_moq_session_check_drain_complete(session);
}

void
xqc_moq_on_publish_done(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_publish_done_msg_t *publish_done = (xqc_moq_publish_done_msg_t*)msg_base;
    xqc_moq_subscribe_t *subscribe;
    xqc_moq_track_t *track;

    subscribe = xqc_moq_find_subscribe(session, publish_done->subscribe_id, 1);
    if (subscribe == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|publish_done subscribe not found|subscribe_id:%ui|",
                publish_done->subscribe_id);
        return;
    }

    track = xqc_moq_find_track_by_alias(session, subscribe->subscribe_msg->track_alias, XQC_MOQ_TRACK_FOR_SUB);
    if (track) {
        char *done_ns = xqc_moq_namespace_tuple_join(track->track_info.track_namespace_tuple, track->track_info.track_namespace_num);
        xqc_log(session->log, XQC_LOG_INFO,
                "|on_publish_done|subscribe_id:%ui|track:%s/%s|status:%ui|streams:%ui|reason:%s|",
                publish_done->subscribe_id, done_ns ? done_ns : "null", track->track_info.track_name,
                publish_done->status_code, publish_done->stream_count,
                publish_done->reason_phrase ? publish_done->reason_phrase : "null");
        xqc_free(done_ns);
        xqc_moq_track_set_alias(track, XQC_MOQ_INVALID_ID);
        xqc_moq_track_set_subscribe_id(track, XQC_MOQ_INVALID_ID);
        if (session->session_callbacks.on_publish_done) {
            session->session_callbacks.on_publish_done(session->user_session, track, publish_done);
        }
        xqc_list_del(&track->list_member);
        xqc_moq_track_destroy(track);
    } else {
        xqc_log(session->log, XQC_LOG_INFO,
                "|on_publish_done no track|subscribe_id:%ui|status:%ui|streams:%ui|",
                publish_done->subscribe_id, publish_done->status_code, publish_done->stream_count);
    }

    xqc_list_del(&subscribe->list_member);
    xqc_moq_subscribe_destroy(subscribe);
    xqc_moq_session_check_drain_complete(session);
}


void
xqc_moq_stream_set_track_type(xqc_moq_stream_t *moq_stream, xqc_moq_track_type_t track_type)
{
    switch (track_type)
    {
    case XQC_MOQ_TRACK_VIDEO:
        moq_stream->moq_frame_type |= (1 << MOQ_VIDEO_FRAME);
        break;
    case XQC_MOQ_TRACK_AUDIO:
        moq_stream->moq_frame_type |= (1 << MOQ_AUDIO_FRAME);
        break;
    
    default:
        break;
    }
}

void
xqc_moq_on_datagram_object(xqc_moq_session_t *session, xqc_moq_object_t *object)
{
    xqc_moq_track_t *track;
    xqc_log(session->log, XQC_LOG_DEBUG,
            "|datagram_object|track_alias:%ui|group_id:%ui|object_id:%ui|"
            "publisher_priority:%ud|status:%ui|payload_len:%ui|",
            object->track_alias, object->group_id, object->object_id,
            object->publisher_priority, object->status, object->payload_len);

    track = xqc_moq_find_track_by_alias(session, object->track_alias, XQC_MOQ_TRACK_FOR_SUB);
    if (track == NULL) {
        xqc_log(session->log, XQC_LOG_WARN,
                "|datagram_object dropped, track not found|track_alias:%ui|group_id:%ui|object_id:%ui|payload_len:%ui|",
                object->track_alias, object->group_id, object->object_id, object->payload_len);
        return;
    }

    object->subscribe_id = track->subscribe_id;

    if (xqc_moq_track_should_drop_recv_object(track, object)) {
        char *dg_ns = xqc_moq_namespace_tuple_join(track->track_info.track_namespace_tuple, track->track_info.track_namespace_num);
        xqc_log(session->log, XQC_LOG_INFO,
                "|drop cancelled datagram object|track:%s/%s|subscribe_id:%ui|group_id:%ui|object_id:%ui|",
                dg_ns ? dg_ns : "null",
                track->track_info.track_name ? track->track_info.track_name : "null",
                object->subscribe_id, object->group_id, object->object_id);
        xqc_free(dg_ns);
        return;
    }

    if (session->session_callbacks.on_datagram_object) {
        session->session_callbacks.on_datagram_object(session->user_session, track, &track->track_info, object);
    } else {
        xqc_log(session->log, XQC_LOG_WARN,
                "|datagram_object dropped, on_datagram_object not registered|"
                "track_alias:%ui|group_id:%ui|object_id:%ui|payload_len:%ui|",
                object->track_alias, object->group_id, object->object_id, object->payload_len);
    }
}

void
xqc_moq_on_object(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_object_t *object)
{
    xqc_moq_track_t *track;
    xqc_log(session->log, XQC_LOG_DEBUG, "|subscribe_id:%ui|track_alias:%ui|group_id:%ui|"
                                         "object_id:%ui|send_order:%ui|publisher_priority_set:%ud|publisher_priority:%ud|"
                                         "status:%ui|payload_len:%ui|",
            object->subscribe_id, object->track_alias, object->group_id,
            object->object_id, object->send_order,
            object->publisher_priority_set, object->publisher_priority,
            object->status, object->payload_len);

    track = xqc_moq_find_track_by_alias(session, object->track_alias, XQC_MOQ_TRACK_FOR_SUB);
    if (track == NULL) {
        track = xqc_moq_find_track_by_subscribe_id(session, object->subscribe_id, XQC_MOQ_TRACK_FOR_SUB);
        if (track) {
            xqc_log(session->log, XQC_LOG_DEBUG,
                    "|track alias updated|subscribe_id:%ui|old_alias:%ui|new_alias:%ui|",
                    object->subscribe_id, track->track_alias, object->track_alias);
            xqc_moq_track_set_alias(track, object->track_alias);
        } else {
            xqc_log(session->log, XQC_LOG_ERROR, "|track not found|track_alias:%ui|", object->track_alias);
            goto error;
        }
    }

    object->subscribe_id = track->subscribe_id;
    if (xqc_moq_track_should_drop_recv_object(track, object)) {
        if (moq_stream) {
            xqc_moq_stream_stop_sending(moq_stream, XQC_MOQ_DATA_STREAM_CANCELLED);
        }
        char *obj_ns = xqc_moq_namespace_tuple_join(track->track_info.track_namespace_tuple, track->track_info.track_namespace_num);
        xqc_log(session->log, XQC_LOG_INFO,
                "|drop cancelled recv object|track:%s/%s|subscribe_id:%ui|group_id:%ui|object_id:%ui|",
                obj_ns ? obj_ns : "null",
                track->track_info.track_name ? track->track_info.track_name : "null",
                object->subscribe_id, object->group_id, object->object_id);
        xqc_free(obj_ns);
        return;
    }
    if (moq_stream) {
        xqc_moq_stream_set_track_type(moq_stream, track->track_info.track_type);
        xqc_moq_track_on_recv_object(track, moq_stream, object);
    }

    if (session->session_callbacks.on_object && track->raw_object) {
        session->session_callbacks.on_object(session->user_session, track, &track->track_info, object);
        return;
    }

    if (track->track_info.track_type == XQC_MOQ_TRACK_DATACHANNEL) {
        char *dc_ns = xqc_moq_namespace_tuple_join(track->track_info.track_namespace_tuple, track->track_info.track_namespace_num);
        xqc_log(session->log, XQC_LOG_INFO,
                "|on_object_datatrack|subscribe_id:%ui|track:%s/%s|payload_len:%ui|",
                object->subscribe_id,
                dc_ns ? dc_ns : "null",
                track->track_info.track_name ? track->track_info.track_name : "null",
                object->payload_len);
        xqc_free(dc_ns);
    }

    track->track_ops.on_object(session, track, object);
    return;

error:
    xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "on object");
}

void
xqc_moq_on_object_stream(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_object_stream_msg_t *msg = (xqc_moq_object_stream_msg_t*)msg_base;
    xqc_moq_object_t object;
    xqc_moq_msg_set_object_by_object(&object, msg);
    object.forwarding_preference = XQC_MOQ_FORWARDING_SUBGROUP;
    xqc_moq_on_object(session, moq_stream, &object);
}

void
xqc_moq_on_subgroup(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_subgroup_msg_t *msg = (xqc_moq_subgroup_msg_t*)msg_base;
    xqc_moq_object_t object;
    object.subscribe_id = msg->subscribe_id;
    object.track_alias = msg->track_alias;
    object.group_id = msg->group_id;
    uint64_t object_id = 0;
    if (moq_stream->subgroup_header_valid && msg->group_id == moq_stream->subgroup_header.group_id
        && msg->subgroup_id == moq_stream->subgroup_header.subgroup_id) 
    {
        if (moq_stream->subgroup_prev_object_id_valid) {
            object_id = moq_stream->subgroup_prev_object_id + msg->object_id_delta + 1;
        } else {
            object_id = msg->object_id_delta;
        }
    } else {
        object_id = msg->object_id_delta;
        moq_stream->subgroup_prev_object_id_valid = 0;
    }
    moq_stream->subgroup_prev_object_id = object_id;
    moq_stream->subgroup_prev_object_id_valid = 1;
    object.object_id = object_id;
    object.subgroup_id = msg->subgroup_id;
    object.object_id_delta = msg->object_id_delta;
    object.send_order = msg->send_order;
    object.status = msg->status;
    object.ext_params_num = msg->ext_params_num;
    object.ext_params = msg->ext_params;
    object.payload = msg->payload;
    object.payload_len = msg->payload_len;
    object.custom_id_flag = 0;
    object.publisher_priority_set = 0;
    object.publisher_priority = 0;
    object.forwarding_preference = XQC_MOQ_FORWARDING_SUBGROUP;
    moq_stream->subgroup_header.track_alias = object.track_alias;
    moq_stream->subgroup_header.group_id = object.group_id;
    moq_stream->subgroup_header.subgroup_id = object.subgroup_id;
    moq_stream->subgroup_header.subgroup_type = msg->subgroup_type;
    moq_stream->subgroup_header.subgroup_priority = msg->subgroup_priority;
    moq_stream->subgroup_header_valid = 1;
    xqc_stream_t *quic_stream = moq_stream->trans_ops.quic_stream(moq_stream->trans_stream);
    xqc_int_t stream_id = quic_stream ? quic_stream->stream_id : 0;
    xqc_log(session->log, XQC_LOG_INFO,
            "|server_recv_subgroup|subscribe_id:%ui|track_alias:%ui|group_id:%ui|subgroup_id:%ui|object_id:%ui|object_id_delta:%ui|stream_id:%llu|",
            object.subscribe_id, object.track_alias, object.group_id,
            object.subgroup_id, object.object_id, msg->object_id_delta, stream_id);
    
    xqc_moq_on_object(session, moq_stream, &object);
}

void
xqc_moq_on_track_stream_obj(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_track_stream_obj_msg_t *msg = (xqc_moq_track_stream_obj_msg_t*)msg_base;
    msg->track_header = moq_stream->track_header;
    xqc_moq_object_t object;
    xqc_moq_msg_set_object_by_track(&object, &msg->track_header, msg);
    object.forwarding_preference = XQC_MOQ_FORWARDING_SUBGROUP;
    xqc_moq_on_object(session, moq_stream, &object);
}

void
xqc_moq_on_track_header(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_stream_header_track_msg_t *track_header = (xqc_moq_stream_header_track_msg_t*)msg_base;
    moq_stream->track_header = *track_header;
}

void
xqc_moq_on_unsubscribe(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_unsubscribe_msg_t *unsubscribe_msg = (xqc_moq_unsubscribe_msg_t*)msg_base;
    xqc_moq_subscribe_t *subscribe = xqc_moq_find_subscribe(session, unsubscribe_msg->subscribe_id, 0);
    if (subscribe == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|unsubscribe not found|subscribe_id:%ui|", unsubscribe_msg->subscribe_id);
        return;
    }

    xqc_moq_track_t *track = xqc_moq_find_track_by_alias(session, subscribe->subscribe_msg->track_alias,
                                                         XQC_MOQ_TRACK_FOR_PUB);
    if (track == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|track not found for unsubscribe|track_alias:%ui|",
                subscribe->subscribe_msg->track_alias);
        xqc_list_del(&subscribe->list_member);
        xqc_moq_subscribe_destroy(subscribe);
        xqc_moq_session_check_drain_complete(session);
        return;
    }

    xqc_log(session->log, XQC_LOG_INFO, "|on_unsubscribe|track_name:%s|subscribe_id:%ui|",
            track->track_info.track_name, unsubscribe_msg->subscribe_id);

    if (session->session_callbacks.on_unsubscribe) {
        session->session_callbacks.on_unsubscribe(session->user_session, unsubscribe_msg->subscribe_id, track);
    }

    xqc_list_del(&subscribe->list_member);
    xqc_moq_subscribe_destroy(subscribe);
    xqc_moq_track_set_subscribe_id(track, XQC_MOQ_INVALID_ID);
    xqc_moq_track_set_alias(track, XQC_MOQ_INVALID_ID);
    xqc_moq_session_check_drain_complete(session);
}

static uint8_t
xqc_moq_param_read_u8(const xqc_moq_message_parameter_t *param)
{
    if (param == NULL) {
        return 0;
    }
    if (param->is_integer) {
        return (uint8_t)param->int_value;
    }
    if (param->value != NULL && param->length > 0) {
        return param->value[0];
    }
    return 0;
}

void
xqc_moq_on_goaway(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_goaway_msg_t *goaway = (xqc_moq_goaway_msg_t *)msg_base;

    if (!session->session_setup_done) {
        xqc_log(session->log, XQC_LOG_ERROR, "|goaway before session setup|");
        xqc_moq_session_error(session, MOQ_PROTOCOL_VIOLATION,
                              "GOAWAY before session setup");
        return;
    }

    if (session->goaway_received) {
        xqc_log(session->log, XQC_LOG_ERROR, "|duplicate goaway received|");
        xqc_moq_session_error(session, MOQ_PROTOCOL_VIOLATION, "duplicate GOAWAY");
        return;
    }

    session->goaway_received = 1;

    /* Use is_server (eng_type) instead of session->role to handle PUBSUB correctly */
    if (xqc_moq_session_is_server(session)
        && goaway->new_session_uri_len > 0)
    {
        xqc_log(session->log, XQC_LOG_ERROR,
                "|server received goaway with non-empty URI|uri_len:%z|",
                goaway->new_session_uri_len);
        xqc_moq_session_error(session, MOQ_PROTOCOL_VIOLATION,
                              "client GOAWAY must have empty URI");
        return;
    }

    if (goaway->new_session_uri_len > 0 && goaway->new_session_uri) {
        session->goaway_new_session_uri = xqc_calloc(1, goaway->new_session_uri_len + 1);
        if (session->goaway_new_session_uri) {
            xqc_memcpy(session->goaway_new_session_uri, goaway->new_session_uri,
                       goaway->new_session_uri_len);
            session->goaway_new_session_uri_len = goaway->new_session_uri_len;
        }
    }

    xqc_log(session->log, XQC_LOG_INFO,
            "|on_goaway|uri_len:%z|uri:%s|",
            goaway->new_session_uri_len,
            goaway->new_session_uri ? goaway->new_session_uri : "");

    xqc_moq_session_drain(session);

    if (session->session_callbacks.on_goaway) {
        session->session_callbacks.on_goaway(session->user_session,
            goaway->new_session_uri, goaway->new_session_uri_len);
    }
}

void
xqc_moq_on_subscribe_namespace(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_subscribe_namespace_msg_t *msg = (xqc_moq_subscribe_namespace_msg_t*)msg_base;
    if (session == NULL || msg == NULL) {
        return;
    }

    uint64_t sender_parity = xqc_moq_session_is_server(session) ? 0 : 1;
    if ((msg->request_id & 1) != sender_parity) {
        xqc_log(session->log, XQC_LOG_ERROR,
                "|subscribe_namespace wrong request_id parity|request_id:%ui|expected_parity:%ui|",
                msg->request_id, sender_parity);
        xqc_moq_session_error(session, MOQ_PROTOCOL_VIOLATION, "wrong request_id parity");
        return;
    }

    if (msg->track_namespace_tuple == NULL
        || msg->track_namespace_num == 0
        || msg->track_namespace_num > XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS)
    {
        xqc_log(session->log, XQC_LOG_ERROR,
                "|subscribe_namespace invalid prefix|request_id:%ui|prefix_num:%ui|",
                msg->request_id, msg->track_namespace_num);
        xqc_moq_session_error(session, MOQ_PROTOCOL_VIOLATION, "subscribe namespace invalid prefix");
        return;
    }

    if (xqc_moq_session_find_request_id(session, msg->request_id)) {
        xqc_log(session->log, XQC_LOG_ERROR,
                "|subscribe_namespace duplicate request_id|request_id:%ui|",
                msg->request_id);
        xqc_moq_session_error(session, MOQ_PROTOCOL_VIOLATION,
                              "duplicate subscribe_namespace request_id");
        return;
    }

    if (xqc_moq_session_namespace_prefix_overlaps(session, msg->track_namespace_tuple, msg->track_namespace_num)) {
        xqc_log(session->log, XQC_LOG_WARN,
                "|subscribe_namespace namespace prefix overlap|request_id:%ui|", msg->request_id);
        session->max_peer_ns_request_id = msg->request_id;
        session->peer_ns_request_id_seen = 1;

        xqc_moq_subscribe_namespace_error_msg_t err;
        xqc_memzero(&err, sizeof(err));
        err.request_id = msg->request_id;
        err.error_code = XQC_MOQ_SUBSCRIBE_NAMESPACE_ERR_PREFIX_OVERLAP;
        err.reason_phrase = "namespace prefix overlap";
        xqc_int_t ret = xqc_moq_write_subscribe_namespace_error(session, &err);
        if (ret < 0) {
            xqc_log(session->log, XQC_LOG_ERROR, "|write_subscribe_namespace_error error|ret:%d|", ret);
            xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "on subscribe namespace");
        }
        return;
    }

    if (session->session_callbacks.on_subscribe_namespace) {
        xqc_int_t rc = xqc_moq_session_add_pending_inbound_ns(session, msg->request_id,
            msg->track_namespace_tuple, msg->track_namespace_num);
        if (rc < 0) {
            xqc_log(session->log, XQC_LOG_ERROR, "|add pending inbound ns failed|ret:%d|", rc);
            xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "on subscribe namespace");
            return;
        }
        session->session_callbacks.on_subscribe_namespace(session->user_session, msg);
        return;
    }

    xqc_int_t ret = xqc_moq_session_add_pending_inbound_ns(session, msg->request_id,
        msg->track_namespace_tuple, msg->track_namespace_num);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|add pending inbound ns failed|ret:%d|", ret);
        xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "on subscribe namespace");
        return;
    }

    xqc_moq_subscribe_namespace_ok_msg_t ok;
    xqc_memzero(&ok, sizeof(ok));
    ok.request_id = msg->request_id;
    ret = xqc_moq_write_subscribe_namespace_ok(session, &ok);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|write_subscribe_namespace_ok error|ret:%d|", ret);
        xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "on subscribe namespace");
        return;
    }

    xqc_log(session->log, XQC_LOG_INFO,
            "|subscribe_namespace accepted|request_id:%ui|prefix_num:%ui|",
            msg->request_id, msg->track_namespace_num);
}

void
xqc_moq_on_subscribe_namespace_ok(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_subscribe_namespace_ok_msg_t *ok = (xqc_moq_subscribe_namespace_ok_msg_t*)msg_base;
    if (session == NULL || ok == NULL) {
        return;
    }

    xqc_moq_pending_ns_request_t *pending = xqc_moq_session_consume_pending_ns_request(session, ok->request_id);
    if (pending == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR,
                "|subscribe_namespace_ok unknown request_id|request_id:%ui|",
                ok->request_id);
        xqc_moq_session_error(session, MOQ_PROTOCOL_VIOLATION,
                              "subscribe_namespace_ok unknown request_id");
        return;
    }

    ok->track_namespace_tuple = pending->track_namespace_tuple;
    ok->track_namespace_num = pending->track_namespace_num;
    pending->track_namespace_tuple = NULL;

    xqc_log(session->log, XQC_LOG_INFO, "|subscribe_namespace_ok|request_id:%ui|", ok->request_id);

    if (session->session_callbacks.on_subscribe_namespace_ok) {
        session->session_callbacks.on_subscribe_namespace_ok(session->user_session, ok);
    }

    xqc_moq_namespace_tuple_free(ok->track_namespace_tuple, ok->track_namespace_num);
    xqc_free(pending);
}

void
xqc_moq_on_subscribe_namespace_error(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_subscribe_namespace_error_msg_t *err = (xqc_moq_subscribe_namespace_error_msg_t*)msg_base;
    if (session == NULL || err == NULL) {
        return;
    }

    xqc_moq_pending_ns_request_t *pending = xqc_moq_session_consume_pending_ns_request(session, err->request_id);
    if (pending == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR,
                "|subscribe_namespace_error unknown request_id|request_id:%ui|",
                err->request_id);
        xqc_moq_session_error(session, MOQ_PROTOCOL_VIOLATION,
                              "subscribe_namespace_error unknown request_id");
        return;
    }

    err->track_namespace_tuple = pending->track_namespace_tuple;
    err->track_namespace_num = pending->track_namespace_num;
    pending->track_namespace_tuple = NULL;

    xqc_log(session->log, XQC_LOG_WARN, "|subscribe_namespace_error|request_id:%ui|error_code:%ui|reason:%s|",
            err->request_id, err->error_code, err->reason_phrase ? err->reason_phrase : "");

    if (session->session_callbacks.on_subscribe_namespace_error) {
        session->session_callbacks.on_subscribe_namespace_error(session->user_session, err);
    }

    xqc_moq_namespace_tuple_free(err->track_namespace_tuple, err->track_namespace_num);
    xqc_free(pending);
}

void
xqc_moq_on_unsubscribe_namespace(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_unsubscribe_namespace_msg_t *msg = (xqc_moq_unsubscribe_namespace_msg_t*)msg_base;
    if (session == NULL || msg == NULL) {
        return;
    }

    xqc_log(session->log, XQC_LOG_INFO,
            "|unsubscribe_namespace|prefix_num:%ui|",
            msg->track_namespace_num);

    if (msg->track_namespace_tuple != NULL && msg->track_namespace_num > 0) {
        xqc_int_t removed = xqc_moq_session_remove_namespace_prefix(
            session, msg->track_namespace_tuple, msg->track_namespace_num);
        if (removed == 0) {
            xqc_log(session->log, XQC_LOG_WARN,
                    "|unsubscribe_namespace prefix not found|prefix_num:%ui|",
                    msg->track_namespace_num);
        }
    }

    if (session->session_callbacks.on_unsubscribe_namespace) {
        session->session_callbacks.on_unsubscribe_namespace(session->user_session, msg);
    }
}
