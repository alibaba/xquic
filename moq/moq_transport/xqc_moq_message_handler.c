
#include "moq/moq_transport/xqc_moq_message_handler.h"
#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/xqc_moq_subscribe.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_media/xqc_moq_catalog.h"

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
                session->peer_role = *param->value;
                if (session->peer_role > XQC_MOQ_PUBSUB) {
                    xqc_log(session->log, XQC_LOG_ERROR, "|illegal role|", param->type);
                    goto error;
                }
                break;
            case XQC_MOQ_PARAM_PATH:
                //TODO: WEBTRANSPORT get path must close session
                break;
            case XQC_MOQ_PARAM_EXTDATA:
                extdata = (char *)param->value;
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

    xqc_moq_message_parameter_t params[] = {
            {XQC_MOQ_PARAM_ROLE, 1, (uint8_t * ) & session->role},
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

    ret = xqc_moq_subscribe_datachannel(session);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_subscribe_datachannel error|ret:%d|", ret);
        goto error;
    }

    ret = xqc_moq_subscribe_catalog(session);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_subscribe_catalog error|ret:%d|", ret);
        goto error;
    }

    session->session_setup_done = 1;

    xqc_moq_session_on_setup(session, extdata);

    return;

error:
    xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "on client setup");
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
                session->peer_role = *param->value;
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

    ret = xqc_moq_subscribe_datachannel(session);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_subscribe_datachannel error|ret:%d|", ret);
        goto error;
    }

    ret = xqc_moq_subscribe_catalog(session);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_subscribe_catalog error|ret:%d|", ret);
        goto error;
    }

    session->session_setup_done = 1;

    xqc_moq_session_on_setup(session, NULL);

    return;

error:
    xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "on server setup");
}

void
xqc_moq_on_subscribe(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_subscribe_t *subscribe;
    xqc_moq_track_t *track;
    xqc_int_t ret;
    xqc_moq_subscribe_msg_t *subscribe_msg = (xqc_moq_subscribe_msg_t*)msg_base;

    track = xqc_moq_find_track_by_name(session, subscribe_msg->track_namespace, subscribe_msg->track_name, XQC_MOQ_TRACK_FOR_PUB);
    if (track == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|track not found|track_alias:%ui|", subscribe_msg->track_alias);
        goto error;
    }

    if (track->track_alias != -1 || track->subscribe_id != -1) {
        xqc_log(session->log, XQC_LOG_ERROR, "|track already subscribed|");
        goto error;
    }

    subscribe = xqc_moq_find_subscribe(session, subscribe_msg->subscribe_id, 0);
    if (subscribe) {
        xqc_log(session->log, XQC_LOG_ERROR, "|subscribe already exist|subscribe_id:%ui|", subscribe_msg->subscribe_id);
        goto error;
    }

    xqc_moq_track_set_subscribe_id(track, subscribe_msg->subscribe_id);
    xqc_moq_track_set_alias(track, subscribe_msg->track_alias);

    subscribe = xqc_moq_subscribe_create(session, subscribe_msg->subscribe_id,
                     subscribe_msg->track_alias, subscribe_msg->track_namespace, subscribe_msg->track_name,
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
    xqc_moq_subscribe_update_msg_t *update = (xqc_moq_subscribe_update_msg_t*)msg_base;
    subscribe = xqc_moq_find_subscribe(session, update->subscribe_id, 0);
    if (subscribe == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|subscribe not exist|subscribe_id:%ui|", update->subscribe_id);
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
    return;

error:
    xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "on subscribe update");
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
    track = xqc_moq_find_track_by_alias(session, subscribe->subscribe_msg->track_alias, XQC_MOQ_TRACK_FOR_SUB);
    if (track == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|track not found|track_alias:%ui|", subscribe->subscribe_msg->track_alias);
        goto error;
    }

    xqc_log(session->log, XQC_LOG_INFO, "|on_subscribe_ok|track_name:%s|track_alias:%ui|subscribe_id:%ui|",
            track->track_info.track_name, track->track_alias, subscribe_ok->subscribe_id);
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
    return;

error:
    xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "on subscribe error");
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
xqc_moq_on_object(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_object_t *object)
{
    xqc_moq_track_t *track;
    xqc_log(session->log, XQC_LOG_DEBUG, "|subscribe_id:%ui|track_alias:%ui|group_id:%ui|"
                                         "object_id:%ui|send_order:%ui|status:%ui|payload_len:%ui|",
            object->subscribe_id, object->track_alias, object->group_id,
            object->object_id, object->send_order, object->status, object->payload_len);

    track = xqc_moq_find_track_by_alias(session, object->track_alias, XQC_MOQ_TRACK_FOR_SUB);
    if (track == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|track not found|track_alias:%ui|", object->track_alias);
        goto error;
    }

    xqc_moq_stream_set_track_type(moq_stream, track->track_info.track_type);

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
    xqc_moq_on_object(session, moq_stream, &object);
}

void
xqc_moq_on_track_stream_obj(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_track_stream_obj_msg_t *msg = (xqc_moq_track_stream_obj_msg_t*)msg_base;
    msg->track_header = moq_stream->track_header;
    xqc_moq_object_t object;
    xqc_moq_msg_set_object_by_track(&object, &msg->track_header, msg);
    xqc_moq_on_object(session, moq_stream, &object);
}

void
xqc_moq_on_track_header(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_stream_header_track_msg_t *track_header = (xqc_moq_stream_header_track_msg_t*)msg_base;
    moq_stream->track_header = *track_header;
}
