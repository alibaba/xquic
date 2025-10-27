
#include "moq/moq_transport/xqc_moq_message_handler.h"
#include "moq/moq_transport/xqc_moq_message.h"
#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/xqc_moq_subscribe.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_transport/xqc_moq_namespace.h"
#include "moq/moq_transport/xqc_moq_track.h"
#include "moq/xqc_moq.h"
#include <stdint.h>
#include <stdio.h>

void
xqc_moq_on_client_setup(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t ret = 0;
    char *extdata = NULL;
    xqc_moq_client_setup_msg_t *client_setup = (xqc_moq_client_setup_msg_t*)msg_base;

    if (session->session_setup_done) {
        return;
    }
    if(!session->version) {
        xqc_log(session->log, XQC_LOG_ERROR, "|version is not support|");
        goto error;
    }

    for (int i = 0; i < client_setup->params_num; i++) {
        xqc_moq_message_parameter_t *param = &client_setup->params[i];
        switch (param->type) {
            case XQC_MOQ_PARAM_ROLE:
                session->peer_role = *param->value;
                if (session->peer_role > XQC_MOQ_PUBSUB) {
                    xqc_log(session->log, XQC_LOG_ERROR, "|illegal role|", param->type);
                    goto error;
                }
                break;
            case XQC_MOQ_PARAM_PATH:
                //TODO: WEBTRANSPORT get path must close session
                break;
            case XQC_MOQ_PARAM_EXTDATA_v05:
            case XQC_MOQ_PARAM_EXTDATA_v11:
                extdata = (char *)param->value;
                break;
            case XQC_MOQ_PARAM_MAX_REQUEST_ID:
                session->max_request_id = *param->value;
                printf("==>max_request_id:%lld\n", session->max_request_id);
                break;
            case XQC_MOQ_PARAM_MAX_AUTH_TOKEN_CACHE_SIZE:
                printf("==>max_auth_token_cache_size:%lld\n", *param->value);
                // TODO
                // session->max_auth_token_cache_size = *param->value; 
                break;
            default:
                xqc_log(session->log, XQC_LOG_ERROR, "|except param type:0x%xi|", param->type);
                goto error;
        }
    }

    xqc_moq_message_parameter_t params[] = {
            {XQC_MOQ_PARAM_ROLE, 1,  (uint64_t *) & session->role},
            // {XQC_MOQ_PARAM_MAX_SUBSCRIBE_ID, 1, (uint8_t * ) & session->max_subscribe_id}, // enable when interop with moxyegn
    };
    xqc_moq_server_setup_msg_t server_setup;
    server_setup.version = session->version;
    server_setup.params_num = sizeof(params) / sizeof(params[0]);
    server_setup.params = params;
    ret = xqc_moq_write_server_setup(session, &server_setup);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_write_server_setup error|ret:%d|", ret);
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
    printf("on_server_setup\n");
    xqc_int_t ret = 0;
    xqc_moq_server_setup_msg_t *server_setup = (xqc_moq_server_setup_msg_t*)msg_base;

    if (session->session_setup_done) {
        return;
    }

    printf("show current selected version: %lld\n", server_setup->version);


    for (int i = 0; i < server_setup->params_num; i++) {
        xqc_moq_message_parameter_t *param = &server_setup->params[i];
        switch (param->type) {
            case XQC_MOQ_PARAM_ROLE:
                session->peer_role = *param->value;
                if (session->peer_role > XQC_MOQ_PUBSUB) {
                    xqc_log(session->log, XQC_LOG_ERROR, "|illegal role:0x%xi|", param->type);
                    goto error;
                }
                break;
            case XQC_MOQ_PARAM_MAX_REQUEST_ID:
                session->max_request_id = *(uint64_t *)param->value;
                printf("==>max_request_id:%lld\n", session->max_request_id);
                break;
            case XQC_MOQ_PARAM_MAX_AUTH_TOKEN_CACHE_SIZE:
                session->max_auth_token_cache_size = *(uint64_t *)param->value;
                printf("==>max_auth_token_cache_size:%lld\n", session->max_auth_token_cache_size);
                break;
            
            default:
                printf("==>except param type:0x%xi\n", (int)param->type);
                // xqc_log(session->log, XQC_LOG_ERROR, "|except param type:0x%xi|", param->type);
                // goto error;
        }
    }

    // ret = xqc_moq_subscribe_datachannel(session);
    // if (ret < 0) {
    //     xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_subscribe_datachannel error|ret:%d|", ret);
    //     goto error;
    // }

    // ret = xqc_moq_subscribe_catalog(session);
    // if (ret < 0) {
    //     xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_subscribe_catalog error|ret:%d|", ret);
    //     goto error;
    // }

    session->session_setup_done = 1;

    xqc_moq_session_on_setup(session, NULL);

    return;

error:
    xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "on server setup");
}


void
xqc_moq_on_subscribe_v05(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_subscribe_t *subscribe;
    xqc_moq_track_t *track;
    xqc_int_t ret;
    xqc_moq_subscribe_msg_t_v05 *subscribe_msg = (xqc_moq_subscribe_msg_t_v05*)msg_base;

    DEBUG_PRINTF("track_namespace: %s\n", subscribe_msg->track_namespace);
    DEBUG_PRINTF("track_name: %s\n", subscribe_msg->track_name);

    if(!subscribe_msg || !subscribe_msg->track_namespace || !subscribe_msg->track_namespace->track_namespace[0]) {
        xqc_log(session->log, XQC_LOG_ERROR, "|subscribe_msg or track_namespace is NULL|");
        goto error;
    }
    track = xqc_moq_find_track_by_name(session, subscribe_msg->track_namespace->track_namespace[0], subscribe_msg->track_name, XQC_MOQ_TRACK_FOR_PUB);
    if (track == NULL) {
        printf("track not found , track_namespace: %s, track_name: %s\n", subscribe_msg->track_namespace->track_namespace[0], subscribe_msg->track_name);
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

    // TODO check it later
    subscribe = xqc_moq_subscribe_create_v05(session, subscribe_msg->subscribe_id,
                     subscribe_msg->track_alias, subscribe_msg->track_namespace->track_namespace[0], subscribe_msg->track_name,
                     subscribe_msg->filter_type, subscribe_msg->start_group_id, subscribe_msg->start_object_id,
                     subscribe_msg->end_group_id, subscribe_msg->end_object_id, NULL, 0);
    if (subscribe == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|create subscribe error|");
        goto error;
    }

    xqc_log(session->log, XQC_LOG_INFO, "|on_subscribe|subscribe_id:%ui|track_name:%s|track_alias:%ui|filter_type:%ui|",
            subscribe_msg->subscribe_id, subscribe_msg->track_name,
            subscribe_msg->track_alias, subscribe_msg->filter_type);

    track->track_ops.on_subscribe_v05(session, subscribe_msg->subscribe_id, track, subscribe_msg);
    return;

error:
    xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "on subscribe");
}

void
xqc_moq_on_subscribe_v13(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    printf("[DEBUG] xqc_moq_on_subscribe_v13 CALLED!\n");

    xqc_moq_subscribe_t *subscribe;
    xqc_moq_track_t *track;
    xqc_int_t ret;
    xqc_moq_subscribe_msg_t_v13 *subscribe_msg = (xqc_moq_subscribe_msg_t_v13*)msg_base;

    DEBUG_PRINTF("track_namespace: %s\n", subscribe_msg->track_namespace);
    DEBUG_PRINTF("track_name: %s\n", subscribe_msg->track_name);

    if(!subscribe_msg || !subscribe_msg->track_namespace || !subscribe_msg->track_namespace->track_namespace[0]) {
        xqc_log(session->log, XQC_LOG_ERROR, "|subscribe_msg or track_namespace is NULL|");
        goto error;
    }
    track = xqc_moq_find_track_by_name(session, subscribe_msg->track_namespace->track_namespace[0], subscribe_msg->track_name, XQC_MOQ_TRACK_FOR_PUB);
    const char *tmp_track_namespace = subscribe_msg->track_namespace->track_namespace[0];
    const char *tmp_track_name = subscribe_msg->track_name;
    printf("tmp_track_namespace: %s\n", tmp_track_namespace);
    printf("tmp_track_name: %s\n", tmp_track_name);
    if (track == NULL) {
        printf("track not found , track_namespace: %s, track_name: %s\n", subscribe_msg->track_namespace->track_namespace[0], subscribe_msg->track_name);
        xqc_log(session->log, XQC_LOG_ERROR, "|track not found|");
        goto error;
    }

    if (track->subscribe_id != -1) {
        xqc_log(session->log, XQC_LOG_ERROR, "|track already subscribed|");
        goto error;
    }

    subscribe = xqc_moq_find_subscribe(session, subscribe_msg->request_id, 0);
    if (subscribe) {
        xqc_log(session->log, XQC_LOG_ERROR, "|subscribe already exist|request_id:%ui|", subscribe_msg->request_id);
        goto error;
    }

    xqc_moq_track_set_subscribe_id(track, subscribe_msg->request_id);
    if (track->track_alias == XQC_MOQ_INVALID_ALIAS) {
        uint64_t track_alias = xqc_moq_session_alloc_track_alias(session);
        xqc_moq_track_set_alias(track, track_alias);
        DEBUG_PRINTF("track_alias: %llu\n", track_alias);
    } else {
        DEBUG_PRINTF("reuse pre-set track_alias: %llu\n", track->track_alias);
    }
    // show all track alias
    


    // TODO check it later
    subscribe = xqc_moq_subscribe_create_v13(session, subscribe_msg->request_id,
                     subscribe_msg->track_namespace->track_namespace[0], subscribe_msg->track_name,
                     subscribe_msg->filter_type, subscribe_msg->start_group_id, subscribe_msg->start_object_id,
                     subscribe_msg->end_group_id, subscribe_msg->end_object_id, NULL, 0);
    if (subscribe == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|create subscribe error|");
        goto error;
    }

    xqc_log(session->log, XQC_LOG_INFO, "|on_subscribe|subscribe_id:%ui|track_name:%s|track_alias:%ui|filter_type:%ui|",
            subscribe_msg->request_id, subscribe_msg->track_name,
            track->track_alias, subscribe_msg->filter_type);

    track->track_ops.on_subscribe_v13(session, subscribe_msg->request_id, track, subscribe_msg);
    return;

error:
    xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "on subscribe");
}

void
xqc_moq_on_subscribe_update_v05(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_subscribe_t *subscribe;
    xqc_moq_track_t *track;
    uint64_t track_alias;
    xqc_moq_subscribe_update_msg_t_v05 *update = (xqc_moq_subscribe_update_msg_t_v05*)msg_base;
    subscribe = xqc_moq_find_subscribe(session, update->subscribe_id, 0);
    if (subscribe == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|subscribe not exist|subscribe_id:%ui|", update->subscribe_id);
        goto error;
    }
    /* 根据 subscribe_id 直接定位 track，避免依赖 track_alias */

    // TODO check it later
    track = xqc_moq_find_track_by_alias(session, subscribe->subscribe_msg_v05->track_alias, XQC_MOQ_TRACK_FOR_SUB);
    if (track == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|track not found|subscribe_id:%ui|", update->subscribe_id);
        goto error;
    }

    track_alias = track->track_alias;

    if (track->track_ops.on_subscribe_update_v05) {
        track->track_ops.on_subscribe_update_v05(session, update->subscribe_id, track, update);
    } else {
        xqc_log(session->log, XQC_LOG_ERROR, "|subscribe update is not supported now|track_type:%d|",
                track->track_info.track_type);
    }
    return;

error:
    xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "on subscribe update");
}

void
xqc_moq_on_subscribe_update_v13(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_subscribe_t *subscribe;
    xqc_moq_track_t *track;
    xqc_moq_subscribe_update_msg_t_v13 *update = (xqc_moq_subscribe_update_msg_t_v13*)msg_base;
    
    subscribe = xqc_moq_find_subscribe(session, update->subscribe_id, 0);
    if (subscribe == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|subscribe not exist|subscribe_id:%llu|", 
                (unsigned long long)update->subscribe_id);
        goto error;
    }
    
    track = xqc_moq_find_track_by_subscribe_id(session, update->subscribe_id, XQC_MOQ_TRACK_FOR_SUB);
    if (track == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|track not found|subscribe_id:%llu|", 
                (unsigned long long)update->subscribe_id);
        goto error;
    }
    
    
    xqc_log(session->log, XQC_LOG_INFO, "|on_subscribe_update|subscribe_id:%llu|",
            (unsigned long long)update->subscribe_id);
    
    if (track->track_ops.on_subscribe_update_v13) {
        track->track_ops.on_subscribe_update_v13(session, update->subscribe_id, track, update);
    } else {
        xqc_log(session->log, XQC_LOG_WARN, "|subscribe update callback not set|track_type:%d|",
                track->track_info.track_type);
    }
    return;

error:
    xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "on subscribe update v13");
}

void
xqc_moq_on_subscribe_ok_v05(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_subscribe_ok_msg_t *subscribe_ok = (xqc_moq_subscribe_ok_msg_t*)msg_base;

    xqc_moq_subscribe_t *subscribe;
    subscribe = xqc_moq_find_subscribe(session, subscribe_ok->subscribe_id, 1);
    if (subscribe == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|subscribe not found|subscribe_id:%ui|", subscribe_ok->subscribe_id);
        goto error;
    }
    xqc_moq_track_t *track;
    track = xqc_moq_find_track_by_alias(session, subscribe->subscribe_msg_v05->track_alias, XQC_MOQ_TRACK_FOR_SUB);
    if (track == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|track not found|track_alias:%ui|", subscribe->subscribe_msg_v05->track_alias);
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
xqc_moq_on_subscribe_ok_v13(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    DEBUG_PRINTF("on subscribe ok v13\n");
    xqc_moq_subscribe_ok_msg_t *subscribe_ok = (xqc_moq_subscribe_ok_msg_t*)msg_base;

    xqc_moq_subscribe_t *subscribe = xqc_moq_find_subscribe(session, subscribe_ok->subscribe_id, 1);

    xqc_moq_track_t *track = NULL;
    if (subscribe_ok->track_alias != XQC_MOQ_INVALID_ALIAS) {
        track = xqc_moq_find_track_by_alias(session, subscribe_ok->track_alias, XQC_MOQ_TRACK_FOR_SUB);
    }
    if (track == NULL && subscribe != NULL) {
        const char *ns = subscribe->subscribe_msg_v13->track_namespace->track_namespace[0];
        const char *name = subscribe->subscribe_msg_v13->track_name;
        track = xqc_moq_find_track_by_name(session, ns, name, XQC_MOQ_TRACK_FOR_SUB);
    }
    if (track == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|on_subscribe_ok_v13 track not found|alias:%ui|subscribe_id:%ui|", subscribe_ok->track_alias, subscribe_ok->subscribe_id);
        return;
    }
    xqc_moq_track_set_subscribe_id(track, subscribe_ok->subscribe_id);
    if (track->track_alias == XQC_MOQ_INVALID_ALIAS && subscribe_ok->track_alias != XQC_MOQ_INVALID_ALIAS) {
        xqc_moq_track_set_alias(track, subscribe_ok->track_alias);
    }

    xqc_log(session->log, XQC_LOG_INFO, "|on_subscribe_ok|track_name:%s|track_alias:%ui|subscribe_id:%ui|",
            track->track_info.track_name, track->track_alias, subscribe_ok->subscribe_id);

    if (track->track_ops.on_subscribe_ok) {
        track->track_ops.on_subscribe_ok(session, track, subscribe_ok);
    }
    return;
}

void
xqc_moq_on_subscribe_error_v05(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    // TODO
    xqc_log(session->log, XQC_LOG_ERROR, "|on_subscribe_error_v05 not implemented|");
    return;   
}


void
xqc_moq_on_subscribe_error_v13(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_subscribe_error_msg_t *subscribe_error = (xqc_moq_subscribe_error_msg_t*)msg_base;

    xqc_moq_subscribe_t *subscribe;

    // TODO subscribe_id will be decided by server side
    // so we need to change logic of on_subscribe_error_v13

    // subscribe = xqc_moq_find_subscribe(session, subscribe_error->subscribe_id, 1);
    // if (subscribe == NULL) {
    //     xqc_log(session->log, XQC_LOG_ERROR, "|subscribe not found|subscribe_id:%ui|", subscribe_error->subscribe_id);
    //     goto error;
    // }
    // xqc_moq_track_t *track;
    // track = xqc_moq_find_track_by_alias(session, subscribe_error->track_alias, XQC_MOQ_TRACK_FOR_SUB);
    // if (track == NULL) {
    //     xqc_log(session->log, XQC_LOG_ERROR, "|track not found|track_alias:%ui|", subscribe_error->track_alias);
    //     goto error;
    // }

    // xqc_log(session->log, XQC_LOG_INFO, "|on_subscribe_error|track_name:%s|track_alias:%ui|",
    //         track->track_info.track_name, track->track_alias);
    // track->track_ops.on_subscribe_error(session, track, subscribe_error);
    if(session->session_callbacks.on_subscribe_error != NULL) {
        session->session_callbacks.on_subscribe_error(session->user_session, subscribe_error);
    }
    else {
        xqc_log(session->log, XQC_LOG_ERROR, "|on_subscribe_error_v13 callback not set|");
    }
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
    xqc_moq_track_t *track = NULL;
    xqc_log(session->log, XQC_LOG_DEBUG, "|subscribe_id:%ui|track_alias:%ui|group_id:%ui|"
                                         "object_id:%ui|send_order:%ui|status:%ui|payload_len:%ui|",
            object->subscribe_id, object->track_alias, object->group_id,
            object->object_id, object->send_order, object->status, object->payload_len);

    static int recv_object_count = 0;
    printf("recv_object\n");
    printf("object->payload_len: %llu\n", object->payload_len);
    printf("object->payload: %.*s\n", (int)object->payload_len, object->payload);
    if(object->payload_len > 0) {
        xqc_log(session->log, XQC_LOG_DEBUG, "|payload:%.*s|", (int)object->payload_len, object->payload);
    }

    if (object->track_alias != XQC_MOQ_INVALID_ALIAS) {
        switch (object->track_alias) {
        case XQC_MOQ_ALIAS_DATACHANNEL: /* datachannel */
            track = xqc_moq_find_track_by_name(session, XQC_MOQ_DATACHANNEL_NAMESPACE, XQC_MOQ_DATACHANNEL_NAME, XQC_MOQ_TRACK_FOR_SUB);
            break;
        case XQC_MOQ_ALIAS_CATALOG: /* catalog */
            track = xqc_moq_find_track_by_name(session, XQC_MOQ_CATALOG_NAMESPACE, XQC_MOQ_CATALOG_NAME, XQC_MOQ_TRACK_FOR_SUB);
            break;
        case XQC_MOQ_ALIAS_VIDEO: /* video */
            track = xqc_moq_find_track_by_name(session, "namespace", "video", XQC_MOQ_TRACK_FOR_SUB);
            break;
        case XQC_MOQ_ALIAS_AUDIO: /* audio */
            track = xqc_moq_find_track_by_name(session, "namespace", "audio", XQC_MOQ_TRACK_FOR_SUB);
            break;
        default:
            break;
        }
        if (track == NULL) {
            track = xqc_moq_find_track_by_alias(session, object->track_alias, XQC_MOQ_TRACK_FOR_SUB);
        }
    }

    if (track == NULL && object->track_alias == XQC_MOQ_INVALID_ALIAS && object->subscribe_id != XQC_MOQ_INVALID_ID) {
        track = xqc_moq_find_track_by_subscribe_id(session, object->subscribe_id, XQC_MOQ_TRACK_FOR_SUB);
    }

    if (track == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR,
                "|object track not found|alias:%ui|subscribe_id:%ui|",
                object->track_alias, object->subscribe_id);
        goto error;
    }

    xqc_moq_stream_set_track_type(moq_stream, track->track_info.track_type);
    // TODO some object may not have subscribe_id , more check later 
    object->subscribe_id = track->subscribe_id;

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
xqc_moq_on_subgroup_object(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_subgroup_object_msg_t *msg = (xqc_moq_subgroup_object_msg_t*)msg_base;
    msg->subgroup_header = moq_stream->subgroup_header;
    xqc_moq_object_t object;
    xqc_moq_msg_set_object_by_subgroup_object(&object, msg);
    xqc_moq_on_object(session, moq_stream, &object);

    // TODO check it later
    if(session->session_callbacks.on_subgroup_object != NULL) {
        session->session_callbacks.on_subgroup_object(session->user_session, msg);
    }
    else {
        xqc_log(session->log, XQC_LOG_ERROR, "|on_subgroup_object callback not set|");
    }
    return;
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

void
xqc_moq_on_max_request_id(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_max_request_id_msg_t *msg = (xqc_moq_max_request_id_msg_t*)msg_base;
    xqc_log(session->log, XQC_LOG_INFO, "|on_max_request_id|max_request_id:%ui|", msg->max_request_id);
    if(session->session_callbacks.on_max_request_id != NULL) {
        session->session_callbacks.on_max_request_id(session->user_session, msg);
    }
    else {
        xqc_log(session->log, XQC_LOG_ERROR, "|on_max_subscribe_id callback not set|");
    }
    return;
}

void xqc_moq_on_subgroup(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    printf("on_subgroup\n");
    xqc_moq_subgroup_msg_t *msg = (xqc_moq_subgroup_msg_t*)msg_base;
    if (moq_stream->subgroup_header == NULL) {
        moq_stream->subgroup_header = xqc_calloc(1, sizeof(xqc_moq_subgroup_msg_t));
        if (moq_stream->subgroup_header == NULL) {
            xqc_log(session->log, XQC_LOG_ERROR, "|alloc subgroup_header failed|");
            return;
        }
    }
    *moq_stream->subgroup_header = *msg;

    xqc_log(session->log, XQC_LOG_INFO, "|on_subgroup|group_id:%ui|subgroup_id:%ui|",
        msg->group_id, msg->subgroup_id);
}

// TODO old callback, check later
// void xqc_moq_on_subgroup_object(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
// {
//     // when recv the object of subgroup
//     xqc_moq_subgroup_object_msg_t *msg = (xqc_moq_subgroup_object_msg_t*)msg_base;
//     msg->subgroup_header = &moq_stream->subgroup_header;
//     if(session->session_callbacks.on_subgroup_object != NULL) {
//         session->session_callbacks.on_subgroup_object(session->user_session, msg);
//     }
//     else {
//         xqc_log(session->log, XQC_LOG_WARN, "|on_subgroup_object callback not set|");
//     }
// }

void xqc_moq_on_subgroup_object_ext(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    // when recv the object of subgroup
    xqc_moq_subgroup_object_msg_ext_t *msg = (xqc_moq_subgroup_object_msg_ext_t*)msg_base;
    msg->subgroup_header = moq_stream->subgroup_header;

    // TODO add new callback for upper layer 
    // if(session->session_callbacks.on_subgroup_object != NULL) {
    //     session->session_callbacks.on_subgroup_object(session->user_session, msg);
    // }
    // else {
    //     xqc_log(session->log, XQC_LOG_WARN, "|on_subgroup_object_ext callback not set|");
    // }
}

void xqc_moq_on_fetch(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_fetch_msg_t *fetch_msg = (xqc_moq_fetch_msg_t *)msg_base;
    // TODO
}

void xqc_moq_on_announce(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_announce_msg_t *announce_msg = (xqc_moq_announce_msg_t *)msg_base;
    xqc_log(session->log, XQC_LOG_INFO, "|xqc_moq_on_announce|track_namespace:%s|",
            announce_msg->track_namespace->track_namespace[0]);
    if(session->session_callbacks.on_announce != NULL) {
        session->session_callbacks.on_announce(session->user_session, announce_msg);
    }
    else {
        xqc_log(session->log, XQC_LOG_WARN, "|on_announce callback not set|");
    }
}

void
xqc_moq_on_track_status(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_track_status_msg_t *track_status = (xqc_moq_track_status_msg_t *)msg_base;
    xqc_log(session->log, XQC_LOG_INFO, "|xqc_moq_on_track_status|track_namespace:%s|track_name:%s|",
        track_status->track_namespace->track_namespace[0], track_status->track_name);
    if(session->session_callbacks.on_track_status != NULL) {
        session->session_callbacks.on_track_status(session->user_session, track_status);
    }
    else {
        xqc_log(session->log, XQC_LOG_WARN, "|on_track_status callback not set|");
    }
}

void
xqc_moq_on_track_status_ok(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_track_status_ok_msg_t *track_status_ok = (xqc_moq_track_status_ok_msg_t*)msg_base;
    xqc_log(session->log, XQC_LOG_INFO, "|on_track_status_ok|request_id:%ui|track_alias:%ui|expires:%ui|",
            track_status_ok->request_id, track_status_ok->track_alias, track_status_ok->expires);
    // 调用用户回调函数
    if (session->session_callbacks.on_track_status_ok) {
        session->session_callbacks.on_track_status_ok(session->user_session, track_status_ok);
    } else {
        xqc_log(session->log, XQC_LOG_WARN, "|on_track_status_ok callback not set|");
    }
}

void
xqc_moq_on_track_status_error(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    printf("on_track_status_error\n");
    xqc_moq_track_status_error_msg_t *track_status_error = (xqc_moq_track_status_error_msg_t*)msg_base;
    
    xqc_log(session->log, XQC_LOG_INFO, "|on_track_status_error|request_id:%ui|error_code:%ui|error_reason:%s|",
            track_status_error->request_id, track_status_error->error_code, 
            track_status_error->error_reason ? track_status_error->error_reason : "");
    
    // 调用用户回调函数
    if (session->session_callbacks.on_track_status_error) {
        session->session_callbacks.on_track_status_error(session->user_session, track_status_error);
    } else {
        xqc_log(session->log, XQC_LOG_WARN, "|on_track_status_error callback not set|");
    }
}

void
xqc_moq_on_subscribe_announces(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_log(session->log, XQC_LOG_DEBUG, "|xqc_moq_on_subscribe_announces stub|\n");
}

/* ------------------- Namespace Subscribe/Unsubscribe (transport) ------------------- */
void
xqc_moq_on_subscribe_namespace(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_subscribe_namespace_msg_t *subscribe_namespace = (xqc_moq_subscribe_namespace_msg_t *)msg_base;
    if (subscribe_namespace == NULL || subscribe_namespace->track_namespace_prefix == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|on_subscribe_namespace invalid msg|\n");
        return;
    }

    if (subscribe_namespace->track_namespace_prefix->track_namespace_num == 0
        || subscribe_namespace->track_namespace_prefix->track_namespace_num > 32) {
        xqc_log(session->log, XQC_LOG_ERROR, "|on_subscribe_namespace invalid prefix segments|num:%llu|\n",
                subscribe_namespace->track_namespace_prefix->track_namespace_num);
    }

    xqc_moq_subscribe_namespace_ok_msg_t *ok = xqc_moq_msg_create_subscribe_namespace_ok(session);
    if (ok) {
        ok->request_id = subscribe_namespace->request_id;
        xqc_moq_write_subscribe_namespace_ok(session, ok);
        xqc_moq_msg_free_subscribe_namespace_ok(ok);
    }
    
    /* register watch */
    xqc_moq_namespace_watch_add(session, subscribe_namespace->request_id,
        subscribe_namespace->track_namespace_prefix);

    xqc_list_head_t *pos, *next;
    xqc_moq_track_t *track;
    int matching_track_count = 0;
    xqc_list_for_each_safe(pos, next, &session->track_list_for_pub) {
        track = xqc_list_entry(pos, xqc_moq_track_t, list_member);
        if (track && track->track_info.track_namespace && track->track_info.track_name) {
            if (xqc_moq_namespace_prefix_match(subscribe_namespace->track_namespace_prefix, 
                                               track->track_info.track_namespace)) {
                matching_track_count++;
                break;
            }
        }
    }
    
    if (matching_track_count > 0) {
        xqc_moq_publish_namespace_msg_t *pub_ns = xqc_moq_msg_create_publish_namespace(session);
        if (pub_ns) {
            pub_ns->request_id = subscribe_namespace->request_id;
            
            pub_ns->track_namespace = xqc_calloc(1, sizeof(xqc_moq_msg_track_namespace_t));
            if (pub_ns->track_namespace) {
                xqc_moq_msg_track_namespace_t *src = subscribe_namespace->track_namespace_prefix;
                xqc_moq_msg_track_namespace_t *dst = pub_ns->track_namespace;
                
                dst->track_namespace_num = src->track_namespace_num;
                dst->track_namespace = xqc_calloc(src->track_namespace_num, sizeof(char*));
                dst->track_namespace_len = xqc_calloc(src->track_namespace_num, sizeof(uint64_t));
                
                if (dst->track_namespace && dst->track_namespace_len) {
                    for (uint64_t i = 0; i < src->track_namespace_num; i++) {
                        dst->track_namespace_len[i] = src->track_namespace_len[i];
                        dst->track_namespace[i] = xqc_malloc(src->track_namespace_len[i] + 1);
                        if (dst->track_namespace[i]) {
                            memcpy(dst->track_namespace[i], src->track_namespace[i], src->track_namespace_len[i]);
                            dst->track_namespace[i][src->track_namespace_len[i]] = '\0';
                        }
                    }
                }
            }
            
            pub_ns->params_num = 0;
            pub_ns->params = NULL;
            
            xqc_int_t ret = xqc_moq_write_publish_namespace(session, pub_ns);
            xqc_log(session->log, XQC_LOG_INFO, 
                    "|send_publish_namespace|request_id:%llu|ret:%d|",
                    (unsigned long long)subscribe_namespace->request_id, ret);
            
            xqc_moq_msg_free_publish_namespace(pub_ns);
        }
    }

    int publish_count = 0;
    xqc_list_for_each_safe(pos, next, &session->track_list_for_pub) {
        track = xqc_list_entry(pos, xqc_moq_track_t, list_member);
        if (track && track->track_info.track_namespace && track->track_info.track_name) {
            if (xqc_moq_namespace_prefix_match(subscribe_namespace->track_namespace_prefix, 
                                               track->track_info.track_namespace)) {
                xqc_log(session->log, XQC_LOG_INFO, 
                        "|ns_existing_track_match|track:%s/%s|alias:%llu|",
                        track->track_info.track_namespace, track->track_info.track_name,
                        (unsigned long long)track->track_alias);
                
                xqc_moq_namespace_notify_on_track_added(session, track);
                publish_count++;
            }
        }
    }
    xqc_log(session->log, XQC_LOG_INFO, "|ns_existing_tracks_published|count:%d|", publish_count);

    if (session->session_callbacks.on_subscribe_namespace != NULL) {
        session->session_callbacks.on_subscribe_namespace(session->user_session, subscribe_namespace);
    } else {
        xqc_log(session->log, XQC_LOG_WARN, "|on_subscribe_namespace callback not set|\n");
    }

}

void
xqc_moq_on_unsubscribe_namespace(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_unsubscribe_namespace_msg_t *unsubscribe_namespace = (xqc_moq_unsubscribe_namespace_msg_t *)msg_base;
    if (unsubscribe_namespace == NULL || unsubscribe_namespace->track_namespace_prefix == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|on_unsubscribe_namespace invalid msg|\n");
        return;
    }
    xqc_moq_namespace_watch_remove_by_prefix(session, unsubscribe_namespace->track_namespace_prefix);
}

void
xqc_moq_on_publish_namespace(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    if (session->session_callbacks.on_publish_namespace) {
        session->session_callbacks.on_publish_namespace(session->user_session, (xqc_moq_publish_namespace_msg_t*)msg_base);
    } else {
        xqc_log(session->log, XQC_LOG_INFO, "|on_publish_namespace cb not set|");
    }
}

void
xqc_moq_on_publish_namespace_done(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    if (session->session_callbacks.on_publish_namespace_done) {
        session->session_callbacks.on_publish_namespace_done(session->user_session, (xqc_moq_publish_namespace_done_msg_t*)msg_base);
    } else {
        xqc_log(session->log, XQC_LOG_INFO, "|on_publish_namespace_done cb not set|");
    }
}
void
xqc_moq_on_publish(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_publish_msg_t *publish = (xqc_moq_publish_msg_t *)msg_base;
    DEBUG_PRINTF("xqc_moq_on_publish|request_id:%"PRIu64"|track_alias:%"PRIu64"\n",
                 publish->request_id, publish->track_alias);
    
    xqc_moq_publish_ok_msg_t *publish_ok = xqc_calloc(1, sizeof(xqc_moq_publish_ok_msg_t));
    if (publish_ok == NULL) {
        return;
    }
    
    xqc_moq_msg_publish_ok_init_handler(&publish_ok->msg_base, session);
    publish_ok->request_id = publish->request_id;

    // TODO add callback function
    if(session->session_callbacks.on_publish != NULL) {
        session->session_callbacks.on_publish(session->user_session, publish);
    }
    else {
        xqc_log(session->log, XQC_LOG_WARN, "|on_publish callback not set|");
    }
    printf("on publish\n");
    
    xqc_moq_msg_free_publish_ok(publish_ok);
}

void
xqc_moq_on_publish_ok(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    printf("[DEBUG] xqc_moq_on_publish_ok CALLED!\n");
    
    xqc_moq_publish_ok_msg_t *publish_ok = (xqc_moq_publish_ok_msg_t *)msg_base;
    printf("[DEBUG] publish_ok->request_id = %llu\n", (unsigned long long)publish_ok->request_id);
    
    if(session->session_callbacks.on_publish_ok != NULL) {
        printf("[DEBUG] Calling user callback on_publish_ok\n");
        session->session_callbacks.on_publish_ok(session->user_session, publish_ok);
    }
    else {
        printf("[DEBUG] on_publish_ok callback NOT SET!\n");
        xqc_log(session->log, XQC_LOG_WARN, "|on_publish_ok callback not set|");
    }
    
    DEBUG_PRINTF("xqc_moq_on_publish_ok|request_id:%"PRIu64"\n",
                 publish_ok->request_id);
}

void
xqc_moq_on_publish_error(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_publish_error_msg_t *publish_error = (xqc_moq_publish_error_msg_t *)msg_base;
    
    DEBUG_PRINTF("xqc_moq_on_publish_error|request_id:%"PRIu64"|error_code:%"PRIu64"\n",
                 publish_error->request_id, publish_error->error_code);
    
    // TODO
} 