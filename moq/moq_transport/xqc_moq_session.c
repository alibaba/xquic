#include "moq/xqc_moq.h"
#include <stdlib.h>
#include <string.h>
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_conn.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_transport/xqc_moq_stream_quic.h"
#include "moq/moq_transport/xqc_moq_subscribe.h"
#include "moq/moq_transport/xqc_moq_datagram.h"

void
xqc_moq_init_alpn(xqc_engine_t *engine, xqc_conn_callbacks_t *conn_cbs, xqc_moq_transport_type_t transport_type)
{
    xqc_stream_callbacks_t callbacks;
    xqc_datagram_callbacks_t dgram_callbacks;
    if (transport_type == XQC_MOQ_TRANSPORT_QUIC) {
        callbacks = xqc_moq_quic_stream_callbacks;
        xqc_app_proto_callbacks_t ap_cbs = {
            .conn_cbs   = *conn_cbs,
            .stream_cbs = callbacks,
        };
        xqc_engine_register_alpn(engine, XQC_ALPN_MOQ_QUIC_V05, strlen(XQC_ALPN_MOQ_QUIC_V05), &ap_cbs, NULL);
    }
}

void
xqc_moq_init_alpn_by_custom(xqc_engine_t *engine, xqc_conn_callbacks_t *conn_cbs, xqc_moq_transport_type_t transport_type, xqc_moq_supported_version_t version)
{
    xqc_stream_callbacks_t callbacks;
    xqc_datagram_callbacks_t dgram_callbacks;
    if (transport_type == XQC_MOQ_TRANSPORT_QUIC) {
        if(version == XQC_MOQ_SUPPORTED_VERSION_14)
            callbacks = xqc_moq_quic_stream_callbacks_v11; // TODO
        else if(version == XQC_MOQ_SUPPORTED_VERSION_05)
            callbacks = xqc_moq_quic_stream_callbacks;
        else {
            DEBUG_PRINTF("illegal version setting for ALPN");
            return;
        }

        dgram_callbacks = xqc_moq_quic_dgram_callbacks;
        xqc_app_proto_callbacks_t ap_cbs = {
            .conn_cbs   = *conn_cbs,
            .stream_cbs = callbacks,
            .dgram_cbs  = dgram_callbacks,
        };
        xqc_int_t ret = 0;
        if(version == XQC_MOQ_SUPPORTED_VERSION_14){
            ret = xqc_engine_register_alpn(engine, XQC_ALPN_MOQ_QUIC_V15_T0, strlen(XQC_ALPN_MOQ_QUIC_V15_T0), &ap_cbs, NULL);
            ret = xqc_engine_register_alpn(engine, XQC_ALPN_MOQ_QUIC_V15_T1, strlen(XQC_ALPN_MOQ_QUIC_V15_T1), &ap_cbs, NULL);
            ret = xqc_engine_register_alpn(engine, XQC_ALPN_MOQ_QUIC_V14, strlen(XQC_ALPN_MOQ_QUIC_V14), &ap_cbs, NULL);
            ret = xqc_engine_register_alpn(engine, XQC_ALPN_MOQ_QUIC_V05, strlen(XQC_ALPN_MOQ_QUIC_V05), &ap_cbs, NULL);
        }
        else if(version == XQC_MOQ_SUPPORTED_VERSION_05){
            ret = xqc_engine_register_alpn(engine, XQC_ALPN_MOQ_QUIC_V05, strlen(XQC_ALPN_MOQ_QUIC_V05), &ap_cbs, NULL);
        }
        else {
            DEBUG_PRINTF("illegal version setting for ALPN");
            return;
        }
        if(ret != XQC_OK){
            DEBUG_PRINTF("xqc_engine_register_alpn error");
            return;
        }
    }
}

xqc_moq_session_t *
 xqc_moq_session_create(void *conn, xqc_moq_user_session_t *user_session, xqc_moq_transport_type_t transport_type, xqc_moq_supported_version_t version,
    xqc_moq_role_t role, xqc_moq_session_callbacks_t callbacks, char *extdata)
{
    xqc_int_t ret = 0;
    xqc_connection_t *quic_conn;
    xqc_moq_session_t *session = xqc_calloc(1, sizeof(*session));
    session->user_session = user_session;
    session->transport_type = transport_type;
    session->role = role;
    session->session_callbacks = callbacks;
    session->trans_conn = conn;
    session->version = version;

    xqc_moq_init_bitrate(session);

    switch (transport_type) {
        case XQC_MOQ_TRANSPORT_QUIC: {
            quic_conn = (xqc_connection_t *)conn;
            break;
        }
        /*case XQC_MOQ_TRANSPORT_WEBTRANSPORT: {
            //TODO: WEBTRANSPORT
            wt_conn = (xqc_wt_t *)conn;
            quic_conn = wt_conn->conn;
            break;
        }*/
        default: {
            goto error;
        }
    }

    session->quic_conn = quic_conn;
    session->engine = quic_conn->engine;
    session->log = quic_conn->log;
    session->timer_manager = &quic_conn->conn_timer_manager;
    session->enable_fec = quic_conn->conn_settings.enable_encode_fec;

    user_session->session = session;

    xqc_init_list_head(&session->local_subscribe_list);
    xqc_init_list_head(&session->peer_subscribe_list);
    xqc_init_list_head(&session->track_list_for_pub);
    xqc_init_list_head(&session->track_list_for_sub);
    xqc_init_list_head(&session->namespace_watch_list);

    if (session->engine->eng_type == XQC_ENGINE_CLIENT) {
        xqc_moq_stream_t *stream = xqc_moq_stream_create_with_transport(session, XQC_STREAM_BIDI);
        if (stream == NULL) {
            xqc_log(session->log, XQC_LOG_ERROR, "|create moq bidi stream error|");
            goto error;
        }
        session->ctl_stream = stream;

        xqc_moq_client_setup_msg_t client_setup;
        uint64_t versions[] = {version}; // TODO: support fallback version v05
        xqc_int_t params_num = 0;
        // extdata need a separate params
        xqc_moq_message_parameter_t params[1] = {
                // {XQC_MOQ_PARAM_ROLE, 1, (uint8_t * ) & session->role},
                // {XQC_MOQ_PARAM_PATH, sizeof("path"), (uint8_t*)""},
        };
        if (extdata && strlen(extdata) > 0) {
            if(session->version == XQC_MOQ_VERSION_DRAFT_05){
                params[params_num].type = XQC_MOQ_PARAM_EXTDATA_v05;
            } else {
                params[params_num].type = XQC_MOQ_PARAM_EXTDATA_v11;
            }
            params[params_num].length = strlen(extdata) + 1;
            params[params_num].value = (uint64_t *)extdata;
            params_num++;
        }
        client_setup.versions_num = sizeof(versions) / sizeof(versions[0]);
        printf("client_setup.versions_num = %d\n", (int)client_setup.versions_num);
        client_setup.versions = versions;
        client_setup.params_num = params_num;
        client_setup.params = params;

        ret = xqc_moq_write_client_setup(session, &client_setup);
        if (ret < 0) {
            xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_write_client_setup error|ret:%d|", ret);
            goto error;
        }
        else {
            printf("xqc_moq_write_client_setup ok\n");
        }

        xqc_log(session->log, XQC_LOG_INFO, "|CLIENT_SETUP sent|alpn:%s|", 
                (session->quic_conn && session->quic_conn->alpn) ? session->quic_conn->alpn : "NULL");
    }
    xqc_log(session->log, XQC_LOG_INFO, "|session create success|role:%d|", role);
    return session;

error:
    user_session->session = NULL;
    xqc_free(session);
    return NULL;
}
xqc_int_t
xqc_moq_bool_norm(xqc_int_t v) {
    return v ? 1 : 0;
}



xqc_int_t
xqc_moq_subscribe_namespace_by_path(xqc_moq_session_t *session, const char **namespace_segments, uint64_t segment_count, uint64_t *out_request_id)
{
    if (session == NULL || namespace_segments == NULL || segment_count == 0) {
        return -XQC_EPARAM;
    }
    
    /* Create SUBSCRIBE_NAMESPACE message */
    xqc_moq_subscribe_namespace_msg_t *msg = xqc_moq_msg_create_subscribe_namespace(session);
    if (msg == NULL) {
        return -XQC_EMALLOC;
    }
    
    /* Generate request_id */
    uint64_t request_id = xqc_moq_session_alloc_subscribe_id(session);
    msg->request_id = request_id;
    
    msg->track_namespace_prefix = xqc_calloc(1, sizeof(xqc_moq_msg_track_namespace_t));
    if (msg->track_namespace_prefix == NULL) {
        xqc_moq_msg_free_subscribe_namespace(msg);
        return -XQC_EMALLOC;
    }
    
    msg->track_namespace_prefix->track_namespace_num = segment_count;
    msg->track_namespace_prefix->track_namespace = xqc_calloc(segment_count, sizeof(char*));
    msg->track_namespace_prefix->track_namespace_len = xqc_calloc(segment_count, sizeof(uint64_t));
    
    if (msg->track_namespace_prefix->track_namespace == NULL || 
        msg->track_namespace_prefix->track_namespace_len == NULL) {
        xqc_moq_msg_free_subscribe_namespace(msg);
        return -XQC_EMALLOC;
    }
    
    for (uint64_t i = 0; i < segment_count; i++) {
        size_t len = strlen(namespace_segments[i]);
        msg->track_namespace_prefix->track_namespace[i] = xqc_calloc(1, len + 1);
        if (msg->track_namespace_prefix->track_namespace[i] == NULL) {
            xqc_moq_msg_free_subscribe_namespace(msg);
            return -XQC_EMALLOC;
        }
        memcpy(msg->track_namespace_prefix->track_namespace[i], namespace_segments[i], len);
        msg->track_namespace_prefix->track_namespace_len[i] = len;
    }
    
    msg->params_num = 0;
    msg->params = NULL;
    
    xqc_int_t ret = xqc_moq_write_subscribe_namespace(session, msg);
    
    if (ret >= 0 && out_request_id) {
        *out_request_id = request_id;
    }
    
    xqc_moq_msg_free_subscribe_namespace(msg);
    
    return ret >= 0 ? XQC_OK : ret;
}

void
xqc_moq_session_destroy(xqc_moq_session_t *session)
{
    xqc_list_head_t *pos, *next;
    xqc_moq_subscribe_t *subscribe;
    xqc_moq_track_t *track;

    xqc_log(session->log, XQC_LOG_INFO, "|session destroy begin|");

    xqc_list_for_each_safe(pos, next, &session->local_subscribe_list) {
        subscribe = xqc_list_entry(pos, xqc_moq_subscribe_t, list_member);
        xqc_list_del(pos);
        xqc_moq_subscribe_destroy(subscribe);
    }
    xqc_list_for_each_safe(pos, next, &session->peer_subscribe_list) {
        subscribe = xqc_list_entry(pos, xqc_moq_subscribe_t, list_member);
        xqc_list_del(pos);
        xqc_moq_subscribe_destroy(subscribe);
    }
    xqc_list_for_each_safe(pos, next, &session->track_list_for_pub) {
        track = xqc_list_entry(pos, xqc_moq_track_t, list_member);
        xqc_list_del(pos);
        xqc_moq_track_destroy(track);
    }
    xqc_list_for_each_safe(pos, next, &session->track_list_for_sub) {
        track = xqc_list_entry(pos, xqc_moq_track_t, list_member);
        xqc_list_del(pos);
        xqc_moq_track_destroy(track);
    }
    /* free namespace watches if any (struct defined in new namespace module) */
    xqc_list_for_each_safe(pos, next, &session->namespace_watch_list) {
        xqc_list_del(pos);
        /* actual node free is handled in namespace module's destroy API; safe if NULL now */
    }
    xqc_free(session);
}
/* keep original on_setup defined earlier; remove stray duplicate */

xqc_connection_t *
xqc_moq_session_quic_conn(xqc_moq_session_t *session)
{
    return session->quic_conn;
}

void
xqc_moq_session_on_setup(xqc_moq_session_t *session, char *extdata)
{
    xqc_log(session->log, XQC_LOG_INFO, "|on_session_setup|");
    session->session_callbacks.on_session_setup(session->user_session, extdata);
}

void
xqc_moq_session_error(xqc_moq_session_t *session, xqc_moq_err_code_t code, const char *msg)
{
    xqc_connection_t *quic_conn = xqc_moq_session_quic_conn(session);
    XQC_CONN_CLOSE_MSG(quic_conn, msg);
    XQC_CONN_ERR(quic_conn, code);
}

void
xqc_moq_session_app_error(xqc_moq_session_t *session, uint64_t code)
{
    xqc_connection_t *quic_conn = xqc_moq_session_quic_conn(session);
    XQC_CONN_CLOSE_MSG(quic_conn, "app error");
    XQC_CONN_ERR(quic_conn, code);
}

uint64_t 
xqc_moq_session_get_error(xqc_moq_session_t *session)
{
    xqc_connection_t *quic_conn = xqc_moq_session_quic_conn(session);
    return quic_conn->conn_err;
}

uint64_t
xqc_moq_session_alloc_subscribe_id(xqc_moq_session_t *session)
{
    return session->subscribe_id_allocator++;
}

xqc_moq_subscribe_t *
xqc_moq_find_subscribe(xqc_moq_session_t *session, uint64_t subscribe_id, xqc_int_t is_local)
{
    xqc_moq_subscribe_t *subscribe = NULL;
    xqc_list_head_t *pos, *next;
    xqc_list_head_t *list;
    if (is_local) {
        list = &session->local_subscribe_list;
    } else {
        list = &session->peer_subscribe_list;
    }

    xqc_list_for_each_safe(pos, next, list) {
        subscribe = xqc_list_entry(pos, xqc_moq_subscribe_t, list_member);
        if (subscribe->is_v05) {
            if (subscribe->subscribe_msg_v05->subscribe_id == subscribe_id) {
                return subscribe;
            }
        } else {
            if (subscribe->subscribe_msg_v13->request_id == subscribe_id) {
            return subscribe;
        }
    }
    }
    return NULL;
}


uint64_t
xqc_moq_session_alloc_track_alias(xqc_moq_session_t *session)
{
    return session->track_alias_allocator++;
}


xqc_moq_track_t *
xqc_moq_find_track_by_alias(xqc_moq_session_t *session,
    uint64_t track_alias, xqc_moq_track_role_t role)
{
    xqc_moq_track_t *track = NULL;
    xqc_list_head_t *pos, *next;
    xqc_list_head_t *list;
    if (role == XQC_MOQ_TRACK_FOR_PUB) {
        list = &session->track_list_for_pub;
    } else {
        list = &session->track_list_for_sub;
    }
    xqc_list_for_each_safe(pos, next, list) {
        track = xqc_list_entry(pos, xqc_moq_track_t, list_member);
        if (track->track_alias == track_alias) {
            return track;
        }
        else {
            printf("xqc_moq_find_track_by_alias track: alias not found and track_alias: %llu\n", track->track_alias);
            printf("we need to find track_alias: %llu\n", track_alias);
        }
    }
    return NULL;
}

xqc_moq_track_t *
xqc_moq_find_track_by_name(xqc_moq_session_t *session,
    const char *track_namespace, const char *track_name, xqc_moq_track_role_t role)
{
    xqc_moq_track_t *track = NULL;
    xqc_list_head_t *pos, *next;
    xqc_list_head_t *list;
    if (role == XQC_MOQ_TRACK_FOR_PUB) {
        list = &session->track_list_for_pub;
    } else {
        list = &session->track_list_for_sub;
    }
    printf("to find track namespace: %s, track_name: %s\n", track_namespace, track_name);
    xqc_list_for_each_safe(pos, next, list) {
        track = xqc_list_entry(pos, xqc_moq_track_t, list_member);
        printf("now track namespace: %s, track_name: %s\n", track->track_info.track_namespace, track->track_info.track_name);
        if (track->track_info.track_namespace && track_namespace && strcmp(track->track_info.track_namespace, track_namespace) == 0
            && track->track_info.track_name && track_name && strcmp(track->track_info.track_name, track_name) == 0) {
            return track;
        }
    }
    return NULL;
}

xqc_int_t
xqc_moq_cancel_subscribe(xqc_moq_session_t *session, uint64_t subscribe_id, xqc_int_t is_local)
{
    xqc_moq_subscribe_t *subscribe = xqc_moq_find_subscribe(session, subscribe_id, is_local);
    if (subscribe == NULL) {
        return -XQC_EILLEGAL_FRAME;
    }
    xqc_list_del(&subscribe->list_member);
    // xqc_moq_msg_free_subscribe(subscribe->subscribe_msg);
    if (subscribe->is_v05) {
        xqc_moq_msg_free_subscribe_v05(subscribe->subscribe_msg_v05);
    } else {
        xqc_moq_msg_free_subscribe_v13(subscribe->subscribe_msg_v13);
    }
    return XQC_OK;
}

xqc_moq_track_t *
xqc_moq_find_track_by_subscribe_id(xqc_moq_session_t *session, uint64_t subscribe_id, xqc_moq_track_role_t role)
{
    xqc_moq_track_t *track = NULL;
    xqc_list_head_t *pos, *next;
    xqc_list_head_t *list;
    if (role == XQC_MOQ_TRACK_FOR_PUB) {
        list = &session->track_list_for_pub;
    } else {
        list = &session->track_list_for_sub;
    }
    xqc_list_for_each_safe(pos, next, list) {
        track = xqc_list_entry(pos, xqc_moq_track_t, list_member);
        if (track->subscribe_id == subscribe_id) {
            return track;
        }
    }
    return NULL;
}

const char *
xqc_moq_get_negotiated_alpn(xqc_moq_session_t *session)
{
    if (!session || !session->quic_conn) {
        return NULL;
    }
    return session->quic_conn->alpn;
}

xqc_int_t
xqc_moq_trigger_session_setup(xqc_moq_session_t *session, const char *extdata)
{
    if (!session) {
        return -XQC_EPARAM;
    }
    
    if (session->session_setup_done) {
        xqc_log(session->log, XQC_LOG_WARN, "|session setup already done|");
        return -XQC_EILLEGAL_FRAME;
    }
    
    session->session_setup_done = 1;
    printf("[Protocol] Manually triggering on_session_setup callback (fast RTT mode)\n");
    xqc_log(session->log, XQC_LOG_INFO, "|manually trigger session setup|alpn:%s|", 
            (session->quic_conn && session->quic_conn->alpn) ? session->quic_conn->alpn : "NULL");
    
    xqc_moq_session_on_setup(session, (char *)extdata);
    return XQC_OK;
}