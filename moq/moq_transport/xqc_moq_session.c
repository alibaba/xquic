#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_send_ctl.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_transport/xqc_moq_stream_quic.h"
#include "moq/moq_transport/xqc_moq_stream_webtransport.h"
#include "moq/moq_transport/xqc_moq_subscribe.h"

void
xqc_moq_init_alpn(xqc_engine_t *engine, xqc_conn_callbacks_t *conn_cbs, xqc_moq_transport_type_t transport_type)
{
    xqc_stream_callbacks_t callbacks;
    if (transport_type == XQC_MOQ_TRANSPORT_QUIC) {
        callbacks = xqc_moq_quic_stream_callbacks;
        xqc_app_proto_callbacks_t ap_cbs = {
            .conn_cbs   = *conn_cbs,
            .stream_cbs = callbacks,
        };
        xqc_engine_register_alpn(engine, XQC_ALPN_MOQ_QUIC, sizeof(XQC_ALPN_MOQ_QUIC) - 1, &ap_cbs, NULL);
    }
}

xqc_moq_session_t *
xqc_moq_session_create(void *conn, xqc_moq_user_session_t *user_session, xqc_moq_transport_type_t transport_type,
    xqc_moq_role_t role, xqc_moq_session_callbacks_t callbacks, char *extdata, xqc_int_t enable_client_setup_v14)
{
    xqc_int_t ret = 0;
    xqc_connection_t *quic_conn;
    xqc_moq_session_t *session = xqc_calloc(1, sizeof(*session));
    session->user_session = user_session;
    session->transport_type = transport_type;
    session->role = role;
    session->session_callbacks = callbacks;
    session->trans_conn = conn;

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

    session->use_client_setup_v14 = enable_client_setup_v14;
    /* Request IDs use parity per endpoint: client even, server odd. */
    session->subscribe_id_allocator = (session->engine->eng_type == XQC_ENGINE_CLIENT) ? 0 : 1;

    if (session->engine->eng_type == XQC_ENGINE_CLIENT) {
        xqc_moq_stream_t *stream = xqc_moq_stream_create_with_transport(session, XQC_STREAM_BIDI);
        if (stream == NULL) {
            xqc_log(session->log, XQC_LOG_ERROR, "|create moq bidi stream error|");
            goto error;
        }
        session->ctl_stream = stream;

        xqc_int_t params_num = 2;
        xqc_moq_message_parameter_t params[3] = {
                {XQC_MOQ_PARAM_ROLE, 1, (uint8_t * ) & session->role, 1, (uint64_t)session->role},
                {XQC_MOQ_PARAM_PATH, sizeof("path"), (uint8_t*)"path", 0, 0},
        };
        if (extdata && strlen(extdata) > 0 && !session->use_client_setup_v14) {
            params[params_num].type = XQC_MOQ_PARAM_EXTDATA;
            params[params_num].length = strlen(extdata) + 1;
            params[params_num].value = (uint8_t *)extdata;
            params[params_num].is_integer = 0;
            params[params_num].int_value = 0;
            params_num++;
        }

        if (session->use_client_setup_v14) {
            xqc_moq_client_setup_v14_msg_t client_setup_v14;
            uint64_t versions_v14[] = {XQC_MOQ_VERSION_14};
            client_setup_v14.versions_num = sizeof(versions_v14) / sizeof(versions_v14[0]);
            client_setup_v14.versions = versions_v14;
            client_setup_v14.params_num = params_num;
            client_setup_v14.params = params;
            xqc_log(session->log, XQC_LOG_INFO, "|send_client_setup_v14|params_num:%d|", params_num);
            ret = xqc_moq_write_client_setup_v14(session, &client_setup_v14);
        } else {
            xqc_moq_client_setup_msg_t client_setup;
            uint64_t versions[] = {XQC_MOQ_VERSION_5};
            client_setup.versions_num = sizeof(versions) / sizeof(versions[0]);
            client_setup.versions = versions;
            client_setup.params_num = params_num;
            client_setup.params = params;
            xqc_log(session->log, XQC_LOG_INFO, "|send_client_setup|params_num:%d|", params_num);
            ret = xqc_moq_write_client_setup(session, &client_setup);
        }
        if (ret < 0) {
            xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_write_client_setup error|ret:%d|", ret);
            goto error;
        }
    }
    xqc_log(session->log, XQC_LOG_INFO, "|session create success|role:%d|", role);
    return session;

error:
    user_session->session = NULL;
    xqc_free(session);
    return NULL;
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
    xqc_free(session);
}

void
xqc_moq_session_on_setup(xqc_moq_session_t *session, char *extdata)
{
    xqc_log(session->log, XQC_LOG_INFO, "|on_session_setup|");
    session->session_callbacks.on_session_setup(session->user_session, extdata);
}

xqc_connection_t *
xqc_moq_session_quic_conn(xqc_moq_session_t *session)
{
    return session->quic_conn;
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
    uint64_t subscribe_id = session->subscribe_id_allocator;
    session->subscribe_id_allocator += 2;
    return subscribe_id;
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
        if (subscribe->subscribe_msg->subscribe_id == subscribe_id) {
            return subscribe;
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
    xqc_list_for_each_safe(pos, next, list) {
        track = xqc_list_entry(pos, xqc_moq_track_t, list_member);
        if (track->track_info.track_namespace && track_namespace && strcmp(track->track_info.track_namespace, track_namespace) == 0
            && track->track_info.track_name && track_name && strcmp(track->track_info.track_name, track_name) == 0) {
            return track;
        }
    }
    return NULL;
}
