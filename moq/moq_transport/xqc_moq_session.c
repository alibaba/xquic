#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_send_ctl.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_transport/xqc_moq_stream_quic.h"
#include "moq/moq_transport/xqc_moq_stream_webtransport.h"
#include "moq/moq_transport/xqc_moq_subscribe.h"
#include "xquic/xqc_webtransport.h"

#define XQC_MOQ_WT_INITIAL_MAX_STREAMS_UNI  1024
#define XQC_MOQ_WT_INITIAL_MAX_STREAMS_BIDI 1
#define XQC_MOQ_WT_INITIAL_MAX_DATA         (16 * 1024 * 1024ULL)

/*
 * will_create_session callback for MOQ-over-WT:
 * Accept the session only if the :path matches XQC_MOQ_WT_PATH.
 */
int
xqc_moq_wt_will_create_session(xqc_http_headers_t *headers,
    xqc_http_headers_t *response)
{
    size_t i;
    if (headers == NULL) {
        return 0;
    }

    for (i = 0; i < headers->count; i++) {
        if (headers->headers[i].name.iov_len == 5
            && memcmp(headers->headers[i].name.iov_base, ":path", 5) == 0
            && headers->headers[i].value.iov_len == sizeof(XQC_MOQ_WT_PATH) - 1
            && memcmp(headers->headers[i].value.iov_base,
                      XQC_MOQ_WT_PATH,
                      sizeof(XQC_MOQ_WT_PATH) - 1) == 0)
        {
            return 1;
        }
    }

    return 0;
}


xqc_int_t
xqc_moq_init_webtransport(xqc_engine_t *engine,
    xqc_h3_callbacks_t *h3_cbs,
    xqc_webtransport_session_callbacks_t *session_cbs)
{
    if (engine == NULL || session_cbs == NULL
        || session_cbs->webtransport_session_create_notify == NULL)
    {
        return -XQC_EPARAM;
    }

    xqc_h3_callbacks_t h3_callbacks = {0};
    if (h3_cbs) {
        h3_callbacks = *h3_cbs;
    }
    xqc_int_t ret = xqc_h3_ctx_init(engine, &h3_callbacks);
    if (ret != XQC_OK) {
        return ret;
    }

    xqc_webtransport_session_callbacks_t wt_session_cbs = *session_cbs;
    wt_session_cbs.webtransport_will_create_session_notify =
        xqc_moq_wt_will_create_session;

    xqc_webtransport_stream_callbacks_t stream_cbs =
        xqc_moq_wt_stream_callbacks;
    xqc_webtransport_dgram_callbacks_t dgram_cbs = {0};
    const char *alpns[] = { XQC_ALPN_H3 };
    ret = xqc_wt_ctx_init_for_alpns(engine, &dgram_cbs, &wt_session_cbs,
        &stream_cbs, 1, alpns, 1);
    if (ret != XQC_OK) {
        return ret;
    }

    /*
     * max_sessions is intentionally one, but MoQ opens one unidirectional
     * WT stream per media object. Override WT's generic default, which
     * otherwise also uses max_sessions as the initial stream credit.
     */
    return xqc_wt_engine_set_default_settings_for_alpn(engine, XQC_ALPN_H3,
        sizeof(XQC_ALPN_H3) - 1, XQC_WT_MODE_DRAFT15_STRICT,
        XQC_MOQ_WT_INITIAL_MAX_STREAMS_UNI,
        XQC_MOQ_WT_INITIAL_MAX_STREAMS_BIDI,
        XQC_MOQ_WT_INITIAL_MAX_DATA, XQC_TRUE, XQC_TRUE, XQC_TRUE);
}

xqc_int_t
xqc_moq_init_alpn(xqc_engine_t *engine, xqc_conn_callbacks_t *conn_cbs,
    xqc_moq_transport_type_t transport_type)
{
    if (engine == NULL) {
        return -XQC_EPARAM;
    }

    if (transport_type == XQC_MOQ_TRANSPORT_QUIC) {
        if (conn_cbs == NULL) {
            return -XQC_EPARAM;
        }
        xqc_stream_callbacks_t callbacks = xqc_moq_quic_stream_callbacks;
        xqc_app_proto_callbacks_t ap_cbs = {
            .conn_cbs   = *conn_cbs,
            .stream_cbs = callbacks,
        };
        return xqc_engine_register_alpn(engine, XQC_ALPN_MOQ_QUIC,
            sizeof(XQC_ALPN_MOQ_QUIC) - 1, &ap_cbs, NULL);

    }
    if (transport_type == XQC_MOQ_TRANSPORT_WEBTRANSPORT) {
        /*
         * The generic ALPN initializer cannot carry the application callback
         * that creates xqc_moq_session_t after the WT CONNECT succeeds.
         */
        return -XQC_EPARAM;
    }
    return -XQC_EPARAM;
}

xqc_moq_session_t *
xqc_moq_session_create(void *conn, xqc_moq_user_session_t *user_session, xqc_moq_transport_type_t transport_type,
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

    xqc_moq_init_bitrate(session);

    switch (transport_type) {
        case XQC_MOQ_TRANSPORT_QUIC: {
            quic_conn = (xqc_connection_t *)conn;
            break;
        }
        case XQC_MOQ_TRANSPORT_WEBTRANSPORT: {
            /* conn is xqc_wt_session_t* for WT transport */
            xqc_wt_session_t *wt_session = (xqc_wt_session_t *)conn;
            quic_conn = xqc_wt_session_get_conn(wt_session);
            if (quic_conn == NULL) {
                goto error;
            }
            break;
        }
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
    xqc_init_list_head(&session->wt_stream_list);

    if (session->engine->eng_type == XQC_ENGINE_CLIENT) {
        xqc_moq_stream_t *stream = xqc_moq_stream_create_with_transport(session, XQC_STREAM_BIDI);
        if (stream == NULL) {
            xqc_log(session->log, XQC_LOG_ERROR, "|create moq bidi stream error|");
            goto error;
        }
        session->ctl_stream = stream;

        xqc_moq_client_setup_msg_t client_setup;
        uint64_t versions[] = {XQC_MOQ_VERSION_5};
        xqc_int_t params_num = 2;
        xqc_moq_message_parameter_t params[3] = {
                {XQC_MOQ_PARAM_ROLE, 1, (uint8_t * ) & session->role},
                {XQC_MOQ_PARAM_PATH, sizeof("path"), (uint8_t*)"path"},
        };
        if (extdata && strlen(extdata) > 0) {
            params[params_num].type = XQC_MOQ_PARAM_EXTDATA;
            params[params_num].length = strlen(extdata) + 1;
            params[params_num].value = (uint8_t *)extdata;
            params_num++;
        }
        client_setup.versions_num = sizeof(versions) / sizeof(versions[0]);
        client_setup.versions = versions;
        client_setup.params_num = params_num;
        client_setup.params = params;

        ret = xqc_moq_write_client_setup(session, &client_setup);
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

    if (session->user_session
        && session->user_session->session == session)
    {
        session->user_session->session = NULL;
    }
    session->closing = XQC_TRUE;

    xqc_log(session->log, XQC_LOG_INFO, "|session destroy begin|");

    /*
     * Stream destruction removes media streams from their owning track's
     * write_stream_list, so WT wrappers must be swept before tracks.
     */
    if (session->transport_type == XQC_MOQ_TRANSPORT_WEBTRANSPORT) {
        xqc_moq_wt_cleanup_stream_list(session);
    }

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
xqc_moq_session_error(xqc_moq_session_t *session,
    xqc_moq_err_code_t code, const char *msg)
{
    session->closing = XQC_TRUE;

    if (session->transport_type == XQC_MOQ_TRANSPORT_WEBTRANSPORT) {
        /* WT: close session only, keep the H3 connection alive */
        xqc_wt_session_t *wt_session =
            (xqc_wt_session_t *)session->trans_conn;
        xqc_wt_session_close_with_error(wt_session, (uint32_t)code,
            msg, msg ? strlen(msg) : 0);

    } else {
        /* raw QUIC: close the entire connection */
        xqc_connection_t *quic_conn = xqc_moq_session_quic_conn(session);
        XQC_CONN_CLOSE_MSG(quic_conn, msg);
        XQC_CONN_ERR(quic_conn, code);
    }
}

void
xqc_moq_session_app_error(xqc_moq_session_t *session, uint64_t code)
{
    session->closing = XQC_TRUE;

    if (session->transport_type == XQC_MOQ_TRANSPORT_WEBTRANSPORT) {
        xqc_wt_session_t *wt_session =
            (xqc_wt_session_t *)session->trans_conn;
        xqc_wt_session_close_with_error(wt_session, (uint32_t)code,
            "app error", sizeof("app error") - 1);

    } else {
        xqc_connection_t *quic_conn = xqc_moq_session_quic_conn(session);
        XQC_CONN_CLOSE_MSG(quic_conn, "app error");
        XQC_CONN_ERR(quic_conn, code);
    }
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
