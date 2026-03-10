#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/congestion_control/xqc_bbr.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_transport/xqc_moq_stream_quic.h"
#include "moq/moq_transport/xqc_moq_stream_webtransport.h"
#include "moq/moq_transport/xqc_moq_subscribe.h"
#include "moq/moq_transport/xqc_moq_fb_report_gen.h"
#include "moq/moq_transport/xqc_moq_feedback_track.h"

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

static xqc_moq_session_t *
xqc_moq_session_create_internal(void *conn, xqc_moq_user_session_t *user_session,
    xqc_moq_transport_type_t transport_type, xqc_moq_role_t role,
    xqc_moq_session_callbacks_t callbacks, char *extdata,
    xqc_int_t enable_client_setup_v14,
    xqc_moq_message_parameter_t *setup_params, uint64_t setup_params_num)
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

    /* draft-moq-delivery-feedback-00: default to advertising all bits for experimentation. */
    session->delivery_feedback_local_bitmap = 0x07;
    session->delivery_feedback_peer_bitmap = 0x00;
    session->delivery_feedback_output = 0;
    session->delivery_feedback_metrics = 0;
    session->delivery_feedback_input = 0;
    session->setup_complete_ts = 0;
    session->playout_ahead_ms = 0;

    session->auto_cc_feedback = 1;
    session->has_custom_decision_config = 0;
    session->had_cc_reduction = 0;
    session->net_stats_timer_id = -1;
    session->net_stats_timer_active = 0;
    xqc_moq_fb_decision_config_default(&session->feedback_decision_config);

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

    xqc_crosslayer_init(&session->crosslayer_ctl, quic_conn, NULL);
    session->crosslayer_initialized = 1;

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

        /* If upper layer provided explicit setup params, use them as-is. */
        if (setup_params && setup_params_num > 0) {
            if (session->use_client_setup_v14) {
                xqc_moq_client_setup_v14_msg_t client_setup_v14;
                uint64_t versions_v14[] = {XQC_MOQ_VERSION_14};
                client_setup_v14.versions_num = sizeof(versions_v14) / sizeof(versions_v14[0]);
                client_setup_v14.versions = versions_v14;
                xqc_log(session->log, XQC_LOG_INFO, "|send_client_setup_v14(custom)|params_num:%ui|",
                        setup_params_num);
                ret = xqc_moq_write_client_setup_v14(session, &client_setup_v14,
                                                     setup_params, setup_params_num);
            } else {
                xqc_moq_client_setup_msg_t client_setup;
                uint64_t versions[] = {XQC_MOQ_VERSION_5};
                client_setup.versions_num = sizeof(versions) / sizeof(versions[0]);
                client_setup.versions = versions;
                client_setup.params_num = setup_params_num;
                client_setup.params = setup_params;
                xqc_log(session->log, XQC_LOG_INFO, "|send_client_setup(custom)|params_num:%ui|",
                        setup_params_num);
                ret = xqc_moq_write_client_setup(session, &client_setup);
            }
        } else {
            /* Default setup params: ROLE + PATH (+ optional EXTDATA for v5). */
            xqc_int_t params_num = 3;
            xqc_moq_message_parameter_t params[4] = {
                    {XQC_MOQ_PARAM_ROLE, 1, (uint8_t * ) & session->role, 1, (uint64_t)session->role},
                    {XQC_MOQ_PARAM_PATH, sizeof("path"), (uint8_t*)"path", 0, 0},
                    {XQC_MOQ_PARAM_DELIVERY_FEEDBACK, 0, NULL,
                     1, (uint64_t)session->delivery_feedback_local_bitmap},
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
                xqc_log(session->log, XQC_LOG_INFO, "|send_client_setup_v14|params_num:%d|", params_num);
                ret = xqc_moq_write_client_setup_v14(session, &client_setup_v14,
                                                     params, params_num);
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

xqc_moq_session_t *
xqc_moq_session_create(void *conn, xqc_moq_user_session_t *user_session,
    xqc_moq_transport_type_t transport_type, xqc_moq_role_t role,
    xqc_moq_session_callbacks_t callbacks, char *extdata,
    xqc_int_t enable_client_setup_v14)
{
    return xqc_moq_session_create_internal(conn, user_session, transport_type,
                                           role, callbacks, extdata,
                                           enable_client_setup_v14,
                                           NULL, 0);
}

xqc_moq_session_t *
xqc_moq_session_create_with_params(void *conn, xqc_moq_user_session_t *user_session,
    xqc_moq_transport_type_t transport_type, xqc_moq_role_t role,
    xqc_moq_session_callbacks_t callbacks, char *extdata,
    xqc_int_t enable_client_setup_v14,
    xqc_moq_message_parameter_t *setup_params, uint64_t setup_params_num)
{
    return xqc_moq_session_create_internal(conn, user_session, transport_type,
                                           role, callbacks, extdata,
                                           enable_client_setup_v14,
                                           setup_params, setup_params_num);
}

void
xqc_moq_session_destroy(xqc_moq_session_t *session)
{
    xqc_list_head_t *pos, *next;
    xqc_moq_subscribe_t *subscribe;
    xqc_moq_track_t *track;

    xqc_log(session->log, XQC_LOG_INFO, "|session destroy begin|");

    xqc_moq_feedback_stop_net_stats_timer(session);

    if (session->fb_report_gen) {
        xqc_moq_fb_report_gen_destroy(session->fb_report_gen);
        session->fb_report_gen = NULL;
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
xqc_moq_session_report_playout_status(xqc_moq_session_t *session, uint64_t playout_ahead_ms)
{
    if (session == NULL) {
        return;
    }
    session->playout_ahead_ms = playout_ahead_ms;
}

uint64_t
xqc_moq_session_get_cc_dispatch_count(xqc_moq_session_t *session)
{
    if (session == NULL) {
        return 0;
    }
    return session->crosslayer_ctl.dispatch_count;
}

float
xqc_moq_session_get_last_dispatched_gain(xqc_moq_session_t *session)
{
    if (session == NULL) {
        return 0.0f;
    }
    return session->crosslayer_ctl.last_dispatched_gain;
}

uint64_t
xqc_moq_session_get_last_dispatched_rate(xqc_moq_session_t *session)
{
    if (session == NULL) {
        return 0;
    }
    return session->crosslayer_ctl.last_dispatched_rate;
}

uint64_t
xqc_moq_session_get_pacing_rate(xqc_moq_session_t *session)
{
    if (session == NULL || session->quic_conn == NULL) {
        return 0;
    }
    xqc_send_ctl_t *send_ctl = session->quic_conn->conn_initial_path->path_send_ctl;
    if (send_ctl == NULL) {
        return 0;
    }
    return xqc_send_ctl_get_pacing_rate(send_ctl);
}

uint8_t
xqc_moq_session_get_cc_override_active(xqc_moq_session_t *session)
{
    if (session == NULL || session->quic_conn == NULL) {
        return 0;
    }
    xqc_send_ctl_t *send_ctl = session->quic_conn->conn_initial_path->path_send_ctl;
    if (send_ctl == NULL || send_ctl->ctl_cong_callback != &xqc_bbr_cb) {
        return 0;
    }
    xqc_bbr_t *bbr = (xqc_bbr_t *)send_ctl->ctl_cong;
    return bbr->moq_override_active;
}

uint64_t
xqc_moq_session_get_feedback_reports_sent(xqc_moq_session_t *session)
{
    if (session == NULL || session->fb_report_gen == NULL) {
        return 0;
    }
    return session->fb_report_gen->report_sequence;
}

void
xqc_moq_session_set_crosslayer_bounds(xqc_moq_session_t *session,
    xqc_usec_t min_interval_us, float min_gain, float max_gain, uint64_t min_rate)
{
    if (session == NULL || !session->crosslayer_initialized) {
        return;
    }
    xqc_crosslayer_ctl_t *ctl = &session->crosslayer_ctl;
    if (min_interval_us > 0) {
        ctl->min_update_interval_us = min_interval_us;
    }
    if (min_gain > 0.0f) {
        ctl->min_pacing_gain = min_gain;
    }
    if (max_gain > 0.0f) {
        ctl->max_pacing_gain = max_gain;
    }
    ctl->min_pacing_rate = min_rate;
}

void
xqc_moq_session_set_auto_cc_feedback(xqc_moq_session_t *session, xqc_int_t enable)
{
    if (session == NULL) {
        return;
    }
    session->auto_cc_feedback = enable ? 1 : 0;
}

void
xqc_moq_session_set_feedback_decision_config(xqc_moq_session_t *session,
    const xqc_moq_fb_decision_config_t *config)
{
    if (session == NULL) {
        return;
    }
    if (config == NULL) {
        xqc_moq_fb_decision_config_default(&session->feedback_decision_config);
        session->has_custom_decision_config = 0;
    } else {
        session->feedback_decision_config = *config;
        session->has_custom_decision_config = 1;
    }
}

xqc_int_t
xqc_moq_session_get_auto_cc_feedback(xqc_moq_session_t *session)
{
    if (session == NULL) {
        return 0;
    }
    return session->auto_cc_feedback;
}

void
xqc_moq_session_get_feedback_decision_config(xqc_moq_session_t *session,
    xqc_moq_fb_decision_config_t *out_config)
{
    if (session == NULL || out_config == NULL) {
        return;
    }
    *out_config = session->feedback_decision_config;
}

xqc_int_t
xqc_moq_session_try_publish_delivery_feedback_track(xqc_moq_session_t *session, xqc_moq_track_t *media_track)
{
    if (session == NULL || media_track == NULL) {
        return -XQC_EPARAM;
    }
    if (!session->delivery_feedback_output) {
        return XQC_OK;
    }
    if (media_track->track_info.track_namespace == NULL) {
        return XQC_OK;
    }

    const char *fb_name = "delivery-feedback";
    xqc_moq_track_t *existing = xqc_moq_find_track_by_name(session,
        media_track->track_info.track_namespace, fb_name, XQC_MOQ_TRACK_FOR_PUB);
    if (existing) {
        return XQC_OK;
    }

    xqc_moq_track_t *fb_track = xqc_moq_track_create(session,
        media_track->track_info.track_namespace, (char *)fb_name,
        XQC_MOQ_TRACK_DELIVERY_FEEDBACK, NULL, XQC_MOQ_CONTAINER_NONE, XQC_MOQ_TRACK_FOR_PUB);
    if (fb_track == NULL) {
        return -XQC_ENULLPTR;
    }

    xqc_moq_publish_msg_t publish_msg;
    xqc_memzero(&publish_msg, sizeof(publish_msg));
    publish_msg.track_namespace = fb_track->track_info.track_namespace;
    publish_msg.track_namespace_len = strlen(publish_msg.track_namespace);
    publish_msg.track_namespace_num = 1;
    publish_msg.track_name = fb_track->track_info.track_name;
    publish_msg.track_name_len = strlen(publish_msg.track_name);
    publish_msg.group_order = 1;
    publish_msg.content_exist = 0;
    publish_msg.largest_group_id = 0;
    publish_msg.largest_object_id = 0;
    publish_msg.forward = 1;
    publish_msg.params_num = 0;
    publish_msg.params = NULL;

    xqc_int_t ret = xqc_moq_publish(session, &publish_msg);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|publish delivery-feedback failed|ret:%d|", ret);
        xqc_list_del(&fb_track->list_member);
        xqc_moq_track_destroy(fb_track);
        return ret;
    }
    return XQC_OK;
}

void
xqc_moq_session_on_setup(xqc_moq_session_t *session, char *extdata,
    const xqc_moq_message_parameter_t *params, uint64_t params_num)
{
    xqc_log(session->log, XQC_LOG_INFO, "|on_session_setup|");
    xqc_moq_feedback_start_net_stats_timer(session);
    session->session_callbacks.on_session_setup(session->user_session, extdata, params, params_num);
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

void
xqc_moq_session_close(xqc_moq_session_t *session, uint64_t code, const char *reason)
{
    if (session == NULL) {
        return;
    }
    xqc_connection_t *quic_conn = xqc_moq_session_quic_conn(session);
    XQC_CONN_CLOSE_MSG(quic_conn, reason ? reason : "");
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

xqc_moq_track_t *
xqc_moq_find_track_by_subscribe_id(xqc_moq_session_t *session,
    uint64_t subscribe_id, xqc_moq_track_role_t role)
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
