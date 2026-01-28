#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_send_ctl.h"
#include "moq/moq_transport/xqc_moq_namespace.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_transport/xqc_moq_stream_quic.h"
#include "moq/moq_transport/xqc_moq_stream_webtransport.h"
#include "moq/moq_transport/xqc_moq_subscribe.h"

static xqc_moq_namespace_prefix_t *
xqc_moq_session_find_namespace_prefix(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *namespace_prefix_tuple, uint64_t namespace_prefix_num)
{
    if (session == NULL || namespace_prefix_tuple == NULL || namespace_prefix_num == 0) {
        return NULL;
    }

    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &session->peer_subscribe_namespace_list) {
        xqc_moq_namespace_prefix_t *namespace_prefix =
            xqc_list_entry(pos, xqc_moq_namespace_prefix_t, list_member);
        if (namespace_prefix->prefix_num != namespace_prefix_num) {
            continue;
        }
        if (xqc_moq_namespace_tuple_equal(namespace_prefix_tuple, namespace_prefix_num,
                                          namespace_prefix->prefix_tuple, namespace_prefix->prefix_num))
        {
            return namespace_prefix;
        }
    }
    return NULL;
}

static xqc_moq_namespace_prefix_t *
xqc_moq_session_find_matching_namespace_prefix(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *track_namespace_tuple, uint64_t track_namespace_num)
{
    if (session == NULL || track_namespace_tuple == NULL || track_namespace_num == 0) {
        return NULL;
    }

    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &session->peer_subscribe_namespace_list) {
        xqc_moq_namespace_prefix_t *namespace_prefix =
            xqc_list_entry(pos, xqc_moq_namespace_prefix_t, list_member);
        if (xqc_moq_namespace_tuple_is_prefix(namespace_prefix->prefix_tuple, namespace_prefix->prefix_num,
                                              track_namespace_tuple, track_namespace_num))
        {
            return namespace_prefix;
        }
    }
    return NULL;
}

static xqc_moq_namespace_advertisement_t *
xqc_moq_namespace_prefix_find_advertisement(xqc_moq_namespace_prefix_t *namespace_subscription,
    const xqc_moq_track_ns_field_t *track_namespace_tuple, uint64_t track_namespace_num)
{
    if (namespace_subscription == NULL || track_namespace_tuple == NULL || track_namespace_num == 0) {
        return NULL;
    }

    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &namespace_subscription->advertised_namespace_list) {
        xqc_moq_namespace_advertisement_t *namespace_advertisement =
            xqc_list_entry(pos, xqc_moq_namespace_advertisement_t, list_member);
        if (namespace_advertisement->track_namespace_num != track_namespace_num) {
            continue;
        }
        if (xqc_moq_namespace_tuple_equal(namespace_advertisement->track_namespace_tuple,
                                          namespace_advertisement->track_namespace_num,
                                          track_namespace_tuple, track_namespace_num))
        {
            return namespace_advertisement;
        }
    }
    return NULL;
}

static xqc_moq_advertised_track_t *
xqc_moq_namespace_advertisement_find_track(xqc_moq_namespace_advertisement_t *namespace_advertisement,
    const xqc_moq_track_t *track)
{
    if (namespace_advertisement == NULL || track == NULL) {
        return NULL;
    }

    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &namespace_advertisement->advertised_track_list) {
        xqc_moq_advertised_track_t *advertised_track =
            xqc_list_entry(pos, xqc_moq_advertised_track_t, list_member);
        if (advertised_track->track == track) {
            return advertised_track;
        }
    }
    return NULL;
}

static xqc_int_t
xqc_moq_namespace_prefix_ensure_advertised(xqc_moq_session_t *session,
    xqc_moq_namespace_prefix_t *namespace_subscription,
    const xqc_moq_track_ns_field_t *track_namespace_tuple, uint64_t track_namespace_num,
    const xqc_moq_namespace_discovery_update_cb_t *discovery_update_callbacks,
    xqc_moq_namespace_advertisement_t **namespace_advertisement)
{
    if (session == NULL || namespace_subscription == NULL
        || track_namespace_tuple == NULL || track_namespace_num == 0
        || discovery_update_callbacks == NULL || discovery_update_callbacks->on_namespace == NULL
        || namespace_advertisement == NULL)
    {
        return -XQC_EPARAM;
    }

    xqc_moq_namespace_advertisement_t *namespace_advertisement_entry =
        xqc_moq_namespace_prefix_find_advertisement(namespace_subscription,
                                                    track_namespace_tuple, track_namespace_num);
    if (namespace_advertisement_entry != NULL) {
        *namespace_advertisement = namespace_advertisement_entry;
        return XQC_OK;
    }

    xqc_int_t ret = discovery_update_callbacks->on_namespace(session, discovery_update_callbacks->user_data,
                                                            track_namespace_tuple, track_namespace_num);
    if (ret < 0) {
        return ret;
    }

    namespace_advertisement_entry =
        xqc_moq_namespace_advertisement_create_copy(track_namespace_tuple, track_namespace_num);
    if (namespace_advertisement_entry == NULL) {
        return -XQC_EMALLOC;
    }
    xqc_list_add_tail(&namespace_advertisement_entry->list_member,
                      &namespace_subscription->advertised_namespace_list);
    *namespace_advertisement = namespace_advertisement_entry;
    return XQC_OK;
}

static xqc_int_t
xqc_moq_session_discovery_subscription_on_track_added(xqc_moq_session_t *session,
    xqc_moq_namespace_prefix_t *subscription, xqc_moq_track_t *track,
    const xqc_moq_namespace_discovery_update_cb_t *discovery_update_callbacks)
{
    if (session == NULL || subscription == NULL || track == NULL || discovery_update_callbacks == NULL) {
        return -XQC_EPARAM;
    }

    xqc_moq_track_info_t *track_info = &track->track_info;
    if (track_info->track_namespace_tuple == NULL || track_info->track_namespace_num == 0
        || track_info->track_name == NULL)
    {
        return -XQC_EPARAM;
    }

    xqc_moq_namespace_advertisement_t *namespace_advertisement = NULL;
    xqc_int_t ret = xqc_moq_namespace_prefix_ensure_advertised(session, subscription,
        track_info->track_namespace_tuple, track_info->track_namespace_num,
        discovery_update_callbacks, &namespace_advertisement);
    if (ret < 0) {
        return ret;
    }

    if (xqc_moq_namespace_advertisement_find_track(namespace_advertisement, track) != NULL) {
        /* Idempotency: this track has already been counted for this namespace. */
        return XQC_OK;
    }

    xqc_moq_advertised_track_t *advertised_track = xqc_calloc(1, sizeof(*advertised_track));
    if (advertised_track == NULL) {
        return -XQC_EMALLOC;
    }
    xqc_init_list_head(&advertised_track->list_member);
    advertised_track->track = track;
    xqc_list_add_tail(&advertised_track->list_member, &namespace_advertisement->advertised_track_list);
    namespace_advertisement->track_refcnt++;

    if (discovery_update_callbacks->on_track != NULL && track->subscribe_id == XQC_MOQ_INVALID_ID) {
        ret = discovery_update_callbacks->on_track(session, discovery_update_callbacks->user_data, track);
        if (ret < 0) {
            return ret;
        }
    }

    return XQC_OK;
}

static xqc_int_t
xqc_moq_session_discovery_subscription_on_track_removed(xqc_moq_session_t *session,
    xqc_moq_namespace_prefix_t *subscription, xqc_moq_track_t *track,
    const xqc_moq_namespace_discovery_update_cb_t *discovery_update_callbacks)
{
    if (session == NULL || subscription == NULL || track == NULL || discovery_update_callbacks == NULL) {
        return -XQC_EPARAM;
    }

    xqc_moq_track_info_t *track_info = &track->track_info;
    if (track_info->track_namespace_tuple == NULL || track_info->track_namespace_num == 0) {
        return -XQC_EPARAM;
    }

    xqc_moq_namespace_advertisement_t *namespace_advertisement =
        xqc_moq_namespace_prefix_find_advertisement(subscription,
            track_info->track_namespace_tuple, track_info->track_namespace_num);
    if (namespace_advertisement == NULL) {
        return XQC_OK;
    }

    xqc_moq_advertised_track_t *advertised_track =
        xqc_moq_namespace_advertisement_find_track(namespace_advertisement, track);
    if (advertised_track == NULL) {
        /* Idempotency: track was never counted (or already removed). */
        return XQC_OK;
    }
    xqc_list_del(&advertised_track->list_member);
    xqc_free(advertised_track);

    if (namespace_advertisement->track_refcnt > 0) {
        namespace_advertisement->track_refcnt--;
    } else {
        namespace_advertisement->track_refcnt = 0;
    }

    if (namespace_advertisement->track_refcnt == 0) {
        if (discovery_update_callbacks->on_namespace_done != NULL) {
            xqc_int_t ret = discovery_update_callbacks->on_namespace_done(session,
                discovery_update_callbacks->user_data,
                namespace_advertisement->track_namespace_tuple, namespace_advertisement->track_namespace_num);
            if (ret < 0) {
                return ret;
            }
        }
        xqc_list_del(&namespace_advertisement->list_member);
        xqc_moq_namespace_advertisement_destroy(namespace_advertisement);
    }

    return XQC_OK;
}

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
    xqc_init_list_head(&session->peer_subscribe_namespace_list);
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
    xqc_list_head_t *npos, *nnext;

    session->is_destroying = 1;
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

    xqc_list_for_each_safe(npos, nnext, &session->peer_subscribe_namespace_list) {
        xqc_moq_namespace_prefix_t *namespace_prefix_subscription =
            xqc_list_entry(npos, xqc_moq_namespace_prefix_t, list_member);
        xqc_list_del(npos);
        xqc_moq_namespace_prefix_destroy(namespace_prefix_subscription);
    }
    xqc_free(session);
}

xqc_int_t
xqc_moq_session_namespace_prefix_overlaps(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *namespace_prefix_tuple, uint64_t namespace_prefix_num)
{
    if (session == NULL || namespace_prefix_tuple == NULL || namespace_prefix_num == 0) {
        return 0;
    }

    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &session->peer_subscribe_namespace_list) {
        xqc_moq_namespace_prefix_t *namespace_prefix_subscription =
            xqc_list_entry(pos, xqc_moq_namespace_prefix_t, list_member);
        if (xqc_moq_namespace_tuple_overlaps(namespace_prefix_tuple, namespace_prefix_num,
                                             namespace_prefix_subscription->prefix_tuple,
                                             namespace_prefix_subscription->prefix_num))
        {
            return 1;
        }
    }
    return 0;
}

xqc_int_t
xqc_moq_session_add_namespace_prefix(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *namespace_prefix_tuple, uint64_t namespace_prefix_num)
{
    if (session == NULL || namespace_prefix_tuple == NULL || namespace_prefix_num == 0) {
        return -XQC_EPARAM;
    }

    if (xqc_moq_session_namespace_prefix_overlaps(session, namespace_prefix_tuple, namespace_prefix_num)) {
        return -XQC_EPARAM;
    }

    xqc_moq_namespace_prefix_t *namespace_prefix_subscription =
        xqc_moq_namespace_prefix_create_copy(namespace_prefix_tuple, namespace_prefix_num);
    if (namespace_prefix_subscription == NULL) {
        return -XQC_EMALLOC;
    }
    xqc_list_add_tail(&namespace_prefix_subscription->list_member, &session->peer_subscribe_namespace_list);
    return XQC_OK;
}

xqc_int_t
xqc_moq_session_remove_namespace_prefix(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *namespace_prefix_tuple, uint64_t namespace_prefix_num)
{
    if (session == NULL || namespace_prefix_tuple == NULL || namespace_prefix_num == 0) {
        return -XQC_EPARAM;
    }

    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &session->peer_subscribe_namespace_list) {
        xqc_moq_namespace_prefix_t *namespace_prefix_subscription =
            xqc_list_entry(pos, xqc_moq_namespace_prefix_t, list_member);
        if (namespace_prefix_subscription->prefix_num != namespace_prefix_num) {
            continue;
        }
        if (!xqc_moq_namespace_tuple_equal(namespace_prefix_tuple, namespace_prefix_num,
                                           namespace_prefix_subscription->prefix_tuple,
                                           namespace_prefix_subscription->prefix_num))
        {
            continue;
        }

        xqc_list_del(pos);
        xqc_moq_namespace_prefix_destroy(namespace_prefix_subscription);
        return 1;
    }

    return 0;
}

static xqc_int_t
xqc_moq_discovery_send_publish_namespace(xqc_moq_session_t *session, void *user_data,
    const xqc_moq_track_ns_field_t *track_namespace_tuple, uint64_t track_namespace_num)
{
    if (session == NULL || track_namespace_tuple == NULL || track_namespace_num == 0) {
        return -XQC_EPARAM;
    }

    xqc_moq_publish_namespace_msg_t publish_namespace_msg;
    memset(&publish_namespace_msg, 0, sizeof(publish_namespace_msg));
    publish_namespace_msg.request_id = xqc_moq_session_alloc_subscribe_id(session);
    publish_namespace_msg.track_namespace_num = track_namespace_num;
    publish_namespace_msg.track_namespace_tuple = (xqc_moq_track_ns_field_t *)track_namespace_tuple;
    publish_namespace_msg.track_namespace_len = 0;
    publish_namespace_msg.params_num = 0;
    publish_namespace_msg.params = NULL;
    return xqc_moq_write_publish_namespace(session, &publish_namespace_msg);
}

static xqc_int_t
xqc_moq_discovery_send_publish_namespace_done(xqc_moq_session_t *session, void *user_data,
    const xqc_moq_track_ns_field_t *track_namespace_tuple, uint64_t track_namespace_num)
{

    if (session == NULL || track_namespace_tuple == NULL || track_namespace_num == 0) {
        return -XQC_EPARAM;
    }

    xqc_moq_publish_namespace_done_msg_t done;
    memset(&done, 0, sizeof(done));
    done.track_namespace_num = track_namespace_num;
    done.track_namespace_tuple = (xqc_moq_track_ns_field_t *)track_namespace_tuple;
    done.track_namespace_len = 0;
    return xqc_moq_write_publish_namespace_done(session, &done);
}

static xqc_int_t
xqc_moq_discovery_send_publish_track(xqc_moq_session_t *session, void *user_data, xqc_moq_track_t *track)
{

    if (session == NULL || track == NULL || track->track_info.track_name == NULL
        || track->track_info.track_namespace_tuple == NULL || track->track_info.track_namespace_num == 0)
    {
        return -XQC_EPARAM;
    }

    xqc_moq_publish_msg_t publish_msg;
    memset(&publish_msg, 0, sizeof(publish_msg));
    publish_msg.track_namespace_num = track->track_info.track_namespace_num;
    publish_msg.track_namespace_tuple = track->track_info.track_namespace_tuple;
    publish_msg.track_namespace_len = 0;
    publish_msg.track_name = track->track_info.track_name;
    publish_msg.track_name_len = 0;
    publish_msg.group_order = 0;
    publish_msg.content_exist = 0;
    publish_msg.largest_group_id = 0;
    publish_msg.largest_object_id = 0;
    publish_msg.forward = 1;
    publish_msg.params_num = 0;
    publish_msg.params = NULL;

    xqc_int_t ret = xqc_moq_publish(session, &publish_msg);
    return ret < 0 ? ret : XQC_OK;
}

xqc_int_t
xqc_moq_session_discovery_refresh_namespace_prefix(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *prefix_tuple, uint64_t prefix_num,
    const xqc_moq_namespace_discovery_update_cb_t *discovery_update_callbacks)
{
    if (session == NULL || prefix_tuple == NULL || prefix_num == 0 || discovery_update_callbacks == NULL) {
        return -XQC_EPARAM;
    }

    xqc_moq_namespace_prefix_t *subscription =
        xqc_moq_session_find_namespace_prefix(session, prefix_tuple, prefix_num);
    if (subscription == NULL) {
        return -XQC_ENULLPTR;
    }

    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &session->track_list_for_pub) {
        xqc_moq_track_t *track = xqc_list_entry(pos, xqc_moq_track_t, list_member);
        xqc_moq_track_info_t *track_info = track ? &track->track_info : NULL;
        if (track_info == NULL || track_info->track_name == NULL
            || track_info->track_namespace_tuple == NULL || track_info->track_namespace_num == 0)
        {
            continue;
        }

        if (!xqc_moq_namespace_tuple_is_prefix(prefix_tuple, prefix_num,
                                               track_info->track_namespace_tuple,
                                               track_info->track_namespace_num))
        {
            continue;
        }

        xqc_int_t ret = xqc_moq_session_discovery_subscription_on_track_added(session,
            subscription, track, discovery_update_callbacks);
        if (ret < 0) {
            return ret;
        }
    }

    return XQC_OK;
}

void
xqc_moq_session_discovery_on_track_added(xqc_moq_session_t *session, xqc_moq_track_t *track)
{
    if (session == NULL || track == NULL) {
        return;
    }
    if (track->track_role != XQC_MOQ_TRACK_FOR_PUB) {
        return;
    }
    if (xqc_list_empty(&session->peer_subscribe_namespace_list)) {
        return;
    }

    xqc_moq_track_info_t *track_info = &track->track_info;
    if (track_info->track_namespace_tuple == NULL || track_info->track_namespace_num == 0) {
        return;
    }

    xqc_moq_namespace_discovery_update_cb_t discovery_update_callbacks = {
        .user_data = NULL,
        .on_namespace = xqc_moq_discovery_send_publish_namespace,
        .on_namespace_done = xqc_moq_discovery_send_publish_namespace_done,
        .on_track = xqc_moq_discovery_send_publish_track,
    };

    xqc_int_t ret = xqc_moq_session_discovery_on_track_added_with_cb(session, track,
                                                                     &discovery_update_callbacks);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|discovery track added failed|ret:%d|", ret);
        xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "discovery track added");
    }
}

void
xqc_moq_session_discovery_on_track_removed(xqc_moq_session_t *session, xqc_moq_track_t *track)
{
    if (session == NULL || track == NULL) {
        return;
    }
    if (track->track_role != XQC_MOQ_TRACK_FOR_PUB) {
        return;
    }
    if (xqc_list_empty(&session->peer_subscribe_namespace_list)) {
        return;
    }

    xqc_moq_track_info_t *track_info = &track->track_info;
    if (track_info->track_namespace_tuple == NULL || track_info->track_namespace_num == 0) {
        return;
    }

    xqc_moq_namespace_discovery_update_cb_t discovery_update_callbacks = {
        .user_data = NULL,
        .on_namespace = xqc_moq_discovery_send_publish_namespace,
        .on_namespace_done = xqc_moq_discovery_send_publish_namespace_done,
        .on_track = xqc_moq_discovery_send_publish_track,
    };

    xqc_int_t ret = xqc_moq_session_discovery_on_track_removed_with_cb(session, track,
                                                                       &discovery_update_callbacks);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|discovery track removed failed|ret:%d|", ret);
        xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "discovery track removed");
    }
}

xqc_int_t
xqc_moq_session_discovery_on_track_added_with_cb(xqc_moq_session_t *session, xqc_moq_track_t *track,
    const xqc_moq_namespace_discovery_update_cb_t *discovery_update_callbacks)
{
    if (session == NULL || track == NULL || discovery_update_callbacks == NULL) {
        return -XQC_EPARAM;
    }
    if (track->track_role != XQC_MOQ_TRACK_FOR_PUB) {
        return XQC_OK;
    }
    if (xqc_list_empty(&session->peer_subscribe_namespace_list)) {
        return XQC_OK;
    }

    xqc_moq_track_info_t *track_info = &track->track_info;
    if (track_info->track_namespace_tuple == NULL || track_info->track_namespace_num == 0) {
        return -XQC_EPARAM;
    }

    xqc_moq_namespace_prefix_t *subscription =
        xqc_moq_session_find_matching_namespace_prefix(session,
            track_info->track_namespace_tuple, track_info->track_namespace_num);
    if (subscription == NULL) {
        return XQC_OK;
    }

    return xqc_moq_session_discovery_subscription_on_track_added(session, subscription, track,
                                                                 discovery_update_callbacks);
}

xqc_int_t
xqc_moq_session_discovery_on_track_removed_with_cb(xqc_moq_session_t *session, xqc_moq_track_t *track,
    const xqc_moq_namespace_discovery_update_cb_t *discovery_update_callbacks)
{
    if (session == NULL || track == NULL || discovery_update_callbacks == NULL) {
        return -XQC_EPARAM;
    }
    if (track->track_role != XQC_MOQ_TRACK_FOR_PUB) {
        return XQC_OK;
    }
    if (xqc_list_empty(&session->peer_subscribe_namespace_list)) {
        return XQC_OK;
    }

    xqc_moq_track_info_t *track_info = &track->track_info;
    if (track_info->track_namespace_tuple == NULL || track_info->track_namespace_num == 0) {
        return -XQC_EPARAM;
    }

    xqc_moq_namespace_prefix_t *subscription =
        xqc_moq_session_find_matching_namespace_prefix(session,
            track_info->track_namespace_tuple, track_info->track_namespace_num);
    if (subscription == NULL) {
        return XQC_OK;
    }

    return xqc_moq_session_discovery_subscription_on_track_removed(session, subscription, track,
                                                                   discovery_update_callbacks);
}

xqc_int_t
xqc_moq_session_foreach_matching_publication(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *namespace_prefix_tuple, uint64_t namespace_prefix_num,
    const xqc_moq_namespace_discovery_cb_t *discovery_callbacks)
{
    if (session == NULL || namespace_prefix_tuple == NULL || namespace_prefix_num == 0
        || discovery_callbacks == NULL)
    {
        return -XQC_EPARAM;
    }

    xqc_int_t ret = XQC_OK;
    xqc_list_head_t sent_track_namespace_list;
    xqc_init_list_head(&sent_track_namespace_list);

    xqc_list_head_t *pos, *next;
    xqc_list_head_t *cleanup_pos, *cleanup_next;
    xqc_list_for_each_safe(pos, next, &session->track_list_for_pub) {
        xqc_moq_track_t *track = xqc_list_entry(pos, xqc_moq_track_t, list_member);
        xqc_moq_track_info_t *track_info = track ? &track->track_info : NULL;
        if (track_info == NULL || track_info->track_name == NULL
            || track_info->track_namespace_tuple == NULL || track_info->track_namespace_num == 0)
        {
            continue;
        }

        if (!xqc_moq_namespace_tuple_is_prefix(namespace_prefix_tuple, namespace_prefix_num,
                                               track_info->track_namespace_tuple,
                                               track_info->track_namespace_num))
        {
            continue;
        }

        if (discovery_callbacks->on_namespace != NULL) {
            xqc_int_t track_namespace_already_sent = 0;
            xqc_list_head_t *sent_pos, *sent_next;
            xqc_list_for_each_safe(sent_pos, sent_next, &sent_track_namespace_list) {
                xqc_moq_namespace_prefix_t *sent_track_namespace =
                    xqc_list_entry(sent_pos, xqc_moq_namespace_prefix_t, list_member);
                if (xqc_moq_namespace_tuple_equal(sent_track_namespace->prefix_tuple,
                                                  sent_track_namespace->prefix_num,
                                                  track_info->track_namespace_tuple,
                                                  track_info->track_namespace_num))
                {
                    track_namespace_already_sent = 1;
                    break;
                }
            }

            if (!track_namespace_already_sent) {
                xqc_moq_namespace_prefix_t *sent_track_namespace =
                    xqc_moq_namespace_prefix_create_copy(track_info->track_namespace_tuple,
                                                         track_info->track_namespace_num);
                if (sent_track_namespace == NULL) {
                    ret = -XQC_EMALLOC;
                    goto cleanup;
                }
                xqc_list_add_tail(&sent_track_namespace->list_member, &sent_track_namespace_list);

                ret = discovery_callbacks->on_namespace(session, discovery_callbacks->user_data,
                                       track_info->track_namespace_tuple,
                                       track_info->track_namespace_num);
                if (ret < 0) {
                    goto cleanup;
                }
            }
        }

        if (discovery_callbacks->on_track != NULL && track->subscribe_id == XQC_MOQ_INVALID_ID) {
            ret = discovery_callbacks->on_track(session, discovery_callbacks->user_data, track);
            if (ret < 0) {
                goto cleanup;
            }
        }
    }

cleanup:
    xqc_list_for_each_safe(cleanup_pos, cleanup_next, &sent_track_namespace_list) {
        xqc_moq_namespace_prefix_t *sent_track_namespace =
            xqc_list_entry(cleanup_pos, xqc_moq_namespace_prefix_t, list_member);
        xqc_list_del(cleanup_pos);
        xqc_moq_namespace_prefix_destroy(sent_track_namespace);
    }

    return ret;
}

void
xqc_moq_session_on_setup(xqc_moq_session_t *session, char *extdata,
    const xqc_moq_message_parameter_t *params, uint64_t params_num)
{
    xqc_log(session->log, XQC_LOG_INFO, "|on_session_setup|");
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
xqc_moq_find_track_by_track_namespace_tuple(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *track_namespace_tuple, uint64_t track_namespace_num,
    const char *track_name, xqc_moq_track_role_t role)
{
    xqc_moq_track_t *track = NULL;
    xqc_list_head_t *pos, *next;
    xqc_list_head_t *list;

    if (session == NULL || track_namespace_tuple == NULL || track_namespace_num == 0 || track_name == NULL) {
        return NULL;
    }

    if (role == XQC_MOQ_TRACK_FOR_PUB) {
        list = &session->track_list_for_pub;
    } else {
        list = &session->track_list_for_sub;
    }

    xqc_list_for_each_safe(pos, next, list) {
        track = xqc_list_entry(pos, xqc_moq_track_t, list_member);
        if (track->track_info.track_name == NULL) {
            continue;
        }
        if (strcmp(track->track_info.track_name, track_name) != 0) {
            continue;
        }
        if (xqc_moq_namespace_tuple_equal(track->track_info.track_namespace_tuple,
                                          track->track_info.track_namespace_num,
                                          track_namespace_tuple, track_namespace_num))
        {
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
