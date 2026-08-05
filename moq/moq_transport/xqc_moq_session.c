#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_conn.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_transport/xqc_moq_stream_quic.h"
#include "moq/moq_transport/xqc_moq_subscribe.h"
#include "moq/moq_transport/xqc_moq_namespace.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_params.h"

static void
xqc_moq_free_draft18_setup_token_buffers(uint8_t **buffers, size_t count)
{
    if (buffers == NULL) {
        return;
    }
    for (size_t i = 0; i < count; i++) {
        xqc_free(buffers[i]);
    }
    xqc_free(buffers);
}

xqc_int_t
xqc_moq_session_encode_draft18_setup_config(
    const xqc_moq_draft18_setup_config_t *config,
    xqc_moq_d18_setup_sender_t sender,
    xqc_moq_d18_setup_transport_t transport,
    uint8_t **encoded, size_t *encoded_len)
{
    if (config == NULL || encoded == NULL || encoded_len == NULL
        || (config->authorization_token_count > 0
            && config->authorization_tokens == NULL))
    {
        return -XQC_EPARAM;
    }
    *encoded = NULL;
    *encoded_len = 0;

    size_t token_count = config->authorization_token_count;
    if (token_count > SIZE_MAX / sizeof(xqc_moq_d18_bytes_view_t)
        || token_count > SIZE_MAX / sizeof(uint8_t *))
    {
        return -XQC_EPARAM;
    }
    xqc_moq_d18_bytes_view_t *token_views = NULL;
    uint8_t **token_buffers = NULL;
    if (token_count > 0) {
        token_views = xqc_calloc(token_count, sizeof(*token_views));
        token_buffers = xqc_calloc(token_count, sizeof(*token_buffers));
        if (token_views == NULL || token_buffers == NULL) {
            xqc_free(token_views);
            xqc_free(token_buffers);
            return -XQC_EMALLOC;
        }
    }

    xqc_int_t ret = XQC_OK;
    for (size_t i = 0; i < token_count; i++) {
        const xqc_moq_draft18_auth_token_t *input =
            &config->authorization_tokens[i];
        if (input->alias_type != XQC_MOQ_DRAFT18_AUTH_REGISTER
            && input->alias_type != XQC_MOQ_DRAFT18_AUTH_USE_VALUE)
        {
            ret = -XQC_EPARAM;
            goto cleanup;
        }
        xqc_moq_d18_auth_token_t token = {
            .alias_type = input->alias_type,
            .token_alias = input->token_alias,
            .token_type = input->token_type,
            .token_value = input->token_value,
            .token_value_len = input->token_value_len,
            .has_alias =
                input->alias_type == XQC_MOQ_DRAFT18_AUTH_REGISTER,
            .has_token_type = 1,
        };
        size_t token_len = 0;
        xqc_moq_d18_auth_result_t auth_ret =
            xqc_moq_d18_auth_token_encoded_length(&token, &token_len);
        if (auth_ret != XQC_MOQ_D18_AUTH_OK) {
            ret = auth_ret == XQC_MOQ_D18_AUTH_NO_MEMORY
                ? -XQC_EMALLOC : -XQC_EPARAM;
            goto cleanup;
        }
        if (token_len > UINT16_MAX) {
            ret = -XQC_ELIMIT;
            goto cleanup;
        }
        token_buffers[i] = xqc_malloc(token_len);
        if (token_buffers[i] == NULL) {
            ret = -XQC_EMALLOC;
            goto cleanup;
        }
        size_t written = 0;
        auth_ret = xqc_moq_d18_auth_token_encode(
            &token, token_buffers[i], token_len, &written);
        if (auth_ret != XQC_MOQ_D18_AUTH_OK || written != token_len) {
            ret = -XQC_EPARAM;
            goto cleanup;
        }
        token_views[i] = (xqc_moq_d18_bytes_view_t){
            token_buffers[i], token_len, 1,
        };
    }

    xqc_moq_d18_setup_options_t options;
    xqc_moq_d18_setup_options_init(&options);
    if (sender == XQC_MOQ_D18_SETUP_SENDER_CLIENT
        && transport == XQC_MOQ_D18_SETUP_TRANSPORT_NATIVE_QUIC)
    {
        if (config->authority == NULL) {
            ret = -XQC_EPARAM;
            goto cleanup;
        }
        const char *path = config->path == NULL ? "" : config->path;
        options.path = (xqc_moq_d18_bytes_view_t){
            (const uint8_t *)path, strlen(path), 1,
        };
        options.authority = (xqc_moq_d18_bytes_view_t){
            (const uint8_t *)config->authority,
            strlen(config->authority), 1,
        };

    } else if (config->path != NULL || config->authority != NULL) {
        ret = -XQC_EPARAM;
        goto cleanup;
    }
    if (config->implementation != NULL) {
        options.implementation = (xqc_moq_d18_bytes_view_t){
            (const uint8_t *)config->implementation,
            strlen(config->implementation), 1,
        };
    }
    options.authorization_tokens = token_views;
    options.authorization_token_count = token_count;
    options.authorization_token_capacity = token_count;
    options.has_max_auth_token_cache_size =
        config->has_max_auth_token_cache_size;
    options.max_auth_token_cache_size =
        config->max_auth_token_cache_size;

    xqc_moq_d18_setup_result_t setup_ret =
        xqc_moq_d18_setup_options_validate(&options, sender, transport);
    if (setup_ret != XQC_MOQ_D18_SETUP_OK) {
        ret = -XQC_EPARAM;
        goto cleanup;
    }
    setup_ret = xqc_moq_d18_setup_options_encoded_length(
        &options, encoded_len);
    if (setup_ret != XQC_MOQ_D18_SETUP_OK) {
        ret = setup_ret == XQC_MOQ_D18_SETUP_NO_MEMORY
            ? -XQC_EMALLOC : -XQC_ELIMIT;
        goto cleanup;
    }
    if (*encoded_len > 0) {
        *encoded = xqc_malloc(*encoded_len);
        if (*encoded == NULL) {
            ret = -XQC_EMALLOC;
            goto cleanup;
        }
        size_t written = 0;
        setup_ret = xqc_moq_d18_setup_options_encode(
            &options, *encoded, *encoded_len, &written);
        if (setup_ret != XQC_MOQ_D18_SETUP_OK
            || written != *encoded_len)
        {
            xqc_free(*encoded);
            *encoded = NULL;
            *encoded_len = 0;
            ret = -XQC_EILLEGAL_FRAME;
            goto cleanup;
        }
    }

cleanup:
    xqc_free(token_views);
    xqc_moq_free_draft18_setup_token_buffers(token_buffers, token_count);
    if (ret != XQC_OK) {
        xqc_free(*encoded);
        *encoded = NULL;
        *encoded_len = 0;
    }
    return ret;
}

void
xqc_moq_init_alpn(xqc_engine_t *engine, xqc_conn_callbacks_t *conn_cbs, xqc_moq_transport_type_t transport_type)
{
    size_t i;
    xqc_int_t ret;
    xqc_stream_callbacks_t callbacks;

    if (transport_type == XQC_MOQ_TRANSPORT_QUIC) {
        callbacks = xqc_moq_quic_stream_callbacks;
        xqc_app_proto_callbacks_t ap_cbs = {
            .conn_cbs   = *conn_cbs,
            .stream_cbs = callbacks,
            .dgram_cbs  = xqc_moq_quic_datagram_callbacks,
        };

        for (i = 0; i < xqc_moq_version_policy_count(); ++i) {
            const xqc_moq_alpn_policy_t *policy =
                xqc_moq_version_policy_at(i);
            ret = xqc_engine_register_alpn(engine, policy->alpn,
                                           policy->alpn_len, &ap_cbs, NULL);
            if (ret != XQC_OK) {
                xqc_log(engine->log, XQC_LOG_ERROR,
                        "|register moq alpn error|alpn:%*s|ret:%d|",
                        policy->alpn_len, policy->alpn, ret);
                return;
            }
        }
    }
}

void
xqc_moq_init_alpn_draft18(xqc_engine_t *engine,
    xqc_conn_callbacks_t *conn_cbs, xqc_moq_transport_type_t transport_type)
{
    if (transport_type != XQC_MOQ_TRANSPORT_QUIC) {
        return;
    }
    const xqc_moq_alpn_policy_t *policy = xqc_moq_version_policy_for_alpn(
        XQC_ALPN_MOQ_DRAFT_18, sizeof(XQC_ALPN_MOQ_DRAFT_18) - 1);
    if (policy == NULL) {
        return;
    }
    xqc_app_proto_callbacks_t ap_cbs = {
        .conn_cbs   = *conn_cbs,
        .stream_cbs = xqc_moq_quic_stream_callbacks,
        .dgram_cbs  = xqc_moq_quic_datagram_callbacks,
    };
    (void)xqc_engine_register_alpn(engine, policy->alpn,
        policy->alpn_len, &ap_cbs, NULL);
}

static xqc_int_t
xqc_moq_write_initial_setup(xqc_moq_session_t *session,
    uint8_t *options, size_t options_len)
{
    xqc_moq_setup_msg_t setup;
    xqc_memzero(&setup, sizeof(setup));
    setup.options = options;
    setup.options_len = options_len;
    return xqc_moq_write_setup(session, &setup);
}

xqc_int_t
xqc_moq_session_bind_policy(xqc_moq_session_t *session,
    const xqc_moq_alpn_policy_t *policy)
{
    if (session == NULL || policy == NULL || policy->profile == NULL) {
        return -XQC_EPARAM;
    }

    if (session->alpn_policy != NULL || session->profile != NULL) {
        if (session->alpn_policy == policy
            && session->profile == policy->profile)
        {
            return XQC_OK;
        }

        return -XQC_EVERSION;
    }

    session->alpn_policy = policy;
    session->profile = policy->profile;
    session->profile_state = XQC_MOQ_PROFILE_ALPN_SELECTED;
    if (session->log != NULL) {
        xqc_log(session->log, XQC_LOG_INFO,
                "|moq_profile_selected|alpn:%*s|profile:%s|wire_version:%ui|",
                policy->alpn_len, policy->alpn, policy->profile->name,
                policy->profile->wire_version);
    }
    return XQC_OK;
}

xqc_int_t
xqc_moq_session_bind_connection_alpn(xqc_moq_session_t *session)
{
    const xqc_moq_alpn_policy_t *policy;
    const char *alpn;
    size_t alpn_len;
    xqc_int_t ret;

    if (session == NULL || session->quic_conn == NULL) {
        return -XQC_EPARAM;
    }

    if (session->alpn_policy != NULL) {
        return session->profile_state == XQC_MOQ_PROFILE_FAILED
               ? -XQC_EVERSION : XQC_OK;
    }

    ret = xqc_conn_get_alpn(session->quic_conn, &alpn, &alpn_len);
    if (ret != XQC_OK) {
        return ret;
    }

    policy = xqc_moq_version_policy_for_alpn(alpn, alpn_len);
    if (policy == NULL) {
        if (session->log != NULL) {
            xqc_log(session->log, XQC_LOG_ERROR,
                    "|unsupported connection alpn|alpn:%*s|",
                    alpn_len, alpn);
        }
        session->profile_state = XQC_MOQ_PROFILE_FAILED;
        return -XQC_EALPN_NOT_SUPPORTED;
    }

    return xqc_moq_session_bind_policy(session, policy);
}

xqc_int_t
xqc_moq_session_validate_setup_type(xqc_moq_session_t *session,
    uint64_t setup_type)
{
    if (session == NULL || session->profile == NULL
        || session->profile_state != XQC_MOQ_PROFILE_ALPN_SELECTED)
    {
        return -XQC_EPARAM;
    }

    if (setup_type != session->profile->client_setup_type
        && setup_type != session->profile->server_setup_type)
    {
        return -XQC_EVERSION;
    }

    return XQC_OK;
}

xqc_int_t
xqc_moq_session_negotiate_version(xqc_moq_session_t *session,
    const uint64_t *offered_versions, uint64_t offered_versions_num)
{
    uint64_t i;

    if (session == NULL || offered_versions == NULL
        || offered_versions_num == 0)
    {
        return -XQC_EPARAM;
    }

    if (session->profile == NULL
        || session->profile_state != XQC_MOQ_PROFILE_ALPN_SELECTED)
    {
        return -XQC_EVERSION;
    }

    for (i = 0; i < offered_versions_num; ++i) {
        if (offered_versions[i] == session->profile->wire_version) {
            session->negotiated_version = offered_versions[i];
            session->version = (uint32_t) offered_versions[i];
            session->profile_state = XQC_MOQ_PROFILE_ACTIVE;
            if (session->log != NULL) {
                xqc_log(session->log, XQC_LOG_INFO,
                        "|moq_setup_active|profile:%s|wire_version:%ui|",
                        session->profile->name, offered_versions[i]);
            }
            return XQC_OK;
        }
    }

    session->profile_state = XQC_MOQ_PROFILE_FAILED;
    return -XQC_EVERSION;
}

xqc_int_t
xqc_moq_session_require_active(const xqc_moq_session_t *session)
{
    if (session == NULL || session->profile == NULL
        || session->profile_state != XQC_MOQ_PROFILE_ACTIVE)
    {
        return -XQC_EVERSION;
    }

    return XQC_OK;
}

static xqc_moq_session_t *
xqc_moq_session_create_internal(void *conn, xqc_moq_user_session_t *user_session,
    xqc_moq_transport_type_t transport_type, xqc_moq_role_t role,
    xqc_moq_session_callbacks_t callbacks, char *extdata,
    const xqc_moq_session_config_t *config,
    const xqc_moq_draft18_setup_config_t *draft18_config)
{
    xqc_int_t ret = 0;
    xqc_moq_draft18_setup_config_t default_draft18_config;
    uint8_t *draft18_setup_options = NULL;
    size_t draft18_setup_options_len = 0;
    const xqc_moq_message_parameter_t *setup_params =
        config != NULL ? config->setup_params : NULL;
    uint64_t setup_params_num =
        config != NULL ? config->setup_params_num : 0;
    xqc_connection_t *quic_conn;
    xqc_moq_session_t *session = xqc_calloc(1, sizeof(*session));
    if (session == NULL) {
        return NULL;
    }

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
    session->enable_datachannel = 1;
    session->enable_catalog = -1;

    ret = xqc_moq_session_bind_connection_alpn(session);
    if (ret != XQC_OK) {
        xqc_log(session->log, XQC_LOG_ERROR,
                "|bind connection MoQ ALPN error|ret:%d|", ret);
        goto error;
    }

    if (session->profile_state != XQC_MOQ_PROFILE_ALPN_SELECTED
        || session->profile == NULL)
    {
        xqc_log(session->log, XQC_LOG_ERROR, "|MoQ ALPN selected no profile|");
        goto error;
    }

    session->use_unified_setup = session->profile->unified_setup;
    if (draft18_config != NULL && !session->use_unified_setup) {
        ret = -XQC_EVERSION;
        goto error;
    }

    user_session->session = session;
    xqc_datagram_set_user_data(quic_conn, user_session);

    xqc_init_list_head(&session->local_subscribe_list);
    xqc_init_list_head(&session->peer_subscribe_list);
    xqc_init_list_head(&session->track_list_for_pub);
    xqc_init_list_head(&session->track_list_for_sub);
    xqc_init_list_head(&session->peer_subscribe_namespace_list);
    xqc_init_list_head(&session->peer_ns_pending_inbound_list);
    xqc_init_list_head(&session->local_advertised_namespace_list);
    xqc_init_list_head(&session->peer_advertised_namespace_list);
    xqc_init_list_head(&session->local_request_stream_list);
    xqc_init_list_head(&session->peer_request_stream_list);
    xqc_init_list_head(&session->d18_deferred_stream_list);
    xqc_init_list_head(&session->local_ns_pending_list);

    if (session->use_unified_setup
        && draft18_config == NULL
        && session->engine->eng_type != XQC_ENGINE_CLIENT)
    {
        xqc_memzero(&default_draft18_config,
                    sizeof(default_draft18_config));
        draft18_config = &default_draft18_config;
    }
    if (session->use_unified_setup) {
        xqc_moq_d18_setup_sender_t sender =
            session->engine->eng_type == XQC_ENGINE_CLIENT
            ? XQC_MOQ_D18_SETUP_SENDER_CLIENT
            : XQC_MOQ_D18_SETUP_SENDER_SERVER;
        xqc_moq_d18_setup_transport_t transport =
            session->transport_type == XQC_MOQ_TRANSPORT_QUIC
            ? XQC_MOQ_D18_SETUP_TRANSPORT_NATIVE_QUIC
            : XQC_MOQ_D18_SETUP_TRANSPORT_WEBTRANSPORT;
        ret = xqc_moq_session_encode_draft18_setup_config(
            draft18_config, sender, transport, &draft18_setup_options,
            &draft18_setup_options_len);
        if (ret != XQC_OK) {
            goto error;
        }
        uint8_t local_is_server =
            session->engine->eng_type == XQC_ENGINE_CLIENT ? 0 : 1;
        xqc_moq_d18_request_registry_init(
            &session->d18_request_registry, local_is_server);
        uint64_t auth_cache_limit = draft18_config != NULL
            && draft18_config->has_max_auth_token_cache_size
            ? draft18_config->max_auth_token_cache_size : 0;
        xqc_moq_d18_auth_cache_init(
            &session->peer_auth_cache, auth_cache_limit);
    }

    /* Request IDs use parity per endpoint: client even, server odd. */
    session->request_id_allocator = (session->engine->eng_type == XQC_ENGINE_CLIENT) ? 0 : 1;

    if (session->use_unified_setup) {
        xqc_moq_stream_t *stream = xqc_moq_stream_create_with_transport(
            session, XQC_STREAM_UNI);
        if (stream == NULL) {
            xqc_log(session->log, XQC_LOG_ERROR,
                    "|create unified control stream error|");
            goto error;
        }
        session->ctl_stream = stream;
        stream->kind = XQC_MOQ_STREAM_CONTROL;
        ret = xqc_moq_write_initial_setup(session, draft18_setup_options,
                                          draft18_setup_options_len);
        xqc_free(draft18_setup_options);
        draft18_setup_options = NULL;
        draft18_setup_options_len = 0;
        if (ret < 0) {
            xqc_log(session->log, XQC_LOG_ERROR,
                    "|write unified SETUP error|ret:%d|", ret);
            goto error;
        }

    } else if (session->engine->eng_type == XQC_ENGINE_CLIENT) {
        xqc_moq_stream_t *stream = xqc_moq_stream_create_with_transport(session, XQC_STREAM_BIDI);
        if (stream == NULL) {
            xqc_log(session->log, XQC_LOG_ERROR, "|create moq bidi stream error|");
            goto error;
        }
        session->ctl_stream = stream;
        stream->kind = XQC_MOQ_STREAM_CONTROL;

        /* If upper layer provided explicit setup params, use them as-is. */
        if (setup_params && setup_params_num > 0) {
            xqc_log(session->log, XQC_LOG_INFO,
                    "|send_client_setup|profile:%s|custom:1|params_num:%ui|",
                    session->profile->name, setup_params_num);
            ret = xqc_moq_write_client_setup_for_profile(
                session, setup_params, setup_params_num);
        } else {
            /* Default setup params: ROLE + PATH (+ optional EXTDATA for v5). */
            xqc_int_t params_num = 2;
            xqc_moq_message_parameter_t params[3] = {
                    {XQC_MOQ_PARAM_ROLE, 1, (uint8_t * ) & session->role, 1, (uint64_t)session->role},
                    {XQC_MOQ_PARAM_PATH, sizeof("path"), (uint8_t*)"path", 0, 0},
            };
            if (extdata && strlen(extdata) > 0
                && session->profile->include_extdata_in_default_setup)
            {
                params[params_num].type = XQC_MOQ_PARAM_EXTDATA;
                params[params_num].length = strlen(extdata) + 1;
                params[params_num].value = (uint8_t *)extdata;
                params[params_num].is_integer = 0;
                params[params_num].int_value = 0;
                params_num++;
            }

            xqc_log(session->log, XQC_LOG_INFO,
                    "|send_client_setup|profile:%s|custom:0|params_num:%d|",
                    session->profile->name, params_num);
            ret = xqc_moq_write_client_setup_for_profile(
                session, params, params_num);
        }
        if (ret < 0) {
            xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_write_client_setup error|ret:%d|", ret);
            goto error;
        }
    }
    xqc_log(session->log, XQC_LOG_INFO, "|session create success|role:%d|", role);
    return session;

error:
    xqc_free(draft18_setup_options);
    if (session->active_stream_count > 0) {
        if (session->ctl_stream != NULL) {
            (void)xqc_moq_stream_close(session->ctl_stream);
        }
        xqc_moq_session_destroy(session);
        return NULL;
    }
    user_session->session = NULL;
    if (session->use_unified_setup) {
        xqc_moq_d18_auth_cache_destroy(&session->peer_auth_cache);
        xqc_moq_d18_request_registry_destroy(
            &session->d18_request_registry);
    }
    xqc_free(session);
    return NULL;
}

xqc_moq_session_t *
xqc_moq_session_create(void *conn, xqc_moq_user_session_t *user_session,
    xqc_moq_transport_type_t transport_type, xqc_moq_role_t role,
    xqc_moq_session_callbacks_t callbacks, char *extdata)
{
    return xqc_moq_session_create_internal(conn, user_session, transport_type,
                                           role, callbacks, extdata, NULL, NULL);
}

xqc_moq_session_t *
xqc_moq_session_create_ex(void *conn, xqc_moq_user_session_t *user_session,
    xqc_moq_transport_type_t transport_type, xqc_moq_role_t role,
    xqc_moq_session_callbacks_t callbacks,
    const xqc_moq_session_config_t *config)
{
    return xqc_moq_session_create_internal(conn, user_session, transport_type,
                                           role, callbacks, NULL, config, NULL);
}

xqc_moq_session_t *
xqc_moq_session_create_with_params(void *conn, xqc_moq_user_session_t *user_session,
    xqc_moq_transport_type_t transport_type, xqc_moq_role_t role,
    xqc_moq_session_callbacks_t callbacks, char *extdata,
    xqc_moq_message_parameter_t *setup_params, uint64_t setup_params_num)
{
    xqc_moq_session_config_t config = {
        .setup_params = setup_params,
        .setup_params_num = setup_params_num,
    };

    return xqc_moq_session_create_internal(conn, user_session, transport_type,
                                           role, callbacks, extdata, &config, NULL);
}

xqc_moq_session_t *
xqc_moq_session_create_draft18(void *conn,
    xqc_moq_user_session_t *user_session,
    xqc_moq_transport_type_t transport_type, xqc_moq_role_t role,
    xqc_moq_session_callbacks_t callbacks,
    const char *authority, const char *path)
{
    xqc_moq_draft18_setup_config_t config;
    xqc_memzero(&config, sizeof(config));
    if (transport_type == XQC_MOQ_TRANSPORT_QUIC && conn != NULL) {
        xqc_connection_t *quic_conn = conn;
        if (quic_conn->engine != NULL
            && quic_conn->engine->eng_type == XQC_ENGINE_CLIENT)
        {
            config.authority = authority;
            config.path = path;
        }
    }
    return xqc_moq_session_create_draft18_with_config(
        conn, user_session, transport_type, role, callbacks, &config);
}

xqc_moq_session_t *
xqc_moq_session_create_draft18_with_config(
    void *conn, xqc_moq_user_session_t *user_session,
    xqc_moq_transport_type_t transport_type, xqc_moq_role_t role,
    xqc_moq_session_callbacks_t callbacks,
    const xqc_moq_draft18_setup_config_t *config)
{
    xqc_moq_session_t *session = xqc_moq_session_create_internal(
        conn, user_session, transport_type, role, callbacks,
        NULL, NULL, config);
    if (session != NULL && !session->use_unified_setup) {
        xqc_moq_session_destroy(session);
        return NULL;
    }
    return session;
}

xqc_int_t
xqc_moq_cancel_request(xqc_moq_session_t *session, uint64_t request_id)
{
    if (session == NULL || !session->use_unified_setup) {
        return -XQC_EPARAM;
    }
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &session->local_request_stream_list) {
        xqc_moq_stream_t *stream = xqc_list_entry(
            pos, xqc_moq_stream_t, request_list_member);
        if (stream->local_request && stream->request_id == request_id) {
            return xqc_moq_stream_cancel(
                stream, XQC_MOQ_REQUEST_CANCELLED);
        }
    }
    return -XQC_ESTREAM_NFOUND;
}

static void
xqc_moq_session_detach_user_session(xqc_moq_session_t *session)
{
    if (session->user_session != NULL
        && session->user_session->session == session)
    {
        session->user_session->session = NULL;
    }
    session->user_session = NULL;
}

static void
xqc_moq_session_destroy_internal(xqc_moq_session_t *session)
{
    xqc_list_head_t *pos, *next;
    xqc_moq_subscribe_t *subscribe;
    xqc_moq_track_t *track;

    session->destroying = 1;
    xqc_log(session->log, XQC_LOG_INFO, "|session destroy begin|");

    xqc_moq_session_unregister_goaway_timer(session);
    xqc_list_for_each_safe(pos, next, &session->local_request_stream_list) {
        xqc_moq_stream_t *stream = xqc_list_entry(
            pos, xqc_moq_stream_t, request_list_member);
        xqc_moq_stream_unregister_goaway_timer(stream);
    }
    xqc_list_for_each_safe(pos, next, &session->peer_request_stream_list) {
        xqc_moq_stream_t *stream = xqc_list_entry(
            pos, xqc_moq_stream_t, request_list_member);
        xqc_moq_stream_unregister_goaway_timer(stream);
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
    xqc_list_for_each_safe(pos, next, &session->peer_subscribe_namespace_list) {
        xqc_moq_namespace_prefix_t *prefix =
            xqc_list_entry(pos, xqc_moq_namespace_prefix_t, list_member);
        xqc_list_del(pos);
        xqc_moq_namespace_prefix_destroy(prefix);
    }
    xqc_list_for_each_safe(pos, next, &session->peer_ns_pending_inbound_list) {
        xqc_moq_namespace_prefix_t *prefix =
            xqc_list_entry(pos, xqc_moq_namespace_prefix_t, list_member);
        xqc_list_del(pos);
        xqc_moq_namespace_prefix_destroy(prefix);
    }
    xqc_list_for_each_safe(pos, next, &session->local_advertised_namespace_list) {
        xqc_moq_namespace_advertisement_t *advertisement =
            xqc_list_entry(pos, xqc_moq_namespace_advertisement_t, list_member);
        xqc_list_del(pos);
        xqc_moq_namespace_advertisement_destroy(advertisement);
    }
    xqc_list_for_each_safe(pos, next, &session->peer_advertised_namespace_list) {
        xqc_moq_namespace_advertisement_t *advertisement =
            xqc_list_entry(pos, xqc_moq_namespace_advertisement_t, list_member);
        xqc_list_del(pos);
        xqc_moq_namespace_advertisement_destroy(advertisement);
    }
    xqc_list_for_each_safe(pos, next, &session->local_ns_pending_list) {
        xqc_moq_pending_ns_request_t *pending =
            xqc_list_entry(pos, xqc_moq_pending_ns_request_t, list_member);
        xqc_list_del(pos);
        xqc_moq_namespace_tuple_free(pending->track_namespace_tuple, pending->track_namespace_num);
        xqc_free(pending);
    }
    xqc_free(session->goaway_new_session_uri);
    xqc_moq_session_clear_peer_setup_options(session);
    if (session->use_unified_setup) {
        xqc_moq_session_clear_peer_setup_auth_tokens(session);
        xqc_moq_d18_auth_cache_destroy(&session->peer_auth_cache);
        xqc_moq_d18_request_registry_destroy(
            &session->d18_request_registry);
    }
    xqc_moq_session_detach_user_session(session);
    xqc_free(session);
}

void
xqc_moq_session_destroy(xqc_moq_session_t *session)
{
    if (session == NULL || session->destroying) {
        return;
    }
    xqc_moq_session_detach_user_session(session);
    if (session->callback_depth > 0
        || session->active_stream_count > 0)
    {
        session->destroy_pending = 1;
        return;
    }
    xqc_moq_session_destroy_internal(session);
}

void
xqc_moq_session_callback_enter(xqc_moq_session_t *session)
{
    if (session != NULL && !session->destroying) {
        session->callback_depth++;
    }
}

void
xqc_moq_session_callback_leave(xqc_moq_session_t *session)
{
    if (session != NULL && !session->destroying
        && session->callback_depth > 0)
    {
        session->callback_depth--;
    }
}

void
xqc_moq_session_destroy_if_pending(xqc_moq_session_t *session)
{
    if (session == NULL || session->destroying
        || session->callback_depth > 0
        || session->active_stream_count > 0
        || !session->destroy_pending)
    {
        return;
    }
    session->destroy_pending = 0;
    xqc_moq_session_destroy_internal(session);
}

static xqc_int_t
xqc_moq_session_copy_setup_view(const xqc_moq_d18_bytes_view_t *view,
    uint8_t **copy)
{
    *copy = NULL;
    if (!view->present || view->len == 0) {
        return XQC_OK;
    }
    if (view->data == NULL) {
        return -XQC_EPARAM;
    }
    *copy = xqc_malloc(view->len);
    if (*copy == NULL) {
        return -XQC_EMALLOC;
    }
    xqc_memcpy(*copy, view->data, view->len);
    return XQC_OK;
}

void
xqc_moq_session_clear_peer_setup_options(xqc_moq_session_t *session)
{
    if (session == NULL) {
        return;
    }
    xqc_free(session->peer_setup_path);
    xqc_free(session->peer_setup_authority);
    xqc_free(session->peer_setup_implementation);
    session->peer_setup_path = NULL;
    session->peer_setup_path_len = 0;
    session->peer_setup_path_present = 0;
    session->peer_setup_authority = NULL;
    session->peer_setup_authority_len = 0;
    session->peer_setup_authority_present = 0;
    session->peer_setup_implementation = NULL;
    session->peer_setup_implementation_len = 0;
    session->peer_setup_implementation_present = 0;
    session->peer_max_auth_token_cache_size = 0;
    session->peer_has_max_auth_token_cache_size = 0;
}

xqc_int_t
xqc_moq_session_store_peer_setup_options(xqc_moq_session_t *session,
    const xqc_moq_d18_setup_options_t *options)
{
    if (session == NULL || options == NULL) {
        return -XQC_EPARAM;
    }

    uint8_t *path = NULL;
    uint8_t *authority = NULL;
    uint8_t *implementation = NULL;
    xqc_int_t ret = xqc_moq_session_copy_setup_view(&options->path, &path);
    if (ret == XQC_OK) {
        ret = xqc_moq_session_copy_setup_view(&options->authority,
                                               &authority);
    }
    if (ret == XQC_OK) {
        ret = xqc_moq_session_copy_setup_view(&options->implementation,
                                               &implementation);
    }
    if (ret != XQC_OK) {
        xqc_free(path);
        xqc_free(authority);
        xqc_free(implementation);
        return ret;
    }

    xqc_moq_session_clear_peer_setup_options(session);
    session->peer_setup_path = path;
    session->peer_setup_path_len = options->path.len;
    session->peer_setup_path_present = options->path.present;
    session->peer_setup_authority = authority;
    session->peer_setup_authority_len = options->authority.len;
    session->peer_setup_authority_present = options->authority.present;
    session->peer_setup_implementation = implementation;
    session->peer_setup_implementation_len = options->implementation.len;
    session->peer_setup_implementation_present =
        options->implementation.present;
    session->peer_max_auth_token_cache_size =
        options->max_auth_token_cache_size;
    session->peer_has_max_auth_token_cache_size =
        options->has_max_auth_token_cache_size;
    return XQC_OK;
}

void
xqc_moq_session_clear_peer_setup_auth_tokens(xqc_moq_session_t *session)
{
    if (session == NULL) {
        return;
    }
    for (size_t i = 0; i < session->peer_setup_auth_token_count; i++) {
        xqc_free(session->peer_setup_auth_tokens[i].token_value);
    }
    xqc_free(session->peer_setup_auth_tokens);
    session->peer_setup_auth_tokens = NULL;
    session->peer_setup_auth_token_count = 0;
}

uint64_t
xqc_moq_session_auth_result_error(xqc_moq_d18_auth_result_t result)
{
    switch (result) {
    case XQC_MOQ_D18_AUTH_OK:
        return XQC_MOQ_D18_NO_ERROR;
    case XQC_MOQ_D18_AUTH_FORMATTING:
        return XQC_MOQ_D18_KEY_VALUE_FORMATTING_ERROR;
    case XQC_MOQ_D18_AUTH_DUPLICATE_ALIAS:
        return XQC_MOQ_D18_DUPLICATE_AUTH_TOKEN_ALIAS;
    case XQC_MOQ_D18_AUTH_UNKNOWN_ALIAS:
        return XQC_MOQ_D18_UNKNOWN_AUTH_TOKEN_ALIAS;
    case XQC_MOQ_D18_AUTH_CACHE_OVERFLOW:
        return XQC_MOQ_D18_AUTH_TOKEN_CACHE_OVERFLOW;
    case XQC_MOQ_D18_AUTH_PROTOCOL_VIOLATION:
        return XQC_MOQ_D18_PROTOCOL_VIOLATION;
    default:
        return XQC_MOQ_D18_INTERNAL_ERROR;
    }
}

static xqc_moq_d18_request_auth_result_t
xqc_moq_session_request_auth_result(
    xqc_moq_d18_request_auth_kind_t kind, uint64_t error_code)
{
    xqc_moq_d18_request_auth_result_t result = {
        .kind = kind,
        .error_code = error_code,
    };
    return result;
}

xqc_moq_d18_request_auth_result_t
xqc_moq_session_classify_request_auth_result(
    xqc_moq_d18_auth_result_t auth_result)
{
    switch (auth_result) {
    case XQC_MOQ_D18_AUTH_OK:
        return xqc_moq_session_request_auth_result(
            XQC_MOQ_D18_REQUEST_AUTH_OK, XQC_MOQ_D18_NO_ERROR);
    case XQC_MOQ_D18_AUTH_FORMATTING:
        return xqc_moq_session_request_auth_result(
            XQC_MOQ_D18_REQUEST_AUTH_SESSION_ERROR,
            XQC_MOQ_D18_KEY_VALUE_FORMATTING_ERROR);
    case XQC_MOQ_D18_AUTH_DUPLICATE_ALIAS:
        return xqc_moq_session_request_auth_result(
            XQC_MOQ_D18_REQUEST_AUTH_SESSION_ERROR,
            XQC_MOQ_D18_DUPLICATE_AUTH_TOKEN_ALIAS);
    case XQC_MOQ_D18_AUTH_UNKNOWN_ALIAS:
        return xqc_moq_session_request_auth_result(
            XQC_MOQ_D18_REQUEST_AUTH_SESSION_ERROR,
            XQC_MOQ_D18_UNKNOWN_AUTH_TOKEN_ALIAS);
    case XQC_MOQ_D18_AUTH_CACHE_OVERFLOW:
        return xqc_moq_session_request_auth_result(
            XQC_MOQ_D18_REQUEST_AUTH_SESSION_ERROR,
            XQC_MOQ_D18_AUTH_TOKEN_CACHE_OVERFLOW);
    case XQC_MOQ_D18_AUTH_PROTOCOL_VIOLATION:
        return xqc_moq_session_request_auth_result(
            XQC_MOQ_D18_REQUEST_AUTH_SESSION_ERROR,
            XQC_MOQ_D18_PROTOCOL_VIOLATION);
    case XQC_MOQ_D18_AUTH_MALFORMED_TOKEN:
        return xqc_moq_session_request_auth_result(
            XQC_MOQ_D18_REQUEST_AUTH_REQUEST_ERROR,
            XQC_MOQ_REQUEST_ERROR_MALFORMED_AUTH_TOKEN);
    case XQC_MOQ_D18_AUTH_EXPIRED_TOKEN:
        return xqc_moq_session_request_auth_result(
            XQC_MOQ_D18_REQUEST_AUTH_REQUEST_ERROR,
            XQC_MOQ_REQUEST_ERROR_EXPIRED_AUTH_TOKEN);
    default:
        return xqc_moq_session_request_auth_result(
            XQC_MOQ_D18_REQUEST_AUTH_SESSION_ERROR,
            XQC_MOQ_D18_INTERNAL_ERROR);
    }
}

void
xqc_moq_request_auth_destroy(xqc_moq_request_auth_t *request_auth)
{
    if (request_auth == NULL) {
        return;
    }
    for (size_t i = 0; i < request_auth->count; i++) {
        xqc_free(request_auth->tokens[i].token_value);
    }
    xqc_free(request_auth->tokens);
    request_auth->tokens = NULL;
    request_auth->count = 0;
}

static xqc_int_t
xqc_moq_request_auth_contains(
    const xqc_moq_request_auth_t *request_auth,
    const xqc_moq_d18_auth_token_t *candidate)
{
    for (size_t i = 0; i < request_auth->count; i++) {
        const xqc_moq_resolved_auth_token_t *existing =
            &request_auth->tokens[i];
        if (existing->token_type != candidate->token_type
            || existing->token_value_len != candidate->token_value_len)
        {
            continue;
        }
        if (candidate->token_value_len == 0
            || memcmp(existing->token_value, candidate->token_value,
                      candidate->token_value_len) == 0)
        {
            return 1;
        }
    }
    return 0;
}

xqc_moq_d18_request_auth_result_t
xqc_moq_session_process_peer_request_auth(
    xqc_moq_session_t *session,
    const xqc_moq_message_parameter_t *params, size_t params_num,
    xqc_moq_request_auth_t *request_auth)
{
    if (session == NULL || request_auth == NULL
        || (params_num > 0 && params == NULL))
    {
        return xqc_moq_session_classify_request_auth_result(
            XQC_MOQ_D18_AUTH_INVALID_ARGUMENT);
    }

    xqc_moq_request_auth_destroy(request_auth);
    size_t token_count = 0;
    for (size_t i = 0; i < params_num; i++) {
        if (params[i].type == XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN) {
            token_count++;
        }
    }
    if (token_count == 0) {
        return xqc_moq_session_classify_request_auth_result(
            XQC_MOQ_D18_AUTH_OK);
    }
    if (token_count > SIZE_MAX / sizeof(*request_auth->tokens)) {
        return xqc_moq_session_classify_request_auth_result(
            XQC_MOQ_D18_AUTH_NO_MEMORY);
    }
    request_auth->tokens = xqc_calloc(
        token_count, sizeof(*request_auth->tokens));
    if (request_auth->tokens == NULL) {
        return xqc_moq_session_classify_request_auth_result(
            XQC_MOQ_D18_AUTH_NO_MEMORY);
    }

    for (size_t i = 0; i < params_num; i++) {
        const xqc_moq_message_parameter_t *param = &params[i];
        if (param->type != XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN) {
            continue;
        }
        if (param->is_integer || param->length > SIZE_MAX) {
            xqc_moq_request_auth_destroy(request_auth);
            return xqc_moq_session_classify_request_auth_result(
                XQC_MOQ_D18_AUTH_FORMATTING);
        }

        xqc_moq_d18_auth_token_t token;
        xqc_moq_d18_auth_result_t auth_result =
            xqc_moq_d18_auth_token_decode(
                param->value, (size_t)param->length, &token);
        if (auth_result != XQC_MOQ_D18_AUTH_OK) {
            xqc_moq_request_auth_destroy(request_auth);
            return xqc_moq_session_classify_request_auth_result(auth_result);
        }

        xqc_moq_d18_auth_token_t resolved;
        auth_result = xqc_moq_d18_auth_cache_apply(
            &session->peer_auth_cache, &token, 0, 0, &resolved, NULL);
        if (auth_result != XQC_MOQ_D18_AUTH_OK) {
            xqc_moq_request_auth_destroy(request_auth);
            return xqc_moq_session_classify_request_auth_result(auth_result);
        }
        if (!resolved.has_token_type) {
            continue;
        }
        if (xqc_moq_request_auth_contains(request_auth, &resolved)) {
            xqc_moq_request_auth_destroy(request_auth);
            return xqc_moq_session_request_auth_result(
                XQC_MOQ_D18_REQUEST_AUTH_SESSION_ERROR,
                XQC_MOQ_D18_PROTOCOL_VIOLATION);
        }

        xqc_moq_resolved_auth_token_t *owned =
            &request_auth->tokens[request_auth->count];
        owned->token_type = resolved.token_type;
        owned->token_value_len = resolved.token_value_len;
        if (resolved.token_value_len > 0) {
            owned->token_value = xqc_malloc(resolved.token_value_len);
            if (owned->token_value == NULL) {
                xqc_moq_request_auth_destroy(request_auth);
                return xqc_moq_session_classify_request_auth_result(
                    XQC_MOQ_D18_AUTH_NO_MEMORY);
            }
            xqc_memcpy(owned->token_value, resolved.token_value,
                       resolved.token_value_len);
        }
        request_auth->count++;
    }

    if (request_auth->count == 0) {
        xqc_free(request_auth->tokens);
        request_auth->tokens = NULL;
    }
    return xqc_moq_session_classify_request_auth_result(
        XQC_MOQ_D18_AUTH_OK);
}

static xqc_int_t
xqc_moq_session_setup_auth_is_duplicate(
    const xqc_moq_d18_resolved_auth_token_t *tokens, size_t count,
    const xqc_moq_d18_auth_token_t *candidate)
{
    for (size_t i = 0; i < count; i++) {
        if (tokens[i].token_type != candidate->token_type
            || tokens[i].token_value_len != candidate->token_value_len)
        {
            continue;
        }
        if (candidate->token_value_len == 0
            || memcmp(tokens[i].token_value, candidate->token_value,
                      candidate->token_value_len) == 0)
        {
            return 1;
        }
    }
    return 0;
}

uint64_t
xqc_moq_session_process_peer_setup_auth(xqc_moq_session_t *session,
    const xqc_moq_d18_setup_options_t *options,
    uint8_t receiver_is_server)
{
    if (session == NULL || options == NULL
        || (options->authorization_token_count > 0
            && options->authorization_tokens == NULL))
    {
        return XQC_MOQ_D18_INTERNAL_ERROR;
    }

    xqc_moq_session_clear_peer_setup_auth_tokens(session);
    size_t capacity = options->authorization_token_count;
    xqc_moq_d18_resolved_auth_token_t *tokens = NULL;
    if (capacity > 0) {
        if (capacity > SIZE_MAX / sizeof(*tokens)) {
            return XQC_MOQ_D18_INTERNAL_ERROR;
        }
        tokens = xqc_calloc(capacity, sizeof(*tokens));
        if (tokens == NULL) {
            return XQC_MOQ_D18_INTERNAL_ERROR;
        }
    }

    size_t count = 0;
    uint64_t error = XQC_MOQ_D18_NO_ERROR;
    for (size_t i = 0; i < capacity; i++) {
        const xqc_moq_d18_bytes_view_t *view =
            &options->authorization_tokens[i];
        xqc_moq_d18_auth_token_t token;
        xqc_moq_d18_auth_result_t auth_ret =
            xqc_moq_d18_auth_token_decode(view->data, view->len, &token);
        if (auth_ret != XQC_MOQ_D18_AUTH_OK) {
            error = xqc_moq_session_auth_result_error(auth_ret);
            break;
        }

        xqc_moq_d18_auth_token_t resolved;
        auth_ret = xqc_moq_d18_auth_cache_apply(
            &session->peer_auth_cache, &token, 1, receiver_is_server,
            &resolved, NULL);
        if (auth_ret != XQC_MOQ_D18_AUTH_OK) {
            error = xqc_moq_session_auth_result_error(auth_ret);
            break;
        }
        if (!resolved.has_token_type) {
            continue;
        }
        if (xqc_moq_session_setup_auth_is_duplicate(
                tokens, count, &resolved))
        {
            error = XQC_MOQ_D18_PROTOCOL_VIOLATION;
            break;
        }

        tokens[count].token_type = resolved.token_type;
        tokens[count].token_value_len = resolved.token_value_len;
        if (resolved.token_value_len > 0) {
            tokens[count].token_value = xqc_malloc(
                resolved.token_value_len);
            if (tokens[count].token_value == NULL) {
                error = XQC_MOQ_D18_INTERNAL_ERROR;
                break;
            }
            xqc_memcpy(tokens[count].token_value, resolved.token_value,
                       resolved.token_value_len);
        }
        count++;
    }

    if (error != XQC_MOQ_D18_NO_ERROR) {
        for (size_t i = 0; i < count; i++) {
            xqc_free(tokens[i].token_value);
        }
        xqc_free(tokens);
        return error;
    }

    session->peer_setup_auth_tokens = tokens;
    session->peer_setup_auth_token_count = count;
    return XQC_MOQ_D18_NO_ERROR;
}

size_t
xqc_moq_session_get_peer_setup_auth_token_count(
    const xqc_moq_session_t *session)
{
    return session == NULL ? 0 : session->peer_setup_auth_token_count;
}

xqc_int_t
xqc_moq_session_get_peer_setup_auth_token(
    const xqc_moq_session_t *session, size_t index, uint64_t *token_type,
    const uint8_t **token_value, size_t *token_value_len)
{
    if (session == NULL || index >= session->peer_setup_auth_token_count
        || token_type == NULL || token_value == NULL
        || token_value_len == NULL)
    {
        return -XQC_EPARAM;
    }
    const xqc_moq_d18_resolved_auth_token_t *token =
        &session->peer_setup_auth_tokens[index];
    *token_type = token->token_type;
    *token_value = token->token_value;
    *token_value_len = token->token_value_len;
    return XQC_OK;
}

xqc_int_t
xqc_moq_session_mark_peer_auth_token_expired(
    xqc_moq_session_t *session, uint64_t token_alias)
{
    if (session == NULL) {
        return -XQC_EPARAM;
    }
    xqc_moq_d18_auth_result_t result =
        xqc_moq_d18_auth_cache_mark_expired(
            &session->peer_auth_cache, token_alias);
    if (result == XQC_MOQ_D18_AUTH_OK) {
        return XQC_OK;
    }
    return result == XQC_MOQ_D18_AUTH_UNKNOWN_ALIAS
        ? -XQC_ENULLPTR : -XQC_EPARAM;
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
xqc_moq_session_error(xqc_moq_session_t *session, uint64_t code,
    const char *msg)
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
xqc_moq_session_alloc_request_id(xqc_moq_session_t *session)
{
    if (session->use_unified_setup) {
        return xqc_moq_d18_request_id_allocate(
            &session->d18_request_registry);
    }

    uint64_t request_id = session->request_id_allocator;
    session->request_id_allocator += 2;
    return request_id;
}

xqc_moq_d18_request_id_result_t
xqc_moq_session_register_local_request_id(xqc_moq_session_t *session,
    uint64_t request_id)
{
    return xqc_moq_d18_request_id_register_local(
        &session->d18_request_registry, request_id);
}

xqc_moq_d18_request_id_result_t
xqc_moq_session_unregister_local_request_id(xqc_moq_session_t *session,
    uint64_t request_id)
{
    return xqc_moq_d18_request_id_unregister_local(
        &session->d18_request_registry, request_id);
}

xqc_moq_d18_request_id_result_t
xqc_moq_session_register_peer_request_id(xqc_moq_session_t *session,
    uint64_t request_id)
{
    xqc_moq_d18_request_id_result_t ret =
        xqc_moq_d18_request_id_register_peer(
            &session->d18_request_registry, request_id);
    if (ret != XQC_MOQ_D18_REQUEST_ID_OK) {
        return ret;
    }

    if (!session->peer_request_id_seen
        || request_id > session->max_peer_request_id)
    {
        session->max_peer_request_id = request_id;
    }
    session->peer_request_id_seen = 1;
    return XQC_MOQ_D18_REQUEST_ID_OK;
}

uint64_t
xqc_moq_session_alloc_subscribe_id(xqc_moq_session_t *session)
{
    return xqc_moq_session_alloc_request_id(session);
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
xqc_moq_find_track_by_ns_tuple(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *ns_tuple, uint64_t ns_num,
    const char *track_name, xqc_moq_track_role_t role)
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
        if (xqc_moq_namespace_tuple_equal(track->track_info.track_namespace_tuple,
                track->track_info.track_namespace_num, ns_tuple, ns_num)
            && track->track_info.track_name && track_name
            && strcmp(track->track_info.track_name, track_name) == 0)
        {
            return track;
        }
    }
    return NULL;
}

xqc_moq_track_t *
xqc_moq_find_track_by_name(xqc_moq_session_t *session,
    const char *track_namespace, const char *track_name, xqc_moq_track_role_t role)
{
    if (track_namespace == NULL) {
        return NULL;
    }
    xqc_moq_track_ns_field_t field;
    field.data = (unsigned char *)track_namespace;
    field.len = strlen(track_namespace);
    return xqc_moq_find_track_by_ns_tuple(session, &field, 1, track_name, role);
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

xqc_int_t
xqc_moq_session_is_server(xqc_moq_session_t *session)
{
    return session && session->engine->eng_type == XQC_ENGINE_SERVER;
}

xqc_int_t
xqc_moq_send_goaway(xqc_moq_session_t *session, const char *new_session_uri, size_t uri_len)
{
    if (session == NULL || session->use_unified_setup) {
        return -XQC_EPARAM;
    }

    if (session->goaway_sent) {
        xqc_log(session->log, XQC_LOG_WARN, "|goaway already sent|");
        return -XQC_EPARAM;
    }

    /* client MUST NOT send URI */
    if (!xqc_moq_session_is_server(session)
        && new_session_uri != NULL && uri_len > 0)
    {
        xqc_log(session->log, XQC_LOG_ERROR,
                "|client cannot send GOAWAY with URI|uri_len:%z|", uri_len);
        return -XQC_EPARAM;
    }

    xqc_int_t ret = xqc_moq_write_goaway(session, new_session_uri, uri_len);
    if (ret < 0) {
        return ret;
    }

    session->goaway_sent = 1;
    xqc_moq_session_drain(session);
    return ret;
}

void
xqc_moq_session_drain(xqc_moq_session_t *session)
{
    if (session->draining) {
        return;
    }
    xqc_log(session->log, XQC_LOG_INFO, "|session entering drain state|");
    session->draining = 1;
    xqc_moq_session_check_drain_complete(session);
}

void
xqc_moq_session_check_drain_complete(xqc_moq_session_t *session)
{
    if (!session->draining) {
        return;
    }

    if (session->use_unified_setup
        && session->d18_control_goaway_sent)
    {
        xqc_list_head_t *request_lists[] = {
            &session->local_request_stream_list,
            &session->peer_request_stream_list,
        };
        for (size_t i = 0;
             i < sizeof(request_lists) / sizeof(request_lists[0]); i++)
        {
            xqc_list_head_t *pos;
            xqc_list_for_each(pos, request_lists[i]) {
                xqc_moq_stream_t *stream = xqc_list_entry(
                    pos, xqc_moq_stream_t, request_list_member);
                if ((stream->local_request || stream->peer_request)
                    && !stream->request_closed_notified)
                {
                    return;
                }
            }
        }
        if (session->d18_control_goaway_timer_registered
            && !session->d18_control_goaway_timer_fired)
        {
            xqc_timer_gp_timer_unset(
                session->timer_manager,
                session->d18_control_goaway_timer_id);
        }
        if (session->quic_conn != NULL
            && (session->quic_conn->conn_flag & XQC_CONN_FLAG_ERROR) == 0)
        {
            xqc_log(session->log, XQC_LOG_INFO,
                    "|draft-18 drain complete, closing session with NO_ERROR|");
            xqc_moq_session_error(
                session, XQC_MOQ_D18_NO_ERROR, "drain complete");
        }
        return;
    }

    /* Check if all subscriptions (both local and peer) are done */
    if (!xqc_list_empty(&session->local_subscribe_list)
        || !xqc_list_empty(&session->peer_subscribe_list))
    {
        return;
    }

    xqc_log(session->log, XQC_LOG_INFO,
            "|drain complete, closing session with NO_ERROR|");
    xqc_moq_session_error(session, MOQ_NO_ERROR, "drain complete");
}

void
xqc_moq_session_set_enable_datachannel(xqc_moq_session_t *session, xqc_int_t enable)
{
    if (session) {
        session->enable_datachannel = enable ? 1 : 0;
    }
}

void
xqc_moq_session_set_enable_catalog(xqc_moq_session_t *session, xqc_int_t enable)
{
    if (session) {
        /* A negative value restores "follow the negotiated profile". */
        session->enable_catalog = enable < 0 ? -1 : (enable ? 1 : 0);
    }
}

xqc_bool_t
xqc_moq_session_catalog_enabled(const xqc_moq_session_t *session)
{
    if (session == NULL) {
        return XQC_FALSE;
    }

    if (session->enable_catalog >= 0) {
        return session->enable_catalog ? XQC_TRUE : XQC_FALSE;
    }

    return session->profile != NULL
           && session->profile->catalog_default_enabled;
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
        xqc_moq_namespace_prefix_t *existing =
            xqc_list_entry(pos, xqc_moq_namespace_prefix_t, list_member);
        if (xqc_moq_namespace_tuple_overlaps(namespace_prefix_tuple, namespace_prefix_num,
                                             existing->prefix_tuple, existing->prefix_num))
        {
            return 1;
        }
    }
    xqc_list_for_each_safe(pos, next, &session->peer_ns_pending_inbound_list) {
        xqc_moq_namespace_prefix_t *existing =
            xqc_list_entry(pos, xqc_moq_namespace_prefix_t, list_member);
        if (xqc_moq_namespace_tuple_overlaps(namespace_prefix_tuple, namespace_prefix_num,
                                             existing->prefix_tuple, existing->prefix_num))
        {
            return 1;
        }
    }
    return 0;
}

xqc_int_t
xqc_moq_session_find_request_id(xqc_moq_session_t *session, uint64_t request_id)
{
    if (session == NULL) {
        return 0;
    }
    if (session->peer_ns_request_id_seen && request_id <= session->max_peer_ns_request_id) {
        return 1;
    }
    return 0;
}

xqc_int_t
xqc_moq_session_add_namespace_prefix(xqc_moq_session_t *session,
    uint64_t request_id,
    const xqc_moq_track_ns_field_t *namespace_prefix_tuple, uint64_t namespace_prefix_num)
{
    if (session == NULL
        || (namespace_prefix_num > 0 && namespace_prefix_tuple == NULL))
    {
        return -XQC_EPARAM;
    }

    if (xqc_moq_session_namespace_prefix_overlaps(session, namespace_prefix_tuple, namespace_prefix_num)) {
        return -XQC_EPARAM;
    }

    xqc_moq_namespace_prefix_t *prefix =
        xqc_moq_namespace_prefix_create_copy(namespace_prefix_tuple, namespace_prefix_num);
    if (prefix == NULL) {
        return -XQC_EMALLOC;
    }
    prefix->request_id = request_id;
    xqc_list_add_tail(&prefix->list_member, &session->peer_subscribe_namespace_list);

    session->max_peer_ns_request_id = request_id;
    session->peer_ns_request_id_seen = 1;

    return XQC_OK;
}

xqc_int_t
xqc_moq_session_remove_namespace_prefix(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *namespace_prefix_tuple, uint64_t namespace_prefix_num)
{
    if (session == NULL
        || (namespace_prefix_num > 0 && namespace_prefix_tuple == NULL))
    {
        return -XQC_EPARAM;
    }

    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &session->peer_subscribe_namespace_list) {
        xqc_moq_namespace_prefix_t *existing =
            xqc_list_entry(pos, xqc_moq_namespace_prefix_t, list_member);
        if (existing->prefix_num != namespace_prefix_num) {
            continue;
        }
        if (!xqc_moq_namespace_tuple_equal(namespace_prefix_tuple, namespace_prefix_num,
                                           existing->prefix_tuple, existing->prefix_num))
        {
            continue;
        }

        xqc_list_del(pos);
        xqc_moq_namespace_prefix_destroy(existing);
        return 1;
    }

    xqc_list_for_each_safe(pos, next, &session->peer_ns_pending_inbound_list) {
        xqc_moq_namespace_prefix_t *existing =
            xqc_list_entry(pos, xqc_moq_namespace_prefix_t, list_member);
        if (existing->prefix_num != namespace_prefix_num) {
            continue;
        }
        if (!xqc_moq_namespace_tuple_equal(namespace_prefix_tuple, namespace_prefix_num,
                                           existing->prefix_tuple, existing->prefix_num))
        {
            continue;
        }

        xqc_list_del(pos);
        xqc_moq_namespace_prefix_destroy(existing);
        return 1;
    }

    return 0;
}

xqc_int_t
xqc_moq_session_add_pending_ns_request(xqc_moq_session_t *session, uint64_t request_id,
    const xqc_moq_track_ns_field_t *ns_tuple, uint64_t ns_num)
{
    if (session == NULL) {
        return -XQC_EPARAM;
    }
    xqc_moq_pending_ns_request_t *pending = xqc_calloc(1, sizeof(*pending));
    if (pending == NULL) {
        return -XQC_EMALLOC;
    }
    pending->request_id = request_id;
    pending->track_namespace_tuple = xqc_moq_namespace_tuple_copy(ns_tuple, ns_num);
    pending->track_namespace_num = ns_num;
    if (ns_tuple && ns_num > 0 && pending->track_namespace_tuple == NULL) {
        xqc_free(pending);
        return -XQC_EMALLOC;
    }
    xqc_list_add_tail(&pending->list_member, &session->local_ns_pending_list);
    return XQC_OK;
}

xqc_moq_pending_ns_request_t *
xqc_moq_session_consume_pending_ns_request(xqc_moq_session_t *session, uint64_t request_id)
{
    if (session == NULL) {
        return NULL;
    }
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &session->local_ns_pending_list) {
        xqc_moq_pending_ns_request_t *pending =
            xqc_list_entry(pos, xqc_moq_pending_ns_request_t, list_member);
        if (pending->request_id == request_id) {
            xqc_list_del(pos);
            return pending;
        }
    }
    return NULL;
}

xqc_int_t
xqc_moq_session_add_pending_inbound_ns(xqc_moq_session_t *session,
    uint64_t request_id,
    const xqc_moq_track_ns_field_t *namespace_prefix_tuple, uint64_t namespace_prefix_num)
{
    if (session == NULL
        || (namespace_prefix_num > 0 && namespace_prefix_tuple == NULL))
    {
        return -XQC_EPARAM;
    }

    xqc_moq_namespace_prefix_t *prefix =
        xqc_moq_namespace_prefix_create_copy(namespace_prefix_tuple, namespace_prefix_num);
    if (prefix == NULL) {
        return -XQC_EMALLOC;
    }
    prefix->request_id = request_id;
    xqc_list_add_tail(&prefix->list_member, &session->peer_ns_pending_inbound_list);

    session->max_peer_ns_request_id = request_id;
    session->peer_ns_request_id_seen = 1;

    return XQC_OK;
}

xqc_int_t
xqc_moq_session_accept_pending_inbound_ns(xqc_moq_session_t *session,
    uint64_t request_id,
    const xqc_moq_track_ns_field_t **namespace_prefix_tuple, uint64_t *namespace_prefix_num)
{
    if (session == NULL) {
        return 0;
    }
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &session->peer_ns_pending_inbound_list) {
        xqc_moq_namespace_prefix_t *pending =
            xqc_list_entry(pos, xqc_moq_namespace_prefix_t, list_member);
        if (pending->request_id == request_id) {
            xqc_list_del(pos);
            xqc_list_add_tail(&pending->list_member, &session->peer_subscribe_namespace_list);
            if (namespace_prefix_tuple) {
                *namespace_prefix_tuple = pending->prefix_tuple;
            }
            if (namespace_prefix_num) {
                *namespace_prefix_num = pending->prefix_num;
            }
            return 1;
        }
    }
    return 0;
}

void
xqc_moq_session_reject_pending_inbound_ns(xqc_moq_session_t *session,
    uint64_t request_id)
{
    if (session == NULL) {
        return;
    }
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &session->peer_ns_pending_inbound_list) {
        xqc_moq_namespace_prefix_t *pending =
            xqc_list_entry(pos, xqc_moq_namespace_prefix_t, list_member);
        if (pending->request_id == request_id) {
            xqc_list_del(pos);
            xqc_moq_namespace_prefix_destroy(pending);
            return;
        }
    }
}

xqc_moq_namespace_advertisement_t *
xqc_moq_session_find_advertised_namespace(xqc_moq_session_t *session, xqc_int_t is_local,
    const xqc_moq_track_ns_field_t *track_namespace_tuple, uint64_t track_namespace_num)
{
    if (session == NULL || track_namespace_tuple == NULL || track_namespace_num == 0) {
        return NULL;
    }

    xqc_list_head_t *list = is_local ? &session->local_advertised_namespace_list
                                     : &session->peer_advertised_namespace_list;
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, list) {
        xqc_moq_namespace_advertisement_t *advertisement =
            xqc_list_entry(pos, xqc_moq_namespace_advertisement_t, list_member);
        if (xqc_moq_namespace_tuple_equal(track_namespace_tuple, track_namespace_num,
                                          advertisement->track_namespace_tuple,
                                          advertisement->track_namespace_num))
        {
            return advertisement;
        }
    }
    return NULL;
}

xqc_int_t
xqc_moq_session_add_advertised_namespace(xqc_moq_session_t *session, xqc_int_t is_local,
    const xqc_moq_track_ns_field_t *track_namespace_tuple, uint64_t track_namespace_num)
{
    if (session == NULL || track_namespace_tuple == NULL || track_namespace_num == 0) {
        return -XQC_EPARAM;
    }

    if (xqc_moq_session_find_advertised_namespace(session, is_local,
            track_namespace_tuple, track_namespace_num) != NULL)
    {
        return XQC_OK;
    }

    xqc_moq_namespace_advertisement_t *advertisement =
        xqc_moq_namespace_advertisement_create_copy(track_namespace_tuple, track_namespace_num);
    if (advertisement == NULL) {
        return -XQC_EMALLOC;
    }

    xqc_list_head_t *list = is_local ? &session->local_advertised_namespace_list
                                     : &session->peer_advertised_namespace_list;
    xqc_list_add_tail(&advertisement->list_member, list);
    return XQC_OK;
}

xqc_int_t
xqc_moq_session_remove_advertised_namespace(xqc_moq_session_t *session, xqc_int_t is_local,
    const xqc_moq_track_ns_field_t *track_namespace_tuple, uint64_t track_namespace_num)
{
    xqc_moq_namespace_advertisement_t *advertisement =
        xqc_moq_session_find_advertised_namespace(session, is_local,
            track_namespace_tuple, track_namespace_num);
    if (advertisement == NULL) {
        return 0;
    }
    xqc_list_del(&advertisement->list_member);
    xqc_moq_namespace_advertisement_destroy(advertisement);
    return 1;
}

xqc_int_t
xqc_moq_session_bind_advertised_namespace_request(xqc_moq_session_t *session,
    xqc_int_t is_local, const xqc_moq_track_ns_field_t *track_namespace_tuple,
    uint64_t track_namespace_num, uint64_t request_id)
{
    xqc_moq_namespace_advertisement_t *advertisement =
        xqc_moq_session_find_advertised_namespace(session, is_local,
            track_namespace_tuple, track_namespace_num);
    if (advertisement == NULL) {
        return -XQC_ENULLPTR;
    }
    advertisement->request_id = request_id;
    return XQC_OK;
}

xqc_moq_namespace_advertisement_t *
xqc_moq_session_find_advertised_namespace_by_request(xqc_moq_session_t *session,
    xqc_int_t is_local, uint64_t request_id)
{
    if (session == NULL || request_id == XQC_MOQ_INVALID_ID) {
        return NULL;
    }

    xqc_list_head_t *list = is_local ? &session->local_advertised_namespace_list
                                     : &session->peer_advertised_namespace_list;
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, list) {
        xqc_moq_namespace_advertisement_t *advertisement =
            xqc_list_entry(pos, xqc_moq_namespace_advertisement_t, list_member);
        if (advertisement->request_id == request_id) {
            return advertisement;
        }
    }
    return NULL;
}

xqc_int_t
xqc_moq_session_has_active_publish_in_namespace(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *track_namespace_tuple, uint64_t track_namespace_num)
{
    if (session == NULL || track_namespace_tuple == NULL || track_namespace_num == 0) {
        return 0;
    }

    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &session->track_list_for_pub) {
        xqc_moq_track_t *track = xqc_list_entry(pos, xqc_moq_track_t, list_member);
        if (track->subscribe_id == XQC_MOQ_INVALID_ID) {
            continue;
        }
        if (xqc_moq_namespace_tuple_equal(track_namespace_tuple, track_namespace_num,
                                          track->track_info.track_namespace_tuple,
                                          track->track_info.track_namespace_num))
        {
            return 1;
        }
    }
    return 0;
}

xqc_int_t
xqc_moq_session_forward_publish_blocked(
    xqc_moq_session_t *session, const xqc_moq_stream_t *origin,
    const xqc_moq_track_ns_field_t *full_namespace,
    uint64_t full_namespace_num, const char *track_name,
    size_t track_name_len)
{
    if (session == NULL) {
        return -XQC_EPARAM;
    }

    xqc_int_t first_error = XQC_OK;
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(
        pos, next, &session->peer_request_stream_list)
    {
        xqc_moq_stream_t *stream =
            xqc_list_entry(pos, xqc_moq_stream_t,
                           request_list_member);
        if (stream == origin || !stream->peer_request
            || stream->local_request
            || stream->request_type != XQC_MOQ_MSG_SUBSCRIBE_TRACKS
            || !stream->response_sent
            || !stream->subscribe_tracks_active
            || stream->request_closed_notified
            || stream->update_failed_wait_publish_done
            || stream->tracks_subscription == NULL
            || !xqc_moq_publish_blocked_stream_context_is_valid(stream)
            || !xqc_moq_namespace_tuple_is_prefix(
                stream->tracks_subscription->prefix_tuple,
                stream->tracks_subscription->prefix_num,
                full_namespace, full_namespace_num))
        {
            continue;
        }
        xqc_int_t ret = xqc_moq_write_publish_blocked(
            session, stream->request_id, full_namespace,
            full_namespace_num, track_name, track_name_len);
        if (ret != XQC_OK && first_error == XQC_OK) {
            first_error = ret;
        }
    }
    return first_error;
}
xqc_int_t
xqc_moq_session_set_callbacks_ext(xqc_moq_session_t *session,
    const xqc_moq_session_callbacks_ext_t *callbacks)
{
    const size_t header_size = offsetof(
        xqc_moq_session_callbacks_ext_t, on_request_ok);
    if (session == NULL || callbacks == NULL
        || callbacks->struct_size < header_size)
    {
        return -XQC_EPARAM;
    }
    if (callbacks->abi_version
        != XQC_MOQ_SESSION_CALLBACKS_EXT_ABI_VERSION)
    {
        return -XQC_EVERSION;
    }

    xqc_memzero(&session->session_callbacks_ext,
                sizeof(session->session_callbacks_ext));
    size_t copy_size = callbacks->struct_size;
    if (copy_size > sizeof(session->session_callbacks_ext)) {
        copy_size = sizeof(session->session_callbacks_ext);
    }
    xqc_memcpy(&session->session_callbacks_ext, callbacks, copy_size);
    session->session_callbacks_ext.struct_size =
        sizeof(session->session_callbacks_ext);
    return XQC_OK;
}

void
xqc_moq_session_set_request_cancelled_callback(
    xqc_moq_session_t *session,
    xqc_moq_on_request_cancelled_pt callback)
{
    if (session != NULL) {
        session->on_request_cancelled = callback;
    }
}

void
xqc_moq_session_set_request_update_callback(
    xqc_moq_session_t *session,
    xqc_moq_on_request_update_pt callback)
{
    if (session != NULL) {
        session->on_request_update = callback;
    }
}

void
xqc_moq_session_set_publish_blocked_callback(
    xqc_moq_session_t *session,
    xqc_moq_on_publish_blocked_pt callback)
{
    if (session != NULL) {
        session->on_publish_blocked = callback;
    }
}

void
xqc_moq_session_set_goaway_draft18_callback(
    xqc_moq_session_t *session,
    xqc_moq_on_goaway_draft18_pt callback)
{
    if (session != NULL) {
        session->on_goaway_draft18 = callback;
    }
}

xqc_int_t
xqc_moq_session_admit_local_initial_request(
    const xqc_moq_session_t *session)
{
    if (session == NULL) {
        return -XQC_EPARAM;
    }
    if (session->use_unified_setup
        && session->d18_control_goaway_received)
    {
        return -XQC_EPARAM;
    }
    return XQC_OK;
}

xqc_int_t
xqc_moq_session_admit_peer_initial_request(
    xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    uint64_t request_id)
{
    if (session == NULL || stream == NULL) {
        return -XQC_EPARAM;
    }
    if (!session->use_unified_setup
        || !session->d18_control_goaway_sent)
    {
        return XQC_OK;
    }

    xqc_int_t ret = xqc_moq_write_going_away_request_error(
        session, stream);
    if (ret != XQC_OK && session->quic_conn != NULL) {
        xqc_moq_session_error(
            session, XQC_MOQ_D18_INTERNAL_ERROR,
            "write GOING_AWAY REQUEST_ERROR");
    }
    xqc_log(session->log, XQC_LOG_INFO,
            "|reject initial request after GOAWAY|request_id:%ui|cutoff:%ui|ret:%d|",
            request_id, session->d18_control_goaway_cutoff, ret);
    return ret == XQC_OK ? -XQC_EPARAM : ret;
}

xqc_int_t
xqc_moq_session_admit_peer_request_update(
    xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    uint64_t request_id)
{
    if (session == NULL || stream == NULL) {
        return -XQC_EPARAM;
    }
    if (!session->use_unified_setup
        || !session->d18_control_goaway_sent)
    {
        return XQC_OK;
    }

    xqc_int_t ret = xqc_moq_write_going_away_request_update_error(
        session, stream);
    if (ret != XQC_OK && session->quic_conn != NULL) {
        xqc_moq_session_error(
            session, XQC_MOQ_D18_INTERNAL_ERROR,
            "write GOING_AWAY REQUEST_UPDATE error");
    }
    xqc_log(session->log, XQC_LOG_INFO,
            "|reject REQUEST_UPDATE after GOAWAY|request_id:%ui|ret:%d|",
            request_id, ret);
    return ret == XQC_OK ? -XQC_EPARAM : ret;
}

static xqc_int_t
xqc_moq_session_has_active_requests(
    xqc_moq_session_t *session)
{
    xqc_list_head_t *request_lists[] = {
        &session->local_request_stream_list,
        &session->peer_request_stream_list,
    };
    for (size_t i = 0;
         i < sizeof(request_lists) / sizeof(request_lists[0]); i++)
    {
        xqc_list_head_t *pos;
        xqc_list_for_each(pos, request_lists[i]) {
            xqc_moq_stream_t *stream = xqc_list_entry(
                pos, xqc_moq_stream_t, request_list_member);
            if ((stream->local_request || stream->peer_request)
                && !stream->request_closed_notified)
            {
                return 1;
            }
        }
    }
    return 0;
}

static void
xqc_moq_session_goaway_timeout(
    xqc_gp_timer_id_t timer_id, xqc_usec_t now, void *user_data)
{
    (void)now;
    xqc_moq_session_t *session = user_data;
    if (session == NULL
        || !session->d18_control_goaway_timer_registered
        || session->d18_control_goaway_timer_id != timer_id
        || session->d18_control_goaway_timer_fired)
    {
        return;
    }
    session->d18_control_goaway_timer_fired = 1;
    xqc_timer_gp_timer_unset(session->timer_manager, timer_id);
    if (xqc_moq_session_has_active_requests(session)) {
        if (session->quic_conn != NULL
            && (session->quic_conn->conn_flag & XQC_CONN_FLAG_ERROR) == 0)
        {
            xqc_moq_session_error(
                session, XQC_MOQ_D18_GOAWAY_TIMEOUT,
                "draft-18 GOAWAY timeout");
        }
        return;
    }
    xqc_moq_session_check_drain_complete(session);
}

void
xqc_moq_session_unregister_goaway_timer(
    xqc_moq_session_t *session)
{
    if (session == NULL || !session->d18_control_goaway_timer_registered) {
        return;
    }
    xqc_timer_unregister_gp_timer(
        session->timer_manager, session->d18_control_goaway_timer_id);
    session->d18_control_goaway_timer_registered = 0;
}

static xqc_int_t
xqc_moq_session_arm_goaway_timer(
    xqc_moq_session_t *session, uint64_t timeout_ms)
{
    if (timeout_ms == 0) {
        return XQC_OK;
    }
    xqc_usec_t now = xqc_monotonic_timestamp();
    if (session->timer_manager == NULL
        || timeout_ms > (UINT64_MAX - now) / 1000)
    {
        return -XQC_EPARAM;
    }
    xqc_gp_timer_id_t timer_id = xqc_timer_register_gp_timer(
        session->timer_manager, "moq_d18_session_goaway",
        xqc_moq_session_goaway_timeout, session);
    if (timer_id < 0) {
        return timer_id;
    }
    xqc_int_t ret = xqc_timer_gp_timer_set(
        session->timer_manager, timer_id,
        now + timeout_ms * 1000);
    if (ret != XQC_OK) {
        xqc_timer_unregister_gp_timer(session->timer_manager, timer_id);
        return ret;
    }
    session->d18_control_goaway_timer_id = timer_id;
    session->d18_control_goaway_timer_registered = 1;
    session->d18_control_goaway_timer_fired = 0;
    return XQC_OK;
}

static xqc_moq_stream_t *
xqc_moq_session_find_established_request(
    xqc_moq_session_t *session, uint64_t request_id)
{
    xqc_list_head_t *request_lists[] = {
        &session->local_request_stream_list,
        &session->peer_request_stream_list,
    };
    for (size_t i = 0;
         i < sizeof(request_lists) / sizeof(request_lists[0]); i++)
    {
        xqc_list_head_t *pos;
        xqc_list_for_each(pos, request_lists[i]) {
            xqc_moq_stream_t *stream = xqc_list_entry(
                pos, xqc_moq_stream_t, request_list_member);
            if (stream->request_id != request_id
                || stream->request_closed_notified)
            {
                continue;
            }
            if ((stream->local_request && stream->response_received)
                || (stream->peer_request && stream->response_sent))
            {
                return stream;
            }
        }
    }
    return NULL;
}

static xqc_int_t
xqc_moq_session_control_goaway_cutoff_is_valid(
    const xqc_moq_session_t *session, uint64_t cutoff)
{
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &session->peer_request_stream_list) {
        const xqc_moq_stream_t *stream = xqc_list_entry(
            pos, xqc_moq_stream_t, request_list_member);
        if (stream->peer_request && stream->response_sent
            && stream->request_id >= cutoff)
        {
            return 0;
        }
    }
    return 1;
}

xqc_int_t
xqc_moq_send_session_goaway_draft18(
    xqc_moq_session_t *session, const char *uri, size_t uri_len,
    uint64_t timeout_ms, uint64_t first_unprocessed_request_id)
{
    if (session == NULL || !session->use_unified_setup
        || !session->session_setup_done
        || session->ctl_stream == NULL || session->d18_control_goaway_sent
        || uri_len > XQC_MOQ_MAX_GOAWAY_URI_LEN
        || (uri_len > 0 && uri == NULL)
        || (!session->d18_request_registry.local_is_server && uri_len > 0))
    {
        return -XQC_EPARAM;
    }
    uint64_t peer_parity =
        session->d18_request_registry.local_is_server ? 0 : 1;
    if ((first_unprocessed_request_id & 1) != peer_parity) {
        return -XQC_EPARAM;
    }
    if (!xqc_moq_session_control_goaway_cutoff_is_valid(
            session, first_unprocessed_request_id))
    {
        return -XQC_EPARAM;
    }
    xqc_int_t ret = xqc_moq_session_arm_goaway_timer(
        session, timeout_ms);
    if (ret != XQC_OK) {
        return ret;
    }
    ret = xqc_moq_write_goaway_draft18(
        session, session->ctl_stream, uri, uri_len, timeout_ms,
        first_unprocessed_request_id, 1);
    if (ret != XQC_OK) {
        xqc_moq_session_unregister_goaway_timer(session);
        return ret;
    }

    session->d18_control_goaway_sent = 1;
    session->d18_control_goaway_cutoff = first_unprocessed_request_id;
    session->d18_control_goaway_timeout_ms = timeout_ms;
    session->goaway_sent = 1;

    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &session->peer_request_stream_list) {
        xqc_moq_stream_t *stream = xqc_list_entry(
            pos, xqc_moq_stream_t, request_list_member);
        if (!stream->peer_request || stream->request_closed_notified
            || stream->request_id < first_unprocessed_request_id)
        {
            continue;
        }
        ret = xqc_moq_write_going_away_request_error(session, stream);
        if (ret != XQC_OK) {
            if (session->quic_conn != NULL) {
                xqc_moq_session_error(
                    session, XQC_MOQ_D18_INTERNAL_ERROR,
                    "reject request at GOAWAY cutoff");
            }
            return ret;
        }
        stream->response_sent = 1;
        xqc_moq_stream_finish_request(
            stream, XQC_MOQ_REQUEST_ERROR_GOING_AWAY);
    }
    xqc_moq_session_drain(session);
    return XQC_OK;
}

static void
xqc_moq_request_goaway_timeout(
    xqc_gp_timer_id_t timer_id, xqc_usec_t now, void *user_data)
{
    (void)now;
    xqc_moq_stream_t *stream = user_data;
    if (stream == NULL || !stream->d18_goaway_timer_registered
        || stream->d18_goaway_timer_id != timer_id
        || stream->d18_goaway_timer_fired)
    {
        return;
    }
    stream->d18_goaway_timer_fired = 1;
    xqc_timer_gp_timer_unset(stream->session->timer_manager, timer_id);
    if (stream->request_closed_notified) {
        return;
    }
    (void)xqc_moq_stream_cancel(
        stream, XQC_MOQ_REQUEST_STREAM_GOING_AWAY);
}

static xqc_int_t
xqc_moq_stream_arm_goaway_timer(
    xqc_moq_stream_t *stream, uint64_t timeout_ms)
{
    if (timeout_ms == 0) {
        return XQC_OK;
    }
    xqc_moq_session_t *session = stream->session;
    xqc_usec_t now = xqc_monotonic_timestamp();
    if (session == NULL || session->timer_manager == NULL
        || timeout_ms > (UINT64_MAX - now) / 1000)
    {
        return -XQC_EPARAM;
    }
    xqc_gp_timer_id_t timer_id = xqc_timer_register_gp_timer(
        session->timer_manager, "moq_d18_request_goaway",
        xqc_moq_request_goaway_timeout, stream);
    if (timer_id < 0) {
        return timer_id;
    }
    xqc_int_t ret = xqc_timer_gp_timer_set(
        session->timer_manager, timer_id,
        now + timeout_ms * 1000);
    if (ret != XQC_OK) {
        xqc_timer_unregister_gp_timer(session->timer_manager, timer_id);
        return ret;
    }
    stream->d18_goaway_timer_id = timer_id;
    stream->d18_goaway_timer_registered = 1;
    stream->d18_goaway_timer_fired = 0;
    return XQC_OK;
}

xqc_int_t
xqc_moq_send_request_goaway_draft18(
    xqc_moq_session_t *session, uint64_t target_request_id,
    const char *uri, size_t uri_len, uint64_t timeout_ms)
{
    if (session == NULL || !session->use_unified_setup
        || !session->session_setup_done
        || uri_len > XQC_MOQ_MAX_GOAWAY_URI_LEN
        || (uri_len > 0 && uri == NULL)
        || (!session->d18_request_registry.local_is_server && uri_len > 0))
    {
        return -XQC_EPARAM;
    }
    xqc_moq_stream_t *stream = xqc_moq_session_find_established_request(
        session, target_request_id);
    if (stream == NULL) {
        return -XQC_ESTREAM_NFOUND;
    }
    if (stream->d18_goaway_sent) {
        return -XQC_EPARAM;
    }
    xqc_int_t ret = xqc_moq_stream_arm_goaway_timer(
        stream, timeout_ms);
    if (ret != XQC_OK) {
        return ret;
    }
    ret = xqc_moq_write_goaway_draft18(
        session, stream, uri, uri_len, timeout_ms, 0, 0);
    if (ret != XQC_OK) {
        xqc_moq_stream_unregister_goaway_timer(stream);
        return ret;
    }
    stream->d18_goaway_sent = 1;
    stream->d18_goaway_timeout_ms = timeout_ms;
    return XQC_OK;
}
