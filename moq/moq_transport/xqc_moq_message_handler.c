
#include "moq/moq_transport/xqc_moq_message_handler.h"
#include "src/transport/xqc_conn.h"
#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/xqc_moq_subscribe.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_transport/xqc_moq_track.h"
#include "moq/moq_transport/xqc_moq_namespace.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_params.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_properties.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_data.h"
#include "moq/moq_media/xqc_moq_catalog.h"

static void
xqc_moq_d18_log_rejected_subscribe_tracks_update(
    xqc_moq_session_t *session, const xqc_moq_stream_t *stream,
    uint64_t update_id)
{
    char accepted_prefix[256];
    size_t written = 0;
    const xqc_moq_namespace_prefix_t *prefix =
        stream->tracks_subscription;
    if (prefix != NULL) {
        for (uint64_t i = 0; i < prefix->prefix_num
             && written + 1 < sizeof(accepted_prefix); i++)
        {
            if (i != 0) {
                accepted_prefix[written++] = '/';
            }
            for (size_t j = 0; j < prefix->prefix_tuple[i].len
                 && written + 1 < sizeof(accepted_prefix); j++)
            {
                uint8_t ch = prefix->prefix_tuple[i].data[j];
                accepted_prefix[written++] =
                    ch >= 0x20 && ch <= 0x7e && ch != '|' && ch != '/'
                    ? (char)ch : '?';
            }
        }
    }
    accepted_prefix[written] = '\0';
    xqc_log(session->log, XQC_LOG_INFO,
            "|request_update_rejected_state|target_id:%ui|update_id:%ui|"
            "accepted_prefix:%s|candidate_applied:0|",
            stream->request_id, update_id, accepted_prefix);
}

static xqc_int_t
xqc_moq_d18_register_peer_request_id(xqc_moq_session_t *session,
    uint64_t request_id, const char *request_name)
{
    xqc_moq_d18_request_id_result_t ret =
        xqc_moq_session_register_peer_request_id(session, request_id);
    if (ret == XQC_MOQ_D18_REQUEST_ID_OK) {
        return XQC_OK;
    }

    uint64_t error_code = xqc_moq_d18_request_id_error_code(ret);
    xqc_log(session->log, XQC_LOG_ERROR,
            "|invalid draft-18 request ID|request:%s|request_id:%ui|"
            "result:%d|error_code:%ui|",
            request_name, request_id, ret, error_code);
    xqc_moq_session_error(session, error_code, "invalid draft-18 request ID");
    return -XQC_EPROTO;
}

static xqc_int_t
xqc_moq_d18_store_peer_initial_params(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream,
    const xqc_moq_message_parameter_t *params, size_t params_num)
{
    xqc_moq_message_parameter_t *copy = NULL;
    if (xqc_moq_d18_params_clone(params, params_num, &copy)
        != XQC_MOQ_D18_UPDATE_OK)
    {
        xqc_moq_session_error(session, XQC_MOQ_D18_INTERNAL_ERROR,
                              "store initial request parameters");
        return -XQC_EMALLOC;
    }
    stream->d18_accepted_params = copy;
    stream->d18_accepted_params_num = params_num;
    return XQC_OK;
}

static uint64_t
xqc_moq_d18_peer_update_response_id(
    xqc_moq_stream_t *moq_stream, uint64_t current_request_id)
{
    xqc_moq_d18_update_record_t *head =
        xqc_moq_d18_update_queue_peek(
            &moq_stream->d18_peer_update_queue);
    return head != NULL ? head->request_id : current_request_id;
}

static xqc_int_t
xqc_moq_d18_apply_request_auth(xqc_moq_session_t *session,
    xqc_moq_stream_t *moq_stream,
    uint64_t response_request_id,
    const xqc_moq_message_parameter_t *params, size_t params_num,
    xqc_moq_request_auth_t *request_auth)
{
    xqc_moq_d18_request_auth_result_t result =
        xqc_moq_session_process_peer_request_auth(
            session, params, params_num, request_auth);
    if (result.kind == XQC_MOQ_D18_REQUEST_AUTH_OK) {
        return XQC_OK;
    }

    if (result.kind == XQC_MOQ_D18_REQUEST_AUTH_SESSION_ERROR) {
        xqc_log(session->log, XQC_LOG_ERROR,
                "|draft-18 request auth session error|"
                "request_id:%ui|request_type:0x%xi|error_code:%ui|",
                moq_stream->request_id, moq_stream->request_type,
                result.error_code);
        xqc_moq_session_error(session, result.error_code,
                              "invalid request authorization token");
        return -XQC_EPROTO;
    }

    const char *reason =
        result.error_code == XQC_MOQ_REQUEST_ERROR_EXPIRED_AUTH_TOKEN
        ? "authorization token expired"
        : "malformed authorization token";
    xqc_moq_request_error_msg_t request_error;
    xqc_memzero(&request_error, sizeof(request_error));
    request_error.error_code = result.error_code;
    request_error.reason_phrase = (char *)reason;
    request_error.reason_phrase_len = strlen(reason);
    xqc_int_t ret = xqc_moq_write_request_error(
        session, response_request_id, &request_error);
    if (ret != XQC_OK) {
        xqc_log(session->log, XQC_LOG_ERROR,
                "|write request auth error failed|"
                "request_id:%ui|error_code:%ui|ret:%d|",
                moq_stream->request_id, result.error_code, ret);
        xqc_moq_session_error(session, XQC_MOQ_D18_INTERNAL_ERROR,
                              "write request authorization error");
    }
    return -XQC_EPROTO;
}

void
xqc_moq_on_request_update(xqc_moq_session_t *session,
    xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_request_update_msg_t *update =
        (xqc_moq_request_update_msg_t *)msg_base;
    if (session == NULL || moq_stream == NULL || update == NULL
        || !session->use_unified_setup
        || moq_stream->request_closed_notified
        || moq_stream->update_failed_wait_publish_done
        || !((moq_stream->peer_request
                && moq_stream->response_sent)
             || (moq_stream->local_request
                && moq_stream->request_type == XQC_MOQ_MSG_PUBLISH
                && moq_stream->response_received)))
    {
        if (session != NULL) {
            xqc_moq_session_error(
                session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
                "REQUEST_UPDATE on invalid request stream");
        }
        return;
    }

    if (xqc_moq_session_admit_peer_request_update(
            session, moq_stream, update->request_id) != XQC_OK)
    {
        return;
    }

    if (xqc_moq_d18_register_peer_request_id(
            session, update->request_id, "REQUEST_UPDATE") != XQC_OK)
    {
        return;
    }
    xqc_moq_d18_update_record_t *record = NULL;
    if (xqc_moq_d18_update_record_create(
            update->request_id, update->params,
            (size_t)update->params_num, &record)
            != XQC_MOQ_D18_UPDATE_OK
        || xqc_moq_d18_update_queue_push(
            &moq_stream->d18_peer_update_queue, record)
            != XQC_MOQ_D18_UPDATE_OK)
    {
        xqc_moq_d18_update_record_destroy(record);
        xqc_moq_session_error(
            session, XQC_MOQ_D18_INTERNAL_ERROR,
            "store REQUEST_UPDATE");
        return;
    }

    if (moq_stream->request_type == XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE
        || moq_stream->request_type == XQC_MOQ_MSG_SUBSCRIBE_TRACKS
        || moq_stream->request_type == XQC_MOQ_MSG_PUBLISH_NAMESPACE)
    {
        const xqc_moq_message_parameter_t *prefix_param = NULL;
        for (size_t i = 0; i < (size_t)record->params_num; i++) {
            if (record->params[i].type
                == XQC_MOQ_D18_PARAM_TRACK_NAMESPACE_PREFIX)
            {
                prefix_param = &record->params[i];
                break;
            }
        }
        if (prefix_param != NULL
            && moq_stream->request_type
                == XQC_MOQ_MSG_PUBLISH_NAMESPACE)
        {
            xqc_moq_d18_update_record_destroy(record);
            xqc_moq_session_error(
                session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
                "TRACK_NAMESPACE_PREFIX on PUBLISH_NAMESPACE update");
            return;
        }
        if (prefix_param != NULL) {
            record->candidate_prefix =
                xqc_moq_namespace_prefix_create_serialized(
                    prefix_param->value,
                    (size_t)prefix_param->length);
            if (record->candidate_prefix == NULL) {
                xqc_moq_d18_update_record_destroy(record);
                xqc_moq_session_error(
                    session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
                    "invalid namespace REQUEST_UPDATE prefix");
                return;
            }
            record->candidate_prefix->request_id = moq_stream->request_id;
        }
    }

    if (xqc_moq_d18_apply_request_auth(
            session, moq_stream,
            xqc_moq_d18_peer_update_response_id(
                moq_stream, update->request_id),
            record->params, (size_t)record->params_num,
            &record->callback_view.request_auth) != XQC_OK)
    {
        return;
    }

    if (record->candidate_prefix != NULL)
    {
        if (xqc_moq_namespace_update_overlaps(
                session, moq_stream, record->candidate_prefix))
        {
            xqc_moq_request_error_msg_t error;
            xqc_memzero(&error, sizeof(error));
            error.error_code = XQC_MOQ_REQUEST_ERROR_PREFIX_OVERLAP;
            error.reason_phrase = "track namespace prefix overlap";
            error.reason_phrase_len = strlen(error.reason_phrase);
            if (xqc_moq_write_request_error(
                    session,
                    xqc_moq_d18_peer_update_response_id(
                        moq_stream, update->request_id),
                    &error) != XQC_OK)
            {
                xqc_moq_session_error(
                    session, XQC_MOQ_D18_INTERNAL_ERROR,
                    "write REQUEST_UPDATE prefix overlap");
            }
            return;
        }
    }

    if (session->on_request_update != NULL) {
        record->callback_view.d18_param_context =
            update->d18_param_context;
        xqc_moq_d18_update_record_retain(record);
        session->on_request_update(
            session->user_session, moq_stream->request_id,
            moq_stream->request_type, &record->callback_view);
        xqc_moq_d18_update_record_release(record);
    }
}

void
xqc_moq_on_publish_blocked(xqc_moq_session_t *session,
    xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_publish_blocked_msg_t *blocked =
        (xqc_moq_publish_blocked_msg_t *)msg_base;
    if (session == NULL) {
        return;
    }
    if (moq_stream == NULL || blocked == NULL
        || !session->use_unified_setup
        || !moq_stream->local_request || moq_stream->peer_request
        || moq_stream->request_type != XQC_MOQ_MSG_SUBSCRIBE_TRACKS
        || !moq_stream->response_received
        || moq_stream->request_closed_notified
        || moq_stream->update_failed_wait_publish_done
        || moq_stream->tracks_subscription == NULL)
    {
        xqc_moq_session_error(
            session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
            "PUBLISH_BLOCKED on invalid request stream");
        return;
    }

    xqc_moq_namespace_prefix_t *prefix =
        moq_stream->tracks_subscription;
    if (prefix->prefix_num > XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS
        || blocked->track_namespace_suffix_num
            > XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS - prefix->prefix_num)
    {
        xqc_moq_session_error(
            session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
            "invalid PUBLISH_BLOCKED Full Track Name");
        return;
    }

    uint64_t full_namespace_num = prefix->prefix_num
        + blocked->track_namespace_suffix_num;
    xqc_moq_track_ns_field_t *full_namespace = NULL;
    if (full_namespace_num > 0) {
        full_namespace = xqc_calloc(
            full_namespace_num, sizeof(*full_namespace));
        if (full_namespace == NULL) {
            xqc_moq_session_error(
                session, XQC_MOQ_D18_INTERNAL_ERROR,
                "allocate PUBLISH_BLOCKED Full Track Name");
            return;
        }
        if (prefix->prefix_num > 0) {
            xqc_memcpy(full_namespace, prefix->prefix_tuple,
                       prefix->prefix_num
                           * sizeof(*full_namespace));
        }
        if (blocked->track_namespace_suffix_num > 0) {
            xqc_memcpy(
                full_namespace + prefix->prefix_num,
                blocked->track_namespace_suffix,
                blocked->track_namespace_suffix_num
                    * sizeof(*full_namespace));
        }
    }

    if (xqc_moq_validate_d18_full_track_name(
            full_namespace_num, full_namespace,
            blocked->track_name, blocked->track_name_len) != XQC_OK)
    {
        xqc_free(full_namespace);
        xqc_moq_session_error(
            session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
            "invalid PUBLISH_BLOCKED Full Track Name");
        return;
    }

    xqc_int_t relay_ret = xqc_moq_session_forward_publish_blocked(
        session, moq_stream, full_namespace, full_namespace_num,
        blocked->track_name, blocked->track_name_len);
    if (session->on_publish_blocked != NULL) {
        session->on_publish_blocked(
            session->user_session, moq_stream->request_id,
            full_namespace, full_namespace_num,
            blocked->track_name, blocked->track_name_len);
    }
    xqc_free(full_namespace);
    if (relay_ret != XQC_OK) {
        xqc_moq_session_error(
            session, XQC_MOQ_D18_INTERNAL_ERROR,
            "forward PUBLISH_BLOCKED");
    }
}

#define XQC_MOQ_ALIAS_TYPE_DELETE      0x0
#define XQC_MOQ_ALIAS_TYPE_REGISTER    0x1
#define XQC_MOQ_ALIAS_TYPE_USE_ALIAS   0x2
#define XQC_MOQ_ALIAS_TYPE_USE_VALUE   0x3

static uint8_t xqc_moq_param_read_u8(const xqc_moq_message_parameter_t *param);

static xqc_moq_d18_property_result_t
xqc_moq_d18_validate_track_properties(
    const uint8_t *properties, size_t properties_len)
{
    xqc_moq_d18_properties_t *parsed = NULL;
    xqc_moq_d18_property_result_t result =
        xqc_moq_d18_properties_parse(
            XQC_MOQ_D18_PROPERTY_SCOPE_TRACK,
            properties, properties_len, &parsed);
    xqc_moq_d18_properties_destroy(parsed);
    return result;
}

static void
xqc_moq_d18_close_for_track_properties(
    xqc_moq_session_t *session,
    xqc_moq_d18_property_result_t result,
    const char *formatting_reason, const char *protocol_reason)
{
    if (result == XQC_MOQ_D18_PROPERTY_FORMATTING) {
        xqc_moq_session_error(
            session, XQC_MOQ_D18_KEY_VALUE_FORMATTING_ERROR,
            formatting_reason);

    } else if (result == XQC_MOQ_D18_PROPERTY_NO_MEMORY) {
        xqc_moq_session_error(
            session, XQC_MOQ_D18_INTERNAL_ERROR,
            "allocate Track Properties");

    } else {
        xqc_moq_session_error(
            session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
            protocol_reason);
    }
}

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

    ret = xqc_moq_session_negotiate_version(
        session, client_setup->versions, client_setup->versions_num);
    if (ret != XQC_OK) {
        xqc_log(session->log, XQC_LOG_ERROR,
                "|client setup version mismatch|profile:%s|ret:%d|",
                session->profile != NULL ? session->profile->name : "none",
                ret);
        goto version_error;
    }
    version = session->version;

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
    ret = xqc_moq_write_server_setup_for_profile(
        session, params, sizeof(params) / sizeof(params[0]));
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

    if (xqc_moq_session_catalog_enabled(session)) {
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
    return;

version_error:
    xqc_moq_session_error(session, MOQ_PROTOCOL_VIOLATION,
                          "client setup version mismatch");
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

    ret = xqc_moq_session_negotiate_version(
        session, client_setup->versions, client_setup->versions_num);
    if (ret != XQC_OK) {
        xqc_log(session->log, XQC_LOG_ERROR,
                "|client setup version mismatch|profile:%s|ret:%d|",
                session->profile != NULL ? session->profile->name : "none",
                ret);
        goto version_error;
    }
    uint32_t version = session->version;
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

    ret = xqc_moq_write_server_setup_for_profile(session, NULL, 0);
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

    if (xqc_moq_session_catalog_enabled(session)) {
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
    return;

version_error:
    xqc_moq_session_error(session, MOQ_PROTOCOL_VIOLATION,
                          "client setup version mismatch");
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

    ret = xqc_moq_session_negotiate_version(
        session, &server_setup->version, 1);
    if (ret != XQC_OK) {
        xqc_log(session->log, XQC_LOG_ERROR,
                "|server setup version mismatch|profile:%s|version:%ui|ret:%d|",
                session->profile != NULL ? session->profile->name : "none",
                server_setup->version, ret);
        goto version_error;
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

    if (xqc_moq_session_catalog_enabled(session)) {
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
    return;

version_error:
    xqc_moq_session_error(session, MOQ_PROTOCOL_VIOLATION,
                          "server setup version mismatch");
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

    ret = xqc_moq_session_negotiate_version(
        session, &server_setup->selected_version, 1);
    if (ret != XQC_OK) {
        xqc_log(session->log, XQC_LOG_ERROR,
                "|server setup version mismatch|profile:%s|version:%ui|ret:%d|",
                session->profile != NULL ? session->profile->name : "none",
                server_setup->selected_version, ret);
        goto version_error;
    }
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

    if (xqc_moq_session_catalog_enabled(session)) {
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
    return;

version_error:
    xqc_moq_session_error(session, MOQ_PROTOCOL_VIOLATION,
                          "server setup version mismatch");
}

void
xqc_moq_on_subscribe(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_subscribe_t *subscribe;
    xqc_moq_track_t *track;
    xqc_int_t ret;
    uint64_t original_subscribe_id;
    uint64_t original_track_alias;
    xqc_moq_subscribe_msg_t *subscribe_msg = (xqc_moq_subscribe_msg_t*)msg_base;

    if (session->use_unified_setup) {
        if (moq_stream == NULL || moq_stream->local_request
            || moq_stream->peer_request)
        {
            xqc_moq_session_error(session, MOQ_PROTOCOL_VIOLATION,
                                  "invalid SUBSCRIBE request stream");
            return;
        }
        if (xqc_moq_session_admit_peer_initial_request(
                session, moq_stream, subscribe_msg->subscribe_id)
            != XQC_OK)
        {
            return;
        }
        if (xqc_moq_d18_register_peer_request_id(
                session, subscribe_msg->subscribe_id, "SUBSCRIBE")
            != XQC_OK)
        {
            return;
        }

        moq_stream->peer_request = 1;
        moq_stream->request_type = XQC_MOQ_MSG_SUBSCRIBE;
        moq_stream->request_id = subscribe_msg->subscribe_id;
        xqc_list_add_tail(&moq_stream->request_list_member,
                          &session->peer_request_stream_list);

        if (xqc_moq_d18_apply_request_auth(
                session, moq_stream, moq_stream->request_id,
                subscribe_msg->params, subscribe_msg->params_num,
                &subscribe_msg->request_auth) != XQC_OK)
        {
            return;
        }
        if (xqc_moq_d18_store_peer_initial_params(
                session, moq_stream, subscribe_msg->params,
                (size_t)subscribe_msg->params_num) != XQC_OK)
        {
            return;
        }
    }

    ret = xqc_moq_profile_adapt_subscribe(session, subscribe_msg);
    if (ret != XQC_OK) {
        xqc_log(session->log, XQC_LOG_ERROR,
                "|adapt subscribe error|profile:%s|ret:%d|",
                session->profile != NULL ? session->profile->name : "none",
                ret);
        goto error;
    }

    track = xqc_moq_find_track_by_ns_tuple(session, subscribe_msg->track_namespace_tuple,
                subscribe_msg->track_namespace_num, subscribe_msg->track_name, XQC_MOQ_TRACK_FOR_PUB);
    if (track == NULL) {
        if (session->use_unified_setup
            && session->session_callbacks.on_subscribe != NULL)
        {
            session->session_callbacks.on_subscribe(
                session->user_session, subscribe_msg->subscribe_id,
                NULL, subscribe_msg);
            return;
        }
        xqc_log(session->log, XQC_LOG_ERROR, "|track not found|track_alias:%ui|", subscribe_msg->track_alias);
        goto error;
    }

    if (track->subscribe_id != XQC_MOQ_INVALID_ID
        || (session->profile->data_strategy
                == XQC_MOQ_DATA_STRATEGY_OBJECT_TRACK
            && track->track_alias != XQC_MOQ_INVALID_ID))
    {
        xqc_log(session->log, XQC_LOG_ERROR, "|track already subscribed|");
        goto error;
    }

    subscribe = xqc_moq_find_subscribe(
        session, subscribe_msg->subscribe_id, 0);
    if (subscribe) {
        xqc_log(session->log, XQC_LOG_ERROR,
                "|subscribe already exist|subscribe_id:%ui|",
                subscribe_msg->subscribe_id);
        goto error;
    }

    original_subscribe_id = track->subscribe_id;
    original_track_alias = track->track_alias;

    if (session->profile->data_strategy
        != XQC_MOQ_DATA_STRATEGY_OBJECT_TRACK)
    {
        /*
         * draft-14 SUBSCRIBE carries no Track Alias, so subscribe_msg holds a
         * zero from calloc. The publisher assigns one and must mirror it back
         * unconditionally: the shared assignment below would otherwise stamp
         * alias 0 onto the track, and 0 is a value the allocator hands out.
         */
        if (track->track_alias == XQC_MOQ_INVALID_ID) {
            xqc_moq_track_set_alias(track, xqc_moq_session_alloc_track_alias(session));
        }
        subscribe_msg->track_alias = track->track_alias;
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
        xqc_moq_track_set_subscribe_id(track, original_subscribe_id);
        xqc_moq_track_set_alias(track, original_track_alias);
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

    if (session->use_unified_setup) {
        if (moq_stream == NULL || !moq_stream->local_request
            || moq_stream->response_received
            || moq_stream->request_type != XQC_MOQ_MSG_SUBSCRIBE)
        {
            xqc_moq_session_error(session, MOQ_PROTOCOL_VIOLATION,
                                  "SUBSCRIBE_OK on invalid request stream");
            return;
        }
        subscribe_ok->subscribe_id = moq_stream->request_id;
        moq_stream->response_received = 1;

        xqc_moq_d18_property_result_t property_result =
            xqc_moq_d18_validate_track_properties(
                subscribe_ok->track_properties,
                subscribe_ok->track_properties_len);
        if (property_result
            == XQC_MOQ_D18_PROPERTY_UNSUPPORTED_EXTENSION)
        {
            xqc_moq_stream_on_request_closed(
                moq_stream, XQC_MOQ_REQUEST_CANCELLED);
            (void)xqc_moq_stream_stop_sending(
                moq_stream, XQC_MOQ_REQUEST_CANCELLED);
            (void)xqc_moq_stream_cancel(
                moq_stream, XQC_MOQ_REQUEST_CANCELLED);
            return;
        }
        if (property_result != XQC_MOQ_D18_PROPERTY_OK) {
            xqc_moq_d18_close_for_track_properties(
                session, property_result,
                "malformed SUBSCRIBE_OK Track Properties",
                "invalid SUBSCRIBE_OK Track Properties");
            return;
        }
    }

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

    if (session->use_unified_setup) {
        if (moq_stream == NULL || moq_stream->local_request
            || moq_stream->peer_request)
        {
            xqc_moq_session_error(session, MOQ_PROTOCOL_VIOLATION,
                                  "invalid PUBLISH_NAMESPACE request stream");
            return;
        }

        if (xqc_moq_session_admit_peer_initial_request(
                session, moq_stream, msg->request_id) != XQC_OK)
        {
            return;
        }

        if (xqc_moq_d18_register_peer_request_id(
                session, msg->request_id, "PUBLISH_NAMESPACE")
            != XQC_OK)
        {
            return;
        }

        moq_stream->peer_request = 1;
        moq_stream->request_type = XQC_MOQ_MSG_PUBLISH_NAMESPACE;
        moq_stream->request_id = msg->request_id;
        xqc_list_add_tail(&moq_stream->request_list_member,
                          &session->peer_request_stream_list);

        if (xqc_moq_d18_apply_request_auth(
                session, moq_stream, moq_stream->request_id,
                msg->params, msg->params_num,
                &msg->request_auth) != XQC_OK)
        {
            return;
        }
        if (xqc_moq_d18_store_peer_initial_params(
                session, moq_stream, msg->params,
                (size_t)msg->params_num) != XQC_OK)
        {
            return;
        }

    } else {
        uint64_t sender_parity =
            xqc_moq_session_is_server(session) ? 0 : 1;
        if ((msg->request_id & 1) != sender_parity) {
            xqc_log(session->log, XQC_LOG_ERROR,
                    "|publish_namespace wrong request_id parity|"
                    "request_id:%ui|expected_parity:%ui|",
                    msg->request_id, sender_parity);
            xqc_moq_session_error(
                session, MOQ_PROTOCOL_VIOLATION,
                "wrong publish_namespace request_id parity");
            return;
        }

        if (xqc_moq_session_find_request_id(session, msg->request_id)) {
            xqc_log(session->log, XQC_LOG_ERROR,
                    "|publish_namespace duplicate request_id|"
                    "request_id:%ui|", msg->request_id);
            xqc_moq_session_error(
                session, MOQ_PROTOCOL_VIOLATION,
                "duplicate publish_namespace request_id");
            return;
        }
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
    ret = xqc_moq_session_bind_advertised_namespace_request(session, 0,
        msg->track_namespace_tuple, msg->track_namespace_num,
        msg->request_id);
    if (ret != XQC_OK) {
        xqc_log(session->log, XQC_LOG_ERROR,
                "|bind peer publish_namespace request failed|ret:%d|", ret);
        xqc_moq_session_error(session, MOQ_INTERNAL_ERROR,
                              "bind publish namespace request");
        return;
    }

    char *ns = xqc_moq_namespace_tuple_join(msg->track_namespace_tuple, msg->track_namespace_num);
    xqc_log(session->log, XQC_LOG_INFO,
            "|publish_namespace|request_id:%ui|namespace_num:%ui|namespace:%s|",
            msg->request_id, msg->track_namespace_num, ns ? ns : "");
    xqc_free(ns);

    if (session->use_unified_setup) {
        xqc_moq_request_ok_msg_t request_ok;
        xqc_memzero(&request_ok, sizeof(request_ok));
        ret = xqc_moq_write_request_ok(session, msg->request_id, &request_ok);
        if (ret != XQC_OK) {
            xqc_log(session->log, XQC_LOG_ERROR,
                    "|write publish_namespace REQUEST_OK failed|request_id:%ui|ret:%d|",
                    msg->request_id, ret);
            xqc_moq_session_error(session, MOQ_INTERNAL_ERROR,
                                  "write publish_namespace REQUEST_OK");
            return;
        }
        xqc_log(session->log, XQC_LOG_INFO,
                "|publish_namespace request accepted|request_id:%ui|",
                msg->request_id);
    }

    if (session->session_callbacks_ext.on_publish_namespace != NULL) {
        session->session_callbacks_ext.on_publish_namespace(session->user_session,
                                                         msg);
    }
}

void
xqc_moq_on_request_ok(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream,
    xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_request_ok_msg_t *msg = (xqc_moq_request_ok_msg_t *)msg_base;
    if (session == NULL || moq_stream == NULL || msg == NULL) {
        return;
    }

    if (((moq_stream->local_request && moq_stream->response_received)
         || (moq_stream->peer_request
             && moq_stream->request_type == XQC_MOQ_MSG_PUBLISH
             && moq_stream->response_sent))
        && xqc_moq_d18_update_queue_peek(
            &moq_stream->d18_local_update_queue) != NULL)
    {
        xqc_moq_d18_update_record_t *record =
            xqc_moq_d18_update_queue_peek(
                &moq_stream->d18_local_update_queue);

        xqc_moq_message_parameter_t *merged = NULL;
        size_t merged_count = 0;
        if (xqc_moq_d18_params_merge(
                moq_stream->d18_accepted_params,
                moq_stream->d18_accepted_params_num,
                record->params, (size_t)record->params_num,
                &merged, &merged_count) != XQC_MOQ_D18_UPDATE_OK)
        {
            xqc_moq_session_error(
                session, XQC_MOQ_D18_INTERNAL_ERROR,
                "merge accepted REQUEST_UPDATE parameters");
            return;
        }

        xqc_moq_message_parameter_t *old_params =
            moq_stream->d18_accepted_params;
        size_t old_params_num = moq_stream->d18_accepted_params_num;
        moq_stream->d18_accepted_params = merged;
        moq_stream->d18_accepted_params_num = merged_count;
        xqc_moq_d18_params_free(old_params, old_params_num);

        if (record->candidate_prefix != NULL
            && moq_stream->request_type
                == XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE)
        {
            xqc_moq_namespace_prefix_t *old_prefix =
                moq_stream->namespace_subscription;
            moq_stream->namespace_subscription =
                record->candidate_prefix;
            record->candidate_prefix = NULL;
            xqc_moq_namespace_prefix_destroy(old_prefix);

        } else if (record->candidate_prefix != NULL
                   && moq_stream->request_type
                       == XQC_MOQ_MSG_SUBSCRIBE_TRACKS)
        {
            xqc_moq_namespace_prefix_t *old_prefix =
                moq_stream->tracks_subscription;
            moq_stream->tracks_subscription =
                record->candidate_prefix;
            record->candidate_prefix = NULL;
            xqc_moq_namespace_prefix_destroy(old_prefix);
        }

        record = xqc_moq_d18_update_queue_pop(
            &moq_stream->d18_local_update_queue);
        uint64_t update_id = record->request_id;
        xqc_moq_d18_update_record_destroy(record);
        if (session->session_callbacks_ext.on_request_ok != NULL) {
            session->session_callbacks_ext.on_request_ok(
                session->user_session, update_id,
                XQC_MOQ_MSG_SUBSCRIBE_UPDATE, msg);
        }
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
    if ((moq_stream->request_type == XQC_MOQ_MSG_PUBLISH_NAMESPACE
         || moq_stream->request_type == XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE)
        && msg->params_num != 0)
    {
        xqc_moq_session_error(session, MOQ_PROTOCOL_VIOLATION,
                              "namespace REQUEST_OK has parameters");
        return;
    }

    xqc_moq_pending_ns_request_t *pending = NULL;
    if (moq_stream->request_type == XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE) {
        pending = xqc_moq_session_consume_pending_ns_request(
            session, moq_stream->request_id);
        if (pending == NULL) {
            xqc_log(session->log, XQC_LOG_ERROR,
                    "|SUBSCRIBE_NAMESPACE REQUEST_OK missing pending state|"
                    "request_id:%ui|",
                    moq_stream->request_id);
            xqc_moq_session_error(
                session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
                "SUBSCRIBE_NAMESPACE REQUEST_OK missing pending state");
            return;
        }
        if (moq_stream->namespace_subscription != NULL) {
            xqc_moq_namespace_tuple_free(
                pending->track_namespace_tuple,
                pending->track_namespace_num);
            xqc_free(pending);
            xqc_moq_session_error(
                session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
                "SUBSCRIBE_NAMESPACE already active");
            return;
        }

        moq_stream->namespace_subscription =
            xqc_moq_namespace_prefix_create_copy(
                pending->track_namespace_tuple,
                pending->track_namespace_num);
        if (moq_stream->namespace_subscription == NULL) {
            xqc_moq_namespace_tuple_free(
                pending->track_namespace_tuple,
                pending->track_namespace_num);
            xqc_free(pending);
            xqc_moq_session_error(
                session, XQC_MOQ_D18_INTERNAL_ERROR,
                "activate SUBSCRIBE_NAMESPACE");
            return;
        }
        moq_stream->namespace_subscription->request_id =
            moq_stream->request_id;
    }

    moq_stream->response_received = 1;
    if (moq_stream->request_type == XQC_MOQ_MSG_SUBSCRIBE_TRACKS
        && moq_stream->tracks_subscription != NULL)
    {
        moq_stream->subscribe_tracks_active = 1;
    }
    xqc_log(session->log, XQC_LOG_INFO,
            "|request_ok|request_id:%ui|request_type:0x%xi|params_num:%ui|",
            moq_stream->request_id, moq_stream->request_type, msg->params_num);
    if (session->session_callbacks_ext.on_request_ok) {
        session->session_callbacks_ext.on_request_ok(session->user_session,
            moq_stream->request_id, moq_stream->request_type, msg);
    }
    if (moq_stream->request_type
            == (xqc_moq_msg_type_t)XQC_MOQ_D18_MSG_TRACK_STATUS
        && session->session_callbacks_ext.on_track_status_ok != NULL)
    {
        session->session_callbacks_ext.on_track_status_ok(
            session->user_session, moq_stream->request_id, msg);
    }

    if (pending != NULL) {
        xqc_moq_subscribe_namespace_ok_msg_t namespace_ok;
        xqc_memzero(&namespace_ok, sizeof(namespace_ok));
        namespace_ok.request_id = moq_stream->request_id;
        namespace_ok.track_namespace_tuple =
            pending->track_namespace_tuple;
        namespace_ok.track_namespace_num =
            pending->track_namespace_num;
        if (session->session_callbacks.on_subscribe_namespace_ok) {
            session->session_callbacks.on_subscribe_namespace_ok(
                session->user_session, &namespace_ok);
        }
        xqc_moq_namespace_tuple_free(
            pending->track_namespace_tuple,
            pending->track_namespace_num);
        xqc_free(pending);
    }

    if (moq_stream->request_type == XQC_MOQ_MSG_PUBLISH
        && session->session_callbacks.on_publish_ok != NULL)
    {
        xqc_moq_publish_ok_msg_t publish_ok;
        xqc_memzero(&publish_ok, sizeof(publish_ok));
        publish_ok.subscribe_id = moq_stream->request_id;
        publish_ok.params_num = msg->params_num;
        publish_ok.params = msg->params;
        for (uint64_t i = 0; i < msg->params_num; i++) {
            const xqc_moq_message_parameter_t *param = &msg->params[i];
            if (!param->is_integer) {
                continue;
            }
            switch (param->type) {
            case XQC_MOQ_D18_PARAM_FORWARD:
                publish_ok.forward = (uint8_t)param->int_value;
                break;
            case XQC_MOQ_D18_PARAM_SUBSCRIBER_PRIORITY:
                publish_ok.subscriber_priority =
                    (uint8_t)param->int_value;
                break;
            case XQC_MOQ_D18_PARAM_GROUP_ORDER:
                publish_ok.group_order = (uint8_t)param->int_value;
                break;
            default:
                break;
            }
        }
        session->session_callbacks.on_publish_ok(
            session->user_session, moq_stream->track, &publish_ok);
    }
}

void
xqc_moq_on_request_error(xqc_moq_session_t *session,
    xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_request_error_msg_t *msg = (xqc_moq_request_error_msg_t *)msg_base;
    if (session == NULL || moq_stream == NULL || msg == NULL) {
        return;
    }

    if (((moq_stream->local_request && moq_stream->response_received)
         || (moq_stream->peer_request
             && moq_stream->request_type == XQC_MOQ_MSG_PUBLISH
             && moq_stream->response_sent))
        && xqc_moq_d18_update_queue_peek(
            &moq_stream->d18_local_update_queue) != NULL)
    {
        xqc_moq_d18_update_record_t *record =
            xqc_moq_d18_update_queue_pop(
                &moq_stream->d18_local_update_queue);
        uint64_t update_id = record->request_id;
        xqc_moq_d18_update_record_destroy(record);
        if (moq_stream->request_type == XQC_MOQ_MSG_SUBSCRIBE
            || moq_stream->request_type == XQC_MOQ_MSG_PUBLISH)
        {
            xqc_int_t done_ret = XQC_OK;
            if ((moq_stream->local_request
                 && moq_stream->request_type == XQC_MOQ_MSG_SUBSCRIBE)
                || (moq_stream->peer_request
                    && moq_stream->request_type == XQC_MOQ_MSG_PUBLISH))
            {
                moq_stream->update_failed_wait_publish_done = 1;
                xqc_moq_d18_update_queue_destroy(
                    &moq_stream->d18_local_update_queue);
                xqc_moq_d18_update_queue_destroy(
                    &moq_stream->d18_peer_update_queue);

            } else if (moq_stream->local_request
                && moq_stream->request_type == XQC_MOQ_MSG_PUBLISH)
            {
                done_ret = xqc_moq_write_d18_update_failed_publish_done(
                    session, moq_stream);
                if (done_ret != XQC_OK
                    && done_ret != -XQC_EAGAIN)
                {
                    xqc_moq_session_error(
                        session, XQC_MOQ_D18_INTERNAL_ERROR,
                        "write UPDATE_FAILED PUBLISH_DONE");
                }
            }
            if (!moq_stream->update_failed_wait_publish_done
                && !moq_stream->d18_publish_done_pending)
            {
                xqc_moq_stream_finish_request(
                    moq_stream, XQC_MOQ_PUBLISH_DONE_UPDATE_FAILED);
            }

        } else if (moq_stream->request_type
                       == XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE
                   || moq_stream->request_type
                       == XQC_MOQ_MSG_SUBSCRIBE_TRACKS
                   || moq_stream->request_type
                       == XQC_MOQ_MSG_PUBLISH_NAMESPACE)
        {
            if (moq_stream->local_request
                && moq_stream->request_type
                    == XQC_MOQ_MSG_SUBSCRIBE_TRACKS)
            {
                xqc_moq_d18_log_rejected_subscribe_tracks_update(
                    session, moq_stream, update_id);
            }
            xqc_moq_stream_finish_request(
                moq_stream, msg->error_code);
        }
        if (session->session_callbacks_ext.on_request_error != NULL) {
            session->session_callbacks_ext.on_request_error(
                session->user_session, update_id,
                XQC_MOQ_MSG_SUBSCRIBE_UPDATE, msg);
        }
        return;
    }

    if (!moq_stream->local_request || moq_stream->response_received) {
        xqc_log(session->log, XQC_LOG_ERROR,
                "|request_error on invalid request stream|local:%d|received:%d|",
                moq_stream->local_request, moq_stream->response_received);
        xqc_moq_session_error(session, MOQ_PROTOCOL_VIOLATION,
                              "REQUEST_ERROR on invalid request stream");
        return;
    }

    xqc_moq_pending_ns_request_t *pending = NULL;
    if (moq_stream->request_type == XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE) {
        pending = xqc_moq_session_consume_pending_ns_request(
            session, moq_stream->request_id);
        if (pending == NULL) {
            xqc_log(session->log, XQC_LOG_ERROR,
                    "|SUBSCRIBE_NAMESPACE REQUEST_ERROR missing pending state|"
                    "request_id:%ui|",
                    moq_stream->request_id);
            xqc_moq_session_error(
                session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
                "SUBSCRIBE_NAMESPACE REQUEST_ERROR missing pending state");
            return;
        }
    }

    moq_stream->response_received = 1;
    xqc_log(session->log, XQC_LOG_INFO,
            "|request_error|request_id:%ui|request_type:0x%xi|error_code:%ui|retry_interval:%ui|reason:%s|",
            moq_stream->request_id, moq_stream->request_type, msg->error_code,
            msg->retry_interval, msg->reason_phrase ? msg->reason_phrase : "");

    xqc_moq_subscribe_t *subscribe = NULL;
    xqc_moq_track_t *track = NULL;
    if (moq_stream->request_type == XQC_MOQ_MSG_SUBSCRIBE) {
        subscribe = xqc_moq_find_subscribe(session, moq_stream->request_id, 1);
        if (subscribe != NULL) {
            track = xqc_moq_find_track_by_subscribe_id(session,
                moq_stream->request_id, XQC_MOQ_TRACK_FOR_SUB);
            if (track == NULL) {
                track = xqc_moq_find_track_by_alias(session,
                    subscribe->subscribe_msg->track_alias, XQC_MOQ_TRACK_FOR_SUB);
            }
        }
    }
    xqc_moq_track_t *publish_track = NULL;
    if (moq_stream->request_type == XQC_MOQ_MSG_PUBLISH) {
        publish_track =
            xqc_moq_stream_finish_publish_request(moq_stream);
    }
    if (moq_stream->request_type == XQC_MOQ_MSG_PUBLISH_NAMESPACE) {
        xqc_moq_stream_finish_request(
            moq_stream, msg->error_code);
    }

    if (session->session_callbacks_ext.on_request_error) {
        session->session_callbacks_ext.on_request_error(session->user_session,
            moq_stream->request_id, moq_stream->request_type, msg);

    } else if (track != NULL && track->track_ops.on_subscribe_error != NULL) {
        xqc_moq_subscribe_error_msg_t subscribe_error;
        xqc_memzero(&subscribe_error, sizeof(subscribe_error));
        subscribe_error.subscribe_id = moq_stream->request_id;
        subscribe_error.error_code = msg->error_code;
        subscribe_error.reason_phrase = msg->reason_phrase;
        subscribe_error.reason_phrase_len = msg->reason_phrase_len;
        track->track_ops.on_subscribe_error(session, track, &subscribe_error);
    }

    if (moq_stream->request_type == XQC_MOQ_MSG_PUBLISH
        && session->session_callbacks.on_publish_error != NULL)
    {
        xqc_moq_publish_error_msg_t publish_error;
        xqc_memzero(&publish_error, sizeof(publish_error));
        publish_error.subscribe_id = moq_stream->request_id;
        publish_error.error_code = msg->error_code;
        publish_error.reason_phrase = msg->reason_phrase;
        publish_error.reason_phrase_len = msg->reason_phrase_len;
        session->session_callbacks.on_publish_error(
            session->user_session, publish_track,
            publish_track != NULL ? &publish_track->track_info : NULL,
            &publish_error);
    }

    if (pending != NULL) {
        xqc_moq_subscribe_namespace_error_msg_t namespace_error;
        xqc_memzero(&namespace_error, sizeof(namespace_error));
        namespace_error.request_id = moq_stream->request_id;
        namespace_error.error_code = msg->error_code;
        namespace_error.reason_phrase = msg->reason_phrase;
        namespace_error.reason_phrase_len = msg->reason_phrase_len;
        namespace_error.track_namespace_tuple =
            pending->track_namespace_tuple;
        namespace_error.track_namespace_num =
            pending->track_namespace_num;
        if (session->session_callbacks.on_subscribe_namespace_error) {
            session->session_callbacks.on_subscribe_namespace_error(
                session->user_session, &namespace_error);
        }
        xqc_moq_namespace_tuple_free(
            pending->track_namespace_tuple,
            pending->track_namespace_num);
        xqc_free(pending);
    }

    if (subscribe != NULL) {
        if (track != NULL) {
            xqc_moq_track_set_subscribe_id(track, XQC_MOQ_INVALID_ID);
            xqc_moq_track_set_alias(track, XQC_MOQ_INVALID_ID);
        }
        xqc_list_del(&subscribe->list_member);
        xqc_moq_subscribe_destroy(subscribe);
        xqc_moq_session_check_drain_complete(session);
    }
    moq_stream->request_closed_notified = 1;

}

static xqc_int_t
xqc_moq_namespace_response_stream_valid(xqc_moq_session_t *session,
    xqc_moq_stream_t *moq_stream)
{
    if (moq_stream != NULL && moq_stream->local_request
        && moq_stream->request_type == XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE
        && moq_stream->response_received
        && moq_stream->namespace_subscription != NULL)
    {
        return 1;
    }

    xqc_moq_session_error(
        session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
        "NAMESPACE before REQUEST_OK");
    return 0;
}

static xqc_moq_track_ns_field_t *
xqc_moq_namespace_full_tuple_from_suffix(
    xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream,
    xqc_moq_d18_namespace_msg_t *msg, uint64_t *full_num)
{
    xqc_moq_namespace_prefix_t *subscription =
        moq_stream->namespace_subscription;
    if (subscription->prefix_num
            > XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS
                - msg->track_namespace_suffix_num
        || subscription->prefix_num
                + msg->track_namespace_suffix_num == 0)
    {
        xqc_moq_session_error(
            session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
            "invalid NAMESPACE suffix");
        return NULL;
    }

    *full_num = subscription->prefix_num
        + msg->track_namespace_suffix_num;
    xqc_moq_track_ns_field_t *full =
        xqc_moq_namespace_tuple_concat(
            subscription->prefix_tuple, subscription->prefix_num,
            msg->track_namespace_suffix_tuple,
            msg->track_namespace_suffix_num);
    if (full == NULL) {
        xqc_moq_session_error(
            session, XQC_MOQ_D18_INTERNAL_ERROR,
            "reconstruct NAMESPACE");
    }
    return full;
}

void
xqc_moq_on_namespace(xqc_moq_session_t *session,
    xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_d18_namespace_msg_t *msg =
        (xqc_moq_d18_namespace_msg_t *)msg_base;
    if (session == NULL || msg == NULL
        || !xqc_moq_namespace_response_stream_valid(
            session, moq_stream))
    {
        return;
    }

    uint64_t full_num = 0;
    xqc_moq_track_ns_field_t *full =
        xqc_moq_namespace_full_tuple_from_suffix(
            session, moq_stream, msg, &full_num);
    if (full == NULL) {
        return;
    }

    xqc_moq_namespace_prefix_t *subscription =
        moq_stream->namespace_subscription;
    if (xqc_moq_namespace_prefix_find_advertised(
            subscription, full, full_num) != NULL)
    {
        xqc_moq_namespace_tuple_free(full, full_num);
        return;
    }

    xqc_int_t ret = xqc_moq_namespace_prefix_add_advertised(
        subscription, full, full_num);
    if (ret != XQC_OK) {
        xqc_moq_namespace_tuple_free(full, full_num);
        xqc_moq_session_error(
            session, XQC_MOQ_D18_INTERNAL_ERROR,
            "record NAMESPACE");
        return;
    }

    if (session->session_callbacks_ext.on_namespace != NULL) {
        session->session_callbacks_ext.on_namespace(
            session->user_session, moq_stream->request_id,
            full, full_num);
    }
    xqc_moq_namespace_tuple_free(full, full_num);
}

void
xqc_moq_on_namespace_done(xqc_moq_session_t *session,
    xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_d18_namespace_msg_t *msg =
        (xqc_moq_d18_namespace_msg_t *)msg_base;
    if (session == NULL || msg == NULL
        || !xqc_moq_namespace_response_stream_valid(
            session, moq_stream))
    {
        return;
    }

    uint64_t full_num = 0;
    xqc_moq_track_ns_field_t *full =
        xqc_moq_namespace_full_tuple_from_suffix(
            session, moq_stream, msg, &full_num);
    if (full == NULL) {
        return;
    }

    xqc_moq_namespace_prefix_t *subscription =
        moq_stream->namespace_subscription;
    xqc_moq_namespace_advertisement_t *active =
        xqc_moq_namespace_prefix_find_advertised(
            subscription, full, full_num);
    if (active == NULL) {
        xqc_moq_namespace_tuple_free(full, full_num);
        xqc_moq_session_error(
            session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
            "NAMESPACE_DONE before NAMESPACE");
        return;
    }

    xqc_list_del_init(&active->list_member);
    if (session->session_callbacks_ext.on_namespace_done != NULL) {
        session->session_callbacks_ext.on_namespace_done(
            session->user_session, moq_stream->request_id,
            active->track_namespace_tuple,
            active->track_namespace_num);
    }
    xqc_moq_namespace_advertisement_destroy(active);
    xqc_moq_namespace_tuple_free(full, full_num);
}

void
xqc_moq_on_publish_namespace_done(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_publish_namespace_done_msg_t *msg = (xqc_moq_publish_namespace_done_msg_t*)msg_base;
    if (session == NULL || msg == NULL) {
        return;
    }

    if (session->use_unified_setup) {
        if (moq_stream != session->peer_ctl_stream) {
            xqc_moq_session_error(session, MOQ_PROTOCOL_VIOLATION,
                                  "PUBLISH_NAMESPACE_DONE on request stream");
            return;
        }

        xqc_list_head_t *pos;
        xqc_list_for_each(pos, &session->peer_request_stream_list) {
            xqc_moq_stream_t *request_stream =
                xqc_list_entry(pos, xqc_moq_stream_t, request_list_member);
            if (request_stream->request_type != XQC_MOQ_MSG_PUBLISH_NAMESPACE
                || request_stream->request_id != msg->request_id)
            {
                continue;
            }

            xqc_log(session->log, XQC_LOG_WARN,
                    "|legacy publish_namespace_done accepted|request_id:%ui|",
                    msg->request_id);
            xqc_moq_stream_on_request_closed(request_stream,
                                             XQC_MOQ_REQUEST_CANCELLED);
            xqc_moq_stream_cancel(request_stream, XQC_MOQ_REQUEST_CANCELLED);
            return;
        }
        xqc_moq_session_error(session, MOQ_PROTOCOL_VIOLATION,
                              "unknown PUBLISH_NAMESPACE_DONE request ID");
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
    if (session == NULL || publish == NULL) {
        return;
    }
    if (session->use_unified_setup) {
        if (moq_stream == NULL || moq_stream->local_request
            || moq_stream->peer_request)
        {
            xqc_moq_session_error(
                session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
                "invalid PUBLISH request stream");
            return;
        }
        if (xqc_moq_session_admit_peer_initial_request(
                session, moq_stream, publish->subscribe_id) != XQC_OK)
        {
            return;
        }
        if (xqc_moq_d18_register_peer_request_id(
                session, publish->subscribe_id, "PUBLISH") != XQC_OK)
        {
            return;
        }
        moq_stream->peer_request = 1;
        moq_stream->request_type = XQC_MOQ_MSG_PUBLISH;
        moq_stream->request_id = publish->subscribe_id;
        xqc_list_add_tail(&moq_stream->request_list_member,
                          &session->peer_request_stream_list);
        if (xqc_moq_d18_apply_request_auth(
                session, moq_stream, moq_stream->request_id,
                publish->params,
                publish->params_num,
                &publish->request_auth) != XQC_OK)
        {
            return;
        }
        if (xqc_moq_d18_store_peer_initial_params(
                session, moq_stream, publish->params,
                (size_t)publish->params_num) != XQC_OK)
        {
            return;
        }

        xqc_moq_d18_property_result_t property_result =
            xqc_moq_d18_validate_track_properties(
                publish->track_properties,
                publish->track_properties_len);
        if (property_result
            == XQC_MOQ_D18_PROPERTY_UNSUPPORTED_EXTENSION)
        {
            xqc_moq_request_error_msg_t error;
            xqc_memzero(&error, sizeof(error));
            error.error_code =
                XQC_MOQ_REQUEST_ERROR_UNSUPPORTED_EXTENSION;
            error.reason_phrase = "unsupported Track Property";
            error.reason_phrase_len = strlen(error.reason_phrase);
            if (xqc_moq_write_request_error(
                    session, publish->subscribe_id, &error) != XQC_OK)
            {
                xqc_moq_session_error(
                    session, XQC_MOQ_D18_INTERNAL_ERROR,
                    "write unsupported PUBLISH Property error");
            }
            return;
        }
        if (property_result != XQC_MOQ_D18_PROPERTY_OK) {
            xqc_moq_d18_close_for_track_properties(
                session, property_result,
                "malformed PUBLISH Track Properties",
                "invalid PUBLISH Track Properties");
            return;
        }

        xqc_moq_track_t *alias_owner =
            xqc_moq_find_track_by_alias(
                session, publish->track_alias,
                XQC_MOQ_TRACK_FOR_SUB);
        xqc_moq_track_t *named_track =
            xqc_moq_find_track_by_ns_tuple(
                session, publish->track_namespace_tuple,
                publish->track_namespace_num, publish->track_name,
                XQC_MOQ_TRACK_FOR_SUB);
        if (alias_owner != NULL && alias_owner != named_track) {
            xqc_moq_session_error(
                session, XQC_MOQ_D18_DUPLICATE_TRACK_ALIAS,
                "duplicate PUBLISH track alias");
            return;
        }
    }

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
        if (session->use_unified_setup) {
            xqc_moq_publish_send_error(
                session, track, publish->subscribe_id,
                XQC_MOQ_REQUEST_ERROR_DUPLICATE_SUBSCRIPTION,
                "duplicate subscription");
            goto clean_up;
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

    subscribe->subscribe_msg->filter_type = selected_params.filter_type;
    subscribe->subscribe_msg->start_group_id = selected_params.start_group_id;
    subscribe->subscribe_msg->start_object_id = selected_params.start_object_id;
    subscribe->subscribe_msg->end_group_id = selected_params.end_group_id;
    subscribe->subscribe_msg->end_object_id = selected_params.end_object_id;
    subscribe->subscribe_msg->forward = selected_params.forward;
    subscribe->subscribe_msg->group_order = selected_params.group_order;

    if (session->use_unified_setup) {
        moq_stream->track = track;

    } else {
        xqc_moq_track_set_alias(track, publish->track_alias);
        xqc_moq_track_set_subscribe_id(
            track, publish->subscribe_id);
    }

    if (session->session_callbacks.on_publish) {
        session->session_callbacks.on_publish(session->user_session, track, publish);
    }
    goto clean_up;

clean_up:
    xqc_free(pub_ns_joined);
    if (track_created && track != NULL
        && track->subscribe_id == XQC_MOQ_INVALID_ID
        && (!session->use_unified_setup
            || moq_stream == NULL || moq_stream->track != track))
    {
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
    xqc_int_t is_d18 = session != NULL
        && session->use_unified_setup;

    if (is_d18) {
        xqc_int_t valid_stream = moq_stream != NULL
            && !moq_stream->request_closed_notified
            && moq_stream->d18_context.direction
                == XQC_MOQ_D18_DIRECTION_BIDI
            && moq_stream->d18_context.stream_class
                == XQC_MOQ_D18_STREAM_REQUEST
            && moq_stream->d18_context.position
                == XQC_MOQ_D18_POSITION_NEXT
            && ((moq_stream->request_type == XQC_MOQ_MSG_PUBLISH
                 && moq_stream->peer_request
                 && moq_stream->response_sent)
                || (moq_stream->request_type == XQC_MOQ_MSG_SUBSCRIBE
                    && moq_stream->local_request
                    && moq_stream->response_received));
        if (!valid_stream) {
            xqc_moq_session_error(
                session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
                "duplicate or invalid PUBLISH_DONE");
            return;
        }
        publish_done->subscribe_id = moq_stream->request_id;
    }

    subscribe = xqc_moq_find_subscribe(session, publish_done->subscribe_id, 1);
    if (subscribe == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|publish_done subscribe not found|subscribe_id:%ui|",
                publish_done->subscribe_id);
        if (is_d18) {
            xqc_moq_session_error(
                session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
                "PUBLISH_DONE subscription not found");
        }
        return;
    }

    track = moq_stream != NULL ? moq_stream->track : NULL;
    if (track == NULL || track->track_role != XQC_MOQ_TRACK_FOR_SUB) {
        track = xqc_moq_find_track_by_alias(
            session, subscribe->subscribe_msg->track_alias,
            XQC_MOQ_TRACK_FOR_SUB);
    }
    if (is_d18 && track == NULL) {
        xqc_moq_session_error(
            session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
            "PUBLISH_DONE track not found");
        return;
    }
    if (is_d18) {
        xqc_bool_t exact_stream_count =
            publish_done->stream_count
                != XQC_MOQ_PUBLISH_DONE_UNKNOWN_STREAM_COUNT;
        if (exact_stream_count
            && publish_done->stream_count
                < track->recv_streams_opened)
        {
            xqc_moq_session_error(
                session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
                "PUBLISH_DONE Stream Count below opened streams");
            return;
        }
        track->streams_count = publish_done->stream_count;
        track->publish_done_stream_count_exact = exact_stream_count;
        track->publish_done_received = 1;
    }
    if (session->use_unified_setup && moq_stream != NULL) {
        xqc_moq_stream_finish_request(
            moq_stream, publish_done->status_code);
        if (moq_stream->request_closed_notified) {
            subscribe = NULL;
        }
    }
    if (track) {
        char *done_ns = xqc_moq_namespace_tuple_join(track->track_info.track_namespace_tuple, track->track_info.track_namespace_num);
        xqc_log(session->log, XQC_LOG_INFO,
                "|on_publish_done|subscribe_id:%ui|track:%s/%s|status:%ui|streams:%ui|reason:%s|",
                publish_done->subscribe_id, done_ns ? done_ns : "null", track->track_info.track_name,
                publish_done->status_code, publish_done->stream_count,
                publish_done->reason_phrase ? publish_done->reason_phrase : "null");
        xqc_free(done_ns);
        if (session->session_callbacks.on_publish_done) {
            xqc_moq_session_callback_enter(session);
            session->session_callbacks.on_publish_done(session->user_session, track, publish_done);
            xqc_moq_session_callback_leave(session);
        }
        if (moq_stream != NULL && moq_stream->track == track) {
            moq_stream->track = NULL;
        }
        if (!is_d18
            || xqc_moq_track_publish_done_recv_complete(track))
        {
            xqc_moq_track_set_alias(track, XQC_MOQ_INVALID_ID);
            xqc_moq_track_set_subscribe_id(
                track, XQC_MOQ_INVALID_ID);
            xqc_list_del(&track->list_member);
            xqc_moq_track_destroy(track);
        }
    } else {
        xqc_log(session->log, XQC_LOG_INFO,
                "|on_publish_done no track|subscribe_id:%ui|status:%ui|streams:%ui|",
                publish_done->subscribe_id, publish_done->status_code, publish_done->stream_count);
    }

    if (subscribe != NULL) {
        xqc_list_del(&subscribe->list_member);
        xqc_moq_subscribe_destroy(subscribe);
    }
    xqc_moq_session_check_drain_complete(session);
    xqc_moq_session_destroy_if_pending(session);
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

    track = xqc_moq_find_track_by_alias(
        session, object->track_alias, XQC_MOQ_TRACK_FOR_SUB);
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

    track = moq_stream != NULL && moq_stream->track != NULL
            && moq_stream->track->publish_done_received
        ? moq_stream->track : NULL;
    if (track == NULL) {
        track = xqc_moq_find_track_by_alias(
            session, object->track_alias, XQC_MOQ_TRACK_FOR_SUB);
    }
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
        if (xqc_moq_track_on_recv_object(
                track, moq_stream, object) != XQC_OK)
        {
            return;
        }
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
    object.forwarding_preference = XQC_MOQ_FORWARDING_OBJECT;
    xqc_moq_on_object(session, moq_stream, &object);
}

void
xqc_moq_on_subgroup(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_subgroup_msg_t *msg = (xqc_moq_subgroup_msg_t*)msg_base;
    if (xqc_moq_on_subgroup_header(session, moq_stream, msg_base)
        != XQC_OK)
    {
        return;
    }
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
    xqc_stream_t *quic_stream = moq_stream->trans_ops.quic_stream(moq_stream->trans_stream);
    xqc_int_t stream_id = quic_stream ? quic_stream->stream_id : 0;
    xqc_log(session->log, XQC_LOG_INFO,
            "|server_recv_subgroup|subscribe_id:%ui|track_alias:%ui|group_id:%ui|subgroup_id:%ui|object_id:%ui|object_id_delta:%ui|stream_id:%llu|",
            object.subscribe_id, object.track_alias, object.group_id,
            object.subgroup_id, object.object_id, msg->object_id_delta, stream_id);

    xqc_moq_on_object(session, moq_stream, &object);
}

xqc_int_t
xqc_moq_on_subgroup_header(xqc_moq_session_t *session,
    xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    if (session == NULL || moq_stream == NULL || msg_base == NULL) {
        return -XQC_EPARAM;
    }
    xqc_moq_subgroup_msg_t *msg =
        (xqc_moq_subgroup_msg_t *)msg_base;

    moq_stream->subgroup_header.track_alias = msg->track_alias;
    moq_stream->subgroup_header.group_id = msg->group_id;
    moq_stream->subgroup_header.subgroup_id = msg->subgroup_id;
    moq_stream->subgroup_header.subgroup_type = msg->subgroup_type;
    moq_stream->subgroup_header.subgroup_priority =
        msg->subgroup_priority;
    moq_stream->subgroup_header_valid = 1;

    xqc_moq_track_t *track = moq_stream->track;
    if (track == NULL) {
        track = xqc_moq_find_track_by_alias(
            session, msg->track_alias, XQC_MOQ_TRACK_FOR_SUB);
    }
    if (track == NULL) {
        return XQC_OK;
    }
    return xqc_moq_track_on_recv_stream(
        track, moq_stream, msg->group_id, 0, msg->subgroup_id);
}

void
xqc_moq_on_track_stream_obj(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_track_stream_obj_msg_t *msg = (xqc_moq_track_stream_obj_msg_t*)msg_base;
    msg->track_header = moq_stream->track_header;
    xqc_moq_object_t object;
    xqc_moq_msg_set_object_by_track(&object, &msg->track_header, msg);
    object.forwarding_preference = XQC_MOQ_FORWARDING_TRACK;
    xqc_moq_on_object(session, moq_stream, &object);
}

void
xqc_moq_on_track_header(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_stream_header_track_msg_t *track_header = (xqc_moq_stream_header_track_msg_t*)msg_base;
    moq_stream->track_header = *track_header;
    moq_stream->track_header_valid = 1;
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
xqc_moq_on_goaway_draft18(xqc_moq_session_t *session,
    xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_d18_goaway_msg_t *goaway =
        (xqc_moq_d18_goaway_msg_t *)msg_base;
    if (session == NULL || moq_stream == NULL || goaway == NULL) {
        return;
    }
    if (!session->session_setup_done
        || !session->use_unified_setup)
    {
        xqc_moq_session_error(
            session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
            "GOAWAY before draft-18 session setup");
        return;
    }

    xqc_int_t control_scope =
        moq_stream == session->peer_ctl_stream
        && moq_stream->d18_context.direction
            == XQC_MOQ_D18_DIRECTION_UNI
        && moq_stream->d18_context.stream_class
            == XQC_MOQ_D18_STREAM_CONTROL
        && moq_stream->d18_context.position
            == XQC_MOQ_D18_POSITION_NEXT;
    xqc_int_t request_scope =
        moq_stream->d18_context.direction
            == XQC_MOQ_D18_DIRECTION_BIDI
        && moq_stream->d18_context.stream_class
            == XQC_MOQ_D18_STREAM_REQUEST
        && moq_stream->d18_context.position
            == XQC_MOQ_D18_POSITION_NEXT
        && ((moq_stream->local_request && moq_stream->response_received)
            || (moq_stream->peer_request && moq_stream->response_sent));
    if ((!control_scope && !request_scope)
        || (control_scope && !goaway->has_request_id)
        || (request_scope && goaway->has_request_id))
    {
        xqc_moq_session_error(
            session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
            "invalid draft-18 GOAWAY scope");
        return;
    }
    if (goaway->new_session_uri_len > XQC_MOQ_MAX_GOAWAY_URI_LEN
        || (goaway->new_session_uri_len > 0
            && goaway->new_session_uri == NULL))
    {
        xqc_moq_session_error(
            session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
            "invalid draft-18 GOAWAY URI");
        return;
    }
    if (session->d18_request_registry.local_is_server
        && goaway->new_session_uri_len > 0)
    {
        xqc_moq_session_error(
            session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
            "client GOAWAY must have empty URI");
        return;
    }

    if (control_scope) {
        if (session->d18_control_goaway_received) {
            xqc_moq_session_error(
                session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
                "duplicate control GOAWAY");
            return;
        }
        uint64_t local_parity =
            session->d18_request_registry.local_is_server ? 1 : 0;
        if ((goaway->request_id & 1) != local_parity) {
            xqc_moq_session_error(
                session, XQC_MOQ_D18_INVALID_REQUEST_ID,
                "invalid GOAWAY Request ID parity");
            return;
        }
    } else if (moq_stream->d18_goaway_received) {
        xqc_moq_session_error(
            session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
            "duplicate request GOAWAY");
        return;
    }

    xqc_moq_on_goaway_draft18_pt extended =
        session->on_goaway_draft18;
    xqc_moq_on_goaway_pt legacy =
        control_scope ? session->session_callbacks.on_goaway : NULL;
    xqc_moq_user_session_t *user_session = session->user_session;
    size_t callback_uri_len = goaway->new_session_uri_len;
    uint64_t callback_timeout_ms = goaway->timeout_ms;

    char *uri_copy = NULL;
    char *callback_uri = NULL;
    if (callback_uri_len > 0) {
        uri_copy = xqc_calloc(1, callback_uri_len + 1);
        if (uri_copy == NULL) {
            xqc_moq_session_error(
                session, XQC_MOQ_D18_INTERNAL_ERROR,
                "store draft-18 GOAWAY URI");
            return;
        }
        xqc_memcpy(uri_copy, goaway->new_session_uri,
                   callback_uri_len);
        if (extended != NULL || legacy != NULL) {
            callback_uri = xqc_calloc(1, callback_uri_len + 1);
            if (callback_uri == NULL) {
                xqc_free(uri_copy);
                xqc_moq_session_error(
                    session, XQC_MOQ_D18_INTERNAL_ERROR,
                    "copy draft-18 GOAWAY callback URI");
                return;
            }
            xqc_memcpy(callback_uri, goaway->new_session_uri,
                       callback_uri_len);
        }
    }

    xqc_moq_goaway_scope_t scope;
    uint64_t target_request_id;
    uint64_t cutoff;
    if (control_scope) {
        xqc_free(session->goaway_new_session_uri);
        session->goaway_new_session_uri = uri_copy;
        session->goaway_new_session_uri_len =
            goaway->new_session_uri_len;
        session->d18_control_goaway_received = 1;
        session->d18_control_goaway_received_cutoff =
            goaway->request_id;
        session->d18_control_goaway_received_timeout_ms =
            goaway->timeout_ms;
        session->goaway_received = 1;
        scope = XQC_MOQ_GOAWAY_SCOPE_CONTROL;
        target_request_id = XQC_MOQ_INVALID_ID;
        cutoff = goaway->request_id;
    } else {
        xqc_free(moq_stream->d18_goaway_uri);
        moq_stream->d18_goaway_uri = uri_copy;
        moq_stream->d18_goaway_uri_len =
            goaway->new_session_uri_len;
        moq_stream->d18_goaway_received = 1;
        moq_stream->d18_peer_goaway_timeout_ms =
            goaway->timeout_ms;
        scope = XQC_MOQ_GOAWAY_SCOPE_REQUEST;
        target_request_id = moq_stream->request_id;
        cutoff = XQC_MOQ_INVALID_ID;
    }

    if (extended != NULL) {
        extended(user_session, scope, target_request_id,
                 callback_uri, callback_uri_len,
                 callback_timeout_ms, cutoff);
    }
    if (legacy != NULL) {
        legacy(user_session, callback_uri, callback_uri_len);
    }
    xqc_free(callback_uri);
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
xqc_moq_on_subscribe_tracks(xqc_moq_session_t *session,
    xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_subscribe_tracks_msg_t *msg =
        (xqc_moq_subscribe_tracks_msg_t *)msg_base;
    if (session == NULL || moq_stream == NULL || msg == NULL) {
        return;
    }
    if (!session->use_unified_setup
        || moq_stream->local_request || moq_stream->peer_request)
    {
        xqc_moq_session_error(
            session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
            "invalid SUBSCRIBE_TRACKS request stream");
        return;
    }
    if (xqc_moq_session_admit_peer_initial_request(
            session, moq_stream, msg->request_id) != XQC_OK)
    {
        return;
    }
    if (msg->track_namespace_num > XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS
        || (msg->track_namespace_num > 0
            && msg->track_namespace_tuple == NULL))
    {
        xqc_moq_session_error(
            session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
            "invalid SUBSCRIBE_TRACKS prefix");
        return;
    }
    if (xqc_moq_d18_register_peer_request_id(
            session, msg->request_id, "SUBSCRIBE_TRACKS") != XQC_OK)
    {
        return;
    }

    moq_stream->peer_request = 1;
    moq_stream->request_type = XQC_MOQ_MSG_SUBSCRIBE_TRACKS;
    moq_stream->request_id = msg->request_id;
    xqc_list_add_tail(&moq_stream->request_list_member,
                      &session->peer_request_stream_list);

    if (xqc_moq_d18_apply_request_auth(
            session, moq_stream, moq_stream->request_id,
            msg->params, msg->params_num,
            &msg->request_auth) != XQC_OK)
    {
        return;
    }
    if (xqc_moq_d18_store_peer_initial_params(
            session, moq_stream, msg->params,
            (size_t)msg->params_num) != XQC_OK)
    {
        return;
    }

    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &session->peer_request_stream_list) {
        xqc_moq_stream_t *active =
            xqc_list_entry(pos, xqc_moq_stream_t, request_list_member);
        if (active == moq_stream || !active->peer_request
            || active->request_type != XQC_MOQ_MSG_SUBSCRIBE_TRACKS
            || !active->subscribe_tracks_active
            || active->tracks_subscription == NULL)
        {
            continue;
        }
        if (xqc_moq_namespace_tuple_overlaps(
                active->tracks_subscription->prefix_tuple,
                active->tracks_subscription->prefix_num,
                msg->track_namespace_tuple,
                msg->track_namespace_num))
        {
            xqc_moq_request_error_msg_t error;
            xqc_memzero(&error, sizeof(error));
            error.error_code =
                XQC_MOQ_REQUEST_ERROR_PREFIX_OVERLAP;
            error.reason_phrase =
                "track namespace prefix overlap";
            error.reason_phrase_len =
                strlen(error.reason_phrase);
            xqc_int_t ret = xqc_moq_write_request_error(
                session, msg->request_id, &error);
            if (ret != XQC_OK) {
                xqc_moq_session_error(
                    session, XQC_MOQ_D18_INTERNAL_ERROR,
                    "write SUBSCRIBE_TRACKS overlap");
            }
            return;
        }
    }

    moq_stream->tracks_subscription =
        xqc_moq_namespace_prefix_create_copy(
            msg->track_namespace_tuple,
            msg->track_namespace_num);
    if (moq_stream->tracks_subscription == NULL) {
        xqc_moq_session_error(
            session, XQC_MOQ_D18_INTERNAL_ERROR,
            "store SUBSCRIBE_TRACKS prefix");
        return;
    }
    moq_stream->tracks_subscription->request_id = msg->request_id;
    moq_stream->subscribe_tracks_forward = 1;
    for (uint64_t i = 0; i < msg->params_num; i++) {
        if (msg->params[i].type == XQC_MOQ_D18_PARAM_FORWARD) {
            moq_stream->subscribe_tracks_forward =
                xqc_moq_param_read_u8(&msg->params[i]) ? 1 : 0;
            break;
        }
    }

    if (session->session_callbacks_ext.on_subscribe_tracks != NULL) {
        session->session_callbacks_ext.on_subscribe_tracks(
            session->user_session, msg);
        return;
    }

    xqc_moq_request_ok_msg_t ok;
    xqc_memzero(&ok, sizeof(ok));
    if (xqc_moq_write_request_ok(
            session, msg->request_id, &ok) != XQC_OK)
    {
        xqc_moq_session_error(
            session, XQC_MOQ_D18_INTERNAL_ERROR,
            "write SUBSCRIBE_TRACKS REQUEST_OK");
    }
}

void
xqc_moq_on_subscribe_namespace(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_subscribe_namespace_msg_t *msg = (xqc_moq_subscribe_namespace_msg_t*)msg_base;
    if (session == NULL || msg == NULL) {
        return;
    }

    if (session->use_unified_setup) {
        if (moq_stream == NULL || moq_stream->local_request
            || moq_stream->peer_request)
        {
            xqc_moq_session_error(
                session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
                "invalid SUBSCRIBE_NAMESPACE request stream");
            return;
        }

        if (xqc_moq_session_admit_peer_initial_request(
                session, moq_stream, msg->request_id) != XQC_OK)
        {
            return;
        }

        if (xqc_moq_d18_register_peer_request_id(
                session, msg->request_id, "SUBSCRIBE_NAMESPACE")
            != XQC_OK)
        {
            return;
        }

        moq_stream->peer_request = 1;
        moq_stream->request_type = XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE;
        moq_stream->request_id = msg->request_id;
        xqc_list_add_tail(&moq_stream->request_list_member,
                          &session->peer_request_stream_list);

        if (xqc_moq_d18_apply_request_auth(
                session, moq_stream, moq_stream->request_id,
                msg->params, msg->params_num,
                &msg->request_auth) != XQC_OK)
        {
            return;
        }
        if (xqc_moq_d18_store_peer_initial_params(
                session, moq_stream, msg->params,
                (size_t)msg->params_num) != XQC_OK)
        {
            return;
        }

    } else {
        uint64_t sender_parity =
            xqc_moq_session_is_server(session) ? 0 : 1;
        if ((msg->request_id & 1) != sender_parity) {
            xqc_log(session->log, XQC_LOG_ERROR,
                    "|subscribe_namespace wrong request_id parity|"
                    "request_id:%ui|expected_parity:%ui|",
                    msg->request_id, sender_parity);
            xqc_moq_session_error(
                session, MOQ_PROTOCOL_VIOLATION,
                "wrong request_id parity");
            return;
        }
    }

    if (msg->track_namespace_num > XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS
        || (msg->track_namespace_num > 0
            && msg->track_namespace_tuple == NULL)
        || (!session->use_unified_setup
            && msg->track_namespace_num == 0))
    {
        xqc_log(session->log, XQC_LOG_ERROR,
                "|subscribe_namespace invalid prefix|"
                "request_id:%ui|prefix_num:%ui|",
                msg->request_id, msg->track_namespace_num);
        xqc_moq_session_error(session, MOQ_PROTOCOL_VIOLATION, "subscribe namespace invalid prefix");
        return;
    }

    if (!session->use_unified_setup
        && xqc_moq_session_find_request_id(session, msg->request_id))
    {
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
        err.error_code = session->use_unified_setup
            ? XQC_MOQ_REQUEST_ERROR_PREFIX_OVERLAP
            : XQC_MOQ_SUBSCRIBE_NAMESPACE_ERR_PREFIX_OVERLAP;
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
void
xqc_moq_on_setup(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream,
    xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_setup_msg_t *setup = (xqc_moq_setup_msg_t *)msg_base;
    if (!session->use_unified_setup || session->session_setup_done
        || (session->peer_ctl_stream && session->peer_ctl_stream != moq_stream))
    {
        xqc_moq_session_error(session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
                              "invalid draft-18 SETUP");
        return;
    }

    xqc_moq_d18_setup_sender_t sender =
        xqc_moq_session_is_server(session)
        ? XQC_MOQ_D18_SETUP_SENDER_CLIENT
        : XQC_MOQ_D18_SETUP_SENDER_SERVER;
    xqc_moq_d18_setup_transport_t transport =
        session->transport_type == XQC_MOQ_TRANSPORT_QUIC
        ? XQC_MOQ_D18_SETUP_TRANSPORT_NATIVE_QUIC
        : XQC_MOQ_D18_SETUP_TRANSPORT_WEBTRANSPORT;
    xqc_moq_d18_setup_result_t setup_ret =
        xqc_moq_d18_setup_options_validate(&setup->decoded_options,
                                            sender, transport);
    if (setup_ret == XQC_MOQ_D18_SETUP_OK
        && sender == XQC_MOQ_D18_SETUP_SENDER_CLIENT
        && !setup->decoded_options.path.present)
    {
        setup_ret = XQC_MOQ_D18_SETUP_INVALID_PATH;
    }
    if (setup_ret == XQC_MOQ_D18_SETUP_OK
        && sender == XQC_MOQ_D18_SETUP_SENDER_CLIENT
        && !setup->decoded_options.authority.present)
    {
        setup_ret = XQC_MOQ_D18_SETUP_INVALID_AUTHORITY;
    }
    if (setup_ret != XQC_MOQ_D18_SETUP_OK) {
        uint64_t error =
            xqc_moq_d18_setup_result_session_error(setup_ret);
        xqc_moq_session_error(session, error,
                              "invalid draft-18 SETUP option");
        return;
    }

    uint64_t auth_error = xqc_moq_session_process_peer_setup_auth(
        session, &setup->decoded_options,
        xqc_moq_session_is_server(session) ? 1 : 0);
    if (auth_error != XQC_MOQ_D18_NO_ERROR) {
        xqc_moq_session_error(session, auth_error,
                              "invalid draft-18 SETUP authorization token");
        return;
    }

    if (xqc_moq_session_store_peer_setup_options(
            session, &setup->decoded_options) != XQC_OK)
    {
        xqc_moq_session_error(session, XQC_MOQ_D18_INTERNAL_ERROR,
                              "store draft-18 SETUP options");
        return;
    }

    session->peer_ctl_stream = moq_stream;
    uint64_t wire_version = session->profile->wire_version;
    if (xqc_moq_session_negotiate_version(
            session, &wire_version, 1) != XQC_OK)
    {
        xqc_moq_session_error(session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
                              "activate draft-18 profile");
        return;
    }
    session->session_setup_done = 1;
    xqc_log(session->log, XQC_LOG_INFO, "|setup_complete|options_len:%ui|",
            setup->options_len);
    xqc_moq_session_on_setup(session, NULL, NULL, 0);
    if (!session->destroying && !session->destroy_pending) {
        xqc_int_t resume_ret =
            xqc_moq_session_resume_deferred_streams(session);
        if (resume_ret != XQC_OK
            && session->quic_conn != NULL
            && (session->quic_conn->conn_flag & XQC_CONN_FLAG_ERROR) == 0)
        {
            xqc_moq_session_error(session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
                                  "resume deferred draft-18 stream");
        }
    }
}

static xqc_int_t
xqc_moq_d18_begin_peer_track_request(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, uint64_t request_id,
    xqc_moq_msg_type_t request_type, const char *name,
    const xqc_moq_message_parameter_t *params, uint64_t params_num,
    xqc_moq_request_auth_t *request_auth)
{
    if (session == NULL || stream == NULL || !session->use_unified_setup
        || stream->local_request || stream->peer_request)
    {
        if (session != NULL) {
            xqc_moq_session_error(session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
                                  "invalid draft-18 request stream");
        }
        return -XQC_EPROTO;
    }
    if (xqc_moq_session_admit_peer_initial_request(
            session, stream, request_id) != XQC_OK
        || xqc_moq_d18_register_peer_request_id(
            session, request_id, name) != XQC_OK)
    {
        return -XQC_EPROTO;
    }
    stream->peer_request = 1;
    stream->request_type = request_type;
    stream->request_id = request_id;
    xqc_list_add_tail(&stream->request_list_member,
                      &session->peer_request_stream_list);
    if (xqc_moq_d18_apply_request_auth(
            session, stream, request_id, params, params_num,
            request_auth) != XQC_OK
        || xqc_moq_d18_store_peer_initial_params(
            session, stream, params, (size_t)params_num) != XQC_OK)
    {
        return -XQC_EPROTO;
    }
    return XQC_OK;
}

static void
xqc_moq_d18_reject_unhandled_track_request(xqc_moq_session_t *session,
    uint64_t request_id, const char *reason)
{
    xqc_moq_request_error_msg_t error;
    xqc_memzero(&error, sizeof(error));
    error.error_code = XQC_MOQ_REQUEST_ERROR_NOT_SUPPORTED;
    error.reason_phrase = (char *)reason;
    error.reason_phrase_len = strlen(reason);
    if (xqc_moq_write_request_error(session, request_id, &error) != XQC_OK) {
        xqc_moq_session_error(session, XQC_MOQ_D18_INTERNAL_ERROR,
                              "write NOT_SUPPORTED REQUEST_ERROR");
    }
}

static xqc_moq_stream_t *
xqc_moq_d18_find_peer_subscription_request(xqc_moq_session_t *session,
    uint64_t request_id)
{
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &session->peer_request_stream_list) {
        xqc_moq_stream_t *stream = xqc_list_entry(
            pos, xqc_moq_stream_t, request_list_member);
        if (stream->peer_request && !stream->request_closed_notified
            && stream->request_type == XQC_MOQ_MSG_SUBSCRIBE
            && stream->request_id == request_id)
        {
            return stream;
        }
    }
    return NULL;
}

static uint8_t
xqc_moq_d18_peer_subscription_forward(const xqc_moq_stream_t *stream)
{
    for (size_t i = 0; i < stream->d18_accepted_params_num; i++) {
        if (stream->d18_accepted_params[i].type
            == XQC_MOQ_D18_PARAM_FORWARD)
        {
            return stream->d18_accepted_params[i].int_value ? 1 : 0;
        }
    }
    return 1;
}

static void
xqc_moq_d18_reject_fetch(xqc_moq_session_t *session, uint64_t request_id,
    uint64_t error_code, const char *reason)
{
    xqc_moq_request_error_msg_t error;
    xqc_memzero(&error, sizeof(error));
    error.error_code = error_code;
    error.reason_phrase = (char *)reason;
    error.reason_phrase_len = strlen(reason);
    if (xqc_moq_write_request_error(session, request_id, &error) != XQC_OK) {
        xqc_moq_session_error(session, XQC_MOQ_D18_INTERNAL_ERROR,
                              "write FETCH REQUEST_ERROR");
    }
}

void
xqc_moq_on_fetch(xqc_moq_session_t *session,
    xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_fetch_msg_t *msg = (xqc_moq_fetch_msg_t *)msg_base;
    if (msg == NULL || xqc_moq_d18_begin_peer_track_request(
            session, moq_stream, msg->request_id, XQC_MOQ_MSG_FETCH,
            "FETCH", msg->params, msg->params_num,
            &msg->request_auth) != XQC_OK)
    {
        return;
    }
    moq_stream->d18_fetch_type = (uint8_t)msg->fetch_type;
    moq_stream->d18_fetch_group_order =
        xqc_moq_d18_group_order_from_params(
            msg->params, (size_t)msg->params_num);
    if (msg->fetch_type == XQC_MOQ_FETCH_STANDALONE) {
        moq_stream->d18_fetch_start_group_id = msg->start_group_id;
        moq_stream->d18_fetch_start_object_id = msg->start_object_id;
    } else if (msg->fetch_type == XQC_MOQ_FETCH_JOINING_ABSOLUTE) {
        moq_stream->d18_fetch_start_group_id = msg->joining_start;
        moq_stream->d18_fetch_start_object_id = 0;
    }
    if (msg->fetch_type == XQC_MOQ_FETCH_STANDALONE) {
        if (msg->end_group_id < msg->start_group_id
            || (msg->end_group_id == msg->start_group_id
                && msg->end_object_id < msg->start_object_id))
        {
            xqc_moq_d18_reject_fetch(
                session, msg->request_id,
                XQC_MOQ_REQUEST_ERROR_INVALID_RANGE,
                "FETCH end before start");
            return;
        }

    } else {
        xqc_moq_stream_t *subscription =
            xqc_moq_d18_find_peer_subscription_request(
                session, msg->joining_request_id);
        if (subscription == NULL) {
            xqc_moq_d18_reject_fetch(
                session, msg->request_id,
                XQC_MOQ_REQUEST_ERROR_INVALID_JOINING_REQUEST_ID,
                "invalid joining request id");
            return;
        }
        if (!xqc_moq_d18_peer_subscription_forward(subscription)) {
            xqc_moq_d18_reject_fetch(
                session, msg->request_id,
                XQC_MOQ_REQUEST_ERROR_INVALID_RANGE,
                "joining subscription has Forward 0");
            return;
        }
    }
    if (session->session_callbacks_ext.on_fetch != NULL) {
        session->session_callbacks_ext.on_fetch(session->user_session, msg);
        return;
    }
    xqc_moq_d18_reject_unhandled_track_request(
        session, msg->request_id, "FETCH not supported");
}

void
xqc_moq_on_track_status(xqc_moq_session_t *session,
    xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_track_status_msg_t *msg =
        (xqc_moq_track_status_msg_t *)msg_base;
    if (msg == NULL || xqc_moq_d18_begin_peer_track_request(
            session, moq_stream, msg->request_id,
            (xqc_moq_msg_type_t)XQC_MOQ_D18_MSG_TRACK_STATUS,
            "TRACK_STATUS", msg->params, msg->params_num,
            &msg->request_auth) != XQC_OK)
    {
        return;
    }
    if (session->session_callbacks_ext.on_track_status != NULL) {
        session->session_callbacks_ext.on_track_status(
            session->user_session, msg);
        return;
    }
    xqc_moq_d18_reject_unhandled_track_request(
        session, msg->request_id, "TRACK_STATUS not supported");
}

void
xqc_moq_on_fetch_ok(xqc_moq_session_t *session,
    xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_fetch_ok_msg_t *msg = (xqc_moq_fetch_ok_msg_t *)msg_base;
    if (session == NULL || moq_stream == NULL || msg == NULL
        || !moq_stream->local_request || moq_stream->response_received
        || moq_stream->request_type != XQC_MOQ_MSG_FETCH)
    {
        if (session != NULL) {
            xqc_moq_session_error(session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
                                  "unexpected FETCH_OK");
        }
        return;
    }
    if ((moq_stream->d18_fetch_type == XQC_MOQ_FETCH_STANDALONE
         || moq_stream->d18_fetch_type
             == XQC_MOQ_FETCH_JOINING_ABSOLUTE)
        && (msg->end_group_id < moq_stream->d18_fetch_start_group_id
            || (msg->end_group_id
                    == moq_stream->d18_fetch_start_group_id
                && msg->end_object_id
                    < moq_stream->d18_fetch_start_object_id)))
    {
        xqc_moq_session_error(session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
                              "FETCH_OK end before start");
        return;
    }
    moq_stream->response_received = 1;
    xqc_log(session->log, XQC_LOG_INFO,
            "|fetch_ok|request_id:%ui|end_of_track:%d|end_group:%ui|end_object:%ui|",
            moq_stream->request_id, msg->end_of_track,
            msg->end_group_id, msg->end_object_id);
    if (session->session_callbacks_ext.on_fetch_ok != NULL) {
        session->session_callbacks_ext.on_fetch_ok(
            session->user_session, moq_stream->request_id, msg);
    }
}

void
xqc_moq_on_fetch_header(xqc_moq_session_t *session,
    xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_fetch_header_msg_t *msg =
        (xqc_moq_fetch_header_msg_t *)msg_base;
    if (session == NULL || moq_stream == NULL || msg == NULL) {
        return;
    }

    xqc_moq_stream_t *request_stream = NULL;
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &session->local_request_stream_list) {
        xqc_moq_stream_t *candidate = xqc_list_entry(
            pos, xqc_moq_stream_t, request_list_member);
        if (candidate->local_request
            && candidate->request_type == XQC_MOQ_MSG_FETCH
            && candidate->request_id == msg->request_id
            && !candidate->request_closed_notified)
        {
            request_stream = candidate;
            break;
        }
    }
    if (request_stream == NULL || request_stream->fetch_data_stream != NULL
        || moq_stream->fetch_request_stream != NULL)
    {
        xqc_moq_session_error(session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
                              "invalid FETCH_HEADER request id");
        return;
    }

    request_stream->fetch_data_stream = moq_stream;
    moq_stream->fetch_request_stream = request_stream;
    moq_stream->request_id = msg->request_id;
    moq_stream->request_type = XQC_MOQ_MSG_FETCH;
    moq_stream->d18_fetch_group_order =
        request_stream->d18_fetch_group_order;
    if (session->session_callbacks_ext.on_fetch_header != NULL) {
        session->session_callbacks_ext.on_fetch_header(
            session->user_session, msg->request_id, msg->fin_received);
    }
    if (msg->fin_received) {
        request_stream->fetch_data_stream = NULL;
        moq_stream->fetch_request_stream = NULL;
        xqc_moq_stream_finish_request(request_stream, XQC_OK);
    }
}
