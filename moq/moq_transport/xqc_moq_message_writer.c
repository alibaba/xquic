
#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_transport/xqc_moq_subscribe.h"
#include "moq/moq_transport/xqc_moq_namespace.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_control.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_data.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_update.h"
#include "src/common/xqc_time.h"
#include "src/transport/xqc_conn.h"

static xqc_int_t xqc_moq_d18_stream_has_local_publisher(
    const xqc_moq_stream_t *request_stream);
static xqc_moq_stream_t *xqc_moq_find_d18_publish_done_stream(
    xqc_moq_session_t *session, uint64_t request_id);
static xqc_int_t xqc_moq_write_d18_publish_done_on_stream(
    xqc_moq_session_t *session, xqc_moq_stream_t *request_stream,
    const xqc_moq_publish_done_msg_t *publish_done);
static xqc_moq_stream_t *xqc_moq_find_request_response_target(
    xqc_moq_session_t *session, uint64_t request_id,
    xqc_int_t *is_update, xqc_int_t *is_initial);
static xqc_int_t xqc_moq_write_initial_track_request(
    xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_msg_base_t *base, xqc_moq_semantic_id_t semantic,
    xqc_moq_msg_type_t request_type, uint64_t request_id,
    const xqc_moq_message_parameter_t *params, size_t params_num);

static void *
xqc_moq_write_buf_realloc(xqc_moq_stream_t *stream, void *ptr, size_t size)
{
    if (stream->write_buf_realloc != NULL) {
        return stream->write_buf_realloc(ptr, size);
    }
    return xqc_realloc(ptr, size);
}

static xqc_int_t
xqc_moq_register_local_request_id(xqc_moq_session_t *session,
    uint64_t request_id)
{
    xqc_moq_d18_request_id_result_t ret =
        xqc_moq_session_register_local_request_id(session, request_id);
    if (ret == XQC_MOQ_D18_REQUEST_ID_OK) {
        return XQC_OK;
    }
    return ret == XQC_MOQ_D18_REQUEST_ID_NO_MEMORY
        ? -XQC_EMALLOC : -XQC_EPARAM;
}

static xqc_int_t
xqc_moq_d18_store_local_initial_params(xqc_moq_stream_t *stream,
    const xqc_moq_message_parameter_t *params, size_t params_num)
{
    xqc_moq_message_parameter_t *copy = NULL;
    xqc_moq_d18_update_result_t ret =
        xqc_moq_d18_params_clone(params, params_num, &copy);
    if (ret != XQC_MOQ_D18_UPDATE_OK) {
        return ret == XQC_MOQ_D18_UPDATE_NO_MEMORY
            ? -XQC_EMALLOC : -XQC_EPARAM;
    }
    stream->d18_accepted_params = copy;
    stream->d18_accepted_params_num = params_num;
    return XQC_OK;
}

static xqc_int_t
xqc_moq_writer_require(xqc_moq_session_t *session,
    xqc_moq_capability_t capability)
{
    if (session == NULL) {
        return -XQC_EPARAM;
    }

    xqc_int_t ret = xqc_moq_session_require_active(session);
    if (ret != XQC_OK) {
        return ret;
    }

    return xqc_moq_profile_require(session->profile, capability);
}

xqc_int_t
xqc_moq_msg_write_internal(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, xqc_moq_msg_base_t *msg_base,
    xqc_bool_t atomic_write)
{
    xqc_int_t encode_len = 0;
    xqc_int_t ret = 0;
    
    if (session == NULL || stream == NULL || msg_base == NULL) {
        return -XQC_EPARAM;
    }

    encode_len = msg_base->encode_len(msg_base);
    if (encode_len < 0) {
        return encode_len;
    }
    if (encode_len > XQC_MOQ_MAX_OBJECT_LEN) {
        return -XQC_ELIMIT;
    }

    size_t new_write_buf_cap;
    xqc_int_t reset_write_buffer;

    /* Last send not finished */
    if (stream->write_buf_processed != stream->write_buf_len) {
        if ((size_t)encode_len > SIZE_MAX - stream->write_buf_cap) {
            return -XQC_ELIMIT;
        }
        new_write_buf_cap = stream->write_buf_cap + (size_t)encode_len;
        reset_write_buffer = 0;
    } else {
        new_write_buf_cap = (size_t)encode_len;
        reset_write_buffer = 1;
    }

    uint8_t *old_write_buf = stream->write_buf;
    size_t old_write_buf_cap = stream->write_buf_cap;
    size_t old_write_buf_len = stream->write_buf_len;
    size_t old_write_buf_processed = stream->write_buf_processed;
    uint8_t *new_write_buf;
    if (atomic_write) {
        new_write_buf = xqc_moq_write_buf_realloc(
            stream, NULL, new_write_buf_cap);
        if (new_write_buf != NULL && !reset_write_buffer) {
            xqc_memcpy(new_write_buf, old_write_buf, old_write_buf_len);
        }

    } else {
        new_write_buf = xqc_moq_write_buf_realloc(
            stream, old_write_buf, new_write_buf_cap);
    }
    if (new_write_buf == NULL) {
        return -XQC_EMALLOC;
    }
    stream->write_buf = new_write_buf;
    stream->write_buf_cap = new_write_buf_cap;
    if (reset_write_buffer) {
        stream->write_buf_processed = 0;
        stream->write_buf_len = 0;
    }

    ret = msg_base->encode(msg_base, stream->write_buf + stream->write_buf_len, stream->write_buf_cap - stream->write_buf_len);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|encode msg error|ret:%d|", ret);
        if (atomic_write) {
            xqc_free(stream->write_buf);
            stream->write_buf = old_write_buf;
            stream->write_buf_cap = old_write_buf_cap;
            stream->write_buf_len = old_write_buf_len;
            stream->write_buf_processed = old_write_buf_processed;
        }
        return ret;
    }
    stream->write_buf_len += ret;

    ret = xqc_moq_stream_write(stream);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_stream_write error|ret:%d|msg_type:0x%xi|", ret, msg_base->type());
        if (atomic_write) {
            xqc_free(stream->write_buf);
            stream->write_buf = old_write_buf;
            stream->write_buf_cap = old_write_buf_cap;
            stream->write_buf_len = old_write_buf_len;
            stream->write_buf_processed = old_write_buf_processed;
        }
        return ret;
    }
    if (atomic_write) {
        xqc_free(old_write_buf);
    }
    return XQC_OK;
}

xqc_int_t
xqc_moq_msg_write(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_msg_base_t *msg_base)
{
    return xqc_moq_msg_write_internal(
        session, stream, msg_base, XQC_FALSE);
}

static xqc_int_t
xqc_moq_write_profile_message_internal(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, xqc_moq_msg_base_t *msg_base,
    xqc_moq_semantic_id_t semantic, xqc_bool_t atomic_write)
{
    xqc_moq_message_resolution_t resolution;
    xqc_int_t ret;

    if (session == NULL || stream == NULL || msg_base == NULL
        || session->profile == NULL)
    {
        return -XQC_EPARAM;
    }

    if (semantic == XQC_MOQ_SEMANTIC_SETUP
        || semantic == XQC_MOQ_SEMANTIC_CLIENT_SETUP
        || semantic == XQC_MOQ_SEMANTIC_SERVER_SETUP)
    {
        if (session->profile_state != XQC_MOQ_PROFILE_ALPN_SELECTED
            && session->profile_state != XQC_MOQ_PROFILE_ACTIVE)
        {
            return -XQC_EVERSION;
        }

    } else {
        ret = xqc_moq_session_require_active(session);
        if (ret != XQC_OK) {
            return ret;
        }
    }

    xqc_moq_d18_stream_context_t resolver_d18_context =
        stream->d18_context;
    if (session->profile->unified_setup
        && stream->d18_context_pending)
    {
        resolver_d18_context = stream->d18_pending_context;
        xqc_moq_d18_stream_commit_message(&resolver_d18_context);
    }

    xqc_moq_stream_kind_t resolver_kind = stream->kind;
    if (session->profile->unified_setup) {
        switch (resolver_d18_context.stream_class) {
        case XQC_MOQ_D18_STREAM_CONTROL:
            resolver_kind = XQC_MOQ_STREAM_CONTROL;
            break;
        case XQC_MOQ_D18_STREAM_REQUEST:
            resolver_kind = XQC_MOQ_STREAM_D18_REQUEST;
            break;
        case XQC_MOQ_D18_STREAM_SUBGROUP:
            resolver_kind = XQC_MOQ_STREAM_D18_SUBGROUP;
            break;
        case XQC_MOQ_D18_STREAM_FETCH:
            resolver_kind = XQC_MOQ_STREAM_D18_FETCH;
            break;
        case XQC_MOQ_D18_STREAM_UNCLASSIFIED:
        default:
            resolver_kind = XQC_MOQ_STREAM_UNKNOWN;
            break;
        }
    }

    ret = xqc_moq_profile_resolve_outbound(
        session->profile, resolver_kind, semantic, &resolution);
    if (ret != XQC_OK) {
        return ret;
    }

    xqc_moq_d18_stream_context_t next_d18_context;
    xqc_bool_t commit_d18_context = XQC_FALSE;
    if (session->profile->unified_setup) {
        xqc_moq_d18_message_desc_t desc;
        next_d18_context = resolver_d18_context;
        ret = xqc_moq_d18_stream_resolve(
            &next_d18_context, resolution.wire_type, &desc);
        if (ret != XQC_MOQ_D18_REGISTRY_OK) {
            return -XQC_EILLEGAL_FRAME;
        }
        xqc_moq_d18_stream_commit_message(&next_d18_context);
        commit_d18_context = semantic != XQC_MOQ_SEMANTIC_SETUP;
    }

    resolution.codec->initialize(msg_base);
    if (semantic != XQC_MOQ_SEMANTIC_SETUP
        && semantic != XQC_MOQ_SEMANTIC_CLIENT_SETUP
        && semantic != XQC_MOQ_SEMANTIC_SERVER_SETUP)
    {
        ret = xqc_moq_profile_prepare_data_message(
            stream, resolution.codec, msg_base);
        if (ret != XQC_OK) {
            return ret;
        }
    }
    ret = xqc_moq_msg_write_internal(
        session, stream, msg_base, atomic_write);
    if (ret == XQC_OK) {
        stream->kind = resolution.stream_kind;
        if (commit_d18_context) {
            stream->d18_context = next_d18_context;
        }
    }
    return ret;
}

static xqc_int_t
xqc_moq_write_profile_message(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, xqc_moq_msg_base_t *msg_base,
    xqc_moq_semantic_id_t semantic)
{
    return xqc_moq_write_profile_message_internal(
        session, stream, msg_base, semantic, XQC_FALSE);
}

xqc_int_t
xqc_moq_write_msg_generic(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_msg_base_t *msg_base, xqc_moq_semantic_id_t semantic)
{
    if (msg_base == NULL) {
        return -XQC_EPARAM;
    }

    return xqc_moq_write_profile_message(session, stream, msg_base, semantic);
}

static xqc_int_t
xqc_moq_write_msg_generic_atomic(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, xqc_moq_msg_base_t *msg_base,
    xqc_moq_semantic_id_t semantic)
{
    if (msg_base == NULL) {
        return -XQC_EPARAM;
    }
    return xqc_moq_write_profile_message_internal(
        session, stream, msg_base, semantic, XQC_TRUE);
}

xqc_int_t
xqc_moq_write_client_setup(xqc_moq_session_t *session, xqc_moq_client_setup_msg_t *client_setup)
{
    return xqc_moq_write_msg_generic(session, session->ctl_stream, &client_setup->msg_base,
                                     XQC_MOQ_SEMANTIC_CLIENT_SETUP);
}

xqc_int_t
xqc_moq_write_client_setup_v14(xqc_moq_session_t *session, xqc_moq_client_setup_v14_msg_t *client_setup,
    xqc_moq_message_parameter_t *params, uint64_t params_num)
{
    if (client_setup && params && params_num > 0) {
        client_setup->params = params;
        client_setup->params_num = params_num;
    }
    return xqc_moq_write_msg_generic(session, session->ctl_stream, &client_setup->msg_base,
                                     XQC_MOQ_SEMANTIC_CLIENT_SETUP);
}

xqc_int_t
xqc_moq_write_client_setup_for_profile(xqc_moq_session_t *session,
    const xqc_moq_message_parameter_t *params, uint64_t params_num)
{
    xqc_moq_client_setup_msg_t client_setup;
    uint64_t versions[1];

    if (session == NULL || session->profile == NULL) {
        return -XQC_EPARAM;
    }

    xqc_memzero(&client_setup, sizeof(client_setup));
    versions[0] = session->profile->wire_version;
    client_setup.versions_num = 1;
    client_setup.versions = versions;
    client_setup.params = (xqc_moq_message_parameter_t *)params;
    client_setup.params_num = params_num;

    return xqc_moq_write_profile_message(
        session, session->ctl_stream, &client_setup.msg_base,
        XQC_MOQ_SEMANTIC_CLIENT_SETUP);
}

xqc_int_t
xqc_moq_write_server_setup(xqc_moq_session_t *session, xqc_moq_server_setup_msg_t *server_setup)
{
    return xqc_moq_write_msg_generic(session, session->ctl_stream, &server_setup->msg_base,
                                     XQC_MOQ_SEMANTIC_SERVER_SETUP);
}

xqc_int_t
xqc_moq_write_server_setup_v14(xqc_moq_session_t *session, xqc_moq_server_setup_v14_msg_t *server_setup)
{
    return xqc_moq_write_msg_generic(session, session->ctl_stream, &server_setup->msg_base,
                                     XQC_MOQ_SEMANTIC_SERVER_SETUP);
}

xqc_int_t
xqc_moq_write_setup(xqc_moq_session_t *session, xqc_moq_setup_msg_t *setup)
{
    if (session == NULL || setup == NULL || session->ctl_stream == NULL
        || !session->use_unified_setup)
    {
        return -XQC_EPARAM;
    }
    session->ctl_stream->d18_setup_write_pending = 1;
    xqc_int_t ret = xqc_moq_write_profile_message_internal(
        session, session->ctl_stream, &setup->msg_base,
        XQC_MOQ_SEMANTIC_SETUP, XQC_TRUE);
    if (ret != XQC_OK) {
        session->ctl_stream->d18_setup_write_pending = 0;
    }
    return ret;
}

xqc_int_t
xqc_moq_write_server_setup_for_profile(xqc_moq_session_t *session,
    const xqc_moq_message_parameter_t *params, uint64_t params_num)
{
    xqc_moq_server_setup_msg_t server_setup;

    if (session == NULL || session->profile == NULL) {
        return -XQC_EPARAM;
    }

    xqc_memzero(&server_setup, sizeof(server_setup));
    server_setup.version = session->profile->wire_version;
    server_setup.params = (xqc_moq_message_parameter_t *)params;
    server_setup.params_num = params_num;

    return xqc_moq_write_profile_message(
        session, session->ctl_stream, &server_setup.msg_base,
        XQC_MOQ_SEMANTIC_SERVER_SETUP);
}

xqc_int_t
xqc_moq_write_subscribe(xqc_moq_session_t *session, xqc_moq_subscribe_msg_t *subscribe)
{
    if (session == NULL || subscribe == NULL) {
        return -XQC_EPARAM;
    }

    xqc_int_t ret = xqc_moq_validate_full_track_name_for_write(session,
        subscribe->track_namespace_num, subscribe->track_namespace_tuple,
        subscribe->track_name, subscribe->track_name_len);
    if (ret != XQC_OK) {
        return ret;
    }

    if (session->use_unified_setup) {
        xqc_moq_stream_t *request_stream =
            xqc_moq_stream_create_with_transport(session, XQC_STREAM_BIDI);
        if (request_stream == NULL) {
            return -XQC_EMALLOC;
        }

        ret = xqc_moq_write_initial_track_request(
            session, request_stream, &subscribe->msg_base,
            XQC_MOQ_SEMANTIC_SUBSCRIBE, XQC_MOQ_MSG_SUBSCRIBE,
            subscribe->subscribe_id, subscribe->params,
            (size_t)subscribe->params_num);
        if (ret != XQC_OK) {
            xqc_moq_stream_close(request_stream);
        }
        return ret;
    }

    return xqc_moq_write_msg_generic(session, session->ctl_stream, &subscribe->msg_base,
                                     XQC_MOQ_SEMANTIC_SUBSCRIBE);
}

xqc_int_t
xqc_moq_write_subscribe_update(xqc_moq_session_t *session, xqc_moq_subscribe_update_msg_t *update)
{
    return xqc_moq_write_msg_generic(session, session->ctl_stream, &update->msg_base,
                                     XQC_MOQ_SEMANTIC_SUBSCRIBE_UPDATE);
}

xqc_int_t
xqc_moq_write_unsubscribe(xqc_moq_session_t *session, xqc_moq_unsubscribe_msg_t *unsubscribe)
{
    return xqc_moq_write_msg_generic(session, session->ctl_stream, &unsubscribe->msg_base,
                                     XQC_MOQ_SEMANTIC_UNSUBSCRIBE);
}

xqc_int_t
xqc_moq_write_subscribe_ok(xqc_moq_session_t *session, xqc_moq_subscribe_ok_msg_t *subscribe_ok)
{
    if (session == NULL || subscribe_ok == NULL) {
        return -XQC_EPARAM;
    }

    if (session->use_unified_setup) {
        xqc_int_t is_update = 0;
        xqc_int_t is_initial = 0;
        xqc_moq_stream_t *request_stream =
            xqc_moq_find_request_response_target(
                session, subscribe_ok->subscribe_id,
                &is_update, &is_initial);
        if (request_stream == NULL || !is_initial || is_update
            || request_stream->request_type != XQC_MOQ_MSG_SUBSCRIBE
            || request_stream->response_sent)
        {
            return -XQC_EPARAM;
        }

        xqc_int_t ret = xqc_moq_write_msg_generic(
            session, request_stream, &subscribe_ok->msg_base,
            XQC_MOQ_SEMANTIC_SUBSCRIBE_OK);
        if (ret == XQC_OK) {
            request_stream->response_sent = 1;
        }
        return ret;
    }

    return xqc_moq_write_msg_generic(session, session->ctl_stream, &subscribe_ok->msg_base,
                                     XQC_MOQ_SEMANTIC_SUBSCRIBE_OK);
}

xqc_int_t
xqc_moq_write_subscribe_error(xqc_moq_session_t *session, xqc_moq_subscribe_error_msg_t *subscribe_error)
{
    if (session == NULL || subscribe_error == NULL) {
        return -XQC_EPARAM;
    }

    if (session->use_unified_setup) {
        xqc_moq_request_error_msg_t request_error;
        xqc_memzero(&request_error, sizeof(request_error));
        request_error.error_code = subscribe_error->error_code;
        request_error.reason_phrase = subscribe_error->reason_phrase;
        request_error.reason_phrase_len = subscribe_error->reason_phrase_len;
        if (request_error.reason_phrase_len == 0
            && request_error.reason_phrase != NULL)
        {
            request_error.reason_phrase_len =
                strlen(request_error.reason_phrase);
        }
        return xqc_moq_write_request_error(
            session, subscribe_error->subscribe_id, &request_error);
    }

    return xqc_moq_write_msg_generic(session, session->ctl_stream, &subscribe_error->msg_base,
                                     XQC_MOQ_SEMANTIC_SUBSCRIBE_ERROR);
}

xqc_int_t
xqc_moq_write_publish(xqc_moq_session_t *session, xqc_moq_publish_msg_t *publish)
{
    if (session == NULL || publish == NULL) {
        return -XQC_EPARAM;
    }

    xqc_int_t ret = xqc_moq_writer_require(session, XQC_MOQ_CAP_PUBLISH);
    if (ret != XQC_OK) {
        return ret;
    }

    ret = xqc_moq_validate_full_track_name_for_write(session,
        publish->track_namespace_num, publish->track_namespace_tuple,
        publish->track_name, publish->track_name_len);
    if (ret != XQC_OK) {
        return ret;
    }

    if (session->use_unified_setup) {
        if (xqc_moq_session_admit_local_initial_request(session) != XQC_OK) {
            return -XQC_EPARAM;
        }

        xqc_moq_message_resolution_t resolution;
        ret = xqc_moq_profile_resolve_outbound(
            session->profile, XQC_MOQ_STREAM_UNKNOWN,
            XQC_MOQ_SEMANTIC_PUBLISH, &resolution);
        if (ret != XQC_OK || resolution.codec == NULL
            || resolution.codec->initialize == NULL)
        {
            return ret != XQC_OK ? ret : -XQC_EALPN_NOT_SUPPORTED;
        }
        resolution.codec->initialize(&publish->msg_base);
        ret = publish->msg_base.encode_len(&publish->msg_base);
        if (ret < 0) {
            return ret;
        }

        xqc_moq_track_t *track = xqc_moq_find_track_by_subscribe_id(
            session, publish->subscribe_id, XQC_MOQ_TRACK_FOR_PUB);
        if (track == NULL) {
            return -XQC_ENULLPTR;
        }

        xqc_moq_stream_t *request_stream =
            xqc_moq_stream_create_with_transport(session, XQC_STREAM_BIDI);
        if (request_stream == NULL) {
            return -XQC_EMALLOC;
        }
        request_stream->local_request = 1;
        request_stream->request_type = XQC_MOQ_MSG_PUBLISH;
        request_stream->request_id = publish->subscribe_id;
        request_stream->track = track;

        ret = xqc_moq_d18_store_local_initial_params(
            request_stream, publish->params, (size_t)publish->params_num);
        if (ret != XQC_OK) {
            request_stream->track = NULL;
            xqc_moq_stream_close(request_stream);
            return ret;
        }
        ret = xqc_moq_register_local_request_id(
            session, publish->subscribe_id);
        if (ret != XQC_OK) {
            request_stream->track = NULL;
            xqc_moq_stream_close(request_stream);
            return ret;
        }
        xqc_list_add_tail(&request_stream->request_list_member,
                          &session->local_request_stream_list);

        ret = xqc_moq_write_msg_generic(
            session, request_stream, &publish->msg_base,
            XQC_MOQ_SEMANTIC_PUBLISH);
        if (ret != XQC_OK) {
            xqc_list_del_init(&request_stream->request_list_member);
            request_stream->track = NULL;
            xqc_moq_stream_close(request_stream);
        }
        return ret;
    }

    return xqc_moq_write_msg_generic(session, session->ctl_stream, &publish->msg_base,
                                     XQC_MOQ_SEMANTIC_PUBLISH);
}

static xqc_int_t
xqc_moq_publish_ok_add_integer_param(
    xqc_moq_message_parameter_t *params, size_t *params_num,
    uint64_t type, uint64_t value)
{
    for (size_t i = 0; i < *params_num; i++) {
        if (params[i].type == type) {
            return XQC_OK;
        }
    }
    if (*params_num >= XQC_MOQ_MAX_PARAMS) {
        return -XQC_ELIMIT;
    }

    xqc_moq_message_parameter_t *param = &params[*params_num];
    xqc_memzero(param, sizeof(*param));
    param->type = type;
    param->is_integer = 1;
    param->int_value = value;
    (*params_num)++;
    return XQC_OK;
}

xqc_int_t
xqc_moq_write_publish_ok(xqc_moq_session_t *session, xqc_moq_publish_ok_msg_t *publish_ok)
{
    if (session == NULL || publish_ok == NULL) {
        return -XQC_EPARAM;
    }

    xqc_int_t ret = xqc_moq_writer_require(session, XQC_MOQ_CAP_PUBLISH);
    if (ret != XQC_OK) {
        return ret;
    }

    if (session->use_unified_setup) {
        if (publish_ok->params_num > XQC_MOQ_MAX_PARAMS
            || (publish_ok->params_num != 0 && publish_ok->params == NULL))
        {
            return publish_ok->params_num > XQC_MOQ_MAX_PARAMS
                ? -XQC_ELIMIT : -XQC_EPARAM;
        }

        xqc_moq_message_parameter_t params[XQC_MOQ_MAX_PARAMS];
        size_t params_num = (size_t)publish_ok->params_num;
        if (params_num != 0) {
            xqc_memcpy(params, publish_ok->params,
                       params_num * sizeof(params[0]));
        }
        ret = xqc_moq_publish_ok_add_integer_param(
            params, &params_num, XQC_MOQ_D18_PARAM_FORWARD,
            publish_ok->forward);
        if (ret == XQC_OK) {
            ret = xqc_moq_publish_ok_add_integer_param(
                params, &params_num,
                XQC_MOQ_D18_PARAM_SUBSCRIBER_PRIORITY,
                publish_ok->subscriber_priority);
        }
        if (ret == XQC_OK) {
            ret = xqc_moq_publish_ok_add_integer_param(
                params, &params_num, XQC_MOQ_D18_PARAM_GROUP_ORDER,
                publish_ok->group_order);
        }
        if (ret != XQC_OK) {
            return ret;
        }

        xqc_moq_request_ok_msg_t request_ok;
        xqc_memzero(&request_ok, sizeof(request_ok));
        request_ok.params_num = params_num;
        request_ok.params = params;
        return xqc_moq_write_request_ok(
            session, publish_ok->subscribe_id, &request_ok);
    }

    return xqc_moq_write_msg_generic(
        session, session->ctl_stream, &publish_ok->msg_base,
        XQC_MOQ_SEMANTIC_PUBLISH_OK);
}

xqc_int_t
xqc_moq_write_publish_error(xqc_moq_session_t *session, xqc_moq_publish_error_msg_t *publish_error)
{
    if (session == NULL || publish_error == NULL) {
        return -XQC_EPARAM;
    }

    xqc_int_t ret = xqc_moq_writer_require(session, XQC_MOQ_CAP_PUBLISH);
    if (ret != XQC_OK) {
        return ret;
    }

    if (session->use_unified_setup) {
        xqc_moq_request_error_msg_t request_error;
        xqc_memzero(&request_error, sizeof(request_error));
        request_error.error_code = publish_error->error_code;
        request_error.reason_phrase = publish_error->reason_phrase;
        request_error.reason_phrase_len =
            publish_error->reason_phrase_len;
        return xqc_moq_write_request_error(
            session, publish_error->subscribe_id, &request_error);
    }

    return xqc_moq_write_msg_generic(
        session, session->ctl_stream, &publish_error->msg_base,
        XQC_MOQ_SEMANTIC_PUBLISH_ERROR);
}

xqc_int_t
xqc_moq_write_publish_done(xqc_moq_session_t *session, xqc_moq_publish_done_msg_t *publish_done)
{
    if (session == NULL || publish_done == NULL) {
        return -XQC_EPARAM;
    }

    xqc_int_t ret = xqc_moq_writer_require(session, XQC_MOQ_CAP_PUBLISH);
    if (ret != XQC_OK) {
        return ret;
    }

    if (session->use_unified_setup) {
        xqc_moq_stream_t *request_stream =
            xqc_moq_find_d18_publish_done_stream(
                session, publish_done->subscribe_id);
        if (request_stream == NULL) {
            return -XQC_ENULLPTR;
        }
        return xqc_moq_write_d18_publish_done_on_stream(
            session, request_stream, publish_done);
    }

    if (publish_done->stream_count == 0) {
        xqc_moq_track_t *track = xqc_moq_find_track_by_subscribe_id(session,
            publish_done->subscribe_id, XQC_MOQ_TRACK_FOR_PUB);
        if (track && track->streams_count > 0) {
            publish_done->stream_count = track->streams_count;
        } else {
            publish_done->stream_count = ((uint64_t)1 << 62) - 1;
        }
    }

    return xqc_moq_write_msg_generic(session, session->ctl_stream, &publish_done->msg_base,
                                     XQC_MOQ_SEMANTIC_PUBLISH_DONE);
}

static void
xqc_moq_mark_object_write_time(xqc_moq_stream_t *stream)
{
    if (stream) {
        stream->last_moq_object_write_time = xqc_monotonic_timestamp();
    }
}

static void
xqc_moq_d18_object_from_subgroup(xqc_moq_object_t *dst,
    const xqc_moq_subgroup_msg_t *src, uint8_t include_header)
{
    xqc_memzero(dst, sizeof(*dst));
    dst->subscribe_id = src->subscribe_id;
    dst->track_alias = src->track_alias;
    dst->group_id = src->group_id;
    dst->object_id = src->object_id;
    dst->subgroup_id = src->subgroup_id;
    dst->status = src->status;
    dst->payload = src->payload;
    dst->payload_len = src->payload_len;
    dst->publisher_priority = src->subgroup_priority;
    dst->publisher_priority_set =
        src->subgroup_priority != XQC_MOQ_DEFAULT_SUBGROUP_PRIORITY;
    dst->object_properties_present = src->object_properties_present;
    dst->object_properties = src->object_properties;
    dst->object_properties_len = src->object_properties_len;
    dst->first_of_subgroup = include_header;
    dst->end_of_group = src->end_of_group
        || src->status == XQC_MOQ_OBJ_STATUS_GROUP_END;
    dst->end_of_stream = src->end_of_stream;
    dst->forwarding_preference = XQC_MOQ_FORWARDING_SUBGROUP;
}

static xqc_int_t
xqc_moq_write_d18_subgroup_data(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, xqc_moq_subgroup_msg_t *source,
    uint8_t include_header)
{
    xqc_moq_d18_data_msg_t msg;
    xqc_moq_object_t object;
    xqc_memzero(&msg, sizeof(msg));
    xqc_moq_d18_object_from_subgroup(&object, source, include_header);
    if (include_header) {
        xqc_moq_d18_subgroup_header_init(&msg.msg_base);
    } else {
        if (!stream->subgroup_header_valid) {
            return -XQC_EILLEGAL_FRAME;
        }
        xqc_moq_d18_subgroup_object_init(&msg.msg_base);
        msg.object.track_alias = stream->subgroup_header.track_alias;
        msg.object.group_id = stream->subgroup_header.group_id;
        msg.object.subgroup_id = stream->subgroup_header.subgroup_id;
        msg.subgroup_wire_type = stream->subgroup_header.subgroup_type;
        msg.subgroup_id_mode = stream->subgroup_header.subgroup_id_mode;
        msg.properties_present = stream->subgroup_header.properties_present;
        msg.default_priority = stream->subgroup_header.default_priority;
        xqc_moq_d18_data_msg_set_previous(
            &msg, stream->subgroup_header.group_id,
            stream->subgroup_prev_object_id,
            stream->subgroup_header.subgroup_id,
            stream->subgroup_header.subgroup_priority,
            stream->subgroup_prev_object_id_valid);
    }
    xqc_int_t ret = xqc_moq_d18_prepare_subgroup_message(
        &msg, &object, include_header);
    if (ret != XQC_OK) {
        return ret;
    }
    ret = include_header
        ? xqc_moq_write_profile_message(
            session, stream, &msg.msg_base, XQC_MOQ_SEMANTIC_SUBGROUP)
        : xqc_moq_msg_write_internal(
            session, stream, &msg.msg_base, XQC_FALSE);
    if (ret != XQC_OK) {
        return ret;
    }
    if (include_header) {
        stream->subgroup_header.track_alias = object.track_alias;
        stream->subgroup_header.group_id = object.group_id;
        stream->subgroup_header.subgroup_id = object.subgroup_id;
        stream->subgroup_header.subgroup_type =
            (uint8_t)msg.subgroup_wire_type;
        stream->subgroup_header.subgroup_priority =
            object.publisher_priority_set
                ? object.publisher_priority
                : XQC_MOQ_DEFAULT_SUBGROUP_PRIORITY;
        stream->subgroup_header.subgroup_id_mode = msg.subgroup_id_mode;
        stream->subgroup_header.properties_present = msg.properties_present;
        stream->subgroup_header.default_priority = msg.default_priority;
        stream->subgroup_header.first_object = msg.first_object;
        stream->subgroup_header.end_of_group = msg.end_of_group;
        stream->subgroup_header_valid = 1;
    }
    stream->subgroup_prev_object_id = object.object_id;
    stream->subgroup_prev_object_id_valid = 1;
    xqc_moq_mark_object_write_time(stream);
    return XQC_OK;
}

xqc_int_t
xqc_moq_write_object_stream_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_object_stream_msg_t *object)
{
    xqc_int_t ret = xqc_moq_write_msg_generic(session, stream, &object->msg_base,
                                              XQC_MOQ_SEMANTIC_OBJECT_STREAM);
    if (ret == XQC_OK) {
        xqc_moq_mark_object_write_time(stream);
    }
    return ret;
}

xqc_int_t
xqc_moq_write_subgroup_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_subgroup_msg_t *object)
{
    xqc_int_t ret = xqc_moq_profile_require(
        session != NULL ? session->profile : NULL,
        XQC_MOQ_CAP_SUBGROUP_STREAM);
    if (ret != XQC_OK) {
        return ret;
    }

    if (session->profile->wire_version == XQC_MOQ_VERSION_18) {
        return xqc_moq_write_d18_subgroup_data(
            session, stream, object, 1);
    }

    ret = xqc_moq_write_msg_generic(session, stream, &object->msg_base,
                                    XQC_MOQ_SEMANTIC_SUBGROUP);
    if (ret == XQC_OK) {
        xqc_moq_mark_object_write_time(stream);
    }
    return ret;
}

xqc_int_t
xqc_moq_append_subgroup_object(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_subgroup_msg_t *object)
{
    xqc_int_t encode_len = 0;
    xqc_int_t ret = 0;

    if (session == NULL || stream == NULL || object == NULL) {
        return -XQC_EPARAM;
    }

    ret = xqc_moq_writer_require(session, XQC_MOQ_CAP_SUBGROUP_STREAM);
    if (ret != XQC_OK) {
        return ret;
    }

    if (session->profile->wire_version == XQC_MOQ_VERSION_18) {
        return xqc_moq_write_d18_subgroup_data(
            session, stream, object, 0);
    }

    encode_len = xqc_moq_msg_append_subgroup_object_len(object);
    if (encode_len > XQC_MOQ_MAX_OBJECT_LEN) {
        return -XQC_ELIMIT;
    }

    if (stream->write_buf_processed != stream->write_buf_len) {
        stream->write_buf_cap += encode_len;
    } else {
        stream->write_buf_cap = encode_len;
        stream->write_buf_processed = 0;
        stream->write_buf_len = 0;
    }

    stream->write_buf = xqc_realloc(stream->write_buf, stream->write_buf_cap);
    ret = xqc_moq_msg_append_subgroup_object(object,
        stream->write_buf + stream->write_buf_len,
        stream->write_buf_cap - stream->write_buf_len);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|encode subgroup object error|ret:%d|", ret);
        return ret;
    }
    stream->write_buf_len += ret;

    ret = xqc_moq_stream_write(stream);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_stream_write error|ret:%d|msg_type:subgroup_object|", ret);
        return ret;
    }

    xqc_moq_mark_object_write_time(stream);

    return XQC_OK;
}

xqc_int_t
xqc_moq_write_stream_header_track_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_stream_header_track_msg_t *track_header)
{
    return xqc_moq_write_msg_generic(session, stream, &track_header->msg_base,
                                     XQC_MOQ_SEMANTIC_TRACK_HEADER);
}

xqc_int_t
xqc_moq_write_track_stream_obj_msg(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_track_stream_obj_msg_t *object)
{
    return xqc_moq_write_msg_generic(session, stream, &object->msg_base,
                                     XQC_MOQ_SEMANTIC_TRACK_STREAM_OBJECT);
}

xqc_int_t
xqc_moq_send_subgroup(xqc_moq_session_t *session, xqc_moq_track_t *track, xqc_moq_subgroup_object_t *subgroup)
{
    if (session == NULL || track == NULL || subgroup == NULL) {
        return -XQC_EPARAM;
    }

    xqc_int_t ret = xqc_moq_writer_require(
        session, XQC_MOQ_CAP_SUBGROUP_STREAM);
    if (ret != XQC_OK) {
        return ret;
    }

    if (!xqc_moq_track_can_send_data(track)) {
        return -XQC_ESTREAM_ST;
    }

    if (subgroup->payload_len > XQC_MOQ_MAX_OBJECT_LEN) {
        return -XQC_ELIMIT;
    }

    if (xqc_moq_track_should_drop_write_object(track, subgroup->group_id, subgroup->object_id)) {
        return XQC_OK;
    }

    xqc_moq_stream_t *stream = xqc_moq_stream_create_with_transport(session, XQC_STREAM_UNI);
    if (stream == NULL) {
        return -XQC_ECREATE_STREAM;
    }
    stream->write_stream_fin = 1;

    xqc_moq_object_stream_msg_t object;
    xqc_memzero(&object, sizeof(object));
    object.subscribe_id = subgroup->subscribe_id;
    object.track_alias = subgroup->track_alias;
    object.group_id = subgroup->group_id;
    object.object_id = subgroup->object_id;
    object.subgroup_id = subgroup->subgroup_id;
    object.object_id_delta = subgroup->object_id_delta ? subgroup->object_id_delta : subgroup->object_id;
    object.subgroup_type = subgroup->subgroup_type ? subgroup->subgroup_type : XQC_MOQ_SUBGROUP_TYPE_WITH_ID;
    object.subgroup_priority = subgroup->subgroup_priority;
    object.send_order = subgroup->send_order;
    object.status = subgroup->status;
    object.payload = (uint8_t *)subgroup->payload;
    object.payload_len = subgroup->payload_len;

    if (object.subgroup_type == 0) {
        object.subgroup_type = XQC_MOQ_SUBGROUP_TYPE_WITH_ID;
    }
    if (object.subgroup_priority == 0) {
        object.subgroup_priority = XQC_MOQ_DEFAULT_SUBGROUP_PRIORITY;
    }
    if (object.object_id_delta == 0) {
        object.object_id_delta = object.object_id;
    }

    xqc_moq_track_on_write_stream(track, stream, object.group_id, object.object_id, 0);

    ret = xqc_moq_write_subgroup_msg(session, stream, &object);
    if (ret < 0) {
        xqc_moq_stream_close(stream);
        return ret;
    }
    return ret;
}


xqc_int_t
xqc_moq_send_object_datagram(xqc_moq_session_t *session, xqc_moq_object_t *object)
{
    if (session == NULL || object == NULL) {
        return -XQC_EPARAM;
    }

    xqc_int_t ret = xqc_moq_profile_require(
        session->profile, XQC_MOQ_CAP_OBJECT_DATAGRAM);
    if (ret != XQC_OK) {
        return ret;
    }

    if (object->track_alias == XQC_MOQ_INVALID_ID) {
        return -XQC_EPARAM;
    }
    if (session->use_unified_setup) {
        xqc_moq_track_t *track = xqc_moq_find_track_by_alias(
            session, object->track_alias, XQC_MOQ_TRACK_FOR_PUB);
        if (!xqc_moq_track_can_send_data(track)) {
            return -XQC_EPARAM;
        }
    }

    if (session->profile->wire_version == XQC_MOQ_VERSION_18) {
        xqc_int_t enc_len =
            xqc_moq_d18_object_datagram_encode_len(object);
        if (enc_len < 0) {
            return enc_len;
        }
        size_t mss = xqc_datagram_get_mss(session->quic_conn);
        if (mss > 0 && (size_t)enc_len > mss) {
            return -XQC_EDGRAM_TOO_LARGE;
        }
        uint8_t *buf = xqc_malloc((size_t)enc_len);
        if (buf == NULL) {
            return -XQC_EMALLOC;
        }
        ret = xqc_moq_d18_object_datagram_encode(
            object, buf, (size_t)enc_len);
        if (ret < 0) {
            xqc_free(buf);
            return ret;
        }
        uint64_t dgram_id = 0;
        xqc_int_t send_ret = xqc_datagram_send(
            session->quic_conn, buf, (size_t)ret, &dgram_id,
            XQC_DATA_QOS_NORMAL);
        xqc_free(buf);
        return send_ret;
    }

    xqc_bool_t ext = (object->ext_params && object->ext_params_num > 0) ? 1 : 0;
    xqc_bool_t payload = (object->payload != NULL && object->payload_len > 0) ? 1 : 0;
    xqc_bool_t oid = payload ? (object->object_id != 0) : 1;

    xqc_moq_object_datagram_msg_t dgram;
    xqc_memzero(&dgram, sizeof(dgram));
    dgram.track_alias = object->track_alias;
    dgram.group_id = object->group_id;
    dgram.object_id = object->object_id;
    dgram.publisher_priority = object->publisher_priority;
    dgram.ext_params = object->ext_params;
    dgram.ext_params_num = object->ext_params_num;
    dgram.status = object->status;
    dgram.payload = object->payload;
    dgram.payload_len = object->payload_len;

    if (payload) {
        uint64_t type = 0;
        if (object->status == XQC_MOQ_OBJ_STATUS_GROUP_END) {
            type |= XQC_MOQ_OBJ_DGRAM_TYPE_END_OF_GROUP;
        }
        if (ext) {
            type |= XQC_MOQ_OBJ_DGRAM_TYPE_HAS_EXT;
        }
        if (!oid) {
            type |= XQC_MOQ_OBJ_DGRAM_TYPE_NO_OBJECT_ID;
        }
        dgram.type = type;
    } else {
        dgram.type = ext ? XQC_MOQ_OBJ_DGRAM_TYPE_STATUS_EXT : XQC_MOQ_OBJ_DGRAM_TYPE_STATUS;
    }

    xqc_int_t enc_len = xqc_moq_object_datagram_encode_len(&dgram);
    if (enc_len < 0) {
        return enc_len;
    }

    size_t mss = xqc_datagram_get_mss(session->quic_conn);
    if (mss > 0 && (size_t)enc_len > mss) {
        xqc_log(session->log, XQC_LOG_INFO, "|dgram_too_large|enc_len:%d|mss:%z|", enc_len, mss);
        return -XQC_EDGRAM_TOO_LARGE;
    }

    uint8_t *buf = xqc_malloc(enc_len);
    if (buf == NULL) {
        return -XQC_EMALLOC;
    }
    ret = xqc_moq_object_datagram_encode(&dgram, buf, enc_len);
    if (ret < 0) {
        xqc_free(buf);
        return ret;
    }

    uint64_t dgram_id = 0;
    xqc_int_t send_ret = xqc_datagram_send(session->quic_conn, buf, ret, &dgram_id, XQC_DATA_QOS_NORMAL);
    xqc_free(buf);
    return send_ret;
}

xqc_int_t
xqc_moq_write_goaway(xqc_moq_session_t *session, const char *new_session_uri, size_t uri_len)
{
    xqc_moq_goaway_msg_t goaway;
    xqc_memzero(&goaway, sizeof(goaway));

    if (new_session_uri && uri_len > 0) {
        goaway.new_session_uri = (char *)new_session_uri;
        goaway.new_session_uri_len = uri_len;
    }

    return xqc_moq_write_msg_generic(session, session->ctl_stream, &goaway.msg_base,
                                     XQC_MOQ_SEMANTIC_GOAWAY);
}

xqc_int_t
xqc_moq_write_subscribe_namespace(xqc_moq_session_t *session,
    xqc_moq_subscribe_namespace_msg_t *subscribe_namespace)
{
    if (session == NULL || subscribe_namespace == NULL) {
        return -XQC_EPARAM;
    }

    xqc_int_t ret = xqc_moq_writer_require(
        session, XQC_MOQ_CAP_SUBSCRIBE_NAMESPACE);
    if (ret != XQC_OK) {
        return ret;
    }

    if (session->use_unified_setup) {
        if (xqc_moq_session_admit_local_initial_request(session) != XQC_OK) {
            return -XQC_EPARAM;
        }

        xqc_moq_message_resolution_t resolution;
        ret = xqc_moq_profile_resolve_outbound(
            session->profile, XQC_MOQ_STREAM_UNKNOWN,
            XQC_MOQ_SEMANTIC_SUBSCRIBE_NAMESPACE, &resolution);
        if (ret != XQC_OK || resolution.codec == NULL
            || resolution.codec->initialize == NULL)
        {
            return ret != XQC_OK ? ret : -XQC_EALPN_NOT_SUPPORTED;
        }
        resolution.codec->initialize(&subscribe_namespace->msg_base);
        ret = subscribe_namespace->msg_base.encode_len(
            &subscribe_namespace->msg_base);
        if (ret < 0) {
            return ret;
        }

        xqc_moq_stream_t *request_stream =
            xqc_moq_stream_create_with_transport(session, XQC_STREAM_BIDI);
        if (request_stream == NULL) {
            return -XQC_EMALLOC;
        }
        request_stream->local_request = 1;
        request_stream->request_type =
            XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE;
        request_stream->request_id = subscribe_namespace->request_id;

        ret = xqc_moq_d18_store_local_initial_params(
            request_stream, subscribe_namespace->params,
            (size_t)subscribe_namespace->params_num);
        if (ret != XQC_OK) {
            xqc_moq_stream_close(request_stream);
            return ret;
        }
        ret = xqc_moq_session_add_pending_ns_request(
            session, subscribe_namespace->request_id,
            subscribe_namespace->track_namespace_tuple,
            subscribe_namespace->track_namespace_num);
        if (ret != XQC_OK) {
            xqc_moq_stream_close(request_stream);
            return ret;
        }
        ret = xqc_moq_register_local_request_id(
            session, subscribe_namespace->request_id);
        if (ret != XQC_OK) {
            xqc_moq_pending_ns_request_t *pending =
                xqc_moq_session_consume_pending_ns_request(
                    session, subscribe_namespace->request_id);
            if (pending != NULL) {
                xqc_moq_namespace_tuple_free(
                    pending->track_namespace_tuple,
                    pending->track_namespace_num);
                xqc_free(pending);
            }
            xqc_moq_stream_close(request_stream);
            return ret;
        }
        xqc_list_add_tail(&request_stream->request_list_member,
                          &session->local_request_stream_list);

        ret = xqc_moq_write_msg_generic(
            session, request_stream, &subscribe_namespace->msg_base,
            XQC_MOQ_SEMANTIC_SUBSCRIBE_NAMESPACE);
        if (ret != XQC_OK) {
            xqc_list_del_init(&request_stream->request_list_member);
            xqc_moq_stream_close(request_stream);
        }

    } else {
        ret = xqc_moq_validate_full_track_name_for_write(
            session, subscribe_namespace->track_namespace_num,
            subscribe_namespace->track_namespace_tuple, NULL, 0);
        if (ret != XQC_OK) {
            return ret;
        }
        ret = xqc_moq_session_add_pending_ns_request(
            session, subscribe_namespace->request_id,
            subscribe_namespace->track_namespace_tuple,
            subscribe_namespace->track_namespace_num);
        if (ret != XQC_OK) {
            return ret;
        }
        ret = xqc_moq_write_msg_generic(
            session, session->ctl_stream,
            &subscribe_namespace->msg_base,
            XQC_MOQ_SEMANTIC_SUBSCRIBE_NAMESPACE);
    }

    if (ret != XQC_OK) {
        xqc_moq_pending_ns_request_t *pending =
            xqc_moq_session_consume_pending_ns_request(
                session, subscribe_namespace->request_id);
        if (pending != NULL) {
            xqc_moq_namespace_tuple_free(
                pending->track_namespace_tuple,
                pending->track_namespace_num);
            xqc_free(pending);
        }
        return ret;
    }
    return XQC_OK;
}

xqc_int_t
xqc_moq_write_subscribe_namespace_ok(xqc_moq_session_t *session,
    xqc_moq_subscribe_namespace_ok_msg_t *subscribe_namespace_ok)
{
    if (session == NULL || subscribe_namespace_ok == NULL) {
        return -XQC_EPARAM;
    }

    xqc_int_t ret = xqc_moq_writer_require(
        session, XQC_MOQ_CAP_SUBSCRIBE_NAMESPACE);
    if (ret != XQC_OK) {
        return ret;
    }

    if (session->use_unified_setup) {
        xqc_moq_request_ok_msg_t request_ok;
        xqc_memzero(&request_ok, sizeof(request_ok));
        ret = xqc_moq_write_request_ok(
            session, subscribe_namespace_ok->request_id, &request_ok);

    } else {
        ret = xqc_moq_write_msg_generic(
            session, session->ctl_stream,
            &subscribe_namespace_ok->msg_base,
            XQC_MOQ_SEMANTIC_SUBSCRIBE_NAMESPACE_OK);
    }
    if (ret == XQC_OK) {
        const xqc_moq_track_ns_field_t *prefix_tuple = NULL;
        uint64_t prefix_num = 0;
        xqc_moq_session_accept_pending_inbound_ns(session, subscribe_namespace_ok->request_id,
            &prefix_tuple, &prefix_num);
        if (prefix_tuple && prefix_num > 0) {
            xqc_moq_session_forward_matching_namespaces(session, prefix_tuple, prefix_num);
            if (!session->use_unified_setup) {
                xqc_moq_session_forward_matching_publishes(
                    session, prefix_tuple, prefix_num, 1);
            }
        }
    }
    return ret;
}

xqc_int_t
xqc_moq_write_subscribe_namespace_error(xqc_moq_session_t *session,
    xqc_moq_subscribe_namespace_error_msg_t *subscribe_namespace_error)
{
    if (session == NULL || subscribe_namespace_error == NULL) {
        return -XQC_EPARAM;
    }

    xqc_int_t ret = xqc_moq_writer_require(
        session, XQC_MOQ_CAP_SUBSCRIBE_NAMESPACE);
    if (ret != XQC_OK) {
        return ret;
    }

    if (session->use_unified_setup) {
        xqc_moq_request_error_msg_t request_error;
        xqc_memzero(&request_error, sizeof(request_error));
        request_error.error_code = subscribe_namespace_error->error_code;
        request_error.reason_phrase =
            subscribe_namespace_error->reason_phrase;
        request_error.reason_phrase_len =
            subscribe_namespace_error->reason_phrase_len;
        if (request_error.reason_phrase_len == 0
            && request_error.reason_phrase != NULL)
        {
            request_error.reason_phrase_len =
                strlen(request_error.reason_phrase);
        }
        ret = xqc_moq_write_request_error(
            session, subscribe_namespace_error->request_id,
            &request_error);

    } else {
        ret = xqc_moq_write_msg_generic(
            session, session->ctl_stream,
            &subscribe_namespace_error->msg_base,
            XQC_MOQ_SEMANTIC_SUBSCRIBE_NAMESPACE_ERROR);
    }
    if (ret == XQC_OK) {
        xqc_moq_session_reject_pending_inbound_ns(session, subscribe_namespace_error->request_id);
    }
    return ret;
}

xqc_int_t
xqc_moq_write_unsubscribe_namespace(xqc_moq_session_t *session,
    xqc_moq_unsubscribe_namespace_msg_t *unsubscribe_namespace)
{
    if (unsubscribe_namespace == NULL) {
        return -XQC_EPARAM;
    }

    xqc_int_t ret = xqc_moq_writer_require(
        session, XQC_MOQ_CAP_SUBSCRIBE_NAMESPACE);
    if (ret != XQC_OK) {
        return ret;
    }

    ret = xqc_moq_validate_full_track_name_for_write(session,
        unsubscribe_namespace->track_namespace_num, unsubscribe_namespace->track_namespace_tuple,
        NULL, 0);
    if (ret != XQC_OK) {
        return ret;
    }

    return xqc_moq_write_msg_generic(session, session->ctl_stream, &unsubscribe_namespace->msg_base,
                                     XQC_MOQ_SEMANTIC_UNSUBSCRIBE_NAMESPACE);
}

xqc_int_t
xqc_moq_validate_full_track_name_for_write(xqc_moq_session_t *session,
    uint64_t track_namespace_num, const xqc_moq_track_ns_field_t *track_namespace_tuple,
    const char *track_name, size_t track_name_len)
{
    if (session == NULL) {
        return -XQC_EPARAM;
    }

    if (track_namespace_tuple == NULL || track_namespace_num == 0) {
        return -XQC_EPARAM;
    }
    if (track_namespace_num > XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS) {
        xqc_log(session->log, XQC_LOG_ERROR,
                "|invalid namespace tuple count|track_namespace_num:%ui|", track_namespace_num);
        return -XQC_EPARAM;
    }

    size_t namespace_total_len = 0;
    for (uint64_t i = 0; i < track_namespace_num; i++) {
        if (track_namespace_tuple[i].len > 0 && track_namespace_tuple[i].data == NULL) {
            xqc_log(session->log, XQC_LOG_ERROR,
                    "|namespace tuple element has len but NULL data|idx:%ui|", i);
            return -XQC_EPARAM;
        }
        if (track_namespace_tuple[i].len > XQC_MOQ_MAX_NAME_LEN
            || namespace_total_len > XQC_MOQ_MAX_FULL_TRACK_NAME_LEN - track_namespace_tuple[i].len)
        {
            xqc_log(session->log, XQC_LOG_ERROR, "|full track name too long (namespace)|");
            return -XQC_EPARAM;
        }
        namespace_total_len += track_namespace_tuple[i].len;
    }

    if (track_name == NULL) {
        if (track_name_len != 0) {
            return -XQC_EPARAM;
        }
        track_name_len = 0;
    }

    if (track_name_len == 0 && track_name != NULL) {
        track_name_len = strlen(track_name);
    }
    if (track_name_len > XQC_MOQ_MAX_FULL_TRACK_NAME_LEN
        || namespace_total_len > XQC_MOQ_MAX_FULL_TRACK_NAME_LEN - track_name_len)
    {
        xqc_log(session->log, XQC_LOG_ERROR, "|full track name too long|");
        return -XQC_EPARAM;
    }

    return XQC_OK;
}

static xqc_int_t
xqc_moq_forward_publish_namespace_done_to_matching_prefixes(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *track_namespace_tuple, uint64_t track_namespace_num)
{
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &session->peer_subscribe_namespace_list) {
        xqc_moq_namespace_prefix_t *prefix =
            xqc_list_entry(pos, xqc_moq_namespace_prefix_t, list_member);
        if (!xqc_moq_namespace_tuple_is_prefix(prefix->prefix_tuple, prefix->prefix_num,
                                               track_namespace_tuple, track_namespace_num))
        {
            continue;
        }

        xqc_int_t ret;
        if (session->use_unified_setup) {
            ret = xqc_moq_write_namespace_done(
                session, prefix->request_id,
                track_namespace_tuple, track_namespace_num);

        } else {
            xqc_moq_publish_namespace_done_msg_t done;
            xqc_memzero(&done, sizeof(done));
            done.track_namespace_tuple =
                (xqc_moq_track_ns_field_t *)track_namespace_tuple;
            done.track_namespace_num = track_namespace_num;
            ret = xqc_moq_write_publish_namespace_done(session, &done);
        }
        if (ret < 0) {
            return ret;
        }
    }
    return XQC_OK;
}

static xqc_int_t
xqc_moq_forward_publish_namespace_to_matching_prefixes(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *track_namespace_tuple, uint64_t track_namespace_num)
{
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &session->peer_subscribe_namespace_list) {
        xqc_moq_namespace_prefix_t *prefix =
            xqc_list_entry(pos, xqc_moq_namespace_prefix_t, list_member);
        if (!xqc_moq_namespace_tuple_is_prefix(prefix->prefix_tuple, prefix->prefix_num,
                                               track_namespace_tuple, track_namespace_num))
        {
            continue;
        }

        xqc_int_t ret;
        if (session->use_unified_setup) {
            ret = xqc_moq_write_namespace(
                session, prefix->request_id,
                track_namespace_tuple, track_namespace_num);

        } else {
            xqc_moq_publish_namespace_msg_t pub_ns;
            xqc_memzero(&pub_ns, sizeof(pub_ns));
            pub_ns.request_id =
                xqc_moq_session_alloc_request_id(session);
            pub_ns.track_namespace_tuple =
                (xqc_moq_track_ns_field_t *)track_namespace_tuple;
            pub_ns.track_namespace_num = track_namespace_num;
            ret = xqc_moq_write_msg_generic(
                session, session->ctl_stream, &pub_ns.msg_base,
                XQC_MOQ_SEMANTIC_PUBLISH_NAMESPACE);
        }
        if (ret < 0) {
            return ret;
        }
    }
    return XQC_OK;
}

xqc_int_t
xqc_moq_write_publish_namespace(xqc_moq_session_t *session,
    xqc_moq_publish_namespace_msg_t *publish_namespace)
{
    if (session == NULL || publish_namespace == NULL) {
        return -XQC_EPARAM;
    }

    xqc_int_t ret = xqc_moq_writer_require(session, XQC_MOQ_CAP_PUBLISH);
    if (ret != XQC_OK) {
        return ret;
    }

    ret = xqc_moq_validate_full_track_name_for_write(session,
        publish_namespace->track_namespace_num, publish_namespace->track_namespace_tuple,
        NULL, 0);
    if (ret != XQC_OK) {
        return ret;
    }

    if (publish_namespace->request_id == 0) {
        publish_namespace->request_id = xqc_moq_session_alloc_request_id(session);
    }

    if (session->use_unified_setup) {
        if (xqc_moq_session_admit_local_initial_request(session) != XQC_OK) {
            return -XQC_EPARAM;
        }

        xqc_moq_message_resolution_t resolution;
        ret = xqc_moq_profile_resolve_outbound(
            session->profile, XQC_MOQ_STREAM_UNKNOWN,
            XQC_MOQ_SEMANTIC_PUBLISH_NAMESPACE, &resolution);
        if (ret != XQC_OK || resolution.codec == NULL
            || resolution.codec->initialize == NULL)
        {
            return ret != XQC_OK ? ret : -XQC_EALPN_NOT_SUPPORTED;
        }
        resolution.codec->initialize(&publish_namespace->msg_base);
        ret = publish_namespace->msg_base.encode_len(
            &publish_namespace->msg_base);
        if (ret < 0) {
            return ret;
        }

        xqc_moq_stream_t *request_stream =
            xqc_moq_stream_create_with_transport(session, XQC_STREAM_BIDI);
        if (request_stream == NULL) {
            return -XQC_EMALLOC;
        }

        request_stream->local_request = 1;
        request_stream->request_type = XQC_MOQ_MSG_PUBLISH_NAMESPACE;
        request_stream->request_id = publish_namespace->request_id;
        ret = xqc_moq_d18_store_local_initial_params(
            request_stream, publish_namespace->params,
            (size_t)publish_namespace->params_num);
        if (ret != XQC_OK) {
            xqc_moq_stream_close(request_stream);
            return ret;
        }
        ret = xqc_moq_register_local_request_id(
            session, publish_namespace->request_id);
        if (ret != XQC_OK) {
            xqc_moq_stream_close(request_stream);
            return ret;
        }
        xqc_list_add_tail(&request_stream->request_list_member,
                          &session->local_request_stream_list);

        ret = xqc_moq_write_msg_generic(
            session, request_stream, &publish_namespace->msg_base,
            XQC_MOQ_SEMANTIC_PUBLISH_NAMESPACE);
        if (ret != XQC_OK) {
            xqc_list_del_init(&request_stream->request_list_member);
            xqc_moq_stream_close(request_stream);
        }
        return ret;
    }

    return xqc_moq_write_msg_generic(session, session->ctl_stream, &publish_namespace->msg_base,
                                     XQC_MOQ_SEMANTIC_PUBLISH_NAMESPACE);
}

xqc_int_t
xqc_moq_write_publish_namespace_done(xqc_moq_session_t *session,
    xqc_moq_publish_namespace_done_msg_t *publish_namespace_done)
{
    if (session == NULL || publish_namespace_done == NULL) {
        return -XQC_EPARAM;
    }

    xqc_int_t ret = xqc_moq_writer_require(session, XQC_MOQ_CAP_PUBLISH);
    if (ret != XQC_OK) {
        return ret;
    }

    ret = xqc_moq_validate_full_track_name_for_write(session,
        publish_namespace_done->track_namespace_num, publish_namespace_done->track_namespace_tuple,
        NULL, 0);
    if (ret != XQC_OK) {
        return ret;
    }

    return xqc_moq_write_msg_generic(session, session->ctl_stream, &publish_namespace_done->msg_base,
                                     XQC_MOQ_SEMANTIC_PUBLISH_NAMESPACE_DONE);
}

static void
xqc_moq_publish_namespace_rollback(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *track_namespace_tuple,
    uint64_t upto, const uint8_t *created, const uint8_t *incremented)
{
    for (uint64_t j = upto; j >= 1; j--) {
        if (created[j]) {
            xqc_moq_session_remove_advertised_namespace(session, 1, track_namespace_tuple, j);
        } else if (incremented[j]) {
            xqc_moq_namespace_advertisement_t *advertisement =
                xqc_moq_session_find_advertised_namespace(session, 1, track_namespace_tuple, j);
            if (advertisement != NULL && advertisement->child_refcnt > 0) {
                advertisement->child_refcnt--;
            }
        }
    }
}

xqc_int_t
xqc_moq_publish_namespace(xqc_moq_session_t *session,
    xqc_moq_publish_namespace_msg_t *publish_namespace)
{
    if (session == NULL || publish_namespace == NULL
        || publish_namespace->track_namespace_tuple == NULL
        || publish_namespace->track_namespace_num == 0
        || publish_namespace->track_namespace_num > XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS)
    {
        return -XQC_EPARAM;
    }

    xqc_int_t ret = xqc_moq_writer_require(session, XQC_MOQ_CAP_PUBLISH);
    if (ret != XQC_OK) {
        return ret;
    }

    ret = xqc_moq_validate_full_track_name_for_write(session,
        publish_namespace->track_namespace_num, publish_namespace->track_namespace_tuple,
        NULL, 0);
    if (ret != XQC_OK) {
        return ret;
    }

    if (session->use_unified_setup)
    {
        xqc_moq_namespace_advertisement_t *existing =
            xqc_moq_session_find_advertised_namespace(
                session, 1,
                publish_namespace->track_namespace_tuple,
                publish_namespace->track_namespace_num);
        if (existing != NULL && existing->explicit_advertised) {
            return XQC_OK;
        }

        ret = xqc_moq_write_publish_namespace(
            session, publish_namespace);
        if (ret != XQC_OK) {
            return ret;
        }

        if (existing == NULL) {
            ret = xqc_moq_session_add_advertised_namespace(
                session, 1,
                publish_namespace->track_namespace_tuple,
                publish_namespace->track_namespace_num);
            if (ret != XQC_OK) {
                xqc_moq_cancel_request(
                    session, publish_namespace->request_id);
                return ret;
            }
            existing = xqc_moq_session_find_advertised_namespace(
                session, 1,
                publish_namespace->track_namespace_tuple,
                publish_namespace->track_namespace_num);
        }
        if (existing == NULL) {
            xqc_moq_cancel_request(
                session, publish_namespace->request_id);
            return -XQC_ENULLPTR;
        }

        existing->request_id = publish_namespace->request_id;
        existing->explicit_advertised = 1;
        ret = xqc_moq_forward_publish_namespace_to_matching_prefixes(
            session, publish_namespace->track_namespace_tuple,
            publish_namespace->track_namespace_num);
        if (ret != XQC_OK) {
            xqc_moq_session_error(
                session, XQC_MOQ_D18_INTERNAL_ERROR,
                "NAMESPACE fanout failed");
        }
        return ret;
    }

    xqc_moq_namespace_advertisement_t *leaf =
        xqc_moq_session_find_advertised_namespace(session, 1,
            publish_namespace->track_namespace_tuple,
            publish_namespace->track_namespace_num);
    if (leaf != NULL) {
        if (!leaf->explicit_advertised) {
            for (uint64_t i = 1; i < publish_namespace->track_namespace_num; i++) {
                xqc_moq_namespace_advertisement_t *ancestor =
                    xqc_moq_session_find_advertised_namespace(session, 1,
                        publish_namespace->track_namespace_tuple, i);
                if (ancestor != NULL) {
                    ancestor->child_refcnt++;
                }
            }
        }
        leaf->explicit_advertised = 1;
        return XQC_OK;
    }

    uint8_t created[XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS + 1] = {0};
    uint8_t incremented[XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS + 1] = {0};
    ret = XQC_OK;
    for (uint64_t i = 1; i <= publish_namespace->track_namespace_num; i++) {
        xqc_moq_namespace_advertisement_t *advertisement =
            xqc_moq_session_find_advertised_namespace(session, 1,
                publish_namespace->track_namespace_tuple, i);
        if (advertisement != NULL) {
            if (i == publish_namespace->track_namespace_num) {
                advertisement->explicit_advertised = 1;
            } else {
                advertisement->child_refcnt++;
                incremented[i] = 1;
            }
            continue;
        }

        ret = xqc_moq_session_add_advertised_namespace(session, 1,
            publish_namespace->track_namespace_tuple, i);
        if (ret != XQC_OK) {
            xqc_moq_publish_namespace_rollback(session, publish_namespace->track_namespace_tuple,
                i, created, incremented);
            return ret;
        }
        created[i] = 1;

        advertisement = xqc_moq_session_find_advertised_namespace(session, 1,
            publish_namespace->track_namespace_tuple, i);
        if (advertisement == NULL) {
            xqc_moq_publish_namespace_rollback(session, publish_namespace->track_namespace_tuple,
                i, created, incremented);
            return -XQC_ENULLPTR;
        }
        if (i == publish_namespace->track_namespace_num) {
            advertisement->explicit_advertised = 1;
        } else {
            advertisement->child_refcnt = 1;
        }

        ret = xqc_moq_forward_publish_namespace_to_matching_prefixes(session,
            publish_namespace->track_namespace_tuple, i);
        if (ret != XQC_OK) {
            xqc_moq_publish_namespace_rollback(session, publish_namespace->track_namespace_tuple,
                i, created, incremented);
            xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "publish_namespace fanout failed");
            return ret;
        }
    }
    return XQC_OK;
}

xqc_int_t
xqc_moq_publish_namespace_done(xqc_moq_session_t *session,
    xqc_moq_publish_namespace_done_msg_t *publish_namespace_done)
{
    if (session == NULL || publish_namespace_done == NULL
        || publish_namespace_done->track_namespace_tuple == NULL
        || publish_namespace_done->track_namespace_num == 0
        || publish_namespace_done->track_namespace_num > XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS)
    {
        return -XQC_EPARAM;
    }

    xqc_int_t ret = xqc_moq_writer_require(session, XQC_MOQ_CAP_PUBLISH);
    if (ret != XQC_OK) {
        return ret;
    }

    ret = xqc_moq_validate_full_track_name_for_write(session,
        publish_namespace_done->track_namespace_num, publish_namespace_done->track_namespace_tuple,
        NULL, 0);
    if (ret != XQC_OK) {
        return ret;
    }

    if (xqc_moq_session_find_advertised_namespace(session, 1,
            publish_namespace_done->track_namespace_tuple,
            publish_namespace_done->track_namespace_num) == NULL)
    {
        return -XQC_EPARAM;
    }

    if (xqc_moq_session_has_active_publish_in_namespace(session,
            publish_namespace_done->track_namespace_tuple,
            publish_namespace_done->track_namespace_num))
    {
        return -XQC_EPARAM;
    }

    xqc_moq_namespace_advertisement_t *advertisement =
        xqc_moq_session_find_advertised_namespace(session, 1,
            publish_namespace_done->track_namespace_tuple,
            publish_namespace_done->track_namespace_num);
    if (advertisement->child_refcnt > 0) {
        return -XQC_EPARAM;
    }

    ret = xqc_moq_forward_publish_namespace_done_to_matching_prefixes(session,
        publish_namespace_done->track_namespace_tuple,
        publish_namespace_done->track_namespace_num);
    if (ret != XQC_OK) {
        return ret;
    }

    if (session->use_unified_setup
        && advertisement->request_id != XQC_MOQ_INVALID_ID)
    {
        xqc_int_t cancel_ret = xqc_moq_cancel_request(
            session, advertisement->request_id);
        if (cancel_ret != XQC_OK) {
            xqc_moq_session_error(
                session, XQC_MOQ_D18_INTERNAL_ERROR,
                "cancel PUBLISH_NAMESPACE request");
            return cancel_ret;
        }
    }

    xqc_moq_session_remove_advertised_namespace(session, 1,
        publish_namespace_done->track_namespace_tuple,
        publish_namespace_done->track_namespace_num);

    for (uint64_t i = publish_namespace_done->track_namespace_num; i > 1; i--) {
        uint64_t parent_num = i - 1;
        xqc_moq_namespace_advertisement_t *ancestor =
            xqc_moq_session_find_advertised_namespace(session, 1,
                publish_namespace_done->track_namespace_tuple, parent_num);
        if (ancestor != NULL && ancestor->child_refcnt > 0) {
            ancestor->child_refcnt--;
        }
    }
    return XQC_OK;
}
static xqc_int_t
xqc_moq_d18_publish_done_stream_is_active(
    const xqc_moq_stream_t *request_stream)
{
    if (request_stream == NULL
        || !xqc_moq_d18_stream_has_local_publisher(request_stream)
        || request_stream->request_closed_notified
        || request_stream->update_failed_wait_publish_done
        || (request_stream->write_stream_fin
            && !request_stream->d18_publish_done_pending)
        || request_stream->d18_context.direction
            != XQC_MOQ_D18_DIRECTION_BIDI
        || request_stream->d18_context.stream_class
            != XQC_MOQ_D18_STREAM_REQUEST
        || request_stream->d18_context.position
            != XQC_MOQ_D18_POSITION_NEXT)
    {
        return 0;
    }
    return (request_stream->local_request
            && request_stream->request_type == XQC_MOQ_MSG_PUBLISH
            && request_stream->response_received)
        || (request_stream->peer_request
            && request_stream->request_type == XQC_MOQ_MSG_SUBSCRIBE
            && request_stream->response_sent);
}

static xqc_moq_track_t *
xqc_moq_d18_publish_done_track(xqc_moq_session_t *session,
    xqc_moq_stream_t *request_stream)
{
    xqc_moq_track_t *track = request_stream->track;
    if (track != NULL && track->track_role == XQC_MOQ_TRACK_FOR_PUB) {
        return track;
    }
    return xqc_moq_find_track_by_subscribe_id(
        session, request_stream->request_id, XQC_MOQ_TRACK_FOR_PUB);
}

static xqc_moq_stream_t *
xqc_moq_find_pending_d18_publish_done_for_data_stream(
    xqc_moq_stream_t *data_stream)
{
    if (data_stream == NULL || data_stream->session == NULL
        || data_stream->track == NULL
        || xqc_list_empty(&data_stream->list_member))
    {
        return NULL;
    }

    xqc_moq_session_t *session = data_stream->session;
    if (!session->use_unified_setup)
    {
        return NULL;
    }

    xqc_list_head_t *request_lists[] = {
        &session->local_request_stream_list,
        &session->peer_request_stream_list,
    };
    for (size_t i = 0;
         i < sizeof(request_lists) / sizeof(request_lists[0]); i++)
    {
        xqc_list_head_t *pos;
        xqc_list_for_each(pos, request_lists[i]) {
            xqc_moq_stream_t *request_stream =
                xqc_list_entry(pos, xqc_moq_stream_t,
                               request_list_member);
            if (request_stream->d18_publish_done_pending
                && xqc_moq_d18_publish_done_track(
                       session, request_stream)
                    == data_stream->track)
            {
                return request_stream;
            }
        }
    }
    return NULL;
}

void
xqc_moq_fail_d18_publish_done_after_data_write(
    xqc_moq_stream_t *data_stream)
{
    xqc_moq_stream_t *request_stream =
        xqc_moq_find_pending_d18_publish_done_for_data_stream(
            data_stream);
    if (request_stream == NULL
        || request_stream->session->quic_conn == NULL)
    {
        return;
    }

    xqc_moq_session_error(
        request_stream->session, XQC_MOQ_D18_INTERNAL_ERROR,
        request_stream->d18_publish_done_status
                == XQC_MOQ_PUBLISH_DONE_UPDATE_FAILED
            ? "write UPDATE_FAILED PUBLISH_DONE"
            : "write PUBLISH_DONE");
}

static xqc_int_t
xqc_moq_write_d18_publish_done_on_stream(
    xqc_moq_session_t *session, xqc_moq_stream_t *request_stream,
    const xqc_moq_publish_done_msg_t *publish_done)
{
    if (session == NULL || publish_done == NULL
        || !session->use_unified_setup
        || !xqc_moq_d18_publish_done_stream_is_active(request_stream))
    {
        return -XQC_EPARAM;
    }

    xqc_moq_track_t *track =
        xqc_moq_d18_publish_done_track(session, request_stream);
    if (!request_stream->d18_publish_done_pending) {
        xqc_moq_publish_done_msg_t candidate = {
            .subscribe_id = request_stream->request_id,
            .status_code = publish_done->status_code,
            .stream_count = track != NULL
                ? track->streams_count
                : XQC_MOQ_PUBLISH_DONE_UNKNOWN_STREAM_COUNT,
            .reason_phrase = publish_done->reason_phrase,
            .reason_phrase_len = publish_done->reason_phrase_len,
        };
        xqc_moq_d18_publish_done_init_handler(
            &candidate.msg_base);
        xqc_int_t validate_ret =
            xqc_moq_d18_publish_done_encode_len(
                &candidate.msg_base);
        if (validate_ret < 0) {
            return validate_ret;
        }

        char *reason = NULL;
        if (publish_done->reason_phrase_len > 0) {
            reason = xqc_malloc(publish_done->reason_phrase_len);
            if (reason == NULL) {
                return -XQC_EMALLOC;
            }
            xqc_memcpy(reason, publish_done->reason_phrase,
                       publish_done->reason_phrase_len);
        }
        request_stream->d18_publish_done_status =
            candidate.status_code;
        request_stream->d18_publish_done_stream_count =
            candidate.stream_count;
        request_stream->d18_publish_done_reason = reason;
        request_stream->d18_publish_done_reason_len =
            publish_done->reason_phrase_len;
        request_stream->d18_publish_done_pending = 1;
        request_stream->d18_publish_done_encoded = 0;
        if (track != NULL) {
            xqc_moq_track_set_subscribe_id(
                track, XQC_MOQ_INVALID_ID);
            xqc_moq_track_set_alias(
                track, XQC_MOQ_INVALID_ID);
        }
    }

    if (track != NULL) {
        request_stream->d18_publish_done_retrying = 1;
        xqc_int_t finish_ret =
            xqc_moq_track_finish_write_streams(track);
        request_stream->d18_publish_done_retrying = 0;
        if (finish_ret != XQC_OK) {
            return finish_ret;
        }
    }

    xqc_moq_publish_done_msg_t wire_done;
    xqc_memzero(&wire_done, sizeof(wire_done));
    wire_done.subscribe_id = request_stream->request_id;
    wire_done.status_code =
        request_stream->d18_publish_done_status;
    wire_done.stream_count =
        request_stream->d18_publish_done_stream_count;
    wire_done.reason_phrase =
        request_stream->d18_publish_done_reason;
    wire_done.reason_phrase_len =
        request_stream->d18_publish_done_reason_len;

    request_stream->write_stream_fin = 1;
    xqc_int_t ret;
    if (!request_stream->d18_publish_done_encoded) {
        size_t previous_write_len = request_stream->write_buf_len;
        ret = xqc_moq_write_msg_generic(
            session, request_stream, &wire_done.msg_base,
            XQC_MOQ_SEMANTIC_PUBLISH_DONE);
        if (request_stream->write_buf_len > previous_write_len) {
            request_stream->d18_publish_done_encoded = 1;
        }

    } else {
        ret = xqc_moq_stream_write(request_stream);
    }
    if (ret != XQC_OK) {
        return ret;
    }
    if (!request_stream->write_fin_submitted) {
        return -XQC_EAGAIN;
    }

    uint64_t status = request_stream->d18_publish_done_status;
    request_stream->d18_publish_done_pending = 0;
    request_stream->d18_publish_done_encoded = 0;
    xqc_free(request_stream->d18_publish_done_reason);
    request_stream->d18_publish_done_reason = NULL;
    request_stream->d18_publish_done_reason_len = 0;
    xqc_moq_stream_finish_request(request_stream, status);
    return XQC_OK;
}

xqc_int_t
xqc_moq_retry_d18_publish_done_after_data_fin(
    xqc_moq_stream_t *data_stream)
{
    if (data_stream == NULL || !data_stream->write_fin_submitted)
    {
        return XQC_OK;
    }

    xqc_moq_session_t *session = data_stream->session;
    if (session != NULL && session->quic_conn != NULL
        && ((session->quic_conn->conn_flag
                & XQC_CONN_FLAG_ERROR) != 0
            || session->quic_conn->conn_state
                >= XQC_CONN_STATE_CLOSING))
    {
        return XQC_OK;
    }

    xqc_moq_stream_t *request_stream =
        xqc_moq_find_pending_d18_publish_done_for_data_stream(
            data_stream);
    if (request_stream == NULL
        || request_stream->d18_publish_done_retrying)
    {
        return XQC_OK;
    }

    xqc_moq_publish_done_msg_t pending = {0};
    xqc_int_t ret = xqc_moq_write_d18_publish_done_on_stream(
        session, request_stream, &pending);
    if (ret != XQC_OK && ret != -XQC_EAGAIN) {
        xqc_moq_session_error(
            session, XQC_MOQ_D18_INTERNAL_ERROR,
            request_stream->d18_publish_done_status
                    == XQC_MOQ_PUBLISH_DONE_UPDATE_FAILED
                ? "write UPDATE_FAILED PUBLISH_DONE"
                : "write PUBLISH_DONE");
    }
    return ret == -XQC_EAGAIN ? XQC_OK : ret;
}

xqc_int_t
xqc_moq_write_subscribe_tracks(xqc_moq_session_t *session,
    xqc_moq_subscribe_tracks_msg_t *subscribe_tracks)
{
    if (session == NULL || subscribe_tracks == NULL
        || !session->use_unified_setup || session->profile == NULL
        || session->draining
        || xqc_moq_session_admit_local_initial_request(session) != XQC_OK)
    {
        return -XQC_EPARAM;
    }

    xqc_moq_message_resolution_t resolution;
    xqc_int_t ret = xqc_moq_profile_resolve_outbound(
        session->profile, XQC_MOQ_STREAM_UNKNOWN,
        XQC_MOQ_SEMANTIC_SUBSCRIBE_TRACKS, &resolution);
    if (ret != XQC_OK || resolution.codec == NULL
        || resolution.codec->initialize == NULL)
    {
        return ret != XQC_OK ? ret : -XQC_EALPN_NOT_SUPPORTED;
    }
    resolution.codec->initialize(&subscribe_tracks->msg_base);
    ret = subscribe_tracks->msg_base.encode_len(
        &subscribe_tracks->msg_base);
    if (ret < 0) {
        return ret;
    }

    if (subscribe_tracks->request_id == 0) {
        subscribe_tracks->request_id =
            xqc_moq_session_alloc_request_id(session);
    }
    if (xqc_moq_d18_request_id_validate_local(
            &session->d18_request_registry,
            subscribe_tracks->request_id)
        != XQC_MOQ_D18_REQUEST_ID_OK)
    {
        return -XQC_EPARAM;
    }

    xqc_moq_stream_t *request_stream =
        xqc_moq_stream_create_with_transport(session, XQC_STREAM_BIDI);
    if (request_stream == NULL) {
        return -XQC_EMALLOC;
    }
    request_stream->local_request = 1;
    request_stream->request_type = XQC_MOQ_MSG_SUBSCRIBE_TRACKS;
    request_stream->request_id = subscribe_tracks->request_id;
    request_stream->tracks_subscription =
        xqc_moq_namespace_prefix_create_copy(
            subscribe_tracks->track_namespace_tuple,
            subscribe_tracks->track_namespace_num);
    if (request_stream->tracks_subscription == NULL) {
        xqc_moq_stream_close(request_stream);
        return -XQC_EMALLOC;
    }
    request_stream->tracks_subscription->request_id =
        subscribe_tracks->request_id;
    ret = xqc_moq_d18_store_local_initial_params(
        request_stream, subscribe_tracks->params,
        (size_t)subscribe_tracks->params_num);
    if (ret != XQC_OK) {
        xqc_moq_stream_close(request_stream);
        return ret;
    }

    ret = xqc_moq_register_local_request_id(
        session, subscribe_tracks->request_id);
    if (ret != XQC_OK) {
        xqc_moq_stream_close(request_stream);
        return ret;
    }
    xqc_list_add_tail(&request_stream->request_list_member,
                      &session->local_request_stream_list);

    ret = xqc_moq_write_msg_generic(
        session, request_stream, &subscribe_tracks->msg_base,
        XQC_MOQ_SEMANTIC_SUBSCRIBE_TRACKS);
    if (ret != XQC_OK) {
        xqc_list_del_init(&request_stream->request_list_member);
        xqc_moq_stream_close(request_stream);
    }
    return ret;
}

static xqc_moq_stream_t *
xqc_moq_find_active_peer_subscribe_tracks_stream(
    xqc_moq_session_t *session, uint64_t request_id)
{
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &session->peer_request_stream_list) {
        xqc_moq_stream_t *stream =
            xqc_list_entry(pos, xqc_moq_stream_t,
                           request_list_member);
        if (stream->request_id == request_id
            && stream->peer_request && !stream->local_request
            && stream->request_type == XQC_MOQ_MSG_SUBSCRIBE_TRACKS
            && stream->response_sent
            && stream->subscribe_tracks_active
            && !stream->request_closed_notified
            && !stream->update_failed_wait_publish_done
            && stream->tracks_subscription != NULL
            && xqc_moq_publish_blocked_stream_context_is_valid(stream))
        {
            return stream;
        }
    }
    return NULL;
}

xqc_int_t
xqc_moq_publish_blocked_stream_context_is_valid(
    const xqc_moq_stream_t *stream)
{
    return stream != NULL
        && stream->d18_context.direction == XQC_MOQ_D18_DIRECTION_BIDI
        && stream->d18_context.stream_class == XQC_MOQ_D18_STREAM_REQUEST
        && stream->d18_context.position == XQC_MOQ_D18_POSITION_NEXT;
}

xqc_int_t
xqc_moq_write_publish_blocked(
    xqc_moq_session_t *session, uint64_t subscribe_tracks_request_id,
    const xqc_moq_track_ns_field_t *full_namespace,
    uint64_t full_namespace_num, const char *track_name,
    size_t track_name_len)
{
    if (session == NULL || !session->use_unified_setup
        || session->profile == NULL || !session->profile->unified_setup
        || session->profile->wire_version != session->version
        || xqc_moq_validate_d18_full_track_name(
               full_namespace_num, full_namespace,
               track_name, track_name_len) != XQC_OK)
    {
        return -XQC_EPARAM;
    }

    xqc_moq_stream_t *request_stream =
        xqc_moq_find_active_peer_subscribe_tracks_stream(
            session, subscribe_tracks_request_id);
    if (request_stream == NULL) {
        return -XQC_ENULLPTR;
    }
    xqc_moq_namespace_prefix_t *prefix =
        request_stream->tracks_subscription;
    if (!xqc_moq_namespace_tuple_is_prefix(
            prefix->prefix_tuple, prefix->prefix_num,
            full_namespace, full_namespace_num))
    {
        return -XQC_EPARAM;
    }

    xqc_moq_publish_blocked_msg_t blocked;
    xqc_memzero(&blocked, sizeof(blocked));
    blocked.track_namespace_suffix_num =
        full_namespace_num - prefix->prefix_num;
    blocked.track_namespace_suffix =
        blocked.track_namespace_suffix_num > 0
        ? (xqc_moq_track_ns_field_t *)full_namespace
            + prefix->prefix_num
        : NULL;
    blocked.track_name = (char *)track_name;
    blocked.track_name_len = track_name_len;
    return xqc_moq_write_msg_generic(
        session, request_stream, &blocked.msg_base,
        XQC_MOQ_SEMANTIC_PUBLISH_BLOCKED);
}

static xqc_moq_stream_t *
xqc_moq_find_peer_namespace_request_stream(xqc_moq_session_t *session,
    uint64_t request_id)
{
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &session->peer_request_stream_list) {
        xqc_moq_stream_t *request_stream =
            xqc_list_entry(pos, xqc_moq_stream_t, request_list_member);
        if (request_stream->peer_request
            && request_stream->request_type
                == XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE
            && request_stream->request_id == request_id)
        {
            return request_stream;
        }
    }
    return NULL;
}

static xqc_moq_namespace_prefix_t *
xqc_moq_find_peer_namespace_prefix_by_request(
    xqc_moq_session_t *session, uint64_t request_id)
{
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &session->peer_subscribe_namespace_list) {
        xqc_moq_namespace_prefix_t *prefix =
            xqc_list_entry(pos, xqc_moq_namespace_prefix_t, list_member);
        if (prefix->request_id == request_id) {
            return prefix;
        }
    }
    return NULL;
}

static xqc_int_t
xqc_moq_write_namespace_notification(xqc_moq_session_t *session,
    uint64_t request_id,
    const xqc_moq_track_ns_field_t *track_namespace_tuple,
    uint64_t track_namespace_num, xqc_int_t done)
{
    if (session == NULL || !session->use_unified_setup
        || track_namespace_tuple == NULL || track_namespace_num == 0)
    {
        return -XQC_EPARAM;
    }

    xqc_moq_stream_t *request_stream =
        xqc_moq_find_peer_namespace_request_stream(session, request_id);
    if (request_stream == NULL) {
        return -XQC_ENULLPTR;
    }
    if (!request_stream->response_sent) {
        return -XQC_EPARAM;
    }

    xqc_moq_namespace_prefix_t *prefix =
        xqc_moq_find_peer_namespace_prefix_by_request(session, request_id);
    if (prefix == NULL
        || !xqc_moq_namespace_tuple_is_prefix(
            prefix->prefix_tuple, prefix->prefix_num,
            track_namespace_tuple, track_namespace_num))
    {
        return -XQC_EPARAM;
    }

    xqc_moq_namespace_advertisement_t *active =
        xqc_moq_namespace_prefix_find_advertised(
            prefix, track_namespace_tuple, track_namespace_num);
    if (!done && active != NULL) {
        return XQC_OK;
    }
    if (done && active == NULL) {
        return -XQC_EPARAM;
    }

    xqc_moq_namespace_advertisement_t *pending = NULL;
    if (!done) {
        pending = xqc_moq_namespace_advertisement_create_copy(
            track_namespace_tuple, track_namespace_num);
        if (pending == NULL) {
            return -XQC_EMALLOC;
        }
    }

    xqc_moq_d18_namespace_msg_t msg;
    xqc_memzero(&msg, sizeof(msg));
    msg.track_namespace_suffix_num =
        track_namespace_num - prefix->prefix_num;
    msg.track_namespace_suffix_tuple =
        msg.track_namespace_suffix_num > 0
        ? (xqc_moq_track_ns_field_t *)track_namespace_tuple
            + prefix->prefix_num
        : NULL;

    xqc_int_t ret = xqc_moq_write_msg_generic(
        session, request_stream, &msg.msg_base,
        done ? XQC_MOQ_SEMANTIC_NAMESPACE_DONE
             : XQC_MOQ_SEMANTIC_NAMESPACE);
    if (ret != XQC_OK) {
        xqc_moq_namespace_advertisement_destroy(pending);
        return ret;
    }

    if (done) {
        xqc_list_del_init(&active->list_member);
        xqc_moq_namespace_advertisement_destroy(active);

    } else {
        xqc_list_add_tail(&pending->list_member,
                          &prefix->advertised_namespace_list);
    }
    return XQC_OK;
}

xqc_int_t
xqc_moq_write_namespace(xqc_moq_session_t *session, uint64_t request_id,
    const xqc_moq_track_ns_field_t *track_namespace_tuple,
    uint64_t track_namespace_num)
{
    return xqc_moq_write_namespace_notification(
        session, request_id, track_namespace_tuple,
        track_namespace_num, 0);
}

xqc_int_t
xqc_moq_write_namespace_done(xqc_moq_session_t *session,
    uint64_t request_id,
    const xqc_moq_track_ns_field_t *track_namespace_tuple,
    uint64_t track_namespace_num)
{
    return xqc_moq_write_namespace_notification(
        session, request_id, track_namespace_tuple,
        track_namespace_num, 1);
}

xqc_int_t
xqc_moq_validate_d18_full_track_name(
    uint64_t track_namespace_num,
    const xqc_moq_track_ns_field_t *track_namespace_tuple,
    const char *track_name, size_t track_name_len)
{
    if (track_namespace_num > XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS
        || (track_namespace_num > 0
            && track_namespace_tuple == NULL)
        || track_name == NULL || track_name_len == 0
        || track_name_len > XQC_MOQ_MAX_NAME_LEN)
    {
        return -XQC_EPARAM;
    }

    size_t total_len = 0;
    for (uint64_t i = 0; i < track_namespace_num; i++) {
        if (track_namespace_tuple[i].data == NULL
            || track_namespace_tuple[i].len == 0
            || track_namespace_tuple[i].len > XQC_MOQ_MAX_NAME_LEN
            || total_len > XQC_MOQ_MAX_FULL_TRACK_NAME_LEN
                - track_namespace_tuple[i].len)
        {
            return -XQC_EPARAM;
        }
        total_len += track_namespace_tuple[i].len;
    }
    if (total_len > XQC_MOQ_MAX_FULL_TRACK_NAME_LEN
            - track_name_len)
    {
        return -XQC_EPARAM;
    }
    return XQC_OK;
}

static xqc_int_t
xqc_moq_d18_location_before(uint64_t left_group, uint64_t left_object,
    uint64_t right_group, uint64_t right_object)
{
    return left_group < right_group
        || (left_group == right_group && left_object < right_object);
}

static xqc_moq_stream_t *
xqc_moq_find_local_subscribe_request(xqc_moq_session_t *session,
    uint64_t request_id)
{
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &session->local_request_stream_list) {
        xqc_moq_stream_t *stream = xqc_list_entry(
            pos, xqc_moq_stream_t, request_list_member);
        if (stream->local_request && !stream->request_closed_notified
            && stream->request_type == XQC_MOQ_MSG_SUBSCRIBE
            && stream->request_id == request_id)
        {
            return stream;
        }
    }
    return NULL;
}

static uint8_t
xqc_moq_d18_request_forward(const xqc_moq_stream_t *stream)
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

static xqc_int_t
xqc_moq_write_initial_track_request(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, xqc_moq_msg_base_t *base,
    xqc_moq_semantic_id_t semantic, xqc_moq_msg_type_t request_type,
    uint64_t request_id, const xqc_moq_message_parameter_t *params,
    size_t params_num)
{
    if (session == NULL || stream == NULL || base == NULL
        || !session->use_unified_setup || session->profile == NULL
        || stream->session != session || stream->local_request
        || stream->peer_request
        || stream->d18_context.direction != XQC_MOQ_D18_DIRECTION_BIDI
        || stream->d18_context.position != XQC_MOQ_D18_POSITION_FIRST
        || xqc_moq_session_admit_local_initial_request(session) != XQC_OK)
    {
        return -XQC_EPARAM;
    }

    xqc_moq_message_resolution_t resolution;
    xqc_int_t ret = xqc_moq_profile_resolve_outbound(
        session->profile, XQC_MOQ_STREAM_UNKNOWN, semantic, &resolution);
    if (ret != XQC_OK || resolution.codec == NULL
        || resolution.codec->initialize == NULL)
    {
        return ret != XQC_OK ? ret : -XQC_EALPN_NOT_SUPPORTED;
    }
    resolution.codec->initialize(base);
    ret = xqc_moq_profile_prepare_data_message(
        stream, resolution.codec, base);
    if (ret != XQC_OK) {
        return ret;
    }
    ret = base->encode_len(base);
    if (ret < 0) {
        return ret;
    }
    if (xqc_moq_d18_request_id_validate_local(
            &session->d18_request_registry, request_id)
        != XQC_MOQ_D18_REQUEST_ID_OK)
    {
        return -XQC_EPARAM;
    }

    ret = xqc_moq_d18_store_local_initial_params(
        stream, params, params_num);
    if (ret != XQC_OK) {
        return ret;
    }
    ret = xqc_moq_register_local_request_id(session, request_id);
    if (ret != XQC_OK) {
        xqc_moq_d18_params_free(
            stream->d18_accepted_params, stream->d18_accepted_params_num);
        stream->d18_accepted_params = NULL;
        stream->d18_accepted_params_num = 0;
        return ret;
    }

    stream->local_request = 1;
    stream->request_type = request_type;
    stream->request_id = request_id;
    xqc_list_add_tail(&stream->request_list_member,
                      &session->local_request_stream_list);
    ret = xqc_moq_write_msg_generic_atomic(
        session, stream, base, semantic);
    if (ret != XQC_OK) {
        xqc_list_del_init(&stream->request_list_member);
        (void)xqc_moq_session_unregister_local_request_id(
            session, request_id);
        xqc_moq_d18_params_free(
            stream->d18_accepted_params, stream->d18_accepted_params_num);
        stream->d18_accepted_params = NULL;
        stream->d18_accepted_params_num = 0;
        stream->local_request = 0;
        stream->request_type = 0;
        stream->request_id = 0;
    }
    return ret;
}

xqc_int_t
xqc_moq_write_fetch(xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    xqc_moq_fetch_msg_t *fetch)
{
    if (session == NULL || stream == NULL || fetch == NULL) {
        return -XQC_EPARAM;
    }
    if (fetch->fetch_type == XQC_MOQ_FETCH_STANDALONE) {
        xqc_int_t ret = xqc_moq_validate_d18_full_track_name(
            fetch->track_namespace_num, fetch->track_namespace_tuple,
            fetch->track_name, fetch->track_name_len);
        if (ret != XQC_OK
            || xqc_moq_d18_location_before(
                fetch->end_group_id, fetch->end_object_id,
                fetch->start_group_id, fetch->start_object_id))
        {
            return -XQC_EPARAM;
        }

    } else if (fetch->fetch_type == XQC_MOQ_FETCH_JOINING_RELATIVE
               || fetch->fetch_type == XQC_MOQ_FETCH_JOINING_ABSOLUTE)
    {
        xqc_moq_stream_t *subscription =
            xqc_moq_find_local_subscribe_request(
                session, fetch->joining_request_id);
        if (subscription == NULL
            || !xqc_moq_d18_request_forward(subscription))
        {
            return -XQC_EPARAM;
        }

    } else {
        return -XQC_EPARAM;
    }

    xqc_int_t ret = xqc_moq_write_initial_track_request(
        session, stream, &fetch->msg_base, XQC_MOQ_SEMANTIC_FETCH,
        XQC_MOQ_MSG_FETCH, fetch->request_id,
        fetch->params, (size_t)fetch->params_num);
    if (ret == XQC_OK) {
        stream->d18_fetch_type = (uint8_t)fetch->fetch_type;
        stream->d18_fetch_group_order =
            xqc_moq_d18_group_order_from_params(
                fetch->params, (size_t)fetch->params_num);
        if (fetch->fetch_type == XQC_MOQ_FETCH_STANDALONE) {
            stream->d18_fetch_start_group_id = fetch->start_group_id;
            stream->d18_fetch_start_object_id = fetch->start_object_id;
        } else if (fetch->fetch_type == XQC_MOQ_FETCH_JOINING_ABSOLUTE) {
            stream->d18_fetch_start_group_id = fetch->joining_start;
            stream->d18_fetch_start_object_id = 0;
        }
    }
    return ret;
}

xqc_int_t
xqc_moq_write_track_status(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, xqc_moq_track_status_msg_t *track_status)
{
    if (session == NULL || stream == NULL || track_status == NULL
        || xqc_moq_validate_d18_full_track_name(
            track_status->track_namespace_num,
            track_status->track_namespace_tuple,
            track_status->track_name,
            track_status->track_name_len) != XQC_OK)
    {
        return -XQC_EPARAM;
    }
    return xqc_moq_write_initial_track_request(
        session, stream, &track_status->msg_base,
        XQC_MOQ_SEMANTIC_TRACK_STATUS,
        (xqc_moq_msg_type_t)XQC_MOQ_D18_MSG_TRACK_STATUS,
        track_status->request_id, track_status->params,
        (size_t)track_status->params_num);
}

xqc_int_t
xqc_moq_write_fetch_ok(xqc_moq_session_t *session, uint64_t request_id,
    xqc_moq_fetch_ok_msg_t *fetch_ok)
{
    if (session == NULL || fetch_ok == NULL || fetch_ok->end_of_track > 1) {
        return -XQC_EPARAM;
    }
    xqc_int_t is_update = 0;
    xqc_int_t is_initial = 0;
    xqc_moq_stream_t *request_stream =
        xqc_moq_find_request_response_target(
            session, request_id, &is_update, &is_initial);
    if (request_stream == NULL || !is_initial || is_update
        || request_stream->request_type != XQC_MOQ_MSG_FETCH
        || request_stream->response_sent)
    {
        return -XQC_EPARAM;
    }
    xqc_int_t ret = xqc_moq_write_msg_generic(
        session, request_stream, &fetch_ok->msg_base,
        XQC_MOQ_SEMANTIC_FETCH_OK);
    if (ret == XQC_OK) {
        request_stream->response_sent = 1;
    }
    return ret;
}

xqc_int_t
xqc_moq_write_fetch_header(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, xqc_moq_fetch_header_msg_t *header,
    uint8_t fin)
{
    if (session == NULL || stream == NULL || header == NULL || fin > 1
        || stream->session != session
        || stream->d18_context.direction != XQC_MOQ_D18_DIRECTION_UNI
        || stream->d18_context.position != XQC_MOQ_D18_POSITION_FIRST)
    {
        return -XQC_EPARAM;
    }
    xqc_moq_stream_t *request_stream = NULL;
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &session->peer_request_stream_list) {
        xqc_moq_stream_t *candidate = xqc_list_entry(
            pos, xqc_moq_stream_t, request_list_member);
        if (candidate->peer_request
            && candidate->request_type == XQC_MOQ_MSG_FETCH
            && candidate->request_id == header->request_id
            && !candidate->request_closed_notified)
        {
            request_stream = candidate;
            break;
        }
    }
    if (request_stream == NULL || request_stream->fetch_data_stream != NULL) {
        return -XQC_EPARAM;
    }

    uint8_t previous_fin = stream->write_stream_fin;
    stream->write_stream_fin = fin;
    xqc_int_t ret = xqc_moq_write_msg_generic(
        session, stream, &header->msg_base,
        XQC_MOQ_SEMANTIC_FETCH_HEADER);
    if (ret != XQC_OK) {
        stream->write_stream_fin = previous_fin;
        return ret;
    }
    request_stream->fetch_data_stream = stream;
    stream->fetch_request_stream = request_stream;
    stream->request_id = header->request_id;
    stream->request_type = XQC_MOQ_MSG_FETCH;
    if (fin) {
        request_stream->fetch_data_stream = NULL;
        stream->fetch_request_stream = NULL;
        xqc_moq_stream_finish_request(request_stream, XQC_OK);
    }
    return XQC_OK;
}

static xqc_int_t
xqc_moq_write_fetch_record(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, xqc_moq_object_t *object,
    uint64_t group_id, uint64_t object_id, uint8_t unknown,
    uint8_t range, uint8_t fin)
{
    if (session == NULL || stream == NULL || fin > 1 || unknown > 1
        || stream->session != session || session->profile == NULL
        || session->profile->wire_version != XQC_MOQ_VERSION_18
        || stream->fetch_request_stream == NULL
        || stream->write_fin_submitted || (range == 0 && object == NULL))
    {
        return -XQC_EPARAM;
    }
    xqc_moq_d18_data_msg_t msg;
    xqc_memzero(&msg, sizeof(msg));
    xqc_moq_d18_fetch_object_init(&msg.msg_base);
    msg.request_id = stream->request_id;
    msg.group_order =
        stream->fetch_request_stream->d18_fetch_group_order;
    xqc_moq_d18_data_msg_set_previous(
        &msg, stream->d18_fetch_previous_group_id,
        stream->d18_fetch_previous_object_id,
        stream->d18_fetch_previous_subgroup_id,
        stream->d18_fetch_previous_priority,
        stream->d18_fetch_previous_valid);
    msg.previous_actual_valid = stream->d18_fetch_previous_actual_valid;
    xqc_int_t ret = range
        ? xqc_moq_d18_prepare_fetch_range(
            &msg, group_id, object_id, unknown)
        : xqc_moq_d18_prepare_fetch_object(&msg, object);
    if (ret != XQC_OK) {
        return ret;
    }
    uint8_t previous_fin = stream->write_stream_fin;
    stream->write_stream_fin = fin;
    ret = xqc_moq_msg_write_internal(
        session, stream, &msg.msg_base, XQC_FALSE);
    if (ret != XQC_OK) {
        stream->write_stream_fin = previous_fin;
        return ret;
    }
    stream->d18_fetch_previous_valid = 1;
    stream->d18_fetch_previous_group_id = msg.object.group_id;
    stream->d18_fetch_previous_object_id = msg.object.object_id;
    if (!range) {
        stream->d18_fetch_previous_actual_valid = 1;
        stream->d18_fetch_previous_subgroup_id = msg.object.subgroup_id;
        stream->d18_fetch_previous_priority = msg.object.publisher_priority;
    }
    if (fin) {
        xqc_moq_stream_t *request_stream = stream->fetch_request_stream;
        stream->fetch_request_stream = NULL;
        if (request_stream->fetch_data_stream == stream) {
            request_stream->fetch_data_stream = NULL;
        }
        xqc_moq_stream_finish_request(request_stream, XQC_OK);
    }
    return XQC_OK;
}

xqc_int_t
xqc_moq_write_fetch_object(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, xqc_moq_object_t *object, uint8_t fin)
{
    return xqc_moq_write_fetch_record(
        session, stream, object, 0, 0, 0, 0, fin);
}

xqc_int_t
xqc_moq_write_fetch_range_end(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, uint64_t group_id, uint64_t object_id,
    uint8_t unknown, uint8_t fin)
{
    return xqc_moq_write_fetch_record(
        session, stream, NULL, group_id, object_id, unknown, 1, fin);
}

static xqc_moq_stream_t *
xqc_moq_find_request_response_target(xqc_moq_session_t *session,
    uint64_t request_id, xqc_int_t *is_update, xqc_int_t *is_initial)
{
    xqc_list_head_t *request_lists[] = {
        &session->peer_request_stream_list,
        &session->local_request_stream_list,
    };
    for (size_t list_index = 0;
         list_index < sizeof(request_lists) / sizeof(request_lists[0]);
         list_index++)
    {
        xqc_list_head_t *pos;
        xqc_list_for_each(pos, request_lists[list_index]) {
            xqc_moq_stream_t *request_stream =
                xqc_list_entry(
                    pos, xqc_moq_stream_t, request_list_member);
            if (request_stream->request_closed_notified
                || request_stream->update_failed_wait_publish_done)
            {
                continue;
            }
            if (!request_stream->peer_request
                && !(request_stream->local_request
                     && request_stream->request_type
                         == XQC_MOQ_MSG_PUBLISH))
            {
                continue;
            }
            xqc_moq_d18_update_record_t *update_record =
                xqc_moq_d18_update_queue_peek(
                    &request_stream->d18_peer_update_queue);
            *is_update = update_record != NULL
                && update_record->request_id == request_id;
            *is_initial = request_stream->peer_request
                && request_stream->request_id == request_id;
            if (*is_update || *is_initial) {
                return request_stream;
            }
        }
    }
    return NULL;
}

xqc_int_t
xqc_moq_write_request_ok(xqc_moq_session_t *session, uint64_t request_id,
    xqc_moq_request_ok_msg_t *request_ok)
{
    if (session == NULL || request_ok == NULL || !session->use_unified_setup) {
        return -XQC_EPARAM;
    }

    xqc_int_t is_update = 0;
    xqc_int_t is_initial = 0;
    xqc_moq_stream_t *request_stream =
        xqc_moq_find_request_response_target(
            session, request_id, &is_update, &is_initial);
    if (request_stream == NULL) {
        return -XQC_ENULLPTR;
    }
    xqc_moq_d18_update_record_t *update_record =
        xqc_moq_d18_update_queue_peek(
            &request_stream->d18_peer_update_queue);
        if ((is_initial && request_stream->response_sent)
            || (is_update
                && ((request_stream->peer_request
                        && !request_stream->response_sent)
                    || (request_stream->local_request
                        && !request_stream->response_received))))
        {
            return -XQC_EPARAM;
        }

        if (is_update && update_record->candidate_prefix != NULL
            && xqc_moq_namespace_update_overlaps(
                session, request_stream,
                update_record->candidate_prefix))
        {
            return -XQC_EPARAM;
        }

        xqc_moq_message_parameter_t *merged = NULL;
        size_t merged_count = 0;
        if (is_update
            && xqc_moq_d18_params_merge(
                request_stream->d18_accepted_params,
                request_stream->d18_accepted_params_num,
                update_record->params,
                (size_t)update_record->params_num,
                &merged, &merged_count) != XQC_MOQ_D18_UPDATE_OK)
        {
            return -XQC_EMALLOC;
        }

        xqc_moq_subscribe_t *publish_subscription = NULL;
        xqc_moq_track_t *publish_track = NULL;
        if (is_initial
            && request_stream->request_type == XQC_MOQ_MSG_PUBLISH)
        {
            publish_subscription = xqc_moq_find_subscribe(
                session, request_id, 1);
            publish_track = request_stream->track;
            if (publish_subscription == NULL || publish_track == NULL) {
                xqc_moq_session_error(
                    session, XQC_MOQ_D18_INTERNAL_ERROR,
                    "PUBLISH REQUEST_OK missing pending state");
                return -XQC_ENULLPTR;
            }
            xqc_moq_track_t *alias_owner =
                xqc_moq_find_track_by_alias(
                    session,
                    publish_subscription->subscribe_msg->track_alias,
                    XQC_MOQ_TRACK_FOR_SUB);
            if (alias_owner != NULL && alias_owner != publish_track) {
                xqc_moq_session_error(
                    session, XQC_MOQ_D18_DUPLICATE_TRACK_ALIAS,
                    "duplicate PUBLISH track alias");
                return -XQC_EPROTO;
            }
        }

        size_t previous_write_len = request_stream->write_buf_len;
        size_t previous_write_processed =
            request_stream->write_buf_processed;
        uint8_t previous_fin = request_stream->write_stream_fin;
        xqc_int_t finish_initial_response = is_initial
            && request_stream->request_type
                == (xqc_moq_msg_type_t)XQC_MOQ_D18_MSG_TRACK_STATUS;
        if (finish_initial_response) {
            request_stream->write_stream_fin = 1;
        }
        xqc_int_t ret = xqc_moq_write_msg_generic(session, request_stream,
            &request_ok->msg_base, XQC_MOQ_SEMANTIC_REQUEST_OK);
        if (ret == XQC_OK) {
            if (is_update) {
                xqc_moq_message_parameter_t *old_params =
                    request_stream->d18_accepted_params;
                size_t old_params_num =
                    request_stream->d18_accepted_params_num;
                request_stream->d18_accepted_params = merged;
                request_stream->d18_accepted_params_num = merged_count;
                merged = NULL;
                merged_count = 0;
                xqc_moq_d18_params_free(old_params, old_params_num);

                if (update_record->candidate_prefix != NULL
                    && request_stream->request_type
                        == XQC_MOQ_MSG_SUBSCRIBE_TRACKS)
                {
                    xqc_moq_namespace_prefix_t *old_prefix =
                        request_stream->tracks_subscription;
                    request_stream->tracks_subscription =
                        update_record->candidate_prefix;
                    update_record->candidate_prefix = NULL;
                    xqc_moq_namespace_prefix_destroy(old_prefix);

                } else if (update_record->candidate_prefix != NULL
                           && request_stream->request_type
                               == XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE)
                {
                    xqc_list_head_t *prefix_pos;
                    xqc_list_for_each(
                        prefix_pos,
                        &session->peer_subscribe_namespace_list)
                    {
                        xqc_moq_namespace_prefix_t *old_prefix =
                            xqc_list_entry(
                                prefix_pos,
                                xqc_moq_namespace_prefix_t,
                                list_member);
                        if (old_prefix->request_id
                            != request_stream->request_id)
                        {
                            continue;
                        }
                        xqc_list_replace(
                            &old_prefix->list_member,
                            &update_record->candidate_prefix
                                ->list_member);
                        xqc_init_list_head(
                            &old_prefix->list_member);
                        xqc_moq_namespace_prefix_destroy(
                            old_prefix);
                        update_record->candidate_prefix = NULL;
                        break;
                    }
                }
                update_record = xqc_moq_d18_update_queue_pop(
                    &request_stream->d18_peer_update_queue);
                xqc_moq_d18_update_record_destroy(update_record);

            } else {
                request_stream->response_sent = 1;
            }
            if (finish_initial_response) {
                xqc_moq_stream_finish_request(request_stream, XQC_OK);
            }
            if (is_initial && publish_subscription != NULL) {
                xqc_moq_track_set_alias(
                    publish_track,
                    publish_subscription->subscribe_msg->track_alias);
                xqc_moq_track_set_subscribe_id(
                    publish_track, request_id);

            } else if (is_initial && request_stream->request_type
                    == XQC_MOQ_MSG_SUBSCRIBE_TRACKS
                && request_stream->tracks_subscription != NULL)
            {
                request_stream->subscribe_tracks_active = 1;
                xqc_moq_session_forward_matching_publishes(
                    session,
                    request_stream->tracks_subscription->prefix_tuple,
                    request_stream->tracks_subscription->prefix_num,
                    request_stream->subscribe_tracks_forward);
            }
        } else {
            request_stream->write_stream_fin = previous_fin;
            if (is_update) {
                request_stream->write_buf_len = previous_write_len;
                request_stream->write_buf_processed =
                    previous_write_processed;
            }
        }
        xqc_moq_d18_params_free(merged, merged_count);
        return ret;
}

static xqc_int_t
xqc_moq_d18_stream_has_local_publisher(
    const xqc_moq_stream_t *request_stream)
{
    return request_stream != NULL
        && ((request_stream->local_request
             && request_stream->request_type == XQC_MOQ_MSG_PUBLISH)
            || (request_stream->peer_request
                && request_stream->request_type
                    == XQC_MOQ_MSG_SUBSCRIBE));
}

static xqc_moq_stream_t *
xqc_moq_find_d18_publish_done_stream(xqc_moq_session_t *session,
    uint64_t request_id)
{
    if (session == NULL || !session->use_unified_setup) {
        return NULL;
    }

    xqc_list_head_t *request_lists[] = {
        &session->local_request_stream_list,
        &session->peer_request_stream_list,
    };
    for (size_t i = 0;
         i < sizeof(request_lists) / sizeof(request_lists[0]); i++)
    {
        xqc_list_head_t *pos;
        xqc_list_for_each(pos, request_lists[i]) {
            xqc_moq_stream_t *request_stream =
                xqc_list_entry(pos, xqc_moq_stream_t,
                               request_list_member);
            if (request_stream->request_id == request_id
                && xqc_moq_d18_stream_has_local_publisher(
                    request_stream))
            {
                return request_stream;
            }
        }
    }
    return NULL;
}

xqc_int_t
xqc_moq_write_request_error(xqc_moq_session_t *session, uint64_t request_id,
    xqc_moq_request_error_msg_t *request_error)
{
    if (session == NULL || request_error == NULL
        || !session->use_unified_setup)
    {
        return -XQC_EPARAM;
    }

    xqc_int_t is_update = 0;
    xqc_int_t is_initial = 0;
    xqc_moq_stream_t *request_stream =
        xqc_moq_find_request_response_target(
            session, request_id, &is_update, &is_initial);
    if (request_stream == NULL) {
        return -XQC_ENULLPTR;
    }
    xqc_moq_d18_update_record_t *update_record =
        xqc_moq_d18_update_queue_peek(
            &request_stream->d18_peer_update_queue);
        if ((is_initial && request_stream->response_sent)
            || (is_update
                && ((request_stream->peer_request
                        && !request_stream->response_sent)
                    || (request_stream->local_request
                        && !request_stream->response_received))))
        {
            return -XQC_EPARAM;
        }

        uint8_t previous_fin = request_stream->write_stream_fin;
        size_t previous_write_len = request_stream->write_buf_len;
        size_t previous_write_processed =
            request_stream->write_buf_processed;
        xqc_int_t subscription_update_failed = is_update
            && (request_stream->request_type == XQC_MOQ_MSG_SUBSCRIBE
                || request_stream->request_type == XQC_MOQ_MSG_PUBLISH);
        xqc_int_t local_publisher_update_failed = is_update
            && xqc_moq_d18_stream_has_local_publisher(
                request_stream);
        request_stream->write_stream_fin =
            subscription_update_failed ? 0 : 1;
        xqc_int_t ret = xqc_moq_write_msg_generic(session, request_stream,
            &request_error->msg_base,
            XQC_MOQ_SEMANTIC_REQUEST_ERROR);
        if (ret == XQC_OK) {
            if (is_update) {
                update_record = xqc_moq_d18_update_queue_pop(
                    &request_stream->d18_peer_update_queue);
                xqc_moq_d18_update_record_destroy(update_record);
                if (local_publisher_update_failed) {
                    xqc_int_t done_ret =
                        xqc_moq_write_d18_update_failed_publish_done(
                            session, request_stream);
                    if (done_ret != XQC_OK
                        && done_ret != -XQC_EAGAIN)
                    {
                        xqc_moq_session_error(
                            session, XQC_MOQ_D18_INTERNAL_ERROR,
                            "write UPDATE_FAILED PUBLISH_DONE");
                        ret = done_ret;
                    }
                }
                if (subscription_update_failed
                    && !local_publisher_update_failed)
                {
                    request_stream->update_failed_wait_publish_done = 1;
                    xqc_moq_d18_update_queue_destroy(
                        &request_stream->d18_local_update_queue);
                    xqc_moq_d18_update_queue_destroy(
                        &request_stream->d18_peer_update_queue);

                } else if (!request_stream->d18_publish_done_pending) {
                    uint64_t finish_error = subscription_update_failed
                        ? XQC_MOQ_PUBLISH_DONE_UPDATE_FAILED
                        : request_error->error_code;
                    xqc_moq_stream_finish_request(
                        request_stream, finish_error);
                }

            } else {
                request_stream->response_sent = 1;
                xqc_moq_stream_finish_request(
                    request_stream, request_error->error_code);
            }

        } else {
            request_stream->write_stream_fin = previous_fin;
            if (is_update) {
                request_stream->write_buf_len = previous_write_len;
                request_stream->write_buf_processed =
                    previous_write_processed;
            }
        }
        return ret;
}

xqc_int_t
xqc_moq_write_d18_update_failed_publish_done(
    xqc_moq_session_t *session, xqc_moq_stream_t *request_stream)
{
    xqc_moq_publish_done_msg_t done;
    xqc_memzero(&done, sizeof(done));
    if (request_stream != NULL) {
        done.subscribe_id = request_stream->request_id;
    }
    done.status_code = XQC_MOQ_PUBLISH_DONE_UPDATE_FAILED;
    return xqc_moq_write_d18_publish_done_on_stream(
        session, request_stream, &done);
}

xqc_int_t
xqc_moq_write_goaway_draft18(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, const char *uri, size_t uri_len,
    uint64_t timeout_ms, uint64_t request_id, uint8_t control_scope)
{
    if (session == NULL || stream == NULL || !session->use_unified_setup
        || uri_len > XQC_MOQ_MAX_GOAWAY_URI_LEN
        || (uri_len > 0 && uri == NULL))
    {
        return -XQC_EPARAM;
    }

    xqc_moq_d18_stream_class_t expected_class = control_scope
        ? XQC_MOQ_D18_STREAM_CONTROL : XQC_MOQ_D18_STREAM_REQUEST;
    xqc_moq_d18_stream_direction_t expected_direction = control_scope
        ? XQC_MOQ_D18_DIRECTION_UNI : XQC_MOQ_D18_DIRECTION_BIDI;
    if (stream->d18_context.stream_class != expected_class
        || stream->d18_context.direction != expected_direction
        || stream->d18_context.position != XQC_MOQ_D18_POSITION_NEXT)
    {
        return -XQC_EILLEGAL_FRAME;
    }

    xqc_moq_d18_goaway_msg_t goaway;
    xqc_memzero(&goaway, sizeof(goaway));
    goaway.new_session_uri = (char *)uri;
    goaway.new_session_uri_len = uri_len;
    goaway.timeout_ms = timeout_ms;
    goaway.request_id = request_id;
    return xqc_moq_write_profile_message_internal(
        session, stream, &goaway.msg_base,
        XQC_MOQ_SEMANTIC_GOAWAY_DRAFT18, XQC_TRUE);
}

xqc_int_t
xqc_moq_write_going_away_request_error(
    xqc_moq_session_t *session, xqc_moq_stream_t *stream)
{
    if (session == NULL || stream == NULL || !session->use_unified_setup
        || stream->write_stream_fin)
    {
        return -XQC_EPARAM;
    }

    xqc_moq_request_error_msg_t error;
    xqc_memzero(&error, sizeof(error));
    error.error_code = XQC_MOQ_REQUEST_ERROR_GOING_AWAY;
    uint8_t previous_fin = stream->write_stream_fin;
    stream->write_stream_fin = 1;
    xqc_int_t ret = xqc_moq_write_profile_message_internal(
        session, stream, &error.msg_base,
        XQC_MOQ_SEMANTIC_REQUEST_ERROR, XQC_TRUE);
    if (ret != XQC_OK) {
        stream->write_stream_fin = previous_fin;
    }
    return ret;
}

xqc_int_t
xqc_moq_write_going_away_request_update_error(
    xqc_moq_session_t *session, xqc_moq_stream_t *stream)
{
    if (session == NULL || stream == NULL || !session->use_unified_setup
        || stream->write_stream_fin)
    {
        return -XQC_EPARAM;
    }

    xqc_moq_request_error_msg_t error;
    xqc_memzero(&error, sizeof(error));
    error.error_code = XQC_MOQ_REQUEST_ERROR_GOING_AWAY;
    return xqc_moq_write_profile_message_internal(
        session, stream, &error.msg_base,
        XQC_MOQ_SEMANTIC_REQUEST_ERROR, XQC_TRUE);
}
static xqc_moq_stream_t *
xqc_moq_find_request_update_target(xqc_moq_session_t *session,
    uint64_t target_request_id)
{
    xqc_list_head_t *lists[] = {
        &session->local_request_stream_list,
        &session->peer_request_stream_list,
    };
    for (size_t i = 0; i < sizeof(lists) / sizeof(lists[0]); i++) {
        xqc_list_head_t *pos;
        xqc_list_for_each(pos, lists[i]) {
            xqc_moq_stream_t *stream =
                xqc_list_entry(pos, xqc_moq_stream_t,
                               request_list_member);
            if (stream->request_id == target_request_id
                && !stream->update_failed_wait_publish_done
                && ((stream->local_request && stream->response_received)
                    || (stream->peer_request
                        && stream->request_type == XQC_MOQ_MSG_PUBLISH
                        && stream->response_sent)))
            {
                return stream;
            }
        }
    }
    return NULL;
}

static xqc_int_t
xqc_moq_request_update_context(xqc_moq_msg_type_t request_type,
    xqc_moq_d18_param_context_t *context)
{
    switch (request_type) {
    case XQC_MOQ_MSG_SUBSCRIBE:
    case XQC_MOQ_MSG_PUBLISH:
        *context = XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_SUBSCRIBE;
        return XQC_OK;
    case XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE:
    case XQC_MOQ_MSG_SUBSCRIBE_TRACKS:
    case XQC_MOQ_MSG_PUBLISH_NAMESPACE:
        *context = XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_NAMESPACE;
        return XQC_OK;
    default:
        if (request_type == (xqc_moq_msg_type_t)XQC_MOQ_D18_MSG_FETCH) {
            *context = XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_FETCH;
            return XQC_OK;
        }
        return -XQC_EPARAM;
    }
}

xqc_int_t
xqc_moq_write_request_update(xqc_moq_session_t *session,
    uint64_t target_request_id, xqc_moq_request_update_msg_t *update)
{
    if (session == NULL || update == NULL || !session->use_unified_setup)
    {
        return -XQC_EPARAM;
    }
    if (xqc_moq_session_admit_local_initial_request(session) != XQC_OK) {
        return -XQC_EPARAM;
    }

    xqc_moq_stream_t *request_stream =
        xqc_moq_find_request_update_target(session, target_request_id);
    xqc_moq_d18_param_context_t context;
    if (request_stream == NULL || request_stream->request_closed_notified
        || request_stream->update_failed_wait_publish_done
        || xqc_moq_request_update_context(
               request_stream->request_type, &context) != XQC_OK)
    {
        return -XQC_EPARAM;
    }

    if (update->request_id == 0) {
        update->request_id = xqc_moq_session_alloc_request_id(session);
    }
    xqc_moq_d18_update_record_t *record = NULL;
    if (xqc_moq_d18_update_record_create(
            update->request_id, update->params,
            (size_t)update->params_num, &record)
        != XQC_MOQ_D18_UPDATE_OK)
    {
        return -XQC_EMALLOC;
    }
    if (context == XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_NAMESPACE) {
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
            && request_stream->request_type
                == XQC_MOQ_MSG_PUBLISH_NAMESPACE)
        {
            xqc_moq_d18_update_record_destroy(record);
            return -XQC_EPARAM;
        }
        if (prefix_param != NULL) {
            record->candidate_prefix =
                xqc_moq_namespace_prefix_create_serialized(
                    prefix_param->value,
                    (size_t)prefix_param->length);
            if (record->candidate_prefix == NULL) {
                xqc_moq_d18_update_record_destroy(record);
                return -XQC_EPARAM;
            }
            record->candidate_prefix->request_id = target_request_id;
        }
    }
    xqc_int_t ret = xqc_moq_register_local_request_id(
        session, update->request_id);
    if (ret != XQC_OK) {
        xqc_moq_d18_update_record_destroy(record);
        return ret;
    }
    if (xqc_moq_d18_update_queue_push(
            &request_stream->d18_local_update_queue, record)
        != XQC_MOQ_D18_UPDATE_OK)
    {
        (void)xqc_moq_session_unregister_local_request_id(
            session, update->request_id);
        xqc_moq_d18_update_record_destroy(record);
        return -XQC_EPARAM;
    }

    update->d18_param_context = (uint8_t)context;
    ret = xqc_moq_write_msg_generic_atomic(
        session, request_stream, &update->msg_base,
        XQC_MOQ_SEMANTIC_REQUEST_UPDATE);
    if (ret != XQC_OK) {
        xqc_list_del_init(&record->list_member);
        (void)xqc_moq_session_unregister_local_request_id(
            session, update->request_id);
        xqc_moq_d18_update_record_destroy(record);
    }
    return ret;
}
