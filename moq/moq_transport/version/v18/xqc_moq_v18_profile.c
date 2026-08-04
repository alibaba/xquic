#include "moq/moq_transport/xqc_moq_message.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_control.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_data.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_defs.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_registry.h"
#include "moq/moq_transport/version/xqc_moq_version.h"

#define D18_CONTROL_MASK XQC_MOQ_STREAM_KIND_MASK(XQC_MOQ_STREAM_CONTROL)
#define D18_REQUEST_MASK \
    XQC_MOQ_STREAM_KIND_MASK(XQC_MOQ_STREAM_D18_REQUEST)
#define D18_SUBGROUP_MASK \
    XQC_MOQ_STREAM_KIND_MASK(XQC_MOQ_STREAM_D18_SUBGROUP)
#define D18_FETCH_MASK XQC_MOQ_STREAM_KIND_MASK(XQC_MOQ_STREAM_D18_FETCH)

static void
xqc_moq_v18_request_update_init(xqc_moq_msg_base_t *base)
{
    xqc_moq_request_update_msg_t *update =
        (xqc_moq_request_update_msg_t *)base;
    xqc_moq_d18_request_update_init_handler(
        base, (xqc_moq_d18_param_context_t)update->d18_param_context);
}

static const xqc_moq_message_codec_entry_t xqc_moq_v18_control_codecs[] = {
    {XQC_MOQ_D18_STREAM_TYPE_SETUP, xqc_moq_msg_create_setup,
     xqc_moq_msg_free_setup, xqc_moq_msg_setup_init_handler,
     XQC_MOQ_SEMANTIC_SETUP, D18_CONTROL_MASK},
    {XQC_MOQ_D18_MSG_GOAWAY, xqc_moq_d18_goaway_create,
     xqc_moq_d18_goaway_free, xqc_moq_d18_control_goaway_init_handler,
     XQC_MOQ_SEMANTIC_GOAWAY_DRAFT18, D18_CONTROL_MASK},
};

static const xqc_moq_message_codec_entry_t xqc_moq_v18_request_codecs[] = {
    {XQC_MOQ_D18_MSG_SUBSCRIBE, xqc_moq_msg_create_subscribe,
     xqc_moq_msg_free_subscribe, xqc_moq_msg_subscribe_request_init_handler,
     XQC_MOQ_SEMANTIC_SUBSCRIBE, D18_REQUEST_MASK},
    {XQC_MOQ_D18_MSG_SUBSCRIBE_OK, xqc_moq_msg_create_subscribe_ok,
     xqc_moq_msg_free_subscribe_ok,
     xqc_moq_msg_subscribe_ok_response_init_handler,
     XQC_MOQ_SEMANTIC_SUBSCRIBE_OK, D18_REQUEST_MASK},
    {XQC_MOQ_D18_MSG_PUBLISH, xqc_moq_msg_create_publish,
     xqc_moq_msg_free_publish, xqc_moq_msg_publish_request_init_handler,
     XQC_MOQ_SEMANTIC_PUBLISH, D18_REQUEST_MASK},
    {XQC_MOQ_D18_MSG_PUBLISH_OK, xqc_moq_msg_create_publish_ok,
     xqc_moq_msg_free_publish_ok, xqc_moq_msg_publish_ok_init_handler,
     XQC_MOQ_SEMANTIC_PUBLISH_OK, D18_REQUEST_MASK},
    {XQC_MOQ_D18_MSG_PUBLISH_DONE, xqc_moq_d18_publish_done_create,
     xqc_moq_d18_publish_done_free, xqc_moq_d18_publish_done_init_handler,
     XQC_MOQ_SEMANTIC_PUBLISH_DONE, D18_REQUEST_MASK},
    {XQC_MOQ_D18_MSG_PUBLISH_NAMESPACE,
     xqc_moq_msg_create_publish_namespace,
     xqc_moq_msg_free_publish_namespace,
     xqc_moq_msg_publish_namespace_vi64_init_handler,
     XQC_MOQ_SEMANTIC_PUBLISH_NAMESPACE, D18_REQUEST_MASK},
    {XQC_MOQ_D18_MSG_SUBSCRIBE_NAMESPACE,
     xqc_moq_msg_create_subscribe_namespace,
     xqc_moq_msg_free_subscribe_namespace,
     xqc_moq_msg_subscribe_namespace_request_init_handler,
     XQC_MOQ_SEMANTIC_SUBSCRIBE_NAMESPACE, D18_REQUEST_MASK},
    {XQC_MOQ_D18_MSG_SUBSCRIBE_TRACKS,
     xqc_moq_msg_create_subscribe_tracks,
     xqc_moq_msg_free_subscribe_tracks,
     xqc_moq_msg_subscribe_tracks_init_handler,
     XQC_MOQ_SEMANTIC_SUBSCRIBE_TRACKS, D18_REQUEST_MASK},
    {XQC_MOQ_D18_MSG_NAMESPACE, xqc_moq_msg_create_namespace,
     xqc_moq_msg_free_namespace, xqc_moq_msg_namespace_init_handler,
     XQC_MOQ_SEMANTIC_NAMESPACE, D18_REQUEST_MASK},
    {XQC_MOQ_D18_MSG_NAMESPACE_DONE, xqc_moq_msg_create_namespace,
     xqc_moq_msg_free_namespace, xqc_moq_msg_namespace_done_init_handler,
     XQC_MOQ_SEMANTIC_NAMESPACE_DONE, D18_REQUEST_MASK},
    {XQC_MOQ_D18_MSG_PUBLISH_BLOCKED,
     xqc_moq_d18_publish_blocked_create,
     xqc_moq_d18_publish_blocked_free,
     xqc_moq_d18_publish_blocked_init_handler,
     XQC_MOQ_SEMANTIC_PUBLISH_BLOCKED, D18_REQUEST_MASK},
    {XQC_MOQ_D18_MSG_REQUEST_UPDATE, xqc_moq_d18_request_update_create,
     xqc_moq_d18_request_update_free, xqc_moq_v18_request_update_init,
     XQC_MOQ_SEMANTIC_REQUEST_UPDATE, D18_REQUEST_MASK},
    {XQC_MOQ_D18_MSG_REQUEST_OK, xqc_moq_msg_create_request_ok,
     xqc_moq_msg_free_request_ok, xqc_moq_msg_request_ok_init_handler,
     XQC_MOQ_SEMANTIC_REQUEST_OK, D18_REQUEST_MASK},
    {XQC_MOQ_D18_MSG_REQUEST_ERROR, xqc_moq_msg_create_request_error,
     xqc_moq_msg_free_request_error, xqc_moq_msg_request_error_init_handler,
     XQC_MOQ_SEMANTIC_REQUEST_ERROR, D18_REQUEST_MASK},
    {XQC_MOQ_D18_MSG_GOAWAY, xqc_moq_d18_goaway_create,
     xqc_moq_d18_goaway_free, xqc_moq_d18_request_goaway_init_handler,
     XQC_MOQ_SEMANTIC_GOAWAY_DRAFT18, D18_REQUEST_MASK},
    {XQC_MOQ_D18_MSG_FETCH, xqc_moq_d18_fetch_create,
     xqc_moq_d18_fetch_free, xqc_moq_d18_fetch_init_handler,
     XQC_MOQ_SEMANTIC_FETCH, D18_REQUEST_MASK},
    {XQC_MOQ_D18_MSG_FETCH_OK, xqc_moq_d18_fetch_ok_create,
     xqc_moq_d18_fetch_ok_free, xqc_moq_d18_fetch_ok_init_handler,
     XQC_MOQ_SEMANTIC_FETCH_OK, D18_REQUEST_MASK},
    {XQC_MOQ_D18_MSG_TRACK_STATUS, xqc_moq_d18_track_status_create,
     xqc_moq_d18_track_status_free, xqc_moq_d18_track_status_init_handler,
     XQC_MOQ_SEMANTIC_TRACK_STATUS, D18_REQUEST_MASK},
    {XQC_MOQ_D18_STREAM_TYPE_FETCH, xqc_moq_d18_fetch_header_create,
     xqc_moq_d18_fetch_header_free, xqc_moq_d18_fetch_header_init_handler,
     XQC_MOQ_SEMANTIC_FETCH_HEADER, D18_FETCH_MASK},
    {XQC_MOQ_SUBGROUP_TYPE_WITH_ID,
     (void *(*)(void))xqc_moq_d18_data_msg_create,
     xqc_moq_d18_data_msg_destroy, xqc_moq_d18_subgroup_header_init,
     XQC_MOQ_SEMANTIC_SUBGROUP, D18_SUBGROUP_MASK},
};

static const xqc_moq_message_codec_entry_t
xqc_moq_v18_continuation_codecs[] = {
    {0, (void *(*)(void))xqc_moq_d18_data_msg_create,
     xqc_moq_d18_data_msg_destroy,
     xqc_moq_d18_subgroup_object_init,
     XQC_MOQ_SEMANTIC_SUBGROUP_OBJECT, D18_SUBGROUP_MASK},
    {XQC_MOQ_D18_STREAM_TYPE_FETCH,
     (void *(*)(void))xqc_moq_d18_data_msg_create,
     xqc_moq_d18_data_msg_destroy, xqc_moq_d18_fetch_object_init,
     XQC_MOQ_SEMANTIC_FETCH_OBJECT, D18_FETCH_MASK},
};

static xqc_moq_stream_kind_t
xqc_moq_v18_classify_stream(xqc_moq_stream_kind_t current_kind,
    uint64_t wire_type)
{
    if (current_kind != XQC_MOQ_STREAM_UNKNOWN) {
        return current_kind;
    }
    if (wire_type == XQC_MOQ_D18_STREAM_TYPE_SETUP) {
        return XQC_MOQ_STREAM_CONTROL;
    }
    if (xqc_moq_d18_is_subgroup_header_type(wire_type)) {
        return XQC_MOQ_STREAM_D18_SUBGROUP;
    }
    return XQC_MOQ_STREAM_D18_REQUEST;
}

static xqc_moq_stream_kind_t
xqc_moq_v18_classify_outbound_stream(
    xqc_moq_stream_kind_t current_kind,
    xqc_moq_semantic_id_t semantic, uint64_t wire_type)
{
    (void)wire_type;
    if (current_kind != XQC_MOQ_STREAM_UNKNOWN) {
        return current_kind;
    }
    switch (semantic) {
    case XQC_MOQ_SEMANTIC_SETUP:
    case XQC_MOQ_SEMANTIC_CLIENT_SETUP:
    case XQC_MOQ_SEMANTIC_SERVER_SETUP:
        return XQC_MOQ_STREAM_CONTROL;
    case XQC_MOQ_SEMANTIC_SUBGROUP:
    case XQC_MOQ_SEMANTIC_SUBGROUP_OBJECT:
        return XQC_MOQ_STREAM_D18_SUBGROUP;
    case XQC_MOQ_SEMANTIC_FETCH_HEADER:
        return XQC_MOQ_STREAM_D18_FETCH;
    default:
        return XQC_MOQ_STREAM_D18_REQUEST;
    }
}

static uint64_t
xqc_moq_v18_normalize_wire_type(xqc_moq_stream_kind_t stream_kind,
    uint64_t wire_type)
{
    if (stream_kind == XQC_MOQ_STREAM_D18_SUBGROUP
        && xqc_moq_d18_is_subgroup_header_type(wire_type))
    {
        return XQC_MOQ_SUBGROUP_TYPE_WITH_ID;
    }
    return wire_type;
}

static xqc_bool_t
xqc_moq_v18_next_data_semantic(xqc_moq_stream_kind_t stream_kind,
    uint64_t current_wire_type,
    xqc_moq_semantic_id_t *next_semantic)
{
    if (stream_kind == XQC_MOQ_STREAM_D18_SUBGROUP
        && xqc_moq_d18_is_subgroup_header_type(current_wire_type))
    {
        *next_semantic = XQC_MOQ_SEMANTIC_SUBGROUP_OBJECT;
        return XQC_TRUE;
    }
    if (stream_kind == XQC_MOQ_STREAM_D18_FETCH
        && current_wire_type == XQC_MOQ_D18_STREAM_TYPE_FETCH)
    {
        *next_semantic = XQC_MOQ_SEMANTIC_FETCH_OBJECT;
        return XQC_TRUE;
    }
    return XQC_FALSE;
}

static xqc_int_t
xqc_moq_v18_resolve_outbound(xqc_moq_stream_kind_t current_kind,
    xqc_moq_semantic_id_t semantic, uint64_t *wire_type)
{
    (void)current_kind;
    if (wire_type == NULL) {
        return -XQC_EPARAM;
    }
    switch (semantic) {
    case XQC_MOQ_SEMANTIC_SETUP:
        *wire_type = XQC_MOQ_D18_STREAM_TYPE_SETUP;
        break;
    case XQC_MOQ_SEMANTIC_SUBSCRIBE:
        *wire_type = XQC_MOQ_D18_MSG_SUBSCRIBE;
        break;
    case XQC_MOQ_SEMANTIC_SUBSCRIBE_OK:
        *wire_type = XQC_MOQ_D18_MSG_SUBSCRIBE_OK;
        break;
    case XQC_MOQ_SEMANTIC_PUBLISH:
        *wire_type = XQC_MOQ_D18_MSG_PUBLISH;
        break;
    case XQC_MOQ_SEMANTIC_PUBLISH_OK:
        *wire_type = XQC_MOQ_D18_MSG_PUBLISH_OK;
        break;
    case XQC_MOQ_SEMANTIC_PUBLISH_DONE:
        *wire_type = XQC_MOQ_D18_MSG_PUBLISH_DONE;
        break;
    case XQC_MOQ_SEMANTIC_PUBLISH_NAMESPACE:
        *wire_type = XQC_MOQ_D18_MSG_PUBLISH_NAMESPACE;
        break;
    case XQC_MOQ_SEMANTIC_SUBSCRIBE_NAMESPACE:
        *wire_type = XQC_MOQ_D18_MSG_SUBSCRIBE_NAMESPACE;
        break;
    case XQC_MOQ_SEMANTIC_SUBSCRIBE_TRACKS:
        *wire_type = XQC_MOQ_D18_MSG_SUBSCRIBE_TRACKS;
        break;
    case XQC_MOQ_SEMANTIC_NAMESPACE:
        *wire_type = XQC_MOQ_D18_MSG_NAMESPACE;
        break;
    case XQC_MOQ_SEMANTIC_NAMESPACE_DONE:
    case XQC_MOQ_SEMANTIC_PUBLISH_NAMESPACE_DONE:
        *wire_type = XQC_MOQ_D18_MSG_NAMESPACE_DONE;
        break;
    case XQC_MOQ_SEMANTIC_PUBLISH_BLOCKED:
        *wire_type = XQC_MOQ_D18_MSG_PUBLISH_BLOCKED;
        break;
    case XQC_MOQ_SEMANTIC_REQUEST_UPDATE:
        *wire_type = XQC_MOQ_D18_MSG_REQUEST_UPDATE;
        break;
    case XQC_MOQ_SEMANTIC_REQUEST_OK:
        *wire_type = XQC_MOQ_D18_MSG_REQUEST_OK;
        break;
    case XQC_MOQ_SEMANTIC_REQUEST_ERROR:
        *wire_type = XQC_MOQ_D18_MSG_REQUEST_ERROR;
        break;
    case XQC_MOQ_SEMANTIC_GOAWAY_DRAFT18:
        *wire_type = XQC_MOQ_D18_MSG_GOAWAY;
        break;
    case XQC_MOQ_SEMANTIC_FETCH:
        *wire_type = XQC_MOQ_D18_MSG_FETCH;
        break;
    case XQC_MOQ_SEMANTIC_FETCH_OK:
        *wire_type = XQC_MOQ_D18_MSG_FETCH_OK;
        break;
    case XQC_MOQ_SEMANTIC_TRACK_STATUS:
        *wire_type = XQC_MOQ_D18_MSG_TRACK_STATUS;
        break;
    case XQC_MOQ_SEMANTIC_SUBGROUP:
        *wire_type = XQC_MOQ_D18_SUBGROUP_BASE | 0x04;
        break;
    case XQC_MOQ_SEMANTIC_SUBGROUP_OBJECT:
        *wire_type = 0;
        break;
    case XQC_MOQ_SEMANTIC_FETCH_HEADER:
        *wire_type = XQC_MOQ_D18_STREAM_TYPE_FETCH;
        break;
    case XQC_MOQ_SEMANTIC_FETCH_OBJECT:
        *wire_type = 0;
        break;
    default:
        return -XQC_EALPN_NOT_SUPPORTED;
    }
    return XQC_OK;
}

static xqc_int_t
xqc_moq_v18_prepare_data_message(xqc_moq_stream_t *stream,
    const xqc_moq_message_codec_entry_t *codec,
    xqc_moq_msg_base_t *msg_base)
{
    if (codec->semantic == XQC_MOQ_SEMANTIC_SUBGROUP_OBJECT) {
        if (!stream->subgroup_header_valid) {
            return -XQC_EILLEGAL_FRAME;
        }
        xqc_moq_d18_data_msg_t *subgroup =
            (xqc_moq_d18_data_msg_t *)msg_base;
        subgroup->object.track_alias = stream->subgroup_header.track_alias;
        subgroup->object.group_id = stream->subgroup_header.group_id;
        subgroup->object.subgroup_id = stream->subgroup_header.subgroup_id;
        subgroup->object.publisher_priority =
            stream->subgroup_header.subgroup_priority;
        subgroup->object.publisher_priority_set = 1;
        subgroup->subgroup_wire_type =
            stream->subgroup_header.subgroup_type;
        subgroup->subgroup_id_mode =
            stream->subgroup_header.subgroup_id_mode;
        subgroup->properties_present =
            stream->subgroup_header.properties_present;
        subgroup->default_priority =
            stream->subgroup_header.default_priority;
        xqc_moq_d18_data_msg_set_previous(
            subgroup, stream->subgroup_header.group_id,
            stream->subgroup_prev_object_id,
            stream->subgroup_header.subgroup_id,
            stream->subgroup_header.subgroup_priority,
            stream->subgroup_prev_object_id_valid);
        return XQC_OK;
    }

    if (codec->semantic == XQC_MOQ_SEMANTIC_FETCH_OBJECT) {
        if (stream->fetch_request_stream == NULL) {
            return -XQC_EILLEGAL_FRAME;
        }
        xqc_moq_d18_data_msg_t *fetch =
            (xqc_moq_d18_data_msg_t *)msg_base;
        fetch->request_id = stream->request_id;
        fetch->group_order =
            stream->fetch_request_stream->d18_fetch_group_order;
        xqc_moq_d18_data_msg_set_previous(
            fetch, stream->d18_fetch_previous_group_id,
            stream->d18_fetch_previous_object_id,
            stream->d18_fetch_previous_subgroup_id,
            stream->d18_fetch_previous_priority,
            stream->d18_fetch_previous_valid);
        fetch->previous_actual_valid =
            stream->d18_fetch_previous_actual_valid;
        return XQC_OK;
    }

    if (codec->semantic == XQC_MOQ_SEMANTIC_REQUEST_OK) {
        xqc_moq_request_ok_msg_t *ok =
            (xqc_moq_request_ok_msg_t *)msg_base;
        ok->d18_param_context = XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_OK;
        if ((stream->local_request && !stream->response_received)
            || (stream->peer_request && !stream->response_sent))
        {
            switch (stream->request_type) {
            case XQC_MOQ_MSG_SUBSCRIBE:
                ok->d18_param_context =
                    XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE_OK;
                break;
            case XQC_MOQ_MSG_PUBLISH:
                ok->d18_param_context =
                    XQC_MOQ_D18_PARAM_CONTEXT_PUBLISH_OK;
                break;
            default:
                if (stream->request_type
                    == (xqc_moq_msg_type_t)XQC_MOQ_D18_MSG_TRACK_STATUS)
                {
                    ok->d18_param_context =
                        XQC_MOQ_D18_PARAM_CONTEXT_TRACK_STATUS_OK;
                }
                break;
            }
        }
        return XQC_OK;
    }

    if (codec->wire_type != XQC_MOQ_D18_MSG_REQUEST_UPDATE) {
        return XQC_OK;
    }

    xqc_moq_d18_param_context_t context;
    switch (stream->request_type) {
    case XQC_MOQ_MSG_SUBSCRIBE:
    case XQC_MOQ_MSG_PUBLISH:
        context = XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_SUBSCRIBE;
        break;
    case XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE:
    case XQC_MOQ_MSG_SUBSCRIBE_TRACKS:
    case XQC_MOQ_MSG_PUBLISH_NAMESPACE:
        context = XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_NAMESPACE;
        break;
    default:
        if (stream->request_type
            != (xqc_moq_msg_type_t)XQC_MOQ_D18_MSG_FETCH)
        {
            return -XQC_EILLEGAL_FRAME;
        }
        context = XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_FETCH;
        break;
    }

    xqc_moq_d18_request_update_init_handler(msg_base, context);
    return XQC_OK;
}

const xqc_moq_version_profile_t xqc_moq_v18_profile_definition = {
    .name = "draft-18",
    .wire_version = XQC_MOQ_VERSION_18,
    .capabilities = XQC_MOQ_CAP_SUBGROUP_STREAM
                    | XQC_MOQ_CAP_OBJECT_DATAGRAM
                    | XQC_MOQ_CAP_PUBLISH
                    | XQC_MOQ_CAP_SUBSCRIBE_NAMESPACE,
    .client_setup_type = XQC_MOQ_D18_STREAM_TYPE_SETUP,
    .server_setup_type = XQC_MOQ_D18_STREAM_TYPE_SETUP,
    .unified_setup = XQC_TRUE,
    .include_extdata_in_default_setup = XQC_FALSE,
    .catalog_default_enabled = XQC_FALSE,
    .data_strategy = XQC_MOQ_DATA_STRATEGY_SUBGROUP,
    .control_codecs = xqc_moq_v18_control_codecs,
    .control_codecs_count = sizeof(xqc_moq_v18_control_codecs)
                            / sizeof(xqc_moq_v18_control_codecs[0]),
    .data_codecs = xqc_moq_v18_request_codecs,
    .data_codecs_count = sizeof(xqc_moq_v18_request_codecs)
                         / sizeof(xqc_moq_v18_request_codecs[0]),
    .continuation_codecs = xqc_moq_v18_continuation_codecs,
    .continuation_codecs_count =
        sizeof(xqc_moq_v18_continuation_codecs)
        / sizeof(xqc_moq_v18_continuation_codecs[0]),
    .classify_stream = xqc_moq_v18_classify_stream,
    .classify_outbound_stream = xqc_moq_v18_classify_outbound_stream,
    .normalize_wire_type = xqc_moq_v18_normalize_wire_type,
    .next_data_semantic = xqc_moq_v18_next_data_semantic,
    .prepare_data_message = xqc_moq_v18_prepare_data_message,
    .decode_datagram = xqc_moq_d18_decode_datagram,
    .resolve_outbound = xqc_moq_v18_resolve_outbound,
};

const xqc_moq_version_profile_t *
xqc_moq_v18_profile(void)
{
    return &xqc_moq_v18_profile_definition;
}
