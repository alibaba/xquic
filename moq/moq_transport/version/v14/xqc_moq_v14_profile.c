#include "moq/moq_transport/xqc_moq_message.h"
#include "moq/moq_transport/xqc_moq_message_handler.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_transport/version/xqc_moq_version.h"

static const xqc_moq_message_codec_entry_t xqc_moq_v14_control_codecs[] = {
    {XQC_MOQ_MSG_SUBSCRIBE_UPDATE, xqc_moq_msg_create_subscribe_update,
     xqc_moq_msg_free_subscribe_update,
     xqc_moq_msg_subscribe_update_init_handler},
    {XQC_MOQ_MSG_SUBSCRIBE, xqc_moq_msg_create_subscribe,
     xqc_moq_msg_free_subscribe, xqc_moq_msg_subscribe_init_handler},
    {XQC_MOQ_MSG_SUBSCRIBE_OK, xqc_moq_msg_create_subscribe_ok,
     xqc_moq_msg_free_subscribe_ok, xqc_moq_msg_subscribe_ok_init_handler},
    {XQC_MOQ_MSG_SUBSCRIBE_ERROR, xqc_moq_msg_create_subscribe_error,
     xqc_moq_msg_free_subscribe_error,
     xqc_moq_msg_subscribe_error_init_handler},
    {XQC_MOQ_MSG_PUBLISH_NAMESPACE, xqc_moq_msg_create_publish_namespace,
     xqc_moq_msg_free_publish_namespace,
     xqc_moq_msg_publish_namespace_init_handler},
    {XQC_MOQ_MSG_PUBLISH_NAMESPACE_DONE,
     xqc_moq_msg_create_publish_namespace_done,
     xqc_moq_msg_free_publish_namespace_done,
     xqc_moq_msg_publish_namespace_done_init_handler},
    {XQC_MOQ_MSG_UNSUBSCRIBE, xqc_moq_msg_create_unsubscribe,
     xqc_moq_msg_free_unsubscribe, xqc_moq_msg_unsubscribe_init_handler},
    {XQC_MOQ_MSG_PUBLISH, xqc_moq_msg_create_publish,
     xqc_moq_msg_free_publish, xqc_moq_msg_publish_init_handler},
    {XQC_MOQ_MSG_PUBLISH_OK, xqc_moq_msg_create_publish_ok,
     xqc_moq_msg_free_publish_ok, xqc_moq_msg_publish_ok_init_handler},
    {XQC_MOQ_MSG_PUBLISH_ERROR, xqc_moq_msg_create_publish_error,
     xqc_moq_msg_free_publish_error,
     xqc_moq_msg_publish_error_init_handler},
    {XQC_MOQ_MSG_PUBLISH_DONE, xqc_moq_msg_create_publish_done,
     xqc_moq_msg_free_publish_done,
     xqc_moq_msg_publish_done_init_handler},
    {XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE,
     xqc_moq_msg_create_subscribe_namespace,
     xqc_moq_msg_free_subscribe_namespace,
     xqc_moq_msg_subscribe_namespace_init_handler},
    {XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE_OK,
     xqc_moq_msg_create_subscribe_namespace_ok,
     xqc_moq_msg_free_subscribe_namespace_ok,
     xqc_moq_msg_subscribe_namespace_ok_init_handler},
    {XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE_ERROR,
     xqc_moq_msg_create_subscribe_namespace_error,
     xqc_moq_msg_free_subscribe_namespace_error,
     xqc_moq_msg_subscribe_namespace_error_init_handler},
    {XQC_MOQ_MSG_UNSUBSCRIBE_NAMESPACE,
     xqc_moq_msg_create_unsubscribe_namespace,
     xqc_moq_msg_free_unsubscribe_namespace,
     xqc_moq_msg_unsubscribe_namespace_init_handler},
    {XQC_MOQ_MSG_GOAWAY, xqc_moq_msg_create_goaway,
     xqc_moq_msg_free_goaway, xqc_moq_msg_goaway_init_handler},
    {XQC_MOQ_MSG_CLIENT_SETUP_V14, xqc_moq_msg_create_client_setup_v14,
     xqc_moq_msg_free_client_setup_v14,
     xqc_moq_msg_client_setup_v14_init_handler},
    {XQC_MOQ_MSG_SERVER_SETUP_V14, xqc_moq_msg_create_server_setup_v14,
     xqc_moq_msg_free_server_setup_v14,
     xqc_moq_msg_server_setup_v14_init_handler},
};

static const xqc_moq_message_codec_entry_t xqc_moq_v14_data_codecs[] = {
    {XQC_MOQ_MSG_SUBGROUP, xqc_moq_msg_create_subgroup,
     xqc_moq_msg_free_subgroup, xqc_moq_msg_subgroup_init_handler},
};

static xqc_moq_stream_kind_t
xqc_moq_v14_classify_stream(xqc_moq_stream_kind_t current_kind,
    uint64_t wire_type)
{
    if (current_kind != XQC_MOQ_STREAM_UNKNOWN) {
        return current_kind;
    }

    if (wire_type >= 0x10 && wire_type <= 0x1d) {
        return XQC_MOQ_STREAM_V14_SUBGROUP;
    }

    return XQC_MOQ_STREAM_UNKNOWN;
}

static uint64_t
xqc_moq_v14_normalize_wire_type(xqc_moq_stream_kind_t stream_kind,
    uint64_t wire_type)
{
    if (stream_kind == XQC_MOQ_STREAM_V14_SUBGROUP
        && ((wire_type >= 0x10 && wire_type <= 0x1d)
            || wire_type == XQC_MOQ_MSG_SUBGROUP_STREAM_OBJECT))
    {
        return XQC_MOQ_MSG_SUBGROUP;
    }

    return wire_type;
}

static xqc_bool_t
xqc_moq_v14_next_data_message(xqc_moq_stream_kind_t stream_kind,
    uint64_t current_wire_type, uint64_t *next_wire_type)
{
    if (stream_kind != XQC_MOQ_STREAM_V14_SUBGROUP) {
        return XQC_FALSE;
    }

    if ((current_wire_type >= 0x10 && current_wire_type <= 0x1d)
        || current_wire_type == XQC_MOQ_MSG_SUBGROUP_STREAM_OBJECT)
    {
        *next_wire_type = XQC_MOQ_MSG_SUBGROUP_STREAM_OBJECT;
        return XQC_TRUE;
    }

    return XQC_FALSE;
}

static xqc_int_t
xqc_moq_v14_prepare_data_message(xqc_moq_stream_t *stream,
    uint64_t wire_type, xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_subgroup_msg_t *subgroup;

    if (wire_type != XQC_MOQ_MSG_SUBGROUP_STREAM_OBJECT) {
        return XQC_OK;
    }

    if (!stream->subgroup_header_valid) {
        return -XQC_EILLEGAL_FRAME;
    }

    subgroup = (xqc_moq_subgroup_msg_t *)msg_base;
    subgroup->track_alias = stream->subgroup_header.track_alias;
    subgroup->group_id = stream->subgroup_header.group_id;
    subgroup->subgroup_id = stream->subgroup_header.subgroup_id;
    subgroup->subgroup_type = stream->subgroup_header.subgroup_type;
    subgroup->subgroup_priority = stream->subgroup_header.subgroup_priority;
    if (stream->decode_msg_ctx.cur_field_idx < 4) {
        stream->decode_msg_ctx.cur_field_idx = 4;
    }

    return XQC_OK;
}

static xqc_int_t
xqc_moq_v14_decode_datagram(xqc_moq_session_t *session,
    const uint8_t *data, size_t data_len)
{
    xqc_moq_object_datagram_msg_t dgram;
    xqc_moq_object_t object;
    xqc_int_t ret;

    xqc_memzero(&dgram, sizeof(dgram));
    ret = xqc_moq_object_datagram_decode((uint8_t *)data, data_len, &dgram);
    if (ret < 0) {
        xqc_moq_object_datagram_free_fields(&dgram);
        return ret;
    }

    xqc_memzero(&object, sizeof(object));
    object.subscribe_id = 0;
    object.track_alias = dgram.track_alias;
    object.group_id = dgram.group_id;
    object.object_id = dgram.object_id;
    object.publisher_priority_set = 1;
    object.publisher_priority = dgram.publisher_priority;
    object.status = dgram.payload_len > 0
                    ? XQC_MOQ_OBJ_STATUS_NORMAL : dgram.status;
    object.ext_params_num = dgram.ext_params_num;
    object.ext_params = dgram.ext_params;
    object.payload = dgram.payload;
    object.payload_len = dgram.payload_len;
    object.forwarding_preference = XQC_MOQ_FORWARDING_DATAGRAM;

    xqc_log(session->log, XQC_LOG_DEBUG,
            "|moq_datagram_recv|profile:%s|type:%ui|track_alias:%ui|group_id:%ui|object_id:%ui|prio:%ud|payload_len:%ui|",
            session->profile->name, dgram.type, dgram.track_alias,
            dgram.group_id, dgram.object_id, dgram.publisher_priority,
            dgram.payload_len);

    xqc_moq_on_datagram_object(session, &object);
    xqc_moq_object_datagram_free_fields(&dgram);
    return XQC_OK;
}

const xqc_moq_version_profile_t xqc_moq_v14_profile_definition = {
    .name = "draft-14",
    .wire_version = XQC_MOQ_VERSION_14,
    .capabilities = XQC_MOQ_CAP_SUBGROUP_STREAM
                    | XQC_MOQ_CAP_OBJECT_DATAGRAM
                    | XQC_MOQ_CAP_PUBLISH
                    | XQC_MOQ_CAP_SUBSCRIBE_NAMESPACE
                    | XQC_MOQ_CAP_HEADER_EXTENSION,
    .client_setup_type = XQC_MOQ_MSG_CLIENT_SETUP_V14,
    .server_setup_type = XQC_MOQ_MSG_SERVER_SETUP_V14,
    .include_extdata_in_default_setup = XQC_FALSE,
    .data_strategy = XQC_MOQ_DATA_STRATEGY_SUBGROUP,
    .control_codecs = xqc_moq_v14_control_codecs,
    .control_codecs_count = sizeof(xqc_moq_v14_control_codecs)
                            / sizeof(xqc_moq_v14_control_codecs[0]),
    .data_codecs = xqc_moq_v14_data_codecs,
    .data_codecs_count = sizeof(xqc_moq_v14_data_codecs)
                         / sizeof(xqc_moq_v14_data_codecs[0]),
    .classify_stream = xqc_moq_v14_classify_stream,
    .normalize_wire_type = xqc_moq_v14_normalize_wire_type,
    .next_data_message = xqc_moq_v14_next_data_message,
    .prepare_data_message = xqc_moq_v14_prepare_data_message,
    .decode_datagram = xqc_moq_v14_decode_datagram,
    .adapt_subscribe = NULL,
};

const xqc_moq_version_profile_t *
xqc_moq_v14_profile(void)
{
    return &xqc_moq_v14_profile_definition;
}
