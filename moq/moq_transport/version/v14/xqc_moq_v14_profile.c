#include "moq/moq_transport/xqc_moq_message.h"
#include "moq/moq_transport/version/xqc_moq_version.h"

static const xqc_moq_message_codec_entry_t xqc_moq_v14_control_codecs[] = {
    {XQC_MOQ_MSG_SUBSCRIBE_UPDATE, xqc_moq_msg_create_subscribe_update,
     xqc_moq_msg_free_subscribe_update},
    {XQC_MOQ_MSG_SUBSCRIBE, xqc_moq_msg_create_subscribe,
     xqc_moq_msg_free_subscribe},
    {XQC_MOQ_MSG_SUBSCRIBE_OK, xqc_moq_msg_create_subscribe_ok,
     xqc_moq_msg_free_subscribe_ok},
    {XQC_MOQ_MSG_SUBSCRIBE_ERROR, xqc_moq_msg_create_subscribe_error,
     xqc_moq_msg_free_subscribe_error},
    {XQC_MOQ_MSG_PUBLISH_NAMESPACE, xqc_moq_msg_create_publish_namespace,
     xqc_moq_msg_free_publish_namespace},
    {XQC_MOQ_MSG_PUBLISH_NAMESPACE_DONE,
     xqc_moq_msg_create_publish_namespace_done,
     xqc_moq_msg_free_publish_namespace_done},
    {XQC_MOQ_MSG_UNSUBSCRIBE, xqc_moq_msg_create_unsubscribe,
     xqc_moq_msg_free_unsubscribe},
    {XQC_MOQ_MSG_PUBLISH, xqc_moq_msg_create_publish,
     xqc_moq_msg_free_publish},
    {XQC_MOQ_MSG_PUBLISH_OK, xqc_moq_msg_create_publish_ok,
     xqc_moq_msg_free_publish_ok},
    {XQC_MOQ_MSG_PUBLISH_ERROR, xqc_moq_msg_create_publish_error,
     xqc_moq_msg_free_publish_error},
    {XQC_MOQ_MSG_PUBLISH_DONE, xqc_moq_msg_create_publish_done,
     xqc_moq_msg_free_publish_done},
    {XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE,
     xqc_moq_msg_create_subscribe_namespace,
     xqc_moq_msg_free_subscribe_namespace},
    {XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE_OK,
     xqc_moq_msg_create_subscribe_namespace_ok,
     xqc_moq_msg_free_subscribe_namespace_ok},
    {XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE_ERROR,
     xqc_moq_msg_create_subscribe_namespace_error,
     xqc_moq_msg_free_subscribe_namespace_error},
    {XQC_MOQ_MSG_UNSUBSCRIBE_NAMESPACE,
     xqc_moq_msg_create_unsubscribe_namespace,
     xqc_moq_msg_free_unsubscribe_namespace},
    {XQC_MOQ_MSG_GOAWAY, xqc_moq_msg_create_goaway,
     xqc_moq_msg_free_goaway},
    {XQC_MOQ_MSG_CLIENT_SETUP_V14, xqc_moq_msg_create_client_setup_v14,
     xqc_moq_msg_free_client_setup_v14},
    {XQC_MOQ_MSG_SERVER_SETUP_V14, xqc_moq_msg_create_server_setup_v14,
     xqc_moq_msg_free_server_setup_v14},
};

static const xqc_moq_message_codec_entry_t xqc_moq_v14_data_codecs[] = {
    {XQC_MOQ_MSG_SUBGROUP, xqc_moq_msg_create_subgroup,
     xqc_moq_msg_free_subgroup},
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
    .control_codecs = xqc_moq_v14_control_codecs,
    .control_codecs_count = sizeof(xqc_moq_v14_control_codecs)
                            / sizeof(xqc_moq_v14_control_codecs[0]),
    .data_codecs = xqc_moq_v14_data_codecs,
    .data_codecs_count = sizeof(xqc_moq_v14_data_codecs)
                         / sizeof(xqc_moq_v14_data_codecs[0]),
    .classify_stream = xqc_moq_v14_classify_stream,
    .normalize_wire_type = xqc_moq_v14_normalize_wire_type,
    .next_data_message = xqc_moq_v14_next_data_message,
};

const xqc_moq_version_profile_t *
xqc_moq_v14_profile(void)
{
    return &xqc_moq_v14_profile_definition;
}
