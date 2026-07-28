#include "moq/moq_transport/version/v5/xqc_moq_v5_message.h"
#include "moq/moq_transport/version/xqc_moq_version.h"
#include "moq/moq_transport/xqc_moq_message.h"

static const xqc_moq_message_codec_entry_t xqc_moq_v5_control_codecs[] = {
    {XQC_MOQ_MSG_CLIENT_SETUP, xqc_moq_v5_create_client_setup,
     xqc_moq_v5_destroy_client_setup},
    {XQC_MOQ_MSG_SERVER_SETUP, xqc_moq_v5_create_server_setup,
     xqc_moq_v5_destroy_server_setup},
    {XQC_MOQ_MSG_SUBSCRIBE, xqc_moq_v5_create_subscribe,
     xqc_moq_v5_destroy_subscribe},
    {XQC_MOQ_MSG_SUBSCRIBE_UPDATE, xqc_moq_v5_create_subscribe_update,
     xqc_moq_v5_destroy_subscribe_update},
    {XQC_MOQ_MSG_SUBSCRIBE_OK, xqc_moq_v5_create_subscribe_ok,
     xqc_moq_v5_destroy_subscribe_ok},
    {XQC_MOQ_MSG_SUBSCRIBE_ERROR, xqc_moq_v5_create_subscribe_error,
     xqc_moq_v5_destroy_subscribe_error},
};

static const xqc_moq_message_codec_entry_t xqc_moq_v5_data_codecs[] = {
    {XQC_MOQ_MSG_OBJECT_STREAM, xqc_moq_v5_create_object_stream,
     xqc_moq_v5_destroy_object_stream},
    {XQC_MOQ_MSG_STREAM_HEADER_TRACK, xqc_moq_v5_create_track_header,
     xqc_moq_v5_destroy_track_header},
    {XQC_MOQ_MSG_TRACK_STREAM_OBJECT, xqc_moq_v5_create_track_stream_obj,
     xqc_moq_v5_destroy_track_stream_obj},
};

static xqc_moq_stream_kind_t
xqc_moq_v5_classify_stream(xqc_moq_stream_kind_t current_kind,
    uint64_t wire_type)
{
    if (current_kind != XQC_MOQ_STREAM_UNKNOWN) {
        return current_kind;
    }

    if (wire_type == XQC_MOQ_MSG_OBJECT_STREAM) {
        return XQC_MOQ_STREAM_V5_OBJECT;
    }

    if (wire_type == XQC_MOQ_MSG_STREAM_HEADER_TRACK) {
        return XQC_MOQ_STREAM_V5_TRACK;
    }

    return XQC_MOQ_STREAM_UNKNOWN;
}

static xqc_bool_t
xqc_moq_v5_next_data_message(xqc_moq_stream_kind_t stream_kind,
    uint64_t current_wire_type, uint64_t *next_wire_type)
{
    if (stream_kind == XQC_MOQ_STREAM_V5_TRACK
        && (current_wire_type == XQC_MOQ_MSG_STREAM_HEADER_TRACK
            || current_wire_type == XQC_MOQ_MSG_TRACK_STREAM_OBJECT))
    {
        *next_wire_type = XQC_MOQ_MSG_TRACK_STREAM_OBJECT;
        return XQC_TRUE;
    }

    return XQC_FALSE;
}

const xqc_moq_version_profile_t xqc_moq_v5_profile_definition = {
    .name = "draft-05",
    .wire_version = XQC_MOQ_VERSION_5,
    .capabilities = XQC_MOQ_CAP_TRACK_STREAM,
    .client_setup_type = XQC_MOQ_MSG_CLIENT_SETUP,
    .server_setup_type = XQC_MOQ_MSG_SERVER_SETUP,
    .control_codecs = xqc_moq_v5_control_codecs,
    .control_codecs_count = sizeof(xqc_moq_v5_control_codecs)
                            / sizeof(xqc_moq_v5_control_codecs[0]),
    .data_codecs = xqc_moq_v5_data_codecs,
    .data_codecs_count = sizeof(xqc_moq_v5_data_codecs)
                         / sizeof(xqc_moq_v5_data_codecs[0]),
    .classify_stream = xqc_moq_v5_classify_stream,
    .normalize_wire_type = NULL,
    .next_data_message = xqc_moq_v5_next_data_message,
};

const xqc_moq_version_profile_t *
xqc_moq_v5_profile(void)
{
    return &xqc_moq_v5_profile_definition;
}
