#include "moq/moq_transport/version/xqc_moq_version.h"
#include "moq/moq_transport/xqc_moq_message.h"

static const xqc_moq_message_codec_entry_t xqc_moq_v5_setup_codecs[] = {
    {
        XQC_MOQ_MSG_CLIENT_SETUP,
        xqc_moq_msg_create_client_setup,
        xqc_moq_msg_free_client_setup,
    },
    {
        XQC_MOQ_MSG_SERVER_SETUP,
        xqc_moq_msg_create_server_setup,
        xqc_moq_msg_free_server_setup,
    },
};

const xqc_moq_version_profile_t xqc_moq_v5_profile_definition = {
    .name = "draft-05",
    .wire_version = XQC_MOQ_VERSION_5,
    .capabilities = XQC_MOQ_CAP_TRACK_STREAM,
    .client_setup_type = XQC_MOQ_MSG_CLIENT_SETUP,
    .server_setup_type = XQC_MOQ_MSG_SERVER_SETUP,
    .control_codecs = xqc_moq_v5_setup_codecs,
    .control_codecs_count = sizeof(xqc_moq_v5_setup_codecs)
                            / sizeof(xqc_moq_v5_setup_codecs[0]),
};

const xqc_moq_version_profile_t *
xqc_moq_v5_profile(void)
{
    return &xqc_moq_v5_profile_definition;
}
