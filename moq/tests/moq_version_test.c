#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "moq/xqc_moq.h"
#include "moq/moq_media/xqc_moq_datachannel.h"
#include "moq/moq_media/xqc_moq_media_track.h"
#include "moq/moq_transport/xqc_moq_message.h"
#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/version/xqc_moq_version.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_transport/xqc_moq_subscribe.h"
#include "moq/moq_transport/xqc_moq_track.h"
#include "moq/moq_transport/version/v5/xqc_moq_v5_message.h"
#include "src/common/xqc_log.h"

#define XQC_TEST_ASSERT(expr)                                             \
    do {                                                                  \
        if (!(expr)) {                                                    \
            fprintf(stderr, "assert failed: %s:%d: %s\n",                \
                    __FILE__, __LINE__, #expr);                            \
            return -1;                                                    \
        }                                                                 \
    } while (0)

typedef void (*xqc_test_configure_message_pt)(void *msg);

typedef struct {
    const char *name;
    xqc_moq_stream_kind_t stream_kind;
    uint64_t wire_type;
    size_t prefix_len;
    const uint8_t *bytes;
    size_t bytes_len;
    xqc_test_configure_message_pt configure;
    xqc_moq_semantic_id_t continuation_semantic;
} xqc_test_v5_vector_t;

typedef struct {
    xqc_moq_msg_base_t          msg_base;
    char                        *track_namespace;
    size_t                      track_namespace_len;
    uint64_t                    params_num;
    xqc_moq_message_parameter_t *params;
} xqc_test_v5_announce_msg_t;

typedef struct {
    xqc_moq_msg_base_t          msg_base;
    char                        *track_namespace;
    size_t                      track_namespace_len;
} xqc_test_v5_namespace_msg_t;

typedef struct {
    xqc_moq_msg_base_t          msg_base;
    char                        *track_namespace;
    size_t                      track_namespace_len;
    uint64_t                    error_code;
    char                        *reason_phrase;
    size_t                      reason_phrase_len;
} xqc_test_v5_announce_error_msg_t;

typedef struct {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    subscribe_id;
    uint64_t                    status_code;
    char                        *reason_phrase;
    size_t                      reason_phrase_len;
    uint8_t                     content_exist;
    uint64_t                    final_group;
    uint64_t                    final_object;
} xqc_test_v5_subscribe_done_msg_t;

typedef struct {
    xqc_moq_msg_base_t          msg_base;
    char                        *track_namespace;
    size_t                      track_namespace_len;
    char                        *track_name;
    size_t                      track_name_len;
} xqc_test_v5_track_status_request_msg_t;

typedef struct {
    xqc_moq_msg_base_t          msg_base;
    char                        *track_namespace;
    size_t                      track_namespace_len;
    char                        *track_name;
    size_t                      track_name_len;
    uint64_t                    status_code;
    uint64_t                    last_group_id;
    uint64_t                    last_object_id;
} xqc_test_v5_track_status_msg_t;

#define XQC_TEST_MOQ_V5_MSG_ANNOUNCE             0x06
#define XQC_TEST_MOQ_V5_MSG_ANNOUNCE_OK          0x07
#define XQC_TEST_MOQ_V5_MSG_ANNOUNCE_ERROR       0x08
#define XQC_TEST_MOQ_V5_MSG_UNANNOUNCE           0x09
#define XQC_TEST_MOQ_V5_MSG_SUBSCRIBE_DONE       0x0b
#define XQC_TEST_MOQ_V5_MSG_ANNOUNCE_CANCEL      0x0c

static int
xqc_test_activate_session(xqc_moq_session_t *session, const char *alpn,
    size_t alpn_len, uint64_t version)
{
    const xqc_moq_alpn_policy_t *policy =
        xqc_moq_version_policy_for_alpn(alpn, alpn_len);

    XQC_TEST_ASSERT(policy != NULL);
    xqc_memzero(session, sizeof(*session));
    XQC_TEST_ASSERT(xqc_moq_session_bind_policy(session, policy) == XQC_OK);
    XQC_TEST_ASSERT(xqc_moq_session_negotiate_version(
        session, &version, 1) == XQC_OK);
    return 0;
}

static void
xqc_test_configure_client_setup(void *ptr)
{
    static uint8_t role = XQC_MOQ_PUBSUB;
    static uint8_t path[] = "path";
    static uint64_t versions[] = {XQC_MOQ_VERSION_5};
    static xqc_moq_message_parameter_t params[] = {
        {.type = XQC_MOQ_PARAM_ROLE, .length = 1, .value = &role},
        {.type = XQC_MOQ_PARAM_PATH, .length = 4, .value = path},
    };
    xqc_moq_client_setup_msg_t *msg = ptr;
    msg->versions_num = 1;
    msg->versions = versions;
    msg->params_num = 2;
    msg->params = params;
}

static void
xqc_test_configure_server_setup(void *ptr)
{
    static uint8_t role = XQC_MOQ_PUBSUB;
    static xqc_moq_message_parameter_t params[] = {
        {.type = XQC_MOQ_PARAM_ROLE, .length = 1, .value = &role},
    };
    xqc_moq_server_setup_msg_t *msg = ptr;
    msg->version = XQC_MOQ_VERSION_5;
    msg->params_num = 1;
    msg->params = params;
}

static void
xqc_test_configure_subscribe(void *ptr)
{
    static uint8_t auth[] = "auth";
    static xqc_moq_message_parameter_t params[] = {
        {.type = XQC_MOQ_PARAM_AUTH, .length = 4, .value = auth},
    };
    xqc_moq_subscribe_msg_t *msg = ptr;
    msg->subscribe_id = 1;
    msg->track_alias = 2;
    msg->track_namespace = "ns";
    msg->track_namespace_len = 2;
    msg->track_name = "track";
    msg->track_name_len = 5;
    msg->filter_type = XQC_MOQ_FILTER_ABSOLUTE_RANGE;
    msg->start_group_id = 3;
    msg->start_object_id = 4;
    msg->end_group_id = 5;
    msg->end_object_id = 6;
    msg->params_num = 1;
    msg->params = params;
}

static void
xqc_test_configure_subscribe_update(void *ptr)
{
    static uint8_t auth[] = "auth";
    static xqc_moq_message_parameter_t params[] = {
        {.type = XQC_MOQ_PARAM_AUTH, .length = 4, .value = auth},
    };
    xqc_moq_subscribe_update_msg_t *msg = ptr;
    msg->subscribe_id = 1;
    msg->start_group_id = 7;
    msg->start_object_id = 8;
    msg->end_group_id = 9;
    msg->end_object_id = 10;
    msg->params_num = 1;
    msg->params = params;
}

static void
xqc_test_configure_subscribe_ok(void *ptr)
{
    xqc_moq_subscribe_ok_msg_t *msg = ptr;
    msg->subscribe_id = 1;
    msg->expire_ms = 1000;
    msg->content_exist = 1;
    msg->largest_group_id = 11;
    msg->largest_object_id = 12;
}

static void
xqc_test_configure_subscribe_error(void *ptr)
{
    xqc_moq_subscribe_error_msg_t *msg = ptr;
    msg->subscribe_id = 1;
    msg->error_code = 2;
    msg->reason_phrase = "bad";
    msg->reason_phrase_len = 3;
    msg->track_alias = 13;
}

static void
xqc_test_configure_unsubscribe(void *ptr)
{
    xqc_moq_unsubscribe_msg_t *msg = ptr;
    msg->subscribe_id = 1;
}

static void
xqc_test_configure_goaway(void *ptr)
{
    xqc_moq_goaway_msg_t *msg = ptr;
    msg->new_session_uri = "next";
    msg->new_session_uri_len = 4;
}

static void
xqc_test_configure_announce(void *ptr)
{
    static uint8_t auth[] = "auth";
    static xqc_moq_message_parameter_t params[] = {
        {.type = XQC_MOQ_PARAM_AUTH, .length = 4, .value = auth},
    };
    xqc_test_v5_announce_msg_t *msg = ptr;

    msg->track_namespace = "ns";
    msg->track_namespace_len = 2;
    msg->params_num = 1;
    msg->params = params;
}

static void
xqc_test_configure_namespace_message(void *ptr)
{
    xqc_test_v5_namespace_msg_t *msg = ptr;

    msg->track_namespace = "ns";
    msg->track_namespace_len = 2;
}

static void
xqc_test_configure_announce_error(void *ptr)
{
    xqc_test_v5_announce_error_msg_t *msg = ptr;

    msg->track_namespace = "ns";
    msg->track_namespace_len = 2;
    msg->error_code = 2;
    msg->reason_phrase = "bad";
    msg->reason_phrase_len = 3;
}

static void
xqc_test_configure_subscribe_done(void *ptr)
{
    xqc_test_v5_subscribe_done_msg_t *msg = ptr;

    msg->subscribe_id = 1;
    msg->status_code = 2;
    msg->reason_phrase = "bye";
    msg->reason_phrase_len = 3;
    msg->content_exist = 1;
    msg->final_group = 3;
    msg->final_object = 4;
}

static void
xqc_test_configure_track_status_request(void *ptr)
{
    xqc_test_v5_track_status_request_msg_t *msg = ptr;

    msg->track_namespace = "ns";
    msg->track_namespace_len = 2;
    msg->track_name = "track";
    msg->track_name_len = 5;
}

static void
xqc_test_configure_track_status(void *ptr)
{
    xqc_test_v5_track_status_msg_t *msg = ptr;

    msg->track_namespace = "ns";
    msg->track_namespace_len = 2;
    msg->track_name = "track";
    msg->track_name_len = 5;
    msg->status_code = 1;
    msg->last_group_id = 3;
    msg->last_object_id = 4;
}

static void
xqc_test_configure_object_stream(void *ptr)
{
    static uint8_t payload[] = "obj";
    xqc_moq_object_stream_msg_t *msg = ptr;
    msg->subscribe_id = 1;
    msg->track_alias = 2;
    msg->group_id = 3;
    msg->object_id = 4;
    msg->send_order = 5;
    msg->payload = payload;
    msg->payload_len = 3;
}

static void
xqc_test_configure_track_header(void *ptr)
{
    xqc_moq_stream_header_track_msg_t *msg = ptr;
    msg->subscribe_id = 1;
    msg->track_alias = 2;
    msg->send_order = 3;
}

static void
xqc_test_configure_track_object(void *ptr)
{
    static uint8_t payload[] = "trk";
    xqc_moq_track_stream_obj_msg_t *msg = ptr;
    msg->group_id = 4;
    msg->object_id = 5;
    msg->payload = payload;
    msg->payload_len = 3;
}

static const uint8_t xqc_v5_client_setup[] = {
    0x40, 0x40, 0x01, 0xc0, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x05,
    0x02, 0x00, 0x01, 0x03, 0x01, 0x04, 0x70, 0x61, 0x74, 0x68,
};
static const uint8_t xqc_v5_server_setup[] = {
    0x40, 0x41, 0xc0, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x05,
    0x01, 0x00, 0x01, 0x03,
};
static const uint8_t xqc_v5_subscribe[] = {
    0x03, 0x01, 0x02, 0x02, 0x6e, 0x73, 0x05, 0x74, 0x72, 0x61, 0x63,
    0x6b, 0x04, 0x03, 0x04, 0x05, 0x06, 0x01, 0x02, 0x04, 0x61, 0x75,
    0x74, 0x68,
};
static const uint8_t xqc_v5_subscribe_update[] = {
    0x02, 0x01, 0x07, 0x08, 0x09, 0x0a, 0x01, 0x02, 0x04, 0x61, 0x75,
    0x74, 0x68,
};
static const uint8_t xqc_v5_subscribe_ok[] = {
    0x04, 0x01, 0x43, 0xe8, 0x01, 0x0b, 0x0c,
};
static const uint8_t xqc_v5_subscribe_error[] = {
    0x05, 0x01, 0x02, 0x03, 0x62, 0x61, 0x64, 0x0d,
};
static const uint8_t xqc_v5_unsubscribe[] = {
    0x0a, 0x01,
};
static const uint8_t xqc_v5_goaway[] = {
    0x10, 0x04, 0x6e, 0x65, 0x78, 0x74,
};
static const uint8_t xqc_v5_announce[] = {
    0x06, 0x02, 0x6e, 0x73, 0x01, 0x02, 0x04, 0x61, 0x75, 0x74, 0x68,
};
static const uint8_t xqc_v5_announce_ok[] = {
    0x07, 0x02, 0x6e, 0x73,
};
static const uint8_t xqc_v5_announce_error[] = {
    0x08, 0x02, 0x6e, 0x73, 0x02, 0x03, 0x62, 0x61, 0x64,
};
static const uint8_t xqc_v5_unannounce[] = {
    0x09, 0x02, 0x6e, 0x73,
};
static const uint8_t xqc_v5_subscribe_done[] = {
    0x0b, 0x01, 0x02, 0x03, 0x62, 0x79, 0x65, 0x01, 0x03, 0x04,
};
static const uint8_t xqc_v5_announce_cancel[] = {
    0x0c, 0x02, 0x6e, 0x73,
};
static const uint8_t xqc_v5_track_status_request[] = {
    0x0d, 0x02, 0x6e, 0x73, 0x05, 0x74, 0x72, 0x61, 0x63, 0x6b,
};
static const uint8_t xqc_v5_track_status[] = {
    0x0e, 0x02, 0x6e, 0x73, 0x05, 0x74, 0x72, 0x61, 0x63, 0x6b,
    0x01, 0x03, 0x04,
};
static const uint8_t xqc_v5_object_stream[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0x6f, 0x62, 0x6a,
};
static const uint8_t xqc_v5_track_header[] = {
    0x40, 0x50, 0x01, 0x02, 0x03,
};
static const uint8_t xqc_v5_track_object[] = {
    0x04, 0x05, 0x03, 0x74, 0x72, 0x6b,
};

static const xqc_test_v5_vector_t xqc_v5_vectors[] = {
    {"client_setup", XQC_MOQ_STREAM_CONTROL, XQC_MOQ_MSG_CLIENT_SETUP, 2,
     xqc_v5_client_setup, sizeof(xqc_v5_client_setup),
     xqc_test_configure_client_setup},
    {"server_setup", XQC_MOQ_STREAM_CONTROL, XQC_MOQ_MSG_SERVER_SETUP, 2,
     xqc_v5_server_setup, sizeof(xqc_v5_server_setup),
     xqc_test_configure_server_setup},
    {"subscribe", XQC_MOQ_STREAM_CONTROL, XQC_MOQ_MSG_SUBSCRIBE, 1,
     xqc_v5_subscribe, sizeof(xqc_v5_subscribe),
     xqc_test_configure_subscribe},
    {"subscribe_update", XQC_MOQ_STREAM_CONTROL,
     XQC_MOQ_MSG_SUBSCRIBE_UPDATE, 1, xqc_v5_subscribe_update,
     sizeof(xqc_v5_subscribe_update), xqc_test_configure_subscribe_update},
    {"subscribe_ok", XQC_MOQ_STREAM_CONTROL, XQC_MOQ_MSG_SUBSCRIBE_OK, 1,
     xqc_v5_subscribe_ok, sizeof(xqc_v5_subscribe_ok),
     xqc_test_configure_subscribe_ok},
    {"subscribe_error", XQC_MOQ_STREAM_CONTROL,
     XQC_MOQ_MSG_SUBSCRIBE_ERROR, 1, xqc_v5_subscribe_error,
     sizeof(xqc_v5_subscribe_error), xqc_test_configure_subscribe_error},
    {"unsubscribe", XQC_MOQ_STREAM_CONTROL, XQC_MOQ_MSG_UNSUBSCRIBE, 1,
     xqc_v5_unsubscribe, sizeof(xqc_v5_unsubscribe),
     xqc_test_configure_unsubscribe},
    {"goaway", XQC_MOQ_STREAM_CONTROL, XQC_MOQ_MSG_GOAWAY, 1,
     xqc_v5_goaway, sizeof(xqc_v5_goaway), xqc_test_configure_goaway},
    {"announce", XQC_MOQ_STREAM_CONTROL, XQC_TEST_MOQ_V5_MSG_ANNOUNCE, 1,
     xqc_v5_announce, sizeof(xqc_v5_announce), xqc_test_configure_announce},
    {"announce_ok", XQC_MOQ_STREAM_CONTROL,
     XQC_TEST_MOQ_V5_MSG_ANNOUNCE_OK, 1, xqc_v5_announce_ok,
     sizeof(xqc_v5_announce_ok), xqc_test_configure_namespace_message},
    {"announce_error", XQC_MOQ_STREAM_CONTROL,
     XQC_TEST_MOQ_V5_MSG_ANNOUNCE_ERROR, 1, xqc_v5_announce_error,
     sizeof(xqc_v5_announce_error), xqc_test_configure_announce_error},
    {"unannounce", XQC_MOQ_STREAM_CONTROL,
     XQC_TEST_MOQ_V5_MSG_UNANNOUNCE, 1, xqc_v5_unannounce,
     sizeof(xqc_v5_unannounce), xqc_test_configure_namespace_message},
    {"subscribe_done", XQC_MOQ_STREAM_CONTROL,
     XQC_TEST_MOQ_V5_MSG_SUBSCRIBE_DONE, 1, xqc_v5_subscribe_done,
     sizeof(xqc_v5_subscribe_done), xqc_test_configure_subscribe_done},
    {"announce_cancel", XQC_MOQ_STREAM_CONTROL,
     XQC_TEST_MOQ_V5_MSG_ANNOUNCE_CANCEL, 1, xqc_v5_announce_cancel,
     sizeof(xqc_v5_announce_cancel), xqc_test_configure_namespace_message},
    {"track_status_request", XQC_MOQ_STREAM_CONTROL,
     XQC_MOQ_MSG_TRACK_STATUS_REQUEST, 1, xqc_v5_track_status_request,
     sizeof(xqc_v5_track_status_request),
     xqc_test_configure_track_status_request},
    {"track_status", XQC_MOQ_STREAM_CONTROL, XQC_MOQ_MSG_TRACK_STATUS, 1,
     xqc_v5_track_status, sizeof(xqc_v5_track_status),
     xqc_test_configure_track_status},
    {"object_stream", XQC_MOQ_STREAM_V5_OBJECT, XQC_MOQ_MSG_OBJECT_STREAM, 1,
     xqc_v5_object_stream, sizeof(xqc_v5_object_stream),
     xqc_test_configure_object_stream},
    {"track_header", XQC_MOQ_STREAM_V5_TRACK,
     XQC_MOQ_MSG_STREAM_HEADER_TRACK, 2, xqc_v5_track_header,
     sizeof(xqc_v5_track_header), xqc_test_configure_track_header},
    {"track_object", XQC_MOQ_STREAM_V5_TRACK,
     XQC_MOQ_MSG_STREAM_HEADER_TRACK, 0, xqc_v5_track_object,
     sizeof(xqc_v5_track_object), xqc_test_configure_track_object,
     XQC_MOQ_SEMANTIC_TRACK_STREAM_OBJECT},
};

static const xqc_moq_message_codec_entry_t *
xqc_test_v5_vector_codec(xqc_moq_session_t *session,
    const xqc_test_v5_vector_t *vector)
{
    if (vector->continuation_semantic != 0) {
        return xqc_moq_profile_find_semantic_codec(
            session->profile, vector->continuation_semantic);
    }
    return xqc_moq_profile_find_codec(
        session->profile, vector->stream_kind, vector->wire_type);
}

static int
xqc_test_profile_lookup(void)
{
    const xqc_moq_alpn_policy_t *policy;

    XQC_TEST_ASSERT(strcmp(XQC_ALPN_MOQ_QUIC, "moq-quic") == 0);
    XQC_TEST_ASSERT(strcmp(XQC_ALPN_MOQ_DRAFT_05, "moq-05") == 0);
    XQC_TEST_ASSERT(strcmp(XQC_ALPN_MOQ_DRAFT_14, "moq-14") == 0);
    XQC_TEST_ASSERT(strcmp(XQC_ALPN_MOQ_DRAFT_18, "moqt-18") == 0);

    policy = xqc_moq_version_policy_for_alpn("moq-quic", 8);
    XQC_TEST_ASSERT(policy != NULL);
    XQC_TEST_ASSERT(policy->profile != NULL);
    XQC_TEST_ASSERT(policy->profile->wire_version == XQC_MOQ_VERSION_5);
    XQC_TEST_ASSERT(policy->profile->control_codecs != NULL);

    policy = xqc_moq_version_policy_for_alpn("moq-05", 6);
    XQC_TEST_ASSERT(policy != NULL);
    XQC_TEST_ASSERT(policy->profile != NULL);
    XQC_TEST_ASSERT(policy->profile->wire_version == XQC_MOQ_VERSION_5);
    XQC_TEST_ASSERT(policy->profile->control_codecs != NULL);

    policy = xqc_moq_version_policy_for_alpn("moq-14", 6);
    XQC_TEST_ASSERT(policy != NULL);
    XQC_TEST_ASSERT(policy->profile != NULL);
    XQC_TEST_ASSERT(policy->profile->wire_version == XQC_MOQ_VERSION_14);
    XQC_TEST_ASSERT(policy->profile->control_codecs != NULL);

    policy = xqc_moq_version_policy_for_alpn("moqt-18", 7);
    XQC_TEST_ASSERT(policy != NULL);
    XQC_TEST_ASSERT(policy->profile != NULL);
    XQC_TEST_ASSERT(policy->profile->wire_version == XQC_MOQ_VERSION_18);
    XQC_TEST_ASSERT(policy->profile->control_codecs != NULL);

    XQC_TEST_ASSERT(xqc_moq_version_policy_for_alpn("moq-00", 6) == NULL);
    XQC_TEST_ASSERT(xqc_moq_version_policy_for_alpn("unknown", 7) == NULL);
    XQC_TEST_ASSERT(xqc_moq_version_policy_count() == 4);
    XQC_TEST_ASSERT(xqc_moq_version_policy_at(0) != NULL);
    XQC_TEST_ASSERT(xqc_moq_version_policy_at(3) != NULL);
    XQC_TEST_ASSERT(xqc_moq_version_policy_at(4) == NULL);

    XQC_TEST_ASSERT(xqc_moq_version_profile_for_version(XQC_MOQ_VERSION_5)
                    == xqc_moq_v5_profile());
    XQC_TEST_ASSERT(xqc_moq_version_profile_for_version(XQC_MOQ_VERSION_14)
                    == xqc_moq_v14_profile());
    XQC_TEST_ASSERT(xqc_moq_version_profile_for_version(XQC_MOQ_VERSION_18)
                    == xqc_moq_v18_profile());
    XQC_TEST_ASSERT(!xqc_moq_profile_has_capability(
        xqc_moq_v5_profile(), XQC_MOQ_CAP_SUBGROUP_STREAM));
    XQC_TEST_ASSERT(xqc_moq_profile_has_capability(
        xqc_moq_v14_profile(), XQC_MOQ_CAP_SUBGROUP_STREAM));
    XQC_TEST_ASSERT(xqc_moq_profile_validate_setup(
        xqc_moq_v14_profile(), XQC_MOQ_VERSION_5) == -XQC_EVERSION);
    XQC_TEST_ASSERT(xqc_moq_profile_validate_setup(
        xqc_moq_v14_profile(), XQC_MOQ_VERSION_14) == XQC_OK);
    XQC_TEST_ASSERT(xqc_moq_profile_require(
        xqc_moq_v5_profile(), XQC_MOQ_CAP_OBJECT_DATAGRAM)
        == -XQC_EALPN_NOT_SUPPORTED);
    return 0;
}

static int
xqc_test_session_profile_state(void)
{
    xqc_moq_session_t session;
    uint64_t v5_versions[] = {XQC_MOQ_VERSION_5};
    const xqc_moq_alpn_policy_t *v5_policy;
    const xqc_moq_alpn_policy_t *v14_policy;

    v5_policy = xqc_moq_version_policy_for_alpn("moq-05", 6);
    v14_policy = xqc_moq_version_policy_for_alpn("moq-14", 6);
    XQC_TEST_ASSERT(v5_policy != NULL);
    XQC_TEST_ASSERT(v14_policy != NULL);

    memset(&session, 0, sizeof(session));
    XQC_TEST_ASSERT(xqc_moq_session_bind_policy(&session, v5_policy) == XQC_OK);
    XQC_TEST_ASSERT(session.profile == xqc_moq_v5_profile());
    XQC_TEST_ASSERT(session.profile_state == XQC_MOQ_PROFILE_ALPN_SELECTED);
    XQC_TEST_ASSERT(xqc_moq_session_require_active(&session) == -XQC_EVERSION);

    XQC_TEST_ASSERT(xqc_moq_session_bind_policy(&session, v14_policy)
                    == -XQC_EVERSION);
    XQC_TEST_ASSERT(session.profile == xqc_moq_v5_profile());
    XQC_TEST_ASSERT(session.profile_state == XQC_MOQ_PROFILE_ALPN_SELECTED);

    XQC_TEST_ASSERT(xqc_moq_session_validate_setup_type(
        &session, XQC_MOQ_MSG_CLIENT_SETUP) == XQC_OK);
    XQC_TEST_ASSERT(xqc_moq_session_negotiate_version(
        &session, v5_versions, 1) == XQC_OK);
    XQC_TEST_ASSERT(session.profile_state == XQC_MOQ_PROFILE_ACTIVE);
    XQC_TEST_ASSERT(session.negotiated_version == XQC_MOQ_VERSION_5);
    XQC_TEST_ASSERT(xqc_moq_session_require_active(&session) == XQC_OK);

    memset(&session, 0, sizeof(session));
    XQC_TEST_ASSERT(xqc_moq_session_bind_policy(&session, v14_policy) == XQC_OK);
    XQC_TEST_ASSERT(xqc_moq_session_validate_setup_type(
        &session, XQC_MOQ_MSG_CLIENT_SETUP) == -XQC_EVERSION);
    XQC_TEST_ASSERT(session.profile == xqc_moq_v14_profile());
    XQC_TEST_ASSERT(session.profile_state == XQC_MOQ_PROFILE_ALPN_SELECTED);
    XQC_TEST_ASSERT(xqc_moq_session_require_active(&session) == -XQC_EVERSION);
    return 0;
}

static int
xqc_test_message_collision_is_profile_local(void)
{
    xqc_moq_session_t v5_session;
    xqc_moq_session_t v14_session;
    const xqc_moq_alpn_policy_t *v5_policy;
    const xqc_moq_alpn_policy_t *v14_policy;
    uint64_t v5_version[] = {XQC_MOQ_VERSION_5};
    uint64_t v14_version[] = {XQC_MOQ_VERSION_14};
    xqc_moq_msg_base_t *v5_subscribe;
    xqc_moq_msg_base_t *v14_subscribe;

    v5_policy = xqc_moq_version_policy_for_alpn("moq-05", 6);
    v14_policy = xqc_moq_version_policy_for_alpn("moq-14", 6);
    memset(&v5_session, 0, sizeof(v5_session));
    memset(&v14_session, 0, sizeof(v14_session));

    XQC_TEST_ASSERT(xqc_moq_session_bind_policy(
        &v5_session, v5_policy) == XQC_OK);
    XQC_TEST_ASSERT(xqc_moq_session_negotiate_version(
        &v5_session, v5_version, 1) == XQC_OK);
    XQC_TEST_ASSERT(xqc_moq_session_bind_policy(
        &v14_session, v14_policy) == XQC_OK);
    XQC_TEST_ASSERT(xqc_moq_session_negotiate_version(
        &v14_session, v14_version, 1) == XQC_OK);

    v5_subscribe = xqc_moq_msg_create(&v5_session,
        XQC_MOQ_STREAM_CONTROL, XQC_MOQ_MSG_SUBSCRIBE);
    v14_subscribe = xqc_moq_msg_create(&v14_session,
        XQC_MOQ_STREAM_CONTROL, XQC_MOQ_MSG_SUBSCRIBE);

    XQC_TEST_ASSERT(v5_subscribe != NULL);
    XQC_TEST_ASSERT(v14_subscribe != NULL);
    XQC_TEST_ASSERT(v5_subscribe->encode != v14_subscribe->encode);

    xqc_moq_msg_free(&v5_session, XQC_MOQ_STREAM_CONTROL,
                     XQC_MOQ_MSG_SUBSCRIBE, v5_subscribe);
    xqc_moq_msg_free(&v14_session, XQC_MOQ_STREAM_CONTROL,
                     XQC_MOQ_MSG_SUBSCRIBE, v14_subscribe);
    return 0;
}

static int
xqc_test_internal_message_ids_are_not_wire_types(void)
{
    const xqc_moq_version_profile_t *profile = xqc_moq_v14_profile();
    xqc_moq_stream_kind_t kind;

    kind = xqc_moq_profile_classify_stream(
        profile, XQC_MOQ_STREAM_UNKNOWN,
        XQC_MOQ_INTERNAL_SUBGROUP_STREAM_OBJECT);
    XQC_TEST_ASSERT(kind == XQC_MOQ_STREAM_UNKNOWN);
    XQC_TEST_ASSERT(xqc_moq_profile_find_codec(
        profile, kind, XQC_MOQ_INTERNAL_SUBGROUP_STREAM_OBJECT) == NULL);

    kind = xqc_moq_profile_classify_stream(
        profile, XQC_MOQ_STREAM_UNKNOWN, XQC_MOQ_INTERNAL_SUBGROUP);
    XQC_TEST_ASSERT(kind == XQC_MOQ_STREAM_UNKNOWN);
    XQC_TEST_ASSERT(xqc_moq_profile_find_codec(
        profile, kind, XQC_MOQ_INTERNAL_SUBGROUP) == NULL);

    kind = xqc_moq_profile_classify_stream(
        profile, XQC_MOQ_STREAM_UNKNOWN, 0x10);
    XQC_TEST_ASSERT(kind == XQC_MOQ_STREAM_V14_SUBGROUP);
    return 0;
}

static int
xqc_test_v5_track_codec_requires_capability(void)
{
    xqc_moq_version_profile_t profile = *xqc_moq_v5_profile();

    profile.capabilities &= ~(uint64_t)XQC_MOQ_CAP_TRACK_STREAM;
    XQC_TEST_ASSERT(xqc_moq_profile_find_codec(
        &profile, XQC_MOQ_STREAM_V5_TRACK,
        XQC_MOQ_MSG_STREAM_HEADER_TRACK) == NULL);
    XQC_TEST_ASSERT(xqc_moq_profile_find_codec(
        xqc_moq_v5_profile(), XQC_MOQ_STREAM_V5_TRACK,
        XQC_MOQ_MSG_STREAM_HEADER_TRACK) != NULL);
    return 0;
}

static int
xqc_test_missing_profile_codec_returns_specific_error(void)
{
    xqc_moq_session_t session;
    xqc_moq_stream_t stream;
    xqc_log_callbacks_t log_callbacks;
    xqc_log_t log;
    xqc_int_t finish;
    xqc_int_t wait_more_data;

    xqc_memzero(&stream, sizeof(stream));
    xqc_memzero(&log_callbacks, sizeof(log_callbacks));
    xqc_memzero(&log, sizeof(log));
    XQC_TEST_ASSERT(xqc_test_activate_session(
        &session, XQC_ALPN_MOQ_DRAFT_05,
        sizeof(XQC_ALPN_MOQ_DRAFT_05) - 1, XQC_MOQ_VERSION_5) == 0);
    stream.session = &session;
    stream.kind = XQC_MOQ_STREAM_CONTROL;
    stream.decode_msg_ctx.cur_msg_type = (xqc_moq_msg_type_t)0x3f;
    log.log_level = XQC_LOG_DEBUG;
    log.log_callbacks = &log_callbacks;
    session.log = &log;

    XQC_TEST_ASSERT(xqc_moq_stream_process_msg(
        &stream, 0, &finish, &wait_more_data)
        == -XQC_EALPN_NOT_SUPPORTED);
    return 0;
}

static ssize_t
xqc_test_stream_write(void *stream, uint8_t *data, size_t data_len,
    uint8_t fin)
{
    (void)stream;
    (void)data;
    (void)fin;
    return (ssize_t)data_len;
}

static int
xqc_test_unsupported_write_is_side_effect_free(void)
{
    xqc_moq_session_t session;
    xqc_moq_stream_t stream;
    xqc_moq_subgroup_msg_t subgroup;
    xqc_moq_object_t datagram;
    xqc_moq_publish_msg_t publish;
    xqc_moq_subscribe_namespace_msg_t subscribe_namespace;

    xqc_memzero(&stream, sizeof(stream));
    xqc_memzero(&subgroup, sizeof(subgroup));
    xqc_memzero(&datagram, sizeof(datagram));
    xqc_memzero(&publish, sizeof(publish));
    xqc_memzero(&subscribe_namespace, sizeof(subscribe_namespace));
    XQC_TEST_ASSERT(xqc_test_activate_session(
        &session, XQC_ALPN_MOQ_DRAFT_05,
        sizeof(XQC_ALPN_MOQ_DRAFT_05) - 1, XQC_MOQ_VERSION_5) == 0);

    stream.session = &session;
    stream.trans_ops.write = xqc_test_stream_write;
    XQC_TEST_ASSERT(xqc_moq_write_subgroup_msg(
        &session, &stream, &subgroup) == -XQC_EALPN_NOT_SUPPORTED);
    XQC_TEST_ASSERT(stream.write_buf_len == 0);
    XQC_TEST_ASSERT(xqc_moq_write_publish(
        &session, &publish) == -XQC_EALPN_NOT_SUPPORTED);
    XQC_TEST_ASSERT(stream.write_buf_len == 0);
    XQC_TEST_ASSERT(xqc_moq_write_subscribe_namespace(
        &session, &subscribe_namespace) == -XQC_EALPN_NOT_SUPPORTED);
    XQC_TEST_ASSERT(stream.write_buf_len == 0);

    datagram.track_alias = 1;
    XQC_TEST_ASSERT(xqc_moq_send_object_datagram(
        &session, &datagram) == -XQC_EALPN_NOT_SUPPORTED);
    {
        const uint8_t encoded_datagram[] = {0};
        XQC_TEST_ASSERT(xqc_moq_profile_decode_datagram(
            &session, encoded_datagram, sizeof(encoded_datagram))
            == -XQC_EALPN_NOT_SUPPORTED);
    }
    return 0;
}

static int
xqc_test_datagram_requires_active_profile(void)
{
    const uint8_t encoded_datagram[] = {0};
    const xqc_moq_alpn_policy_t *policy;
    xqc_moq_session_t session;

    policy = xqc_moq_version_policy_for_alpn(
        XQC_ALPN_MOQ_DRAFT_14, sizeof(XQC_ALPN_MOQ_DRAFT_14) - 1);
    XQC_TEST_ASSERT(policy != NULL);
    xqc_memzero(&session, sizeof(session));
    XQC_TEST_ASSERT(xqc_moq_session_bind_policy(&session, policy) == XQC_OK);
    XQC_TEST_ASSERT(xqc_moq_profile_decode_datagram(
        &session, encoded_datagram, sizeof(encoded_datagram))
        == -XQC_EVERSION);

    XQC_TEST_ASSERT(xqc_moq_session_validate_setup_type(
        &session, XQC_MOQ_MSG_CLIENT_SETUP) == -XQC_EVERSION);
    XQC_TEST_ASSERT(session.profile_state == XQC_MOQ_PROFILE_ALPN_SELECTED);
    XQC_TEST_ASSERT(xqc_moq_profile_decode_datagram(
        &session, encoded_datagram, sizeof(encoded_datagram))
        == -XQC_EVERSION);
    return 0;
}

static int
xqc_test_v5_control_writer_uses_profile_codec(void)
{
    static uint8_t namespace_value[] = "ns";
    xqc_moq_track_ns_field_t namespace_tuple = {
        .len = 2,
        .data = namespace_value,
    };
    xqc_moq_session_t session;
    xqc_moq_stream_t stream;
    xqc_moq_client_setup_msg_t client_setup;
    xqc_moq_subscribe_msg_t subscribe;

    xqc_memzero(&stream, sizeof(stream));
    xqc_memzero(&client_setup, sizeof(client_setup));
    xqc_memzero(&subscribe, sizeof(subscribe));
    XQC_TEST_ASSERT(xqc_test_activate_session(
        &session, XQC_ALPN_MOQ_DRAFT_05,
        sizeof(XQC_ALPN_MOQ_DRAFT_05) - 1, XQC_MOQ_VERSION_5) == 0);

    stream.session = &session;
    stream.kind = XQC_MOQ_STREAM_CONTROL;
    stream.trans_ops.write = xqc_test_stream_write;
    session.ctl_stream = &stream;
    xqc_test_configure_subscribe(&subscribe);
    subscribe.track_namespace_num = 1;
    subscribe.track_namespace_tuple = &namespace_tuple;

    XQC_TEST_ASSERT(xqc_moq_write_subscribe(
        &session, &subscribe) == XQC_OK);
    XQC_TEST_ASSERT(stream.write_buf_len == sizeof(xqc_v5_subscribe));
    XQC_TEST_ASSERT(memcmp(stream.write_buf, xqc_v5_subscribe,
                           sizeof(xqc_v5_subscribe)) == 0);

    xqc_test_configure_client_setup(&client_setup);
    XQC_TEST_ASSERT(xqc_moq_write_client_setup_for_profile(
        &session, client_setup.params, client_setup.params_num) == XQC_OK);
    XQC_TEST_ASSERT(stream.write_buf_len == sizeof(xqc_v5_client_setup));
    XQC_TEST_ASSERT(memcmp(stream.write_buf, xqc_v5_client_setup,
                           sizeof(xqc_v5_client_setup)) == 0);

    xqc_free(stream.write_buf);
    return 0;
}

static int
xqc_test_v5_outbound_object_stream_is_classified_by_profile(void)
{
    xqc_moq_session_t session;
    xqc_moq_stream_t stream;
    xqc_moq_object_stream_msg_t object;

    xqc_memzero(&stream, sizeof(stream));
    xqc_memzero(&object, sizeof(object));
    XQC_TEST_ASSERT(xqc_test_activate_session(
        &session, XQC_ALPN_MOQ_DRAFT_05,
        sizeof(XQC_ALPN_MOQ_DRAFT_05) - 1, XQC_MOQ_VERSION_5) == 0);

    stream.session = &session;
    stream.kind = XQC_MOQ_STREAM_UNKNOWN;
    stream.trans_ops.write = xqc_test_stream_write;
    xqc_test_configure_object_stream(&object);

    XQC_TEST_ASSERT(xqc_moq_write_object_stream_msg(
        &session, &stream, &object) == XQC_OK);
    XQC_TEST_ASSERT(stream.kind == XQC_MOQ_STREAM_V5_OBJECT);
    XQC_TEST_ASSERT(stream.write_buf_len == sizeof(xqc_v5_object_stream));
    XQC_TEST_ASSERT(memcmp(stream.write_buf, xqc_v5_object_stream,
                           sizeof(xqc_v5_object_stream)) == 0);

    xqc_free(stream.write_buf);
    return 0;
}

static int
xqc_test_v14_outbound_subgroup_stream_is_classified_by_profile(void)
{
    static uint8_t payload[] = "obj";
    xqc_moq_session_t session;
    xqc_moq_stream_t stream;
    xqc_moq_subgroup_msg_t subgroup;

    xqc_memzero(&stream, sizeof(stream));
    xqc_memzero(&subgroup, sizeof(subgroup));
    XQC_TEST_ASSERT(xqc_test_activate_session(
        &session, XQC_ALPN_MOQ_DRAFT_14,
        sizeof(XQC_ALPN_MOQ_DRAFT_14) - 1, XQC_MOQ_VERSION_14) == 0);

    stream.session = &session;
    stream.kind = XQC_MOQ_STREAM_UNKNOWN;
    stream.trans_ops.write = xqc_test_stream_write;
    subgroup.track_alias = 1;
    subgroup.group_id = 2;
    subgroup.subgroup_id = 3;
    subgroup.subgroup_type = XQC_MOQ_SUBGROUP_TYPE_WITH_ID;
    subgroup.subgroup_priority = 4;
    subgroup.object_id_delta = 5;
    subgroup.payload = payload;
    subgroup.payload_len = 3;

    XQC_TEST_ASSERT(xqc_moq_write_subgroup_msg(
        &session, &stream, &subgroup) == XQC_OK);
    XQC_TEST_ASSERT(stream.kind == XQC_MOQ_STREAM_V14_SUBGROUP);
    XQC_TEST_ASSERT(stream.write_buf_len > 0);
    XQC_TEST_ASSERT(stream.write_buf[0] == XQC_MOQ_SUBGROUP_TYPE_WITH_ID);

    xqc_free(stream.write_buf);
    return 0;
}

static int
xqc_test_v14_stream_preparation_is_profile_local(void)
{
    xqc_moq_session_t session;
    xqc_moq_stream_t stream;
    xqc_moq_subgroup_msg_t subgroup;

    xqc_memzero(&stream, sizeof(stream));
    xqc_memzero(&subgroup, sizeof(subgroup));
    XQC_TEST_ASSERT(xqc_test_activate_session(
        &session, XQC_ALPN_MOQ_DRAFT_14,
        sizeof(XQC_ALPN_MOQ_DRAFT_14) - 1, XQC_MOQ_VERSION_14) == 0);

    stream.session = &session;
    stream.subgroup_header_valid = 1;
    stream.subgroup_header.track_alias = 11;
    stream.subgroup_header.group_id = 12;
    stream.subgroup_header.subgroup_id = 13;
    stream.subgroup_header.subgroup_type = XQC_MOQ_SUBGROUP_TYPE_WITH_ID;
    stream.subgroup_header.subgroup_priority = 14;
    const xqc_moq_message_codec_entry_t *codec =
        xqc_moq_profile_find_semantic_codec(
            session.profile, XQC_MOQ_SEMANTIC_SUBGROUP_OBJECT);
    XQC_TEST_ASSERT(codec != NULL);
    XQC_TEST_ASSERT(xqc_moq_profile_prepare_data_message(
        &stream, codec, &subgroup.msg_base)
        == XQC_OK);
    XQC_TEST_ASSERT(subgroup.track_alias == 11);
    XQC_TEST_ASSERT(subgroup.group_id == 12);
    XQC_TEST_ASSERT(subgroup.subgroup_id == 13);
    XQC_TEST_ASSERT(subgroup.subgroup_priority == 14);
    XQC_TEST_ASSERT(stream.decode_msg_ctx.cur_field_idx == 0);
    XQC_TEST_ASSERT(codec->initialize
                    == xqc_moq_msg_subgroup_object_init_handler);
    return 0;
}

static int
xqc_test_v5_stream_preparation_requires_track_header(void)
{
    xqc_moq_session_t session;
    xqc_moq_stream_t stream;
    xqc_moq_track_stream_obj_msg_t object;

    xqc_memzero(&stream, sizeof(stream));
    xqc_memzero(&object, sizeof(object));
    XQC_TEST_ASSERT(xqc_test_activate_session(
        &session, XQC_ALPN_MOQ_DRAFT_05,
        sizeof(XQC_ALPN_MOQ_DRAFT_05) - 1, XQC_MOQ_VERSION_5) == 0);

    stream.session = &session;
    stream.kind = XQC_MOQ_STREAM_V5_TRACK;
    const xqc_moq_message_codec_entry_t *codec =
        xqc_moq_profile_find_semantic_codec(
            session.profile, XQC_MOQ_SEMANTIC_TRACK_STREAM_OBJECT);
    XQC_TEST_ASSERT(codec != NULL);
    XQC_TEST_ASSERT(xqc_moq_profile_prepare_data_message(
        &stream, codec, &object.msg_base)
        == -XQC_EILLEGAL_FRAME);

    stream.track_header_valid = 1;
    XQC_TEST_ASSERT(xqc_moq_profile_prepare_data_message(
        &stream, codec, &object.msg_base)
        == XQC_OK);
    return 0;
}

static int
xqc_test_subscribe_semantic_adapter(void)
{
    static unsigned char ns0[] = "ns";
    static unsigned char ns1[] = "extra";
    xqc_moq_track_ns_field_t one[] = {
        {.len = 2, .data = ns0},
    };
    xqc_moq_track_ns_field_t two[] = {
        {.len = 2, .data = ns0},
        {.len = 5, .data = ns1},
    };
    xqc_moq_session_t session;
    xqc_moq_stream_t stream;
    xqc_moq_subscribe_t *subscribe;
    xqc_moq_subscribe_msg_t decoded;

    XQC_TEST_ASSERT(xqc_moq_subscribe_create_with_ns_tuple(
        NULL, 0, 0, NULL, 0, NULL, XQC_MOQ_FILTER_LAST_GROUP,
        0, 0, 0, 0, NULL, 1) == NULL);
    XQC_TEST_ASSERT(xqc_moq_subscribe_create(
        NULL, 0, 0, NULL, NULL, XQC_MOQ_FILTER_LAST_GROUP,
        0, 0, 0, 0, NULL, 1) == NULL);

    XQC_TEST_ASSERT(xqc_test_activate_session(
        &session, XQC_ALPN_MOQ_DRAFT_05,
        sizeof(XQC_ALPN_MOQ_DRAFT_05) - 1, XQC_MOQ_VERSION_5) == 0);
    xqc_memzero(&stream, sizeof(stream));
    xqc_init_list_head(&session.local_subscribe_list);
    xqc_init_list_head(&session.peer_subscribe_list);

    subscribe = xqc_moq_subscribe_create_with_ns_tuple(
        &session, 1, 2, one, 1, "track", XQC_MOQ_FILTER_ABSOLUTE_RANGE,
        3, 4, 5, 6, "auth", 1);
    XQC_TEST_ASSERT(subscribe != NULL);
    XQC_TEST_ASSERT(subscribe->subscribe_msg->track_namespace_len == 2);
    XQC_TEST_ASSERT(memcmp(subscribe->subscribe_msg->track_namespace,
                           "ns", 2) == 0);
    stream.session = &session;
    stream.kind = XQC_MOQ_STREAM_CONTROL;
    stream.trans_ops.write = xqc_test_stream_write;
    session.ctl_stream = &stream;
    XQC_TEST_ASSERT(xqc_moq_write_subscribe(
        &session, subscribe->subscribe_msg) == XQC_OK);
    XQC_TEST_ASSERT(stream.write_buf_len == sizeof(xqc_v5_subscribe));
    XQC_TEST_ASSERT(memcmp(stream.write_buf, xqc_v5_subscribe,
                           sizeof(xqc_v5_subscribe)) == 0);
    xqc_free(stream.write_buf);
    xqc_list_del(&subscribe->list_member);
    xqc_moq_subscribe_destroy(subscribe);

    XQC_TEST_ASSERT(xqc_moq_subscribe_create_with_ns_tuple(
        &session, 3, 4, two, 2, "track", XQC_MOQ_FILTER_LAST_GROUP,
        0, 0, 0, 0, NULL, 1) == NULL);

    xqc_memzero(&decoded, sizeof(decoded));
    decoded.track_namespace = "ns";
    decoded.track_namespace_len = 2;
    XQC_TEST_ASSERT(xqc_moq_profile_adapt_subscribe(
        &session, &decoded) == XQC_OK);
    XQC_TEST_ASSERT(decoded.track_namespace_num == 1);
    XQC_TEST_ASSERT(decoded.track_namespace_tuple != NULL);
    XQC_TEST_ASSERT(decoded.track_namespace_tuple[0].len == 2);
    XQC_TEST_ASSERT(memcmp(decoded.track_namespace_tuple[0].data,
                           "ns", 2) == 0);
    xqc_moq_namespace_tuple_free(decoded.track_namespace_tuple,
                                 decoded.track_namespace_num);

    XQC_TEST_ASSERT(xqc_test_activate_session(
        &session, XQC_ALPN_MOQ_DRAFT_14,
        sizeof(XQC_ALPN_MOQ_DRAFT_14) - 1, XQC_MOQ_VERSION_14) == 0);
    xqc_init_list_head(&session.local_subscribe_list);
    xqc_init_list_head(&session.peer_subscribe_list);
    subscribe = xqc_moq_subscribe_create_with_ns_tuple(
        &session, 5, 6, two, 2, "track", XQC_MOQ_FILTER_LAST_GROUP,
        0, 0, 0, 0, NULL, 1);
    XQC_TEST_ASSERT(subscribe != NULL);
    XQC_TEST_ASSERT(subscribe->subscribe_msg->track_namespace_num == 2);
    xqc_list_del(&subscribe->list_member);
    xqc_moq_subscribe_destroy(subscribe);
    return 0;
}

static int
xqc_test_high_level_media_apis_require_active_profile(void)
{
    static unsigned char ns[] = "ns";
    static uint8_t payload[] = "x";
    xqc_moq_track_ns_field_t namespace_tuple = {
        .len = 2,
        .data = ns,
    };
    const xqc_moq_alpn_policy_t *policy;
    xqc_moq_session_t session;

    policy = xqc_moq_version_policy_for_alpn(
        XQC_ALPN_MOQ_DRAFT_05, sizeof(XQC_ALPN_MOQ_DRAFT_05) - 1);
    XQC_TEST_ASSERT(policy != NULL);
    xqc_memzero(&session, sizeof(session));
    XQC_TEST_ASSERT(xqc_moq_session_bind_policy(&session, policy) == XQC_OK);
    xqc_init_list_head(&session.local_subscribe_list);
    xqc_init_list_head(&session.peer_subscribe_list);

    XQC_TEST_ASSERT(xqc_moq_subscribe_create_with_ns_tuple(
        &session, 1, 2, &namespace_tuple, 1, "track",
        XQC_MOQ_FILTER_LAST_GROUP, 0, 0, 0, 0, NULL, 1) == NULL);
    XQC_TEST_ASSERT(xqc_moq_write_datachannel(
        &session, payload, sizeof(payload)) == -XQC_EVERSION);
    return 0;
}

static int
xqc_test_v5_golden_encode(void)
{
    xqc_moq_session_t session;
    uint8_t encoded[256];

    XQC_TEST_ASSERT(xqc_test_activate_session(
        &session, XQC_ALPN_MOQ_DRAFT_05,
        sizeof(XQC_ALPN_MOQ_DRAFT_05) - 1, XQC_MOQ_VERSION_5) == 0);

    for (size_t i = 0;
         i < sizeof(xqc_v5_vectors) / sizeof(xqc_v5_vectors[0]); ++i)
    {
        const xqc_test_v5_vector_t *vector = &xqc_v5_vectors[i];
        const xqc_moq_message_codec_entry_t *codec =
            xqc_test_v5_vector_codec(&session, vector);
        xqc_moq_msg_base_t *base = NULL;
        XQC_TEST_ASSERT(codec != NULL);
        XQC_TEST_ASSERT(xqc_moq_msg_create_with_codec(
            &session, vector->stream_kind, vector->wire_type,
            codec, (void **)&base) == XQC_OK);
        XQC_TEST_ASSERT(base != NULL);
        vector->configure(base);

        xqc_int_t encoded_len = base->encode_len(base);
        XQC_TEST_ASSERT(encoded_len == (xqc_int_t)vector->bytes_len);
        XQC_TEST_ASSERT(base->encode(base, encoded, sizeof(encoded))
                        == encoded_len);
        if (memcmp(encoded, vector->bytes, vector->bytes_len) != 0) {
            fprintf(stderr, "v5 encode mismatch: %s\n", vector->name);
            return -1;
        }
    }

    return 0;
}

static int
xqc_test_v5_decode_once(xqc_moq_session_t *session,
    const xqc_test_v5_vector_t *vector, size_t first_body_len)
{
    xqc_moq_decode_msg_ctx_t ctx;
    xqc_moq_msg_base_t *base;
    xqc_int_t finish = 0;
    xqc_int_t wait_more_data = 0;
    xqc_int_t first_processed = 0;
    xqc_int_t second_processed;
    size_t body_len = vector->bytes_len - vector->prefix_len;
    uint8_t encoded[256];
    const xqc_moq_message_codec_entry_t *codec =
        xqc_test_v5_vector_codec(session, vector);

    xqc_memzero(&ctx, sizeof(ctx));
    ctx.cur_msg_type = (xqc_moq_msg_type_t)vector->wire_type;
    XQC_TEST_ASSERT(codec != NULL);
    XQC_TEST_ASSERT(xqc_moq_msg_create_with_codec(
        session, vector->stream_kind, vector->wire_type,
        codec, (void **)&base) == XQC_OK);
    XQC_TEST_ASSERT(base != NULL);

    if (first_body_len > 0) {
        first_processed = base->decode(
            (uint8_t *)vector->bytes + vector->prefix_len,
            first_body_len, 0, &ctx, base, &finish, &wait_more_data);
        XQC_TEST_ASSERT(first_processed >= 0);
        XQC_TEST_ASSERT(finish == 0);
        XQC_TEST_ASSERT(wait_more_data == 1);
    }

    finish = 0;
    wait_more_data = 0;
    second_processed = base->decode(
        (uint8_t *)vector->bytes + vector->prefix_len + first_processed,
        body_len - (size_t)first_processed, 1, &ctx, base, &finish,
        &wait_more_data);
    XQC_TEST_ASSERT(second_processed >= 0);
    XQC_TEST_ASSERT((size_t)(first_processed + second_processed) == body_len);
    XQC_TEST_ASSERT(finish == 1);
    XQC_TEST_ASSERT(wait_more_data == 0);

    if (vector->wire_type == XQC_MOQ_MSG_SUBSCRIBE_OK) {
        XQC_TEST_ASSERT(((xqc_moq_subscribe_ok_msg_t *)base)->track_alias
                        == XQC_MOQ_INVALID_ID);
    }

    XQC_TEST_ASSERT(base->encode_len(base) == (xqc_int_t)vector->bytes_len);
    XQC_TEST_ASSERT(base->encode(base, encoded, sizeof(encoded))
                    == (xqc_int_t)vector->bytes_len);
    if (memcmp(encoded, vector->bytes, vector->bytes_len) != 0) {
        fprintf(stderr, "v5 decode mismatch: %s split=%zu\n",
                vector->name, first_body_len);
        return -1;
    }

    xqc_moq_msg_free_with_codec(codec, base);
    return 0;
}

static int
xqc_test_v5_golden_decode_split_points(void)
{
    xqc_moq_session_t session;

    XQC_TEST_ASSERT(xqc_test_activate_session(
        &session, XQC_ALPN_MOQ_DRAFT_05,
        sizeof(XQC_ALPN_MOQ_DRAFT_05) - 1, XQC_MOQ_VERSION_5) == 0);

    for (size_t i = 0;
         i < sizeof(xqc_v5_vectors) / sizeof(xqc_v5_vectors[0]); ++i)
    {
        const xqc_test_v5_vector_t *vector = &xqc_v5_vectors[i];
        size_t body_len = vector->bytes_len - vector->prefix_len;

        XQC_TEST_ASSERT(xqc_test_v5_decode_once(&session, vector, 0) == 0);
        for (size_t split = 1; split < body_len; ++split) {
            XQC_TEST_ASSERT(xqc_test_v5_decode_once(
                &session, vector, split) == 0);
        }
    }

    return 0;
}

static int
xqc_test_oversized_setup_params_cleanup_is_safe(void)
{
    struct {
        const char *alpn;
        size_t alpn_len;
        uint64_t setup_type;
        uint64_t version;
        xqc_bool_t length_prefixed;
    } cases[] = {
        {
            XQC_ALPN_MOQ_DRAFT_05,
            sizeof(XQC_ALPN_MOQ_DRAFT_05) - 1,
            XQC_MOQ_MSG_CLIENT_SETUP,
            XQC_MOQ_VERSION_5,
            XQC_FALSE,
        },
        {
            XQC_ALPN_MOQ_DRAFT_14,
            sizeof(XQC_ALPN_MOQ_DRAFT_14) - 1,
            XQC_MOQ_MSG_CLIENT_SETUP_V14,
            XQC_MOQ_VERSION_14,
            XQC_TRUE,
        },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        xqc_moq_session_t session;
        xqc_moq_decode_msg_ctx_t ctx;
        xqc_moq_msg_base_t *base;
        const xqc_moq_alpn_policy_t *policy;
        uint8_t payload[32];
        uint8_t body[40];
        uint8_t *p = payload;
        uint8_t *body_end;
        xqc_int_t finish = 0;
        xqc_int_t wait_more_data = 0;
        xqc_int_t ret;

        policy = xqc_moq_version_policy_for_alpn(
            cases[i].alpn, cases[i].alpn_len);
        XQC_TEST_ASSERT(policy != NULL);
        xqc_memzero(&session, sizeof(session));
        xqc_memzero(&ctx, sizeof(ctx));
        XQC_TEST_ASSERT(xqc_moq_session_bind_policy(
            &session, policy) == XQC_OK);

        base = xqc_moq_msg_create(
            &session, XQC_MOQ_STREAM_CONTROL, cases[i].setup_type);
        XQC_TEST_ASSERT(base != NULL);

        p = xqc_put_varint(p, 1);
        p = xqc_put_varint(p, cases[i].version);
        p = xqc_put_varint(p, XQC_MOQ_MAX_PARAMS + 1);
        if (cases[i].length_prefixed) {
            /* draft-14 Length is a fixed-width 2-byte field, not a varint. */
            size_t payload_len = (size_t)(p - payload);
            body[0] = (uint8_t)((payload_len >> 8) & 0xff);
            body[1] = (uint8_t)(payload_len & 0xff);
            body_end = body + XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
            xqc_memcpy(body_end, payload, payload_len);
            body_end += payload_len;

        } else {
            xqc_memcpy(body, payload, (size_t)(p - payload));
            body_end = body + (p - payload);
        }

        ret = base->decode(body, (size_t)(body_end - body), 1, &ctx, base,
                           &finish, &wait_more_data);
        XQC_TEST_ASSERT(ret == -XQC_ELIMIT);
        xqc_moq_msg_free(&session, XQC_MOQ_STREAM_CONTROL,
                         cases[i].setup_type, base);
    }

    return 0;
}

/*
 * A SUBSCRIBE whose Track Name is empty. Splitting the stream right after the
 * zero length byte must not make the decoder read that length a second time.
 */
static const uint8_t xqc_v14_subscribe_empty_track_name[] = {
    0x03,                   /* SUBSCRIBE                                   */
    0x00, 0x0b,             /* Length = 11 (2-byte fixed width)            */
    0x01,                   /* Subscribe ID                                */
    0x01,                   /* Track Namespace tuple count                 */
    0x02, 0x6e, 0x73,       /* tuple[0] = "ns"                             */
    0x00,                   /* Track Name Length = 0  <-- split point      */
    0x41,                   /* Subscriber Priority (bogus length if reread)*/
    0x01,                   /* Group Order                                 */
    0x01,                   /* Forward                                     */
    0x02,                   /* Filter Type = LatestObject                  */
    0x00,                   /* Number of Parameters                        */
};

static int
xqc_test_v14_empty_track_name_split_is_safe(void)
{
    xqc_moq_session_t session;
    const size_t prefix_len = 1;
    const size_t body_len =
        sizeof(xqc_v14_subscribe_empty_track_name) - prefix_len;

    XQC_TEST_ASSERT(xqc_test_activate_session(
        &session, XQC_ALPN_MOQ_DRAFT_14,
        sizeof(XQC_ALPN_MOQ_DRAFT_14) - 1, XQC_MOQ_VERSION_14) == 0);

    for (size_t split = 0; split < body_len; ++split) {
        xqc_moq_decode_msg_ctx_t ctx;
        xqc_moq_msg_base_t *base;
        xqc_moq_subscribe_msg_t *subscribe;
        xqc_int_t finish = 0;
        xqc_int_t wait_more_data = 0;
        xqc_int_t first_processed = 0;
        xqc_int_t second_processed;

        xqc_memzero(&ctx, sizeof(ctx));
        ctx.cur_msg_type = XQC_MOQ_MSG_SUBSCRIBE;
        base = xqc_moq_msg_create(&session, XQC_MOQ_STREAM_CONTROL,
                                  XQC_MOQ_MSG_SUBSCRIBE);
        XQC_TEST_ASSERT(base != NULL);

        if (split > 0) {
            first_processed = base->decode(
                (uint8_t *)xqc_v14_subscribe_empty_track_name + prefix_len,
                split, 0, &ctx, base, &finish, &wait_more_data);
            XQC_TEST_ASSERT(first_processed >= 0);
            XQC_TEST_ASSERT(finish == 0);
            XQC_TEST_ASSERT(wait_more_data == 1);
        }

        finish = 0;
        wait_more_data = 0;
        second_processed = base->decode(
            (uint8_t *)xqc_v14_subscribe_empty_track_name + prefix_len
                + first_processed,
            body_len - (size_t)first_processed, 1, &ctx, base, &finish,
            &wait_more_data);

        subscribe = (xqc_moq_subscribe_msg_t *)base;
        if (second_processed < 0 || finish != 1
            || subscribe->track_name_len != 0
            || subscribe->subscriber_priority != 0x41)
        {
            fprintf(stderr,
                    "empty track name split=%zu: first=%d ret=%d finish=%d "
                    "wait=%d name_len=%zu prio=%u idx=%d declared=%llu "
                    "consumed=%llu\n",
                    split, first_processed, second_processed, finish,
                    wait_more_data, subscribe->track_name_len,
                    (unsigned)subscribe->subscriber_priority,
                    ctx.cur_field_idx,
                    (unsigned long long)ctx.msg_declared_length,
                    (unsigned long long)ctx.msg_payload_consumed);
            xqc_moq_msg_free(&session, XQC_MOQ_STREAM_CONTROL,
                             XQC_MOQ_MSG_SUBSCRIBE, base);
            return -1;
        }

        xqc_moq_msg_free(&session, XQC_MOQ_STREAM_CONTROL,
                         XQC_MOQ_MSG_SUBSCRIBE, base);
    }

    return 0;
}

/* draft-05 SUBSCRIBE with an empty Track Name; same re-entry hazard as v14. */
static const uint8_t xqc_v5_subscribe_empty_track_name[] = {
    0x03,                   /* SUBSCRIBE                                   */
    0x01,                   /* Subscribe ID                                */
    0x02,                   /* Track Alias                                 */
    0x02, 0x6e, 0x73,       /* Track Namespace = "ns"                      */
    0x00,                   /* Track Name Length = 0  <-- split point      */
    0x02,                   /* Filter Type = LatestObject                  */
    0x00,                   /* Number of Parameters                        */
};

static int
xqc_test_v5_empty_track_name_split_is_safe(void)
{
    xqc_moq_session_t session;
    const size_t prefix_len = 1;
    const size_t body_len =
        sizeof(xqc_v5_subscribe_empty_track_name) - prefix_len;

    XQC_TEST_ASSERT(xqc_test_activate_session(
        &session, XQC_ALPN_MOQ_DRAFT_05,
        sizeof(XQC_ALPN_MOQ_DRAFT_05) - 1, XQC_MOQ_VERSION_5) == 0);

    for (size_t split = 0; split < body_len; ++split) {
        xqc_moq_decode_msg_ctx_t ctx;
        xqc_moq_msg_base_t *base;
        xqc_moq_subscribe_msg_t *subscribe;
        xqc_int_t finish = 0;
        xqc_int_t wait_more_data = 0;
        xqc_int_t first_processed = 0;
        xqc_int_t second_processed;

        xqc_memzero(&ctx, sizeof(ctx));
        ctx.cur_msg_type = XQC_MOQ_MSG_SUBSCRIBE;
        base = xqc_moq_msg_create(&session, XQC_MOQ_STREAM_CONTROL,
                                  XQC_MOQ_MSG_SUBSCRIBE);
        XQC_TEST_ASSERT(base != NULL);

        if (split > 0) {
            first_processed = base->decode(
                (uint8_t *)xqc_v5_subscribe_empty_track_name + prefix_len,
                split, 0, &ctx, base, &finish, &wait_more_data);
            XQC_TEST_ASSERT(first_processed >= 0);
            XQC_TEST_ASSERT(finish == 0);
            XQC_TEST_ASSERT(wait_more_data == 1);
        }

        finish = 0;
        wait_more_data = 0;
        second_processed = base->decode(
            (uint8_t *)xqc_v5_subscribe_empty_track_name + prefix_len
                + first_processed,
            body_len - (size_t)first_processed, 1, &ctx, base, &finish,
            &wait_more_data);

        subscribe = (xqc_moq_subscribe_msg_t *)base;
        if (second_processed < 0 || finish != 1
            || subscribe->track_name_len != 0
            || subscribe->filter_type != XQC_MOQ_FILTER_LAST_OBJECT)
        {
            fprintf(stderr,
                    "v5 empty track name split=%zu: first=%d ret=%d finish=%d "
                    "name_len=%zu filter=%llu idx=%d\n",
                    split, first_processed, second_processed, finish,
                    subscribe->track_name_len,
                    (unsigned long long)subscribe->filter_type,
                    ctx.cur_field_idx);
            xqc_moq_msg_free(&session, XQC_MOQ_STREAM_CONTROL,
                             XQC_MOQ_MSG_SUBSCRIBE, base);
            return -1;
        }

        xqc_moq_msg_free(&session, XQC_MOQ_STREAM_CONTROL,
                         XQC_MOQ_MSG_SUBSCRIBE, base);
    }

    return 0;
}

static int
xqc_test_catalog_default_follows_profile(void)
{
    xqc_moq_session_t v5;
    xqc_moq_session_t v14;

    XQC_TEST_ASSERT(xqc_test_activate_session(
        &v5, XQC_ALPN_MOQ_DRAFT_05,
        sizeof(XQC_ALPN_MOQ_DRAFT_05) - 1, XQC_MOQ_VERSION_5) == 0);
    XQC_TEST_ASSERT(xqc_test_activate_session(
        &v14, XQC_ALPN_MOQ_DRAFT_14,
        sizeof(XQC_ALPN_MOQ_DRAFT_14) - 1, XQC_MOQ_VERSION_14) == 0);

    /* "unset" is what xqc_moq_session_create() leaves behind */
    xqc_moq_session_set_enable_catalog(&v5, -1);
    xqc_moq_session_set_enable_catalog(&v14, -1);
    XQC_TEST_ASSERT(xqc_moq_session_catalog_enabled(&v5) == XQC_TRUE);
    XQC_TEST_ASSERT(xqc_moq_session_catalog_enabled(&v14) == XQC_FALSE);

    /* an explicit choice overrides the profile default in both directions */
    xqc_moq_session_set_enable_catalog(&v14, 1);
    XQC_TEST_ASSERT(xqc_moq_session_catalog_enabled(&v14) == XQC_TRUE);
    xqc_moq_session_set_enable_catalog(&v5, 0);
    XQC_TEST_ASSERT(xqc_moq_session_catalog_enabled(&v5) == XQC_FALSE);

    /* and a negative value goes back to following the profile */
    xqc_moq_session_set_enable_catalog(&v5, -1);
    xqc_moq_session_set_enable_catalog(&v14, -1);
    XQC_TEST_ASSERT(xqc_moq_session_catalog_enabled(&v5) == XQC_TRUE);
    XQC_TEST_ASSERT(xqc_moq_session_catalog_enabled(&v14) == XQC_FALSE);

    XQC_TEST_ASSERT(xqc_moq_session_catalog_enabled(NULL) == XQC_FALSE);
    return 0;
}

/*
 * A failed subscribe must leave the track exactly as it was, otherwise the
 * track keeps a live alias with no subscribe_id and every later attempt is
 * rejected as "already subscribed".
 */
static int
xqc_test_subscribe_failure_rolls_back_track(void)
{
    static unsigned char ns_head[] = "ns";
    static unsigned char ns_tail[] = "sub";
    xqc_moq_track_ns_field_t ns[2] = {
        {.len = 2, .data = ns_head},
        {.len = 3, .data = ns_tail},
    };
    xqc_moq_session_t session;
    xqc_log_callbacks_t log_callbacks;
    xqc_log_t log;
    xqc_moq_track_t *track;

    xqc_memzero(&log_callbacks, sizeof(log_callbacks));
    xqc_memzero(&log, sizeof(log));
    XQC_TEST_ASSERT(xqc_test_activate_session(
        &session, XQC_ALPN_MOQ_DRAFT_05,
        sizeof(XQC_ALPN_MOQ_DRAFT_05) - 1, XQC_MOQ_VERSION_5) == 0);
    log.log_level = XQC_LOG_DEBUG;
    log.log_callbacks = &log_callbacks;
    session.log = &log;
    xqc_init_list_head(&session.local_subscribe_list);
    xqc_init_list_head(&session.peer_subscribe_list);
    xqc_init_list_head(&session.track_list_for_pub);
    xqc_init_list_head(&session.track_list_for_sub);

    track = xqc_moq_track_create_with_ns_tuple(
        &session, ns, 2, "track", XQC_MOQ_TRACK_VIDEO, NULL,
        XQC_MOQ_CONTAINER_LOC, XQC_MOQ_TRACK_FOR_SUB);
    XQC_TEST_ASSERT(track != NULL);
    XQC_TEST_ASSERT(track->track_alias == XQC_MOQ_INVALID_ID);
    XQC_TEST_ASSERT(track->subscribe_id == XQC_MOQ_INVALID_ID);

    /*
     * draft-05 carries a single namespace element, so building the subscribe
     * record fails after the track has already been stamped.
     */
    XQC_TEST_ASSERT(xqc_moq_subscribe_with_ns_tuple(
        &session, ns, 2, "track", XQC_MOQ_FILTER_LAST_GROUP,
        0, 0, 0, 0, NULL) < 0);
    XQC_TEST_ASSERT(track->track_alias == XQC_MOQ_INVALID_ID);
    XQC_TEST_ASSERT(track->subscribe_id == XQC_MOQ_INVALID_ID);

    /* and the retry must fail the same way, not with "already subscribed" */
    XQC_TEST_ASSERT(xqc_moq_subscribe_with_ns_tuple(
        &session, ns, 2, "track", XQC_MOQ_FILTER_LAST_GROUP,
        0, 0, 0, 0, NULL) < 0);
    XQC_TEST_ASSERT(track->track_alias == XQC_MOQ_INVALID_ID);
    XQC_TEST_ASSERT(track->subscribe_id == XQC_MOQ_INVALID_ID);
    return 0;
}

/*
 * A publish that is rejected because the track already has a subscriber must
 * not allocate an alias on the way out. Otherwise the track ends up with a
 * live alias and no subscribe_id, which is the state that later lets an
 * inbound draft-14 SUBSCRIBE stamp alias 0 onto it.
 */
static int
xqc_test_publish_rejection_leaves_track_untouched(void)
{
    static unsigned char ns_head[] = "ns";
    xqc_moq_track_ns_field_t ns = {.len = 2, .data = ns_head};
    xqc_moq_session_t session;
    xqc_log_callbacks_t log_callbacks;
    xqc_log_t log;
    xqc_moq_track_t *track;
    xqc_moq_publish_msg_t publish;

    xqc_memzero(&log_callbacks, sizeof(log_callbacks));
    xqc_memzero(&log, sizeof(log));
    XQC_TEST_ASSERT(xqc_test_activate_session(
        &session, XQC_ALPN_MOQ_DRAFT_14,
        sizeof(XQC_ALPN_MOQ_DRAFT_14) - 1, XQC_MOQ_VERSION_14) == 0);
    log.log_level = XQC_LOG_DEBUG;
    log.log_callbacks = &log_callbacks;
    session.log = &log;
    xqc_init_list_head(&session.local_subscribe_list);
    xqc_init_list_head(&session.peer_subscribe_list);
    xqc_init_list_head(&session.track_list_for_pub);
    xqc_init_list_head(&session.track_list_for_sub);

    track = xqc_moq_track_create_with_ns_tuple(
        &session, &ns, 1, "track", XQC_MOQ_TRACK_VIDEO, NULL,
        XQC_MOQ_CONTAINER_LOC, XQC_MOQ_TRACK_FOR_PUB);
    XQC_TEST_ASSERT(track != NULL);

    /* pretend the track already serves a subscriber */
    xqc_moq_track_set_subscribe_id(track, 5);

    xqc_memzero(&publish, sizeof(publish));
    publish.track_namespace_tuple = &ns;
    publish.track_namespace_num = 1;
    publish.track_name = "track";
    publish.track_name_len = 5;

    XQC_TEST_ASSERT(xqc_moq_publish(&session, &publish)
                    == -MOQ_PROTOCOL_VIOLATION);
    XQC_TEST_ASSERT(track->track_alias == XQC_MOQ_INVALID_ID);
    XQC_TEST_ASSERT(track->subscribe_id == 5);

    /*
     * A later failure must restore the exact state that existed before the
     * attempt. In particular, an alias owned by the track before publish must
     * not be cleared merely because writing PUBLISH failed.
     */
    xqc_moq_track_set_subscribe_id(track, XQC_MOQ_INVALID_ID);
    xqc_moq_track_set_alias(track, 77);
    xqc_memzero(&publish, sizeof(publish));
    publish.track_namespace_tuple = &ns;
    publish.track_namespace_num = 1;
    publish.track_name = "track";
    publish.track_name_len = 5;

    XQC_TEST_ASSERT(xqc_moq_publish(&session, &publish) < 0);
    XQC_TEST_ASSERT(track->track_alias == 77);
    XQC_TEST_ASSERT(track->subscribe_id == XQC_MOQ_INVALID_ID);
    return 0;
}

/*
 * Every draft-14 parameter-bearing success path must use the same grammar:
 * even types carry a bare varint, odd types carry length-prefixed bytes, and
 * a zero-length odd parameter completes immediately.
 */
static const uint8_t xqc_v14_subscribe_params[] = {
    0x03, 0x00, 0x19,                   /* SUBSCRIBE, Length = 25          */
    0x01,                               /* Subscribe ID                    */
    0x01, 0x02, 0x6e, 0x73,             /* namespace tuple = ("ns")        */
    0x05, 0x74, 0x72, 0x61, 0x63, 0x6b, /* Track Name = "track"            */
    0x04, 0x01, 0x01, 0x02,             /* priority/order/forward/filter   */
    0x03,                               /* Number of Parameters            */
    0x00, 0x03,                         /* ROLE = integer 3                */
    0x03, 0x02, 0x61, 0x62,             /* AUTHORIZATION_TOKEN = "ab"      */
    0x40, 0xa1, 0x00,                   /* CATALOG = empty bytes           */
};

static const uint8_t xqc_v14_subscribe_ok_params[] = {
    0x04, 0x00, 0x0f,                   /* SUBSCRIBE_OK, Length = 15       */
    0x01, 0x02, 0x00, 0x01, 0x00,       /* id/alias/expiry/order/no-content*/
    0x03,                               /* Number of Parameters            */
    0x00, 0x03,
    0x03, 0x02, 0x61, 0x62,
    0x40, 0xa1, 0x00,
};

static const uint8_t xqc_v14_publish_ok_params[] = {
    0x1e, 0x00, 0x0f,                   /* PUBLISH_OK, Length = 15         */
    0x01, 0x01, 0x04, 0x01, 0x02,       /* id/forward/priority/order/filter*/
    0x03,                               /* Number of Parameters            */
    0x00, 0x03,
    0x03, 0x02, 0x61, 0x62,
    0x40, 0xa1, 0x00,
};

static void
xqc_test_v14_params_view(xqc_moq_msg_base_t *base, uint64_t wire_type,
    uint64_t **params_num, xqc_moq_message_parameter_t ***params)
{
    if (wire_type == XQC_MOQ_MSG_SUBSCRIBE) {
        xqc_moq_subscribe_msg_t *msg = (xqc_moq_subscribe_msg_t *)base;
        *params_num = &msg->params_num;
        *params = &msg->params;

    } else if (wire_type == XQC_MOQ_MSG_SUBSCRIBE_OK) {
        xqc_moq_subscribe_ok_msg_t *msg =
            (xqc_moq_subscribe_ok_msg_t *)base;
        *params_num = &msg->params_num;
        *params = &msg->params;

    } else {
        xqc_moq_publish_ok_msg_t *msg = (xqc_moq_publish_ok_msg_t *)base;
        *params_num = &msg->params_num;
        *params = &msg->params;
    }
}

static int
xqc_test_v14_parameter_vectors(void)
{
    struct {
        const char *name;
        uint64_t wire_type;
        const uint8_t *bytes;
        size_t bytes_len;
    } cases[] = {
        {
            "SUBSCRIBE", XQC_MOQ_MSG_SUBSCRIBE,
            xqc_v14_subscribe_params, sizeof(xqc_v14_subscribe_params),
        },
        {
            "SUBSCRIBE_OK", XQC_MOQ_MSG_SUBSCRIBE_OK,
            xqc_v14_subscribe_ok_params,
            sizeof(xqc_v14_subscribe_ok_params),
        },
        {
            "PUBLISH_OK", XQC_MOQ_MSG_PUBLISH_OK,
            xqc_v14_publish_ok_params, sizeof(xqc_v14_publish_ok_params),
        },
    };
    xqc_moq_message_parameter_t params[3];
    xqc_moq_track_ns_field_t ns;
    xqc_moq_session_t session;
    uint8_t namespace_value[] = {'n', 's'};
    uint8_t odd_value[] = {'a', 'b'};

    XQC_TEST_ASSERT(xqc_test_activate_session(
        &session, XQC_ALPN_MOQ_DRAFT_14,
        sizeof(XQC_ALPN_MOQ_DRAFT_14) - 1, XQC_MOQ_VERSION_14) == 0);

    xqc_memzero(params, sizeof(params));
    params[0].type = XQC_MOQ_PARAM_ROLE;
    params[0].is_integer = 1;
    params[0].int_value = 3;
    params[1].type = XQC_MOQ_PARAM_AUTHORIZATION_TOKEN;
    params[1].length = sizeof(odd_value);
    params[1].value = odd_value;
    params[2].type = XQC_MOQ_PARAM_CATALOG;
    ns.len = sizeof(namespace_value);
    ns.data = namespace_value;

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        union {
            xqc_moq_subscribe_msg_t subscribe;
            xqc_moq_subscribe_ok_msg_t subscribe_ok;
            xqc_moq_publish_ok_msg_t publish_ok;
        } message;
        xqc_moq_msg_base_t *base;
        uint8_t encoded[128];
        xqc_int_t encoded_len;

        xqc_memzero(&message, sizeof(message));
        if (cases[i].wire_type == XQC_MOQ_MSG_SUBSCRIBE) {
            xqc_moq_msg_subscribe_init_handler(&message.subscribe.msg_base);
            message.subscribe.subscribe_id = 1;
            message.subscribe.track_namespace_num = 1;
            message.subscribe.track_namespace_tuple = &ns;
            message.subscribe.track_name = "track";
            message.subscribe.track_name_len = 5;
            message.subscribe.subscriber_priority = 4;
            message.subscribe.group_order = 1;
            message.subscribe.forward = 1;
            message.subscribe.filter_type = XQC_MOQ_FILTER_LAST_OBJECT;
            message.subscribe.params_num = 3;
            message.subscribe.params = params;
            base = &message.subscribe.msg_base;

        } else if (cases[i].wire_type == XQC_MOQ_MSG_SUBSCRIBE_OK) {
            xqc_moq_msg_subscribe_ok_init_handler(
                &message.subscribe_ok.msg_base);
            message.subscribe_ok.subscribe_id = 1;
            message.subscribe_ok.track_alias = 2;
            message.subscribe_ok.group_order = 1;
            message.subscribe_ok.params_num = 3;
            message.subscribe_ok.params = params;
            base = &message.subscribe_ok.msg_base;

        } else {
            xqc_moq_msg_publish_ok_init_handler(&message.publish_ok.msg_base);
            message.publish_ok.subscribe_id = 1;
            message.publish_ok.forward = 1;
            message.publish_ok.subscriber_priority = 4;
            message.publish_ok.group_order = 1;
            message.publish_ok.filter_type = XQC_MOQ_FILTER_LAST_OBJECT;
            message.publish_ok.params_num = 3;
            message.publish_ok.params = params;
            base = &message.publish_ok.msg_base;
        }

        encoded_len = base->encode(base, encoded, sizeof(encoded));
        if (encoded_len != (xqc_int_t)cases[i].bytes_len
            || memcmp(encoded, cases[i].bytes, cases[i].bytes_len) != 0)
        {
            fprintf(stderr, "%s byte-exact encode mismatch: ret=%d want=%zu\n",
                    cases[i].name, encoded_len, cases[i].bytes_len);
            return -1;
        }

        size_t prefix_len = (size_t)xqc_put_varint_len(cases[i].wire_type);
        size_t body_len = cases[i].bytes_len - prefix_len;
        for (size_t split = 0; split < body_len; ++split) {
            xqc_moq_decode_msg_ctx_t ctx;
            xqc_moq_msg_base_t *decoded;
            uint64_t *params_num;
            xqc_moq_message_parameter_t **decoded_params;
            uint8_t reencoded[128];
            xqc_int_t first_processed = 0;
            xqc_int_t second_processed;
            xqc_int_t reencoded_len;
            xqc_int_t finish = 0;
            xqc_int_t wait_more_data = 0;

            xqc_memzero(&ctx, sizeof(ctx));
            ctx.cur_msg_type = (xqc_moq_msg_type_t)cases[i].wire_type;
            decoded = xqc_moq_msg_create(
                &session, XQC_MOQ_STREAM_CONTROL, cases[i].wire_type);
            XQC_TEST_ASSERT(decoded != NULL);

            if (split > 0) {
                first_processed = decoded->decode(
                    (uint8_t *)cases[i].bytes + prefix_len, split, 0, &ctx,
                    decoded, &finish, &wait_more_data);
                XQC_TEST_ASSERT(first_processed >= 0);
                XQC_TEST_ASSERT(finish == 0);
                XQC_TEST_ASSERT(wait_more_data == 1);
            }

            finish = 0;
            wait_more_data = 0;
            second_processed = decoded->decode(
                (uint8_t *)cases[i].bytes + prefix_len + first_processed,
                body_len - (size_t)first_processed, 1, &ctx, decoded, &finish,
                &wait_more_data);
            xqc_test_v14_params_view(
                decoded, cases[i].wire_type, &params_num, &decoded_params);

            if (second_processed < 0
                || (size_t)(first_processed + second_processed) != body_len
                || finish != 1 || wait_more_data != 0 || *params_num != 3
                || *decoded_params == NULL
                || (*decoded_params)[0].type != XQC_MOQ_PARAM_ROLE
                || !(*decoded_params)[0].is_integer
                || (*decoded_params)[0].int_value != 3
                || (*decoded_params)[1].type
                    != XQC_MOQ_PARAM_AUTHORIZATION_TOKEN
                || (*decoded_params)[1].length != sizeof(odd_value)
                || (*decoded_params)[1].value == NULL
                || memcmp((*decoded_params)[1].value, odd_value,
                          sizeof(odd_value)) != 0
                || (*decoded_params)[2].type != XQC_MOQ_PARAM_CATALOG
                || (*decoded_params)[2].length != 0
                || (*decoded_params)[2].value != NULL)
            {
                fprintf(stderr,
                        "%s parameter decode mismatch at split=%zu: "
                        "first=%d second=%d finish=%d wait=%d num=%llu\n",
                        cases[i].name, split, first_processed,
                        second_processed, finish, wait_more_data,
                        (unsigned long long)*params_num);
                xqc_moq_msg_free(&session, XQC_MOQ_STREAM_CONTROL,
                                 cases[i].wire_type, decoded);
                return -1;
            }

            reencoded_len = decoded->encode(
                decoded, reencoded, sizeof(reencoded));
            if (reencoded_len != (xqc_int_t)cases[i].bytes_len
                || memcmp(reencoded, cases[i].bytes, cases[i].bytes_len) != 0)
            {
                fprintf(stderr,
                        "%s parameter re-encode mismatch at split=%zu\n",
                        cases[i].name, split);
                xqc_moq_msg_free(&session, XQC_MOQ_STREAM_CONTROL,
                                 cases[i].wire_type, decoded);
                return -1;
            }

            xqc_moq_msg_free(&session, XQC_MOQ_STREAM_CONTROL,
                             cases[i].wire_type, decoded);
        }
    }

    return 0;
}

/*
 * draft-05 SUBSCRIBE carrying (a) this project's own CATALOG parameter, whose
 * type is above the old hardcoded ceiling, and (b) a zero-length parameter.
 * Neither may tear the session down: the v5 encoder emits both without
 * complaint, and unknown parameters are not a protocol violation.
 */
static const uint8_t xqc_v5_subscribe_catalog_param[] = {
    0x03,                               /* SUBSCRIBE                       */
    0x01,                               /* Subscribe ID                    */
    0x02,                               /* Track Alias                     */
    0x02, 0x6e, 0x73,                   /* Track Namespace = "ns"          */
    0x05, 0x74, 0x72, 0x61, 0x63, 0x6b, /* Track Name = "track"            */
    0x02,                               /* Filter Type = LatestObject      */
    0x01,                               /* Number of Parameters            */
    0x40, 0xa1,                         /* type = CATALOG (0xA1)           */
    0x02, 0x61, 0x62,                   /* length = 2, value = "ab"        */
};

static const uint8_t xqc_v5_subscribe_empty_param[] = {
    0x03,                               /* SUBSCRIBE                       */
    0x01,                               /* Subscribe ID                    */
    0x02,                               /* Track Alias                     */
    0x02, 0x6e, 0x73,                   /* Track Namespace = "ns"          */
    0x05, 0x74, 0x72, 0x61, 0x63, 0x6b, /* Track Name = "track"            */
    0x02,                               /* Filter Type = LatestObject      */
    0x01,                               /* Number of Parameters            */
    0x40, 0xa3,                         /* type = unknown odd parameter    */
    0x00,                               /* length = 0                      */
};

static int
xqc_test_v5_tolerates_catalog_and_empty_params(void)
{
    struct {
        const char *name;
        const uint8_t *bytes;
        size_t bytes_len;
        uint64_t expect_type;
        uint64_t expect_len;
    } cases[] = {
        {
            "catalog param",
            xqc_v5_subscribe_catalog_param,
            sizeof(xqc_v5_subscribe_catalog_param),
            XQC_MOQ_PARAM_CATALOG, 2,
        },
        {
            "empty param",
            xqc_v5_subscribe_empty_param,
            sizeof(xqc_v5_subscribe_empty_param),
            0xa3, 0,
        },
    };
    xqc_moq_session_t session;

    XQC_TEST_ASSERT(xqc_test_activate_session(
        &session, XQC_ALPN_MOQ_DRAFT_05,
        sizeof(XQC_ALPN_MOQ_DRAFT_05) - 1, XQC_MOQ_VERSION_5) == 0);

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        size_t body_len = cases[i].bytes_len - 1;
        for (size_t split = 0; split < body_len; ++split) {
            xqc_moq_decode_msg_ctx_t ctx;
            xqc_moq_msg_base_t *base;
            xqc_moq_subscribe_msg_t *subscribe;
            uint8_t reencoded[128];
            xqc_int_t first_processed = 0;
            xqc_int_t second_processed;
            xqc_int_t reencoded_len;
            xqc_int_t finish = 0;
            xqc_int_t wait_more_data = 0;

            xqc_memzero(&ctx, sizeof(ctx));
            ctx.cur_msg_type = XQC_MOQ_MSG_SUBSCRIBE;
            base = xqc_moq_msg_create(&session, XQC_MOQ_STREAM_CONTROL,
                                      XQC_MOQ_MSG_SUBSCRIBE);
            XQC_TEST_ASSERT(base != NULL);

            if (split > 0) {
                first_processed = base->decode(
                    (uint8_t *)cases[i].bytes + 1, split, 0, &ctx, base,
                    &finish, &wait_more_data);
                XQC_TEST_ASSERT(first_processed >= 0);
                XQC_TEST_ASSERT(finish == 0);
                XQC_TEST_ASSERT(wait_more_data == 1);
            }

            finish = 0;
            wait_more_data = 0;
            second_processed = base->decode(
                (uint8_t *)cases[i].bytes + 1 + first_processed,
                body_len - (size_t)first_processed, 1, &ctx, base, &finish,
                &wait_more_data);

            subscribe = (xqc_moq_subscribe_msg_t *)base;
            if (second_processed < 0
                || (size_t)(first_processed + second_processed) != body_len
                || finish != 1 || wait_more_data != 0
                || subscribe->params_num != 1 || subscribe->params == NULL
                || subscribe->params[0].type != cases[i].expect_type
                || subscribe->params[0].length != cases[i].expect_len)
            {
                fprintf(stderr,
                        "v5 %s split=%zu: first=%d ret=%d finish=%d "
                        "wait=%d num=%llu type=%llu len=%llu\n",
                        cases[i].name, split, first_processed,
                        second_processed, finish, wait_more_data,
                        (unsigned long long)subscribe->params_num,
                        subscribe->params ?
                            (unsigned long long)subscribe->params[0].type
                            : 0ULL,
                        subscribe->params ?
                            (unsigned long long)subscribe->params[0].length
                            : 0ULL);
                xqc_moq_msg_free(&session, XQC_MOQ_STREAM_CONTROL,
                                 XQC_MOQ_MSG_SUBSCRIBE, base);
                return -1;
            }

            reencoded_len = base->encode(base, reencoded, sizeof(reencoded));
            if (reencoded_len != (xqc_int_t)cases[i].bytes_len
                || memcmp(reencoded, cases[i].bytes, cases[i].bytes_len) != 0)
            {
                fprintf(stderr, "v5 %s re-encode mismatch at split=%zu\n",
                        cases[i].name, split);
                xqc_moq_msg_free(&session, XQC_MOQ_STREAM_CONTROL,
                                 XQC_MOQ_MSG_SUBSCRIBE, base);
                return -1;
            }

            xqc_moq_msg_free(&session, XQC_MOQ_STREAM_CONTROL,
                             XQC_MOQ_MSG_SUBSCRIBE, base);
        }
    }

    return 0;
}

static int
xqc_test_v5_media_extension_rejection_preserves_location(void)
{
    xqc_moq_session_t session;
    xqc_moq_media_track_t media_track;
    xqc_moq_track_t *track = &media_track.track;
    xqc_moq_video_frame_t video;
    xqc_moq_audio_frame_t audio;
    xqc_moq_object_t raw;
    xqc_moq_message_parameter_t ext;
    uint8_t payload = 1;
    uint8_t metadata = 2;

    XQC_TEST_ASSERT(xqc_test_activate_session(
        &session, XQC_ALPN_MOQ_DRAFT_05,
        sizeof(XQC_ALPN_MOQ_DRAFT_05) - 1, XQC_MOQ_VERSION_5) == 0);
    xqc_init_list_head(&session.local_subscribe_list);
    xqc_init_list_head(&session.peer_subscribe_list);
    xqc_init_list_head(&session.track_list_for_pub);
    xqc_init_list_head(&session.track_list_for_sub);

    xqc_memzero(&media_track, sizeof(media_track));
    xqc_init_list_head(&track->write_stream_list);
    track->container_format = XQC_MOQ_CONTAINER_NONE;
    track->track_info.track_name = "track";
    track->track_alias = 3;
    track->subscribe_id = 5;

#define XQC_RESET_MEDIA_LOCATION()                                      \
    do {                                                                \
        track->cur_group_id = 7;                                        \
        track->cur_object_id = 9;                                       \
        track->cur_subgroup_group_id = 6;                               \
        track->cur_subgroup_id = 4;                                     \
    } while (0)

#define XQC_ASSERT_MEDIA_LOCATION_UNCHANGED()                            \
    do {                                                                \
        XQC_TEST_ASSERT(track->cur_group_id == 7);                       \
        XQC_TEST_ASSERT(track->cur_object_id == 9);                      \
        XQC_TEST_ASSERT(track->cur_subgroup_group_id == 6);              \
        XQC_TEST_ASSERT(track->cur_subgroup_id == 4);                    \
    } while (0)

    XQC_RESET_MEDIA_LOCATION();
    xqc_memzero(&video, sizeof(video));
    video.type = XQC_MOQ_VIDEO_KEY;
    video.video_data = &payload;
    video.video_len = 1;
    video.has_bizinfo = 1;
    video.bizinfo = &metadata;
    video.bizinfo_len = 1;
    XQC_TEST_ASSERT(xqc_moq_write_video_frame(
        &session, 5, track, &video) == -XQC_EALPN_NOT_SUPPORTED);
    XQC_ASSERT_MEDIA_LOCATION_UNCHANGED();

    XQC_RESET_MEDIA_LOCATION();
    xqc_memzero(&audio, sizeof(audio));
    audio.audio_data = &payload;
    audio.audio_len = 1;
    audio.has_audio_level = 1;
    audio.audio_level = 7;
    XQC_TEST_ASSERT(xqc_moq_write_audio_frame(
        &session, 5, track, &audio) == -XQC_EALPN_NOT_SUPPORTED);
    XQC_ASSERT_MEDIA_LOCATION_UNCHANGED();

    XQC_RESET_MEDIA_LOCATION();
    xqc_memzero(&ext, sizeof(ext));
    ext.type = XQC_MOQ_PARAM_CATALOG;
    ext.length = 1;
    ext.value = &metadata;
    xqc_memzero(&raw, sizeof(raw));
    raw.payload = &payload;
    raw.payload_len = 1;
    raw.ext_params = &ext;
    raw.ext_params_num = 1;
    XQC_TEST_ASSERT(xqc_moq_write_raw_object(
        &session, track, &raw) == -XQC_EALPN_NOT_SUPPORTED);
    XQC_ASSERT_MEDIA_LOCATION_UNCHANGED();

#undef XQC_ASSERT_MEDIA_LOCATION_UNCHANGED
#undef XQC_RESET_MEDIA_LOCATION

    return 0;
}

static int
xqc_test_profile_continuation_routing(void)
{
    const xqc_moq_version_profile_t *v5 = xqc_moq_v5_profile();
    const xqc_moq_version_profile_t *v14 = xqc_moq_v14_profile();
    const xqc_moq_message_codec_entry_t *codec;
    const xqc_moq_message_codec_entry_t *next_codec = NULL;

    codec = xqc_moq_profile_find_codec(
        v14, XQC_MOQ_STREAM_V14_SUBGROUP, 0x10);
    XQC_TEST_ASSERT(codec != NULL);
    XQC_TEST_ASSERT(codec->wire_type == XQC_MOQ_SUBGROUP_TYPE_WITH_ID);
    XQC_TEST_ASSERT(codec->semantic == XQC_MOQ_SEMANTIC_SUBGROUP);

    XQC_TEST_ASSERT(xqc_moq_profile_next_data_codec(
        v14, XQC_MOQ_STREAM_V14_SUBGROUP, 0x10, &next_codec));
    XQC_TEST_ASSERT(next_codec != NULL);
    XQC_TEST_ASSERT(next_codec->semantic
                    == XQC_MOQ_SEMANTIC_SUBGROUP_OBJECT);
    XQC_TEST_ASSERT(next_codec->initialize
                    == xqc_moq_msg_subgroup_object_init_handler);

    next_codec = NULL;
    XQC_TEST_ASSERT(xqc_moq_profile_next_data_codec(
        v5, XQC_MOQ_STREAM_V5_TRACK, XQC_MOQ_MSG_STREAM_HEADER_TRACK,
        &next_codec));
    XQC_TEST_ASSERT(next_codec != NULL);
    XQC_TEST_ASSERT(next_codec->semantic
                    == XQC_MOQ_SEMANTIC_TRACK_STREAM_OBJECT);
    return 0;
}

static int
xqc_test_wrong_setup_preserves_version_error(void)
{
    xqc_moq_session_t session;
    void *msg = NULL;

    xqc_memzero(&session, sizeof(session));
    XQC_TEST_ASSERT(xqc_moq_session_bind_policy(
        &session, xqc_moq_version_policy_for_alpn(
            XQC_ALPN_MOQ_DRAFT_14,
            sizeof(XQC_ALPN_MOQ_DRAFT_14) - 1)) == XQC_OK);

    XQC_TEST_ASSERT(xqc_moq_session_validate_setup_type(
        &session, XQC_MOQ_MSG_CLIENT_SETUP) == -XQC_EVERSION);
    XQC_TEST_ASSERT(session.profile_state
                    == XQC_MOQ_PROFILE_ALPN_SELECTED);
    XQC_TEST_ASSERT(xqc_moq_msg_create_ex(
        &session, XQC_MOQ_STREAM_CONTROL, XQC_MOQ_MSG_CLIENT_SETUP,
        &msg) == -XQC_EVERSION);
    XQC_TEST_ASSERT(msg == NULL);
    XQC_TEST_ASSERT(session.profile_state
                    == XQC_MOQ_PROFILE_ALPN_SELECTED);
    return 0;
}

static int
xqc_test_v5_subscribe_done_cleans_local_state(void)
{
    static unsigned char ns_data[] = "ns";
    xqc_moq_track_ns_field_t ns = {.len = 2, .data = ns_data};
    xqc_moq_session_t session;
    xqc_log_callbacks_t log_callbacks;
    xqc_log_t log;
    xqc_moq_track_t *track;
    xqc_moq_subscribe_t *subscribe;
    xqc_moq_msg_base_t *base;
    xqc_moq_v5_subscribe_done_msg_t *done;

    XQC_TEST_ASSERT(xqc_test_activate_session(
        &session, XQC_ALPN_MOQ_DRAFT_05,
        sizeof(XQC_ALPN_MOQ_DRAFT_05) - 1, XQC_MOQ_VERSION_5) == 0);
    xqc_memzero(&log_callbacks, sizeof(log_callbacks));
    xqc_memzero(&log, sizeof(log));
    log.log_level = XQC_LOG_DEBUG;
    log.log_callbacks = &log_callbacks;
    session.log = &log;
    xqc_init_list_head(&session.local_subscribe_list);
    xqc_init_list_head(&session.peer_subscribe_list);
    xqc_init_list_head(&session.track_list_for_pub);
    xqc_init_list_head(&session.track_list_for_sub);

    track = xqc_moq_track_create_with_ns_tuple(
        &session, &ns, 1, "track", XQC_MOQ_TRACK_VIDEO, NULL,
        XQC_MOQ_CONTAINER_LOC, XQC_MOQ_TRACK_FOR_SUB);
    XQC_TEST_ASSERT(track != NULL);
    xqc_moq_track_set_subscribe_id(track, 9);
    xqc_moq_track_set_alias(track, 7);

    subscribe = xqc_moq_subscribe_create_with_ns_tuple(
        &session, 9, 7, &ns, 1, "track", XQC_MOQ_FILTER_LAST_GROUP,
        0, 0, 0, 0, NULL, 1);
    XQC_TEST_ASSERT(subscribe != NULL);
    XQC_TEST_ASSERT(xqc_moq_find_subscribe(&session, 9, 1) == subscribe);

    base = xqc_moq_msg_create(
        &session, XQC_MOQ_STREAM_CONTROL, XQC_MOQ_V5_MSG_SUBSCRIBE_DONE);
    XQC_TEST_ASSERT(base != NULL);
    done = (xqc_moq_v5_subscribe_done_msg_t *)base;
    done->subscribe_id = 9;
    base->on_msg(&session, NULL, base);

    XQC_TEST_ASSERT(xqc_moq_find_subscribe(&session, 9, 1) == NULL);
    XQC_TEST_ASSERT(track->subscribe_id == XQC_MOQ_INVALID_ID);
    XQC_TEST_ASSERT(track->track_alias == XQC_MOQ_INVALID_ID);
    xqc_moq_msg_free(&session, XQC_MOQ_STREAM_CONTROL,
                     XQC_MOQ_V5_MSG_SUBSCRIBE_DONE, base);
    return 0;
}

static int
xqc_test_v14_object_defaults_and_eog_status(void)
{
    xqc_moq_subgroup_msg_t *subgroup;
    xqc_moq_object_datagram_msg_t encoded;
    xqc_moq_object_datagram_msg_t decoded;
    uint8_t payload = 0x42;
    uint8_t buf[64];
    xqc_int_t len;

    subgroup = xqc_moq_msg_create_subgroup();
    XQC_TEST_ASSERT(subgroup != NULL);
    XQC_TEST_ASSERT(subgroup->subgroup_type
                    == XQC_MOQ_SUBGROUP_TYPE_WITH_ID);
    xqc_moq_msg_free_subgroup(subgroup);

    xqc_memzero(&encoded, sizeof(encoded));
    xqc_memzero(&decoded, sizeof(decoded));
    encoded.type = XQC_MOQ_OBJ_DGRAM_TYPE_END_OF_GROUP;
    encoded.track_alias = 1;
    encoded.group_id = 2;
    encoded.object_id = 3;
    encoded.publisher_priority = 4;
    encoded.payload = &payload;
    encoded.payload_len = 1;

    len = xqc_moq_object_datagram_encode(&encoded, buf, sizeof(buf));
    XQC_TEST_ASSERT(len > 0);
    XQC_TEST_ASSERT(xqc_moq_object_datagram_decode(
        buf, (size_t)len, &decoded) == len);
    XQC_TEST_ASSERT(decoded.status == XQC_MOQ_OBJ_STATUS_GROUP_END);
    xqc_moq_object_datagram_free_fields(&decoded);
    return 0;
}

int
main(void)
{
    if (xqc_test_profile_lookup() != 0
        || xqc_test_session_profile_state() != 0
        || xqc_test_message_collision_is_profile_local() != 0
        || xqc_test_internal_message_ids_are_not_wire_types() != 0
        || xqc_test_v5_track_codec_requires_capability() != 0
        || xqc_test_missing_profile_codec_returns_specific_error() != 0
        || xqc_test_unsupported_write_is_side_effect_free() != 0
        || xqc_test_datagram_requires_active_profile() != 0
        || xqc_test_v5_control_writer_uses_profile_codec() != 0
        || xqc_test_v5_outbound_object_stream_is_classified_by_profile() != 0
        || xqc_test_v14_outbound_subgroup_stream_is_classified_by_profile() != 0
        || xqc_test_v14_stream_preparation_is_profile_local() != 0
        || xqc_test_v5_stream_preparation_requires_track_header() != 0
        || xqc_test_subscribe_semantic_adapter() != 0
        || xqc_test_high_level_media_apis_require_active_profile() != 0
        || xqc_test_v5_golden_encode() != 0
        || xqc_test_v5_golden_decode_split_points() != 0
        || xqc_test_oversized_setup_params_cleanup_is_safe() != 0
        || xqc_test_v14_empty_track_name_split_is_safe() != 0
        || xqc_test_v5_empty_track_name_split_is_safe() != 0
        || xqc_test_catalog_default_follows_profile() != 0
        || xqc_test_subscribe_failure_rolls_back_track() != 0
        || xqc_test_publish_rejection_leaves_track_untouched() != 0
        || xqc_test_v14_parameter_vectors() != 0
        || xqc_test_v5_tolerates_catalog_and_empty_params() != 0
        || xqc_test_v5_media_extension_rejection_preserves_location() != 0
        || xqc_test_profile_continuation_routing() != 0
        || xqc_test_wrong_setup_preserves_version_error() != 0
        || xqc_test_v5_subscribe_done_cleans_local_state() != 0
        || xqc_test_v14_object_defaults_and_eog_status() != 0)
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
