#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "moq/xqc_moq.h"
#include "moq/moq_transport/xqc_moq_message.h"
#include "moq/moq_transport/version/xqc_moq_version.h"
#include "moq/moq_transport/xqc_moq_session.h"

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
} xqc_test_v5_vector_t;

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
    {"object_stream", XQC_MOQ_STREAM_V5_OBJECT, XQC_MOQ_MSG_OBJECT_STREAM, 1,
     xqc_v5_object_stream, sizeof(xqc_v5_object_stream),
     xqc_test_configure_object_stream},
    {"track_header", XQC_MOQ_STREAM_V5_TRACK,
     XQC_MOQ_MSG_STREAM_HEADER_TRACK, 2, xqc_v5_track_header,
     sizeof(xqc_v5_track_header), xqc_test_configure_track_header},
    {"track_object", XQC_MOQ_STREAM_V5_TRACK,
     XQC_MOQ_MSG_TRACK_STREAM_OBJECT, 0, xqc_v5_track_object,
     sizeof(xqc_v5_track_object), xqc_test_configure_track_object},
};

static int
xqc_test_profile_lookup(void)
{
    const xqc_moq_alpn_policy_t *policy;

    XQC_TEST_ASSERT(strcmp(XQC_ALPN_MOQ_QUIC, "moq-quic") == 0);
    XQC_TEST_ASSERT(strcmp(XQC_ALPN_MOQ_DRAFT_05, "moq-05") == 0);
    XQC_TEST_ASSERT(strcmp(XQC_ALPN_MOQ_DRAFT_14, "moq-14") == 0);

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

    XQC_TEST_ASSERT(xqc_moq_version_policy_for_alpn("moq-00", 6) == NULL);
    XQC_TEST_ASSERT(xqc_moq_version_policy_for_alpn("unknown", 7) == NULL);
    XQC_TEST_ASSERT(xqc_moq_version_policy_count() == 3);
    XQC_TEST_ASSERT(xqc_moq_version_policy_at(0) != NULL);
    XQC_TEST_ASSERT(xqc_moq_version_policy_at(2) != NULL);
    XQC_TEST_ASSERT(xqc_moq_version_policy_at(3) == NULL);

    XQC_TEST_ASSERT(xqc_moq_version_profile_for_version(XQC_MOQ_VERSION_5)
                    == xqc_moq_v5_profile());
    XQC_TEST_ASSERT(xqc_moq_version_profile_for_version(XQC_MOQ_VERSION_14)
                    == xqc_moq_v14_profile());
    XQC_TEST_ASSERT(!xqc_moq_profile_has_capability(
        xqc_moq_v5_profile(), XQC_MOQ_CAP_SUBGROUP_STREAM));
    XQC_TEST_ASSERT(xqc_moq_profile_has_capability(
        xqc_moq_v14_profile(), XQC_MOQ_CAP_SUBGROUP_STREAM));
    return 0;
}

static int
xqc_test_session_profile_state(void)
{
    xqc_moq_session_t session;
    uint64_t v5_versions[] = {XQC_MOQ_VERSION_5};
    uint64_t v14_versions[] = {XQC_MOQ_VERSION_14};
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
    XQC_TEST_ASSERT(session.profile_state == XQC_MOQ_PROFILE_FAILED);
    XQC_TEST_ASSERT(xqc_moq_session_negotiate_version(
        &session, v14_versions, 1) == -XQC_EVERSION);
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
        xqc_moq_msg_base_t *base = xqc_moq_msg_create(
            &session, vector->stream_kind, vector->wire_type);
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

    xqc_memzero(&ctx, sizeof(ctx));
    ctx.cur_msg_type = (xqc_moq_msg_type_t)vector->wire_type;
    base = xqc_moq_msg_create(session, vector->stream_kind,
                              vector->wire_type);
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

    XQC_TEST_ASSERT(base->encode_len(base) == (xqc_int_t)vector->bytes_len);
    XQC_TEST_ASSERT(base->encode(base, encoded, sizeof(encoded))
                    == (xqc_int_t)vector->bytes_len);
    if (memcmp(encoded, vector->bytes, vector->bytes_len) != 0) {
        fprintf(stderr, "v5 decode mismatch: %s split=%zu\n",
                vector->name, first_body_len);
        return -1;
    }

    xqc_moq_msg_free(session, vector->stream_kind, vector->wire_type, base);
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

int
main(void)
{
    if (xqc_test_profile_lookup() != 0
        || xqc_test_session_profile_state() != 0
        || xqc_test_message_collision_is_profile_local() != 0
        || xqc_test_v5_golden_encode() != 0
        || xqc_test_v5_golden_decode_split_points() != 0)
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
