#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "moq/moq_transport/draft18/xqc_moq_d18_defs.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_registry.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_request.h"
#include "moq/moq_transport/xqc_moq_session.h"

#define XQC_TEST_ASSERT(expr) \
    do { \
        if (!(expr)) { \
            fprintf(stderr, "assert failed: %s:%d: %s\n", \
                    __FILE__, __LINE__, #expr); \
            return -1; \
        } \
    } while (0)

static int
xqc_test_d18_error_codes(void)
{
    XQC_TEST_ASSERT(XQC_MOQ_D18_PROTOCOL_VIOLATION == 0x3);
    XQC_TEST_ASSERT(XQC_MOQ_D18_INVALID_REQUEST_ID == 0x4);
    XQC_TEST_ASSERT(XQC_MOQ_D18_DUPLICATE_TRACK_ALIAS == 0x5);
    XQC_TEST_ASSERT(XQC_MOQ_D18_KEY_VALUE_FORMATTING_ERROR == 0x6);
    XQC_TEST_ASSERT(XQC_MOQ_D18_MALFORMED_AUTHORITY == 0x1a);
    return 0;
}

static int
xqc_test_d18_type_50_uses_stream_context(void)
{
    xqc_moq_d18_message_desc_t desc;

    XQC_TEST_ASSERT(xqc_moq_d18_registry_lookup(
        XQC_MOQ_D18_VERSION, XQC_MOQ_D18_DIRECTION_BIDI,
        XQC_MOQ_D18_STREAM_UNCLASSIFIED, XQC_MOQ_D18_POSITION_FIRST,
        0x50, &desc) == XQC_MOQ_D18_REGISTRY_OK);
    XQC_TEST_ASSERT(desc.kind
                    == XQC_MOQ_D18_MESSAGE_SUBSCRIBE_NAMESPACE);
    XQC_TEST_ASSERT(desc.stream_class == XQC_MOQ_D18_STREAM_REQUEST);

    XQC_TEST_ASSERT(xqc_moq_d18_registry_lookup(
        XQC_MOQ_D18_VERSION, XQC_MOQ_D18_DIRECTION_UNI,
        XQC_MOQ_D18_STREAM_UNCLASSIFIED, XQC_MOQ_D18_POSITION_FIRST,
        0x50, &desc) == XQC_MOQ_D18_REGISTRY_OK);
    XQC_TEST_ASSERT(desc.kind == XQC_MOQ_D18_MESSAGE_SUBGROUP_HEADER);
    XQC_TEST_ASSERT(desc.stream_class == XQC_MOQ_D18_STREAM_SUBGROUP);
    return 0;
}

typedef struct {
    xqc_moq_d18_stream_direction_t direction;
    xqc_moq_d18_stream_class_t stream_class;
    xqc_moq_d18_message_position_t position;
    uint64_t wire_type;
    xqc_moq_d18_message_kind_t expected_kind;
    xqc_moq_d18_stream_class_t expected_class;
} xqc_test_d18_valid_placement_t;

static int
xqc_test_d18_valid_placements(void)
{
    static const xqc_test_d18_valid_placement_t cases[] = {
        {
            XQC_MOQ_D18_DIRECTION_UNI,
            XQC_MOQ_D18_STREAM_UNCLASSIFIED,
            XQC_MOQ_D18_POSITION_FIRST,
            XQC_MOQ_D18_STREAM_TYPE_SETUP,
            XQC_MOQ_D18_MESSAGE_SETUP,
            XQC_MOQ_D18_STREAM_CONTROL,
        },
        {
            XQC_MOQ_D18_DIRECTION_BIDI,
            XQC_MOQ_D18_STREAM_UNCLASSIFIED,
            XQC_MOQ_D18_POSITION_FIRST,
            XQC_MOQ_D18_MSG_SUBSCRIBE,
            XQC_MOQ_D18_MESSAGE_SUBSCRIBE,
            XQC_MOQ_D18_STREAM_REQUEST,
        },
        {
            XQC_MOQ_D18_DIRECTION_BIDI,
            XQC_MOQ_D18_STREAM_REQUEST,
            XQC_MOQ_D18_POSITION_NEXT,
            XQC_MOQ_D18_MSG_REQUEST_ERROR,
            XQC_MOQ_D18_MESSAGE_REQUEST_ERROR,
            XQC_MOQ_D18_STREAM_REQUEST,
        },
        {
            XQC_MOQ_D18_DIRECTION_UNI,
            XQC_MOQ_D18_STREAM_CONTROL,
            XQC_MOQ_D18_POSITION_NEXT,
            XQC_MOQ_D18_MSG_GOAWAY,
            XQC_MOQ_D18_MESSAGE_GOAWAY,
            XQC_MOQ_D18_STREAM_CONTROL,
        },
        {
            XQC_MOQ_D18_DIRECTION_UNI,
            XQC_MOQ_D18_STREAM_UNCLASSIFIED,
            XQC_MOQ_D18_POSITION_FIRST,
            XQC_MOQ_D18_STREAM_TYPE_FETCH,
            XQC_MOQ_D18_MESSAGE_FETCH_HEADER,
            XQC_MOQ_D18_STREAM_FETCH,
        },
        {
            XQC_MOQ_D18_DIRECTION_UNI,
            XQC_MOQ_D18_STREAM_UNCLASSIFIED,
            XQC_MOQ_D18_POSITION_FIRST,
            XQC_MOQ_D18_STREAM_TYPE_PADDING,
            XQC_MOQ_D18_MESSAGE_PADDING,
            XQC_MOQ_D18_STREAM_PADDING,
        },
        {
            XQC_MOQ_D18_DIRECTION_UNI,
            XQC_MOQ_D18_STREAM_UNCLASSIFIED,
            XQC_MOQ_D18_POSITION_FIRST,
            0x10,
            XQC_MOQ_D18_MESSAGE_SUBGROUP_HEADER,
            XQC_MOQ_D18_STREAM_SUBGROUP,
        },
        {
            XQC_MOQ_D18_DIRECTION_BIDI,
            XQC_MOQ_D18_STREAM_UNCLASSIFIED,
            XQC_MOQ_D18_POSITION_FIRST,
            0x51,
            XQC_MOQ_D18_MESSAGE_SUBSCRIBE_TRACKS,
            XQC_MOQ_D18_STREAM_REQUEST,
        },
        {
            XQC_MOQ_D18_DIRECTION_UNI,
            XQC_MOQ_D18_STREAM_UNCLASSIFIED,
            XQC_MOQ_D18_POSITION_FIRST,
            0x51,
            XQC_MOQ_D18_MESSAGE_SUBGROUP_HEADER,
            XQC_MOQ_D18_STREAM_SUBGROUP,
        },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        xqc_moq_d18_message_desc_t desc;
        int ret = xqc_moq_d18_registry_lookup(
            XQC_MOQ_D18_VERSION, cases[i].direction, cases[i].stream_class,
            cases[i].position, cases[i].wire_type, &desc);
        XQC_TEST_ASSERT(ret == XQC_MOQ_D18_REGISTRY_OK);
        XQC_TEST_ASSERT(desc.wire_type == cases[i].wire_type);
        XQC_TEST_ASSERT(desc.kind == cases[i].expected_kind);
        XQC_TEST_ASSERT(desc.stream_class == cases[i].expected_class);
    }

    return 0;
}

static int
xqc_test_d18_invalid_placements(void)
{
    xqc_moq_d18_message_desc_t desc;

    XQC_TEST_ASSERT(xqc_moq_d18_registry_lookup(
        XQC_MOQ_D18_VERSION, XQC_MOQ_D18_DIRECTION_BIDI,
        XQC_MOQ_D18_STREAM_UNCLASSIFIED, XQC_MOQ_D18_POSITION_FIRST,
        XQC_MOQ_D18_MSG_SETUP, &desc)
        == XQC_MOQ_D18_REGISTRY_INVALID_PLACEMENT);
    XQC_TEST_ASSERT(xqc_moq_d18_registry_lookup(
        XQC_MOQ_D18_VERSION, XQC_MOQ_D18_DIRECTION_UNI,
        XQC_MOQ_D18_STREAM_UNCLASSIFIED, XQC_MOQ_D18_POSITION_FIRST,
        XQC_MOQ_D18_MSG_SUBSCRIBE, &desc)
        == XQC_MOQ_D18_REGISTRY_INVALID_PLACEMENT);
    XQC_TEST_ASSERT(xqc_moq_d18_registry_lookup(
        XQC_MOQ_D18_VERSION, XQC_MOQ_D18_DIRECTION_BIDI,
        XQC_MOQ_D18_STREAM_UNCLASSIFIED, XQC_MOQ_D18_POSITION_FIRST,
        XQC_MOQ_D18_MSG_REQUEST_ERROR, &desc)
        == XQC_MOQ_D18_REGISTRY_INVALID_PLACEMENT);
    XQC_TEST_ASSERT(xqc_moq_d18_registry_lookup(
        XQC_MOQ_D18_VERSION, XQC_MOQ_D18_DIRECTION_UNI,
        XQC_MOQ_D18_STREAM_CONTROL, XQC_MOQ_D18_POSITION_NEXT,
        XQC_MOQ_D18_MSG_SETUP, &desc)
        == XQC_MOQ_D18_REGISTRY_INVALID_PLACEMENT);
    XQC_TEST_ASSERT(xqc_moq_d18_registry_lookup(
        XQC_MOQ_D18_VERSION, XQC_MOQ_D18_DIRECTION_BIDI,
        XQC_MOQ_D18_STREAM_UNCLASSIFIED, XQC_MOQ_D18_POSITION_FIRST,
        0x22ff, &desc) == XQC_MOQ_D18_REGISTRY_UNKNOWN_TYPE);
    XQC_TEST_ASSERT(xqc_moq_d18_registry_lookup(
        0xff00000e, XQC_MOQ_D18_DIRECTION_BIDI,
        XQC_MOQ_D18_STREAM_UNCLASSIFIED, XQC_MOQ_D18_POSITION_FIRST,
        XQC_MOQ_D18_MSG_SUBSCRIBE, &desc)
        == XQC_MOQ_D18_REGISTRY_UNSUPPORTED_VERSION);
    XQC_TEST_ASSERT(xqc_moq_d18_registry_lookup(
        XQC_MOQ_D18_VERSION, XQC_MOQ_D18_DIRECTION_UNKNOWN,
        XQC_MOQ_D18_STREAM_UNCLASSIFIED, XQC_MOQ_D18_POSITION_FIRST,
        XQC_MOQ_D18_MSG_SUBSCRIBE, &desc)
        == XQC_MOQ_D18_REGISTRY_INVALID_ARGUMENT);
    XQC_TEST_ASSERT(xqc_moq_d18_registry_lookup(
        XQC_MOQ_D18_VERSION, XQC_MOQ_D18_DIRECTION_BIDI,
        XQC_MOQ_D18_STREAM_UNCLASSIFIED, XQC_MOQ_D18_POSITION_FIRST,
        XQC_MOQ_D18_MSG_SUBSCRIBE, NULL)
        == XQC_MOQ_D18_REGISTRY_INVALID_ARGUMENT);
    return 0;
}

static int
xqc_test_d18_control_kinds_require_version_and_context(void)
{
    static const uint64_t wire_types[] = {
        XQC_MOQ_D18_MSG_REQUEST_UPDATE,
        XQC_MOQ_D18_MSG_PUBLISH_BLOCKED,
        XQC_MOQ_D18_MSG_PUBLISH_DONE,
        XQC_MOQ_D18_MSG_GOAWAY,
    };
    xqc_moq_d18_message_desc_t desc;

    for (size_t i = 0; i < sizeof(wire_types) / sizeof(wire_types[0]); i++) {
        XQC_TEST_ASSERT(xqc_moq_d18_registry_lookup(
            0xff00000e, XQC_MOQ_D18_DIRECTION_BIDI,
            XQC_MOQ_D18_STREAM_REQUEST, XQC_MOQ_D18_POSITION_NEXT,
            wire_types[i], &desc)
            == XQC_MOQ_D18_REGISTRY_UNSUPPORTED_VERSION);
    }

    XQC_TEST_ASSERT(xqc_moq_d18_registry_lookup(
        XQC_MOQ_D18_VERSION, XQC_MOQ_D18_DIRECTION_UNI,
        XQC_MOQ_D18_STREAM_CONTROL, XQC_MOQ_D18_POSITION_NEXT,
        XQC_MOQ_D18_MSG_REQUEST_UPDATE, &desc)
        == XQC_MOQ_D18_REGISTRY_INVALID_PLACEMENT);
    XQC_TEST_ASSERT(xqc_moq_d18_registry_lookup(
        XQC_MOQ_D18_VERSION, XQC_MOQ_D18_DIRECTION_UNI,
        XQC_MOQ_D18_STREAM_CONTROL, XQC_MOQ_D18_POSITION_NEXT,
        XQC_MOQ_D18_MSG_PUBLISH_BLOCKED, &desc)
        == XQC_MOQ_D18_REGISTRY_INVALID_PLACEMENT);
    XQC_TEST_ASSERT(xqc_moq_d18_registry_lookup(
        XQC_MOQ_D18_VERSION, XQC_MOQ_D18_DIRECTION_UNI,
        XQC_MOQ_D18_STREAM_CONTROL, XQC_MOQ_D18_POSITION_NEXT,
        XQC_MOQ_D18_MSG_PUBLISH_DONE, &desc)
        == XQC_MOQ_D18_REGISTRY_INVALID_PLACEMENT);
    XQC_TEST_ASSERT(xqc_moq_d18_registry_lookup(
        XQC_MOQ_D18_VERSION, XQC_MOQ_D18_DIRECTION_BIDI,
        XQC_MOQ_D18_STREAM_UNCLASSIFIED, XQC_MOQ_D18_POSITION_FIRST,
        XQC_MOQ_D18_MSG_GOAWAY, &desc)
        == XQC_MOQ_D18_REGISTRY_INVALID_PLACEMENT);
    return 0;
}

static int
xqc_test_d18_client_request_ids(void)
{
    xqc_moq_d18_request_registry_t registry;

    xqc_moq_d18_request_registry_init(&registry, 0);
    XQC_TEST_ASSERT(xqc_moq_d18_request_id_allocate(&registry) == 0);
    XQC_TEST_ASSERT(xqc_moq_d18_request_id_allocate(&registry) == 2);
    XQC_TEST_ASSERT(xqc_moq_d18_request_id_register_peer(&registry, 1)
                    == XQC_MOQ_D18_REQUEST_ID_OK);
    XQC_TEST_ASSERT(xqc_moq_d18_request_id_register_peer(&registry, 5)
                    == XQC_MOQ_D18_REQUEST_ID_OK);
    XQC_TEST_ASSERT(xqc_moq_d18_request_id_register_peer(&registry, 3)
                    == XQC_MOQ_D18_REQUEST_ID_OK);
    XQC_TEST_ASSERT(xqc_moq_d18_request_id_register_peer(&registry, 5)
                    == XQC_MOQ_D18_REQUEST_ID_DUPLICATE);
    XQC_TEST_ASSERT(xqc_moq_d18_request_id_register_peer(&registry, 2)
                    == XQC_MOQ_D18_REQUEST_ID_INVALID_PARITY);
    xqc_moq_d18_request_registry_destroy(&registry);
    XQC_TEST_ASSERT(xqc_list_empty(&registry.peer_ids));
    return 0;
}

static int
xqc_test_d18_server_request_ids(void)
{
    xqc_moq_d18_request_registry_t registry;

    xqc_moq_d18_request_registry_init(&registry, 1);
    XQC_TEST_ASSERT(xqc_moq_d18_request_id_allocate(&registry) == 1);
    XQC_TEST_ASSERT(xqc_moq_d18_request_id_allocate(&registry) == 3);
    XQC_TEST_ASSERT(xqc_moq_d18_request_id_register_peer(&registry, 0)
                    == XQC_MOQ_D18_REQUEST_ID_OK);
    XQC_TEST_ASSERT(xqc_moq_d18_request_id_register_peer(&registry, 4)
                    == XQC_MOQ_D18_REQUEST_ID_OK);
    XQC_TEST_ASSERT(xqc_moq_d18_request_id_register_peer(&registry, 2)
                    == XQC_MOQ_D18_REQUEST_ID_OK);
    XQC_TEST_ASSERT(xqc_moq_d18_request_id_register_peer(&registry, 4)
                    == XQC_MOQ_D18_REQUEST_ID_DUPLICATE);
    XQC_TEST_ASSERT(xqc_moq_d18_request_id_register_peer(&registry, 3)
                    == XQC_MOQ_D18_REQUEST_ID_INVALID_PARITY);
    xqc_moq_d18_request_registry_destroy(&registry);
    XQC_TEST_ASSERT(xqc_list_empty(&registry.peer_ids));
    return 0;
}

static int
xqc_test_d18_local_request_ids_are_reserved_once(void)
{
    xqc_moq_d18_request_registry_t registry;

    xqc_moq_d18_request_registry_init(&registry, 0);
    XQC_TEST_ASSERT(xqc_moq_d18_request_id_allocate(
        &registry) == 0);
    XQC_TEST_ASSERT(xqc_moq_d18_request_id_register_local(
        &registry, 0) == XQC_MOQ_D18_REQUEST_ID_OK);
    XQC_TEST_ASSERT(xqc_moq_d18_request_id_register_local(
        &registry, 0) == XQC_MOQ_D18_REQUEST_ID_DUPLICATE);
    XQC_TEST_ASSERT(xqc_moq_d18_request_id_register_local(
        &registry, 1) == XQC_MOQ_D18_REQUEST_ID_INVALID_PARITY);

    XQC_TEST_ASSERT(xqc_moq_d18_request_id_allocate(
        &registry) == 2);
    XQC_TEST_ASSERT(xqc_moq_d18_request_id_register_local(
        &registry, 2) == XQC_MOQ_D18_REQUEST_ID_OK);
    XQC_TEST_ASSERT(xqc_moq_d18_request_id_register_local(
        &registry, 4) == XQC_MOQ_D18_REQUEST_ID_OK);
    XQC_TEST_ASSERT(xqc_moq_d18_request_id_allocate(
        &registry) == 6);

    xqc_moq_d18_request_registry_destroy(&registry);
    return 0;
}

static int
xqc_test_d18_stream_context_commits_after_message(void)
{
    xqc_moq_d18_stream_context_t context = {
        .direction = XQC_MOQ_D18_DIRECTION_UNI,
        .stream_class = XQC_MOQ_D18_STREAM_UNCLASSIFIED,
        .position = XQC_MOQ_D18_POSITION_FIRST,
    };
    xqc_moq_d18_message_desc_t desc;

    XQC_TEST_ASSERT(xqc_moq_d18_stream_resolve(
        &context, XQC_MOQ_D18_STREAM_TYPE_SETUP, &desc)
        == XQC_MOQ_D18_REGISTRY_OK);
    XQC_TEST_ASSERT(context.stream_class == XQC_MOQ_D18_STREAM_CONTROL);
    XQC_TEST_ASSERT(context.position == XQC_MOQ_D18_POSITION_FIRST);
    xqc_moq_d18_stream_commit_message(&context);
    XQC_TEST_ASSERT(context.position == XQC_MOQ_D18_POSITION_NEXT);
    XQC_TEST_ASSERT(xqc_moq_d18_stream_resolve(
        &context, XQC_MOQ_D18_STREAM_TYPE_SETUP, &desc)
        == XQC_MOQ_D18_REGISTRY_INVALID_PLACEMENT);
    return 0;
}

static int
xqc_test_d18_failed_resolve_preserves_stream_context(void)
{
    xqc_moq_d18_stream_context_t context = {
        .direction = XQC_MOQ_D18_DIRECTION_BIDI,
        .stream_class = XQC_MOQ_D18_STREAM_UNCLASSIFIED,
        .position = XQC_MOQ_D18_POSITION_FIRST,
    };
    xqc_moq_d18_message_desc_t desc;

    XQC_TEST_ASSERT(xqc_moq_d18_stream_resolve(
        &context, XQC_MOQ_D18_MSG_REQUEST_ERROR, &desc)
        == XQC_MOQ_D18_REGISTRY_INVALID_PLACEMENT);
    XQC_TEST_ASSERT(context.stream_class
                    == XQC_MOQ_D18_STREAM_UNCLASSIFIED);
    XQC_TEST_ASSERT(context.position == XQC_MOQ_D18_POSITION_FIRST);
    XQC_TEST_ASSERT(xqc_moq_d18_stream_resolve(
        &context, XQC_MOQ_D18_MSG_SUBSCRIBE, &desc)
        == XQC_MOQ_D18_REGISTRY_OK);
    XQC_TEST_ASSERT(context.stream_class == XQC_MOQ_D18_STREAM_REQUEST);
    xqc_moq_d18_stream_commit_message(&context);
    XQC_TEST_ASSERT(context.position == XQC_MOQ_D18_POSITION_NEXT);
    return 0;
}

static int
xqc_test_d18_request_id_error_mapping(void)
{
    XQC_TEST_ASSERT(xqc_moq_d18_request_id_error_code(
        XQC_MOQ_D18_REQUEST_ID_OK) == XQC_MOQ_D18_NO_ERROR);
    XQC_TEST_ASSERT(xqc_moq_d18_request_id_error_code(
        XQC_MOQ_D18_REQUEST_ID_INVALID_PARITY)
        == XQC_MOQ_D18_INVALID_REQUEST_ID);
    XQC_TEST_ASSERT(xqc_moq_d18_request_id_error_code(
        XQC_MOQ_D18_REQUEST_ID_DUPLICATE)
        == XQC_MOQ_D18_INVALID_REQUEST_ID);
    XQC_TEST_ASSERT(xqc_moq_d18_request_id_error_code(
        XQC_MOQ_D18_REQUEST_ID_NO_MEMORY)
        == XQC_MOQ_D18_INTERNAL_ERROR);
    return 0;
}

static int
xqc_test_d18_session_registers_peer_ids_out_of_order(void)
{
    xqc_moq_session_t session = {0};

    xqc_moq_d18_request_registry_init(&session.d18_request_registry, 0);
    XQC_TEST_ASSERT(xqc_moq_session_register_peer_request_id(&session, 5)
                    == XQC_MOQ_D18_REQUEST_ID_OK);
    XQC_TEST_ASSERT(session.peer_request_id_seen == 1);
    XQC_TEST_ASSERT(session.max_peer_request_id == 5);
    XQC_TEST_ASSERT(xqc_moq_session_register_peer_request_id(&session, 1)
                    == XQC_MOQ_D18_REQUEST_ID_OK);
    XQC_TEST_ASSERT(session.max_peer_request_id == 5);
    XQC_TEST_ASSERT(xqc_moq_session_register_peer_request_id(&session, 5)
                    == XQC_MOQ_D18_REQUEST_ID_DUPLICATE);
    XQC_TEST_ASSERT(xqc_moq_session_register_peer_request_id(&session, 2)
                    == XQC_MOQ_D18_REQUEST_ID_INVALID_PARITY);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    return 0;
}

int
main(void)
{
    if (xqc_test_d18_error_codes() != 0) {
        return EXIT_FAILURE;
    }

    if (xqc_test_d18_type_50_uses_stream_context() != 0) {
        return EXIT_FAILURE;
    }

    if (xqc_test_d18_valid_placements() != 0) {
        return EXIT_FAILURE;
    }

    if (xqc_test_d18_invalid_placements() != 0) {
        return EXIT_FAILURE;
    }

    if (xqc_test_d18_control_kinds_require_version_and_context() != 0) {
        return EXIT_FAILURE;
    }

    if (xqc_test_d18_client_request_ids() != 0) {
        return EXIT_FAILURE;
    }

    if (xqc_test_d18_server_request_ids() != 0) {
        return EXIT_FAILURE;
    }

    if (xqc_test_d18_local_request_ids_are_reserved_once() != 0) {
        return EXIT_FAILURE;
    }

    if (xqc_test_d18_stream_context_commits_after_message() != 0) {
        return EXIT_FAILURE;
    }

    if (xqc_test_d18_failed_resolve_preserves_stream_context() != 0) {
        return EXIT_FAILURE;
    }

    if (xqc_test_d18_request_id_error_mapping() != 0) {
        return EXIT_FAILURE;
    }

    if (xqc_test_d18_session_registers_peer_ids_out_of_order() != 0) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
