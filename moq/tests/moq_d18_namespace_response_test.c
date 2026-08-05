#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "src/common/xqc_malloc.h"
#include "src/transport/xqc_conn.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_params.h"
#include "moq/moq_transport/xqc_moq_message_handler.h"
#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_transport/xqc_moq_subscribe.h"
#include "moq/moq_transport/xqc_moq_track.h"

#define XQC_TEST_D18_PREFIX_OVERLAP 0x30

#define XQC_TEST_ASSERT(expr) \
    do { \
        if (!(expr)) { \
            fprintf(stderr, "assert failed: %s:%d: %s\n", \
                    __FILE__, __LINE__, #expr); \
            return -1; \
        } \
    } while (0)

typedef struct {
    uint8_t bytes[128];
    size_t  length;
    int     write_count;
    uint8_t fin;
    int     fail_write;
} xqc_test_write_capture_t;

typedef struct {
    int                generic_ok_count;
    int                namespace_ok_count;
    int                generic_error_count;
    int                namespace_error_count;
    int                namespace_count;
    int                namespace_done_count;
    uint64_t           request_id;
    xqc_moq_msg_type_t request_type;
} xqc_test_callback_state_t;

static xqc_test_callback_state_t xqc_test_callbacks;
static xqc_log_t xqc_test_log;
static int xqc_test_updated_namespace_count;

static ssize_t
xqc_test_capture_write(void *stream, uint8_t *send_data,
    size_t send_data_size, uint8_t fin)
{
    xqc_test_write_capture_t *capture = stream;
    if (capture->fail_write) {
        return -XQC_ESYS;
    }
    if (send_data_size > sizeof(capture->bytes) - capture->length) {
        return -XQC_ELIMIT;
    }
    xqc_memcpy(capture->bytes + capture->length,
               send_data, send_data_size);
    capture->length += send_data_size;
    capture->write_count++;
    capture->fin = fin;
    return (ssize_t)send_data_size;
}

static void
xqc_test_init_session(xqc_moq_session_t *session)
{
    xqc_memzero(session, sizeof(*session));
    xqc_memzero(&xqc_test_log, sizeof(xqc_test_log));
    session->use_unified_setup = 1;
    session->profile = xqc_moq_v18_profile();
    session->profile_state = XQC_MOQ_PROFILE_ACTIVE;
    session->log = &xqc_test_log;
    xqc_init_list_head(&session->local_request_stream_list);
    xqc_init_list_head(&session->peer_request_stream_list);
    xqc_init_list_head(&session->local_subscribe_list);
    xqc_init_list_head(&session->peer_subscribe_list);
    xqc_init_list_head(&session->local_ns_pending_list);
    xqc_init_list_head(&session->peer_ns_pending_inbound_list);
    xqc_init_list_head(&session->peer_subscribe_namespace_list);
    xqc_init_list_head(&session->local_advertised_namespace_list);
    xqc_init_list_head(&session->peer_advertised_namespace_list);
    xqc_init_list_head(&session->track_list_for_pub);
    xqc_init_list_head(&session->track_list_for_sub);
}

static void
xqc_test_init_stream(xqc_moq_stream_t *stream,
    xqc_moq_session_t *session, xqc_test_write_capture_t *capture)
{
    xqc_memzero(stream, sizeof(*stream));
    stream->session = session;
    stream->trans_stream = capture;
    stream->trans_ops.write = xqc_test_capture_write;
    stream->kind = XQC_MOQ_STREAM_UNKNOWN;
    xqc_init_list_head(&stream->request_list_member);
}

static void
xqc_test_free_stream_write_buffer(xqc_moq_stream_t *stream)
{
    xqc_free(stream->write_buf);
    stream->write_buf = NULL;
}

static void
xqc_test_mark_d18_request_stream(xqc_moq_stream_t *stream)
{
    stream->kind = XQC_MOQ_STREAM_D18_REQUEST;
    stream->d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream->d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream->d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
}

static void
xqc_test_destroy_local_pending(xqc_moq_session_t *session,
    uint64_t request_id)
{
    xqc_moq_pending_ns_request_t *pending =
        xqc_moq_session_consume_pending_ns_request(session, request_id);
    if (pending == NULL) {
        return;
    }
    xqc_moq_namespace_tuple_free(pending->track_namespace_tuple,
                                 pending->track_namespace_num);
    xqc_free(pending);
}

static int
xqc_test_namespace_wire_vectors(void)
{
    static const uint8_t expected_empty_namespace[] = {
        0x08, 0x00, 0x01, 0x00,
    };
    static const uint8_t expected_multi_namespace[] = {
        0x08, 0x00, 0x0a, 0x02,
        0x04, 'l', 'i', 'v', 'e',
        0x03, 'c', 'a', 'm',
    };
    static const uint8_t expected_empty_done[] = {
        0x0e, 0x00, 0x01, 0x00,
    };
    xqc_moq_track_ns_field_t suffix[] = {
        {
            .len = 4,
            .data = (unsigned char *)"live",
        },
        {
            .len = 3,
            .data = (unsigned char *)"cam",
        },
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.version = XQC_MOQ_VERSION_18;

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    stream.peer_request = 1;
    stream.request_type = XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE;
    stream.response_sent = 1;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;

    xqc_moq_d18_namespace_msg_t msg;
    xqc_memzero(&msg, sizeof(msg));
    XQC_TEST_ASSERT(xqc_moq_write_msg_generic(
        &session, &stream, &msg.msg_base,
        XQC_MOQ_SEMANTIC_NAMESPACE) == XQC_OK);
    XQC_TEST_ASSERT(capture.length == sizeof(expected_empty_namespace));
    XQC_TEST_ASSERT(memcmp(capture.bytes, expected_empty_namespace,
                           sizeof(expected_empty_namespace)) == 0);

    capture.length = 0;
    capture.write_count = 0;
    stream.write_buf_len = 0;
    stream.write_buf_processed = 0;
    msg.track_namespace_suffix_num = 2;
    msg.track_namespace_suffix_tuple = suffix;
    XQC_TEST_ASSERT(xqc_moq_write_msg_generic(
        &session, &stream, &msg.msg_base,
        XQC_MOQ_SEMANTIC_NAMESPACE) == XQC_OK);
    XQC_TEST_ASSERT(capture.length == sizeof(expected_multi_namespace));
    XQC_TEST_ASSERT(memcmp(capture.bytes, expected_multi_namespace,
                           sizeof(expected_multi_namespace)) == 0);

    capture.length = 0;
    capture.write_count = 0;
    stream.write_buf_len = 0;
    stream.write_buf_processed = 0;
    msg.track_namespace_suffix_num = 0;
    msg.track_namespace_suffix_tuple = NULL;
    XQC_TEST_ASSERT(xqc_moq_write_msg_generic(
        &session, &stream, &msg.msg_base,
        XQC_MOQ_SEMANTIC_NAMESPACE_DONE) == XQC_OK);
    XQC_TEST_ASSERT(capture.length == sizeof(expected_empty_done));
    XQC_TEST_ASSERT(memcmp(capture.bytes, expected_empty_done,
                           sizeof(expected_empty_done)) == 0);

    xqc_test_free_stream_write_buffer(&stream);
    return 0;
}

static int
xqc_test_namespace_writer_uses_accepted_response_stream(void)
{
    static const uint8_t expected[] = {
        0x08, 0x00, 0x0a, 0x02,
        0x04, 'l', 'i', 'v', 'e',
        0x03, 'c', 'a', 'm',
    };
    xqc_moq_track_ns_field_t prefix = {
        .len = 8,
        .data = (unsigned char *)"external",
    };
    xqc_moq_track_ns_field_t full[] = {
        prefix,
        {
            .len = 4,
            .data = (unsigned char *)"live",
        },
        {
            .len = 3,
            .data = (unsigned char *)"cam",
        },
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.version = XQC_MOQ_VERSION_18;

    xqc_test_write_capture_t ctl_capture = {0};
    xqc_test_write_capture_t request_capture = {0};
    xqc_moq_stream_t ctl_stream;
    xqc_moq_stream_t request_stream;
    xqc_test_init_stream(&ctl_stream, &session, &ctl_capture);
    xqc_test_init_stream(&request_stream, &session, &request_capture);
    session.ctl_stream = &ctl_stream;

    request_stream.peer_request = 1;
    request_stream.request_type = XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE;
    request_stream.request_id = 2;
    request_stream.response_sent = 1;
    xqc_test_mark_d18_request_stream(&request_stream);
    xqc_list_add_tail(&request_stream.request_list_member,
                      &session.peer_request_stream_list);
    XQC_TEST_ASSERT(xqc_moq_session_add_namespace_prefix(
        &session, 2, &prefix, 1) == XQC_OK);

    XQC_TEST_ASSERT(xqc_moq_write_namespace(
        &session, 2, full, 3) == XQC_OK);
    XQC_TEST_ASSERT(ctl_capture.write_count == 0);
    XQC_TEST_ASSERT(request_capture.write_count == 1);
    XQC_TEST_ASSERT(request_capture.length == sizeof(expected));
    XQC_TEST_ASSERT(memcmp(request_capture.bytes, expected,
                           sizeof(expected)) == 0);
    XQC_TEST_ASSERT(xqc_moq_write_namespace(
        &session, 2, full, 3) == XQC_OK);
    XQC_TEST_ASSERT(request_capture.write_count == 1);

    request_capture.length = 0;
    request_capture.write_count = 0;
    request_stream.write_buf_len = 0;
    request_stream.write_buf_processed = 0;
    XQC_TEST_ASSERT(xqc_moq_write_namespace_done(
        &session, 2, full, 3) == XQC_OK);
    XQC_TEST_ASSERT(request_capture.bytes[0]
                    == XQC_MOQ_D18_MSG_NAMESPACE_DONE);
    XQC_TEST_ASSERT(xqc_moq_write_namespace_done(
        &session, 2, full, 3) == -XQC_EPARAM);

    request_stream.response_sent = 0;
    XQC_TEST_ASSERT(xqc_moq_write_namespace(
        &session, 2, full, 3) == -XQC_EPARAM);
    request_stream.response_sent = 1;
    full[0].data = (unsigned char *)"different";
    full[0].len = 9;
    XQC_TEST_ASSERT(xqc_moq_write_namespace(
        &session, 2, full, 3) == -XQC_EPARAM);
    XQC_TEST_ASSERT(xqc_moq_write_namespace(
        &session, 4, full, 3) == -XQC_ENULLPTR);

    XQC_TEST_ASSERT(xqc_moq_session_remove_namespace_prefix(
        &session, &prefix, 1) == 1);
    xqc_list_del_init(&request_stream.request_list_member);
    xqc_test_free_stream_write_buffer(&request_stream);
    xqc_test_free_stream_write_buffer(&ctl_stream);
    return 0;
}

static int
xqc_test_namespace_history_replay_uses_response_stream(void)
{
    static const uint8_t expected[] = {
        0x08, 0x00, 0x06, 0x01, 0x04, 'l', 'i', 'v', 'e',
    };
    xqc_moq_track_ns_field_t prefix = {
        .len = 8,
        .data = (unsigned char *)"external",
    };
    xqc_moq_track_ns_field_t full[] = {
        prefix,
        {
            .len = 4,
            .data = (unsigned char *)"live",
        },
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.version = XQC_MOQ_VERSION_18;

    xqc_test_write_capture_t ctl_capture = {0};
    xqc_test_write_capture_t request_capture = {0};
    xqc_moq_stream_t ctl_stream;
    xqc_moq_stream_t request_stream;
    xqc_test_init_stream(&ctl_stream, &session, &ctl_capture);
    xqc_test_init_stream(&request_stream, &session, &request_capture);
    session.ctl_stream = &ctl_stream;

    request_stream.peer_request = 1;
    request_stream.request_type = XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE;
    request_stream.request_id = 0;
    request_stream.response_sent = 1;
    request_stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    request_stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    request_stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    xqc_list_add_tail(&request_stream.request_list_member,
                      &session.peer_request_stream_list);
    XQC_TEST_ASSERT(xqc_moq_session_add_namespace_prefix(
        &session, 0, &prefix, 1) == XQC_OK);
    XQC_TEST_ASSERT(xqc_moq_session_add_advertised_namespace(
        &session, 1, full, 2) == XQC_OK);

    xqc_moq_session_forward_matching_namespaces(
        &session, &prefix, 1);
    XQC_TEST_ASSERT(ctl_capture.write_count == 0);
    XQC_TEST_ASSERT(request_capture.write_count == 1);
    XQC_TEST_ASSERT(request_capture.length == sizeof(expected));
    XQC_TEST_ASSERT(memcmp(request_capture.bytes, expected,
                           sizeof(expected)) == 0);

    XQC_TEST_ASSERT(xqc_moq_session_remove_advertised_namespace(
        &session, 1, full, 2) == 1);
    XQC_TEST_ASSERT(xqc_moq_session_remove_namespace_prefix(
        &session, &prefix, 1) == 1);
    xqc_list_del_init(&request_stream.request_list_member);
    xqc_test_free_stream_write_buffer(&request_stream);
    xqc_test_free_stream_write_buffer(&ctl_stream);
    return 0;
}

static int
xqc_test_namespace_incremental_fanout_uses_response_stream(void)
{
    xqc_moq_track_ns_field_t prefix = {
        .len = 8,
        .data = (unsigned char *)"external",
    };
    xqc_moq_track_ns_field_t full[] = {
        prefix,
        {
            .len = 4,
            .data = (unsigned char *)"live",
        },
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.version = XQC_MOQ_VERSION_18;

    xqc_test_write_capture_t ctl_capture = {0};
    xqc_test_write_capture_t request_capture = {0};
    xqc_moq_stream_t ctl_stream;
    xqc_moq_stream_t request_stream;
    xqc_test_init_stream(&ctl_stream, &session, &ctl_capture);
    xqc_test_init_stream(&request_stream, &session, &request_capture);
    session.ctl_stream = &ctl_stream;

    request_stream.peer_request = 1;
    request_stream.request_type = XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE;
    request_stream.request_id = 0;
    request_stream.response_sent = 1;
    request_stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    request_stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    request_stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    xqc_list_add_tail(&request_stream.request_list_member,
                      &session.peer_request_stream_list);
    XQC_TEST_ASSERT(xqc_moq_session_add_namespace_prefix(
        &session, 0, &prefix, 1) == XQC_OK);

    XQC_TEST_ASSERT(xqc_moq_session_forward_namespace_update(
        &session, full, 2, 0) == XQC_OK);
    XQC_TEST_ASSERT(ctl_capture.write_count == 0);
    XQC_TEST_ASSERT(request_capture.write_count == 1);
    XQC_TEST_ASSERT(request_capture.bytes[0]
                    == XQC_MOQ_D18_MSG_NAMESPACE);

    request_capture.length = 0;
    request_capture.write_count = 0;
    request_stream.write_buf_len = 0;
    request_stream.write_buf_processed = 0;
    XQC_TEST_ASSERT(xqc_moq_session_forward_namespace_update(
        &session, full, 2, 1) == XQC_OK);
    XQC_TEST_ASSERT(ctl_capture.write_count == 0);
    XQC_TEST_ASSERT(request_capture.write_count == 1);
    XQC_TEST_ASSERT(request_capture.bytes[0]
                    == XQC_MOQ_D18_MSG_NAMESPACE_DONE);

    XQC_TEST_ASSERT(xqc_moq_session_remove_namespace_prefix(
        &session, &prefix, 1) == 1);
    xqc_list_del_init(&request_stream.request_list_member);
    xqc_test_free_stream_write_buffer(&request_stream);
    xqc_test_free_stream_write_buffer(&ctl_stream);
    return 0;
}

static void
xqc_test_on_request_ok(xqc_moq_user_session_t *user_session,
    uint64_t request_id, xqc_moq_msg_type_t request_type,
    xqc_moq_request_ok_msg_t *msg)
{
    (void)user_session;
    if (msg != NULL && msg->params_num == 0) {
        xqc_test_callbacks.generic_ok_count++;
        xqc_test_callbacks.request_id = request_id;
        xqc_test_callbacks.request_type = request_type;
    }
}

static void
xqc_test_on_namespace_ok(xqc_moq_user_session_t *user_session,
    xqc_moq_subscribe_namespace_ok_msg_t *msg)
{
    (void)user_session;
    if (msg != NULL && msg->request_id == 0
        && msg->track_namespace_tuple == NULL
        && msg->track_namespace_num == 0)
    {
        xqc_test_callbacks.namespace_ok_count++;
    }
}

static void
xqc_test_on_request_error(xqc_moq_user_session_t *user_session,
    uint64_t request_id, xqc_moq_msg_type_t request_type,
    xqc_moq_request_error_msg_t *msg)
{
    (void)user_session;
    if (msg != NULL
        && msg->error_code == XQC_TEST_D18_PREFIX_OVERLAP
        && msg->retry_interval == 0
        && msg->reason_phrase_len == sizeof("overlap") - 1
        && memcmp(msg->reason_phrase, "overlap",
                  sizeof("overlap") - 1) == 0)
    {
        xqc_test_callbacks.generic_error_count++;
        xqc_test_callbacks.request_id = request_id;
        xqc_test_callbacks.request_type = request_type;
    }
}

static void
xqc_test_on_namespace_error(xqc_moq_user_session_t *user_session,
    xqc_moq_subscribe_namespace_error_msg_t *msg)
{
    (void)user_session;
    if (msg != NULL && msg->request_id == 2
        && msg->error_code == XQC_TEST_D18_PREFIX_OVERLAP
        && msg->reason_phrase_len == sizeof("overlap") - 1
        && memcmp(msg->reason_phrase, "overlap",
                  sizeof("overlap") - 1) == 0
        && msg->track_namespace_num == 1
        && msg->track_namespace_tuple != NULL
        && msg->track_namespace_tuple[0].len == 7
        && memcmp(msg->track_namespace_tuple[0].data,
                  "overlap", 7) == 0)
    {
        xqc_test_callbacks.namespace_error_count++;
    }
}

static int
xqc_test_is_external_namespace(
    const xqc_moq_track_ns_field_t *track_namespace_tuple,
    uint64_t track_namespace_num)
{
    return track_namespace_tuple != NULL
        && track_namespace_num == 2
        && track_namespace_tuple[0].len == 8
        && memcmp(track_namespace_tuple[0].data, "external", 8) == 0
        && track_namespace_tuple[1].len == 4
        && memcmp(track_namespace_tuple[1].data, "live", 4) == 0;
}

static void
xqc_test_on_namespace(xqc_moq_user_session_t *user_session,
    uint64_t request_id,
    const xqc_moq_track_ns_field_t *track_namespace_tuple,
    uint64_t track_namespace_num)
{
    (void)user_session;
    if (request_id == 0
        && xqc_test_is_external_namespace(
            track_namespace_tuple, track_namespace_num))
    {
        xqc_test_callbacks.namespace_count++;
    }
}

static void
xqc_test_on_namespace_done(xqc_moq_user_session_t *user_session,
    uint64_t request_id,
    const xqc_moq_track_ns_field_t *track_namespace_tuple,
    uint64_t track_namespace_num)
{
    (void)user_session;
    if (request_id == 0
        && xqc_test_is_external_namespace(
            track_namespace_tuple, track_namespace_num))
    {
        xqc_test_callbacks.namespace_done_count++;
    }
}

static void
xqc_test_on_updated_namespace(xqc_moq_user_session_t *user_session,
    uint64_t request_id,
    const xqc_moq_track_ns_field_t *track_namespace_tuple,
    uint64_t track_namespace_num)
{
    (void)user_session;
    if (request_id == 1 && track_namespace_num == 2
        && track_namespace_tuple[0].len == 3
        && memcmp(track_namespace_tuple[0].data, "new", 3) == 0
        && track_namespace_tuple[1].len == 3
        && memcmp(track_namespace_tuple[1].data, "cam", 3) == 0)
    {
        xqc_test_updated_namespace_count++;
    }
}

static int
xqc_test_namespace_request_update_installs_prefix_after_ok(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.version = XQC_MOQ_VERSION_18;
    session.session_callbacks_ext.on_namespace =
        xqc_test_on_updated_namespace;
    xqc_moq_d18_request_registry_init(
        &session.d18_request_registry, 1);
    xqc_moq_d18_auth_cache_init(&session.peer_auth_cache, 0);

    xqc_moq_track_ns_field_t old_prefix = {
        .len = 3,
        .data = (unsigned char *)"old",
    };
    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    xqc_moq_d18_update_queue_init(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&stream.d18_peer_update_queue);
    stream.local_request = 1;
    stream.response_received = 1;
    stream.request_type = XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE;
    stream.request_id = 1;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    stream.namespace_subscription =
        xqc_moq_namespace_prefix_create_copy(&old_prefix, 1);
    XQC_TEST_ASSERT(stream.namespace_subscription != NULL);
    stream.namespace_subscription->request_id = stream.request_id;
    XQC_TEST_ASSERT(xqc_moq_session_register_local_request_id(
        &session, stream.request_id) == XQC_MOQ_D18_REQUEST_ID_OK);
    xqc_list_add_tail(&stream.request_list_member,
                      &session.local_request_stream_list);

    uint8_t new_prefix[] = {0x01, 0x03, 'n', 'e', 'w'};
    xqc_moq_message_parameter_t prefix_param = {
        .type = XQC_MOQ_D18_PARAM_TRACK_NAMESPACE_PREFIX,
        .length = sizeof(new_prefix),
        .value = new_prefix,
    };
    xqc_moq_request_update_msg_t update = {
        .params_num = 1,
        .params = &prefix_param,
    };
    XQC_TEST_ASSERT(xqc_moq_write_request_update(
        &session, stream.request_id, &update) == XQC_OK);
    XQC_TEST_ASSERT(stream.namespace_subscription->prefix_tuple[0].len == 3);
    XQC_TEST_ASSERT(memcmp(
        stream.namespace_subscription->prefix_tuple[0].data,
        "old", 3) == 0);

    xqc_moq_request_ok_msg_t ok = {0};
    xqc_moq_on_request_ok(&session, &stream, &ok.msg_base);
    XQC_TEST_ASSERT(stream.namespace_subscription->prefix_num == 1);
    XQC_TEST_ASSERT(stream.namespace_subscription->prefix_tuple[0].len == 3);
    XQC_TEST_ASSERT(memcmp(
        stream.namespace_subscription->prefix_tuple[0].data,
        "new", 3) == 0);

    xqc_moq_track_ns_field_t suffix = {
        .len = 3,
        .data = (unsigned char *)"cam",
    };
    xqc_moq_d18_namespace_msg_t namespace_msg = {
        .track_namespace_suffix_num = 1,
        .track_namespace_suffix_tuple = &suffix,
    };
    xqc_test_updated_namespace_count = 0;
    xqc_moq_on_namespace(
        &session, &stream, &namespace_msg.msg_base);
    XQC_TEST_ASSERT(xqc_test_updated_namespace_count == 1);

    xqc_moq_namespace_prefix_destroy(stream.namespace_subscription);
    stream.namespace_subscription = NULL;
    xqc_moq_d18_params_free(stream.d18_accepted_params,
                            stream.d18_accepted_params_num);
    stream.d18_accepted_params = NULL;
    stream.d18_accepted_params_num = 0;
    xqc_moq_d18_update_queue_destroy(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(&stream.d18_peer_update_queue);
    xqc_list_del_init(&stream.request_list_member);
    xqc_test_free_stream_write_buffer(&stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    return 0;
}

static int
xqc_test_activate_local_namespace_subscription(
    xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    const xqc_moq_track_ns_field_t *prefix)
{
    XQC_TEST_ASSERT(xqc_moq_session_add_pending_ns_request(
        session, 0, prefix, 1) == XQC_OK);
    stream->session = session;
    stream->local_request = 1;
    stream->request_type = XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE;
    stream->request_id = 0;
    stream->d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream->d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream->d18_context.position = XQC_MOQ_D18_POSITION_NEXT;

    xqc_moq_request_ok_msg_t ok;
    xqc_memzero(&ok, sizeof(ok));
    xqc_moq_on_request_ok(session, stream, &ok.msg_base);
    return 0;
}

static int
xqc_test_namespace_receive_state_and_done(void)
{
    static const uint8_t namespace_bytes[] = {
        0x08, 0x00, 0x06, 0x01, 0x04, 'l', 'i', 'v', 'e',
    };
    static const uint8_t done_bytes[] = {
        0x0e, 0x00, 0x06, 0x01, 0x04, 'l', 'i', 'v', 'e',
    };
    xqc_moq_track_ns_field_t prefix = {
        .len = 8,
        .data = (unsigned char *)"external",
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.version = XQC_MOQ_VERSION_18;
    session.session_callbacks_ext.on_namespace = xqc_test_on_namespace;
    session.session_callbacks_ext.on_namespace_done =
        xqc_test_on_namespace_done;

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    xqc_memzero(&xqc_test_callbacks, sizeof(xqc_test_callbacks));
    XQC_TEST_ASSERT(xqc_test_activate_local_namespace_subscription(
        &session, &stream, &prefix) == 0);
    XQC_TEST_ASSERT(stream.namespace_subscription != NULL);

    XQC_TEST_ASSERT(xqc_moq_stream_process(
        &stream, (uint8_t *)namespace_bytes,
        sizeof(namespace_bytes), 0) == sizeof(namespace_bytes));
    XQC_TEST_ASSERT(xqc_test_callbacks.namespace_count == 1);
    XQC_TEST_ASSERT(xqc_test_callbacks.namespace_done_count == 0);
    XQC_TEST_ASSERT(!xqc_list_empty(
        &stream.namespace_subscription->advertised_namespace_list));

    XQC_TEST_ASSERT(xqc_moq_stream_process(
        &stream, (uint8_t *)namespace_bytes,
        sizeof(namespace_bytes), 0) == sizeof(namespace_bytes));
    XQC_TEST_ASSERT(xqc_test_callbacks.namespace_count == 1);

    XQC_TEST_ASSERT(xqc_moq_stream_process(
        &stream, (uint8_t *)done_bytes,
        sizeof(done_bytes), 0) == sizeof(done_bytes));
    XQC_TEST_ASSERT(xqc_test_callbacks.namespace_done_count == 1);
    XQC_TEST_ASSERT(xqc_list_empty(
        &stream.namespace_subscription->advertised_namespace_list));

    xqc_moq_stream_on_request_closed(
        &stream, XQC_MOQ_REQUEST_CANCELLED);
    XQC_TEST_ASSERT(stream.namespace_subscription == NULL);
    xqc_free(stream.read_buf);
    xqc_test_free_stream_write_buffer(&stream);
    return 0;
}

static int
xqc_test_namespace_done_before_namespace_is_violation(void)
{
    static const uint8_t done_bytes[] = {
        0x0e, 0x00, 0x06, 0x01, 0x04, 'l', 'i', 'v', 'e',
    };
    xqc_moq_track_ns_field_t prefix = {
        .len = 8,
        .data = (unsigned char *)"external",
    };
    xqc_connection_t quic_conn;
    xqc_memzero(&quic_conn, sizeof(quic_conn));
    quic_conn.conn_err = UINT64_MAX;
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.version = XQC_MOQ_VERSION_18;
    session.quic_conn = &quic_conn;
    session.session_callbacks_ext.on_namespace_done =
        xqc_test_on_namespace_done;

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    xqc_memzero(&xqc_test_callbacks, sizeof(xqc_test_callbacks));
    XQC_TEST_ASSERT(xqc_test_activate_local_namespace_subscription(
        &session, &stream, &prefix) == 0);

    XQC_TEST_ASSERT(xqc_moq_stream_process(
        &stream, (uint8_t *)done_bytes,
        sizeof(done_bytes), 0) == sizeof(done_bytes));
    XQC_TEST_ASSERT(xqc_test_callbacks.namespace_done_count == 0);
    XQC_TEST_ASSERT(quic_conn.conn_close_msg != NULL);
    XQC_TEST_ASSERT(strcmp(
        quic_conn.conn_close_msg,
        "NAMESPACE_DONE before NAMESPACE") == 0);

    xqc_moq_stream_on_request_closed(
        &stream, XQC_MOQ_REQUEST_CANCELLED);
    xqc_free(stream.read_buf);
    xqc_test_free_stream_write_buffer(&stream);
    return 0;
}

static int
xqc_test_namespace_fin_clears_active_state(void)
{
    static const uint8_t namespace_bytes[] = {
        0x08, 0x00, 0x06, 0x01, 0x04, 'l', 'i', 'v', 'e',
    };
    xqc_moq_track_ns_field_t prefix = {
        .len = 8,
        .data = (unsigned char *)"external",
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.version = XQC_MOQ_VERSION_18;
    session.session_callbacks_ext.on_namespace = xqc_test_on_namespace;
    session.session_callbacks_ext.on_namespace_done =
        xqc_test_on_namespace_done;

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    xqc_memzero(&xqc_test_callbacks, sizeof(xqc_test_callbacks));
    XQC_TEST_ASSERT(xqc_test_activate_local_namespace_subscription(
        &session, &stream, &prefix) == 0);
    XQC_TEST_ASSERT(xqc_moq_stream_process(
        &stream, (uint8_t *)namespace_bytes,
        sizeof(namespace_bytes), 0) == sizeof(namespace_bytes));

    xqc_moq_stream_on_request_closed(
        &stream, XQC_MOQ_REQUEST_CANCELLED);
    XQC_TEST_ASSERT(xqc_test_callbacks.namespace_count == 1);
    XQC_TEST_ASSERT(xqc_test_callbacks.namespace_done_count == 1);
    XQC_TEST_ASSERT(stream.namespace_subscription == NULL);

    xqc_free(stream.read_buf);
    xqc_test_free_stream_write_buffer(&stream);
    return 0;
}

static int
xqc_test_initial_request_write_commits_stream_context_on_success(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.version = XQC_MOQ_VERSION_18;

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    stream.local_request = 1;
    stream.request_type = XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_FIRST;

    xqc_moq_subscribe_namespace_msg_t request;
    xqc_memzero(&request, sizeof(request));
    XQC_TEST_ASSERT(xqc_moq_write_msg_generic(
        &session, &stream, &request.msg_base,
        XQC_MOQ_SEMANTIC_SUBSCRIBE_NAMESPACE) == XQC_OK);

    XQC_TEST_ASSERT(stream.d18_context.stream_class
                    == XQC_MOQ_D18_STREAM_REQUEST);
    XQC_TEST_ASSERT(stream.d18_context.position
                    == XQC_MOQ_D18_POSITION_NEXT);

    xqc_test_free_stream_write_buffer(&stream);
    return 0;
}

static int
xqc_test_initial_request_write_failure_preserves_stream_context(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.version = XQC_MOQ_VERSION_18;

    xqc_test_write_capture_t capture = {
        .fail_write = 1,
    };
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    stream.local_request = 1;
    stream.request_type = XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_FIRST;

    xqc_moq_subscribe_namespace_msg_t request;
    xqc_memzero(&request, sizeof(request));
    XQC_TEST_ASSERT(xqc_moq_write_msg_generic(
        &session, &stream, &request.msg_base,
        XQC_MOQ_SEMANTIC_SUBSCRIBE_NAMESPACE) == -XQC_ESYS);

    XQC_TEST_ASSERT(stream.d18_context.stream_class
                    == XQC_MOQ_D18_STREAM_UNCLASSIFIED);
    XQC_TEST_ASSERT(stream.d18_context.position
                    == XQC_MOQ_D18_POSITION_FIRST);

    xqc_test_free_stream_write_buffer(&stream);
    return 0;
}

static int
xqc_test_namespace_ok_uses_request_stream(void)
{
    static const uint8_t expected[] = {0x07, 0x00, 0x01, 0x00};
    xqc_moq_session_t session;
    xqc_test_init_session(&session);

    xqc_test_write_capture_t ctl_capture = {0};
    xqc_test_write_capture_t request_capture = {0};
    xqc_moq_stream_t ctl_stream;
    xqc_moq_stream_t request_stream;
    xqc_test_init_stream(&ctl_stream, &session, &ctl_capture);
    xqc_test_init_stream(&request_stream, &session, &request_capture);
    session.ctl_stream = &ctl_stream;

    request_stream.peer_request = 1;
    request_stream.request_type = XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE;
    request_stream.request_id = 0;
    request_stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    request_stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    request_stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    xqc_list_add_tail(&request_stream.request_list_member,
                      &session.peer_request_stream_list);
    XQC_TEST_ASSERT(xqc_moq_session_add_pending_inbound_ns(
        &session, 0, NULL, 0) == XQC_OK);

    xqc_moq_subscribe_namespace_ok_msg_t ok;
    xqc_memzero(&ok, sizeof(ok));
    ok.request_id = 0;
    XQC_TEST_ASSERT(xqc_moq_write_subscribe_namespace_ok(
        &session, &ok) == XQC_OK);

    XQC_TEST_ASSERT(ctl_capture.write_count == 0);
    XQC_TEST_ASSERT(request_capture.write_count == 1);
    XQC_TEST_ASSERT(request_capture.length == sizeof(expected));
    XQC_TEST_ASSERT(memcmp(request_capture.bytes, expected,
                           sizeof(expected)) == 0);
    XQC_TEST_ASSERT(request_capture.fin == 0);
    XQC_TEST_ASSERT(request_stream.response_sent == 1);
    XQC_TEST_ASSERT(xqc_list_empty(
        &session.peer_ns_pending_inbound_list));
    XQC_TEST_ASSERT(!xqc_list_empty(
        &session.peer_subscribe_namespace_list));

    XQC_TEST_ASSERT(xqc_moq_session_remove_namespace_prefix(
        &session, NULL, 0) == 1);
    xqc_list_del_init(&request_stream.request_list_member);
    xqc_test_free_stream_write_buffer(&request_stream);
    xqc_test_free_stream_write_buffer(&ctl_stream);
    return 0;
}

static int
xqc_test_d18_namespace_ok_does_not_initiate_publish(void)
{
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.version = XQC_MOQ_VERSION_18;
    session.transport_type = (xqc_moq_transport_type_t)99;
    xqc_moq_d18_request_registry_init(
        &session.d18_request_registry, 1);

    xqc_moq_track_t track;
    xqc_memzero(&track, sizeof(track));
    track.session = &session;
    track.track_role = XQC_MOQ_TRACK_FOR_PUB;
    track.track_alias = XQC_MOQ_INVALID_ID;
    track.subscribe_id = XQC_MOQ_INVALID_ID;
    track.track_info.track_namespace_tuple = &live;
    track.track_info.track_namespace_num = 1;
    track.track_info.track_name = "audio";
    xqc_init_list_head(&track.list_member);
    xqc_list_add_tail(
        &track.list_member, &session.track_list_for_pub);

    xqc_test_write_capture_t request_capture = {0};
    xqc_moq_stream_t request_stream;
    xqc_test_init_stream(
        &request_stream, &session, &request_capture);
    request_stream.peer_request = 1;
    request_stream.request_type =
        XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE;
    request_stream.request_id = 0;
    xqc_test_mark_d18_request_stream(&request_stream);
    xqc_list_add_tail(
        &request_stream.request_list_member,
        &session.peer_request_stream_list);
    XQC_TEST_ASSERT(xqc_moq_session_add_pending_inbound_ns(
        &session, 0, NULL, 0) == XQC_OK);

    xqc_moq_subscribe_namespace_ok_msg_t ok;
    xqc_memzero(&ok, sizeof(ok));
    ok.request_id = 0;
    XQC_TEST_ASSERT(xqc_moq_write_subscribe_namespace_ok(
        &session, &ok) == XQC_OK);

    XQC_TEST_ASSERT(
        session.d18_request_registry.next_local_id == 1);
    XQC_TEST_ASSERT(track.track_alias == XQC_MOQ_INVALID_ID);
    XQC_TEST_ASSERT(track.subscribe_id == XQC_MOQ_INVALID_ID);
    XQC_TEST_ASSERT(xqc_list_empty(
        &session.peer_subscribe_list));

    XQC_TEST_ASSERT(xqc_moq_session_remove_namespace_prefix(
        &session, NULL, 0) == 1);
    xqc_list_del_init(&request_stream.request_list_member);
    xqc_list_del_init(&track.list_member);
    xqc_test_free_stream_write_buffer(&request_stream);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

static int
xqc_test_namespace_error_uses_request_stream_and_fin(void)
{
    static const uint8_t expected[] = {
        0x05, 0x00, 0x0a, 0x30, 0x00, 0x07,
        'o', 'v', 'e', 'r', 'l', 'a', 'p',
    };
    xqc_moq_track_ns_field_t prefix = {
        .len = 7,
        .data = (unsigned char *)"overlap",
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);

    xqc_test_write_capture_t ctl_capture = {0};
    xqc_test_write_capture_t request_capture = {0};
    xqc_moq_stream_t ctl_stream;
    xqc_moq_stream_t request_stream;
    xqc_test_init_stream(&ctl_stream, &session, &ctl_capture);
    xqc_test_init_stream(&request_stream, &session, &request_capture);
    session.ctl_stream = &ctl_stream;

    request_stream.peer_request = 1;
    request_stream.request_type = XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE;
    request_stream.request_id = 2;
    xqc_test_mark_d18_request_stream(&request_stream);
    xqc_list_add_tail(&request_stream.request_list_member,
                      &session.peer_request_stream_list);
    XQC_TEST_ASSERT(xqc_moq_session_add_pending_inbound_ns(
        &session, 2, &prefix, 1) == XQC_OK);

    xqc_moq_subscribe_namespace_error_msg_t error;
    xqc_memzero(&error, sizeof(error));
    error.request_id = 2;
    error.error_code = XQC_TEST_D18_PREFIX_OVERLAP;
    error.reason_phrase = "overlap";
    error.reason_phrase_len = sizeof("overlap") - 1;
    XQC_TEST_ASSERT(xqc_moq_write_subscribe_namespace_error(
        &session, &error) == XQC_OK);

    XQC_TEST_ASSERT(ctl_capture.write_count == 0);
    XQC_TEST_ASSERT(request_capture.write_count == 1);
    XQC_TEST_ASSERT(request_capture.length == sizeof(expected));
    XQC_TEST_ASSERT(memcmp(request_capture.bytes, expected,
                           sizeof(expected)) == 0);
    XQC_TEST_ASSERT(request_capture.fin == 1);
    XQC_TEST_ASSERT(request_stream.response_sent == 1);
    XQC_TEST_ASSERT(xqc_list_empty(
        &session.peer_ns_pending_inbound_list));

    xqc_list_del_init(&request_stream.request_list_member);
    xqc_test_free_stream_write_buffer(&request_stream);
    xqc_test_free_stream_write_buffer(&ctl_stream);
    return 0;
}

static int
xqc_test_namespace_ok_consumes_pending_and_calls_callbacks(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.session_callbacks_ext.on_request_ok = xqc_test_on_request_ok;
    session.session_callbacks.on_subscribe_namespace_ok =
        xqc_test_on_namespace_ok;
    XQC_TEST_ASSERT(xqc_moq_session_add_pending_ns_request(
        &session, 0, NULL, 0) == XQC_OK);

    xqc_moq_stream_t stream;
    xqc_memzero(&stream, sizeof(stream));
    stream.session = &session;
    stream.local_request = 1;
    stream.request_type = XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE;
    stream.request_id = 0;

    xqc_moq_request_ok_msg_t ok;
    xqc_memzero(&ok, sizeof(ok));
    xqc_memzero(&xqc_test_callbacks, sizeof(xqc_test_callbacks));
    xqc_moq_on_request_ok(&session, &stream, &ok.msg_base);

    XQC_TEST_ASSERT(stream.response_received == 1);
    XQC_TEST_ASSERT(xqc_test_callbacks.generic_ok_count == 1);
    XQC_TEST_ASSERT(xqc_test_callbacks.namespace_ok_count == 1);
    XQC_TEST_ASSERT(xqc_test_callbacks.request_id == 0);
    XQC_TEST_ASSERT(xqc_test_callbacks.request_type
                    == XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE);
    XQC_TEST_ASSERT(xqc_list_empty(&session.local_ns_pending_list));
    return 0;
}

static int
xqc_test_namespace_error_consumes_pending_and_calls_callbacks(void)
{
    xqc_moq_track_ns_field_t prefix = {
        .len = 7,
        .data = (unsigned char *)"overlap",
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.session_callbacks_ext.on_request_error = xqc_test_on_request_error;
    session.session_callbacks.on_subscribe_namespace_error =
        xqc_test_on_namespace_error;
    XQC_TEST_ASSERT(xqc_moq_session_add_pending_ns_request(
        &session, 2, &prefix, 1) == XQC_OK);

    xqc_moq_stream_t stream;
    xqc_memzero(&stream, sizeof(stream));
    stream.session = &session;
    stream.local_request = 1;
    stream.request_type = XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE;
    stream.request_id = 2;

    xqc_moq_request_error_msg_t error;
    xqc_memzero(&error, sizeof(error));
    error.error_code = XQC_TEST_D18_PREFIX_OVERLAP;
    error.reason_phrase = "overlap";
    error.reason_phrase_len = sizeof("overlap") - 1;
    xqc_memzero(&xqc_test_callbacks, sizeof(xqc_test_callbacks));
    xqc_moq_on_request_error(&session, &stream, &error.msg_base);

    XQC_TEST_ASSERT(stream.response_received == 1);
    XQC_TEST_ASSERT(xqc_test_callbacks.generic_error_count == 1);
    XQC_TEST_ASSERT(xqc_test_callbacks.namespace_error_count == 1);
    XQC_TEST_ASSERT(xqc_test_callbacks.request_id == 2);
    XQC_TEST_ASSERT(xqc_test_callbacks.request_type
                    == XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE);
    XQC_TEST_ASSERT(xqc_list_empty(&session.local_ns_pending_list));
    return 0;
}

static int
xqc_test_local_publish_namespace_request_error_allows_retry(void)
{
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.version = XQC_MOQ_VERSION_18;
    session.transport_type = (xqc_moq_transport_type_t)99;
    xqc_moq_d18_request_registry_init(
        &session.d18_request_registry, 1);
    XQC_TEST_ASSERT(xqc_moq_session_register_local_request_id(
        &session, 1) == XQC_MOQ_D18_REQUEST_ID_OK);
    XQC_TEST_ASSERT(xqc_moq_session_add_advertised_namespace(
        &session, 1, &live, 1) == XQC_OK);
    XQC_TEST_ASSERT(xqc_moq_session_bind_advertised_namespace_request(
        &session, 1, &live, 1, 1) == XQC_OK);
    xqc_moq_namespace_advertisement_t *advertisement =
        xqc_moq_session_find_advertised_namespace_by_request(
            &session, 1, 1);
    XQC_TEST_ASSERT(advertisement != NULL);
    advertisement->explicit_advertised = 1;

    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, NULL);
    stream.local_request = 1;
    stream.request_type = XQC_MOQ_MSG_PUBLISH_NAMESPACE;
    stream.request_id = 1;
    xqc_moq_request_error_msg_t error = {
        .error_code = XQC_MOQ_REQUEST_ERROR_UNAUTHORIZED,
    };
    xqc_moq_on_request_error(
        &session, &stream, &error.msg_base);

    XQC_TEST_ASSERT(stream.response_received == 1);
    XQC_TEST_ASSERT(stream.request_closed_notified == 1);
    XQC_TEST_ASSERT(xqc_moq_session_find_advertised_namespace(
        &session, 1, &live, 1) == NULL);

    xqc_moq_publish_namespace_msg_t retry = {
        .request_id = 3,
        .track_namespace_num = 1,
        .track_namespace_tuple = &live,
    };
    /*
     * The invalid transport makes stream creation fail. Reaching that failure
     * proves retry was not swallowed by the explicit_advertised fast path.
     */
    XQC_TEST_ASSERT(xqc_moq_publish_namespace(
        &session, &retry) == -XQC_EMALLOC);

    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

static int
xqc_test_local_publish_namespace_abrupt_close_allows_retry(void)
{
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.version = XQC_MOQ_VERSION_18;
    session.transport_type = (xqc_moq_transport_type_t)99;
    xqc_moq_d18_request_registry_init(
        &session.d18_request_registry, 1);
    XQC_TEST_ASSERT(xqc_moq_session_register_local_request_id(
        &session, 1) == XQC_MOQ_D18_REQUEST_ID_OK);
    XQC_TEST_ASSERT(xqc_moq_session_add_advertised_namespace(
        &session, 1, &live, 1) == XQC_OK);
    XQC_TEST_ASSERT(xqc_moq_session_bind_advertised_namespace_request(
        &session, 1, &live, 1, 1) == XQC_OK);
    xqc_moq_namespace_advertisement_t *advertisement =
        xqc_moq_session_find_advertised_namespace_by_request(
            &session, 1, 1);
    XQC_TEST_ASSERT(advertisement != NULL);
    advertisement->explicit_advertised = 1;

    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, NULL);
    stream.local_request = 1;
    stream.request_type = XQC_MOQ_MSG_PUBLISH_NAMESPACE;
    stream.request_id = 1;
    xqc_moq_stream_on_request_closed(
        &stream, XQC_MOQ_REQUEST_CANCELLED);

    XQC_TEST_ASSERT(stream.request_closed_notified == 1);
    XQC_TEST_ASSERT(xqc_moq_session_find_advertised_namespace(
        &session, 1, &live, 1) == NULL);

    xqc_moq_publish_namespace_msg_t retry = {
        .request_id = 3,
        .track_namespace_num = 1,
        .track_namespace_tuple = &live,
    };
    XQC_TEST_ASSERT(xqc_moq_publish_namespace(
        &session, &retry) == -XQC_EMALLOC);

    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

static int
xqc_test_namespace_response_rejects_missing_or_duplicate_state(void)
{
    xqc_connection_t quic_conn;
    xqc_memzero(&quic_conn, sizeof(quic_conn));
    quic_conn.conn_err = UINT64_MAX;
    xqc_log_t log;
    xqc_memzero(&log, sizeof(log));

    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.quic_conn = &quic_conn;
    session.log = &log;
    session.session_callbacks_ext.on_request_ok = xqc_test_on_request_ok;
    session.session_callbacks.on_subscribe_namespace_ok =
        xqc_test_on_namespace_ok;

    xqc_moq_stream_t stream;
    xqc_memzero(&stream, sizeof(stream));
    stream.session = &session;
    stream.local_request = 1;
    stream.request_type = XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE;
    stream.request_id = 4;
    xqc_moq_request_ok_msg_t ok;
    xqc_memzero(&ok, sizeof(ok));
    xqc_memzero(&xqc_test_callbacks, sizeof(xqc_test_callbacks));

    xqc_moq_on_request_ok(&session, &stream, &ok.msg_base);
    XQC_TEST_ASSERT(quic_conn.conn_err == UINT64_MAX);
    XQC_TEST_ASSERT(quic_conn.conn_close_msg != NULL);
    XQC_TEST_ASSERT(strcmp(quic_conn.conn_close_msg,
                    "SUBSCRIBE_NAMESPACE REQUEST_OK missing pending state")
                    == 0);
    XQC_TEST_ASSERT(stream.response_received == 0);
    XQC_TEST_ASSERT(xqc_test_callbacks.generic_ok_count == 0);
    XQC_TEST_ASSERT(xqc_test_callbacks.namespace_ok_count == 0);

    quic_conn.conn_err = UINT64_MAX;
    quic_conn.conn_close_msg = NULL;
    stream.request_id = 6;
    stream.response_received = 1;
    XQC_TEST_ASSERT(xqc_moq_session_add_pending_ns_request(
        &session, 6, NULL, 0) == XQC_OK);
    xqc_moq_on_request_ok(&session, &stream, &ok.msg_base);
    XQC_TEST_ASSERT(quic_conn.conn_err == UINT64_MAX);
    XQC_TEST_ASSERT(quic_conn.conn_close_msg != NULL);
    XQC_TEST_ASSERT(strcmp(quic_conn.conn_close_msg,
                           "REQUEST_OK on invalid request stream") == 0);
    XQC_TEST_ASSERT(!xqc_list_empty(&session.local_ns_pending_list));
    XQC_TEST_ASSERT(xqc_test_callbacks.generic_ok_count == 0);
    XQC_TEST_ASSERT(xqc_test_callbacks.namespace_ok_count == 0);

    xqc_test_destroy_local_pending(&session, 6);
    return 0;
}

int
main(void)
{
    if (xqc_test_namespace_wire_vectors() != 0
        || xqc_test_namespace_writer_uses_accepted_response_stream() != 0
        || xqc_test_namespace_history_replay_uses_response_stream() != 0
        || xqc_test_namespace_incremental_fanout_uses_response_stream()
            != 0
        || xqc_test_namespace_receive_state_and_done() != 0
        || xqc_test_namespace_request_update_installs_prefix_after_ok() != 0
        || xqc_test_namespace_done_before_namespace_is_violation() != 0
        || xqc_test_namespace_fin_clears_active_state() != 0
        || xqc_test_initial_request_write_commits_stream_context_on_success()
            != 0
        || xqc_test_initial_request_write_failure_preserves_stream_context()
            != 0
        || xqc_test_namespace_ok_uses_request_stream() != 0
        || xqc_test_d18_namespace_ok_does_not_initiate_publish() != 0
        || xqc_test_namespace_error_uses_request_stream_and_fin() != 0
        || xqc_test_namespace_ok_consumes_pending_and_calls_callbacks() != 0
        || xqc_test_namespace_error_consumes_pending_and_calls_callbacks() != 0
        || xqc_test_local_publish_namespace_request_error_allows_retry()
            != 0
        || xqc_test_local_publish_namespace_abrupt_close_allows_retry()
            != 0
        || xqc_test_namespace_response_rejects_missing_or_duplicate_state()
            != 0)
    {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
