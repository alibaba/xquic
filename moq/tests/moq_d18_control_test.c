#include "moq/moq_transport/draft18/xqc_moq_d18_control.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_update.h"
#include "moq/moq_transport/xqc_moq_message_handler.h"
#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define XQC_TEST_ASSERT(expr) \
    do { \
        if (!(expr)) { \
            fprintf(stderr, "assert failed: %s:%d: %s\n", \
                    __FILE__, __LINE__, #expr); \
            return -1; \
        } \
    } while (0)

_Static_assert(XQC_MOQ_D18_MSG_REQUEST_UPDATE == 0x02,
               "REQUEST_UPDATE type changed");
_Static_assert(XQC_MOQ_D18_MSG_PUBLISH_DONE == 0x0b,
               "PUBLISH_DONE type changed");
_Static_assert(XQC_MOQ_D18_MSG_PUBLISH_BLOCKED == 0x0f,
               "PUBLISH_BLOCKED type changed");
_Static_assert(XQC_MOQ_D18_MSG_GOAWAY == 0x10,
               "GOAWAY type changed");
_Static_assert(XQC_MOQ_D18_MSG_FETCH == 0x16,
               "FETCH type changed");
_Static_assert(XQC_MOQ_D18_MSG_FETCH_OK == 0x18,
               "FETCH_OK type changed");
_Static_assert(XQC_MOQ_D18_MSG_TRACK_STATUS == 0x0d,
               "TRACK_STATUS type changed");

extern xqc_int_t xqc_moq_write_fetch(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, xqc_moq_fetch_msg_t *fetch);
extern xqc_int_t xqc_moq_write_track_status(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, xqc_moq_track_status_msg_t *track_status);
extern xqc_int_t xqc_moq_write_fetch_ok(xqc_moq_session_t *session,
    uint64_t request_id, xqc_moq_fetch_ok_msg_t *fetch_ok);
extern xqc_int_t xqc_moq_write_fetch_header(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, xqc_moq_fetch_header_msg_t *header,
    uint8_t fin);
extern void xqc_moq_on_fetch_header(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, xqc_moq_msg_base_t *msg_base);

typedef struct {
    ssize_t scripted_results[2];
    size_t scripted_results_count;
    size_t scripted_results_index;
    size_t bytes_written;
    size_t write_call_count;
    size_t send_size_history[4];
    uint8_t data[256];
    size_t data_len;
    uint8_t last_fin;
} xqc_test_setup_write_capture_t;

static xqc_log_t xqc_test_setup_log;
static int xqc_test_setup_callback_count;

static void
xqc_test_on_session_setup(xqc_moq_user_session_t *user_session,
    char *extdata, const xqc_moq_message_parameter_t *params,
    uint64_t params_num)
{
    (void)user_session;
    (void)extdata;
    (void)params;
    (void)params_num;
    xqc_test_setup_callback_count++;
}

static ssize_t
xqc_test_setup_capture_write(void *stream, uint8_t *send_data,
    size_t send_data_size, uint8_t fin)
{
    xqc_test_setup_write_capture_t *capture = stream;
    (void)send_data;
    (void)fin;
    if (capture->write_call_count
        < sizeof(capture->send_size_history)
            / sizeof(capture->send_size_history[0]))
    {
        capture->send_size_history[capture->write_call_count] =
            send_data_size;
    }
    capture->write_call_count++;
    capture->last_fin = fin;
    ssize_t ret = (ssize_t)send_data_size;
    if (capture->scripted_results_index
        < capture->scripted_results_count)
    {
        ret = capture->scripted_results[
            capture->scripted_results_index++];
    }
    if (ret > 0) {
        size_t copy_len = (size_t)ret;
        if (copy_len > sizeof(capture->data) - capture->data_len) {
            copy_len = sizeof(capture->data) - capture->data_len;
        }
        if (copy_len > 0) {
            memcpy(capture->data + capture->data_len, send_data, copy_len);
            capture->data_len += copy_len;
        }
        capture->bytes_written += (size_t)ret;
    }
    return ret;
}

static void
xqc_test_init_setup_write(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, xqc_test_setup_write_capture_t *capture,
    uint64_t version, uint8_t unified)
{
    memset(session, 0, sizeof(*session));
    memset(stream, 0, sizeof(*stream));
    session->version = version;
    session->use_unified_setup = unified;
    session->profile = xqc_moq_version_profile_for_version(version);
    session->profile_state = XQC_MOQ_PROFILE_ALPN_SELECTED;
    session->log = &xqc_test_setup_log;
    session->ctl_stream = stream;
    stream->session = session;
    stream->kind = XQC_MOQ_STREAM_UNKNOWN;
    stream->trans_stream = capture;
    stream->trans_ops.write = xqc_test_setup_capture_write;
    stream->d18_context.direction = XQC_MOQ_D18_DIRECTION_UNI;
    stream->d18_context.position = XQC_MOQ_D18_POSITION_FIRST;
}

static void
xqc_test_clean_setup_write(xqc_moq_stream_t *stream)
{
    free(stream->write_buf);
    stream->write_buf = NULL;
}

static int
xqc_test_received_setup_activates_profile_before_callback(void)
{
    xqc_engine_t engine;
    xqc_moq_session_t session;
    xqc_moq_stream_t stream;
    xqc_moq_setup_msg_t setup;

    memset(&engine, 0, sizeof(engine));
    memset(&session, 0, sizeof(session));
    memset(&stream, 0, sizeof(stream));
    memset(&setup, 0, sizeof(setup));
    engine.eng_type = XQC_ENGINE_CLIENT;
    session.engine = &engine;
    session.transport_type = XQC_MOQ_TRANSPORT_QUIC;
    session.version = XQC_MOQ_VERSION_18;
    session.use_unified_setup = 1;
    session.profile = xqc_moq_v18_profile();
    session.profile_state = XQC_MOQ_PROFILE_ALPN_SELECTED;
    session.log = &xqc_test_setup_log;
    session.session_callbacks.on_session_setup = xqc_test_on_session_setup;
    stream.session = &session;
    xqc_moq_d18_setup_options_init(&setup.decoded_options);

    xqc_test_setup_callback_count = 0;
    xqc_moq_on_setup(&session, &stream, &setup.msg_base);

    XQC_TEST_ASSERT(session.profile_state == XQC_MOQ_PROFILE_ACTIVE);
    XQC_TEST_ASSERT(session.session_setup_done == 1);
    XQC_TEST_ASSERT(session.peer_ctl_stream == &stream);
    XQC_TEST_ASSERT(xqc_test_setup_callback_count == 1);
    xqc_moq_session_clear_peer_setup_options(&session);
    xqc_moq_d18_setup_options_destroy(&setup.decoded_options);
    return 0;
}

static int
xqc_test_setup_write_commits_control_context_only_after_completion(void)
{
    xqc_moq_setup_msg_t setup = {0};
    xqc_moq_session_t session;
    xqc_moq_stream_t stream;
    xqc_test_setup_write_capture_t capture = {0};

    xqc_test_init_setup_write(
        &session, &stream, &capture, XQC_MOQ_VERSION_18, 1);
    XQC_TEST_ASSERT(xqc_moq_write_setup(&session, &setup) == XQC_OK);
    XQC_TEST_ASSERT(capture.bytes_written == stream.write_buf_len);
    XQC_TEST_ASSERT(stream.d18_context.stream_class
                    == XQC_MOQ_D18_STREAM_CONTROL);
    XQC_TEST_ASSERT(stream.d18_context.position
                    == XQC_MOQ_D18_POSITION_NEXT);
    xqc_test_clean_setup_write(&stream);

    memset(&capture, 0, sizeof(capture));
    capture.scripted_results[0] = 1;
    capture.scripted_results_count = 1;
    xqc_test_init_setup_write(
        &session, &stream, &capture, XQC_MOQ_VERSION_18, 1);
    memset(&setup, 0, sizeof(setup));
    XQC_TEST_ASSERT(xqc_moq_write_setup(&session, &setup) == XQC_OK);
    XQC_TEST_ASSERT(stream.write_buf_processed == 1);
    XQC_TEST_ASSERT(stream.write_buf_processed < stream.write_buf_len);
    XQC_TEST_ASSERT(stream.d18_context.stream_class
                    == XQC_MOQ_D18_STREAM_UNCLASSIFIED);
    XQC_TEST_ASSERT(stream.d18_context.position
                    == XQC_MOQ_D18_POSITION_FIRST);
    XQC_TEST_ASSERT(xqc_moq_stream_write(&stream) == XQC_OK);
    XQC_TEST_ASSERT(stream.write_buf_processed == stream.write_buf_len);
    XQC_TEST_ASSERT(stream.d18_context.stream_class
                    == XQC_MOQ_D18_STREAM_CONTROL);
    XQC_TEST_ASSERT(stream.d18_context.position
                    == XQC_MOQ_D18_POSITION_NEXT);
    xqc_test_clean_setup_write(&stream);

    memset(&capture, 0, sizeof(capture));
    capture.scripted_results[0] = -XQC_EAGAIN;
    capture.scripted_results_count = 1;
    xqc_test_init_setup_write(
        &session, &stream, &capture, XQC_MOQ_VERSION_18, 1);
    memset(&setup, 0, sizeof(setup));
    XQC_TEST_ASSERT(xqc_moq_write_setup(&session, &setup) == XQC_OK);
    XQC_TEST_ASSERT(stream.write_buf_processed == 0);
    XQC_TEST_ASSERT(stream.d18_context.position
                    == XQC_MOQ_D18_POSITION_FIRST);
    XQC_TEST_ASSERT(xqc_moq_stream_write(&stream) == XQC_OK);
    XQC_TEST_ASSERT(stream.d18_context.position
                    == XQC_MOQ_D18_POSITION_NEXT);
    xqc_test_clean_setup_write(&stream);

    memset(&capture, 0, sizeof(capture));
    capture.scripted_results[0] = -XQC_ESYS;
    capture.scripted_results_count = 1;
    xqc_test_init_setup_write(
        &session, &stream, &capture, XQC_MOQ_VERSION_18, 1);
    memset(&setup, 0, sizeof(setup));
    XQC_TEST_ASSERT(xqc_moq_write_setup(&session, &setup) == -XQC_ESYS);
    XQC_TEST_ASSERT(stream.d18_context.stream_class
                    == XQC_MOQ_D18_STREAM_UNCLASSIFIED);
    XQC_TEST_ASSERT(stream.d18_context.position
                    == XQC_MOQ_D18_POSITION_FIRST);
    xqc_test_clean_setup_write(&stream);

    memset(&capture, 0, sizeof(capture));
    xqc_test_init_setup_write(
        &session, &stream, &capture, XQC_MOQ_VERSION_14, 0);
    memset(&setup, 0, sizeof(setup));
    XQC_TEST_ASSERT(xqc_moq_write_setup(&session, &setup)
                    == -XQC_EPARAM);
    XQC_TEST_ASSERT(stream.d18_context.stream_class
                    == XQC_MOQ_D18_STREAM_UNCLASSIFIED);
    XQC_TEST_ASSERT(stream.d18_context.position
                    == XQC_MOQ_D18_POSITION_FIRST);
    xqc_test_clean_setup_write(&stream);
    return 0;
}

static int
xqc_test_setup_hard_write_failure_has_no_ghost_retry(void)
{
    enum { old_cap = 8 };
    uint8_t old_content[old_cap];
    memset(old_content, 0xa5, sizeof(old_content));

    for (size_t old_len = 0; old_len <= old_cap; old_len += old_cap) {
        xqc_moq_setup_msg_t setup = {0};
        xqc_moq_msg_setup_init_handler(&setup.msg_base);
        xqc_int_t expected_len = setup.msg_base.encode_len(
            &setup.msg_base);
        uint8_t expected[16] = {0};
        XQC_TEST_ASSERT(expected_len > 0);
        XQC_TEST_ASSERT((size_t)expected_len <= sizeof(expected));
        XQC_TEST_ASSERT(setup.msg_base.encode(
            &setup.msg_base, expected, sizeof(expected)) == expected_len);

        xqc_moq_session_t session;
        xqc_moq_stream_t stream;
        xqc_test_setup_write_capture_t capture = {0};
        capture.scripted_results[0] = -XQC_ESYS;
        capture.scripted_results_count = 1;
        xqc_test_init_setup_write(
            &session, &stream, &capture, XQC_MOQ_VERSION_18, 1);
        stream.write_buf = malloc(old_cap);
        XQC_TEST_ASSERT(stream.write_buf != NULL);
        memcpy(stream.write_buf, old_content, old_cap);
        stream.write_buf_cap = old_cap;
        stream.write_buf_len = old_len;
        stream.write_buf_processed = old_len;
        uint8_t *old_buf = stream.write_buf;

        XQC_TEST_ASSERT(xqc_moq_write_setup(
            &session, &setup) == -XQC_ESYS);
        int hard_state_preserved = stream.write_buf == old_buf
            && stream.write_buf_cap == old_cap
            && stream.write_buf_len == old_len
            && stream.write_buf_processed == old_len
            && memcmp(stream.write_buf, old_content, old_cap) == 0
            && stream.d18_setup_write_pending == 0
            && stream.d18_context.stream_class
                == XQC_MOQ_D18_STREAM_UNCLASSIFIED
            && stream.d18_context.position
                == XQC_MOQ_D18_POSITION_FIRST;

        xqc_int_t direct_ret = xqc_moq_stream_write(&stream);
        int direct_write_has_no_ghost = direct_ret == XQC_OK
            && capture.write_call_count == 2
            && capture.send_size_history[1] == 0
            && capture.bytes_written == 0
            && stream.write_buf == old_buf
            && stream.write_buf_cap == old_cap
            && stream.write_buf_len == old_len
            && stream.write_buf_processed == old_len
            && memcmp(stream.write_buf, old_content, old_cap) == 0
            && stream.d18_setup_write_pending == 0
            && stream.d18_context.stream_class
                == XQC_MOQ_D18_STREAM_UNCLASSIFIED
            && stream.d18_context.position
                == XQC_MOQ_D18_POSITION_FIRST;

        memset(&setup, 0, sizeof(setup));
        xqc_int_t retry_ret = xqc_moq_write_setup(&session, &setup);
        int api_retry_writes_once = retry_ret == XQC_OK
            && capture.write_call_count == 3
            && capture.send_size_history[2] == (size_t)expected_len
            && capture.bytes_written == (size_t)expected_len
            && stream.write_buf != old_buf
            && stream.write_buf_cap == (size_t)expected_len
            && stream.write_buf_len == (size_t)expected_len
            && stream.write_buf_processed == (size_t)expected_len
            && memcmp(stream.write_buf, expected,
                      (size_t)expected_len) == 0
            && stream.d18_setup_write_pending == 0
            && stream.d18_context.stream_class
                == XQC_MOQ_D18_STREAM_CONTROL
            && stream.d18_context.position
                == XQC_MOQ_D18_POSITION_NEXT;

        XQC_TEST_ASSERT(hard_state_preserved);
        XQC_TEST_ASSERT(direct_write_has_no_ghost);
        XQC_TEST_ASSERT(api_retry_writes_once);
        xqc_test_clean_setup_write(&stream);
    }
    return 0;
}

static int
xqc_test_request_update_wire(void)
{
    static const uint8_t expected[] = {
        0x02, 0x00, 0x04, 0x00, 0x01, 0x10, 0x00,
    };
    xqc_moq_message_parameter_t forward = {
        .type = XQC_MOQ_D18_PARAM_FORWARD,
        .is_integer = 1,
        .int_value = 0,
    };
    xqc_moq_request_update_msg_t msg = {
        .request_id = 0,
        .params_num = 1,
        .params = &forward,
        .d18_param_context =
            XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_SUBSCRIBE,
    };
    uint8_t buf[32] = {0};
    xqc_moq_d18_request_update_init_handler(
        &msg.msg_base,
        XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_SUBSCRIBE);
    XQC_TEST_ASSERT(xqc_moq_d18_request_update_encode_len(&msg.msg_base)
                    == (xqc_int_t)sizeof(expected));
    XQC_TEST_ASSERT(xqc_moq_d18_request_update_encode(
                        &msg.msg_base, buf, sizeof(buf))
                    == (xqc_int_t)sizeof(expected));
    XQC_TEST_ASSERT(memcmp(buf, expected, sizeof(expected)) == 0);
    return 0;
}

static int
xqc_test_publish_blocked_wire(void)
{
    static const uint8_t expected[] = {
        0x0f, 0x00, 0x05, 0x01, 0x01, 'v', 0x01, 'a',
    };
    xqc_moq_track_ns_field_t suffix = {
        .len = 1,
        .data = (unsigned char *)"v",
    };
    xqc_moq_publish_blocked_msg_t msg = {
        .track_namespace_suffix_num = 1,
        .track_namespace_suffix = &suffix,
        .track_name = "a",
        .track_name_len = 1,
    };
    uint8_t buf[32] = {0};
    xqc_moq_d18_publish_blocked_init_handler(&msg.msg_base);
    XQC_TEST_ASSERT(xqc_moq_d18_publish_blocked_encode_len(&msg.msg_base)
                    == (xqc_int_t)sizeof(expected));
    XQC_TEST_ASSERT(xqc_moq_d18_publish_blocked_encode(
                        &msg.msg_base, buf, sizeof(buf))
                    == (xqc_int_t)sizeof(expected));
    XQC_TEST_ASSERT(memcmp(buf, expected, sizeof(expected)) == 0);
    return 0;
}

static int
xqc_test_publish_blocked_dispatch_hook(void)
{
    xqc_moq_publish_blocked_msg_t *msg =
        xqc_moq_d18_publish_blocked_create();
    XQC_TEST_ASSERT(msg != NULL);
    XQC_TEST_ASSERT(msg->msg_base.on_msg == xqc_moq_on_publish_blocked);
    xqc_moq_d18_publish_blocked_free(msg);
    return 0;
}

static int
xqc_test_publish_done_wire(void)
{
    static const uint8_t expected[] = {
        0x0b, 0x00, 0x04, 0x02, 0x00, 0x01, 'x',
    };
    xqc_moq_publish_done_msg_t msg = {
        .subscribe_id = 9,
        .status_code = XQC_MOQ_PUBLISH_DONE_TRACK_ENDED,
        .stream_count = 0,
        .reason_phrase = "x",
        .reason_phrase_len = 1,
    };
    uint8_t buf[32] = {0};
    xqc_moq_d18_publish_done_init_handler(&msg.msg_base);
    XQC_TEST_ASSERT(xqc_moq_d18_publish_done_encode_len(&msg.msg_base)
                    == (xqc_int_t)sizeof(expected));
    XQC_TEST_ASSERT(xqc_moq_d18_publish_done_encode(
                        &msg.msg_base, buf, sizeof(buf))
                    == (xqc_int_t)sizeof(expected));
    XQC_TEST_ASSERT(memcmp(buf, expected, sizeof(expected)) == 0);
    return 0;
}

static int
xqc_test_goaway_wire(void)
{
    static const uint8_t control_expected[] = {
        0x10, 0x00, 0x03, 0x00, 0x0a, 0x00,
    };
    static const uint8_t request_expected[] = {
        0x10, 0x00, 0x02, 0x00, 0x0a,
    };
    xqc_moq_d18_goaway_msg_t msg = {
        .timeout_ms = 10,
        .request_id = 0,
    };
    uint8_t buf[32] = {0};

    xqc_moq_d18_control_goaway_init_handler(&msg.msg_base);
    XQC_TEST_ASSERT(msg.has_request_id == 1);
    XQC_TEST_ASSERT(xqc_moq_d18_goaway_encode(
                        &msg.msg_base, buf, sizeof(buf))
                    == (xqc_int_t)sizeof(control_expected));
    XQC_TEST_ASSERT(memcmp(buf, control_expected,
                           sizeof(control_expected)) == 0);

    memset(buf, 0, sizeof(buf));
    xqc_moq_d18_request_goaway_init_handler(&msg.msg_base);
    XQC_TEST_ASSERT(msg.has_request_id == 0);
    XQC_TEST_ASSERT(xqc_moq_d18_goaway_encode(
                        &msg.msg_base, buf, sizeof(buf))
                    == (xqc_int_t)sizeof(request_expected));
    XQC_TEST_ASSERT(memcmp(buf, request_expected,
                           sizeof(request_expected)) == 0);

    xqc_moq_message_resolution_t resolution;
    XQC_TEST_ASSERT(xqc_moq_profile_resolve_outbound(
        xqc_moq_v18_profile(), XQC_MOQ_STREAM_CONTROL,
        XQC_MOQ_SEMANTIC_GOAWAY_DRAFT18, &resolution) == XQC_OK);
    XQC_TEST_ASSERT(resolution.codec->initialize
                    == xqc_moq_d18_control_goaway_init_handler);
    XQC_TEST_ASSERT(xqc_moq_profile_resolve_outbound(
        xqc_moq_v18_profile(), XQC_MOQ_STREAM_D18_REQUEST,
        XQC_MOQ_SEMANTIC_GOAWAY_DRAFT18, &resolution) == XQC_OK);
    XQC_TEST_ASSERT(resolution.codec->initialize
                    == xqc_moq_d18_request_goaway_init_handler);
    return 0;
}

static int
xqc_test_goaway_dispatch_hook(void)
{
    xqc_moq_d18_goaway_msg_t *msg = xqc_moq_d18_goaway_create();
    XQC_TEST_ASSERT(msg != NULL);
    XQC_TEST_ASSERT(msg->msg_base.on_msg == xqc_moq_on_goaway_draft18);
    xqc_moq_d18_goaway_free(msg);
    return 0;
}

static int
xqc_test_request_update_decode_once(const uint8_t *wire, size_t wire_len,
    size_t first_len)
{
    xqc_moq_request_update_msg_t *decoded =
        xqc_moq_d18_request_update_create();
    xqc_moq_decode_msg_ctx_t ctx = {0};
    xqc_int_t finish = 0;
    xqc_int_t wait_more = 0;
    size_t body_len = wire_len - 1;
    size_t consumed = 0;

    XQC_TEST_ASSERT(decoded != NULL);
    xqc_moq_d18_request_update_init_handler(
        &decoded->msg_base,
        XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_SUBSCRIBE);
    if (first_len < body_len) {
        xqc_int_t ret = decoded->msg_base.decode(
            (uint8_t *)wire + 1, first_len, 0, &ctx,
            &decoded->msg_base, &finish, &wait_more);
        XQC_TEST_ASSERT(ret >= 0);
        XQC_TEST_ASSERT((size_t)ret <= first_len);
        XQC_TEST_ASSERT(finish == 0);
        XQC_TEST_ASSERT(wait_more == 1);
        consumed = (size_t)ret;
    }
    finish = 0;
    wait_more = 0;
    xqc_int_t ret = decoded->msg_base.decode(
        (uint8_t *)wire + 1 + consumed, body_len - consumed, 1,
        &ctx, &decoded->msg_base, &finish, &wait_more);
    XQC_TEST_ASSERT(ret == (xqc_int_t)(body_len - consumed));
    XQC_TEST_ASSERT(finish == 1);
    XQC_TEST_ASSERT(wait_more == 0);
    XQC_TEST_ASSERT(decoded->request_id == 0);
    XQC_TEST_ASSERT(decoded->params_num == 1);
    XQC_TEST_ASSERT(decoded->params != NULL);
    XQC_TEST_ASSERT(decoded->params[0].type == XQC_MOQ_D18_PARAM_FORWARD);
    XQC_TEST_ASSERT(decoded->params[0].is_integer == 1);
    XQC_TEST_ASSERT(decoded->params[0].int_value == 0);
    xqc_moq_d18_request_update_free(decoded);
    return 0;
}

static int
xqc_test_request_update_fragmented_decode(void)
{
    static const uint8_t wire[] = {
        0x02, 0x00, 0x04, 0x00, 0x01, 0x10, 0x00,
    };
    for (size_t split = 0; split < sizeof(wire); split++) {
        XQC_TEST_ASSERT(xqc_test_request_update_decode_once(
            wire, sizeof(wire), split) == 0);
    }
    return 0;
}

static int
xqc_test_publish_blocked_decode_once(const uint8_t *wire, size_t wire_len,
    size_t first_len)
{
    xqc_moq_publish_blocked_msg_t *decoded =
        xqc_moq_d18_publish_blocked_create();
    xqc_moq_decode_msg_ctx_t ctx = {0};
    xqc_int_t finish = 0;
    xqc_int_t wait_more = 0;
    size_t body_len = wire_len - 1;
    size_t consumed = 0;

    XQC_TEST_ASSERT(decoded != NULL);
    if (first_len < body_len) {
        xqc_int_t ret = decoded->msg_base.decode(
            (uint8_t *)wire + 1, first_len, 0, &ctx,
            &decoded->msg_base, &finish, &wait_more);
        XQC_TEST_ASSERT(ret >= 0);
        XQC_TEST_ASSERT((size_t)ret <= first_len);
        XQC_TEST_ASSERT(finish == 0);
        XQC_TEST_ASSERT(wait_more == 1);
        consumed = (size_t)ret;
    }
    finish = 0;
    wait_more = 0;
    xqc_int_t ret = decoded->msg_base.decode(
        (uint8_t *)wire + 1 + consumed, body_len - consumed, 1,
        &ctx, &decoded->msg_base, &finish, &wait_more);
    XQC_TEST_ASSERT(ret == (xqc_int_t)(body_len - consumed));
    XQC_TEST_ASSERT(finish == 1);
    XQC_TEST_ASSERT(wait_more == 0);
    XQC_TEST_ASSERT(decoded->track_namespace_suffix_num == 1);
    XQC_TEST_ASSERT(decoded->track_namespace_suffix != NULL);
    XQC_TEST_ASSERT(decoded->track_namespace_suffix[0].len == 1);
    XQC_TEST_ASSERT(memcmp(
        decoded->track_namespace_suffix[0].data, "v", 1) == 0);
    XQC_TEST_ASSERT(decoded->track_name_len == 1);
    XQC_TEST_ASSERT(memcmp(decoded->track_name, "a", 1) == 0);
    xqc_moq_d18_publish_blocked_free(decoded);
    return 0;
}

static int
xqc_test_publish_blocked_fragmented_decode(void)
{
    static const uint8_t wire[] = {
        0x0f, 0x00, 0x05, 0x01, 0x01, 'v', 0x01, 'a',
    };
    for (size_t split = 0; split < sizeof(wire); split++) {
        XQC_TEST_ASSERT(xqc_test_publish_blocked_decode_once(
            wire, sizeof(wire), split) == 0);
    }
    return 0;
}

static int
xqc_test_publish_done_decode_once(const uint8_t *wire, size_t wire_len,
    size_t first_len)
{
    xqc_moq_publish_done_msg_t *decoded =
        xqc_moq_d18_publish_done_create();
    xqc_moq_decode_msg_ctx_t ctx = {0};
    xqc_int_t finish = 0;
    xqc_int_t wait_more = 0;
    size_t body_len = wire_len - 1;
    size_t consumed = 0;

    XQC_TEST_ASSERT(decoded != NULL);
    if (first_len < body_len) {
        xqc_int_t ret = decoded->msg_base.decode(
            (uint8_t *)wire + 1, first_len, 0, &ctx,
            &decoded->msg_base, &finish, &wait_more);
        XQC_TEST_ASSERT(ret >= 0);
        XQC_TEST_ASSERT((size_t)ret <= first_len);
        XQC_TEST_ASSERT(finish == 0);
        XQC_TEST_ASSERT(wait_more == 1);
        consumed = (size_t)ret;
    }
    finish = 0;
    wait_more = 0;
    xqc_int_t ret = decoded->msg_base.decode(
        (uint8_t *)wire + 1 + consumed, body_len - consumed, 1,
        &ctx, &decoded->msg_base, &finish, &wait_more);
    XQC_TEST_ASSERT(ret == (xqc_int_t)(body_len - consumed));
    XQC_TEST_ASSERT(finish == 1);
    XQC_TEST_ASSERT(wait_more == 0);
    XQC_TEST_ASSERT(decoded->subscribe_id == 0);
    XQC_TEST_ASSERT(decoded->status_code == XQC_MOQ_PUBLISH_DONE_TRACK_ENDED);
    XQC_TEST_ASSERT(decoded->stream_count == 0);
    XQC_TEST_ASSERT(decoded->reason_phrase_len == 1);
    XQC_TEST_ASSERT(memcmp(decoded->reason_phrase, "x", 1) == 0);
    xqc_moq_d18_publish_done_free(decoded);
    return 0;
}

static int
xqc_test_publish_done_fragmented_decode(void)
{
    static const uint8_t wire[] = {
        0x0b, 0x00, 0x04, 0x02, 0x00, 0x01, 'x',
    };
    for (size_t split = 0; split < sizeof(wire); split++) {
        XQC_TEST_ASSERT(xqc_test_publish_done_decode_once(
            wire, sizeof(wire), split) == 0);
    }
    return 0;
}

static int
xqc_test_goaway_decode_once(const uint8_t *wire, size_t wire_len,
    size_t first_len, uint8_t control)
{
    xqc_moq_d18_goaway_msg_t *decoded = xqc_moq_d18_goaway_create();
    xqc_moq_decode_msg_ctx_t ctx = {0};
    xqc_int_t finish = 0;
    xqc_int_t wait_more = 0;
    size_t body_len = wire_len - 1;
    size_t consumed = 0;

    XQC_TEST_ASSERT(decoded != NULL);
    if (control) {
        xqc_moq_d18_control_goaway_init_handler(&decoded->msg_base);
    } else {
        xqc_moq_d18_request_goaway_init_handler(&decoded->msg_base);
    }
    if (first_len < body_len) {
        xqc_int_t ret = decoded->msg_base.decode(
            (uint8_t *)wire + 1, first_len, 0, &ctx,
            &decoded->msg_base, &finish, &wait_more);
        XQC_TEST_ASSERT(ret >= 0);
        XQC_TEST_ASSERT((size_t)ret <= first_len);
        XQC_TEST_ASSERT(finish == 0);
        XQC_TEST_ASSERT(wait_more == 1);
        consumed = (size_t)ret;
    }
    finish = 0;
    wait_more = 0;
    xqc_int_t ret = decoded->msg_base.decode(
        (uint8_t *)wire + 1 + consumed, body_len - consumed, 1,
        &ctx, &decoded->msg_base, &finish, &wait_more);
    XQC_TEST_ASSERT(ret == (xqc_int_t)(body_len - consumed));
    XQC_TEST_ASSERT(finish == 1);
    XQC_TEST_ASSERT(wait_more == 0);
    XQC_TEST_ASSERT(decoded->new_session_uri_len == 0);
    XQC_TEST_ASSERT(decoded->timeout_ms == 10);
    XQC_TEST_ASSERT(decoded->has_request_id == control);
    XQC_TEST_ASSERT(decoded->request_id == 0);
    xqc_moq_d18_goaway_free(decoded);
    return 0;
}

static int
xqc_test_goaway_fragmented_decode(void)
{
    static const uint8_t control_wire[] = {
        0x10, 0x00, 0x03, 0x00, 0x0a, 0x00,
    };
    static const uint8_t request_wire[] = {
        0x10, 0x00, 0x02, 0x00, 0x0a,
    };
    for (size_t split = 0; split < sizeof(control_wire); split++) {
        XQC_TEST_ASSERT(xqc_test_goaway_decode_once(
            control_wire, sizeof(control_wire), split, 1) == 0);
    }
    for (size_t split = 0; split < sizeof(request_wire); split++) {
        XQC_TEST_ASSERT(xqc_test_goaway_decode_once(
            request_wire, sizeof(request_wire), split, 0) == 0);
    }
    return 0;
}

static xqc_int_t xqc_test_decode_full(xqc_moq_msg_base_t *base,
    uint8_t *body, size_t body_len, xqc_int_t *finish,
    xqc_int_t *wait_more);

static int
xqc_test_fetch_decode_once(const uint8_t *wire, size_t wire_len,
    size_t first_len, xqc_moq_fetch_type_t expected_type)
{
    xqc_moq_fetch_msg_t *decoded = xqc_moq_d18_fetch_create();
    xqc_moq_decode_msg_ctx_t ctx = {0};
    xqc_int_t finish = 0;
    xqc_int_t wait_more = 0;
    size_t body_len = wire_len - 1;
    size_t consumed = 0;

    XQC_TEST_ASSERT(decoded != NULL);
    if (first_len < body_len) {
        xqc_int_t ret = decoded->msg_base.decode(
            (uint8_t *)wire + 1, first_len, 0, &ctx,
            &decoded->msg_base, &finish, &wait_more);
        XQC_TEST_ASSERT(ret >= 0);
        XQC_TEST_ASSERT((size_t)ret <= first_len);
        XQC_TEST_ASSERT(finish == 0);
        XQC_TEST_ASSERT(wait_more == 1);
        consumed = (size_t)ret;
    }
    finish = 0;
    wait_more = 0;
    xqc_int_t ret = decoded->msg_base.decode(
        (uint8_t *)wire + 1 + consumed, body_len - consumed, 1,
        &ctx, &decoded->msg_base, &finish, &wait_more);
    XQC_TEST_ASSERT(ret == (xqc_int_t)(body_len - consumed));
    XQC_TEST_ASSERT(finish == 1);
    XQC_TEST_ASSERT(wait_more == 0);
    XQC_TEST_ASSERT(decoded->request_id ==
                    (expected_type == XQC_MOQ_FETCH_STANDALONE ? 0 : 2));
    XQC_TEST_ASSERT(decoded->fetch_type == expected_type);
    XQC_TEST_ASSERT(decoded->params_num == 0);
    if (expected_type == XQC_MOQ_FETCH_STANDALONE) {
        XQC_TEST_ASSERT(decoded->track_namespace_num == 1);
        XQC_TEST_ASSERT(decoded->track_namespace_tuple[0].len == 2);
        XQC_TEST_ASSERT(memcmp(
            decoded->track_namespace_tuple[0].data, "ns", 2) == 0);
        XQC_TEST_ASSERT(decoded->track_name_len == 5);
        XQC_TEST_ASSERT(memcmp(decoded->track_name, "video", 5) == 0);
        XQC_TEST_ASSERT(decoded->start_group_id == 1);
        XQC_TEST_ASSERT(decoded->start_object_id == 2);
        XQC_TEST_ASSERT(decoded->end_group_id == 3);
        XQC_TEST_ASSERT(decoded->end_object_id == 4);
    } else {
        XQC_TEST_ASSERT(decoded->joining_request_id == 0);
        XQC_TEST_ASSERT(decoded->joining_start == 5);
    }
    xqc_moq_d18_fetch_free(decoded);
    return 0;
}

static int
xqc_test_fetch_wire_and_fragmented_decode(void)
{
    static const uint8_t standalone_wire[] = {
        0x16, 0x00, 0x11, 0x00, 0x01,
        0x01, 0x02, 'n', 's', 0x05, 'v', 'i', 'd', 'e', 'o',
        0x01, 0x02, 0x03, 0x04, 0x00,
    };
    static const uint8_t relative_wire[] = {
        0x16, 0x00, 0x05, 0x02, 0x02, 0x00, 0x05, 0x00,
    };
    static const uint8_t absolute_wire[] = {
        0x16, 0x00, 0x05, 0x02, 0x03, 0x00, 0x05, 0x00,
    };
    xqc_moq_track_ns_field_t ns = {
        .data = (uint8_t *)"ns",
        .len = 2,
    };
    xqc_moq_fetch_msg_t msg = {
        .request_id = 0,
        .fetch_type = XQC_MOQ_FETCH_STANDALONE,
        .track_namespace_num = 1,
        .track_namespace_tuple = &ns,
        .track_name = "video",
        .track_name_len = 5,
        .start_group_id = 1,
        .start_object_id = 2,
        .end_group_id = 3,
        .end_object_id = 4,
    };
    uint8_t encoded[64] = {0};

    xqc_moq_d18_fetch_init_handler(&msg.msg_base);
    XQC_TEST_ASSERT(msg.msg_base.encode(
        &msg.msg_base, encoded, sizeof(encoded))
        == (xqc_int_t)sizeof(standalone_wire));
    XQC_TEST_ASSERT(memcmp(encoded, standalone_wire,
                           sizeof(standalone_wire)) == 0);

    for (size_t split = 0; split < sizeof(standalone_wire); split++) {
        XQC_TEST_ASSERT(xqc_test_fetch_decode_once(
            standalone_wire, sizeof(standalone_wire), split,
            XQC_MOQ_FETCH_STANDALONE) == 0);
    }
    for (size_t split = 0; split < sizeof(relative_wire); split++) {
        XQC_TEST_ASSERT(xqc_test_fetch_decode_once(
            relative_wire, sizeof(relative_wire), split,
            XQC_MOQ_FETCH_JOINING_RELATIVE) == 0);
    }
    for (size_t split = 0; split < sizeof(absolute_wire); split++) {
        XQC_TEST_ASSERT(xqc_test_fetch_decode_once(
            absolute_wire, sizeof(absolute_wire), split,
            XQC_MOQ_FETCH_JOINING_ABSOLUTE) == 0);
    }
    return 0;
}

static int
xqc_test_fetch_ok_wire_and_fragmented_decode(void)
{
    static const uint8_t wire[] = {
        0x18, 0x00, 0x04, 0x01, 0x03, 0x04, 0x00,
    };
    xqc_moq_fetch_ok_msg_t msg = {
        .end_of_track = 1,
        .end_group_id = 3,
        .end_object_id = 4,
    };
    uint8_t encoded[32] = {0};

    xqc_moq_d18_fetch_ok_init_handler(&msg.msg_base);
    XQC_TEST_ASSERT(msg.msg_base.encode(
        &msg.msg_base, encoded, sizeof(encoded)) == (xqc_int_t)sizeof(wire));
    XQC_TEST_ASSERT(memcmp(encoded, wire, sizeof(wire)) == 0);

    for (size_t split = 0; split < sizeof(wire); split++) {
        xqc_moq_fetch_ok_msg_t *decoded = xqc_moq_d18_fetch_ok_create();
        xqc_moq_decode_msg_ctx_t ctx = {0};
        xqc_int_t finish = 0;
        xqc_int_t wait_more = 0;
        size_t body_len = sizeof(wire) - 1;
        size_t consumed = 0;
        XQC_TEST_ASSERT(decoded != NULL);
        if (split < body_len) {
            xqc_int_t ret = decoded->msg_base.decode(
                (uint8_t *)wire + 1, split, 0, &ctx,
                &decoded->msg_base, &finish, &wait_more);
            XQC_TEST_ASSERT(ret >= 0);
            XQC_TEST_ASSERT(finish == 0 && wait_more == 1);
            consumed = (size_t)ret;
        }
        finish = wait_more = 0;
        XQC_TEST_ASSERT(decoded->msg_base.decode(
            (uint8_t *)wire + 1 + consumed, body_len - consumed, 1,
            &ctx, &decoded->msg_base, &finish, &wait_more)
            == (xqc_int_t)(body_len - consumed));
        XQC_TEST_ASSERT(finish == 1 && wait_more == 0);
        XQC_TEST_ASSERT(decoded->end_of_track == 1);
        XQC_TEST_ASSERT(decoded->end_group_id == 3);
        XQC_TEST_ASSERT(decoded->end_object_id == 4);
        XQC_TEST_ASSERT(decoded->params_num == 0);
        XQC_TEST_ASSERT(decoded->track_properties_len == 0);
        xqc_moq_d18_fetch_ok_free(decoded);
    }
    return 0;
}

static int
xqc_test_track_status_wire_and_fragmented_decode(void)
{
    static const uint8_t wire[] = {
        0x0d, 0x00, 0x0c, 0x00,
        0x01, 0x02, 'n', 's', 0x05, 'v', 'i', 'd', 'e', 'o', 0x00,
    };
    xqc_moq_track_ns_field_t ns = {
        .data = (uint8_t *)"ns",
        .len = 2,
    };
    xqc_moq_track_status_msg_t msg = {
        .request_id = 0,
        .track_namespace_num = 1,
        .track_namespace_tuple = &ns,
        .track_name = "video",
        .track_name_len = 5,
    };
    uint8_t encoded[32] = {0};

    xqc_moq_d18_track_status_init_handler(&msg.msg_base);
    XQC_TEST_ASSERT(msg.msg_base.encode(
        &msg.msg_base, encoded, sizeof(encoded)) == (xqc_int_t)sizeof(wire));
    XQC_TEST_ASSERT(memcmp(encoded, wire, sizeof(wire)) == 0);

    for (size_t split = 0; split < sizeof(wire); split++) {
        xqc_moq_track_status_msg_t *decoded =
            xqc_moq_d18_track_status_create();
        xqc_moq_decode_msg_ctx_t ctx = {0};
        xqc_int_t finish = 0;
        xqc_int_t wait_more = 0;
        size_t body_len = sizeof(wire) - 1;
        size_t consumed = 0;
        XQC_TEST_ASSERT(decoded != NULL);
        if (split < body_len) {
            xqc_int_t ret = decoded->msg_base.decode(
                (uint8_t *)wire + 1, split, 0, &ctx,
                &decoded->msg_base, &finish, &wait_more);
            XQC_TEST_ASSERT(ret >= 0);
            XQC_TEST_ASSERT(finish == 0 && wait_more == 1);
            consumed = (size_t)ret;
        }
        finish = wait_more = 0;
        XQC_TEST_ASSERT(decoded->msg_base.decode(
            (uint8_t *)wire + 1 + consumed, body_len - consumed, 1,
            &ctx, &decoded->msg_base, &finish, &wait_more)
            == (xqc_int_t)(body_len - consumed));
        XQC_TEST_ASSERT(finish == 1 && wait_more == 0);
        XQC_TEST_ASSERT(decoded->request_id == 0);
        XQC_TEST_ASSERT(decoded->track_namespace_num == 1);
        XQC_TEST_ASSERT(decoded->track_name_len == 5);
        XQC_TEST_ASSERT(memcmp(decoded->track_name, "video", 5) == 0);
        xqc_moq_d18_track_status_free(decoded);
    }
    return 0;
}

static int
xqc_test_fetch_track_status_malformed(void)
{
    static uint8_t bad_fetch_type[] = {0x00, 0x03, 0x00, 0x04, 0x00};
    static uint8_t empty_fetch_namespace[] = {
        0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    static uint8_t bad_fetch_ok_eot[] = {0x00, 0x04, 0x02, 0x00, 0x00, 0x00};
    static uint8_t empty_status_namespace[] = {
        0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
    };
    xqc_int_t finish = 0;
    xqc_int_t wait_more = 0;

    xqc_moq_fetch_msg_t *fetch = xqc_moq_d18_fetch_create();
    XQC_TEST_ASSERT(fetch != NULL);
    XQC_TEST_ASSERT(xqc_test_decode_full(&fetch->msg_base,
        bad_fetch_type, sizeof(bad_fetch_type), &finish, &wait_more)
        == -XQC_EILLEGAL_FRAME);
    xqc_moq_d18_fetch_free(fetch);

    fetch = xqc_moq_d18_fetch_create();
    XQC_TEST_ASSERT(fetch != NULL);
    XQC_TEST_ASSERT(xqc_test_decode_full(&fetch->msg_base,
        empty_fetch_namespace, sizeof(empty_fetch_namespace),
        &finish, &wait_more) == -XQC_EILLEGAL_FRAME);
    xqc_moq_d18_fetch_free(fetch);

    xqc_moq_fetch_ok_msg_t *fetch_ok = xqc_moq_d18_fetch_ok_create();
    XQC_TEST_ASSERT(fetch_ok != NULL);
    XQC_TEST_ASSERT(xqc_test_decode_full(&fetch_ok->msg_base,
        bad_fetch_ok_eot, sizeof(bad_fetch_ok_eot), &finish, &wait_more)
        == -XQC_EILLEGAL_FRAME);
    xqc_moq_d18_fetch_ok_free(fetch_ok);

    xqc_moq_track_status_msg_t *status =
        xqc_moq_d18_track_status_create();
    XQC_TEST_ASSERT(status != NULL);
    XQC_TEST_ASSERT(xqc_test_decode_full(&status->msg_base,
        empty_status_namespace, sizeof(empty_status_namespace),
        &finish, &wait_more) == -XQC_EILLEGAL_FRAME);
    xqc_moq_d18_track_status_free(status);

    xqc_moq_fetch_msg_t invalid = {.fetch_type = 4};
    xqc_moq_d18_fetch_init_handler(&invalid.msg_base);
    XQC_TEST_ASSERT(invalid.msg_base.encode_len(&invalid.msg_base)
                    == -XQC_EPARAM);
    return 0;
}

static int
xqc_test_fetch_track_status_profile_dispatch(void)
{
    const xqc_moq_version_profile_t *profile = xqc_moq_v18_profile();
    static const struct {
        uint64_t wire_type;
        xqc_moq_semantic_id_t semantic;
    } cases[] = {
        {XQC_MOQ_D18_MSG_FETCH, XQC_MOQ_SEMANTIC_FETCH},
        {XQC_MOQ_D18_MSG_FETCH_OK, XQC_MOQ_SEMANTIC_FETCH_OK},
        {XQC_MOQ_D18_MSG_TRACK_STATUS, XQC_MOQ_SEMANTIC_TRACK_STATUS},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        const xqc_moq_message_codec_entry_t *codec =
            xqc_moq_profile_find_codec(
                profile, XQC_MOQ_STREAM_D18_REQUEST, cases[i].wire_type);
        XQC_TEST_ASSERT(codec != NULL);
        XQC_TEST_ASSERT(codec->semantic == cases[i].semantic);
        xqc_moq_message_resolution_t resolution;
        XQC_TEST_ASSERT(xqc_moq_profile_resolve_outbound(
            profile, XQC_MOQ_STREAM_UNKNOWN, cases[i].semantic,
            &resolution) == XQC_OK);
        XQC_TEST_ASSERT(resolution.wire_type == cases[i].wire_type);
        XQC_TEST_ASSERT(resolution.codec == codec);
    }
    return 0;
}

static int
xqc_test_track_status_request_ok_properties(void)
{
    static const uint8_t properties[] = {0x02, 0x01};
    static const uint8_t wire[] = {0x07, 0x00, 0x03, 0x00, 0x02, 0x01};
    xqc_moq_request_ok_msg_t msg = {
        .d18_param_context = XQC_MOQ_D18_PARAM_CONTEXT_TRACK_STATUS_OK,
        .track_properties = (uint8_t *)properties,
        .track_properties_len = sizeof(properties),
    };
    uint8_t encoded[32] = {0};
    xqc_moq_msg_request_ok_init_handler(&msg.msg_base);
    XQC_TEST_ASSERT(msg.msg_base.encode(
        &msg.msg_base, encoded, sizeof(encoded)) == (xqc_int_t)sizeof(wire));
    XQC_TEST_ASSERT(memcmp(encoded, wire, sizeof(wire)) == 0);

    for (size_t split = 0; split < sizeof(wire); split++) {
        xqc_moq_request_ok_msg_t *decoded = xqc_moq_msg_create_request_ok();
        xqc_moq_decode_msg_ctx_t ctx = {0};
        xqc_int_t finish = 0;
        xqc_int_t wait_more = 0;
        size_t body_len = sizeof(wire) - 1;
        size_t consumed = 0;
        XQC_TEST_ASSERT(decoded != NULL);
        decoded->d18_param_context =
            XQC_MOQ_D18_PARAM_CONTEXT_TRACK_STATUS_OK;
        if (split < body_len) {
            xqc_int_t ret = decoded->msg_base.decode(
                (uint8_t *)wire + 1, split, 0, &ctx,
                &decoded->msg_base, &finish, &wait_more);
            XQC_TEST_ASSERT(ret >= 0);
            XQC_TEST_ASSERT(finish == 0 && wait_more == 1);
            consumed = (size_t)ret;
        }
        finish = wait_more = 0;
        XQC_TEST_ASSERT(decoded->msg_base.decode(
            (uint8_t *)wire + 1 + consumed, body_len - consumed, 1,
            &ctx, &decoded->msg_base, &finish, &wait_more)
            == (xqc_int_t)(body_len - consumed));
        XQC_TEST_ASSERT(finish == 1 && wait_more == 0);
        XQC_TEST_ASSERT(decoded->params_num == 0);
        XQC_TEST_ASSERT(decoded->track_properties_len == sizeof(properties));
        XQC_TEST_ASSERT(memcmp(decoded->track_properties,
                               properties, sizeof(properties)) == 0);
        xqc_moq_msg_free_request_ok(decoded);
    }

    msg.d18_param_context = XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_OK;
    XQC_TEST_ASSERT(msg.msg_base.encode_len(&msg.msg_base) == -XQC_EPARAM);
    return 0;
}

static int
xqc_test_fetch_header_wire_and_profile(void)
{
    static const uint8_t wire[] = {0x05, 0x40};
    xqc_moq_fetch_header_msg_t msg = {.request_id = 64};
    uint8_t encoded[8] = {0};
    xqc_moq_d18_fetch_header_init_handler(&msg.msg_base);
    XQC_TEST_ASSERT(msg.msg_base.encode(
        &msg.msg_base, encoded, sizeof(encoded)) == (xqc_int_t)sizeof(wire));
    XQC_TEST_ASSERT(memcmp(encoded, wire, sizeof(wire)) == 0);

    for (size_t split = 0; split < sizeof(wire); split++) {
        xqc_moq_fetch_header_msg_t *decoded =
            xqc_moq_d18_fetch_header_create();
        xqc_moq_decode_msg_ctx_t ctx = {0};
        xqc_int_t finish = 0;
        xqc_int_t wait_more = 0;
        size_t body_len = sizeof(wire) - 1;
        size_t consumed = 0;
        XQC_TEST_ASSERT(decoded != NULL);
        if (split < body_len) {
            xqc_int_t ret = decoded->msg_base.decode(
                (uint8_t *)wire + 1, split, 0, &ctx,
                &decoded->msg_base, &finish, &wait_more);
            XQC_TEST_ASSERT(ret >= 0);
            XQC_TEST_ASSERT(finish == 0 && wait_more == 1);
            consumed = (size_t)ret;
        }
        finish = wait_more = 0;
        XQC_TEST_ASSERT(decoded->msg_base.decode(
            (uint8_t *)wire + 1 + consumed, body_len - consumed, 1,
            &ctx, &decoded->msg_base, &finish, &wait_more)
            == (xqc_int_t)(body_len - consumed));
        XQC_TEST_ASSERT(finish == 1 && wait_more == 0);
        XQC_TEST_ASSERT(decoded->request_id == 64);
        XQC_TEST_ASSERT(decoded->fin_received == 1);
        xqc_moq_d18_fetch_header_free(decoded);
    }

    const xqc_moq_message_codec_entry_t *codec =
        xqc_moq_profile_find_codec(xqc_moq_v18_profile(),
            XQC_MOQ_STREAM_D18_FETCH, XQC_MOQ_D18_STREAM_TYPE_FETCH);
    XQC_TEST_ASSERT(codec != NULL);
    XQC_TEST_ASSERT(codec->semantic == XQC_MOQ_SEMANTIC_FETCH_HEADER);
    xqc_moq_message_resolution_t resolution;
    XQC_TEST_ASSERT(xqc_moq_profile_resolve_outbound(
        xqc_moq_v18_profile(), XQC_MOQ_STREAM_UNKNOWN,
        XQC_MOQ_SEMANTIC_FETCH_HEADER, &resolution) == XQC_OK);
    XQC_TEST_ASSERT(resolution.stream_kind == XQC_MOQ_STREAM_D18_FETCH);
    return 0;
}

static void
xqc_test_init_peer_request_session(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, xqc_moq_user_session_t *user_session,
    xqc_engine_t *engine, xqc_test_setup_write_capture_t *capture)
{
    memset(session, 0, sizeof(*session));
    memset(stream, 0, sizeof(*stream));
    memset(user_session, 0, sizeof(*user_session));
    memset(engine, 0, sizeof(*engine));
    engine->eng_type = XQC_ENGINE_SERVER;
    session->engine = engine;
    session->user_session = user_session;
    user_session->session = session;
    session->profile = xqc_moq_v18_profile();
    session->profile_state = XQC_MOQ_PROFILE_ACTIVE;
    session->version = XQC_MOQ_VERSION_18;
    session->use_unified_setup = 1;
    session->session_setup_done = 1;
    session->log = &xqc_test_setup_log;
    xqc_init_list_head(&session->local_subscribe_list);
    xqc_init_list_head(&session->peer_subscribe_list);
    xqc_init_list_head(&session->track_list_for_sub);
    xqc_init_list_head(&session->track_list_for_pub);
    xqc_init_list_head(&session->local_request_stream_list);
    xqc_init_list_head(&session->peer_request_stream_list);
    xqc_moq_d18_request_registry_init(&session->d18_request_registry, 1);
    xqc_moq_d18_auth_cache_init(&session->peer_auth_cache, 0);

    stream->session = session;
    stream->kind = XQC_MOQ_STREAM_D18_REQUEST;
    stream->d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream->d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream->d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    stream->trans_stream = capture;
    stream->trans_ops.write = xqc_test_setup_capture_write;
    xqc_init_list_head(&stream->request_list_member);
    xqc_moq_d18_update_queue_init(&stream->d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&stream->d18_peer_update_queue);
}

static xqc_int_t xqc_test_track_status_response_ret;

static void
xqc_test_on_track_status_respond_ok(xqc_moq_user_session_t *user_session,
    xqc_moq_track_status_msg_t *msg)
{
    static uint8_t properties[] = {0x02, 0x01};
    xqc_moq_request_ok_msg_t response = {
        .track_properties = properties,
        .track_properties_len = sizeof(properties),
    };
    xqc_test_track_status_response_ret = xqc_moq_write_request_ok(
        user_session->session, msg->request_id, &response);
}

static int
xqc_test_track_status_success_finishes_without_subscription(void)
{
    static const uint8_t expected[] = {
        XQC_MOQ_D18_MSG_REQUEST_OK, 0x00, 0x03, 0x00, 0x02, 0x01,
    };
    xqc_moq_session_t session;
    xqc_moq_stream_t stream;
    xqc_moq_user_session_t user_session;
    xqc_engine_t engine;
    xqc_test_setup_write_capture_t capture = {0};
    xqc_moq_track_ns_field_t ns = {
        .data = (uint8_t *)"ns",
        .len = 2,
    };
    xqc_moq_track_status_msg_t status = {
        .request_id = 0,
        .track_namespace_num = 1,
        .track_namespace_tuple = &ns,
        .track_name = "video",
        .track_name_len = 5,
    };

    xqc_test_init_peer_request_session(
        &session, &stream, &user_session, &engine, &capture);
    session.session_callbacks_ext.on_track_status =
        xqc_test_on_track_status_respond_ok;
    xqc_test_track_status_response_ret = -XQC_ERROR;
    xqc_moq_on_track_status(&session, &stream, &status.msg_base);

    XQC_TEST_ASSERT(xqc_test_track_status_response_ret == XQC_OK);
    XQC_TEST_ASSERT(stream.response_sent == 1);
    XQC_TEST_ASSERT(stream.request_closed_notified == 1);
    XQC_TEST_ASSERT(capture.last_fin == 1);
    XQC_TEST_ASSERT(capture.data_len == sizeof(expected));
    XQC_TEST_ASSERT(memcmp(capture.data, expected, sizeof(expected)) == 0);
    XQC_TEST_ASSERT(xqc_list_empty(&session.local_subscribe_list));
    XQC_TEST_ASSERT(xqc_list_empty(&session.peer_subscribe_list));

    free(stream.write_buf);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static int
xqc_test_subscribe_error_uses_request_error_and_fin(void)
{
    xqc_moq_session_t session;
    xqc_moq_stream_t stream;
    xqc_moq_user_session_t user_session;
    xqc_engine_t engine;
    xqc_test_setup_write_capture_t capture = {0};
    xqc_moq_subscribe_error_msg_t error = {
        .subscribe_id = 0,
        .error_code = XQC_MOQ_REQUEST_ERROR_DOES_NOT_EXIST,
        .reason_phrase = "track does not exist",
        .reason_phrase_len = sizeof("track does not exist") - 1,
    };

    xqc_test_init_peer_request_session(
        &session, &stream, &user_session, &engine, &capture);
    stream.peer_request = 1;
    stream.request_id = 0;
    stream.request_type = XQC_MOQ_MSG_SUBSCRIBE;
    xqc_list_add_tail(
        &stream.request_list_member, &session.peer_request_stream_list);

    XQC_TEST_ASSERT(xqc_moq_write_subscribe_error(&session, &error)
                    == XQC_OK);
    XQC_TEST_ASSERT(stream.response_sent == 1);
    XQC_TEST_ASSERT(stream.request_closed_notified == 1);
    XQC_TEST_ASSERT(capture.last_fin == 1);
    XQC_TEST_ASSERT(capture.data_len >= 4);
    XQC_TEST_ASSERT(capture.data[0] == XQC_MOQ_D18_MSG_REQUEST_ERROR);
    XQC_TEST_ASSERT(capture.data[3]
                    == XQC_MOQ_REQUEST_ERROR_DOES_NOT_EXIST);

    if (!xqc_list_empty(&stream.request_list_member)) {
        xqc_list_del_init(&stream.request_list_member);
    }
    free(stream.write_buf);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

static int
xqc_test_unhandled_fetch_and_track_status_return_not_supported(void)
{
    xqc_moq_session_t session;
    xqc_moq_stream_t stream;
    xqc_moq_user_session_t user_session;
    xqc_engine_t engine;
    xqc_test_setup_write_capture_t capture = {0};
    xqc_moq_track_ns_field_t ns = {
        .data = (uint8_t *)"ns",
        .len = 2,
    };
    xqc_moq_track_status_msg_t status = {
        .request_id = 0,
        .track_namespace_num = 1,
        .track_namespace_tuple = &ns,
        .track_name = "video",
        .track_name_len = 5,
    };

    xqc_test_init_peer_request_session(
        &session, &stream, &user_session, &engine, &capture);
    xqc_moq_on_track_status(&session, &stream, &status.msg_base);
    XQC_TEST_ASSERT(stream.request_type
                    == (xqc_moq_msg_type_t)XQC_MOQ_D18_MSG_TRACK_STATUS);
    XQC_TEST_ASSERT(stream.response_sent == 1);
    XQC_TEST_ASSERT(stream.request_closed_notified == 1);
    XQC_TEST_ASSERT(capture.last_fin == 1);
    XQC_TEST_ASSERT(capture.data_len >= 4);
    XQC_TEST_ASSERT(capture.data[0] == XQC_MOQ_D18_MSG_REQUEST_ERROR);
    XQC_TEST_ASSERT(capture.data[3] == XQC_MOQ_REQUEST_ERROR_NOT_SUPPORTED);
    XQC_TEST_ASSERT(xqc_list_empty(&session.local_subscribe_list));
    XQC_TEST_ASSERT(xqc_list_empty(&session.peer_subscribe_list));
    free(stream.write_buf);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);

    memset(&capture, 0, sizeof(capture));
    xqc_test_init_peer_request_session(
        &session, &stream, &user_session, &engine, &capture);
    xqc_moq_fetch_msg_t fetch = {
        .request_id = 0,
        .fetch_type = XQC_MOQ_FETCH_STANDALONE,
        .track_namespace_num = 1,
        .track_namespace_tuple = &ns,
        .track_name = "video",
        .track_name_len = 5,
        .start_group_id = 0,
        .start_object_id = 0,
        .end_group_id = 1,
        .end_object_id = 0,
    };
    xqc_moq_on_fetch(&session, &stream, &fetch.msg_base);
    XQC_TEST_ASSERT(stream.request_type == XQC_MOQ_MSG_FETCH);
    XQC_TEST_ASSERT(stream.response_sent == 1);
    XQC_TEST_ASSERT(stream.request_closed_notified == 1);
    XQC_TEST_ASSERT(capture.last_fin == 1);
    XQC_TEST_ASSERT(capture.data[0] == XQC_MOQ_D18_MSG_REQUEST_ERROR);
    XQC_TEST_ASSERT(capture.data[3] == XQC_MOQ_REQUEST_ERROR_NOT_SUPPORTED);
    free(stream.write_buf);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static void
xqc_test_init_outbound_d18_stream(xqc_moq_stream_t *stream,
    xqc_moq_session_t *session, xqc_test_setup_write_capture_t *capture,
    uint8_t direction)
{
    memset(stream, 0, sizeof(*stream));
    stream->session = session;
    stream->kind = XQC_MOQ_STREAM_UNKNOWN;
    stream->d18_context.direction = direction;
    stream->d18_context.position = XQC_MOQ_D18_POSITION_FIRST;
    stream->trans_stream = capture;
    stream->trans_ops.write = xqc_test_setup_capture_write;
    xqc_init_list_head(&stream->request_list_member);
    xqc_moq_d18_update_queue_init(&stream->d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&stream->d18_peer_update_queue);
}

static int
xqc_test_fetch_track_status_and_empty_fetch_writers(void)
{
    static const uint8_t fetch_wire[] = {
        0x16, 0x00, 0x11, 0x01, 0x01, 0x01, 0x02, 'n', 's',
        0x05, 'v', 'i', 'd', 'e', 'o', 0x01, 0x02, 0x03, 0x04, 0x00,
    };
    static const uint8_t status_wire[] = {
        0x0d, 0x00, 0x0c, 0x03, 0x01, 0x02, 'n', 's',
        0x05, 'v', 'i', 'd', 'e', 'o', 0x00,
    };
    static const uint8_t fetch_ok_wire[] = {
        0x18, 0x00, 0x04, 0x01, 0x03, 0x04, 0x00,
    };
    static const uint8_t fetch_header_wire[] = {0x05, 0x05};
    xqc_moq_session_t session;
    xqc_moq_stream_t seed_stream;
    xqc_moq_user_session_t user_session;
    xqc_engine_t engine;
    xqc_test_setup_write_capture_t seed_capture = {0};
    xqc_moq_track_ns_field_t ns = {
        .data = (uint8_t *)"ns",
        .len = 2,
    };
    xqc_test_init_peer_request_session(
        &session, &seed_stream, &user_session, &engine, &seed_capture);

    xqc_moq_stream_t fetch_stream;
    xqc_test_setup_write_capture_t fetch_capture = {0};
    xqc_test_init_outbound_d18_stream(&fetch_stream, &session,
        &fetch_capture, XQC_MOQ_D18_DIRECTION_BIDI);
    xqc_moq_fetch_msg_t fetch = {
        .request_id = 1,
        .fetch_type = XQC_MOQ_FETCH_STANDALONE,
        .track_namespace_num = 1,
        .track_namespace_tuple = &ns,
        .track_name = "video",
        .track_name_len = 5,
        .start_group_id = 1,
        .start_object_id = 2,
        .end_group_id = 3,
        .end_object_id = 4,
    };
    XQC_TEST_ASSERT(xqc_moq_write_fetch(
        &session, &fetch_stream, &fetch) == XQC_OK);
    XQC_TEST_ASSERT(fetch_stream.local_request == 1);
    XQC_TEST_ASSERT(fetch_stream.request_type == XQC_MOQ_MSG_FETCH);
    XQC_TEST_ASSERT(fetch_capture.data_len == sizeof(fetch_wire));
    XQC_TEST_ASSERT(memcmp(fetch_capture.data, fetch_wire,
                           sizeof(fetch_wire)) == 0);

    xqc_moq_stream_t status_stream;
    xqc_test_setup_write_capture_t status_capture = {0};
    xqc_test_init_outbound_d18_stream(&status_stream, &session,
        &status_capture, XQC_MOQ_D18_DIRECTION_BIDI);
    xqc_moq_track_status_msg_t status = {
        .request_id = 3,
        .track_namespace_num = 1,
        .track_namespace_tuple = &ns,
        .track_name = "video",
        .track_name_len = 5,
    };
    XQC_TEST_ASSERT(xqc_moq_write_track_status(
        &session, &status_stream, &status) == XQC_OK);
    XQC_TEST_ASSERT(status_stream.local_request == 1);
    XQC_TEST_ASSERT(status_stream.request_type
                    == (xqc_moq_msg_type_t)XQC_MOQ_D18_MSG_TRACK_STATUS);
    XQC_TEST_ASSERT(status_capture.data_len == sizeof(status_wire));
    XQC_TEST_ASSERT(memcmp(status_capture.data, status_wire,
                           sizeof(status_wire)) == 0);

    xqc_moq_stream_t peer_fetch;
    xqc_test_setup_write_capture_t ok_capture = {0};
    xqc_test_init_outbound_d18_stream(&peer_fetch, &session,
        &ok_capture, XQC_MOQ_D18_DIRECTION_BIDI);
    peer_fetch.kind = XQC_MOQ_STREAM_D18_REQUEST;
    peer_fetch.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    peer_fetch.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    peer_fetch.peer_request = 1;
    peer_fetch.request_type = XQC_MOQ_MSG_FETCH;
    peer_fetch.request_id = 5;
    xqc_list_add_tail(&peer_fetch.request_list_member,
                      &session.peer_request_stream_list);
    xqc_moq_fetch_ok_msg_t fetch_ok = {
        .end_of_track = 1,
        .end_group_id = 3,
        .end_object_id = 4,
    };
    XQC_TEST_ASSERT(xqc_moq_write_fetch_ok(
        &session, 5, &fetch_ok) == XQC_OK);
    XQC_TEST_ASSERT(peer_fetch.response_sent == 1);
    XQC_TEST_ASSERT(ok_capture.last_fin == 0);
    XQC_TEST_ASSERT(ok_capture.data_len == sizeof(fetch_ok_wire));
    XQC_TEST_ASSERT(memcmp(ok_capture.data, fetch_ok_wire,
                           sizeof(fetch_ok_wire)) == 0);

    xqc_moq_stream_t data_stream;
    xqc_test_setup_write_capture_t data_capture = {0};
    xqc_test_init_outbound_d18_stream(&data_stream, &session,
        &data_capture, XQC_MOQ_D18_DIRECTION_UNI);
    xqc_moq_fetch_header_msg_t header = {.request_id = 5};
    XQC_TEST_ASSERT(xqc_moq_write_fetch_header(
        &session, &data_stream, &header, 1) == XQC_OK);
    XQC_TEST_ASSERT(data_stream.kind == XQC_MOQ_STREAM_D18_FETCH);
    XQC_TEST_ASSERT(data_capture.last_fin == 1);
    XQC_TEST_ASSERT(data_capture.data_len == sizeof(fetch_header_wire));
    XQC_TEST_ASSERT(memcmp(data_capture.data, fetch_header_wire,
                           sizeof(fetch_header_wire)) == 0);
    XQC_TEST_ASSERT(peer_fetch.request_closed_notified == 1);

    xqc_list_del_init(&fetch_stream.request_list_member);
    xqc_list_del_init(&status_stream.request_list_member);
    xqc_list_del_init(&peer_fetch.request_list_member);
    free(fetch_stream.write_buf);
    free(status_stream.write_buf);
    free(peer_fetch.write_buf);
    free(data_stream.write_buf);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    return 0;
}

static int xqc_test_fetch_ok_callback_count;
static int xqc_test_fetch_header_callback_count;
static int xqc_test_fetch_complete_callback_count;
static int xqc_test_track_status_ok_callback_count;
static int xqc_test_finite_request_cancelled_count;
static uint64_t xqc_test_fetch_callback_request_id;
static uint64_t xqc_test_fetch_complete_error;
static uint8_t xqc_test_fetch_callback_fin;

static void
xqc_test_on_finite_request_cancelled(xqc_moq_user_session_t *user_session,
    uint64_t request_id, xqc_moq_msg_type_t request_type,
    uint8_t locally_initiated, uint64_t error_code)
{
    (void)user_session;
    (void)request_id;
    (void)request_type;
    (void)locally_initiated;
    (void)error_code;
    xqc_test_finite_request_cancelled_count++;
}

static void
xqc_test_on_fetch_ok(xqc_moq_user_session_t *user_session,
    uint64_t request_id, xqc_moq_fetch_ok_msg_t *msg)
{
    (void)user_session;
    if (msg->end_group_id != 3 || msg->end_object_id != 4) {
        xqc_test_fetch_ok_callback_count = -100;
        return;
    }
    xqc_test_fetch_callback_request_id = request_id;
    xqc_test_fetch_ok_callback_count++;
}

static void
xqc_test_on_fetch_header(xqc_moq_user_session_t *user_session,
    uint64_t request_id, uint8_t fin)
{
    (void)user_session;
    xqc_test_fetch_callback_request_id = request_id;
    xqc_test_fetch_callback_fin = fin;
    xqc_test_fetch_header_callback_count++;
}

static void
xqc_test_on_fetch_complete(xqc_moq_user_session_t *user_session,
    uint64_t request_id, uint64_t error_code)
{
    (void)user_session;
    xqc_test_fetch_callback_request_id = request_id;
    xqc_test_fetch_complete_error = error_code;
    xqc_test_fetch_complete_callback_count++;
}

static void
xqc_test_on_track_status_ok(xqc_moq_user_session_t *user_session,
    uint64_t request_id, xqc_moq_request_ok_msg_t *msg)
{
    (void)user_session;
    if (request_id != 3 || msg->track_properties_len != 2) {
        xqc_test_track_status_ok_callback_count = -100;
        return;
    }
    xqc_test_track_status_ok_callback_count++;
}

static int
xqc_test_fetch_and_track_status_receive_lifecycle(void)
{
    xqc_moq_session_t session;
    xqc_moq_stream_t seed_stream;
    xqc_moq_user_session_t user_session;
    xqc_engine_t engine;
    xqc_test_setup_write_capture_t seed_capture = {0};
    xqc_test_init_peer_request_session(
        &session, &seed_stream, &user_session, &engine, &seed_capture);
    xqc_moq_session_callbacks_ext_t callbacks_ext = {
        .struct_size = sizeof(callbacks_ext),
        .abi_version = XQC_MOQ_SESSION_CALLBACKS_EXT_ABI_VERSION,
        .on_fetch_ok = xqc_test_on_fetch_ok,
        .on_fetch_header = xqc_test_on_fetch_header,
        .on_fetch_complete = xqc_test_on_fetch_complete,
        .on_track_status_ok = xqc_test_on_track_status_ok,
    };
    XQC_TEST_ASSERT(xqc_moq_session_set_callbacks_ext(
        &session, &callbacks_ext) == XQC_OK);
    session.on_request_cancelled =
        xqc_test_on_finite_request_cancelled;

    xqc_moq_stream_t fetch_request;
    xqc_test_setup_write_capture_t fetch_capture = {0};
    xqc_test_init_outbound_d18_stream(&fetch_request, &session,
        &fetch_capture, XQC_MOQ_D18_DIRECTION_BIDI);
    fetch_request.kind = XQC_MOQ_STREAM_D18_REQUEST;
    fetch_request.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    fetch_request.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    fetch_request.local_request = 1;
    fetch_request.request_type = XQC_MOQ_MSG_FETCH;
    fetch_request.request_id = 1;
    fetch_request.d18_fetch_type = XQC_MOQ_FETCH_STANDALONE;
    fetch_request.d18_fetch_start_group_id = 1;
    fetch_request.d18_fetch_start_object_id = 2;
    xqc_list_add_tail(&fetch_request.request_list_member,
                      &session.local_request_stream_list);

    xqc_test_fetch_ok_callback_count = 0;
    xqc_test_fetch_header_callback_count = 0;
    xqc_test_fetch_complete_callback_count = 0;
    xqc_test_fetch_complete_error = UINT64_MAX;
    xqc_moq_fetch_ok_msg_t fetch_ok = {
        .end_of_track = 1,
        .end_group_id = 3,
        .end_object_id = 4,
    };
    xqc_moq_on_fetch_ok(&session, &fetch_request, &fetch_ok.msg_base);
    XQC_TEST_ASSERT(fetch_request.response_received == 1);
    XQC_TEST_ASSERT(fetch_request.request_closed_notified == 0);
    XQC_TEST_ASSERT(xqc_test_fetch_ok_callback_count == 1);
    XQC_TEST_ASSERT(xqc_test_fetch_callback_request_id == 1);

    xqc_moq_stream_t fetch_data;
    xqc_test_setup_write_capture_t data_capture = {0};
    xqc_test_init_outbound_d18_stream(&fetch_data, &session,
        &data_capture, XQC_MOQ_D18_DIRECTION_UNI);
    fetch_data.kind = XQC_MOQ_STREAM_D18_FETCH;
    fetch_data.d18_context.stream_class = XQC_MOQ_D18_STREAM_FETCH;
    fetch_data.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    xqc_moq_fetch_header_msg_t header = {
        .request_id = 1,
        .fin_received = 0,
    };
    {
        uint8_t header_and_object[] = {0x01, 0xaa};
        xqc_moq_fetch_header_msg_t decoded_header = {0};
        xqc_moq_decode_msg_ctx_t decode_ctx = {0};
        xqc_int_t finish = 0;
        xqc_int_t wait_more = 0;
        xqc_moq_d18_fetch_header_init_handler(&decoded_header.msg_base);
        XQC_TEST_ASSERT(xqc_moq_d18_fetch_header_decode(
            header_and_object, sizeof(header_and_object), 1,
            &decode_ctx, &decoded_header.msg_base, &finish, &wait_more) == 1);
        XQC_TEST_ASSERT(finish == 1);
        XQC_TEST_ASSERT(wait_more == 0);
        XQC_TEST_ASSERT(decoded_header.request_id == 1);
        XQC_TEST_ASSERT(decoded_header.fin_received == 0);
    }
    xqc_moq_on_fetch_header(&session, &fetch_data, &header.msg_base);
    XQC_TEST_ASSERT(xqc_test_fetch_header_callback_count == 1);
    XQC_TEST_ASSERT(xqc_test_fetch_callback_request_id == 1);
    XQC_TEST_ASSERT(xqc_test_fetch_callback_fin == 0);
    XQC_TEST_ASSERT(fetch_request.request_closed_notified == 0);
    XQC_TEST_ASSERT(fetch_request.fetch_data_stream == &fetch_data);
    xqc_test_finite_request_cancelled_count = 0;
    XQC_TEST_ASSERT(xqc_moq_stream_process(
        &fetch_data, NULL, 0, 1) == 0);
    XQC_TEST_ASSERT(fetch_data.peer_fin_received == 1);
    XQC_TEST_ASSERT(fetch_request.request_closed_notified == 1);
    XQC_TEST_ASSERT(fetch_request.fetch_data_stream == NULL);
    XQC_TEST_ASSERT(fetch_data.fetch_request_stream == NULL);
    XQC_TEST_ASSERT(xqc_test_finite_request_cancelled_count == 0);
    XQC_TEST_ASSERT(xqc_test_fetch_complete_callback_count == 1);
    XQC_TEST_ASSERT(xqc_test_fetch_callback_request_id == 1);
    XQC_TEST_ASSERT(xqc_test_fetch_complete_error == XQC_OK);

    xqc_moq_stream_t status_request;
    xqc_test_setup_write_capture_t status_capture = {0};
    xqc_test_init_outbound_d18_stream(&status_request, &session,
        &status_capture, XQC_MOQ_D18_DIRECTION_BIDI);
    status_request.kind = XQC_MOQ_STREAM_D18_REQUEST;
    status_request.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    status_request.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    status_request.local_request = 1;
    status_request.request_type =
        (xqc_moq_msg_type_t)XQC_MOQ_D18_MSG_TRACK_STATUS;
    status_request.request_id = 3;
    xqc_list_add_tail(&status_request.request_list_member,
                      &session.local_request_stream_list);
    uint8_t properties[] = {0x02, 0x01};
    xqc_moq_request_ok_msg_t status_ok = {
        .track_properties = properties,
        .track_properties_len = sizeof(properties),
        .d18_param_context = XQC_MOQ_D18_PARAM_CONTEXT_TRACK_STATUS_OK,
    };
    xqc_test_track_status_ok_callback_count = 0;
    xqc_moq_on_request_ok(&session, &status_request, &status_ok.msg_base);
    XQC_TEST_ASSERT(status_request.response_received == 1);
    XQC_TEST_ASSERT(xqc_test_track_status_ok_callback_count == 1);
    xqc_test_finite_request_cancelled_count = 0;
    XQC_TEST_ASSERT(xqc_moq_stream_process(
        &status_request, NULL, 0, 1) == 0);
    XQC_TEST_ASSERT(status_request.peer_fin_received == 1);
    XQC_TEST_ASSERT(status_request.request_closed_notified == 1);
    XQC_TEST_ASSERT(xqc_test_finite_request_cancelled_count == 0);

    xqc_list_del_init(&fetch_request.request_list_member);
    xqc_list_del_init(&status_request.request_list_member);
    free(fetch_request.write_buf);
    free(fetch_data.write_buf);
    free(status_request.write_buf);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    return 0;
}

static int xqc_test_incoming_fetch_callback_count;

static void
xqc_test_on_incoming_fetch(xqc_moq_user_session_t *user_session,
    xqc_moq_fetch_msg_t *msg)
{
    (void)user_session;
    (void)msg;
    xqc_test_incoming_fetch_callback_count++;
}

static int
xqc_test_fetch_state_rules_precede_application_callback(void)
{
    enum {
        XQC_TEST_FETCH_BAD_RANGE,
        XQC_TEST_FETCH_BAD_JOINING_ID,
        XQC_TEST_FETCH_FORWARD_ZERO,
        XQC_TEST_FETCH_FORWARD_ONE,
    } cases[] = {
        XQC_TEST_FETCH_BAD_RANGE,
        XQC_TEST_FETCH_BAD_JOINING_ID,
        XQC_TEST_FETCH_FORWARD_ZERO,
        XQC_TEST_FETCH_FORWARD_ONE,
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        xqc_moq_session_t session;
        xqc_moq_stream_t seed_stream;
        xqc_moq_user_session_t user_session;
        xqc_engine_t engine;
        xqc_test_setup_write_capture_t seed_capture = {0};
        xqc_test_init_peer_request_session(
            &session, &seed_stream, &user_session, &engine, &seed_capture);
        session.session_callbacks_ext.on_fetch = xqc_test_on_incoming_fetch;

        xqc_moq_message_parameter_t forward = {
            .type = XQC_MOQ_D18_PARAM_FORWARD,
            .is_integer = 1,
            .int_value = cases[i] == XQC_TEST_FETCH_FORWARD_ONE ? 1 : 0,
        };
        xqc_moq_stream_t subscription;
        xqc_test_setup_write_capture_t subscription_capture = {0};
        if (cases[i] == XQC_TEST_FETCH_FORWARD_ZERO
            || cases[i] == XQC_TEST_FETCH_FORWARD_ONE)
        {
            xqc_test_init_outbound_d18_stream(&subscription, &session,
                &subscription_capture, XQC_MOQ_D18_DIRECTION_BIDI);
            subscription.kind = XQC_MOQ_STREAM_D18_REQUEST;
            subscription.d18_context.stream_class =
                XQC_MOQ_D18_STREAM_REQUEST;
            subscription.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
            subscription.peer_request = 1;
            subscription.request_type = XQC_MOQ_MSG_SUBSCRIBE;
            subscription.request_id = 0;
            subscription.response_sent = 1;
            subscription.d18_accepted_params = &forward;
            subscription.d18_accepted_params_num = 1;
            xqc_list_add_tail(&subscription.request_list_member,
                              &session.peer_request_stream_list);
            XQC_TEST_ASSERT(xqc_moq_session_register_peer_request_id(
                &session, 0) == XQC_MOQ_D18_REQUEST_ID_OK);
        }

        xqc_moq_stream_t fetch_stream;
        xqc_test_setup_write_capture_t capture = {0};
        xqc_test_init_outbound_d18_stream(&fetch_stream, &session,
            &capture, XQC_MOQ_D18_DIRECTION_BIDI);
        fetch_stream.kind = XQC_MOQ_STREAM_D18_REQUEST;
        fetch_stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
        fetch_stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
        xqc_moq_fetch_msg_t fetch = {
            .request_id = cases[i] == XQC_TEST_FETCH_BAD_RANGE ? 0 : 2,
            .fetch_type = cases[i] == XQC_TEST_FETCH_BAD_RANGE
                ? XQC_MOQ_FETCH_STANDALONE
                : XQC_MOQ_FETCH_JOINING_ABSOLUTE,
            .joining_request_id = cases[i]
                    == XQC_TEST_FETCH_BAD_JOINING_ID
                ? 42 : 0,
            .joining_start = 1,
            .start_group_id = 5,
            .start_object_id = 0,
            .end_group_id = 4,
            .end_object_id = 0,
        };
        xqc_moq_track_ns_field_t ns = {
            .data = (uint8_t *)"ns",
            .len = 2,
        };
        if (cases[i] == XQC_TEST_FETCH_BAD_RANGE) {
            fetch.track_namespace_num = 1;
            fetch.track_namespace_tuple = &ns;
            fetch.track_name = "video";
            fetch.track_name_len = 5;
        }

        xqc_test_incoming_fetch_callback_count = 0;
        xqc_moq_on_fetch(&session, &fetch_stream, &fetch.msg_base);
        if (cases[i] == XQC_TEST_FETCH_FORWARD_ONE) {
            XQC_TEST_ASSERT(xqc_test_incoming_fetch_callback_count == 1);
            XQC_TEST_ASSERT(capture.data_len == 0);

        } else {
            uint8_t expected_error = cases[i]
                    == XQC_TEST_FETCH_BAD_JOINING_ID
                ? 0x32 : 0x11;
            XQC_TEST_ASSERT(xqc_test_incoming_fetch_callback_count == 0);
            XQC_TEST_ASSERT(capture.data_len >= 4);
            XQC_TEST_ASSERT(capture.data[0]
                            == XQC_MOQ_D18_MSG_REQUEST_ERROR);
            XQC_TEST_ASSERT(capture.data[3] == expected_error);
            XQC_TEST_ASSERT(capture.last_fin == 1);
        }

        xqc_list_del_init(&fetch_stream.request_list_member);
        free(fetch_stream.write_buf);
        if (cases[i] == XQC_TEST_FETCH_FORWARD_ZERO
            || cases[i] == XQC_TEST_FETCH_FORWARD_ONE)
        {
            subscription.d18_accepted_params = NULL;
            subscription.d18_accepted_params_num = 0;
            xqc_list_del_init(&subscription.request_list_member);
            free(subscription.write_buf);
        }
        xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
        xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    }
    return 0;
}

static xqc_int_t
xqc_test_decode_full(xqc_moq_msg_base_t *base, uint8_t *body,
    size_t body_len, xqc_int_t *finish, xqc_int_t *wait_more)
{
    xqc_moq_decode_msg_ctx_t ctx = {0};
    *finish = 0;
    *wait_more = 0;
    return base->decode(body, body_len, 1, &ctx, base, finish, wait_more);
}

static int
xqc_test_request_update_malformed(void)
{
    static uint8_t truncated_length[] = {0x00};
    static uint8_t truncated_payload[] = {
        0x00, 0x04, 0x00, 0x01, 0x10,
    };
    static uint8_t trailing_payload[] = {
        0x00, 0x05, 0x00, 0x01, 0x10, 0x00, 0x00,
    };
    static uint8_t malformed_param[] = {
        0x00, 0x03, 0x00, 0x01, 0x10,
    };
    static uint8_t wrong_scope[] = {
        0x00, 0x04, 0x00, 0x01, 0x10, 0x00,
    };
    static uint8_t excessive_params[] = {
        0x00, 0x02, 0x00, 0x0b,
    };
    xqc_int_t finish = 0;
    xqc_int_t wait_more = 0;

    xqc_moq_request_update_msg_t *msg =
        xqc_moq_d18_request_update_create();
    XQC_TEST_ASSERT(msg != NULL);
    XQC_TEST_ASSERT(xqc_test_decode_full(&msg->msg_base,
        truncated_length, sizeof(truncated_length),
        &finish, &wait_more) == -XQC_EILLEGAL_FRAME);
    xqc_moq_d18_request_update_free(msg);

    msg = xqc_moq_d18_request_update_create();
    XQC_TEST_ASSERT(msg != NULL);
    XQC_TEST_ASSERT(xqc_test_decode_full(&msg->msg_base,
        truncated_payload, sizeof(truncated_payload),
        &finish, &wait_more) == -XQC_EILLEGAL_FRAME);
    xqc_moq_d18_request_update_free(msg);

    msg = xqc_moq_d18_request_update_create();
    XQC_TEST_ASSERT(msg != NULL);
    XQC_TEST_ASSERT(xqc_test_decode_full(&msg->msg_base,
        trailing_payload, sizeof(trailing_payload),
        &finish, &wait_more) == -XQC_EILLEGAL_FRAME);
    XQC_TEST_ASSERT(msg->d18_error_code
                    == XQC_MOQ_D18_KEY_VALUE_FORMATTING_ERROR);
    xqc_moq_d18_request_update_free(msg);

    msg = xqc_moq_d18_request_update_create();
    XQC_TEST_ASSERT(msg != NULL);
    XQC_TEST_ASSERT(xqc_test_decode_full(&msg->msg_base,
        malformed_param, sizeof(malformed_param),
        &finish, &wait_more) == -XQC_EILLEGAL_FRAME);
    XQC_TEST_ASSERT(msg->d18_error_code
                    == XQC_MOQ_D18_KEY_VALUE_FORMATTING_ERROR);
    xqc_moq_d18_request_update_free(msg);

    msg = xqc_moq_d18_request_update_create();
    XQC_TEST_ASSERT(msg != NULL);
    xqc_moq_d18_request_update_init_handler(&msg->msg_base,
        XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_NAMESPACE);
    XQC_TEST_ASSERT(xqc_test_decode_full(&msg->msg_base,
        wrong_scope, sizeof(wrong_scope),
        &finish, &wait_more) == -XQC_EPROTO);
    XQC_TEST_ASSERT(msg->d18_error_code
                    == XQC_MOQ_D18_PROTOCOL_VIOLATION);
    xqc_moq_d18_request_update_free(msg);

    msg = xqc_moq_d18_request_update_create();
    XQC_TEST_ASSERT(msg != NULL);
    XQC_TEST_ASSERT(xqc_test_decode_full(&msg->msg_base,
        excessive_params, sizeof(excessive_params),
        &finish, &wait_more) == -XQC_ELIMIT);
    xqc_moq_d18_request_update_free(msg);
    return 0;
}

static int
xqc_test_publish_blocked_boundaries(void)
{
    static uint8_t empty_track_name[] = {
        0x00, 0x02, 0x00, 0x00,
    };
    static uint8_t truncated_track_name[] = {
        0x00, 0x03, 0x00, 0x02, 'a',
    };
    static uint8_t excessive_suffix_count[] = {
        0x00, 0x01, 0x21,
    };
    xqc_int_t finish = 0;
    xqc_int_t wait_more = 0;

    xqc_moq_publish_blocked_msg_t *msg =
        xqc_moq_d18_publish_blocked_create();
    XQC_TEST_ASSERT(msg != NULL);
    XQC_TEST_ASSERT(xqc_test_decode_full(&msg->msg_base,
        empty_track_name, sizeof(empty_track_name),
        &finish, &wait_more) == -XQC_EPROTO);
    xqc_moq_d18_publish_blocked_free(msg);

    msg = xqc_moq_d18_publish_blocked_create();
    XQC_TEST_ASSERT(msg != NULL);
    XQC_TEST_ASSERT(xqc_test_decode_full(&msg->msg_base,
        truncated_track_name, sizeof(truncated_track_name),
        &finish, &wait_more) == -XQC_EILLEGAL_FRAME);
    xqc_moq_d18_publish_blocked_free(msg);

    msg = xqc_moq_d18_publish_blocked_create();
    XQC_TEST_ASSERT(msg != NULL);
    XQC_TEST_ASSERT(xqc_test_decode_full(&msg->msg_base,
        excessive_suffix_count, sizeof(excessive_suffix_count),
        &finish, &wait_more) == -XQC_EPROTO);
    xqc_moq_d18_publish_blocked_free(msg);

    xqc_moq_publish_blocked_msg_t encoded = {0};
    xqc_moq_d18_publish_blocked_init_handler(&encoded.msg_base);
    XQC_TEST_ASSERT(encoded.msg_base.encode_len(&encoded.msg_base)
                    == -XQC_EPARAM);
    encoded.track_namespace_suffix_num = 33;
    XQC_TEST_ASSERT(encoded.msg_base.encode_len(&encoded.msg_base)
                    == -XQC_EPARAM);
    return 0;
}

static int
xqc_test_publish_done_boundaries(void)
{
    static uint8_t invalid_utf8[] = {
        0x00, 0x04, 0x02, 0x00, 0x01, 0xff,
    };
    xqc_int_t finish = 0;
    xqc_int_t wait_more = 0;
    xqc_moq_publish_done_msg_t *decoded =
        xqc_moq_d18_publish_done_create();

    XQC_TEST_ASSERT(decoded != NULL);
    XQC_TEST_ASSERT(xqc_test_decode_full(&decoded->msg_base,
        invalid_utf8, sizeof(invalid_utf8),
        &finish, &wait_more) == -XQC_EPROTO);
    xqc_moq_d18_publish_done_free(decoded);

    size_t reason_len = XQC_MOQ_MAX_REASON_PHRASE_LEN + 1;
    size_t payload_len = 1 + 1 + 2 + reason_len;
    uint8_t *too_long = calloc(1, payload_len + 2);
    XQC_TEST_ASSERT(too_long != NULL);
    too_long[0] = (uint8_t)(payload_len >> 8);
    too_long[1] = (uint8_t)payload_len;
    too_long[2] = XQC_MOQ_PUBLISH_DONE_TRACK_ENDED;
    too_long[3] = 0x00;
    too_long[4] = 0x84;
    too_long[5] = 0x01;
    memset(too_long + 6, 'x', reason_len);
    decoded = xqc_moq_d18_publish_done_create();
    XQC_TEST_ASSERT(decoded != NULL);
    XQC_TEST_ASSERT(xqc_test_decode_full(&decoded->msg_base,
        too_long, payload_len + 2,
        &finish, &wait_more) == -XQC_EPROTO);
    xqc_moq_d18_publish_done_free(decoded);
    free(too_long);

    char invalid_reason[] = {(char)0xff};
    xqc_moq_publish_done_msg_t encoded = {
        .status_code = XQC_MOQ_PUBLISH_DONE_TRACK_ENDED,
        .reason_phrase = invalid_reason,
        .reason_phrase_len = sizeof(invalid_reason),
    };
    xqc_moq_d18_publish_done_init_handler(&encoded.msg_base);
    XQC_TEST_ASSERT(encoded.msg_base.encode_len(&encoded.msg_base)
                    == -XQC_EPARAM);

    encoded.reason_phrase = NULL;
    encoded.reason_phrase_len = 0;
    encoded.stream_count = (UINT64_C(1) << 62) - 1;
    uint8_t max_wire[32] = {0};
    xqc_int_t max_len = encoded.msg_base.encode(
        &encoded.msg_base, max_wire, sizeof(max_wire));
    XQC_TEST_ASSERT(max_len > 0);
    decoded = xqc_moq_d18_publish_done_create();
    XQC_TEST_ASSERT(decoded != NULL);
    XQC_TEST_ASSERT(xqc_test_decode_full(&decoded->msg_base,
        max_wire + 1, (size_t)max_len - 1,
        &finish, &wait_more) == max_len - 1);
    XQC_TEST_ASSERT(finish == 1);
    XQC_TEST_ASSERT(decoded->stream_count == (UINT64_C(1) << 62) - 1);
    xqc_moq_d18_publish_done_free(decoded);

    encoded.stream_count = UINT64_C(1) << 62;
    XQC_TEST_ASSERT(encoded.msg_base.encode_len(&encoded.msg_base)
                    == -XQC_EPARAM);
    return 0;
}

static int
xqc_test_goaway_boundaries(void)
{
    static uint8_t control_body[] = {
        0x00, 0x03, 0x00, 0x0a, 0x00,
    };
    static uint8_t request_body[] = {
        0x00, 0x02, 0x00, 0x0a,
    };
    xqc_int_t finish = 0;
    xqc_int_t wait_more = 0;

    xqc_moq_d18_goaway_msg_t *msg = xqc_moq_d18_goaway_create();
    XQC_TEST_ASSERT(msg != NULL);
    xqc_moq_d18_control_goaway_init_handler(&msg->msg_base);
    XQC_TEST_ASSERT(xqc_test_decode_full(&msg->msg_base,
        request_body, sizeof(request_body),
        &finish, &wait_more) == -XQC_EILLEGAL_FRAME);
    xqc_moq_d18_goaway_free(msg);

    msg = xqc_moq_d18_goaway_create();
    XQC_TEST_ASSERT(msg != NULL);
    xqc_moq_d18_request_goaway_init_handler(&msg->msg_base);
    XQC_TEST_ASSERT(xqc_test_decode_full(&msg->msg_base,
        control_body, sizeof(control_body),
        &finish, &wait_more) == -XQC_EILLEGAL_FRAME);
    xqc_moq_d18_goaway_free(msg);

    size_t uri_len = XQC_MOQ_MAX_GOAWAY_URI_LEN + 1;
    size_t payload_len = 2 + uri_len + 1;
    uint8_t *too_long = calloc(1, payload_len + 2);
    XQC_TEST_ASSERT(too_long != NULL);
    too_long[0] = (uint8_t)(payload_len >> 8);
    too_long[1] = (uint8_t)payload_len;
    too_long[2] = 0xa0;
    too_long[3] = 0x01;
    memset(too_long + 4, 'u', uri_len);
    msg = xqc_moq_d18_goaway_create();
    XQC_TEST_ASSERT(msg != NULL);
    xqc_moq_d18_request_goaway_init_handler(&msg->msg_base);
    XQC_TEST_ASSERT(xqc_test_decode_full(&msg->msg_base,
        too_long, payload_len + 2,
        &finish, &wait_more) == -XQC_EPROTO);
    xqc_moq_d18_goaway_free(msg);
    free(too_long);

    char *uri = malloc(uri_len);
    XQC_TEST_ASSERT(uri != NULL);
    memset(uri, 'u', uri_len);
    xqc_moq_d18_goaway_msg_t encoded = {
        .new_session_uri = uri,
        .new_session_uri_len = uri_len,
    };
    xqc_moq_d18_request_goaway_init_handler(&encoded.msg_base);
    XQC_TEST_ASSERT(encoded.msg_base.encode_len(&encoded.msg_base)
                    == -XQC_EPARAM);
    free(uri);
    return 0;
}

static void
xqc_test_init_dispatch_stream(xqc_moq_stream_t *stream,
    xqc_moq_session_t *session, xqc_moq_d18_message_kind_t kind,
    xqc_moq_d18_stream_class_t stream_class, uint64_t wire_type,
    xqc_moq_msg_type_t request_type)
{
    memset(session, 0, sizeof(*session));
    memset(stream, 0, sizeof(*stream));
    session->version = XQC_MOQ_VERSION_18;
    session->use_unified_setup = 1;
    session->profile = xqc_moq_v18_profile();
    session->profile_state = XQC_MOQ_PROFILE_ACTIVE;
    stream->session = session;
    stream->d18_context.direction = stream_class == XQC_MOQ_D18_STREAM_CONTROL
        ? XQC_MOQ_D18_DIRECTION_UNI : XQC_MOQ_D18_DIRECTION_BIDI;
    stream->d18_context.stream_class = stream_class;
    stream->d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    stream->d18_message_kind = kind;
    stream->decode_msg_ctx.cur_msg_type = (xqc_moq_msg_type_t)wire_type;
    stream->request_type = request_type;
}

static int
xqc_test_d18_initial_request_dispatch_uses_pending_context(void)
{
    static const struct {
        uint64_t wire_type;
        xqc_moq_d18_message_kind_t kind;
    } cases[] = {
        {
            XQC_MOQ_D18_MSG_PUBLISH_NAMESPACE,
            XQC_MOQ_D18_MESSAGE_PUBLISH_NAMESPACE,
        },
        {
            XQC_MOQ_D18_MSG_SUBSCRIBE,
            XQC_MOQ_D18_MESSAGE_SUBSCRIBE,
        },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        xqc_moq_session_t session;
        xqc_moq_stream_t stream;
        xqc_moq_d18_message_desc_t desc;
        xqc_moq_d18_stream_context_t pending;

        memset(&session, 0, sizeof(session));
        memset(&stream, 0, sizeof(stream));
        session.version = XQC_MOQ_VERSION_18;
        session.use_unified_setup = 1;
        session.profile = xqc_moq_v18_profile();
        session.profile_state = XQC_MOQ_PROFILE_ACTIVE;
        stream.session = &session;
        stream.kind = XQC_MOQ_STREAM_UNKNOWN;
        stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
        stream.d18_context.stream_class =
            XQC_MOQ_D18_STREAM_UNCLASSIFIED;
        stream.d18_context.position = XQC_MOQ_D18_POSITION_FIRST;

        pending = stream.d18_context;
        XQC_TEST_ASSERT(xqc_moq_d18_stream_resolve(
            &pending, cases[i].wire_type, &desc)
            == XQC_MOQ_D18_REGISTRY_OK);
        XQC_TEST_ASSERT(desc.kind == cases[i].kind);
        XQC_TEST_ASSERT(pending.stream_class
                        == XQC_MOQ_D18_STREAM_REQUEST);

        stream.d18_pending_context = pending;
        stream.d18_context_pending = 1;
        stream.d18_message_kind = desc.kind;
        stream.decode_msg_ctx.cur_msg_type =
            (xqc_moq_msg_type_t)cases[i].wire_type;

        XQC_TEST_ASSERT(xqc_moq_stream_get_or_alloc_cur_decode_msg(&stream)
                        != NULL);
        XQC_TEST_ASSERT(stream.decode_codec != NULL);
        XQC_TEST_ASSERT(stream.decode_codec->wire_type == cases[i].wire_type);
        xqc_moq_stream_free_cur_decode_msg(&stream);
    }
    return 0;
}

static int
xqc_test_d18_request_before_setup_is_buffered(void)
{
    static const uint8_t early_request[] = {
        XQC_MOQ_D18_MSG_PUBLISH_NAMESPACE,
    };
    xqc_connection_t quic_conn;
    xqc_moq_session_t session;
    xqc_moq_stream_t stream;

    memset(&quic_conn, 0, sizeof(quic_conn));
    memset(&session, 0, sizeof(session));
    memset(&stream, 0, sizeof(stream));
    quic_conn.conn_err = UINT64_MAX;
    session.version = XQC_MOQ_VERSION_18;
    session.use_unified_setup = 1;
    session.profile = xqc_moq_v18_profile();
    session.profile_state = XQC_MOQ_PROFILE_ALPN_SELECTED;
    session.quic_conn = &quic_conn;
    session.log = &xqc_test_setup_log;
    xqc_init_list_head(&session.d18_deferred_stream_list);
    stream.session = &session;
    stream.kind = XQC_MOQ_STREAM_UNKNOWN;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_UNCLASSIFIED;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_FIRST;
    xqc_init_list_head(&stream.d18_deferred_list_member);

    XQC_TEST_ASSERT(xqc_moq_stream_process(
        &stream, (uint8_t *)early_request, sizeof(early_request), 0)
        == (xqc_int_t)sizeof(early_request));
    XQC_TEST_ASSERT(quic_conn.conn_err == UINT64_MAX);
    XQC_TEST_ASSERT(stream.decode_msg_ctx.cur_decode_state
                    == XQC_MOQ_DECODE_MSG_TYPE);
    XQC_TEST_ASSERT(stream.d18_context.stream_class
                    == XQC_MOQ_D18_STREAM_UNCLASSIFIED);
    XQC_TEST_ASSERT(stream.read_buf_len == sizeof(early_request));
    XQC_TEST_ASSERT(stream.d18_waiting_for_setup == 1);
    XQC_TEST_ASSERT(session.d18_deferred_stream_bytes
                    == sizeof(early_request));

    session.profile_state = XQC_MOQ_PROFILE_ACTIVE;
    XQC_TEST_ASSERT(xqc_moq_session_resume_deferred_streams(&session)
                    == XQC_OK);
    XQC_TEST_ASSERT(stream.d18_waiting_for_setup == 0);
    XQC_TEST_ASSERT(session.d18_deferred_stream_bytes == 0);
    XQC_TEST_ASSERT(xqc_list_empty(&session.d18_deferred_stream_list));
    XQC_TEST_ASSERT(stream.decode_msg_ctx.cur_decode_state
                    == XQC_MOQ_DECODE_MSG);
    XQC_TEST_ASSERT(stream.d18_context_pending == 1);
    XQC_TEST_ASSERT(stream.d18_pending_context.stream_class
                    == XQC_MOQ_D18_STREAM_REQUEST);

    xqc_free(stream.read_buf);
    stream.read_buf = NULL;
    return 0;
}

static int
xqc_test_d18_live_dispatch_phase_guards(void)
{
    xqc_moq_session_t session;
    xqc_moq_stream_t stream;

    xqc_test_init_dispatch_stream(&stream, &session,
        XQC_MOQ_D18_MESSAGE_REQUEST_UPDATE, XQC_MOQ_D18_STREAM_REQUEST,
        XQC_MOQ_D18_MSG_REQUEST_UPDATE, XQC_MOQ_MSG_SUBSCRIBE);
    stream.local_request = 1;
    XQC_TEST_ASSERT(xqc_moq_stream_get_or_alloc_cur_decode_msg(&stream)
                    == NULL);
    stream.response_received = 1;
    xqc_moq_request_update_msg_t *update =
        xqc_moq_stream_get_or_alloc_cur_decode_msg(&stream);
    XQC_TEST_ASSERT(update != NULL);
    XQC_TEST_ASSERT(update->msg_base.encode
                    == xqc_moq_d18_request_update_encode);
    XQC_TEST_ASSERT(update->msg_base.decode
                    == xqc_moq_d18_request_update_decode);
    XQC_TEST_ASSERT(update->d18_param_context
                    == XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_SUBSCRIBE);
    xqc_moq_stream_free_cur_decode_msg(&stream);
    XQC_TEST_ASSERT(stream.decode_msg_ctx.cur_decode_msg == NULL);

    xqc_test_init_dispatch_stream(&stream, &session,
        XQC_MOQ_D18_MESSAGE_PUBLISH_BLOCKED, XQC_MOQ_D18_STREAM_REQUEST,
        XQC_MOQ_D18_MSG_PUBLISH_BLOCKED, XQC_MOQ_MSG_SUBSCRIBE_TRACKS);
    stream.local_request = 1;
    XQC_TEST_ASSERT(xqc_moq_stream_get_or_alloc_cur_decode_msg(&stream)
                    == NULL);
    stream.response_received = 1;
    xqc_moq_publish_blocked_msg_t *blocked =
        xqc_moq_stream_get_or_alloc_cur_decode_msg(&stream);
    XQC_TEST_ASSERT(blocked != NULL);
    XQC_TEST_ASSERT(blocked->msg_base.encode
                    == xqc_moq_d18_publish_blocked_encode);
    XQC_TEST_ASSERT(blocked->msg_base.decode
                    == xqc_moq_d18_publish_blocked_decode);
    xqc_moq_stream_free_cur_decode_msg(&stream);

    xqc_test_init_dispatch_stream(&stream, &session,
        XQC_MOQ_D18_MESSAGE_PUBLISH_DONE, XQC_MOQ_D18_STREAM_REQUEST,
        XQC_MOQ_D18_MSG_PUBLISH_DONE, XQC_MOQ_MSG_PUBLISH);
    stream.peer_request = 1;
    XQC_TEST_ASSERT(xqc_moq_stream_get_or_alloc_cur_decode_msg(&stream)
                    == NULL);
    stream.response_sent = 1;
    xqc_moq_publish_done_msg_t *done =
        xqc_moq_stream_get_or_alloc_cur_decode_msg(&stream);
    XQC_TEST_ASSERT(done != NULL);
    XQC_TEST_ASSERT(done->msg_base.encode
                    == xqc_moq_d18_publish_done_encode);
    XQC_TEST_ASSERT(done->msg_base.decode
                    == xqc_moq_d18_publish_done_decode);
    XQC_TEST_ASSERT(done->msg_base.on_msg
                    == xqc_moq_on_publish_done);
    xqc_moq_stream_free_cur_decode_msg(&stream);
    return 0;
}

static int
xqc_test_d18_live_dispatch_context_selection(void)
{
    xqc_moq_session_t session;
    xqc_moq_stream_t stream;

    xqc_test_init_dispatch_stream(&stream, &session,
        XQC_MOQ_D18_MESSAGE_REQUEST_UPDATE, XQC_MOQ_D18_STREAM_REQUEST,
        XQC_MOQ_D18_MSG_REQUEST_UPDATE, XQC_MOQ_MSG_SUBSCRIBE_TRACKS);
    stream.peer_request = 1;
    stream.response_sent = 1;
    xqc_moq_request_update_msg_t *update =
        xqc_moq_stream_get_or_alloc_cur_decode_msg(&stream);
    XQC_TEST_ASSERT(update != NULL);
    XQC_TEST_ASSERT(update->d18_param_context
                    == XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_NAMESPACE);
    xqc_moq_stream_free_cur_decode_msg(&stream);

    xqc_test_init_dispatch_stream(&stream, &session,
        XQC_MOQ_D18_MESSAGE_GOAWAY, XQC_MOQ_D18_STREAM_CONTROL,
        XQC_MOQ_D18_MSG_GOAWAY, 0);
    xqc_moq_d18_goaway_msg_t *goaway =
        xqc_moq_stream_get_or_alloc_cur_decode_msg(&stream);
    XQC_TEST_ASSERT(goaway != NULL);
    XQC_TEST_ASSERT(goaway->msg_base.encode == xqc_moq_d18_goaway_encode);
    XQC_TEST_ASSERT(goaway->msg_base.decode == xqc_moq_d18_goaway_decode);
    XQC_TEST_ASSERT(goaway->has_request_id == 1);
    xqc_moq_stream_free_cur_decode_msg(&stream);

    xqc_test_init_dispatch_stream(&stream, &session,
        XQC_MOQ_D18_MESSAGE_GOAWAY, XQC_MOQ_D18_STREAM_REQUEST,
        XQC_MOQ_D18_MSG_GOAWAY, XQC_MOQ_MSG_SUBSCRIBE);
    goaway = xqc_moq_stream_get_or_alloc_cur_decode_msg(&stream);
    XQC_TEST_ASSERT(goaway != NULL);
    XQC_TEST_ASSERT(goaway->msg_base.encode == xqc_moq_d18_goaway_encode);
    XQC_TEST_ASSERT(goaway->msg_base.decode == xqc_moq_d18_goaway_decode);
    XQC_TEST_ASSERT(goaway->has_request_id == 0);
    xqc_moq_stream_free_cur_decode_msg(&stream);
    return 0;
}

static int
xqc_test_d18_request_ok_context_selection(void)
{
    xqc_moq_session_t session;
    xqc_moq_stream_t stream;

    xqc_test_init_dispatch_stream(&stream, &session,
        XQC_MOQ_D18_MESSAGE_REQUEST_OK, XQC_MOQ_D18_STREAM_REQUEST,
        XQC_MOQ_D18_MSG_REQUEST_OK, XQC_MOQ_MSG_PUBLISH);
    stream.local_request = 1;

    xqc_moq_request_ok_msg_t *ok =
        xqc_moq_stream_get_or_alloc_cur_decode_msg(&stream);
    XQC_TEST_ASSERT(ok != NULL);
    XQC_TEST_ASSERT(ok->d18_param_context
                    == XQC_MOQ_D18_PARAM_CONTEXT_PUBLISH_OK);
    xqc_moq_stream_free_cur_decode_msg(&stream);

    xqc_test_init_dispatch_stream(&stream, &session,
        XQC_MOQ_D18_MESSAGE_REQUEST_OK, XQC_MOQ_D18_STREAM_REQUEST,
        XQC_MOQ_D18_MSG_REQUEST_OK, XQC_MOQ_MSG_SUBSCRIBE);
    stream.local_request = 1;
    ok = xqc_moq_stream_get_or_alloc_cur_decode_msg(&stream);
    XQC_TEST_ASSERT(ok != NULL);
    XQC_TEST_ASSERT(ok->d18_param_context
                    == XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE_OK);
    xqc_moq_stream_free_cur_decode_msg(&stream);

    xqc_test_init_dispatch_stream(&stream, &session,
        XQC_MOQ_D18_MESSAGE_REQUEST_OK, XQC_MOQ_D18_STREAM_REQUEST,
        XQC_MOQ_D18_MSG_REQUEST_OK, XQC_MOQ_MSG_PUBLISH);
    stream.local_request = 1;
    stream.response_received = 1;
    ok = xqc_moq_stream_get_or_alloc_cur_decode_msg(&stream);
    XQC_TEST_ASSERT(ok != NULL);
    XQC_TEST_ASSERT(ok->d18_param_context
                    == XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_OK);
    xqc_moq_stream_free_cur_decode_msg(&stream);

    xqc_test_init_dispatch_stream(&stream, &session,
        XQC_MOQ_D18_MESSAGE_REQUEST_OK, XQC_MOQ_D18_STREAM_REQUEST,
        XQC_MOQ_D18_MSG_REQUEST_OK, XQC_MOQ_MSG_PUBLISH);
    stream.peer_request = 1;
    stream.response_sent = 1;
    ok = xqc_moq_stream_get_or_alloc_cur_decode_msg(&stream);
    XQC_TEST_ASSERT(ok != NULL);
    XQC_TEST_ASSERT(ok->d18_param_context
                    == XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_OK);
    xqc_moq_stream_free_cur_decode_msg(&stream);
    return 0;
}

static int
xqc_test_d18_live_dispatch_rejects_wrong_context(void)
{
    static const xqc_moq_d18_message_kind_t kinds[] = {
        XQC_MOQ_D18_MESSAGE_REQUEST_UPDATE,
        XQC_MOQ_D18_MESSAGE_PUBLISH_BLOCKED,
        XQC_MOQ_D18_MESSAGE_PUBLISH_DONE,
    };
    static const uint64_t types[] = {
        XQC_MOQ_D18_MSG_REQUEST_UPDATE,
        XQC_MOQ_D18_MSG_PUBLISH_BLOCKED,
        XQC_MOQ_D18_MSG_PUBLISH_DONE,
    };
    xqc_moq_session_t session;
    xqc_moq_stream_t stream;

    for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
        xqc_test_init_dispatch_stream(&stream, &session, kinds[i],
            XQC_MOQ_D18_STREAM_CONTROL, types[i], XQC_MOQ_MSG_PUBLISH);
        stream.peer_request = 1;
        stream.response_sent = 1;
        XQC_TEST_ASSERT(xqc_moq_stream_get_or_alloc_cur_decode_msg(&stream)
                        == NULL);
    }

    xqc_test_init_dispatch_stream(&stream, &session,
        XQC_MOQ_D18_MESSAGE_GOAWAY, XQC_MOQ_D18_STREAM_UNCLASSIFIED,
        XQC_MOQ_D18_MSG_GOAWAY, 0);
    XQC_TEST_ASSERT(xqc_moq_stream_get_or_alloc_cur_decode_msg(&stream)
                    == NULL);

    xqc_test_init_dispatch_stream(&stream, &session,
        XQC_MOQ_D18_MESSAGE_REQUEST_UPDATE, XQC_MOQ_D18_STREAM_REQUEST,
        XQC_MOQ_D18_MSG_REQUEST_UPDATE, XQC_MOQ_MSG_TRACK_STATUS_REQUEST);
    stream.local_request = 1;
    stream.response_received = 1;
    XQC_TEST_ASSERT(xqc_moq_stream_get_or_alloc_cur_decode_msg(&stream)
                    == NULL);
    return 0;
}

static int
xqc_test_d18_params_clone_owns_values(void)
{
    uint8_t token[] = {'a', 'b'};
    xqc_moq_message_parameter_t source[] = {
        {
            .type = XQC_MOQ_D18_PARAM_OBJECT_DELIVERY_TIMEOUT,
            .is_integer = 1,
            .int_value = 17,
        },
        {
            .type = XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN,
            .length = sizeof(token),
            .value = token,
        },
    };
    xqc_moq_message_parameter_t *copy = NULL;

    XQC_TEST_ASSERT(xqc_moq_d18_params_clone(source, 2, &copy)
                    == XQC_MOQ_D18_UPDATE_OK);
    XQC_TEST_ASSERT(copy != NULL);
    XQC_TEST_ASSERT(copy[0].is_integer == 1);
    XQC_TEST_ASSERT(copy[0].int_value == 17);
    XQC_TEST_ASSERT(copy[1].value != token);
    XQC_TEST_ASSERT(copy[1].length == sizeof(token));
    XQC_TEST_ASSERT(memcmp(copy[1].value, "ab", 2) == 0);
    token[0] = 'z';
    XQC_TEST_ASSERT(memcmp(copy[1].value, "ab", 2) == 0);
    xqc_moq_d18_params_free(copy, 2);
    return 0;
}

static int
xqc_test_d18_params_merge_replaces_type_groups(void)
{
    uint8_t old_a[] = {'a'};
    uint8_t old_b[] = {'b'};
    uint8_t new_c[] = {'c'};
    uint8_t new_d[] = {'d'};
    xqc_moq_message_parameter_t current[] = {
        {
            .type = XQC_MOQ_D18_PARAM_OBJECT_DELIVERY_TIMEOUT,
            .is_integer = 1,
            .int_value = 10,
        },
        {
            .type = XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN,
            .length = 1,
            .value = old_a,
        },
        {
            .type = XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN,
            .length = 1,
            .value = old_b,
        },
        {
            .type = XQC_MOQ_D18_PARAM_FORWARD,
            .is_integer = 1,
            .int_value = 1,
        },
    };
    xqc_moq_message_parameter_t update[] = {
        {
            .type = XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN,
            .length = 1,
            .value = new_c,
        },
        {
            .type = XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN,
            .length = 1,
            .value = new_d,
        },
    };
    xqc_moq_message_parameter_t *merged = NULL;
    size_t merged_count = 0;

    XQC_TEST_ASSERT(xqc_moq_d18_params_merge(current, 4, update, 2,
        &merged, &merged_count) == XQC_MOQ_D18_UPDATE_OK);
    XQC_TEST_ASSERT(merged_count == 4);
    XQC_TEST_ASSERT(merged[0].type
                    == XQC_MOQ_D18_PARAM_OBJECT_DELIVERY_TIMEOUT);
    XQC_TEST_ASSERT(merged[0].int_value == 10);
    XQC_TEST_ASSERT(merged[1].type
                    == XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN);
    XQC_TEST_ASSERT(memcmp(merged[1].value, "c", 1) == 0);
    XQC_TEST_ASSERT(merged[2].type
                    == XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN);
    XQC_TEST_ASSERT(memcmp(merged[2].value, "d", 1) == 0);
    XQC_TEST_ASSERT(merged[3].type == XQC_MOQ_D18_PARAM_FORWARD);
    XQC_TEST_ASSERT(merged[3].int_value == 1);
    new_c[0] = 'x';
    XQC_TEST_ASSERT(memcmp(merged[1].value, "c", 1) == 0);
    xqc_moq_d18_params_free(merged, merged_count);
    return 0;
}

static int
xqc_test_d18_params_merge_failure_is_atomic(void)
{
    xqc_moq_message_parameter_t current = {
        .type = XQC_MOQ_D18_PARAM_FORWARD,
        .is_integer = 1,
        .int_value = 1,
    };
    xqc_moq_message_parameter_t update = {
        .type = XQC_MOQ_D18_PARAM_FORWARD,
        .is_integer = 1,
        .int_value = 0,
    };
    xqc_moq_message_parameter_t *merged = NULL;
    size_t merged_count = 0;
    size_t impossible = SIZE_MAX / sizeof(current) + 1;

    XQC_TEST_ASSERT(xqc_moq_d18_params_merge(
        &current, 1, &update, impossible, &merged, &merged_count)
        == XQC_MOQ_D18_UPDATE_NO_MEMORY);
    XQC_TEST_ASSERT(merged == NULL);
    XQC_TEST_ASSERT(merged_count == 0);
    XQC_TEST_ASSERT(current.int_value == 1);
    return 0;
}

static int
xqc_test_d18_update_queues_are_owned_fifo(void)
{
    xqc_list_head_t local;
    xqc_list_head_t peer;
    xqc_moq_message_parameter_t param = {
        .type = XQC_MOQ_D18_PARAM_FORWARD,
        .is_integer = 1,
        .int_value = 1,
    };
    xqc_moq_d18_update_record_t *records[4] = {0};

    xqc_moq_d18_update_queue_init(&local);
    xqc_moq_d18_update_queue_init(&peer);
    for (size_t i = 0; i < 3; i++) {
        XQC_TEST_ASSERT(xqc_moq_d18_update_record_create(
            2 + 2 * i, &param, 1, &records[i])
            == XQC_MOQ_D18_UPDATE_OK);
        XQC_TEST_ASSERT(xqc_moq_d18_update_queue_push(
            &local, records[i]) == XQC_MOQ_D18_UPDATE_OK);
    }
    XQC_TEST_ASSERT(xqc_moq_d18_update_record_create(
        1, &param, 1, &records[3]) == XQC_MOQ_D18_UPDATE_OK);
    records[3]->candidate_prefix =
        xqc_moq_namespace_prefix_create_copy(NULL, 0);
    XQC_TEST_ASSERT(records[3]->candidate_prefix != NULL);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_push(
        &peer, records[3]) == XQC_MOQ_D18_UPDATE_OK);
    param.int_value = 0;

    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(&local)->request_id == 2);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(&peer)->request_id == 1);
    for (size_t i = 0; i < 3; i++) {
        xqc_moq_d18_update_record_t *record =
            xqc_moq_d18_update_queue_pop(&local);
        XQC_TEST_ASSERT(record != NULL);
        XQC_TEST_ASSERT(record->request_id == 2 + 2 * i);
        XQC_TEST_ASSERT(record->params[0].int_value == 1);
        xqc_moq_d18_update_record_destroy(record);
    }
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_pop(&local) == NULL);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(&peer)->request_id == 1);
    xqc_moq_d18_update_queue_destroy(&peer);
    xqc_moq_d18_update_queue_destroy(&peer);
    xqc_moq_d18_update_queue_destroy(&local);
    XQC_TEST_ASSERT(xqc_list_empty(&peer));
    XQC_TEST_ASSERT(xqc_list_empty(&local));
    return 0;
}

static int
xqc_test_initial_request_write_failure_is_transactional(void)
{
    xqc_moq_session_t session;
    xqc_moq_stream_t seed_stream;
    xqc_moq_user_session_t user_session;
    xqc_engine_t engine;
    xqc_test_setup_write_capture_t seed_capture = {0};
    xqc_test_init_peer_request_session(
        &session, &seed_stream, &user_session, &engine, &seed_capture);

    xqc_moq_stream_t stream;
    xqc_test_setup_write_capture_t capture = {0};
    capture.scripted_results[0] = -XQC_ESYS;
    capture.scripted_results_count = 1;
    xqc_test_init_outbound_d18_stream(
        &stream, &session, &capture, XQC_MOQ_D18_DIRECTION_BIDI);
    xqc_moq_track_ns_field_t ns = {
        .data = (uint8_t *)"ns",
        .len = 2,
    };
    xqc_moq_fetch_msg_t fetch = {
        .request_id = 1,
        .fetch_type = XQC_MOQ_FETCH_STANDALONE,
        .track_namespace_num = 1,
        .track_namespace_tuple = &ns,
        .track_name = "video",
        .track_name_len = 5,
        .start_group_id = 1,
        .start_object_id = 2,
        .end_group_id = 3,
        .end_object_id = 4,
    };

    XQC_TEST_ASSERT(xqc_moq_write_fetch(&session, &stream, &fetch)
                    == -XQC_ESYS);
    XQC_TEST_ASSERT(xqc_moq_d18_request_id_validate_local(
        &session.d18_request_registry, 1) == XQC_MOQ_D18_REQUEST_ID_OK);
    XQC_TEST_ASSERT(xqc_list_empty(&session.local_request_stream_list));
    XQC_TEST_ASSERT(stream.local_request == 0);
    XQC_TEST_ASSERT(stream.write_buf_len == 0);
    XQC_TEST_ASSERT(stream.write_buf_processed == 0);

    XQC_TEST_ASSERT(xqc_moq_write_fetch(&session, &stream, &fetch) == XQC_OK);
    XQC_TEST_ASSERT(stream.local_request == 1);
    XQC_TEST_ASSERT(stream.request_id == 1);
    XQC_TEST_ASSERT(capture.write_call_count == 2);

    xqc_list_del_init(&stream.request_list_member);
    free(stream.write_buf);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    return 0;
}

static int
xqc_test_request_update_write_failure_is_transactional(void)
{
    xqc_moq_session_t session;
    xqc_moq_stream_t target;
    xqc_moq_user_session_t user_session;
    xqc_engine_t engine;
    xqc_test_setup_write_capture_t capture = {0};
    xqc_test_init_peer_request_session(
        &session, &target, &user_session, &engine, &capture);
    target.local_request = 1;
    target.request_type = XQC_MOQ_MSG_SUBSCRIBE;
    target.request_id = 1;
    target.response_received = 1;
    xqc_list_add_tail(
        &target.request_list_member, &session.local_request_stream_list);
    XQC_TEST_ASSERT(xqc_moq_session_register_local_request_id(&session, 1)
                    == XQC_MOQ_D18_REQUEST_ID_OK);

    capture.scripted_results[0] = -XQC_ESYS;
    capture.scripted_results_count = 1;
    xqc_moq_message_parameter_t forward = {
        .type = XQC_MOQ_D18_PARAM_FORWARD,
        .is_integer = 1,
        .int_value = 0,
    };
    xqc_moq_request_update_msg_t update = {
        .request_id = 3,
        .params = &forward,
        .params_num = 1,
    };

    XQC_TEST_ASSERT(xqc_moq_write_request_update(&session, 1, &update)
                    == -XQC_ESYS);
    XQC_TEST_ASSERT(xqc_moq_d18_request_id_validate_local(
        &session.d18_request_registry, 3) == XQC_MOQ_D18_REQUEST_ID_OK);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &target.d18_local_update_queue) == NULL);
    XQC_TEST_ASSERT(target.write_buf_len == 0);
    XQC_TEST_ASSERT(target.write_buf_processed == 0);

    XQC_TEST_ASSERT(xqc_moq_write_request_update(&session, 1, &update)
                    == XQC_OK);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &target.d18_local_update_queue)->request_id == 3);
    XQC_TEST_ASSERT(capture.write_call_count == 2);

    xqc_list_del_init(&target.request_list_member);
    xqc_moq_d18_update_queue_destroy(&target.d18_local_update_queue);
    free(target.write_buf);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    return 0;
}

static int xqc_test_request_goaway_cancel_count;
static uint64_t xqc_test_request_goaway_cancel_id;
static uint64_t xqc_test_request_goaway_cancel_error;
static xqc_moq_msg_type_t xqc_test_request_goaway_cancel_type;
static uint8_t xqc_test_request_goaway_cancel_local;

static void
xqc_test_on_request_goaway_cancelled(
    xqc_moq_user_session_t *user_session, uint64_t request_id,
    xqc_moq_msg_type_t request_type, uint8_t locally_initiated,
    uint64_t error_code)
{
    (void)user_session;
    xqc_test_request_goaway_cancel_count++;
    xqc_test_request_goaway_cancel_id = request_id;
    xqc_test_request_goaway_cancel_error = error_code;
    xqc_test_request_goaway_cancel_type = request_type;
    xqc_test_request_goaway_cancel_local = locally_initiated;
}

static int
xqc_test_request_goaway_fin_cancels_only_target(void)
{
    xqc_moq_session_t session;
    xqc_moq_stream_t seed_stream;
    xqc_moq_user_session_t user_session;
    xqc_engine_t engine;
    xqc_test_setup_write_capture_t seed_capture = {0};
    xqc_test_init_peer_request_session(
        &session, &seed_stream, &user_session, &engine, &seed_capture);
    session.on_request_cancelled =
        xqc_test_on_request_goaway_cancelled;

    xqc_moq_stream_t target;
    xqc_moq_stream_t other;
    xqc_test_setup_write_capture_t target_capture = {0};
    xqc_test_setup_write_capture_t other_capture = {0};
    xqc_test_init_outbound_d18_stream(
        &target, &session, &target_capture, XQC_MOQ_D18_DIRECTION_BIDI);
    xqc_test_init_outbound_d18_stream(
        &other, &session, &other_capture, XQC_MOQ_D18_DIRECTION_BIDI);

    target.kind = other.kind = XQC_MOQ_STREAM_D18_REQUEST;
    target.d18_context.stream_class =
        other.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    target.d18_context.position =
        other.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    target.local_request = other.local_request = 1;
    target.request_type = other.request_type =
        XQC_MOQ_MSG_SUBSCRIBE_TRACKS;
    target.request_id = 1;
    other.request_id = 3;
    target.response_received = other.response_received = 1;
    xqc_list_add_tail(
        &target.request_list_member, &session.local_request_stream_list);
    xqc_list_add_tail(
        &other.request_list_member, &session.local_request_stream_list);

    xqc_moq_d18_goaway_msg_t goaway = {
        .has_request_id = 0,
        .timeout_ms = 100,
    };
    xqc_test_request_goaway_cancel_count = 0;
    xqc_test_request_goaway_cancel_id = XQC_MOQ_INVALID_ID;
    xqc_test_request_goaway_cancel_error = 0;
    xqc_test_request_goaway_cancel_type = 0;
    xqc_test_request_goaway_cancel_local = 0;
    xqc_moq_on_goaway_draft18(
        &session, &target, &goaway.msg_base);
    XQC_TEST_ASSERT(target.d18_goaway_received == 1);
    XQC_TEST_ASSERT(xqc_test_request_goaway_cancel_count == 0);
    XQC_TEST_ASSERT(xqc_moq_stream_peer_close_error(&target)
                    == XQC_MOQ_REQUEST_STREAM_GOING_AWAY);
    XQC_TEST_ASSERT(xqc_moq_stream_peer_close_error(&other)
                    == XQC_MOQ_REQUEST_CANCELLED);

    XQC_TEST_ASSERT(xqc_moq_stream_process(&target, NULL, 0, 1) == 0);
    XQC_TEST_ASSERT(target.peer_fin_received == 1);
    XQC_TEST_ASSERT(target.request_closed_notified == 1);
    XQC_TEST_ASSERT(xqc_test_request_goaway_cancel_count == 1);
    XQC_TEST_ASSERT(xqc_test_request_goaway_cancel_id == 1);
    XQC_TEST_ASSERT(xqc_test_request_goaway_cancel_type
                    == XQC_MOQ_MSG_SUBSCRIBE_TRACKS);
    XQC_TEST_ASSERT(xqc_test_request_goaway_cancel_local == 1);
    XQC_TEST_ASSERT(xqc_test_request_goaway_cancel_error
                    == XQC_MOQ_REQUEST_STREAM_GOING_AWAY);
    XQC_TEST_ASSERT(other.request_closed_notified == 0);
    XQC_TEST_ASSERT(other.peer_fin_received == 0);

    xqc_list_del_init(&target.request_list_member);
    xqc_list_del_init(&other.request_list_member);
    free(target.write_buf);
    free(other.write_buf);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

int
main(void)
{
    if (xqc_test_d18_request_ok_context_selection() != 0
        || xqc_test_request_update_wire() != 0
        || xqc_test_received_setup_activates_profile_before_callback() != 0
        || xqc_test_setup_write_commits_control_context_only_after_completion()
        || xqc_test_setup_hard_write_failure_has_no_ghost_retry()
        || xqc_test_publish_blocked_wire() != 0
        || xqc_test_publish_blocked_dispatch_hook() != 0
        || xqc_test_publish_done_wire() != 0
        || xqc_test_goaway_wire() != 0
        || xqc_test_goaway_dispatch_hook() != 0
        || xqc_test_request_update_fragmented_decode() != 0
        || xqc_test_publish_blocked_fragmented_decode() != 0
        || xqc_test_publish_done_fragmented_decode() != 0
        || xqc_test_goaway_fragmented_decode() != 0
        || xqc_test_fetch_wire_and_fragmented_decode() != 0
        || xqc_test_fetch_ok_wire_and_fragmented_decode() != 0
        || xqc_test_track_status_wire_and_fragmented_decode() != 0
        || xqc_test_fetch_track_status_profile_dispatch() != 0
        || xqc_test_fetch_track_status_malformed() != 0
        || xqc_test_track_status_request_ok_properties() != 0
        || xqc_test_fetch_header_wire_and_profile() != 0
        || xqc_test_track_status_success_finishes_without_subscription() != 0
        || xqc_test_subscribe_error_uses_request_error_and_fin() != 0
        || xqc_test_unhandled_fetch_and_track_status_return_not_supported() != 0
        || xqc_test_fetch_track_status_and_empty_fetch_writers() != 0
        || xqc_test_fetch_and_track_status_receive_lifecycle() != 0
        || xqc_test_fetch_state_rules_precede_application_callback() != 0
        || xqc_test_request_update_malformed() != 0
        || xqc_test_publish_blocked_boundaries() != 0
        || xqc_test_publish_done_boundaries() != 0
        || xqc_test_goaway_boundaries() != 0
        || xqc_test_d18_initial_request_dispatch_uses_pending_context() != 0
        || xqc_test_d18_request_before_setup_is_buffered() != 0
        || xqc_test_d18_live_dispatch_phase_guards() != 0
        || xqc_test_d18_live_dispatch_context_selection() != 0
        || xqc_test_d18_live_dispatch_rejects_wrong_context() != 0
        || xqc_test_d18_params_clone_owns_values() != 0
        || xqc_test_d18_params_merge_replaces_type_groups() != 0
        || xqc_test_d18_params_merge_failure_is_atomic() != 0
        || xqc_test_d18_update_queues_are_owned_fifo() != 0
        || xqc_test_initial_request_write_failure_is_transactional() != 0
        || xqc_test_request_update_write_failure_is_transactional() != 0
        || xqc_test_request_goaway_fin_cancels_only_target() != 0)
    {
        return 1;
    }
    printf("moq_d18_control_test: PASS\n");
    return 0;
}
