#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "src/common/xqc_malloc.h"
#include "src/transport/xqc_conn.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_control.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_params.h"
#include "moq/moq_transport/xqc_moq_message.h"
#include "moq/moq_transport/xqc_moq_message_handler.h"
#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/xqc_moq_namespace.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_transport/xqc_moq_subscribe.h"
#include "moq/moq_media/xqc_moq_datachannel.h"

#define XQC_TEST_ASSERT(expr) \
    do { \
        if (!(expr)) { \
            fprintf(stderr, "assert failed: %s:%d: %s\n", \
                    __FILE__, __LINE__, #expr); \
            return -1; \
        } \
    } while (0)

typedef struct {
    uint8_t bytes[256];
    size_t  length;
    ssize_t scripted_results[16];
    size_t  scripted_results_count;
    size_t  scripted_results_index;
    int     call_count;
    uint8_t call_fin_history[32];
    int     write_count;
    uint8_t fin;
    uint8_t fin_history[16];
    int     cancel_count;
    uint64_t cancel_error;
    int     stop_sending_count;
    uint64_t stop_sending_error;
    int     fail_write;
    xqc_moq_stream_t *cancel_closes_stream;
    xqc_moq_stream_t *cancel_destroys_stream;
} xqc_test_write_capture_t;

static xqc_log_t xqc_test_log;
static int xqc_test_subscribe_tracks_callback_count;
static int xqc_test_publish_callback_count;
static int xqc_test_subscribe_ok_callback_count;
static int xqc_test_publish_ok_callback_count;
static int xqc_test_publish_ok_callback_fields_valid;
static int xqc_test_generic_ok_callback_count;
static int xqc_test_publish_error_callback_count;
static int xqc_test_generic_error_callback_count;
static xqc_int_t xqc_test_publish_response_ret;
static int xqc_test_publish_error_saw_idle_track;
static int xqc_test_request_cancelled_callback_count;
static uint64_t xqc_test_cancelled_request_id;
static xqc_moq_msg_type_t xqc_test_cancelled_request_type;
static uint8_t xqc_test_cancelled_locally_initiated;
static uint64_t xqc_test_cancelled_error_code;
static int xqc_test_request_update_callback_count;
static int xqc_test_request_update_auth_ready;
static uint64_t xqc_test_request_update_id;
static uint64_t xqc_test_request_update_target_id;
static xqc_moq_msg_type_t xqc_test_request_update_type;
static uint64_t xqc_test_update_result_ids[3];
static xqc_moq_msg_type_t xqc_test_update_result_types[3];
static size_t xqc_test_update_result_count;
static xqc_moq_stream_t *xqc_test_reentrant_update_stream;
static xqc_test_write_capture_t *xqc_test_reentrant_update_capture;
static uint64_t xqc_test_reentrant_update_target_id;
static xqc_int_t xqc_test_reentrant_update_ret;
static int xqc_test_reentrant_update_callback_count;
static int xqc_test_reentrant_update_saw_terminal;
static int xqc_test_reentrant_update_saw_publish_done;
static int xqc_test_publish_done_callback_count;
static uint64_t xqc_test_publish_done_request_id;
static uint64_t xqc_test_publish_done_status;
static uint64_t xqc_test_publish_done_stream_count;
static int xqc_test_publish_done_callback_fields_valid;
static int xqc_test_publish_done_object_callback_count;
static int xqc_test_publish_done_destroy_callback_count;
static xqc_moq_track_t *xqc_test_publish_done_reentrant_track;
static xqc_moq_stream_t *xqc_test_publish_done_reentrant_stream;
static xqc_test_write_capture_t *xqc_test_publish_done_reentrant_capture;
static int xqc_test_publish_done_reentrant_refused;
static int xqc_test_update_error_result_count;
static uint64_t xqc_test_update_error_result_id;
static xqc_moq_msg_type_t xqc_test_update_error_result_type;
static const xqc_moq_request_update_msg_t *xqc_test_deferred_update_view;
static const xqc_moq_message_parameter_t *xqc_test_deferred_update_params;
static const xqc_moq_resolved_auth_token_t *xqc_test_deferred_update_tokens;
static xqc_moq_stream_t *xqc_test_sync_update_stream;
static xqc_int_t xqc_test_sync_update_response_ret;
static int xqc_test_sync_update_view_matches_record;
static int xqc_test_sync_update_view_safe_after_response;
static int xqc_test_publish_blocked_callback_count;
static xqc_moq_stream_t *xqc_test_goaway_timeout_reentrant_stream;
static xqc_test_write_capture_t *xqc_test_goaway_timeout_reentrant_capture;
static int xqc_test_goaway_timeout_callback_order_safe;
static uint64_t xqc_test_publish_blocked_request_id;
static uint64_t xqc_test_publish_blocked_namespace_num;
static size_t xqc_test_publish_blocked_namespace_lens[4];
static uint8_t xqc_test_publish_blocked_namespace_data[4][16];
static size_t xqc_test_publish_blocked_track_name_len;
static uint8_t xqc_test_publish_blocked_track_name[16];

static void
xqc_test_on_publish_blocked(
    xqc_moq_user_session_t *user_session, uint64_t request_id,
    const xqc_moq_track_ns_field_t *full_namespace,
    uint64_t full_namespace_num, const char *track_name,
    size_t track_name_len)
{
    xqc_test_publish_blocked_callback_count++;
    xqc_test_publish_blocked_request_id = request_id;
    xqc_test_publish_blocked_namespace_num = full_namespace_num;
    if (user_session == NULL || user_session->session == NULL
        || full_namespace_num > 4 || track_name_len > 16)
    {
        return;
    }
    for (uint64_t i = 0; i < full_namespace_num; i++) {
        if (full_namespace[i].len > 16) {
            return;
        }
        xqc_test_publish_blocked_namespace_lens[i] =
            full_namespace[i].len;
        xqc_memcpy(xqc_test_publish_blocked_namespace_data[i],
                   full_namespace[i].data, full_namespace[i].len);
    }
    xqc_test_publish_blocked_track_name_len = track_name_len;
    xqc_memcpy(xqc_test_publish_blocked_track_name,
               track_name, track_name_len);
}

static void
xqc_test_on_subscribe_tracks(
    xqc_moq_user_session_t *user_session,
    xqc_moq_subscribe_tracks_msg_t *msg)
{
    (void)user_session;
    if (msg != NULL && msg->track_namespace_num == 0)
    {
        xqc_test_subscribe_tracks_callback_count++;
    }
}

static void
xqc_test_on_publish(
    xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_publish_msg_t *msg)
{
    (void)track;
    xqc_test_publish_callback_count++;
    xqc_moq_publish_ok_msg_t ok = {
        .subscribe_id = msg->subscribe_id,
        .forward = 1,
        .subscriber_priority = 7,
        .group_order = 1,
    };
    xqc_test_publish_response_ret =
        xqc_moq_write_publish_ok(user_session->session, &ok);
}

static void
xqc_test_on_publish_observe(
    xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_publish_msg_t *msg)
{
    (void)user_session;
    (void)track;
    (void)msg;
    xqc_test_publish_callback_count++;
}

static void
xqc_test_on_subscribe_ok_observe(
    xqc_moq_session_t *session, xqc_moq_track_t *track,
    xqc_moq_subscribe_ok_msg_t *msg)
{
    (void)session;
    (void)track;
    (void)msg;
    xqc_test_subscribe_ok_callback_count++;
}

static void
xqc_test_track_on_subscribe_observe(
    xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_subscribe_msg_t *msg)
{
    (void)session;
    (void)subscribe_id;
    (void)track;
    (void)msg;
}

static void
xqc_test_on_request_ok(
    xqc_moq_user_session_t *user_session, uint64_t request_id,
    xqc_moq_msg_type_t request_type, xqc_moq_request_ok_msg_t *msg)
{
    (void)user_session;
    if (request_id == 0
        && request_type == XQC_MOQ_MSG_PUBLISH
        && msg != NULL)
    {
        xqc_test_generic_ok_callback_count++;
    }
    if (request_type == XQC_MOQ_MSG_SUBSCRIBE_UPDATE
        && msg != NULL
        && xqc_test_update_result_count
            < sizeof(xqc_test_update_result_ids)
                / sizeof(xqc_test_update_result_ids[0]))
    {
        size_t index = xqc_test_update_result_count++;
        xqc_test_update_result_ids[index] = request_id;
        xqc_test_update_result_types[index] = request_type;
    }
}

static void
xqc_test_on_publish_ok(
    xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_publish_ok_msg_t *msg)
{
    (void)user_session;
    if (track != NULL && msg != NULL
        && msg->subscribe_id == 0)
    {
        xqc_test_publish_ok_callback_count++;
        xqc_test_publish_ok_callback_fields_valid =
            msg->forward == 1
            && msg->subscriber_priority == 7
            && msg->group_order == 1
            && msg->params_num == 3
            && msg->params != NULL
            && msg->params[0].type == XQC_MOQ_D18_PARAM_FORWARD
            && msg->params[0].int_value == 1
            && msg->params[1].type
                == XQC_MOQ_D18_PARAM_SUBSCRIBER_PRIORITY
            && msg->params[1].int_value == 7
            && msg->params[2].type == XQC_MOQ_D18_PARAM_GROUP_ORDER
            && msg->params[2].int_value == 1;
    }
}

static void
xqc_test_on_request_error(
    xqc_moq_user_session_t *user_session, uint64_t request_id,
    xqc_moq_msg_type_t request_type, xqc_moq_request_error_msg_t *msg)
{
    (void)user_session;
    if (request_id == 0
        && request_type == XQC_MOQ_MSG_PUBLISH
        && msg != NULL
        && msg->error_code == XQC_MOQ_REQUEST_ERROR_UNAUTHORIZED)
    {
        xqc_test_generic_error_callback_count++;
    }
}

static void
xqc_test_on_update_error_reentrant(
    xqc_moq_user_session_t *user_session, uint64_t request_id,
    xqc_moq_msg_type_t request_type, xqc_moq_request_error_msg_t *msg)
{
    static const uint8_t expected_done[] = {
        XQC_MOQ_D18_MSG_PUBLISH_DONE,
        0x00, 0x03,
        XQC_MOQ_PUBLISH_DONE_UPDATE_FAILED,
        0x03,
        0x00,
    };
    if (user_session == NULL || user_session->session == NULL
        || request_id != 3
        || request_type != XQC_MOQ_MSG_SUBSCRIBE_UPDATE
        || msg == NULL)
    {
        return;
    }

    xqc_test_reentrant_update_callback_count++;
    xqc_test_reentrant_update_saw_terminal =
        xqc_test_reentrant_update_stream->request_closed_notified
        && xqc_moq_d18_update_queue_peek(
               &xqc_test_reentrant_update_stream
                    ->d18_local_update_queue) == NULL
        && xqc_moq_d18_update_queue_peek(
               &xqc_test_reentrant_update_stream
                    ->d18_peer_update_queue) == NULL;
    xqc_test_reentrant_update_saw_publish_done =
        xqc_test_reentrant_update_capture->length
            >= sizeof(expected_done)
        && memcmp(
               xqc_test_reentrant_update_capture->bytes
                   + xqc_test_reentrant_update_capture->length
                   - sizeof(expected_done),
               expected_done, sizeof(expected_done)) == 0
        && xqc_test_reentrant_update_capture->fin_history[
               xqc_test_reentrant_update_capture->write_count - 1] == 1;

    xqc_moq_message_parameter_t forward = {
        .type = XQC_MOQ_D18_PARAM_FORWARD,
        .is_integer = 1,
        .int_value = 0,
    };
    xqc_moq_request_update_msg_t update = {
        .params_num = 1,
        .params = &forward,
    };
    xqc_test_reentrant_update_ret = xqc_moq_write_request_update(
        user_session->session, xqc_test_reentrant_update_target_id,
        &update);
}

static void
xqc_test_on_update_error_observe(
    xqc_moq_user_session_t *user_session, uint64_t request_id,
    xqc_moq_msg_type_t request_type, xqc_moq_request_error_msg_t *msg)
{
    (void)user_session;
    if (request_type == XQC_MOQ_MSG_SUBSCRIBE_UPDATE && msg != NULL) {
        xqc_test_update_error_result_count++;
        xqc_test_update_error_result_id = request_id;
        xqc_test_update_error_result_type = request_type;
    }
}

static void
xqc_test_on_publish_error(
    xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_track_info_t *track_info,
    xqc_moq_publish_error_msg_t *msg)
{
    (void)user_session;
    if (track != NULL && track_info == &track->track_info
        && msg != NULL && msg->subscribe_id == 0
        && msg->error_code == XQC_MOQ_REQUEST_ERROR_UNAUTHORIZED)
    {
        xqc_test_publish_error_callback_count++;
    }
}

static void
xqc_test_on_publish_error_after_cleanup(
    xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_track_info_t *track_info,
    xqc_moq_publish_error_msg_t *msg)
{
    (void)user_session;
    if (track != NULL && track_info == &track->track_info
        && msg != NULL
        && track->track_alias == XQC_MOQ_INVALID_ID
        && track->subscribe_id == XQC_MOQ_INVALID_ID
        && xqc_moq_find_subscribe(
            track->session, msg->subscribe_id, 0) == NULL)
    {
        xqc_test_publish_error_saw_idle_track = 1;
    }
}

static void
xqc_test_on_publish_done_observe(
    xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_publish_done_msg_t *msg)
{
    (void)user_session;
    if (track != NULL && msg != NULL) {
        xqc_test_publish_done_callback_count++;
        xqc_test_publish_done_request_id = msg->subscribe_id;
        xqc_test_publish_done_status = msg->status_code;
        xqc_test_publish_done_stream_count = msg->stream_count;
        xqc_test_publish_done_callback_fields_valid =
            msg->subscribe_id == 5
            && msg->status_code == XQC_MOQ_PUBLISH_DONE_TRACK_ENDED
            && msg->stream_count == 1
            && msg->reason_phrase_len == 4
            && msg->reason_phrase != NULL
            && memcmp(msg->reason_phrase, "done", 4) == 0
            && track->streams_count == msg->stream_count;
    }
}

static void
xqc_test_on_publish_done_object(
    xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_track_info_t *track_info, xqc_moq_object_t *object)
{
    (void)user_session;
    if (track != NULL && track_info == &track->track_info
        && object != NULL && object->payload_len == 1)
    {
        xqc_test_publish_done_object_callback_count++;
    }
}

static void
xqc_test_on_publish_done_destroy_session(
    xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_publish_done_msg_t *msg)
{
    (void)track;
    (void)msg;
    xqc_test_publish_done_destroy_callback_count++;
    if (user_session != NULL && user_session->session != NULL) {
        xqc_moq_session_destroy(user_session->session);
        xqc_moq_session_destroy(user_session->session);
    }
}

static void
xqc_test_on_request_cancelled(
    xqc_moq_user_session_t *user_session, uint64_t request_id,
    xqc_moq_msg_type_t request_type, uint8_t locally_initiated,
    uint64_t error_code)
{
    (void)user_session;
    xqc_test_request_cancelled_callback_count++;
    xqc_test_cancelled_request_id = request_id;
    xqc_test_cancelled_request_type = request_type;
    xqc_test_cancelled_locally_initiated = locally_initiated;
    xqc_test_cancelled_error_code = error_code;
}

static void
xqc_test_on_request_cancelled_poison_stream(
    xqc_moq_user_session_t *user_session, uint64_t request_id,
    xqc_moq_msg_type_t request_type, uint8_t locally_initiated,
    uint64_t error_code)
{
    (void)user_session;
    (void)request_id;
    (void)request_type;
    (void)locally_initiated;
    (void)error_code;
    xqc_bool_t is_set = XQC_TRUE;
    xqc_usec_t expires = 0;
    xqc_moq_stream_t *stream = xqc_test_goaway_timeout_reentrant_stream;
    xqc_test_goaway_timeout_callback_order_safe = stream != NULL
        && xqc_test_goaway_timeout_reentrant_capture != NULL
        && xqc_test_goaway_timeout_reentrant_capture->cancel_count == 1
        && stream->d18_goaway_timer_fired == 1
        && xqc_timer_gp_timer_get_info(
            stream->session->timer_manager, stream->d18_goaway_timer_id,
            &is_set, &expires) == XQC_OK
        && is_set == XQC_FALSE;
    if (stream != NULL) {
        stream->trans_stream = NULL;
        stream->session = NULL;
    }
}

static void
xqc_test_on_request_update(
    xqc_moq_user_session_t *user_session, uint64_t target_request_id,
    xqc_moq_msg_type_t request_type,
    const xqc_moq_request_update_msg_t *update)
{
    xqc_test_request_update_callback_count++;
    xqc_test_request_update_target_id = target_request_id;
    xqc_test_request_update_type = request_type;
    xqc_test_request_update_id = update->request_id;
    xqc_test_request_update_auth_ready =
        user_session != NULL && user_session->session != NULL
        && user_session->session->peer_auth_cache.current_size == 18
        && update->request_auth.count == 1
        && update->request_auth.tokens[0].token_type == 2
        && update->request_auth.tokens[0].token_value_len == 2
        && memcmp(update->request_auth.tokens[0].token_value,
                  "ab", 2) == 0;
}

static void
xqc_test_on_request_update_deferred(
    xqc_moq_user_session_t *user_session, uint64_t target_request_id,
    xqc_moq_msg_type_t request_type,
    const xqc_moq_request_update_msg_t *update)
{
    (void)user_session;
    (void)target_request_id;
    (void)request_type;
    xqc_test_deferred_update_view = update;
    xqc_test_deferred_update_params = update->params;
    xqc_test_deferred_update_tokens = update->request_auth.tokens;
}

static void
xqc_test_on_request_update_sync_ok(
    xqc_moq_user_session_t *user_session, uint64_t target_request_id,
    xqc_moq_msg_type_t request_type,
    const xqc_moq_request_update_msg_t *update)
{
    (void)request_type;
    xqc_moq_d18_update_record_t *record =
        xqc_moq_d18_update_queue_peek(
            &xqc_test_sync_update_stream->d18_peer_update_queue);
    xqc_test_sync_update_view_matches_record = record != NULL
        && update->params == record->params;

    xqc_moq_request_ok_msg_t ok = {0};
    xqc_test_sync_update_response_ret = xqc_moq_write_request_ok(
        user_session->session, update->request_id, &ok);
    xqc_test_sync_update_view_safe_after_response =
        update->request_id == 2
        && update->params_num == 1
        && update->params[0].type == XQC_MOQ_D18_PARAM_FORWARD
        && update->params[0].int_value == 1
        && target_request_id == xqc_test_sync_update_stream->request_id;
}

static ssize_t
xqc_test_capture_write(void *stream, uint8_t *send_data,
    size_t send_data_size, uint8_t fin)
{
    xqc_test_write_capture_t *capture = stream;
    if ((size_t)capture->call_count
        < sizeof(capture->call_fin_history)
            / sizeof(capture->call_fin_history[0]))
    {
        capture->call_fin_history[capture->call_count] = fin;
    }
    capture->call_count++;
    if (capture->fail_write) {
        return -XQC_ESYS;
    }
    ssize_t result = (ssize_t)send_data_size;
    if (capture->scripted_results_index
        < capture->scripted_results_count)
    {
        result = capture->scripted_results[
            capture->scripted_results_index++];
        if (result < 0) {
            return result;
        }
        if ((size_t)result > send_data_size) {
            return -XQC_ELIMIT;
        }
    }
    if ((size_t)result > sizeof(capture->bytes) - capture->length) {
        return -XQC_ELIMIT;
    }
    xqc_memcpy(capture->bytes + capture->length,
               send_data, (size_t)result);
    capture->length += (size_t)result;
    if ((size_t)capture->write_count
        < sizeof(capture->fin_history) / sizeof(capture->fin_history[0]))
    {
        capture->fin_history[capture->write_count] = fin;
    }
    capture->write_count++;
    capture->fin = fin;
    if (capture == xqc_test_publish_done_reentrant_capture
        && xqc_test_publish_done_reentrant_track != NULL
        && xqc_test_publish_done_reentrant_stream != NULL)
    {
        xqc_moq_track_on_write_stream(
            xqc_test_publish_done_reentrant_track,
            xqc_test_publish_done_reentrant_stream, 7, 8, 0);
        xqc_test_publish_done_reentrant_refused =
            xqc_test_publish_done_reentrant_stream->track == NULL
            && xqc_list_empty(
                &xqc_test_publish_done_reentrant_stream->list_member);
    }
    return result;
}

static xqc_stream_t *
xqc_test_capture_quic_stream(void *stream)
{
    (void)stream;
    return NULL;
}

static xqc_int_t
xqc_test_capture_cancel(void *stream, uint64_t error_code)
{
    xqc_test_write_capture_t *capture = stream;
    capture->cancel_count++;
    capture->cancel_error = error_code;
    if (capture->cancel_destroys_stream != NULL) {
        xqc_moq_stream_t *stream = capture->cancel_destroys_stream;
        capture->cancel_destroys_stream = NULL;
        xqc_moq_stream_destroy(stream);

    } else if (capture->cancel_closes_stream != NULL) {
        xqc_moq_stream_on_request_closed(
            capture->cancel_closes_stream, error_code);
    }
    return XQC_OK;
}

static xqc_int_t
xqc_test_capture_stop_sending(void *stream, uint64_t error_code)
{
    xqc_test_write_capture_t *capture = stream;
    capture->stop_sending_count++;
    capture->stop_sending_error = error_code;
    return XQC_OK;
}

static void
xqc_test_init_session(xqc_moq_session_t *session)
{
    xqc_memzero(session, sizeof(*session));
    xqc_memzero(&xqc_test_log, sizeof(xqc_test_log));
    session->version = XQC_MOQ_VERSION_18;
    session->use_unified_setup = 1;
    session->profile = xqc_moq_v18_profile();
    session->profile_state = XQC_MOQ_PROFILE_ACTIVE;
    session->role = XQC_MOQ_PUBLISHER;
    session->log = &xqc_test_log;
    xqc_init_list_head(&session->local_subscribe_list);
    xqc_init_list_head(&session->peer_subscribe_list);
    xqc_init_list_head(&session->track_list_for_pub);
    xqc_init_list_head(&session->track_list_for_sub);
    xqc_init_list_head(&session->peer_subscribe_namespace_list);
    xqc_init_list_head(&session->peer_ns_pending_inbound_list);
    xqc_init_list_head(&session->local_advertised_namespace_list);
    xqc_init_list_head(&session->peer_advertised_namespace_list);
    xqc_init_list_head(&session->local_request_stream_list);
    xqc_init_list_head(&session->peer_request_stream_list);
    xqc_init_list_head(&session->local_ns_pending_list);
    xqc_moq_d18_request_registry_init(
        &session->d18_request_registry, 1);
    xqc_moq_d18_auth_cache_init(&session->peer_auth_cache, 0);
}

static void
xqc_test_init_stream(xqc_moq_stream_t *stream,
    xqc_moq_session_t *session, xqc_test_write_capture_t *capture)
{
    xqc_memzero(stream, sizeof(*stream));
    stream->session = session;
    stream->trans_stream = capture;
    stream->trans_ops.write = xqc_test_capture_write;
    stream->trans_ops.quic_stream = xqc_test_capture_quic_stream;
    stream->trans_ops.cancel = xqc_test_capture_cancel;
    stream->trans_ops.stop_sending = xqc_test_capture_stop_sending;
    xqc_init_list_head(&stream->list_member);
    xqc_init_list_head(&stream->recv_list_member);
    xqc_init_list_head(&stream->request_list_member);
}

static void
xqc_test_clean_stream(xqc_moq_stream_t *stream)
{
    xqc_list_del_init(&stream->request_list_member);
    xqc_free(stream->write_buf);
    stream->write_buf = NULL;
}

static int
xqc_test_subscribe_tracks_wire_vectors(void)
{
    static const uint8_t expected_root[] = {
        0x51, 0x00, 0x03,
        0x00,
        0x00,
        0x00,
    };
    static const uint8_t expected_live_forward_zero[] = {
        0x51, 0x00, 0x0a,
        0x02,
        0x01, 0x04, 'l', 'i', 'v', 'e',
        0x01, 0x10, 0x00,
    };
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_moq_message_parameter_t forward = {
        .type = XQC_MOQ_D18_PARAM_FORWARD,
        .is_integer = 1,
        .int_value = 0,
    };
    xqc_moq_subscribe_tracks_msg_t root = {0};
    xqc_moq_subscribe_tracks_msg_t prefixed = {
        .request_id = 2,
        .track_namespace_num = 1,
        .track_namespace_tuple = &live,
        .params_num = 1,
        .params = &forward,
    };
    uint8_t buf[64] = {0};

    xqc_moq_msg_subscribe_tracks_init_handler(&root.msg_base);
    xqc_int_t len =
        xqc_moq_msg_encode_subscribe_tracks_len(&root.msg_base);
    XQC_TEST_ASSERT(len == (xqc_int_t)sizeof(expected_root));
    XQC_TEST_ASSERT(xqc_moq_msg_encode_subscribe_tracks(
        &root.msg_base, buf, sizeof(buf)) == len);
    XQC_TEST_ASSERT(memcmp(buf, expected_root, sizeof(expected_root)) == 0);

    memset(buf, 0, sizeof(buf));
    xqc_moq_msg_subscribe_tracks_init_handler(&prefixed.msg_base);
    len = xqc_moq_msg_encode_subscribe_tracks_len(&prefixed.msg_base);
    XQC_TEST_ASSERT(len
                    == (xqc_int_t)sizeof(expected_live_forward_zero));
    XQC_TEST_ASSERT(xqc_moq_msg_encode_subscribe_tracks(
        &prefixed.msg_base, buf, sizeof(buf)) == len);
    XQC_TEST_ASSERT(memcmp(buf, expected_live_forward_zero,
                           sizeof(expected_live_forward_zero)) == 0);
    return 0;
}

static int
xqc_test_subscribe_tracks_then_request_update_continuous_decode(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.session_setup_done = 1;
    xqc_moq_user_session_t user_session = {
        .session = &session,
    };
    session.user_session = &user_session;
    xqc_moq_session_set_request_update_callback(
        &session, xqc_test_on_request_update);

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    stream.kind = XQC_MOQ_STREAM_D18_REQUEST;
    xqc_moq_d18_update_queue_init(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&stream.d18_peer_update_queue);
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class =
        XQC_MOQ_D18_STREAM_UNCLASSIFIED;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_FIRST;

    xqc_moq_track_ns_field_t initial_prefix[2] = {
        {
            .len = sizeof("update") - 1,
            .data = (unsigned char *)"update",
        },
        {
            .len = sizeof("old") - 1,
            .data = (unsigned char *)"old",
        },
    };
    xqc_moq_message_parameter_t forward = {
        .type = XQC_MOQ_D18_PARAM_FORWARD,
        .is_integer = 1,
        .int_value = 0,
    };
    xqc_moq_subscribe_tracks_msg_t initial = {
        .request_id = 0,
        .track_namespace_num = 2,
        .track_namespace_tuple = initial_prefix,
        .params_num = 1,
        .params = &forward,
    };
    xqc_moq_msg_subscribe_tracks_init_handler(&initial.msg_base);

    uint8_t serialized_prefix[] = {
        0x02, 0x06, 'u', 'p', 'd', 'a', 't', 'e',
        0x03, 'n', 'e', 'w',
    };
    xqc_moq_message_parameter_t prefix = {
        .type = XQC_MOQ_D18_PARAM_TRACK_NAMESPACE_PREFIX,
        .length = sizeof(serialized_prefix),
        .value = serialized_prefix,
    };
    xqc_moq_request_update_msg_t update = {
        .request_id = 2,
        .params_num = 1,
        .params = &prefix,
    };
    xqc_moq_d18_request_update_init_handler(
        &update.msg_base,
        XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_NAMESPACE);

    uint8_t wire[128] = {0};
    xqc_int_t initial_len =
        xqc_moq_msg_encode_subscribe_tracks_len(&initial.msg_base);
    XQC_TEST_ASSERT(initial_len > 0);
    XQC_TEST_ASSERT(xqc_moq_msg_encode_subscribe_tracks(
        &initial.msg_base, wire, sizeof(wire)) == initial_len);
    xqc_int_t update_len =
        xqc_moq_d18_request_update_encode_len(&update.msg_base);
    XQC_TEST_ASSERT(update_len > 0);
    XQC_TEST_ASSERT(xqc_moq_d18_request_update_encode(
        &update.msg_base, wire + initial_len,
        sizeof(wire) - (size_t)initial_len) == update_len);

    xqc_test_request_update_callback_count = 0;
    xqc_test_request_update_target_id = XQC_MOQ_INVALID_ID;
    xqc_test_request_update_id = XQC_MOQ_INVALID_ID;
    XQC_TEST_ASSERT(xqc_moq_stream_process(
        &stream, wire, (size_t)(initial_len + update_len), 0)
        == initial_len + update_len);
    XQC_TEST_ASSERT(stream.d18_context.stream_class
                    == XQC_MOQ_D18_STREAM_REQUEST);
    XQC_TEST_ASSERT(stream.d18_context.position
                    == XQC_MOQ_D18_POSITION_NEXT);
    XQC_TEST_ASSERT(stream.decode_msg_ctx.cur_decode_state
                    == XQC_MOQ_DECODE_MSG_TYPE);
    XQC_TEST_ASSERT(xqc_test_request_update_callback_count == 1);
    XQC_TEST_ASSERT(xqc_test_request_update_target_id == 0);
    XQC_TEST_ASSERT(xqc_test_request_update_id == 2);

    xqc_moq_stream_on_request_closed(
        &stream, XQC_MOQ_REQUEST_CANCELLED);
    xqc_moq_d18_update_queue_destroy(
        &stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(
        &stream.d18_peer_update_queue);
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

static int
xqc_test_subscribe_tracks_fragmented_decode(void)
{
    static const uint8_t encoded[] = {
        0x00, 0x0a,
        0x02,
        0x01, 0x04, 'l', 'i', 'v', 'e',
        0x01, 0x10, 0x00,
    };
    xqc_moq_subscribe_tracks_msg_t *decoded =
        xqc_moq_msg_create_subscribe_tracks();
    xqc_moq_decode_msg_ctx_t msg_ctx = {0};
    xqc_int_t finish = 0;
    xqc_int_t wait_more_data = 0;

    XQC_TEST_ASSERT(decoded != NULL);
    xqc_moq_msg_subscribe_tracks_init_handler(&decoded->msg_base);
    XQC_TEST_ASSERT(decoded->msg_base.decode(
        (uint8_t *)encoded, 2, 0, &msg_ctx, &decoded->msg_base,
        &finish, &wait_more_data) == 2);
    XQC_TEST_ASSERT(finish == 0);
    XQC_TEST_ASSERT(wait_more_data == 1);
    for (size_t i = 2; i < sizeof(encoded); i++) {
        finish = 0;
        wait_more_data = 0;
        XQC_TEST_ASSERT(decoded->msg_base.decode(
            (uint8_t *)encoded + i, 1, i + 1 == sizeof(encoded),
            &msg_ctx, &decoded->msg_base, &finish,
            &wait_more_data) == 1);
        XQC_TEST_ASSERT(finish == (i + 1 == sizeof(encoded)));
        XQC_TEST_ASSERT(wait_more_data
                        == (i + 1 != sizeof(encoded)));
    }
    XQC_TEST_ASSERT(decoded->request_id == 2);
    XQC_TEST_ASSERT(decoded->track_namespace_num == 1);
    XQC_TEST_ASSERT(decoded->track_namespace_tuple != NULL);
    XQC_TEST_ASSERT(decoded->track_namespace_tuple[0].len == 4);
    XQC_TEST_ASSERT(memcmp(decoded->track_namespace_tuple[0].data,
                           "live", 4) == 0);
    XQC_TEST_ASSERT(decoded->params_num == 1);
    XQC_TEST_ASSERT(decoded->params[0].type
                    == XQC_MOQ_D18_PARAM_FORWARD);
    XQC_TEST_ASSERT(decoded->params[0].is_integer == 1);
    XQC_TEST_ASSERT(decoded->params[0].int_value == 0);
    xqc_moq_msg_free_subscribe_tracks(decoded);
    return 0;
}

static int
xqc_test_request_update_writer_uses_established_request_stream(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_auth_cache_init(&session.peer_auth_cache, 64);

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    xqc_moq_d18_update_queue_init(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&stream.d18_peer_update_queue);
    stream.local_request = 1;
    stream.response_received = 1;
    stream.request_type = XQC_MOQ_MSG_SUBSCRIBE;
    stream.request_id = 1;
    XQC_TEST_ASSERT(xqc_moq_session_register_local_request_id(
        &session, stream.request_id) == XQC_MOQ_D18_REQUEST_ID_OK);
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    xqc_list_add_tail(&stream.request_list_member,
                      &session.local_request_stream_list);

    xqc_moq_message_parameter_t forward = {
        .type = XQC_MOQ_D18_PARAM_FORWARD,
        .is_integer = 1,
        .int_value = 1,
    };
    xqc_moq_request_update_msg_t update = {
        .params_num = 1,
        .params = &forward,
    };
    XQC_TEST_ASSERT(xqc_moq_write_request_update(
        &session, stream.request_id, &update) == XQC_OK);
    XQC_TEST_ASSERT(update.request_id == 3);
    XQC_TEST_ASSERT(capture.write_count == 1);
    XQC_TEST_ASSERT(capture.bytes[0] == XQC_MOQ_D18_MSG_REQUEST_UPDATE);
    XQC_TEST_ASSERT(stream.response_received == 1);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_local_update_queue)->request_id == update.request_id);

    xqc_moq_request_update_msg_t duplicate = {
        .request_id = update.request_id,
    };
    size_t bytes_before = capture.length;
    XQC_TEST_ASSERT(xqc_moq_write_request_update(
        &session, stream.request_id, &duplicate) == -XQC_EPARAM);
    XQC_TEST_ASSERT(capture.length == bytes_before);

    xqc_moq_request_update_msg_t wrong_parity = {
        .request_id = 2,
    };
    XQC_TEST_ASSERT(xqc_moq_write_request_update(
        &session, stream.request_id, &wrong_parity) == -XQC_EPARAM);
    XQC_TEST_ASSERT(capture.length == bytes_before);

    xqc_moq_d18_update_queue_destroy(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(&stream.d18_peer_update_queue);
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static int
xqc_test_failed_request_update_consumes_id_without_leaking_frame(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);

    xqc_test_write_capture_t capture = {
        .fail_write = 1,
    };
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    xqc_moq_d18_update_queue_init(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&stream.d18_peer_update_queue);
    stream.local_request = 1;
    stream.response_received = 1;
    stream.request_type = XQC_MOQ_MSG_SUBSCRIBE;
    stream.request_id = 1;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    XQC_TEST_ASSERT(xqc_moq_session_register_local_request_id(
        &session, stream.request_id) == XQC_MOQ_D18_REQUEST_ID_OK);
    xqc_list_add_tail(&stream.request_list_member,
                      &session.local_request_stream_list);

    xqc_moq_request_update_msg_t failed = {0};
    XQC_TEST_ASSERT(xqc_moq_write_request_update(
        &session, stream.request_id, &failed) == -XQC_ESYS);
    XQC_TEST_ASSERT(failed.request_id == 3);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_local_update_queue) == NULL);

    capture.fail_write = 0;
    xqc_moq_request_update_msg_t succeeded = {0};
    XQC_TEST_ASSERT(xqc_moq_write_request_update(
        &session, stream.request_id, &succeeded) == XQC_OK);
    XQC_TEST_ASSERT(succeeded.request_id == 5);
    XQC_TEST_ASSERT(capture.length == 5);
    XQC_TEST_ASSERT(capture.bytes[3] == succeeded.request_id);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_local_update_queue)->request_id
        == succeeded.request_id);

    xqc_moq_d18_update_queue_destroy(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(&stream.d18_peer_update_queue);
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static int
xqc_test_publish_reverse_request_update_directions(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    xqc_connection_t quic_conn;
    xqc_memzero(&quic_conn, sizeof(quic_conn));
    quic_conn.conn_err = UINT64_MAX;
    quic_conn.log = &xqc_test_log;
    session.quic_conn = &quic_conn;
    session.session_callbacks_ext.on_request_ok = xqc_test_on_request_ok;

    xqc_test_write_capture_t peer_capture = {0};
    xqc_moq_stream_t peer_publish;
    xqc_test_init_stream(&peer_publish, &session, &peer_capture);
    xqc_moq_d18_update_queue_init(&peer_publish.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&peer_publish.d18_peer_update_queue);
    peer_publish.peer_request = 1;
    peer_publish.response_sent = 1;
    peer_publish.request_type = XQC_MOQ_MSG_PUBLISH;
    peer_publish.request_id = 0;
    peer_publish.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    peer_publish.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    peer_publish.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    XQC_TEST_ASSERT(xqc_moq_session_register_peer_request_id(
        &session, peer_publish.request_id) == XQC_MOQ_D18_REQUEST_ID_OK);
    xqc_list_add_tail(&peer_publish.request_list_member,
                      &session.peer_request_stream_list);

    xqc_moq_message_parameter_t forward = {
        .type = XQC_MOQ_D18_PARAM_FORWARD,
        .is_integer = 1,
        .int_value = 1,
    };
    xqc_moq_request_update_msg_t local_update = {
        .params_num = 1,
        .params = &forward,
    };
    XQC_TEST_ASSERT(xqc_moq_write_request_update(
        &session, peer_publish.request_id, &local_update) == XQC_OK);
    XQC_TEST_ASSERT(local_update.request_id == 1);
    xqc_test_update_result_count = 0;
    xqc_moq_request_ok_msg_t ok = {0};
    xqc_moq_on_request_ok(&session, &peer_publish, &ok.msg_base);
    XQC_TEST_ASSERT(xqc_test_update_result_count == 1);
    XQC_TEST_ASSERT(xqc_test_update_result_ids[0]
                    == local_update.request_id);
    XQC_TEST_ASSERT(peer_publish.response_sent == 1);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &peer_publish.d18_local_update_queue) == NULL);

    xqc_test_write_capture_t local_capture = {0};
    xqc_moq_stream_t local_publish;
    xqc_test_init_stream(&local_publish, &session, &local_capture);
    xqc_moq_d18_update_queue_init(&local_publish.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&local_publish.d18_peer_update_queue);
    local_publish.local_request = 1;
    local_publish.response_received = 1;
    local_publish.request_type = XQC_MOQ_MSG_PUBLISH;
    local_publish.request_id = 3;
    local_publish.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    local_publish.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    local_publish.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    XQC_TEST_ASSERT(xqc_moq_session_register_local_request_id(
        &session, local_publish.request_id) == XQC_MOQ_D18_REQUEST_ID_OK);
    xqc_list_add_tail(&local_publish.request_list_member,
                      &session.local_request_stream_list);

    xqc_moq_request_update_msg_t peer_update = {
        .request_id = 2,
        .params_num = 1,
        .params = &forward,
    };
    xqc_moq_on_request_update(
        &session, &local_publish, &peer_update.msg_base);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &local_publish.d18_peer_update_queue)->request_id
        == peer_update.request_id);
    XQC_TEST_ASSERT(xqc_moq_write_request_ok(
        &session, peer_update.request_id, &ok) == XQC_OK);
    XQC_TEST_ASSERT(local_publish.response_received == 1);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &local_publish.d18_peer_update_queue) == NULL);

    xqc_moq_d18_params_free(peer_publish.d18_accepted_params,
                            peer_publish.d18_accepted_params_num);
    peer_publish.d18_accepted_params = NULL;
    peer_publish.d18_accepted_params_num = 0;
    xqc_moq_d18_params_free(local_publish.d18_accepted_params,
                            local_publish.d18_accepted_params_num);
    local_publish.d18_accepted_params = NULL;
    local_publish.d18_accepted_params_num = 0;
    xqc_moq_d18_update_queue_destroy(&peer_publish.d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(&peer_publish.d18_peer_update_queue);
    xqc_moq_d18_update_queue_destroy(&local_publish.d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(&local_publish.d18_peer_update_queue);
    xqc_test_clean_stream(&local_publish);
    xqc_test_clean_stream(&peer_publish);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_free((void *)quic_conn.conn_close_msg);
    return 0;
}

static int
xqc_test_non_publish_reverse_request_updates_are_rejected(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    xqc_connection_t quic_conn;
    xqc_memzero(&quic_conn, sizeof(quic_conn));
    quic_conn.conn_err = UINT64_MAX;
    quic_conn.log = &xqc_test_log;
    session.quic_conn = &quic_conn;

    xqc_test_write_capture_t peer_capture = {0};
    xqc_moq_stream_t peer_subscribe;
    xqc_test_init_stream(&peer_subscribe, &session, &peer_capture);
    xqc_moq_d18_update_queue_init(&peer_subscribe.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&peer_subscribe.d18_peer_update_queue);
    peer_subscribe.peer_request = 1;
    peer_subscribe.response_sent = 1;
    peer_subscribe.request_type = XQC_MOQ_MSG_SUBSCRIBE;
    peer_subscribe.request_id = 0;
    peer_subscribe.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    peer_subscribe.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    peer_subscribe.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    XQC_TEST_ASSERT(xqc_moq_session_register_peer_request_id(
        &session, peer_subscribe.request_id) == XQC_MOQ_D18_REQUEST_ID_OK);
    xqc_list_add_tail(&peer_subscribe.request_list_member,
                      &session.peer_request_stream_list);
    xqc_moq_request_update_msg_t illegal_local = {0};
    XQC_TEST_ASSERT(xqc_moq_write_request_update(
        &session, peer_subscribe.request_id, &illegal_local)
        == -XQC_EPARAM);
    XQC_TEST_ASSERT(peer_capture.write_count == 0);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &peer_subscribe.d18_local_update_queue) == NULL);

    xqc_test_write_capture_t local_capture = {0};
    xqc_moq_stream_t local_subscribe;
    xqc_test_init_stream(&local_subscribe, &session, &local_capture);
    xqc_moq_d18_update_queue_init(&local_subscribe.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&local_subscribe.d18_peer_update_queue);
    local_subscribe.local_request = 1;
    local_subscribe.response_received = 1;
    local_subscribe.request_type = XQC_MOQ_MSG_SUBSCRIBE;
    local_subscribe.request_id = 1;
    XQC_TEST_ASSERT(xqc_moq_session_register_local_request_id(
        &session, local_subscribe.request_id)
        == XQC_MOQ_D18_REQUEST_ID_OK);
    xqc_list_add_tail(&local_subscribe.request_list_member,
                      &session.local_request_stream_list);
    xqc_moq_request_update_msg_t illegal_peer = {
        .request_id = 2,
    };
    xqc_moq_on_request_update(
        &session, &local_subscribe, &illegal_peer.msg_base);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &local_subscribe.d18_peer_update_queue) == NULL);
    XQC_TEST_ASSERT(quic_conn.conn_err == UINT64_MAX);
    XQC_TEST_ASSERT(quic_conn.conn_close_msg != NULL);
    XQC_TEST_ASSERT(strcmp(quic_conn.conn_close_msg,
                           "REQUEST_UPDATE on invalid request stream") == 0);
    XQC_TEST_ASSERT(local_subscribe.response_received == 1);

    xqc_moq_d18_update_queue_destroy(&peer_subscribe.d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(&peer_subscribe.d18_peer_update_queue);
    xqc_moq_d18_update_queue_destroy(&local_subscribe.d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(&local_subscribe.d18_peer_update_queue);
    xqc_test_clean_stream(&local_subscribe);
    xqc_test_clean_stream(&peer_subscribe);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static int
xqc_test_incoming_request_update_rejects_duplicate_and_wrong_parity_ids(void)
{
    struct {
        uint64_t update_id;
        uint8_t pre_register;
    } cases[] = {
        {2, 1},
        {1, 0},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        xqc_moq_session_t session;
        xqc_test_init_session(&session);
        xqc_connection_t quic_conn;
        xqc_memzero(&quic_conn, sizeof(quic_conn));
        quic_conn.conn_err = UINT64_MAX;
        quic_conn.log = &xqc_test_log;
        session.quic_conn = &quic_conn;
        xqc_moq_session_set_request_update_callback(
            &session, xqc_test_on_request_update);

        xqc_test_write_capture_t capture = {0};
        xqc_moq_stream_t stream;
        xqc_test_init_stream(&stream, &session, &capture);
        xqc_moq_d18_update_queue_init(&stream.d18_local_update_queue);
        xqc_moq_d18_update_queue_init(&stream.d18_peer_update_queue);
        stream.peer_request = 1;
        stream.response_sent = 1;
        stream.request_type = XQC_MOQ_MSG_SUBSCRIBE;
        stream.request_id = 0;
        XQC_TEST_ASSERT(xqc_moq_session_register_peer_request_id(
            &session, stream.request_id) == XQC_MOQ_D18_REQUEST_ID_OK);
        if (cases[i].pre_register) {
            XQC_TEST_ASSERT(xqc_moq_session_register_peer_request_id(
                &session, cases[i].update_id)
                == XQC_MOQ_D18_REQUEST_ID_OK);
        }
        xqc_list_add_tail(&stream.request_list_member,
                          &session.peer_request_stream_list);

        xqc_moq_message_parameter_t forward = {
            .type = XQC_MOQ_D18_PARAM_FORWARD,
            .is_integer = 1,
            .int_value = 1,
        };
        xqc_moq_request_update_msg_t update = {
            .request_id = cases[i].update_id,
            .params_num = 1,
            .params = &forward,
        };
        xqc_test_request_update_callback_count = 0;
        xqc_moq_on_request_update(&session, &stream, &update.msg_base);
        XQC_TEST_ASSERT(xqc_test_request_update_callback_count == 0);
        XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
            &stream.d18_peer_update_queue) == NULL);
        XQC_TEST_ASSERT(quic_conn.conn_close_msg != NULL);
        XQC_TEST_ASSERT(strcmp(quic_conn.conn_close_msg,
                               "invalid draft-18 request ID") == 0);

        xqc_moq_d18_update_queue_destroy(&stream.d18_local_update_queue);
        xqc_moq_d18_update_queue_destroy(&stream.d18_peer_update_queue);
        xqc_test_clean_stream(&stream);
        xqc_moq_d18_request_registry_destroy(
            &session.d18_request_registry);
        xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    }
    return 0;
}

static int
xqc_test_request_update_writer_rejects_pending_terminal_and_ineligible(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    xqc_moq_stream_t streams[3];
    xqc_test_write_capture_t captures[3] = {0};
    xqc_moq_msg_type_t request_types[] = {
        XQC_MOQ_MSG_SUBSCRIBE,
        XQC_MOQ_MSG_SUBSCRIBE,
        XQC_MOQ_MSG_TRACK_STATUS,
    };
    for (size_t i = 0; i < 3; i++) {
        xqc_test_init_stream(&streams[i], &session, &captures[i]);
        xqc_moq_d18_update_queue_init(&streams[i].d18_local_update_queue);
        xqc_moq_d18_update_queue_init(&streams[i].d18_peer_update_queue);
        streams[i].local_request = 1;
        streams[i].request_type = request_types[i];
        streams[i].request_id = 1 + 2 * i;
        streams[i].response_received = i == 0 ? 0 : 1;
        streams[i].request_closed_notified = i == 1 ? 1 : 0;
        streams[i].d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
        streams[i].d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
        streams[i].d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
        XQC_TEST_ASSERT(xqc_moq_session_register_local_request_id(
            &session, streams[i].request_id)
            == XQC_MOQ_D18_REQUEST_ID_OK);
        xqc_list_add_tail(&streams[i].request_list_member,
                          &session.local_request_stream_list);

        xqc_moq_message_parameter_t forward = {
            .type = XQC_MOQ_D18_PARAM_FORWARD,
            .is_integer = 1,
            .int_value = 1,
        };
        xqc_moq_request_update_msg_t update = {
            .params_num = 1,
            .params = &forward,
        };
        XQC_TEST_ASSERT(xqc_moq_write_request_update(
            &session, streams[i].request_id, &update) == -XQC_EPARAM);
        XQC_TEST_ASSERT(captures[i].length == 0);
        XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
            &streams[i].d18_local_update_queue) == NULL);
    }

    for (size_t i = 0; i < 3; i++) {
        xqc_moq_d18_update_queue_destroy(&streams[i].d18_local_update_queue);
        xqc_moq_d18_update_queue_destroy(&streams[i].d18_peer_update_queue);
        xqc_test_clean_stream(&streams[i]);
    }
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static int
xqc_test_local_namespace_updates_allow_prefix_absent(void)
{
    xqc_moq_msg_type_t request_types[] = {
        XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE,
        XQC_MOQ_MSG_SUBSCRIBE_TRACKS,
        XQC_MOQ_MSG_PUBLISH_NAMESPACE,
    };
    for (size_t type_index = 0;
         type_index < sizeof(request_types) / sizeof(request_types[0]);
         type_index++)
    {
        xqc_moq_session_t session;
        xqc_test_init_session(&session);
        xqc_test_write_capture_t capture = {0};
        xqc_moq_stream_t stream;
        xqc_test_init_stream(&stream, &session, &capture);
        xqc_moq_d18_update_queue_init(&stream.d18_local_update_queue);
        xqc_moq_d18_update_queue_init(&stream.d18_peer_update_queue);
        stream.local_request = 1;
        stream.response_received = 1;
        stream.request_type = request_types[type_index];
        stream.request_id = 1;
        stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
        stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
        stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
        XQC_TEST_ASSERT(xqc_moq_session_register_local_request_id(
            &session, stream.request_id) == XQC_MOQ_D18_REQUEST_ID_OK);
        xqc_list_add_tail(&stream.request_list_member,
                          &session.local_request_stream_list);

        xqc_moq_track_ns_field_t old_field = {
            .len = 3,
            .data = (unsigned char *)"old",
        };
        xqc_moq_namespace_prefix_t *old_prefix = NULL;
        if (stream.request_type == XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE
            || stream.request_type == XQC_MOQ_MSG_SUBSCRIBE_TRACKS)
        {
            old_prefix =
                xqc_moq_namespace_prefix_create_copy(&old_field, 1);
            XQC_TEST_ASSERT(old_prefix != NULL);
            old_prefix->request_id = stream.request_id;
            if (stream.request_type == XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE) {
                stream.namespace_subscription = old_prefix;
            } else {
                stream.tracks_subscription = old_prefix;
                stream.subscribe_tracks_active = 1;
            }
        }

        xqc_moq_request_update_msg_t noop = {
            .request_id = 3,
        };
        XQC_TEST_ASSERT(xqc_moq_write_request_update(
            &session, stream.request_id, &noop) == XQC_OK);
        xqc_moq_request_ok_msg_t ok = {0};
        xqc_moq_on_request_ok(&session, &stream, &ok.msg_base);
        XQC_TEST_ASSERT(stream.d18_accepted_params_num == 0);
        XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
            &stream.d18_local_update_queue) == NULL);

        uint8_t register_token[] = {
            XQC_MOQ_D18_AUTH_REGISTER, 0x07, 0x02, 'a', 'b',
        };
        xqc_moq_message_parameter_t auth = {
            .type = XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN,
            .length = sizeof(register_token),
            .value = register_token,
        };
        xqc_moq_request_update_msg_t auth_only = {
            .request_id = 5,
            .params_num = 1,
            .params = &auth,
        };
        XQC_TEST_ASSERT(xqc_moq_write_request_update(
            &session, stream.request_id, &auth_only) == XQC_OK);
        xqc_moq_on_request_ok(&session, &stream, &ok.msg_base);
        XQC_TEST_ASSERT(stream.d18_accepted_params_num == 1);
        XQC_TEST_ASSERT(stream.d18_accepted_params[0].type
                        == XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN);
        if (stream.request_type == XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE) {
            XQC_TEST_ASSERT(stream.namespace_subscription == old_prefix);
            XQC_TEST_ASSERT(memcmp(
                stream.namespace_subscription->prefix_tuple[0].data,
                "old", 3) == 0);

        } else if (stream.request_type
                   == XQC_MOQ_MSG_SUBSCRIBE_TRACKS)
        {
            XQC_TEST_ASSERT(stream.tracks_subscription == old_prefix);
            XQC_TEST_ASSERT(memcmp(
                stream.tracks_subscription->prefix_tuple[0].data,
                "old", 3) == 0);
        }

        if (stream.request_type == XQC_MOQ_MSG_PUBLISH_NAMESPACE) {
            uint8_t serialized_prefix[] = {
                0x01, 0x03, 'n', 'e', 'w',
            };
            xqc_moq_message_parameter_t prefix = {
                .type = XQC_MOQ_D18_PARAM_TRACK_NAMESPACE_PREFIX,
                .length = sizeof(serialized_prefix),
                .value = serialized_prefix,
            };
            xqc_moq_request_update_msg_t invalid = {
                .request_id = 7,
                .params_num = 1,
                .params = &prefix,
            };
            size_t previous_length = capture.length;
            XQC_TEST_ASSERT(xqc_moq_write_request_update(
                &session, stream.request_id, &invalid) == -XQC_EPARAM);
            XQC_TEST_ASSERT(capture.length == previous_length);
            XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
                &stream.d18_local_update_queue) == NULL);
        }

        if (stream.namespace_subscription != NULL) {
            xqc_moq_namespace_prefix_destroy(
                stream.namespace_subscription);
            stream.namespace_subscription = NULL;
        }
        if (stream.tracks_subscription != NULL) {
            xqc_moq_namespace_prefix_destroy(
                stream.tracks_subscription);
            stream.tracks_subscription = NULL;
        }
        xqc_moq_d18_params_free(stream.d18_accepted_params,
                                stream.d18_accepted_params_num);
        stream.d18_accepted_params = NULL;
        stream.d18_accepted_params_num = 0;
        xqc_moq_d18_update_queue_destroy(
            &stream.d18_local_update_queue);
        xqc_moq_d18_update_queue_destroy(
            &stream.d18_peer_update_queue);
        xqc_test_clean_stream(&stream);
        xqc_moq_d18_request_registry_destroy(
            &session.d18_request_registry);
        xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    }
    return 0;
}

static int
xqc_test_peer_namespace_updates_allow_prefix_absent(void)
{
    xqc_moq_msg_type_t request_types[] = {
        XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE,
        XQC_MOQ_MSG_SUBSCRIBE_TRACKS,
        XQC_MOQ_MSG_PUBLISH_NAMESPACE,
    };
    for (size_t type_index = 0;
         type_index < sizeof(request_types) / sizeof(request_types[0]);
         type_index++)
    {
        xqc_moq_session_t session;
        xqc_test_init_session(&session);
        xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
        xqc_moq_d18_auth_cache_init(&session.peer_auth_cache, 64);
        xqc_connection_t quic_conn;
        xqc_memzero(&quic_conn, sizeof(quic_conn));
        quic_conn.conn_err = UINT64_MAX;
        quic_conn.log = &xqc_test_log;
        session.quic_conn = &quic_conn;
        xqc_moq_session_set_request_update_callback(
            &session, xqc_test_on_request_update);

        xqc_test_write_capture_t capture = {0};
        xqc_moq_stream_t stream;
        xqc_test_init_stream(&stream, &session, &capture);
        xqc_moq_d18_update_queue_init(&stream.d18_local_update_queue);
        xqc_moq_d18_update_queue_init(&stream.d18_peer_update_queue);
        stream.peer_request = 1;
        stream.response_sent = 1;
        stream.request_type = request_types[type_index];
        stream.request_id = 0;
        stream.kind = XQC_MOQ_STREAM_D18_REQUEST;
        stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
        stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
        stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
        XQC_TEST_ASSERT(xqc_moq_session_register_peer_request_id(
            &session, stream.request_id) == XQC_MOQ_D18_REQUEST_ID_OK);
        xqc_list_add_tail(&stream.request_list_member,
                          &session.peer_request_stream_list);

        xqc_moq_track_ns_field_t old_field = {
            .len = 3,
            .data = (unsigned char *)"old",
        };
        xqc_moq_namespace_prefix_t *old_prefix = NULL;
        if (stream.request_type == XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE
            || stream.request_type == XQC_MOQ_MSG_SUBSCRIBE_TRACKS)
        {
            old_prefix =
                xqc_moq_namespace_prefix_create_copy(&old_field, 1);
            XQC_TEST_ASSERT(old_prefix != NULL);
            old_prefix->request_id = stream.request_id;
            if (stream.request_type == XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE) {
                xqc_list_add_tail(
                    &old_prefix->list_member,
                    &session.peer_subscribe_namespace_list);

            } else {
                stream.tracks_subscription = old_prefix;
                stream.subscribe_tracks_active = 1;
            }
        }

        xqc_moq_request_update_msg_t noop = {
            .request_id = 2,
        };
        xqc_test_request_update_callback_count = 0;
        xqc_moq_on_request_update(&session, &stream, &noop.msg_base);
        XQC_TEST_ASSERT(xqc_test_request_update_callback_count == 1);
        XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
            &stream.d18_peer_update_queue)->request_id
            == noop.request_id);
        xqc_moq_request_ok_msg_t ok = {0};
        XQC_TEST_ASSERT(xqc_moq_write_request_ok(
            &session, noop.request_id, &ok) == XQC_OK);
        XQC_TEST_ASSERT(stream.d18_accepted_params_num == 0);

        uint8_t register_token[] = {
            XQC_MOQ_D18_AUTH_REGISTER, 0x07, 0x02, 'a', 'b',
        };
        xqc_moq_message_parameter_t auth = {
            .type = XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN,
            .length = sizeof(register_token),
            .value = register_token,
        };
        xqc_moq_request_update_msg_t auth_only = {
            .request_id = 4,
            .params_num = 1,
            .params = &auth,
        };
        xqc_moq_on_request_update(
            &session, &stream, &auth_only.msg_base);
        XQC_TEST_ASSERT(xqc_test_request_update_callback_count == 2);
        XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
            &stream.d18_peer_update_queue)->request_id
            == auth_only.request_id);
        XQC_TEST_ASSERT(xqc_moq_write_request_ok(
            &session, auth_only.request_id, &ok) == XQC_OK);
        XQC_TEST_ASSERT(stream.d18_accepted_params_num == 1);
        XQC_TEST_ASSERT(stream.d18_accepted_params[0].type
                        == XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN);
        xqc_moq_request_auth_destroy(&auth_only.request_auth);

        if (stream.request_type == XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE) {
            XQC_TEST_ASSERT(!xqc_list_empty(&old_prefix->list_member));
            XQC_TEST_ASSERT(memcmp(
                old_prefix->prefix_tuple[0].data, "old", 3) == 0);

        } else if (stream.request_type
                   == XQC_MOQ_MSG_SUBSCRIBE_TRACKS)
        {
            XQC_TEST_ASSERT(stream.tracks_subscription == old_prefix);
            XQC_TEST_ASSERT(memcmp(
                old_prefix->prefix_tuple[0].data, "old", 3) == 0);
        }

        if (stream.request_type == XQC_MOQ_MSG_PUBLISH_NAMESPACE) {
            uint8_t serialized_prefix[] = {
                0x01, 0x03, 'n', 'e', 'w',
            };
            xqc_moq_message_parameter_t prefix = {
                .type = XQC_MOQ_D18_PARAM_TRACK_NAMESPACE_PREFIX,
                .length = sizeof(serialized_prefix),
                .value = serialized_prefix,
            };
            xqc_moq_request_update_msg_t invalid = {
                .request_id = 6,
                .params_num = 1,
                .params = &prefix,
            };
            xqc_moq_on_request_update(
                &session, &stream, &invalid.msg_base);
            XQC_TEST_ASSERT(xqc_test_request_update_callback_count == 2);
            XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
                &stream.d18_peer_update_queue) == NULL);
            XQC_TEST_ASSERT(quic_conn.conn_close_msg != NULL);
            XQC_TEST_ASSERT(strcmp(
                quic_conn.conn_close_msg,
                "TRACK_NAMESPACE_PREFIX on PUBLISH_NAMESPACE update")
                == 0);
        }

        if (stream.request_type == XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE) {
            xqc_list_del_init(&old_prefix->list_member);
            xqc_moq_namespace_prefix_destroy(old_prefix);
        } else if (stream.tracks_subscription != NULL) {
            xqc_moq_namespace_prefix_destroy(
                stream.tracks_subscription);
            stream.tracks_subscription = NULL;
        }
        xqc_moq_d18_params_free(stream.d18_accepted_params,
                                stream.d18_accepted_params_num);
        stream.d18_accepted_params = NULL;
        stream.d18_accepted_params_num = 0;
        xqc_moq_d18_update_queue_destroy(
            &stream.d18_local_update_queue);
        xqc_moq_d18_update_queue_destroy(
            &stream.d18_peer_update_queue);
        xqc_test_clean_stream(&stream);
        xqc_moq_d18_request_registry_destroy(
            &session.d18_request_registry);
        xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    }
    return 0;
}

static int
xqc_test_encode_request_update(
    xqc_moq_request_update_msg_t *update,
    xqc_moq_d18_param_context_t context,
    uint8_t *buf, size_t cap, size_t *encoded_len)
{
    xqc_moq_d18_request_update_init_handler(
        &update->msg_base, context);
    xqc_int_t len = xqc_moq_d18_request_update_encode(
        &update->msg_base, buf, cap);
    XQC_TEST_ASSERT(len > 0);
    *encoded_len = (size_t)len;
    return 0;
}

static int
xqc_test_request_update_callback_view_survives_decode_cleanup(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_auth_cache_init(&session.peer_auth_cache, 64);
    xqc_moq_user_session_t user_session = {
        .session = &session,
    };
    session.user_session = &user_session;
    xqc_moq_session_set_request_update_callback(
        &session, xqc_test_on_request_update_deferred);

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    xqc_moq_d18_update_queue_init(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&stream.d18_peer_update_queue);
    stream.peer_request = 1;
    stream.response_sent = 1;
    stream.request_type = XQC_MOQ_MSG_SUBSCRIBE;
    stream.request_id = 0;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    XQC_TEST_ASSERT(xqc_moq_session_register_peer_request_id(
        &session, stream.request_id) == XQC_MOQ_D18_REQUEST_ID_OK);
    xqc_list_add_tail(&stream.request_list_member,
                      &session.peer_request_stream_list);

    uint8_t register_token[] = {
        XQC_MOQ_D18_AUTH_REGISTER, 0x07, 0x02, 'a', 'b',
    };
    xqc_moq_message_parameter_t auth = {
        .type = XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN,
        .length = sizeof(register_token),
        .value = register_token,
    };
    xqc_moq_request_update_msg_t update = {
        .request_id = 2,
        .params_num = 1,
        .params = &auth,
    };
    uint8_t encoded[64] = {0};
    size_t encoded_len = 0;
    XQC_TEST_ASSERT(xqc_test_encode_request_update(
        &update, XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_SUBSCRIBE,
        encoded, sizeof(encoded), &encoded_len) == 0);

    xqc_test_deferred_update_view = NULL;
    xqc_test_deferred_update_params = NULL;
    xqc_test_deferred_update_tokens = NULL;
    XQC_TEST_ASSERT(xqc_moq_stream_process(
        &stream, encoded, encoded_len, 0) == (xqc_int_t)encoded_len);
    XQC_TEST_ASSERT(stream.decode_msg_ctx.cur_decode_msg == NULL);
    XQC_TEST_ASSERT(xqc_test_deferred_update_view != NULL);
    XQC_TEST_ASSERT(xqc_test_deferred_update_view->request_id == 2);
    XQC_TEST_ASSERT(xqc_test_deferred_update_view->params_num == 1);
    XQC_TEST_ASSERT(xqc_test_deferred_update_params[0].type
                    == XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN);

    xqc_moq_d18_update_record_t *record =
        xqc_moq_d18_update_queue_peek(&stream.d18_peer_update_queue);
    XQC_TEST_ASSERT(record != NULL);
    XQC_TEST_ASSERT(xqc_test_deferred_update_params == record->params);
    XQC_TEST_ASSERT(xqc_test_deferred_update_view->request_auth.count == 1);
    XQC_TEST_ASSERT(xqc_test_deferred_update_tokens
                    == xqc_test_deferred_update_view->request_auth.tokens);
    XQC_TEST_ASSERT(xqc_test_deferred_update_tokens[0].token_type == 2);
    XQC_TEST_ASSERT(xqc_test_deferred_update_tokens[0].token_value_len == 2);
    XQC_TEST_ASSERT(memcmp(
        xqc_test_deferred_update_tokens[0].token_value, "ab", 2) == 0);

    xqc_moq_request_ok_msg_t ok = {0};
    XQC_TEST_ASSERT(xqc_moq_write_request_ok(
        &session, xqc_test_deferred_update_view->request_id,
        &ok) == XQC_OK);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_peer_update_queue) == NULL);

    xqc_free(stream.read_buf);
    stream.read_buf = NULL;
    xqc_moq_d18_params_free(stream.d18_accepted_params,
                            stream.d18_accepted_params_num);
    stream.d18_accepted_params = NULL;
    stream.d18_accepted_params_num = 0;
    xqc_moq_d18_update_queue_destroy(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(&stream.d18_peer_update_queue);
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static int
xqc_test_request_update_callback_view_survives_sync_response(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    xqc_moq_user_session_t user_session = {
        .session = &session,
    };
    session.user_session = &user_session;
    xqc_moq_session_set_request_update_callback(
        &session, xqc_test_on_request_update_sync_ok);

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    xqc_moq_d18_update_queue_init(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&stream.d18_peer_update_queue);
    stream.peer_request = 1;
    stream.response_sent = 1;
    stream.request_type = XQC_MOQ_MSG_SUBSCRIBE;
    stream.request_id = 0;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    XQC_TEST_ASSERT(xqc_moq_session_register_peer_request_id(
        &session, stream.request_id) == XQC_MOQ_D18_REQUEST_ID_OK);
    xqc_list_add_tail(&stream.request_list_member,
                      &session.peer_request_stream_list);

    xqc_moq_message_parameter_t forward = {
        .type = XQC_MOQ_D18_PARAM_FORWARD,
        .is_integer = 1,
        .int_value = 1,
    };
    xqc_moq_request_update_msg_t update = {
        .request_id = 2,
        .params_num = 1,
        .params = &forward,
    };
    uint8_t encoded[64] = {0};
    size_t encoded_len = 0;
    XQC_TEST_ASSERT(xqc_test_encode_request_update(
        &update, XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_SUBSCRIBE,
        encoded, sizeof(encoded), &encoded_len) == 0);

    xqc_test_sync_update_stream = &stream;
    xqc_test_sync_update_response_ret = -XQC_EPARAM;
    xqc_test_sync_update_view_matches_record = 0;
    xqc_test_sync_update_view_safe_after_response = 0;
    XQC_TEST_ASSERT(xqc_moq_stream_process(
        &stream, encoded, encoded_len, 0) == (xqc_int_t)encoded_len);
    XQC_TEST_ASSERT(xqc_test_sync_update_response_ret == XQC_OK);
    XQC_TEST_ASSERT(xqc_test_sync_update_view_matches_record == 1);
    XQC_TEST_ASSERT(xqc_test_sync_update_view_safe_after_response == 1);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_peer_update_queue) == NULL);

    xqc_test_sync_update_stream = NULL;
    xqc_free(stream.read_buf);
    stream.read_buf = NULL;
    xqc_moq_d18_params_free(stream.d18_accepted_params,
                            stream.d18_accepted_params_num);
    stream.d18_accepted_params = NULL;
    stream.d18_accepted_params_num = 0;
    xqc_moq_d18_update_queue_destroy(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(&stream.d18_peer_update_queue);
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static int
xqc_test_automatic_update_rejection_responds_to_fifo_head(void)
{
    enum {
        XQC_TEST_AUTO_REJECT_AUTH,
        XQC_TEST_AUTO_REJECT_OVERLAP,
    } modes[] = {
        XQC_TEST_AUTO_REJECT_AUTH,
        XQC_TEST_AUTO_REJECT_OVERLAP,
    };
    for (size_t mode_index = 0;
         mode_index < sizeof(modes) / sizeof(modes[0]); mode_index++)
    {
        xqc_moq_session_t session;
        xqc_test_init_session(&session);
        xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
        xqc_moq_d18_auth_cache_init(&session.peer_auth_cache, 64);
        xqc_connection_t quic_conn;
        xqc_memzero(&quic_conn, sizeof(quic_conn));
        quic_conn.conn_err = UINT64_MAX;
        quic_conn.log = &xqc_test_log;
        session.quic_conn = &quic_conn;
        xqc_moq_user_session_t user_session = {
            .session = &session,
        };
        session.user_session = &user_session;
        xqc_moq_session_set_request_update_callback(
            &session, xqc_test_on_request_update);

        xqc_test_write_capture_t capture = {0};
        xqc_moq_stream_t stream;
        xqc_test_init_stream(&stream, &session, &capture);
        xqc_moq_d18_update_queue_init(&stream.d18_local_update_queue);
        xqc_moq_d18_update_queue_init(&stream.d18_peer_update_queue);
        stream.peer_request = 1;
        stream.response_sent = 1;
        stream.request_type = XQC_MOQ_MSG_SUBSCRIBE_TRACKS;
        stream.request_id = 0;
        stream.subscribe_tracks_active = 1;
        stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
        stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
        stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
        xqc_moq_track_ns_field_t old_field = {
            .len = 3,
            .data = (unsigned char *)"old",
        };
        stream.tracks_subscription =
            xqc_moq_namespace_prefix_create_copy(&old_field, 1);
        XQC_TEST_ASSERT(stream.tracks_subscription != NULL);
        stream.tracks_subscription->request_id = stream.request_id;
        XQC_TEST_ASSERT(xqc_moq_session_register_peer_request_id(
            &session, stream.request_id) == XQC_MOQ_D18_REQUEST_ID_OK);
        xqc_list_add_tail(&stream.request_list_member,
                          &session.peer_request_stream_list);

        xqc_test_write_capture_t other_capture = {0};
        xqc_moq_stream_t other;
        xqc_test_init_stream(&other, &session, &other_capture);
        if (modes[mode_index] == XQC_TEST_AUTO_REJECT_OVERLAP) {
            other.peer_request = 1;
            other.response_sent = 1;
            other.request_type = XQC_MOQ_MSG_SUBSCRIBE_TRACKS;
            other.request_id = 8;
            other.subscribe_tracks_active = 1;
            xqc_moq_track_ns_field_t new_field = {
                .len = 3,
                .data = (unsigned char *)"new",
            };
            other.tracks_subscription =
                xqc_moq_namespace_prefix_create_copy(&new_field, 1);
            XQC_TEST_ASSERT(other.tracks_subscription != NULL);
            xqc_list_add_tail(&other.request_list_member,
                              &session.peer_request_stream_list);
        }

        xqc_moq_request_update_msg_t first = {
            .request_id = 2,
        };
        uint8_t first_bytes[64] = {0};
        size_t first_len = 0;
        XQC_TEST_ASSERT(xqc_test_encode_request_update(
            &first, XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_NAMESPACE,
            first_bytes, sizeof(first_bytes), &first_len) == 0);
        xqc_test_request_update_callback_count = 0;
        XQC_TEST_ASSERT(xqc_moq_stream_process(
            &stream, first_bytes, first_len, 0) == (xqc_int_t)first_len);
        XQC_TEST_ASSERT(xqc_test_request_update_callback_count == 1);
        XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
            &stream.d18_peer_update_queue)->request_id == 2);

        uint8_t expired_alias[] = {
            XQC_MOQ_D18_AUTH_USE_ALIAS, 0x07,
        };
        uint8_t serialized_prefix[] = {
            0x01, 0x03, 'n', 'e', 'w',
        };
        xqc_moq_message_parameter_t rejected_param = {
            .type = modes[mode_index] == XQC_TEST_AUTO_REJECT_AUTH
                ? XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN
                : XQC_MOQ_D18_PARAM_TRACK_NAMESPACE_PREFIX,
            .length = modes[mode_index] == XQC_TEST_AUTO_REJECT_AUTH
                ? sizeof(expired_alias) : sizeof(serialized_prefix),
            .value = modes[mode_index] == XQC_TEST_AUTO_REJECT_AUTH
                ? expired_alias : serialized_prefix,
        };
        if (modes[mode_index] == XQC_TEST_AUTO_REJECT_AUTH) {
            uint8_t register_token[] = {
                XQC_MOQ_D18_AUTH_REGISTER, 0x07, 0x02, 'a', 'b',
            };
            xqc_moq_message_parameter_t register_param = {
                .type = XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN,
                .length = sizeof(register_token),
                .value = register_token,
            };
            xqc_moq_request_auth_t request_auth = {0};
            XQC_TEST_ASSERT(xqc_moq_session_process_peer_request_auth(
                &session, &register_param, 1, &request_auth).kind
                == XQC_MOQ_D18_REQUEST_AUTH_OK);
            xqc_moq_request_auth_destroy(&request_auth);
            XQC_TEST_ASSERT(xqc_moq_session_mark_peer_auth_token_expired(
                &session, 7) == XQC_OK);
        }

        xqc_moq_request_update_msg_t second = {
            .request_id = 4,
            .params_num = 1,
            .params = &rejected_param,
        };
        uint8_t second_bytes[64] = {0};
        size_t second_len = 0;
        XQC_TEST_ASSERT(xqc_test_encode_request_update(
            &second, XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_NAMESPACE,
            second_bytes, sizeof(second_bytes), &second_len) == 0);
        XQC_TEST_ASSERT(xqc_moq_stream_process(
            &stream, second_bytes, second_len, 0)
            == (xqc_int_t)second_len);

        XQC_TEST_ASSERT(quic_conn.conn_err == UINT64_MAX);
        XQC_TEST_ASSERT(capture.write_count == 1);
        XQC_TEST_ASSERT(capture.bytes[0] == XQC_MOQ_MSG_REQUEST_ERROR);
        XQC_TEST_ASSERT(capture.fin == 1);
        XQC_TEST_ASSERT(stream.request_closed_notified == 1);
        XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
            &stream.d18_peer_update_queue) == NULL);
        XQC_TEST_ASSERT(xqc_test_request_update_callback_count == 1);
        size_t terminal_length = capture.length;
        xqc_moq_request_ok_msg_t late_ok = {0};
        XQC_TEST_ASSERT(xqc_moq_write_request_ok(
            &session, first.request_id, &late_ok) == -XQC_ENULLPTR);
        XQC_TEST_ASSERT(capture.length == terminal_length);

        xqc_moq_namespace_prefix_destroy(other.tracks_subscription);
        other.tracks_subscription = NULL;
        xqc_test_clean_stream(&other);
        xqc_free(stream.read_buf);
        stream.read_buf = NULL;
        xqc_moq_d18_params_free(stream.d18_accepted_params,
                                stream.d18_accepted_params_num);
        stream.d18_accepted_params = NULL;
        stream.d18_accepted_params_num = 0;
        xqc_moq_d18_update_queue_destroy(&stream.d18_local_update_queue);
        xqc_moq_d18_update_queue_destroy(&stream.d18_peer_update_queue);
        xqc_test_clean_stream(&stream);
        xqc_moq_d18_request_registry_destroy(
            &session.d18_request_registry);
        xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    }
    return 0;
}

static int
xqc_test_terminal_initial_request_rejects_deferred_response(void)
{
    enum {
        XQC_TEST_DEFERRED_OK,
        XQC_TEST_DEFERRED_ERROR,
    } response_kinds[] = {
        XQC_TEST_DEFERRED_OK,
        XQC_TEST_DEFERRED_ERROR,
    };
    for (size_t response_index = 0;
         response_index
            < sizeof(response_kinds) / sizeof(response_kinds[0]);
         response_index++)
    {
        xqc_moq_session_t session;
        xqc_test_init_session(&session);
        session.role = XQC_MOQ_SUBSCRIBER;
        xqc_moq_user_session_t user_session = {
            .session = &session,
        };
        session.user_session = &user_session;
        session.session_callbacks.on_publish =
            xqc_test_on_publish_observe;
        xqc_connection_t quic_conn;
        xqc_memzero(&quic_conn, sizeof(quic_conn));
        quic_conn.conn_err = UINT64_MAX;
        quic_conn.log = &xqc_test_log;
        session.quic_conn = &quic_conn;

        xqc_test_write_capture_t capture = {0};
        xqc_moq_stream_t stream;
        xqc_test_init_stream(&stream, &session, &capture);
        xqc_moq_d18_update_queue_init(&stream.d18_local_update_queue);
        xqc_moq_d18_update_queue_init(&stream.d18_peer_update_queue);
        xqc_moq_track_ns_field_t live = {
            .len = 4,
            .data = (unsigned char *)"live",
        };
        xqc_moq_publish_msg_t publish = {
            .subscribe_id = 0,
            .track_alias = 4,
            .track_namespace_num = 1,
            .track_namespace_tuple = &live,
            .track_name = "audio",
            .track_name_len = 5,
        };
        xqc_moq_on_publish(&session, &stream, &publish.msg_base);
        XQC_TEST_ASSERT(stream.peer_request == 1);
        XQC_TEST_ASSERT(stream.request_type == XQC_MOQ_MSG_PUBLISH);
        XQC_TEST_ASSERT(stream.track != NULL);
        XQC_TEST_ASSERT(xqc_moq_find_subscribe(&session, 0, 1) != NULL);

        xqc_moq_stream_on_request_closed(
            &stream, XQC_MOQ_REQUEST_CANCELLED);
        XQC_TEST_ASSERT(stream.request_closed_notified == 1);
        XQC_TEST_ASSERT(stream.track == NULL);
        XQC_TEST_ASSERT(xqc_list_empty(&session.local_subscribe_list));
        XQC_TEST_ASSERT(!xqc_list_empty(&stream.request_list_member));

        xqc_int_t ret;
        if (response_kinds[response_index] == XQC_TEST_DEFERRED_OK) {
            xqc_moq_request_ok_msg_t ok = {0};
            ret = xqc_moq_write_request_ok(
                &session, stream.request_id, &ok);

        } else {
            xqc_moq_request_error_msg_t error = {
                .error_code = XQC_MOQ_REQUEST_ERROR_UNAUTHORIZED,
            };
            ret = xqc_moq_write_request_error(
                &session, stream.request_id, &error);
        }
        XQC_TEST_ASSERT(ret == -XQC_ENULLPTR);
        XQC_TEST_ASSERT(capture.length == 0);
        XQC_TEST_ASSERT(quic_conn.conn_err == UINT64_MAX);
        XQC_TEST_ASSERT(quic_conn.conn_close_msg == NULL);

        xqc_moq_d18_update_queue_destroy(&stream.d18_local_update_queue);
        xqc_moq_d18_update_queue_destroy(&stream.d18_peer_update_queue);
        xqc_test_clean_stream(&stream);
        xqc_moq_d18_request_registry_destroy(
            &session.d18_request_registry);
        xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    }
    return 0;
}

static int
xqc_test_request_update_receive_registers_id_and_authorizes_before_callback(
    void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_auth_cache_init(&session.peer_auth_cache, 64);
    xqc_moq_user_session_t user_session = {
        .session = &session,
    };
    session.user_session = &user_session;
    xqc_moq_session_set_request_update_callback(
        &session, xqc_test_on_request_update);

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    xqc_moq_d18_update_queue_init(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&stream.d18_peer_update_queue);
    stream.peer_request = 1;
    stream.response_sent = 1;
    stream.request_type = XQC_MOQ_MSG_SUBSCRIBE;
    stream.request_id = 0;
    XQC_TEST_ASSERT(xqc_moq_session_register_peer_request_id(
        &session, stream.request_id) == XQC_MOQ_D18_REQUEST_ID_OK);
    xqc_list_add_tail(&stream.request_list_member,
                      &session.peer_request_stream_list);

    uint8_t register_token[] = {
        XQC_MOQ_D18_AUTH_REGISTER, 0x07, 0x02, 'a', 'b',
    };
    xqc_moq_message_parameter_t auth = {
        .type = XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN,
        .length = sizeof(register_token),
        .value = register_token,
    };
    xqc_moq_request_update_msg_t update = {
        .request_id = 2,
        .params_num = 1,
        .params = &auth,
    };
    xqc_test_request_update_callback_count = 0;
    xqc_test_request_update_auth_ready = 0;
    xqc_moq_on_request_update(&session, &stream, &update.msg_base);

    XQC_TEST_ASSERT(xqc_test_request_update_callback_count == 1);
    XQC_TEST_ASSERT(xqc_test_request_update_auth_ready == 1);
    XQC_TEST_ASSERT(xqc_test_request_update_target_id == stream.request_id);
    XQC_TEST_ASSERT(xqc_test_request_update_type == XQC_MOQ_MSG_SUBSCRIBE);
    XQC_TEST_ASSERT(xqc_test_request_update_id == update.request_id);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_peer_update_queue)->request_id == update.request_id);
    XQC_TEST_ASSERT(stream.response_sent == 1);

    xqc_moq_request_auth_destroy(&update.request_auth);
    xqc_moq_d18_update_queue_destroy(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(&stream.d18_peer_update_queue);
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static int
xqc_test_request_update_auth_error_responds_to_update_id_before_callback(void)
{
    static const uint8_t expected_done[] = {
        XQC_MOQ_D18_MSG_PUBLISH_DONE,
        0x00, 0x0b,
        XQC_MOQ_PUBLISH_DONE_UPDATE_FAILED,
        0xff, 0x3f, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0x00,
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_auth_cache_init(&session.peer_auth_cache, 64);
    xqc_connection_t quic_conn;
    xqc_memzero(&quic_conn, sizeof(quic_conn));
    quic_conn.conn_err = UINT64_MAX;
    quic_conn.log = &xqc_test_log;
    session.quic_conn = &quic_conn;
    xqc_moq_session_set_request_update_callback(
        &session, xqc_test_on_request_update);

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    xqc_moq_d18_update_queue_init(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&stream.d18_peer_update_queue);
    stream.peer_request = 1;
    stream.response_sent = 1;
    stream.request_type = XQC_MOQ_MSG_SUBSCRIBE;
    stream.request_id = 0;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    XQC_TEST_ASSERT(xqc_moq_session_register_peer_request_id(
        &session, stream.request_id) == XQC_MOQ_D18_REQUEST_ID_OK);
    xqc_list_add_tail(&stream.request_list_member,
                      &session.peer_request_stream_list);

    uint8_t register_token[] = {
        XQC_MOQ_D18_AUTH_REGISTER, 0x07, 0x02, 'a', 'b',
    };
    xqc_moq_message_parameter_t register_param = {
        .type = XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN,
        .length = sizeof(register_token),
        .value = register_token,
    };
    xqc_moq_request_auth_t request_auth = {0};
    XQC_TEST_ASSERT(xqc_moq_session_process_peer_request_auth(
        &session, &register_param, 1, &request_auth).kind
        == XQC_MOQ_D18_REQUEST_AUTH_OK);
    xqc_moq_request_auth_destroy(&request_auth);
    XQC_TEST_ASSERT(xqc_moq_session_mark_peer_auth_token_expired(
        &session, 7) == XQC_OK);
    uint8_t use_expired_alias[] = {
        XQC_MOQ_D18_AUTH_USE_ALIAS, 0x07,
    };
    xqc_moq_message_parameter_t auth = {
        .type = XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN,
        .length = sizeof(use_expired_alias),
        .value = use_expired_alias,
    };
    xqc_moq_request_update_msg_t update = {
        .request_id = 2,
        .params_num = 1,
        .params = &auth,
    };
    xqc_test_request_update_callback_count = 0;
    xqc_moq_on_request_update(&session, &stream, &update.msg_base);

    XQC_TEST_ASSERT(xqc_test_request_update_callback_count == 0);
    XQC_TEST_ASSERT(capture.write_count == 2);
    XQC_TEST_ASSERT(capture.bytes[0] == XQC_MOQ_MSG_REQUEST_ERROR);
    XQC_TEST_ASSERT(capture.fin_history[0] == 0);
    XQC_TEST_ASSERT(capture.length >= sizeof(expected_done));
    XQC_TEST_ASSERT(memcmp(
        capture.bytes + capture.length - sizeof(expected_done),
        expected_done, sizeof(expected_done)) == 0);
    XQC_TEST_ASSERT(capture.fin == 1);
    XQC_TEST_ASSERT(stream.response_sent == 1);
    XQC_TEST_ASSERT(stream.request_closed_notified == 1);
    XQC_TEST_ASSERT(stream.update_failed_wait_publish_done == 0);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_peer_update_queue) == NULL);
    XQC_TEST_ASSERT(quic_conn.conn_err == UINT64_MAX);

    xqc_moq_d18_update_queue_destroy(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(&stream.d18_peer_update_queue);
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_free((void *)quic_conn.conn_close_msg);
    return 0;
}

static int
xqc_test_initial_subscribe_tracks_params_are_cloned_and_merged(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_auth_cache_init(&session.peer_auth_cache, 64);

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    stream.kind = XQC_MOQ_STREAM_D18_REQUEST;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    xqc_moq_d18_update_queue_init(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&stream.d18_peer_update_queue);

    xqc_moq_track_ns_field_t old_prefix = {
        .len = 3,
        .data = (unsigned char *)"old",
    };
    uint8_t register_token[] = {
        XQC_MOQ_D18_AUTH_REGISTER, 0x07, 0x02, 'a', 'b',
    };
    xqc_moq_message_parameter_t initial_params[] = {
        {
            .type = XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN,
            .length = sizeof(register_token),
            .value = register_token,
        },
        {
            .type = XQC_MOQ_D18_PARAM_FORWARD,
            .is_integer = 1,
            .int_value = 0,
        },
    };
    xqc_moq_subscribe_tracks_msg_t initial = {
        .request_id = 0,
        .track_namespace_num = 1,
        .track_namespace_tuple = &old_prefix,
        .params_num = 2,
        .params = initial_params,
    };
    xqc_moq_on_subscribe_tracks(
        &session, &stream, &initial.msg_base);

    XQC_TEST_ASSERT(stream.response_sent == 1);
    XQC_TEST_ASSERT(stream.d18_accepted_params_num == 2);
    XQC_TEST_ASSERT(stream.d18_accepted_params != initial_params);
    XQC_TEST_ASSERT(stream.d18_accepted_params[0].value != register_token);
    XQC_TEST_ASSERT(memcmp(stream.d18_accepted_params[0].value,
                           register_token, sizeof(register_token)) == 0);
    register_token[3] = 'x';
    XQC_TEST_ASSERT(stream.d18_accepted_params[0].value[3] == 'a');

    uint8_t new_prefix[] = {0x01, 0x03, 'n', 'e', 'w'};
    xqc_moq_message_parameter_t prefix_param = {
        .type = XQC_MOQ_D18_PARAM_TRACK_NAMESPACE_PREFIX,
        .length = sizeof(new_prefix),
        .value = new_prefix,
    };
    xqc_moq_request_update_msg_t update = {
        .request_id = 2,
        .params_num = 1,
        .params = &prefix_param,
    };
    xqc_moq_on_request_update(&session, &stream, &update.msg_base);
    xqc_moq_request_ok_msg_t ok = {0};
    XQC_TEST_ASSERT(xqc_moq_write_request_ok(
        &session, update.request_id, &ok) == XQC_OK);
    XQC_TEST_ASSERT(stream.d18_accepted_params_num == 3);
    XQC_TEST_ASSERT(stream.d18_accepted_params[0].type
                    == XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN);
    XQC_TEST_ASSERT(stream.d18_accepted_params[0].value[3] == 'a');
    XQC_TEST_ASSERT(stream.d18_accepted_params[1].type
                    == XQC_MOQ_D18_PARAM_FORWARD);
    XQC_TEST_ASSERT(stream.d18_accepted_params[1].int_value == 0);
    XQC_TEST_ASSERT(stream.d18_accepted_params[2].type
                    == XQC_MOQ_D18_PARAM_TRACK_NAMESPACE_PREFIX);

    xqc_moq_request_auth_destroy(&initial.request_auth);
    xqc_moq_namespace_prefix_destroy(stream.tracks_subscription);
    stream.tracks_subscription = NULL;
    xqc_moq_d18_params_free(stream.d18_accepted_params,
                            stream.d18_accepted_params_num);
    stream.d18_accepted_params = NULL;
    stream.d18_accepted_params_num = 0;
    xqc_moq_d18_update_queue_destroy(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(&stream.d18_peer_update_queue);
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static int
xqc_test_request_update_results_consume_local_fifo_and_merge(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    xqc_moq_user_session_t user_session = {
        .session = &session,
    };
    session.user_session = &user_session;
    session.role = XQC_MOQ_SUBSCRIBER;
    session.session_callbacks.on_publish = xqc_test_on_publish;
    xqc_connection_t quic_conn;
    xqc_memzero(&quic_conn, sizeof(quic_conn));
    quic_conn.log = &xqc_test_log;
    session.quic_conn = &quic_conn;
    session.session_callbacks_ext.on_request_ok = xqc_test_on_request_ok;

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    stream.kind = XQC_MOQ_STREAM_D18_REQUEST;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    xqc_moq_d18_update_queue_init(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&stream.d18_peer_update_queue);
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_moq_message_parameter_t accepted = {
        .type = XQC_MOQ_D18_PARAM_FORWARD,
        .is_integer = 1,
        .int_value = 0,
    };
    xqc_moq_publish_msg_t publish = {
        .subscribe_id = 0,
        .track_alias = 4,
        .track_namespace_num = 1,
        .track_namespace_tuple = &live,
        .track_name = "audio",
        .track_name_len = 5,
        .params_num = 1,
        .params = &accepted,
    };
    xqc_moq_on_publish(&session, &stream, &publish.msg_base);
    XQC_TEST_ASSERT(stream.peer_request == 1);
    XQC_TEST_ASSERT(stream.response_sent == 1);
    XQC_TEST_ASSERT(stream.request_type == XQC_MOQ_MSG_PUBLISH);
    XQC_TEST_ASSERT(stream.d18_accepted_params_num == 1);
    XQC_TEST_ASSERT(stream.d18_accepted_params[0].int_value == 0);
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    xqc_memzero(&capture, sizeof(capture));

    uint64_t update_ids[3] = {0};
    for (size_t i = 0; i < 3; i++) {
        xqc_moq_message_parameter_t forward = {
            .type = XQC_MOQ_D18_PARAM_FORWARD,
            .is_integer = 1,
            .int_value = (i + 1) & 1,
        };
        xqc_moq_request_update_msg_t update = {
            .params_num = 1,
            .params = &forward,
        };
        XQC_TEST_ASSERT(xqc_moq_write_request_update(
            &session, stream.request_id, &update) == XQC_OK);
        update_ids[i] = update.request_id;
    }

    xqc_test_update_result_count = 0;
    xqc_moq_request_ok_msg_t ok = {0};
    for (size_t i = 0; i < 3; i++) {
        xqc_moq_on_request_ok(&session, &stream, &ok.msg_base);
        XQC_TEST_ASSERT(stream.response_sent == 1);
        XQC_TEST_ASSERT(xqc_test_update_result_count == i + 1);
        XQC_TEST_ASSERT(xqc_test_update_result_ids[i] == update_ids[i]);
        XQC_TEST_ASSERT(xqc_test_update_result_types[i]
                        == XQC_MOQ_MSG_SUBSCRIBE_UPDATE);
        XQC_TEST_ASSERT(stream.d18_accepted_params_num == 1);
        XQC_TEST_ASSERT(stream.d18_accepted_params[0].int_value
                        == ((i + 1) & 1));
    }
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_local_update_queue) == NULL);

    xqc_moq_d18_params_free(stream.d18_accepted_params,
                            stream.d18_accepted_params_num);
    stream.d18_accepted_params = NULL;
    stream.d18_accepted_params_num = 0;
    xqc_moq_d18_update_queue_destroy(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(&stream.d18_peer_update_queue);
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static int
xqc_test_request_update_responses_require_peer_fifo_head(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    stream.kind = XQC_MOQ_STREAM_D18_REQUEST;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    xqc_moq_d18_update_queue_init(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&stream.d18_peer_update_queue);
    xqc_moq_track_ns_field_t old_prefix = {
        .len = 3,
        .data = (unsigned char *)"old",
    };
    xqc_moq_message_parameter_t accepted = {
        .type = XQC_MOQ_D18_PARAM_FORWARD,
        .is_integer = 1,
        .int_value = 0,
    };
    xqc_moq_subscribe_tracks_msg_t initial = {
        .request_id = 0,
        .track_namespace_num = 1,
        .track_namespace_tuple = &old_prefix,
        .params_num = 1,
        .params = &accepted,
    };
    xqc_moq_on_subscribe_tracks(&session, &stream, &initial.msg_base);
    XQC_TEST_ASSERT(stream.response_sent == 1);
    XQC_TEST_ASSERT(stream.d18_accepted_params_num == 1);
    XQC_TEST_ASSERT(stream.d18_accepted_params[0].int_value == 0);
    xqc_memzero(&capture, sizeof(capture));

    uint64_t update_ids[] = {2, 4, 6};
    uint8_t prefixes[][6] = {
        {0x01, 0x04, 'n', 'e', 'w', '0'},
        {0x01, 0x04, 'n', 'e', 'w', '1'},
        {0x01, 0x04, 'n', 'e', 'w', '2'},
    };
    for (size_t i = 0; i < 3; i++) {
        xqc_moq_message_parameter_t prefix = {
            .type = XQC_MOQ_D18_PARAM_TRACK_NAMESPACE_PREFIX,
            .length = sizeof(prefixes[i]),
            .value = prefixes[i],
        };
        xqc_moq_request_update_msg_t update = {
            .request_id = update_ids[i],
            .params_num = 1,
            .params = &prefix,
        };
        xqc_moq_on_request_update(&session, &stream, &update.msg_base);
    }

    xqc_moq_request_ok_msg_t ok = {0};
    XQC_TEST_ASSERT(xqc_moq_write_request_ok(
        &session, update_ids[1], &ok) != XQC_OK);
    XQC_TEST_ASSERT(capture.length == 0);

    capture.fail_write = 1;
    XQC_TEST_ASSERT(xqc_moq_write_request_ok(
        &session, update_ids[0], &ok) == -XQC_ESYS);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_peer_update_queue)->request_id == update_ids[0]);
    XQC_TEST_ASSERT(stream.d18_accepted_params_num == 1);
    XQC_TEST_ASSERT(stream.d18_accepted_params[0].int_value == 0);
    XQC_TEST_ASSERT(memcmp(
        stream.tracks_subscription->prefix_tuple[0].data,
        "old", 3) == 0);
    capture.fail_write = 0;
    for (size_t i = 0; i < 3; i++) {
        XQC_TEST_ASSERT(xqc_moq_write_request_ok(
            &session, update_ids[i], &ok) == XQC_OK);
        if (i == 0) {
            XQC_TEST_ASSERT(capture.length == 4);
        }
        XQC_TEST_ASSERT(stream.response_sent == 1);
        XQC_TEST_ASSERT(stream.d18_accepted_params_num == 2);
        XQC_TEST_ASSERT(stream.d18_accepted_params[0].int_value
                        == 0);
        XQC_TEST_ASSERT(memcmp(
            stream.tracks_subscription->prefix_tuple[0].data,
            &prefixes[i][2], 4) == 0);
    }
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_peer_update_queue) == NULL);

    xqc_moq_namespace_prefix_destroy(stream.tracks_subscription);
    stream.tracks_subscription = NULL;
    xqc_moq_d18_params_free(stream.d18_accepted_params,
                            stream.d18_accepted_params_num);
    stream.d18_accepted_params = NULL;
    stream.d18_accepted_params_num = 0;
    xqc_moq_d18_update_queue_destroy(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(&stream.d18_peer_update_queue);
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static int
xqc_test_subscribe_tracks_request_update_swaps_prefix_without_publish_teardown(
    void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    xqc_moq_d18_update_queue_init(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&stream.d18_peer_update_queue);
    stream.peer_request = 1;
    stream.response_sent = 1;
    stream.request_type = XQC_MOQ_MSG_SUBSCRIBE_TRACKS;
    stream.request_id = 0;
    stream.kind = XQC_MOQ_STREAM_D18_REQUEST;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    stream.subscribe_tracks_active = 1;
    xqc_moq_track_ns_field_t old_prefix = {
        .len = 3,
        .data = (unsigned char *)"old",
    };
    stream.tracks_subscription =
        xqc_moq_namespace_prefix_create_copy(&old_prefix, 1);
    XQC_TEST_ASSERT(stream.tracks_subscription != NULL);
    stream.tracks_subscription->request_id = stream.request_id;
    XQC_TEST_ASSERT(xqc_moq_session_register_peer_request_id(
        &session, stream.request_id) == XQC_MOQ_D18_REQUEST_ID_OK);
    xqc_list_add_tail(&stream.request_list_member,
                      &session.peer_request_stream_list);

    xqc_moq_stream_t publish_stream;
    xqc_test_write_capture_t publish_capture = {0};
    xqc_test_init_stream(
        &publish_stream, &session, &publish_capture);
    publish_stream.peer_request = 1;
    publish_stream.response_sent = 1;
    publish_stream.request_type = XQC_MOQ_MSG_PUBLISH;
    publish_stream.request_id = 4;
    xqc_list_add_tail(&publish_stream.request_list_member,
                      &session.peer_request_stream_list);

    uint8_t new_prefix[] = {0x01, 0x03, 'n', 'e', 'w'};
    xqc_moq_message_parameter_t prefix_param = {
        .type = XQC_MOQ_D18_PARAM_TRACK_NAMESPACE_PREFIX,
        .length = sizeof(new_prefix),
        .value = new_prefix,
    };
    xqc_moq_request_update_msg_t update = {
        .request_id = 2,
        .params_num = 1,
        .params = &prefix_param,
    };
    xqc_moq_on_request_update(&session, &stream, &update.msg_base);
    XQC_TEST_ASSERT(memcmp(
        stream.tracks_subscription->prefix_tuple[0].data,
        "old", 3) == 0);

    xqc_moq_request_ok_msg_t ok = {0};
    XQC_TEST_ASSERT(xqc_moq_write_request_ok(
        &session, update.request_id, &ok) == XQC_OK);
    XQC_TEST_ASSERT(stream.tracks_subscription->prefix_num == 1);
    XQC_TEST_ASSERT(memcmp(
        stream.tracks_subscription->prefix_tuple[0].data,
        "new", 3) == 0);
    XQC_TEST_ASSERT(stream.subscribe_tracks_active == 1);
    XQC_TEST_ASSERT(publish_stream.request_closed_notified == 0);
    XQC_TEST_ASSERT(!xqc_list_empty(
        &publish_stream.request_list_member));

    xqc_moq_namespace_prefix_destroy(stream.tracks_subscription);
    stream.tracks_subscription = NULL;
    xqc_moq_d18_params_free(stream.d18_accepted_params,
                            stream.d18_accepted_params_num);
    stream.d18_accepted_params = NULL;
    stream.d18_accepted_params_num = 0;
    xqc_moq_d18_update_queue_destroy(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(&stream.d18_peer_update_queue);
    xqc_test_clean_stream(&publish_stream);
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static int
xqc_test_subscribe_tracks_update_overlap_excludes_only_own_prefix(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    xqc_moq_session_set_request_update_callback(
        &session, xqc_test_on_request_update);

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    xqc_moq_d18_update_queue_init(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&stream.d18_peer_update_queue);
    stream.peer_request = 1;
    stream.response_sent = 1;
    stream.request_type = XQC_MOQ_MSG_SUBSCRIBE_TRACKS;
    stream.request_id = 0;
    stream.kind = XQC_MOQ_STREAM_D18_REQUEST;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    stream.subscribe_tracks_active = 1;
    xqc_moq_track_ns_field_t old_prefix = {
        .len = 3,
        .data = (unsigned char *)"old",
    };
    stream.tracks_subscription =
        xqc_moq_namespace_prefix_create_copy(&old_prefix, 1);
    XQC_TEST_ASSERT(stream.tracks_subscription != NULL);
    stream.tracks_subscription->request_id = stream.request_id;
    XQC_TEST_ASSERT(xqc_moq_session_register_peer_request_id(
        &session, stream.request_id) == XQC_MOQ_D18_REQUEST_ID_OK);
    xqc_list_add_tail(&stream.request_list_member,
                      &session.peer_request_stream_list);

    xqc_moq_stream_t other;
    xqc_test_write_capture_t other_capture = {0};
    xqc_test_init_stream(&other, &session, &other_capture);
    other.peer_request = 1;
    other.response_sent = 1;
    other.request_type = XQC_MOQ_MSG_SUBSCRIBE_TRACKS;
    other.request_id = 4;
    other.subscribe_tracks_active = 1;
    xqc_moq_track_ns_field_t other_prefix[] = {
        {
            .len = 3,
            .data = (unsigned char *)"old",
        },
        {
            .len = 3,
            .data = (unsigned char *)"sub",
        },
        {
            .len = 5,
            .data = (unsigned char *)"child",
        },
    };
    other.tracks_subscription =
        xqc_moq_namespace_prefix_create_copy(other_prefix, 3);
    XQC_TEST_ASSERT(other.tracks_subscription != NULL);
    xqc_list_add_tail(&other.request_list_member,
                      &session.peer_request_stream_list);

    uint8_t candidate[] = {
        0x02, 0x03, 'o', 'l', 'd', 0x03, 's', 'u', 'b',
    };
    xqc_moq_message_parameter_t prefix_param = {
        .type = XQC_MOQ_D18_PARAM_TRACK_NAMESPACE_PREFIX,
        .length = sizeof(candidate),
        .value = candidate,
    };
    xqc_moq_request_update_msg_t update = {
        .request_id = 2,
        .params_num = 1,
        .params = &prefix_param,
    };
    xqc_test_request_update_callback_count = 0;
    xqc_moq_on_request_update(&session, &stream, &update.msg_base);

    XQC_TEST_ASSERT(xqc_test_request_update_callback_count == 0);
    XQC_TEST_ASSERT(capture.write_count == 1);
    XQC_TEST_ASSERT(capture.fin == 1);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_peer_update_queue) == NULL);
    XQC_TEST_ASSERT(stream.request_closed_notified == 1);
    XQC_TEST_ASSERT(stream.subscribe_tracks_active == 0);
    XQC_TEST_ASSERT(stream.tracks_subscription == NULL);

    xqc_moq_namespace_prefix_destroy(other.tracks_subscription);
    other.tracks_subscription = NULL;
    xqc_moq_namespace_prefix_destroy(stream.tracks_subscription);
    stream.tracks_subscription = NULL;
    xqc_moq_d18_update_queue_destroy(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(&stream.d18_peer_update_queue);
    xqc_test_clean_stream(&other);
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static int
xqc_test_namespace_update_request_error_terminates_state(void)
{
    xqc_moq_msg_type_t request_types[] = {
        XQC_MOQ_MSG_SUBSCRIBE_TRACKS,
        XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE,
    };
    for (size_t i = 0;
         i < sizeof(request_types) / sizeof(request_types[0]); i++)
    {
        xqc_moq_session_t session;
        xqc_test_init_session(&session);
        xqc_test_write_capture_t capture = {0};
        xqc_moq_stream_t stream;
        xqc_test_init_stream(&stream, &session, &capture);
        xqc_moq_d18_update_queue_init(&stream.d18_local_update_queue);
        xqc_moq_d18_update_queue_init(&stream.d18_peer_update_queue);
        stream.peer_request = 1;
        stream.response_sent = 1;
        stream.request_type = request_types[i];
        stream.request_id = 0;
        stream.kind = XQC_MOQ_STREAM_D18_REQUEST;
        stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
        stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
        stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
        xqc_moq_track_ns_field_t old_prefix = {
            .len = 3,
            .data = (unsigned char *)"old",
        };
        xqc_moq_namespace_prefix_t *active =
            xqc_moq_namespace_prefix_create_copy(&old_prefix, 1);
        XQC_TEST_ASSERT(active != NULL);
        active->request_id = stream.request_id;
        if (request_types[i] == XQC_MOQ_MSG_SUBSCRIBE_TRACKS) {
            stream.subscribe_tracks_active = 1;
            stream.tracks_subscription = active;
        } else {
            xqc_list_add_tail(
                &active->list_member,
                &session.peer_subscribe_namespace_list);
        }
        XQC_TEST_ASSERT(xqc_moq_session_register_peer_request_id(
            &session, stream.request_id) == XQC_MOQ_D18_REQUEST_ID_OK);
        xqc_list_add_tail(&stream.request_list_member,
                          &session.peer_request_stream_list);

        uint8_t new_prefix[] = {0x01, 0x03, 'n', 'e', 'w'};
        xqc_moq_message_parameter_t prefix_param = {
            .type = XQC_MOQ_D18_PARAM_TRACK_NAMESPACE_PREFIX,
            .length = sizeof(new_prefix),
            .value = new_prefix,
        };
        xqc_moq_request_update_msg_t update = {
            .request_id = 2,
            .params_num = 1,
            .params = &prefix_param,
        };
        xqc_moq_on_request_update(&session, &stream, &update.msg_base);
        XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
            &stream.d18_peer_update_queue) != NULL);

        xqc_moq_request_error_msg_t error = {
            .error_code = XQC_MOQ_REQUEST_ERROR_UNAUTHORIZED,
        };
        XQC_TEST_ASSERT(xqc_moq_write_request_error(
            &session, update.request_id, &error) == XQC_OK);
        XQC_TEST_ASSERT(stream.request_closed_notified == 1);
        XQC_TEST_ASSERT(stream.write_stream_fin == 1);
        XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
            &stream.d18_peer_update_queue) == NULL);
        if (request_types[i] == XQC_MOQ_MSG_SUBSCRIBE_TRACKS) {
            XQC_TEST_ASSERT(stream.subscribe_tracks_active == 0);
            XQC_TEST_ASSERT(stream.tracks_subscription == NULL);
        } else {
            XQC_TEST_ASSERT(xqc_list_empty(
                &session.peer_subscribe_namespace_list));
        }

        xqc_moq_d18_update_queue_destroy(&stream.d18_local_update_queue);
        xqc_moq_d18_update_queue_destroy(&stream.d18_peer_update_queue);
        xqc_test_clean_stream(&stream);
        xqc_moq_d18_request_registry_destroy(
            &session.d18_request_registry);
        xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    }
    return 0;
}

static int
xqc_test_deferred_namespace_update_rechecks_overlap_before_ok(void)
{
    xqc_moq_msg_type_t request_types[] = {
        XQC_MOQ_MSG_SUBSCRIBE_TRACKS,
        XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE,
    };
    for (size_t type_index = 0;
         type_index < sizeof(request_types) / sizeof(request_types[0]);
         type_index++)
    {
        xqc_moq_session_t session;
        xqc_test_init_session(&session);
        xqc_moq_stream_t streams[2];
        xqc_test_write_capture_t captures[2] = {0};
        xqc_moq_namespace_prefix_t *old_prefixes[2] = {0};
        char old_names[2][4] = {{'o', 'l', 'd', '0'},
                                {'o', 'l', 'd', '1'}};
        for (size_t i = 0; i < 2; i++) {
            xqc_test_init_stream(&streams[i], &session, &captures[i]);
            xqc_moq_d18_update_queue_init(
                &streams[i].d18_local_update_queue);
            xqc_moq_d18_update_queue_init(
                &streams[i].d18_peer_update_queue);
            streams[i].peer_request = 1;
            streams[i].response_sent = 1;
            streams[i].request_type = request_types[type_index];
            streams[i].request_id = i * 2;
            streams[i].kind = XQC_MOQ_STREAM_D18_REQUEST;
            streams[i].d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
            streams[i].d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
            streams[i].d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
            xqc_moq_track_ns_field_t old_prefix = {
                .len = sizeof(old_names[i]),
                .data = (unsigned char *)old_names[i],
            };
            old_prefixes[i] =
                xqc_moq_namespace_prefix_create_copy(&old_prefix, 1);
            XQC_TEST_ASSERT(old_prefixes[i] != NULL);
            old_prefixes[i]->request_id = streams[i].request_id;
            if (request_types[type_index]
                == XQC_MOQ_MSG_SUBSCRIBE_TRACKS)
            {
                streams[i].subscribe_tracks_active = 1;
                streams[i].tracks_subscription = old_prefixes[i];

            } else {
                xqc_list_add_tail(
                    &old_prefixes[i]->list_member,
                    &session.peer_subscribe_namespace_list);
            }
            XQC_TEST_ASSERT(xqc_moq_session_register_peer_request_id(
                &session, streams[i].request_id)
                == XQC_MOQ_D18_REQUEST_ID_OK);
            xqc_list_add_tail(
                &streams[i].request_list_member,
                &session.peer_request_stream_list);
        }

        uint8_t candidate[] = {0x01, 0x03, 'n', 'e', 'w'};
        xqc_moq_message_parameter_t prefix = {
            .type = XQC_MOQ_D18_PARAM_TRACK_NAMESPACE_PREFIX,
            .length = sizeof(candidate),
            .value = candidate,
        };
        uint64_t update_ids[] = {4, 6};
        for (size_t i = 0; i < 2; i++) {
            xqc_moq_request_update_msg_t update = {
                .request_id = update_ids[i],
                .params_num = 1,
                .params = &prefix,
            };
            xqc_moq_on_request_update(
                &session, &streams[i], &update.msg_base);
            XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
                &streams[i].d18_peer_update_queue) != NULL);
            XQC_TEST_ASSERT(captures[i].write_count == 0);
        }

        xqc_moq_request_ok_msg_t ok = {0};
        XQC_TEST_ASSERT(xqc_moq_write_request_ok(
            &session, update_ids[0], &ok) == XQC_OK);
        size_t second_length = captures[1].length;
        int second_write_count = captures[1].write_count;
        XQC_TEST_ASSERT(xqc_moq_write_request_ok(
            &session, update_ids[1], &ok) == -XQC_EPARAM);
        XQC_TEST_ASSERT(captures[1].length == second_length);
        XQC_TEST_ASSERT(captures[1].write_count == second_write_count);
        XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
            &streams[1].d18_peer_update_queue)->request_id
            == update_ids[1]);
        if (request_types[type_index]
            == XQC_MOQ_MSG_SUBSCRIBE_TRACKS)
        {
            XQC_TEST_ASSERT(streams[1].tracks_subscription
                            == old_prefixes[1]);

        } else {
            XQC_TEST_ASSERT(!xqc_list_empty(
                &old_prefixes[1]->list_member));
        }

        xqc_moq_request_error_msg_t error = {
            .error_code = XQC_MOQ_REQUEST_ERROR_UNAUTHORIZED,
        };
        XQC_TEST_ASSERT(xqc_moq_write_request_error(
            &session, update_ids[1], &error) == XQC_OK);
        XQC_TEST_ASSERT(streams[1].request_closed_notified == 1);
        xqc_moq_stream_finish_request(&streams[0], 0);

        for (size_t i = 0; i < 2; i++) {
            xqc_moq_d18_params_free(
                streams[i].d18_accepted_params,
                streams[i].d18_accepted_params_num);
            streams[i].d18_accepted_params = NULL;
            streams[i].d18_accepted_params_num = 0;
            xqc_moq_d18_update_queue_destroy(
                &streams[i].d18_local_update_queue);
            xqc_moq_d18_update_queue_destroy(
                &streams[i].d18_peer_update_queue);
            xqc_test_clean_stream(&streams[i]);
        }
        XQC_TEST_ASSERT(xqc_list_empty(
            &session.peer_subscribe_namespace_list));
        xqc_moq_d18_request_registry_destroy(
            &session.d18_request_registry);
        xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    }
    return 0;
}

static int
xqc_test_namespace_update_overlap_isolated_by_request_type(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    xqc_moq_track_ns_field_t shared = {
        .len = 6,
        .data = (unsigned char *)"shared",
    };

    xqc_moq_stream_t tracks_stream;
    xqc_test_write_capture_t tracks_capture = {0};
    xqc_test_init_stream(&tracks_stream, &session, &tracks_capture);
    tracks_stream.peer_request = 1;
    tracks_stream.response_sent = 1;
    tracks_stream.request_type = XQC_MOQ_MSG_SUBSCRIBE_TRACKS;
    tracks_stream.request_id = 0;
    tracks_stream.subscribe_tracks_active = 1;
    tracks_stream.tracks_subscription =
        xqc_moq_namespace_prefix_create_copy(&shared, 1);
    XQC_TEST_ASSERT(tracks_stream.tracks_subscription != NULL);
    tracks_stream.tracks_subscription->request_id =
        tracks_stream.request_id;
    xqc_list_add_tail(&tracks_stream.request_list_member,
                      &session.peer_request_stream_list);

    xqc_moq_stream_t namespace_stream;
    xqc_test_write_capture_t namespace_capture = {0};
    xqc_test_init_stream(
        &namespace_stream, &session, &namespace_capture);
    namespace_stream.peer_request = 1;
    namespace_stream.response_sent = 1;
    namespace_stream.request_type = XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE;
    namespace_stream.request_id = 2;
    xqc_moq_namespace_prefix_t *namespace_prefix =
        xqc_moq_namespace_prefix_create_copy(&shared, 1);
    XQC_TEST_ASSERT(namespace_prefix != NULL);
    namespace_prefix->request_id = namespace_stream.request_id;
    xqc_list_add_tail(
        &namespace_prefix->list_member,
        &session.peer_subscribe_namespace_list);
    xqc_list_add_tail(&namespace_stream.request_list_member,
                      &session.peer_request_stream_list);

    xqc_moq_namespace_prefix_t *candidate =
        xqc_moq_namespace_prefix_create_copy(&shared, 1);
    XQC_TEST_ASSERT(candidate != NULL);
    XQC_TEST_ASSERT(xqc_moq_namespace_update_overlaps(
        &session, &tracks_stream, candidate) == 0);
    XQC_TEST_ASSERT(xqc_moq_namespace_update_overlaps(
        &session, &namespace_stream, candidate) == 0);

    xqc_moq_namespace_prefix_destroy(candidate);
    xqc_moq_namespace_prefix_destroy(
        tracks_stream.tracks_subscription);
    tracks_stream.tracks_subscription = NULL;
    xqc_list_del_init(&namespace_prefix->list_member);
    xqc_moq_namespace_prefix_destroy(namespace_prefix);
    xqc_test_clean_stream(&namespace_stream);
    xqc_test_clean_stream(&tracks_stream);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static int
xqc_test_local_subscribe_tracks_update_error_terminates_state(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    xqc_moq_d18_update_queue_init(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&stream.d18_peer_update_queue);
    stream.local_request = 1;
    stream.response_received = 1;
    stream.request_type = XQC_MOQ_MSG_SUBSCRIBE_TRACKS;
    stream.request_id = 1;
    stream.subscribe_tracks_active = 1;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    XQC_TEST_ASSERT(xqc_moq_session_register_local_request_id(
        &session, stream.request_id) == XQC_MOQ_D18_REQUEST_ID_OK);
    xqc_list_add_tail(&stream.request_list_member,
                      &session.local_request_stream_list);

    uint8_t new_prefix[] = {0x01, 0x03, 'n', 'e', 'w'};
    xqc_moq_message_parameter_t prefix = {
        .type = XQC_MOQ_D18_PARAM_TRACK_NAMESPACE_PREFIX,
        .length = sizeof(new_prefix),
        .value = new_prefix,
    };
    xqc_moq_request_update_msg_t accepted_update = {
        .request_id = 3,
        .params_num = 1,
        .params = &prefix,
    };
    XQC_TEST_ASSERT(xqc_moq_write_request_update(
        &session, stream.request_id, &accepted_update) == XQC_OK);
    xqc_moq_request_ok_msg_t ok = {0};
    xqc_moq_on_request_ok(&session, &stream, &ok.msg_base);
    XQC_TEST_ASSERT(stream.tracks_subscription != NULL);
    XQC_TEST_ASSERT(memcmp(
        stream.tracks_subscription->prefix_tuple[0].data,
        "new", 3) == 0);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_local_update_queue) == NULL);

    uint8_t rejected_prefix[] = {0x01, 0x04, 'n', 'e', 'x', 't'};
    prefix.length = sizeof(rejected_prefix);
    prefix.value = rejected_prefix;
    xqc_moq_request_update_msg_t rejected_update = {
        .request_id = 5,
        .params_num = 1,
        .params = &prefix,
    };
    XQC_TEST_ASSERT(xqc_moq_write_request_update(
        &session, stream.request_id, &rejected_update) == XQC_OK);
    xqc_moq_request_error_msg_t error = {
        .error_code = XQC_MOQ_REQUEST_ERROR_UNAUTHORIZED,
    };
    xqc_moq_on_request_error(&session, &stream, &error.msg_base);

    XQC_TEST_ASSERT(stream.request_closed_notified == 1);
    XQC_TEST_ASSERT(stream.subscribe_tracks_active == 0);
    XQC_TEST_ASSERT(stream.tracks_subscription == NULL);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_local_update_queue) == NULL);

    xqc_moq_d18_update_queue_destroy(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(&stream.d18_peer_update_queue);
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static int
xqc_test_first_update_error_clears_both_queues_and_rejects_residuals(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    xqc_connection_t quic_conn;
    xqc_memzero(&quic_conn, sizeof(quic_conn));
    quic_conn.conn_err = UINT64_MAX;
    quic_conn.log = &xqc_test_log;
    session.quic_conn = &quic_conn;

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    xqc_moq_d18_update_queue_init(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&stream.d18_peer_update_queue);
    stream.peer_request = 1;
    stream.response_sent = 1;
    stream.request_type = XQC_MOQ_MSG_PUBLISH;
    stream.request_id = 0;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    XQC_TEST_ASSERT(xqc_moq_session_register_peer_request_id(
        &session, stream.request_id) == XQC_MOQ_D18_REQUEST_ID_OK);
    xqc_list_add_tail(&stream.request_list_member,
                      &session.peer_request_stream_list);

    xqc_moq_message_parameter_t forward = {
        .type = XQC_MOQ_D18_PARAM_FORWARD,
        .is_integer = 1,
        .int_value = 1,
    };
    uint64_t local_ids[] = {1, 3};
    for (size_t i = 0; i < sizeof(local_ids) / sizeof(local_ids[0]); i++) {
        xqc_moq_request_update_msg_t update = {
            .request_id = local_ids[i],
            .params_num = 1,
            .params = &forward,
        };
        XQC_TEST_ASSERT(xqc_moq_write_request_update(
            &session, stream.request_id, &update) == XQC_OK);
    }
    uint64_t peer_ids[] = {2, 4};
    for (size_t i = 0; i < sizeof(peer_ids) / sizeof(peer_ids[0]); i++) {
        xqc_moq_request_update_msg_t update = {
            .request_id = peer_ids[i],
            .params_num = 1,
            .params = &forward,
        };
        xqc_moq_on_request_update(&session, &stream, &update.msg_base);
    }
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_local_update_queue) != NULL);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_peer_update_queue) != NULL);

    xqc_moq_request_error_msg_t error = {
        .error_code = XQC_MOQ_REQUEST_ERROR_UNAUTHORIZED,
    };
    XQC_TEST_ASSERT(xqc_moq_write_request_error(
        &session, peer_ids[0], &error) == XQC_OK);
    XQC_TEST_ASSERT(stream.request_closed_notified == 0);
    XQC_TEST_ASSERT(stream.update_failed_wait_publish_done == 1);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_local_update_queue) == NULL);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_peer_update_queue) == NULL);

    xqc_moq_request_ok_msg_t ok = {0};
    xqc_moq_on_request_ok(&session, &stream, &ok.msg_base);
    XQC_TEST_ASSERT(quic_conn.conn_close_msg != NULL);
    XQC_TEST_ASSERT(strcmp(quic_conn.conn_close_msg,
                           "REQUEST_OK on invalid request stream") == 0);
    quic_conn.conn_close_msg = NULL;
    xqc_moq_on_request_error(&session, &stream, &error.msg_base);
    XQC_TEST_ASSERT(quic_conn.conn_close_msg != NULL);
    XQC_TEST_ASSERT(strcmp(quic_conn.conn_close_msg,
                           "REQUEST_ERROR on invalid request stream") == 0);

    size_t terminal_length = capture.length;
    xqc_moq_request_update_msg_t future = {
        .params_num = 1,
        .params = &forward,
    };
    XQC_TEST_ASSERT(xqc_moq_write_request_update(
        &session, stream.request_id, &future) == -XQC_EPARAM);
    XQC_TEST_ASSERT(capture.length == terminal_length);

    xqc_moq_d18_update_queue_destroy(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(&stream.d18_peer_update_queue);
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static int
xqc_test_only_local_publisher_emits_update_failed_publish_done(void)
{
    static const uint8_t expected_done[] = {
        XQC_MOQ_D18_MSG_PUBLISH_DONE,
        0x00, 0x0b,
        XQC_MOQ_PUBLISH_DONE_UPDATE_FAILED,
        0xff, 0x3f, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0x00,
    };
    struct {
        xqc_moq_msg_type_t request_type;
        uint8_t local_request;
        uint8_t reject_received_update;
        int expected_writes;
        uint8_t expect_publish_done;
        uint8_t expect_terminal;
    } cases[] = {
        {XQC_MOQ_MSG_PUBLISH, 1, 1, 2, 1, 1},
        {XQC_MOQ_MSG_PUBLISH, 1, 0, 2, 1, 1},
        {XQC_MOQ_MSG_PUBLISH, 0, 0, 1, 0, 0},
        {XQC_MOQ_MSG_SUBSCRIBE, 0, 1, 2, 1, 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        xqc_moq_session_t session;
        xqc_test_init_session(&session);
        xqc_test_write_capture_t request_capture = {0};
        xqc_test_write_capture_t ctl_capture = {0};
        xqc_moq_stream_t request_stream;
        xqc_moq_stream_t ctl_stream;
        xqc_test_init_stream(
            &request_stream, &session, &request_capture);
        xqc_test_init_stream(&ctl_stream, &session, &ctl_capture);
        xqc_moq_d18_update_queue_init(
            &request_stream.d18_local_update_queue);
        xqc_moq_d18_update_queue_init(
            &request_stream.d18_peer_update_queue);
        session.ctl_stream = &ctl_stream;
        request_stream.request_type = cases[i].request_type;
        request_stream.d18_context.direction =
            XQC_MOQ_D18_DIRECTION_BIDI;
        request_stream.d18_context.stream_class =
            XQC_MOQ_D18_STREAM_REQUEST;
        request_stream.d18_context.position =
            XQC_MOQ_D18_POSITION_NEXT;
        if (cases[i].local_request) {
            request_stream.local_request = 1;
            request_stream.response_received = 1;
            request_stream.request_id = 1;
            XQC_TEST_ASSERT(xqc_moq_session_register_local_request_id(
                &session, request_stream.request_id)
                == XQC_MOQ_D18_REQUEST_ID_OK);
            xqc_list_add_tail(
                &request_stream.request_list_member,
                &session.local_request_stream_list);
        } else {
            request_stream.peer_request = 1;
            request_stream.response_sent = 1;
            request_stream.request_id = 0;
            XQC_TEST_ASSERT(xqc_moq_session_register_peer_request_id(
                &session, request_stream.request_id)
                == XQC_MOQ_D18_REQUEST_ID_OK);
            xqc_list_add_tail(
                &request_stream.request_list_member,
                &session.peer_request_stream_list);
        }

        xqc_moq_message_parameter_t forward = {
            .type = XQC_MOQ_D18_PARAM_FORWARD,
            .is_integer = 1,
            .int_value = 1,
        };
        xqc_moq_request_error_msg_t error = {
            .error_code = XQC_MOQ_REQUEST_ERROR_UNAUTHORIZED,
        };
        if (cases[i].reject_received_update) {
            xqc_moq_request_update_msg_t update = {
                .request_id = 2,
                .params_num = 1,
                .params = &forward,
            };
            xqc_moq_on_request_update(
                &session, &request_stream, &update.msg_base);
            XQC_TEST_ASSERT(xqc_moq_write_request_error(
                &session, update.request_id, &error) == XQC_OK);
        } else {
            xqc_moq_request_update_msg_t update = {
                .request_id = cases[i].local_request ? 3 : 1,
                .params_num = 1,
                .params = &forward,
            };
            XQC_TEST_ASSERT(xqc_moq_write_request_update(
                &session, request_stream.request_id, &update) == XQC_OK);
            xqc_moq_on_request_error(
                &session, &request_stream, &error.msg_base);
        }

        XQC_TEST_ASSERT(request_capture.write_count
                        == cases[i].expected_writes);
        XQC_TEST_ASSERT(ctl_capture.write_count == 0);
        XQC_TEST_ASSERT(request_stream.request_closed_notified
                        == cases[i].expect_terminal);
        XQC_TEST_ASSERT(request_stream.update_failed_wait_publish_done
                        == !cases[i].expect_terminal);
        XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
            &request_stream.d18_local_update_queue) == NULL);
        XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
            &request_stream.d18_peer_update_queue) == NULL);
        if (cases[i].expect_publish_done) {
            XQC_TEST_ASSERT(request_capture.length
                            >= sizeof(expected_done));
            XQC_TEST_ASSERT(memcmp(
                request_capture.bytes + request_capture.length
                    - sizeof(expected_done),
                expected_done, sizeof(expected_done)) == 0);
            XQC_TEST_ASSERT(request_capture.fin_history[
                request_capture.write_count - 1] == 1);
            if (cases[i].reject_received_update) {
                XQC_TEST_ASSERT(request_capture.fin_history[0] == 0);
            }
        } else {
            XQC_TEST_ASSERT(request_capture.bytes[0]
                            == XQC_MOQ_D18_MSG_REQUEST_UPDATE);
            XQC_TEST_ASSERT(request_capture.fin_history[0] == 0);
        }

        xqc_moq_d18_update_queue_destroy(
            &request_stream.d18_local_update_queue);
        xqc_moq_d18_update_queue_destroy(
            &request_stream.d18_peer_update_queue);
        session.ctl_stream = NULL;
        xqc_test_clean_stream(&ctl_stream);
        xqc_test_clean_stream(&request_stream);
        xqc_moq_d18_request_registry_destroy(
            &session.d18_request_registry);
        xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    }
    return 0;
}

static int
xqc_test_peer_subscribe_update_error_cleans_publisher_owner(void)
{
    static const uint8_t expected_done[] = {
        XQC_MOQ_D18_MSG_PUBLISH_DONE,
        0x00, 0x03,
        XQC_MOQ_PUBLISH_DONE_UPDATE_FAILED,
        0x03,
        0x00,
    };
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    xqc_moq_track_t *track = xqc_moq_track_create_with_ns_tuple(
        &session, &live, 1, "audio", XQC_MOQ_TRACK_AUDIO, NULL,
        XQC_MOQ_CONTAINER_NONE, XQC_MOQ_TRACK_FOR_PUB);
    XQC_TEST_ASSERT(track != NULL);
    track->streams_count = 3;
    track->track_ops.on_subscribe =
        xqc_test_track_on_subscribe_observe;

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    xqc_moq_d18_update_queue_init(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&stream.d18_peer_update_queue);
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_FIRST;
    xqc_moq_subscribe_msg_t initial = {
        .subscribe_id = 0,
        .track_namespace_num = 1,
        .track_namespace_tuple = &live,
        .track_name = "audio",
        .track_name_len = 5,
        .filter_type = XQC_MOQ_FILTER_LAST_GROUP,
    };
    xqc_moq_on_subscribe(&session, &stream, &initial.msg_base);
    XQC_TEST_ASSERT(stream.peer_request == 1);
    XQC_TEST_ASSERT(stream.request_type == XQC_MOQ_MSG_SUBSCRIBE);
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    XQC_TEST_ASSERT(xqc_moq_find_subscribe(&session, 0, 0) != NULL);
    XQC_TEST_ASSERT(track->subscribe_id == 0);
    XQC_TEST_ASSERT(track->track_alias != XQC_MOQ_INVALID_ID);

    xqc_moq_request_ok_msg_t initial_ok = {0};
    XQC_TEST_ASSERT(xqc_moq_write_request_ok(
        &session, stream.request_id, &initial_ok) == XQC_OK);
    XQC_TEST_ASSERT(stream.response_sent == 1);
    xqc_memzero(&capture, sizeof(capture));

    xqc_moq_message_parameter_t forward = {
        .type = XQC_MOQ_D18_PARAM_FORWARD,
        .is_integer = 1,
        .int_value = 0,
    };
    xqc_moq_request_update_msg_t update = {
        .request_id = 2,
        .params_num = 1,
        .params = &forward,
    };
    xqc_moq_on_request_update(&session, &stream, &update.msg_base);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_peer_update_queue) != NULL);

    xqc_moq_request_error_msg_t error = {
        .error_code = XQC_MOQ_REQUEST_ERROR_UNAUTHORIZED,
    };
    XQC_TEST_ASSERT(xqc_moq_write_request_error(
        &session, update.request_id, &error) == XQC_OK);

    XQC_TEST_ASSERT(capture.write_count == 2);
    XQC_TEST_ASSERT(capture.bytes[0] == XQC_MOQ_MSG_REQUEST_ERROR);
    XQC_TEST_ASSERT(capture.fin_history[0] == 0);
    XQC_TEST_ASSERT(capture.length >= sizeof(expected_done));
    XQC_TEST_ASSERT(memcmp(
        capture.bytes + capture.length - sizeof(expected_done),
        expected_done, sizeof(expected_done)) == 0);
    XQC_TEST_ASSERT(capture.fin_history[1] == 1);
    XQC_TEST_ASSERT(stream.request_closed_notified == 1);
    XQC_TEST_ASSERT(xqc_moq_find_subscribe(&session, 0, 0) == NULL);
    XQC_TEST_ASSERT(track->subscribe_id == XQC_MOQ_INVALID_ID);
    XQC_TEST_ASSERT(track->track_alias == XQC_MOQ_INVALID_ID);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_local_update_queue) == NULL);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_peer_update_queue) == NULL);

    xqc_list_del_init(&track->list_member);
    xqc_moq_track_destroy(track);
    xqc_moq_d18_params_free(stream.d18_accepted_params,
                            stream.d18_accepted_params_num);
    stream.d18_accepted_params = NULL;
    stream.d18_accepted_params_num = 0;
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static int
xqc_test_update_error_callback_observes_terminal_publish_state(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    xqc_moq_user_session_t user_session = {
        .session = &session,
    };
    session.user_session = &user_session;
    session.session_callbacks_ext.on_request_error =
        xqc_test_on_update_error_reentrant;

    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_moq_track_t *track = xqc_moq_track_create_with_ns_tuple(
        &session, &live, 1, "audio", XQC_MOQ_TRACK_AUDIO, NULL,
        XQC_MOQ_CONTAINER_NONE, XQC_MOQ_TRACK_FOR_PUB);
    XQC_TEST_ASSERT(track != NULL);
    xqc_moq_track_set_subscribe_id(track, 1);
    xqc_moq_track_set_alias(track, 4);
    track->streams_count = 3;

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    xqc_moq_d18_update_queue_init(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&stream.d18_peer_update_queue);
    stream.local_request = 1;
    stream.response_received = 1;
    stream.request_type = XQC_MOQ_MSG_PUBLISH;
    stream.request_id = 1;
    stream.track = track;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    XQC_TEST_ASSERT(xqc_moq_session_register_local_request_id(
        &session, stream.request_id) == XQC_MOQ_D18_REQUEST_ID_OK);
    xqc_list_add_tail(&stream.request_list_member,
                      &session.local_request_stream_list);

    xqc_moq_message_parameter_t forward = {
        .type = XQC_MOQ_D18_PARAM_FORWARD,
        .is_integer = 1,
        .int_value = 1,
    };
    xqc_moq_request_update_msg_t update = {
        .request_id = 3,
        .params_num = 1,
        .params = &forward,
    };
    XQC_TEST_ASSERT(xqc_moq_write_request_update(
        &session, stream.request_id, &update) == XQC_OK);

    xqc_test_reentrant_update_stream = &stream;
    xqc_test_reentrant_update_capture = &capture;
    xqc_test_reentrant_update_target_id = stream.request_id;
    xqc_test_reentrant_update_ret = XQC_OK;
    xqc_test_reentrant_update_callback_count = 0;
    xqc_test_reentrant_update_saw_terminal = 0;
    xqc_test_reentrant_update_saw_publish_done = 0;
    xqc_moq_request_error_msg_t error = {
        .error_code = XQC_MOQ_REQUEST_ERROR_UNAUTHORIZED,
    };
    xqc_moq_on_request_error(&session, &stream, &error.msg_base);

    XQC_TEST_ASSERT(xqc_test_reentrant_update_callback_count == 1);
    XQC_TEST_ASSERT(xqc_test_reentrant_update_ret == -XQC_EPARAM);
    XQC_TEST_ASSERT(xqc_test_reentrant_update_saw_terminal == 1);
    XQC_TEST_ASSERT(xqc_test_reentrant_update_saw_publish_done == 1);
    XQC_TEST_ASSERT(capture.write_count == 2);
    XQC_TEST_ASSERT(stream.request_closed_notified == 1);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_local_update_queue) == NULL);

    xqc_test_reentrant_update_stream = NULL;
    xqc_test_reentrant_update_capture = NULL;
    xqc_list_del_init(&track->list_member);
    xqc_moq_track_destroy(track);
    xqc_moq_d18_update_queue_destroy(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(&stream.d18_peer_update_queue);
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static int
xqc_test_subscriber_update_error_waits_for_publish_done(void)
{
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.role = XQC_MOQ_SUBSCRIBER;
    xqc_moq_user_session_t user_session = {
        .session = &session,
    };
    session.user_session = &user_session;
    session.session_callbacks_ext.on_request_error =
        xqc_test_on_update_error_observe;
    session.session_callbacks.on_publish_done =
        xqc_test_on_publish_done_observe;

    xqc_moq_track_t *track = xqc_moq_track_create_with_ns_tuple(
        &session, &live, 1, "audio", XQC_MOQ_TRACK_AUDIO, NULL,
        XQC_MOQ_CONTAINER_NONE, XQC_MOQ_TRACK_FOR_SUB);
    XQC_TEST_ASSERT(track != NULL);
    xqc_moq_track_set_alias(track, 4);
    xqc_moq_track_set_subscribe_id(track, 5);
    XQC_TEST_ASSERT(xqc_moq_subscribe_create_with_ns_tuple(
        &session, 5, 4, &live, 1, "audio",
        XQC_MOQ_FILTER_LAST_GROUP, 0, 0, 0, 0, NULL, 1)
        != NULL);

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    xqc_moq_d18_update_queue_init(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&stream.d18_peer_update_queue);
    stream.local_request = 1;
    stream.request_type = XQC_MOQ_MSG_SUBSCRIBE;
    stream.request_id = 5;
    stream.track = track;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    XQC_TEST_ASSERT(xqc_moq_session_register_local_request_id(
        &session, stream.request_id) == XQC_MOQ_D18_REQUEST_ID_OK);
    xqc_list_add_tail(&stream.request_list_member,
                      &session.local_request_stream_list);

    xqc_moq_request_ok_msg_t initial_ok = {0};
    xqc_moq_on_request_ok(&session, &stream, &initial_ok.msg_base);
    XQC_TEST_ASSERT(stream.response_received == 1);

    xqc_moq_message_parameter_t forward = {
        .type = XQC_MOQ_D18_PARAM_FORWARD,
        .is_integer = 1,
        .int_value = 0,
    };
    uint64_t update_ids[] = {7, 9};
    for (size_t i = 0; i < sizeof(update_ids) / sizeof(update_ids[0]); i++) {
        xqc_moq_request_update_msg_t update = {
            .request_id = update_ids[i],
            .params_num = 1,
            .params = &forward,
        };
        XQC_TEST_ASSERT(xqc_moq_write_request_update(
            &session, stream.request_id, &update) == XQC_OK);
    }

    xqc_test_update_error_result_count = 0;
    xqc_test_update_error_result_id = XQC_MOQ_INVALID_ID;
    xqc_test_update_error_result_type = (xqc_moq_msg_type_t)0;
    xqc_moq_request_error_msg_t error = {
        .error_code = XQC_MOQ_REQUEST_ERROR_UNAUTHORIZED,
    };
    xqc_moq_on_request_error(&session, &stream, &error.msg_base);

    XQC_TEST_ASSERT(xqc_test_update_error_result_count == 1);
    XQC_TEST_ASSERT(xqc_test_update_error_result_id == update_ids[0]);
    XQC_TEST_ASSERT(xqc_test_update_error_result_type
                    == XQC_MOQ_MSG_SUBSCRIBE_UPDATE);
    XQC_TEST_ASSERT(stream.request_closed_notified == 0);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_local_update_queue) == NULL);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_peer_update_queue) == NULL);
    XQC_TEST_ASSERT(xqc_moq_find_subscribe(&session, 5, 1) != NULL);
    XQC_TEST_ASSERT(track->track_alias == 4);
    XQC_TEST_ASSERT(track->subscribe_id == 5);

    xqc_moq_request_update_msg_t future = {
        .params_num = 1,
        .params = &forward,
    };
    XQC_TEST_ASSERT(xqc_moq_write_request_update(
        &session, stream.request_id, &future) == -XQC_EPARAM);

    xqc_moq_publish_done_msg_t done = {
        .status_code = XQC_MOQ_PUBLISH_DONE_UPDATE_FAILED,
        .stream_count = 0,
    };
    xqc_test_publish_done_callback_count = 0;
    xqc_test_publish_done_request_id = XQC_MOQ_INVALID_ID;
    xqc_moq_on_publish_done(&session, &stream, &done.msg_base);

    XQC_TEST_ASSERT(xqc_test_publish_done_callback_count == 1);
    XQC_TEST_ASSERT(xqc_test_publish_done_request_id == 5);
    XQC_TEST_ASSERT(stream.request_closed_notified == 1);
    XQC_TEST_ASSERT(stream.track == NULL);
    XQC_TEST_ASSERT(xqc_list_empty(&session.local_subscribe_list));
    XQC_TEST_ASSERT(xqc_list_empty(&session.track_list_for_sub));

    xqc_test_clean_stream(&stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

static int
xqc_test_peer_publish_update_error_waits_for_publish_done(void)
{
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.role = XQC_MOQ_SUBSCRIBER;
    xqc_moq_user_session_t user_session = {
        .session = &session,
    };
    session.user_session = &user_session;
    session.session_callbacks.on_publish =
        xqc_test_on_publish_observe;
    session.session_callbacks_ext.on_request_error =
        xqc_test_on_update_error_observe;
    session.session_callbacks.on_publish_done =
        xqc_test_on_publish_done_observe;

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    xqc_moq_d18_update_queue_init(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&stream.d18_peer_update_queue);
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_FIRST;
    xqc_moq_publish_msg_t publish = {
        .subscribe_id = 0,
        .track_alias = 4,
        .track_namespace_num = 1,
        .track_namespace_tuple = &live,
        .track_name = "audio",
        .track_name_len = 5,
    };
    xqc_moq_on_publish(&session, &stream, &publish.msg_base);
    XQC_TEST_ASSERT(stream.peer_request == 1);
    XQC_TEST_ASSERT(stream.request_type == XQC_MOQ_MSG_PUBLISH);
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    XQC_TEST_ASSERT(stream.track != NULL);
    XQC_TEST_ASSERT(xqc_moq_find_subscribe(&session, 0, 1) != NULL);

    xqc_moq_request_ok_msg_t initial_ok = {0};
    XQC_TEST_ASSERT(xqc_moq_write_request_ok(
        &session, stream.request_id, &initial_ok) == XQC_OK);
    XQC_TEST_ASSERT(stream.response_sent == 1);
    xqc_memzero(&capture, sizeof(capture));

    xqc_moq_message_parameter_t forward = {
        .type = XQC_MOQ_D18_PARAM_FORWARD,
        .is_integer = 1,
        .int_value = 0,
    };
    xqc_moq_request_update_msg_t update = {
        .request_id = 1,
        .params_num = 1,
        .params = &forward,
    };
    XQC_TEST_ASSERT(xqc_moq_write_request_update(
        &session, stream.request_id, &update) == XQC_OK);

    xqc_test_update_error_result_count = 0;
    xqc_moq_request_error_msg_t error = {
        .error_code = XQC_MOQ_REQUEST_ERROR_UNAUTHORIZED,
    };
    xqc_moq_on_request_error(&session, &stream, &error.msg_base);
    XQC_TEST_ASSERT(xqc_test_update_error_result_count == 1);
    XQC_TEST_ASSERT(xqc_test_update_error_result_id == update.request_id);
    XQC_TEST_ASSERT(stream.request_closed_notified == 0);
    XQC_TEST_ASSERT(stream.update_failed_wait_publish_done == 1);
    XQC_TEST_ASSERT(xqc_moq_find_subscribe(&session, 0, 1) != NULL);
    XQC_TEST_ASSERT(stream.track != NULL);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_local_update_queue) == NULL);

    xqc_moq_request_update_msg_t future = {
        .params_num = 1,
        .params = &forward,
    };
    XQC_TEST_ASSERT(xqc_moq_write_request_update(
        &session, stream.request_id, &future) == -XQC_EPARAM);

    xqc_moq_publish_done_msg_t done = {
        .status_code = XQC_MOQ_PUBLISH_DONE_UPDATE_FAILED,
        .stream_count = 0,
    };
    xqc_test_publish_done_callback_count = 0;
    xqc_moq_on_publish_done(&session, &stream, &done.msg_base);
    XQC_TEST_ASSERT(xqc_test_publish_done_callback_count == 1);
    XQC_TEST_ASSERT(xqc_test_publish_done_request_id == 0);
    XQC_TEST_ASSERT(stream.request_closed_notified == 1);
    XQC_TEST_ASSERT(stream.update_failed_wait_publish_done == 0);
    XQC_TEST_ASSERT(stream.track == NULL);
    XQC_TEST_ASSERT(xqc_list_empty(&session.local_subscribe_list));
    XQC_TEST_ASSERT(xqc_list_empty(&session.track_list_for_sub));

    xqc_moq_d18_params_free(stream.d18_accepted_params,
                            stream.d18_accepted_params_num);
    stream.d18_accepted_params = NULL;
    stream.d18_accepted_params_num = 0;
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static int
xqc_test_peer_publish_received_update_rejection_waits_for_publish_done(void)
{
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.role = XQC_MOQ_SUBSCRIBER;
    xqc_moq_user_session_t user_session = {
        .session = &session,
    };
    session.user_session = &user_session;
    session.session_callbacks.on_publish =
        xqc_test_on_publish_observe;
    session.session_callbacks.on_publish_done =
        xqc_test_on_publish_done_observe;

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    xqc_moq_d18_update_queue_init(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&stream.d18_peer_update_queue);
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_FIRST;
    xqc_moq_publish_msg_t publish = {
        .subscribe_id = 0,
        .track_alias = 4,
        .track_namespace_num = 1,
        .track_namespace_tuple = &live,
        .track_name = "audio",
        .track_name_len = 5,
    };
    xqc_moq_on_publish(&session, &stream, &publish.msg_base);
    XQC_TEST_ASSERT(stream.peer_request == 1);
    XQC_TEST_ASSERT(stream.request_type == XQC_MOQ_MSG_PUBLISH);
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    XQC_TEST_ASSERT(stream.track != NULL);
    XQC_TEST_ASSERT(xqc_moq_find_subscribe(&session, 0, 1) != NULL);

    xqc_moq_request_ok_msg_t initial_ok = {0};
    XQC_TEST_ASSERT(xqc_moq_write_request_ok(
        &session, stream.request_id, &initial_ok) == XQC_OK);
    XQC_TEST_ASSERT(stream.response_sent == 1);
    xqc_memzero(&capture, sizeof(capture));

    xqc_moq_message_parameter_t forward = {
        .type = XQC_MOQ_D18_PARAM_FORWARD,
        .is_integer = 1,
        .int_value = 0,
    };
    xqc_moq_request_update_msg_t update = {
        .request_id = 2,
        .params_num = 1,
        .params = &forward,
    };
    xqc_moq_on_request_update(&session, &stream, &update.msg_base);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_peer_update_queue)->request_id
        == update.request_id);

    xqc_moq_request_error_msg_t error = {
        .error_code = XQC_MOQ_REQUEST_ERROR_UNAUTHORIZED,
    };
    XQC_TEST_ASSERT(xqc_moq_write_request_error(
        &session, update.request_id, &error) == XQC_OK);
    XQC_TEST_ASSERT(capture.write_count == 1);
    XQC_TEST_ASSERT(capture.bytes[0] == XQC_MOQ_MSG_REQUEST_ERROR);
    XQC_TEST_ASSERT(capture.fin_history[0] == 0);
    XQC_TEST_ASSERT(stream.request_closed_notified == 0);
    XQC_TEST_ASSERT(stream.update_failed_wait_publish_done == 1);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_local_update_queue) == NULL);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_peer_update_queue) == NULL);
    XQC_TEST_ASSERT(xqc_moq_find_subscribe(&session, 0, 1) != NULL);
    XQC_TEST_ASSERT(stream.track != NULL);

    xqc_moq_request_update_msg_t future = {
        .params_num = 1,
        .params = &forward,
    };
    XQC_TEST_ASSERT(xqc_moq_write_request_update(
        &session, stream.request_id, &future) == -XQC_EPARAM);

    xqc_moq_publish_done_msg_t done = {
        .status_code = XQC_MOQ_PUBLISH_DONE_UPDATE_FAILED,
        .stream_count = 0,
    };
    xqc_test_publish_done_callback_count = 0;
    xqc_test_publish_done_request_id = XQC_MOQ_INVALID_ID;
    xqc_moq_on_publish_done(&session, &stream, &done.msg_base);
    XQC_TEST_ASSERT(xqc_test_publish_done_callback_count == 1);
    XQC_TEST_ASSERT(xqc_test_publish_done_request_id == 0);
    XQC_TEST_ASSERT(stream.request_closed_notified == 1);
    XQC_TEST_ASSERT(stream.update_failed_wait_publish_done == 0);
    XQC_TEST_ASSERT(stream.track == NULL);
    XQC_TEST_ASSERT(xqc_list_empty(&session.local_subscribe_list));
    XQC_TEST_ASSERT(xqc_list_empty(&session.track_list_for_sub));

    xqc_moq_d18_params_free(stream.d18_accepted_params,
                            stream.d18_accepted_params_num);
    stream.d18_accepted_params = NULL;
    stream.d18_accepted_params_num = 0;
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static int
xqc_test_failed_subscription_request_update_preserves_accepted_params(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    xqc_moq_d18_update_queue_init(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&stream.d18_peer_update_queue);
    stream.kind = XQC_MOQ_STREAM_D18_REQUEST;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    xqc_moq_track_ns_field_t old_prefix = {
        .len = 3,
        .data = (unsigned char *)"old",
    };
    xqc_moq_message_parameter_t accepted = {
        .type = XQC_MOQ_D18_PARAM_FORWARD,
        .is_integer = 1,
        .int_value = 0,
    };
    xqc_moq_subscribe_tracks_msg_t initial = {
        .request_id = 0,
        .track_namespace_num = 1,
        .track_namespace_tuple = &old_prefix,
        .params_num = 1,
        .params = &accepted,
    };
    xqc_moq_on_subscribe_tracks(&session, &stream, &initial.msg_base);
    XQC_TEST_ASSERT(stream.response_sent == 1);
    XQC_TEST_ASSERT(stream.d18_accepted_params_num == 1);
    XQC_TEST_ASSERT(stream.d18_accepted_params[0].int_value == 0);
    xqc_memzero(&capture, sizeof(capture));

    uint8_t new_prefix[] = {0x01, 0x03, 'n', 'e', 'w'};
    xqc_moq_message_parameter_t replacement = {
        .type = XQC_MOQ_D18_PARAM_TRACK_NAMESPACE_PREFIX,
        .length = sizeof(new_prefix),
        .value = new_prefix,
    };
    xqc_moq_request_update_msg_t update = {
        .request_id = 2,
        .params_num = 1,
        .params = &replacement,
    };
    xqc_moq_on_request_update(&session, &stream, &update.msg_base);

    xqc_moq_request_error_msg_t error = {
        .error_code = XQC_MOQ_REQUEST_ERROR_UNAUTHORIZED,
    };
    XQC_TEST_ASSERT(xqc_moq_write_request_error(
        &session, update.request_id, &error) == XQC_OK);
    XQC_TEST_ASSERT(stream.response_sent == 1);
    XQC_TEST_ASSERT(stream.write_stream_fin == 1);
    XQC_TEST_ASSERT(stream.request_closed_notified == 1);
    XQC_TEST_ASSERT(stream.d18_accepted_params_num == 1);
    XQC_TEST_ASSERT(stream.d18_accepted_params[0].int_value == 0);
    XQC_TEST_ASSERT(stream.tracks_subscription == NULL);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_peer_update_queue) == NULL);

    xqc_moq_d18_params_free(stream.d18_accepted_params,
                            stream.d18_accepted_params_num);
    stream.d18_accepted_params = NULL;
    stream.d18_accepted_params_num = 0;
    xqc_moq_d18_update_queue_destroy(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(&stream.d18_peer_update_queue);
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static int
xqc_test_subscribe_tracks_rejects_wrong_scope(void)
{
    static const uint8_t wrong_scope[] = {
        0x00, 0x05,
        0x00,
        0x00,
        0x01, 0x08, 0x01,
    };
    xqc_moq_subscribe_tracks_msg_t *decoded =
        xqc_moq_msg_create_subscribe_tracks();
    xqc_moq_decode_msg_ctx_t msg_ctx = {0};
    xqc_int_t finish = 0;
    xqc_int_t wait_more_data = 0;

    XQC_TEST_ASSERT(decoded != NULL);
    xqc_moq_msg_subscribe_tracks_init_handler(&decoded->msg_base);
    XQC_TEST_ASSERT(decoded->msg_base.decode(
        (uint8_t *)wrong_scope, sizeof(wrong_scope), 1,
        &msg_ctx, &decoded->msg_base, &finish,
        &wait_more_data) == -XQC_EPROTO);
    xqc_moq_msg_free_subscribe_tracks(decoded);
    return 0;
}

static int
xqc_test_subscribe_tracks_request_lifecycle(void)
{
    static const uint8_t expected_ok[] = {
        0x07, 0x00, 0x01, 0x00,
    };
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_moq_track_ns_field_t overlapping[] = {
        live,
        {
            .len = 6,
            .data = (unsigned char *)"camera",
        },
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    XQC_TEST_ASSERT(xqc_moq_session_add_namespace_prefix(
        &session, 8, &live, 1) == XQC_OK);

    xqc_test_write_capture_t first_capture = {0};
    xqc_moq_stream_t first_stream;
    xqc_test_init_stream(&first_stream, &session, &first_capture);
    first_stream.kind = XQC_MOQ_STREAM_D18_REQUEST;
    first_stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    first_stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    first_stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    xqc_moq_subscribe_tracks_msg_t first = {
        .request_id = 0,
        .track_namespace_num = 1,
        .track_namespace_tuple = &live,
    };
    xqc_moq_on_subscribe_tracks(
        &session, &first_stream, &first.msg_base);
    XQC_TEST_ASSERT(first_stream.peer_request == 1);
    XQC_TEST_ASSERT(first_stream.request_type
                    == XQC_MOQ_MSG_SUBSCRIBE_TRACKS);
    XQC_TEST_ASSERT(first_stream.request_id == 0);
    XQC_TEST_ASSERT(first_stream.response_sent == 1);
    XQC_TEST_ASSERT(first_stream.subscribe_tracks_active == 1);
    XQC_TEST_ASSERT(first_stream.tracks_subscription != NULL);
    XQC_TEST_ASSERT(first_capture.fin == 0);
    XQC_TEST_ASSERT(first_capture.length == sizeof(expected_ok));
    XQC_TEST_ASSERT(memcmp(first_capture.bytes, expected_ok,
                           sizeof(expected_ok)) == 0);

    xqc_test_write_capture_t overlap_capture = {0};
    xqc_moq_stream_t overlap_stream;
    xqc_test_init_stream(
        &overlap_stream, &session, &overlap_capture);
    overlap_stream.kind = XQC_MOQ_STREAM_D18_REQUEST;
    overlap_stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    overlap_stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    overlap_stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    xqc_moq_subscribe_tracks_msg_t overlap = {
        .request_id = 2,
        .track_namespace_num = 2,
        .track_namespace_tuple = overlapping,
    };
    xqc_moq_on_subscribe_tracks(
        &session, &overlap_stream, &overlap.msg_base);
    XQC_TEST_ASSERT(overlap_stream.peer_request == 1);
    XQC_TEST_ASSERT(overlap_stream.response_sent == 1);
    XQC_TEST_ASSERT(overlap_stream.subscribe_tracks_active == 0);
    XQC_TEST_ASSERT(overlap_capture.fin == 1);
    XQC_TEST_ASSERT(overlap_capture.bytes[0]
                    == XQC_MOQ_D18_MSG_REQUEST_ERROR);

    xqc_moq_request_error_msg_t *error =
        xqc_moq_msg_create_request_error();
    xqc_moq_decode_msg_ctx_t msg_ctx = {0};
    xqc_int_t finish = 0;
    xqc_int_t wait_more_data = 0;
    XQC_TEST_ASSERT(error != NULL);
    XQC_TEST_ASSERT(error->msg_base.decode(
        overlap_capture.bytes + 1, overlap_capture.length - 1, 1,
        &msg_ctx, &error->msg_base, &finish,
        &wait_more_data) == (xqc_int_t)overlap_capture.length - 1);
    XQC_TEST_ASSERT(finish == 1);
    XQC_TEST_ASSERT(error->error_code
                    == XQC_MOQ_REQUEST_ERROR_PREFIX_OVERLAP);
    xqc_moq_msg_free_request_error(error);

    xqc_moq_stream_on_request_closed(
        &first_stream, XQC_MOQ_REQUEST_CANCELLED);
    XQC_TEST_ASSERT(first_stream.subscribe_tracks_active == 0);
    XQC_TEST_ASSERT(first_stream.tracks_subscription == NULL);

    xqc_test_write_capture_t replacement_capture = {0};
    xqc_moq_stream_t replacement_stream;
    xqc_test_init_stream(
        &replacement_stream, &session, &replacement_capture);
    replacement_stream.kind = XQC_MOQ_STREAM_D18_REQUEST;
    replacement_stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    replacement_stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    replacement_stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    xqc_moq_subscribe_tracks_msg_t replacement = {
        .request_id = 4,
        .track_namespace_num = 1,
        .track_namespace_tuple = &live,
    };
    xqc_moq_on_subscribe_tracks(
        &session, &replacement_stream, &replacement.msg_base);
    XQC_TEST_ASSERT(replacement_stream.subscribe_tracks_active == 1);
    XQC_TEST_ASSERT(replacement_capture.fin == 0);
    XQC_TEST_ASSERT(replacement_capture.length == sizeof(expected_ok));

    xqc_moq_stream_on_request_closed(
        &replacement_stream, XQC_MOQ_REQUEST_CANCELLED);
    XQC_TEST_ASSERT(xqc_moq_session_remove_namespace_prefix(
        &session, &live, 1) == 1);
    xqc_test_clean_stream(&replacement_stream);
    xqc_test_clean_stream(&overlap_stream);
    xqc_test_clean_stream(&first_stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

static int
xqc_test_subscribe_tracks_application_decides_response(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    xqc_moq_user_session_t user_session = {
        .session = &session,
    };
    session.user_session = &user_session;
    session.session_callbacks_ext.on_subscribe_tracks =
        xqc_test_on_subscribe_tracks;

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    stream.kind = XQC_MOQ_STREAM_D18_REQUEST;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    xqc_moq_subscribe_tracks_msg_t request = {
        .request_id = 0,
    };
    xqc_test_subscribe_tracks_callback_count = 0;
    xqc_moq_on_subscribe_tracks(
        &session, &stream, &request.msg_base);
    XQC_TEST_ASSERT(xqc_test_subscribe_tracks_callback_count == 1);
    XQC_TEST_ASSERT(stream.response_sent == 0);
    XQC_TEST_ASSERT(stream.subscribe_tracks_active == 0);
    XQC_TEST_ASSERT(stream.tracks_subscription != NULL);
    XQC_TEST_ASSERT(capture.write_count == 0);

    xqc_moq_request_ok_msg_t ok = {0};
    XQC_TEST_ASSERT(xqc_moq_write_request_ok(
        &session, 0, &ok) == XQC_OK);
    XQC_TEST_ASSERT(stream.response_sent == 1);
    XQC_TEST_ASSERT(stream.subscribe_tracks_active == 1);
    XQC_TEST_ASSERT(capture.bytes[0]
                    == XQC_MOQ_D18_MSG_REQUEST_OK);

    xqc_moq_stream_on_request_closed(
        &stream, XQC_MOQ_REQUEST_CANCELLED);
    xqc_test_clean_stream(&stream);

    xqc_test_write_capture_t reject_capture = {0};
    xqc_moq_stream_t reject_stream;
    xqc_test_init_stream(
        &reject_stream, &session, &reject_capture);
    reject_stream.kind = XQC_MOQ_STREAM_D18_REQUEST;
    reject_stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    reject_stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    reject_stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    xqc_moq_subscribe_tracks_msg_t reject_request = {
        .request_id = 2,
    };
    xqc_moq_on_subscribe_tracks(
        &session, &reject_stream, &reject_request.msg_base);
    XQC_TEST_ASSERT(xqc_test_subscribe_tracks_callback_count == 2);
    XQC_TEST_ASSERT(reject_stream.tracks_subscription != NULL);
    xqc_moq_request_error_msg_t error = {
        .error_code = XQC_MOQ_REQUEST_ERROR_UNAUTHORIZED,
        .reason_phrase = "denied",
        .reason_phrase_len = sizeof("denied") - 1,
    };
    XQC_TEST_ASSERT(xqc_moq_write_request_error(
        &session, 2, &error) == XQC_OK);
    XQC_TEST_ASSERT(reject_stream.response_sent == 1);
    XQC_TEST_ASSERT(reject_stream.subscribe_tracks_active == 0);
    XQC_TEST_ASSERT(reject_stream.tracks_subscription == NULL);
    XQC_TEST_ASSERT(reject_capture.fin == 1);
    xqc_test_clean_stream(&reject_stream);

    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

static int
xqc_test_subscribe_tracks_writer_rejects_legacy_session(void)
{
    xqc_moq_session_t session = {
        .version = XQC_MOQ_VERSION_14,
    };
    xqc_moq_subscribe_tracks_msg_t request = {0};
    XQC_TEST_ASSERT(xqc_moq_write_subscribe_tracks(
        &session, &request) == -XQC_EPARAM);
    return 0;
}

static int
xqc_test_publish_wire_vectors(void)
{
    static const uint8_t expected_minimal[] = {
        0x1d, 0x00, 0x0f,
        0x02,
        0x01, 0x04, 'l', 'i', 'v', 'e',
        0x05, 'a', 'u', 'd', 'i', 'o',
        0x04,
        0x00,
    };
    static const uint8_t expected_forward_properties[] = {
        0x1d, 0x00, 0x1a,
        0x02,
        0x01, 0x04, 'l', 'i', 'v', 'e',
        0x05, 'a', 'u', 'd', 'i', 'o',
        0x04,
        0x01, 0x10, 0x00,
        0x02, 0x01,
        0x09, 0x02, 0x04, 0x07,
        0x2e, 0x01, 'z',
    };
    static uint8_t properties[] = {
        0x02, 0x01,
        0x09, 0x02, 0x04, 0x07,
        0x2e, 0x01, 'z',
    };
    static uint8_t malformed_properties[] = {0x02};
    static uint8_t wrong_scope_properties[] = {0x3c, 0x01};
    static uint8_t invalid_value_properties[] = {0x0e, 0x81, 0x00};
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_moq_message_parameter_t forward = {
        .type = XQC_MOQ_D18_PARAM_FORWARD,
        .is_integer = 1,
        .int_value = 0,
    };
    xqc_moq_publish_msg_t minimal = {
        .subscribe_id = 2,
        .track_alias = 4,
        .track_namespace_num = 1,
        .track_namespace_tuple = &live,
        .track_name = "audio",
        .track_name_len = 5,
    };
    xqc_moq_publish_msg_t with_properties = minimal;
    with_properties.params_num = 1;
    with_properties.params = &forward;
    with_properties.track_properties = properties;
    with_properties.track_properties_len = sizeof(properties);
    uint8_t buf[64] = {0};

    xqc_moq_msg_publish_request_init_handler(&minimal.msg_base);
    xqc_int_t len =
        xqc_moq_msg_encode_publish_request_len(&minimal.msg_base);
    XQC_TEST_ASSERT(len == (xqc_int_t)sizeof(expected_minimal));
    XQC_TEST_ASSERT(xqc_moq_msg_encode_publish_request(
        &minimal.msg_base, buf, sizeof(buf)) == len);
    XQC_TEST_ASSERT(memcmp(buf, expected_minimal,
                           sizeof(expected_minimal)) == 0);

    memset(buf, 0, sizeof(buf));
    xqc_moq_msg_publish_request_init_handler(
        &with_properties.msg_base);
    len = xqc_moq_msg_encode_publish_request_len(
        &with_properties.msg_base);
    XQC_TEST_ASSERT(len
                    == (xqc_int_t)sizeof(expected_forward_properties));
    XQC_TEST_ASSERT(xqc_moq_msg_encode_publish_request(
        &with_properties.msg_base, buf, sizeof(buf)) == len);
    XQC_TEST_ASSERT(memcmp(buf, expected_forward_properties,
                           sizeof(expected_forward_properties)) == 0);

    xqc_moq_publish_msg_t *decoded = xqc_moq_msg_create_publish();
    xqc_moq_decode_msg_ctx_t msg_ctx = {0};
    xqc_int_t finish = 0;
    xqc_int_t wait_more_data = 0;
    XQC_TEST_ASSERT(decoded != NULL);
    xqc_moq_msg_publish_request_init_handler(&decoded->msg_base);
    XQC_TEST_ASSERT(decoded->msg_base.decode(
        buf + 1, 5, 0, &msg_ctx, &decoded->msg_base,
        &finish, &wait_more_data) == 5);
    XQC_TEST_ASSERT(finish == 0);
    XQC_TEST_ASSERT(wait_more_data == 1);
    XQC_TEST_ASSERT(decoded->msg_base.decode(
        buf + 6, len - 6, 1, &msg_ctx, &decoded->msg_base,
        &finish, &wait_more_data) == len - 6);
    XQC_TEST_ASSERT(finish == 1);
    XQC_TEST_ASSERT(wait_more_data == 0);
    XQC_TEST_ASSERT(decoded->subscribe_id == 2);
    XQC_TEST_ASSERT(decoded->track_alias == 4);
    XQC_TEST_ASSERT(decoded->track_namespace_num == 1);
    XQC_TEST_ASSERT(decoded->track_name_len == 5);
    XQC_TEST_ASSERT(memcmp(decoded->track_name, "audio", 5) == 0);
    XQC_TEST_ASSERT(decoded->params_num == 1);
    XQC_TEST_ASSERT(decoded->params[0].type
                    == XQC_MOQ_D18_PARAM_FORWARD);
    XQC_TEST_ASSERT(decoded->params[0].int_value == 0);
    XQC_TEST_ASSERT(decoded->track_properties_len
                    == sizeof(properties));
    XQC_TEST_ASSERT(memcmp(decoded->track_properties,
                           properties, sizeof(properties)) == 0);
    xqc_moq_msg_free_publish(decoded);

    xqc_moq_publish_msg_t invalid = minimal;
    invalid.track_properties = malformed_properties;
    invalid.track_properties_len = sizeof(malformed_properties);
    xqc_moq_msg_publish_request_init_handler(&invalid.msg_base);
    XQC_TEST_ASSERT(xqc_moq_msg_encode_publish_request_len(
        &invalid.msg_base) == -XQC_EPARAM);
    invalid.track_properties = wrong_scope_properties;
    invalid.track_properties_len = sizeof(wrong_scope_properties);
    XQC_TEST_ASSERT(xqc_moq_msg_encode_publish_request_len(
        &invalid.msg_base) == -XQC_EPARAM);
    invalid.track_properties = invalid_value_properties;
    invalid.track_properties_len = sizeof(invalid_value_properties);
    XQC_TEST_ASSERT(xqc_moq_msg_encode_publish_request_len(
        &invalid.msg_base) == -XQC_EPARAM);
    return 0;
}

static int
xqc_test_outgoing_publish_never_falls_back_to_control_stream(void)
{
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.transport_type = (xqc_moq_transport_type_t)99;

    xqc_moq_track_t track;
    xqc_memzero(&track, sizeof(track));
    track.session = &session;
    track.subscribe_id = 2;
    track.track_alias = 4;
    xqc_init_list_head(&track.list_member);
    xqc_list_add_tail(&track.list_member, &session.track_list_for_pub);

    xqc_test_write_capture_t ctl_capture = {0};
    xqc_moq_stream_t ctl_stream;
    xqc_test_init_stream(&ctl_stream, &session, &ctl_capture);
    session.ctl_stream = &ctl_stream;

    xqc_moq_publish_msg_t publish = {
        .subscribe_id = 2,
        .track_alias = 4,
        .track_namespace_num = 1,
        .track_namespace_tuple = &live,
        .track_name = "audio",
        .track_name_len = 5,
    };
    XQC_TEST_ASSERT(xqc_moq_write_publish(
        &session, &publish) < 0);
    XQC_TEST_ASSERT(ctl_capture.write_count == 0);

    xqc_list_del_init(&track.list_member);
    xqc_test_clean_stream(&ctl_stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

static int
xqc_test_discovered_publish_honors_forward_without_legacy_params(void)
{
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_moq_track_t track;
    xqc_memzero(&track, sizeof(track));
    track.track_info.track_namespace_num = 1;
    track.track_info.track_namespace_tuple = &live;
    track.track_info.track_name = "audio";

    xqc_moq_publish_msg_t publish;
    xqc_moq_message_parameter_t forward_param;
    XQC_TEST_ASSERT(xqc_moq_prepare_d18_discovered_publish(
        &publish, &track, 0, &forward_param) == XQC_OK);
    XQC_TEST_ASSERT(publish.track_namespace_num == 1);
    XQC_TEST_ASSERT(publish.track_namespace_tuple == &live);
    XQC_TEST_ASSERT(publish.track_name == track.track_info.track_name);
    XQC_TEST_ASSERT(publish.track_name_len == 5);
    XQC_TEST_ASSERT(publish.params_num == 1);
    XQC_TEST_ASSERT(publish.params == &forward_param);
    XQC_TEST_ASSERT(forward_param.type == XQC_MOQ_D18_PARAM_FORWARD);
    XQC_TEST_ASSERT(forward_param.is_integer == 1);
    XQC_TEST_ASSERT(forward_param.int_value == 0);

    XQC_TEST_ASSERT(xqc_moq_prepare_d18_discovered_publish(
        &publish, &track, 1, &forward_param) == XQC_OK);
    XQC_TEST_ASSERT(publish.params_num == 0);
    XQC_TEST_ASSERT(publish.params == NULL);
    return 0;
}

static int
xqc_test_incoming_publish_uses_request_stream_response(void)
{
    static const uint8_t expected_ok[] = {
        0x07, 0x00, 0x07, 0x03,
        0x10, 0x01,
        0x10, 0x07,
        0x02, 0x01,
    };
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    xqc_moq_user_session_t user_session = {
        .session = &session,
    };
    session.user_session = &user_session;
    session.role = XQC_MOQ_SUBSCRIBER;
    session.session_callbacks.on_publish = xqc_test_on_publish;

    xqc_test_write_capture_t ctl_capture = {0};
    xqc_test_write_capture_t request_capture = {0};
    xqc_moq_stream_t ctl_stream;
    xqc_moq_stream_t request_stream;
    xqc_test_init_stream(&ctl_stream, &session, &ctl_capture);
    xqc_test_init_stream(
        &request_stream, &session, &request_capture);
    request_stream.kind = XQC_MOQ_STREAM_D18_REQUEST;
    request_stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    request_stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    request_stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    session.ctl_stream = &ctl_stream;

    xqc_moq_publish_msg_t publish = {
        .subscribe_id = 0,
        .track_alias = 4,
        .track_namespace_num = 1,
        .track_namespace_tuple = &live,
        .track_name = "audio",
        .track_name_len = 5,
    };
    xqc_test_publish_callback_count = 0;
    xqc_test_publish_response_ret = -XQC_EPARAM;
    xqc_moq_on_publish(
        &session, &request_stream, &publish.msg_base);
    XQC_TEST_ASSERT(request_stream.peer_request == 1);
    XQC_TEST_ASSERT(request_stream.request_type
                    == XQC_MOQ_MSG_PUBLISH);
    XQC_TEST_ASSERT(request_stream.request_id == 0);
    XQC_TEST_ASSERT(request_stream.response_sent == 1);
    XQC_TEST_ASSERT(xqc_test_publish_callback_count == 1);
    XQC_TEST_ASSERT(xqc_test_publish_response_ret == XQC_OK);
    XQC_TEST_ASSERT(ctl_capture.write_count == 0);
    XQC_TEST_ASSERT(request_capture.length == sizeof(expected_ok));
    XQC_TEST_ASSERT(memcmp(request_capture.bytes, expected_ok,
                           sizeof(expected_ok)) == 0);

    xqc_test_clean_stream(&request_stream);
    xqc_test_clean_stream(&ctl_stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

static int
xqc_test_incoming_publish_rejects_mandatory_property(void)
{
    static uint8_t mandatory[] = {0xc0, 0x40, 0x00, 0x00};
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_connection_t quic_conn;
    xqc_memzero(&quic_conn, sizeof(quic_conn));
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    quic_conn.log = &xqc_test_log;
    session.role = XQC_MOQ_SUBSCRIBER;
    session.quic_conn = &quic_conn;
    xqc_moq_user_session_t user_session = {
        .session = &session,
    };
    session.user_session = &user_session;
    session.session_callbacks.on_publish = xqc_test_on_publish_observe;

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    stream.kind = XQC_MOQ_STREAM_D18_REQUEST;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    xqc_moq_publish_msg_t publish = {
        .subscribe_id = 0,
        .track_alias = 4,
        .track_namespace_num = 1,
        .track_namespace_tuple = &live,
        .track_name = "audio",
        .track_name_len = 5,
        .track_properties = mandatory,
        .track_properties_len = sizeof(mandatory),
    };

    XQC_TEST_ASSERT(
        XQC_MOQ_REQUEST_ERROR_UNSUPPORTED_EXTENSION == 0x33);
    xqc_test_publish_callback_count = 0;
    xqc_moq_on_publish(&session, &stream, &publish.msg_base);
    XQC_TEST_ASSERT(quic_conn.conn_err == 0);
    XQC_TEST_ASSERT(xqc_test_publish_callback_count == 0);
    XQC_TEST_ASSERT(capture.write_count == 1);
    XQC_TEST_ASSERT(capture.bytes[0] == XQC_MOQ_D18_MSG_REQUEST_ERROR);
    XQC_TEST_ASSERT(capture.bytes[3]
                    == XQC_MOQ_REQUEST_ERROR_UNSUPPORTED_EXTENSION);
    XQC_TEST_ASSERT(capture.fin == 1);
    XQC_TEST_ASSERT(stream.request_closed_notified == 1);
    XQC_TEST_ASSERT(xqc_moq_find_track_by_ns_tuple(
        &session, &live, 1, "audio", XQC_MOQ_TRACK_FOR_SUB) == NULL);
    XQC_TEST_ASSERT(xqc_list_empty(&session.local_subscribe_list));

    xqc_test_clean_stream(&stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

static int
xqc_test_incoming_publish_property_session_errors(void)
{
    static uint8_t malformed[] = {0x02};
    static uint8_t invalid_value[] = {0x0e, 0x81, 0x00};
    struct {
        uint8_t *properties;
        size_t properties_len;
        uint64_t expected_error;
        const char *expected_reason;
    } cases[] = {
        {
            malformed, sizeof(malformed),
            XQC_MOQ_D18_KEY_VALUE_FORMATTING_ERROR,
            "malformed PUBLISH Track Properties",
        },
        {
            invalid_value, sizeof(invalid_value),
            XQC_MOQ_D18_PROTOCOL_VIOLATION,
            "invalid PUBLISH Track Properties",
        },
    };
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        xqc_connection_t quic_conn;
        xqc_memzero(&quic_conn, sizeof(quic_conn));
        xqc_moq_session_t session;
        xqc_test_init_session(&session);
        quic_conn.log = &xqc_test_log;
        session.role = XQC_MOQ_SUBSCRIBER;
        session.quic_conn = &quic_conn;
        xqc_moq_user_session_t user_session = {
            .session = &session,
        };
        session.user_session = &user_session;
        session.session_callbacks.on_publish = xqc_test_on_publish_observe;
        xqc_test_write_capture_t capture = {0};
        xqc_moq_stream_t stream;
        xqc_test_init_stream(&stream, &session, &capture);
        xqc_moq_publish_msg_t publish = {
            .subscribe_id = 0,
            .track_alias = 4,
            .track_namespace_num = 1,
            .track_namespace_tuple = &live,
            .track_name = "audio",
            .track_name_len = 5,
            .track_properties = cases[i].properties,
            .track_properties_len = cases[i].properties_len,
        };

        xqc_test_publish_callback_count = 0;
        xqc_moq_on_publish(&session, &stream, &publish.msg_base);
        XQC_TEST_ASSERT(quic_conn.conn_err == cases[i].expected_error);
        XQC_TEST_ASSERT(quic_conn.conn_close_msg != NULL);
        XQC_TEST_ASSERT(strcmp(quic_conn.conn_close_msg,
                               cases[i].expected_reason) == 0);
        XQC_TEST_ASSERT(xqc_test_publish_callback_count == 0);
        XQC_TEST_ASSERT(capture.write_count == 0);
        XQC_TEST_ASSERT(xqc_moq_find_track_by_ns_tuple(
            &session, &live, 1, "audio", XQC_MOQ_TRACK_FOR_SUB) == NULL);

        xqc_test_clean_stream(&stream);
        xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
        xqc_moq_d18_request_registry_destroy(
            &session.d18_request_registry);
    }
    return 0;
}

static int
xqc_test_subscribe_ok_mandatory_property_cancels_subscription(void)
{
    static uint8_t mandatory[] = {0xc0, 0x40, 0x00, 0x00};
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_connection_t quic_conn;
    xqc_memzero(&quic_conn, sizeof(quic_conn));
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    quic_conn.log = &xqc_test_log;
    session.role = XQC_MOQ_SUBSCRIBER;
    session.quic_conn = &quic_conn;

    xqc_moq_track_t *track = xqc_moq_track_create_with_ns_tuple(
        &session, &live, 1, "audio", XQC_MOQ_TRACK_AUDIO, NULL,
        XQC_MOQ_CONTAINER_NONE, XQC_MOQ_TRACK_FOR_SUB);
    XQC_TEST_ASSERT(track != NULL);
    track->track_ops.on_subscribe_ok = xqc_test_on_subscribe_ok_observe;
    xqc_moq_track_set_alias(track, 4);
    xqc_moq_track_set_subscribe_id(track, 0);
    XQC_TEST_ASSERT(xqc_moq_subscribe_create_with_ns_tuple(
        &session, 0, 4, &live, 1, "audio",
        XQC_MOQ_FILTER_LAST_GROUP, 0, 0, 0, 0, NULL, 1) != NULL);

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    stream.local_request = 1;
    stream.request_type = XQC_MOQ_MSG_SUBSCRIBE;
    stream.request_id = 0;
    xqc_list_add_tail(&stream.request_list_member,
                      &session.local_request_stream_list);

    xqc_moq_subscribe_ok_msg_t subscribe_ok = {
        .track_alias = 4,
        .track_properties = mandatory,
        .track_properties_len = sizeof(mandatory),
    };
    xqc_test_subscribe_ok_callback_count = 0;
    xqc_moq_on_subscribe_ok(
        &session, &stream, &subscribe_ok.msg_base);
    XQC_TEST_ASSERT(quic_conn.conn_err == 0);
    XQC_TEST_ASSERT(xqc_test_subscribe_ok_callback_count == 0);
    XQC_TEST_ASSERT(stream.response_received == 1);
    XQC_TEST_ASSERT(stream.request_closed_notified == 1);
    XQC_TEST_ASSERT(capture.cancel_count == 1);
    XQC_TEST_ASSERT(capture.cancel_error == XQC_MOQ_REQUEST_CANCELLED);
    XQC_TEST_ASSERT(capture.stop_sending_count == 1);
    XQC_TEST_ASSERT(capture.stop_sending_error
                    == XQC_MOQ_REQUEST_CANCELLED);
    XQC_TEST_ASSERT(xqc_moq_find_subscribe(&session, 0, 1) == NULL);
    XQC_TEST_ASSERT(track->track_alias == XQC_MOQ_INVALID_ID);
    XQC_TEST_ASSERT(track->subscribe_id == XQC_MOQ_INVALID_ID);

    xqc_list_del_init(&track->list_member);
    xqc_moq_track_destroy(track);
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

static int
xqc_test_publish_request_ok_reaches_compatibility_callback(void)
{
    xqc_moq_message_parameter_t params[] = {
        {
            .type = XQC_MOQ_D18_PARAM_FORWARD,
            .is_integer = 1,
            .int_value = 1,
        },
        {
            .type = XQC_MOQ_D18_PARAM_SUBSCRIBER_PRIORITY,
            .is_integer = 1,
            .int_value = 7,
        },
        {
            .type = XQC_MOQ_D18_PARAM_GROUP_ORDER,
            .is_integer = 1,
            .int_value = 1,
        },
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    xqc_moq_user_session_t user_session = {
        .session = &session,
    };
    session.user_session = &user_session;
    session.session_callbacks_ext.on_request_ok =
        xqc_test_on_request_ok;
    session.session_callbacks.on_publish_ok =
        xqc_test_on_publish_ok;

    xqc_moq_track_t track;
    xqc_memzero(&track, sizeof(track));
    track.session = &session;
    track.subscribe_id = 0;
    track.track_alias = 4;
    xqc_moq_stream_t stream;
    xqc_memzero(&stream, sizeof(stream));
    stream.session = &session;
    stream.local_request = 1;
    stream.request_type = XQC_MOQ_MSG_PUBLISH;
    stream.request_id = 0;
    stream.track = &track;

    xqc_moq_request_ok_msg_t ok = {
        .params_num = sizeof(params) / sizeof(params[0]),
        .params = params,
    };
    xqc_test_generic_ok_callback_count = 0;
    xqc_test_publish_ok_callback_count = 0;
    xqc_test_publish_ok_callback_fields_valid = 0;
    xqc_moq_on_request_ok(&session, &stream, &ok.msg_base);
    XQC_TEST_ASSERT(stream.response_received == 1);
    XQC_TEST_ASSERT(xqc_test_generic_ok_callback_count == 1);
    XQC_TEST_ASSERT(xqc_test_publish_ok_callback_count == 1);
    XQC_TEST_ASSERT(xqc_test_publish_ok_callback_fields_valid == 1);

    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

static int
xqc_test_publish_request_error_uses_stream_and_callbacks(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    xqc_moq_user_session_t user_session = {
        .session = &session,
    };
    session.user_session = &user_session;

    xqc_test_write_capture_t ctl_capture = {0};
    xqc_test_write_capture_t request_capture = {0};
    xqc_moq_stream_t ctl_stream;
    xqc_moq_stream_t peer_stream;
    xqc_test_init_stream(&ctl_stream, &session, &ctl_capture);
    xqc_test_init_stream(
        &peer_stream, &session, &request_capture);
    session.ctl_stream = &ctl_stream;
    peer_stream.peer_request = 1;
    peer_stream.request_type = XQC_MOQ_MSG_PUBLISH;
    peer_stream.request_id = 0;
    peer_stream.kind = XQC_MOQ_STREAM_D18_REQUEST;
    peer_stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    peer_stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    peer_stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    xqc_list_add_tail(&peer_stream.request_list_member,
                      &session.peer_request_stream_list);

    xqc_moq_publish_error_msg_t publish_error = {
        .subscribe_id = 0,
        .error_code = XQC_MOQ_REQUEST_ERROR_UNAUTHORIZED,
        .reason_phrase = "denied",
        .reason_phrase_len = sizeof("denied") - 1,
    };
    XQC_TEST_ASSERT(xqc_moq_write_publish_error(
        &session, &publish_error) == XQC_OK);
    XQC_TEST_ASSERT(ctl_capture.write_count == 0);
    XQC_TEST_ASSERT(request_capture.bytes[0]
                    == XQC_MOQ_D18_MSG_REQUEST_ERROR);
    XQC_TEST_ASSERT(request_capture.fin == 1);

    session.session_callbacks_ext.on_request_error =
        xqc_test_on_request_error;
    session.session_callbacks.on_publish_error =
        xqc_test_on_publish_error;
    xqc_moq_track_t track;
    xqc_memzero(&track, sizeof(track));
    track.session = &session;
    xqc_moq_stream_t local_stream;
    xqc_memzero(&local_stream, sizeof(local_stream));
    local_stream.session = &session;
    local_stream.local_request = 1;
    local_stream.request_type = XQC_MOQ_MSG_PUBLISH;
    local_stream.request_id = 0;
    local_stream.track = &track;
    xqc_moq_request_error_msg_t request_error = {
        .error_code = XQC_MOQ_REQUEST_ERROR_UNAUTHORIZED,
        .reason_phrase = "denied",
        .reason_phrase_len = sizeof("denied") - 1,
    };
    xqc_test_generic_error_callback_count = 0;
    xqc_test_publish_error_callback_count = 0;
    xqc_moq_on_request_error(
        &session, &local_stream, &request_error.msg_base);
    XQC_TEST_ASSERT(local_stream.response_received == 1);
    XQC_TEST_ASSERT(xqc_test_generic_error_callback_count == 1);
    XQC_TEST_ASSERT(xqc_test_publish_error_callback_count == 1);

    xqc_test_clean_stream(&peer_stream);
    xqc_test_clean_stream(&ctl_stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

static int
xqc_test_incoming_publish_binds_alias_only_after_ok(void)
{
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.role = XQC_MOQ_SUBSCRIBER;
    xqc_moq_session_set_request_cancelled_callback(
        &session, xqc_test_on_request_cancelled);

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    stream.kind = XQC_MOQ_STREAM_D18_REQUEST;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    xqc_moq_publish_msg_t publish = {
        .subscribe_id = 0,
        .track_alias = 4,
        .track_namespace_num = 1,
        .track_namespace_tuple = &live,
        .track_name = "audio",
        .track_name_len = 5,
    };

    xqc_moq_on_publish(&session, &stream, &publish.msg_base);
    XQC_TEST_ASSERT(stream.track != NULL);
    xqc_moq_track_t *track = stream.track;
    XQC_TEST_ASSERT(
        track->track_alias == XQC_MOQ_INVALID_ID);
    XQC_TEST_ASSERT(
        track->subscribe_id == XQC_MOQ_INVALID_ID);
    XQC_TEST_ASSERT(!xqc_list_empty(
        &session.local_subscribe_list));

    xqc_moq_request_ok_msg_t ok = {0};
    XQC_TEST_ASSERT(xqc_moq_write_request_ok(
        &session, 0, &ok) == XQC_OK);
    XQC_TEST_ASSERT(track->track_alias == 4);
    XQC_TEST_ASSERT(track->subscribe_id == 0);

    xqc_test_request_cancelled_callback_count = 0;
    xqc_moq_stream_on_request_closed(
        &stream, XQC_MOQ_REQUEST_CANCELLED);
    XQC_TEST_ASSERT(xqc_test_request_cancelled_callback_count == 1);
    XQC_TEST_ASSERT(xqc_test_cancelled_request_id == 0);
    XQC_TEST_ASSERT(
        xqc_test_cancelled_request_type == XQC_MOQ_MSG_PUBLISH);
    XQC_TEST_ASSERT(xqc_test_cancelled_locally_initiated == 0);
    XQC_TEST_ASSERT(
        xqc_test_cancelled_error_code == XQC_MOQ_REQUEST_CANCELLED);
    XQC_TEST_ASSERT(stream.track == NULL);
    XQC_TEST_ASSERT(xqc_list_empty(
        &session.local_subscribe_list));
    XQC_TEST_ASSERT(
        track->track_alias == XQC_MOQ_INVALID_ID);
    XQC_TEST_ASSERT(
        track->subscribe_id == XQC_MOQ_INVALID_ID);
    xqc_list_del_init(&track->list_member);
    xqc_moq_track_destroy(track);
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

static int
xqc_test_incoming_publish_error_rolls_back_state(void)
{
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.role = XQC_MOQ_SUBSCRIBER;

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    stream.kind = XQC_MOQ_STREAM_D18_REQUEST;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    xqc_moq_publish_msg_t publish = {
        .subscribe_id = 0,
        .track_alias = 4,
        .track_namespace_num = 1,
        .track_namespace_tuple = &live,
        .track_name = "audio",
        .track_name_len = 5,
    };
    xqc_moq_on_publish(&session, &stream, &publish.msg_base);
    XQC_TEST_ASSERT(stream.track != NULL);
    xqc_moq_track_t *track = stream.track;

    xqc_moq_request_error_msg_t error = {
        .error_code = XQC_MOQ_REQUEST_ERROR_UNAUTHORIZED,
        .reason_phrase = "denied",
        .reason_phrase_len = sizeof("denied") - 1,
    };
    XQC_TEST_ASSERT(xqc_moq_write_request_error(
        &session, 0, &error) == XQC_OK);
    XQC_TEST_ASSERT(stream.request_closed_notified == 1);
    XQC_TEST_ASSERT(xqc_list_empty(
        &session.local_subscribe_list));
    XQC_TEST_ASSERT(stream.track == NULL);
    XQC_TEST_ASSERT(
        track->track_alias == XQC_MOQ_INVALID_ID);
    XQC_TEST_ASSERT(
        track->subscribe_id == XQC_MOQ_INVALID_ID);

    xqc_list_del_init(&track->list_member);
    xqc_moq_track_destroy(track);
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

static int
xqc_test_outgoing_publish_error_and_close_roll_back_state(void)
{
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.session_callbacks.on_publish_error =
        xqc_test_on_publish_error_after_cleanup;
    xqc_moq_session_set_request_cancelled_callback(
        &session, xqc_test_on_request_cancelled);

    xqc_moq_track_t track;
    xqc_memzero(&track, sizeof(track));
    track.session = &session;
    track.track_role = XQC_MOQ_TRACK_FOR_PUB;
    track.track_alias = 4;
    track.subscribe_id = 1;
    track.track_info.track_namespace_tuple = &live;
    track.track_info.track_namespace_num = 1;
    track.track_info.track_name = "audio";
    xqc_init_list_head(&track.list_member);
    xqc_list_add_tail(
        &track.list_member, &session.track_list_for_pub);
    XQC_TEST_ASSERT(xqc_moq_subscribe_create_with_ns_tuple(
        &session, 1, 4, &live, 1, "audio",
        XQC_MOQ_FILTER_LAST_GROUP, 0, 0, 0, 0, NULL, 0)
        != NULL);

    xqc_moq_stream_t stream;
    xqc_memzero(&stream, sizeof(stream));
    stream.session = &session;
    stream.local_request = 1;
    stream.request_type = XQC_MOQ_MSG_PUBLISH;
    stream.request_id = 1;
    stream.track = &track;
    xqc_init_list_head(&stream.request_list_member);

    xqc_moq_request_error_msg_t error = {
        .error_code = XQC_MOQ_REQUEST_ERROR_UNAUTHORIZED,
    };
    xqc_test_publish_error_saw_idle_track = 0;
    xqc_test_request_cancelled_callback_count = 0;
    xqc_moq_on_request_error(
        &session, &stream, &error.msg_base);
    XQC_TEST_ASSERT(xqc_test_publish_error_saw_idle_track == 1);
    XQC_TEST_ASSERT(xqc_test_request_cancelled_callback_count == 0);
    XQC_TEST_ASSERT(track.track_alias == XQC_MOQ_INVALID_ID);
    XQC_TEST_ASSERT(track.subscribe_id == XQC_MOQ_INVALID_ID);
    XQC_TEST_ASSERT(xqc_list_empty(
        &session.peer_subscribe_list));

    track.track_alias = 6;
    track.subscribe_id = 3;
    XQC_TEST_ASSERT(xqc_moq_subscribe_create_with_ns_tuple(
        &session, 3, 6, &live, 1, "audio",
        XQC_MOQ_FILTER_LAST_GROUP, 0, 0, 0, 0, NULL, 0)
        != NULL);
    stream.request_id = 3;
    stream.track = &track;
    stream.response_received = 0;
    stream.request_closed_notified = 0;
    xqc_moq_stream_on_request_closed(
        &stream, XQC_MOQ_REQUEST_CANCELLED);
    XQC_TEST_ASSERT(xqc_test_request_cancelled_callback_count == 1);
    XQC_TEST_ASSERT(xqc_test_cancelled_request_id == 3);
    XQC_TEST_ASSERT(
        xqc_test_cancelled_request_type == XQC_MOQ_MSG_PUBLISH);
    XQC_TEST_ASSERT(xqc_test_cancelled_locally_initiated == 1);
    XQC_TEST_ASSERT(
        xqc_test_cancelled_error_code == XQC_MOQ_REQUEST_CANCELLED);
    XQC_TEST_ASSERT(track.track_alias == XQC_MOQ_INVALID_ID);
    XQC_TEST_ASSERT(track.subscribe_id == XQC_MOQ_INVALID_ID);
    XQC_TEST_ASSERT(xqc_list_empty(
        &session.peer_subscribe_list));

    xqc_list_del_init(&track.list_member);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

static int
xqc_test_incoming_publish_rejects_duplicate_established_alias(void)
{
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_connection_t quic_conn;
    xqc_memzero(&quic_conn, sizeof(quic_conn));
    quic_conn.conn_err = UINT64_MAX;
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.role = XQC_MOQ_SUBSCRIBER;
    session.quic_conn = &quic_conn;

    xqc_moq_track_t *existing =
        xqc_moq_track_create_with_ns_tuple(
            &session, &live, 1, "audio",
            XQC_MOQ_TRACK_AUDIO, NULL, XQC_MOQ_CONTAINER_NONE,
            XQC_MOQ_TRACK_FOR_SUB);
    XQC_TEST_ASSERT(existing != NULL);
    xqc_moq_track_set_alias(existing, 4);
    xqc_moq_track_set_subscribe_id(existing, 2);

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    xqc_moq_publish_msg_t publish = {
        .subscribe_id = 0,
        .track_alias = 4,
        .track_namespace_num = 1,
        .track_namespace_tuple = &live,
        .track_name = "video",
        .track_name_len = 5,
    };
    xqc_moq_on_publish(&session, &stream, &publish.msg_base);

    XQC_TEST_ASSERT(quic_conn.conn_close_msg != NULL);
    XQC_TEST_ASSERT(strcmp(
        quic_conn.conn_close_msg,
        "duplicate PUBLISH track alias") == 0);
    XQC_TEST_ASSERT(xqc_moq_find_track_by_ns_tuple(
        &session, &live, 1, "video",
        XQC_MOQ_TRACK_FOR_SUB) == NULL);
    XQC_TEST_ASSERT(xqc_list_empty(
        &session.local_subscribe_list));

    xqc_list_del_init(&existing->list_member);
    xqc_moq_track_destroy(existing);
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

static int
xqc_test_incoming_publish_rejects_duplicate_subscription(void)
{
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_connection_t quic_conn;
    xqc_memzero(&quic_conn, sizeof(quic_conn));
    quic_conn.conn_err = UINT64_MAX;
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.role = XQC_MOQ_SUBSCRIBER;
    session.quic_conn = &quic_conn;

    xqc_moq_track_t *existing =
        xqc_moq_track_create_with_ns_tuple(
            &session, &live, 1, "audio",
            XQC_MOQ_TRACK_AUDIO, NULL, XQC_MOQ_CONTAINER_NONE,
            XQC_MOQ_TRACK_FOR_SUB);
    XQC_TEST_ASSERT(existing != NULL);
    xqc_moq_track_set_alias(existing, 4);
    xqc_moq_track_set_subscribe_id(existing, 2);
    XQC_TEST_ASSERT(xqc_moq_subscribe_create_with_ns_tuple(
        &session, 2, 4, &live, 1, "audio",
        XQC_MOQ_FILTER_LAST_GROUP, 0, 0, 0, 0, NULL, 1)
        != NULL);

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    stream.kind = XQC_MOQ_STREAM_D18_REQUEST;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    xqc_moq_publish_msg_t publish = {
        .subscribe_id = 0,
        .track_alias = 4,
        .track_namespace_num = 1,
        .track_namespace_tuple = &live,
        .track_name = "audio",
        .track_name_len = 5,
    };
    xqc_moq_on_publish(&session, &stream, &publish.msg_base);

    XQC_TEST_ASSERT(quic_conn.conn_err == UINT64_MAX);
    XQC_TEST_ASSERT(capture.write_count == 1);
    XQC_TEST_ASSERT(capture.bytes[0]
                    == XQC_MOQ_D18_MSG_REQUEST_ERROR);
    XQC_TEST_ASSERT(capture.bytes[3] == 0x19);
    XQC_TEST_ASSERT(capture.fin == 1);
    XQC_TEST_ASSERT(stream.request_closed_notified == 1);
    XQC_TEST_ASSERT(existing->track_alias == 4);
    XQC_TEST_ASSERT(existing->subscribe_id == 2);
    XQC_TEST_ASSERT(xqc_moq_find_subscribe(
        &session, 2, 1) != NULL);

    xqc_moq_subscribe_t *subscription =
        xqc_moq_find_subscribe(&session, 2, 1);
    xqc_list_del_init(&subscription->list_member);
    xqc_moq_subscribe_destroy(subscription);
    xqc_list_del_init(&existing->list_member);
    xqc_moq_track_destroy(existing);
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

static int
xqc_test_publish_done_waits_for_data_fin_acceptance(void)
{
    static const uint8_t expected[] = {
        XQC_MOQ_D18_MSG_PUBLISH_DONE,
        0x00, 0x03,
        XQC_MOQ_PUBLISH_DONE_TRACK_ENDED,
        0x01,
        0x00,
    };
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };

    const ssize_t first_results[] = {
        -XQC_EAGAIN,
        1,
        -XQC_ESYS,
    };
    for (size_t i = 0;
         i < sizeof(first_results) / sizeof(first_results[0]); i++)
    {
        xqc_moq_session_t session;
        xqc_test_init_session(&session);
        xqc_moq_track_t *track =
            xqc_moq_track_create_with_ns_tuple(
                &session, &live, 1, "audio",
                XQC_MOQ_TRACK_AUDIO, NULL,
                XQC_MOQ_CONTAINER_NONE,
                XQC_MOQ_TRACK_FOR_PUB);
        XQC_TEST_ASSERT(track != NULL);
        xqc_moq_track_set_alias(track, 4);
        xqc_moq_track_set_subscribe_id(track, 9);
        XQC_TEST_ASSERT(xqc_moq_subscribe_create_with_ns_tuple(
            &session, 9, 4, &live, 1, "audio",
            XQC_MOQ_FILTER_LAST_GROUP, 0, 0, 0, 0, NULL, 0)
            != NULL);

        xqc_test_write_capture_t request_capture = {0};
        xqc_test_write_capture_t data_capture = {
            .scripted_results = {
                first_results[i],
            },
            .scripted_results_count = 1,
        };
        xqc_moq_stream_t request_stream;
        xqc_moq_stream_t data_stream;
        xqc_test_init_stream(
            &request_stream, &session, &request_capture);
        xqc_test_init_stream(&data_stream, &session, &data_capture);
        xqc_moq_d18_update_queue_init(
            &request_stream.d18_local_update_queue);
        xqc_moq_d18_update_queue_init(
            &request_stream.d18_peer_update_queue);
        request_stream.local_request = 1;
        request_stream.response_received = 1;
        request_stream.request_type = XQC_MOQ_MSG_PUBLISH;
        request_stream.request_id = 9;
        request_stream.track = track;
        request_stream.kind = XQC_MOQ_STREAM_D18_REQUEST;
        request_stream.d18_context.direction =
            XQC_MOQ_D18_DIRECTION_BIDI;
        request_stream.d18_context.stream_class =
            XQC_MOQ_D18_STREAM_REQUEST;
        request_stream.d18_context.position =
            XQC_MOQ_D18_POSITION_NEXT;
        xqc_list_add_tail(
            &request_stream.request_list_member,
            &session.local_request_stream_list);

        data_stream.write_buf = xqc_malloc(2);
        XQC_TEST_ASSERT(data_stream.write_buf != NULL);
        data_stream.write_buf[0] = 'a';
        data_stream.write_buf[1] = 'b';
        data_stream.write_buf_len = 2;
        data_stream.write_buf_cap = 2;
        xqc_moq_track_on_write_stream(
            track, &data_stream, 1, 0, 0);

        xqc_moq_publish_done_msg_t done = {
            .subscribe_id = 9,
            .status_code = XQC_MOQ_PUBLISH_DONE_TRACK_ENDED,
        };
        xqc_int_t first_ret = xqc_moq_write_publish_done(
            &session, &done);
        XQC_TEST_ASSERT(request_capture.length == 0);
        XQC_TEST_ASSERT(first_ret
                        == (i == 2 ? -XQC_ESYS : -XQC_EAGAIN));
        XQC_TEST_ASSERT(request_stream.request_closed_notified == 0);
        XQC_TEST_ASSERT(data_stream.write_stream_fin == 1);
        XQC_TEST_ASSERT(data_capture.call_fin_history[0] == 1);
        XQC_TEST_ASSERT(track->track_alias == XQC_MOQ_INVALID_ID);
        XQC_TEST_ASSERT(track->subscribe_id == XQC_MOQ_INVALID_ID);

        xqc_int_t retry_ret = xqc_moq_write_publish_done(
            &session, &done);
        XQC_TEST_ASSERT(retry_ret == XQC_OK);
        XQC_TEST_ASSERT(data_capture.length == 2);
        XQC_TEST_ASSERT(request_capture.length == sizeof(expected));
        XQC_TEST_ASSERT(memcmp(
            request_capture.bytes, expected, sizeof(expected)) == 0);
        XQC_TEST_ASSERT(request_capture.write_count == 1);
        XQC_TEST_ASSERT(request_capture.fin == 1);

        xqc_list_del_init(&data_stream.list_member);
        data_stream.track = NULL;
        xqc_moq_d18_update_queue_destroy(
            &request_stream.d18_local_update_queue);
        xqc_moq_d18_update_queue_destroy(
            &request_stream.d18_peer_update_queue);
        xqc_test_clean_stream(&data_stream);
        xqc_test_clean_stream(&request_stream);
        xqc_list_del_init(&track->list_member);
        xqc_moq_track_destroy(track);
        xqc_moq_d18_request_registry_destroy(
            &session.d18_request_registry);
        xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    }
    return 0;
}

static int
xqc_test_update_failed_publish_done_retries_after_data_fin_writable(void)
{
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_connection_t quic_conn;
    xqc_memzero(&quic_conn, sizeof(quic_conn));
    quic_conn.log = &xqc_test_log;
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.quic_conn = &quic_conn;
    xqc_moq_track_t *track =
        xqc_moq_track_create_with_ns_tuple(
            &session, &live, 1, "audio",
            XQC_MOQ_TRACK_AUDIO, NULL,
            XQC_MOQ_CONTAINER_NONE,
            XQC_MOQ_TRACK_FOR_PUB);
    XQC_TEST_ASSERT(track != NULL);
    xqc_moq_track_set_alias(track, 4);
    xqc_moq_track_set_subscribe_id(track, 1);
    XQC_TEST_ASSERT(xqc_moq_subscribe_create_with_ns_tuple(
        &session, 1, 4, &live, 1, "audio",
        XQC_MOQ_FILTER_LAST_GROUP, 0, 0, 0, 0, NULL, 0)
        != NULL);

    xqc_test_write_capture_t request_capture = {0};
    xqc_test_write_capture_t data_capture = {
        .scripted_results = {
            -XQC_EAGAIN,
        },
        .scripted_results_count = 1,
    };
    xqc_test_write_capture_t second_data_capture = {
        .scripted_results = {
            -XQC_EAGAIN,
        },
        .scripted_results_count = 1,
    };
    xqc_test_write_capture_t third_data_capture = {
        .scripted_results = {
            -XQC_ESYS,
        },
        .scripted_results_count = 1,
    };
    xqc_moq_stream_t request_stream;
    xqc_moq_stream_t data_stream;
    xqc_moq_stream_t second_data_stream;
    xqc_moq_stream_t third_data_stream;
    xqc_test_init_stream(
        &request_stream, &session, &request_capture);
    xqc_test_init_stream(&data_stream, &session, &data_capture);
    xqc_test_init_stream(
        &second_data_stream, &session, &second_data_capture);
    xqc_test_init_stream(
        &third_data_stream, &session, &third_data_capture);
    xqc_moq_d18_update_queue_init(
        &request_stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(
        &request_stream.d18_peer_update_queue);
    request_stream.local_request = 1;
    request_stream.response_received = 1;
    request_stream.request_type = XQC_MOQ_MSG_PUBLISH;
    request_stream.request_id = 1;
    request_stream.track = track;
    request_stream.d18_context.direction =
        XQC_MOQ_D18_DIRECTION_BIDI;
    request_stream.d18_context.stream_class =
        XQC_MOQ_D18_STREAM_REQUEST;
    request_stream.d18_context.position =
        XQC_MOQ_D18_POSITION_NEXT;
    XQC_TEST_ASSERT(xqc_moq_session_register_local_request_id(
        &session, request_stream.request_id)
        == XQC_MOQ_D18_REQUEST_ID_OK);
    xqc_list_add_tail(
        &request_stream.request_list_member,
        &session.local_request_stream_list);

    data_stream.write_buf = xqc_malloc(1);
    XQC_TEST_ASSERT(data_stream.write_buf != NULL);
    data_stream.write_buf[0] = 'x';
    data_stream.write_buf_len = 1;
    data_stream.write_buf_cap = 1;
    xqc_moq_track_on_write_stream(
        track, &data_stream, 1, 0, 0);
    second_data_stream.write_buf = xqc_malloc(1);
    XQC_TEST_ASSERT(second_data_stream.write_buf != NULL);
    second_data_stream.write_buf[0] = 'y';
    second_data_stream.write_buf_len = 1;
    second_data_stream.write_buf_cap = 1;
    xqc_moq_track_on_write_stream(
        track, &second_data_stream, 2, 0, 0);
    third_data_stream.write_buf = xqc_malloc(1);
    XQC_TEST_ASSERT(third_data_stream.write_buf != NULL);
    third_data_stream.write_buf[0] = 'z';
    third_data_stream.write_buf_len = 1;
    third_data_stream.write_buf_cap = 1;
    xqc_moq_track_on_write_stream(
        track, &third_data_stream, 3, 0, 0);

    xqc_moq_message_parameter_t forward = {
        .type = XQC_MOQ_D18_PARAM_FORWARD,
        .is_integer = 1,
        .int_value = 1,
    };
    xqc_moq_request_update_msg_t update = {
        .params_num = 1,
        .params = &forward,
    };
    XQC_TEST_ASSERT(xqc_moq_write_request_update(
        &session, request_stream.request_id, &update) == XQC_OK);
    xqc_memzero(&request_capture, sizeof(request_capture));

    xqc_moq_request_error_msg_t error = {
        .error_code = XQC_MOQ_REQUEST_ERROR_UNAUTHORIZED,
    };
    xqc_moq_on_request_error(
        &session, &request_stream, &error.msg_base);
    XQC_TEST_ASSERT(data_capture.call_count == 1);
    XQC_TEST_ASSERT(second_data_capture.call_count == 0);
    XQC_TEST_ASSERT(third_data_capture.call_count == 0);
    XQC_TEST_ASSERT(data_stream.write_stream_fin == 1);
    XQC_TEST_ASSERT(data_stream.write_fin_submitted == 0);
    XQC_TEST_ASSERT(request_stream.d18_publish_done_pending == 1);
    XQC_TEST_ASSERT(request_capture.length == 0);

    XQC_TEST_ASSERT(xqc_moq_stream_write(&data_stream) == XQC_OK);
    XQC_TEST_ASSERT(data_stream.write_fin_submitted == 1);
    XQC_TEST_ASSERT(second_data_capture.call_count == 1);
    XQC_TEST_ASSERT(second_data_stream.write_stream_fin == 1);
    XQC_TEST_ASSERT(second_data_stream.write_fin_submitted == 0);
    XQC_TEST_ASSERT(request_stream.d18_publish_done_pending == 1);
    XQC_TEST_ASSERT(request_capture.length == 0);

    XQC_TEST_ASSERT(xqc_moq_stream_write(
        &second_data_stream) == -XQC_ESYS);
    XQC_TEST_ASSERT(second_data_stream.write_fin_submitted == 1);
    XQC_TEST_ASSERT(third_data_capture.call_count == 1);
    XQC_TEST_ASSERT(third_data_stream.write_stream_fin == 1);
    XQC_TEST_ASSERT(third_data_stream.write_fin_submitted == 0);
    XQC_TEST_ASSERT(quic_conn.conn_err
                    == XQC_MOQ_D18_INTERNAL_ERROR);
    XQC_TEST_ASSERT(request_stream.d18_publish_done_pending == 1);
    XQC_TEST_ASSERT(request_capture.length == 0);

    XQC_TEST_ASSERT(xqc_moq_stream_write(
        &third_data_stream) == XQC_OK);
    XQC_TEST_ASSERT(third_data_stream.write_fin_submitted == 1);
    XQC_TEST_ASSERT(request_capture.length == 0);
    XQC_TEST_ASSERT(request_capture.write_count == 0);
    XQC_TEST_ASSERT(request_stream.request_closed_notified == 0);
    XQC_TEST_ASSERT(request_stream.d18_publish_done_pending == 1);

    xqc_list_del_init(&data_stream.list_member);
    data_stream.track = NULL;
    xqc_list_del_init(&second_data_stream.list_member);
    second_data_stream.track = NULL;
    xqc_list_del_init(&third_data_stream.list_member);
    third_data_stream.track = NULL;
    xqc_moq_d18_update_queue_destroy(
        &request_stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(
        &request_stream.d18_peer_update_queue);
    xqc_test_clean_stream(&data_stream);
    xqc_test_clean_stream(&second_data_stream);
    xqc_test_clean_stream(&third_data_stream);
    xqc_test_clean_stream(&request_stream);
    xqc_list_del_init(&track->list_member);
    xqc_moq_track_destroy(track);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static int
xqc_test_update_failed_publish_done_data_fin_hard_error_closes_session(void)
{
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_connection_t quic_conn;
    xqc_memzero(&quic_conn, sizeof(quic_conn));
    quic_conn.log = &xqc_test_log;
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.quic_conn = &quic_conn;
    xqc_moq_track_t *track =
        xqc_moq_track_create_with_ns_tuple(
            &session, &live, 1, "audio",
            XQC_MOQ_TRACK_AUDIO, NULL,
            XQC_MOQ_CONTAINER_NONE,
            XQC_MOQ_TRACK_FOR_PUB);
    XQC_TEST_ASSERT(track != NULL);
    xqc_moq_track_set_alias(track, 4);
    xqc_moq_track_set_subscribe_id(track, 1);
    XQC_TEST_ASSERT(xqc_moq_subscribe_create_with_ns_tuple(
        &session, 1, 4, &live, 1, "audio",
        XQC_MOQ_FILTER_LAST_GROUP, 0, 0, 0, 0, NULL, 0)
        != NULL);

    xqc_test_write_capture_t request_capture = {0};
    xqc_test_write_capture_t data_capture = {
        .scripted_results = {
            -XQC_EAGAIN,
            -XQC_ESYS,
            1,
        },
        .scripted_results_count = 3,
    };
    xqc_moq_stream_t request_stream;
    xqc_moq_stream_t data_stream;
    xqc_test_init_stream(
        &request_stream, &session, &request_capture);
    xqc_test_init_stream(&data_stream, &session, &data_capture);
    xqc_moq_d18_update_queue_init(
        &request_stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(
        &request_stream.d18_peer_update_queue);
    request_stream.local_request = 1;
    request_stream.response_received = 1;
    request_stream.request_type = XQC_MOQ_MSG_PUBLISH;
    request_stream.request_id = 1;
    request_stream.track = track;
    request_stream.d18_context.direction =
        XQC_MOQ_D18_DIRECTION_BIDI;
    request_stream.d18_context.stream_class =
        XQC_MOQ_D18_STREAM_REQUEST;
    request_stream.d18_context.position =
        XQC_MOQ_D18_POSITION_NEXT;
    XQC_TEST_ASSERT(xqc_moq_session_register_local_request_id(
        &session, request_stream.request_id)
        == XQC_MOQ_D18_REQUEST_ID_OK);
    xqc_list_add_tail(
        &request_stream.request_list_member,
        &session.local_request_stream_list);

    data_stream.write_buf = xqc_malloc(1);
    XQC_TEST_ASSERT(data_stream.write_buf != NULL);
    data_stream.write_buf[0] = 'x';
    data_stream.write_buf_len = 1;
    data_stream.write_buf_cap = 1;
    xqc_moq_track_on_write_stream(
        track, &data_stream, 1, 0, 0);

    xqc_moq_message_parameter_t forward = {
        .type = XQC_MOQ_D18_PARAM_FORWARD,
        .is_integer = 1,
        .int_value = 1,
    };
    xqc_moq_request_update_msg_t update = {
        .params_num = 1,
        .params = &forward,
    };
    XQC_TEST_ASSERT(xqc_moq_write_request_update(
        &session, request_stream.request_id, &update) == XQC_OK);
    xqc_memzero(&request_capture, sizeof(request_capture));

    xqc_moq_request_error_msg_t error = {
        .error_code = XQC_MOQ_REQUEST_ERROR_UNAUTHORIZED,
    };
    xqc_moq_on_request_error(
        &session, &request_stream, &error.msg_base);
    XQC_TEST_ASSERT(data_capture.call_count == 1);
    XQC_TEST_ASSERT(data_stream.write_stream_fin == 1);
    XQC_TEST_ASSERT(data_stream.write_fin_submitted == 0);
    XQC_TEST_ASSERT(request_stream.d18_publish_done_pending == 1);
    XQC_TEST_ASSERT(request_stream.request_closed_notified == 0);
    XQC_TEST_ASSERT(request_capture.length == 0);

    XQC_TEST_ASSERT(xqc_moq_stream_write(
        &data_stream) == -XQC_ESYS);
    XQC_TEST_ASSERT(data_capture.call_count == 2);
    XQC_TEST_ASSERT(data_stream.write_fin_submitted == 0);
    XQC_TEST_ASSERT(quic_conn.conn_err
                    == XQC_MOQ_D18_INTERNAL_ERROR);
    XQC_TEST_ASSERT(request_stream.d18_publish_done_pending == 1);
    XQC_TEST_ASSERT(request_stream.request_closed_notified == 0);
    XQC_TEST_ASSERT(request_capture.length == 0);
    XQC_TEST_ASSERT(request_capture.cancel_count == 0);
    XQC_TEST_ASSERT(request_capture.stop_sending_count == 0);

    XQC_TEST_ASSERT(xqc_moq_stream_write(&data_stream) == XQC_OK);
    XQC_TEST_ASSERT(data_capture.call_count == 3);
    XQC_TEST_ASSERT(data_stream.write_fin_submitted == 1);
    XQC_TEST_ASSERT(request_stream.d18_publish_done_pending == 1);
    XQC_TEST_ASSERT(request_stream.request_closed_notified == 0);
    XQC_TEST_ASSERT(request_capture.length == 0);
    XQC_TEST_ASSERT(request_capture.write_count == 0);
    XQC_TEST_ASSERT(request_capture.cancel_count == 0);
    XQC_TEST_ASSERT(request_capture.stop_sending_count == 0);

    xqc_list_del_init(&data_stream.list_member);
    data_stream.track = NULL;
    xqc_moq_d18_update_queue_destroy(
        &request_stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(
        &request_stream.d18_peer_update_queue);
    xqc_test_clean_stream(&data_stream);
    xqc_test_clean_stream(&request_stream);
    xqc_list_del_init(&track->list_member);
    xqc_moq_track_destroy(track);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static int
xqc_test_publish_done_retries_request_fin_without_duplicate_bytes(void)
{
    static const uint8_t expected[] = {
        XQC_MOQ_D18_MSG_PUBLISH_DONE,
        0x00, 0x07,
        XQC_MOQ_PUBLISH_DONE_TRACK_ENDED,
        0x01,
        0x04, 'o', 'r', 'i', 'g',
    };
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    for (size_t i = 0; i < 2; i++) {
        xqc_moq_session_t session;
        xqc_test_init_session(&session);
        xqc_moq_track_t *track =
            xqc_moq_track_create_with_ns_tuple(
                &session, &live, 1, "audio",
                XQC_MOQ_TRACK_AUDIO, NULL,
                XQC_MOQ_CONTAINER_NONE,
                XQC_MOQ_TRACK_FOR_PUB);
        XQC_TEST_ASSERT(track != NULL);
        xqc_moq_track_set_alias(track, 4);
        xqc_moq_track_set_subscribe_id(track, 9);
        XQC_TEST_ASSERT(xqc_moq_subscribe_create_with_ns_tuple(
            &session, 9, 4, &live, 1, "audio",
            XQC_MOQ_FILTER_LAST_GROUP, 0, 0, 0, 0, NULL, 0)
            != NULL);

        xqc_test_write_capture_t request_capture = {
            .scripted_results = {
                i == 0 ? -XQC_EAGAIN : 2,
            },
            .scripted_results_count = 1,
        };
        xqc_test_write_capture_t data_capture = {0};
        xqc_moq_stream_t request_stream;
        xqc_moq_stream_t data_stream;
        xqc_test_init_stream(
            &request_stream, &session, &request_capture);
        xqc_test_init_stream(&data_stream, &session, &data_capture);
        xqc_moq_d18_update_queue_init(
            &request_stream.d18_local_update_queue);
        xqc_moq_d18_update_queue_init(
            &request_stream.d18_peer_update_queue);
        request_stream.local_request = 1;
        request_stream.response_received = 1;
        request_stream.request_type = XQC_MOQ_MSG_PUBLISH;
        request_stream.request_id = 9;
        request_stream.track = track;
        request_stream.d18_context.direction =
            XQC_MOQ_D18_DIRECTION_BIDI;
        request_stream.d18_context.stream_class =
            XQC_MOQ_D18_STREAM_REQUEST;
        request_stream.d18_context.position =
            XQC_MOQ_D18_POSITION_NEXT;
        xqc_list_add_tail(
            &request_stream.request_list_member,
            &session.local_request_stream_list);
        data_stream.write_buf = xqc_malloc(1);
        XQC_TEST_ASSERT(data_stream.write_buf != NULL);
        data_stream.write_buf[0] = 'x';
        data_stream.write_buf_len = 1;
        data_stream.write_buf_cap = 1;
        xqc_moq_track_on_write_stream(
            track, &data_stream, 1, 0, 0);

        xqc_moq_publish_done_msg_t done = {
            .subscribe_id = 9,
            .status_code = XQC_MOQ_PUBLISH_DONE_TRACK_ENDED,
            .reason_phrase = "orig",
            .reason_phrase_len = 4,
        };
        XQC_TEST_ASSERT(xqc_moq_write_publish_done(
            &session, &done) == -XQC_EAGAIN);
        XQC_TEST_ASSERT(request_stream.request_closed_notified == 0);
        XQC_TEST_ASSERT(request_capture.length == (i == 0 ? 0 : 2));
        XQC_TEST_ASSERT(data_capture.length == 1);
        XQC_TEST_ASSERT(data_capture.fin == 1);

        done.status_code = XQC_MOQ_PUBLISH_DONE_MALFORMED_TRACK;
        done.reason_phrase = "new";
        done.reason_phrase_len = 3;
        xqc_int_t request_retry_ret = xqc_moq_write_publish_done(
            &session, &done);
        XQC_TEST_ASSERT(request_retry_ret == XQC_OK);
        XQC_TEST_ASSERT(request_capture.length == sizeof(expected));
        XQC_TEST_ASSERT(memcmp(
            request_capture.bytes, expected, sizeof(expected)) == 0);
        XQC_TEST_ASSERT(request_capture.call_count == 2);
        XQC_TEST_ASSERT(request_capture.call_fin_history[0] == 1);
        XQC_TEST_ASSERT(request_capture.call_fin_history[1] == 1);

        xqc_list_del_init(&data_stream.list_member);
        data_stream.track = NULL;
        xqc_moq_d18_update_queue_destroy(
            &request_stream.d18_local_update_queue);
        xqc_moq_d18_update_queue_destroy(
            &request_stream.d18_peer_update_queue);
        xqc_test_clean_stream(&data_stream);
        xqc_test_clean_stream(&request_stream);
        xqc_list_del_init(&track->list_member);
        xqc_moq_track_destroy(track);
        xqc_moq_d18_request_registry_destroy(
            &session.d18_request_registry);
        xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    }
    return 0;
}

static int
xqc_test_publish_done_request_writable_hard_error_closes_session(void)
{
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    for (size_t i = 0; i < 2; i++) {
        xqc_connection_t quic_conn;
        xqc_memzero(&quic_conn, sizeof(quic_conn));
        quic_conn.log = &xqc_test_log;
        xqc_moq_session_t session;
        xqc_test_init_session(&session);
        session.quic_conn = &quic_conn;
        xqc_moq_track_t *track =
            xqc_moq_track_create_with_ns_tuple(
                &session, &live, 1, "audio",
                XQC_MOQ_TRACK_AUDIO, NULL,
                XQC_MOQ_CONTAINER_NONE,
                XQC_MOQ_TRACK_FOR_PUB);
        XQC_TEST_ASSERT(track != NULL);
        xqc_moq_track_set_alias(track, 4);
        xqc_moq_track_set_subscribe_id(track, 9);
        XQC_TEST_ASSERT(xqc_moq_subscribe_create_with_ns_tuple(
            &session, 9, 4, &live, 1, "audio",
            XQC_MOQ_FILTER_LAST_GROUP, 0, 0, 0, 0, NULL, 0)
            != NULL);

        xqc_test_write_capture_t request_capture = {
            .scripted_results = {
                i == 0 ? 2 : -XQC_EAGAIN,
                -XQC_ESYS,
            },
            .scripted_results_count = 2,
        };
        xqc_moq_stream_t request_stream;
        xqc_test_init_stream(
            &request_stream, &session, &request_capture);
        xqc_moq_d18_update_queue_init(
            &request_stream.d18_local_update_queue);
        xqc_moq_d18_update_queue_init(
            &request_stream.d18_peer_update_queue);
        request_stream.local_request = 1;
        request_stream.response_received = 1;
        request_stream.request_type = XQC_MOQ_MSG_PUBLISH;
        request_stream.request_id = 9;
        request_stream.track = track;
        request_stream.d18_context.direction =
            XQC_MOQ_D18_DIRECTION_BIDI;
        request_stream.d18_context.stream_class =
            XQC_MOQ_D18_STREAM_REQUEST;
        request_stream.d18_context.position =
            XQC_MOQ_D18_POSITION_NEXT;
        xqc_list_add_tail(
            &request_stream.request_list_member,
            &session.local_request_stream_list);

        xqc_moq_publish_done_msg_t done = {
            .subscribe_id = 9,
            .status_code = XQC_MOQ_PUBLISH_DONE_TRACK_ENDED,
        };
        XQC_TEST_ASSERT(xqc_moq_write_publish_done(
            &session, &done) == -XQC_EAGAIN);
        size_t bytes_before_error = request_capture.length;
        XQC_TEST_ASSERT(bytes_before_error == (i == 0 ? 2 : 0));
        XQC_TEST_ASSERT(request_capture.call_count == 1);
        XQC_TEST_ASSERT(request_stream.d18_publish_done_pending == 1);
        XQC_TEST_ASSERT(request_stream.d18_publish_done_encoded == 1);
        XQC_TEST_ASSERT(request_stream.write_stream_fin == 1);
        XQC_TEST_ASSERT(request_stream.write_fin_submitted == 0);
        XQC_TEST_ASSERT(request_stream.request_closed_notified == 0);

        XQC_TEST_ASSERT(xqc_moq_stream_write(
            &request_stream) == -XQC_ESYS);
        XQC_TEST_ASSERT(request_capture.call_count == 2);
        XQC_TEST_ASSERT(request_capture.length == bytes_before_error);
        XQC_TEST_ASSERT(quic_conn.conn_err
                        == XQC_MOQ_D18_INTERNAL_ERROR);
        XQC_TEST_ASSERT(request_stream.d18_publish_done_pending == 1);
        XQC_TEST_ASSERT(request_stream.d18_publish_done_encoded == 1);
        XQC_TEST_ASSERT(request_stream.write_fin_submitted == 0);
        XQC_TEST_ASSERT(request_stream.request_closed_notified == 0);
        XQC_TEST_ASSERT(request_capture.cancel_count == 0);
        XQC_TEST_ASSERT(request_capture.stop_sending_count == 0);

        XQC_TEST_ASSERT(xqc_moq_stream_write(
            &request_stream) == XQC_OK);
        XQC_TEST_ASSERT(request_capture.call_count == 2);
        XQC_TEST_ASSERT(request_capture.length == bytes_before_error);
        XQC_TEST_ASSERT(request_stream.d18_publish_done_pending == 1);
        XQC_TEST_ASSERT(request_stream.d18_publish_done_encoded == 1);
        XQC_TEST_ASSERT(request_stream.write_fin_submitted == 0);
        XQC_TEST_ASSERT(request_stream.request_closed_notified == 0);
        XQC_TEST_ASSERT(request_capture.cancel_count == 0);
        XQC_TEST_ASSERT(request_capture.stop_sending_count == 0);

        xqc_free(request_stream.d18_publish_done_reason);
        request_stream.d18_publish_done_reason = NULL;
        request_stream.d18_publish_done_reason_len = 0;
        request_stream.d18_publish_done_pending = 0;
        xqc_moq_d18_update_queue_destroy(
            &request_stream.d18_local_update_queue);
        xqc_moq_d18_update_queue_destroy(
            &request_stream.d18_peer_update_queue);
        xqc_test_clean_stream(&request_stream);
        xqc_list_del_init(&track->list_member);
        xqc_moq_track_destroy(track);
        xqc_moq_d18_request_registry_destroy(
            &session.d18_request_registry);
        xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    }
    return 0;
}

static int
xqc_test_publish_done_writer_uses_terminal_request_stream(void)
{
    static const uint8_t expected_zero[] = {
        XQC_MOQ_D18_MSG_PUBLISH_DONE,
        0x00, 0x03,
        XQC_MOQ_PUBLISH_DONE_TRACK_ENDED,
        0x00,
        0x00,
    };
    static const uint8_t expected_three[] = {
        XQC_MOQ_D18_MSG_PUBLISH_DONE,
        0x00, 0x03,
        XQC_MOQ_PUBLISH_DONE_TRACK_ENDED,
        0x03,
        0x00,
    };
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };

    for (size_t i = 0; i < 2; i++) {
        xqc_moq_session_t session;
        xqc_test_init_session(&session);
        xqc_moq_track_t *track =
            xqc_moq_track_create_with_ns_tuple(
                &session, &live, 1, "audio",
                XQC_MOQ_TRACK_AUDIO, NULL,
                XQC_MOQ_CONTAINER_NONE,
                XQC_MOQ_TRACK_FOR_PUB);
        XQC_TEST_ASSERT(track != NULL);
        xqc_moq_track_set_alias(track, 4);
        xqc_moq_track_set_subscribe_id(track, 9);
        track->streams_count = i == 0 ? 0 : 3;
        XQC_TEST_ASSERT(xqc_moq_subscribe_create_with_ns_tuple(
            &session, 9, 4, &live, 1, "audio",
            XQC_MOQ_FILTER_LAST_GROUP, 0, 0, 0, 0, NULL, 0)
            != NULL);

        xqc_test_write_capture_t request_capture = {0};
        xqc_test_write_capture_t ctl_capture = {0};
        xqc_test_write_capture_t late_capture = {0};
        xqc_moq_stream_t request_stream;
        xqc_moq_stream_t ctl_stream;
        xqc_moq_stream_t late_stream;
        xqc_test_init_stream(
            &request_stream, &session, &request_capture);
        xqc_test_init_stream(&ctl_stream, &session, &ctl_capture);
        xqc_test_init_stream(&late_stream, &session, &late_capture);
        xqc_moq_d18_update_queue_init(
            &request_stream.d18_local_update_queue);
        xqc_moq_d18_update_queue_init(
            &request_stream.d18_peer_update_queue);
        session.ctl_stream = &ctl_stream;
        request_stream.request_id = 9;
        request_stream.track = track;
        request_stream.d18_context.direction =
            XQC_MOQ_D18_DIRECTION_BIDI;
        request_stream.d18_context.stream_class =
            XQC_MOQ_D18_STREAM_REQUEST;
        request_stream.d18_context.position =
            XQC_MOQ_D18_POSITION_NEXT;
        if (i == 0) {
            request_stream.local_request = 1;
            request_stream.response_received = 1;
            request_stream.request_type = XQC_MOQ_MSG_PUBLISH;
            xqc_list_add_tail(
                &request_stream.request_list_member,
                &session.local_request_stream_list);
        } else {
            request_stream.peer_request = 1;
            request_stream.response_sent = 1;
            request_stream.request_type = XQC_MOQ_MSG_SUBSCRIBE;
            xqc_list_add_tail(
                &request_stream.request_list_member,
                &session.peer_request_stream_list);
            xqc_test_publish_done_reentrant_track = track;
            xqc_test_publish_done_reentrant_stream = &late_stream;
            xqc_test_publish_done_reentrant_capture =
                &request_capture;
            xqc_test_publish_done_reentrant_refused = 0;
        }

        xqc_moq_publish_done_msg_t done = {
            .subscribe_id = 9,
            .status_code = XQC_MOQ_PUBLISH_DONE_TRACK_ENDED,
            .stream_count = 0,
        };
        XQC_TEST_ASSERT(xqc_moq_write_publish_done(
            &session, &done) == XQC_OK);
        const uint8_t *expected =
            i == 0 ? expected_zero : expected_three;
        size_t expected_len =
            i == 0 ? sizeof(expected_zero) : sizeof(expected_three);
        XQC_TEST_ASSERT(request_capture.write_count == 1);
        XQC_TEST_ASSERT(request_capture.length == expected_len);
        XQC_TEST_ASSERT(memcmp(
            request_capture.bytes, expected, expected_len) == 0);
        XQC_TEST_ASSERT(request_capture.fin_history[0] == 1);
        XQC_TEST_ASSERT(ctl_capture.write_count == 0);
        XQC_TEST_ASSERT(ctl_capture.length == 0);
        XQC_TEST_ASSERT(done.subscribe_id == 9);
        XQC_TEST_ASSERT(done.stream_count == 0);
        XQC_TEST_ASSERT(request_stream.request_closed_notified == 1);
        XQC_TEST_ASSERT(track->subscribe_id == XQC_MOQ_INVALID_ID);
        XQC_TEST_ASSERT(track->track_alias == XQC_MOQ_INVALID_ID);
        XQC_TEST_ASSERT(xqc_moq_find_subscribe(
            &session, 9, 0) == NULL);
        if (i == 1) {
            XQC_TEST_ASSERT(
                xqc_test_publish_done_reentrant_refused == 1);
            xqc_moq_track_on_write_stream(
                track, &late_stream, 9, 10, 0);
            XQC_TEST_ASSERT(late_stream.track == NULL);
            XQC_TEST_ASSERT(xqc_list_empty(
                &late_stream.list_member));
        }
        size_t request_bytes = request_capture.length;
        XQC_TEST_ASSERT(xqc_moq_write_publish_done(
            &session, &done) < 0);
        XQC_TEST_ASSERT(request_capture.length == request_bytes);
        XQC_TEST_ASSERT(ctl_capture.length == 0);

        xqc_test_publish_done_reentrant_track = NULL;
        xqc_test_publish_done_reentrant_stream = NULL;
        xqc_test_publish_done_reentrant_capture = NULL;
        session.ctl_stream = NULL;
        xqc_moq_d18_update_queue_destroy(
            &request_stream.d18_local_update_queue);
        xqc_moq_d18_update_queue_destroy(
            &request_stream.d18_peer_update_queue);
        xqc_test_clean_stream(&late_stream);
        xqc_test_clean_stream(&ctl_stream);
        xqc_test_clean_stream(&request_stream);
        xqc_list_del_init(&track->list_member);
        xqc_moq_track_destroy(track);
        xqc_moq_d18_request_registry_destroy(
            &session.d18_request_registry);
        xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    }
    return 0;
}

static int
xqc_test_publish_done_writer_rejects_invalid_request_streams(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    xqc_test_write_capture_t request_capture = {0};
    xqc_test_write_capture_t ctl_capture = {0};
    xqc_moq_stream_t request_stream;
    xqc_moq_stream_t ctl_stream;
    xqc_test_init_stream(
        &request_stream, &session, &request_capture);
    xqc_test_init_stream(&ctl_stream, &session, &ctl_capture);
    xqc_moq_d18_update_queue_init(
        &request_stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(
        &request_stream.d18_peer_update_queue);
    session.ctl_stream = &ctl_stream;
    xqc_moq_publish_done_msg_t done = {
        .subscribe_id = 9,
        .status_code = XQC_MOQ_PUBLISH_DONE_MALFORMED_TRACK,
        .stream_count = 0,
    };

    XQC_TEST_ASSERT(xqc_moq_write_publish_done(
        &session, &done) < 0);
    request_stream.local_request = 1;
    request_stream.request_type = XQC_MOQ_MSG_PUBLISH;
    request_stream.request_id = 9;
    request_stream.d18_context.direction =
        XQC_MOQ_D18_DIRECTION_BIDI;
    request_stream.d18_context.stream_class =
        XQC_MOQ_D18_STREAM_REQUEST;
    request_stream.d18_context.position =
        XQC_MOQ_D18_POSITION_NEXT;
    xqc_list_add_tail(&request_stream.request_list_member,
                      &session.local_request_stream_list);
    XQC_TEST_ASSERT(xqc_moq_write_publish_done(
        &session, &done) < 0);
    request_stream.response_received = 1;
    request_stream.request_closed_notified = 1;
    XQC_TEST_ASSERT(xqc_moq_write_publish_done(
        &session, &done) < 0);
    request_stream.request_closed_notified = 0;
    request_stream.d18_context.stream_class =
        XQC_MOQ_D18_STREAM_CONTROL;
    XQC_TEST_ASSERT(xqc_moq_write_publish_done(
        &session, &done) < 0);
    XQC_TEST_ASSERT(request_capture.length == 0);
    XQC_TEST_ASSERT(ctl_capture.length == 0);
    XQC_TEST_ASSERT(done.subscribe_id == 9);
    XQC_TEST_ASSERT(done.stream_count == 0);

    session.ctl_stream = NULL;
    xqc_moq_d18_update_queue_destroy(
        &request_stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(
        &request_stream.d18_peer_update_queue);
    xqc_test_clean_stream(&ctl_stream);
    xqc_test_clean_stream(&request_stream);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static int
xqc_test_publish_done_invalid_reason_case(
    const char *case_name, const char *reason, size_t reason_len)
{
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    xqc_moq_track_t *track =
        xqc_moq_track_create_with_ns_tuple(
            &session, &live, 1, "audio",
            XQC_MOQ_TRACK_AUDIO, NULL,
            XQC_MOQ_CONTAINER_NONE,
            XQC_MOQ_TRACK_FOR_PUB);
    XQC_TEST_ASSERT(track != NULL);
    xqc_moq_track_set_alias(track, 4);
    xqc_moq_track_set_subscribe_id(track, 9);
    XQC_TEST_ASSERT(xqc_moq_subscribe_create_with_ns_tuple(
        &session, 9, 4, &live, 1, "audio",
        XQC_MOQ_FILTER_LAST_GROUP, 0, 0, 0, 0, NULL, 0)
        != NULL);

    xqc_test_write_capture_t request_capture = {0};
    xqc_test_write_capture_t data_capture = {0};
    xqc_moq_stream_t request_stream;
    xqc_moq_stream_t data_stream;
    xqc_test_init_stream(
        &request_stream, &session, &request_capture);
    xqc_test_init_stream(&data_stream, &session, &data_capture);
    xqc_moq_d18_update_queue_init(
        &request_stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(
        &request_stream.d18_peer_update_queue);
    request_stream.local_request = 1;
    request_stream.response_received = 1;
    request_stream.request_type = XQC_MOQ_MSG_PUBLISH;
    request_stream.request_id = 9;
    request_stream.track = track;
    request_stream.kind = XQC_MOQ_STREAM_D18_REQUEST;
    request_stream.d18_context.direction =
        XQC_MOQ_D18_DIRECTION_BIDI;
    request_stream.d18_context.stream_class =
        XQC_MOQ_D18_STREAM_REQUEST;
    request_stream.d18_context.position =
        XQC_MOQ_D18_POSITION_NEXT;
    xqc_list_add_tail(
        &request_stream.request_list_member,
        &session.local_request_stream_list);

    data_stream.write_buf = xqc_malloc(1);
    XQC_TEST_ASSERT(data_stream.write_buf != NULL);
    data_stream.write_buf[0] = 'x';
    data_stream.write_buf_len = 1;
    data_stream.write_buf_cap = 1;
    xqc_moq_track_on_write_stream(
        track, &data_stream, 1, 0, 0);

    xqc_moq_publish_done_msg_t invalid = {
        .subscribe_id = 9,
        .status_code = XQC_MOQ_PUBLISH_DONE_TRACK_ENDED,
        .reason_phrase = (char *)reason,
        .reason_phrase_len = reason_len,
    };
    xqc_int_t invalid_ret = xqc_moq_write_publish_done(
        &session, &invalid);
    int invalid_left_state_untouched =
        invalid_ret == -XQC_EPARAM
        && request_stream.d18_publish_done_pending == 0
        && request_stream.d18_publish_done_encoded == 0
        && request_stream.d18_publish_done_reason == NULL
        && request_stream.d18_publish_done_reason_len == 0
        && request_stream.write_stream_fin == 0
        && request_stream.write_fin_submitted == 0
        && request_stream.request_closed_notified == 0
        && track->subscribe_id == 9
        && track->track_alias == 4
        && data_stream.write_stream_fin == 0
        && data_stream.write_fin_submitted == 0
        && data_capture.call_count == 0
        && request_capture.length == 0
        && request_capture.write_count == 0;

    char corrected_reason[] = "ok";
    xqc_moq_publish_done_msg_t corrected = {
        .subscribe_id = 9,
        .status_code = XQC_MOQ_PUBLISH_DONE_TRACK_ENDED,
        .reason_phrase = corrected_reason,
        .reason_phrase_len = sizeof(corrected_reason) - 1,
    };
    xqc_int_t corrected_ret = xqc_moq_write_publish_done(
        &session, &corrected);
    int corrected_succeeded = corrected_ret == XQC_OK
        && data_stream.write_fin_submitted == 1
        && request_capture.length > 0
        && request_capture.write_count == 1
        && request_capture.fin == 1
        && request_stream.d18_publish_done_pending == 0
        && request_stream.request_closed_notified == 1;

    xqc_list_del_init(&data_stream.list_member);
    data_stream.track = NULL;
    xqc_free(request_stream.d18_publish_done_reason);
    request_stream.d18_publish_done_reason = NULL;
    request_stream.d18_publish_done_reason_len = 0;
    request_stream.d18_publish_done_pending = 0;
    xqc_moq_d18_update_queue_destroy(
        &request_stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(
        &request_stream.d18_peer_update_queue);
    xqc_test_clean_stream(&data_stream);
    xqc_test_clean_stream(&request_stream);
    xqc_list_del_init(&track->list_member);
    xqc_moq_track_destroy(track);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);

    if (!invalid_left_state_untouched) {
        fprintf(stderr,
                "assert failed: invalid %s PUBLISH_DONE mutated terminal state\n",
                case_name);
    }
    if (!corrected_succeeded) {
        fprintf(stderr,
                "assert failed: corrected PUBLISH_DONE after invalid %s did not succeed\n",
                case_name);
    }
    return invalid_left_state_untouched && corrected_succeeded
        ? 0 : -1;
}

static int
xqc_test_publish_done_invalid_reason_does_not_poison_snapshot(void)
{
    char oversized[XQC_MOQ_MAX_REASON_PHRASE_LEN + 1];
    memset(oversized, 'a', sizeof(oversized));
    static const char invalid_utf8[] = {
        (char)0xc0, (char)0xaf,
    };
    int failed = 0;
    if (xqc_test_publish_done_invalid_reason_case(
            "length", oversized, sizeof(oversized)) != 0)
    {
        failed = 1;
    }
    if (xqc_test_publish_done_invalid_reason_case(
            "UTF-8", invalid_utf8, sizeof(invalid_utf8)) != 0)
    {
        failed = 1;
    }
    return failed ? -1 : 0;
}

static int
xqc_test_publish_done_write_failure_keeps_terminal_state_and_retries(void)
{
    static const uint8_t expected[] = {
        XQC_MOQ_D18_MSG_PUBLISH_DONE,
        0x00, 0x03,
        XQC_MOQ_PUBLISH_DONE_UPDATE_FAILED,
        0x02,
        0x00,
    };
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    xqc_moq_track_t *track =
        xqc_moq_track_create_with_ns_tuple(
            &session, &live, 1, "audio",
            XQC_MOQ_TRACK_AUDIO, NULL,
            XQC_MOQ_CONTAINER_NONE, XQC_MOQ_TRACK_FOR_PUB);
    XQC_TEST_ASSERT(track != NULL);
    xqc_moq_track_set_alias(track, 4);
    xqc_moq_track_set_subscribe_id(track, 9);
    XQC_TEST_ASSERT(xqc_moq_subscribe_create_with_ns_tuple(
        &session, 9, 4, &live, 1, "audio",
        XQC_MOQ_FILTER_LAST_GROUP, 0, 0, 0, 0, NULL, 0)
        != NULL);

    xqc_test_write_capture_t request_capture = {
        .fail_write = 1,
    };
    xqc_test_write_capture_t first_data_capture = {0};
    xqc_test_write_capture_t second_data_capture = {0};
    xqc_test_write_capture_t late_capture = {0};
    xqc_moq_stream_t request_stream;
    xqc_moq_stream_t first_data_stream;
    xqc_moq_stream_t second_data_stream;
    xqc_moq_stream_t late_stream;
    xqc_test_init_stream(
        &request_stream, &session, &request_capture);
    xqc_test_init_stream(
        &first_data_stream, &session, &first_data_capture);
    xqc_test_init_stream(
        &second_data_stream, &session, &second_data_capture);
    xqc_test_init_stream(&late_stream, &session, &late_capture);
    xqc_moq_d18_update_queue_init(
        &request_stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(
        &request_stream.d18_peer_update_queue);
    request_stream.local_request = 1;
    request_stream.response_received = 1;
    request_stream.request_type = XQC_MOQ_MSG_PUBLISH;
    request_stream.request_id = 9;
    request_stream.track = track;
    request_stream.d18_context.direction =
        XQC_MOQ_D18_DIRECTION_BIDI;
    request_stream.d18_context.stream_class =
        XQC_MOQ_D18_STREAM_REQUEST;
    request_stream.d18_context.position =
        XQC_MOQ_D18_POSITION_NEXT;
    xqc_list_add_tail(&request_stream.request_list_member,
                      &session.local_request_stream_list);

    first_data_stream.write_buf = xqc_malloc(1);
    second_data_stream.write_buf = xqc_malloc(1);
    XQC_TEST_ASSERT(first_data_stream.write_buf != NULL);
    XQC_TEST_ASSERT(second_data_stream.write_buf != NULL);
    first_data_stream.write_buf[0] = 'a';
    second_data_stream.write_buf[0] = 'b';
    first_data_stream.write_buf_len = 1;
    first_data_stream.write_buf_cap = 1;
    second_data_stream.write_buf_len = 1;
    second_data_stream.write_buf_cap = 1;
    xqc_moq_track_on_write_stream(
        track, &first_data_stream, 1, 0, 0);
    xqc_moq_track_on_write_stream(
        track, &second_data_stream, 2, 0, 0);

    xqc_moq_publish_done_msg_t done = {
        .subscribe_id = 9,
        .status_code = XQC_MOQ_PUBLISH_DONE_UPDATE_FAILED,
        .stream_count = 0,
    };
    XQC_TEST_ASSERT(xqc_moq_write_publish_done(
        &session, &done) == -XQC_ESYS);
    XQC_TEST_ASSERT(first_data_capture.length == 1);
    XQC_TEST_ASSERT(first_data_capture.fin == 1);
    XQC_TEST_ASSERT(second_data_capture.length == 1);
    XQC_TEST_ASSERT(second_data_capture.fin == 1);
    XQC_TEST_ASSERT(track->subscribe_id == XQC_MOQ_INVALID_ID);
    XQC_TEST_ASSERT(track->track_alias == XQC_MOQ_INVALID_ID);
    XQC_TEST_ASSERT(request_stream.request_closed_notified == 0);
    XQC_TEST_ASSERT(request_stream.write_stream_fin == 1);
    XQC_TEST_ASSERT(done.subscribe_id == 9);
    XQC_TEST_ASSERT(done.stream_count == 0);
    xqc_moq_track_on_write_stream(
        track, &late_stream, 1, 1, 0);
    XQC_TEST_ASSERT(late_stream.track == NULL);
    XQC_TEST_ASSERT(xqc_list_empty(&late_stream.list_member));

    request_capture.fail_write = 0;
    XQC_TEST_ASSERT(xqc_moq_write_publish_done(
        &session, &done) == XQC_OK);
    XQC_TEST_ASSERT(request_capture.length == sizeof(expected));
    XQC_TEST_ASSERT(memcmp(
        request_capture.bytes, expected, sizeof(expected)) == 0);
    XQC_TEST_ASSERT(request_capture.write_count == 1);
    size_t request_length = request_capture.length;
    XQC_TEST_ASSERT(xqc_moq_write_publish_done(
        &session, &done) < 0);
    XQC_TEST_ASSERT(request_capture.length == request_length);

    xqc_list_del_init(&first_data_stream.list_member);
    xqc_list_del_init(&second_data_stream.list_member);
    first_data_stream.track = NULL;
    second_data_stream.track = NULL;
    xqc_moq_d18_update_queue_destroy(
        &request_stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(
        &request_stream.d18_peer_update_queue);
    xqc_test_clean_stream(&first_data_stream);
    xqc_test_clean_stream(&second_data_stream);
    xqc_test_clean_stream(&late_stream);
    xqc_test_clean_stream(&request_stream);
    xqc_list_del_init(&track->list_member);
    xqc_moq_track_destroy(track);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static int
xqc_test_publish_done_counts_public_datachannel_streams_and_gates_senders(void)
{
    static const uint8_t expected[] = {
        XQC_MOQ_D18_MSG_PUBLISH_DONE,
        0x00, 0x03,
        XQC_MOQ_PUBLISH_DONE_TRACK_ENDED,
        0x02,
        0x00,
    };
    xqc_moq_track_ns_field_t datachannel = {
        .len = 11,
        .data = (unsigned char *)"datachannel",
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    xqc_moq_track_t *track =
        xqc_moq_track_create_with_ns_tuple(
            &session, &datachannel, 1, "datachannel",
            XQC_MOQ_TRACK_DATACHANNEL, NULL,
            XQC_MOQ_CONTAINER_NONE,
            XQC_MOQ_TRACK_FOR_PUB);
    XQC_TEST_ASSERT(track != NULL);
    xqc_moq_track_set_alias(track, 4);
    xqc_moq_track_set_subscribe_id(track, 9);
    XQC_TEST_ASSERT(xqc_moq_subscribe_create_with_ns_tuple(
        &session, 9, 4, &datachannel, 1, "datachannel",
        XQC_MOQ_FILTER_LAST_GROUP, 0, 0, 0, 0, NULL, 0)
        != NULL);

    xqc_test_write_capture_t request_capture = {0};
    xqc_test_write_capture_t ordered_capture = {0};
    xqc_test_write_capture_t reuse_capture = {0};
    xqc_moq_stream_t request_stream;
    xqc_moq_stream_t ordered_stream;
    xqc_moq_stream_t reuse_stream;
    xqc_test_init_stream(
        &request_stream, &session, &request_capture);
    xqc_test_init_stream(
        &ordered_stream, &session, &ordered_capture);
    xqc_test_init_stream(
        &reuse_stream, &session, &reuse_capture);
    ordered_stream.kind = XQC_MOQ_STREAM_UNKNOWN;
    ordered_stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_UNI;
    reuse_stream.kind = XQC_MOQ_STREAM_UNKNOWN;
    reuse_stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_UNI;
    xqc_moq_d18_update_queue_init(
        &request_stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(
        &request_stream.d18_peer_update_queue);
    request_stream.local_request = 1;
    request_stream.response_received = 1;
    request_stream.request_type = XQC_MOQ_MSG_PUBLISH;
    request_stream.request_id = 9;
    request_stream.track = track;
    request_stream.kind = XQC_MOQ_STREAM_D18_REQUEST;
    request_stream.d18_context.direction =
        XQC_MOQ_D18_DIRECTION_BIDI;
    request_stream.d18_context.stream_class =
        XQC_MOQ_D18_STREAM_REQUEST;
    request_stream.d18_context.position =
        XQC_MOQ_D18_POSITION_NEXT;
    xqc_list_add_tail(
        &request_stream.request_list_member,
        &session.local_request_stream_list);

    session.datachannel.ready = 1;
    session.datachannel.track_for_pub = track;
    session.datachannel.peer_subscribe_id = 9;
    session.datachannel.ordered_stream = &ordered_stream;
    track->reuse_subgroup_stream = 1;
    track->subgroup_stream = &ordered_stream;
    uint8_t payload = 'x';
    XQC_TEST_ASSERT(xqc_moq_write_datachannel(
        &session, &payload, 1) == XQC_OK);
    XQC_TEST_ASSERT(track->streams_count == 1);
    XQC_TEST_ASSERT(xqc_moq_write_datachannel(
        &session, &payload, 1) == XQC_OK);
    XQC_TEST_ASSERT(track->streams_count == 1);

    track->cur_object_id = 0;
    track->reuse_subgroup_stream = 1;
    track->subgroup_stream = &reuse_stream;
    XQC_TEST_ASSERT(xqc_moq_send_datachannel_msg(
        &session, track, &payload, 1) == XQC_OK);
    XQC_TEST_ASSERT(track->streams_count == 2);

    xqc_moq_publish_done_msg_t done = {
        .subscribe_id = 9,
        .status_code = XQC_MOQ_PUBLISH_DONE_TRACK_ENDED,
    };
    XQC_TEST_ASSERT(xqc_moq_write_publish_done(
        &session, &done) == XQC_OK);
    XQC_TEST_ASSERT(request_capture.length == sizeof(expected));
    XQC_TEST_ASSERT(memcmp(
        request_capture.bytes, expected, sizeof(expected)) == 0);

    size_t ordered_bytes = ordered_capture.length;
    track->reuse_subgroup_stream = 0;
    XQC_TEST_ASSERT(xqc_moq_write_datachannel(
        &session, &payload, 1) < 0);
    XQC_TEST_ASSERT(ordered_capture.length == ordered_bytes);
    track->reuse_subgroup_stream = 1;
    XQC_TEST_ASSERT(xqc_moq_send_datachannel_msg(
        &session, track, &payload, 1) < 0);

    xqc_moq_subgroup_object_t subgroup = {
        .subscribe_id = 9,
        .track_alias = 4,
        .group_id = 7,
        .object_id = 0,
        .payload = &payload,
        .payload_len = 1,
    };
    XQC_TEST_ASSERT(xqc_moq_send_subgroup(
        &session, track, &subgroup) < 0);
    xqc_moq_object_t datagram = {
        .track_alias = 4,
        .group_id = 7,
        .object_id = 0,
        .payload = &payload,
        .payload_len = 1,
    };
    XQC_TEST_ASSERT(xqc_moq_send_object_datagram(
        &session, &datagram) < 0);

    session.datachannel.ordered_stream = NULL;
    session.datachannel.track_for_pub = NULL;
    track->subgroup_stream = NULL;
    xqc_list_del_init(&ordered_stream.list_member);
    xqc_list_del_init(&reuse_stream.list_member);
    ordered_stream.track = NULL;
    reuse_stream.track = NULL;
    xqc_moq_d18_update_queue_destroy(
        &request_stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(
        &request_stream.d18_peer_update_queue);
    xqc_test_clean_stream(&ordered_stream);
    xqc_test_clean_stream(&reuse_stream);
    xqc_test_clean_stream(&request_stream);
    xqc_list_del_init(&track->list_member);
    xqc_moq_track_destroy(track);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static int
xqc_test_legacy_datachannel_stream_keeps_unknown_publish_done_count(void)
{
    xqc_moq_track_ns_field_t datachannel_ns = {
        .len = sizeof("datachannel") - 1,
        .data = (unsigned char *)"datachannel",
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.profile = xqc_moq_v14_profile();
    session.version = XQC_MOQ_VERSION_14;
    session.use_unified_setup = session.profile->unified_setup;

    xqc_moq_track_t *track =
        xqc_moq_track_create_with_ns_tuple(
            &session, &datachannel_ns, 1, "datachannel",
            XQC_MOQ_TRACK_DATACHANNEL, NULL,
            XQC_MOQ_CONTAINER_NONE,
            XQC_MOQ_TRACK_FOR_PUB);
    XQC_TEST_ASSERT(track != NULL);
    xqc_moq_track_set_alias(track, 4);
    xqc_moq_track_set_subscribe_id(track, 9);

    xqc_test_write_capture_t ctl_capture = {0};
    xqc_test_write_capture_t data_capture = {0};
    xqc_moq_stream_t ctl_stream;
    xqc_moq_stream_t data_stream;
    xqc_test_init_stream(&ctl_stream, &session, &ctl_capture);
    xqc_test_init_stream(&data_stream, &session, &data_capture);
    session.ctl_stream = &ctl_stream;

    xqc_moq_track_on_write_stream(
        track, &data_stream, 1, 0, 0);
    XQC_TEST_ASSERT(data_stream.track == track);
    XQC_TEST_ASSERT(track->streams_count == 0);

    xqc_moq_publish_done_msg_t done = {
        .subscribe_id = 9,
        .status_code = XQC_MOQ_PUBLISH_DONE_TRACK_ENDED,
    };
    XQC_TEST_ASSERT(xqc_moq_write_publish_done(
        &session, &done) == XQC_OK);
    XQC_TEST_ASSERT(done.stream_count
                    == XQC_MOQ_PUBLISH_DONE_UNKNOWN_STREAM_COUNT);
    XQC_TEST_ASSERT(ctl_capture.length > 1);
    XQC_TEST_ASSERT(ctl_capture.bytes[0]
                    == XQC_MOQ_MSG_PUBLISH_DONE);

    xqc_moq_publish_done_msg_t decoded = {0};
    xqc_moq_decode_msg_ctx_t decode_ctx = {0};
    xqc_int_t finish = 0;
    xqc_int_t wait_more = 0;
    xqc_moq_msg_publish_done_init_handler(&decoded.msg_base);
    XQC_TEST_ASSERT(xqc_moq_msg_decode_publish_done(
        ctl_capture.bytes + 1, ctl_capture.length - 1, 0,
        &decode_ctx, &decoded.msg_base, &finish, &wait_more)
        == (xqc_int_t)ctl_capture.length - 1);
    XQC_TEST_ASSERT(finish == 1);
    XQC_TEST_ASSERT(wait_more == 0);
    XQC_TEST_ASSERT(decoded.stream_count
                    == XQC_MOQ_PUBLISH_DONE_UNKNOWN_STREAM_COUNT);
    xqc_free(decoded.reason_phrase);

    xqc_list_del_init(&data_stream.list_member);
    data_stream.track = NULL;
    session.ctl_stream = NULL;
    xqc_test_clean_stream(&data_stream);
    xqc_test_clean_stream(&ctl_stream);
    xqc_list_del_init(&track->list_member);
    xqc_moq_track_destroy(track);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static int
xqc_test_init_publish_done_receiver(
    xqc_moq_session_t *session, xqc_moq_stream_t *request_stream,
    xqc_test_write_capture_t *request_capture,
    xqc_moq_track_t **track_out)
{
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_moq_track_t *track =
        xqc_moq_track_create_with_ns_tuple(
            session, &live, 1, "audio",
            XQC_MOQ_TRACK_AUDIO, NULL,
            XQC_MOQ_CONTAINER_NONE,
            XQC_MOQ_TRACK_FOR_SUB);
    if (track == NULL) {
        return -1;
    }
    track->raw_object = 1;
    xqc_moq_track_set_alias(track, 4);
    xqc_moq_track_set_subscribe_id(track, 5);
    if (xqc_moq_subscribe_create_with_ns_tuple(
            session, 5, 4, &live, 1, "audio",
            XQC_MOQ_FILTER_LAST_GROUP, 0, 0, 0, 0, NULL, 1)
        == NULL)
    {
        xqc_list_del_init(&track->list_member);
        xqc_moq_track_destroy(track);
        return -1;
    }

    xqc_test_init_stream(
        request_stream, session, request_capture);
    xqc_moq_d18_update_queue_init(
        &request_stream->d18_local_update_queue);
    xqc_moq_d18_update_queue_init(
        &request_stream->d18_peer_update_queue);
    request_stream->local_request = 1;
    request_stream->response_received = 1;
    request_stream->request_type = XQC_MOQ_MSG_SUBSCRIBE;
    request_stream->request_id = 5;
    request_stream->track = track;
    request_stream->d18_context.direction =
        XQC_MOQ_D18_DIRECTION_BIDI;
    request_stream->d18_context.stream_class =
        XQC_MOQ_D18_STREAM_REQUEST;
    request_stream->d18_context.position =
        XQC_MOQ_D18_POSITION_NEXT;
    xqc_list_add_tail(
        &request_stream->request_list_member,
        &session->local_request_stream_list);
    *track_out = track;
    return 0;
}

static void
xqc_test_clean_publish_done_receiver_request(
    xqc_moq_session_t *session, xqc_moq_stream_t *request_stream)
{
    xqc_moq_d18_update_queue_destroy(
        &request_stream->d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(
        &request_stream->d18_peer_update_queue);
    xqc_test_clean_stream(request_stream);
    xqc_moq_d18_request_registry_destroy(
        &session->d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session->peer_auth_cache);
}

static int
xqc_test_d18_stream_type_uses_moq_integer(void)
{
    static const uint8_t unknown_high_type[] = {0x81, 0x0c};
    static const uint8_t truncated_high_type[] = {0x81};
    xqc_connection_t quic_conn;
    xqc_memzero(&quic_conn, sizeof(quic_conn));
    quic_conn.log = &xqc_test_log;
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.quic_conn = &quic_conn;

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_UNI;
    XQC_TEST_ASSERT(xqc_moq_stream_process(
        &stream, (uint8_t *)unknown_high_type,
        sizeof(unknown_high_type), 1) == -XQC_EILLEGAL_FRAME);
    XQC_TEST_ASSERT(quic_conn.conn_err == XQC_MOQ_D18_PROTOCOL_VIOLATION);
    xqc_test_clean_stream(&stream);

    quic_conn.conn_err = 0;
    xqc_test_init_stream(&stream, &session, &capture);
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_UNI;
    XQC_TEST_ASSERT(xqc_moq_stream_process(
        &stream, (uint8_t *)truncated_high_type,
        sizeof(truncated_high_type), 1) == -XQC_EILLEGAL_FRAME);
    XQC_TEST_ASSERT(quic_conn.conn_err == XQC_MOQ_D18_PROTOCOL_VIOLATION);
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static int
xqc_test_publish_done_receiver_counts_header_only_stream(void)
{
    static const uint8_t subgroup_header[] = {
        XQC_MOQ_SUBGROUP_TYPE_WITH_ID,
        0x04,
        0x01,
        0x00,
        0x00,
    };
    xqc_connection_t quic_conn;
    xqc_memzero(&quic_conn, sizeof(quic_conn));
    quic_conn.conn_err = 0;
    quic_conn.log = &xqc_test_log;
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.role = XQC_MOQ_SUBSCRIBER;
    session.quic_conn = &quic_conn;
    xqc_test_write_capture_t request_capture = {0};
    xqc_moq_stream_t request_stream;
    xqc_moq_track_t *track = NULL;
    XQC_TEST_ASSERT(xqc_test_init_publish_done_receiver(
        &session, &request_stream, &request_capture, &track) == 0);

    xqc_moq_publish_done_msg_t done = {
        .status_code = XQC_MOQ_PUBLISH_DONE_TRACK_ENDED,
        .stream_count = 1,
    };
    xqc_moq_on_publish_done(
        &session, &request_stream, &done.msg_base);
    XQC_TEST_ASSERT(!xqc_list_empty(
        &session.track_list_for_sub));

    xqc_test_write_capture_t data_capture = {0};
    xqc_moq_stream_t *data_stream =
        xqc_calloc(1, sizeof(*data_stream));
    XQC_TEST_ASSERT(data_stream != NULL);
    xqc_test_init_stream(data_stream, &session, &data_capture);
    xqc_moq_d18_update_queue_init(
        &data_stream->d18_local_update_queue);
    xqc_moq_d18_update_queue_init(
        &data_stream->d18_peer_update_queue);
    data_stream->d18_context.direction =
        XQC_MOQ_D18_DIRECTION_UNI;

    xqc_int_t process_ret = xqc_moq_stream_process(
        data_stream, (uint8_t *)subgroup_header,
        sizeof(subgroup_header), 1);
    XQC_TEST_ASSERT(process_ret == (xqc_int_t)sizeof(subgroup_header));
    XQC_TEST_ASSERT(data_stream->track == track);
    XQC_TEST_ASSERT(data_stream->recv_stream_counted == 1);
    XQC_TEST_ASSERT(track->recv_streams_opened == 1);
    XQC_TEST_ASSERT(track->recv_streams_processed == 0);

    xqc_moq_stream_destroy(data_stream);
    XQC_TEST_ASSERT(xqc_list_empty(
        &session.track_list_for_sub));

    xqc_test_clean_publish_done_receiver_request(
        &session, &request_stream);
    return 0;
}

static int
xqc_test_publish_done_receiver_counts_header_before_object_and_rejects_excess(void)
{
    static const uint8_t subgroup_object[] = {
        XQC_MOQ_SUBGROUP_TYPE_WITH_ID,
        0x04,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01, 'x',
    };
    static const uint8_t subgroup_header[] = {
        XQC_MOQ_SUBGROUP_TYPE_WITH_ID,
        0x04,
        0x02,
        0x00,
        0x00,
    };
    xqc_connection_t quic_conn;
    xqc_memzero(&quic_conn, sizeof(quic_conn));
    quic_conn.conn_err = 0;
    quic_conn.log = &xqc_test_log;
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.role = XQC_MOQ_SUBSCRIBER;
    session.quic_conn = &quic_conn;
    xqc_test_write_capture_t request_capture = {0};
    xqc_moq_stream_t request_stream;
    xqc_moq_track_t *track = NULL;
    XQC_TEST_ASSERT(xqc_test_init_publish_done_receiver(
        &session, &request_stream, &request_capture, &track) == 0);

    xqc_test_write_capture_t first_capture = {0};
    xqc_moq_stream_t *first_stream =
        xqc_calloc(1, sizeof(*first_stream));
    XQC_TEST_ASSERT(first_stream != NULL);
    xqc_test_init_stream(first_stream, &session, &first_capture);
    xqc_moq_d18_update_queue_init(
        &first_stream->d18_local_update_queue);
    xqc_moq_d18_update_queue_init(
        &first_stream->d18_peer_update_queue);
    first_stream->d18_context.direction =
        XQC_MOQ_D18_DIRECTION_UNI;
    XQC_TEST_ASSERT(xqc_moq_stream_process(
        first_stream, (uint8_t *)subgroup_object,
        sizeof(subgroup_object), 0)
        == (xqc_int_t)sizeof(subgroup_object));
    XQC_TEST_ASSERT(first_stream->track == track);
    XQC_TEST_ASSERT(track->recv_streams_opened == 1);

    xqc_moq_publish_done_msg_t done = {
        .status_code = XQC_MOQ_PUBLISH_DONE_TRACK_ENDED,
        .stream_count = 1,
    };
    xqc_moq_on_publish_done(
        &session, &request_stream, &done.msg_base);
    XQC_TEST_ASSERT(!xqc_list_empty(
        &session.track_list_for_sub));

    xqc_test_write_capture_t excess_capture = {0};
    xqc_moq_stream_t *excess_stream =
        xqc_calloc(1, sizeof(*excess_stream));
    XQC_TEST_ASSERT(excess_stream != NULL);
    xqc_test_init_stream(excess_stream, &session, &excess_capture);
    xqc_moq_d18_update_queue_init(
        &excess_stream->d18_local_update_queue);
    xqc_moq_d18_update_queue_init(
        &excess_stream->d18_peer_update_queue);
    excess_stream->d18_context.direction =
        XQC_MOQ_D18_DIRECTION_UNI;
    XQC_TEST_ASSERT(xqc_moq_stream_process(
        excess_stream, (uint8_t *)subgroup_header,
        sizeof(subgroup_header), 1) < 0);
    XQC_TEST_ASSERT(excess_stream->track == NULL);
    XQC_TEST_ASSERT(excess_capture.stop_sending_count == 1);
    XQC_TEST_ASSERT(quic_conn.conn_err
                    == XQC_MOQ_D18_PROTOCOL_VIOLATION);
    XQC_TEST_ASSERT(track->recv_streams_opened == 1);

    xqc_moq_stream_destroy(excess_stream);
    xqc_moq_stream_destroy(first_stream);
    XQC_TEST_ASSERT(xqc_list_empty(
        &session.track_list_for_sub));
    xqc_test_clean_publish_done_receiver_request(
        &session, &request_stream);
    return 0;
}

static int
xqc_test_publish_done_receiver_allows_late_stream_up_to_exact_count(void)
{
    xqc_connection_t quic_conn;
    xqc_memzero(&quic_conn, sizeof(quic_conn));
    quic_conn.conn_err = UINT64_MAX;
    quic_conn.log = &xqc_test_log;
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.role = XQC_MOQ_SUBSCRIBER;
    session.quic_conn = &quic_conn;
    xqc_test_write_capture_t request_capture = {0};
    xqc_moq_stream_t request_stream;
    xqc_moq_track_t *track = NULL;
    XQC_TEST_ASSERT(xqc_test_init_publish_done_receiver(
        &session, &request_stream, &request_capture, &track) == 0);

    xqc_moq_publish_done_msg_t done = {
        .status_code = XQC_MOQ_PUBLISH_DONE_TRACK_ENDED,
        .stream_count = 1,
    };
    xqc_moq_on_publish_done(
        &session, &request_stream, &done.msg_base);
    XQC_TEST_ASSERT(!xqc_list_empty(
        &session.track_list_for_sub));
    XQC_TEST_ASSERT(track->track_alias == 4);
    XQC_TEST_ASSERT(track->subscribe_id == 5);

    xqc_test_write_capture_t late_capture = {0};
    xqc_test_write_capture_t excess_capture = {0};
    xqc_moq_stream_t late_stream;
    xqc_moq_stream_t excess_stream;
    xqc_test_init_stream(&late_stream, &session, &late_capture);
    xqc_test_init_stream(&excess_stream, &session, &excess_capture);
    xqc_moq_object_t object = {
        .track_alias = 4,
        .group_id = 1,
        .object_id = 0,
    };
    xqc_moq_track_on_recv_object(
        track, &late_stream, &object);
    XQC_TEST_ASSERT(late_stream.track == track);

    quic_conn.conn_err = 0;
    xqc_moq_track_on_recv_object(
        track, &excess_stream, &object);
    XQC_TEST_ASSERT(excess_stream.track == NULL);
    XQC_TEST_ASSERT(quic_conn.conn_err
                    == XQC_MOQ_D18_PROTOCOL_VIOLATION);

    xqc_list_del_init(&late_stream.recv_list_member);
    late_stream.track = NULL;
    xqc_test_clean_stream(&late_stream);
    xqc_test_clean_stream(&excess_stream);
    xqc_list_del_init(&track->list_member);
    xqc_moq_track_destroy(track);
    xqc_test_clean_publish_done_receiver_request(
        &session, &request_stream);
    return 0;
}

static int
xqc_test_publish_done_receiver_waits_for_all_exact_streams(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.role = XQC_MOQ_SUBSCRIBER;
    xqc_test_write_capture_t request_capture = {0};
    xqc_moq_stream_t request_stream;
    xqc_moq_track_t *track = NULL;
    XQC_TEST_ASSERT(xqc_test_init_publish_done_receiver(
        &session, &request_stream, &request_capture, &track) == 0);

    xqc_test_write_capture_t first_capture = {0};
    xqc_moq_stream_t *first_stream =
        xqc_calloc(1, sizeof(*first_stream));
    XQC_TEST_ASSERT(first_stream != NULL);
    xqc_test_init_stream(first_stream, &session, &first_capture);
    xqc_moq_d18_update_queue_init(
        &first_stream->d18_local_update_queue);
    xqc_moq_d18_update_queue_init(
        &first_stream->d18_peer_update_queue);
    xqc_moq_object_t first_object = {
        .track_alias = 4,
        .group_id = 1,
        .object_id = 0,
    };
    xqc_moq_track_on_recv_object(
        track, first_stream, &first_object);
    XQC_TEST_ASSERT(first_stream->track == track);

    xqc_moq_publish_done_msg_t done = {
        .status_code = XQC_MOQ_PUBLISH_DONE_TRACK_ENDED,
        .stream_count = 2,
    };
    xqc_moq_on_publish_done(
        &session, &request_stream, &done.msg_base);
    XQC_TEST_ASSERT(!xqc_list_empty(
        &session.track_list_for_sub));

    xqc_moq_stream_destroy(first_stream);
    XQC_TEST_ASSERT(!xqc_list_empty(
        &session.track_list_for_sub));
    XQC_TEST_ASSERT(track->track_alias == 4);
    XQC_TEST_ASSERT(track->subscribe_id == 5);

    xqc_test_write_capture_t second_capture = {0};
    xqc_moq_stream_t *second_stream =
        xqc_calloc(1, sizeof(*second_stream));
    XQC_TEST_ASSERT(second_stream != NULL);
    xqc_test_init_stream(second_stream, &session, &second_capture);
    xqc_moq_d18_update_queue_init(
        &second_stream->d18_local_update_queue);
    xqc_moq_d18_update_queue_init(
        &second_stream->d18_peer_update_queue);
    xqc_moq_object_t second_object = {
        .track_alias = 4,
        .group_id = 2,
        .object_id = 0,
    };
    xqc_moq_track_on_recv_object(
        track, second_stream, &second_object);
    XQC_TEST_ASSERT(second_stream->track == track);
    xqc_moq_stream_destroy(second_stream);
    XQC_TEST_ASSERT(xqc_list_empty(
        &session.track_list_for_sub));

    xqc_test_clean_publish_done_receiver_request(
        &session, &request_stream);
    return 0;
}

static int
xqc_test_publish_done_receiver_zero_and_unknown_counts(void)
{
    const uint64_t counts[] = {
        0,
        XQC_MOQ_PUBLISH_DONE_UNKNOWN_STREAM_COUNT,
    };
    for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
        xqc_moq_session_t session;
        xqc_test_init_session(&session);
        session.role = XQC_MOQ_SUBSCRIBER;
        xqc_test_write_capture_t request_capture = {0};
        xqc_moq_stream_t request_stream;
        xqc_moq_track_t *track = NULL;
        XQC_TEST_ASSERT(xqc_test_init_publish_done_receiver(
            &session, &request_stream, &request_capture, &track) == 0);
        xqc_moq_publish_done_msg_t done = {
            .status_code = XQC_MOQ_PUBLISH_DONE_TRACK_ENDED,
            .stream_count = counts[i],
        };
        xqc_moq_on_publish_done(
            &session, &request_stream, &done.msg_base);
        if (counts[i] == 0) {
            XQC_TEST_ASSERT(xqc_list_empty(
                &session.track_list_for_sub));

        } else {
            XQC_TEST_ASSERT(!xqc_list_empty(
                &session.track_list_for_sub));
            xqc_test_write_capture_t late_capture = {0};
            xqc_moq_stream_t late_stream;
            xqc_test_init_stream(
                &late_stream, &session, &late_capture);
            xqc_moq_object_t object = {
                .track_alias = 4,
                .group_id = 1,
                .object_id = 0,
            };
            xqc_moq_track_on_recv_object(
                track, &late_stream, &object);
            XQC_TEST_ASSERT(late_stream.track == track);
            xqc_list_del_init(&late_stream.recv_list_member);
            late_stream.track = NULL;
            xqc_test_clean_stream(&late_stream);
            xqc_list_del_init(&track->list_member);
            xqc_moq_track_destroy(track);
        }
        xqc_test_clean_publish_done_receiver_request(
            &session, &request_stream);
    }
    return 0;
}

static int
xqc_test_publish_done_receiver_retains_bound_streams_and_rejects_duplicate(void)
{
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_connection_t quic_conn;
    xqc_memzero(&quic_conn, sizeof(quic_conn));
    quic_conn.conn_err = UINT64_MAX;
    quic_conn.log = &xqc_test_log;
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.role = XQC_MOQ_SUBSCRIBER;
    session.quic_conn = &quic_conn;
    xqc_moq_user_session_t user_session = {
        .session = &session,
    };
    session.user_session = &user_session;
    session.session_callbacks.on_publish_done =
        xqc_test_on_publish_done_observe;
    session.session_callbacks.on_object =
        xqc_test_on_publish_done_object;

    xqc_moq_track_t *track =
        xqc_moq_track_create_with_ns_tuple(
            &session, &live, 1, "audio",
            XQC_MOQ_TRACK_AUDIO, NULL,
            XQC_MOQ_CONTAINER_NONE,
            XQC_MOQ_TRACK_FOR_SUB);
    XQC_TEST_ASSERT(track != NULL);
    track->raw_object = 1;
    xqc_moq_track_set_alias(track, 4);
    xqc_moq_track_set_subscribe_id(track, 5);
    XQC_TEST_ASSERT(xqc_moq_subscribe_create_with_ns_tuple(
        &session, 5, 4, &live, 1, "audio",
        XQC_MOQ_FILTER_LAST_GROUP, 0, 0, 0, 0, NULL, 1)
        != NULL);

    xqc_test_write_capture_t request_capture = {0};
    xqc_test_write_capture_t data_capture = {0};
    xqc_moq_stream_t request_stream;
    xqc_moq_stream_t data_stream;
    xqc_test_init_stream(
        &request_stream, &session, &request_capture);
    xqc_test_init_stream(&data_stream, &session, &data_capture);
    xqc_moq_d18_update_queue_init(
        &request_stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(
        &request_stream.d18_peer_update_queue);
    request_stream.local_request = 1;
    request_stream.response_received = 1;
    request_stream.request_type = XQC_MOQ_MSG_SUBSCRIBE;
    request_stream.request_id = 5;
    request_stream.track = track;
    request_stream.d18_context.direction =
        XQC_MOQ_D18_DIRECTION_BIDI;
    request_stream.d18_context.stream_class =
        XQC_MOQ_D18_STREAM_REQUEST;
    request_stream.d18_context.position =
        XQC_MOQ_D18_POSITION_NEXT;
    xqc_list_add_tail(&request_stream.request_list_member,
                      &session.local_request_stream_list);
    xqc_moq_object_t bound_object = {
        .group_id = 1,
        .object_id = 0,
        .subgroup_id = 0,
    };
    xqc_moq_track_on_recv_object(
        track, &data_stream, &bound_object);
    XQC_TEST_ASSERT(data_stream.track == track);

    xqc_moq_publish_done_msg_t done = {
        .status_code = XQC_MOQ_PUBLISH_DONE_TRACK_ENDED,
        .stream_count = 1,
        .reason_phrase = "done",
        .reason_phrase_len = 4,
    };
    xqc_test_publish_done_callback_count = 0;
    xqc_test_publish_done_request_id = XQC_MOQ_INVALID_ID;
    xqc_test_publish_done_status = XQC_MOQ_INVALID_ID;
    xqc_test_publish_done_stream_count = XQC_MOQ_INVALID_ID;
    xqc_test_publish_done_callback_fields_valid = 0;
    xqc_test_publish_done_object_callback_count = 0;
    xqc_moq_on_publish_done(
        &session, &request_stream, &done.msg_base);
    XQC_TEST_ASSERT(xqc_test_publish_done_callback_count == 1);
    XQC_TEST_ASSERT(xqc_test_publish_done_request_id == 5);
    XQC_TEST_ASSERT(xqc_test_publish_done_status
                    == XQC_MOQ_PUBLISH_DONE_TRACK_ENDED);
    XQC_TEST_ASSERT(xqc_test_publish_done_stream_count == 1);
    XQC_TEST_ASSERT(xqc_test_publish_done_callback_fields_valid == 1);
    XQC_TEST_ASSERT(request_stream.request_closed_notified == 1);
    XQC_TEST_ASSERT(request_stream.track == NULL);
    XQC_TEST_ASSERT(xqc_list_empty(&session.local_subscribe_list));
    XQC_TEST_ASSERT(!xqc_list_empty(&session.track_list_for_sub));
    XQC_TEST_ASSERT(data_stream.track == track);

    uint8_t payload = 'x';
    xqc_moq_object_t late_object = {
        .track_alias = 4,
        .group_id = 1,
        .object_id = 1,
        .subgroup_id = 0,
        .payload = &payload,
        .payload_len = 1,
    };
    xqc_moq_on_object(&session, &data_stream, &late_object);
    XQC_TEST_ASSERT(
        xqc_test_publish_done_object_callback_count == 1);
    XQC_TEST_ASSERT(data_stream.track == track);

    quic_conn.conn_err = 0;
    xqc_free((void *)quic_conn.conn_close_msg);
    quic_conn.conn_close_msg = NULL;
    xqc_moq_on_publish_done(
        &session, &request_stream, &done.msg_base);
    XQC_TEST_ASSERT(quic_conn.conn_err
                    == XQC_MOQ_D18_PROTOCOL_VIOLATION);
    XQC_TEST_ASSERT(quic_conn.conn_close_msg != NULL);
    XQC_TEST_ASSERT(strcmp(quic_conn.conn_close_msg,
                           "duplicate or invalid PUBLISH_DONE") == 0);
    XQC_TEST_ASSERT(xqc_test_publish_done_callback_count == 1);

    xqc_list_del_init(&data_stream.recv_list_member);
    data_stream.track = NULL;
    xqc_test_clean_stream(&data_stream);
    xqc_test_clean_stream(&request_stream);
    xqc_list_del_init(&track->list_member);
    xqc_moq_track_destroy(track);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    return 0;
}

static int
xqc_test_publish_done_detaches_request_stream_track(void)
{
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.role = XQC_MOQ_SUBSCRIBER;
    xqc_moq_session_set_request_cancelled_callback(
        &session, xqc_test_on_request_cancelled);

    xqc_moq_track_t *track =
        xqc_moq_track_create_with_ns_tuple(
            &session, &live, 1, "audio",
            XQC_MOQ_TRACK_AUDIO, NULL, XQC_MOQ_CONTAINER_NONE,
            XQC_MOQ_TRACK_FOR_SUB);
    XQC_TEST_ASSERT(track != NULL);
    xqc_moq_track_set_alias(track, 4);
    xqc_moq_track_set_subscribe_id(track, 0);
    XQC_TEST_ASSERT(xqc_moq_subscribe_create_with_ns_tuple(
        &session, 0, 4, &live, 1, "audio",
        XQC_MOQ_FILTER_LAST_GROUP, 0, 0, 0, 0, NULL, 1)
        != NULL);

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    xqc_moq_d18_update_queue_init(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&stream.d18_peer_update_queue);
    stream.peer_request = 1;
    stream.response_sent = 1;
    stream.request_type = XQC_MOQ_MSG_PUBLISH;
    stream.request_id = 0;
    stream.track = track;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    xqc_list_add_tail(
        &stream.request_list_member,
        &session.peer_request_stream_list);
    xqc_moq_d18_update_record_t *local_update = NULL;
    xqc_moq_d18_update_record_t *peer_update = NULL;
    XQC_TEST_ASSERT(xqc_moq_d18_update_record_create(
        1, NULL, 0, &local_update) == XQC_MOQ_D18_UPDATE_OK);
    XQC_TEST_ASSERT(xqc_moq_d18_update_record_create(
        2, NULL, 0, &peer_update) == XQC_MOQ_D18_UPDATE_OK);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_push(
        &stream.d18_local_update_queue, local_update)
        == XQC_MOQ_D18_UPDATE_OK);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_push(
        &stream.d18_peer_update_queue, peer_update)
        == XQC_MOQ_D18_UPDATE_OK);

    xqc_moq_publish_done_msg_t done = {
        .subscribe_id = 0,
    };
    xqc_test_request_cancelled_callback_count = 0;
    xqc_moq_on_publish_done(
        &session, &stream, &done.msg_base);

    XQC_TEST_ASSERT(stream.track == NULL);
    XQC_TEST_ASSERT(xqc_list_empty(
        &session.local_subscribe_list));
    XQC_TEST_ASSERT(xqc_list_empty(
        &session.track_list_for_sub));
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_local_update_queue) == NULL);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_peer_update_queue) == NULL);
    xqc_moq_stream_on_request_closed(
        &stream, XQC_MOQ_REQUEST_CANCELLED);
    XQC_TEST_ASSERT(stream.request_closed_notified == 1);
    XQC_TEST_ASSERT(xqc_test_request_cancelled_callback_count == 0);

    xqc_test_clean_stream(&stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

static int
xqc_test_publish_done_defers_reentrant_session_destroy_until_cleanup(void)
{
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_moq_session_t *session = xqc_calloc(1, sizeof(*session));
    XQC_TEST_ASSERT(session != NULL);
    xqc_test_init_session(session);
    session->role = XQC_MOQ_SUBSCRIBER;
    xqc_moq_user_session_t user_session = {
        .session = session,
    };
    session->user_session = &user_session;
    session->session_callbacks.on_publish_done =
        xqc_test_on_publish_done_destroy_session;

    xqc_moq_track_t *track =
        xqc_moq_track_create_with_ns_tuple(
            session, &live, 1, "audio",
            XQC_MOQ_TRACK_AUDIO, NULL, XQC_MOQ_CONTAINER_NONE,
            XQC_MOQ_TRACK_FOR_SUB);
    XQC_TEST_ASSERT(track != NULL);
    xqc_moq_track_set_alias(track, 4);
    xqc_moq_track_set_subscribe_id(track, 5);
    XQC_TEST_ASSERT(xqc_moq_subscribe_create_with_ns_tuple(
        session, 5, 4, &live, 1, "audio",
        XQC_MOQ_FILTER_LAST_GROUP, 0, 0, 0, 0, NULL, 1)
        != NULL);

    xqc_test_write_capture_t capture = {0};
    session->transport_type = XQC_MOQ_TRANSPORT_QUIC;
    xqc_moq_stream_t *stream = xqc_moq_stream_create(session);
    XQC_TEST_ASSERT(stream != NULL);
    stream->trans_stream = &capture;
    stream->trans_ops.write = xqc_test_capture_write;
    stream->trans_ops.quic_stream = xqc_test_capture_quic_stream;
    stream->trans_ops.cancel = xqc_test_capture_cancel;
    stream->trans_ops.stop_sending = xqc_test_capture_stop_sending;
    stream->local_request = 1;
    stream->response_received = 1;
    stream->request_type = XQC_MOQ_MSG_SUBSCRIBE;
    stream->request_id = 5;
    stream->track = track;
    stream->d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream->d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream->d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    xqc_list_add_tail(&stream->request_list_member,
                      &session->local_request_stream_list);

    xqc_moq_publish_done_msg_t done = {
        .status_code = XQC_MOQ_PUBLISH_DONE_TRACK_ENDED,
        .stream_count = 0,
    };
    xqc_test_publish_done_destroy_callback_count = 0;
    xqc_moq_on_publish_done(session, stream, &done.msg_base);

    XQC_TEST_ASSERT(xqc_test_publish_done_destroy_callback_count == 1);
    XQC_TEST_ASSERT(user_session.session == NULL);
    XQC_TEST_ASSERT(session->destroy_pending == 1);
    XQC_TEST_ASSERT(stream->request_closed_notified == 1);
    XQC_TEST_ASSERT(stream->track == NULL);
    xqc_moq_stream_destroy(stream);
    return 0;
}

static int
xqc_test_publish_done_uses_subscribe_stream_request_id(void)
{
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.role = XQC_MOQ_SUBSCRIBER;
    xqc_moq_user_session_t user_session = {
        .session = &session,
    };
    session.user_session = &user_session;
    session.session_callbacks.on_publish_done =
        xqc_test_on_publish_done_observe;

    xqc_moq_track_t *track =
        xqc_moq_track_create_with_ns_tuple(
            &session, &live, 1, "audio",
            XQC_MOQ_TRACK_AUDIO, NULL, XQC_MOQ_CONTAINER_NONE,
            XQC_MOQ_TRACK_FOR_SUB);
    XQC_TEST_ASSERT(track != NULL);
    xqc_moq_track_set_alias(track, 4);
    xqc_moq_track_set_subscribe_id(track, 5);
    XQC_TEST_ASSERT(xqc_moq_subscribe_create_with_ns_tuple(
        &session, 5, 4, &live, 1, "audio",
        XQC_MOQ_FILTER_LAST_GROUP, 0, 0, 0, 0, NULL, 1)
        != NULL);

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    xqc_moq_d18_update_queue_init(&stream.d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&stream.d18_peer_update_queue);
    stream.local_request = 1;
    stream.response_received = 1;
    stream.request_type = XQC_MOQ_MSG_SUBSCRIBE;
    stream.request_id = 5;
    stream.track = track;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    stream.d18_message_kind = XQC_MOQ_D18_MESSAGE_PUBLISH_DONE;
    stream.decode_msg_ctx.cur_msg_type =
        (xqc_moq_msg_type_t)XQC_MOQ_D18_MSG_PUBLISH_DONE;
    XQC_TEST_ASSERT(xqc_moq_session_register_local_request_id(
        &session, stream.request_id) == XQC_MOQ_D18_REQUEST_ID_OK);
    xqc_list_add_tail(&stream.request_list_member,
                      &session.local_request_stream_list);

    xqc_moq_publish_done_msg_t *decoded =
        xqc_moq_stream_get_or_alloc_cur_decode_msg(&stream);
    XQC_TEST_ASSERT(decoded != NULL);
    xqc_moq_stream_free_cur_decode_msg(&stream);

    xqc_moq_publish_done_msg_t done = {
        .status_code = XQC_MOQ_PUBLISH_DONE_UPDATE_FAILED,
        .stream_count = 0,
    };
    xqc_test_publish_done_callback_count = 0;
    xqc_test_publish_done_request_id = XQC_MOQ_INVALID_ID;
    xqc_test_publish_done_status = XQC_MOQ_INVALID_ID;
    xqc_moq_on_publish_done(&session, &stream, &done.msg_base);

    XQC_TEST_ASSERT(xqc_test_publish_done_callback_count == 1);
    XQC_TEST_ASSERT(xqc_test_publish_done_request_id == 5);
    XQC_TEST_ASSERT(xqc_test_publish_done_status
                    == XQC_MOQ_PUBLISH_DONE_UPDATE_FAILED);
    XQC_TEST_ASSERT(stream.request_closed_notified == 1);
    XQC_TEST_ASSERT(stream.track == NULL);
    XQC_TEST_ASSERT(xqc_list_empty(&session.local_subscribe_list));
    XQC_TEST_ASSERT(xqc_list_empty(&session.track_list_for_sub));
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_local_update_queue) == NULL);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_peer_update_queue) == NULL);

    xqc_test_clean_stream(&stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

static int
xqc_test_publish_done_cleans_state_when_stream_is_already_terminal(void)
{
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.role = XQC_MOQ_SUBSCRIBER;
    xqc_connection_t quic_conn;
    xqc_memzero(&quic_conn, sizeof(quic_conn));
    quic_conn.conn_err = 0;
    quic_conn.log = &xqc_test_log;
    session.quic_conn = &quic_conn;

    xqc_moq_track_t *track =
        xqc_moq_track_create_with_ns_tuple(
            &session, &live, 1, "audio",
            XQC_MOQ_TRACK_AUDIO, NULL, XQC_MOQ_CONTAINER_NONE,
            XQC_MOQ_TRACK_FOR_SUB);
    XQC_TEST_ASSERT(track != NULL);
    xqc_moq_track_set_alias(track, 4);
    xqc_moq_track_set_subscribe_id(track, 0);
    XQC_TEST_ASSERT(xqc_moq_subscribe_create_with_ns_tuple(
        &session, 0, 4, &live, 1, "audio",
        XQC_MOQ_FILTER_LAST_GROUP, 0, 0, 0, 0, NULL, 1)
        != NULL);

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    stream.peer_request = 1;
    stream.response_sent = 1;
    stream.request_type = XQC_MOQ_MSG_PUBLISH;
    stream.request_id = 0;
    stream.request_closed_notified = 1;
    stream.track = track;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;

    xqc_moq_publish_done_msg_t done = {
        .subscribe_id = 0,
    };
    xqc_moq_on_publish_done(
        &session, &stream, &done.msg_base);

    XQC_TEST_ASSERT(quic_conn.conn_err
                    == XQC_MOQ_D18_PROTOCOL_VIOLATION);
    XQC_TEST_ASSERT(stream.track == track);
    XQC_TEST_ASSERT(!xqc_list_empty(
        &session.local_subscribe_list));
    XQC_TEST_ASSERT(!xqc_list_empty(
        &session.track_list_for_sub));

    xqc_moq_subscribe_t *subscription =
        xqc_moq_find_subscribe(&session, 0, 1);
    XQC_TEST_ASSERT(subscription != NULL);
    xqc_list_del_init(&subscription->list_member);
    xqc_moq_subscribe_destroy(subscription);
    stream.track = NULL;
    xqc_list_del_init(&track->list_member);
    xqc_moq_track_destroy(track);
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

static int
xqc_test_subscribe_tracks_writer_rejects_bad_local_request_ids(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.transport_type = (xqc_moq_transport_type_t)99;

    xqc_moq_subscribe_tracks_msg_t wrong_parity = {
        .request_id = 2,
    };
    XQC_TEST_ASSERT(xqc_moq_write_subscribe_tracks(
        &session, &wrong_parity) == -XQC_EPARAM);

    xqc_moq_stream_t existing;
    xqc_memzero(&existing, sizeof(existing));
    existing.local_request = 1;
    existing.request_id = 1;
    xqc_init_list_head(&existing.request_list_member);
    XQC_TEST_ASSERT(xqc_moq_session_register_local_request_id(
        &session, 1) == XQC_MOQ_D18_REQUEST_ID_OK);
    xqc_list_add_tail(
        &existing.request_list_member,
        &session.local_request_stream_list);
    xqc_moq_subscribe_tracks_msg_t duplicate = {
        .request_id = 1,
    };
    XQC_TEST_ASSERT(xqc_moq_write_subscribe_tracks(
        &session, &duplicate) == -XQC_EPARAM);

    xqc_list_del_init(&existing.request_list_member);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

static int
xqc_test_public_session_callbacks_layout_stays_compatible(void)
{
    size_t expected_size =
        offsetof(xqc_moq_session_callbacks_t, on_unsubscribe_namespace)
        + sizeof(((xqc_moq_session_callbacks_t *)0)->on_unsubscribe_namespace);
    XQC_TEST_ASSERT(sizeof(xqc_moq_session_callbacks_t) == expected_size);
    XQC_TEST_ASSERT(offsetof(xqc_moq_session_callbacks_t,
        on_subscribe_namespace)
        == offsetof(xqc_moq_session_callbacks_t, on_goaway)
            + sizeof(((xqc_moq_session_callbacks_t *)0)->on_goaway));
    XQC_TEST_ASSERT(offsetof(xqc_moq_session_callbacks_t,
        on_subscribe_namespace_ok)
        == offsetof(xqc_moq_session_callbacks_t, on_subscribe_namespace)
            + sizeof(((xqc_moq_session_callbacks_t *)0)
                ->on_subscribe_namespace));

    xqc_moq_session_t session;
    xqc_memzero(&session, sizeof(session));
    xqc_moq_session_callbacks_ext_t ext = {
        .struct_size = sizeof(ext),
        .abi_version = XQC_MOQ_SESSION_CALLBACKS_EXT_ABI_VERSION,
    };
    XQC_TEST_ASSERT(xqc_moq_session_set_callbacks_ext(&session, &ext)
                    == XQC_OK);
    ext.abi_version++;
    XQC_TEST_ASSERT(xqc_moq_session_set_callbacks_ext(&session, &ext)
                    == -XQC_EVERSION);
    return 0;
}

static void
xqc_test_make_active_peer_tracks_stream(
    xqc_moq_stream_t *stream, xqc_moq_session_t *session,
    xqc_test_write_capture_t *capture, uint64_t request_id,
    const xqc_moq_track_ns_field_t *prefix, uint64_t prefix_num)
{
    xqc_test_init_stream(stream, session, capture);
    stream->peer_request = 1;
    stream->response_sent = 1;
    stream->request_type = XQC_MOQ_MSG_SUBSCRIBE_TRACKS;
    stream->request_id = request_id;
    stream->subscribe_tracks_active = 1;
    stream->d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream->d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream->d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    stream->tracks_subscription =
        xqc_moq_namespace_prefix_create_copy(prefix, prefix_num);
    if (stream->tracks_subscription != NULL) {
        stream->tracks_subscription->request_id = request_id;
    }
    xqc_list_add_tail(&stream->request_list_member,
                      &session->peer_request_stream_list);
}

static void
xqc_test_clean_tracks_stream(xqc_moq_stream_t *stream)
{
    xqc_moq_namespace_prefix_destroy(stream->tracks_subscription);
    stream->tracks_subscription = NULL;
    xqc_free(stream->read_buf);
    stream->read_buf = NULL;
    xqc_test_clean_stream(stream);
}

static int
xqc_test_publish_blocked_writer_suffix_and_lifecycle(void)
{
    static const uint8_t expected_suffix[] = {
        0x0f, 0x00, 0x0c,
        0x01, 0x06, 's', 'p', 'o', 'r', 't', 's',
        0x03, 'c', 'a', 'm',
    };
    static const uint8_t expected_root[] = {
        0x0f, 0x00, 0x11,
        0x02,
        0x04, 'l', 'i', 'v', 'e',
        0x06, 's', 'p', 'o', 'r', 't', 's',
        0x03, 'c', 'a', 'm',
    };
    xqc_moq_track_ns_field_t full_namespace[] = {
        {.len = 4, .data = (unsigned char *)"live"},
        {.len = 6, .data = (unsigned char *)"sports"},
    };
    xqc_moq_track_ns_field_t unrelated = {
        .len = 5,
        .data = (unsigned char *)"other",
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    uint64_t request_allocator = session.request_id_allocator;
    uint64_t alias_allocator = session.track_alias_allocator;
    uint64_t registry_next = session.d18_request_registry.next_local_id;

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_make_active_peer_tracks_stream(
        &stream, &session, &capture, 0, full_namespace, 1);
    XQC_TEST_ASSERT(stream.tracks_subscription != NULL);
    XQC_TEST_ASSERT(xqc_moq_write_publish_blocked(
        &session, stream.request_id, full_namespace, 2,
        "cam", 3) == XQC_OK);
    XQC_TEST_ASSERT(capture.length == sizeof(expected_suffix));
    XQC_TEST_ASSERT(memcmp(capture.bytes, expected_suffix,
                           sizeof(expected_suffix)) == 0);

    xqc_test_write_capture_t root_capture = {0};
    xqc_moq_stream_t root_stream;
    xqc_test_make_active_peer_tracks_stream(
        &root_stream, &session, &root_capture, 2, NULL, 0);
    XQC_TEST_ASSERT(root_stream.tracks_subscription != NULL);
    XQC_TEST_ASSERT(xqc_moq_write_publish_blocked(
        &session, root_stream.request_id, full_namespace, 2,
        "cam", 3) == XQC_OK);
    XQC_TEST_ASSERT(root_capture.length == sizeof(expected_root));
    XQC_TEST_ASSERT(memcmp(root_capture.bytes, expected_root,
                           sizeof(expected_root)) == 0);

    xqc_memzero(&capture, sizeof(capture));
    XQC_TEST_ASSERT(xqc_moq_write_publish_blocked(
        &session, stream.request_id, &unrelated, 1,
        "cam", 3) != XQC_OK);
    XQC_TEST_ASSERT(capture.length == 0);

    stream.response_sent = 0;
    XQC_TEST_ASSERT(xqc_moq_write_publish_blocked(
        &session, stream.request_id, full_namespace, 2,
        "cam", 3) != XQC_OK);
    XQC_TEST_ASSERT(capture.length == 0);
    stream.response_sent = 1;
    stream.subscribe_tracks_active = 0;
    XQC_TEST_ASSERT(xqc_moq_write_publish_blocked(
        &session, stream.request_id, full_namespace, 2,
        "cam", 3) != XQC_OK);
    XQC_TEST_ASSERT(capture.length == 0);
    stream.subscribe_tracks_active = 1;
    stream.request_closed_notified = 1;
    XQC_TEST_ASSERT(xqc_moq_write_publish_blocked(
        &session, stream.request_id, full_namespace, 2,
        "cam", 3) != XQC_OK);
    XQC_TEST_ASSERT(capture.length == 0);
    stream.request_closed_notified = 0;
    stream.peer_request = 0;
    stream.local_request = 1;
    XQC_TEST_ASSERT(xqc_moq_write_publish_blocked(
        &session, stream.request_id, full_namespace, 2,
        "cam", 3) != XQC_OK);
    XQC_TEST_ASSERT(capture.length == 0);
    stream.local_request = 0;
    stream.peer_request = 1;
    stream.request_type = XQC_MOQ_MSG_PUBLISH;
    XQC_TEST_ASSERT(xqc_moq_write_publish_blocked(
        &session, stream.request_id, full_namespace, 2,
        "cam", 3) != XQC_OK);
    XQC_TEST_ASSERT(capture.length == 0);
    stream.request_type = XQC_MOQ_MSG_SUBSCRIBE_TRACKS;
    session.version = XQC_MOQ_VERSION_14;
    XQC_TEST_ASSERT(xqc_moq_write_publish_blocked(
        &session, stream.request_id, full_namespace, 2,
        "cam", 3) != XQC_OK);
    XQC_TEST_ASSERT(capture.length == 0);
    session.version = XQC_MOQ_VERSION_18;
    XQC_TEST_ASSERT(xqc_moq_write_publish_blocked(
        &session, stream.request_id, full_namespace, 2,
        "", 0) != XQC_OK);
    XQC_TEST_ASSERT(capture.length == 0);

    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_UNKNOWN;
    XQC_TEST_ASSERT(xqc_moq_write_publish_blocked(
        &session, stream.request_id, full_namespace, 2,
        "cam", 3) != XQC_OK);
    XQC_TEST_ASSERT(capture.length == 0);
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_UNCLASSIFIED;
    XQC_TEST_ASSERT(xqc_moq_write_publish_blocked(
        &session, stream.request_id, full_namespace, 2,
        "cam", 3) != XQC_OK);
    XQC_TEST_ASSERT(capture.length == 0);
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_FIRST;
    XQC_TEST_ASSERT(xqc_moq_write_publish_blocked(
        &session, stream.request_id, full_namespace, 2,
        "cam", 3) != XQC_OK);
    XQC_TEST_ASSERT(capture.length == 0);
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;

    XQC_TEST_ASSERT(session.request_id_allocator == request_allocator);
    XQC_TEST_ASSERT(session.track_alias_allocator == alias_allocator);
    XQC_TEST_ASSERT(session.d18_request_registry.next_local_id
                    == registry_next);
    XQC_TEST_ASSERT(xqc_list_empty(
        &session.d18_request_registry.local_ids));
    XQC_TEST_ASSERT(xqc_list_empty(
        &session.d18_request_registry.peer_ids));
    XQC_TEST_ASSERT(xqc_list_empty(&session.local_subscribe_list));
    XQC_TEST_ASSERT(xqc_list_empty(&session.peer_subscribe_list));
    XQC_TEST_ASSERT(xqc_list_empty(&session.track_list_for_pub));
    XQC_TEST_ASSERT(xqc_list_empty(&session.track_list_for_sub));

    xqc_test_clean_tracks_stream(&root_stream);
    xqc_test_clean_tracks_stream(&stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

static int
xqc_test_publish_blocked_receive_callback_and_relay(void)
{
    static const uint8_t incoming[] = {
        0x0f, 0x00, 0x0c,
        0x01, 0x06, 's', 'p', 'o', 'r', 't', 's',
        0x03, 'c', 'a', 'm',
    };
    static const uint8_t expected_root[] = {
        0x0f, 0x00, 0x11,
        0x02,
        0x04, 'l', 'i', 'v', 'e',
        0x06, 's', 'p', 'o', 'r', 't', 's',
        0x03, 'c', 'a', 'm',
    };
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_moq_track_ns_field_t other = {
        .len = 5,
        .data = (unsigned char *)"other",
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    xqc_moq_user_session_t user_session = {.session = &session};
    session.user_session = &user_session;
    xqc_moq_session_set_publish_blocked_callback(
        &session, xqc_test_on_publish_blocked);

    xqc_test_write_capture_t origin_capture = {0};
    xqc_moq_stream_t origin;
    xqc_test_init_stream(&origin, &session, &origin_capture);
    origin.local_request = 1;
    origin.response_received = 1;
    origin.request_type = XQC_MOQ_MSG_SUBSCRIBE_TRACKS;
    origin.request_id = 1;
    origin.tracks_subscription =
        xqc_moq_namespace_prefix_create_copy(&live, 1);
    XQC_TEST_ASSERT(origin.tracks_subscription != NULL);
    origin.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    origin.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    origin.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    xqc_list_add_tail(&origin.request_list_member,
                      &session.local_request_stream_list);

    xqc_test_write_capture_t captures[8] = {{0}};
    xqc_moq_stream_t downstream[8];
    xqc_test_make_active_peer_tracks_stream(
        &downstream[0], &session, &captures[0], 0, &live, 1);
    xqc_test_make_active_peer_tracks_stream(
        &downstream[1], &session, &captures[1], 2, NULL, 0);
    xqc_test_make_active_peer_tracks_stream(
        &downstream[2], &session, &captures[2], 4, &other, 1);
    xqc_test_make_active_peer_tracks_stream(
        &downstream[3], &session, &captures[3], 6, &live, 1);
    downstream[3].response_sent = 0;
    xqc_test_make_active_peer_tracks_stream(
        &downstream[4], &session, &captures[4], 8, &live, 1);
    downstream[4].request_closed_notified = 1;
    xqc_test_make_active_peer_tracks_stream(
        &downstream[5], &session, &captures[5], 10, &live, 1);
    downstream[5].d18_context.direction =
        XQC_MOQ_D18_DIRECTION_UNKNOWN;
    xqc_test_make_active_peer_tracks_stream(
        &downstream[6], &session, &captures[6], 12, &live, 1);
    downstream[6].d18_context.stream_class =
        XQC_MOQ_D18_STREAM_UNCLASSIFIED;
    xqc_test_make_active_peer_tracks_stream(
        &downstream[7], &session, &captures[7], 14, &live, 1);
    downstream[7].d18_context.position = XQC_MOQ_D18_POSITION_FIRST;

    xqc_test_publish_blocked_callback_count = 0;
    xqc_test_publish_blocked_request_id = XQC_MOQ_INVALID_ID;
    xqc_test_publish_blocked_namespace_num = 0;
    xqc_memzero(xqc_test_publish_blocked_namespace_lens,
                sizeof(xqc_test_publish_blocked_namespace_lens));
    xqc_memzero(xqc_test_publish_blocked_namespace_data,
                sizeof(xqc_test_publish_blocked_namespace_data));
    xqc_test_publish_blocked_track_name_len = 0;
    xqc_memzero(xqc_test_publish_blocked_track_name,
                sizeof(xqc_test_publish_blocked_track_name));

    XQC_TEST_ASSERT(xqc_moq_stream_process(
        &origin, (uint8_t *)incoming, sizeof(incoming), 0)
        == (xqc_int_t)sizeof(incoming));
    XQC_TEST_ASSERT(xqc_test_publish_blocked_callback_count == 1);
    XQC_TEST_ASSERT(xqc_test_publish_blocked_request_id == 1);
    XQC_TEST_ASSERT(xqc_test_publish_blocked_namespace_num == 2);
    XQC_TEST_ASSERT(xqc_test_publish_blocked_namespace_lens[0] == 4);
    XQC_TEST_ASSERT(memcmp(
        xqc_test_publish_blocked_namespace_data[0], "live", 4) == 0);
    XQC_TEST_ASSERT(xqc_test_publish_blocked_namespace_lens[1] == 6);
    XQC_TEST_ASSERT(memcmp(
        xqc_test_publish_blocked_namespace_data[1], "sports", 6) == 0);
    XQC_TEST_ASSERT(xqc_test_publish_blocked_track_name_len == 3);
    XQC_TEST_ASSERT(memcmp(
        xqc_test_publish_blocked_track_name, "cam", 3) == 0);
    XQC_TEST_ASSERT(origin_capture.length == 0);
    XQC_TEST_ASSERT(captures[0].length == sizeof(incoming));
    XQC_TEST_ASSERT(memcmp(captures[0].bytes, incoming,
                           sizeof(incoming)) == 0);
    XQC_TEST_ASSERT(captures[1].length == sizeof(expected_root));
    XQC_TEST_ASSERT(memcmp(captures[1].bytes, expected_root,
                           sizeof(expected_root)) == 0);
    XQC_TEST_ASSERT(captures[2].length == 0);
    XQC_TEST_ASSERT(captures[3].length == 0);
    XQC_TEST_ASSERT(captures[4].length == 0);
    XQC_TEST_ASSERT(captures[5].length == 0);
    XQC_TEST_ASSERT(captures[6].length == 0);
    XQC_TEST_ASSERT(captures[7].length == 0);
    XQC_TEST_ASSERT(xqc_list_empty(&session.local_subscribe_list));
    XQC_TEST_ASSERT(xqc_list_empty(&session.peer_subscribe_list));
    XQC_TEST_ASSERT(xqc_list_empty(&session.track_list_for_pub));
    XQC_TEST_ASSERT(xqc_list_empty(&session.track_list_for_sub));

    for (size_t i = 0; i < 8; i++) {
        xqc_test_clean_tracks_stream(&downstream[i]);
    }
    xqc_test_clean_tracks_stream(&origin);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

static int
xqc_test_publish_blocked_invalid_receive_is_protocol_violation(void)
{
    xqc_connection_t quic_conn;
    xqc_memzero(&quic_conn, sizeof(quic_conn));
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    quic_conn.log = &xqc_test_log;
    session.quic_conn = &quic_conn;
    xqc_moq_user_session_t user_session = {.session = &session};
    session.user_session = &user_session;
    xqc_moq_session_set_publish_blocked_callback(
        &session, xqc_test_on_publish_blocked);

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    stream.local_request = 1;
    stream.request_type = XQC_MOQ_MSG_SUBSCRIBE_TRACKS;
    stream.request_id = 1;
    stream.tracks_subscription =
        xqc_moq_namespace_prefix_create_copy(NULL, 0);
    XQC_TEST_ASSERT(stream.tracks_subscription != NULL);
    xqc_moq_track_ns_field_t suffix = {
        .len = 1,
        .data = (unsigned char *)"x",
    };
    xqc_moq_publish_blocked_msg_t blocked = {
        .track_namespace_suffix_num = 1,
        .track_namespace_suffix = &suffix,
        .track_name = "cam",
        .track_name_len = 3,
    };
    xqc_test_publish_blocked_callback_count = 0;
    xqc_moq_on_publish_blocked(
        &session, &stream, &blocked.msg_base);
    XQC_TEST_ASSERT(quic_conn.conn_err
                    == XQC_MOQ_D18_PROTOCOL_VIOLATION);
    XQC_TEST_ASSERT(xqc_test_publish_blocked_callback_count == 0);
    XQC_TEST_ASSERT(capture.length == 0);

    xqc_test_clean_tracks_stream(&stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

static int
xqc_test_publish_blocked_invalid_wire_is_protocol_violation(void)
{
    static const uint8_t empty_track_name[] = {
        0x0f, 0x00, 0x02, 0x00, 0x00,
    };
    xqc_connection_t quic_conn;
    xqc_memzero(&quic_conn, sizeof(quic_conn));
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    quic_conn.log = &xqc_test_log;
    session.quic_conn = &quic_conn;

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    stream.local_request = 1;
    stream.response_received = 1;
    stream.request_type = XQC_MOQ_MSG_SUBSCRIBE_TRACKS;
    stream.request_id = 1;
    stream.tracks_subscription =
        xqc_moq_namespace_prefix_create_copy(NULL, 0);
    XQC_TEST_ASSERT(stream.tracks_subscription != NULL);
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;

    XQC_TEST_ASSERT(xqc_moq_stream_process(
        &stream, (uint8_t *)empty_track_name,
        sizeof(empty_track_name), 0) < 0);
    XQC_TEST_ASSERT(quic_conn.conn_err
                    == XQC_MOQ_D18_PROTOCOL_VIOLATION);
    XQC_TEST_ASSERT(capture.length == 0);

    xqc_test_clean_tracks_stream(&stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

static xqc_int_t
xqc_test_publish_blocked_decode_emalloc(
    uint8_t *buf, size_t len, uint8_t fin,
    xqc_moq_decode_msg_ctx_t *ctx, xqc_moq_msg_base_t *base,
    xqc_int_t *finish, xqc_int_t *wait_more)
{
    (void)buf;
    (void)len;
    (void)fin;
    (void)ctx;
    (void)base;
    (void)finish;
    (void)wait_more;
    return -XQC_EMALLOC;
}

static int
xqc_test_publish_blocked_decode_oom_is_internal_error(void)
{
    xqc_connection_t quic_conn;
    xqc_memzero(&quic_conn, sizeof(quic_conn));
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    quic_conn.log = &xqc_test_log;
    session.quic_conn = &quic_conn;

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    stream.local_request = 1;
    stream.response_received = 1;
    stream.request_type = XQC_MOQ_MSG_SUBSCRIBE_TRACKS;
    stream.request_id = 1;
    stream.tracks_subscription =
        xqc_moq_namespace_prefix_create_copy(NULL, 0);
    XQC_TEST_ASSERT(stream.tracks_subscription != NULL);
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    stream.d18_message_kind = XQC_MOQ_D18_MESSAGE_PUBLISH_BLOCKED;
    stream.decode_msg_ctx.cur_decode_state = XQC_MOQ_DECODE_MSG;
    stream.decode_msg_ctx.cur_msg_type =
        (xqc_moq_msg_type_t)XQC_MOQ_D18_MSG_PUBLISH_BLOCKED;
    xqc_moq_publish_blocked_msg_t *blocked =
        xqc_moq_d18_publish_blocked_create();
    XQC_TEST_ASSERT(blocked != NULL);
    blocked->msg_base.decode = xqc_test_publish_blocked_decode_emalloc;
    stream.decode_msg_ctx.cur_decode_msg = blocked;

    uint8_t byte = 0;
    XQC_TEST_ASSERT(xqc_moq_stream_process(
        &stream, &byte, sizeof(byte), 0) < 0);
    XQC_TEST_ASSERT(quic_conn.conn_err == XQC_MOQ_D18_INTERNAL_ERROR);
    XQC_TEST_ASSERT(capture.length == 0);

    xqc_test_clean_tracks_stream(&stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

static int
xqc_test_publish_done_invalid_wire_case(
    const char *case_name, const uint8_t *wire, size_t wire_len)
{
    xqc_connection_t quic_conn;
    xqc_memzero(&quic_conn, sizeof(quic_conn));
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    quic_conn.log = &xqc_test_log;
    session.quic_conn = &quic_conn;

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    stream.local_request = 1;
    stream.response_received = 1;
    stream.request_type = XQC_MOQ_MSG_SUBSCRIBE;
    stream.request_id = 5;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;

    xqc_int_t process_ret = xqc_moq_stream_process(
        &stream, (uint8_t *)wire, wire_len, 0);
    int mapped = process_ret < 0
        && quic_conn.conn_err == XQC_MOQ_D18_PROTOCOL_VIOLATION
        && capture.length == 0;

    xqc_free(stream.read_buf);
    stream.read_buf = NULL;
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    if (!mapped) {
        fprintf(stderr,
                "assert failed: invalid %s PUBLISH_DONE did not map to PROTOCOL_VIOLATION\n",
                case_name);
    }
    return mapped ? 0 : -1;
}

static xqc_int_t
xqc_test_publish_done_decode_emalloc(
    uint8_t *buf, size_t len, uint8_t fin,
    xqc_moq_decode_msg_ctx_t *ctx, xqc_moq_msg_base_t *base,
    xqc_int_t *finish, xqc_int_t *wait_more)
{
    (void)buf;
    (void)len;
    (void)fin;
    (void)ctx;
    (void)base;
    (void)finish;
    (void)wait_more;
    return -XQC_EMALLOC;
}

static int
xqc_test_publish_done_create_oom_is_decode_emalloc(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    stream.local_request = 1;
    stream.response_received = 1;
    stream.request_type = XQC_MOQ_MSG_SUBSCRIBE;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    stream.d18_message_kind = XQC_MOQ_D18_MESSAGE_PUBLISH_DONE;

    XQC_TEST_ASSERT(
        xqc_moq_stream_classify_d18_control_alloc_failure(&stream)
        == -XQC_EMALLOC);

    stream.request_closed_notified = 1;
    XQC_TEST_ASSERT(
        xqc_moq_stream_classify_d18_control_alloc_failure(&stream)
        == XQC_OK);

    stream.request_closed_notified = 0;
    session.version = XQC_MOQ_VERSION_14;
    session.profile = xqc_moq_v14_profile();
    session.use_unified_setup = 0;
    XQC_TEST_ASSERT(
        xqc_moq_stream_classify_d18_control_alloc_failure(&stream)
        == XQC_OK);

    session.version = XQC_MOQ_VERSION_18;
    session.profile = xqc_moq_v18_profile();
    session.use_unified_setup = 1;
    stream.d18_message_kind = XQC_MOQ_D18_MESSAGE_NONE;
    XQC_TEST_ASSERT(
        xqc_moq_stream_classify_d18_control_alloc_failure(&stream)
        == XQC_OK);

    xqc_test_clean_stream(&stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    return 0;
}

static int
xqc_test_publish_done_decode_oom_is_internal_error(void)
{
    xqc_connection_t quic_conn;
    xqc_memzero(&quic_conn, sizeof(quic_conn));
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    quic_conn.log = &xqc_test_log;
    session.quic_conn = &quic_conn;

    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &session, &capture);
    stream.local_request = 1;
    stream.response_received = 1;
    stream.request_type = XQC_MOQ_MSG_SUBSCRIBE;
    stream.request_id = 5;
    stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    stream.d18_message_kind = XQC_MOQ_D18_MESSAGE_PUBLISH_DONE;
    stream.decode_msg_ctx.cur_decode_state = XQC_MOQ_DECODE_MSG;
    stream.decode_msg_ctx.cur_msg_type =
        (xqc_moq_msg_type_t)XQC_MOQ_D18_MSG_PUBLISH_DONE;
    xqc_moq_publish_done_msg_t *done =
        xqc_moq_d18_publish_done_create();
    XQC_TEST_ASSERT(done != NULL);
    done->msg_base.decode = xqc_test_publish_done_decode_emalloc;
    stream.decode_msg_ctx.cur_decode_msg = done;

    uint8_t byte = 0;
    xqc_int_t process_ret = xqc_moq_stream_process(
        &stream, &byte, sizeof(byte), 0);
    int mapped = process_ret < 0
        && quic_conn.conn_err == XQC_MOQ_D18_INTERNAL_ERROR
        && capture.length == 0;

    xqc_free(stream.read_buf);
    stream.read_buf = NULL;
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(
        &session.d18_request_registry);
    if (!mapped) {
        fprintf(stderr,
                "assert failed: PUBLISH_DONE decode OOM did not map to INTERNAL_ERROR\n");
    }
    return mapped ? 0 : -1;
}

static int
xqc_test_publish_done_decode_errors_map_session_error(void)
{
    static const uint8_t malformed_count[] = {
        XQC_MOQ_D18_MSG_PUBLISH_DONE,
        0x00, 0x01,
        XQC_MOQ_PUBLISH_DONE_TRACK_ENDED,
    };
    static const uint8_t excessive_reason_count[] = {
        XQC_MOQ_D18_MSG_PUBLISH_DONE,
        0x00, 0x04,
        XQC_MOQ_PUBLISH_DONE_TRACK_ENDED,
        0x00,
        0x44, 0x01,
    };
    static const uint8_t invalid_utf8[] = {
        XQC_MOQ_D18_MSG_PUBLISH_DONE,
        0x00, 0x04,
        XQC_MOQ_PUBLISH_DONE_TRACK_ENDED,
        0x00,
        0x01, 0xff,
    };
    int failed = 0;
    if (xqc_test_publish_done_invalid_wire_case(
            "Stream Count", malformed_count,
            sizeof(malformed_count)) != 0)
    {
        failed = 1;
    }
    if (xqc_test_publish_done_invalid_wire_case(
            "Reason Phrase Length", excessive_reason_count,
            sizeof(excessive_reason_count)) != 0)
    {
        failed = 1;
    }
    if (xqc_test_publish_done_invalid_wire_case(
            "UTF-8", invalid_utf8,
            sizeof(invalid_utf8)) != 0)
    {
        failed = 1;
    }
    if (xqc_test_publish_done_decode_oom_is_internal_error() != 0) {
        failed = 1;
    }
    return failed ? -1 : 0;
}

typedef struct {
    int count;
    xqc_moq_goaway_scope_t scope;
    uint64_t target_request_id;
    uint64_t timeout_ms;
    uint64_t cutoff;
    size_t uri_len;
    char uri[16];
} xqc_test_goaway_callback_state_t;

static xqc_test_goaway_callback_state_t xqc_test_goaway_callback_state;
static int xqc_test_legacy_goaway_callback_count;
static xqc_moq_session_t *xqc_test_goaway_reentrant_session;
static int xqc_test_goaway_reentrant_legacy_uri_stable;

static void
xqc_test_on_goaway_draft18(
    xqc_moq_user_session_t *user_session, xqc_moq_goaway_scope_t scope,
    uint64_t target_request_id, const char *uri, size_t uri_len,
    uint64_t timeout_ms, uint64_t first_unprocessed_request_id)
{
    (void)user_session;
    xqc_test_goaway_callback_state.count++;
    xqc_test_goaway_callback_state.scope = scope;
    xqc_test_goaway_callback_state.target_request_id = target_request_id;
    xqc_test_goaway_callback_state.timeout_ms = timeout_ms;
    xqc_test_goaway_callback_state.cutoff = first_unprocessed_request_id;
    xqc_test_goaway_callback_state.uri_len = uri_len;
    if (uri != NULL && uri_len <= sizeof(xqc_test_goaway_callback_state.uri)) {
        xqc_memcpy(xqc_test_goaway_callback_state.uri, uri, uri_len);
    }
}

static void
xqc_test_on_legacy_goaway(xqc_moq_user_session_t *user_session,
    const char *uri, size_t uri_len)
{
    (void)user_session;
    (void)uri;
    (void)uri_len;
    xqc_test_legacy_goaway_callback_count++;
}

static void
xqc_test_on_goaway_draft18_invalidate_owned_state(
    xqc_moq_user_session_t *user_session, xqc_moq_goaway_scope_t scope,
    uint64_t target_request_id, const char *uri, size_t uri_len,
    uint64_t timeout_ms, uint64_t first_unprocessed_request_id)
{
    (void)scope;
    (void)target_request_id;
    (void)uri;
    (void)timeout_ms;
    (void)first_unprocessed_request_id;
    if (xqc_test_goaway_reentrant_session != NULL
        && xqc_test_goaway_reentrant_session->goaway_new_session_uri != NULL)
    {
        memset(xqc_test_goaway_reentrant_session->goaway_new_session_uri,
               'X', uri_len);
        xqc_test_goaway_reentrant_session->on_goaway_draft18 = NULL;
    }
    if (user_session != NULL) {
        user_session->session = NULL;
    }
}

static void
xqc_test_on_legacy_goaway_after_reentrant_close(
    xqc_moq_user_session_t *user_session, const char *uri, size_t uri_len)
{
    (void)user_session;
    xqc_test_goaway_reentrant_legacy_uri_stable = uri != NULL
        && uri_len == 4 && memcmp(uri, "next", 4) == 0;
}

static void
xqc_test_init_goaway_control_stream(xqc_moq_stream_t *stream,
    xqc_moq_session_t *session, xqc_test_write_capture_t *capture)
{
    xqc_test_init_stream(stream, session, capture);
    stream->d18_context.direction = XQC_MOQ_D18_DIRECTION_UNI;
    stream->d18_context.stream_class = XQC_MOQ_D18_STREAM_CONTROL;
    stream->d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
}

static void
xqc_test_init_goaway_request_stream(xqc_moq_stream_t *stream,
    xqc_moq_session_t *session, xqc_test_write_capture_t *capture,
    uint64_t request_id, uint8_t local_request)
{
    xqc_test_init_stream(stream, session, capture);
    stream->local_request = local_request;
    stream->peer_request = local_request ? 0 : 1;
    stream->response_received = local_request ? 1 : 0;
    stream->response_sent = local_request ? 0 : 1;
    stream->request_type = XQC_MOQ_MSG_SUBSCRIBE_TRACKS;
    stream->request_id = request_id;
    stream->d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
    stream->d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
    stream->d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    xqc_list_add_tail(&stream->request_list_member,
        local_request ? &session->local_request_stream_list
                      : &session->peer_request_stream_list);
}

static int
xqc_test_goaway_send_scopes_and_atomic_rejections(void)
{
    static const uint8_t expected_control[] = {
        XQC_MOQ_D18_MSG_GOAWAY, 0x00, 0x07,
        0x04, 'n', 'e', 'x', 't', 0x00, 0x06,
    };
    static const uint8_t expected_request[] = {
        XQC_MOQ_D18_MSG_GOAWAY, 0x00, 0x03,
        0x01, 'r', 0x00,
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.session_setup_done = 1;
    xqc_test_write_capture_t ctl_capture = {0};
    xqc_moq_stream_t ctl_stream;
    xqc_test_init_goaway_control_stream(
        &ctl_stream, &session, &ctl_capture);
    session.ctl_stream = &ctl_stream;

    XQC_TEST_ASSERT(xqc_moq_send_session_goaway_draft18(
        &session, "next", 4, 0, 7) == -XQC_EPARAM);
    XQC_TEST_ASSERT(ctl_capture.length == 0);
    XQC_TEST_ASSERT(session.d18_control_goaway_sent == 0);
    XQC_TEST_ASSERT(xqc_moq_send_goaway(&session, NULL, 0)
                    == -XQC_EPARAM);
    XQC_TEST_ASSERT(ctl_capture.length == 0);

    XQC_TEST_ASSERT(xqc_moq_send_session_goaway_draft18(
        &session, "next", 4, 0, 6) == XQC_OK);
    XQC_TEST_ASSERT(ctl_capture.length == sizeof(expected_control));
    XQC_TEST_ASSERT(memcmp(ctl_capture.bytes, expected_control,
                           sizeof(expected_control)) == 0);
    XQC_TEST_ASSERT(session.d18_control_goaway_sent == 1);
    size_t control_len = ctl_capture.length;
    XQC_TEST_ASSERT(xqc_moq_send_session_goaway_draft18(
        &session, NULL, 0, 0, 8) == -XQC_EPARAM);
    XQC_TEST_ASSERT(ctl_capture.length == control_len);

    xqc_test_write_capture_t request_capture = {0};
    xqc_moq_stream_t request_stream;
    xqc_test_init_goaway_request_stream(
        &request_stream, &session, &request_capture, 1, 1);
    XQC_TEST_ASSERT(xqc_moq_send_request_goaway_draft18(
        &session, 1, "r", 1, 0) == XQC_OK);
    XQC_TEST_ASSERT(request_capture.length == sizeof(expected_request));
    XQC_TEST_ASSERT(memcmp(request_capture.bytes, expected_request,
                           sizeof(expected_request)) == 0);
    size_t request_len = request_capture.length;
    XQC_TEST_ASSERT(xqc_moq_send_request_goaway_draft18(
        &session, 1, NULL, 0, 0) == -XQC_EPARAM);
    XQC_TEST_ASSERT(request_capture.length == request_len);
    XQC_TEST_ASSERT(xqc_moq_send_request_goaway_draft18(
        &session, 3, NULL, 0, 0) == -XQC_ESTREAM_NFOUND);

    xqc_test_clean_stream(&request_stream);
    xqc_test_clean_stream(&ctl_stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);

    xqc_test_init_session(&session);
    session.d18_request_registry.local_is_server = 0;
    session.session_setup_done = 1;
    memset(&ctl_capture, 0, sizeof(ctl_capture));
    xqc_test_init_goaway_control_stream(
        &ctl_stream, &session, &ctl_capture);
    session.ctl_stream = &ctl_stream;
    XQC_TEST_ASSERT(xqc_moq_send_session_goaway_draft18(
        &session, "forbidden", 9, 0, 1) == -XQC_EPARAM);
    XQC_TEST_ASSERT(ctl_capture.length == 0);
    XQC_TEST_ASSERT(session.d18_control_goaway_sent == 0);
    xqc_test_clean_stream(&ctl_stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    return 0;
}

static int
xqc_test_goaway_receive_scopes_callbacks_and_duplicates(void)
{
    xqc_connection_t quic_conn;
    xqc_memzero(&quic_conn, sizeof(quic_conn));
    quic_conn.log = &xqc_test_log;
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.d18_request_registry.local_is_server = 0;
    session.session_setup_done = 1;
    session.quic_conn = &quic_conn;
    xqc_moq_user_session_t user_session = {.session = &session};
    session.user_session = &user_session;
    session.session_callbacks.on_goaway = xqc_test_on_legacy_goaway;
    xqc_moq_session_set_goaway_draft18_callback(
        &session, xqc_test_on_goaway_draft18);

    xqc_test_write_capture_t ctl_capture = {0};
    xqc_moq_stream_t ctl_stream;
    xqc_test_init_goaway_control_stream(
        &ctl_stream, &session, &ctl_capture);
    session.peer_ctl_stream = &ctl_stream;
    xqc_moq_d18_goaway_msg_t control = {
        .new_session_uri = "next",
        .new_session_uri_len = 4,
        .timeout_ms = 11,
        .request_id = 0,
        .has_request_id = 1,
    };
    xqc_moq_d18_control_goaway_init_handler(&control.msg_base);
    memset(&xqc_test_goaway_callback_state, 0,
           sizeof(xqc_test_goaway_callback_state));
    xqc_test_legacy_goaway_callback_count = 0;
    xqc_moq_on_goaway_draft18(
        &session, &ctl_stream, &control.msg_base);
    XQC_TEST_ASSERT(quic_conn.conn_err == 0);
    XQC_TEST_ASSERT(session.d18_control_goaway_received == 1);
    XQC_TEST_ASSERT(session.d18_control_goaway_received_cutoff == 0);
    XQC_TEST_ASSERT(session.d18_control_goaway_received_timeout_ms == 11);
    XQC_TEST_ASSERT(xqc_test_goaway_callback_state.count == 1);
    XQC_TEST_ASSERT(xqc_test_goaway_callback_state.scope
                    == XQC_MOQ_GOAWAY_SCOPE_CONTROL);
    XQC_TEST_ASSERT(xqc_test_goaway_callback_state.target_request_id
                    == XQC_MOQ_INVALID_ID);
    XQC_TEST_ASSERT(xqc_test_goaway_callback_state.cutoff == 0);
    XQC_TEST_ASSERT(xqc_test_goaway_callback_state.timeout_ms == 11);
    XQC_TEST_ASSERT(xqc_test_goaway_callback_state.uri_len == 4);
    XQC_TEST_ASSERT(memcmp(xqc_test_goaway_callback_state.uri,
                           "next", 4) == 0);
    XQC_TEST_ASSERT(xqc_test_legacy_goaway_callback_count == 1);

    xqc_moq_on_goaway_draft18(
        &session, &ctl_stream, &control.msg_base);
    XQC_TEST_ASSERT(quic_conn.conn_err
                    == XQC_MOQ_D18_PROTOCOL_VIOLATION);
    XQC_TEST_ASSERT(xqc_test_goaway_callback_state.count == 1);

    xqc_test_clean_stream(&ctl_stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);

    xqc_memzero(&quic_conn, sizeof(quic_conn));
    quic_conn.log = &xqc_test_log;
    xqc_test_init_session(&session);
    session.d18_request_registry.local_is_server = 0;
    session.session_setup_done = 1;
    session.quic_conn = &quic_conn;
    user_session.session = &session;
    session.user_session = &user_session;
    session.session_callbacks.on_goaway = xqc_test_on_legacy_goaway;
    xqc_moq_session_set_goaway_draft18_callback(
        &session, xqc_test_on_goaway_draft18);
    xqc_test_write_capture_t request_capture = {0};
    xqc_moq_stream_t request_stream;
    xqc_test_init_goaway_request_stream(
        &request_stream, &session, &request_capture, 0, 1);
    xqc_moq_d18_goaway_msg_t request = {
        .new_session_uri = "request",
        .new_session_uri_len = 7,
        .timeout_ms = 12,
    };
    xqc_moq_d18_request_goaway_init_handler(&request.msg_base);
    memset(&xqc_test_goaway_callback_state, 0,
           sizeof(xqc_test_goaway_callback_state));
    xqc_test_legacy_goaway_callback_count = 0;
    xqc_moq_on_goaway_draft18(
        &session, &request_stream, &request.msg_base);
    XQC_TEST_ASSERT(quic_conn.conn_err == 0);
    XQC_TEST_ASSERT(request_stream.d18_goaway_received == 1);
    XQC_TEST_ASSERT(request_stream.d18_peer_goaway_timeout_ms == 12);
    XQC_TEST_ASSERT(xqc_test_goaway_callback_state.count == 1);
    XQC_TEST_ASSERT(xqc_test_goaway_callback_state.scope
                    == XQC_MOQ_GOAWAY_SCOPE_REQUEST);
    XQC_TEST_ASSERT(xqc_test_goaway_callback_state.target_request_id == 0);
    XQC_TEST_ASSERT(xqc_test_goaway_callback_state.cutoff
                    == XQC_MOQ_INVALID_ID);
    XQC_TEST_ASSERT(xqc_test_legacy_goaway_callback_count == 0);
    XQC_TEST_ASSERT(request_stream.request_closed_notified == 0);

    xqc_moq_on_goaway_draft18(
        &session, &request_stream, &request.msg_base);
    XQC_TEST_ASSERT(quic_conn.conn_err
                    == XQC_MOQ_D18_PROTOCOL_VIOLATION);
    xqc_test_clean_stream(&request_stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    return 0;
}

static int
xqc_test_goaway_callback_reentrant_close_keeps_later_values_safe(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.d18_request_registry.local_is_server = 0;
    session.session_setup_done = 1;
    xqc_moq_user_session_t user_session = {.session = &session};
    session.user_session = &user_session;
    session.session_callbacks.on_goaway =
        xqc_test_on_legacy_goaway_after_reentrant_close;
    xqc_moq_session_set_goaway_draft18_callback(
        &session, xqc_test_on_goaway_draft18_invalidate_owned_state);
    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_goaway_control_stream(&stream, &session, &capture);
    session.peer_ctl_stream = &stream;
    xqc_moq_d18_goaway_msg_t control = {
        .new_session_uri = "next",
        .new_session_uri_len = 4,
        .request_id = 0,
        .has_request_id = 1,
    };
    xqc_moq_d18_control_goaway_init_handler(&control.msg_base);
    xqc_test_goaway_reentrant_session = &session;
    xqc_test_goaway_reentrant_legacy_uri_stable = 0;

    xqc_moq_on_goaway_draft18(&session, &stream, &control.msg_base);

    XQC_TEST_ASSERT(user_session.session == NULL);
    XQC_TEST_ASSERT(xqc_test_goaway_reentrant_legacy_uri_stable == 1);
    user_session.session = &session;
    xqc_test_goaway_reentrant_session = NULL;
    xqc_test_clean_stream(&stream);
    xqc_free(session.goaway_new_session_uri);
    session.goaway_new_session_uri = NULL;
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    return 0;
}

static int
xqc_test_goaway_receive_rejects_client_uri_and_bad_cutoff(void)
{
    xqc_connection_t quic_conn;
    xqc_memzero(&quic_conn, sizeof(quic_conn));
    quic_conn.log = &xqc_test_log;
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.session_setup_done = 1;
    session.quic_conn = &quic_conn;
    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_goaway_control_stream(&stream, &session, &capture);
    session.peer_ctl_stream = &stream;

    xqc_moq_d18_goaway_msg_t bad_parity = {
        .request_id = 0,
        .has_request_id = 1,
    };
    xqc_moq_d18_control_goaway_init_handler(&bad_parity.msg_base);
    xqc_moq_on_goaway_draft18(
        &session, &stream, &bad_parity.msg_base);
    XQC_TEST_ASSERT(quic_conn.conn_err == XQC_MOQ_D18_INVALID_REQUEST_ID);
    XQC_TEST_ASSERT(session.d18_control_goaway_received == 0);

    quic_conn.conn_err = 0;
    quic_conn.conn_flag = 0;
    quic_conn.conn_close_msg = NULL;
    xqc_moq_d18_goaway_msg_t client_uri = {
        .new_session_uri = "bad",
        .new_session_uri_len = 3,
        .request_id = 1,
        .has_request_id = 1,
    };
    xqc_moq_d18_control_goaway_init_handler(&client_uri.msg_base);
    xqc_moq_on_goaway_draft18(
        &session, &stream, &client_uri.msg_base);
    XQC_TEST_ASSERT(quic_conn.conn_err
                    == XQC_MOQ_D18_PROTOCOL_VIOLATION);
    XQC_TEST_ASSERT(session.d18_control_goaway_received == 0);

    xqc_test_clean_stream(&stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    return 0;
}

static int
xqc_test_goaway_admission_rejects_all_initial_request_families(void)
{
    static const uint8_t expected[] = {
        XQC_MOQ_D18_MSG_REQUEST_ERROR, 0x00, 0x03,
        XQC_MOQ_REQUEST_ERROR_GOING_AWAY, 0x00, 0x00,
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.d18_control_goaway_sent = 1;
    session.d18_control_goaway_cutoff = 6;
    xqc_moq_user_session_t user_session = {.session = &session};
    session.user_session = &user_session;
    session.session_callbacks.on_publish = xqc_test_on_publish_observe;
    session.session_callbacks_ext.on_subscribe_tracks =
        xqc_test_on_subscribe_tracks;
    xqc_test_publish_callback_count = 0;
    xqc_test_subscribe_tracks_callback_count = 0;

    for (size_t i = 0; i < 5; i++) {
        uint64_t request_id = 6 + 2 * i;
        xqc_test_write_capture_t capture = {0};
        xqc_moq_stream_t stream;
        xqc_test_init_stream(&stream, &session, &capture);
        stream.kind = XQC_MOQ_STREAM_D18_REQUEST;
        stream.d18_context.direction = XQC_MOQ_D18_DIRECTION_BIDI;
        stream.d18_context.stream_class = XQC_MOQ_D18_STREAM_REQUEST;
        stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
        switch (i) {
        case 0: {
            xqc_moq_subscribe_msg_t msg = {.subscribe_id = request_id};
            xqc_moq_on_subscribe(&session, &stream, &msg.msg_base);
            break;
        }
        case 1: {
            xqc_moq_publish_msg_t msg = {.subscribe_id = request_id};
            xqc_moq_on_publish(&session, &stream, &msg.msg_base);
            break;
        }
        case 2: {
            xqc_moq_subscribe_tracks_msg_t msg = {.request_id = request_id};
            xqc_moq_on_subscribe_tracks(&session, &stream, &msg.msg_base);
            break;
        }
        case 3: {
            xqc_moq_subscribe_namespace_msg_t msg = {
                .request_id = request_id,
            };
            xqc_moq_on_subscribe_namespace(
                &session, &stream, &msg.msg_base);
            break;
        }
        default: {
            xqc_moq_publish_namespace_msg_t msg = {
                .request_id = request_id,
            };
            xqc_moq_on_publish_namespace(
                &session, &stream, &msg.msg_base);
            break;
        }
        }
        XQC_TEST_ASSERT(capture.length == sizeof(expected));
        XQC_TEST_ASSERT(memcmp(capture.bytes, expected,
                               sizeof(expected)) == 0);
        XQC_TEST_ASSERT(capture.fin == 1);
        XQC_TEST_ASSERT(stream.peer_request == 0);
        XQC_TEST_ASSERT(stream.request_closed_notified == 0);
        XQC_TEST_ASSERT(xqc_moq_session_register_peer_request_id(
            &session, request_id) == XQC_MOQ_D18_REQUEST_ID_OK);
        xqc_test_clean_stream(&stream);
    }
    XQC_TEST_ASSERT(xqc_test_publish_callback_count == 0);
    XQC_TEST_ASSERT(xqc_test_subscribe_tracks_callback_count == 0);
    XQC_TEST_ASSERT(xqc_list_empty(&session.peer_request_stream_list));
    XQC_TEST_ASSERT(xqc_list_empty(&session.peer_subscribe_namespace_list));
    XQC_TEST_ASSERT(xqc_list_empty(&session.peer_advertised_namespace_list));
    XQC_TEST_ASSERT(xqc_list_empty(&session.track_list_for_sub));
    XQC_TEST_ASSERT(xqc_list_empty(&session.local_subscribe_list));
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    return 0;
}

static int
xqc_test_received_control_goaway_refuses_local_initial_writers(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.d18_control_goaway_received = 1;
    uint64_t next_id = session.d18_request_registry.next_local_id;
    xqc_moq_subscribe_msg_t subscribe = {0};
    xqc_moq_publish_msg_t publish = {0};
    xqc_moq_subscribe_tracks_msg_t tracks = {0};
    xqc_moq_subscribe_namespace_msg_t namespace = {0};
    xqc_moq_publish_namespace_msg_t publish_namespace = {0};
    XQC_TEST_ASSERT(xqc_moq_write_subscribe(&session, &subscribe)
                    == -XQC_EPARAM);
    XQC_TEST_ASSERT(xqc_moq_write_publish(&session, &publish)
                    == -XQC_EPARAM);
    XQC_TEST_ASSERT(xqc_moq_write_subscribe_tracks(&session, &tracks)
                    == -XQC_EPARAM);
    XQC_TEST_ASSERT(xqc_moq_write_subscribe_namespace(
        &session, &namespace) == -XQC_EPARAM);
    XQC_TEST_ASSERT(xqc_moq_write_publish_namespace(
        &session, &publish_namespace) == -XQC_EPARAM);
    XQC_TEST_ASSERT(session.d18_request_registry.next_local_id == next_id);
    XQC_TEST_ASSERT(tracks.request_id == 0);
    XQC_TEST_ASSERT(publish_namespace.request_id == 0);
    XQC_TEST_ASSERT(xqc_list_empty(&session.local_request_stream_list));
    XQC_TEST_ASSERT(xqc_list_empty(&session.local_ns_pending_list));
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    return 0;
}

static int
xqc_test_received_control_goaway_refuses_public_subscribe_without_state(void)
{
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    for (int tuple_api = 0; tuple_api < 2; tuple_api++) {
        xqc_moq_session_t session;
        xqc_test_init_session(&session);
        session.d18_control_goaway_received = 1;
        xqc_moq_track_t *track = xqc_moq_track_create_with_ns_tuple(
            &session, &live, 1, "audio", XQC_MOQ_TRACK_AUDIO,
            NULL, XQC_MOQ_CONTAINER_NONE, XQC_MOQ_TRACK_FOR_SUB);
        XQC_TEST_ASSERT(track != NULL);
        uint64_t next_request_id =
            session.d18_request_registry.next_local_id;
        uint64_t next_alias = session.track_alias_allocator;

        xqc_int_t ret = tuple_api
            ? xqc_moq_subscribe_with_ns_tuple(
                &session, &live, 1, "audio",
                XQC_MOQ_FILTER_LAST_GROUP, 0, 0, 0, 0, NULL)
            : xqc_moq_subscribe(
                &session, "live", "audio",
                XQC_MOQ_FILTER_LAST_GROUP, 0, 0, 0, 0, NULL);
        XQC_TEST_ASSERT(ret == -XQC_EPARAM);
        XQC_TEST_ASSERT(session.d18_request_registry.next_local_id
                        == next_request_id);
        XQC_TEST_ASSERT(session.track_alias_allocator == next_alias);
        XQC_TEST_ASSERT(track->subscribe_id == XQC_MOQ_INVALID_ID);
        XQC_TEST_ASSERT(track->track_alias == XQC_MOQ_INVALID_ID);
        XQC_TEST_ASSERT(xqc_list_empty(&session.local_subscribe_list));
        XQC_TEST_ASSERT(xqc_list_empty(&session.local_request_stream_list));

        xqc_list_del_init(&track->list_member);
        xqc_moq_track_destroy(track);
        xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
        xqc_moq_d18_request_registry_destroy(
            &session.d18_request_registry);
    }
    return 0;
}

static int
xqc_test_received_control_goaway_refuses_public_publish_without_state(void)
{
    xqc_moq_track_ns_field_t live = {
        .len = 4,
        .data = (unsigned char *)"live",
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.d18_control_goaway_received = 1;
    xqc_moq_track_t *track = xqc_moq_track_create_with_ns_tuple(
        &session, &live, 1, "audio", XQC_MOQ_TRACK_AUDIO,
        NULL, XQC_MOQ_CONTAINER_NONE, XQC_MOQ_TRACK_FOR_PUB);
    XQC_TEST_ASSERT(track != NULL);
    uint64_t next_request_id = session.d18_request_registry.next_local_id;
    uint64_t next_alias = session.track_alias_allocator;
    xqc_moq_publish_msg_t publish = {
        .track_namespace_num = 1,
        .track_namespace_tuple = &live,
        .track_name = "audio",
        .track_name_len = 5,
    };

    XQC_TEST_ASSERT(xqc_moq_publish(&session, &publish) == -XQC_EPARAM);
    XQC_TEST_ASSERT(session.d18_request_registry.next_local_id
                    == next_request_id);
    XQC_TEST_ASSERT(session.track_alias_allocator == next_alias);
    XQC_TEST_ASSERT(track->subscribe_id == XQC_MOQ_INVALID_ID);
    XQC_TEST_ASSERT(track->track_alias == XQC_MOQ_INVALID_ID);
    XQC_TEST_ASSERT(publish.subscribe_id == 0);
    XQC_TEST_ASSERT(publish.track_alias == 0);
    XQC_TEST_ASSERT(xqc_list_empty(&session.local_subscribe_list));
    XQC_TEST_ASSERT(xqc_list_empty(&session.local_request_stream_list));

    xqc_list_del_init(&track->list_member);
    xqc_moq_track_destroy(track);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    return 0;
}

static int
xqc_test_received_control_goaway_refuses_datachannel_without_track(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.d18_control_goaway_received = 1;
    uint64_t next_request_id = session.d18_request_registry.next_local_id;
    uint64_t next_alias = session.track_alias_allocator;
    xqc_moq_track_t *track = NULL;
    uint64_t request_id = XQC_MOQ_INVALID_ID;

    XQC_TEST_ASSERT(xqc_moq_create_datachannel(
        &session, "live", "dc", &track, &request_id, 0)
        == -XQC_EPARAM);
    XQC_TEST_ASSERT(track == NULL);
    XQC_TEST_ASSERT(request_id == XQC_MOQ_INVALID_ID);
    XQC_TEST_ASSERT(session.d18_request_registry.next_local_id
                    == next_request_id);
    XQC_TEST_ASSERT(session.track_alias_allocator == next_alias);
    XQC_TEST_ASSERT(xqc_list_empty(&session.track_list_for_pub));
    XQC_TEST_ASSERT(xqc_list_empty(&session.local_subscribe_list));
    XQC_TEST_ASSERT(xqc_list_empty(&session.local_request_stream_list));

    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    return 0;
}

static int
xqc_test_goaway_admission_rejects_request_updates_without_mutation(void)
{
    static const uint8_t expected_error[] = {
        XQC_MOQ_D18_MSG_REQUEST_ERROR, 0x00, 0x03,
        XQC_MOQ_REQUEST_ERROR_GOING_AWAY, 0x00, 0x00,
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_goaway_request_stream(
        &stream, &session, &capture, 1, 1);
    session.d18_control_goaway_received = 1;
    uint64_t next_id = session.d18_request_registry.next_local_id;
    xqc_moq_request_update_msg_t local_update = {0};
    XQC_TEST_ASSERT(xqc_moq_write_request_update(
        &session, stream.request_id, &local_update) == -XQC_EPARAM);
    XQC_TEST_ASSERT(local_update.request_id == 0);
    XQC_TEST_ASSERT(session.d18_request_registry.next_local_id == next_id);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_local_update_queue) == NULL);
    XQC_TEST_ASSERT(capture.length == 0);

    xqc_test_clean_stream(&stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);

    xqc_test_init_session(&session);
    memset(&capture, 0, sizeof(capture));
    xqc_test_init_goaway_request_stream(
        &stream, &session, &capture, 4, 0);
    session.d18_control_goaway_sent = 1;
    session.d18_control_goaway_cutoff = 6;
    xqc_moq_request_update_msg_t peer_update = {
        .request_id = 6,
    };
    xqc_test_request_update_callback_count = 0;
    session.on_request_update = xqc_test_on_request_update;
    xqc_moq_on_request_update(&session, &stream, &peer_update.msg_base);
    XQC_TEST_ASSERT(capture.length == sizeof(expected_error));
    XQC_TEST_ASSERT(memcmp(capture.bytes, expected_error,
                           sizeof(expected_error)) == 0);
    XQC_TEST_ASSERT(capture.fin == 0);
    XQC_TEST_ASSERT(stream.response_sent == 1);
    XQC_TEST_ASSERT(stream.request_closed_notified == 0);
    XQC_TEST_ASSERT(xqc_moq_d18_update_queue_peek(
        &stream.d18_peer_update_queue) == NULL);
    XQC_TEST_ASSERT(xqc_test_request_update_callback_count == 0);
    XQC_TEST_ASSERT(xqc_moq_session_register_peer_request_id(
        &session, peer_update.request_id) == XQC_MOQ_D18_REQUEST_ID_OK);

    xqc_test_clean_stream(&stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    return 0;
}

static int
xqc_test_control_goaway_cutoff_preserves_only_earlier_requests(void)
{
    static const uint8_t expected_error[] = {
        XQC_MOQ_D18_MSG_REQUEST_ERROR, 0x00, 0x03,
        XQC_MOQ_REQUEST_ERROR_GOING_AWAY, 0x00, 0x00,
    };
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.session_setup_done = 1;
    xqc_test_write_capture_t ctl_capture = {0};
    xqc_moq_stream_t ctl_stream;
    xqc_test_init_goaway_control_stream(
        &ctl_stream, &session, &ctl_capture);
    session.ctl_stream = &ctl_stream;
    xqc_test_write_capture_t earlier_capture = {0};
    xqc_test_write_capture_t cutoff_capture = {0};
    xqc_moq_stream_t earlier;
    xqc_moq_stream_t cutoff;
    xqc_test_init_goaway_request_stream(
        &earlier, &session, &earlier_capture, 4, 0);
    xqc_test_init_goaway_request_stream(
        &cutoff, &session, &cutoff_capture, 6, 0);

    XQC_TEST_ASSERT(xqc_moq_send_session_goaway_draft18(
        &session, NULL, 0, 0, 6) == -XQC_EPARAM);
    XQC_TEST_ASSERT(ctl_capture.length == 0);
    XQC_TEST_ASSERT(session.d18_control_goaway_sent == 0);
    XQC_TEST_ASSERT(session.d18_control_goaway_cutoff == 0);
    XQC_TEST_ASSERT(earlier.request_closed_notified == 0);
    XQC_TEST_ASSERT(cutoff.request_closed_notified == 0);
    XQC_TEST_ASSERT(earlier_capture.length == 0);
    XQC_TEST_ASSERT(cutoff_capture.length == 0);

    cutoff.response_sent = 0;
    XQC_TEST_ASSERT(xqc_moq_send_session_goaway_draft18(
        &session, NULL, 0, 0, 6) == XQC_OK);
    XQC_TEST_ASSERT(earlier.request_closed_notified == 0);
    XQC_TEST_ASSERT(earlier_capture.length == 0);
    XQC_TEST_ASSERT(cutoff_capture.length == sizeof(expected_error));
    XQC_TEST_ASSERT(memcmp(cutoff_capture.bytes, expected_error,
                           sizeof(expected_error)) == 0);
    XQC_TEST_ASSERT(cutoff_capture.fin == 1);
    XQC_TEST_ASSERT(cutoff.request_closed_notified == 1);

    xqc_test_clean_stream(&cutoff);
    xqc_test_clean_stream(&earlier);
    xqc_test_clean_stream(&ctl_stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    return 0;
}

typedef struct {
    xqc_timer_manager_t *manager;
    xqc_gp_timer_id_t    timer_to_remove;
    xqc_int_t            unregister_ret;
    unsigned             remover_calls;
    unsigned             removed_calls;
} xqc_test_gp_timer_delete_next_ctx_t;

static void
xqc_test_gp_timer_removed_callback(xqc_gp_timer_id_t timer_id,
    xqc_usec_t now, void *user_data)
{
    (void)timer_id;
    (void)now;
    xqc_test_gp_timer_delete_next_ctx_t *ctx = user_data;
    ctx->removed_calls++;
}

static void
xqc_test_gp_timer_remover_callback(xqc_gp_timer_id_t timer_id,
    xqc_usec_t now, void *user_data)
{
    (void)timer_id;
    (void)now;
    xqc_test_gp_timer_delete_next_ctx_t *ctx = user_data;
    ctx->remover_calls++;
    ctx->unregister_ret = xqc_timer_unregister_gp_timer(
        ctx->manager, ctx->timer_to_remove);
}

static int
xqc_test_gp_timer_callback_can_delete_next(void)
{

    xqc_timer_manager_t timers;
    xqc_timer_init(&timers, &xqc_test_log, NULL);
    xqc_test_gp_timer_delete_next_ctx_t ctx = {
        .manager = &timers,
        .unregister_ret = XQC_ERROR,
    };
    xqc_gp_timer_id_t remover_id = xqc_timer_register_gp_timer(
        &timers, "delete_next_remover",
        xqc_test_gp_timer_remover_callback, &ctx);
    XQC_TEST_ASSERT(remover_id >= 0);
    ctx.timer_to_remove = xqc_timer_register_gp_timer(
        &timers, "delete_next_victim",
        xqc_test_gp_timer_removed_callback, &ctx);
    XQC_TEST_ASSERT(ctx.timer_to_remove >= 0);

    xqc_usec_t expires = xqc_monotonic_timestamp() + 1;
    XQC_TEST_ASSERT(xqc_timer_gp_timer_set(
        &timers, remover_id, expires) == XQC_OK);
    XQC_TEST_ASSERT(xqc_timer_gp_timer_set(
        &timers, ctx.timer_to_remove, expires) == XQC_OK);
    xqc_timer_expire(&timers, expires);

    XQC_TEST_ASSERT(ctx.remover_calls == 1);
    XQC_TEST_ASSERT(ctx.removed_calls == 0);
    XQC_TEST_ASSERT(ctx.unregister_ret == XQC_OK);
    XQC_TEST_ASSERT(xqc_timer_unregister_gp_timer(
        &timers, remover_id) == XQC_OK);
    XQC_TEST_ASSERT(xqc_list_empty(&timers.gp_timer_list));
    return 0;
}

static int
xqc_test_goaway_timers_and_teardown(void)
{
    xqc_connection_t quic_conn;
    xqc_memzero(&quic_conn, sizeof(quic_conn));
    quic_conn.log = &xqc_test_log;
    xqc_timer_manager_t timers;
    xqc_timer_init(&timers, &xqc_test_log, NULL);
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.session_setup_done = 1;
    session.quic_conn = &quic_conn;
    session.timer_manager = &timers;
    xqc_test_write_capture_t ctl_capture = {0};
    xqc_moq_stream_t ctl_stream;
    xqc_test_init_goaway_control_stream(
        &ctl_stream, &session, &ctl_capture);
    session.ctl_stream = &ctl_stream;
    xqc_test_write_capture_t active_capture = {0};
    xqc_moq_stream_t active;
    xqc_test_init_goaway_request_stream(
        &active, &session, &active_capture, 4, 0);

    XQC_TEST_ASSERT(xqc_moq_send_session_goaway_draft18(
        &session, NULL, 0, 5, 6) == XQC_OK);
    XQC_TEST_ASSERT(session.d18_control_goaway_timer_registered == 1);
    xqc_bool_t is_set = XQC_FALSE;
    xqc_usec_t expires = 0;
    XQC_TEST_ASSERT(xqc_timer_gp_timer_get_info(
        &timers, session.d18_control_goaway_timer_id,
        &is_set, &expires) == XQC_OK);
    XQC_TEST_ASSERT(is_set == XQC_TRUE);
    xqc_timer_expire(&timers, expires);
    XQC_TEST_ASSERT(quic_conn.conn_err == XQC_MOQ_D18_GOAWAY_TIMEOUT);
    xqc_timer_expire(&timers, expires + 1);
    XQC_TEST_ASSERT(quic_conn.conn_err == XQC_MOQ_D18_GOAWAY_TIMEOUT);

    xqc_test_clean_stream(&active);
    xqc_test_clean_stream(&ctl_stream);
    xqc_moq_session_unregister_goaway_timer(&session);
    XQC_TEST_ASSERT(xqc_list_empty(&timers.gp_timer_list));
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);

    xqc_memzero(&quic_conn, sizeof(quic_conn));
    quic_conn.log = &xqc_test_log;
    xqc_timer_init(&timers, &xqc_test_log, NULL);
    xqc_test_init_session(&session);
    session.session_setup_done = 1;
    session.quic_conn = &quic_conn;
    session.timer_manager = &timers;
    memset(&ctl_capture, 0, sizeof(ctl_capture));
    xqc_test_init_goaway_control_stream(
        &ctl_stream, &session, &ctl_capture);
    session.ctl_stream = &ctl_stream;
    memset(&active_capture, 0, sizeof(active_capture));
    xqc_test_init_goaway_request_stream(
        &active, &session, &active_capture, 4, 0);
    XQC_TEST_ASSERT(xqc_moq_send_session_goaway_draft18(
        &session, NULL, 0, 5, 6) == XQC_OK);
    xqc_moq_stream_finish_request(&active, XQC_MOQ_REQUEST_CANCELLED);
    XQC_TEST_ASSERT(quic_conn.conn_err == 0);
    XQC_TEST_ASSERT(quic_conn.conn_close_msg != NULL);
    XQC_TEST_ASSERT(strcmp(quic_conn.conn_close_msg,
                           "drain complete") == 0);
    XQC_TEST_ASSERT(xqc_timer_gp_timer_get_info(
        &timers, session.d18_control_goaway_timer_id,
        &is_set, &expires) == XQC_OK);
    XQC_TEST_ASSERT(is_set == XQC_FALSE);
    xqc_test_clean_stream(&active);
    xqc_test_clean_stream(&ctl_stream);
    xqc_moq_session_unregister_goaway_timer(&session);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);

    xqc_timer_init(&timers, &xqc_test_log, NULL);
    xqc_test_init_session(&session);
    session.session_setup_done = 1;
    session.timer_manager = &timers;
    memset(&ctl_capture, 0, sizeof(ctl_capture));
    xqc_test_init_goaway_control_stream(
        &ctl_stream, &session, &ctl_capture);
    session.ctl_stream = &ctl_stream;
    xqc_test_write_capture_t request_capture = {0};
    xqc_moq_stream_t *request = xqc_calloc(1, sizeof(*request));
    XQC_TEST_ASSERT(request != NULL);
    xqc_test_init_goaway_request_stream(
        request, &session, &request_capture, 1, 1);
    xqc_moq_d18_update_queue_init(&request->d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&request->d18_peer_update_queue);
    request_capture.cancel_destroys_stream = request;
    XQC_TEST_ASSERT(xqc_moq_send_request_goaway_draft18(
        &session, 1, NULL, 0, 5) == XQC_OK);
    XQC_TEST_ASSERT(request->d18_goaway_timer_registered == 1);
    XQC_TEST_ASSERT(request->request_closed_notified == 0);
    XQC_TEST_ASSERT(xqc_timer_gp_timer_get_info(
        &timers, request->d18_goaway_timer_id,
        &is_set, &expires) == XQC_OK);
    XQC_TEST_ASSERT(is_set == XQC_TRUE);
    xqc_timer_expire(&timers, expires);
    XQC_TEST_ASSERT(request_capture.cancel_count == 1);
    XQC_TEST_ASSERT(request_capture.cancel_error
                    == XQC_MOQ_REQUEST_STREAM_GOING_AWAY);
    XQC_TEST_ASSERT(request_capture.cancel_destroys_stream == NULL);
    XQC_TEST_ASSERT(xqc_list_empty(&timers.gp_timer_list));
    xqc_timer_expire(&timers, expires + 1);
    XQC_TEST_ASSERT(request_capture.cancel_count == 1);
    xqc_test_clean_stream(&ctl_stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    return 0;
}

static xqc_int_t
xqc_test_goaway_decode_emalloc(
    uint8_t *buf, size_t len, uint8_t fin,
    xqc_moq_decode_msg_ctx_t *ctx, xqc_moq_msg_base_t *base,
    xqc_int_t *finish, xqc_int_t *wait_more)
{
    (void)buf;
    (void)len;
    (void)fin;
    (void)ctx;
    (void)base;
    (void)finish;
    (void)wait_more;
    return -XQC_EMALLOC;
}

static int
xqc_test_goaway_decode_errors_map_session_error(void)
{
    static const uint8_t malformed[] = {
        XQC_MOQ_D18_MSG_GOAWAY, 0x00, 0x01, 0x00,
    };
    xqc_connection_t quic_conn;
    xqc_memzero(&quic_conn, sizeof(quic_conn));
    quic_conn.log = &xqc_test_log;
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.session_setup_done = 1;
    session.quic_conn = &quic_conn;
    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_goaway_control_stream(&stream, &session, &capture);
    session.peer_ctl_stream = &stream;
    XQC_TEST_ASSERT(xqc_moq_stream_process(
        &stream, (uint8_t *)malformed, sizeof(malformed), 0) < 0);
    XQC_TEST_ASSERT(quic_conn.conn_err
                    == XQC_MOQ_D18_PROTOCOL_VIOLATION);

    xqc_free(stream.read_buf);
    stream.read_buf = NULL;
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);

    xqc_memzero(&quic_conn, sizeof(quic_conn));
    quic_conn.log = &xqc_test_log;
    xqc_test_init_session(&session);
    session.session_setup_done = 1;
    session.quic_conn = &quic_conn;
    memset(&capture, 0, sizeof(capture));
    xqc_test_init_goaway_control_stream(&stream, &session, &capture);
    session.peer_ctl_stream = &stream;
    stream.d18_message_kind = XQC_MOQ_D18_MESSAGE_GOAWAY;
    stream.decode_msg_ctx.cur_decode_state = XQC_MOQ_DECODE_MSG;
    stream.decode_msg_ctx.cur_msg_type =
        (xqc_moq_msg_type_t)XQC_MOQ_D18_MSG_GOAWAY;
    xqc_moq_d18_goaway_msg_t *goaway = xqc_moq_d18_goaway_create();
    XQC_TEST_ASSERT(goaway != NULL);
    xqc_moq_d18_control_goaway_init_handler(&goaway->msg_base);
    goaway->msg_base.decode = xqc_test_goaway_decode_emalloc;
    stream.decode_msg_ctx.cur_decode_msg = goaway;
    uint8_t byte = 0;
    XQC_TEST_ASSERT(xqc_moq_stream_process(
        &stream, &byte, sizeof(byte), 0) < 0);
    XQC_TEST_ASSERT(quic_conn.conn_err == XQC_MOQ_D18_INTERNAL_ERROR);

    xqc_free(stream.read_buf);
    stream.read_buf = NULL;
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    return 0;
}

static int
xqc_test_goaway_wrong_context_and_zero_timer_are_atomic(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.session_setup_done = 1;
    xqc_test_write_capture_t ctl_capture = {0};
    xqc_moq_stream_t ctl_stream;
    xqc_test_init_goaway_control_stream(
        &ctl_stream, &session, &ctl_capture);
    session.ctl_stream = &ctl_stream;
    ctl_stream.d18_context.position = XQC_MOQ_D18_POSITION_FIRST;
    XQC_TEST_ASSERT(xqc_moq_send_session_goaway_draft18(
        &session, NULL, 0, 0, 6) == -XQC_EILLEGAL_FRAME);
    XQC_TEST_ASSERT(ctl_capture.length == 0);
    XQC_TEST_ASSERT(session.d18_control_goaway_sent == 0);
    XQC_TEST_ASSERT(session.d18_control_goaway_timer_registered == 0);

    ctl_stream.d18_context.position = XQC_MOQ_D18_POSITION_NEXT;
    XQC_TEST_ASSERT(xqc_moq_send_session_goaway_draft18(
        &session, NULL, 0, 5, 6) == -XQC_EPARAM);
    XQC_TEST_ASSERT(ctl_capture.length == 0);
    XQC_TEST_ASSERT(session.d18_control_goaway_sent == 0);
    XQC_TEST_ASSERT(session.d18_control_goaway_timer_registered == 0);

    xqc_timer_manager_t timers;
    xqc_timer_init(&timers, &xqc_test_log, NULL);
    session.timer_manager = &timers;
    XQC_TEST_ASSERT(xqc_moq_send_session_goaway_draft18(
        &session, NULL, 0, UINT64_MAX / 1000, 6) == -XQC_EPARAM);
    XQC_TEST_ASSERT(ctl_capture.length == 0);
    XQC_TEST_ASSERT(session.d18_control_goaway_sent == 0);
    XQC_TEST_ASSERT(session.d18_control_goaway_timer_registered == 0);
    XQC_TEST_ASSERT(xqc_list_empty(&timers.gp_timer_list));
    ctl_capture.fail_write = 1;
    XQC_TEST_ASSERT(xqc_moq_send_session_goaway_draft18(
        &session, NULL, 0, 5, 6) == -XQC_ESYS);
    XQC_TEST_ASSERT(ctl_capture.length == 0);
    XQC_TEST_ASSERT(ctl_stream.write_buf_len == 0);
    XQC_TEST_ASSERT(ctl_stream.write_buf_processed == 0);
    XQC_TEST_ASSERT(session.d18_control_goaway_sent == 0);
    XQC_TEST_ASSERT(session.d18_control_goaway_timer_registered == 0);
    XQC_TEST_ASSERT(xqc_list_empty(&timers.gp_timer_list));
    ctl_capture.fail_write = 0;

    xqc_test_write_capture_t request_capture = {0};
    xqc_moq_stream_t request;
    xqc_test_init_goaway_request_stream(
        &request, &session, &request_capture, 1, 1);
    request.d18_context.position = XQC_MOQ_D18_POSITION_FIRST;
    XQC_TEST_ASSERT(xqc_moq_send_request_goaway_draft18(
        &session, 1, NULL, 0, 0) == -XQC_EILLEGAL_FRAME);
    XQC_TEST_ASSERT(request_capture.length == 0);
    XQC_TEST_ASSERT(request.d18_goaway_sent == 0);
    XQC_TEST_ASSERT(request.d18_goaway_timer_registered == 0);

    xqc_test_clean_stream(&request);
    xqc_test_clean_stream(&ctl_stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    return 0;
}

static int
xqc_test_seed_consumed_writer_buffer(xqc_moq_stream_t *stream,
    size_t size, uint8_t fill)
{
    stream->write_buf = xqc_malloc(size);
    if (stream->write_buf == NULL) {
        return -1;
    }
    memset(stream->write_buf, fill, size);
    stream->write_buf_cap = size;
    stream->write_buf_len = size;
    stream->write_buf_processed = size;
    return 0;
}

static void *
xqc_test_fail_realloc(void *ptr, size_t size)
{
    (void)ptr;
    (void)size;
    return NULL;
}

static int
xqc_test_goaway_writer_hard_failure_is_atomic(void)
{
    enum { old_size = 64 };
    uint8_t expected[old_size];
    memset(expected, 0xa5, sizeof(expected));
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.session_setup_done = 1;

    xqc_test_write_capture_t capture = {.fail_write = 1};
    xqc_moq_stream_t stream;
    xqc_test_init_goaway_control_stream(&stream, &session, &capture);
    XQC_TEST_ASSERT(xqc_test_seed_consumed_writer_buffer(
        &stream, old_size, 0xa5) == 0);
    uint8_t *old_buf = stream.write_buf;
    XQC_TEST_ASSERT(xqc_moq_write_goaway_draft18(
        &session, &stream, NULL, 0, 0, 6, 1) == -XQC_ESYS);
    XQC_TEST_ASSERT(stream.write_buf == old_buf);
    XQC_TEST_ASSERT(stream.write_buf_cap == old_size);
    XQC_TEST_ASSERT(stream.write_buf_len == old_size);
    XQC_TEST_ASSERT(stream.write_buf_processed == old_size);
    XQC_TEST_ASSERT(memcmp(stream.write_buf, expected, old_size) == 0);
    XQC_TEST_ASSERT(stream.write_stream_fin == 0);
    xqc_test_clean_stream(&stream);

    memset(&capture, 0, sizeof(capture));
    capture.fail_write = 1;
    xqc_test_init_goaway_request_stream(
        &stream, &session, &capture, 1, 1);
    XQC_TEST_ASSERT(xqc_test_seed_consumed_writer_buffer(
        &stream, old_size, 0xa5) == 0);
    stream.write_buf_len = 48;
    stream.write_buf_processed = 16;
    old_buf = stream.write_buf;
    XQC_TEST_ASSERT(xqc_moq_write_goaway_draft18(
        &session, &stream, NULL, 0, 0, 1, 0) == -XQC_ESYS);
    XQC_TEST_ASSERT(stream.write_buf == old_buf);
    XQC_TEST_ASSERT(stream.write_buf_cap == old_size);
    XQC_TEST_ASSERT(stream.write_buf_len == 48);
    XQC_TEST_ASSERT(stream.write_buf_processed == 16);
    XQC_TEST_ASSERT(memcmp(stream.write_buf, expected, old_size) == 0);
    XQC_TEST_ASSERT(stream.write_stream_fin == 0);
    xqc_test_clean_stream(&stream);

    memset(&capture, 0, sizeof(capture));
    capture.fail_write = 1;
    xqc_test_init_goaway_request_stream(
        &stream, &session, &capture, 5, 0);
    XQC_TEST_ASSERT(xqc_test_seed_consumed_writer_buffer(
        &stream, old_size, 0xa5) == 0);
    stream.write_buf_len = 48;
    stream.write_buf_processed = 16;
    old_buf = stream.write_buf;
    XQC_TEST_ASSERT(xqc_moq_write_going_away_request_update_error(
        &session, &stream) == -XQC_ESYS);
    XQC_TEST_ASSERT(stream.write_buf == old_buf);
    XQC_TEST_ASSERT(stream.write_buf_cap == old_size);
    XQC_TEST_ASSERT(stream.write_buf_len == 48);
    XQC_TEST_ASSERT(stream.write_buf_processed == 16);
    XQC_TEST_ASSERT(memcmp(stream.write_buf, expected, old_size) == 0);
    XQC_TEST_ASSERT(stream.write_stream_fin == 0);
    xqc_test_clean_stream(&stream);

    memset(&capture, 0, sizeof(capture));
    capture.fail_write = 1;
    xqc_test_init_goaway_request_stream(
        &stream, &session, &capture, 3, 0);
    XQC_TEST_ASSERT(xqc_test_seed_consumed_writer_buffer(
        &stream, old_size, 0xa5) == 0);
    old_buf = stream.write_buf;
    XQC_TEST_ASSERT(xqc_moq_write_going_away_request_error(
        &session, &stream) == -XQC_ESYS);
    XQC_TEST_ASSERT(stream.write_buf == old_buf);
    XQC_TEST_ASSERT(stream.write_buf_cap == old_size);
    XQC_TEST_ASSERT(stream.write_buf_len == old_size);
    XQC_TEST_ASSERT(stream.write_buf_processed == old_size);
    XQC_TEST_ASSERT(memcmp(stream.write_buf, expected, old_size) == 0);
    XQC_TEST_ASSERT(stream.write_stream_fin == 0);
    xqc_test_clean_stream(&stream);

    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    return 0;
}

static int
xqc_test_goaway_reserve_oom_preserves_writer_state(void)
{
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.session_setup_done = 1;
    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_goaway_control_stream(&stream, &session, &capture);
    session.ctl_stream = &stream;
    stream.write_buf = xqc_malloc(8);
    XQC_TEST_ASSERT(stream.write_buf != NULL);
    memset(stream.write_buf, 0xa5, 8);
    uint8_t *old_buf = stream.write_buf;
    size_t old_cap = 8;
    stream.write_buf_cap = old_cap;
    stream.write_buf_len = 1;
    stream.write_buf_processed = 0;
    stream.write_buf_realloc = xqc_test_fail_realloc;

    XQC_TEST_ASSERT(xqc_moq_send_session_goaway_draft18(
        &session, NULL, 0, 0, 6) == -XQC_EMALLOC);
    XQC_TEST_ASSERT(stream.write_buf == old_buf);
    XQC_TEST_ASSERT(stream.write_buf_cap == old_cap);
    XQC_TEST_ASSERT(stream.write_buf_len == 1);
    XQC_TEST_ASSERT(stream.write_buf_processed == 0);
    XQC_TEST_ASSERT(stream.write_buf[0] == 0xa5);
    XQC_TEST_ASSERT(session.d18_control_goaway_sent == 0);
    XQC_TEST_ASSERT(session.d18_control_goaway_timer_registered == 0);

    xqc_test_clean_stream(&stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    return 0;
}

static int
xqc_test_request_goaway_timeout_is_target_isolated(void)
{
    xqc_timer_manager_t timers;
    xqc_timer_init(&timers, &xqc_test_log, NULL);
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.session_setup_done = 1;
    session.timer_manager = &timers;
    xqc_test_write_capture_t target_capture = {0};
    xqc_test_write_capture_t other_capture = {0};
    xqc_moq_stream_t target;
    xqc_moq_stream_t other;
    xqc_test_init_goaway_request_stream(
        &target, &session, &target_capture, 1, 1);
    target_capture.cancel_closes_stream = &target;
    xqc_test_init_goaway_request_stream(
        &other, &session, &other_capture, 3, 1);

    XQC_TEST_ASSERT(xqc_moq_send_request_goaway_draft18(
        &session, 1, NULL, 0, 5) == XQC_OK);
    xqc_bool_t is_set = XQC_FALSE;
    xqc_usec_t expires = 0;
    XQC_TEST_ASSERT(xqc_timer_gp_timer_get_info(
        &timers, target.d18_goaway_timer_id,
        &is_set, &expires) == XQC_OK);
    xqc_timer_expire(&timers, expires);
    XQC_TEST_ASSERT(target_capture.cancel_count == 1);
    XQC_TEST_ASSERT(target.request_closed_notified == 1);
    XQC_TEST_ASSERT(other_capture.cancel_count == 0);
    XQC_TEST_ASSERT(other.request_closed_notified == 0);

    xqc_moq_stream_unregister_goaway_timer(&target);
    xqc_test_clean_stream(&other);
    xqc_test_clean_stream(&target);
    XQC_TEST_ASSERT(xqc_list_empty(&timers.gp_timer_list));
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    return 0;
}

static int
xqc_test_request_goaway_timeout_is_safe_for_reentrant_close(void)
{
    xqc_timer_manager_t timers;
    xqc_timer_init(&timers, &xqc_test_log, NULL);
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.session_setup_done = 1;
    session.timer_manager = &timers;
    xqc_moq_user_session_t user_session = {.session = &session};
    session.user_session = &user_session;
    xqc_moq_session_set_request_cancelled_callback(
        &session, xqc_test_on_request_cancelled_poison_stream);
    xqc_test_write_capture_t capture = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_goaway_request_stream(
        &stream, &session, &capture, 1, 1);
    capture.cancel_closes_stream = &stream;
    XQC_TEST_ASSERT(xqc_moq_send_request_goaway_draft18(
        &session, 1, NULL, 0, 5) == XQC_OK);
    xqc_bool_t is_set = XQC_FALSE;
    xqc_usec_t expires = 0;
    XQC_TEST_ASSERT(xqc_timer_gp_timer_get_info(
        &timers, stream.d18_goaway_timer_id,
        &is_set, &expires) == XQC_OK);
    xqc_test_goaway_timeout_reentrant_stream = &stream;
    xqc_test_goaway_timeout_reentrant_capture = &capture;
    xqc_test_goaway_timeout_callback_order_safe = 0;

    xqc_timer_expire(&timers, expires);

    XQC_TEST_ASSERT(capture.cancel_count == 1);
    XQC_TEST_ASSERT(xqc_test_goaway_timeout_callback_order_safe == 1);
    stream.session = &session;
    stream.trans_stream = &capture;
    xqc_test_goaway_timeout_reentrant_stream = NULL;
    xqc_test_goaway_timeout_reentrant_capture = NULL;
    xqc_moq_stream_unregister_goaway_timer(&stream);
    xqc_test_clean_stream(&stream);
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);
    return 0;
}

static int
xqc_test_goaway_destroy_unregisters_timers(void)
{
    xqc_timer_manager_t timers;
    xqc_timer_init(&timers, &xqc_test_log, NULL);
    xqc_moq_session_t session;
    xqc_test_init_session(&session);
    session.session_setup_done = 1;
    session.timer_manager = &timers;
    xqc_test_write_capture_t request_capture = {0};
    xqc_moq_stream_t *request = xqc_calloc(1, sizeof(*request));
    XQC_TEST_ASSERT(request != NULL);
    xqc_test_init_goaway_request_stream(
        request, &session, &request_capture, 1, 1);
    xqc_moq_d18_update_queue_init(&request->d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&request->d18_peer_update_queue);
    XQC_TEST_ASSERT(xqc_moq_send_request_goaway_draft18(
        &session, 1, NULL, 0, 5) == XQC_OK);
    XQC_TEST_ASSERT(!xqc_list_empty(&timers.gp_timer_list));
    xqc_moq_stream_destroy(request);
    XQC_TEST_ASSERT(xqc_list_empty(&timers.gp_timer_list));
    xqc_moq_d18_auth_cache_destroy(&session.peer_auth_cache);
    xqc_moq_d18_request_registry_destroy(&session.d18_request_registry);

    xqc_timer_init(&timers, &xqc_test_log, NULL);
    xqc_moq_session_t *owned_session =
        xqc_calloc(1, sizeof(*owned_session));
    XQC_TEST_ASSERT(owned_session != NULL);
    xqc_test_init_session(owned_session);
    owned_session->session_setup_done = 1;
    owned_session->timer_manager = &timers;
    xqc_test_write_capture_t ctl_capture = {0};
    xqc_moq_stream_t ctl_stream;
    xqc_test_init_goaway_control_stream(
        &ctl_stream, owned_session, &ctl_capture);
    owned_session->ctl_stream = &ctl_stream;
    xqc_test_write_capture_t active_capture = {0};
    xqc_moq_stream_t active;
    xqc_test_init_goaway_request_stream(
        &active, owned_session, &active_capture, 4, 0);
    XQC_TEST_ASSERT(xqc_moq_send_session_goaway_draft18(
        owned_session, NULL, 0, 5, 6) == XQC_OK);
    XQC_TEST_ASSERT(!xqc_list_empty(&timers.gp_timer_list));
    xqc_list_del_init(&active.request_list_member);
    xqc_moq_session_destroy(owned_session);
    XQC_TEST_ASSERT(xqc_list_empty(&timers.gp_timer_list));
    xqc_test_clean_stream(&active);
    xqc_test_clean_stream(&ctl_stream);
    return 0;
}

int
main(void)
{
    if (xqc_test_goaway_send_scopes_and_atomic_rejections() != 0) {
        return 1;
    }
    if (xqc_test_goaway_receive_scopes_callbacks_and_duplicates() != 0) {
        return 1;
    }
    if (xqc_test_goaway_callback_reentrant_close_keeps_later_values_safe()
        != 0)
    {
        return 1;
    }
    if (xqc_test_goaway_receive_rejects_client_uri_and_bad_cutoff() != 0) {
        return 1;
    }
    if (xqc_test_goaway_admission_rejects_all_initial_request_families()
        != 0)
    {
        return 1;
    }
    if (xqc_test_received_control_goaway_refuses_local_initial_writers()
        != 0)
    {
        return 1;
    }
    if (xqc_test_received_control_goaway_refuses_public_subscribe_without_state()
        != 0)
    {
        return 1;
    }
    if (xqc_test_received_control_goaway_refuses_public_publish_without_state()
        != 0)
    {
        return 1;
    }
    if (xqc_test_received_control_goaway_refuses_datachannel_without_track()
        != 0)
    {
        return 1;
    }
    if (xqc_test_goaway_admission_rejects_request_updates_without_mutation()
        != 0)
    {
        return 1;
    }
    if (xqc_test_control_goaway_cutoff_preserves_only_earlier_requests()
        != 0)
    {
        return 1;
    }
    if (xqc_test_goaway_timers_and_teardown() != 0) {
        return 1;
    }
    if (xqc_test_gp_timer_callback_can_delete_next() != 0) {
        return 1;
    }
    if (xqc_test_goaway_decode_errors_map_session_error() != 0) {
        return 1;
    }
    if (xqc_test_goaway_wrong_context_and_zero_timer_are_atomic() != 0) {
        return 1;
    }
    if (xqc_test_goaway_writer_hard_failure_is_atomic() != 0) {
        return 1;
    }
    if (xqc_test_goaway_reserve_oom_preserves_writer_state()
        != 0)
    {
        return 1;
    }
    if (xqc_test_request_goaway_timeout_is_target_isolated() != 0) {
        return 1;
    }
    if (xqc_test_request_goaway_timeout_is_safe_for_reentrant_close()
        != 0)
    {
        return 1;
    }
    if (xqc_test_goaway_destroy_unregisters_timers() != 0) {
        return 1;
    }
    if (xqc_test_subscribe_tracks_wire_vectors() != 0) {
        return 1;
    }
    if (xqc_test_subscribe_tracks_then_request_update_continuous_decode()
        != 0)
    {
        return 1;
    }
    if (xqc_test_publish_blocked_receive_callback_and_relay() != 0) {
        return 1;
    }
    if (xqc_test_publish_blocked_writer_suffix_and_lifecycle() != 0) {
        return 1;
    }
    if (xqc_test_publish_blocked_invalid_receive_is_protocol_violation()
        != 0)
    {
        return 1;
    }
    if (xqc_test_publish_blocked_invalid_wire_is_protocol_violation()
        != 0)
    {
        return 1;
    }
    if (xqc_test_publish_blocked_decode_oom_is_internal_error() != 0) {
        return 1;
    }
    if (xqc_test_publish_done_create_oom_is_decode_emalloc() != 0) {
        return 1;
    }
    if (xqc_test_publish_done_decode_errors_map_session_error() != 0) {
        return 1;
    }
    if (xqc_test_subscribe_tracks_fragmented_decode() != 0) {
        return 1;
    }
    if (xqc_test_request_update_writer_uses_established_request_stream()
        != 0)
    {
        return 1;
    }
    if (xqc_test_failed_request_update_consumes_id_without_leaking_frame()
        != 0)
    {
        return 1;
    }
    if (xqc_test_publish_reverse_request_update_directions() != 0) {
        return 1;
    }
    if (xqc_test_non_publish_reverse_request_updates_are_rejected() != 0) {
        return 1;
    }
    if (xqc_test_initial_subscribe_tracks_params_are_cloned_and_merged()
        != 0)
    {
        return 1;
    }
    if (xqc_test_incoming_request_update_rejects_duplicate_and_wrong_parity_ids()
        != 0)
    {
        return 1;
    }
    if (xqc_test_request_update_writer_rejects_pending_terminal_and_ineligible()
        != 0)
    {
        return 1;
    }
    if (xqc_test_local_namespace_updates_allow_prefix_absent() != 0) {
        return 1;
    }
    if (xqc_test_peer_namespace_updates_allow_prefix_absent() != 0) {
        return 1;
    }
    if (xqc_test_request_update_callback_view_survives_decode_cleanup()
        != 0)
    {
        return 1;
    }
    if (xqc_test_request_update_callback_view_survives_sync_response()
        != 0)
    {
        return 1;
    }
    if (xqc_test_automatic_update_rejection_responds_to_fifo_head()
        != 0)
    {
        return 1;
    }
    if (xqc_test_terminal_initial_request_rejects_deferred_response()
        != 0)
    {
        return 1;
    }
    if (xqc_test_request_update_receive_registers_id_and_authorizes_before_callback()
        != 0)
    {
        return 1;
    }
    if (xqc_test_request_update_auth_error_responds_to_update_id_before_callback()
        != 0)
    {
        return 1;
    }
    if (xqc_test_request_update_results_consume_local_fifo_and_merge() != 0) {
        return 1;
    }
    if (xqc_test_request_update_responses_require_peer_fifo_head() != 0) {
        return 1;
    }
    if (xqc_test_subscribe_tracks_request_update_swaps_prefix_without_publish_teardown()
        != 0)
    {
        return 1;
    }
    if (xqc_test_subscribe_tracks_update_overlap_excludes_only_own_prefix()
        != 0)
    {
        return 1;
    }
    if (xqc_test_namespace_update_request_error_terminates_state() != 0) {
        return 1;
    }
    if (xqc_test_deferred_namespace_update_rechecks_overlap_before_ok()
        != 0)
    {
        return 1;
    }
    if (xqc_test_namespace_update_overlap_isolated_by_request_type()
        != 0)
    {
        return 1;
    }
    if (xqc_test_local_subscribe_tracks_update_error_terminates_state()
        != 0)
    {
        return 1;
    }
    if (xqc_test_first_update_error_clears_both_queues_and_rejects_residuals()
        != 0)
    {
        return 1;
    }
    if (xqc_test_only_local_publisher_emits_update_failed_publish_done()
        != 0)
    {
        return 1;
    }
    if (xqc_test_peer_subscribe_update_error_cleans_publisher_owner()
        != 0)
    {
        return 1;
    }
    if (xqc_test_update_error_callback_observes_terminal_publish_state()
        != 0)
    {
        return 1;
    }
    if (xqc_test_subscriber_update_error_waits_for_publish_done() != 0) {
        return 1;
    }
    if (xqc_test_peer_publish_update_error_waits_for_publish_done()
        != 0)
    {
        return 1;
    }
    if (xqc_test_peer_publish_received_update_rejection_waits_for_publish_done()
        != 0)
    {
        return 1;
    }
    if (xqc_test_failed_subscription_request_update_preserves_accepted_params()
        != 0)
    {
        return 1;
    }
    if (xqc_test_subscribe_tracks_rejects_wrong_scope() != 0) {
        return 1;
    }
    if (xqc_test_subscribe_tracks_request_lifecycle() != 0) {
        return 1;
    }
    if (xqc_test_subscribe_tracks_application_decides_response() != 0) {
        return 1;
    }
    if (xqc_test_subscribe_tracks_writer_rejects_legacy_session() != 0) {
        return 1;
    }
    if (xqc_test_publish_wire_vectors() != 0) {
        return 1;
    }
    if (xqc_test_outgoing_publish_never_falls_back_to_control_stream() != 0) {
        return 1;
    }
    if (xqc_test_discovered_publish_honors_forward_without_legacy_params() != 0) {
        return 1;
    }
    if (xqc_test_incoming_publish_uses_request_stream_response() != 0) {
        return 1;
    }
    if (xqc_test_incoming_publish_rejects_mandatory_property() != 0) {
        return 1;
    }
    if (xqc_test_incoming_publish_property_session_errors() != 0) {
        return 1;
    }
    if (xqc_test_subscribe_ok_mandatory_property_cancels_subscription()
        != 0)
    {
        return 1;
    }
    if (xqc_test_publish_request_ok_reaches_compatibility_callback() != 0) {
        return 1;
    }
    if (xqc_test_publish_request_error_uses_stream_and_callbacks() != 0) {
        return 1;
    }
    if (xqc_test_incoming_publish_binds_alias_only_after_ok() != 0) {
        return 1;
    }
    if (xqc_test_incoming_publish_error_rolls_back_state() != 0) {
        return 1;
    }
    if (xqc_test_outgoing_publish_error_and_close_roll_back_state() != 0) {
        return 1;
    }
    if (xqc_test_incoming_publish_rejects_duplicate_established_alias() != 0) {
        return 1;
    }
    if (xqc_test_incoming_publish_rejects_duplicate_subscription() != 0) {
        return 1;
    }
    if (xqc_test_publish_done_waits_for_data_fin_acceptance() != 0) {
        return 1;
    }
    if (xqc_test_update_failed_publish_done_retries_after_data_fin_writable()
        != 0)
    {
        return 1;
    }
    if (xqc_test_update_failed_publish_done_data_fin_hard_error_closes_session()
        != 0)
    {
        return 1;
    }
    if (xqc_test_publish_done_retries_request_fin_without_duplicate_bytes()
        != 0)
    {
        return 1;
    }
    if (xqc_test_publish_done_request_writable_hard_error_closes_session()
        != 0)
    {
        return 1;
    }
    if (xqc_test_publish_done_writer_uses_terminal_request_stream() != 0) {
        return 1;
    }
    if (xqc_test_publish_done_writer_rejects_invalid_request_streams()
        != 0)
    {
        return 1;
    }
    if (xqc_test_publish_done_invalid_reason_does_not_poison_snapshot()
        != 0)
    {
        return 1;
    }
    if (xqc_test_publish_done_write_failure_keeps_terminal_state_and_retries()
        != 0)
    {
        return 1;
    }
    if (xqc_test_publish_done_counts_public_datachannel_streams_and_gates_senders()
        != 0)
    {
        return 1;
    }
    if (xqc_test_legacy_datachannel_stream_keeps_unknown_publish_done_count()
        != 0)
    {
        return 1;
    }
    if (xqc_test_d18_stream_type_uses_moq_integer() != 0) {
        return 1;
    }
    if (xqc_test_publish_done_receiver_counts_header_only_stream()
        != 0)
    {
        return 1;
    }
    if (xqc_test_publish_done_receiver_counts_header_before_object_and_rejects_excess()
        != 0)
    {
        return 1;
    }
    if (xqc_test_publish_done_receiver_allows_late_stream_up_to_exact_count()
        != 0)
    {
        return 1;
    }
    if (xqc_test_publish_done_receiver_waits_for_all_exact_streams()
        != 0)
    {
        return 1;
    }
    if (xqc_test_publish_done_receiver_zero_and_unknown_counts() != 0) {
        return 1;
    }
    if (xqc_test_publish_done_receiver_retains_bound_streams_and_rejects_duplicate()
        != 0)
    {
        return 1;
    }
    if (xqc_test_publish_done_detaches_request_stream_track() != 0) {
        return 1;
    }
    if (xqc_test_publish_done_defers_reentrant_session_destroy_until_cleanup()
        != 0)
    {
        return 1;
    }
    if (xqc_test_publish_done_uses_subscribe_stream_request_id() != 0) {
        return 1;
    }
    if (xqc_test_publish_done_cleans_state_when_stream_is_already_terminal()
        != 0)
    {
        return 1;
    }
    if (xqc_test_subscribe_tracks_writer_rejects_bad_local_request_ids() != 0) {
        return 1;
    }
    if (xqc_test_public_session_callbacks_layout_stays_compatible() != 0) {
        return 1;
    }
    return 0;
}
