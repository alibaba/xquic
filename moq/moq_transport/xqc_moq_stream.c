#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_conn.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_int.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_subscribe.h"
#include "moq/moq_transport/xqc_moq_message_handler.h"
#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/xqc_moq_track.h"
#include "moq/moq_transport/xqc_moq_stream_quic.h"
#include "moq/moq_transport/xqc_moq_stream_webtransport.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_control.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_data.h"

#define XQC_MOQ_D18_EARLY_STREAM_BUFFER_LIMIT ((size_t)65545)
#define XQC_MOQ_D18_EARLY_SESSION_BUFFER_LIMIT ((size_t)1048576)

static void xqc_moq_stream_finish_request_internal(
    xqc_moq_stream_t *moq_stream, uint64_t error_code,
    uint8_t notify_cancelled, uint8_t flush_pending_destroy);

xqc_moq_stream_t *
xqc_moq_stream_create(xqc_moq_session_t *session)
{
    if (session == NULL || session->destroying
        || session->destroy_pending)
    {
        return NULL;
    }

    xqc_moq_stream_t *stream = xqc_calloc(1, sizeof(*stream));
    if (stream == NULL) {
        return NULL;
    }
    switch (session->transport_type) {
        case XQC_MOQ_TRANSPORT_QUIC: {
            stream->trans_ops = xqc_moq_quic_stream_ops;
            break;
        }
        /*case XQC_MOQ_TRANSPORT_WEBTRANSPORT: {
            //TODO: WEBTRANSPORT
            stream->trans_ops = xqc_moq_wt_stream_ops;
            break;
        }*/
        default: {
            xqc_log(session->log, XQC_LOG_ERROR, "|transport_type error|");
            goto error;
        }
    }

    stream->session = session;
    stream->kind = XQC_MOQ_STREAM_UNKNOWN;
    stream->d18_context.position = XQC_MOQ_D18_POSITION_FIRST;
    xqc_init_list_head(&stream->list_member);
    xqc_init_list_head(&stream->recv_list_member);
    xqc_init_list_head(&stream->request_list_member);
    xqc_init_list_head(&stream->d18_deferred_list_member);
    xqc_moq_d18_update_queue_init(&stream->d18_local_update_queue);
    xqc_moq_d18_update_queue_init(&stream->d18_peer_update_queue);
    stream->session_lifetime_counted = 1;
    session->active_stream_count++;

    return stream;

error:
    xqc_free(stream);
    return NULL;
}

static void
xqc_moq_stream_clear_local_namespace_subscription(
    xqc_moq_stream_t *stream)
{
    if (stream == NULL || stream->namespace_subscription == NULL) {
        return;
    }

    xqc_moq_namespace_prefix_t *subscription =
        stream->namespace_subscription;
    stream->namespace_subscription = NULL;
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(
        pos, next, &subscription->advertised_namespace_list)
    {
        xqc_moq_namespace_advertisement_t *advertisement =
            xqc_list_entry(pos, xqc_moq_namespace_advertisement_t,
                           list_member);
        xqc_list_del_init(pos);
        if (stream->session != NULL
            && stream->session->session_callbacks_ext.on_namespace_done
                != NULL)
        {
            stream->session->session_callbacks_ext.on_namespace_done(
                stream->session->user_session, stream->request_id,
                advertisement->track_namespace_tuple,
                advertisement->track_namespace_num);
        }
        xqc_moq_namespace_advertisement_destroy(advertisement);
    }
    xqc_moq_namespace_prefix_destroy(subscription);
}

static void
xqc_moq_stream_clear_publish_request(xqc_moq_stream_t *stream)
{
    xqc_moq_session_t *session = stream->session;
    xqc_int_t is_local_subscription =
        stream->peer_request ? 1 : 0;
    xqc_moq_subscribe_t *subscribe =
        xqc_moq_find_subscribe(
            session, stream->request_id, is_local_subscription);
    xqc_moq_track_t *track = stream->track;

    if (track == NULL && subscribe != NULL) {
        xqc_moq_track_role_t role = is_local_subscription
            ? XQC_MOQ_TRACK_FOR_SUB : XQC_MOQ_TRACK_FOR_PUB;
        track = xqc_moq_find_track_by_subscribe_id(
            session, stream->request_id, role);
        if (track == NULL) {
            track = xqc_moq_find_track_by_alias(
                session, subscribe->subscribe_msg->track_alias, role);
        }
    }

    if (track != NULL
        && track->subscribe_id == stream->request_id
        && (!track->publish_done_received
            || xqc_moq_track_publish_done_recv_complete(track)))
    {
        xqc_moq_track_set_subscribe_id(
            track, XQC_MOQ_INVALID_ID);
        xqc_moq_track_set_alias(track, XQC_MOQ_INVALID_ID);
    }

    if (subscribe != NULL) {
        xqc_list_del_init(&subscribe->list_member);
        xqc_moq_subscribe_destroy(subscribe);
    }
    stream->track = NULL;
}

xqc_moq_track_t *
xqc_moq_stream_finish_publish_request(xqc_moq_stream_t *stream)
{
    if (stream == NULL || stream->session == NULL
        || !stream->session->use_unified_setup
        || (!stream->local_request && !stream->peer_request)
        || stream->request_type != XQC_MOQ_MSG_PUBLISH
        || stream->request_closed_notified)
    {
        return NULL;
    }

    xqc_moq_track_t *track = stream->track;
    stream->request_closed_notified = 1;
    xqc_moq_stream_clear_publish_request(stream);
    xqc_moq_d18_update_queue_destroy(
        &stream->d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(
        &stream->d18_peer_update_queue);
    return track;
}

void
xqc_moq_stream_destroy(xqc_moq_stream_t *stream)
{
    xqc_moq_session_t *session = stream->session;
    uint8_t session_lifetime_counted =
        stream->session_lifetime_counted;
    xqc_stream_t *quic_stream = stream->trans_ops.quic_stream(stream->trans_stream);
    xqc_usec_t now = xqc_monotonic_timestamp();

    xqc_moq_stream_unregister_goaway_timer(stream);
    xqc_moq_stream_finish_request_internal(
        stream, xqc_moq_stream_peer_close_error(stream), 1, 0);

    if (stream->fetch_request_stream != NULL
        && stream->fetch_request_stream->fetch_data_stream == stream)
    {
        stream->fetch_request_stream->fetch_data_stream = NULL;
    }
    if (stream->fetch_data_stream != NULL
        && stream->fetch_data_stream->fetch_request_stream == stream)
    {
        stream->fetch_data_stream->fetch_request_stream = NULL;
    }
    stream->fetch_request_stream = NULL;
    stream->fetch_data_stream = NULL;

    if (stream->d18_waiting_for_setup) {
        xqc_list_del_init(&stream->d18_deferred_list_member);
        if (session->d18_deferred_stream_bytes >= stream->read_buf_len) {
            session->d18_deferred_stream_bytes -= stream->read_buf_len;
        } else {
            session->d18_deferred_stream_bytes = 0;
        }
        stream->d18_waiting_for_setup = 0;
    }
    
    if (stream == session->ctl_stream || stream == session->peer_ctl_stream) {
        if (stream == session->ctl_stream) {
            session->ctl_stream = NULL;
        }
        if (stream == session->peer_ctl_stream) {
            session->peer_ctl_stream = NULL;
        }
        /* The control stream MUST NOT be abruptly closed at the underlying transport layer.
         * Doing so results in the session being closed as a 'Protocol Violation'. */
        if (quic_stream->stream_conn->conn_state <= XQC_CONN_STATE_ESTABED) {
            xqc_log(session->log, XQC_LOG_ERROR, "|control stream closed|");
            xqc_moq_session_error(session, MOQ_PROTOCOL_VIOLATION, "control stream closed");
        }
    }
    
    if (stream == session->datachannel.ordered_stream) {
        session->datachannel.ordered_stream = NULL;
        session->datachannel.msg_header_write = 0;
        if (!stream->cancel_write_close && quic_stream->stream_conn->conn_state <= XQC_CONN_STATE_ESTABED) {
            xqc_log(session->log, XQC_LOG_ERROR, "|datachannel stream closed|");
            xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "datachannel stream closed");
        }
    }
    
    if (quic_stream && quic_stream->stream_stats.all_data_acked_time
        && stream->track && stream->track->track_info.track_type == XQC_MOQ_TRACK_VIDEO)
    {
        xqc_usec_t latest_delay = quic_stream->stream_stats.all_data_acked_time - quic_stream->stream_stats.create_time;
        xqc_moq_track_t *track = stream->track;
        xqc_moq_track_info_t *track_info = track ? &track->track_info : NULL;
        xqc_moq_bitrate_alloc_on_frame_acked(session, track, track_info, latest_delay,
                                             quic_stream->stream_stats.create_time, now,
                                             quic_stream->stream_send_offset, stream->seq_num);
    }

    // if stream finished && stream is fec protected type (video or audio)
    if (quic_stream && xqc_is_stream_finished(quic_stream) 
        && (stream->moq_frame_type & (1 << MOQ_VIDEO_FRAME)))
    {
        // calculate current stream close delay and average session close delay
        xqc_record_stream_state(quic_stream);
    }

    if (stream->track && stream->track->subgroup_stream == stream) {
        stream->track->subgroup_stream = NULL;
    }

    xqc_free(stream->read_buf);
    stream->read_buf = NULL;

    xqc_free(stream->write_buf);
    stream->write_buf = NULL;

    xqc_moq_stream_free_cur_decode_msg(stream);
    xqc_moq_d18_update_queue_destroy(&stream->d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(&stream->d18_peer_update_queue);
    xqc_moq_d18_params_free(stream->d18_accepted_params,
                            stream->d18_accepted_params_num);
    stream->d18_accepted_params = NULL;
    stream->d18_accepted_params_num = 0;
    xqc_free(stream->d18_publish_done_reason);
    stream->d18_publish_done_reason = NULL;
    stream->d18_publish_done_reason_len = 0;
    xqc_free(stream->d18_goaway_uri);
    stream->d18_goaway_uri = NULL;
    stream->d18_goaway_uri_len = 0;

    xqc_moq_track_t *retained_track = stream->track;
    xqc_bool_t closed_recv_stream = retained_track != NULL
        && stream->recv_stream_counted
        && !stream->recv_stream_processed;
    xqc_list_del_init(&stream->list_member);
    xqc_list_del_init(&stream->recv_list_member);
    xqc_list_del_init(&stream->request_list_member);

    if (closed_recv_stream
        && xqc_moq_track_on_recv_stream_closed(retained_track))
    {
        stream->recv_stream_processed = 1;
        stream->track = NULL;
        xqc_list_del_init(&retained_track->list_member);
        xqc_moq_track_destroy(retained_track);

    } else if (closed_recv_stream) {
        stream->recv_stream_processed = 1;
    }

    stream->session_lifetime_counted = 0;
    xqc_free(stream);
    if (session_lifetime_counted && session->active_stream_count > 0) {
        session->active_stream_count--;
    }
    xqc_moq_session_destroy_if_pending(session);
}

static xqc_int_t
xqc_moq_stream_is_control(xqc_moq_stream_t *moq_stream)
{
    return moq_stream->session
        && (moq_stream == moq_stream->session->ctl_stream
            || moq_stream == moq_stream->session->peer_ctl_stream);
}

static xqc_int_t
xqc_moq_stream_is_d18(xqc_moq_stream_t *moq_stream)
{
    return moq_stream->session
        && moq_stream->session->use_unified_setup;
}

static xqc_int_t
xqc_moq_stream_decode_d18_type(const uint8_t *buf, size_t buf_len,
    xqc_moq_msg_type_t *msg_type, xqc_int_t *wait_more_data)
{
    uint64_t wire_type = 0;
    int ret = xqc_moq_d18_int_read(buf, buf + buf_len, &wire_type);
    if (ret < 0) {
        *wait_more_data = 1;
        return 0;
    }
    *msg_type = (xqc_moq_msg_type_t)wire_type;
    *wait_more_data = 0;
    return ret;
}

static xqc_moq_stream_kind_t
xqc_moq_stream_kind_from_d18_class(
    xqc_moq_d18_stream_class_t stream_class)
{
    switch (stream_class) {
    case XQC_MOQ_D18_STREAM_CONTROL:
        return XQC_MOQ_STREAM_CONTROL;
    case XQC_MOQ_D18_STREAM_REQUEST:
        return XQC_MOQ_STREAM_D18_REQUEST;
    case XQC_MOQ_D18_STREAM_SUBGROUP:
        return XQC_MOQ_STREAM_D18_SUBGROUP;
    case XQC_MOQ_D18_STREAM_FETCH:
        return XQC_MOQ_STREAM_D18_FETCH;
    default:
        return XQC_MOQ_STREAM_UNKNOWN;
    }
}

static xqc_moq_stream_kind_t
xqc_moq_stream_effective_kind(const xqc_moq_stream_t *stream)
{
    if (stream->session != NULL
        && stream->session->use_unified_setup)
    {
        const xqc_moq_d18_stream_context_t *context =
            stream->d18_context_pending
            ? &stream->d18_pending_context : &stream->d18_context;
        xqc_moq_stream_kind_t kind =
            xqc_moq_stream_kind_from_d18_class(context->stream_class);
        if (kind != XQC_MOQ_STREAM_UNKNOWN) {
            return kind;
        }
    }
    return stream->kind;
}

static void
xqc_moq_stream_commit_d18_read(xqc_moq_stream_t *stream)
{
    if (!xqc_moq_stream_is_d18(stream)
        || !stream->d18_context_pending)
    {
        return;
    }

    xqc_moq_d18_stream_commit_message(&stream->d18_pending_context);
    stream->d18_context = stream->d18_pending_context;
    stream->kind = xqc_moq_stream_kind_from_d18_class(
        stream->d18_context.stream_class);
    stream->d18_context_pending = 0;
}

static xqc_int_t
xqc_moq_stream_d18_request_established(const xqc_moq_stream_t *stream)
{
    return (stream->local_request && stream->response_received)
        || (stream->peer_request && stream->response_sent);
}

static xqc_int_t
xqc_moq_stream_d18_update_context(const xqc_moq_stream_t *stream,
    xqc_moq_d18_param_context_t *context)
{
    if (context == NULL) {
        return 0;
    }
    switch (stream->request_type) {
    case XQC_MOQ_MSG_SUBSCRIBE:
    case XQC_MOQ_MSG_PUBLISH:
        *context = XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_SUBSCRIBE;
        return 1;
    case XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE:
    case XQC_MOQ_MSG_SUBSCRIBE_TRACKS:
    case XQC_MOQ_MSG_PUBLISH_NAMESPACE:
        *context = XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_NAMESPACE;
        return 1;
    default:
        if (stream->request_type
            == (xqc_moq_msg_type_t)XQC_MOQ_D18_MSG_FETCH)
        {
            *context = XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_FETCH;
            return 1;
        }
        return 0;
    }
}

static xqc_int_t
xqc_moq_stream_d18_control_kind_allowed(const xqc_moq_stream_t *stream)
{
    switch (stream->d18_message_kind) {
    case XQC_MOQ_D18_MESSAGE_REQUEST_UPDATE: {
        xqc_moq_d18_param_context_t context;
        return stream->d18_context.position
                == XQC_MOQ_D18_POSITION_NEXT
            && stream->d18_context.stream_class
                == XQC_MOQ_D18_STREAM_REQUEST
            && xqc_moq_stream_d18_request_established(stream)
            && xqc_moq_stream_d18_update_context(stream, &context);
    }
    case XQC_MOQ_D18_MESSAGE_PUBLISH_BLOCKED:
        return stream->d18_context.position
                == XQC_MOQ_D18_POSITION_NEXT
            && stream->d18_context.stream_class
                == XQC_MOQ_D18_STREAM_REQUEST
            && stream->request_type == XQC_MOQ_MSG_SUBSCRIBE_TRACKS
            && stream->local_request && stream->response_received;
    case XQC_MOQ_D18_MESSAGE_PUBLISH_DONE:
        return stream->d18_context.position
                == XQC_MOQ_D18_POSITION_NEXT
            && stream->d18_context.stream_class
                == XQC_MOQ_D18_STREAM_REQUEST
            && !stream->request_closed_notified
            && ((stream->request_type == XQC_MOQ_MSG_PUBLISH
                 && stream->peer_request && stream->response_sent)
                || (stream->request_type == XQC_MOQ_MSG_SUBSCRIBE
                    && stream->local_request
                    && stream->response_received));
    case XQC_MOQ_D18_MESSAGE_GOAWAY:
        return stream->d18_context.position
                == XQC_MOQ_D18_POSITION_NEXT
            && (stream->d18_context.stream_class
                == XQC_MOQ_D18_STREAM_CONTROL
            || stream->d18_context.stream_class
                == XQC_MOQ_D18_STREAM_REQUEST);
    default:
        return 1;
    }
}

xqc_int_t
xqc_moq_stream_classify_d18_control_alloc_failure(
    const xqc_moq_stream_t *stream)
{
    if (stream == NULL || stream->session == NULL
        || !stream->session->use_unified_setup)
    {
        return XQC_OK;
    }

    switch (stream->d18_message_kind) {
    case XQC_MOQ_D18_MESSAGE_REQUEST_UPDATE:
    case XQC_MOQ_D18_MESSAGE_PUBLISH_BLOCKED:
    case XQC_MOQ_D18_MESSAGE_PUBLISH_DONE:
    case XQC_MOQ_D18_MESSAGE_GOAWAY:
        return xqc_moq_stream_d18_control_kind_allowed(stream)
            ? -XQC_EMALLOC
            : XQC_OK;
    default:
        return XQC_OK;
    }
}

static void *
xqc_moq_stream_create_d18_control_msg(xqc_moq_stream_t *stream)
{
    if (!xqc_moq_stream_d18_control_kind_allowed(stream)) {
        return NULL;
    }

    switch (stream->d18_message_kind) {
    case XQC_MOQ_D18_MESSAGE_REQUEST_UPDATE: {
        xqc_moq_d18_param_context_t context;
        if (!xqc_moq_stream_d18_update_context(stream, &context)) {
            return NULL;
        }
        xqc_moq_request_update_msg_t *msg =
            xqc_moq_d18_request_update_create();
        if (msg != NULL) {
            xqc_moq_d18_request_update_init_handler(
                &msg->msg_base, context);
        }
        return msg;
    }
    case XQC_MOQ_D18_MESSAGE_PUBLISH_BLOCKED:
        return xqc_moq_d18_publish_blocked_create();
    case XQC_MOQ_D18_MESSAGE_PUBLISH_DONE:
        return xqc_moq_d18_publish_done_create();
    case XQC_MOQ_D18_MESSAGE_GOAWAY: {
        xqc_moq_d18_goaway_msg_t *msg = xqc_moq_d18_goaway_create();
        if (msg != NULL
            && stream->d18_context.stream_class
                == XQC_MOQ_D18_STREAM_CONTROL)
        {
            xqc_moq_d18_control_goaway_init_handler(&msg->msg_base);
        }
        return msg;
    }
    default:
        return NULL;
    }
}

static void
xqc_moq_stream_free_d18_control_msg(xqc_moq_stream_t *stream)
{
    void *msg = stream->decode_msg_ctx.cur_decode_msg;
    switch (stream->d18_message_kind) {
    case XQC_MOQ_D18_MESSAGE_REQUEST_UPDATE:
        xqc_moq_d18_request_update_free(msg);
        break;
    case XQC_MOQ_D18_MESSAGE_PUBLISH_BLOCKED:
        xqc_moq_d18_publish_blocked_free(msg);
        break;
    case XQC_MOQ_D18_MESSAGE_PUBLISH_DONE:
        xqc_moq_d18_publish_done_free(msg);
        break;
    case XQC_MOQ_D18_MESSAGE_GOAWAY:
        xqc_moq_d18_goaway_free(msg);
        break;
    default:
        break;
    }
    stream->decode_msg_ctx.cur_decode_msg = NULL;
}

xqc_moq_stream_t *
xqc_moq_stream_create_with_transport(xqc_moq_session_t *session, xqc_stream_direction_t direction)
{
    xqc_moq_stream_t *moq_stream;
    moq_stream = xqc_moq_stream_create(session);
    if (moq_stream == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|create moq stream error|");
        return NULL;
    }

    moq_stream->d18_context.direction =
        direction == XQC_STREAM_UNI
        ? XQC_MOQ_D18_DIRECTION_UNI
        : XQC_MOQ_D18_DIRECTION_BIDI;
    moq_stream->trans_stream = moq_stream->trans_ops.create(session->trans_conn, direction, moq_stream);
    if (moq_stream->trans_stream == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|create transport stream error|direction:%d|", direction);
        goto error;
    }

    return moq_stream;

error:
    xqc_moq_stream_destroy(moq_stream);
    return NULL;
}

xqc_int_t
xqc_moq_stream_close(xqc_moq_stream_t *moq_stream)
{
    return moq_stream->trans_ops.close(moq_stream->trans_stream);
}

xqc_int_t
xqc_moq_stream_cancel(xqc_moq_stream_t *moq_stream, uint64_t err_code)
{
    if (moq_stream == NULL || moq_stream->trans_stream == NULL
        || moq_stream->trans_ops.cancel == NULL)
    {
        return -XQC_EPARAM;
    }

    return moq_stream->trans_ops.cancel(moq_stream->trans_stream, err_code);
}

xqc_int_t
xqc_moq_stream_stop_sending(xqc_moq_stream_t *moq_stream, uint64_t err_code)
{
    if (moq_stream == NULL || moq_stream->trans_stream == NULL
        || moq_stream->trans_ops.stop_sending == NULL)
    {
        return -XQC_EPARAM;
    }

    return moq_stream->trans_ops.stop_sending(moq_stream->trans_stream, err_code);
}

static xqc_int_t
xqc_moq_stream_commit_d18_setup_write(xqc_moq_stream_t *moq_stream)
{
    if (!moq_stream->d18_setup_write_pending
        || moq_stream->write_buf_processed != moq_stream->write_buf_len)
    {
        return XQC_OK;
    }

    xqc_moq_d18_stream_context_t next = moq_stream->d18_context;
    xqc_moq_d18_message_desc_t desc;
    if (xqc_moq_d18_stream_resolve(
            &next, XQC_MOQ_D18_MSG_SETUP, &desc)
            != XQC_MOQ_D18_REGISTRY_OK
        || desc.kind != XQC_MOQ_D18_MESSAGE_SETUP
        || desc.stream_class != XQC_MOQ_D18_STREAM_CONTROL)
    {
        return -XQC_EILLEGAL_FRAME;
    }

    xqc_moq_d18_stream_commit_message(&next);
    moq_stream->d18_context = next;
    moq_stream->kind = XQC_MOQ_STREAM_CONTROL;
    moq_stream->d18_setup_write_pending = 0;
    return XQC_OK;
}

xqc_int_t
xqc_moq_stream_write(xqc_moq_stream_t *moq_stream)
{
    xqc_int_t   ret;
    uint8_t     fin_was_submitted;
    uint8_t     pending_d18_publish_done;
    
    ret = 0;
    fin_was_submitted = moq_stream->write_fin_submitted;
    pending_d18_publish_done =
        moq_stream->session != NULL
        && moq_stream->session->use_unified_setup
        && moq_stream->d18_context.direction
            == XQC_MOQ_D18_DIRECTION_BIDI
        && moq_stream->d18_context.stream_class
            == XQC_MOQ_D18_STREAM_REQUEST
        && moq_stream->d18_publish_done_pending;
    if (pending_d18_publish_done
        && moq_stream->session->quic_conn != NULL
        && ((moq_stream->session->quic_conn->conn_flag
                & XQC_CONN_FLAG_ERROR) != 0
            || moq_stream->session->quic_conn->conn_state
                >= XQC_CONN_STATE_CLOSING))
    {
        return XQC_OK;
    }

    // FEC initiation
    if (moq_stream->enable_fec) {
        xqc_init_quic_fec(moq_stream);
    }

    ret = moq_stream->trans_ops.write(moq_stream->trans_stream,
                                      moq_stream->write_buf + moq_stream->write_buf_processed,
                                      moq_stream->write_buf_len - moq_stream->write_buf_processed,
                                      moq_stream->write_stream_fin);
    if (ret == -XQC_EAGAIN) {
        return XQC_OK;
    } else if (ret < 0) {
        if (pending_d18_publish_done) {
            if (moq_stream->session->quic_conn != NULL) {
                xqc_moq_session_error(
                    moq_stream->session,
                    XQC_MOQ_D18_INTERNAL_ERROR,
                    moq_stream->d18_publish_done_status
                            == XQC_MOQ_PUBLISH_DONE_UPDATE_FAILED
                        ? "write UPDATE_FAILED PUBLISH_DONE"
                        : "write PUBLISH_DONE");
            }

        } else {
            xqc_moq_fail_d18_publish_done_after_data_write(
                moq_stream);
        }
        return ret;
    } else {
        moq_stream->write_buf_processed += ret;
        if (moq_stream->write_stream_fin
            && moq_stream->write_buf_processed
                == moq_stream->write_buf_len)
        {
            moq_stream->write_fin_submitted = 1;
        }
    }
    if (moq_stream->d18_publish_done_pending
        && moq_stream->d18_publish_done_encoded
        && moq_stream->write_fin_submitted)
    {
        uint64_t status = moq_stream->d18_publish_done_status;
        moq_stream->d18_publish_done_pending = 0;
        moq_stream->d18_publish_done_encoded = 0;
        xqc_free(moq_stream->d18_publish_done_reason);
        moq_stream->d18_publish_done_reason = NULL;
        moq_stream->d18_publish_done_reason_len = 0;
        xqc_moq_stream_finish_request(moq_stream, status);
    }
    if (!fin_was_submitted && moq_stream->write_fin_submitted) {
        ret = xqc_moq_retry_d18_publish_done_after_data_fin(
            moq_stream);
        if (ret != XQC_OK) {
            return ret;
        }
    }
    return xqc_moq_stream_commit_d18_setup_write(moq_stream);
}

void
xqc_moq_stream_on_track_write(xqc_moq_stream_t *moq_stream, xqc_moq_track_t *track,
    uint64_t group_id, uint64_t object_id, uint64_t seq_num)
{
    moq_stream->track = track;
    moq_stream->group_id = group_id;
    moq_stream->object_id = object_id;
    moq_stream->seq_num = seq_num;
}

static void *
xqc_moq_stream_get_or_alloc_cur_decode_msg_internal(
    xqc_moq_stream_t *moq_stream, xqc_int_t *error)
{
    if (error != NULL) {
        *error = XQC_OK;
    }
    if (moq_stream->decode_msg_ctx.cur_decode_msg) {
        return moq_stream->decode_msg_ctx.cur_decode_msg;
    }
    if (moq_stream->decode_codec == NULL
        && xqc_moq_stream_is_d18(moq_stream)
        && !xqc_moq_stream_d18_control_kind_allowed(moq_stream))
    {
        if (error != NULL) {
            *error = -XQC_EALPN_NOT_SUPPORTED;
        }
        return NULL;
    }

    uint64_t type = moq_stream->decode_msg_ctx.cur_msg_type;
    xqc_moq_stream_kind_t stream_kind;
    if (xqc_moq_stream_is_d18(moq_stream)) {
        stream_kind = xqc_moq_stream_effective_kind(moq_stream);

    } else {
        moq_stream->kind = xqc_moq_profile_classify_stream(
            moq_stream->session->profile, moq_stream->kind, type);
        stream_kind = moq_stream->kind;
    }

    const xqc_moq_message_codec_entry_t *codec =
        moq_stream->decode_codec;
    if (codec == NULL) {
        codec = xqc_moq_profile_find_codec(
            moq_stream->session->profile, stream_kind, type);
    }
    if (codec == NULL) {
        if (error != NULL) {
            *error = -XQC_EALPN_NOT_SUPPORTED;
        }
        return NULL;
    }

    void *msg = NULL;
    xqc_int_t ret = xqc_moq_msg_create_with_codec(
        moq_stream->session, stream_kind, type, codec, &msg);
    if (ret != XQC_OK)
    {
        if (error != NULL) {
            *error = ret;
        }
        return NULL;
    }
    moq_stream->decode_codec = codec;
    if (stream_kind != XQC_MOQ_STREAM_CONTROL
        && (ret = xqc_moq_profile_prepare_data_message(
                moq_stream, codec, (xqc_moq_msg_base_t *)msg)) != XQC_OK)
    {
        xqc_moq_msg_free_with_codec(codec, msg);
        moq_stream->decode_codec = NULL;
        if (error != NULL) {
            *error = ret;
        }
        return NULL;
    }

    moq_stream->decode_msg_ctx.cur_decode_msg = msg;
    return msg;
}

void *
xqc_moq_stream_get_or_alloc_cur_decode_msg(xqc_moq_stream_t *moq_stream)
{
    return xqc_moq_stream_get_or_alloc_cur_decode_msg_internal(
        moq_stream, NULL);
}

void
xqc_moq_stream_free_cur_decode_msg(xqc_moq_stream_t *moq_stream)
{
    xqc_moq_msg_free_with_codec(
        moq_stream->decode_codec,
        moq_stream->decode_msg_ctx.cur_decode_msg);
    moq_stream->decode_msg_ctx.cur_decode_msg = NULL;
}

void
xqc_moq_stream_clean_decode_msg_ctx(xqc_moq_stream_t *moq_stream)
{
    xqc_moq_stream_free_cur_decode_msg(moq_stream);
    xqc_moq_decode_msg_ctx_reset(&moq_stream->decode_msg_ctx);
    moq_stream->decode_codec = NULL;
    moq_stream->d18_context_pending = 0;
    moq_stream->d18_message_kind = XQC_MOQ_D18_MESSAGE_NONE;
}

static void
xqc_moq_session_ensure_deferred_stream_list(xqc_moq_session_t *session)
{
    if (session->d18_deferred_stream_list.next == NULL
        && session->d18_deferred_stream_list.prev == NULL)
    {
        xqc_init_list_head(&session->d18_deferred_stream_list);
    }
}

static xqc_int_t
xqc_moq_stream_defer_until_setup(xqc_moq_stream_t *stream,
    const uint8_t *buf, size_t buf_len, uint8_t fin)
{
    xqc_moq_session_t *session = stream->session;
    if (buf_len > XQC_MOQ_D18_EARLY_STREAM_BUFFER_LIMIT
                    - stream->read_buf_len
        || buf_len > XQC_MOQ_D18_EARLY_SESSION_BUFFER_LIMIT
                    - session->d18_deferred_stream_bytes)
    {
        return -XQC_ELIMIT;
    }

    size_t new_len = stream->read_buf_len + buf_len;
    if (new_len > stream->read_buf_cap) {
        uint8_t *new_buf = xqc_realloc(stream->read_buf, new_len);
        if (new_buf == NULL) {
            return -XQC_EMALLOC;
        }
        stream->read_buf = new_buf;
        stream->read_buf_cap = new_len;
    }
    if (buf_len > 0) {
        xqc_memcpy(stream->read_buf + stream->read_buf_len, buf, buf_len);
    }
    stream->read_buf_len = new_len;
    session->d18_deferred_stream_bytes += buf_len;
    stream->d18_deferred_fin |= fin ? 1 : 0;

    if (!stream->d18_waiting_for_setup) {
        xqc_moq_session_ensure_deferred_stream_list(session);
        xqc_list_add_tail(&stream->d18_deferred_list_member,
                          &session->d18_deferred_stream_list);
        stream->d18_waiting_for_setup = 1;
    }
    xqc_log(session->log, XQC_LOG_DEBUG,
            "|defer draft-18 stream until SETUP|bytes:%uz|fin:%d|",
            stream->read_buf_len, stream->d18_deferred_fin);
    return (xqc_int_t)buf_len;
}

xqc_int_t
xqc_moq_session_resume_deferred_streams(xqc_moq_session_t *session)
{
    if (session == NULL || !session->use_unified_setup
        || session->profile_state != XQC_MOQ_PROFILE_ACTIVE)
    {
        return -XQC_EVERSION;
    }

    xqc_moq_session_ensure_deferred_stream_list(session);
    while (!xqc_list_empty(&session->d18_deferred_stream_list)) {
        xqc_list_head_t *member = session->d18_deferred_stream_list.next;
        xqc_moq_stream_t *stream = xqc_list_entry(
            member, xqc_moq_stream_t, d18_deferred_list_member);
        xqc_list_del_init(member);

        uint8_t *deferred_buf = stream->read_buf;
        size_t deferred_len = stream->read_buf_len;
        uint8_t deferred_fin = stream->d18_deferred_fin;
        stream->read_buf = NULL;
        stream->read_buf_cap = 0;
        stream->read_buf_len = 0;
        stream->read_buf_processed = 0;
        stream->d18_waiting_for_setup = 0;
        stream->d18_deferred_fin = 0;
        if (session->d18_deferred_stream_bytes >= deferred_len) {
            session->d18_deferred_stream_bytes -= deferred_len;
        } else {
            session->d18_deferred_stream_bytes = 0;
        }

        xqc_int_t ret = xqc_moq_stream_process(
            stream, deferred_buf, deferred_len, deferred_fin);
        xqc_free(deferred_buf);
        if (ret < 0) {
            return ret;
        }
    }
    return XQC_OK;
}

//return processed or error
xqc_int_t
xqc_moq_stream_process(xqc_moq_stream_t *moq_stream, uint8_t *buf, size_t buf_len, uint8_t fin)
{
    if (moq_stream == NULL || moq_stream->session == NULL
        || (buf_len > 0 && buf == NULL))
    {
        return -XQC_EPARAM;
    }
    if (moq_stream->session->use_unified_setup
        && moq_stream->session->profile_state
            == XQC_MOQ_PROFILE_ALPN_SELECTED
        && moq_stream->d18_context.direction
            == XQC_MOQ_D18_DIRECTION_BIDI)
    {
        return xqc_moq_stream_defer_until_setup(
            moq_stream, buf, buf_len, fin);
    }

    xqc_int_t stop = 0;
    xqc_moq_msg_type_t msg_type = 0xFF;
    xqc_int_t remained = moq_stream->remain_read_buf_len;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_int_t msg_finish = 0;
    xqc_int_t wait_more_data = 0;
    if (moq_stream->remain_read_buf_len + buf_len > moq_stream->read_buf_cap) {
        moq_stream->read_buf_cap = moq_stream->remain_read_buf_len + buf_len;
        moq_stream->read_buf = xqc_realloc(moq_stream->read_buf, moq_stream->read_buf_cap);
    }
    if (moq_stream->remain_read_buf_len > 0) {
        moq_stream->read_buf_len = moq_stream->remain_read_buf_len + buf_len;
        xqc_memcpy(moq_stream->read_buf, moq_stream->remain_read_buf, moq_stream->remain_read_buf_len);
        xqc_memcpy(moq_stream->read_buf + moq_stream->remain_read_buf_len, buf, buf_len);
        moq_stream->remain_read_buf_len = 0;
    } else {
        moq_stream->read_buf_len = buf_len;
        xqc_memcpy(moq_stream->read_buf, buf, buf_len);
    }
    moq_stream->read_buf_processed = 0;

    /* A FETCH data stream may end with a FIN-only frame after its last Object.
     * The prior Object may leave an empty decoder pre-created for the next
     * record.  No buffered bytes and no decoded fields is a clean record
     * boundary, not a truncated record. */
    if (fin && moq_stream->read_buf_len == 0
        && moq_stream->decode_msg_ctx.cur_field_idx == 0
        && moq_stream->fetch_request_stream != NULL)
    {
        xqc_moq_stream_clean_decode_msg_ctx(moq_stream);
        moq_stream->peer_fin_received = 1;
        xqc_moq_stream_finish_request(moq_stream, XQC_OK);
        return 0;
    }

    do {
        switch (moq_stream->decode_msg_ctx.cur_decode_state) {
            case XQC_MOQ_DECODE_MSG_TYPE:
                if (moq_stream->session->use_unified_setup) {
                    ret = xqc_moq_stream_decode_d18_type(
                        moq_stream->read_buf + moq_stream->read_buf_processed,
                        moq_stream->read_buf_len - moq_stream->read_buf_processed,
                        &msg_type, &wait_more_data);
                } else {
                    ret = xqc_moq_msg_decode_type(
                        moq_stream->read_buf + moq_stream->read_buf_processed,
                        moq_stream->read_buf_len - moq_stream->read_buf_processed,
                        &msg_type, &wait_more_data);
                }
                if (ret < 0) {
                    xqc_log(moq_stream->session->log, XQC_LOG_ERROR,
                            "|decode message type error|ret:%d|", ret);
                    return ret;
                }
                moq_stream->read_buf_processed += ret;
                processed += ret;

                xqc_log(moq_stream->session->log, XQC_LOG_DEBUG,
                        "|decode message type|ret:%d|msg_type:0x%xi|wait_more_data:%d|processed:%d|",
                        ret, msg_type, wait_more_data, processed);

                if (wait_more_data == 1) {
                    stop = 1;
                    break;
                }

                if (xqc_moq_stream_is_d18(moq_stream)) {
                    xqc_moq_d18_message_desc_t desc;
                    xqc_moq_d18_stream_context_t next_context =
                        moq_stream->d18_context;
                    ret = xqc_moq_d18_stream_resolve(
                        &next_context, msg_type, &desc);
                    if (ret != XQC_MOQ_D18_REGISTRY_OK) {
                        xqc_log(moq_stream->session->log, XQC_LOG_ERROR,
                                "|invalid draft-18 stream placement|"
                                "type:0x%xi|class:%d|direction:%d|ret:%d|",
                                msg_type,
                                moq_stream->d18_context.stream_class,
                                moq_stream->d18_context.direction, ret);
                        xqc_moq_session_error(
                            moq_stream->session,
                            XQC_MOQ_D18_PROTOCOL_VIOLATION,
                            "invalid draft-18 message stream placement");
                        return -XQC_EILLEGAL_FRAME;
                    }
                    moq_stream->d18_pending_context = next_context;
                    moq_stream->d18_context_pending = 1;
                    moq_stream->d18_message_kind = desc.kind;
                    if (!xqc_moq_stream_d18_control_kind_allowed(moq_stream)) {
                        xqc_log(moq_stream->session->log, XQC_LOG_ERROR,
                                "|invalid draft-18 control message phase|"
                                "type:0x%xi|kind:%d|request_type:0x%xi|",
                                msg_type, desc.kind,
                                moq_stream->request_type);
                        xqc_moq_session_error(
                            moq_stream->session,
                            XQC_MOQ_D18_PROTOCOL_VIOLATION,
                            "invalid draft-18 control message phase");
                        return -XQC_EILLEGAL_FRAME;
                    }
                }

                if (moq_stream->session->use_unified_setup && msg_type == XQC_MOQ_MSG_SETUP) {
                    if (moq_stream->session->peer_ctl_stream
                        && moq_stream->session->peer_ctl_stream != moq_stream)
                    {
                        return -XQC_EILLEGAL_FRAME;
                    }
                    moq_stream->session->peer_ctl_stream = moq_stream;
                } else if (moq_stream->session->use_unified_setup
                           && moq_stream == moq_stream->session->peer_ctl_stream
                           && !moq_stream->session->session_setup_done)
                {
                    return -XQC_EILLEGAL_FRAME;
                }

                DEBUG_PRINTF(">>>msg_type:0x%x\n",msg_type);

                moq_stream->decode_msg_ctx.cur_msg_type = msg_type;
                moq_stream->decode_msg_ctx.cur_decode_state = XQC_MOQ_DECODE_MSG;
                break;
            case XQC_MOQ_DECODE_MSG:
                ret = xqc_moq_stream_process_msg(moq_stream, fin, &msg_finish, &wait_more_data);
                if (ret < 0) {
                    xqc_log(moq_stream->session->log, XQC_LOG_ERROR,
                            "|decode message error|ret:%d|msg_type:0x%xi|cur_field_idx:%d|",
                            ret, moq_stream->decode_msg_ctx.cur_msg_type,
                            moq_stream->decode_msg_ctx.cur_field_idx);
                    if (xqc_moq_stream_is_d18(moq_stream)) {
                        uint64_t error = ret == -XQC_EMALLOC
                            ? XQC_MOQ_D18_INTERNAL_ERROR
                            : XQC_MOQ_D18_PROTOCOL_VIOLATION;
                        if (moq_stream->d18_message_kind
                                == XQC_MOQ_D18_MESSAGE_SETUP
                            && moq_stream->decode_msg_ctx.cur_decode_msg
                                != NULL)
                        {
                            xqc_moq_setup_msg_t *setup =
                                moq_stream->decode_msg_ctx.cur_decode_msg;
                            if (setup->d18_error_code
                                != XQC_MOQ_D18_NO_ERROR)
                            {
                                error = setup->d18_error_code;
                            }
                        }
                        moq_stream->session->profile_state =
                            XQC_MOQ_PROFILE_FAILED;
                        xqc_moq_session_error(
                            moq_stream->session, error,
                            "decode draft-18 message");

                    } else if (ret == -XQC_EPROTO
                        || ret == -XQC_EALPN_NOT_SUPPORTED
                        || ret == -XQC_EVERSION)
                    {
                        moq_stream->session->profile_state =
                            XQC_MOQ_PROFILE_FAILED;
                        xqc_moq_session_error(
                            moq_stream->session, MOQ_PROTOCOL_VIOLATION,
                            "invalid message for negotiated profile");
                    }
                    xqc_moq_stream_clean_decode_msg_ctx(moq_stream);
                    return ret;
                }
                if (ret == 0 && wait_more_data == 0) {
                    xqc_log(moq_stream->session->log, XQC_LOG_ERROR,
                            "|decode message error|ret:%d|msg_type:0x%xi|cur_field_idx:%d|",
                            ret, moq_stream->decode_msg_ctx.cur_msg_type, moq_stream->decode_msg_ctx.cur_field_idx);
                    if (xqc_moq_stream_is_d18(moq_stream)
                        && moq_stream->d18_message_kind
                            == XQC_MOQ_D18_MESSAGE_SETUP)
                    {
                        uint64_t error = XQC_MOQ_D18_PROTOCOL_VIOLATION;
                        xqc_moq_setup_msg_t *setup =
                            moq_stream->decode_msg_ctx.cur_decode_msg;
                        if (setup != NULL
                            && setup->d18_error_code
                                != XQC_MOQ_D18_NO_ERROR)
                        {
                            error = setup->d18_error_code;
                        }
                        xqc_moq_session_error(moq_stream->session, error,
                                              "decode draft-18 SETUP");

                    } else if (xqc_moq_stream_is_d18(moq_stream)
                        && moq_stream->d18_message_kind
                            == XQC_MOQ_D18_MESSAGE_PUBLISH_BLOCKED)
                    {
                        xqc_moq_session_error(
                            moq_stream->session,
                            ret == -XQC_EMALLOC
                                ? XQC_MOQ_D18_INTERNAL_ERROR
                                : XQC_MOQ_D18_PROTOCOL_VIOLATION,
                            "decode draft-18 PUBLISH_BLOCKED");

                    } else if (xqc_moq_stream_is_d18(moq_stream)
                        && moq_stream->d18_message_kind
                            == XQC_MOQ_D18_MESSAGE_PUBLISH_DONE)
                    {
                        xqc_moq_session_error(
                            moq_stream->session,
                            ret == -XQC_EMALLOC
                                ? XQC_MOQ_D18_INTERNAL_ERROR
                                : XQC_MOQ_D18_PROTOCOL_VIOLATION,
                            "decode draft-18 PUBLISH_DONE");

                    } else if (xqc_moq_stream_is_d18(moq_stream)
                        && moq_stream->d18_message_kind
                            == XQC_MOQ_D18_MESSAGE_GOAWAY)
                    {
                        xqc_moq_session_error(
                            moq_stream->session,
                            ret == -XQC_EMALLOC
                                ? XQC_MOQ_D18_INTERNAL_ERROR
                                : XQC_MOQ_D18_PROTOCOL_VIOLATION,
                            "decode draft-18 GOAWAY");
                    }
                    xqc_moq_stream_clean_decode_msg_ctx(moq_stream);
                    return -XQC_EILLEGAL_FRAME;
                }
                processed += ret;

                xqc_log(moq_stream->session->log, XQC_LOG_DEBUG,
                        "|decode message|ret:%d|msg_type:0x%xi|msg_finish:%d|wait_more_data:%d|processed:%d|",
                        ret, moq_stream->decode_msg_ctx.cur_msg_type, msg_finish, wait_more_data, processed);

                if (wait_more_data == 1) {
                    stop = 1;
                    break;
                }
                if (msg_finish == 1) {
                    DEBUG_PRINTF(">>>msg decode finish\n");
                    xqc_moq_stream_commit_d18_read(moq_stream);
                    xqc_moq_decode_state_t next_state = XQC_MOQ_DECODE_MSG_TYPE;
                    uint64_t cur_msg_type =
                        moq_stream->decode_msg_ctx.cur_msg_type;
                    const xqc_moq_message_codec_entry_t *next_codec = NULL;
                    if (xqc_moq_profile_next_data_codec(
                            moq_stream->session->profile, moq_stream->kind,
                            cur_msg_type, &next_codec))
                    {
                        next_state = XQC_MOQ_DECODE_MSG;
                    }
                    xqc_moq_stream_clean_decode_msg_ctx(moq_stream);
                    moq_stream->decode_msg_ctx.cur_decode_state = next_state;
                    moq_stream->decode_msg_ctx.cur_msg_type =
                        next_state == XQC_MOQ_DECODE_MSG
                            ? (xqc_moq_msg_type_t)cur_msg_type
                            : (xqc_moq_msg_type_t)0xFF;
                    moq_stream->decode_codec = next_codec;
                    if (fin && moq_stream->read_buf_processed
                            == moq_stream->read_buf_len)
                    {
                        stop = 1;
                    }
                    break;
                }
                break;
            default:
                xqc_log(moq_stream->session->log, XQC_LOG_ERROR,
                        "|decode state error|state:%d|", moq_stream->decode_msg_ctx.cur_decode_state);
                return -XQC_EILLEGAL_FRAME;
        }
    } while (stop == 0);

    moq_stream->remain_read_buf_len = moq_stream->read_buf_len - moq_stream->read_buf_processed;
    if (moq_stream->remain_read_buf_len >= 8) {
        xqc_log(moq_stream->session->log, XQC_LOG_ERROR,
                "|remain_read_buf_len error|remain_read_buf_len:%uz|", moq_stream->remain_read_buf_len);
        return -XQC_EILLEGAL_FRAME;
    } else if (moq_stream->remain_read_buf_len > 0) {
        xqc_memcpy(moq_stream->remain_read_buf, moq_stream->read_buf + moq_stream->read_buf_processed,
                   moq_stream->remain_read_buf_len);
        processed += moq_stream->remain_read_buf_len;
    }

    processed -= remained;
    if (processed != buf_len) {
        xqc_log(moq_stream->session->log, XQC_LOG_ERROR,
                "|input buf not processed completely|");
        return -XQC_EILLEGAL_FRAME;
    }
    if (fin && (moq_stream->decode_msg_ctx.cur_decode_msg != NULL
                || (wait_more_data && moq_stream->read_buf_len > 0)))
    {
        if (xqc_moq_stream_is_d18(moq_stream)) {
            xqc_moq_session_error(
                moq_stream->session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
                "truncated draft-18 data record");
        }
        xqc_moq_stream_clean_decode_msg_ctx(moq_stream);
        return -XQC_EILLEGAL_FRAME;
    }
    if (fin) {
        moq_stream->peer_fin_received = 1;
        if (moq_stream->fetch_request_stream != NULL
            || (moq_stream->local_request
                && moq_stream->request_type
                    == (xqc_moq_msg_type_t)XQC_MOQ_D18_MSG_TRACK_STATUS
                && moq_stream->response_received))
        {
            xqc_moq_stream_finish_request(moq_stream, XQC_OK);

        } else {
            xqc_moq_stream_on_request_closed(
                moq_stream, xqc_moq_stream_peer_close_error(moq_stream));
        }
    }
    return processed;
}

static void
xqc_moq_stream_finish_request_internal(xqc_moq_stream_t *moq_stream,
    uint64_t error_code, uint8_t notify_cancelled,
    uint8_t flush_pending_destroy)
{
    if (moq_stream == NULL || moq_stream->session == NULL
        || !moq_stream->session->use_unified_setup
        || moq_stream->request_closed_notified)
    {
        return;
    }

    xqc_moq_session_t *session = moq_stream->session;
    if (moq_stream->fetch_request_stream != NULL) {
        xqc_moq_stream_t *request_stream =
            moq_stream->fetch_request_stream;
        uint64_t request_id = request_stream->request_id;
        xqc_int_t notify_fetch_complete = request_stream->local_request
            && request_stream->request_type == XQC_MOQ_MSG_FETCH
            && !request_stream->request_closed_notified
            && session->session_callbacks_ext.on_fetch_complete != NULL;
        moq_stream->fetch_request_stream = NULL;
        if (request_stream->fetch_data_stream == moq_stream) {
            request_stream->fetch_data_stream = NULL;
        }
        xqc_moq_stream_finish_request_internal(
            request_stream, error_code, notify_cancelled, 0);
        if (notify_fetch_complete) {
            xqc_moq_session_callback_enter(session);
            session->session_callbacks_ext.on_fetch_complete(
                session->user_session, request_id, error_code);
            xqc_moq_session_callback_leave(session);
        }
    }
    if (moq_stream->local_request
        && moq_stream->request_type
            == XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE)
    {
        moq_stream->request_closed_notified = 1;
        xqc_moq_stream_clear_local_namespace_subscription(moq_stream);
        goto finish;
    }

    if (moq_stream->peer_request
        && moq_stream->request_type
            == XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE)
    {
        moq_stream->request_closed_notified = 1;
        xqc_list_head_t *pos, *next;
        xqc_list_for_each_safe(
            pos, next, &session->peer_subscribe_namespace_list)
        {
            xqc_moq_namespace_prefix_t *prefix =
                xqc_list_entry(pos, xqc_moq_namespace_prefix_t,
                               list_member);
            if (prefix->request_id == moq_stream->request_id) {
                xqc_list_del_init(pos);
                xqc_moq_namespace_prefix_destroy(prefix);
                break;
            }
        }
        xqc_moq_session_reject_pending_inbound_ns(
            session, moq_stream->request_id);
        goto finish;
    }

    if ((moq_stream->local_request || moq_stream->peer_request)
        && moq_stream->request_type
            == XQC_MOQ_MSG_SUBSCRIBE_TRACKS)
    {
        moq_stream->request_closed_notified = 1;
        moq_stream->subscribe_tracks_active = 0;
        xqc_moq_namespace_prefix_destroy(
            moq_stream->tracks_subscription);
        moq_stream->tracks_subscription = NULL;
        goto finish;
    }

    if ((moq_stream->local_request || moq_stream->peer_request)
        && moq_stream->request_type == XQC_MOQ_MSG_PUBLISH)
    {
        xqc_moq_stream_finish_publish_request(moq_stream);
        xqc_log(session->log, XQC_LOG_INFO,
                "|publish request ended|request_id:%ui|error_code:%ui|",
                moq_stream->request_id, error_code);
        goto finish;
    }

    if ((moq_stream->local_request || moq_stream->peer_request)
        && moq_stream->request_type == XQC_MOQ_MSG_SUBSCRIBE)
    {
        moq_stream->request_closed_notified = 1;
        xqc_int_t is_local_subscription =
            moq_stream->local_request ? 1 : 0;
        xqc_moq_track_role_t track_role =
            is_local_subscription
                ? XQC_MOQ_TRACK_FOR_SUB : XQC_MOQ_TRACK_FOR_PUB;
        xqc_moq_subscribe_t *subscribe = xqc_moq_find_subscribe(
            session, moq_stream->request_id,
            is_local_subscription);
        xqc_moq_track_t *track = xqc_moq_find_track_by_subscribe_id(
            session, moq_stream->request_id, track_role);
        if (track != NULL
            && (!track->publish_done_received
                || xqc_moq_track_publish_done_recv_complete(track)))
        {
            xqc_moq_track_set_subscribe_id(
                track, XQC_MOQ_INVALID_ID);
            xqc_moq_track_set_alias(track, XQC_MOQ_INVALID_ID);
        }
        if (subscribe != NULL) {
            xqc_list_del_init(&subscribe->list_member);
            xqc_moq_subscribe_destroy(subscribe);
        }
        moq_stream->track = NULL;
        goto finish;
    }

    if ((!moq_stream->local_request && !moq_stream->peer_request)
        || moq_stream->request_type
            != XQC_MOQ_MSG_PUBLISH_NAMESPACE)
    {
        if (moq_stream->local_request || moq_stream->peer_request) {
            moq_stream->request_closed_notified = 1;
        }
        goto finish;
    }

    xqc_int_t is_local_advertisement =
        moq_stream->local_request ? 1 : 0;
    xqc_moq_namespace_advertisement_t *advertisement =
        xqc_moq_session_find_advertised_namespace_by_request(
            session, is_local_advertisement, moq_stream->request_id);
    if (advertisement == NULL) {
        moq_stream->request_closed_notified = 1;
        goto finish;
    }

    moq_stream->request_closed_notified = 1;
    xqc_log(session->log, XQC_LOG_INFO,
            "|publish_namespace request ended|request_id:%ui|error_code:%ui|",
            moq_stream->request_id, error_code);
    if (!is_local_advertisement
        && session->session_callbacks_ext.on_publish_namespace_done != NULL)
    {
        session->session_callbacks_ext.on_publish_namespace_done(
            session->user_session, moq_stream->request_id,
            advertisement->track_namespace_tuple,
            advertisement->track_namespace_num, error_code);
    }
    xqc_moq_session_remove_advertised_namespace(
        session, is_local_advertisement,
        advertisement->track_namespace_tuple,
        advertisement->track_namespace_num);

finish:
    moq_stream->update_failed_wait_publish_done = 0;
    xqc_moq_d18_update_queue_destroy(
        &moq_stream->d18_local_update_queue);
    xqc_moq_d18_update_queue_destroy(
        &moq_stream->d18_peer_update_queue);
    if (notify_cancelled && moq_stream->request_closed_notified
        && session->on_request_cancelled != NULL)
    {
        xqc_moq_session_callback_enter(session);
        session->on_request_cancelled(
            session->user_session, moq_stream->request_id,
            moq_stream->request_type,
            moq_stream->local_request ? 1 : 0, error_code);
        xqc_moq_session_callback_leave(session);
    }
    if (moq_stream->d18_goaway_timer_registered
        && !moq_stream->d18_goaway_timer_fired)
    {
        xqc_timer_gp_timer_unset(
            session->timer_manager, moq_stream->d18_goaway_timer_id);
    }
    xqc_moq_session_check_drain_complete(session);
    if (flush_pending_destroy) {
        xqc_moq_session_destroy_if_pending(session);
    }
}

void
xqc_moq_stream_finish_request(xqc_moq_stream_t *moq_stream,
    uint64_t error_code)
{
    xqc_moq_stream_finish_request_internal(
        moq_stream, error_code, 0, 1);
}

void
xqc_moq_stream_on_request_closed(xqc_moq_stream_t *moq_stream,
    uint64_t error_code)
{
    xqc_moq_stream_finish_request_internal(
        moq_stream, error_code, 1, 1);
}

uint64_t
xqc_moq_stream_peer_close_error(const xqc_moq_stream_t *moq_stream)
{
    return moq_stream != NULL && moq_stream->d18_goaway_received
        ? XQC_MOQ_REQUEST_STREAM_GOING_AWAY
        : XQC_MOQ_REQUEST_CANCELLED;
}

void
xqc_moq_stream_unregister_goaway_timer(
    xqc_moq_stream_t *stream)
{
    if (stream == NULL || !stream->d18_goaway_timer_registered) {
        return;
    }
    xqc_moq_session_t *session = stream->session;
    if (session != NULL && session->timer_manager != NULL) {
        xqc_timer_unregister_gp_timer(
            session->timer_manager, stream->d18_goaway_timer_id);
    }
    stream->d18_goaway_timer_registered = 0;
}


//return processed or error
xqc_int_t
xqc_moq_stream_process_msg(xqc_moq_stream_t *moq_stream, uint8_t stream_fin, xqc_int_t *msg_finish, xqc_int_t *wait_more_data)
{
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    *msg_finish = 0;
    *wait_more_data = 0;

    xqc_int_t create_error = XQC_OK;
    xqc_moq_msg_base_t *msg_base =
        moq_stream->decode_msg_ctx.cur_decode_msg;
    xqc_moq_stream_kind_t stream_kind =
        xqc_moq_stream_effective_kind(moq_stream);
    if (msg_base == NULL) {
        msg_base = xqc_moq_stream_get_or_alloc_cur_decode_msg_internal(
            moq_stream, &create_error);
    }

    if (msg_base == NULL) {
        xqc_log(moq_stream->session->log, XQC_LOG_ERROR, "|unkonwn message type|msg_type:0x%xi|",
                moq_stream->decode_msg_ctx.cur_msg_type);
        return create_error != XQC_OK ? create_error : -XQC_EMALLOC;
    }

    if (stream_kind != XQC_MOQ_STREAM_CONTROL
        && moq_stream->decode_codec != NULL)
    {
        ret = xqc_moq_profile_prepare_data_message(
            moq_stream, moq_stream->decode_codec, msg_base);
        if (ret != XQC_OK) {
            return ret;
        }
    }
    ret = msg_base->decode(moq_stream->read_buf + moq_stream->read_buf_processed,
                           moq_stream->read_buf_len - moq_stream->read_buf_processed,
                           stream_fin,
                           &moq_stream->decode_msg_ctx,
                           msg_base,
                           msg_finish, wait_more_data);
    if (ret < 0) {
        return ret;
    }
    moq_stream->read_buf_processed += ret;
    processed += ret;

    if (moq_stream->decode_codec != NULL
        && moq_stream->decode_codec->semantic
            == XQC_MOQ_SEMANTIC_SUBGROUP
        && !moq_stream->subgroup_header_valid)
    {
        xqc_int_t header_ret;
        if (moq_stream->session->profile->wire_version
            == XQC_MOQ_VERSION_18)
        {
            xqc_moq_d18_data_msg_t *d18_msg =
                (xqc_moq_d18_data_msg_t *)msg_base;
            header_ret = xqc_moq_d18_subgroup_header_ready(d18_msg)
                ? xqc_moq_d18_on_subgroup_header(
                    moq_stream->session, moq_stream, d18_msg)
                : XQC_OK;
        } else if (moq_stream->decode_msg_ctx.cur_field_idx >= 4) {
            header_ret = xqc_moq_on_subgroup_header(
                moq_stream->session, moq_stream, msg_base);
        } else {
            header_ret = XQC_OK;
        }
        if (header_ret != XQC_OK) {
            return header_ret;
        }
    }

    if (*wait_more_data == 1) {
        return processed;
    }
    if (*msg_finish == 1) {
        msg_base->on_msg(moq_stream->session, moq_stream, msg_base);
    }

    return processed;
}
