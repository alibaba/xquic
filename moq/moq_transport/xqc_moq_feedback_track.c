#include "moq/moq_transport/xqc_moq_feedback_track.h"

#include "moq/xqc_moq_fb_report.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_feedback_decision.h"
#include "src/cc/xqc_crosslayer.h"
#include "src/common/xqc_time.h"

static void xqc_moq_feedback_on_create(xqc_moq_track_t *track);
static void xqc_moq_feedback_on_destroy(xqc_moq_track_t *track);
static void xqc_moq_feedback_on_subscribe(xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_subscribe_msg_t *msg);
static void xqc_moq_feedback_on_subscribe_ok(xqc_moq_session_t *session, xqc_moq_track_t *track,
    xqc_moq_subscribe_ok_msg_t *subscribe_ok);
static void xqc_moq_feedback_on_subscribe_error(xqc_moq_session_t *session, xqc_moq_track_t *track,
    xqc_moq_subscribe_error_msg_t *subscribe_error);
static void xqc_moq_feedback_on_object(xqc_moq_session_t *session, xqc_moq_track_t *track, xqc_moq_object_t *object);

const xqc_moq_track_ops_t xqc_moq_feedback_track_ops = {
    .on_create           = xqc_moq_feedback_on_create,
    .on_destroy          = xqc_moq_feedback_on_destroy,
    .on_subscribe        = xqc_moq_feedback_on_subscribe,
    .on_subscribe_update = NULL,
    .on_subscribe_ok     = xqc_moq_feedback_on_subscribe_ok,
    .on_subscribe_error  = xqc_moq_feedback_on_subscribe_error,
    .on_object           = xqc_moq_feedback_on_object,
};

static void
xqc_moq_feedback_on_create(xqc_moq_track_t *track)
{
    (void)track;
}

static void
xqc_moq_feedback_on_destroy(xqc_moq_track_t *track)
{
    (void)track;
}

static void
xqc_moq_feedback_on_subscribe(xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_subscribe_msg_t *msg)
{
    (void)session;
    (void)subscribe_id;
    (void)track;
    (void)msg;
}

static void
xqc_moq_feedback_on_subscribe_ok(xqc_moq_session_t *session, xqc_moq_track_t *track,
    xqc_moq_subscribe_ok_msg_t *subscribe_ok)
{
    (void)session;
    (void)track;
    (void)subscribe_ok;
}

static void
xqc_moq_feedback_on_subscribe_error(xqc_moq_session_t *session, xqc_moq_track_t *track,
    xqc_moq_subscribe_error_msg_t *subscribe_error)
{
    (void)session;
    (void)track;
    (void)subscribe_error;
}

static uint64_t
xqc_moq_feedback_get_metric(const xqc_moq_fb_report_t *report, uint64_t metric_type)
{
    for (uint64_t i = 0; i < report->optional_metric_count; i++) {
        if (report->optional_metrics[i].metric_type == metric_type) {
            return report->optional_metrics[i].metric_value;
        }
    }
    return 0;
}

/*
 * Convert feedback_decision output to a crosslayer_event and dispatch
 * through the unified crosslayer gateway.
 */
static xqc_int_t
xqc_moq_feedback_dispatch_via_crosslayer(xqc_moq_session_t *session,
    const xqc_moq_fb_decision_t *decision, xqc_usec_t expire_us, xqc_usec_t now)
{
    if (!session->crosslayer_initialized) {
        return XQC_ERROR;
    }

    xqc_crosslayer_event_t ev;
    switch (decision->action) {
    case XQC_MOQ_FB_ACTION_PACING_GAIN:
        ev.type = XQC_EVENT_PACING_GAIN_UPDATE;
        ev.payload.pacing_gain.gain = decision->u.pacing_gain.gain;
        ev.payload.pacing_gain.expire_us = expire_us;
        break;
    case XQC_MOQ_FB_ACTION_PACING_RATE:
        ev.type = XQC_EVENT_PACING_RATE_UPDATE;
        ev.payload.pacing_rate.rate = decision->u.pacing_rate.rate;
        ev.payload.pacing_rate.expire_us = expire_us;
        break;
    case XQC_MOQ_FB_ACTION_TARGET_BITRATE:
        ev.type = XQC_EVENT_TARGET_BITRATE_UPDATE;
        ev.payload.target_bitrate.bitrate = decision->u.target_bitrate.bitrate;
        ev.payload.target_bitrate.expire_us = expire_us;
        break;
    default:
        return XQC_ERROR;
    }

    return xqc_crosslayer_apply(&session->crosslayer_ctl, &ev, now);
}

static void
xqc_moq_feedback_dispatch_and_notify(xqc_moq_session_t *session,
    const xqc_moq_fb_decision_t *decision, xqc_usec_t now)
{
    xqc_usec_t duration = session->feedback_decision_config.override_duration_us;
    if (duration == 0) {
        duration = 200000;
    }

    xqc_int_t rc = xqc_moq_feedback_dispatch_via_crosslayer(session,
        decision, now + duration, now);

    if (rc == XQC_OK) {
        xqc_log(session->log, XQC_LOG_STATS,
            "|feedback_cc|action:%d|src:%s|",
            decision->action,
            session->session_callbacks.on_feedback_decision ? "user" : "auto");
    }

    if (decision->action == XQC_MOQ_FB_ACTION_TARGET_BITRATE
        && session->session_callbacks.on_bitrate_change)
    {
        session->session_callbacks.on_bitrate_change(
            session->user_session, NULL, NULL,
            decision->u.target_bitrate.bitrate);
    }
}

static void
xqc_moq_feedback_on_object(xqc_moq_session_t *session, xqc_moq_track_t *track, xqc_moq_object_t *object)
{
    (void)track;
    if (session == NULL || object == NULL || object->payload == NULL || object->payload_len == 0) {
        return;
    }

    /* 1. Decode feedback report */
    xqc_moq_fb_report_t report;
    xqc_int_t ret = xqc_moq_fb_report_decode(object->payload, object->payload_len, &report);
    if (ret != XQC_OK) {
        xqc_log(session->log, XQC_LOG_ERROR, "|fb_report_decode error|ret:%d|len:%ui|", ret, object->payload_len);
        return;
    }

    /* 2. Compute fb_input (always, for both observer and decision) */
    uint64_t total = report.summary_stats.total_objects_evaluated;
    uint64_t lost  = report.summary_stats.objects_lost;
    uint64_t late  = report.summary_stats.objects_received_late;

    xqc_moq_fb_input_t input;
    input.loss_rate        = (total > 0) ? ((double)lost / (double)total) : 0.0;
    input.late_rate        = (total > 0) ? ((double)late / (double)total) : 0.0;
    input.playout_ahead_ms = xqc_moq_feedback_get_metric(&report,
        XQC_MOQ_FB_METRIC_PLAYOUT_AHEAD_MS);
    input.estimated_bw_kbps = xqc_moq_feedback_get_metric(&report,
        XQC_MOQ_FB_METRIC_ESTIMATED_BANDWIDTH_KBPS);

    /* 3. Observer callback (logging/stats, does not affect CC) */
    if (session->session_callbacks.on_delivery_feedback) {
        session->session_callbacks.on_delivery_feedback(session, &report, session->user_session);
    }

    /* 4-5. CC decision: user callback takes priority over auto */
    if (session->quic_conn && session->delivery_feedback_input) {
        xqc_usec_t now = xqc_monotonic_timestamp();
        xqc_moq_fb_decision_t decision;
        decision.action = XQC_MOQ_FB_ACTION_NONE;
        xqc_int_t decided = 0;

        /* 4. User decision callback (Level 2.5)
         *    rc==XQC_OK means "user has decided" -- even if action==NONE
         *    (intentional no-op that suppresses auto fallback).
         *    Return non-OK to let auto decision run. */
        xqc_int_t user_decided = 0;
        if (session->session_callbacks.on_feedback_decision) {
            xqc_int_t rc = session->session_callbacks.on_feedback_decision(
                session, &report, &input, &decision, session->user_session);
            if (rc == XQC_OK) {
                user_decided = 1;
                if (decision.action != XQC_MOQ_FB_ACTION_NONE) {
                    decided = 1;
                }
            }
        }

        /* 5. Auto decision (if user didn't decide, and auto is enabled) */
        if (!user_decided && !decided && session->auto_cc_feedback) {
            xqc_moq_fb_decision_evaluate(&session->feedback_decision_config,
                &input, now, &decision);
            if (decision.action != XQC_MOQ_FB_ACTION_NONE) {
                decided = 1;
            }
        }

        /* 6. Dispatch through crosslayer (unified clamp/rate-limit/expiry) */
        if (decided) {
            xqc_moq_feedback_dispatch_and_notify(session, &decision, now);
        }
    }

    xqc_moq_fb_report_free(&report);
}
