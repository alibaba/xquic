#include "moq/moq_transport/xqc_moq_fb_report_gen.h"

#include "moq/moq_transport/xqc_moq_feedback_tracker.h"
#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_transport/xqc_moq_track.h"

#include "src/common/xqc_malloc.h"
#include "src/common/xqc_str.h"

#include "moq/xqc_moq_fb_report.h"

#define XQC_MOQ_FB_REPORT_MAX_PACKET_SIZE 1200
#define XQC_MOQ_FB_REPORT_DEFAULT_INTERVAL_US 100000 /* 100ms */

static void
xqc_moq_fb_report_gen_timeout(xqc_gp_timer_id_t gp_timer_id, xqc_usec_t now, void *user_data);

static xqc_int_t
xqc_moq_fb_report_gen_send_report(xqc_moq_fb_report_gen_t *gen, xqc_usec_t now)
{
    xqc_moq_session_t *session = gen->session;
    xqc_moq_track_t *fb = gen->feedback_track_pub;
    if (session == NULL || fb == NULL) {
        return -XQC_EPARAM;
    }

    if (fb->subscribe_id == XQC_MOQ_INVALID_ID || fb->track_alias == XQC_MOQ_INVALID_ID) {
        return XQC_OK;
    }

    xqc_moq_fb_report_t report;
    xqc_memzero(&report, sizeof(report));

    /* draft Section 5.1: absolute monotonic clock (microseconds). */
    report.report_timestamp = now;
    report.report_sequence = gen->report_sequence++;

    xqc_moq_track_t *media_track = NULL;
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &session->track_list_for_sub) {
        xqc_moq_track_t *t = xqc_list_entry(pos, xqc_moq_track_t, list_member);
        if ((t->track_info.track_type == XQC_MOQ_TRACK_VIDEO || t->track_info.track_type == XQC_MOQ_TRACK_AUDIO)
            && t->feedback_tracker != NULL)
        {
            media_track = t;
            break;
        }
    }

    if (media_track != NULL) {
        xqc_moq_feedback_tracker_check_tail_loss(media_track->feedback_tracker, now);

        uint64_t rows = 0;
        report.object_entries = xqc_moq_feedback_tracker_export_object_rows(
            media_track->feedback_tracker, 50, &rows);
        report.object_entry_count = rows;

        xqc_int_t have_prev = 0;
        xqc_usec_t prev_arrival = 0;
        for (uint64_t j = 0; j < report.object_entry_count; j++) {
            xqc_moq_fb_object_row_t *row = &report.object_entries[j];
            if ((row->obj.status == XQC_MOQ_FB_STATUS_RECEIVED || row->obj.status == XQC_MOQ_FB_STATUS_RECEIVED_LATE)
                && row->obj.has_recv_ts_delta)
            {
                xqc_usec_t arrival = (xqc_usec_t)row->obj.recv_ts_delta;
                int64_t delta;
                if (!have_prev) {
                    delta = (int64_t)arrival - (int64_t)now;
                } else {
                    delta = (int64_t)arrival - (int64_t)prev_arrival;
                }
                row->obj.recv_ts_delta = delta;
                have_prev = 1;
                prev_arrival = arrival;
            } else {
                row->obj.has_recv_ts_delta = 0;
                row->obj.recv_ts_delta = 0;
            }
        }
    }

    /* Summary Stats: only count objects recorded since last report (per-period). */
    report.summary_stats.report_interval = XQC_MOQ_FB_REPORT_DEFAULT_INTERVAL_US;
    if (media_track != NULL) {
        xqc_moq_feedback_tracker_summary_t ts;
        xqc_moq_feedback_tracker_get_summary(media_track->feedback_tracker,
            gen->last_report_ts, &ts);
        report.summary_stats.total_objects_evaluated = ts.total_objects_evaluated;
        report.summary_stats.objects_received = ts.objects_received;
        report.summary_stats.objects_received_late = ts.objects_received_late;
        report.summary_stats.objects_lost = ts.objects_lost;
        report.summary_stats.avg_inter_arrival_delta = ts.avg_inter_arrival_delta;
    }

    gen->last_report_ts = now;

    /* Optional Metrics (only when negotiated). */
    if (session->delivery_feedback_metrics) {
        report.optional_metric_count = 1;
        report.optional_metrics = xqc_calloc(1, sizeof(xqc_moq_fb_optional_metric_t));
        if (report.optional_metrics == NULL) {
            xqc_moq_fb_report_free(&report);
            return -XQC_EMALLOC;
        }
        report.optional_metrics[0].metric_type = XQC_MOQ_FB_METRIC_PLAYOUT_AHEAD_MS;
        report.optional_metrics[0].metric_value = session->playout_ahead_ms;
    } else {
        report.optional_metric_count = 0;
        report.optional_metrics = NULL;
    }

    uint8_t buf[XQC_MOQ_FB_REPORT_MAX_PACKET_SIZE];
    size_t written = 0;
    xqc_int_t ret = xqc_moq_fb_report_encode(&report, buf, sizeof(buf), &written);
    if (ret != XQC_OK) {
        xqc_moq_fb_report_free(&report);
        return ret;
    }

    xqc_moq_fb_report_free(&report);

    xqc_moq_stream_t *stream = xqc_moq_stream_create_with_transport(session, XQC_STREAM_UNI);
    if (stream == NULL) {
        return -XQC_ECREATE_STREAM;
    }
    stream->write_stream_fin = 1;

    uint64_t group_id = 0;
    uint64_t object_id = fb->cur_object_id++;

    xqc_moq_object_stream_msg_t obj;
    xqc_memzero(&obj, sizeof(obj));
    obj.subscribe_id = fb->subscribe_id;
    obj.track_alias = fb->track_alias;
    obj.group_id = group_id;
    obj.object_id = object_id;
    obj.subgroup_id = 0;
    obj.object_id_delta = object_id;
    obj.subgroup_type = XQC_MOQ_SUBGROUP_TYPE_WITH_ID;
    obj.subgroup_priority = XQC_MOQ_DEFAULT_SUBGROUP_PRIORITY;
    obj.send_order = 0;
    obj.status = XQC_MOQ_OBJ_STATUS_NORMAL;
    obj.payload = buf;
    obj.payload_len = written;

    xqc_moq_stream_on_track_write(stream, fb, group_id, object_id, 0);
    ret = xqc_moq_write_subgroup_msg(session, stream, &obj);
    if (ret < 0) {
        xqc_moq_stream_destroy(stream);
        return ret;
    }

    return XQC_OK;
}

static void
xqc_moq_fb_report_gen_timeout(xqc_gp_timer_id_t gp_timer_id, xqc_usec_t now, void *user_data)
{
    xqc_moq_fb_report_gen_t *gen = (xqc_moq_fb_report_gen_t *)user_data;
    if (gen == NULL || gen->session == NULL) {
        return;
    }
    (void)gp_timer_id;

    (void)xqc_moq_fb_report_gen_send_report(gen, now);

    xqc_timer_gp_timer_set(gen->session->timer_manager, gen->timer_id, now + XQC_MOQ_FB_REPORT_DEFAULT_INTERVAL_US);
}

xqc_moq_fb_report_gen_t *
xqc_moq_fb_report_gen_create(xqc_moq_session_t *session, xqc_moq_track_t *feedback_track_pub)
{
    if (session == NULL || feedback_track_pub == NULL) {
        return NULL;
    }

    xqc_moq_fb_report_gen_t *gen = xqc_calloc(1, sizeof(*gen));
    if (gen == NULL) {
        return NULL;
    }
    gen->session = session;
    gen->feedback_track_pub = feedback_track_pub;
    gen->last_report_ts = 0;
    gen->report_sequence = 0;
    gen->timer_id = xqc_timer_register_gp_timer(session->timer_manager,
        "moq_fb_report", xqc_moq_fb_report_gen_timeout, gen);
    if (gen->timer_id < 0) {
        xqc_free(gen);
        return NULL;
    }

    xqc_usec_t now = xqc_monotonic_timestamp();
    xqc_timer_gp_timer_set(session->timer_manager, gen->timer_id, now + XQC_MOQ_FB_REPORT_DEFAULT_INTERVAL_US);
    return gen;
}

void
xqc_moq_fb_report_gen_destroy(xqc_moq_fb_report_gen_t *gen)
{
    if (gen == NULL) {
        return;
    }
    if (gen->session && gen->session->timer_manager) {
        xqc_timer_unregister_gp_timer(gen->session->timer_manager, gen->timer_id);
    }
    xqc_free(gen);
}

void
xqc_moq_fb_report_gen_on_media_object_received(xqc_moq_session_t *session, xqc_moq_track_t *track,
    const xqc_moq_object_t *object, xqc_usec_t now)
{
    if (session == NULL || track == NULL || object == NULL) {
        return;
    }
    if (!session->delivery_feedback_output) {
        return;
    }
    if (track->feedback_tracker == NULL) {
        track->feedback_tracker = xqc_moq_feedback_tracker_create(track->track_alias);
        if (track->feedback_tracker == NULL) {
            return;
        }
        xqc_moq_feedback_tracker_set_target_latency(track->feedback_tracker, track->target_latency_us);
        uint64_t interval = (track->track_info.track_type == XQC_MOQ_TRACK_AUDIO) ? 20000 : 33333;
        xqc_moq_feedback_tracker_set_expected_interval(track->feedback_tracker, interval);
    }
    xqc_moq_feedback_tracker_record_received(track->feedback_tracker,
        object->group_id, object->object_id, now, object->payload_len);
}
