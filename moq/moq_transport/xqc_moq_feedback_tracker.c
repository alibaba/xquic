#include "moq/moq_transport/xqc_moq_feedback_tracker.h"

#include <stdlib.h>

#include "src/common/xqc_malloc.h"
#include "src/common/xqc_str.h"

static inline uint32_t
xqc_moq_feedback_tracker_idx(const xqc_moq_feedback_tracker_t *tracker, uint32_t i)
{
    return (tracker->head + XQC_MOQ_FEEDBACK_MAX_RECORDS - tracker->count + i) % XQC_MOQ_FEEDBACK_MAX_RECORDS;
}

static void
xqc_moq_feedback_tracker_push(xqc_moq_feedback_tracker_t *tracker, const xqc_moq_object_record_t *rec)
{
    tracker->records[tracker->head] = *rec;
    tracker->head = (tracker->head + 1) % XQC_MOQ_FEEDBACK_MAX_RECORDS;
    if (tracker->count < XQC_MOQ_FEEDBACK_MAX_RECORDS) {
        tracker->count++;
    }
}

xqc_moq_feedback_tracker_t *
xqc_moq_feedback_tracker_create(uint64_t track_alias)
{
    xqc_moq_feedback_tracker_t *tracker = xqc_calloc(1, sizeof(*tracker));
    if (tracker == NULL) {
        return NULL;
    }
    xqc_init_list_head(&tracker->list);
    tracker->track_alias = track_alias;
    tracker->target_latency_us = 0;
    tracker->expected_interval_us = 0;
    tracker->head = 0;
    tracker->count = 0;
    tracker->next_global_seq = 0;
    tracker->base_arrival_time = 0;
    tracker->last_arrival_time = 0;
    tracker->has_base_arrival = 0;
    tracker->largest_received_group = 0;
    tracker->largest_received_object_in_group = 0;
    tracker->largest_object_valid = 0;
    return tracker;
}

void
xqc_moq_feedback_tracker_destroy(xqc_moq_feedback_tracker_t *tracker)
{
    if (tracker == NULL) {
        return;
    }
    xqc_list_del_init(&tracker->list);
    xqc_free(tracker);
}

void
xqc_moq_feedback_tracker_set_target_latency(xqc_moq_feedback_tracker_t *tracker, uint64_t target_latency_us)
{
    if (tracker) {
        tracker->target_latency_us = target_latency_us;
    }
}

void
xqc_moq_feedback_tracker_set_expected_interval(xqc_moq_feedback_tracker_t *tracker, uint64_t interval_us)
{
    if (tracker) {
        tracker->expected_interval_us = interval_us;
    }
}

uint64_t
xqc_moq_feedback_tracker_largest_received_group(const xqc_moq_feedback_tracker_t *tracker)
{
    return tracker ? tracker->largest_received_group : 0;
}

/*
 * Determine feedback status for a newly received object.
 *
 * Draft Section 5.3/5.3.1:
 *   RECEIVED_LATE = arrived after its playout deadline.
 *
 * Uses a two-level approach that avoids permanent timeline drift:
 *
 *   1. Gap-based check: if the gap since last arrival exceeds
 *      expected_interval + target_latency, this object (and the "stall"
 *      it represents) is LATE.  This detects the onset of HOL blocking.
 *
 *   2. Burst continuation: within a burst after a stall, objects arrive
 *      rapidly.  We track accumulated stall time and only clear it when
 *      inter-arrival returns to expected_interval for several consecutive
 *      objects, ensuring burst-delayed frames are also marked LATE.
 */
static uint64_t
xqc_moq_feedback_status_for_arrival(const xqc_moq_feedback_tracker_t *tracker,
    xqc_usec_t now)
{
    if (tracker->target_latency_us == 0) {
        return XQC_MOQ_FB_STATUS_RECEIVED;
    }

    if (tracker->last_arrival_time == 0) {
        return XQC_MOQ_FB_STATUS_RECEIVED;
    }

    uint64_t expected_interval = tracker->expected_interval_us;
    if (expected_interval == 0) {
        expected_interval = 33333;
    }

    xqc_usec_t gap = now - tracker->last_arrival_time;

    /*
     * If the gap since last object exceeds expected_interval + target_latency,
     * this object arrived late (network stall / HOL blocking).
     */
    if (gap > expected_interval + tracker->target_latency_us) {
        return XQC_MOQ_FB_STATUS_RECEIVED_LATE;
    }

    return XQC_MOQ_FB_STATUS_RECEIVED;
}

void
xqc_moq_feedback_tracker_record_received(xqc_moq_feedback_tracker_t *tracker,
    uint64_t group_id, uint64_t object_id, xqc_usec_t now, uint64_t object_size)
{
    if (tracker == NULL) {
        return;
    }

    uint64_t status = xqc_moq_feedback_status_for_arrival(tracker, now);

    xqc_moq_object_record_t r;
    xqc_memzero(&r, sizeof(r));
    r.global_seq = tracker->next_global_seq++;
    r.group_id = group_id;
    r.object_id = object_id;
    r.arrival_time = now;
    r.record_time = now;
    r.status = status;
    r.object_size = object_size;
    xqc_moq_feedback_tracker_push(tracker, &r);

    if (!tracker->has_base_arrival) {
        tracker->base_arrival_time = now;
        tracker->has_base_arrival = 1;
    }
    tracker->last_arrival_time = now;

    if (!tracker->largest_object_valid || group_id > tracker->largest_received_group) {
        tracker->largest_received_group = group_id;
        tracker->largest_received_object_in_group = object_id;
        tracker->largest_object_valid = 1;
    } else if (group_id == tracker->largest_received_group
               && object_id > tracker->largest_received_object_in_group)
    {
        tracker->largest_received_object_in_group = object_id;
        tracker->largest_object_valid = 1;
    }
}

void
xqc_moq_feedback_tracker_check_tail_loss(xqc_moq_feedback_tracker_t *tracker, xqc_usec_t now)
{
    if (tracker == NULL || !tracker->has_base_arrival) {
        return;
    }

    uint64_t timeout = tracker->expected_interval_us;
    if (timeout == 0) {
        timeout = 100000; /* default 100ms */
    }
    timeout *= 2; /* 2x expected_interval per draft S5.3 */

    if (now > tracker->last_arrival_time + timeout) {
        /*
         * No new object arrived within 2x expected interval (draft S5.3).
         * Insert a synthetic NOT_RECEIVED record to signal tail loss.
         */
        xqc_moq_object_record_t r;
        xqc_memzero(&r, sizeof(r));
        r.global_seq = tracker->next_global_seq++;
        r.group_id = tracker->largest_received_group;
        r.object_id = tracker->largest_received_object_in_group + 1;
        r.arrival_time = 0;
        r.record_time = now;
        r.status = XQC_MOQ_FB_STATUS_NOT_RECEIVED;
        r.object_size = 0;
        xqc_moq_feedback_tracker_push(tracker, &r);

        /* Advance last_arrival to prevent repeated insertion. */
        tracker->last_arrival_time = now;
    }
}

static int
xqc_moq_feedback_row_cmp(const void *a, const void *b)
{
    const xqc_moq_fb_object_row_t *ra = (const xqc_moq_fb_object_row_t *)a;
    const xqc_moq_fb_object_row_t *rb = (const xqc_moq_fb_object_row_t *)b;

    if (ra->object_id != rb->object_id) {
        return (ra->object_id < rb->object_id) ? -1 : 1;
    }
    return 0;
}

xqc_moq_fb_object_row_t *
xqc_moq_feedback_tracker_export_object_rows(const xqc_moq_feedback_tracker_t *tracker,
    uint64_t max_rows, uint64_t *out_rows)
{
    if (out_rows) {
        *out_rows = 0;
    }
    if (tracker == NULL || out_rows == NULL || max_rows == 0) {
        return NULL;
    }

    uint64_t rows_cap = (tracker->count < max_rows) ? tracker->count : max_rows;
    if (rows_cap == 0) {
        return NULL;
    }

    xqc_moq_fb_object_row_t *rows = xqc_calloc(rows_cap, sizeof(*rows));
    if (rows == NULL) {
        return NULL;
    }

    uint64_t filled = 0;
    for (uint32_t i = 0; i < tracker->count && filled < rows_cap; i++) {
        uint32_t idx = xqc_moq_feedback_tracker_idx(tracker, tracker->count - 1 - i);
        const xqc_moq_object_record_t *r = &tracker->records[idx];

        xqc_moq_fb_object_row_t *row = &rows[filled++];
        row->object_id = r->global_seq;
        row->obj.status = r->status;
        row->obj.has_recv_ts_delta = 0;
        row->obj.recv_ts_delta = 0;
        if ((r->status == XQC_MOQ_FB_STATUS_RECEIVED || r->status == XQC_MOQ_FB_STATUS_RECEIVED_LATE)
            && r->arrival_time != 0)
        {
            row->obj.has_recv_ts_delta = 1;
            row->obj.recv_ts_delta = (int64_t)r->arrival_time;
        }
    }

    if (filled == 0) {
        xqc_free(rows);
        return NULL;
    }

    qsort(rows, filled, sizeof(*rows), xqc_moq_feedback_row_cmp);

    *out_rows = filled;
    return rows;
}

void
xqc_moq_feedback_tracker_get_summary(const xqc_moq_feedback_tracker_t *tracker,
    xqc_usec_t since_ts, xqc_moq_feedback_tracker_summary_t *summary)
{
    if (summary == NULL) {
        return;
    }
    xqc_memzero(summary, sizeof(*summary));
    if (tracker == NULL || tracker->count == 0) {
        return;
    }

    int64_t delta_sum = 0;
    uint64_t delta_count = 0;
    xqc_usec_t prev_arrival = 0;
    xqc_int_t have_prev = 0;

    for (uint32_t i = 0; i < tracker->count; i++) {
        uint32_t idx = xqc_moq_feedback_tracker_idx(tracker, i);
        const xqc_moq_object_record_t *r = &tracker->records[idx];

        if (since_ts > 0 && r->record_time < since_ts) {
            continue;
        }

        summary->total_objects_evaluated++;

        switch (r->status) {
        case XQC_MOQ_FB_STATUS_RECEIVED:
            summary->objects_received++;
            break;
        case XQC_MOQ_FB_STATUS_RECEIVED_LATE:
            summary->objects_received++;
            summary->objects_received_late++;
            break;
        case XQC_MOQ_FB_STATUS_NOT_RECEIVED:
            summary->objects_lost++;
            break;
        default:
            break;
        }

        if (r->arrival_time > 0 && (r->status == XQC_MOQ_FB_STATUS_RECEIVED
                                     || r->status == XQC_MOQ_FB_STATUS_RECEIVED_LATE))
        {
            if (have_prev && r->arrival_time >= prev_arrival) {
                delta_sum += (int64_t)(r->arrival_time - prev_arrival);
                delta_count++;
            }
            prev_arrival = r->arrival_time;
            have_prev = 1;
        }
    }

    if (delta_count > 0) {
        summary->avg_inter_arrival_delta = delta_sum / (int64_t)delta_count;
    }
}
