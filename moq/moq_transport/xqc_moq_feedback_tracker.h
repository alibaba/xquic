#ifndef _XQC_MOQ_FEEDBACK_TRACKER_H_INCLUDED_
#define _XQC_MOQ_FEEDBACK_TRACKER_H_INCLUDED_

#include "src/common/xqc_list.h"
#include "src/common/xqc_time.h"
#include "moq/xqc_moq.h"

#define XQC_MOQ_FEEDBACK_MAX_RECORDS 2048

typedef struct {
    uint64_t    global_seq;     /* track-wide monotonic sequence for fb_report object_id */
    uint64_t    group_id;
    uint64_t    object_id;
    xqc_usec_t  arrival_time;   /* monotonic, 0 if not received */
    xqc_usec_t  record_time;    /* when status was first set */
    uint64_t    status;         /* xqc_moq_fb_status_t */
    uint64_t    object_size;
} xqc_moq_object_record_t;

typedef struct xqc_moq_feedback_tracker_s {
    xqc_list_head_t list;

    uint64_t    track_alias;
    uint64_t    target_latency_us;      /* playout deadline: 0 if unknown */
    uint64_t    expected_interval_us;   /* expected inter-object interval */

    xqc_moq_object_record_t records[XQC_MOQ_FEEDBACK_MAX_RECORDS];
    uint32_t    head;                   /* next write */
    uint32_t    count;

    uint64_t    next_global_seq;        /* next global_seq to assign */

    xqc_usec_t  base_arrival_time;      /* arrival time of the first object (baseline) */
    xqc_usec_t  last_arrival_time;      /* arrival time of the most recent object */
    xqc_int_t   has_base_arrival;

    uint64_t    largest_received_group;
    uint64_t    largest_received_object_in_group;
    xqc_int_t   largest_object_valid;
} xqc_moq_feedback_tracker_t;

xqc_moq_feedback_tracker_t *xqc_moq_feedback_tracker_create(uint64_t track_alias);
void xqc_moq_feedback_tracker_destroy(xqc_moq_feedback_tracker_t *tracker);

void xqc_moq_feedback_tracker_set_target_latency(xqc_moq_feedback_tracker_t *tracker,
    uint64_t target_latency_us);

void xqc_moq_feedback_tracker_set_expected_interval(xqc_moq_feedback_tracker_t *tracker,
    uint64_t interval_us);

void xqc_moq_feedback_tracker_record_received(xqc_moq_feedback_tracker_t *tracker,
    uint64_t group_id, uint64_t object_id, xqc_usec_t now, uint64_t object_size);

/**
 * Mark trailing objects as NOT_RECEIVED if no new object arrives within
 * 2 * expected_interval after the last arrival (tail loss timeout).
 */
void xqc_moq_feedback_tracker_check_tail_loss(xqc_moq_feedback_tracker_t *tracker,
    xqc_usec_t now);

uint64_t xqc_moq_feedback_tracker_largest_received_group(const xqc_moq_feedback_tracker_t *tracker);

/**
 * Export recent object records for feedback report (draft Section 5.2).
 * Uses global_seq as object_id -- guaranteed unique and ascending.
 */
xqc_moq_fb_object_row_t *xqc_moq_feedback_tracker_export_object_rows(
    const xqc_moq_feedback_tracker_t *tracker,
    uint64_t max_rows, uint64_t *out_rows);

typedef struct {
    uint64_t    total_objects_evaluated;
    uint64_t    objects_received;
    uint64_t    objects_received_late;
    uint64_t    objects_lost;
    int64_t     avg_inter_arrival_delta;
} xqc_moq_feedback_tracker_summary_t;

/**
 * Compute summary stats for objects recorded after since_ts.
 * Pass 0 for since_ts to include all records (backward compat).
 */
void xqc_moq_feedback_tracker_get_summary(const xqc_moq_feedback_tracker_t *tracker,
    xqc_usec_t since_ts, xqc_moq_feedback_tracker_summary_t *summary);

#endif /* _XQC_MOQ_FEEDBACK_TRACKER_H_INCLUDED_ */
