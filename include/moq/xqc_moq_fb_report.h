#ifndef _XQC_MOQ_FB_REPORT_H_INCLUDED_
#define _XQC_MOQ_FB_REPORT_H_INCLUDED_

#include <stdint.h>
#include <stddef.h>
#include <xquic/xquic_typedef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* draft-moq-delivery-feedback-00 Section 5 -- Feedback Report wire format. */

typedef enum {
    XQC_MOQ_FB_STATUS_RECEIVED           = 0x00,
    XQC_MOQ_FB_STATUS_RECEIVED_LATE      = 0x01,
    XQC_MOQ_FB_STATUS_NOT_RECEIVED       = 0x02,
    XQC_MOQ_FB_STATUS_PARTIALLY_RECEIVED = 0x03,
} xqc_moq_fb_status_t;

/* Section 5.2 Object Entry */
typedef struct {
    uint64_t status;            /* xqc_moq_fb_status_t (varint) */
    xqc_int_t has_recv_ts_delta;
    int64_t recv_ts_delta;      /* microseconds, ZigZag(varint) */
} xqc_moq_fb_object_entry_t;

typedef struct {
    uint64_t object_id;
    xqc_moq_fb_object_entry_t obj;
} xqc_moq_fb_object_row_t;

/* Section 5.4 Summary Stats */
typedef struct {
    uint64_t report_interval;              /* microseconds */
    uint64_t total_objects_evaluated;
    uint64_t objects_received;
    uint64_t objects_received_late;
    uint64_t objects_lost;
    int64_t  avg_inter_arrival_delta;      /* microseconds, ZigZag(varint) */
} xqc_moq_fb_summary_stats_t;

/* Section 5.5 Optional Metric */

#define XQC_MOQ_FB_METRIC_PLAYOUT_AHEAD_MS         0x02
#define XQC_MOQ_FB_METRIC_ESTIMATED_BANDWIDTH_KBPS 0x04
#define XQC_MOQ_FB_METRIC_PEER_RTT_US              0x10
#define XQC_MOQ_FB_METRIC_PEER_LOSS_RATE           0x12

typedef struct {
    uint64_t metric_type;
    uint64_t metric_value;
} xqc_moq_fb_optional_metric_t;

/* Section 5.1 top-level report */
typedef struct {
    uint64_t report_timestamp;             /* absolute monotonic clock, microseconds */
    uint64_t report_sequence;
    uint64_t object_entry_count;
    xqc_moq_fb_object_row_t *object_entries;
    xqc_moq_fb_summary_stats_t summary_stats;
    uint64_t optional_metric_count;
    xqc_moq_fb_optional_metric_t *optional_metrics;
} xqc_moq_fb_report_t;

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_fb_report_encode(const xqc_moq_fb_report_t *report, uint8_t *buf, size_t buf_len, size_t *written);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_moq_fb_report_decode(const uint8_t *buf, size_t buf_len, xqc_moq_fb_report_t *report);

XQC_EXPORT_PUBLIC_API
void xqc_moq_fb_report_free(xqc_moq_fb_report_t *report);

#ifdef __cplusplus
}
#endif

#endif /* _XQC_MOQ_FB_REPORT_H_INCLUDED_ */
