#include "moq/xqc_moq_fb_report.h"

#include "src/common/xqc_malloc.h"
#include "src/common/xqc_str.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"

#define XQC_MOQ_FB_REPORT_MAX_OBJECT_ENTRIES  512
#define XQC_MOQ_FB_REPORT_MAX_METRICS         64

static inline uint64_t
xqc_moq_fb_zigzag_encode(int64_t v)
{
    return ((uint64_t)v << 1) ^ (uint64_t)(v >> 63);
}

static inline int64_t
xqc_moq_fb_zigzag_decode(uint64_t v)
{
    return (int64_t)((v >> 1) ^ (uint64_t)-(int64_t)(v & 1));
}

static inline xqc_int_t
xqc_moq_fb_put_varint(uint8_t **pp, const uint8_t *end, uint64_t v)
{
    if (v >= (1ULL << 62)) {
        return -XQC_ELIMIT;
    }
    size_t need = xqc_put_varint_len(v);
    if (*pp + need > end) {
        return -XQC_ENOBUF;
    }
    *pp = xqc_put_varint(*pp, v);
    return XQC_OK;
}

static inline xqc_int_t
xqc_moq_fb_get_varint(const uint8_t **pp, const uint8_t *end, uint64_t *out)
{
    int vlen = xqc_vint_read((unsigned char *)*pp, (unsigned char *)end, out);
    if (vlen < 0) {
        return -XQC_EVINTREAD;
    }
    *pp += vlen;
    return XQC_OK;
}

void
xqc_moq_fb_report_free(xqc_moq_fb_report_t *report)
{
    if (report == NULL) {
        return;
    }

    if (report->object_entries) {
        xqc_free(report->object_entries);
        report->object_entries = NULL;
    }
    report->object_entry_count = 0;

    if (report->optional_metrics) {
        xqc_free(report->optional_metrics);
        report->optional_metrics = NULL;
    }
    report->optional_metric_count = 0;
}

xqc_int_t
xqc_moq_fb_report_encode(const xqc_moq_fb_report_t *report, uint8_t *buf, size_t buf_len, size_t *written)
{
    if (written) {
        *written = 0;
    }
    if (report == NULL || buf == NULL || buf_len == 0 || written == NULL) {
        return -XQC_EPARAM;
    }

    uint8_t *p = buf;
    const uint8_t *end = buf + buf_len;
    xqc_int_t ret;

    ret = xqc_moq_fb_put_varint(&p, end, report->report_timestamp);
    if (ret != XQC_OK) return ret;
    ret = xqc_moq_fb_put_varint(&p, end, report->report_sequence);
    if (ret != XQC_OK) return ret;
    ret = xqc_moq_fb_put_varint(&p, end, report->object_entry_count);
    if (ret != XQC_OK) return ret;

    for (uint64_t j = 0; j < report->object_entry_count; j++) {
        const xqc_moq_fb_object_row_t *row = &report->object_entries[j];
        const xqc_moq_fb_object_entry_t *obj = &row->obj;

        ret = xqc_moq_fb_put_varint(&p, end, row->object_id);
        if (ret != XQC_OK) return ret;
        ret = xqc_moq_fb_put_varint(&p, end, obj->status);
        if (ret != XQC_OK) return ret;

        if (obj->status == XQC_MOQ_FB_STATUS_RECEIVED
            || obj->status == XQC_MOQ_FB_STATUS_RECEIVED_LATE)
        {
            int64_t delta = obj->has_recv_ts_delta ? obj->recv_ts_delta : 0;
            uint64_t zz = xqc_moq_fb_zigzag_encode(delta);
            ret = xqc_moq_fb_put_varint(&p, end, zz);
            if (ret != XQC_OK) return ret;
        }
    }

    /* Summary Stats */
    ret = xqc_moq_fb_put_varint(&p, end, report->summary_stats.report_interval);
    if (ret != XQC_OK) return ret;
    ret = xqc_moq_fb_put_varint(&p, end, report->summary_stats.total_objects_evaluated);
    if (ret != XQC_OK) return ret;
    ret = xqc_moq_fb_put_varint(&p, end, report->summary_stats.objects_received);
    if (ret != XQC_OK) return ret;
    ret = xqc_moq_fb_put_varint(&p, end, report->summary_stats.objects_received_late);
    if (ret != XQC_OK) return ret;
    ret = xqc_moq_fb_put_varint(&p, end, report->summary_stats.objects_lost);
    if (ret != XQC_OK) return ret;
    ret = xqc_moq_fb_put_varint(&p, end, xqc_moq_fb_zigzag_encode(report->summary_stats.avg_inter_arrival_delta));
    if (ret != XQC_OK) return ret;

    /* Optional Metrics */
    ret = xqc_moq_fb_put_varint(&p, end, report->optional_metric_count);
    if (ret != XQC_OK) return ret;

    for (uint64_t i = 0; i < report->optional_metric_count; i++) {
        const xqc_moq_fb_optional_metric_t *m = &report->optional_metrics[i];
        ret = xqc_moq_fb_put_varint(&p, end, m->metric_type);
        if (ret != XQC_OK) return ret;
        ret = xqc_moq_fb_put_varint(&p, end, m->metric_value);
        if (ret != XQC_OK) return ret;
    }

    *written = (size_t)(p - buf);
    return XQC_OK;
}

xqc_int_t
xqc_moq_fb_report_decode(const uint8_t *buf, size_t buf_len, xqc_moq_fb_report_t *report)
{
    if (buf == NULL || report == NULL) {
        return -XQC_EPARAM;
    }

    xqc_memzero(report, sizeof(*report));

    const uint8_t *p = buf;
    const uint8_t *end = buf + buf_len;
    xqc_int_t ret;

    ret = xqc_moq_fb_get_varint(&p, end, &report->report_timestamp);
    if (ret != XQC_OK) goto fail;
    ret = xqc_moq_fb_get_varint(&p, end, &report->report_sequence);
    if (ret != XQC_OK) goto fail;
    ret = xqc_moq_fb_get_varint(&p, end, &report->object_entry_count);
    if (ret != XQC_OK) goto fail;
    if (report->object_entry_count > XQC_MOQ_FB_REPORT_MAX_OBJECT_ENTRIES) {
        ret = -XQC_ELIMIT;
        goto fail;
    }

    if (report->object_entry_count > 0) {
        report->object_entries = xqc_calloc(report->object_entry_count, sizeof(xqc_moq_fb_object_row_t));
        if (report->object_entries == NULL) {
            ret = -XQC_EMALLOC;
            goto fail;
        }
    }

    for (uint64_t j = 0; j < report->object_entry_count; j++) {
        xqc_moq_fb_object_row_t *row = &report->object_entries[j];
        uint64_t status = 0;

        ret = xqc_moq_fb_get_varint(&p, end, &row->object_id);
        if (ret != XQC_OK) goto fail;
        ret = xqc_moq_fb_get_varint(&p, end, &status);
        if (ret != XQC_OK) goto fail;

        row->obj.status = status;
        row->obj.has_recv_ts_delta = 0;
        row->obj.recv_ts_delta = 0;

        if (status == XQC_MOQ_FB_STATUS_RECEIVED || status == XQC_MOQ_FB_STATUS_RECEIVED_LATE) {
            uint64_t zz = 0;
            ret = xqc_moq_fb_get_varint(&p, end, &zz);
            if (ret != XQC_OK) goto fail;
            row->obj.has_recv_ts_delta = 1;
            row->obj.recv_ts_delta = xqc_moq_fb_zigzag_decode(zz);
        }
    }

    /* Summary Stats */
    ret = xqc_moq_fb_get_varint(&p, end, &report->summary_stats.report_interval);
    if (ret != XQC_OK) goto fail;
    ret = xqc_moq_fb_get_varint(&p, end, &report->summary_stats.total_objects_evaluated);
    if (ret != XQC_OK) goto fail;
    ret = xqc_moq_fb_get_varint(&p, end, &report->summary_stats.objects_received);
    if (ret != XQC_OK) goto fail;
    ret = xqc_moq_fb_get_varint(&p, end, &report->summary_stats.objects_received_late);
    if (ret != XQC_OK) goto fail;
    ret = xqc_moq_fb_get_varint(&p, end, &report->summary_stats.objects_lost);
    if (ret != XQC_OK) goto fail;
    {
        uint64_t zz = 0;
        ret = xqc_moq_fb_get_varint(&p, end, &zz);
        if (ret != XQC_OK) goto fail;
        report->summary_stats.avg_inter_arrival_delta = xqc_moq_fb_zigzag_decode(zz);
    }

    /* Optional Metrics */
    ret = xqc_moq_fb_get_varint(&p, end, &report->optional_metric_count);
    if (ret != XQC_OK) goto fail;
    if (report->optional_metric_count > XQC_MOQ_FB_REPORT_MAX_METRICS) {
        ret = -XQC_ELIMIT;
        goto fail;
    }

    if (report->optional_metric_count > 0) {
        report->optional_metrics = xqc_calloc(report->optional_metric_count, sizeof(xqc_moq_fb_optional_metric_t));
        if (report->optional_metrics == NULL) {
            ret = -XQC_EMALLOC;
            goto fail;
        }
    }
    for (uint64_t i = 0; i < report->optional_metric_count; i++) {
        ret = xqc_moq_fb_get_varint(&p, end, &report->optional_metrics[i].metric_type);
        if (ret != XQC_OK) goto fail;
        ret = xqc_moq_fb_get_varint(&p, end, &report->optional_metrics[i].metric_value);
        if (ret != XQC_OK) goto fail;
    }

    return XQC_OK;

fail:
    xqc_moq_fb_report_free(report);
    return ret;
}
