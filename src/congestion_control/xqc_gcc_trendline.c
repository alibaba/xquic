/**
 * @file xqc_gcc_trendline.c
 * @brief Trendline overuse estimator (WebRTC goog_cc TrendlineEstimator aligned).
 */

#include "src/congestion_control/xqc_gcc_sensor.h"

#ifdef XQC_ENABLE_GCC_SENSOR

#include <xquic/xquic.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#define XQC_GCC_TL_WINDOW_SIZE              20
#define XQC_GCC_TL_SMOOTH_ALPHA             0.9
#define XQC_GCC_TL_THRESHOLD_GAIN           4.0
#define XQC_GCC_TL_INITIAL_THRESHOLD_MS     12.5f
#define XQC_GCC_TL_DELTA_COUNTER_MAX        1000
#define XQC_GCC_TL_OVERUSING_TIME_THRESHOLD_MS  10
#define XQC_GCC_TL_UNDERUSE_COUNTER_TH      3
#define XQC_GCC_TL_MAX_ADAPT_OFFSET_MS      15.0
#define XQC_GCC_TL_THRESHOLD_K_UP           0.0087
#define XQC_GCC_TL_THRESHOLD_K_DOWN         0.039
#define XQC_GCC_TL_THRESHOLD_MIN_MS         6.0f
#define XQC_GCC_TL_THRESHOLD_MAX_MS         600.0f
#define XQC_GCC_TL_SLOPE_CAP_BEGIN_PACKETS  3
#define XQC_GCC_TL_SLOPE_CAP_END_PACKETS    3
#define XQC_GCC_TL_SLOPE_CAP_UNCERTAINTY    0.0

struct xqc_gcc_trendline_point_s {
    double arrival_time_ms;
    double smoothed_delay_ms;
    double raw_delay_ms;
};

struct xqc_gcc_trendline_s {
    struct xqc_gcc_trendline_point_s points[XQC_GCC_TL_WINDOW_SIZE];
    uint32_t                      count;
    uint32_t                      head;
    double                        accumulated_delay_ms;
    double                        smoothed_delay_ms;
    int64_t                       first_arrival_time_ms;
    uint32_t                      num_of_deltas;
    float                         threshold_ms;
    double                        prev_trend;
    double                        last_slope;
    double                        last_modified_trend;
    int64_t                       time_over_using_ms;
    int64_t                       last_threshold_update_ms;
    uint32_t                      overuse_counter;
    uint32_t                      underuse_counter;
    xqc_gcc_bandwidth_usage_e     usage;
};

size_t
xqc_gcc_tl_size(void)
{
    return sizeof(xqc_gcc_trendline_t);
}

void
xqc_gcc_tl_reset(xqc_gcc_trendline_t *tl)
{
    memset(tl, 0, sizeof(*tl));
    tl->threshold_ms = XQC_GCC_TL_INITIAL_THRESHOLD_MS;
    tl->usage = XQC_GCC_BW_NORMAL;
    tl->first_arrival_time_ms = -1;
    tl->time_over_using_ms = -1;
    tl->last_threshold_update_ms = -1;
}

void
xqc_gcc_tl_init(xqc_gcc_trendline_t *tl)
{
    xqc_gcc_tl_reset(tl);
}

static uint32_t
xqc_gcc_tl_point_index(const xqc_gcc_trendline_t *tl, uint32_t i)
{
    if (tl->count < XQC_GCC_TL_WINDOW_SIZE) {
        return i;
    }
    return (tl->head + i) % XQC_GCC_TL_WINDOW_SIZE;
}

static void
xqc_gcc_tl_push_point(xqc_gcc_trendline_t *tl, double arrival_ms,
    double smoothed_ms, double raw_ms)
{
    uint32_t idx;
    if (tl->count < XQC_GCC_TL_WINDOW_SIZE) {
        idx = tl->count;
        tl->count++;
    } else {
        idx = tl->head;
        tl->head = (tl->head + 1) % XQC_GCC_TL_WINDOW_SIZE;
    }
    tl->points[idx].arrival_time_ms = arrival_ms;
    tl->points[idx].smoothed_delay_ms = smoothed_ms;
    tl->points[idx].raw_delay_ms = raw_ms;
}

static double
xqc_gcc_tl_fit_slope(const xqc_gcc_trendline_t *tl)
{
    uint32_t n = tl->count;
    uint32_t i;
    double sum_x = 0, sum_y = 0;
    double x_avg, y_avg;
    double numerator = 0, denominator = 0;

    if (n < 2) {
        return 0.0;
    }

    for (i = 0; i < n; ++i) {
        uint32_t idx = xqc_gcc_tl_point_index(tl, i);
        sum_x += tl->points[idx].arrival_time_ms;
        sum_y += tl->points[idx].smoothed_delay_ms;
    }
    x_avg = sum_x / n;
    y_avg = sum_y / n;

    for (i = 0; i < n; ++i) {
        uint32_t idx = xqc_gcc_tl_point_index(tl, i);
        double x = tl->points[idx].arrival_time_ms - x_avg;
        double y = tl->points[idx].smoothed_delay_ms - y_avg;
        numerator += x * y;
        denominator += x * x;
    }

    if (fabs(denominator) < 1e-9) {
        return 0.0;
    }
    return numerator / denominator;
}

static double
xqc_gcc_tl_compute_slope_cap(const xqc_gcc_trendline_t *tl)
{
    uint32_t n = tl->count;
    uint32_t begin_n = XQC_GCC_TL_SLOPE_CAP_BEGIN_PACKETS;
    uint32_t end_n = XQC_GCC_TL_SLOPE_CAP_END_PACKETS;
    uint32_t late_start;
    uint32_t i;
    double early_raw, late_raw;
    double early_arr, late_arr;
    uint32_t early_idx, late_idx;

    if (begin_n + end_n > n || n < 2) {
        return -1.0;
    }

    early_idx = xqc_gcc_tl_point_index(tl, 0);
    early_raw = tl->points[early_idx].raw_delay_ms;
    early_arr = tl->points[early_idx].arrival_time_ms;
    for (i = 1; i < begin_n; ++i) {
        uint32_t idx = xqc_gcc_tl_point_index(tl, i);
        if (tl->points[idx].raw_delay_ms < early_raw) {
            early_raw = tl->points[idx].raw_delay_ms;
            early_arr = tl->points[idx].arrival_time_ms;
        }
    }

    late_start = n - end_n;
    late_idx = xqc_gcc_tl_point_index(tl, late_start);
    late_raw = tl->points[late_idx].raw_delay_ms;
    late_arr = tl->points[late_idx].arrival_time_ms;
    for (i = late_start + 1; i < n; ++i) {
        uint32_t idx = xqc_gcc_tl_point_index(tl, i);
        if (tl->points[idx].raw_delay_ms < late_raw) {
            late_raw = tl->points[idx].raw_delay_ms;
            late_arr = tl->points[idx].arrival_time_ms;
        }
    }

    if (late_arr - early_arr < 1.0) {
        return -1.0;
    }

    return (late_raw - early_raw) / (late_arr - early_arr)
        + XQC_GCC_TL_SLOPE_CAP_UNCERTAINTY;
}

static uint32_t
xqc_gcc_tl_modified_trend_nd(const xqc_gcc_trendline_t *tl)
{
    /* Scale by regression window, not lifetime ack count (weak-net / burst ACK). */
    uint32_t nd = tl->count;
    if (nd < 2) {
        nd = tl->num_of_deltas;
    }
    if (nd > XQC_GCC_TL_WINDOW_SIZE) {
        nd = XQC_GCC_TL_WINDOW_SIZE;
    }
    return nd;
}

static void
xqc_gcc_tl_update_threshold(xqc_gcc_trendline_t *tl, double modified_trend, int64_t now_ms)
{
    int64_t time_delta_ms;

    if (tl->last_threshold_update_ms < 0) {
        tl->last_threshold_update_ms = now_ms;
        return;
    }

    if (fabs(modified_trend) > (double)tl->threshold_ms + XQC_GCC_TL_MAX_ADAPT_OFFSET_MS) {
        tl->last_threshold_update_ms = now_ms;
        return;
    }

    time_delta_ms = now_ms - tl->last_threshold_update_ms;
    if (time_delta_ms > 100) {
        time_delta_ms = 100;
    }

    {
        double k = (fabs(modified_trend) < (double)tl->threshold_ms)
            ? XQC_GCC_TL_THRESHOLD_K_DOWN : XQC_GCC_TL_THRESHOLD_K_UP;
        double updated = (double)tl->threshold_ms
            + k * (fabs(modified_trend) - (double)tl->threshold_ms) * time_delta_ms;
        if (updated < (double)XQC_GCC_TL_THRESHOLD_MIN_MS) {
            updated = (double)XQC_GCC_TL_THRESHOLD_MIN_MS;
        } else if (updated > (double)XQC_GCC_TL_THRESHOLD_MAX_MS) {
            updated = (double)XQC_GCC_TL_THRESHOLD_MAX_MS;
        }
        tl->threshold_ms = (float)updated;
    }
    tl->last_threshold_update_ms = now_ms;
}

static void
xqc_gcc_tl_detect(xqc_gcc_trendline_t *tl, double trend, double send_delta_ms, int64_t now_ms)
{
    uint32_t nd;
    double modified_trend;
    double th = (double)tl->threshold_ms;

    if (tl->num_of_deltas < 2 || tl->count < XQC_GCC_TL_WINDOW_SIZE) {
        tl->usage = XQC_GCC_BW_NORMAL;
        tl->last_modified_trend = 0;
        return;
    }

    nd = xqc_gcc_tl_modified_trend_nd(tl);
    modified_trend = (double)nd * trend * XQC_GCC_TL_THRESHOLD_GAIN;
    tl->last_modified_trend = modified_trend;

    if (modified_trend > th) {
        tl->underuse_counter = 0;
        if (tl->time_over_using_ms < 0) {
            tl->time_over_using_ms = (int64_t)(send_delta_ms / 2.0);
        } else {
            tl->time_over_using_ms += (int64_t)send_delta_ms;
        }
        tl->overuse_counter++;
        if (tl->time_over_using_ms > XQC_GCC_TL_OVERUSING_TIME_THRESHOLD_MS
            && tl->overuse_counter > 1 && trend >= tl->prev_trend) {
            tl->time_over_using_ms = 0;
            tl->overuse_counter = 0;
            tl->usage = XQC_GCC_BW_OVERUSING;
        }
    } else if (modified_trend < -th) {
        tl->time_over_using_ms = -1;
        tl->overuse_counter = 0;
        tl->underuse_counter++;
        if (tl->underuse_counter >= XQC_GCC_TL_UNDERUSE_COUNTER_TH) {
            tl->usage = XQC_GCC_BW_UNDERUSING;
        } else {
            tl->usage = XQC_GCC_BW_NORMAL;
        }
    } else {
        tl->time_over_using_ms = -1;
        tl->overuse_counter = 0;
        tl->underuse_counter = 0;
        tl->usage = XQC_GCC_BW_NORMAL;
    }

    tl->prev_trend = trend;
    xqc_gcc_tl_update_threshold(tl, modified_trend, now_ms);
}

xqc_gcc_bandwidth_usage_e
xqc_gcc_tl_update(xqc_gcc_trendline_t *tl,
    xqc_usec_t send_delta_us, xqc_usec_t recv_delta_us, int64_t arrival_time_ms)
{
    double send_delta_ms = (double)send_delta_us / 1000.0;
    double recv_delta_ms = (double)recv_delta_us / 1000.0;
    double delta_ms = recv_delta_ms - send_delta_ms;
    double relative_arrival_ms;
    double trend;
    double cap;

    tl->num_of_deltas++;
    if (tl->num_of_deltas > XQC_GCC_TL_DELTA_COUNTER_MAX) {
        tl->num_of_deltas = XQC_GCC_TL_DELTA_COUNTER_MAX;
    }

    if (tl->first_arrival_time_ms < 0) {
        tl->first_arrival_time_ms = arrival_time_ms;
    }

    tl->accumulated_delay_ms += delta_ms;
    tl->smoothed_delay_ms = XQC_GCC_TL_SMOOTH_ALPHA * tl->smoothed_delay_ms
        + (1.0 - XQC_GCC_TL_SMOOTH_ALPHA) * tl->accumulated_delay_ms;

    relative_arrival_ms = (double)(arrival_time_ms - tl->first_arrival_time_ms);
    xqc_gcc_tl_push_point(tl, relative_arrival_ms, tl->smoothed_delay_ms,
        tl->accumulated_delay_ms);

    trend = tl->prev_trend;
    if (tl->count == XQC_GCC_TL_WINDOW_SIZE) {
        trend = xqc_gcc_tl_fit_slope(tl);
        cap = xqc_gcc_tl_compute_slope_cap(tl);
        if (trend >= 0 && cap >= 0 && trend > cap) {
            trend = cap;
        }
    }
    tl->last_slope = trend;
    xqc_gcc_tl_detect(tl, trend, send_delta_ms, arrival_time_ms);
    return tl->usage;
}

/* Legacy entry points: add_sample + detect_overuse map to xqc_gcc_tl_update */
void
xqc_gcc_tl_add_sample(xqc_gcc_trendline_t *tl,
    xqc_usec_t send_delta_us, xqc_usec_t recv_delta_us, xqc_usec_t now_us)
{
    int64_t arrival_time_ms = (int64_t)(now_us / 1000);
    xqc_gcc_tl_update(tl, send_delta_us, recv_delta_us, arrival_time_ms);
}

xqc_gcc_bandwidth_usage_e
xqc_gcc_tl_detect_overuse(xqc_gcc_trendline_t *tl)
{
    return tl->usage;
}

double
xqc_gcc_tl_get_slope(const xqc_gcc_trendline_t *tl)
{
    return tl ? tl->last_slope : 0.0;
}

double
xqc_gcc_tl_get_modified_trend(const xqc_gcc_trendline_t *tl)
{
    return tl ? tl->last_modified_trend : 0.0;
}

double
xqc_gcc_tl_get_smoothed_delay_ms(const xqc_gcc_trendline_t *tl)
{
    return tl ? tl->smoothed_delay_ms : 0.0;
}

xqc_gcc_bandwidth_usage_e
xqc_gcc_tl_get_usage(const xqc_gcc_trendline_t *tl)
{
    return tl ? tl->usage : XQC_GCC_BW_NORMAL;
}

float
xqc_gcc_tl_get_threshold(const xqc_gcc_trendline_t *tl)
{
    return tl ? tl->threshold_ms : 0.0f;
}

uint32_t
xqc_gcc_tl_get_count(const xqc_gcc_trendline_t *tl)
{
    return tl ? tl->count : 0;
}

uint32_t
xqc_gcc_tl_get_overuse_counter(const xqc_gcc_trendline_t *tl)
{
    return tl ? tl->overuse_counter : 0;
}

uint32_t
xqc_gcc_tl_get_underuse_counter(const xqc_gcc_trendline_t *tl)
{
    return tl ? tl->underuse_counter : 0;
}

#endif /* XQC_ENABLE_GCC_SENSOR */
