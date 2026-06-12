/**
 * @file xqc_gcc_sensor.c
 * @brief Goodput meter + queue-ratio bandwidth usage for application rate control.
 */

#include "src/congestion_control/xqc_gcc_sensor.h"

#ifdef XQC_ENABLE_GCC_SENSOR

#include "src/congestion_control/xqc_sample.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_conn.h"
#include "src/common/xqc_time.h"
#include <xquic/xquic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#define XQC_GCC_ACK_RATE_WINDOW_US          1000000
#define XQC_GCC_FEEDBACK_INTERVAL_MS        1000
#define XQC_GCC_MIN_RTT_WINDOW_US           3000000
#define XQC_GCC_MIN_RTT_RING_SIZE             32
#define XQC_GCC_GOODPUT_EMA_NEW_NUM           3
#define XQC_GCC_GOODPUT_EMA_NEW_DEN           10
#define XQC_GCC_QUEUE_OVER_RATIO            0.50f
#define XQC_GCC_QUEUE_UNDER_RATIO           0.08f
#define XQC_GCC_OVER_STREAK_TH                3
#define XQC_GCC_MIN_RTT_SAMPLE_MAX_RATIO    1.12f
#define XQC_GCC_APP_LIMITED_INFLIGHT_BYTES    8192
#define XQC_GCC_UNDER_GOODPUT_GAIN          1.10f

typedef struct xqc_gcc_min_rtt_window_s {
    xqc_usec_t  ts_us[XQC_GCC_MIN_RTT_RING_SIZE];
    uint32_t    rtt_us[XQC_GCC_MIN_RTT_RING_SIZE];
    uint8_t     count;
    uint8_t     head;
} xqc_gcc_min_rtt_window_t;

size_t
xqc_gcc_sensor_size(void)
{
    return sizeof(xqc_gcc_sensor_t);
}

void
xqc_gcc_sensor_init(xqc_gcc_sensor_t *sensor)
{
    memset(sensor, 0, sizeof(*sensor));
    sensor->last_usage = XQC_GCC_BW_NORMAL;
    sensor->min_rtt_us = UINT32_MAX;
    sensor->min_rtt_win = calloc(1, sizeof(xqc_gcc_min_rtt_window_t));
}

void
xqc_gcc_sensor_destroy(xqc_gcc_sensor_t *sensor)
{
    if (!sensor) {
        return;
    }
    free(sensor->ia);
    free(sensor->tl);
    free(sensor->min_rtt_win);
    sensor->ia = NULL;
    sensor->tl = NULL;
    sensor->min_rtt_win = NULL;
}

static void
xqc_gcc_sensor_update_ack_rate(xqc_gcc_sensor_t *sensor, uint32_t acked_bytes, xqc_usec_t now_us)
{
    if (sensor->ack_rate_window_start_us == 0) {
        sensor->ack_rate_window_start_us = now_us;
        sensor->ack_bytes_acc = acked_bytes;
        return;
    }

    sensor->ack_bytes_acc += acked_bytes;
    xqc_usec_t elapsed = now_us - sensor->ack_rate_window_start_us;
    if (elapsed >= XQC_GCC_ACK_RATE_WINDOW_US) {
        if (elapsed > 0) {
            sensor->ack_rate_bps = (uint32_t)((uint64_t)sensor->ack_bytes_acc * 8000000ULL / elapsed);
        }
        sensor->ack_bytes_acc = 0;
        sensor->ack_rate_window_start_us = now_us;
    }
}

static void
xqc_gcc_sensor_recompute_min_rtt(xqc_gcc_sensor_t *sensor)
{
    xqc_gcc_min_rtt_window_t *win = sensor->min_rtt_win;
    uint32_t min_rtt = UINT32_MAX;
    uint8_t i;

    if (!win || win->count == 0) {
        sensor->min_rtt_us = UINT32_MAX;
        return;
    }

    for (i = 0; i < win->count; ++i) {
        uint8_t idx = (uint8_t)((win->head + i) % XQC_GCC_MIN_RTT_RING_SIZE);
        if (win->rtt_us[idx] < min_rtt) {
            min_rtt = win->rtt_us[idx];
        }
    }
    sensor->min_rtt_us = min_rtt;
}

static void
xqc_gcc_sensor_update_min_rtt_window(xqc_gcc_sensor_t *sensor, uint32_t rtt_us,
    xqc_usec_t now_us)
{
    xqc_gcc_min_rtt_window_t *win = sensor->min_rtt_win;
    xqc_usec_t cutoff;
    uint8_t tail;

    if (!win || rtt_us == 0) {
        return;
    }

    /* Only baseline (non-queued) RTT samples update min_rtt. */
    if (sensor->min_rtt_us != UINT32_MAX && sensor->min_rtt_us > 0
        && rtt_us > (uint32_t)(sensor->min_rtt_us * XQC_GCC_MIN_RTT_SAMPLE_MAX_RATIO)) {
        return;
    }

    cutoff = (now_us > XQC_GCC_MIN_RTT_WINDOW_US)
        ? (now_us - XQC_GCC_MIN_RTT_WINDOW_US) : 0;
    while (win->count > 0) {
        if (win->ts_us[win->head] >= cutoff) {
            break;
        }
        win->head = (uint8_t)((win->head + 1) % XQC_GCC_MIN_RTT_RING_SIZE);
        win->count--;
    }

    if (win->count < XQC_GCC_MIN_RTT_RING_SIZE) {
        tail = (uint8_t)((win->head + win->count) % XQC_GCC_MIN_RTT_RING_SIZE);
        win->count++;
    } else {
        win->head = (uint8_t)((win->head + 1) % XQC_GCC_MIN_RTT_RING_SIZE);
        tail = (uint8_t)((win->head + win->count - 1) % XQC_GCC_MIN_RTT_RING_SIZE);
    }

    win->ts_us[tail] = now_us;
    win->rtt_us[tail] = rtt_us;
    xqc_gcc_sensor_recompute_min_rtt(sensor);
}

static uint32_t
xqc_gcc_sensor_goodput_bps(xqc_gcc_sensor_t *sensor, xqc_sample_t *sampler)
{
    uint32_t goodput = sensor->ack_rate_bps;

    if (sampler->delivery_rate > 0) {
        uint32_t delivery_bps = (uint32_t)((uint64_t)sampler->delivery_rate * 8);
        if (goodput == 0 || delivery_bps < goodput) {
            goodput = delivery_bps;
        }
    }
    return goodput;
}

static void
xqc_gcc_sensor_update_goodput_ema(xqc_gcc_sensor_t *sensor, uint32_t instant_bps)
{
    uint32_t capped;

    if (instant_bps == 0) {
        return;
    }
    capped = instant_bps;
    if (sensor->goodput_ema_bps > 0 && instant_bps > sensor->goodput_ema_bps * 2) {
        capped = sensor->goodput_ema_bps * 2;
    }
    if (sensor->goodput_ema_bps == 0) {
        sensor->goodput_ema_bps = capped;
        return;
    }
    sensor->goodput_ema_bps = (uint32_t)(
        ((uint64_t)sensor->goodput_ema_bps * (XQC_GCC_GOODPUT_EMA_NEW_DEN - XQC_GCC_GOODPUT_EMA_NEW_NUM)
        + (uint64_t)capped * XQC_GCC_GOODPUT_EMA_NEW_NUM) / XQC_GCC_GOODPUT_EMA_NEW_DEN);
}

static xqc_gcc_bandwidth_usage_e
xqc_gcc_sensor_compute_usage(xqc_gcc_sensor_t *sensor, xqc_sample_t *sampler,
    uint32_t queue_rtt_us, uint32_t goodput_bps)
{
    uint32_t min_rtt = sensor->min_rtt_us;
    float queue_ratio = 0.0f;

    if (min_rtt != UINT32_MAX && min_rtt > 0 && queue_rtt_us > min_rtt) {
        queue_ratio = (float)(queue_rtt_us - min_rtt) / (float)min_rtt;
    }

    /* App-limited: small inflight cannot build a sustained queue signal. */
    if (sampler && sampler->bytes_inflight <= XQC_GCC_APP_LIMITED_INFLIGHT_BYTES) {
        sensor->over_streak = 0;
        if (queue_ratio < XQC_GCC_QUEUE_UNDER_RATIO && goodput_bps > 0
            && sensor->goodput_ema_bps > 0
            && goodput_bps > (uint32_t)(sensor->goodput_ema_bps * XQC_GCC_UNDER_GOODPUT_GAIN)) {
            return XQC_GCC_BW_UNDERUSING;
        }
        return XQC_GCC_BW_NORMAL;
    }

    if (queue_ratio > XQC_GCC_QUEUE_OVER_RATIO) {
        if (sensor->over_streak < 255) {
            sensor->over_streak++;
        }
    } else {
        sensor->over_streak = 0;
    }

    if (sensor->over_streak >= XQC_GCC_OVER_STREAK_TH) {
        return XQC_GCC_BW_OVERUSING;
    }

    if (queue_ratio < XQC_GCC_QUEUE_UNDER_RATIO && goodput_bps > 0
        && sensor->goodput_ema_bps > 0
        && goodput_bps > (uint32_t)(sensor->goodput_ema_bps * XQC_GCC_UNDER_GOODPUT_GAIN)) {
        return XQC_GCC_BW_UNDERUSING;
    }

    return XQC_GCC_BW_NORMAL;
}

static void
xqc_gcc_sensor_maybe_notify(xqc_connection_t *conn, xqc_gcc_sensor_t *sensor,
    xqc_send_ctl_t *send_ctl, xqc_gcc_bandwidth_usage_e usage, xqc_usec_t now_us)
{
    if (!conn || !conn->conn_settings.gcc_feedback_notify) {
        if (getenv("XQC_GCC_SENSOR_DEBUG")) {
            fprintf(stderr, "[gcc] skip notify: feedback_notify callback is NULL\n");
        }
        return;
    }

    uint32_t interval_ms = conn->conn_settings.gcc_feedback_interval_ms;
    if (interval_ms == 0) {
        interval_ms = XQC_GCC_FEEDBACK_INTERVAL_MS;
    }
    xqc_usec_t interval_us = (xqc_usec_t)interval_ms * 1000;

    int interval_elapsed = (sensor->last_notify_us == 0)
        || (now_us - sensor->last_notify_us >= interval_us);
    int entering_over = (usage == XQC_GCC_BW_OVERUSING
        && sensor->last_usage != XQC_GCC_BW_OVERUSING);
    int leaving_over = (usage != XQC_GCC_BW_OVERUSING
        && sensor->last_usage == XQC_GCC_BW_OVERUSING);

    /* Periodic update + OVER edges only; suppress NORMAL/UND flip-flop storms. */
    if (!interval_elapsed && !entering_over && !leaving_over) {
        return;
    }

    xqc_gcc_transport_feedback_t fb;
    uint32_t report_bps;

    memset(&fb, 0, sizeof(fb));
    fb.usage = usage;
    fb.rtt_us = sensor->last_rtt_us;
    if (send_ctl && send_ctl->ctl_srtt > 0) {
        fb.rtt_us = send_ctl->ctl_srtt;
    }
    fb.min_rtt_us = (sensor->min_rtt_us != UINT32_MAX) ? sensor->min_rtt_us : 0;
    report_bps = sensor->ack_rate_bps > 0 ? sensor->ack_rate_bps : sensor->goodput_ema_bps;
    if (report_bps == 0) {
        report_bps = sensor->last_goodput_bps;
    }
    fb.ack_rate_bps = report_bps;
    fb.trendline_slope_scaled = 0;
    fb.timestamp_us = now_us;

    conn->conn_settings.gcc_feedback_notify(conn, &conn->scid_set.user_scid, &fb,
        conn->conn_settings.gcc_feedback_user_data);

    sensor->last_usage = usage;
    sensor->last_notify_us = now_us;
}

void
xqc_gcc_sensor_on_ack(xqc_connection_t *conn, xqc_send_ctl_t *send_ctl,
    xqc_sample_t *sampler, xqc_usec_t ack_recv_time)
{
    if (!conn || !conn->gcc_sensor || !sampler || !send_ctl) {
        return;
    }

    xqc_gcc_sensor_t *sensor = conn->gcc_sensor;
    xqc_usec_t now_us = ack_recv_time;
    uint32_t sample_rtt = 0;
    uint32_t queue_rtt = 0;
    uint32_t goodput_bps;
    xqc_gcc_bandwidth_usage_e usage;

    if (sampler->rtt > 0) {
        sample_rtt = sampler->rtt;
    } else if (send_ctl->ctl_srtt > 0) {
        sample_rtt = send_ctl->ctl_srtt;
    }
    if (sample_rtt > 0) {
        sensor->last_rtt_us = sample_rtt;
    }
    queue_rtt = send_ctl->ctl_srtt > 0 ? send_ctl->ctl_srtt : sensor->last_rtt_us;
    if (send_ctl->ctl_srtt > 0) {
        xqc_gcc_sensor_update_min_rtt_window(sensor, send_ctl->ctl_srtt, now_us);
    } else if (sample_rtt > 0) {
        xqc_gcc_sensor_update_min_rtt_window(sensor, sample_rtt, now_us);
    }

    if (sampler->acked > 0) {
        xqc_gcc_sensor_update_ack_rate(sensor, sampler->acked, now_us);
    }

    goodput_bps = xqc_gcc_sensor_goodput_bps(sensor, sampler);
    sensor->last_goodput_bps = goodput_bps;
    xqc_gcc_sensor_update_goodput_ema(sensor, goodput_bps);
    usage = xqc_gcc_sensor_compute_usage(sensor, sampler, queue_rtt, goodput_bps);

    if (getenv("XQC_GCC_SENSOR_DEBUG")) {
        char ts[32];
        struct timeval tv;
        struct tm tm;
        float queue_ratio = 0.0f;
        const char *usage_tag = "NRM";

        gettimeofday(&tv, NULL);
#ifdef XQC_SYS_WINDOWS
        localtime_s(&tm, &tv.tv_sec);
#else
        localtime_r(&tv.tv_sec, &tm);
#endif
        (void)strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);
        if (sensor->min_rtt_us != UINT32_MAX && sensor->min_rtt_us > 0
            && queue_rtt > sensor->min_rtt_us) {
            queue_ratio = (float)(queue_rtt - sensor->min_rtt_us)
                / (float)sensor->min_rtt_us;
        }
        if (usage == XQC_GCC_BW_OVERUSING) {
            usage_tag = "OVR";
        } else if (usage == XQC_GCC_BW_UNDERUSING) {
            usage_tag = "UND";
        }
        fprintf(stderr,
            "[%s] [gcc] goodput=%uK queue=%.2f usage=%s rtt=%u min=%u ema=%u inflight=%u\n",
            ts,
            (unsigned)(goodput_bps / 1000),
            (double)queue_ratio,
            usage_tag,
            (unsigned)sensor->last_rtt_us,
            (unsigned)((sensor->min_rtt_us != UINT32_MAX) ? sensor->min_rtt_us : 0),
            (unsigned)sensor->goodput_ema_bps,
            (unsigned)sampler->bytes_inflight);
    }

    xqc_gcc_sensor_maybe_notify(conn, sensor, send_ctl, usage, now_us);
}

xqc_gcc_bandwidth_usage_e
xqc_gcc_sensor_get_usage(const xqc_gcc_sensor_t *sensor)
{
    if (!sensor) {
        return XQC_GCC_BW_NORMAL;
    }
    return sensor->last_usage;
}

#endif /* XQC_ENABLE_GCC_SENSOR */
