/**
 * @file xqc_gcc_sensor.h
 * @brief WebRTC-style GCC delay sensor (inter-arrival + trendline), no AIMD.
 */

#ifndef XQC_GCC_SENSOR_H
#define XQC_GCC_SENSOR_H

#include <xquic/xquic.h>

#ifdef XQC_ENABLE_GCC_SENSOR

typedef struct xqc_gcc_inter_arrival_s xqc_gcc_inter_arrival_t;
typedef struct xqc_gcc_trendline_s       xqc_gcc_trendline_t;

typedef struct xqc_gcc_sensor_s {
    xqc_gcc_inter_arrival_t    *ia;
    xqc_gcc_trendline_t        *tl;
    xqc_gcc_bandwidth_usage_e   last_usage;
    xqc_usec_t                  last_notify_us;
    uint64_t                    ack_bytes_acc;
    xqc_usec_t                  ack_rate_window_start_us;
    uint32_t                    ack_rate_bps;
    uint32_t                    last_goodput_bps;
    uint32_t                    goodput_ema_bps;
    uint32_t                    last_rtt_us;
    uint32_t                    min_rtt_us;
    uint8_t                     over_streak;
    struct xqc_gcc_min_rtt_window_s *min_rtt_win;
} xqc_gcc_sensor_t;

size_t xqc_gcc_sensor_size(void);

void xqc_gcc_sensor_init(xqc_gcc_sensor_t *sensor);

void xqc_gcc_sensor_destroy(xqc_gcc_sensor_t *sensor);

void xqc_gcc_sensor_on_ack(xqc_connection_t *conn, xqc_send_ctl_t *send_ctl,
    xqc_sample_t *sampler, xqc_usec_t ack_recv_time);

xqc_gcc_bandwidth_usage_e xqc_gcc_sensor_get_usage(const xqc_gcc_sensor_t *sensor);

#endif /* XQC_ENABLE_GCC_SENSOR */

#endif /* XQC_GCC_SENSOR_H */
