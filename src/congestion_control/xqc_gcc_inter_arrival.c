/**
 * @file xqc_gcc_inter_arrival.c
 * @brief Packet-group inter-arrival delta computation (WebRTC GCC style).
 */

#include "src/congestion_control/xqc_gcc_sensor.h"

#ifdef XQC_ENABLE_GCC_SENSOR

#include <xquic/xquic.h>
#include <string.h>
#include <stdlib.h>

/* Align with ~500ms app pacing: one burst group per control interval */
#define XQC_GCC_BURST_THRESHOLD_US  400000

struct xqc_gcc_inter_arrival_s {
    xqc_usec_t  last_send_ts;
    xqc_usec_t  last_recv_ts;
    uint32_t    accumulated_size;
    uint8_t     initialized;
    uint8_t     current_group_started;
};

size_t
xqc_gcc_ia_size(void)
{
    return sizeof(xqc_gcc_inter_arrival_t);
}

void
xqc_gcc_ia_reset(xqc_gcc_inter_arrival_t *ia)
{
    memset(ia, 0, sizeof(*ia));
}

void
xqc_gcc_ia_init(xqc_gcc_inter_arrival_t *ia)
{
    xqc_gcc_ia_reset(ia);
}

/**
 * @return 1 if a completed group produced send_delta/recv_delta; 0 otherwise.
 */
int
xqc_gcc_ia_compute_deltas(xqc_gcc_inter_arrival_t *ia,
    xqc_usec_t send_ts_us, xqc_usec_t recv_ts_us, uint32_t size,
    xqc_usec_t *send_delta_us, xqc_usec_t *recv_delta_us, uint32_t *size_delta)
{
    if (!ia->initialized) {
        ia->last_send_ts = send_ts_us;
        ia->last_recv_ts = recv_ts_us;
        ia->accumulated_size = size;
        ia->initialized = 1;
        ia->current_group_started = 1;
        return 0;
    }

    xqc_usec_t send_diff = send_ts_us - ia->last_send_ts;

    if (send_diff < XQC_GCC_BURST_THRESHOLD_US && ia->current_group_started) {
        ia->accumulated_size += size;
        return 0;
    }

    if (!ia->current_group_started) {
        ia->last_send_ts = send_ts_us;
        ia->last_recv_ts = recv_ts_us;
        ia->accumulated_size = size;
        ia->current_group_started = 1;
        return 0;
    }

    *send_delta_us = send_ts_us - ia->last_send_ts;
    *recv_delta_us = recv_ts_us - ia->last_recv_ts;
    *size_delta = ia->accumulated_size;

    ia->last_send_ts = send_ts_us;
    ia->last_recv_ts = recv_ts_us;
    ia->accumulated_size = size;
    ia->current_group_started = 1;

    if (*send_delta_us == 0) {
        return 0;
    }
    return 1;
}

#endif /* XQC_ENABLE_GCC_SENSOR */
