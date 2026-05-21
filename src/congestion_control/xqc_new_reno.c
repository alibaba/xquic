/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <xquic/xquic.h>
#include "src/congestion_control/xqc_new_reno.h"
#include "src/common/xqc_config.h"
#include "src/common/xqc_time.h"
#include "src/transport/xqc_packet.h"

/* https://tools.ietf.org/html/draft-ietf-quic-recovery-19#appendix-B */

#define XQC_kMaxDatagramSize XQC_MSS
#define XQC_kMinimumWindow (2 * XQC_kMaxDatagramSize)

/*
 * RFC 9002 Section 7.2: endpoints SHOULD use an initial congestion
 * window of ten times the maximum datagram size, while limiting the
 * window to the larger of 14720 bytes or twice the maximum datagram
 * size. That is:
 *
 *     IW = min(10 * kMaxDatagramSize,
 *              max(2 * kMaxDatagramSize, 14720))
 *
 * With the default XQC_MSS the 14720-byte ceiling is not binding, but
 * a deployment built with a larger maximum datagram size (for example,
 * jumbo frames) would otherwise compute an initial window well above
 * the value the RFC permits.
 */
#define XQC_kInitialWindowMinBytes 14720
#define XQC_kInitialWindow                                                    \
    xqc_min(10 * XQC_kMaxDatagramSize,                                        \
            xqc_max(2 * XQC_kMaxDatagramSize, XQC_kInitialWindowMinBytes))

#define XQC_kLossReductionFactor (0.5f)

size_t
xqc_reno_size()
{
    return sizeof(xqc_new_reno_t);
}

static void
xqc_reno_init(void *cong_ctl, xqc_send_ctl_t *ctl_ctx, xqc_cc_params_t cc_params)
{
    xqc_new_reno_t *reno = (xqc_new_reno_t*)(cong_ctl);

    reno->reno_congestion_window = XQC_kInitialWindow;
    reno->reno_ssthresh = 0xffffffff;
    reno->reno_recovery_start_time = 0;
    reno->ctl_ctx = ctl_ctx;
}

/**
 * InRecovery
 */
static int
xqc_reno_was_pkt_sent_in_recovery(void *cong_ctl, xqc_usec_t sent_time)
{
    xqc_new_reno_t *reno = (xqc_new_reno_t*)(cong_ctl);
    return sent_time <= reno->reno_recovery_start_time;
}

static void
xqc_reno_on_lost(void *cong_ctl, xqc_usec_t lost_sent_time)
{
    xqc_new_reno_t *reno = (xqc_new_reno_t*)(cong_ctl);

    /*
     * Start a new congestion event if the sent time is larger
     * than the start time of the previous recovery epoch.
     */
    if (!xqc_reno_was_pkt_sent_in_recovery(cong_ctl, lost_sent_time)) {
        reno->reno_recovery_start_time = xqc_monotonic_timestamp();
        reno->reno_congestion_window *= XQC_kLossReductionFactor;
        reno->reno_congestion_window = xqc_max(reno->reno_congestion_window, XQC_kMinimumWindow);
        reno->reno_ssthresh = reno->reno_congestion_window;
    }
}

static void
xqc_reno_on_ack(void *cong_ctl, xqc_packet_out_t *po, xqc_usec_t now)
{
    xqc_new_reno_t *reno = (xqc_new_reno_t*)(cong_ctl);
    xqc_usec_t sent_time = po->po_sent_time;
    uint32_t acked_bytes = po->po_used_size;
    if (xqc_reno_was_pkt_sent_in_recovery(cong_ctl, sent_time)) {
        /* Do not increase congestion window in recovery period. */
        return;
    }

    if (sent_time > reno->reno_recovery_start_time) {
        reno->reno_recovery_start_time = 0;
    }

    if (reno->ctl_ctx && !xqc_send_ctl_is_cwnd_limited(reno->ctl_ctx)) {
        return;
    }

    if (reno->reno_congestion_window < reno->reno_ssthresh) {
        /* Slow start. */
        reno->reno_congestion_window += acked_bytes;
    }
    else {
        /* Congestion avoidance. */
        reno->reno_congestion_window += XQC_kMaxDatagramSize * acked_bytes / reno->reno_congestion_window;
    }
}

uint64_t
xqc_reno_get_cwnd(void *cong_ctl)
{
    xqc_new_reno_t *reno = (xqc_new_reno_t*)(cong_ctl);
    return reno->reno_congestion_window;
}

void
xqc_reno_reset_cwnd(void *cong_ctl)
{
    xqc_new_reno_t *reno = (xqc_new_reno_t*)(cong_ctl);
    reno->reno_congestion_window = XQC_kMinimumWindow;
    reno->reno_recovery_start_time  = 0; /* clear recovery epoch. */
}

int
xqc_reno_in_slow_start(void *cong_ctl)
{
    xqc_new_reno_t *reno = (xqc_new_reno_t*)(cong_ctl);
    return reno->reno_congestion_window < reno->reno_ssthresh ? 1 : 0;
}

void
xqc_reno_restart_from_idle(void *cong_ctl, uint64_t arg) {
    return;
}

static int
xqc_reno_in_recovery(void *cong_ctl) {
    xqc_new_reno_t *reno = (xqc_new_reno_t*)(cong_ctl);
    return reno->reno_recovery_start_time > 0;
}

const xqc_cong_ctrl_callback_t xqc_reno_cb = {
    .xqc_cong_ctl_size              = xqc_reno_size,
    .xqc_cong_ctl_init              = xqc_reno_init,
    .xqc_cong_ctl_on_lost           = xqc_reno_on_lost,
    .xqc_cong_ctl_on_ack            = xqc_reno_on_ack,
    .xqc_cong_ctl_get_cwnd          = xqc_reno_get_cwnd,
    .xqc_cong_ctl_reset_cwnd        = xqc_reno_reset_cwnd,
    .xqc_cong_ctl_in_slow_start     = xqc_reno_in_slow_start,
    .xqc_cong_ctl_restart_from_idle = xqc_reno_restart_from_idle,
    .xqc_cong_ctl_in_recovery       = xqc_reno_in_recovery,
};
