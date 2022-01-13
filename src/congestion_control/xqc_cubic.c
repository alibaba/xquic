/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 * 
 * CUBIC based on https://tools.ietf.org/html/rfc8312
 */

#include "src/congestion_control/xqc_cubic.h"
#include "src/common/xqc_config.h"
#include <math.h>

#define XQC_CUBIC_FAST_CONVERGENCE  1
#define XQC_CUBIC_MSS               1460
#define XQC_CUBIC_BETA              718     /* 718/1024=0.7 */
#define XQC_CUBIC_BETA_SCALE        1024
#define XQC_CUBIC_C                 410     /* 410/1024=0.4 */
#define XQC_CUBE_SCALE              40u     /* 2^40=1024 * 1024^3 */
#define XQC_CUBIC_TIME_SCALE        10u
#define XQC_CUBIC_MAX_SSTHRESH      0xFFFFFFFF

#define XQC_CUBIC_MIN_WIN           (4 * XQC_CUBIC_MSS)
#define XQC_CUBIC_MAX_INIT_WIN      (100 * XQC_CUBIC_MSS)
#define XQC_CUBIC_INIT_WIN          (32 * XQC_CUBIC_MSS)

const static uint64_t xqc_cube_factor =
    (1ull << XQC_CUBE_SCALE) / XQC_CUBIC_C / XQC_CUBIC_MSS;

/*
 * Compute congestion window to use.
 * W_cubic(t) = C*(t-K)^3 + W_max (Eq. 1)
 * K = cubic_root(W_max*(1-beta_cubic)/C) (Eq. 2)
 * t: the time difference between the current time and the last window reduction
 * K: the time period for the function to grow from W to Wmax
 * C: window growth factor
 * beta: window reduction factor
 */
static void
xqc_cubic_update(void *cong_ctl, uint32_t acked_bytes, xqc_usec_t now)
{
    xqc_cubic_t    *cubic = (xqc_cubic_t *)(cong_ctl);
    uint64_t        t;      /* unit: ms */
    uint64_t        offs;   /* offs = |t - K| */
    uint64_t        delta, bic_target;  /* delta = C*(t-K)^3 */

    /* First ACK after a loss event. */
    if (cubic->epoch_start == 0) {
        cubic->epoch_start = now;

        /* take max(last_max_cwnd, cwnd) as current Wmax origin point */
        if (cubic->cwnd >= cubic->last_max_cwnd) {
            /* exceed origin point, use cwnd as the new point */
            cubic->bic_K = 0;
            cubic->bic_origin_point = cubic->cwnd;

        } else {
            /*
             * K = cubic_root(W_max*(1-beta_cubic)/C) = cubic_root((W_max-cwnd)/C)
             * cube_factor = (1ull << XQC_CUBE_SCALE) / XQC_CUBIC_C / XQC_MSS
             *             = 2^40 / (410 * MSS) = 2^30 / (410/1024*MSS)
             *             = 2^30 / (C*MSS)
             */
            cubic->bic_K = cbrt(xqc_cube_factor * (cubic->last_max_cwnd - cubic->cwnd));
            cubic->bic_origin_point = cubic->last_max_cwnd;
        }
    }

    /*
     * t = elapsed_time * 1024 / 1000000, convert microseconds to milliseconds,
     * multiply by 1024 in order to be able to use bit operations later.
     */
    t = (now + cubic->min_rtt - cubic->epoch_start) << XQC_CUBIC_TIME_SCALE / XQC_MICROS_PER_SECOND;

    /* calculate |t - K| */
    if (t < cubic->bic_K) {
        offs = cubic->bic_K - t;

    } else {
        offs = t - cubic->bic_K;
    }

    /* 410/1024 * off/1024 * off/1024 * off/1024 * MSS */
    delta = (XQC_CUBIC_C * offs * offs * offs * XQC_CUBIC_MSS) >> XQC_CUBE_SCALE;

    if (t < cubic->bic_K) {
        bic_target = cubic->bic_origin_point - delta;

    } else {
        bic_target = cubic->bic_origin_point + delta;
    }

    /* the maximum growth rate of CUBIC is 1.5x per RTT, i.e. 1 window every 2 ack. */
    bic_target = xqc_min(bic_target, cubic->cwnd + acked_bytes / 2);

    /* take the maximum of the cwnd of TCP reno and the cwnd of cubic */
    bic_target = xqc_max(cubic->tcp_cwnd, bic_target);

    if (bic_target == 0) {
        bic_target = cubic->init_cwnd;
    }

    cubic->cwnd = bic_target;
}

size_t
xqc_cubic_size()
{
    return sizeof(xqc_cubic_t);
}

static void
xqc_cubic_init(void *cong_ctl, xqc_send_ctl_t *ctl_ctx, xqc_cc_params_t cc_params)
{
    xqc_cubic_t *cubic = (xqc_cubic_t *)(cong_ctl);
    cubic->epoch_start = 0;
    cubic->cwnd = XQC_CUBIC_INIT_WIN;
    cubic->tcp_cwnd = XQC_CUBIC_INIT_WIN;
    cubic->last_max_cwnd = XQC_CUBIC_INIT_WIN;
    cubic->ssthresh = XQC_CUBIC_MAX_SSTHRESH;

    if (cc_params.customize_on) {
        cc_params.init_cwnd *= XQC_CUBIC_MSS;
        cubic->init_cwnd =
                cc_params.init_cwnd >= XQC_CUBIC_MIN_WIN && cc_params.init_cwnd <= XQC_CUBIC_MAX_INIT_WIN ?
                cc_params.init_cwnd : XQC_CUBIC_INIT_WIN;
    }
}


static void
xqc_cubic_on_lost(void *cong_ctl, xqc_usec_t lost_sent_time)
{
    xqc_cubic_t *cubic = (xqc_cubic_t*)(cong_ctl);

    cubic->epoch_start = 0;

    /* should we make room for others */
    if (XQC_CUBIC_FAST_CONVERGENCE && cubic->cwnd < cubic->last_max_cwnd) {
        /* (1.0f + XQC_CUBIC_BETA) / 2.0f convert to bitwise operations */
        cubic->last_max_cwnd = cubic->cwnd * (XQC_CUBIC_BETA_SCALE + XQC_CUBIC_BETA) / (2 * XQC_CUBIC_BETA_SCALE);

    } else {
        cubic->last_max_cwnd = cubic->cwnd;
    }

    /* Multiplicative Decrease */
    cubic->cwnd = cubic->cwnd * XQC_CUBIC_BETA / XQC_CUBIC_BETA_SCALE;
    cubic->tcp_cwnd = cubic->cwnd;
    /* threshold is at least XQC_CUBIC_MIN_WIN */
    cubic->ssthresh = xqc_max(cubic->cwnd, XQC_CUBIC_MIN_WIN);
}


static void
xqc_cubic_on_ack(void *cong_ctl, xqc_packet_out_t *po, xqc_usec_t now)
{
    xqc_cubic_t *cubic = (xqc_cubic_t *)(cong_ctl);
    xqc_usec_t  sent_time = po->po_sent_time;
    uint32_t    acked_bytes = po->po_used_size;

    xqc_usec_t  rtt = now - sent_time;

    if (cubic->min_rtt == 0 || rtt < cubic->min_rtt) {
        cubic->min_rtt = rtt;
    }

    if (cubic->cwnd < cubic->ssthresh) {
        /* slow start */
        cubic->tcp_cwnd += acked_bytes;
        cubic->cwnd += acked_bytes;

    } else {
        /* congestion avoidance */
        cubic->tcp_cwnd += XQC_CUBIC_MSS * XQC_CUBIC_MSS / cubic->tcp_cwnd;
        xqc_cubic_update(cong_ctl, acked_bytes, now);
    }
}

uint64_t
xqc_cubic_get_cwnd(void *cong_ctl)
{
    xqc_cubic_t *cubic = (xqc_cubic_t *)(cong_ctl);
    return cubic->cwnd;
}

void
xqc_cubic_reset_cwnd(void *cong_ctl)
{
    xqc_cubic_t *cubic = (xqc_cubic_t *)(cong_ctl);
    cubic->epoch_start = 0;
    cubic->cwnd = XQC_CUBIC_MIN_WIN;
    cubic->tcp_cwnd = XQC_CUBIC_MIN_WIN;
    cubic->last_max_cwnd = XQC_CUBIC_MIN_WIN;
}

int32_t
xqc_cubic_in_slow_start(void *cong_ctl)
{
    xqc_cubic_t *cubic = (xqc_cubic_t *)(cong_ctl);
    return cubic->cwnd < cubic->ssthresh ? 1 : 0;
}

void
xqc_cubic_restart_from_idle(void *cong_ctl, uint64_t arg)
{
    return;
}

static int
xqc_cubic_in_recovery(void *cong_ctl)
{
    return 0;
}

const xqc_cong_ctrl_callback_t xqc_cubic_cb = {
    .xqc_cong_ctl_size              = xqc_cubic_size,
    .xqc_cong_ctl_init              = xqc_cubic_init,
    .xqc_cong_ctl_on_lost           = xqc_cubic_on_lost,
    .xqc_cong_ctl_on_ack            = xqc_cubic_on_ack,
    .xqc_cong_ctl_get_cwnd          = xqc_cubic_get_cwnd,
    .xqc_cong_ctl_reset_cwnd        = xqc_cubic_reset_cwnd,
    .xqc_cong_ctl_in_slow_start     = xqc_cubic_in_slow_start,
    .xqc_cong_ctl_restart_from_idle = xqc_cubic_restart_from_idle,
    .xqc_cong_ctl_in_recovery       = xqc_cubic_in_recovery,
};
