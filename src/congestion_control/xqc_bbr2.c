/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "src/congestion_control/xqc_bbr2.h"
#include "src/congestion_control/xqc_sample.h"
#include "src/common/xqc_time.h"
#include "src/common/xqc_config.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_packet.h"

#define XQC_BBR2_MAX_DATAGRAM_SIZE XQC_QUIC_MSS
#define XQC_BBR2_MIN_WINDOW (4 * XQC_BBR2_MAX_DATAGRAM_SIZE)
/* The RECOMMENDED value is the minimum of 10 * kMaxDatagramSize and max(2* kMaxDatagramSize, 14720)). */
#define XQC_BBR2_INITIAL_WINDOW (32 * XQC_BBR2_MAX_DATAGRAM_SIZE)
/* Pacing gain cycle rounds */
#define XQC_BBR2_INF_RTT 0x7fffffff
#define XQC_BBR2_UNSIGNED_INF ~0U
#define XQC_BBR2_CYCLE_LENGTH 8

/* Window of min rtt filter, in sec */
static const uint32_t xqc_bbr2_minrtt_win_size_us = 2500000;
static const uint32_t xqc_bbr2_probe_minrtt_win_size_us = 2500000;
/* Minimum time spent in bbr2_PROBE_RTT, in usec */
static const uint32_t xqc_bbr2_probertt_time_us = 200000;
/* Initial rtt before any samples are received, in usec */
static const uint64_t xqc_bbr2_initial_rtt_us = 100;
/* The gain of pacing rate for START_UP, 2/(ln2) */
static const float xqc_bbr2_high_gain = 2.885;
/* Gain in bbr2_DRAIN */
static const float xqc_bbr2_drain_gain = 0.75;
/* Gain for cwnd in probe_bw, like slow start */
static const float xqc_bbr2_cwnd_gain = 2.0;
/* Cycle of gains in PROBE_BW for pacing rate */
#if XQC_BBR2_PLUS_ENABLED
static const float xqc_bbr2_pacing_gain[] = {1.25, 0.75, 1, 1, 1.10, 1, 1, 1};
#else
static const float xqc_bbr2_pacing_gain[] = {1.25, 0.75, 1, 1, 1, 1, 1, 1};
#endif
/* Minimum packets that need to ensure ack if there is delayed ack */
static const uint32_t xqc_bbr2_min_cwnd = 4 * XQC_BBR2_MAX_DATAGRAM_SIZE;
/* If bandwidth has increased by 1.25, there may be more bandwidth available */
static const float xqc_bbr2_fullbw_thresh = 1.25;
/* After 3 rounds bandwidth less than (1.25x), estimate the pipe is full */
static const uint32_t xqc_bbr2_fullbw_cnt = 3;
static const float xqc_bbr2_probe_rtt_gain = 0.75;
static const uint32_t xqc_bbr2_extra_ack_gain = 1;
static const float xqc_bbr2_max_extra_ack_time = 0.1;
static const uint32_t xqc_bbr2_ack_epoch_acked_reset_thresh = 1 << 20;
static const float xqc_bbr2_startup_cwnd_gain = 2;
static const bool xqc_bbr2_extra_ack_in_startup = 1;
/* 10 packet-timed rtt */
static const uint32_t xqc_bbr2_extra_ack_win_rtt = 5;
static const uint32_t xqc_bbr2_extra_ack_win_rtt_in_startup = 1;
static const float xqc_bbr2_startup_pacing_gain_on_lost = 1.5;
static const float xqc_bbr2_inflight_lo_beta = 0.3;
static const uint8_t xqc_bbr2_full_loss_cnt = 8;
/* resistant to 2% random loss */
static const float xqc_bbr2_loss_thresh = 0.02;
static const uint32_t xqc_bbr2_bw_probe_max_rounds = 63;
static const uint32_t xqc_bbr2_bw_probe_rand_rounds = 2;
static const uint32_t xqc_bbr2_bw_probe_base_us = 2 * MSEC2SEC;
static const uint32_t xqc_bbr2_bw_probe_rand_us = 1 * MSEC2SEC;
static const float xqc_bbr2_bw_probe_reno_gain = 1.0;
static const uint32_t xqc_bbr2_refill_and_inc = 0;
static const float xqc_bbr2_bw_probe_up_gain = 1.25;
static const float xqc_bbr2_inflight_headroom = 0.15;
static const float xqc_bbr2_pacing_rate_margin_percent = 0.01;

/* For BBRv2 + */
/* 5RTT */
#if XQC_BBR2_PLUS_ENABLED
static const int xqc_bbr2_windowed_max_rtt_win_size = 5;
static const float xqc_bbr2_rtt_compensation_startup_thresh = 2;
static const float xqc_bbr2_rtt_compensation_thresh = 1;
static const float xqc_bbr2_rtt_compensation_cwnd_factor = 1;
/* Probe bw for every 4-8 RTTs */
static const int xqc_bbr2_fast_convergence_probe_round_base = 4;
static const int xqc_bbr2_fast_convergence_probe_round_rand = 4;
static const float xqc_bbr2_fast_convergence_rtt_factor = 1.25;
/* Tolerate jitters in 2ms */
static const float xqc_bbr2_fast_convergence_srtt_error = 2000;
/* If max bw has increased by 20%, we enter probe_up phase again */
static const float xqc_bbr2_fast_convergence_probe_again_factor = 1.20;
#endif

static void xqc_bbr2_raise_inflight_hi_slope(xqc_bbr2_t *);
static uint32_t xqc_bbr2_target_inflight(xqc_bbr2_t *bbr2);
static void xqc_bbr2_enter_probe_refill(xqc_bbr2_t *bbr2,
    xqc_sample_t *sampler, uint32_t cnt);
static bool xqc_bbr2_is_inflight_too_high(xqc_bbr2_t *bbr2,
    xqc_sample_t *sampler);
static void xqc_bbr2_set_cycle_idx(xqc_bbr2_t *bbr2,
    xqc_bbr2_pacing_gain_phase idx);
static void xqc_bbr2_enter_probe_down(xqc_bbr2_t *bbr2, xqc_sample_t *sampler);
static void xqc_bbr2_restore_cwnd(xqc_bbr2_t *bbr2);
static void xqc_bbr2_enter_probe_rtt(xqc_bbr2_t *bbr2);
static void xqc_bbr2_save_cwnd(xqc_bbr2_t *bbr2);
static bool xqc_bbr2_is_probing_bandwidth(xqc_bbr2_t *bbr2);

size_t
xqc_bbr2_size()
{
    return sizeof(xqc_bbr2_t);
}

static void
xqc_bbr2_enter_startup(xqc_bbr2_t *bbr2)
{
    bbr2->mode = BBR2_STARTUP;
    bbr2->pacing_gain = xqc_bbr2_high_gain;
    bbr2->cwnd_gain = xqc_bbr2_startup_cwnd_gain;
#if XQC_BBR2_PLUS_ENABLED
    bbr2->rtt_compensation_thresh = xqc_bbr2_rtt_compensation_startup_thresh;
#endif
}

static void
xqc_bbr2_init_pacing_rate(xqc_bbr2_t *bbr2, xqc_sample_t *sampler)
{
    uint64_t bandwidth;
    if (sampler->srtt) {
        bbr2->has_srtt = 1;
    }
    bandwidth = bbr2->congestion_window * (uint64_t)MSEC2SEC 
        / (sampler->srtt ? sampler->srtt : 1000);
    bbr2->pacing_rate = bbr2->pacing_gain * bandwidth;
}

static void
xqc_bbr2_reset_congestion_signals(void *cong_ctl)
{
    xqc_bbr2_t *bbr2 = (xqc_bbr2_t *)cong_ctl;

    bbr2->loss_in_round = 0;
    bbr2->loss_in_cycle = 0;
    bbr2->bw_latest = 0;
    bbr2->inflight_latest = 0;
}

static void
xqc_bbr2_init(void *cong_ctl, xqc_sample_t *sampler, xqc_cc_params_t cc_params)
{
    xqc_bbr2_t *bbr2 = (xqc_bbr2_t *)(cong_ctl);
    uint64_t now = xqc_monotonic_timestamp();
    memset(bbr2, 0, sizeof(*bbr2));

#if XQC_BBR2_PLUS_ENABLED
    xqc_win_filter_reset_u64(&bbr2->max_rtt, 0, 0);
    bbr2->max_rtt_win_len = xqc_bbr2_windowed_max_rtt_win_size;
    if (cc_params.cc_optimization_flags & XQC_BBR2_FLAG_RTTVAR_COMPENSATION) {
        bbr2->rtt_compensation_on = 1;
    }
    if (cc_params.cc_optimization_flags & XQC_BBR2_FLAG_FAST_CONVERGENCE) {
        bbr2->fast_convergence_on = 1;
    }
    bbr2->srtt_in_current_round = XQC_BBR2_INF_RTT;
    bbr2->srtt_in_last_round = XQC_BBR2_INF_RTT;
#endif

    bbr2->min_rtt = sampler->srtt ? sampler->srtt : XQC_BBR2_INF_RTT;
    bbr2->min_rtt_stamp = now;
    bbr2->probe_rtt_min_us = sampler->srtt ? sampler->srtt : XQC_BBR2_INF_RTT;
    bbr2->probe_rtt_min_us_stamp = now;
    bbr2->round_start = 0;
    bbr2->round_cnt = 0;
    bbr2->next_round_delivered = 0;
    bbr2->probe_rtt_round_done = FALSE;
    bbr2->probe_rtt_round_done_stamp = 0;
    bbr2->packet_conservation = FALSE;
    bbr2->prior_cwnd = 0;
    bbr2->initial_congestion_window = 32 * XQC_BBR2_MAX_DATAGRAM_SIZE; 
    bbr2->congestion_window = bbr2->initial_congestion_window;
    bbr2->has_srtt = 0;
    bbr2->idle_restart = 0;
    bbr2->packet_conservation = 0;
    bbr2->recovery_mode = BBR2_OPEN;
    bbr2->recovery_start_time = 0;
    bbr2->loss_start_time = 0;

    bbr2->extra_ack_stamp = now;
    bbr2->epoch_ack = 0;
    bbr2->extra_ack_round_rtt = 0;
    bbr2->extra_ack_idx = 0;
    bbr2->extra_ack[0] = 0;
    bbr2->extra_ack[1] = 0;
    bbr2->extra_ack_in_startup = xqc_bbr2_extra_ack_in_startup;
    bbr2->extra_ack_win_len = xqc_bbr2_extra_ack_win_rtt;
    bbr2->extra_ack_win_len_in_startup = xqc_bbr2_extra_ack_win_rtt_in_startup;

    bbr2->full_bandwidth_cnt = 0;
    bbr2->full_bandwidth_reached = FALSE;

    /* skip the first round */
    bbr2->loss_round_delivered = 1;
    bbr2->loss_round_start = 0;
    bbr2->undo_bw_lo = 0;
    bbr2->undo_inflight_lo = 0;
    bbr2->undo_inflight_hi = 0;
    bbr2->loss_events_in_round = 0;
    bbr2->bw_lo = XQC_BBR2_UNSIGNED_INF;
    bbr2->bw_hi[0] = 0;
    bbr2->bw_hi[1] = 0;
    bbr2->inflight_lo = XQC_BBR2_UNSIGNED_INF;
    bbr2->inflight_hi = XQC_BBR2_UNSIGNED_INF;
    bbr2->bw_probe_up_cnt = XQC_BBR2_UNSIGNED_INF;
    bbr2->bw_probe_up_acks = 0;
    bbr2->bw_probe_up_rounds = 0;
    bbr2->probe_wait_us = 0;
    bbr2->stopped_risky_probe = 0;
    bbr2->ack_phase = BBR2_ACKS_INIT;
    bbr2->rounds_since_probe = 0;
    bbr2->bw_probe_samples = 0;
    bbr2->prev_probe_too_high = 0;
    bbr2->exit_startup_on_loss = (xqc_bbr2_full_loss_cnt > 0);
    xqc_bbr2_reset_congestion_signals(cong_ctl);

    xqc_bbr2_enter_startup(bbr2);
    xqc_bbr2_init_pacing_rate(bbr2, sampler);
}

static uint32_t
xqc_bbr2_max_bw(xqc_bbr2_t *bbr2)
{
    return xqc_max(bbr2->bw_hi[0], bbr2->bw_hi[1]);
}

static void
xqc_bbr2_update_round_start(xqc_bbr2_t *bbr2, xqc_sample_t *sampler)
{
    bbr2->round_start = FALSE;
    /* Check whether the data is legal */
    if (/*sampler->delivered < 0 ||*/ sampler->interval <= 0) {
        return;
    }

    if (bbr2->next_round_delivered <= sampler->prior_delivered) {
        bbr2->next_round_delivered = sampler->total_acked;
        bbr2->round_start = TRUE;
    }
}

static void
xqc_bbr2_calculate_bw_sample(xqc_sample_t *sampler, xqc_bbr2_context_t *ctx)
{
    if (sampler->delivered < 0 || sampler->interval <= 0) {
        return;
    }
    /* Calculate the new bandwidth, bytes per second */
    ctx->sample_bw = 1.0 * sampler->delivered / sampler->interval * MSEC2SEC;
}


static uint32_t 
xqc_bbr2_inflight(xqc_bbr2_t *bbr2, uint32_t bw, float gain)
{
    if (bbr2->min_rtt == XQC_BBR2_INF_RTT) {
        return bbr2->initial_congestion_window;
    }
    uint64_t bdp = bbr2->min_rtt * (uint64_t)bw / MSEC2SEC;
    return (uint32_t)(bdp * gain);
}

static uint32_t
xqc_bbr2_bdp(xqc_bbr2_t *bbr2, uint32_t bw)
{
    return xqc_bbr2_inflight(bbr2, bw, 1.0);
}

static void 
xqc_bbr2_advance_bw_hi_filter(xqc_bbr2_t *bbr2)
{
    if (!bbr2->bw_hi[1]) {
        return;
    }
    bbr2->bw_hi[0] = bbr2->bw_hi[1];
    bbr2->bw_hi[1] = 0;
}

static void 
xqc_bbr2_probe_inflight_hi_upward(xqc_bbr2_t *bbr2, xqc_sample_t *sampler)
{
    uint32_t delta = 0;
    xqc_log(sampler->send_ctl->ctl_conn->log, XQC_LOG_DEBUG,
            "|raising inflight hi|cwnd:%ud|inflight_sample:%ud|"
            "inflight_hi:%ud|newlyacked:%ud|prior_inflight:%ud|",
            bbr2->congestion_window, sampler->bytes_inflight, 
            bbr2->inflight_hi, sampler->acked, sampler->prior_inflight);
    bool not_cwnd_limited = FALSE;
    if (sampler->prior_inflight < bbr2->congestion_window) {
        not_cwnd_limited = (bbr2->congestion_window - sampler->prior_inflight)
            >= XQC_BBR2_MAX_DATAGRAM_SIZE;
    }
    /* not cwnd_limited or ... */
    if (not_cwnd_limited || (bbr2->inflight_hi > bbr2->congestion_window)) {
        bbr2->bw_probe_up_acks = 0; /* don't accumulate unused credits */
        return;
        /* not fully using inflight_hi, so don't grow it */
    }

    /* For each bw_probe_up_cnt packets ACKed, increase inflight_hi by 1. */
    bbr2->bw_probe_up_acks += sampler->acked / XQC_BBR2_MAX_DATAGRAM_SIZE;
    if (bbr2->bw_probe_up_acks >= bbr2->bw_probe_up_cnt) {
        delta = bbr2->bw_probe_up_acks / bbr2->bw_probe_up_cnt;
        bbr2->bw_probe_up_acks -= delta * bbr2->bw_probe_up_cnt;
        bbr2->inflight_hi += delta * XQC_BBR2_MAX_DATAGRAM_SIZE;
    }

    xqc_log(sampler->send_ctl->ctl_conn->log, XQC_LOG_DEBUG, 
            "|increase_inflight_hi|probe_up_acks:%ud|newlyacked:%ud"
            "|probe_up_cnt:%udinflight_hi:%uddelta:%udprobe_up_rounds:%u|",
            bbr2->bw_probe_up_acks, sampler->acked, bbr2->bw_probe_up_cnt, 
            bbr2->inflight_hi, delta, bbr2->bw_probe_up_rounds);

    if (bbr2->round_start) {
        xqc_bbr2_raise_inflight_hi_slope(bbr2);
    }
}

static void 
xqc_bbr2_handle_inflight_too_high(xqc_bbr2_t *bbr2, xqc_sample_t *sampler)
{
    double beta = xqc_bbr2_inflight_lo_beta;
    bbr2->prev_probe_too_high = 1;
    bbr2->bw_probe_samples = 0; /* only react once per probe */
    /*
     * If we are app-limited then we are not robustly
     * probing the max volume of inflight data we think
     * might be safe (analogous to how app-limited bw
     * samples are not known to be robustly probing bw).
     */
    if (!sampler->is_app_limited) {
        bbr2->inflight_hi = xqc_max(sampler->tx_in_flight,
            xqc_bbr2_target_inflight(bbr2) * (1.0 - beta));
    }
    if (bbr2->mode == BBR2_PROBE_BW && bbr2->cycle_idx == BBR2_BW_PROBE_UP) {
        xqc_bbr2_enter_probe_down(bbr2, sampler);
    }
}

static bool 
xqc_bbr2_adapt_upper_bounds(xqc_bbr2_t *bbr2, xqc_sample_t *sampler)
{
    /* Track when we'll see bw/loss samples resulting from our bw probes. */
    if (bbr2->ack_phase == BBR2_ACKS_PROBE_STARTING && bbr2->round_start) {
        bbr2->ack_phase = BBR2_ACKS_PROBE_FEEDBACK;
    }
    if (bbr2->ack_phase == BBR2_ACKS_PROBE_STOPPING && bbr2->round_start) {
        /* End of samples from bw probing phase. */
        bbr2->bw_probe_samples = 0;
        bbr2->ack_phase = BBR2_ACKS_INIT;
        /*
         * At this point in the cycle, our current bw sample is also
         * our best recent chance at finding the highest available bw
         * for this flow. So now is the best time to forget the bw
         * samples from the previous cycle, by advancing the window.
         */
        if (bbr2->mode == BBR2_PROBE_BW && !sampler->is_app_limited) {
            xqc_bbr2_advance_bw_hi_filter(bbr2);
        }
        /*
         * If we had an inflight_hi, then probed and pushed inflight all
         * the way up to hit that inflight_hi without seeing any
         * high loss/ECN in all the resulting ACKs from that probing,
         * then probe up again, this time letting inflight persist at
         * inflight_hi for a round trip, then accelerating beyond.
         */
        if (bbr2->mode == BBR2_PROBE_BW 
            && bbr2->stopped_risky_probe && !bbr2->prev_probe_too_high)
        {
            xqc_bbr2_enter_probe_refill(bbr2, sampler, 0);
            return TRUE; /* yes, decided state transition */
        }
    }

    if (xqc_bbr2_is_inflight_too_high(bbr2, sampler)) {
        if (bbr2->bw_probe_samples) {/*  sample is from bw probing? */
            xqc_bbr2_handle_inflight_too_high(bbr2, sampler);
        }

    } else {
        /* Loss/ECN rate is declared safe. Adjust upper bound upward. */
        /* no excess queue signals yet? */
        if (bbr2->inflight_hi == XQC_BBR2_UNSIGNED_INF) {
            return FALSE;
        }
        /*
         * To be resilient to random loss, we must raise inflight_hi
         * if we observe in any phase that a higher level is safe.
         */
        if (sampler->tx_in_flight > bbr2->inflight_hi) {
            bbr2->inflight_hi = sampler->tx_in_flight;
        }

        if (bbr2->mode == BBR2_PROBE_BW 
            && bbr2->cycle_idx == BBR2_BW_PROBE_UP)
            xqc_bbr2_probe_inflight_hi_upward(bbr2, sampler);
    }

    return FALSE;
}

static uint32_t 
xqc_bbr2_bw(xqc_bbr2_t *bbr2)
{
    return xqc_min(xqc_bbr2_max_bw(bbr2), bbr2->bw_lo);
}

uint32_t 
xqc_bbr2_target_inflight(xqc_bbr2_t *bbr2)
{
    uint32_t bdp = xqc_bbr2_bdp(bbr2, xqc_bbr2_bw(bbr2));
    return xqc_min(bdp, bbr2->congestion_window);
}

static bool 
xqc_bbr2_is_reno_coexistence_probe_time(xqc_bbr2_t *bbr2)
{
    uint32_t inflight_in_pkts, rounds, reno_gain, reno_rounds;
    rounds = xqc_bbr2_bw_probe_max_rounds;
    reno_gain = xqc_bbr2_bw_probe_reno_gain;
    if (reno_gain) {
        inflight_in_pkts = xqc_bbr2_target_inflight(bbr2) 
            / XQC_BBR2_MAX_DATAGRAM_SIZE;
        reno_rounds = inflight_in_pkts * reno_gain;
        rounds = xqc_min(rounds, reno_rounds);
    }
    return bbr2->rounds_since_probe >= rounds;
}

static void 
xqc_bbr2_reset_lower_bounds(xqc_bbr2_t *bbr2)
{
    bbr2->bw_lo = XQC_BBR2_UNSIGNED_INF;
    bbr2->inflight_lo = XQC_BBR2_UNSIGNED_INF;
}

void 
xqc_bbr2_enter_probe_refill(xqc_bbr2_t *bbr2, 
    xqc_sample_t *sampler, uint32_t cnt)
{
    xqc_bbr2_reset_lower_bounds(bbr2);
    if (bbr2->inflight_hi != XQC_BBR2_UNSIGNED_INF) {
        bbr2->inflight_hi += xqc_bbr2_refill_and_inc;
    }
    bbr2->bw_probe_up_rounds = cnt;
    bbr2->bw_probe_up_acks = 0;
    bbr2->stopped_risky_probe = FALSE;
    bbr2->ack_phase = BBR2_ACKS_REFILLING;
    bbr2->next_round_delivered = sampler->total_acked;
    xqc_bbr2_set_cycle_idx(bbr2, BBR2_BW_PROBE_REFILL);

    bbr2->cwnd_gain = xqc_bbr2_cwnd_gain;
    bbr2->pacing_gain = xqc_bbr2_pacing_gain[bbr2->cycle_idx];
}

static bool 
xqc_bbr2_has_elapsed_in_phase(xqc_bbr2_t *bbr2, uint64_t now, uint64_t usec)
{
    return (now > (usec + bbr2->cycle_start_stamp));
}

static bool 
xqc_bbr2_check_time_to_probe_bw(xqc_bbr2_t *bbr2, xqc_sample_t *sampler)
{
    uint64_t now = sampler->now;
    if (xqc_bbr2_has_elapsed_in_phase(bbr2, now, bbr2->probe_wait_us) 
        || xqc_bbr2_is_reno_coexistence_probe_time(bbr2)) {
        xqc_bbr2_enter_probe_refill(bbr2, sampler, 0);
        return TRUE;
    }
    return FALSE;
}

void 
xqc_bbr2_raise_inflight_hi_slope(xqc_bbr2_t *bbr2)
{
    uint32_t growth_this_round, cnt;

    /* Calculate "slope": packets S/Acked per inflight_hi increment. */
    growth_this_round = 1 << bbr2->bw_probe_up_rounds;
    bbr2->bw_probe_up_rounds = xqc_min(bbr2->bw_probe_up_rounds + 1, 30);
    cnt = (bbr2->congestion_window / XQC_BBR2_MAX_DATAGRAM_SIZE) / 
          growth_this_round;
    cnt = xqc_max(cnt, 1U);
    bbr2->bw_probe_up_cnt = cnt;
}

static void 
xqc_bbr2_enter_probe_up(xqc_bbr2_t *bbr2, xqc_sample_t *sampler)
{
    bbr2->ack_phase = BBR2_ACKS_PROBE_STARTING;
    bbr2->next_round_delivered = sampler->total_acked;
    bbr2->cycle_start_stamp = sampler->now;
    xqc_bbr2_set_cycle_idx(bbr2, BBR2_BW_PROBE_UP);
    xqc_bbr2_raise_inflight_hi_slope(bbr2);
    bbr2->cwnd_gain = xqc_bbr2_cwnd_gain;
    bbr2->pacing_gain = xqc_bbr2_pacing_gain[bbr2->cycle_idx];
#if XQC_BBR2_PLUS_ENABLED
    if (bbr2->fast_convergence_on) {
        bbr2->bw_before_probe = xqc_bbr2_max_bw(bbr2);
    }
#endif
}

static uint32_t 
xqc_bbr2_inflight_with_headroom(xqc_bbr2_t *bbr2)
{
    if (bbr2->inflight_hi == XQC_BBR2_UNSIGNED_INF) {
        return XQC_BBR2_UNSIGNED_INF;
    }
    uint32_t headroom, inflight_wo_headroom = 0;
    float headroom_fraction;
    headroom_fraction = xqc_bbr2_inflight_headroom;
    headroom = (bbr2->inflight_hi * headroom_fraction);
    headroom = xqc_max(headroom, XQC_BBR2_MAX_DATAGRAM_SIZE);
    if (bbr2->inflight_hi >= headroom) {
        inflight_wo_headroom = bbr2->inflight_hi - headroom;
    }
    return xqc_max(inflight_wo_headroom, xqc_bbr2_min_cwnd);
}

static bool 
xqc_bbr2_check_time_to_cruise(xqc_bbr2_t *bbr2, uint32_t inflight, uint32_t bw)
{
    bool is_under_bdp;
    /* Always need to pull inflight down to leave headroom in queue. */
    if (inflight > xqc_bbr2_inflight_with_headroom(bbr2)) {
        return FALSE;
    }
    is_under_bdp = inflight <= xqc_bbr2_bdp(bbr2, bw);
    return is_under_bdp;
}

static void 
xqc_bbr2_enter_probe_cruise(xqc_bbr2_t *bbr2, xqc_sample_t *sampler)
{
    if (bbr2->inflight_lo != XQC_BBR2_UNSIGNED_INF) {
        bbr2->inflight_lo = xqc_min(bbr2->inflight_lo, bbr2->inflight_hi);
    }
    xqc_bbr2_set_cycle_idx(bbr2, BBR2_BW_PROBE_CRUISE);
    bbr2->cwnd_gain = xqc_bbr2_cwnd_gain;
    bbr2->pacing_gain = xqc_bbr2_pacing_gain[bbr2->cycle_idx];
}

#if XQC_BBR2_PLUS_ENABLED
static void 
xqc_bbr2_enter_probe_pre_up(xqc_bbr2_t *bbr2, xqc_sample_t *sampler)
{
    xqc_bbr2_set_cycle_idx(bbr2, BBR2_BW_PROBE_PRE_UP);
    bbr2->cwnd_gain = xqc_bbr2_cwnd_gain;
    bbr2->pacing_gain = xqc_bbr2_pacing_gain[bbr2->cycle_idx];
    xqc_log(sampler->send_ctl->ctl_conn->log, XQC_LOG_DEBUG, 
            "|BBRv2 Plus|State probe pre_up|pacing_gain %.2f|",
            bbr2->pacing_gain);
}
#endif

static void 
xqc_bbr2_update_cycle_phase(xqc_bbr2_t *bbr2, xqc_sample_t *sampler)
{
    bool is_risky = FALSE, is_queuing = FALSE;
    uint32_t inflight, bw;
    uint64_t now = sampler->now;

    if (!bbr2->full_bandwidth_reached) {
        return;
    }
    /* In DRAIN, PROBE_BW, or PROBE_RTT, adjust upper bounds. */
    if (xqc_bbr2_adapt_upper_bounds(bbr2, sampler)) {
        return; /* already decided state transition */
    }
    if (bbr2->mode != BBR2_PROBE_BW) {
        return;
    }

    inflight = sampler->prior_inflight;
    bw = xqc_bbr2_max_bw(bbr2);

    switch (bbr2->cycle_idx) {
    /* 
     * First we spend most of our time cruising with a pacing_gain of 1.0,
     * which paces at the estimated bw, to try to fully use the pipe
     * without building queue. If we encounter loss/ECN marks, we adapt
     * by slowing down.
     */
    case BBR2_BW_PROBE_CRUISE:
#if XQC_BBR2_PLUS_ENABLED
        if (bbr2->fast_convergence_on) {
            xqc_log(sampler->send_ctl->ctl_conn->log, XQC_LOG_DEBUG, 
                    "|BBRv2 Plus|State probe cruise|last_round_srtt %ui|"
                    "current_round_srtt %ui|",
                    bbr2->srtt_in_last_round,
                    bbr2->srtt_in_current_round);
            if (bbr2->srtt_in_current_round != XQC_BBR2_INF_RTT) {
                xqc_usec_t rtt_thresh = xqc_bbr2_fast_convergence_rtt_factor *
                                        bbr2->srtt_in_last_round;
                xqc_log(sampler->send_ctl->ctl_conn->log, XQC_LOG_DEBUG, 
                            "|BBRv2 Plus|rtt_thresh %ui|", rtt_thresh);
                if (bbr2->srtt_in_current_round > rtt_thresh) {
                    xqc_bbr2_advance_bw_hi_filter(bbr2);
                    xqc_log(sampler->send_ctl->ctl_conn->log, XQC_LOG_DEBUG, 
                            "|BBRv2 Plus|advanced bw hi filter|");
                }
            }
        }
#endif
        if (xqc_bbr2_check_time_to_probe_bw(bbr2, sampler)) {
            return; /* already decided state transition */
        }
        break;

    /*
     * After cruising, when it's time to probe, we first "refill": we send
     * at the estimated bw to fill the pipe, before probing higher and
     * knowingly risking overflowing the bottleneck buffer (causing loss).
     */
    case BBR2_BW_PROBE_REFILL:
        if (bbr2->round_start) {
            /* 
             * After one full round trip of sending in REFILL, we
             * start to see bw samples reflecting our REFILL, which
             * may be putting too much data in flight.
             */
#if XQC_BBR2_PLUS_ENABLED
            if (bbr2->fast_convergence_on) {
                xqc_bbr2_enter_probe_pre_up(bbr2, sampler);

            } else {
                bbr2->bw_probe_samples = 1;
                xqc_bbr2_enter_probe_up(bbr2, sampler);
            }
#else
            bbr2->bw_probe_samples = 1;
            xqc_bbr2_enter_probe_up(bbr2, sampler);
#endif
        }
        break;

#if XQC_BBR2_PLUS_ENABLED
    case BBR2_BW_PROBE_PRE_UP:
        if (bbr2->round_start) {
            xqc_usec_t rtt_thresh = bbr2->srtt_in_last_round + 
                                    xqc_bbr2_fast_convergence_srtt_error;
            xqc_log(sampler->send_ctl->ctl_conn->log, XQC_LOG_DEBUG, 
                    "|BBRv2 Plus|State probe pre_up|last_round_srtt %ui|"
                    "current_round_srtt %ui| rtt_thresh %ui|",
                    bbr2->srtt_in_last_round, bbr2->srtt_in_current_round,
                    rtt_thresh);
            if (bbr2->srtt_in_current_round <= rtt_thresh) {
                bbr2->bw_probe_samples = 1;
                xqc_bbr2_enter_probe_up(bbr2, sampler);

            } else {
                xqc_bbr2_enter_probe_down(bbr2, sampler);
            }
        }
        break;
#endif

    /*
     * After we refill the pipe, we probe by using a pacing_gain > 1.0, to
     * probe for bw. If we have not seen loss/ECN, we try to raise inflight
     * to at least pacing_gain*BDP; note that this may take more than
     * min_rtt if min_rtt is small (e.g. on a LAN).
     *
     * We terminate PROBE_UP bandwidth probing upon any of the following:
     *
     * (1) We've pushed inflight up to hit the inflight_hi target set in the
     *     most recent previous bw probe phase. Thus we want to start
     *     draining the queue immediately because it's very likely the most
     *     recently sent packets will fill the queue and cause drops.
     *     (checked here)
     * (2) We have probed for at least 1*min_rtt_us, and the
     *     estimated queue is high enough (inflight > 1.25 * estimated_bdp).
     *     (checked here)
     * (3) Loss filter says loss rate is "too high".
     *     (checked in bbr_is_inflight_too_high())
     * (4) ECN filter says ECN mark rate is "too high".
     *     (checked in bbr_is_inflight_too_high())
     */
    case BBR2_BW_PROBE_UP:
        if (bbr2->prev_probe_too_high 
            && inflight >= bbr2->inflight_hi)
        {
            bbr2->stopped_risky_probe = 1;
            is_risky = TRUE;

        }
        else if (xqc_bbr2_has_elapsed_in_phase(bbr2, now, bbr2->min_rtt) 
                && inflight >= 
                   xqc_bbr2_inflight(bbr2, bw, xqc_bbr2_bw_probe_up_gain))
        {
#if XQC_BBR2_PLUS_ENABLED
            if (bbr2->fast_convergence_on) {
                uint32_t bw_thresh = bbr2->bw_before_probe * 
                                xqc_bbr2_fast_convergence_probe_again_factor;
                xqc_log(sampler->send_ctl->ctl_conn->log, XQC_LOG_DEBUG, 
                        "|BBRv2 Plus|State probe up|max_bw_before_probe %ud|"
                        "current_max_bw %ud|bw_thresh %ud|",
                        bbr2->bw_before_probe, xqc_bbr2_max_bw(bbr2),
                        bw_thresh);
                if (xqc_bbr2_max_bw(bbr2) < bw_thresh) {
                    is_queuing = TRUE;

                } else {
                    xqc_bbr2_enter_probe_up(bbr2, sampler);
                }

            } else {
                is_queuing = TRUE;
            }
#else
            is_queuing = TRUE;
#endif
        }
        xqc_log(sampler->send_ctl->ctl_conn->log, XQC_LOG_DEBUG, 
                "|PROBE_UP_GO|inflight:%ud|target:%ud|queuing:%ud|bw:%ud|",
                inflight, 
                xqc_bbr2_inflight(bbr2, bw, xqc_bbr2_bw_probe_up_gain), bw);
        if (is_risky || is_queuing) {
            bbr2->prev_probe_too_high = 0;            /* no loss/ECN (yet) */
            xqc_bbr2_enter_probe_down(bbr2, sampler); /* restart w/ down */
        }
        break;

    /*
     * After probing in PROBE_UP, we have usually accumulated some data in
     * the bottleneck buffer (if bw probing didn't find more bw). We next
     * enter PROBE_DOWN to try to drain any excess data from the queue. To
     * do this, we use a pacing_gain < 1.0. We hold this pacing gain until
     * our inflight is less then that target cruising point, which is the
     * minimum of (a) the amount needed to leave headroom, and (b) the
     * estimated BDP. Once inflight falls to match the target, we estimate
     * the queue is drained; persisting would underutilize the pipe.
     */
    case BBR2_BW_PROBE_DOWN:
#if XQC_BBR2_PLUS_ENABLED
        if (bbr2->fast_convergence_on) {
            xqc_log(sampler->send_ctl->ctl_conn->log, XQC_LOG_DEBUG, 
                    "|BBRv2 Plus|State probe down|last_round_srtt %ui|"
                    "current_round_srtt %ui|",
                    bbr2->srtt_in_last_round,
                    bbr2->srtt_in_current_round);
            if (bbr2->srtt_in_current_round != XQC_BBR2_INF_RTT) {
                xqc_usec_t rtt_thresh = xqc_bbr2_fast_convergence_rtt_factor *
                                        bbr2->srtt_in_last_round;
                xqc_log(sampler->send_ctl->ctl_conn->log, XQC_LOG_DEBUG, 
                        "|BBRv2 Plus|State probe down| rtt_thresh %ui|",
                        rtt_thresh);
                if (bbr2->srtt_in_current_round > rtt_thresh) {
                    xqc_bbr2_advance_bw_hi_filter(bbr2);
                }
            }
        }
#endif
        if (xqc_bbr2_check_time_to_probe_bw(bbr2, sampler)) {
            return; /* already decided state transition */
        }
        if (xqc_bbr2_check_time_to_cruise(bbr2, inflight, bw)) {
            xqc_bbr2_enter_probe_cruise(bbr2, sampler);
        }
        break;

    default:
        xqc_log(bbr2->send_ctl->ctl_conn->log, XQC_LOG_WARN, 
                "|BBR invalid cycle index %ud|", bbr2->cycle_idx);
    }
}

static uint32_t 
xqc_bbr2_extra_ack(xqc_bbr2_t *bbr2)
{
    return xqc_max(bbr2->extra_ack[0], bbr2->extra_ack[1]);
}

static uint32_t 
xqc_bbr2_ack_aggregation_cwnd(xqc_bbr2_t *bbr2)
{
    uint32_t max_aggr_cwnd, aggr_cwnd = 0;
    if (xqc_bbr2_extra_ack_gain 
        && (bbr2->full_bandwidth_reached || bbr2->extra_ack_in_startup))
    {
        max_aggr_cwnd = xqc_bbr2_bw(bbr2) * xqc_bbr2_max_extra_ack_time;
        aggr_cwnd = xqc_bbr2_extra_ack_gain * xqc_bbr2_extra_ack(bbr2);
        aggr_cwnd = xqc_min(aggr_cwnd, max_aggr_cwnd);
    }
    return aggr_cwnd;
}

static void 
xqc_update_ack_aggregation(xqc_bbr2_t *bbr2, xqc_sample_t *sampler)
{
    uint32_t epoch, expected_ack, extra_ack;
    uint32_t extra_ack_win_thresh = bbr2->extra_ack_win_len;
    if (!xqc_bbr2_extra_ack_gain || sampler->delivered < 0 
        || sampler->interval <= 0 || sampler->acked <= 0) {
        return;
    }
    if (bbr2->round_start) {
        bbr2->extra_ack_round_rtt += 1;
        if (bbr2->extra_ack_in_startup && !bbr2->full_bandwidth_reached) {
            extra_ack_win_thresh = bbr2->extra_ack_win_len_in_startup;
        } 
        if (bbr2->extra_ack_round_rtt >= extra_ack_win_thresh) {
            bbr2->extra_ack_round_rtt = 0;
            bbr2->extra_ack_idx = bbr2->extra_ack_idx ? 0 : 1;
            bbr2->extra_ack[bbr2->extra_ack_idx] = 0;
        }
    }

    epoch = sampler->now - bbr2->extra_ack_stamp;
    expected_ack = ((uint64_t)xqc_bbr2_bw(bbr2) * epoch) / MSEC2SEC;

    if (bbr2->epoch_ack <= expected_ack 
        || (bbr2->epoch_ack + sampler->acked 
            >= xqc_bbr2_ack_epoch_acked_reset_thresh))
    {
        bbr2->epoch_ack = 0;
        bbr2->extra_ack_stamp = sampler->now;
        expected_ack = 0;
    }
    /* Compute excess data delivered, beyond what was expected. */
    uint32_t cap = 0xFFFFFU * XQC_BBR2_MAX_DATAGRAM_SIZE;
    bbr2->epoch_ack = xqc_min(cap, bbr2->epoch_ack + sampler->acked);
    extra_ack = bbr2->epoch_ack - expected_ack;
    extra_ack = xqc_min(extra_ack, bbr2->congestion_window);

    if (extra_ack > bbr2->extra_ack[bbr2->extra_ack_idx]) {
        bbr2->extra_ack[bbr2->extra_ack_idx] = extra_ack;
    } 
}

static void 
xqc_bbr2_check_full_bw_reached(xqc_bbr2_t *bbr2, xqc_sample_t *sampler)
{
    /*
     * we MUST only check whether full bw is reached ONCE per RTT!!!
     * Otherwise, startup may end too early due to multiple ACKs arrive in a 
     * RTT. 
     */
    if (!bbr2->round_start || bbr2->full_bandwidth_reached 
        || sampler->is_app_limited)
    {
        return;
    }

    uint32_t bw_thresh = bbr2->last_bandwidth * xqc_bbr2_fullbw_thresh;
    if (xqc_bbr2_max_bw(bbr2) >= bw_thresh) {
        bbr2->last_bandwidth = xqc_bbr2_max_bw(bbr2);
        bbr2->full_bandwidth_cnt = 0;
        return;
    }
    ++bbr2->full_bandwidth_cnt;
    bbr2->full_bandwidth_reached = bbr2->full_bandwidth_cnt >= 
                                   xqc_bbr2_fullbw_cnt;
}

static void 
xqc_bbr2_enter_drain(xqc_bbr2_t *bbr2)
{
    bbr2->mode = BBR2_DRAIN;
    bbr2->pacing_gain = xqc_bbr2_drain_gain;
    bbr2->cwnd_gain = xqc_bbr2_startup_cwnd_gain;
    xqc_bbr2_reset_congestion_signals((void *)bbr2);
}

static void 
xqc_bbr2_pick_probe_wait(xqc_bbr2_t *bbr2)
{
    bbr2->rounds_since_probe = random() % xqc_bbr2_bw_probe_rand_rounds;
#if XQC_BBR2_PLUS_ENABLED
    if (bbr2->fast_convergence_on) {
        uint32_t rand_rtt_rounds = random() % 
                                   xqc_bbr2_fast_convergence_probe_round_rand;
        rand_rtt_rounds += (1 + xqc_bbr2_fast_convergence_probe_round_base);
    } else {
        bbr2->probe_wait_us = xqc_bbr2_bw_probe_base_us + 
                              (random() % xqc_bbr2_bw_probe_rand_us);
    }
#else
    bbr2->probe_wait_us = xqc_bbr2_bw_probe_base_us + 
                          (random() % xqc_bbr2_bw_probe_rand_us);
#endif
}

void 
xqc_bbr2_set_cycle_idx(xqc_bbr2_t *bbr2, xqc_bbr2_pacing_gain_phase idx)
{
    bbr2->cycle_idx = (uint32_t)idx;
}

void 
xqc_bbr2_enter_probe_down(xqc_bbr2_t *bbr2, xqc_sample_t *sampler)
{
    bbr2->mode = BBR2_PROBE_BW;
    xqc_bbr2_reset_congestion_signals((void *)bbr2);
    bbr2->bw_probe_up_cnt = XQC_BBR2_UNSIGNED_INF;
    xqc_bbr2_pick_probe_wait(bbr2);
    bbr2->cycle_start_stamp = sampler->now; /* start wall clock */
    bbr2->ack_phase = BBR2_ACKS_PROBE_STOPPING;
    bbr2->next_round_delivered = sampler->total_acked;
    xqc_bbr2_set_cycle_idx(bbr2, BBR2_BW_PROBE_DOWN);

    bbr2->cwnd_gain = xqc_bbr2_cwnd_gain;
    bbr2->pacing_gain = xqc_bbr2_pacing_gain[bbr2->cycle_idx];
}

static void 
xqc_bbr2_check_drain(xqc_bbr2_t *bbr2, xqc_sample_t *sampler, 
    xqc_bbr2_context_t *ctx)
{
    if (bbr2->mode == BBR2_STARTUP && bbr2->full_bandwidth_reached) {
        xqc_bbr2_enter_drain(bbr2);
    }

    if (bbr2->mode == BBR2_DRAIN 
        && sampler->bytes_inflight <= xqc_bbr2_bdp(bbr2, xqc_bbr2_max_bw(bbr2)))
    {
#if XQC_BBR2_PLUS_ENABLED
        bbr2->rtt_compensation_thresh = xqc_bbr2_rtt_compensation_thresh;
#endif
        xqc_bbr2_enter_probe_down(bbr2, sampler);
    }
}

static uint32_t 
xqc_bbr2_probe_rtt_cwnd(xqc_bbr2_t *bbr2)
{
    uint32_t probe_rtt_cwnd = xqc_bbr2_inflight(bbr2, xqc_bbr2_bw(bbr2), 
                                                xqc_bbr2_probe_rtt_gain);
    return xqc_max(xqc_bbr2_min_cwnd, probe_rtt_cwnd);
}

static void 
xqc_bbr2_exit_probe_rtt(xqc_bbr2_t *bbr2, xqc_sample_t *sampler)
{
    xqc_bbr2_reset_lower_bounds(bbr2);
    if (bbr2->full_bandwidth_reached) {
        xqc_bbr2_enter_probe_down(bbr2, sampler);
        xqc_bbr2_enter_probe_cruise(bbr2, sampler);

    } else {
        xqc_bbr2_enter_startup(bbr2);
    }
}

static void 
xqc_bbr2_check_probe_rtt_done(xqc_bbr2_t *bbr2, xqc_sample_t *sampler)
{
    if (!bbr2->probe_rtt_round_done_stamp 
        || sampler->now < bbr2->probe_rtt_round_done_stamp) {
        return;
    }
    bbr2->probe_rtt_min_us_stamp = sampler->now;
    xqc_bbr2_restore_cwnd(bbr2);
    xqc_bbr2_exit_probe_rtt(bbr2, sampler);
}

static void 
xqc_bbr2_update_min_rtt(xqc_bbr2_t *bbr2, xqc_sample_t *sampler)
{
    bool probe_rtt_expired, min_rtt_expired;
    probe_rtt_expired = sampler->now > (bbr2->probe_rtt_min_us_stamp +  
        xqc_bbr2_probe_minrtt_win_size_us);
    if (sampler->rtt >= 0 
        && (sampler->rtt <= bbr2->probe_rtt_min_us || probe_rtt_expired))
    {
        bbr2->probe_rtt_min_us = sampler->rtt;
        bbr2->probe_rtt_min_us_stamp = sampler->now;
    }
    min_rtt_expired = sampler->now > 
                      (bbr2->min_rtt_stamp + xqc_bbr2_minrtt_win_size_us);
    bbr2->min_rtt_expired = min_rtt_expired;
    if (bbr2->probe_rtt_min_us <= bbr2->min_rtt || min_rtt_expired) {
        bbr2->min_rtt = bbr2->probe_rtt_min_us;
        bbr2->min_rtt_stamp = bbr2->probe_rtt_min_us_stamp;
    }
    if (probe_rtt_expired && !bbr2->idle_restart 
        && bbr2->mode != BBR2_PROBE_RTT)
    {
        xqc_bbr2_enter_probe_rtt(bbr2);
        xqc_bbr2_save_cwnd(bbr2);
        bbr2->probe_rtt_round_done_stamp = 0;
        bbr2->ack_phase = BBR2_ACKS_PROBE_STOPPING;
    }
    if (bbr2->mode == BBR2_PROBE_RTT) {
        /* Ignore low rate samples during this mode. */
        xqc_send_ctl_t *send_ctl = sampler->send_ctl;
        send_ctl->ctl_app_limited = (send_ctl->ctl_delivered 
            + send_ctl->ctl_bytes_in_flight)? : 1;
        xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG, 
                "|BBR PROBE_RTT|inflight:%ud|done_stamp:%ui|done:%ud|"
                "round_start:%ud|",
                sampler->bytes_inflight, bbr2->probe_rtt_round_done_stamp, 
                bbr2->probe_rtt_round_done, bbr2->round_start);
        /* Maintain min packets in flight for max(200 ms, 1 round). */
        if (!bbr2->probe_rtt_round_done_stamp 
            && sampler->bytes_inflight <= xqc_bbr2_probe_rtt_cwnd(bbr2))
        {
            bbr2->probe_rtt_round_done_stamp = sampler->now + 
                                               xqc_bbr2_probertt_time_us;
            bbr2->probe_rtt_round_done = FALSE;
            bbr2->next_round_delivered = sampler->total_acked;

        } else if (bbr2->probe_rtt_round_done_stamp) {
            if (bbr2->round_start) {
                bbr2->probe_rtt_round_done = TRUE;
            }
            if (bbr2->probe_rtt_round_done) {
                xqc_bbr2_check_probe_rtt_done(bbr2, sampler);
            }
        }
    }
    if (sampler->delivered > 0) {
        bbr2->idle_restart = 0;
    }
        
}

void 
xqc_bbr2_enter_probe_rtt(xqc_bbr2_t *bbr2)
{
    bbr2->mode = BBR2_PROBE_RTT;
    bbr2->pacing_gain = 1;
    bbr2->cwnd_gain = 1;
}

void 
xqc_bbr2_save_cwnd(xqc_bbr2_t *bbr2)
{
    if (bbr2->recovery_mode != BBR2_RECOVERY && bbr2->mode != BBR2_PROBE_RTT) {
        bbr2->prior_cwnd = bbr2->congestion_window;

    } else {
        bbr2->prior_cwnd = xqc_max(bbr2->congestion_window, bbr2->prior_cwnd);
    }
}

void 
xqc_bbr2_restore_cwnd(xqc_bbr2_t *bbr2)
{
    bbr2->congestion_window = 
        xqc_max(bbr2->congestion_window, bbr2->prior_cwnd);
}

static void 
_xqc_bbr2_set_pacing_rate_helper(xqc_bbr2_t *bbr2, float pacing_gain)
{
    uint32_t bandwidth, rate;
    bandwidth = xqc_bbr2_bw(bbr2);
    rate = bandwidth * pacing_gain * 
        (1.0 - xqc_bbr2_pacing_rate_margin_percent);
    if (bbr2->full_bandwidth_reached || rate > bbr2->pacing_rate 
        || bbr2->recovery_mode == BBR2_RECOVERY) {
        bbr2->pacing_rate = rate;
    }
}

static void 
xqc_bbr2_set_pacing_rate(xqc_bbr2_t *bbr2, xqc_sample_t *sampler)
{
    if (!bbr2->has_srtt && sampler->srtt) {
        xqc_bbr2_init_pacing_rate(bbr2, sampler);
    }
    _xqc_bbr2_set_pacing_rate_helper(bbr2, bbr2->pacing_gain);
    if (bbr2->pacing_rate == 0) {
        xqc_bbr2_init_pacing_rate(bbr2, sampler);
        xqc_log(sampler->send_ctl->ctl_conn->log, XQC_LOG_WARN,
                "|rate dropped to 0|reset pacing_rate:%ud|", bbr2->pacing_rate);
    }
}

/* this will be called iff persistent congestion occurs */
static void 
xqc_bbr2_reset_cwnd(void *cong_ctl)
{
    xqc_bbr2_t *bbr2 = (xqc_bbr2_t *)cong_ctl;
    xqc_bbr2_save_cwnd(bbr2);
    /* cut window to the minimal */
    bbr2->congestion_window = xqc_bbr2_min_cwnd;
    /* enter loss state */
    bbr2->recovery_mode = BBR2_LOSS;
    bbr2->last_bandwidth = 0;
    bbr2->loss_start_time = xqc_monotonic_timestamp();
    if (!xqc_bbr2_is_probing_bandwidth(bbr2) 
        && bbr2->inflight_lo == XQC_BBR2_UNSIGNED_INF) {
        bbr2->inflight_lo = bbr2->prior_cwnd;
    }
    /* cancel & disable entering RECOVERY mode */
    bbr2->recovery_start_time = 0;
}

#if XQC_BBR2_PLUS_ENABLED
static uint32_t
xqc_bbr2_compensate_cwnd_for_rttvar(xqc_bbr2_t *bbr2, xqc_sample_t *sampler)
{
    xqc_usec_t srtt = sampler->srtt;
    xqc_usec_t recent_max_rtt = xqc_win_filter_get_u64(&bbr2->max_rtt);
    xqc_usec_t compensation_thresh = (1 + bbr2->rtt_compensation_thresh) * 
                                     bbr2->min_rtt;
    uint32_t cwnd_addition = 0;
    if (recent_max_rtt >= compensation_thresh) {
        if (srtt > bbr2->min_rtt) {
            xqc_usec_t rtt_var = (srtt - bbr2->min_rtt);
            cwnd_addition = (xqc_bbr2_bw(bbr2) * rtt_var / MSEC2SEC) * 
                                       xqc_bbr2_rtt_compensation_cwnd_factor;

        } else {
            xqc_log(sampler->send_ctl->ctl_conn->log, XQC_LOG_WARN, 
                    "|cwnd compensation: weird things happened|"
                    "|srtt %ui <= min_rtt %ui|", 
                    srtt, bbr2->min_rtt);
        }
    }
    return cwnd_addition;
}
#endif

static void 
xqc_bbr2_set_cwnd(xqc_bbr2_t *bbr2, xqc_sample_t *sampler, 
    xqc_bbr2_context_t *ctx)
{
    xqc_send_ctl_t *send_ctl = sampler->send_ctl;
    uint32_t target_cwnd, extra_cwnd;
    
    if (sampler->acked == 0) {
        goto done;
    }
    target_cwnd = xqc_bbr2_inflight(bbr2, xqc_bbr2_bw(bbr2), bbr2->cwnd_gain);
    extra_cwnd = xqc_bbr2_ack_aggregation_cwnd(bbr2);
    xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG,
            "|xqc_bbr2_set_cwnd|target_cwnd:%ud|extra_cwnd:%ud|"
            "current_cwnd:%ud|new_acked:%ud|",
            target_cwnd, extra_cwnd, bbr2->congestion_window, sampler->acked);
    target_cwnd += extra_cwnd;

#if XQC_BBR2_PLUS_ENABLED
    if (bbr2->rtt_compensation_on) {
        uint32_t cwnd_for_rttvar;
        cwnd_for_rttvar = xqc_bbr2_compensate_cwnd_for_rttvar(bbr2, sampler);
        target_cwnd += cwnd_for_rttvar;
        xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG,
                "|xqc_bbr2_set_cwnd|cwnd_for_rttvar: %ud|", cwnd_for_rttvar);
    }
#endif

    if (bbr2->full_bandwidth_reached) {
        bbr2->congestion_window = xqc_min(target_cwnd, 
                                          bbr2->congestion_window 
                                          + sampler->acked);

    }
    else if (bbr2->congestion_window < target_cwnd 
             || bbr2->congestion_window < 2 * bbr2->initial_congestion_window)
    {
        bbr2->congestion_window += sampler->acked;
    }
    bbr2->congestion_window = 
        xqc_max(bbr2->congestion_window, xqc_bbr2_min_cwnd);

done:
    if (bbr2->mode == BBR2_PROBE_RTT) {
        bbr2->congestion_window = xqc_min(bbr2->congestion_window, 
                                          xqc_bbr2_probe_rtt_cwnd(bbr2));
    }
}

static void 
xqc_bbr2_on_lost(void *cong_ctl, xqc_usec_t lost_sent_time)
{
    xqc_bbr2_t *bbr2 = (xqc_bbr2_t *)cong_ctl;
    /* we do not enter RECOVERY from LOSS */
    if (bbr2->recovery_mode == BBR2_LOSS) {
        return;
    }
    /* start loss recovery epoch */
    if (lost_sent_time > bbr2->recovery_start_time) {
        bbr2->recovery_start_time = xqc_monotonic_timestamp();
    }
}

static void 
xqc_bbr2_update_pacing_gain_for_loss_recovery(void *cong_ctl)
{
    xqc_bbr2_t *bbr2 = (xqc_bbr2_t *)cong_ctl;
    if (bbr2->mode == BBR2_STARTUP) {
        if (bbr2->recovery_mode == BBR2_RECOVERY) {
            bbr2->pacing_gain = xqc_bbr2_startup_pacing_gain_on_lost;
        }
        if (bbr2->recovery_mode == BBR2_OPEN) {
            bbr2->pacing_gain = xqc_bbr2_high_gain;
        }
    }
}

static void 
xqc_bbr2_update_recovery_mode(void *cong_ctl, xqc_sample_t *sampler)
{
    xqc_bbr2_t *bbr2 = (xqc_bbr2_t *)cong_ctl;
    if (sampler->po_sent_time > bbr2->loss_start_time 
        && bbr2->recovery_mode == BBR2_LOSS)
    {
        /* exit from LOSS mode */
        bbr2->recovery_mode = BBR2_OPEN;
        /* restore cwnd */
        xqc_bbr2_restore_cwnd(bbr2);
        return;
    }
    if (sampler->po_sent_time <= bbr2->recovery_start_time 
        && bbr2->recovery_mode == BBR2_OPEN)
    {
        bbr2->recovery_mode = BBR2_RECOVERY;
        /* just save it. make the logic consistent with Linux Kernel */
        xqc_bbr2_save_cwnd(bbr2);

    }
    else if (sampler->po_sent_time > bbr2->recovery_start_time 
             && bbr2->recovery_mode == BBR2_RECOVERY)
    {
        /* 
         * exit recovery mode once any packet sent during the 
         * recovery epoch is acked. 
         */
        bbr2->recovery_mode = BBR2_OPEN;
        bbr2->recovery_start_time = 0;
        /* 
         * we do not restore cwnd here as we do not bound cwnd to 
         * inflight when entering recovery
         */
    }
}

static void 
xqc_bbr2_take_bw_hi_sample(xqc_bbr2_t *bbr2, uint32_t bw)
{
    bbr2->bw_hi[1] = xqc_max(bbr2->bw_hi[1], bw);
}

bool 
xqc_bbr2_is_probing_bandwidth(xqc_bbr2_t *bbr2)
{
#if XQC_BBR2_PLUS_ENABLED
    return (bbr2->mode == BBR2_STARTUP) 
            || (bbr2->mode == BBR2_PROBE_BW 
               && (bbr2->cycle_idx == BBR2_BW_PROBE_REFILL 
                   || bbr2->cycle_idx == BBR2_BW_PROBE_UP
                   || bbr2->cycle_idx == BBR2_BW_PROBE_PRE_UP));
#else
    return (bbr2->mode == BBR2_STARTUP) 
            || (bbr2->mode == BBR2_PROBE_BW 
               && (bbr2->cycle_idx == BBR2_BW_PROBE_REFILL 
                   || bbr2->cycle_idx == BBR2_BW_PROBE_UP));
#endif
}

static void 
xqc_bbr2_adapt_lower_bounds(xqc_bbr2_t *bbr2)
{
    /*
     * We only use lower-bound estimates when not probing bw.
     * When probing we need to push inflight higher to probe bw.
     */
    if (xqc_bbr2_is_probing_bandwidth(bbr2)) {
        return;
    }

    /* Loss response. */
    if (bbr2->loss_in_round) {
        /* Reduce bw and inflight to (1 - beta). */
        if (bbr2->bw_lo == XQC_BBR2_UNSIGNED_INF) {
            bbr2->bw_lo = xqc_bbr2_max_bw(bbr2);
        }   
        if (bbr2->inflight_lo == XQC_BBR2_UNSIGNED_INF) {
            bbr2->inflight_lo = bbr2->congestion_window;
        }
        bbr2->bw_lo = xqc_max(bbr2->bw_latest, 
            (1 - xqc_bbr2_inflight_lo_beta) * bbr2->bw_lo);
        bbr2->inflight_lo = xqc_max(bbr2->inflight_latest, 
            (1 - xqc_bbr2_inflight_lo_beta) * bbr2->inflight_lo);
    }
}

static void 
xqc_bbr2_update_congestion_signals(xqc_bbr2_t *bbr2, xqc_sample_t *sampler, 
    xqc_bbr2_context_t *ctx)
{
    uint32_t bw;
    bbr2->loss_round_start = FALSE;
    if (sampler->interval <= 0 || sampler->acked == 0) {
        return; /* not a valid sample, no new acked data */
    }
    bw = ctx->sample_bw;
    /* update bw_hi */
    if (!sampler->is_app_limited || bw >= xqc_bbr2_max_bw(bbr2)) {
        xqc_bbr2_take_bw_hi_sample(bbr2, bw);
    }
        
    bbr2->loss_in_round |= (sampler->loss > 0);

    /* Update rate and volume of delivered data from latest round trip: */
    bbr2->bw_latest = xqc_max(bbr2->bw_latest, ctx->sample_bw);
    bbr2->inflight_latest = xqc_max(bbr2->inflight_latest, sampler->delivered);

    if (sampler->prior_delivered < bbr2->loss_round_delivered) {
        return; /* skip the per-round-trip updates */
    }
        
    /* Now do per-round-trip updates. */
    bbr2->loss_round_delivered = sampler->total_acked; /* mark round trip */
    bbr2->loss_round_start = 1;

    xqc_bbr2_adapt_lower_bounds(bbr2);

    /* Update windowed "latest" (single-round-trip) filters. */
    bbr2->loss_in_round = 0;
    bbr2->bw_latest = ctx->sample_bw;
    bbr2->inflight_latest = sampler->delivered;
}

bool 
xqc_bbr2_is_inflight_too_high(xqc_bbr2_t *bbr2, xqc_sample_t *sampler)
{
    uint32_t loss_thresh, inflight_pkts;
    /* if loss rate is too large */
    if (sampler->lost_pkts > 0 && sampler->tx_in_flight) {
        inflight_pkts = sampler->tx_in_flight / XQC_BBR2_MAX_DATAGRAM_SIZE;
        loss_thresh = inflight_pkts * xqc_bbr2_loss_thresh;
        if (sampler->lost_pkts > loss_thresh) {
            return TRUE;
        }
    }
    return FALSE;
}

static void 
xqc_bbr2_handle_queue_too_high_in_startup(xqc_bbr2_t *bbr2)
{
    bbr2->full_bandwidth_reached = 1;
    bbr2->inflight_hi = xqc_bbr2_bdp(bbr2, xqc_bbr2_max_bw(bbr2));
}

static void 
xqc_bbr2_check_loss_too_high_in_startup(xqc_bbr2_t *bbr2, xqc_sample_t *sampler)
{
    if (bbr2->full_bandwidth_reached) {
        return;
    }
    /* TODO: put 0xf into a BBRv2 parameter */
    if (sampler->loss && bbr2->loss_events_in_round < 0xf) {
        bbr2->loss_events_in_round++;
    }
    if (bbr2->exit_startup_on_loss && bbr2->loss_round_start 
        && bbr2->recovery_mode == BBR2_RECOVERY 
        && bbr2->loss_events_in_round >= xqc_bbr2_full_loss_cnt 
        && xqc_bbr2_is_inflight_too_high(bbr2, sampler))
    {
        xqc_bbr2_handle_queue_too_high_in_startup(bbr2);
        return;
    }
    if (bbr2->loss_round_start) {
        bbr2->loss_events_in_round = 0;
    }
}

static void 
xqc_bbr2_update_model(xqc_bbr2_t *bbr2, xqc_sample_t *sampler, 
    xqc_bbr2_context_t *ctx)
{
    xqc_bbr2_update_congestion_signals(bbr2, sampler, ctx);
    xqc_update_ack_aggregation(bbr2, sampler);
    xqc_bbr2_check_loss_too_high_in_startup(bbr2, sampler);
    xqc_bbr2_check_full_bw_reached(bbr2, sampler);
    xqc_bbr2_check_drain(bbr2, sampler, ctx);
    xqc_bbr2_update_cycle_phase(bbr2, sampler);
    xqc_bbr2_update_min_rtt(bbr2, sampler);
}

static void 
xqc_bbr2_bound_cwnd_for_inflight_model(xqc_bbr2_t *bbr2)
{
    uint32_t cap;
    cap = XQC_BBR2_UNSIGNED_INF;
    if (bbr2->mode == BBR2_PROBE_BW 
        && bbr2->cycle_idx != BBR2_BW_PROBE_CRUISE)
    {
        /* Probe to see if more packets fit in the path. */
        cap = bbr2->inflight_hi;

    } else {
        if (bbr2->mode == BBR2_PROBE_RTT 
            || (bbr2->mode == BBR2_PROBE_BW 
                && bbr2->cycle_idx == BBR2_BW_PROBE_CRUISE))
        {
            cap = xqc_bbr2_inflight_with_headroom(bbr2);
        }
    }
    /* Adapt to any loss/ECN since our last bw probe. */
    cap = xqc_min(cap, bbr2->inflight_lo);
    cap = xqc_max(cap, xqc_bbr2_min_cwnd);
    bbr2->congestion_window = xqc_min(cap, bbr2->congestion_window);
}

static void 
xqc_bbr2_on_ack(void *cong_ctl, xqc_sample_t *sampler)
{
    xqc_bbr2_t *bbr2 = (xqc_bbr2_t *)(cong_ctl);
    xqc_bbr2_context_t bbr2_ctx = {0};
    /* Update model and state */
    xqc_bbr2_update_round_start(bbr2, sampler);
    if (bbr2->round_start) {
        bbr2->rounds_since_probe = xqc_min(bbr2->rounds_since_probe + 1, 0xff);
        bbr2->round_cnt++;
    }
#if XQC_BBR2_PLUS_ENABLED
    /* maintain windowed max rtt here */
    if (bbr2->rtt_compensation_on) {
        if (sampler->rtt >= 0) {
            xqc_usec_t last_max_rtt = xqc_win_filter_get_u64(&bbr2->max_rtt);
            xqc_win_filter_max_u64(&bbr2->max_rtt, bbr2->max_rtt_win_len,
                                bbr2->round_cnt, sampler->rtt);
            xqc_log(sampler->send_ctl->ctl_conn->log, XQC_LOG_DEBUG, 
                    "|BBRv2 Plus|windowed max rtt info: rtt %ui, "
                    "last_max %ui, max %ui|",
                    sampler->rtt, last_max_rtt, 
                    xqc_win_filter_get_u64(&bbr2->max_rtt));
        }
    }
#endif
    xqc_bbr2_calculate_bw_sample(sampler, &bbr2_ctx);
    xqc_bbr2_update_model(bbr2, sampler, &bbr2_ctx);

#if XQC_BBR2_PLUS_ENABLED
    if (bbr2->fast_convergence_on) {
        /* maintain srtt in last and current round */
        if (sampler->rtt >= 0) {
            /* initialization */
            if (bbr2->srtt_in_current_round == XQC_BBR2_INF_RTT) {
                bbr2->srtt_in_current_round = sampler->rtt;
                bbr2->srtt_in_last_round = sampler->rtt;
            } else {
                /* shift values at the beginning of every RTT */
                if (bbr2->round_start) {
                    bbr2->srtt_in_last_round = bbr2->srtt_in_current_round;
                    bbr2->srtt_in_current_round = sampler->rtt;
                } else {
                    /* calculate EWMA */
                    xqc_usec_t _tmp = 7 * bbr2->srtt_in_current_round;
                    bbr2->srtt_in_current_round = (_tmp + sampler->rtt) / 8;
                }
            }
        }
        xqc_log(sampler->send_ctl->ctl_conn->log, XQC_LOG_DEBUG, 
                "|BBRv2 Plus|srtt update|last_round_srtt %ui|"
                "current_round_srtt %ui|",
                bbr2->srtt_in_last_round, bbr2->srtt_in_current_round);
    }
#endif

    xqc_bbr2_update_recovery_mode(bbr2, sampler);
    xqc_bbr2_update_pacing_gain_for_loss_recovery(bbr2);
    /* Update control parameter */
    xqc_bbr2_set_pacing_rate(bbr2, sampler);
    xqc_bbr2_set_cwnd(bbr2, sampler, &bbr2_ctx);
    xqc_bbr2_bound_cwnd_for_inflight_model(bbr2);
    xqc_log(sampler->send_ctl->ctl_conn->log, XQC_LOG_DEBUG,
            "|xqc_bbr2_on_ack|inflight_hi:%ud|inflight_lo:%ud|"
            "inflight_latest:%ud|",
            bbr2->inflight_hi, bbr2->inflight_lo, bbr2->inflight_latest);
    bbr2->loss_in_cycle |= (sampler->loss > 0);
}

static uint64_t 
xqc_bbr2_get_cwnd(void *cong_ctl)
{
    xqc_bbr2_t *bbr = (xqc_bbr2_t *)(cong_ctl);
    return bbr->congestion_window;
}

static uint32_t 
xqc_bbr2_get_pacing_rate(void *cong_ctl)
{
    xqc_bbr2_t *bbr = (xqc_bbr2_t *)(cong_ctl);
    return bbr->pacing_rate;
}

static uint32_t 
xqc_bbr2_get_bandwidth(void *cong_ctl)
{
    xqc_bbr2_t *bbr = (xqc_bbr2_t *)(cong_ctl);
    return xqc_bbr2_bw(bbr);
}

static void 
xqc_bbr2_restart_from_idle(void *cong_ctl, uint64_t conn_delivered)
{
    xqc_bbr2_t *bbr = (xqc_bbr2_t *)(cong_ctl);
    uint32_t rate;
    uint64_t now = xqc_monotonic_timestamp();
    bbr->idle_restart = 1;
    bbr->extra_ack_stamp = now;
    bbr->epoch_ack = 0;
    xqc_sample_t sampler = {.now = now, .total_acked = conn_delivered};

    if (bbr->mode == BBR2_PROBE_BW) {
        _xqc_bbr2_set_pacing_rate_helper(bbr, 1.0);
        if (bbr->pacing_rate == 0) {
            xqc_bbr2_init_pacing_rate(bbr, &sampler);
        }
    } else if (bbr->mode == BBR2_PROBE_RTT) {
        xqc_bbr2_check_probe_rtt_done(bbr, &sampler);
    }
}

/* These functions are mainly for debug */
static uint8_t 
xqc_bbr2_info_mode(void *cong)
{
    xqc_bbr2_t *bbr2 = (xqc_bbr2_t *)cong;
    return bbr2->mode;
}

static uint64_t 
xqc_bbr2_info_min_rtt(void *cong)
{
    xqc_bbr2_t *bbr2 = (xqc_bbr2_t *)cong;
    return bbr2->min_rtt;
}

static uint8_t 
xqc_bbr2_info_idle_restart(void *cong)
{
    xqc_bbr2_t *bbr2 = (xqc_bbr2_t *)cong;
    return bbr2->idle_restart;
}

static uint8_t 
xqc_bbr2_info_full_bw_reached(void *cong)
{
    xqc_bbr2_t *bbr2 = (xqc_bbr2_t *)cong;
    return bbr2->full_bandwidth_reached;
}

static uint8_t 
xqc_bbr2_info_recovery_mode(void *cong)
{
    xqc_bbr2_t *bbr2 = (xqc_bbr2_t *)cong;
    return bbr2->recovery_mode;
}

static uint64_t 
xqc_bbr2_info_recovery_start_time(void *cong)
{
    xqc_bbr2_t *bbr2 = (xqc_bbr2_t *)cong;
    return bbr2->recovery_start_time;
}

static uint8_t 
xqc_bbr2_info_packet_conservation(void *cong)
{
    xqc_bbr2_t *bbr2 = (xqc_bbr2_t *)cong;
    return bbr2->packet_conservation;
}

static uint8_t 
xqc_bbr2_info_round_start(void *cong)
{
    xqc_bbr2_t *bbr2 = (xqc_bbr2_t *)cong;
    return bbr2->round_start;
}

static float 
xqc_bbr2_info_pacing_gain(void *cong)
{
    xqc_bbr2_t *bbr2 = (xqc_bbr2_t *)cong;
    return bbr2->pacing_gain;
}

static float 
xqc_bbr2_info_cwnd_gain(void *cong)
{
    xqc_bbr2_t *bbr2 = (xqc_bbr2_t *)cong;
    return bbr2->cwnd_gain;
}

static int
xqc_bbr2_in_recovery(void *cong) {
    xqc_bbr2_t *bbr2 = (xqc_bbr2_t *)cong;
    return bbr2->recovery_start_time > 0;
}

static xqc_bbr_info_interface_t xqc_bbr2_info_cb = {
    .mode                   = xqc_bbr2_info_mode,
    .min_rtt                = xqc_bbr2_info_min_rtt,
    .idle_restart           = xqc_bbr2_info_idle_restart,
    .full_bw_reached        = xqc_bbr2_info_full_bw_reached,
    .recovery_mode          = xqc_bbr2_info_recovery_mode,
    .recovery_start_time    = xqc_bbr2_info_recovery_start_time,
    .packet_conservation    = xqc_bbr2_info_packet_conservation,
    .round_start            = xqc_bbr2_info_round_start,
    .pacing_gain            = xqc_bbr2_info_pacing_gain,
    .cwnd_gain              = xqc_bbr2_info_cwnd_gain,
};

const xqc_cong_ctrl_callback_t xqc_bbr2_cb = {
    .xqc_cong_ctl_size                   = xqc_bbr2_size,
    .xqc_cong_ctl_init_bbr               = xqc_bbr2_init,
    .xqc_cong_ctl_bbr                    = xqc_bbr2_on_ack,
    .xqc_cong_ctl_get_cwnd               = xqc_bbr2_get_cwnd,
    .xqc_cong_ctl_get_pacing_rate        = xqc_bbr2_get_pacing_rate,
    .xqc_cong_ctl_get_bandwidth_estimate = xqc_bbr2_get_bandwidth,
    .xqc_cong_ctl_restart_from_idle      = xqc_bbr2_restart_from_idle,
    .xqc_cong_ctl_on_lost                = xqc_bbr2_on_lost,
    .xqc_cong_ctl_reset_cwnd             = xqc_bbr2_reset_cwnd,
    .xqc_cong_ctl_info_cb                = &xqc_bbr2_info_cb,
    .xqc_cong_ctl_in_recovery            = xqc_bbr2_in_recovery,
};