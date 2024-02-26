/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <xquic/xquic.h>
#include "src/common/xqc_config.h"
#include "src/common/xqc_time.h"
#include "src/congestion_control/xqc_copa.h"
#include "src/transport/xqc_send_ctl.h"

#define XQC_COPA_MSS                   (XQC_MSS)
#define XQC_COPA_MIN_WIN               (4 * XQC_COPA_MSS)
#define XQC_COPA_MAX_INIT_WIN          (100 * XQC_COPA_MSS)
#define XQC_COPA_INIT_WIN              (32 * XQC_COPA_MSS)
#define XQC_COPA_RTT_MIN_WINDOW        (10000000) /* 10s */
#define XQC_COPA_RTT_MAX_WINDOW        (4) /* 4 RTTs */
#define XQC_COPA_RTT_STA_WINDOW        (0.5) /* 0.5 RTT */
/* mode switching threshold: 5 RTTs */
#define XQC_COPA_MS_THRESHOLD          (5) 
/* the default value recommended by Facebook */
#define XQC_COPA_DEFAULT_DELTA         (0.05)
/* the upper bound of delta for the competitive mode */
#define XQC_COPA_DEFAULT_DELTA_MAX     (0.5)
#define XQC_COPA_MAX_DELTA             (1.0)
#define XQC_COPA_INF_U64               (~0ULL)
#define XQC_COPA_INIT_VELOCITY         (1.0)
#define XQC_COPA_MAX_RATE              (1.0 * (~0ULL))
#define XQC_COPA_USEC2SEC              (1000000)
#define XQC_COPA_DEFAULT_DELTA_AI_UNIT (1.0)

#define XQC_COPA_LOG_STATE(comment_str, log_level) \
do { \
    xqc_log(copa->ctl_ctx->ctl_conn->log, log_level,  \
            "|copa|"comment_str"|init_cwnd_bytes:%ui|cwnd_bytes:%ui|" \
            "rtt_min:%ui|rtt_max:%ui|rtt_standing:%ui|delta:%.4f|" \
            "velocity:%.4f|curr_dir:%d|prev_dir:%d|same_dir_cnt:%d|mode:%d|" \
            "t_last_delay_min:%ui|slow_start:%d|pacing_rate:%ui|" \
            "recovery_start_time:%ui|round_cnt:%ud|next_round_delivered:%ui|" \
            "round_start:%d|delta_base:%.4f|delta_max:%.4f|" \
            "last_round_cwnd_bytes:%ui|cwnd_adjustment_accumulated:%i|" \
            "delta_ai_unit:%.4f|", \
            copa->init_cwnd_bytes, copa->cwnd_bytes, \
            xqc_win_filter_get(&copa->rtt_min), \
            xqc_win_filter_get(&copa->rtt_max), \
            xqc_win_filter_get(&copa->rtt_standing), \
            copa->delta, copa->v, copa->curr_dir, copa->prev_dir, \
            copa->same_dir_cnt, copa->mode, copa->t_last_delay_min, \
            copa->in_slow_start, copa->pacing_rate, copa->recovery_start_time, \
            copa->round_cnt, copa->next_round_delivered,  \
            copa->round_start, copa->delta_base, copa->delta_max, \
            copa->last_round_cwnd_bytes, copa->cwnd_adjustment_accumulated, \
            copa->delta_ai_unit); \
} while (0)



static void 
xqc_copa_set_pacing_rate(xqc_copa_t *copa)
{
    /* 2*cwnd / rtt_standing */
    xqc_usec_t rtt_standing = xqc_win_filter_get(&copa->rtt_standing);
    xqc_usec_t initial_rtt = copa->ctl_ctx->ctl_conn->conn_settings.initial_rtt;
    if (rtt_standing == XQC_COPA_INF_U64) {
        /* initialization */
        rtt_standing = copa->ctl_ctx->ctl_srtt;
    }
    if (rtt_standing == 0) {
        xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_WARN, 
                "|copa|rtt_standing_error:%ui|", rtt_standing);
        /* initialization */
        rtt_standing = initial_rtt;
        xqc_win_filter_reset(&copa->rtt_standing, 0, XQC_COPA_INF_U64);
    }
    copa->pacing_rate = ((copa->cwnd_bytes) * XQC_COPA_USEC2SEC) << 1;
    copa->pacing_rate /= rtt_standing;
    copa->pacing_rate = xqc_max(copa->pacing_rate, XQC_COPA_MSS);
}

static size_t
xqc_copa_size()
{
    return sizeof(xqc_copa_t);
}

static void
xqc_copa_init(void *cong, xqc_send_ctl_t *ctl_ctx, xqc_cc_params_t cc_params)
{
    xqc_copa_t *copa = (xqc_copa_t*)cong;
    copa->init_cwnd_bytes = XQC_COPA_INIT_WIN;
    copa->delta_base = XQC_COPA_DEFAULT_DELTA;
    copa->delta_max  = XQC_COPA_DEFAULT_DELTA_MAX;
    copa->delta_ai_unit = XQC_COPA_DEFAULT_DELTA_AI_UNIT;
    xqc_win_filter_reset(&copa->rtt_min, 0, XQC_COPA_INF_U64);
    xqc_win_filter_reset(&copa->rtt_max, 0, 0);
    xqc_win_filter_reset(&copa->rtt_standing, 0, XQC_COPA_INF_U64);
    copa->v = XQC_COPA_INIT_VELOCITY;
    copa->curr_dir = COPA_UNDEF; /* slow start */
    copa->prev_dir = COPA_UNDEF;
    copa->same_dir_cnt = 0;
    copa->mode = COPA_DELAY_MODE;
    copa->t_last_delay_min = 0;
    copa->in_slow_start = XQC_TRUE;
    copa->ctl_ctx = ctl_ctx;
    if (cc_params.customize_on) {
        copa->init_cwnd_bytes = xqc_clamp(cc_params.init_cwnd * XQC_COPA_MSS,
                                          XQC_COPA_MIN_WIN,
                                          XQC_COPA_MAX_INIT_WIN);
        if (cc_params.copa_delta_base > 0) {
            copa->delta_base = cc_params.copa_delta_base;
        }

        if (cc_params.copa_delta_max > 0) {
            copa->delta_max = cc_params.copa_delta_max;
        }

        if (cc_params.copa_delta_ai_unit > 1.0) {
            copa->delta_ai_unit = cc_params.copa_delta_ai_unit;
        }

        copa->delta_max = xqc_min(copa->delta_max, XQC_COPA_MAX_DELTA);
        copa->delta_base = xqc_min(copa->delta_base, copa->delta_max);
    }
    copa->delta = copa->delta_base;
    copa->cwnd_bytes = copa->init_cwnd_bytes;
    copa->last_round_cwnd_bytes = 0; 
    xqc_copa_set_pacing_rate(copa);
    copa->recovery_start_time = 0;
    copa->next_round_delivered = 0;
    copa->round_cnt = 0;
    copa->round_start = XQC_FALSE;
    copa->cwnd_adjustment_accumulated = 0;

    XQC_COPA_LOG_STATE("initialization", XQC_LOG_DEBUG);
    return;
}

static void
xqc_copa_on_lost(void *cong, xqc_usec_t lost_sent_time)
{
    xqc_copa_t *copa = (xqc_copa_t*)cong;
    /* already in recovery mode */
    if (lost_sent_time < copa->recovery_start_time) {
        xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG, 
                "|copa|loss_before_recovery|loss_sent_time:%ui|"
                "recovery_start_time:%ui|",
                lost_sent_time, copa->recovery_start_time);

    } else {
        /* start a new recovery epoch */
        copa->recovery_start_time = xqc_monotonic_timestamp();
        xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG, 
                "|copa|recovery_start_at:%ui|", copa->recovery_start_time);
        if (copa->mode == COPA_COMPETITIVE_MODE) {
            /* 
             * multiplicative decrease on 1 / delta, 
             * once per epoch (RTT) at most.
             */
            copa->delta = xqc_min(copa->delta * 2, copa->delta_max);
            xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG, 
                    "|copa|MD_on_delta:%.4f|", copa->delta);
        }
    }

    XQC_COPA_LOG_STATE("on_lost", XQC_LOG_DEBUG);
    return;
}

static inline void
xqc_copa_handle_sudden_direction_change(xqc_copa_t *copa, 
    xqc_copa_direction_t new_dir)
{
    copa->v = XQC_COPA_INIT_VELOCITY;
    copa->same_dir_cnt = 0;
    copa->last_round_cwnd_bytes = copa->cwnd_bytes;
    copa->prev_dir = copa->curr_dir;
    copa->curr_dir = new_dir;
    xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG, 
            "|copa|handle_sudden_direction_change|cwnd_bytes:%ui|"
            "last_round_cwnd_bytes:%ui|curr_dir:%d|prev_dir:%d|",
            copa->cwnd_bytes, copa->last_round_cwnd_bytes,
            copa->curr_dir, copa->prev_dir);
}

static void
xqc_copa_on_ack(void *cong, xqc_sample_t *sampler)
{
    xqc_copa_t *copa = (xqc_copa_t*)cong;
    xqc_usec_t  largest_pkt_sent_time = sampler->po_sent_time;
    uint32_t    newly_acked_bytes = sampler->acked;
    xqc_usec_t  ack_recv_time = sampler->now;
    xqc_usec_t  latest_rtt = copa->ctl_ctx->ctl_latest_rtt;
    xqc_usec_t  srtt = copa->ctl_ctx->ctl_srtt;
    xqc_usec_t  rtt_min_win = XQC_COPA_RTT_MIN_WINDOW;
    xqc_usec_t  rtt_sta_win = XQC_COPA_RTT_STA_WINDOW * srtt;
    xqc_usec_t  rtt_max_win = XQC_COPA_RTT_MAX_WINDOW;

    XQC_COPA_LOG_STATE("before_on_ack", XQC_LOG_DEBUG);

    xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG, "|copa|sampler|"
            "ack_time:%ui|prior_delivered:%ui|delivered:%ud|acked:%ud|"
            "bytes_inflight:%ud|prior_inflight:%ud|rtt:%ui|"
            "is_applimit:%ud|srtt:%ui|loss:%ud|total_acked:%ui|",
            sampler->now, sampler->prior_delivered, sampler->delivered,
            sampler->acked, sampler->bytes_inflight, sampler->prior_inflight,
            sampler->rtt, sampler->is_app_limited, sampler->srtt,
            sampler->loss, sampler->total_acked);

    /* check if we have recovered from losses */
    if (copa->recovery_start_time > 0 
        && largest_pkt_sent_time > copa->recovery_start_time)
    {
        copa->recovery_start_time = 0;
        xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG, 
                "|copa|loss_recovered|sent_time:%ui|ack_time:%ui|",
                largest_pkt_sent_time, ack_recv_time);
    }
    /* 
     * Copa does not care about if it is in recovery mode. 
     * It always adjusts cwnd with the AIAD law. 
     */

    copa->round_start = XQC_FALSE;

    /* update packet-timed round trip counter */
    if (sampler->prior_delivered >= copa->next_round_delivered) {
        copa->round_cnt++;
        copa->next_round_delivered = sampler->total_acked;
        copa->round_start = XQC_TRUE;
        xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG, 
                "|copa|round_cnt_advanced|round_cnt:%ud|"
                "next_round_delivered:%ui|",
                copa->round_cnt, copa->next_round_delivered);
    }

    /* update delta */
    if (copa->mode == COPA_COMPETITIVE_MODE && copa->round_start) {
        /* 
         * additive increase on 1 / delta.
         * 1 / delta = 1 / delta + 1 = (delta + 1) / delta 
         */
        copa->delta = copa->delta / (copa->delta * copa->delta_ai_unit + 1);
    }

    /* Once we have a valid ack sample, rtt statistics must not be zero */
    if (latest_rtt == 0) {
        /* invalid latest_rtt */
        xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_WARN, 
                "|copa|invalid_latest_rtt:%ui|ack_time:%ui|", 
                ack_recv_time, latest_rtt);
        goto on_ack_end;
    }
    
    /* update rtt statistics */
    xqc_win_filter_min(&copa->rtt_min, rtt_min_win,
                       ack_recv_time, latest_rtt);
    xqc_win_filter_min(&copa->rtt_standing, rtt_sta_win,
                       ack_recv_time, latest_rtt);
    xqc_win_filter_max(&copa->rtt_max, rtt_max_win, 
                       copa->round_cnt, latest_rtt);

    /* calculate data */
    double     target_rate, current_rate;
    xqc_usec_t rtt_standing, rtt_min, rtt_max, delay;

    rtt_standing = xqc_win_filter_get(&copa->rtt_standing);
    rtt_min = xqc_win_filter_get(&copa->rtt_min);
    if (rtt_standing < rtt_min) {
        xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_WARN, 
                "|copa|negative_queuing_delay|srtt:%ui|"
                "rtt_standing:%ui|rtt_min:%ui|",
                srtt, rtt_standing, rtt_min);
        goto on_ack_end;
    }

    delay = rtt_standing - rtt_min;

    /* update the time when a low queuing delay is observed */
    /* <= guarantees the update the timestamp when delay is zero */
    if (delay <= ((xqc_win_filter_get(&copa->rtt_max) - rtt_min) / 10)) {
        copa->t_last_delay_min = ack_recv_time;
        if (copa->mode != COPA_DELAY_MODE) {
            /* switch to delay mode and reset delta */
            copa->mode = COPA_DELAY_MODE;
            copa->delta = copa->delta_base;
        }
        xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG, 
                "|copa|low_delay_is_observed_at:%ui|mode:%d|", 
                ack_recv_time, copa->mode);
    }

    if (delay == 0) {
        /* no queuing delay */
        target_rate = XQC_COPA_MAX_RATE;

    } else {
        target_rate = XQC_COPA_MSS * 1.0 
                      * XQC_COPA_USEC2SEC / (delay * copa->delta);
    }
    current_rate = copa->cwnd_bytes * 1.0 * XQC_COPA_USEC2SEC / rtt_standing;

    xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG, 
            "|copa|rate_generated|target_rate:%.4f|current_rate:%.4f|"
            "delay:%ui|", 
            target_rate, current_rate, delay);

    /* slow start */
    if (copa->in_slow_start) {
        if (current_rate > target_rate) {
            /* exit slow start */
            copa->in_slow_start = 0;
            xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG, 
                    "|copa|slow_start_exit|");
            /* @TODO: we may set Copa's direction to DOWN at here */

        } else {
            /* 
             * We make sure that cwnd must NOT increase by more than 2x 
             * at a time.
             */
            if (newly_acked_bytes > copa->cwnd_bytes) {
                copa->cwnd_bytes <<= 1;
            } else {
                copa->cwnd_bytes += newly_acked_bytes;
            }
            xqc_copa_set_pacing_rate(copa);
            goto on_ack_end;
        }
    }

    /* steady phase start */

    /* check mode switching conditions at round start */
    /* @TODO: may switch to packet-timed rounds for t_last_delay_min */
    if (copa->round_start 
        && copa->mode != COPA_COMPETITIVE_MODE
        && ((ack_recv_time - copa->t_last_delay_min) 
        >= (XQC_COPA_MS_THRESHOLD * srtt)))
    {
        copa->mode = COPA_COMPETITIVE_MODE;
        xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG, 
                "|copa|switch_to_competitive_mode_at:%ui|"
                "round_cnt:%ud|t_last_delay_min:%ui|", 
                ack_recv_time, copa->round_cnt, copa->t_last_delay_min);
    }

    /* check & update the direction for cwnd adjustment */
    if (copa->round_start) {
        xqc_copa_direction_t new_dir;
        if (copa->cwnd_bytes > copa->last_round_cwnd_bytes) {
            new_dir = COPA_UP;

        } else {
            new_dir = COPA_DOWN;
        }

        copa->last_round_cwnd_bytes = copa->cwnd_bytes;

        if (new_dir != copa->curr_dir) {
            copa->v = XQC_COPA_INIT_VELOCITY;
            copa->same_dir_cnt = 0;

        } else {
            copa->same_dir_cnt++;
        }

        copa->prev_dir = copa->curr_dir;
        copa->curr_dir = new_dir;

        xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG, 
                "|copa|direction_update|curr_dir:%d|prev_dir:%d|"
                "same_dir_cnt:%ud|velocity:%.4f|",
                copa->curr_dir, copa->prev_dir, copa->same_dir_cnt, copa->v);

        /* 
        * if cnt == 3, it means the direction remains the same for 
        * a bit less than 3 RTTs.
        */
        if (copa->same_dir_cnt > 3) {
            /* 
            * double v every RTT once the direction has remained the same
            * for 3 RTTs.
            */
            copa->v *= 2.0;
            xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG, 
                "|copa|velocity_update|velocity:%.4f|", copa->v);
        }

        /* 
         * if v makes cwnd grow faster than slow start, 
         * we should reduce it
         */
        if ((copa->v * XQC_COPA_MSS) >= (copa->delta * copa->cwnd_bytes)) {
            copa->v /= 2.0;
            xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG, 
                    "|copa|velocity_too_large|velocity:%.4f|", copa->v);
        }
        /* but, we need to ensure v is at least XQC_COPA_INIT_VELOCITY */
        copa->v = xqc_max(copa->v, XQC_COPA_INIT_VELOCITY);
    }

    int aiad_sign;
    /* update cwnd */
    if (current_rate > target_rate) {
        /* 
         * According to Facebook's Copa implementation, they reset the velocity
         * to 1.0, if the current direction indicates the opposite cwnd 
         * adjustment direction of what current_rate and target_rate indicate 
         * and the velocity is greater than XQC_COPA_INIT_VELOCITY.
         */
        if (copa->curr_dir != COPA_DOWN && copa->v > XQC_COPA_INIT_VELOCITY) {
            xqc_copa_handle_sudden_direction_change(copa, COPA_DOWN);
        }
        aiad_sign = -1;

    } else {
        if (copa->curr_dir != COPA_UP && copa->v > XQC_COPA_INIT_VELOCITY) {
            xqc_copa_handle_sudden_direction_change(copa, COPA_UP);
        }
        aiad_sign = 1;
    }

    uint64_t numerator_bytes = (uint64_t)(copa->v * newly_acked_bytes 
                                   / copa->delta);
    /* v * delta should be always greater than 1.0 */
    if (numerator_bytes == 0) {
        xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_WARN, 
                "|copa|acked_bytes_too_less|velocity:%.4f|delta:%.4f|"
                "newly_acked_bytes:%ui|", 
                copa->v, copa->delta, newly_acked_bytes);
    }
    copa->cwnd_adjustment_accumulated += (aiad_sign * numerator_bytes);
    xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG, 
            "|copa|aiad_bytes_accumulated|aiad_sign:%d|numertor_bytes:%ui|"
            "cwnd_adjustment_accumulated:%i|", 
            aiad_sign, numerator_bytes, copa->cwnd_adjustment_accumulated);

    if (copa->cwnd_adjustment_accumulated > 0
        && copa->cwnd_adjustment_accumulated >= copa->cwnd_bytes) {
        int64_t d = copa->cwnd_adjustment_accumulated / copa->cwnd_bytes;
        copa->cwnd_adjustment_accumulated -= (d * copa->cwnd_bytes);
        copa->cwnd_bytes += (d * XQC_COPA_MSS);
        xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG, 
                "|copa|aiad_bytes_applied|UP|cwnd_bytes:%ui|"
                "cwnd_adjustment_accumulated:%i|", 
                copa->cwnd_bytes, copa->cwnd_adjustment_accumulated);

    } else if (copa->cwnd_adjustment_accumulated < 0
               && copa->cwnd_adjustment_accumulated <= -copa->cwnd_bytes) {
        int64_t d = -copa->cwnd_adjustment_accumulated / copa->cwnd_bytes;
        copa->cwnd_adjustment_accumulated += (d * copa->cwnd_bytes);
        /* avoid underflow */
        d = d * XQC_COPA_MSS;
        if (d <= copa->cwnd_bytes) {
            copa->cwnd_bytes -= d;
        } else {
            copa->cwnd_bytes = 0;
        }
        xqc_log(copa->ctl_ctx->ctl_conn->log, XQC_LOG_DEBUG, 
                "|copa|aiad_bytes_applied|DOWN|cwnd_bytes:%ui|"
                "cwnd_adjustment_accumulated:%i|", 
                copa->cwnd_bytes, copa->cwnd_adjustment_accumulated);
    }

    copa->cwnd_bytes = xqc_max(XQC_COPA_MIN_WIN, copa->cwnd_bytes);
    xqc_copa_set_pacing_rate(copa);

on_ack_end:
    XQC_COPA_LOG_STATE("after_on_ack", XQC_LOG_DEBUG);
    return;
}

static uint64_t
xqc_copa_get_cwnd(void *cong)
{
    xqc_copa_t *copa = (xqc_copa_t*)cong;
    return copa->cwnd_bytes;
}

static void
xqc_copa_reset_cwnd(void *cong)
{
    xqc_copa_t *copa = (xqc_copa_t*)cong;
    /* 
     * @NOTE: We reinitialize Copa and do slow start again. After recovering 
     * from a persistent congestion event, the network path may have changed 
     * significantly. Therefore, the safest way to do congestion control is to 
     * cut the cwnd to the minimal value and re-probe the network path by 
     * slow start.
     */
    xqc_win_filter_reset(&copa->rtt_min, 0, XQC_COPA_INF_U64);
    xqc_win_filter_reset(&copa->rtt_max, 0, 0);
    xqc_win_filter_reset(&copa->rtt_standing, 0, XQC_COPA_INF_U64);
    copa->v = XQC_COPA_INIT_VELOCITY;
    copa->curr_dir = COPA_UNDEF; /* slow start */
    copa->prev_dir = COPA_UNDEF;
    copa->same_dir_cnt = 0;
    copa->mode = COPA_DELAY_MODE;
    copa->t_last_delay_min = 0;
    copa->in_slow_start = XQC_TRUE;
    copa->delta = copa->delta_base;
    copa->recovery_start_time = 0;
    copa->cwnd_adjustment_accumulated = 0;
    copa->cwnd_bytes = XQC_COPA_MIN_WIN;
    xqc_copa_set_pacing_rate(copa);

    XQC_COPA_LOG_STATE("persistent_congestion", XQC_LOG_DEBUG);
    return;
}

static int
xqc_copa_in_slow_start(void *cong)
{
    xqc_copa_t *copa = (xqc_copa_t*)cong;
    return copa->in_slow_start;
}

static void
xqc_copa_restart_from_idle(void *cong, uint64_t arg)
{
    /* 
     * @TODO: may do something here in the future, 
     * e.g. resetting congestion state and restarting from slow start.
     */
    return;
}

static int
xqc_copa_in_recovery(void *cong)
{
    xqc_copa_t *copa = (xqc_copa_t*)cong;
    return copa->recovery_start_time > 0;
}

/* @TODO: use u64 for pacing rate all the time */
static uint32_t
xqc_copa_get_pacing_rate(void *cong)
{
    xqc_copa_t *copa = (xqc_copa_t*)cong;
    return copa->pacing_rate;
}

const xqc_cong_ctrl_callback_t xqc_copa_cb = {
    .xqc_cong_ctl_size                 = xqc_copa_size,
    .xqc_cong_ctl_init                 = xqc_copa_init,
    .xqc_cong_ctl_on_lost              = xqc_copa_on_lost,
    /* @TODO: rename this callback interface */
    .xqc_cong_ctl_on_ack_multiple_pkts = xqc_copa_on_ack,
    .xqc_cong_ctl_get_cwnd             = xqc_copa_get_cwnd,
    .xqc_cong_ctl_reset_cwnd           = xqc_copa_reset_cwnd,
    .xqc_cong_ctl_in_slow_start        = xqc_copa_in_slow_start,
    .xqc_cong_ctl_restart_from_idle    = xqc_copa_restart_from_idle,
    .xqc_cong_ctl_in_recovery          = xqc_copa_in_recovery,
    .xqc_cong_ctl_get_pacing_rate      = xqc_copa_get_pacing_rate,
};