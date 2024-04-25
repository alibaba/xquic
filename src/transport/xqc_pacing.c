/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/transport/xqc_pacing.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_packet.h"
#include "src/common/xqc_log.h"

#define XQC_MIN_BURST_NUM (2 * XQC_MSS)
#define XQC_MAX_BURST_NUM (10 * XQC_MSS)
#define TRUE 1
#define FALSE 0
#define XQC_CLOCK_GRANULARITY_US 1000 /* 1ms */
#define XQC_PACING_DELAY_US XQC_CLOCK_GRANULARITY_US
#define XQC_DEFAULT_PACING_RATE(init_rtt) (((2 * XQC_MSS * 1000000ULL)/(init_rtt)))

void
xqc_pacing_init(xqc_pacing_t *pacing, int pacing_on, xqc_send_ctl_t *send_ctl)
{
    pacing->bytes_budget = XQC_MAX_BURST_NUM;
    pacing->last_sent_time = 0;
    pacing->ctl_ctx = send_ctl;
    pacing->pacing_on = pacing_on;
    pacing->pending_budget = 0;
    if (send_ctl->ctl_cong_callback->xqc_cong_ctl_on_ack_multiple_pkts) {
        pacing->pacing_on = 1;
    }
}

uint64_t
xqc_pacing_rate_calc(xqc_pacing_t *pacing)
{
    /* see linux kernel tcp_update_pacing_rate(struct sock *sk) */
    uint64_t pacing_rate;
    uint64_t cwnd;
    xqc_send_ctl_t *send_ctl = pacing->ctl_ctx;
    if (send_ctl->ctl_cong_callback->xqc_cong_ctl_get_pacing_rate) {
        pacing_rate = send_ctl->ctl_cong_callback->
                      xqc_cong_ctl_get_pacing_rate(send_ctl->ctl_cong);
        return pacing_rate;
    }

    cwnd = send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(send_ctl->ctl_cong);

    xqc_usec_t srtt = send_ctl->ctl_srtt;
    if (srtt == 0) {
        srtt = send_ctl->ctl_conn->conn_settings.initial_rtt;
    }

    /* bytes can be sent per second */
    pacing_rate = cwnd * 1000000 / srtt;
    if (pacing_rate == 0) {
        pacing_rate = XQC_DEFAULT_PACING_RATE(srtt);
        xqc_log(pacing->ctl_ctx->ctl_conn->log, XQC_LOG_ERROR,
                "|pacing_rate zero|cwnd:%ui|srtt:%ui|", cwnd, srtt);
    }

    if (send_ctl->ctl_cong_callback->xqc_cong_ctl_in_slow_start 
        && send_ctl->ctl_cong_callback->xqc_cong_ctl_in_slow_start(send_ctl->ctl_cong))
    {
        pacing_rate *= 2;

    } else {
        pacing_rate = pacing_rate * 12 / 10;
    }

    return pacing_rate;
}

static uint32_t 
xqc_pacing_max_burst_size(xqc_pacing_t *pacing)
{
    xqc_usec_t t_diff = (XQC_PACING_DELAY_US + XQC_CLOCK_GRANULARITY_US);
    uint64_t max_burst_bytes = t_diff * xqc_pacing_rate_calc(pacing) 
                                / 1000000;
    return xqc_max(XQC_MAX_BURST_NUM, max_burst_bytes);
}

static uint32_t 
xqc_pacing_calc_budget(xqc_pacing_t *pacing, xqc_usec_t now)
{
    uint32_t budget = pacing->bytes_budget;
    uint32_t max_burst_bytes = xqc_pacing_max_burst_size(pacing);
    if (pacing->last_sent_time == 0) {
        budget = max_burst_bytes;

    } else {
        budget += (now - pacing->last_sent_time) * xqc_pacing_rate_calc(pacing)
                    / 1000000;
    }
    return xqc_min(budget, max_burst_bytes);
}

void
xqc_pacing_on_timeout(xqc_pacing_t *pacing)
{
    xqc_usec_t now = xqc_monotonic_timestamp();
    uint32_t budget = xqc_pacing_calc_budget(pacing, now);
    pacing->bytes_budget = xqc_max(budget, pacing->bytes_budget + pacing->pending_budget);
    pacing->pending_budget = 0;
    pacing->last_sent_time = now;
}

void 
xqc_pacing_on_packet_sent(xqc_pacing_t *pacing, uint32_t bytes)
{
    xqc_usec_t now = xqc_monotonic_timestamp();
    uint32_t budget = xqc_pacing_calc_budget(pacing, now);
    if (bytes > budget) {
        budget = 0;

    } else {
        budget -= bytes;
    }
    pacing->bytes_budget = budget;
    pacing->last_sent_time = now;
}

xqc_usec_t 
xqc_pacing_time_until_send(xqc_pacing_t *pacing, uint32_t bytes)
{
    if (pacing->bytes_budget >= bytes) {
        return 0;
    }
    xqc_usec_t delay_us;
    delay_us = (uint64_t)(bytes - pacing->bytes_budget) * 1000000 
            / xqc_pacing_rate_calc(pacing);
    delay_us = xqc_max(delay_us, XQC_PACING_DELAY_US);
    pacing->pending_budget = bytes - pacing->bytes_budget;
    return delay_us;
}

int 
xqc_pacing_can_write(xqc_pacing_t *pacing, uint32_t total_bytes)
{
    xqc_send_ctl_t *send_ctl = pacing->ctl_ctx;
    if (xqc_timer_is_set(&send_ctl->path_timer_manager, XQC_TIMER_PACING)) {
        xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG, "|waiting for pacing timer to expire!|");
        return FALSE;
    }

    uint64_t delay = xqc_pacing_time_until_send(pacing, total_bytes);
    xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG, "|pacing_delay:%ui|", delay);

    if (delay != 0) {
        xqc_timer_update(&send_ctl->path_timer_manager, XQC_TIMER_PACING, xqc_monotonic_timestamp(), delay);
        xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG, "|PACING timer update|delay:%ui|", 
                delay);
        return FALSE;
    }

    return TRUE;
}

void
xqc_pacing_on_app_limit(xqc_pacing_t *pacing) {
    pacing->bytes_budget = XQC_MAX_BURST_NUM;
    pacing->last_sent_time = xqc_monotonic_timestamp();
}

int
xqc_pacing_is_on(xqc_pacing_t *pacing) {
    return pacing->pacing_on;
}
