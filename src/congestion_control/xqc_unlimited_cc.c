/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/congestion_control/xqc_unlimited_cc.h"
#include "src/common/xqc_config.h"

size_t
xqc_unlimited_cc_size()
{
    return 0;
}

static void
xqc_unlimited_cc_init(void *cong_ctl, xqc_send_ctl_t *ctl_ctx, xqc_cc_params_t cc_params)
{
    return;
}


static void
xqc_unlimited_cc_on_lost(void *cong_ctl, xqc_usec_t lost_sent_time)
{
    return;
}


static void
xqc_unlimited_cc_on_ack(void *cong_ctl, xqc_packet_out_t *po, xqc_usec_t now)
{
    return;
}

uint64_t
xqc_unlimited_cc_get_cwnd(void *cong_ctl)
{
    return XQC_MAX_UINT64_VALUE;
}

void
xqc_unlimited_cc_reset_cwnd(void *cong_ctl)
{
    return;
}

int32_t
xqc_unlimited_cc_in_slow_start(void *cong_ctl)
{
    return 0;
}

void
xqc_unlimited_cc_restart_from_idle(void *cong_ctl, uint64_t arg)
{
    return;
}

static int
xqc_unlimited_cc_in_recovery(void *cong_ctl)
{
    return 0;
}

const xqc_cong_ctrl_callback_t xqc_unlimited_cc_cb = {
    .xqc_cong_ctl_size              = xqc_unlimited_cc_size,
    .xqc_cong_ctl_init              = xqc_unlimited_cc_init,
    .xqc_cong_ctl_on_lost           = xqc_unlimited_cc_on_lost,
    .xqc_cong_ctl_on_ack            = xqc_unlimited_cc_on_ack,
    .xqc_cong_ctl_get_cwnd          = xqc_unlimited_cc_get_cwnd,
    .xqc_cong_ctl_reset_cwnd        = xqc_unlimited_cc_reset_cwnd,
    .xqc_cong_ctl_in_slow_start     = xqc_unlimited_cc_in_slow_start,
    .xqc_cong_ctl_restart_from_idle = xqc_unlimited_cc_restart_from_idle,
    .xqc_cong_ctl_in_recovery       = xqc_unlimited_cc_in_recovery,
};
