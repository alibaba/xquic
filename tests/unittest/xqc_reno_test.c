/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_reno_test.h"
#include "src/congestion_control/xqc_new_reno.h"
#include <stdio.h>
#include "src/common/xqc_time.h"
#include "src/transport/xqc_packet_out.h"

void
print_reno(xqc_new_reno_t *reno)
{
#ifdef DEBUG_PRINT
    printf("cwnd:%u, ssthresh:%u, recovery_start_time:%llu\n",
           reno->reno_congestion_window, reno->reno_ssthresh, reno->reno_recovery_start_time);
#endif
}

void
xqc_test_reno()
{
#ifdef XQC_DISABLE_RENO
    return;
#endif
    xqc_msec_t now = xqc_monotonic_timestamp();

    xqc_new_reno_t reno;
    xqc_msec_t delay = 100;
    xqc_cc_params_t params = {.init_cwnd = 10};
    xqc_reno_cb.xqc_cong_ctl_init(&reno, NULL, params);
    print_reno(&reno);

    /* slow start */
    for (int i = 0; i < 10; ++i) {
        xqc_packet_out_t po;
        po.po_sent_time = now;
        po.po_used_size = 1000;
        xqc_reno_cb.xqc_cong_ctl_on_ack(&reno, &po, now + delay);
        now += 1000000;
        print_reno(&reno);
    }

    /* lost */
    xqc_reno_cb.xqc_cong_ctl_on_lost(&reno, now);
    print_reno(&reno);

    /* congestion avoid */
    for (int i = 0; i < 10; ++i) {
        xqc_packet_out_t po;
        po.po_sent_time = now;
        po.po_used_size = 1000;
        xqc_reno_cb.xqc_cong_ctl_on_ack(&reno, &po, now + delay);
        now += 1000000;
        print_reno(&reno);
    }

    xqc_reno_cb.xqc_cong_ctl_reset_cwnd(&reno);
    print_reno(&reno);

}