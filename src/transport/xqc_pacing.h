/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_PACING_H_INCLUDED_
#define _XQC_PACING_H_INCLUDED_

#include <xquic/xquic_typedef.h>

typedef struct xqc_pacing_s {
    int             pacing_on;
    uint32_t        bytes_budget;
    xqc_usec_t      last_sent_time;
    xqc_send_ctl_t *ctl_ctx;
    uint32_t        pending_budget;
} xqc_pacing_t;

int xqc_pacing_is_on(xqc_pacing_t *pacing);

void xqc_pacing_init(xqc_pacing_t *pacing, int pacing_on, xqc_send_ctl_t *ctl);

void xqc_pacing_on_timeout(xqc_pacing_t *pacing);

void xqc_pacing_on_packet_sent(xqc_pacing_t *pacing, uint32_t bytes);

void xqc_pacing_on_app_limit(xqc_pacing_t *pacing);

int xqc_pacing_can_write(xqc_pacing_t *pacing, uint32_t total_bytes);

#endif /* _XQC_PACING_H_INCLUDED_ */
