/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_SCHEDULER_MINRTT_H_INCLUDED_
#define _XQC_SCHEDULER_MINRTT_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>

/* 
 * RAP: Reinjection on Any Path. Reinjected packets can be scheduled onto 
 *      the same path where the original packets were sent if no other paths 
 *      are available.
 */

extern const xqc_scheduler_callback_t xqc_rap_scheduler_cb;

#endif /* _XQC_SCHEDULER_MINRTT_H_INCLUDED_ */