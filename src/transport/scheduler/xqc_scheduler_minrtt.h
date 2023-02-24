/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_SCHEDULER_MINRTT_H_INCLUDED_
#define _XQC_SCHEDULER_MINRTT_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>

extern const xqc_scheduler_callback_t xqc_minrtt_scheduler_cb;

xqc_path_ctx_t* 
xqc_minrtt_scheduler_get_path(void *scheduler, xqc_connection_t *conn, 
    xqc_packet_out_t *packet_out, int check_cwnd, int reinject);

#endif /* _XQC_SCHEDULER_MINRTT_H_INCLUDED_ */
