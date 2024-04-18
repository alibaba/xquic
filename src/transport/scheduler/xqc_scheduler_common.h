#ifndef _XQC_SCHEDULER_COMMON_H_INCLUDED_
#define _XQC_SCHEDULER_COMMON_H_INCLUDED_

#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>

xqc_bool_t xqc_scheduler_check_path_can_send(xqc_path_ctx_t *path, xqc_packet_out_t *packet_out, int check_cwnd);

#endif /* _XQC_SCHEDULER_COMMON_H_INCLUDED_ */