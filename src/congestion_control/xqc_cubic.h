/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_CUBIC_H_INCLUDED_
#define _XQC_CUBIC_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_packet_out.h"

typedef struct {
    uint64_t        init_cwnd;          /* initial window size in MSS */
    uint64_t        cwnd;               /* current window size in bytes */
    uint64_t        tcp_cwnd;           /* cwnd calculated according to Reno's algorithm */
    uint64_t        last_max_cwnd;      /* last max window size */
    uint64_t        ssthresh;           /* slow start threshold */
    uint64_t        bic_origin_point;   /* Wmax origin point */
    uint64_t        bic_K;              /* time period from W growth to Wmax */
    xqc_usec_t      epoch_start;        /* the moment when congestion switchover begins, in microseconds */
    xqc_usec_t      min_rtt;
} xqc_cubic_t;

extern const xqc_cong_ctrl_callback_t xqc_cubic_cb;

#endif /* _XQC_CUBIC_H_INCLUDED_ */
