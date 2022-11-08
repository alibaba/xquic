/*
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 *
 * An implementation of the delay-based Copa (NSDI'18) algorithm. 
 */

#ifndef _XQC_COPA_H_INCLUDED_
#define _XQC_COPA_H_INCLUDED_

#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>
#include "src/congestion_control/xqc_window_filter.h"

typedef enum {
    COPA_UNDEF = 0,
    COPA_UP = 1,
    COPA_DOWN = 2,
} xqc_copa_direction_t;

typedef enum {
    COPA_DELAY_MODE = 0, /* to operate with copa's delay-based control */
    COPA_COMPETITIVE_MODE = 1, /* to co-exist with loss-based CCAs */
} xqc_copa_mode_t;

typedef struct xqc_copa_s {
    /* 
     * The parameter to control copa's tradeoff between latency and throughput.
     * Smaller values lead copa to more favor throughput over latency. 0.5 is 
     * the default value recommended by the paper. It should be always greater 
     * than zero.
     */
    double               delta_ai_unit;
    double               delta_base;
    double               delta_max;
    double               delta;    
    uint64_t             init_cwnd_bytes;                
    uint64_t             cwnd_bytes;
    uint64_t             last_round_cwnd_bytes;
    /* copa paces packets out at the rate of 2*cwnd/rtt_standing */
    uint64_t             pacing_rate;
    /* min rtt over the past srtt/2 period */
    xqc_win_filter_t     rtt_standing;   
    /* min rtt over last 10s */
    xqc_win_filter_t     rtt_min; 
    /* max rtt over the past four RTTs */       
    xqc_win_filter_t     rtt_max;
    /* velocity */      
    double               v;   
    /* direction related states */
    xqc_copa_direction_t curr_dir, prev_dir;
    uint32_t             same_dir_cnt;
    /* copa mode */
    xqc_copa_mode_t      mode;
    /* when observed a low queuing delay over the past five RTTs */
    xqc_usec_t           t_last_delay_min;
    /* in slow start */
    xqc_bool_t           in_slow_start; 
    /* loss recovery start time */
    xqc_usec_t           recovery_start_time;
    /* for packet-timed round trip counting */
    uint32_t             round_cnt;
    uint64_t             next_round_delivered;
    xqc_bool_t           round_start;
    int64_t              cwnd_adjustment_accumulated;      
    /* connection/path context */
    xqc_send_ctl_t      *ctl_ctx;
} xqc_copa_t;

extern const xqc_cong_ctrl_callback_t xqc_copa_cb;

#endif