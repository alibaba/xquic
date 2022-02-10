/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_BBR_H_INCLUDED_
#define _XQC_BBR_H_INCLUDED_


#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>
#include "src/congestion_control/xqc_window_filter.h"
#include "src/congestion_control/xqc_bbr_common.h"

typedef char bool;
#define TRUE 1
#define FALSE 0
#define MSEC2SEC 1000000

typedef enum {
    /* Start phase quickly to fill pipe */
    BBR_STARTUP,
    /* After reaching maximum bandwidth, lower pacing rate to drain the queue*/
    BBR_DRAIN,
    /* Steady phase */
    BBR_PROBE_BW,
    /* Slow down to empty the buffer to probe real min rtt */
    BBR_PROBE_RTT,
} xqc_bbr_mode;

typedef enum {
    BBR_NOT_IN_RECOVERY=0,
    BBR_IN_RECOVERY,
} xqc_bbr_recovery_mode;

typedef struct xqc_bbr_s {
    /* Current mode */
    xqc_bbr_mode           mode;
    /* State of the sender */
    xqc_send_ctl_t         *send_ctl;
    /* Minimum rrt in the time window, in usec */
    xqc_usec_t             min_rtt;
    /* Time stamp of min_rtt */
    uint64_t               min_rtt_stamp;
    /* min_rtt does not update in the time window */
    bool                   min_rtt_expired;
    /* Time to exit PROBE_RTT */
    xqc_usec_t             probe_rtt_round_done_stamp;
    /* Maximum bandwidth byte/sec */
    xqc_win_filter_t       bandwidth;
    /* Count round trips during the connection */
    uint32_t               round_cnt;
    /* Start of an measurement? */
    bool                   round_start;
    /* packet delivered value denoting the end of a packet-timed round trip */
    uint32_t               next_round_delivered;
    uint64_t               aggregation_epoch_start_time;
    /* Number of bytes acked during the aggregation time */
    uint32_t               aggregation_epoch_bytes;
    /* The maximum allowed number of bytes in flight */
    uint32_t               congestion_window;
    uint32_t               prior_cwnd;
    /* Initial congestion window of connection */
    uint32_t               initial_congestion_window;
    /* Current pacing rate */
    uint32_t               pacing_rate;
    /* Gain currently applied to pacing rate */
    float                  pacing_gain;
    xqc_usec_t             last_cycle_start;
    /* Gain currently applied to congestion window */
    float                  cwnd_gain;
    /* If packet loss in STARTUP without bandwidth increase, exit STARTUP and
    the connection is in recovery*/
    bool                   exit_startup_on_loss;
    /* Current pacing gain cycle offset */
    uint32_t               cycle_idx;
    /* Time that the last pacing gain cycle was started */
    uint64_t               cycle_start_stamp;
    /* Indicates whether maximum bandwidth is reached in STARTUP */
    bool                   full_bandwidth_reached;
    /* Number of rounds during which there was no significant bandwidth increase */
    uint32_t               full_bandwidth_cnt;
    /* The bandwidth compared to which the increase is measured */
    uint32_t               last_bandwidth;
    /* Indicates whether a round-trip has passed since PROBE_RTT became active */
    bool                   probe_rtt_round_done;
    /* Indicates whether the most recent bandwidth sample was marked as
    app-limited. */
    bool                   last_sample_app_limited;
    /* Indicates whether any non app-limited samples have been recorded*/
    bool                   has_non_app_limited_sample;
    /* If true, use a CWND of 0.75*BDP during probe_rtt instead of 4 packets.*/
    bool                   probe_rtt_based_on_bdp;
    /**
     * If true, skip probe_rtt and update the timestamp of the existing min_rtt to
     * now if min_rtt over the last cycle is within 12.5% of the current min_rtt.
     */
    bool                   probe_rtt_skipped_if_similar_rtt;
    /* Indicates app-limited calls should be ignored as long as there's
    enough data inflight to see more bandwidth when necessary. */
    bool                   flexible_app_limited;
    bool                   probe_rtt_disabled_if_app_limited;
    /* record extra acks in 2 cycles, a cycle contain 10 rtts*/
    uint32_t               extra_ack[2];
    xqc_usec_t             extra_ack_stamp;
    uint32_t               extra_ack_round_rtt;
    uint32_t               extra_ack_idx;
    uint32_t               epoch_ack;
    bool                   extra_ack_in_startup;
    uint8_t                has_srtt;
    uint8_t                idle_restart;
    uint32_t               extra_ack_win_len;
    uint32_t               extra_ack_win_len_in_startup;

    xqc_usec_t             last_round_trip_time;

    /* adjust cwnd in loss recovery*/
    xqc_bbr_recovery_mode  recovery_mode;
    bool                   just_enter_recovery_mode;
    bool                   just_exit_recovery_mode;
    xqc_usec_t             recovery_start_time;
    bool                   packet_conservation;
    uint32_t               expect_bw;
    bool                   enable_expect_bw;
    uint32_t               max_expect_bw;
    bool                   enable_max_expect_bw;

    uint64_t               probe_rtt_min_us;
    uint64_t               probe_rtt_min_us_stamp;

    uint32_t               snd_cwnd_cnt_bytes; /* For AI */
    uint32_t               beyond_target_cwnd; /* To compete with buffer fillers */
    uint32_t               ai_scale_accumulated_bytes;
    uint32_t               ai_scale;

#if XQC_BBR_RTTVAR_COMPENSATION_ENABLED
    /* CWND compensation for RTT variation+ */
    xqc_win_filter_t       max_rtt;
    uint32_t               max_rtt_win_len;
    uint32_t               rtt_compensation_thresh;
    uint8_t                rttvar_compensation_on;
#endif
} xqc_bbr_t;
extern const xqc_cong_ctrl_callback_t xqc_bbr_cb;

#endif