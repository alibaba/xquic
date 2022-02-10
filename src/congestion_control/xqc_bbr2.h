/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_BBR2_H_INCLUDED_
#define _XQC_BBR2_H_INCLUDED_

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
    BBR2_STARTUP,
    /* After reaching maximum bandwidth, lower pacing rate to drain the queue*/
    BBR2_DRAIN,
    /* Steady phase */
    BBR2_PROBE_BW,
    /* Slow down to empty the buffer to probe real min rtt */
    BBR2_PROBE_RTT,
} xqc_bbr2_mode;

/*
                          packet loss
   BBR2_OPEN      --------------------------->  BBR2_RECOVERY

                        a new pkt acked
   BBR2_RECOVERY  --------------------------->  BBR2_OPEN

   BBR2_OPEN         persistent congestion
   BBR2_RECOVERY  --------------------------->  BBR2_LOSS

                        a new pkt acked
   BBR2_LOSS      --------------------------->  BBR2_OPEN
*/
typedef enum {
    BBR2_OPEN = 0,
    BBR2_RECOVERY,
    BBR2_LOSS,
} xqc_bbr2_recovery_mode;

/* How does the incoming ACK stream relate to our bandwidth probing? */
typedef enum {
    BBR2_ACKS_INIT,               /* not probing; not getting probe feedback */
    BBR2_ACKS_REFILLING,       /* sending at est. bw to fill pipe */
    BBR2_ACKS_PROBE_STARTING,  /* inflight rising to probe bw */
    BBR2_ACKS_PROBE_FEEDBACK,  /* getting feedback from bw probing */
    BBR2_ACKS_PROBE_STOPPING,  /* stopped probing; still getting feedback */
} xqc_bbr2_ack_phase;

typedef struct xqc_bbr2_s {
    /* Current mode */
    xqc_bbr2_mode       mode;
    /* State of the sender */
    xqc_send_ctl_t      *send_ctl;
    /* Minimum rrt in the time window, in usec */
    xqc_usec_t          min_rtt;
    /* Time stamp of min_rtt */
    uint64_t            min_rtt_stamp;
    /* min_rtt does not update in the time window */
    bool                min_rtt_expired;
    /* Time to exit PROBE_RTT */
    xqc_usec_t          probe_rtt_round_done_stamp;
    /* Count round trips during the connection */
    uint32_t            round_cnt;
    /* Start of an measurement? */
    bool                round_start;
    /* packet delivered value denoting the end of a packet-timed round trip */
    uint32_t            next_round_delivered;
    uint64_t            aggregation_epoch_start_time;
    /* Number of bytes acked during the aggregation time */
    uint32_t            aggregation_epoch_bytes;
    /* The maximum allowed number of bytes in flight */
    uint32_t            congestion_window;
    uint32_t            prior_cwnd;
    /* Initial congestion window of connection */
    uint32_t            initial_congestion_window;
    /* Current pacing rate */
    uint32_t            pacing_rate;
    /* Gain currently applied to pacing rate */
    float               pacing_gain;
    xqc_usec_t          last_cycle_start;
    /* Gain currently applied to congestion window */
    float               cwnd_gain;
    /* If packet loss in STARTUP without bandwidth increase, exit STARTUP and
       the connection is in recovery */
    bool                exit_startup_on_loss;
    /* Current pacing gain cycle offset */
    uint32_t            cycle_idx;
    /* Time that the last pacing gain cycle was started */
    uint64_t            cycle_start_stamp;
    /* Indicates whether maximum bandwidth is reached in STARTUP */
    bool                full_bandwidth_reached;
    /* Number of rounds during which there was no significant bandwidth increase */
    uint32_t            full_bandwidth_cnt;
    /* The bandwidth compared to which the increase is measured */
    uint32_t            last_bandwidth;
    /* Indicates whether a round-trip has passed since PROBE_RTT became active */
    bool                probe_rtt_round_done;
    /* Indicates whether the most recent bandwidth sample was marked as
       app-limited. */
    bool                last_sample_app_limited;
    /* Indicates whether any non app-limited samples have been recorded*/
    bool                has_non_app_limited_sample;
    /* If TRUE, use a CWND of 0.75*BDP during probe_rtt instead of 4 packets. */
    bool                probe_rtt_based_on_bdp;
    /**
     * If TRUE, skip probe_rtt and update the timestamp of the existing min_rtt 
     * to now if min_rtt over the last cycle is within 12.5% of the current 
     * min_rtt.
     */
    bool                probe_rtt_skipped_if_similar_rtt;
    /* Indicates app-limited calls should be ignored as long as there's
       enough data inflight to see more bandwidth when necessary. */
    bool                flexible_app_limited;
    bool                probe_rtt_disabled_if_app_limited;
    /* record extra acks in 2 cycles, a cycle contain 10 rtts */
    uint32_t            extra_ack[2];
    xqc_usec_t          extra_ack_stamp;
    uint32_t            extra_ack_round_rtt;
    uint32_t            extra_ack_idx;
    uint32_t            epoch_ack;
    bool                extra_ack_in_startup;
    uint8_t             has_srtt;
    uint8_t             idle_restart;
    uint32_t            extra_ack_win_len;
    uint32_t            extra_ack_win_len_in_startup;

    xqc_usec_t          last_round_trip_time;

    /* BBRv2 State */
    /* packet loss in this cycle? */
    bool                loss_in_cycle;
    /* scb->tx.delivered ending loss round */
    uint32_t            loss_round_delivered;
    /* bw_lo before latest losses */
    uint32_t            undo_bw_lo;
    /* inflight_lo before latest losses */
    uint32_t            undo_inflight_lo;
    /* inflight_hi before latest losses */
    uint32_t            undo_inflight_hi;
    uint32_t            bw_latest;     /* max delivered bw in last round trip */
    uint32_t            bw_lo;         /* lower bound on sending bandwidth */
    uint32_t            bw_hi[2];      /* upper bound of sending bandwidth range */
    /* max delivered data in last round trip */
    uint32_t            inflight_latest;
    /* lower bound of inflight data range */
    uint32_t            inflight_lo;
    /* upper bound of inflight data range */
    uint32_t            inflight_hi;
    /* packets delivered per inflight_hi incr */
    uint32_t            bw_probe_up_cnt;
    /* packets (S)ACKed since inflight_hi incr */
    uint32_t            bw_probe_up_acks;
    /* cwnd-limited rounds in PROBE_UP */
    uint8_t             bw_probe_up_rounds;
    /* PROBE_DOWN until next clock-driven probe */
    uint32_t            probe_wait_us;
    /* rate samples reflect bw probing? */
    bool                bw_probe_samples;
    /* did last PROBE_UP go too high? */
    bool                prev_probe_too_high;
    /* last PROBE_UP stopped due to risk? */
    bool                stopped_risky_probe;
    /* packet-timed rounds since probed bw */
    uint8_t             rounds_since_probe;
    /* loss_round_delivered round trip? */
    bool                loss_round_start;
    /* loss marked in this round trip? */
    bool                loss_in_round;
    /* bbr_ack_phase: meaning of ACKs */
    xqc_bbr2_ack_phase  ack_phase;
    /* losses in STARTUP round */
    uint8_t             loss_events_in_round;
    uint64_t            probe_rtt_min_us;
    uint64_t            probe_rtt_min_us_stamp;

    /* adjust cwnd in loss recovery */
    xqc_usec_t              recovery_start_time;
    bool                    packet_conservation;
    xqc_usec_t              loss_start_time;
    xqc_bbr2_recovery_mode  recovery_mode;

#if XQC_BBR2_PLUS_ENABLED
    /* For BBRv2+ */
    xqc_win_filter_t        max_rtt;
    uint32_t                max_rtt_win_len;
    uint32_t                rtt_compensation_thresh;
    uint8_t                 rtt_compensation_on;
    uint8_t                 fast_convergence_on;
    xqc_usec_t              srtt_in_last_round;
    xqc_usec_t              srtt_in_current_round;
    uint32_t                bw_before_probe;
#endif
} xqc_bbr2_t;

typedef enum {
    BBR2_BW_PROBE_UP        = 0,  /* push up inflight to probe for bw/vol */
    BBR2_BW_PROBE_DOWN      = 1,  /* drain excess inflight from the queue */
    BBR2_BW_PROBE_CRUISE    = 2,  /* use pipe, w/ headroom in queue/pipe */
    BBR2_BW_PROBE_REFILL    = 3,  /* v2: refill the pipe again to 100% */
#if XQC_BBR2_PLUS_ENABLED
    BBR2_BW_PROBE_PRE_UP    = 4,  /* try if we can really enter probe up */
#endif
} xqc_bbr2_pacing_gain_phase;

typedef struct xqc_bbr2_context_s {
    uint32_t sample_bw;
    uint32_t target_cwnd;
} xqc_bbr2_context_t;

extern const xqc_cong_ctrl_callback_t xqc_bbr2_cb;

#endif