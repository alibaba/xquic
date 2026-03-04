#ifndef XQC_CROSSLAYER_H
#define XQC_CROSSLAYER_H

#include <xquic/xquic_typedef.h>
#include "include/xqc_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Cross-layer control gateway (draft Section 3.3).
 *
 * Sits between the MoQ feedback decision layer and the CC algorithm.
 * Provides a single entry point with rate-limiting, clamping, and
 * validation, then dispatches to the CC via xqc_conn_signal_x_layer_app_event.
 *
 * Architecture:
 *   feedback_decision -> crosslayer_apply() -> conn_signal -> CC
 */

struct xqc_connection_s;

typedef struct {
    xqc_usec_t  min_update_interval_us;
    float       min_pacing_gain;
    float       max_pacing_gain;
    uint64_t    min_pacing_rate;
} xqc_crosslayer_config_t;

typedef struct {
    struct xqc_connection_s *conn;

    xqc_usec_t  last_gain_update;
    xqc_usec_t  last_rate_update;
    xqc_usec_t  min_update_interval_us;

    float       min_pacing_gain;
    float       max_pacing_gain;
    uint64_t    min_pacing_rate;

    uint64_t    dispatch_count;         /* actual CC events dispatched */
    float       last_dispatched_gain;  /* last pacing_gain sent to CC */
    uint64_t    last_dispatched_rate;  /* last pacing_rate sent to CC (bytes/s) */
} xqc_crosslayer_ctl_t;

void xqc_crosslayer_init(xqc_crosslayer_ctl_t *ctl,
    struct xqc_connection_s *conn, const xqc_crosslayer_config_t *config);

/**
 * Apply a cross-layer event: validate, clamp, rate-limit, then dispatch.
 * Returns XQC_OK on success, XQC_ERROR if rate-limited.
 */
xqc_int_t xqc_crosslayer_apply(xqc_crosslayer_ctl_t *ctl,
    const xqc_crosslayer_event_t *event, xqc_usec_t now);

#ifdef __cplusplus
}
#endif

#endif /* XQC_CROSSLAYER_H */
