#ifndef _XQC_MOQ_FEEDBACK_DECISION_H_INCLUDED_
#define _XQC_MOQ_FEEDBACK_DECISION_H_INCLUDED_

/*
 * draft-moq-delivery-feedback-00 Section 3.3 cross-layer control decision.
 *
 * Public types (xqc_moq_fb_decision_t, xqc_moq_fb_input_t,
 * xqc_moq_fb_decision_config_t) are defined in include/moq/xqc_moq.h.
 *
 * This internal header declares the default policy evaluate function.
 */

#include "moq/xqc_moq.h"

/**
 * Pure policy: evaluate feedback metrics against thresholds.
 * Rate-limiting is handled by the crosslayer gateway.
 * @param had_reduction  nonzero if a prior reduction (gain<1.0 or bitrate cut)
 *                       was dispatched; gates the recovery probe-up rule.
 */
void xqc_moq_fb_decision_evaluate(const xqc_moq_fb_decision_config_t *config,
    const xqc_moq_fb_input_t *input, xqc_usec_t now,
    xqc_int_t had_reduction,
    xqc_moq_fb_decision_t *decision);

#endif /* _XQC_MOQ_FEEDBACK_DECISION_H_INCLUDED_ */
