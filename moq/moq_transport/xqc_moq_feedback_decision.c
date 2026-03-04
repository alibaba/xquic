#include "moq/moq_transport/xqc_moq_feedback_decision.h"

#include "src/common/xqc_str.h"

void
xqc_moq_fb_decision_config_default(xqc_moq_fb_decision_config_t *config)
{
    xqc_memzero(config, sizeof(*config));

    config->playout_critical_ms   = 50;
    config->playout_warning_ms    = 100;
    config->playout_critical_gain = 0.8f;
    config->playout_warning_gain  = 0.9f;

    config->loss_heavy_threshold  = 0.05;
    config->late_heavy_threshold  = 0.08;
    config->heavy_gain            = 0.8f;

    config->loss_mild_threshold   = 0.02;
    config->late_mild_threshold   = 0.02;
    config->mild_gain             = 0.9f;

    config->loss_severe_threshold = 0.30;
    config->bitrate_floor_kbps    = 500;

    config->override_duration_us  = 200000;

    config->recovery_gain         = 1.05f;
}

void
xqc_moq_fb_decision_evaluate(const xqc_moq_fb_decision_config_t *config,
    const xqc_moq_fb_input_t *input, xqc_usec_t now,
    xqc_moq_fb_decision_t *decision)
{
    decision->action = XQC_MOQ_FB_ACTION_NONE;
    (void)now;

    if (config == NULL || input == NULL) {
        return;
    }

    /*
     * Priority order (descending severity):
     *   1. Severe loss -> target_bitrate reduction
     *   2. Playout critically low -> pacing_gain reduction
     *   3. High loss/late -> heavy pacing_gain reduction
     *   4. Moderate loss/late -> mild pacing_gain reduction
     *   5. All reduction rules passed + BWE available -> pacing_rate hint
     *   6. All reduction rules passed, no BWE -> probe-up (recovery)
     */

    /* 1. Severe loss: halve target bitrate. */
    if (input->loss_rate > config->loss_severe_threshold) {
        if (input->estimated_bw_kbps > 0) {
            uint64_t new_bw = input->estimated_bw_kbps / 2;
            if (new_bw < config->bitrate_floor_kbps) {
                new_bw = config->bitrate_floor_kbps;
            }
            decision->action = XQC_MOQ_FB_ACTION_TARGET_BITRATE;
            decision->u.target_bitrate.bitrate = new_bw * 1000;
        } else {
            decision->action = XQC_MOQ_FB_ACTION_PACING_GAIN;
            decision->u.pacing_gain.gain = config->heavy_gain;
        }
        return;
    }

    /* 2. Playout critically low. */
    if (input->playout_ahead_ms > 0 && input->playout_ahead_ms < config->playout_critical_ms) {
        decision->action = XQC_MOQ_FB_ACTION_PACING_GAIN;
        decision->u.pacing_gain.gain = config->playout_critical_gain;
        return;
    }

    /* 3. Playout warning zone. */
    if (input->playout_ahead_ms > 0 && input->playout_ahead_ms < config->playout_warning_ms) {
        decision->action = XQC_MOQ_FB_ACTION_PACING_GAIN;
        decision->u.pacing_gain.gain = config->playout_warning_gain;
        return;
    }

    /* 4. Heavy loss or late. */
    if (input->loss_rate > config->loss_heavy_threshold
        || input->late_rate > config->late_heavy_threshold)
    {
        decision->action = XQC_MOQ_FB_ACTION_PACING_GAIN;
        decision->u.pacing_gain.gain = config->heavy_gain;
        return;
    }

    /* 5. Mild loss or late. */
    if (input->loss_rate > config->loss_mild_threshold
        || input->late_rate > config->late_mild_threshold)
    {
        decision->action = XQC_MOQ_FB_ACTION_PACING_GAIN;
        decision->u.pacing_gain.gain = config->mild_gain;
        return;
    }

    /* 6. Receiver has BW estimate, loss/late below all reduction thresholds -> pacing_rate. */
    if (input->estimated_bw_kbps > 0) {
        decision->action = XQC_MOQ_FB_ACTION_PACING_RATE;
        decision->u.pacing_rate.rate = (input->estimated_bw_kbps * 1000) / 8;
        return;
    }

    /* 7. All reduction rules passed, no BW estimate -> mild probe-up (GCC increase 1.05). */
    if (config->recovery_gain > 1.0f) {
        decision->action = XQC_MOQ_FB_ACTION_PACING_GAIN;
        decision->u.pacing_gain.gain = config->recovery_gain;
        return;
    }
}
