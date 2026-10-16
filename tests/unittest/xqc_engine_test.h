/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_ENGINE_TEST_H
#define XQC_ENGINE_TEST_H

void xqc_test_engine_create();
void xqc_test_engine_packet_process();
void xqc_test_engine_drop_small_initial();
void xqc_test_engine_drop_small_unknown_0rtt();
void xqc_test_engine_min_initial_not_pre_dropped();
void xqc_test_engine_min_unknown_0rtt_not_pre_dropped();
void xqc_test_rebinding_candidate_budget_limit();
void xqc_test_rebinding_no_padding_flag();
void xqc_test_rebinding_min_padding_flag();
void xqc_test_rebinding_response_state_transition();
void xqc_test_rebinding_clear();
void xqc_test_rebinding_ignores_unauthenticated_packet();
void xqc_test_rebinding_path_challenge_requires_confirmed();
void xqc_test_rebinding_timeout_retry_limit();
void xqc_test_rebinding_response_mismatch_preserves_state();
void xqc_test_rebinding_sender_error_clears_candidate();

#endif
