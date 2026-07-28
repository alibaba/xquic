/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */

#ifndef _XQC_MOQ_WEBTRANSPORT_TEST_H_INCLUDED_
#define _XQC_MOQ_WEBTRANSPORT_TEST_H_INCLUDED_

void xqc_test_moq_stream_retries_after_short_write(void);
void xqc_test_moq_session_destroy_clears_user_session(void);
void xqc_test_moq_wt_rejects_duplicate_control_stream(void);
void xqc_test_moq_legacy_wt_init_requires_session_callbacks(void);
void xqc_test_moq_wt_init_requires_session_create_notify(void);
void xqc_test_moq_wt_uni_retries_after_stream_credit(void);
void xqc_test_moq_wt_uni_reset_waits_for_final_close(void);

#endif
