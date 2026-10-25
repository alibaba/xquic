/*
 * Per-path app-limited marking at the end of each engine pass.
 */
#ifndef XQC_APPLIMIT_TEST_H_INCLUDED
#define XQC_APPLIMIT_TEST_H_INCLUDED

void xqc_test_applimit_unfed_path_conn_logic(void);
void xqc_test_applimit_unfed_path_main_logic(void);
void xqc_test_applimit_idle_path_conn_logic(void);
void xqc_test_applimit_idle_path_main_logic(void);
void xqc_test_applimit_idle_path_batch_send(void);
void xqc_test_applimit_next_packet_flagged(void);
void xqc_test_applimit_pacing_held_packet(void);
void xqc_test_applimit_cwnd_full(void);
void xqc_test_applimit_sndbuf_full(void);
void xqc_test_applimit_lingering_ack_only(void);
void xqc_test_applimit_marker_value(void);
void xqc_test_applimit_pacer_untouched(void);
void xqc_test_applimit_requeued_on_send_error(void);
void xqc_test_applimit_lost_packet_held(void);
void xqc_test_applimit_pto_probe_held(void);
void xqc_test_applimit_marker_kept_when_blocked(void);
void xqc_test_applimit_ack_clears_then_remarks(void);

#endif /* XQC_APPLIMIT_TEST_H_INCLUDED */
