/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_WEBTRANSPORT_TEST_H_INCLUDED_
#define _XQC_WEBTRANSPORT_TEST_H_INCLUDED_

void xqc_test_wt_request_lifecycle(void);
void xqc_test_wt_h3_passthrough_callbacks(void);
void xqc_test_wt_bidi_create_notify_after_session_id(void);
void xqc_test_wt_browser_dgram_fallback_on_establish(void);
void xqc_test_wt_max_sessions_setting_survives_default_update(void);
void xqc_test_wt_bidi_create_reject_stops_read(void);
void xqc_test_wt_uni_create_reject_stops_read(void);
void xqc_test_wt_pending_stream_fallback_to_conn_table(void);
void xqc_test_wt_unistream_closing_notify_dispatch(void);
void xqc_test_wt_bidi_close_uses_cached_stream_id(void);
void xqc_test_wt_send_bidi_preserves_stream_blocked(void);
void xqc_test_wt_bidi_bytestream_failure_rolls_back(void);
void xqc_test_wt_strict_requirements_are_role_aware(void);
void xqc_test_wt_server_defers_connect_until_settings(void);
void xqc_test_wt_finish_connect_after_peer_stop_sending(void);

#endif
