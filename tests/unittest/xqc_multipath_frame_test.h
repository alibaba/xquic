#ifndef XQC_MULTIPATH_FRAME_TEST_H_INCLUDED_
#define XQC_MULTIPATH_FRAME_TEST_H_INCLUDED_

void xqc_test_mp3e_path_abandon_frame(void);
void xqc_test_mp3e_path_status_parse(void);
void xqc_test_mp3e_path_ack_ecn_counts(void);
void xqc_test_mp3e_blocked_frames_roundtrip(void);
void xqc_test_mp3e_paths_blocked_limit(void);
void xqc_test_mp3e_path_cids_blocked_limit(void);
void xqc_test_mp3e_max_path_id_validation(void);
void xqc_test_mp3e_frames_require_negotiation(void);
void xqc_test_mp3e_frames_require_1rtt(void);
void xqc_test_mp10_max_path_id_lower_bound(void);
void xqc_test_mp3e_blocked_frames_bounds(void);
void xqc_test_mp3e_report_path_blocked(void);

#endif /* XQC_MULTIPATH_FRAME_TEST_H_INCLUDED_ */
