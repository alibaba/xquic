/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQUIC_XQC_H3_TEST_H
#define XQUIC_XQC_H3_TEST_H

void xqc_test_frame();
void xqc_test_h3_single_vint_frame_valid();
void xqc_test_h3_single_vint_frame_length_error();
void xqc_test_stream();
void xqc_test_ins();
void xqc_test_rep();
void xqc_test_h3_critical_stream_close();
void xqc_test_h3_second_control_stream_rejected();
void xqc_test_h3_reserved_uni_stream_accepted();
void xqc_test_h3_push_stream_error_codes();
void xqc_test_h3_max_push_id_valid();
void xqc_test_h3_max_push_id_errors();
void xqc_test_h3_goaway_id_valid();
void xqc_test_h3_goaway_id_increase_rejected();
void xqc_test_h3_settings_accepted();
void xqc_test_h3_reserved_h2_settings_rejected();
void xqc_test_h3_reserved_control_frame_accepted();
void xqc_test_h3_h2_reserved_frames_rejected();
void xqc_test_h3_cancel_push_rejected();
void xqc_test_h3_uncompressed_fields_size();
void xqc_test_h3_recv_header_field_section_size();

/* issue #744: RFC 9114 §4.1.2 / §8.1 H3_MESSAGE_ERROR + INTERNAL split */
void xqc_test_h3_message_error_code_value();
void xqc_test_h3_malformed_headers_uses_message_error();
void xqc_test_h3_headers_capacity_uses_internal_error();
void xqc_test_h3_valid_headers_smoke();
void xqc_test_h3_frame_parse_error_uses_frame_error();
void xqc_test_h3_control_frame_unexpected();
void xqc_test_h3_missing_settings();

/* issue #609: RFC 9114 §7.2 control-only frames on request stream */
void xqc_test_h3_request_frame_unexpected();

/* issue #849: RFC 9114 §7.2.5 PUSH_PROMISE sender role */
void xqc_test_h3_server_reserved_request_frame_accepted();
void xqc_test_h3_server_push_promise_rejected();

/* issue #746: RFC 9114 §4.2 forbidden connection-specific headers */
void xqc_test_h3_message_error_enum();
void xqc_test_h3_forbidden_headers_rejected();
void xqc_test_h3_allowed_headers_pass();

/* vul 42057008: blocked stream limit must use local settings (RFC 9204 §2.1.2) */
void xqc_test_h3_blocked_stream_limit_uses_local();
/* ALIBABA-2026-42073004: SETTINGS frame size limit */
void xqc_test_h3_settings_frame_size_limit();

/* issue #748: RFC 9114 §4.2 uppercase field name rejection */
void xqc_test_h3_field_name_uppercase_rejection();
void xqc_test_h3_lowercase_field_name_stream_accepted();
void xqc_test_h3_uppercase_field_name_stream_rejected();

#endif //XQUIC_XQC_H3_TEST_H
