/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQUIC_XQC_H3_TEST_H
#define XQUIC_XQC_H3_TEST_H

void xqc_test_frame();
void xqc_test_stream();
void xqc_test_ins();
void xqc_test_rep();
void xqc_test_h3_critical_stream_close();
void xqc_test_h3_second_control_stream_rejected();
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

#endif //XQUIC_XQC_H3_TEST_H
