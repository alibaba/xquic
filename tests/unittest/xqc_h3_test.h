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

#endif //XQUIC_XQC_H3_TEST_H
