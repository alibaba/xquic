/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_PACKET_TEST_H
#define XQC_PACKET_TEST_H

void xqc_test_short_header_packet_parse_cid();
void xqc_test_long_header_packet_parse_cid();
void xqc_test_packet_encrypt_hp_sample_boundary();
void xqc_test_empty_pkt();
void xqc_test_coalesced_continue_after_tolerant_error();
void xqc_test_coalesced_zero_progress_terminates();


#endif
