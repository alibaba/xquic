/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_PACKET_TEST_H
#define XQC_PACKET_TEST_H

void xqc_test_short_header_packet_parse_cid();
void xqc_test_long_header_packet_parse_cid();
void xqc_test_client_discards_received_zero_rtt(void);
void xqc_test_server_buffers_received_zero_rtt(void);
void xqc_test_client_initial_zero_token(void);
void xqc_test_client_initial_nonzero_token(void);
void xqc_test_server_initial_token(void);
void xqc_test_initial_token_bounds(void);
void xqc_test_initial_token_discard_recovery(void);
void xqc_test_client_initial_sends_token(void);
void xqc_test_server_initial_omits_token(void);
void xqc_test_packet_out_remained_size(void);
void xqc_test_packet_encrypt_hp_sample_boundary();
void xqc_test_empty_pkt();
void xqc_test_stateless_reset_parse_boundary(void);
void xqc_test_coalesced_matching_dcid_processed(void);
void xqc_test_coalesced_mismatching_dcid_ignored(void);
void xqc_test_coalesced_initial_datagram_minimum(void);
void xqc_test_coalesced_initial_datagram_too_small(void);


#endif
