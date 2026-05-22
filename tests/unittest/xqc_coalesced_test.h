/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 *
 * Tests for RFC 9000 Section 12.2: every coalesced QUIC packet that follows
 * the first one in a UDP datagram MUST share the same Destination Connection
 * ID. Receivers SHOULD discard offenders but continue processing the rest.
 */

#ifndef _XQC_COALESCED_TEST_H_INCLUDED_
#define _XQC_COALESCED_TEST_H_INCLUDED_

void xqc_test_coalesced_single_pkt(void);
void xqc_test_coalesced_dcid_match(void);
void xqc_test_coalesced_dcid_mismatch(void);
void xqc_test_coalesced_dcid_len_mismatch(void);
void xqc_test_coalesced_dcid_a_b_a(void);

#endif /* _XQC_COALESCED_TEST_H_INCLUDED_ */
