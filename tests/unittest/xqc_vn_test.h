/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_VN_TEST_H
#define XQC_VN_TEST_H

/*
 * Validation suite for the RFC 9000 Section 6.2 Version Negotiation
 * abort behaviour. Each test exercises one branch of
 * xqc_packet_parse_version_negotiation in isolation.
 */

/* Happy-path abort: valid VN, peer offers a foreign version. */
void xqc_test_vn_abort_on_unsupported_version(void);

/* Downgrade defence: VN echoes the client's current version. */
void xqc_test_vn_downgrade_protection_when_version_matches(void);

/* CID reverse validation: VN.DCID != client.SCID is rejected. */
void xqc_test_vn_reject_when_dcid_mismatch(void);

/* CID reverse validation: VN.SCID != client.DCID is rejected. */
void xqc_test_vn_reject_when_scid_mismatch(void);

/* State gate: a late VN after the initial flight is dropped. */
void xqc_test_vn_reject_when_state_not_initial_sent(void);

/* Abort even when the VN list contains multiple foreign versions. */
void xqc_test_vn_abort_on_multi_unsupported_versions(void);

#endif /* XQC_VN_TEST_H */
