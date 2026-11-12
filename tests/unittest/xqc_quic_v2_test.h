/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_QUIC_V2_TEST_H
#define XQC_QUIC_V2_TEST_H

/* RFC 9369: QUIC version 2 */
void xqc_test_quic_v2_version(void);
void xqc_test_quic_v2_packet_types(void);
void xqc_test_quic_v2_initial_keys(void);
void xqc_test_quic_v2_server_initial(void);
void xqc_test_quic_v2_retry_tag(void);
void xqc_test_quic_v2_chacha20(void);

/* RFC 9368 and RFC 9369 Sections 4 and 5 */
void xqc_test_quic_v2_version_info_codec(void);
void xqc_test_quic_v2_version_info_malformed(void);
void xqc_test_quic_v2_version_info_conn(void);
void xqc_test_quic_v2_token_version(void);

/* RFC 9368 Section 2.3 and RFC 9369 Section 4.1 */
void xqc_test_quic_v2_cvn_select(void);
void xqc_test_quic_v2_cvn_client(void);
void xqc_test_quic_v2_cvn_header(void);
void xqc_test_quic_v2_cvn_initial_keys(void);

#endif /* XQC_QUIC_V2_TEST_H */
