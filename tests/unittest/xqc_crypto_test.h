/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_CRYPTO_TEST_INCLUDE_
#define _XQC_CRYPTO_TEST_INCLUDE_

void xqc_test_crypto();
void xqc_test_hp_sample_boundary();

/* RFC 9001 Appendix A test vector verification */
void xqc_test_rfc9001_initial_secret();
void xqc_test_rfc9001_derive_initial_secrets();
void xqc_test_rfc9001_client_initial_keys();
void xqc_test_rfc9001_server_initial_keys();

#endif
