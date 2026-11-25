/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_RETRY_TEST_H
#define XQC_RETRY_TEST_H

void xqc_test_retry();
void xqc_test_retry_same_length_dcid();
void xqc_test_retry_invalid_token_close();
void xqc_test_retry_invalid_token_ignore_original_dcid();
void xqc_test_token_lifetime();
void xqc_test_token_address_mismatch();

/* RFC 10069 Section 3.1.3: tokens for every validated client address */
void xqc_test_token_all_validated_addresses();

/* no token without a new client address, which tokens keep to */
void xqc_test_token_no_new_address();

#endif
