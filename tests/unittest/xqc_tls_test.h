/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_TLS_TEST_INCLUDE_
#define _XQC_TLS_TEST_INCLUDE_

void xqc_test_tls(void);
void xqc_test_tls_default_cert_with_sni(void);
void xqc_test_tls_default_cert_without_sni(void);
void xqc_test_tls_key_update_discards_retired_keys(void);
void xqc_test_tls_key_update_keeps_retired_keys(void);
void xqc_test_tls_key_update_responder_keeps_retired_keys(void);

#endif
