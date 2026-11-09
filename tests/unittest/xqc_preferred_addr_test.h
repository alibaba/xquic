/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_PREFERRED_ADDR_TEST_H
#define XQC_PREFERRED_ADDR_TEST_H

/* a client's migration to the server's preferred address, RFC 9000 9.6 */
void xqc_test_preferred_addr_store();
void xqc_test_preferred_addr_ipv6();
void xqc_test_preferred_addr_none_usable();
void xqc_test_preferred_addr_cid_in_use();
void xqc_test_preferred_addr_migrate();
void xqc_test_preferred_addr_migrate_new_ip();
void xqc_test_preferred_addr_wrong_response();
void xqc_test_preferred_addr_timeout();
void xqc_test_preferred_addr_wait_for_cid();
void xqc_test_preferred_addr_disabled();
void xqc_test_preferred_addr_challenge_path();
void xqc_test_preferred_addr_response_and_challenge();
void xqc_test_preferred_addr_transport_params();

#endif /* XQC_PREFERRED_ADDR_TEST_H */
