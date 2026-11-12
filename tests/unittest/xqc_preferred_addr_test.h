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

/* a server's move to its preferred address, RFC 9000 9.6.2 */
void xqc_test_server_preferred_addr_offer();
void xqc_test_server_preferred_addr_not_offered();
void xqc_test_server_preferred_addr_migrate();
void xqc_test_server_preferred_addr_order();
void xqc_test_server_preferred_addr_no_cid();
void xqc_test_server_preferred_addr_give_up();
void xqc_test_server_preferred_addr_new_client_addr();
void xqc_test_server_preferred_addr_spoofed();
void xqc_test_server_preferred_addr_padding();
void xqc_test_server_preferred_addr_multipath();

#endif /* XQC_PREFERRED_ADDR_TEST_H */
