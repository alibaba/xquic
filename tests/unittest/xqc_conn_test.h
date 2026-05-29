/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_CONN_TEST_H
#define XQC_CONN_TEST_H

void xqc_test_conn_create();
void xqc_test_conn_idle_timeout();
void xqc_test_conn_early_data_reject();
void xqc_test_conn_early_data_reject_flow_ctl();

/* RFC 9000 §20.1 CRYPTO_ERROR dynamic construction */
void xqc_test_conn_tls_error_cb_constructs_crypto_error();
void xqc_test_conn_crypto_error_base_value();
void xqc_test_conn_tls_error_first_writer_wins();
void xqc_test_conn_tls_error_cb_alert_zero();
void xqc_test_conn_tls_error_cb_max_alert();

#endif
