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

/* 0-RTT transport parameter validation (issue #717, RFC 9000 Section 7.4.1) */
void xqc_test_0rtt_params_all_equal(void);
void xqc_test_0rtt_params_all_increased(void);
void xqc_test_0rtt_params_initial_max_data_reduced(void);

#endif
