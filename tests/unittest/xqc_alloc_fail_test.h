#ifndef XQC_ALLOC_FAIL_TEST_H
#define XQC_ALLOC_FAIL_TEST_H

void xqc_test_conn_create_alloc_failures(void);
void xqc_test_engine_create_alloc_failures(void);
void xqc_test_conn_create_recv_ts_alloc_failures(void);
void xqc_test_conn_destroy_frees_crypto_data(void);
void xqc_test_client_connect_active_queue_full(void);

#endif
