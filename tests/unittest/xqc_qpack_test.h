/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_QPACK_TEST_H
#define XQC_QPACK_TEST_H

void xqc_qpack_test();
void xqc_test_qpack_create_alloc_failures(void);
void xqc_test_qpack_h3_conn_create_alloc_failures(void);
void xqc_test_qpack_decoder_ins_log(void);
void xqc_test_qpack_encoder_ins_log(void);
void xqc_test_qpack_state_updated_log(void);
void xqc_test_qpack_dtable_duplicate_log(void);

#endif
