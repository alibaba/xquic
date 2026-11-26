/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_QPACK_TEST_H
#define XQC_QPACK_TEST_H

void xqc_qpack_test();
void xqc_test_qpack_create_alloc_failures(void);
void xqc_test_qpack_h3_conn_create_alloc_failures(void);
void xqc_test_qpack_dtable_cap_raises(void);
void xqc_test_qpack_dtable_cap_above_max(void);

#endif
