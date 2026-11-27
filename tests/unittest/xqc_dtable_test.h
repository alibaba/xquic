/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_DTABLE_TEST_H
#define XQC_DTABLE_TEST_H

void xqc_test_dtable_insert_alloc_failure(void);
void xqc_test_dtable();
void xqc_test_dtable_capacity_raise_lookup(void);
void xqc_test_dtable_capacity_raise_evicted(void);
void xqc_test_dtable_evicted_entries(void);

#endif
