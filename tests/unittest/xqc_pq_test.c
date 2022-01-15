/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>

#include "xqc_pq_test.h"

void
xqc_test_pq()
{
    xqc_pq_t pq;
    memset(&pq, 0, sizeof(pq));
    int i = xqc_pq_init(&pq, sizeof(xqc_pq_key_t), 4, xqc_default_allocator, xqc_pq_default_cmp);
    CU_ASSERT(i == 0);

    xqc_pq_push(&pq, 4);
    xqc_pq_push(&pq, 5);
    xqc_pq_push(&pq, 1);
    xqc_pq_push(&pq, 3);
    xqc_pq_push(&pq, 2);

    xqc_pq_key_t key = (xqc_pq_key_t) -1;
    
    while (!xqc_pq_empty(&pq)) {
        xqc_pq_element_t *e = xqc_pq_top(&pq);
        CU_ASSERT(e->key <= key);
        key = e->key;
        xqc_pq_pop(&pq);
    }

    xqc_pq_destroy(&pq);
}

