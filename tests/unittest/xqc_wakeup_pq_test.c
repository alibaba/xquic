/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xqc_wakeup_pq_test.h"
#include "src/transport/xqc_wakeup_pq.h"


void
xqc_test_wakeup_pq()
{
    int ret;
    xqc_wakeup_pq_t pq;
    memset(&pq, 0, sizeof(pq));
    ret = xqc_wakeup_pq_init(&pq, 4, xqc_default_allocator, xqc_wakeup_pq_revert_cmp);
    CU_ASSERT(ret == 0);

    xqc_wakeup_pq_elem_t *elem;
    xqc_connection_t *conn = (xqc_connection_t *)malloc(5 * sizeof(xqc_connection_t));

    elem = xqc_wakeup_pq_push(&pq, 3, &conn[0]);
    CU_ASSERT(elem != NULL);

    elem = xqc_wakeup_pq_push(&pq, 1, &conn[1]);
    CU_ASSERT(elem != NULL);

    elem = xqc_wakeup_pq_push(&pq, 4, &conn[2]);
    CU_ASSERT(elem != NULL);

    elem = xqc_wakeup_pq_push(&pq, 2, &conn[3]);
    CU_ASSERT(elem != NULL);

    elem = xqc_wakeup_pq_push(&pq, 5, &conn[4]);
    CU_ASSERT(elem != NULL);


    xqc_wakeup_pq_remove(&pq, &conn[0]);

    while (!xqc_wakeup_pq_empty(&pq)) {
        elem = xqc_wakeup_pq_top(&pq);
        //printf("key:%llu\n", elem->wakeup_time);
        xqc_wakeup_pq_pop(&pq);
    }

    free(conn);

    xqc_wakeup_pq_destroy(&pq);
}