/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_id_hash_test.h"
#include "src/common/xqc_id_hash.h"
#include <CUnit/CUnit.h>


void
xqc_test_id_hash()
{
    xqc_id_hash_table_t hash_tab;
    xqc_id_hash_init(&hash_tab, xqc_default_allocator, 100);

    xqc_id_hash_element_t e1 = {1, "hello"};
    xqc_id_hash_add(&hash_tab, e1);

    xqc_id_hash_element_t e2 = {3, "world"};
    xqc_id_hash_add(&hash_tab, e2);

    xqc_id_hash_element_t e3 = {5, "!"};
    xqc_id_hash_add(&hash_tab, e3);

    char *p1 = xqc_id_hash_find(&hash_tab, 3);
    CU_ASSERT(p1 != NULL);

    void *p2 = xqc_id_hash_find(&hash_tab, 4);
    CU_ASSERT(p2 == NULL);

    int ret = xqc_id_hash_delete(&hash_tab, 3);
    CU_ASSERT(ret == XQC_OK);

    void *p3 = xqc_id_hash_find(&hash_tab, 3);
    CU_ASSERT(p3 == NULL);

    ret = xqc_id_hash_delete(&hash_tab, 4);
    CU_ASSERT(ret != XQC_OK);


    xqc_id_hash_release(&hash_tab);
}
