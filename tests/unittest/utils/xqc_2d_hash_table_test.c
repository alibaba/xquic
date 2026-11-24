/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xqc_2d_hash_table_test.h"
#include "src/common/utils/2d_hash/xqc_2d_hash_table.h"
#include <inttypes.h>


typedef struct xqc_2d_ht_node_s {
    uint64_t        idx;
    char           *name;
    size_t          nlen;
    char           *value;
    size_t          vlen;
} xqc_2d_ht_node_t;



/* compare two entries */
int
xqc_2d_ht_compare_data(void *data1, void *data2, void *ud)
{
    xqc_2d_ht_node_t *e1 = (xqc_2d_ht_node_t *)data1;
    xqc_2d_ht_node_t *e2 = (xqc_2d_ht_node_t *)data2;

    /* compare absolute index, larger absolute index means larger */
    if (e1->idx == e2->idx) {
        return 0;
    }

    return e1->idx > e2->idx ? 1 : -1;
}


/* compare name/value with entry */
xqc_2d_cmp_res_t
xqc_2d_ht_compare_value(void *data, void *v1, size_t len1, void *v2, size_t len2,
    xqc_2d_cmp_dim_t dims, void *ud)
{
    uint8_t *name = (uint8_t *)v1;
    uint8_t *value = (uint8_t *)v2;
    xqc_2d_ht_node_t *node = (xqc_2d_ht_node_t *)data;

    int res = 0;
    xqc_2d_cmp_res_t cmp_res = XQC_2D_CMP_RES_NONE;

    /* compare name first */
    if (node->nlen == len1) {
        res = strcmp(node->name, name);
        if (res == 0) {
            cmp_res = XQC_2D_CMP_RES_1D;

            /* check value if required and name is matched */
            if (dims == XQC_2D_CMP_DIM_2) {
                if (node->vlen == len2) {
                    /* name matched, compare value */
                    res = strcmp(node->value, value);
                    if (res == 0) {
                        cmp_res = XQC_2D_CMP_RES_2D;
                    }
                }
            }
        }
    }

    return cmp_res;
}


void
test_2d_hash_table_basic()
{
    xqc_int_t ret = XQC_OK;
    xqc_2d_cmp_res_t cres = XQC_2D_CMP_RES_NONE;
    xqc_2d_ht_node_t *data = NULL;

    xqc_2d_hash_table_t *ht2d = xqc_2d_hash_table_create(16, xqc_2d_ht_compare_data,
        xqc_2d_ht_compare_value, NULL);

    /* add data with hash [0, 0] */
    xqc_2d_ht_node_t n0 = {0, "node0", 5, "value0", 6};
    ret = xqc_2d_hash_table_add(ht2d, 0, 0, &n0);
    CU_ASSERT(ret == XQC_OK);

    /* lookup data with hash [0, 0] */
    cres = xqc_2d_hash_lookup(ht2d, 0, "node0", 5, 0, "value0", 6, (void**)&data);
    CU_ASSERT(cres == XQC_2D_CMP_RES_2D && data->idx == 0);


    /* add repeatly hash [0, 0] */
    ret = xqc_2d_hash_table_add(ht2d, 0, 0, &n0);
    CU_ASSERT(ret == XQC_OK);
    cres = xqc_2d_hash_lookup(ht2d, 0, "node0", 5, 0, "value0", 6, (void**)&data);
    CU_ASSERT(cres == XQC_2D_CMP_RES_2D && data->idx == 0);


    cres = XQC_2D_CMP_RES_NONE;
    data = NULL;
    /* add another node */
    xqc_2d_ht_node_t n1 = {1, "node1", 5, "value1", 6};
    ret = xqc_2d_hash_table_add(ht2d, 1, 11, &n1);
    CU_ASSERT(ret == XQC_OK);
    cres = xqc_2d_hash_lookup(ht2d, 1, "node1", 5, 11, "value1", 6, (void**)&data);
    CU_ASSERT(cres == XQC_2D_CMP_RES_2D && data->idx == 1);


    /* 1d match */
    cres = xqc_2d_hash_lookup(ht2d, 0, "node0", 5, 100, "value000", 8, (void**)&data);
    CU_ASSERT(cres == XQC_2D_CMP_RES_1D && data->idx == 0);


    /* none match */
    cres = xqc_2d_hash_lookup(ht2d, 10, "node0", 5, 100, "value000", 8, (void**)&data);
    CU_ASSERT(cres == XQC_2D_CMP_RES_NONE);


    /* none match with same hash */
    cres = xqc_2d_hash_lookup(ht2d, 0, "node_0", 5, 10, "value_0", 8, (void**)&data);
    CU_ASSERT(cres == XQC_2D_CMP_RES_NONE);


    /* add node with same name and value, the newest shall always be returned */
    cres = XQC_2D_CMP_RES_NONE;
    data = NULL;
    xqc_2d_ht_node_t n2 = {2, "node2", 5, "value2", 6};
    ret = xqc_2d_hash_table_add(ht2d, 2, 21, &n2);
    CU_ASSERT(ret == XQC_OK);
    cres = xqc_2d_hash_lookup(ht2d, 2, "node2", 5, 21, "value2", 6, (void**)&data);
    CU_ASSERT(cres == XQC_2D_CMP_RES_2D && data->idx == 2);

    xqc_2d_ht_node_t n3 = {3, "node2", 5, "value2", 6};
    ret = xqc_2d_hash_table_add(ht2d, 2, 21, &n3);
    CU_ASSERT(ret == XQC_OK);
    cres = xqc_2d_hash_lookup(ht2d, 2, "node2", 5, 21, "value2", 6, (void**)&data);
    CU_ASSERT(cres == XQC_2D_CMP_RES_2D && data->idx == 3);

    xqc_2d_ht_node_t n4 = {4, "node2", 5, "value2", 6};
    ret = xqc_2d_hash_table_add(ht2d, 2, 21, &n4);
    CU_ASSERT(ret == XQC_OK);
    cres = xqc_2d_hash_lookup(ht2d, 2, "node2", 5, 21, "value2", 6, (void**)&data);
    CU_ASSERT(cres == XQC_2D_CMP_RES_2D && data->idx == 4);


    /* remove newest */
    ret = xqc_2d_hash_table_remove(ht2d, 2, 21, &n4);
    CU_ASSERT(ret == XQC_OK);

    cres = xqc_2d_hash_lookup(ht2d, 2, "node2", 5, 21, "value2", 6, (void**)&data);
    CU_ASSERT(cres == XQC_2D_CMP_RES_2D && data->idx == 3);


    /* remove eldest */
    ret = xqc_2d_hash_table_remove(ht2d, 2, 21, &n2);
    CU_ASSERT(ret == XQC_OK);

    cres = xqc_2d_hash_lookup(ht2d, 2, "node2", 5, 21, "value2", 6, (void**)&data);
    CU_ASSERT(cres == XQC_2D_CMP_RES_2D && data->idx == 3);


    xqc_2d_hash_table_free(ht2d);
}


void
test_2d_hash_table_immediate_free()
{
    xqc_2d_hash_table_t *ht2d = xqc_2d_hash_table_create(16, xqc_2d_ht_compare_data,
        xqc_2d_ht_compare_value, NULL);

    xqc_2d_hash_table_free(ht2d);
}


void
test_2d_hash_table_robust()
{
    void *data = NULL;
    xqc_int_t ret;

    xqc_2d_hash_table_t *ht2d = xqc_2d_hash_table_create(16, xqc_2d_ht_compare_data,
        xqc_2d_ht_compare_value, NULL);

    ret = xqc_2d_hash_table_add(ht2d, 0, 0, NULL);
    CU_ASSERT(ret == XQC_OK);


    /* remove inexist */
    ret = xqc_2d_hash_table_remove(ht2d, 1, 1, (void**)&data);
    CU_ASSERT(ret == XQC_OK);

    xqc_2d_hash_table_free(ht2d);
}


void
test_2d_hash_table_non_pow2_bkt()
{
    xqc_int_t ret = XQC_OK;
    xqc_2d_cmp_res_t cres = XQC_2D_CMP_RES_NONE;
    xqc_2d_ht_node_t *data = NULL;

    /* 10 buckets shall be rounded up to 16, all buckets initialized */
    xqc_2d_hash_table_t *ht2d = xqc_2d_hash_table_create(10,
        xqc_2d_ht_compare_data, xqc_2d_ht_compare_value, NULL);
    CU_ASSERT(ht2d != NULL);
    if (ht2d == NULL) {
        return;
    }

    /* hashes 10-15 fall into buckets beyond the requested count */
    xqc_2d_ht_node_t nodes[6];
    for (uint64_t i = 0; i < 6; i++) {
        nodes[i].idx = 10 + i;
        nodes[i].name = "nodeX";
        nodes[i].nlen = 5;
        nodes[i].value = "valueX";
        nodes[i].vlen = 6;

        ret = xqc_2d_hash_table_add(ht2d, 10 + i, 20 + i, &nodes[i]);
        CU_ASSERT(ret == XQC_OK);
    }

    /* every rounded-up bucket shall be retrievable */
    for (uint64_t i = 0; i < 6; i++) {
        cres = xqc_2d_hash_lookup(ht2d, 10 + i, "nodeX", 5,
                                  20 + i, "valueX", 6, (void**)&data);
        CU_ASSERT(cres == XQC_2D_CMP_RES_2D && data->idx == 10 + i);
    }

    /* remove nodes in rounded-up buckets */
    for (uint64_t i = 0; i < 6; i++) {
        ret = xqc_2d_hash_table_remove(ht2d, 10 + i, 20 + i, &nodes[i]);
        CU_ASSERT(ret == XQC_OK);

        cres = xqc_2d_hash_lookup(ht2d, 10 + i, "nodeX", 5,
                                  20 + i, "valueX", 6, (void**)&data);
        CU_ASSERT(cres == XQC_2D_CMP_RES_NONE);
    }

    xqc_2d_hash_table_free(ht2d);


    /* free traverses all rounded-up buckets even if never inserted */
    ht2d = xqc_2d_hash_table_create(3, xqc_2d_ht_compare_data,
        xqc_2d_ht_compare_value, NULL);
    CU_ASSERT(ht2d != NULL);
    xqc_2d_hash_table_free(ht2d);


    /* bucket count exceeding power-of-2 limit shall fail creation */
    ht2d = xqc_2d_hash_table_create(SIZE_MAX, xqc_2d_ht_compare_data,
        xqc_2d_ht_compare_value, NULL);
    CU_ASSERT(ht2d == NULL);
}


void
test_2d_hash_table()
{
    test_2d_hash_table_basic();

    test_2d_hash_table_immediate_free();

    test_2d_hash_table_robust();

    test_2d_hash_table_non_pow2_bkt();
}
