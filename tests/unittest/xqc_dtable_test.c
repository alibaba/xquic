/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xqc_dtable_test.h"
#include "src/http3/qpack/dtable/xqc_dtable.h"
#include <inttypes.h>
#include "tests/unittest/xqc_common_test.h"


void
xqc_test_dtable_basic()
{
    xqc_engine_t *engine = test_create_engine();

    xqc_var_buf_t *nbuf = xqc_var_buf_create(1024);
    xqc_var_buf_t *vbuf = xqc_var_buf_create(1024);

    xqc_dtable_t *dt = xqc_dtable_create(2, engine->log);
    CU_ASSERT(dt != NULL);

    xqc_int_t ret = xqc_dtable_set_capacity(dt, 256);
    CU_ASSERT(ret == XQC_OK);


    uint64_t idx = XQC_INVALID_INDEX;
    ret = xqc_dtable_add(dt, "test_name0", 10, "test_value0", 11, &idx);    /* 53 */
    CU_ASSERT(ret == XQC_OK && idx == 0);
    ret = xqc_dtable_get_nv(dt, 0, nbuf, vbuf);
    CU_ASSERT(ret == XQC_OK && strcmp(nbuf->data, "test_name0") == 0
              && strcmp(vbuf->data, "test_value0") == 0);

    ret = xqc_dtable_add(dt, "test_name1", 10, "test_value1", 11, &idx);    /* 53 */
    CU_ASSERT(ret == XQC_OK && idx == 1);
    ret = xqc_dtable_get_nv(dt, 1, nbuf, vbuf);
    CU_ASSERT(ret == XQC_OK && strcmp(nbuf->data, "test_name1") == 0
              && strcmp(vbuf->data, "test_value1") == 0);

    /* repeated n-v pair is allowed in dtable */
    idx = XQC_INVALID_INDEX;
    ret = xqc_dtable_add(dt, "test_name1", 10, "test_value1", 11, &idx);    /* 53 */
    CU_ASSERT(ret == XQC_OK && idx == 2);
    ret = xqc_dtable_get_nv(dt, 2, nbuf, vbuf);
    CU_ASSERT(ret == XQC_OK && strcmp(nbuf->data, "test_name1") == 0
              && strcmp(vbuf->data, "test_value1") == 0);

    /* entry with same name but not same value */
    idx = XQC_INVALID_INDEX;
    ret = xqc_dtable_add(dt, "test_name1", 10, "test_value_xxxx", 15, &idx);    /* 57 */
    CU_ASSERT(ret == XQC_OK && idx == 3);
    ret = xqc_dtable_get_nv(dt, 3, nbuf, vbuf);
    CU_ASSERT(ret == XQC_OK && strcmp(nbuf->data, "test_name1") == 0
              && strcmp(vbuf->data, "test_value_xxxx") == 0);


    xqc_nv_ref_type_t ref = xqc_dtable_lookup(dt, "test_name1", 10, "test_value1", 11, &idx);
    CU_ASSERT(ref == XQC_NV_REF_NAME_AND_VALUE && idx == 2);    /* get newest entry */

    ref = xqc_dtable_lookup(dt, "test_name1", 10, "test_value_xxx", 14, &idx);
    CU_ASSERT(ref == XQC_NV_REF_NAME && idx == 3);

    ref = xqc_dtable_lookup(dt, "test_name_xxx", 13, "test_value_xxx", 14, &idx);
    CU_ASSERT(ref == XQC_NV_REF_NONE);


    /* this entry shall evict entry 0, and make entry 1 draining */
    idx = XQC_INVALID_INDEX;
    ret = xqc_dtable_add(dt, "test_name4", 10, "test_value4__________", 21, &idx);  /* 53 */
    CU_ASSERT(ret == XQC_OK && idx == 4);
    ret = xqc_dtable_get_nv(dt, 4, nbuf, vbuf);
    CU_ASSERT(ret == XQC_OK && strcmp(nbuf->data, "test_name4") == 0
              && strcmp(vbuf->data, "test_value4__________") == 0);
    ret = xqc_dtable_get_nv(dt, 0, nbuf, vbuf);
    CU_ASSERT(ret != XQC_OK);

    /* lock entry 1 */
    ret = xqc_dtable_set_min_ref(dt, 1);
    CU_ASSERT(ret == XQC_OK);

    idx = XQC_INVALID_INDEX;
    ret = xqc_dtable_add(dt, "test_name_full", 14, "test_value_full", 15, &idx);
    CU_ASSERT(ret != XQC_OK);

    idx = xqc_dtable_get_insert_cnt(dt);
    CU_ASSERT(idx == 5);

    /* draining entry 1 */
    xqc_bool_t draining = XQC_FALSE;
    ret = xqc_dtable_is_entry_draining(dt, 1, &draining);
    CU_ASSERT(ret == XQC_OK && draining == XQC_TRUE);
    ret = xqc_dtable_is_entry_draining(dt, 100, &draining);
    CU_ASSERT(ret != XQC_OK);


    /* set entry 1 evictable */
    ret = xqc_dtable_set_min_ref(dt, 2);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_dtable_set_min_ref(dt, 2);
    CU_ASSERT(ret == XQC_OK);


    /* duplicate entry 2, result in entry 5 */
    ret = xqc_dtable_duplicate(dt, 2, &idx);
    CU_ASSERT(ret == XQC_OK && idx == 5);
    ret = xqc_dtable_get_nv(dt, 5, nbuf, vbuf);
    CU_ASSERT(ret == XQC_OK && strcmp(nbuf->data, "test_name1") == 0
              && strcmp(vbuf->data, "test_value1") == 0);
    ref = xqc_dtable_lookup(dt, "test_name1", 10, "test_value1", 11, &idx);
    CU_ASSERT(ref == XQC_NV_REF_NAME_AND_VALUE && idx == 5);    /* get newest entry */


    ret = xqc_dtable_duplicate(dt, 100, &idx);
    CU_ASSERT(ret != XQC_OK);



    xqc_dtable_free(dt);
    xqc_var_buf_free(nbuf);
    xqc_var_buf_free(vbuf);
    xqc_engine_destroy(engine);
}


void
xqc_test_dtable_immediate_free()
{
    xqc_engine_t *engine = test_create_engine();

    xqc_dtable_t *dt = xqc_dtable_create(256, engine->log);
    CU_ASSERT(dt != NULL);
    xqc_dtable_free(dt);    /* shall not crash */
    xqc_engine_destroy(engine);
}


void
xqc_test_dtable_no_bkt()
{
    xqc_engine_t *engine = test_create_engine();
    xqc_dtable_t *dt = xqc_dtable_create(0, engine->log);
    CU_ASSERT(dt == NULL);

    xqc_engine_destroy(engine);
}

void
xqc_test_dtable_illegal_call()
{
    xqc_int_t ret = XQC_OK;
    xqc_engine_t *engine = test_create_engine();
    xqc_dtable_t *dt = xqc_dtable_create(256, engine->log);

    ret = xqc_dtable_set_min_ref(dt, 2);
    CU_ASSERT(ret != XQC_OK);

    /* capacity not set yet */
    uint64_t idx = XQC_INVALID_INDEX;
    ret = xqc_dtable_add(dt, "test_name0", 10, "test_value0", 11, &idx);    /* 53 */
    CU_ASSERT(ret != XQC_OK);

    ret = xqc_dtable_set_min_ref(dt, 2);
    CU_ASSERT(ret != XQC_OK);

    xqc_dtable_free(dt);
    xqc_engine_destroy(engine);
}


void
xqc_test_dtable_robust()
{
    xqc_test_dtable_immediate_free();
    xqc_test_dtable_no_bkt();
    xqc_test_dtable_illegal_call();
}


void
xqc_test_dtable_set_capacity()
{
    xqc_engine_t *engine = test_create_engine();

    xqc_var_buf_t *nbuf = xqc_var_buf_create(1024);
    xqc_var_buf_t *vbuf = xqc_var_buf_create(1024);
    uint64_t idx = XQC_INVALID_INDEX;

    xqc_dtable_t *dt = xqc_dtable_create(32, engine->log);
    CU_ASSERT(dt != NULL);


    xqc_int_t ret = xqc_dtable_set_capacity(dt, 256);
    CU_ASSERT(ret == XQC_OK);


    idx = XQC_INVALID_INDEX;
    ret = xqc_dtable_add(dt, "test_name0", 10, "test_value0", 11, &idx);    /* 53 */
    CU_ASSERT(ret == XQC_OK && idx == 0);
    ret = xqc_dtable_get_nv(dt, 0, nbuf, vbuf);
    CU_ASSERT(ret == XQC_OK && strcmp(nbuf->data, "test_name0") == 0
              && strcmp(vbuf->data, "test_value0") == 0);

    ret = xqc_dtable_add(dt, "test_name1", 10, "test_value1", 11, &idx);    /* 53 */
    CU_ASSERT(ret == XQC_OK && idx == 1);
    xqc_var_buf_clear(nbuf);
    xqc_var_buf_clear(vbuf);
    ret = xqc_dtable_get_nv(dt, 1, nbuf, vbuf);
    CU_ASSERT(ret == XQC_OK && strcmp(nbuf->data, "test_name1") == 0
              && strcmp(vbuf->data, "test_value1") == 0);

    /* repeated n-v pair is allowed in dtable */
    idx = XQC_INVALID_INDEX;
    ret = xqc_dtable_add(dt, "test_name1", 10, "test_value1", 11, &idx);    /* 53 */
    CU_ASSERT(ret == XQC_OK && idx == 2);
    xqc_var_buf_clear(nbuf);
    xqc_var_buf_clear(vbuf);
    ret = xqc_dtable_get_nv(dt, 2, nbuf, vbuf);
    CU_ASSERT(ret == XQC_OK && strcmp(nbuf->data, "test_name1") == 0
              && strcmp(vbuf->data, "test_value1") == 0);

    /* entry with same name but not same value */
    idx = XQC_INVALID_INDEX;
    ret = xqc_dtable_add(dt, "test_name1", 10, "test_value_xxxx", 15, &idx);    /* 57 */
    CU_ASSERT(ret == XQC_OK && idx == 3);
    xqc_var_buf_clear(nbuf);
    xqc_var_buf_clear(vbuf);
    ret = xqc_dtable_get_nv(dt, 3, nbuf, vbuf);
    CU_ASSERT(ret == XQC_OK && strcmp(nbuf->data, "test_name1") == 0
              && strcmp(vbuf->data, "test_value_xxxx") == 0);


    /* shrink dtable and pop entry 0 and entry 1 */
    ret = xqc_dtable_set_capacity(dt, 128);
    CU_ASSERT(ret == XQC_OK);
    xqc_var_buf_clear(nbuf);
    xqc_var_buf_clear(vbuf);
    ret = xqc_dtable_get_nv(dt, 0, nbuf, vbuf);
    CU_ASSERT(ret != XQC_OK);
    xqc_var_buf_clear(nbuf);
    xqc_var_buf_clear(vbuf);
    ret = xqc_dtable_get_nv(dt, 1, nbuf, vbuf);
    CU_ASSERT(ret != XQC_OK);
    xqc_var_buf_clear(nbuf);
    xqc_var_buf_clear(vbuf);
    ret = xqc_dtable_get_nv(dt, 2, nbuf, vbuf);
    CU_ASSERT(ret == XQC_OK && strcmp(nbuf->data, "test_name1") == 0
              && strcmp(vbuf->data, "test_value1") == 0);
    xqc_var_buf_clear(nbuf);
    xqc_var_buf_clear(vbuf);
    ret = xqc_dtable_get_nv(dt, 3, nbuf, vbuf);
    CU_ASSERT(ret == XQC_OK && strcmp(nbuf->data, "test_name1") == 0
              && strcmp(vbuf->data, "test_value_xxxx") == 0);


    /* insert and pop entry 2 */
    idx = XQC_INVALID_INDEX;
    ret = xqc_dtable_add(dt, "test_name0", 10, "test_value0", 11, &idx);    /* 53 */
    CU_ASSERT(ret == XQC_OK && idx == 4);
    xqc_var_buf_clear(nbuf);
    xqc_var_buf_clear(vbuf);
    ret = xqc_dtable_get_nv(dt, 4, nbuf, vbuf);
    CU_ASSERT(ret == XQC_OK && strcmp(nbuf->data, "test_name0") == 0
              && strcmp(vbuf->data, "test_value0") == 0);
    xqc_var_buf_clear(nbuf);
    xqc_var_buf_clear(vbuf);
    ret = xqc_dtable_get_nv(dt, 2, nbuf, vbuf);
    CU_ASSERT(ret != XQC_OK);
    xqc_var_buf_clear(nbuf);
    xqc_var_buf_clear(vbuf);
    ret = xqc_dtable_get_nv(dt, 3, nbuf, vbuf);
    CU_ASSERT(ret == XQC_OK && strcmp(nbuf->data, "test_name1") == 0
              && strcmp(vbuf->data, "test_value_xxxx") == 0);

    /* duplicate and pop entry 3 */
    idx = XQC_INVALID_INDEX;
    ret = xqc_dtable_duplicate(dt, 4, &idx);
    CU_ASSERT(ret == XQC_OK && idx == 5);
    xqc_var_buf_clear(nbuf);
    xqc_var_buf_clear(vbuf);
    ret = xqc_dtable_get_nv(dt, 5, nbuf, vbuf);
    CU_ASSERT(ret == XQC_OK && strcmp(nbuf->data, "test_name0") == 0
              && strcmp(vbuf->data, "test_value0") == 0);
    xqc_var_buf_clear(nbuf);
    xqc_var_buf_clear(vbuf);
    ret = xqc_dtable_get_nv(dt, 3, nbuf, vbuf);
    CU_ASSERT(ret != XQC_OK);
    xqc_var_buf_clear(nbuf);
    xqc_var_buf_clear(vbuf);
    ret = xqc_dtable_get_nv(dt, 4, nbuf, vbuf);
    CU_ASSERT(ret == XQC_OK && strcmp(nbuf->data, "test_name0") == 0
              && strcmp(vbuf->data, "test_value0") == 0);
                  ret = xqc_dtable_get_nv(dt, 5, nbuf, vbuf);
    CU_ASSERT(ret == XQC_OK && strcmp(nbuf->data, "test_name0") == 0
              && strcmp(vbuf->data, "test_value0") == 0);


    ret = xqc_dtable_set_min_ref(dt, 100);
    CU_ASSERT(ret != XQC_OK);

    ret = xqc_dtable_set_min_ref(dt, 4);
    CU_ASSERT(ret == XQC_OK);
    ret = xqc_dtable_set_capacity(dt, 64);
    CU_ASSERT(ret != XQC_OK);


    xqc_dtable_free(dt);
    xqc_var_buf_free(nbuf);
    xqc_var_buf_free(vbuf);
    xqc_engine_destroy(engine);

}


void
xqc_test_dtable()
{
    xqc_test_dtable_basic();

    xqc_test_dtable_robust();

    xqc_test_dtable_set_capacity();
}
