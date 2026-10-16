/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xqc_ring_array_test.h"
#include "src/common/utils/ringarray/xqc_ring_array.h"
#include <inttypes.h>


typedef struct xqc_rarray_test_node_s {
    uint64_t idx;
    uint64_t value;
} xqc_rarray_test_node_t;


void
xqc_test_ring_array_basic()
{
    xqc_int_t ret = XQC_OK;
    xqc_rarray_test_node_t *node = NULL;

    xqc_rarray_t *ra = xqc_rarray_create(32, sizeof(xqc_rarray_test_node_t));
    CU_ASSERT(ra != NULL);

    node = (xqc_rarray_test_node_t *)xqc_rarray_push(ra);
    CU_ASSERT(node != NULL);
    node->idx = 0;
    node->value = 0;


    node = (xqc_rarray_test_node_t *)xqc_rarray_push(ra);
    CU_ASSERT(node != NULL);
    node->idx = 1;
    node->value = 1;

    CU_ASSERT(xqc_rarray_size(ra) == 2);

    node = (xqc_rarray_test_node_t *)xqc_rarray_front(ra);
    CU_ASSERT(node != NULL && node->idx == 0 && node->value == 0);

    ret = xqc_rarray_pop_front(ra);
    CU_ASSERT(ret == XQC_OK);

    node = (xqc_rarray_test_node_t *)xqc_rarray_get(ra, 0);
    CU_ASSERT(node != NULL && node->idx == 1 && node->value == 1);

    ret = xqc_rarray_pop_back(ra);
    CU_ASSERT(ret == XQC_OK);

    CU_ASSERT(xqc_rarray_pop_front(ra) != XQC_OK);
    CU_ASSERT(xqc_rarray_pop_back(ra) != XQC_OK);

    xqc_rarray_destroy(ra);
}


void
xqc_test_ring_array_rollover()
{
    xqc_int_t ret = XQC_OK;
    xqc_rarray_test_node_t *node = NULL;

    xqc_rarray_t *ra = xqc_rarray_create(32, sizeof(xqc_rarray_test_node_t));
    for (size_t i = 0; i < 32; i++) {
        node = (xqc_rarray_test_node_t *)xqc_rarray_push(ra);
        CU_ASSERT(node != NULL);
        node->idx = i;
        node->value = i;
    }

    size_t sz = xqc_rarray_size(ra);
    CU_ASSERT(sz == 32);

    node = (xqc_rarray_test_node_t *)xqc_rarray_get(ra, 33);
    CU_ASSERT(node == NULL);

    for (size_t i = 0; i < 32; i++) {
        node = (xqc_rarray_test_node_t *)xqc_rarray_get(ra, i);
        CU_ASSERT(node != NULL && node->idx == i && node->value == i);
    }

    /* pop front 8 nodes */
    for (size_t i = 0; i < 8; i++) {
        ret = xqc_rarray_pop_front(ra);
        CU_ASSERT(ret == XQC_OK);
        node = (xqc_rarray_test_node_t *)xqc_rarray_get(ra, 0);
        CU_ASSERT(node != NULL && node->idx == i + 1 && node->value == i + 1);
    }

    /* pop back 8 nodes */
    for (size_t i = 31; i >= 24; i--) {
        ret = xqc_rarray_pop_back(ra);
        CU_ASSERT(ret == XQC_OK);

        sz = xqc_rarray_size(ra);
        CU_ASSERT(sz == (i - 8));
        node = (xqc_rarray_test_node_t *)xqc_rarray_get(ra, sz - 1);
        CU_ASSERT(node != NULL && node->idx == i - 1 && node->value == i - 1);
    }

    /* insert 16 nodes, make it full. [8, 23], [32, 47] */
    for (size_t i = 32; i < 48; i++) {
        node = (xqc_rarray_test_node_t *)xqc_rarray_push(ra);
        CU_ASSERT(node != NULL);
        node->idx = i;
        node->value = i;
    }

    for (size_t i = 0; i < 16; i++) {
        node = (xqc_rarray_test_node_t *)xqc_rarray_get(ra, i);
        CU_ASSERT(node != NULL && node->idx == i + 8 && node->value == i + 8);
    }

    for (size_t i = 16; i < 32; i++) {
        node = (xqc_rarray_test_node_t *)xqc_rarray_get(ra, i);
        CU_ASSERT(node != NULL && node->idx == i + 16 && node->value == i + 16);
    }

    /* rollover resize, pop [8, 23], [32, 47] remains, truncated into [32, 39], [40, 47] */
    for (size_t i = 0; i < 16; i++) {
        ret = xqc_rarray_pop_front(ra);
        CU_ASSERT(ret == XQC_OK);
    }

    node = (xqc_rarray_test_node_t *)xqc_rarray_get(ra, 0);
    CU_ASSERT(node != NULL && node->idx == 32 && node->value == 32);

    ret = xqc_rarray_resize(ra, 16);
    CU_ASSERT(ret == XQC_OK);

    ret = xqc_rarray_resize(ra, 64);
    CU_ASSERT(ret == XQC_OK);


    xqc_rarray_destroy(ra);
}


void
xqc_test_ring_array_resize()
{
    xqc_int_t ret = XQC_OK;
    xqc_rarray_test_node_t *node = NULL;

    xqc_rarray_t *ra = xqc_rarray_create(32, sizeof(xqc_rarray_test_node_t));

    ret = xqc_rarray_resize(ra, 16);
    CU_ASSERT(ret == XQC_OK);

    for (size_t i = 0; i < 16; i++) {
        node = (xqc_rarray_test_node_t *)xqc_rarray_push(ra);
        CU_ASSERT(node != NULL);
        node->idx = i;
        node->value = i;
    }

    ret = xqc_rarray_resize(ra, 8);
    CU_ASSERT(ret != XQC_OK);

    ret = xqc_rarray_resize(ra, 64);
    CU_ASSERT(ret == XQC_OK);

    for (size_t i = 0; i < 16; i++) {
        node = (xqc_rarray_test_node_t *)xqc_rarray_get(ra, i);
        CU_ASSERT(node != NULL && node->idx == i && node->value == i);
    }

    xqc_rarray_destroy(ra);
}


void
xqc_test_ring_array_robust()
{
    xqc_rarray_t *ra = xqc_rarray_create(0, sizeof(xqc_rarray_test_node_t));
    CU_ASSERT(ra != NULL && xqc_rarray_size(ra) == 0);
    xqc_rarray_destroy(ra);
}


void
test_ring_array()
{
    xqc_test_ring_array_basic();
    xqc_test_ring_array_rollover();
    xqc_test_ring_array_resize();
    xqc_test_ring_array_robust();
    xqc_test_ring_array_resize_full_wrapped();
    xqc_test_ring_array_resize_empty();
}


/**
 * Test xqc_rarray_resize() when array is exactly full and wrapping.
 * When count == cap (full), end = (offset + cap) & mask = offset, so end == offset.
 * The old code used `end >= offset` which incorrectly treated this as continuous data.
 * The fix uses `end > offset` to correctly identify wrapping.
 */
void
xqc_test_ring_array_resize_full_wrapped()
{
    xqc_int_t ret;
    xqc_rarray_test_node_t *node = NULL;

    /*
     * Create ring array with capacity 8.
     * Push 4 elements, then pop 4 to advance offset.
     * Then push 8 more elements to fill the array (count == cap).
     * This makes the data wrap around: elements at positions [4,5,6,7,0,1,2,3].
     */
    xqc_rarray_t *ra = xqc_rarray_create(8, sizeof(xqc_rarray_test_node_t));
    CU_ASSERT(ra != NULL);

    /* Push 4 elements to positions [0,1,2,3] */
    for (size_t i = 0; i < 4; i++) {
        node = (xqc_rarray_test_node_t *)xqc_rarray_push(ra);
        CU_ASSERT(node != NULL);
        node->idx = i;
        node->value = i * 100;
    }

    /* Pop 4 elements to advance offset to 4 */
    for (size_t i = 0; i < 4; i++) {
        ret = xqc_rarray_pop_front(ra);
        CU_ASSERT(ret == XQC_OK);
    }

    CU_ASSERT(xqc_rarray_size(ra) == 0);

    /* Push 8 elements to fill the array: positions [4,5,6,7,0,1,2,3] */
    for (size_t i = 0; i < 8; i++) {
        node = (xqc_rarray_test_node_t *)xqc_rarray_push(ra);
        CU_ASSERT(node != NULL);
        node->idx = i + 10;
        node->value = (i + 10) * 100;
    }

    CU_ASSERT(xqc_rarray_size(ra) == 8);  /* count == cap (full) */

    /* Verify data before resize */
    for (size_t i = 0; i < 8; i++) {
        node = (xqc_rarray_test_node_t *)xqc_rarray_get(ra, i);
        CU_ASSERT(node != NULL);
        CU_ASSERT(node->idx == i + 10);
        CU_ASSERT(node->value == (i + 10) * 100);
    }

    /*
     * Resize to 16: this triggers the bug.
     * offset=4, count=8, cap=8, mask=7
     * end = (4 + 8) & 7 = 12 & 7 = 4 = offset
     * Old code: end >= offset (4 >= 4) -> TRUE -> linear memcpy (WRONG, OOB)
     * New code: end > offset (4 > 4) -> FALSE -> wrapping memcpy (CORRECT)
     */
    ret = xqc_rarray_resize(ra, 16);
    CU_ASSERT(ret == XQC_OK);

    /* Verify data integrity after resize */
    for (size_t i = 0; i < 8; i++) {
        node = (xqc_rarray_test_node_t *)xqc_rarray_get(ra, i);
        CU_ASSERT(node != NULL);
        CU_ASSERT(node->idx == i + 10);
        CU_ASSERT(node->value == (i + 10) * 100);
    }

    xqc_rarray_destroy(ra);
}


/**
 * Test xqc_rarray_resize() with empty array (count == 0).
 * When count == 0, end == offset, and the condition should route to
 * the continuous branch (which copies 0 bytes).
 */
void
xqc_test_ring_array_resize_empty()
{
    xqc_int_t ret;

    /* Create ring array with capacity 8 but no elements */
    xqc_rarray_t *ra = xqc_rarray_create(8, sizeof(xqc_rarray_test_node_t));
    CU_ASSERT(ra != NULL);
    CU_ASSERT(xqc_rarray_size(ra) == 0);

    /* Resize empty array: count=0, offset=0, end=0 */
    ret = xqc_rarray_resize(ra, 16);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(xqc_rarray_size(ra) == 0);

    /* Verify we can still push elements after resize */
    xqc_rarray_test_node_t *node = (xqc_rarray_test_node_t *)xqc_rarray_push(ra);
    CU_ASSERT(node != NULL);
    node->idx = 42;
    node->value = 4200;

    CU_ASSERT(xqc_rarray_size(ra) == 1);
    node = (xqc_rarray_test_node_t *)xqc_rarray_get(ra, 0);
    CU_ASSERT(node != NULL && node->idx == 42 && node->value == 4200);

    xqc_rarray_destroy(ra);
}