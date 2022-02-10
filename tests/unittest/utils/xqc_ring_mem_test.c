/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xqc_ring_mem_test.h"
#include "src/common/utils/ringmem/xqc_ring_mem.h"
#include <inttypes.h>


#define RING_MEM_TEST_CAP 64

#define STR1_16B    "16_bytes_string1"
#define STR2_16B    "16_bytes_string2"
#define STR3_32B    "32_bytes_string2_is_twice_of_16B"

#define MAKE_STR(a, b) a##b


void
xqc_test_ring_mem_basic()
{
    xqc_int_t ret = XQC_OK;
    xqc_ring_mem_idx_t idx;
    size_t used = 0;
    char buf[RING_MEM_TEST_CAP] = {0};

    /* alloc a ring memory of 64 bytes */
    xqc_ring_mem_t *rm = xqc_ring_mem_create(RING_MEM_TEST_CAP);
    CU_ASSERT(rm != NULL);
    used = xqc_ring_mem_used_size(rm);
    CU_ASSERT(used == 0);

    /* [0, 15] */
    ret = xqc_ring_mem_enqueue(rm, "16_bytes_string1", 16, &idx);
    CU_ASSERT(ret == XQC_OK && idx == 0);
    used = xqc_ring_mem_used_size(rm);
    CU_ASSERT(used == 16);
    ret = xqc_ring_mem_copy(rm, 0, 16, buf, RING_MEM_TEST_CAP);
    CU_ASSERT(ret == XQC_OK && memcmp(buf, STR1_16B, 16) == 0
        && xqc_ring_mem_cmp(rm, 0, STR1_16B, 16) == 0);

    /* [0, 31] */
    ret = xqc_ring_mem_enqueue(rm, "16_bytes_string2", 16, &idx);
    CU_ASSERT(ret == XQC_OK && idx == 16);
    used = xqc_ring_mem_used_size(rm);
    CU_ASSERT(used == 32);
    ret = xqc_ring_mem_copy(rm, idx, 16, buf, RING_MEM_TEST_CAP);
    CU_ASSERT(ret == XQC_OK && memcmp(buf, STR2_16B, 16) == 0
        && xqc_ring_mem_cmp(rm, 16, STR2_16B, 16) == 0);

    /* if we copy from 0, it's STR1_16B#STR2_16B */
    ret = xqc_ring_mem_copy(rm, 0, 32, buf, RING_MEM_TEST_CAP);
    CU_ASSERT(ret == XQC_OK && memcmp(buf, "16_bytes_string116_bytes_string2", 32) == 0
        && xqc_ring_mem_cmp(rm, 0, "16_bytes_string116_bytes_string2", 32) == 0);

    /* invalid dequeue */
    ret = xqc_ring_mem_dequeue(rm, 16, 16);
    CU_ASSERT(ret != XQC_OK);
    CU_ASSERT(xqc_ring_mem_used_size(rm) == 32);
    ret = xqc_ring_mem_copy(rm, 0, 16, buf, RING_MEM_TEST_CAP);
    CU_ASSERT(ret == XQC_OK && memcmp(buf, STR1_16B, 16) == 0
        && xqc_ring_mem_cmp(rm, 0, STR1_16B, 16) == 0);


    /* [16, 31], dequeue STR1 */
    ret = xqc_ring_mem_dequeue(rm, 0, 16);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(xqc_ring_mem_used_size(rm) == 16);
    ret = xqc_ring_mem_copy(rm, 0, 16, buf, RING_MEM_TEST_CAP);
    CU_ASSERT(ret != XQC_OK);
    ret = xqc_ring_mem_copy(rm, 16, 16, buf, RING_MEM_TEST_CAP);
    CU_ASSERT(ret == XQC_OK && memcmp(buf, STR2_16B, 16) == 0
        && xqc_ring_mem_cmp(rm, 16, STR2_16B, 16) == 0);


    /* [16, 47] */
    ret = xqc_ring_mem_enqueue(rm, STR2_16B, 16, &idx);
    CU_ASSERT(ret == XQC_OK && idx == 32);
    CU_ASSERT(xqc_ring_mem_used_size(rm) == 32);
    ret = xqc_ring_mem_copy(rm, 16, 32, buf, RING_MEM_TEST_CAP);
    CU_ASSERT(ret == XQC_OK && memcmp(buf, "16_bytes_string216_bytes_string2", 32) == 0
        && xqc_ring_mem_cmp(rm, 16, "16_bytes_string216_bytes_string2", 32) == 0);


    /* [16, 63], [0, 15], truncated string */
    ret = xqc_ring_mem_enqueue(rm, STR3_32B, 32, &idx);
    CU_ASSERT(ret == XQC_OK && idx == 48);
    CU_ASSERT(xqc_ring_mem_used_size(rm) == 64);
    ret = xqc_ring_mem_copy(rm, 16, 64, buf, RING_MEM_TEST_CAP);
    CU_ASSERT(ret == XQC_OK
        && memcmp(buf, "16_bytes_string216_bytes_string232_bytes_string2_is_twice_of_16B", 64) == 0
        &&  xqc_ring_mem_cmp(rm, 16, "16_bytes_string216_bytes_string232_bytes_string2_is_twice_of_16B", 64) == 0);


    /* undo latest, [16, 47] */
    ret = xqc_ring_mem_undo(rm, 48, 32);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(xqc_ring_mem_used_size(rm) == 32);
    ret = xqc_ring_mem_copy(rm, 48, 32, buf, RING_MEM_TEST_CAP);
    CU_ASSERT(ret != XQC_OK);
    ret = xqc_ring_mem_copy(rm, 16, 32, buf, RING_MEM_TEST_CAP);
    CU_ASSERT(ret == XQC_OK && memcmp(buf, "16_bytes_string216_bytes_string2", 32) == 0
        && xqc_ring_mem_cmp(rm, 16, "16_bytes_string216_bytes_string2", 32) == 0);

    /* shrink to 32 bytes */
    ret = xqc_ring_mem_resize(rm, 32);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(xqc_ring_mem_used_size(rm) == 32);
    ret = xqc_ring_mem_copy(rm, 16, 32, buf, RING_MEM_TEST_CAP);
    CU_ASSERT(ret == XQC_OK && memcmp(buf, "16_bytes_string216_bytes_string2", 32) == 0
        && xqc_ring_mem_cmp(rm, 16, "16_bytes_string216_bytes_string2", 32) == 0);


    ret = xqc_ring_mem_resize(rm, 16);
    CU_ASSERT(ret != XQC_OK);
    CU_ASSERT(xqc_ring_mem_used_size(rm) == 32);
    ret = xqc_ring_mem_copy(rm, 16, 32, buf, RING_MEM_TEST_CAP);
    CU_ASSERT(ret == XQC_OK && memcmp(buf, "16_bytes_string216_bytes_string2", 32) == 0
        && xqc_ring_mem_cmp(rm, 16, "16_bytes_string216_bytes_string2", 32) == 0);


    ret = xqc_ring_mem_resize(rm, 128);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(xqc_ring_mem_used_size(rm) == 32);
    ret = xqc_ring_mem_copy(rm, 16, 32, buf, RING_MEM_TEST_CAP);
    CU_ASSERT(ret == XQC_OK && memcmp(buf, "16_bytes_string216_bytes_string2", 32) == 0
        && xqc_ring_mem_cmp(rm, 16, "16_bytes_string216_bytes_string2", 32) == 0);


    /* enqueue after undo and resize, shall be [16, 79] */
    ret = xqc_ring_mem_enqueue(rm, STR3_32B, 32, &idx);
    CU_ASSERT(ret == XQC_OK && idx == 48);
    CU_ASSERT(xqc_ring_mem_used_size(rm) == 64);
    ret = xqc_ring_mem_copy(rm, 16, 64, buf, RING_MEM_TEST_CAP);
    CU_ASSERT(ret == XQC_OK 
        && memcmp(buf, "16_bytes_string216_bytes_string232_bytes_string2_is_twice_of_16B", 64) == 0
        && xqc_ring_mem_cmp(rm, 16, "16_bytes_string216_bytes_string232_bytes_string2_is_twice_of_16B", 64) == 0);


    /* [16, 111] */
    ret = xqc_ring_mem_duplicate(rm, 48, 32, &idx);
    CU_ASSERT(ret == XQC_OK && idx == 80);
    CU_ASSERT(xqc_ring_mem_used_size(rm) == 96);
    ret = xqc_ring_mem_copy(rm, 80, 32, buf, RING_MEM_TEST_CAP);
    CU_ASSERT(ret == XQC_OK && memcmp(buf, STR3_32B, 32) == 0 
        && xqc_ring_mem_cmp(rm, 80, STR3_32B, 32) == 0);


    /* undo dequeue */
    ret = xqc_ring_mem_dequeue(rm, 16, 32);
    CU_ASSERT(ret == XQC_OK && xqc_ring_mem_used_size(rm) == 64);
    ret = xqc_ring_mem_undo(rm, 16, 32);
    CU_ASSERT(ret == XQC_OK && xqc_ring_mem_used_size(rm) == 96);

    /* illegal undo dequeue */
    ret = xqc_ring_mem_undo(rm, 0, 15);
    CU_ASSERT(ret != XQC_OK);

    /* illegal undo enqueue */
    ret = xqc_ring_mem_undo(rm, 80, 31);
    CU_ASSERT(ret != XQC_OK);

    xqc_ring_mem_free(rm);
}



void
xqc_test_ring_mem_duplicate_dst_truncated()
{
    xqc_int_t ret = XQC_OK;
    xqc_ring_mem_idx_t idx;
    size_t used = 0;
    char buf[RING_MEM_TEST_CAP] = {0};

    /* alloc a ring memory of 64 bytes */
    xqc_ring_mem_t *rm = xqc_ring_mem_create(RING_MEM_TEST_CAP);
    CU_ASSERT(rm != NULL);

    /* [0, 15] */
    ret = xqc_ring_mem_enqueue(rm, "16_bytes_string1", 16, &idx);
    CU_ASSERT(ret == XQC_OK && idx == 0);
    used = xqc_ring_mem_used_size(rm);
    CU_ASSERT(used == 16);
    ret = xqc_ring_mem_copy(rm, 0, 16, buf, RING_MEM_TEST_CAP);
    CU_ASSERT(ret == XQC_OK && memcmp(buf, STR1_16B, 16) == 0
        && xqc_ring_mem_cmp(rm, 0, STR1_16B, 16) == 0);


    /* [0, 47] */
    ret = xqc_ring_mem_enqueue(rm, STR3_32B, 32, &idx);
    CU_ASSERT(ret == XQC_OK && idx == 16);
    CU_ASSERT(xqc_ring_mem_used_size(rm) == 48);
    ret = xqc_ring_mem_copy(rm, 16, 32, buf, RING_MEM_TEST_CAP);
    CU_ASSERT(ret == XQC_OK && memcmp(buf, STR3_32B, 32) == 0
        && xqc_ring_mem_cmp(rm, 16, STR3_32B, 32) == 0);


    /* [16, 47] */
    ret = xqc_ring_mem_dequeue(rm, 0, 16);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(xqc_ring_mem_used_size(rm) == 32);
    ret = xqc_ring_mem_copy(rm, 16, 32, buf, RING_MEM_TEST_CAP);
    CU_ASSERT(ret == XQC_OK && memcmp(buf, STR3_32B, 32) == 0
        && xqc_ring_mem_cmp(rm, 16, STR3_32B, 32) == 0);


    /* [16, 63], [0, 15] */
    ret = xqc_ring_mem_duplicate(rm, 16, 32, &idx);
    CU_ASSERT(ret == XQC_OK && idx == 48);
    CU_ASSERT(xqc_ring_mem_used_size(rm) == 64);
    ret = xqc_ring_mem_copy(rm, 16, 64, buf, RING_MEM_TEST_CAP);
    CU_ASSERT(ret == XQC_OK && memcmp(buf, "32_bytes_string2_is_twice_of_16B32_bytes_string2_is_twice_of_16B", 64) == 0
        && xqc_ring_mem_cmp(rm, 16, "32_bytes_string2_is_twice_of_16B32_bytes_string2_is_twice_of_16B", 64) == 0);

    xqc_ring_mem_free(rm);
}


void
xqc_test_ring_mem_duplicate_src_truncated()
{
    xqc_int_t ret = XQC_OK;
    xqc_ring_mem_idx_t idx;
    size_t used = 0;
    char buf[RING_MEM_TEST_CAP] = {0};

    /* alloc a ring memory of 64 bytes */
    xqc_ring_mem_t *rm = xqc_ring_mem_create(RING_MEM_TEST_CAP);
    CU_ASSERT(rm != NULL);


    /* [0, 31] */
    ret = xqc_ring_mem_enqueue(rm, STR3_32B, 32, &idx);
    CU_ASSERT(ret == XQC_OK && idx == 0);
    CU_ASSERT(xqc_ring_mem_used_size(rm) == 32);
    ret = xqc_ring_mem_copy(rm, 0, 32, buf, RING_MEM_TEST_CAP);
    CU_ASSERT(ret == XQC_OK && memcmp(buf, STR3_32B, 32) == 0
        && xqc_ring_mem_cmp(rm, 0, STR3_32B, 32) == 0);


    /* [0, 47] */
    ret = xqc_ring_mem_enqueue(rm, "16_bytes_string1", 16, &idx);
    CU_ASSERT(ret == XQC_OK && idx == 32);
    used = xqc_ring_mem_used_size(rm);
    CU_ASSERT(used == 48);
    ret = xqc_ring_mem_copy(rm, 32, 16, buf, RING_MEM_TEST_CAP);
    CU_ASSERT(ret == XQC_OK && memcmp(buf, STR1_16B, 16) == 0
        && xqc_ring_mem_cmp(rm, 32, STR1_16B, 16) == 0);


    /* dequeue all */
    ret = xqc_ring_mem_dequeue(rm, 0, 48);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(xqc_ring_mem_used_size(rm) == 0);
    ret = xqc_ring_mem_copy(rm, 16, 32, buf, RING_MEM_TEST_CAP);
    CU_ASSERT(ret != XQC_OK);


    /* [48, 63], [0, 15] */
    ret = xqc_ring_mem_enqueue(rm, STR3_32B, 32, &idx);
    CU_ASSERT(ret == XQC_OK && idx == 48);
    CU_ASSERT(xqc_ring_mem_used_size(rm) == 32);
    ret = xqc_ring_mem_copy(rm, 48, 32, buf, RING_MEM_TEST_CAP);
    CU_ASSERT(ret == XQC_OK && memcmp(buf, STR3_32B, 32) == 0
        && xqc_ring_mem_cmp(rm, 48, STR3_32B, 32) == 0);


    /* [48, 63], [0, 15], [16, 47] */
    ret = xqc_ring_mem_duplicate(rm, 48, 32, &idx);
    CU_ASSERT(ret == XQC_OK && idx == 80);
    CU_ASSERT(xqc_ring_mem_used_size(rm) == 64);
    memset(buf, 0, 64);
    ret = xqc_ring_mem_copy(rm, 48, 64, buf, RING_MEM_TEST_CAP);
    CU_ASSERT(ret == XQC_OK && memcmp(buf, "32_bytes_string2_is_twice_of_16B32_bytes_string2_is_twice_of_16B", 64) == 0
        && xqc_ring_mem_cmp(rm, 48, "32_bytes_string2_is_twice_of_16B32_bytes_string2_is_twice_of_16B", 64) == 0);


    ret = xqc_ring_mem_copy(rm, 48, 64, buf, 32);
    CU_ASSERT(ret != XQC_OK);


    xqc_ring_mem_free(rm);
}


void
xqc_test_ring_mem_robust()
{
    xqc_int_t ret = XQC_OK;
    xqc_ring_mem_idx_t idx;
    size_t used = 0;
    char buf[RING_MEM_TEST_CAP] = {0};

    /* alloc a ring memory of 64 bytes */
    xqc_ring_mem_t *rm = xqc_ring_mem_create(RING_MEM_TEST_CAP);
    CU_ASSERT(rm != NULL);

    /* enqueue error */
    ret = xqc_ring_mem_enqueue(rm, STR3_32B, 128, &idx);
    CU_ASSERT(ret != XQC_OK);


    /* duplicate inexist */
    ret = xqc_ring_mem_duplicate(rm, 0, 32, &idx);
    CU_ASSERT(ret != XQC_OK);


    /* copy error */
    ret = xqc_ring_mem_enqueue(rm, STR3_32B, 32, &idx);
    CU_ASSERT(ret == XQC_OK && idx == 0);
    ret = xqc_ring_mem_cmp(rm, 32, buf, 32);
    CU_ASSERT(ret != XQC_OK);


    ret = xqc_ring_mem_duplicate(rm, 0, 33, &idx);
    CU_ASSERT(ret != XQC_OK);


    xqc_ring_mem_free(rm);

}


void
xqc_test_ring_mem()
{
    xqc_test_ring_mem_basic();
    xqc_test_ring_mem_duplicate_dst_truncated();
    xqc_test_ring_mem_duplicate_src_truncated();
    xqc_test_ring_mem_robust();
}
