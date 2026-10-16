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


    /* undo dequeue */
    ret = xqc_ring_mem_dequeue(rm, 16, 32);
    CU_ASSERT(ret == XQC_OK && xqc_ring_mem_used_size(rm) == 32);
    ret = xqc_ring_mem_undo(rm, 16, 32);
    CU_ASSERT(ret == XQC_OK && xqc_ring_mem_used_size(rm) == 64);

    /* illegal undo dequeue */
    ret = xqc_ring_mem_undo(rm, 0, 15);
    CU_ASSERT(ret != XQC_OK);

    /* illegal undo enqueue */
    ret = xqc_ring_mem_undo(rm, 48, 31);
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


    /* copy error */
    ret = xqc_ring_mem_enqueue(rm, STR3_32B, 32, &idx);
    CU_ASSERT(ret == XQC_OK && idx == 0);
    ret = xqc_ring_mem_cmp(rm, 32, buf, 32);
    CU_ASSERT(ret != XQC_OK);


    xqc_ring_mem_free(rm);

}


void
xqc_test_ring_mem()
{
    xqc_test_ring_mem_basic();
    xqc_test_ring_mem_robust();
    xqc_test_ring_mem_resize_wrapped();
    xqc_test_ring_mem_copy_bounds();
}


/**
 * Test xqc_ring_mem_resize() when data wraps in the original buffer.
 */
void
xqc_test_ring_mem_resize_wrapped()
{
    xqc_int_t ret;
    xqc_ring_mem_idx_t idx;
    char buf[256] = {0};

    /*
     * Create ring mem with capacity 64 (power of 2).
     * Enqueue 32 bytes, dequeue 16 bytes to advance sidx.
     * Then enqueue 48 more bytes to make data wrap: sidx=16, eidx=80.
     * Data layout in 64-byte buffer: [16..63] + [0..15] (wrapped)
     */
    xqc_ring_mem_t *rm = xqc_ring_mem_create(64);
    CU_ASSERT(rm != NULL);

    /* Enqueue 32 bytes at [0,31] */
    ret = xqc_ring_mem_enqueue(rm, "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB", 32, &idx);
    CU_ASSERT(ret == XQC_OK && idx == 0);

    /* Dequeue first 16 bytes, sidx becomes 16 */
    ret = xqc_ring_mem_dequeue(rm, 0, 16);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(xqc_ring_mem_used_size(rm) == 16);

    /* Enqueue 48 bytes: fills [16..63] then wraps to [0..15] */
    ret = xqc_ring_mem_enqueue(rm, "CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEE", 48, &idx);
    CU_ASSERT(ret == XQC_OK && idx == 32);
    CU_ASSERT(xqc_ring_mem_used_size(rm) == 64);

    /* Now sidx=16, eidx=80, data wraps in old 64-byte buffer */
    /* Resize to 128 bytes: new buffer is 128, sidx=16&127=16, eidx=80&127=80 */
    /* soffset_new=16 < eoffset_new=80, so data is continuous in new buffer */
    ret = xqc_ring_mem_resize(rm, 128);
    CU_ASSERT(ret == XQC_OK);

    /* Verify data integrity after resize */
    ret = xqc_ring_mem_copy(rm, 16, 64, buf, 256);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(memcmp(buf, "BBBBBBBBBBBBBBBB", 16) == 0);
    CU_ASSERT(memcmp(buf + 16, "CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEE", 48) == 0);

    xqc_ring_mem_free(rm);
}


/**
 * Test xqc_ring_mem_copy() bounds checking:
 * the requested range [idx, idx+len) must not exceed eidx.
 */
void
xqc_test_ring_mem_copy_bounds()
{
    xqc_int_t ret;
    xqc_ring_mem_idx_t idx;
    char buf[256] = {0};

    xqc_ring_mem_t *rm = xqc_ring_mem_create(64);
    CU_ASSERT(rm != NULL);

    /* Enqueue 16 bytes: sidx=0, eidx=16 */
    ret = xqc_ring_mem_enqueue(rm, "0123456789ABCDEF", 16, &idx);
    CU_ASSERT(ret == XQC_OK && idx == 0);

    /* Normal copy: idx=0, len=16 -> [0,16) within [sidx=0, eidx=16) */
    ret = xqc_ring_mem_copy(rm, 0, 16, buf, 256);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(memcmp(buf, "0123456789ABCDEF", 16) == 0);

    /* Boundary: idx=0, len=16 -> exactly [0,16), should succeed */
    ret = xqc_ring_mem_copy(rm, 0, 16, buf, 256);
    CU_ASSERT(ret == XQC_OK);

    /* OOB: idx=0, len=17 -> [0,17) exceeds eidx=16, should fail */
    ret = xqc_ring_mem_copy(rm, 0, 17, buf, 256);
    CU_ASSERT(ret != XQC_OK);

    /* OOB: idx=0, len=32000 -> way beyond eidx, should fail */
    ret = xqc_ring_mem_copy(rm, 0, 32000, buf, 256);
    CU_ASSERT(ret != XQC_OK);

    /* OOB: idx=8, len=16 -> [8,24) exceeds eidx=16, should fail */
    ret = xqc_ring_mem_copy(rm, 8, 16, buf, 256);
    CU_ASSERT(ret != XQC_OK);

    /* Normal: idx=8, len=8 -> [8,16) within bounds, should succeed */
    ret = xqc_ring_mem_copy(rm, 8, 8, buf, 256);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(memcmp(buf, "89ABCDEF", 8) == 0);

    xqc_ring_mem_free(rm);
}
