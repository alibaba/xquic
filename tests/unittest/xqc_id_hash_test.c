/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_id_hash_test.h"
#include "src/common/xqc_id_hash.h"
#include "src/common/xqc_str_hash.h"
#include <CUnit/CUnit.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


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


/* the blocks of a string hash table, and the malloc call that fails */
typedef struct xqc_test_str_hash_alloc_s {
    int live;    /* blocks allocated and not freed yet */
    int mallocs; /* malloc calls so far */
    int fail_at; /* the malloc call that returns NULL, or 0 */
} xqc_test_str_hash_alloc_t;

static void *
xqc_test_str_hash_malloc(void *opaque, size_t size)
{
    xqc_test_str_hash_alloc_t *alloc = opaque;
    void *ptr;

    if (++alloc->mallocs == alloc->fail_at) {
        return NULL;
    }

    ptr = malloc(size);
    if (ptr != NULL) {
        alloc->live++;
    }
    return ptr;
}

static void
xqc_test_str_hash_free(void *opaque, void *ptr)
{
    xqc_test_str_hash_alloc_t *alloc = opaque;

    if (ptr != NULL) {
        alloc->live--;
    }
    free(ptr);
}

static xqc_int_t
xqc_test_str_hash_add_key(xqc_str_hash_table_t *tab, const char *key,
                          void *value)
{
    char buf[16];
    xqc_str_hash_element_t e;

    /* the table copies the key: the caller's buffer does not outlive it */
    snprintf(buf, sizeof(buf), "%s", key);
    e.str.data = (unsigned char *)buf;
    e.str.len = strlen(buf);
    e.hash = xqc_siphash_get_hash(&tab->siphash_ctx, e.str.data, e.str.len);
    e.value = value;
    return xqc_str_hash_add(tab, e);
}

static void *
xqc_test_str_hash_find_key(xqc_str_hash_table_t *tab, const char *key)
{
    xqc_str_t str = {strlen(key), (unsigned char *)key};
    uint64_t hash = xqc_siphash_get_hash(&tab->siphash_ctx, str.data, str.len);

    return xqc_str_hash_find(tab, hash, str);
}

void
xqc_test_str_hash_release(void)
{
    xqc_test_str_hash_alloc_t alloc = {0};
    xqc_allocator_t allocator = {xqc_test_str_hash_malloc,
                                 xqc_test_str_hash_free, &alloc};
    uint8_t sipkey[XQC_SIPHASH_KEY_SIZE] = {0};
    xqc_log_t log = {0};
    xqc_str_hash_table_t tab;
    char key[16];
    int values[8];
    xqc_str_t deleted = {5, (unsigned char *)"key-3"};
    uint64_t hash;
    int ret;

    /* 8 elements in 4 buckets: several share a bucket */
    ret = xqc_str_hash_init(&tab, allocator, 4, 0, sipkey, sizeof(sipkey),
                            &log);
    CU_ASSERT_FATAL(ret == XQC_OK);
    for (int i = 0; i < 8; i++) {
        snprintf(key, sizeof(key), "key-%d", i);
        ret = xqc_test_str_hash_add_key(&tab, key, &values[i]);
        CU_ASSERT(ret == XQC_OK);
    }
    /* the bucket array, the conflict counters, a node and a key each */
    CU_ASSERT(alloc.live == 2 + 8 * 2);

    for (int i = 0; i < 8; i++) {
        snprintf(key, sizeof(key), "key-%d", i);
        CU_ASSERT(xqc_test_str_hash_find_key(&tab, key) == &values[i]);
    }

    hash = xqc_siphash_get_hash(&tab.siphash_ctx, deleted.data, deleted.len);
    ret = xqc_str_hash_delete(&tab, hash, deleted, &values[3]);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(xqc_test_str_hash_find_key(&tab, "key-3") == NULL);
    CU_ASSERT(alloc.live == 2 + 7 * 2);

    /* the release frees the 7 elements left, with the keys they copied */
    xqc_str_hash_release(&tab);
    CU_ASSERT(alloc.live == 0);
}

void
xqc_test_str_hash_release_after_add_failure(void)
{
    uint8_t sipkey[XQC_SIPHASH_KEY_SIZE] = {0};
    xqc_log_t log = {0};
    int values[3];
    int ret;

    /*
     * the second element cannot get its node (malloc call 5) or its key
     * (malloc call 6): it is not added, and the release frees the other
     * two elements and their keys
     */
    for (int fail_at = 5; fail_at <= 6; fail_at++) {
        xqc_test_str_hash_alloc_t alloc = {.fail_at = fail_at};
        xqc_allocator_t allocator = {xqc_test_str_hash_malloc,
                                     xqc_test_str_hash_free, &alloc};
        xqc_str_hash_table_t tab;

        ret = xqc_str_hash_init(&tab, allocator, 4, 0, sipkey, sizeof(sipkey),
                                &log);
        CU_ASSERT_FATAL(ret == XQC_OK);
        CU_ASSERT(xqc_test_str_hash_add_key(&tab, "a", &values[0]) == XQC_OK);
        ret = xqc_test_str_hash_add_key(&tab, "b", &values[1]);
        CU_ASSERT(ret == XQC_ERROR);
        CU_ASSERT(xqc_test_str_hash_add_key(&tab, "c", &values[2]) == XQC_OK);
        CU_ASSERT(alloc.live == 2 + 2 * 2);

        CU_ASSERT(xqc_test_str_hash_find_key(&tab, "a") == &values[0]);
        CU_ASSERT(xqc_test_str_hash_find_key(&tab, "b") == NULL);
        CU_ASSERT(xqc_test_str_hash_find_key(&tab, "c") == &values[2]);

        xqc_str_hash_release(&tab);
        CU_ASSERT(alloc.live == 0);
    }
}
