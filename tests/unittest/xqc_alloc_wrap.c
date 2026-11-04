/*
 * Allocation failures and counts for unit tests (see xqc_alloc_wrap.h).
 */

#include <stddef.h>
#include "xqc_alloc_wrap.h"

#ifdef XQC_TEST_ALLOC_WRAP

long xqc_test_alloc_count = -1;     /* -1: not counting */
long xqc_test_alloc_fail_at;
int  xqc_test_alloc_failed;
int  xqc_test_alloc_tracking;
long xqc_test_alloc_live;

void *__real_malloc(size_t size);
void *__real_calloc(size_t nmemb, size_t size);
void *__real_realloc(void *ptr, size_t size);
void __real_free(void *ptr);

static int
xqc_test_alloc_should_fail(void)
{
    if (xqc_test_alloc_count < 0) {
        return 0;
    }
    if (++xqc_test_alloc_count == xqc_test_alloc_fail_at) {
        xqc_test_alloc_failed = 1;
        return 1;
    }
    return 0;
}

static void *
xqc_test_alloc_track(void *ptr)
{
    if (xqc_test_alloc_tracking && ptr != NULL) {
        xqc_test_alloc_live++;
    }
    return ptr;
}

void *
__wrap_malloc(size_t size)
{
    if (xqc_test_alloc_should_fail()) {
        return NULL;
    }
    return xqc_test_alloc_track(__real_malloc(size));
}

void *
__wrap_calloc(size_t nmemb, size_t size)
{
    if (xqc_test_alloc_should_fail()) {
        return NULL;
    }
    return xqc_test_alloc_track(__real_calloc(nmemb, size));
}

void *
__wrap_realloc(void *ptr, size_t size)
{
    if (xqc_test_alloc_should_fail()) {
        return NULL;
    }
    /* resizing keeps the allocation that was counted when it was made */
    if (ptr == NULL) {
        return xqc_test_alloc_track(__real_realloc(ptr, size));
    }
    return __real_realloc(ptr, size);
}

void
__wrap_free(void *ptr)
{
    if (xqc_test_alloc_tracking && ptr != NULL) {
        xqc_test_alloc_live--;
    }
    __real_free(ptr);
}

#endif
