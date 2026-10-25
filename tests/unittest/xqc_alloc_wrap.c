/*
 * Allocation failures for unit tests (see xqc_alloc_wrap.h).
 */

#include <stddef.h>
#include "xqc_alloc_wrap.h"

#ifdef XQC_TEST_ALLOC_WRAP

long xqc_test_alloc_count = -1;     /* -1: not counting */
long xqc_test_alloc_fail_at;
int  xqc_test_alloc_failed;

void *__real_malloc(size_t size);
void *__real_calloc(size_t nmemb, size_t size);
void *__real_realloc(void *ptr, size_t size);

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

void *
__wrap_malloc(size_t size)
{
    return xqc_test_alloc_should_fail() ? NULL : __real_malloc(size);
}

void *
__wrap_calloc(size_t nmemb, size_t size)
{
    return xqc_test_alloc_should_fail() ? NULL : __real_calloc(nmemb, size);
}

void *
__wrap_realloc(void *ptr, size_t size)
{
    return xqc_test_alloc_should_fail() ? NULL : __real_realloc(ptr, size);
}

#endif
