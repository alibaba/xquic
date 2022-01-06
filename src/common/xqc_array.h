/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_H_ARRAY_INCLUDED_
#define _XQC_H_ARRAY_INCLUDED_

#include <string.h>

#include "src/common/xqc_malloc.h"

/* dynamic arrays with contiguous memory at the bottom */
typedef struct xqc_array_s {
    void               *elts;       /* pointer to first element */
    unsigned            elt_size;   /* size of each element */
    unsigned            size;       /* number of elements */
    unsigned            capacity;   /* capacity of elements */
    xqc_allocator_t     allocator;  /* memory allocator */
} xqc_array_t;


static inline xqc_array_t *
xqc_array_create(xqc_allocator_t allocator, size_t elt_capacity, size_t elt_size)
{
    xqc_array_t *a = allocator.malloc(allocator.opaque, sizeof(xqc_array_t));
    if (a == NULL) {
        return NULL;
    }

    a->elts = allocator.malloc(allocator.opaque, elt_capacity * elt_size);
    if (a->elts == NULL) {
        allocator.free(allocator.opaque, a);
        return NULL;
    }

    a->elt_size = elt_size;
    a->size = 0;
    a->capacity = elt_capacity;
    a->allocator = allocator;

    return a;
}

static inline void
xqc_array_destroy(xqc_array_t *a)
{
    a->allocator.free(a->allocator.opaque, a->elts);
    a->allocator.free(a->allocator.opaque, a);
}

static inline void *
xqc_array_push_n(xqc_array_t *a, size_t n)
{
    if (a->size + n > a->capacity) {

        size_t new_capacity = (a->capacity >= n ? a->capacity : n) * 2;
        void *p = a->allocator.malloc(a->allocator.opaque, a->elt_size * new_capacity);
        if (p == NULL) {
            return NULL;
        }

        memcpy(p, a->elts, a->elt_size * a->size);

        a->allocator.free(a->allocator.opaque, a->elts);

        a->elts = p;
        a->capacity = new_capacity;
    }

    void *p = (char *)a->elts + a->elt_size * a->size;
    a->size += n;

    return p;
}

static inline void *
xqc_array_push(xqc_array_t *a)
{
    return xqc_array_push_n(a, 1);
}

#endif /*_XQC_H_ARRAY_INCLUDED_*/
