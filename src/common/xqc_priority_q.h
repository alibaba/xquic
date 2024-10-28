/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_H_PRIORITY_Q_INCLUDED_
#define _XQC_H_PRIORITY_Q_INCLUDED_

#include <string.h>
#include <stdint.h>

#include "src/common/xqc_malloc.h"
#include "src/common/xqc_str.h"

/* Priority Queue based on Binary Heap
 *
 * Interfaces:
 * xqc_pq_init()
 * xqc_pq_push()
 * xqc_pq_pop()
 * xqc_pq_top()
 * xqc_pq_empty()
 * xqc_pq_remove()
 */

typedef uint64_t xqc_pq_key_t;
typedef struct xqc_priority_queue_s xqc_pq_t;

typedef struct xqc_priority_queue_element_s {
    xqc_pq_key_t    key;
    char            data[0];
} xqc_pq_element_t;

/* element compare function */
typedef int (*xqc_pq_compare_ptr)(xqc_pq_key_t a, xqc_pq_key_t b);
typedef int (*xqc_pq_element_op_t)(xqc_pq_t *pq, xqc_pq_element_t *e);

/* default element compare function, priority: a < b */
static inline int
xqc_pq_default_cmp(xqc_pq_key_t a, xqc_pq_key_t b)
{
    return (a < b) ? 1 : 0;
}

/* revert element compare function, priority: b < a */
static inline int
xqc_pq_revert_cmp(xqc_pq_key_t a, xqc_pq_key_t b)
{
    return (b < a) ? 1 : 0;
}

typedef struct xqc_priority_queue_s {
    char               *elements;       /* elements */
    size_t              element_size;   /* memory size of element objects */
    size_t              count;          /* number of elements */
    size_t              capacity;       /* capacity */
    xqc_allocator_t     a;              /* memory allocator */
    xqc_pq_compare_ptr  cmp;            /* compare function */
    xqc_pq_element_op_t eop;            /* callback function to operate element */
} xqc_pq_t;

#define xqc_pq_element(pq, index) ((xqc_pq_element_t *)&(pq)->elements[(index) * (pq)->element_size])
#define xqc_pq_element_index(pq, elem) ((((char*)elem) - pq->elements) / pq->element_size)
#define xqc_pq_element_copy(pq, dst, src) (xqc_memcpy(xqc_pq_element((pq), (dst)), xqc_pq_element((pq), (src)), (pq)->element_size))
#define xqc_pq_element_init(pq, elem, key, data) \
    xqc_memzero(elem, pq->element_size); \
    elem->key = key; \
    if (data != NULL) { \
        xqc_memcpy(elem->data, (char*)data, pq->element_size - sizeof(elem->key)); \
    }

#define xqc_pq_default_capacity 16

static inline int
xqc_pq_init(xqc_pq_t *pq, size_t element_size, 
    size_t capacity, xqc_allocator_t a, xqc_pq_compare_ptr cmp,
    xqc_pq_element_op_t eop)
{
    if (element_size < sizeof(xqc_pq_element_t) || capacity == 0) {
        return -1;
    }

   pq->elements = a.malloc(a.opaque, element_size * capacity);
   if (pq->elements == NULL) {
       return -2;
   }

   pq->element_size = element_size;
   pq->count = 0;
   pq->capacity = capacity;
   pq->a = a;
   pq->cmp = cmp;
   pq->eop = eop;

   return 0;
}

static inline void
xqc_pq_destroy(xqc_pq_t *pq)
{
    pq->a.free(pq->a.opaque, pq->elements);
    pq->elements = NULL;
    pq->element_size = 0;
    pq->count = 0;
    pq->capacity = 0;
    pq->cmp = NULL;
    pq->eop = NULL;
}

static inline void
xqc_pq_element_swap(xqc_pq_t *pq, size_t i, size_t j)
{
#if !defined(XQC_SYS_WINDOWS) || defined(XQC_ON_MINGW)
    char buf[pq->element_size];
#else
    char *buf = (char *)_alloca(pq->element_size);
#endif

    memcpy(buf, xqc_pq_element(pq, j), pq->element_size);
    memcpy(xqc_pq_element(pq, j), xqc_pq_element(pq, i), pq->element_size);
    memcpy(xqc_pq_element(pq, i), buf, pq->element_size);

    if (pq->eop) {
        pq->eop(pq, xqc_pq_element(pq, i));
        pq->eop(pq, xqc_pq_element(pq, j));
    }
}

static inline uint32_t
xqc_pq_move_towards_top(xqc_pq_t *pq, uint32_t i)
{
    uint32_t j;
    while (i != 0) {
        j = (i - 1) / 2;

        if (!pq->cmp(xqc_pq_element(pq, j)->key, xqc_pq_element(pq, i)->key))
            break;

        xqc_pq_element_swap(pq, i, j);

        i = j;
    }
    return i;
}

static inline void
xqc_pq_move_towards_bottom(xqc_pq_t *pq, uint32_t i)
{
    uint32_t j = 2 * i + 1;
    while (j <= pq->count - 1) {
        if (j < pq->count - 1 && pq->cmp(xqc_pq_element(pq, j)->key, xqc_pq_element(pq, j+1)->key)) {
            ++j;
        }

        if (!pq->cmp(xqc_pq_element(pq, i)->key, xqc_pq_element(pq, j)->key)) {
            break;
        }

        xqc_pq_element_swap(pq, i, j);

        i = j;
        j = 2 * i + 1;
    }
}

static inline xqc_pq_element_t *
xqc_pq_push(xqc_pq_t *pq, xqc_pq_key_t key, const void *data)
{
    if (pq->count == pq->capacity) {
        size_t capacity = pq->capacity * 2;
        size_t size = capacity * pq->element_size;
        void *buf = pq->a.malloc(pq->a.opaque, size);
        if (buf == NULL) {
            return NULL;
        }

        memcpy(buf, pq->elements, pq->capacity * pq->element_size);
        pq->a.free(pq->a.opaque, pq->elements);
        pq->elements = buf;
        pq->capacity = capacity;
    }

    xqc_pq_element_t *p = xqc_pq_element(pq, pq->count);
    xqc_pq_element_init(pq, p, key, data);

    if (pq->eop) {
        pq->eop(pq, p);
    }

    size_t i = pq->count++;
    i = xqc_pq_move_towards_top(pq, i);

    return xqc_pq_element(pq, i);
}

static inline xqc_pq_element_t *
xqc_pq_top(xqc_pq_t *pq)
{
    if (pq->count == 0) {
        return NULL;
    }
    return xqc_pq_element(pq, 0);
}

static inline int
xqc_pq_empty(xqc_pq_t *pq)
{
    return pq->count == 0 ? 1 : 0;
}

static inline void
xqc_pq_pop(xqc_pq_t *pq)
{
    if (pq->count == 0 || --pq->count == 0) {
        return;
    }

    xqc_pq_element_copy(pq, 0, pq->count);
    
    if (pq->eop) {
        pq->eop(pq, xqc_pq_element(pq, 0));
    }

    xqc_pq_move_towards_bottom(pq, 0);
}


static inline void
xqc_pq_remove(xqc_pq_t *pq, uint32_t index)
{
    if (index >= pq->count || pq->count == 0 || --pq->count == 0) {
        return;
    }

    xqc_pq_element_copy(pq, index, pq->count);
    xqc_pq_element_t *p = xqc_pq_element(pq, index);

    if (pq->eop) {
        pq->eop(pq, p);
    }

    xqc_pq_move_towards_bottom(pq, index);
    xqc_pq_move_towards_top(pq, index);
}

#endif /*_XQC_H_PRIORITY_Q_INCLUDED_*/
