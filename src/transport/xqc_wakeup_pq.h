/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_WAKEUP_PQ_H_INCLUDED_
#define _XQC_WAKEUP_PQ_H_INCLUDED_

#include "src/transport/xqc_conn.h"
#include "src/common/xqc_malloc.h"
#include <memory.h>

typedef uint64_t xqc_pq_wakeup_time_t;

typedef struct {
    xqc_pq_wakeup_time_t wakeup_time;
    struct xqc_connection_s *conn;
} xqc_wakeup_pq_elem_t;

/* element compare function */
typedef int (*xqc_wakeup_pq_compare_ptr)(xqc_pq_wakeup_time_t a, xqc_pq_wakeup_time_t b);

/*
 * default element compare function, priority: a < b
 * higher priority first
 */
static inline int
xqc_wakeup_pq_default_cmp(xqc_pq_wakeup_time_t a, xqc_pq_wakeup_time_t b)
{
    return (a < b) ? 1 : 0;
}

/*
 * inverse element compare function, priority: a > b
 * lower priority first
 */
static inline int
xqc_wakeup_pq_revert_cmp(xqc_pq_wakeup_time_t a, xqc_pq_wakeup_time_t b)
{
    return (b < a) ? 1 : 0;
}

typedef struct xqc_wakeup_pq_s {
    char* elements;         /* elements */
    size_t element_size;    /* memory size of element objects */
    size_t count;           /* number of elements */
    size_t capacity;        /* element capacity */
    xqc_allocator_t a;      /* memory allocator */
    xqc_wakeup_pq_compare_ptr cmp; /* compare function */
} xqc_wakeup_pq_t;


#define xqc_wakeup_pq_element(pq, index) ((xqc_wakeup_pq_elem_t*)&(pq)->elements[(index) * (pq)->element_size])
#define xqc_wakeup_pq_element_copy(pq, dst, src) memmove(xqc_wakeup_pq_element((pq), (dst)), xqc_wakeup_pq_element((pq), (src)), (pq)->element_size)
#define xqc_wakeup_pq_default_capacity 16

static inline int
xqc_wakeup_pq_init(xqc_wakeup_pq_t *pq, size_t capacity, xqc_allocator_t a, xqc_wakeup_pq_compare_ptr cmp)
{
    size_t element_size = sizeof(xqc_wakeup_pq_elem_t);
    if (capacity == 0) {
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

    return 0;
}

static inline int
xqc_wakeup_pq_init_default(xqc_wakeup_pq_t *pq, xqc_allocator_t a, xqc_wakeup_pq_compare_ptr cmp)
{
    return xqc_wakeup_pq_init(pq, xqc_wakeup_pq_default_capacity, a, cmp);
}

static inline void
xqc_wakeup_pq_destroy(xqc_wakeup_pq_t *pq)
{
    pq->a.free(pq->a.opaque, pq->elements);
    pq->elements = NULL;
    pq->element_size = 0;
    pq->count = 0;
    pq->capacity = 0;
}

static inline void
xqc_wakeup_pq_element_swap(xqc_wakeup_pq_t *pq, size_t i, size_t j)
{
    char buf[pq->element_size];
    xqc_wakeup_pq_elem_t* p;
    p = xqc_wakeup_pq_element(pq, i);
    p->conn->wakeup_pq_index = j;
    p = xqc_wakeup_pq_element(pq, j);
    p->conn->wakeup_pq_index = i;

    memcpy(buf, xqc_wakeup_pq_element(pq, j), pq->element_size);
    memcpy(xqc_wakeup_pq_element(pq, j), xqc_wakeup_pq_element(pq, i), pq->element_size);
    memcpy(xqc_wakeup_pq_element(pq, i), buf, pq->element_size);
}

static inline xqc_wakeup_pq_elem_t *
xqc_wakeup_pq_push(xqc_wakeup_pq_t *pq, xqc_pq_wakeup_time_t wakeup_time, struct xqc_connection_s *conn)
{
    if (pq->count == pq->capacity) {
        size_t capacity = pq->capacity * 2;
        size_t size = capacity * pq->element_size;
        void* buf = pq->a.malloc(pq->a.opaque, size);
        if (buf == NULL) {
            return NULL;
        }
        memcpy(buf, pq->elements, pq->capacity * pq->element_size);
        pq->a.free(pq->a.opaque, pq->elements);
        pq->elements = buf;
        pq->capacity = capacity;
    }

    xqc_wakeup_pq_elem_t* p = xqc_wakeup_pq_element(pq, pq->count);
    p->wakeup_time = wakeup_time;
    p->conn = conn;
    conn->wakeup_pq_index = pq->count;

    size_t i = pq->count++;
    while (i != 0) {
        int j = (i - 1) / 2;
        if (!pq->cmp(xqc_wakeup_pq_element(pq, j)->wakeup_time, xqc_wakeup_pq_element(pq, i)->wakeup_time))
            break;

        xqc_wakeup_pq_element_swap(pq, i, j);

        i = j;
    }

    return xqc_wakeup_pq_element(pq, i);
}

static inline xqc_wakeup_pq_elem_t *
xqc_wakeup_pq_top(xqc_wakeup_pq_t *pq)
{
    if (pq->count == 0) {
        return NULL;
    }
    return xqc_wakeup_pq_element(pq, 0);
}

static inline int
xqc_wakeup_pq_empty(xqc_wakeup_pq_t *pq)
{
    return pq->count == 0 ? 1 : 0;
}

static inline void
xqc_wakeup_pq_pop(xqc_wakeup_pq_t *pq)
{
    if (pq->count == 0 || --pq->count == 0) {
        return;
    }

    xqc_wakeup_pq_element_copy(pq, 0, pq->count);
    xqc_wakeup_pq_elem_t* p = xqc_wakeup_pq_element(pq, 0);
    p->conn->wakeup_pq_index = 0;

    int i = 0, j = 2 * i + 1;
    while (j <= pq->count - 1) {
        if (j < pq->count - 1 && pq->cmp(xqc_wakeup_pq_element(pq, j)->wakeup_time, xqc_wakeup_pq_element(pq, j+1)->wakeup_time)) {
            ++j;
        }

        if (!pq->cmp(xqc_wakeup_pq_element(pq, i)->wakeup_time, xqc_wakeup_pq_element(pq, j)->wakeup_time)) {
            break;
        }

        xqc_wakeup_pq_element_swap(pq, i, j);

        i = j;
        j = 2 * i + 1;
    }
}

static inline void
xqc_wakeup_pq_remove(xqc_wakeup_pq_t *pq, struct xqc_connection_s *conn)
{
    unsigned pq_index = conn->wakeup_pq_index;
    if (pq_index >= pq->count || pq->count == 0 || --pq->count == 0) {
        return;
    }

    xqc_wakeup_pq_element_copy(pq, pq_index, pq->count);
    xqc_wakeup_pq_elem_t* p = xqc_wakeup_pq_element(pq, pq_index);
    p->conn->wakeup_pq_index = pq_index;

    int i = pq_index, j = 2 * i + 1;
    while (j <= pq->count - 1) {
        if (j < pq->count - 1 && pq->cmp(xqc_wakeup_pq_element(pq, j)->wakeup_time, xqc_wakeup_pq_element(pq, j+1)->wakeup_time)) {
            ++j;
        }

        if (!pq->cmp(xqc_wakeup_pq_element(pq, i)->wakeup_time, xqc_wakeup_pq_element(pq, j)->wakeup_time)) {
            break;
        }

        xqc_wakeup_pq_element_swap(pq, i, j);

        i = j;
        j = 2 * i + 1;
    }

    i = pq_index;
    while (i != 0) {
        j = (i - 1)/2;
        if (!pq->cmp(xqc_wakeup_pq_element(pq, j)->wakeup_time, xqc_wakeup_pq_element(pq, i)->wakeup_time)) {
            break;
        }

        xqc_wakeup_pq_element_swap(pq, i, j);
        i = j;
    }
}

#undef xqc_wakeup_pq_element
#undef xqc_wakeup_pq_element_copy

#endif /* _XQC_WAKEUP_PQ_H_INCLUDED_ */
