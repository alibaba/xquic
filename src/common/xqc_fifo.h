/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_H_FIFO_INCLUDED_
#define _XQC_H_FIFO_INCLUDED_

#include <stdint.h>

#include "src/common/xqc_memory_pool.h"
#include "src/common/xqc_common.h"

/*
 * FIFO Queue
 * The elements in it can be of any type, including int, char, void*, and custom structs.
 * 
 * Interfaces:
 * xqc_fifo_init, xqc_fifo_release
 * xqc_fifo_length, xqc_fifo_full, xqc_fifo_empty
 * xqc_fifo_push, xqc_fifo_top, xqc_fifo_pop
 * xqc_fifo_push_typeX, xqc_fifo_top_typeX
 */

typedef struct {
    char           *buf;            /* buffer */
    unsigned int    in;             /* cursor for input */
    unsigned int    out;            /* cursor for output */
    unsigned int    element_size;   /* element size */
    unsigned int    capacity;       /* element capacity */
    xqc_allocator_t allocator;      /* memory allocator */
} xqc_fifo_t; 


static inline size_t
xqc_fifo_roundup(size_t i)
{
    unsigned int n = 2;
    while (n < i) n *= 2;
    return n;
}


static inline int
xqc_fifo_init(xqc_fifo_t *fifo, xqc_allocator_t allocator, size_t element_size, size_t capacity)
{
    if (capacity & (capacity - 1)) {
        capacity = xqc_fifo_roundup(capacity);
    }

    fifo->allocator = allocator;
    fifo->buf = allocator.malloc(allocator.opaque, element_size * capacity);
    if (fifo->buf == NULL) {
        return XQC_ERROR;
    }

    fifo->in = 0;
    fifo->out = 0;
    fifo->element_size = element_size;
    fifo->capacity = capacity;

    return XQC_OK;
}

static inline void
xqc_fifo_release(xqc_fifo_t *fifo)
{
    xqc_allocator_t *a = &fifo->allocator;
    a->free(a->opaque, fifo->buf);
    fifo->buf = NULL;
}

static inline size_t
xqc_fifo_length(const xqc_fifo_t *fifo)
{
    return fifo->in - fifo->out;
}

static inline int
xqc_fifo_full(const xqc_fifo_t *fifo)
{
    return xqc_fifo_length(fifo) >= fifo->capacity ? XQC_TRUE : XQC_FALSE;
}

static inline int
xqc_fifo_empty(const xqc_fifo_t *fifo)
{
    return xqc_fifo_length(fifo) == 0 ? XQC_TRUE : XQC_FALSE;
}

static inline int
xqc_fifo_push(xqc_fifo_t *fifo, void *buf, size_t size)
{
    if (fifo->element_size != size) {
        return XQC_ERROR;
    }

    if (xqc_fifo_full(fifo)) {
        return XQC_ERROR;
    }

    memcpy(fifo->buf + fifo->in++ % fifo->capacity * fifo->element_size, buf, size);

    return XQC_OK;
}

static inline int
xqc_fifo_pop(xqc_fifo_t *fifo)
{
    if (xqc_fifo_empty(fifo) == XQC_TRUE) {
        return XQC_ERROR;
    }

    if (++fifo->out == fifo->in) {
        fifo->in = fifo->out = 0;
    }

    return XQC_OK;
}

static inline void *
xqc_fifo_top(xqc_fifo_t *fifo)
{
    if (xqc_fifo_empty(fifo) == XQC_TRUE) {
        return NULL;
    }

    return fifo->buf + fifo->out % fifo->capacity * fifo->element_size;
}

static inline void *
xqc_fifo_top_ptr(xqc_fifo_t *fifo)
{
    assert(fifo->element_size == sizeof(void*));
    return *(void **)xqc_fifo_top(fifo);
}

static inline int
xqc_fifo_top_int(xqc_fifo_t *fifo)
{
    assert(fifo->element_size == sizeof(int));
    return *(int *)xqc_fifo_top(fifo);
}

static inline unsigned int
xqc_fifo_top_uint(xqc_fifo_t *fifo)
{
    assert(fifo->element_size == sizeof(unsigned int));
    return *(unsigned int*)xqc_fifo_top(fifo);
}

static inline long
xqc_fifo_top_long(xqc_fifo_t *fifo)
{
    assert(fifo->element_size == sizeof(long));
    return *(long *)xqc_fifo_top(fifo);
}

static inline unsigned long
xqc_fifo_top_ulong(xqc_fifo_t *fifo)
{
    assert(fifo->element_size == sizeof(unsigned long));
    return *(unsigned long *)xqc_fifo_top(fifo);
}

static inline int8_t
xqc_fifo_top_int8(xqc_fifo_t *fifo)
{
    assert(fifo->element_size == sizeof(int8_t));
    return *(int8_t *)xqc_fifo_top(fifo);
}

static inline uint8_t
xqc_fifo_top_uint8(xqc_fifo_t *fifo)
{
    assert(fifo->element_size == sizeof(uint8_t));
    return *(uint8_t *)xqc_fifo_top(fifo);
}

static inline int16_t
xqc_fifo_top_int16(xqc_fifo_t *fifo)
{
    assert(fifo->element_size == sizeof(int16_t));
    return *(int16_t*)xqc_fifo_top(fifo);
}

static inline uint16_t
xqc_fifo_top_uint16(xqc_fifo_t *fifo)
{
    assert(fifo->element_size == sizeof(uint16_t));
    return *(uint16_t *)xqc_fifo_top(fifo);
}

static inline int32_t
xqc_fifo_top_int32(xqc_fifo_t *fifo)
{
    assert(fifo->element_size == sizeof(int32_t));
    return *(int32_t *)xqc_fifo_top(fifo);
}

static inline uint32_t
xqc_fifo_top_uint32(xqc_fifo_t *fifo)
{
    assert(fifo->element_size == sizeof(uint32_t));
    return *(uint32_t *)xqc_fifo_top(fifo);
}

static inline int64_t
xqc_fifo_top_int64(xqc_fifo_t *fifo)
{
    assert(fifo->element_size == sizeof(int64_t));
    return *(int64_t *)xqc_fifo_top(fifo);
}

static inline uint64_t
xqc_fifo_top_uint64(xqc_fifo_t *fifo)
{
    assert(fifo->element_size == sizeof(uint64_t));
    return *(uint64_t *)xqc_fifo_top(fifo);
}

static inline int
xqc_fifo_push_ptr(xqc_fifo_t *fifo, void *ptr)
{
    return xqc_fifo_push(fifo, &ptr, sizeof(ptr));
}

static inline int
xqc_fifo_push_int(xqc_fifo_t *fifo, int i)
{
    return xqc_fifo_push(fifo, &i, sizeof(i));
}

static inline int
xqc_fifo_push_uint(xqc_fifo_t *fifo, unsigned int i)
{
    return xqc_fifo_push(fifo, &i, sizeof(i));
}

static inline int
xqc_fifo_push_long(xqc_fifo_t *fifo, long i)
{
    return xqc_fifo_push(fifo, &i, sizeof(i));
}

static inline int
xqc_fifo_push_ulong(xqc_fifo_t *fifo, unsigned long i)
{
    return xqc_fifo_push(fifo, &i, sizeof(i));
}

static inline int
xqc_fifo_push_int8(xqc_fifo_t *fifo, int8_t i)
{
    return xqc_fifo_push(fifo, &i, sizeof(i));
}

static inline int
xqc_fifo_push_uint8(xqc_fifo_t *fifo, uint8_t i)
{
    return xqc_fifo_push(fifo, &i, sizeof(i));
}

static inline int
xqc_fifo_push_int16(xqc_fifo_t *fifo, int16_t i)
{
    return xqc_fifo_push(fifo, &i, sizeof(i));
}

static inline int
xqc_fifo_push_uint16(xqc_fifo_t *fifo, uint16_t i)
{
    return xqc_fifo_push(fifo, &i, sizeof(i));
}

static inline int
xqc_fifo_push_int32(xqc_fifo_t *fifo, int32_t i)
{
    return xqc_fifo_push(fifo, &i, sizeof(i));
}

static inline int
xqc_fifo_push_uint32(xqc_fifo_t *fifo, uint32_t i)
{
    return xqc_fifo_push(fifo, &i, sizeof(i));
}

static inline int
xqc_fifo_push_int64(xqc_fifo_t *fifo, int64_t i)
{
    return xqc_fifo_push(fifo, &i, sizeof(i));
}

static inline int
xqc_fifo_push_uint64(xqc_fifo_t *fifo, uint64_t i)
{
    return xqc_fifo_push(fifo, &i, sizeof(i));
}

#endif /*_XQC_H_FIFO_INCLUDED_*/

