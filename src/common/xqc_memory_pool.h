/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_MEMORY_POOL_H_INCLUDED_
#define _XQC_MEMORY_POOL_H_INCLUDED_

#include <string.h>
#include <stdint.h>

#include "src/common/xqc_malloc.h"

/* Interfaces:
 * xqc_memory_pool_t *xqc_create_pool(size_t size)
 * void xqc_destroy_pool(xqc_memory_pool_t* pool)
 * void* xqc_palloc(xqc_memory_pool_t *pool, size_t size)
 * void* xqc_pnalloc(xqc_memory_pool_t *pool, size_t size)
 * void* xqc_pcalloc(xqc_memory_pool_t *pool, size_t size)
 */

typedef struct xqc_memory_block_s {
    char       *last;
    char       *end;
    unsigned    failed;
    struct xqc_memory_block_s *next;
} xqc_memory_block_t;

typedef struct xqc_memory_large_s {
    struct xqc_memory_large_s *next;
    unsigned    size;
    char        data[0];
} xqc_memory_large_t;

typedef struct xqc_memory_pool_s {
    xqc_memory_block_t  block;
    xqc_memory_block_t *current;
    xqc_memory_large_t *large;  /* large chunk list */
    size_t              max;
} xqc_memory_pool_t;

#define XQC_MAX_MALLOC_FROM_POOL (4096)


static inline xqc_memory_pool_t *
xqc_create_pool(size_t size)
{
    if (size <= sizeof(xqc_memory_pool_t)) {
        return NULL;
    }

    char *m = xqc_malloc(size);
    if (m == NULL) {
        return NULL;
    }

    xqc_memory_pool_t *pool = (xqc_memory_pool_t *)m;
    pool->block.last = m + sizeof(xqc_memory_pool_t);
    pool->block.end = m + size;
    pool->block.failed = 0;
    pool->block.next = NULL;

    pool->current = &pool->block;
    pool->large = NULL;
    pool->max = size - sizeof(xqc_memory_pool_t);
    if (pool->max > XQC_MAX_MALLOC_FROM_POOL) {
        pool->max = XQC_MAX_MALLOC_FROM_POOL;
    }

    return pool;
}

static inline void
xqc_destroy_pool(xqc_memory_pool_t *pool)
{
    xqc_memory_block_t *block = pool->block.next;
    while (block) {
        xqc_memory_block_t *p = block;
        block = block->next;
        xqc_free(p);
    }

    xqc_memory_large_t *large = pool->large;
    while (large) {
        xqc_memory_large_t * p = large;
        large = large->next;
        xqc_free(p);
    }

    xqc_free(pool);
}

static inline void *
xqc_palloc_large(xqc_memory_pool_t *pool, size_t size)
{
    xqc_memory_large_t *p = xqc_malloc(size + sizeof(xqc_memory_large_t));
    if (p == NULL) {
        return NULL;
    }

    p->size = size;
    p->next = pool->large;
    pool->large = p;

    return p->data;
}

#define XQC_ALIGNMENT (16)
#define xqc_align_ptr(p, a) ((char *) (((uintptr_t)(p) + ((uintptr_t)a - 1)) & ~((uintptr_t)a - 1)))

static inline void *
xqc_palloc_block(xqc_memory_pool_t *pool, size_t size)
{
    size_t psize = pool->block.end - (char *)pool;

    char *m = xqc_malloc(psize);
    if (m == NULL) {
        return NULL;
    }

    xqc_memory_block_t *b = (xqc_memory_block_t *)m;

    b->end = m + psize;

    m += sizeof(xqc_memory_block_t);
    m = xqc_align_ptr(m, XQC_ALIGNMENT);

    b->last = m + size;
    b->failed = 0;
    b->next = NULL;

    xqc_memory_block_t *block = pool->current;
    for (; block->next; block = block->next) {
        if (++block->failed > 4) {
            pool->current = block->next;
        }
    }

    block->next = b;

    return m;
}

/* aligned memory block access may be faster */
static inline void *
xqc_palloc(xqc_memory_pool_t *pool, size_t size)
{
    if (size < pool->max) {
        xqc_memory_block_t * block = pool->current;

        do {
            char* p = xqc_align_ptr(block->last, XQC_ALIGNMENT);
            if ((size_t)(block->end - p) >= size) {
                block->last = p + size;
                return p;
            }

            block = block->next;
        } while (block);

        return xqc_palloc_block(pool, size);
    }

    return xqc_palloc_large(pool, size);
}

/* allocate memory interface from pool, no alignment */
static inline void *
xqc_pnalloc(xqc_memory_pool_t *pool, size_t size)
{
    if (size < pool->max) {
        xqc_memory_block_t * block = pool->current;

        do {
            char *p = block->last;
            if ((size_t)(block->end - p) >= size) {
                block->last = p + size;
                return p;
            }

            block = block->next;
        } while (block);

        return xqc_palloc_block(pool, size);
    }

    return xqc_palloc_large(pool, size);
}

/* aligned and zeroed out */
static inline void *
xqc_pcalloc(xqc_memory_pool_t *pool, size_t size)
{
    void* p = xqc_palloc(pool, size);
    if (p) {
        memset(p, 0, size);
        return p;
    }
    return NULL;
}

#endif /*_XQC_MEMORY_POOL_H_INCLUDED_*/

