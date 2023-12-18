/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_MEMORY_POOL_H_INCLUDED_
#define _XQC_MEMORY_POOL_H_INCLUDED_

#include <string.h>
#include <stdint.h>
#include <xquic/xquic.h>

#include "src/common/xqc_malloc.h"

#ifdef XQC_PROTECT_POOL_MEM
#ifndef XQC_SYS_WINDOWS
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>
#endif
#endif

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
#ifdef XQC_PROTECT_POOL_MEM
    xqc_bool_t          protect_block;
    size_t              page_size;
#endif
} xqc_memory_pool_t;

#define XQC_MAX_MALLOC_FROM_POOL (4096)

#ifdef XQC_PROTECT_POOL_MEM
static inline void *
xqc_mempool_malloc_protected(size_t size, size_t page_sz)
{
#ifndef XQC_SYS_WINDOWS
    int ret;
    void *ptr = NULL;
    ret = posix_memalign(&ptr, page_sz, page_sz + size);
    if (ret != 0) {
        return NULL;
    }
    ret = mprotect(ptr, page_sz, PROT_READ);
    if (ret != 0) {
        xqc_free(ptr);
        return NULL;
    }
    return (void*)((char*)ptr + page_sz);
#else
    return xqc_malloc(size);
#endif
}

static inline void
xqc_mempool_free_protected(void* ptr, size_t page_sz) {
#ifndef XQC_SYS_WINDOWS
    void *start;
    int ret;
    start = (void*)((char*)ptr - page_sz);
    ret = mprotect(start, page_sz, PROT_READ | PROT_WRITE | PROT_EXEC);
    assert(ret == 0);
    xqc_free(start);
#else
    xqc_free(ptr);
#endif
}
#endif

#ifdef XQC_PROTECT_POOL_MEM
static inline xqc_memory_pool_t *
xqc_create_pool(size_t size, xqc_bool_t protect_block)
#else
static inline xqc_memory_pool_t *
xqc_create_pool(size_t size)
#endif
{
    if (size <= sizeof(xqc_memory_pool_t)) {
        return NULL;
    }

#ifdef XQC_PROTECT_POOL_MEM
    char *m;
#ifndef XQC_SYS_WINDOWS
    size_t page_sz = sysconf(_SC_PAGESIZE);
#else
    size_t page_sz = 4096;
#endif
    if (protect_block) {
        m = xqc_mempool_malloc_protected(size, page_sz);
    } else {
        m = xqc_malloc(size);
    }
#else
    char *m = xqc_malloc(size);
#endif
    if (m == NULL) {
        return NULL;
    }

    xqc_memory_pool_t *pool = (xqc_memory_pool_t *)m;
    pool->block.last = m + sizeof(xqc_memory_pool_t);
    pool->block.end = m + size;
    pool->block.failed = 0;
    pool->block.next = NULL;
#ifdef XQC_PROTECT_POOL_MEM
    pool->protect_block = protect_block;
    pool->page_size = page_sz;
#endif

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
#ifdef XQC_PROTECT_POOL_MEM
        if (pool->protect_block) {
            xqc_mempool_free_protected(p, pool->page_size);

        } else {
            xqc_free(p); 
        }
#else
        xqc_free(p);
#endif
    }

    xqc_memory_large_t *large = pool->large;
    while (large) {
        xqc_memory_large_t * p = large;
        large = large->next;
#ifdef XQC_PROTECT_POOL_MEM
        if (pool->protect_block) {
            xqc_mempool_free_protected(p, pool->page_size);
            
        } else {
            xqc_free(p); 
        }
#else
        xqc_free(p);
#endif
    }

#ifdef XQC_PROTECT_POOL_MEM
    if (pool->protect_block) {
        xqc_mempool_free_protected(pool, pool->page_size);
        
    } else {
        xqc_free(pool); 
    }
#else
        xqc_free(pool);
#endif
}

static inline void *
xqc_palloc_large(xqc_memory_pool_t *pool, size_t size)
{
#ifdef XQC_PROTECT_POOL_MEM
    xqc_memory_large_t *p;
    if (pool->protect_block) {
        p = xqc_mempool_malloc_protected(size + sizeof(xqc_memory_large_t), pool->page_size);
        
    } else {
        p = xqc_malloc(size + sizeof(xqc_memory_large_t));
    }
#else
    xqc_memory_large_t *p = xqc_malloc(size + sizeof(xqc_memory_large_t));
#endif

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

#ifdef XQC_PROTECT_POOL_MEM
    char *m;
    if (pool->protect_block) {
        m = xqc_mempool_malloc_protected(psize, pool->page_size);
        
    } else {
        m = xqc_malloc(psize);
    }
#else
    char *m = xqc_malloc(psize);
#endif
    
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
            char *p = xqc_align_ptr(block->last, XQC_ALIGNMENT);
            if (block->end > p && (size_t)(block->end - p) >= size) {
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
            if (block->end > p && (size_t)(block->end - p) >= size) {
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

/* TODO: xqc_pfree is needed */

#endif /*_XQC_MEMORY_POOL_H_INCLUDED_*/

