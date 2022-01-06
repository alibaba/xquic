/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_INT_HASH_H_INCLUDED_
#define _XQC_INT_HASH_H_INCLUDED_

#include <stdint.h>
#include <math.h>

#include "src/common/xqc_common.h"
#include "src/common/xqc_memory_pool.h"


typedef struct xqc_id_hash_element_s {
    uint64_t                    hash;
    void                       *value;
} xqc_id_hash_element_t;


typedef struct xqc_id_hash_node_s {
    struct xqc_id_hash_node_s  *next;
    xqc_id_hash_element_t       element;
} xqc_id_hash_node_t;

typedef struct xqc_id_hash_table_s {
    xqc_id_hash_node_t        **list;
    size_t                      count;
    size_t                      mask;
    xqc_allocator_t             allocator;
} xqc_id_hash_table_t;


/* make n to 2 pow  */
static inline int
xqc_pow2(unsigned int n)
{
    int clz , power = sizeof(n);
    if (__builtin_popcount(n) <= 1) {
        return n ;
    }
    clz     = __builtin_clz(n);
    power   = (power << 3) - clz ;
    return pow(2 , power);
}


static inline xqc_int_t
xqc_id_hash_init(xqc_id_hash_table_t *hash_tab,  xqc_allocator_t allocator, size_t bucket_num)
{
    hash_tab->allocator = allocator;
    bucket_num = xqc_pow2(bucket_num);
    hash_tab->list = allocator.malloc(allocator.opaque, sizeof(xqc_id_hash_node_t *) * bucket_num);
    if (hash_tab->list == NULL) {
        return XQC_ERROR;
    }
    memset(hash_tab->list, 0, sizeof(xqc_id_hash_node_t *) * bucket_num);
    hash_tab->count = bucket_num;
    hash_tab->mask  = bucket_num - 1;
    return XQC_OK;
}


static inline void
xqc_id_hash_release(xqc_id_hash_table_t *hash_tab)
{
    xqc_allocator_t *a = &hash_tab->allocator;
    for (size_t i = 0; i < hash_tab->count; ++i) {
        xqc_id_hash_node_t *node = hash_tab->list[i];
        while (node) {
            xqc_id_hash_node_t *p = node;
            if (node->next == node) {
                break;
            }
            node = node->next;
            a->free(a->opaque, p);
        }
    }
    a->free(a->opaque, hash_tab->list);
}


static inline void *
xqc_id_hash_find(xqc_id_hash_table_t *hash_tab, uint64_t hash)
{
    uint64_t index = hash & hash_tab->mask;
    xqc_id_hash_node_t *node = hash_tab->list[index];

    while (node) {
        if (node->element.hash == hash) {
            return node->element.value;
        }

        if (node->next == node) {
            return NULL;
        }
        node = node->next;
    }

    return NULL;
}


static inline xqc_int_t
xqc_id_hash_add(xqc_id_hash_table_t *hash_tab, xqc_id_hash_element_t e)
{
    if (xqc_id_hash_find(hash_tab, e.hash)) {
        return XQC_ERROR;
    }

    uint64_t index = e.hash & hash_tab->mask;
    xqc_allocator_t *a = &hash_tab->allocator;

    xqc_id_hash_node_t *node = a->malloc(a->opaque, sizeof(xqc_id_hash_node_t));
    if (node == NULL) {
        return XQC_ERROR;
    }

    node->element = e;
    node->next = hash_tab->list[index];
    hash_tab->list[index] = node;

    return XQC_OK;
}


#define XQC_ID_HASH_LOOP -9

static inline xqc_int_t
xqc_id_hash_delete(xqc_id_hash_table_t* hash_tab, uint64_t hash)
{
    uint64_t index = hash & hash_tab->mask;
    xqc_allocator_t    *a     = &hash_tab->allocator;
    xqc_id_hash_node_t **pp   = &hash_tab->list[index];
    xqc_id_hash_node_t  *node = hash_tab->list[index];

    while (node) {
        if (node->element.hash == hash) {
            *pp = node->next;
            a->free(a->opaque, node);
            return XQC_OK;
        }

        if (node->next == node) {
            return XQC_ID_HASH_LOOP;
        }
        pp = &node->next;
        node = node->next;
    }

    return XQC_ERROR;
}

#endif
