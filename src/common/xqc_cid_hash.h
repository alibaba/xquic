/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_CID_HASH_H_INCLUDED_
#define _XQC_CID_HASH_H_INCLUDED_

#include <stdint.h>
#include <string.h>

#include "src/common/xqc_common.h"
#include "src/common/xqc_memory_pool.h"

/*
 * hash table for CID
 * interface reference: xqc_id_hash.h
 */

typedef struct xqc_cid_hash_element_s {
    uint8_t     cid_len;
    uint8_t     cid_buf[XQC_MAX_CID_LEN];
    void       *value;                      /* associated element data */
} xqc_cid_hash_element_t;

typedef struct xqc_cid_hash_node_s {
    struct xqc_cid_hash_node_s *next;
    xqc_cid_hash_element_t      element;
} xqc_cid_hash_node_t;

typedef struct xqc_cid_hash_table_s {
    xqc_cid_hash_node_t   **list; 
    size_t                  count;
    xqc_allocator_t         allocator;
} xqc_cid_hash_table_t;


static inline int 
xqc_cid_hash_init(xqc_cid_hash_table_t *hash_tab,  xqc_allocator_t allocator, size_t bucket_num)
{
    hash_tab->allocator = allocator;
    hash_tab->list = allocator.malloc(allocator.opaque, sizeof(xqc_cid_hash_node_t *) * bucket_num);
    if (hash_tab->list == NULL) {
        return XQC_ERROR;
    }

    memset(hash_tab->list, 0, sizeof(xqc_cid_hash_node_t *) * bucket_num);
    hash_tab->count = bucket_num;

    return XQC_OK;
}


static inline void 
xqc_cid_hash_release(xqc_cid_hash_table_t *hash_tab)
{
    xqc_allocator_t *a = &hash_tab->allocator;
    for (size_t i = 0; i < hash_tab->count; ++i) {
        xqc_cid_hash_node_t *node = hash_tab->list[i];
        while (node) {
            xqc_cid_hash_node_t *p = node;
            node = node->next;
            a->free(a->opaque, p);
        }
    }

    a->free(a->opaque, hash_tab->list);
}


static inline uint64_t 
xqc_cid_hash(const uint8_t *cid_buf, uint8_t cid_len)
{
    uint64_t hash = 0;
    while (cid_len) {
        if (cid_len >= 8) {
            hash ^= *(const uint64_t *)cid_buf;
            cid_buf += 8;
            cid_len -= 8;

        } else if (cid_len >= 4) {
            hash ^= *(const uint32_t *)cid_buf;
            cid_buf += 4;
            cid_len -= 4;

        } else if (cid_len >= 2) {
            hash ^= *(const uint16_t *)cid_buf;
            cid_buf += 2;
            cid_len -= 2;

        } else {
            hash ^= *(const uint8_t *)cid_buf;
            cid_buf += 1;
            cid_len -= 1;
        }
    }

    return hash;
}


static inline void* 
xqc_cid_hash_find(xqc_cid_hash_table_t* hash_tab, const uint8_t *cid_buf, uint8_t cid_len)
{
    if (cid_len > XQC_MAX_CID_LEN) {
        return NULL;
    }

    uint64_t hash = xqc_cid_hash(cid_buf, cid_len);
    uint64_t index = hash % hash_tab->count;
    xqc_cid_hash_node_t *node = hash_tab->list[index];

    while (node) {
        if (cid_len == node->element.cid_len
            && 0 == memcmp(node->element.cid_buf, cid_buf, cid_len))
        {
            return node->element.value;
        }
        node = node->next;
    }

    return NULL;
}


static inline int 
xqc_cid_hash_add(xqc_cid_hash_table_t *hash_tab, const uint8_t *cid_buf, uint8_t cid_len, void *value)
{
    if (cid_len > XQC_MAX_CID_LEN) {
        return XQC_ERROR;
    }

    uint64_t hash = xqc_cid_hash(cid_buf, cid_len);
    uint64_t index = hash % hash_tab->count;

    /* duplicate connection id */
    xqc_cid_hash_node_t *node = hash_tab->list[index];
    while (node) {
        if (cid_len == node->element.cid_len
            && 0 == memcmp(node->element.cid_buf, cid_buf, cid_len))
        {
            return XQC_ERROR;
        }
        node = node->next;
    }

    xqc_allocator_t *a = &hash_tab->allocator;
    node = a->malloc(a->opaque, sizeof(xqc_cid_hash_node_t));
    if (node == NULL) {
        return XQC_ERROR;
    }

    node->element.cid_len = cid_len;
    memcpy(node->element.cid_buf, cid_buf, cid_len);
    memset(node->element.cid_buf + cid_len, 0, sizeof(node->element.cid_buf) - cid_len);
    node->element.value = value;
    node->next = hash_tab->list[index];
    hash_tab->list[index] = node;

    return XQC_OK;
}


static inline int 
xqc_cid_hash_delete(xqc_cid_hash_table_t *hash_tab, const uint8_t *cid_buf, uint8_t cid_len)
{
    if (cid_len > XQC_MAX_CID_LEN) {
        return XQC_ERROR;
    }

    uint64_t hash   = xqc_cid_hash(cid_buf, cid_len);
    uint64_t index  = hash % hash_tab->count;
    xqc_cid_hash_node_t **pp   = &hash_tab->list[index];
    xqc_cid_hash_node_t  *node = hash_tab->list[index];

    while (node) {
        if (cid_len == node->element.cid_len
            && 0 == memcmp(node->element.cid_buf, cid_buf, cid_len))
        {
            *pp = node->next;
            return XQC_OK;
        }

        pp = &node->next;
        node = node->next;
    }

    return XQC_ERROR;
}

#endif /*_XQC_CID_HASH_H_INCLUDED_*/
