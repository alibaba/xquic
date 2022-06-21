/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_2d_hash_table.h"


typedef struct xqc_2d_hash_node_s {
    /* list head of node */
    xqc_list_head_t     head;

    /* hash of first dimension */
    uint64_t            hash1;

    /* hash of second dimension */
    uint64_t            hash2;

    /*
     * the pointer of data. among different nodes, hash values are allowd to be
     * same, while the data shall be unique. when comparing two different nodes
     * with xqc_2d_hash_table_data_cmp, non-zero MUST be returned.
     */
    void                *data;
} xqc_2d_hash_node_t;


typedef struct xqc_2d_hash_table_s {
    /* conflict list */
    xqc_list_head_t *list;

    /* count of buckets */
    size_t          bkt_cnt;

    /* mask for fast retrieve */
    uint64_t        mask;

    /* data comparison callback */
    xqc_2d_hash_table_data_cmp  dcmp;

    /* value comparison callback */
    xqc_2d_hash_table_value_cmp vcmp;

    /* callback user data */
    void            *ud;

} xqc_2d_hash_table_s;


xqc_2d_hash_table_t *
xqc_2d_hash_table_create(size_t bkt_cnt, xqc_2d_hash_table_data_cmp dcmp, 
    xqc_2d_hash_table_value_cmp vcmp, void *ud)
{
    xqc_2d_hash_table_t *ht = xqc_malloc(sizeof(xqc_2d_hash_table_t));
    if (NULL == ht) {
        return NULL;
    }

    /* make bucket count the least upper power of 2 */
    uint64_t bcnt = xqc_pow2_upper(bkt_cnt);
    xqc_list_head_t *list = (xqc_list_head_t *)xqc_malloc(bcnt * sizeof(xqc_list_head_t));
    if (NULL == list) {
        xqc_free(ht);
        return NULL;
    }

    for (size_t i = 0; i < bkt_cnt; i++) {
        xqc_list_head_t *head = &list[i];
        xqc_init_list_head(head);
    }

    ht->list = list;
    ht->bkt_cnt = bcnt;
    ht->mask = bcnt - 1;
    ht->dcmp = dcmp;
    ht->vcmp = vcmp;
    ht->ud = ud;

    return ht;
}


void
xqc_2d_hash_table_free(xqc_2d_hash_table_t *ht)
{
    xqc_list_head_t *pos, *next;
    xqc_2d_hash_node_t *node = NULL;

    /* foreach conflict list and free nodes */
    for (size_t i = 0; i < ht->bkt_cnt; i++) {
        xqc_list_head_t *list = &ht->list[i];
        xqc_list_for_each_safe(pos, next, list) {
            node = xqc_list_entry(pos, xqc_2d_hash_node_t, head);
            xqc_free(node);
        }
    }

    xqc_free(ht->list);
    xqc_free(ht);
}


static inline xqc_2d_hash_node_t *
xqc_2d_hash_table_create_node(uint64_t first, uint64_t second, void *data)
{
    xqc_2d_hash_node_t *node = xqc_malloc(sizeof(xqc_2d_hash_node_t));
    if (NULL == node) {
        return NULL;
    }

    xqc_init_list_head(&node->head);

    node->hash1 = first;
    node->hash2 = second;
    node->data = data;

    return node;
}


static inline xqc_bool_t
xqc_2d_hash_lookup_data(xqc_2d_hash_table_t *ht, uint64_t first, uint64_t second, void *data)
{
    xqc_list_head_t *pos, *next;
    xqc_2d_hash_node_t *node = NULL;
    int dres = 0;

    xqc_list_head_t *list = &ht->list[first & ht->mask];
    xqc_list_for_each_safe(pos, next, list) {
        node = xqc_list_entry(pos, xqc_2d_hash_node_t, head);
        dres = ht->dcmp(node->data, data, ht->ud);
        if (dres == 0) {
            return XQC_TRUE;
        }
    }

    return XQC_FALSE;
}


xqc_int_t
xqc_2d_hash_table_add(xqc_2d_hash_table_t *ht, uint64_t first, uint64_t second, void *data)
{
    /* already have a same node in hash table, return */
    if (xqc_2d_hash_lookup_data(ht, first, second, data) == XQC_TRUE) {
        return XQC_OK;
    }

    /* create node */
    xqc_2d_hash_node_t *node = xqc_2d_hash_table_create_node(first, second, data);
    if (NULL == node) {
        return -XQC_EMALLOC;
    }

    /* insert into conflict list */
    xqc_list_head_t *list = &ht->list[first & ht->mask];
    xqc_list_add(&node->head, list);

    return XQC_OK;
}


xqc_int_t
xqc_2d_hash_table_remove(xqc_2d_hash_table_t *ht, uint64_t h1, uint64_t h2, void *data)
{
    xqc_list_head_t *pos, *next;
    xqc_2d_hash_node_t *node = NULL;

    xqc_list_head_t *list = &ht->list[h1 & ht->mask];
    xqc_list_for_each_safe(pos, next, list) {
        node = xqc_list_entry(pos, xqc_2d_hash_node_t, head);

        /* MUST compare 2 dimensions on deletion */
        if (node->hash1 == h1 && node->hash2 == h2
            && ht->dcmp(node->data, data, ht->ud) == 0)
        {
            xqc_list_del(pos);
            xqc_free(node);
            break;
        }
    }

    return XQC_OK;
}


xqc_2d_cmp_res_t
xqc_2d_hash_lookup(xqc_2d_hash_table_t *ht, uint64_t h1, void *v1, size_t len1,
    uint64_t h2, void *v2, size_t len2, void **data)
{
    xqc_2d_cmp_res_t ret_cmp = XQC_2D_CMP_RES_NONE; /* compare result of function */
    xqc_2d_cmp_res_t ret_cb = XQC_2D_CMP_RES_NONE;  /* compare result of callback functions */
    xqc_list_head_t *pos;
    xqc_2d_hash_node_t *node = NULL;
    *data = NULL;

    xqc_list_head_t *list = &ht->list[h1 & ht->mask];
    xqc_list_for_each(pos, list) {
        node = xqc_list_entry(pos, xqc_2d_hash_node_t, head);

        if (node->hash1 == h1) {
            if (node->hash2 == h2) {
                /* 2d hash matched, compare values with data */
                ret_cb = ht->vcmp(node->data, v1, len1, v2, len2, XQC_2D_CMP_DIM_2, ht->ud);
                if (ret_cb > ret_cmp) {
                    /* 1d or 2d matched, remember result */
                    ret_cmp = ret_cb;
                    *data = node->data;

                    /*
                     * as we put data at the head of a list, the first found
                     * 2d-matched data is always newest and better, break and
                     * take this node as comparison result
                     */
                    if (ret_cb == XQC_2D_CMP_RES_2D) {
                        break;
                    }
                }

            } else {
                /* compare value of 1st dimension, if already found one data, do not update data */
                ret_cb = ht->vcmp(node->data, v1, len1, v2, len2, XQC_2D_CMP_DIM_1, ht->ud);
                if (ret_cb == XQC_2D_CMP_RES_1D && ret_cmp != XQC_2D_CMP_RES_1D) {
                    /* d1 is matched, continue to find if a 2d-match exists */
                    ret_cmp = XQC_2D_CMP_RES_1D;
                    *data = node->data;
                }
            }
        }
    }

    return ret_cmp;
}

