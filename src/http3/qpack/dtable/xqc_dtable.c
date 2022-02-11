/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/http3/qpack/dtable/xqc_dtable.h"
#include "src/common/xqc_hash.h"

#include "src/common/utils/ringarray/xqc_ring_array.h"
#include "src/common/utils/ringmem/xqc_ring_mem.h"
#include "src/common/utils/2d_hash/xqc_2d_hash_table.h"


/* ring memory name-value entry content */
typedef struct xqc_dtable_nv_s {
    /* name index, which is generated when store name in ring memory */
    xqc_ring_mem_idx_t  nidx;

    /* name len */
    size_t              nlen;

    /* value index, same usage as nidx */
    xqc_ring_mem_idx_t  vidx;

    /* value len */
    size_t              vlen;

} xqc_dtable_nv_t;

/* entry */
typedef struct xqc_dtable_entry_s {
    /* name-value pair information */
    xqc_dtable_nv_t     nv;

    /* absolute index of entry */
    uint64_t            abs_index;

    /* hash for name and value, might help when undo and duplicate on 2d hash table */
    uint64_t            nhash;
    uint64_t            vhash;

    uint64_t            sum;
} xqc_dtable_entry_t;



/*
 * dynamic table
 */
typedef struct xqc_dtable_s {
    /* 2d hash table, used to retrieve name-value pair */
    xqc_2d_hash_table_t    *ht2d;

    /* array of entries, with ordered sequence to maintain entries as FIFO */
    xqc_rarray_t           *entries;

    /* ring memory used to store name-value */
    xqc_ring_mem_t         *rmem;

    /* total number of inserts into the decoder's dynamic table */
    uint64_t                insert_cnt;

    /* the index of first entry, increase when an entry is popped from dtable */
    uint64_t                first_idx;

    /* capacity = sum(name_len + value_len + 32) */
    size_t                  capacity;

    /* total size used */
    size_t                  used;

    /* sum of all added entries */
    uint64_t                byte_sum;

    /* 
     * the low limit of dynamic table, which MUST NOT be evicted.
     * if dtable is empty, this value MUST be XQC_INVALID_INDEX 
     */
    uint64_t                min_ref;

    xqc_log_t              *log;
} xqc_dtable_s;



/* make the hash of value of name-value pair */
static inline uint64_t
xqc_dtable_make_value_hash(unsigned char *value, size_t vlen)
{
    /*
     * make the last char of value the value hash. this is 
     * STRONGLY RELEVANT with xqc_dtable_compare_nv function
     */
    return (uint64_t)(vlen != 0 ? *(value + vlen - 1) : 0);
}


/* compare two entries */
int
xqc_dtable_compare_entry(void *data1, void *data2, void *ud)
{
    xqc_dtable_entry_t *e1 = (xqc_dtable_entry_t *)data1;
    xqc_dtable_entry_t *e2 = (xqc_dtable_entry_t *)data2;

    /* compare absolute index, larger absolute index means larger */
    if (e1->abs_index == e2->abs_index) {
        return 0;
    }

    return e1->abs_index > e2->abs_index ? 1 : -1;
}


/* compare name/value with entry */
xqc_2d_cmp_res_t
xqc_dtable_compare_nv(void *data, void *v1, size_t len1, void *v2, size_t len2,
    xqc_2d_cmp_dim_t dims, void *ud)
{
    xqc_dtable_t *dt = (xqc_dtable_t *)ud;
    uint8_t *name = (uint8_t *)v1;
    uint8_t *value = (uint8_t *)v2;
    xqc_dtable_entry_t *entry = (xqc_dtable_entry_t *)data;
    xqc_dtable_nv_t *nv = &entry->nv;
    int res = 0;
    xqc_2d_cmp_res_t cmp_res = XQC_2D_CMP_RES_NONE;

    if (nv->nlen == len1) {
        /* compare name first */
        res = xqc_ring_mem_cmp(dt->rmem, nv->nidx, name, len1);
        if (res == 0) {
            cmp_res = XQC_2D_CMP_RES_1D;

            /* 2d compare is required, continue to compare value if name if matched */
            if (dims == XQC_2D_CMP_DIM_2) {
                if (nv->vlen == len2) {
                    res = xqc_ring_mem_cmp(dt->rmem, nv->vidx, value, len2);
                    if (res == 0) {
                        cmp_res = XQC_2D_CMP_RES_2D;
                    }
                }
            }
        }
    }

    return cmp_res;
}


xqc_dtable_t *
xqc_dtable_create(size_t htable_buckets, xqc_log_t *log)
{
    if (htable_buckets == 0) {
        return NULL;
    }

    xqc_dtable_t *dt = xqc_calloc(1, sizeof(xqc_dtable_t));
    if (NULL == dt) {
        xqc_log(log, XQC_LOG_ERROR, "|create dtable error|");
        return NULL;
    }
    dt->log = log;

    /* create 2d hash table */
    dt->ht2d = xqc_2d_hash_table_create(htable_buckets, xqc_dtable_compare_entry,
                                        xqc_dtable_compare_nv, dt);
    if (dt->ht2d == NULL) {
        xqc_log(log, XQC_LOG_ERROR, "|create 2d hash table error|");
        xqc_free(dt);
        return NULL;
    }

    /* make the capacity of ring memory same with dtable, initialized to be 0 */
    dt->rmem = xqc_ring_mem_create(0);
    if (dt->rmem == NULL) {
        xqc_log(dt->log, XQC_LOG_ERROR, "|create rmem error|");
        xqc_dtable_free(dt);
        return NULL;
    }

    /* ring array is used to store the entry information, initialized to be 0 */
    dt->entries = xqc_rarray_create(0, sizeof(xqc_dtable_entry_t));
    if (dt->entries == NULL) {
        xqc_log(dt->log, XQC_LOG_ERROR, "|create rarray error|");
        xqc_dtable_free(dt);
        return NULL;
    }

    /* set min_ref to largest, all entries can be evictable by default */
    dt->min_ref = XQC_INVALID_INDEX;

    return dt;
}


void
xqc_dtable_free(xqc_dtable_t *dt)
{
    if (dt != NULL) {
        if (dt->ht2d != NULL) {
            xqc_2d_hash_table_free(dt->ht2d);
        }

        if (dt->rmem != NULL) {
            xqc_ring_mem_free(dt->rmem);
        }

        if (dt->entries != NULL) {
            xqc_rarray_destroy(dt->entries);
        }

        xqc_free(dt);
    }
}


static inline xqc_int_t
xqc_dtable_enqueue_nv(xqc_dtable_t *dt, xqc_dtable_entry_t *entry,
    unsigned char *name, uint64_t nlen, unsigned char *value, uint64_t vlen)
{
    xqc_int_t ret = XQC_OK;

    ret = xqc_ring_mem_enqueue(dt->rmem, name, nlen, &entry->nv.nidx);
    if (ret != XQC_OK) {
        xqc_log(dt->log, XQC_LOG_ERROR, "|enqueue name error|ret:%d|", ret);
        return ret;
    }

    if (vlen > 0) {
        ret = xqc_ring_mem_enqueue(dt->rmem, value, vlen, &entry->nv.vidx);
        if (ret != XQC_OK) {
            xqc_log(dt->log, XQC_LOG_ERROR, "|enqueue value error|ret:%d|", ret);
            return ret;
        }
    }

    entry->nv.nlen = nlen;
    entry->nv.vlen = vlen;

    return XQC_OK;
}


static inline xqc_int_t
xqc_dtable_dequeue_nv(xqc_dtable_t *dt, xqc_dtable_entry_t *entry)
{
    xqc_int_t ret = XQC_OK;

    /* remove name from ring memory */
    if (entry->nv.nlen > 0) {
        ret = xqc_ring_mem_dequeue(dt->rmem, entry->nv.nidx, entry->nv.nlen);
        if (ret != XQC_OK) {
            xqc_log(dt->log, XQC_LOG_ERROR, "|dequeue name error|ret:%d|nidx:%ui|nlen:%ui|", ret,
                    entry->nv.nidx, entry->nv.nlen);
            return ret;
        }
    }

    /* remove value from ring memory */
    if (entry->nv.vlen > 0) {
        ret = xqc_ring_mem_dequeue(dt->rmem, entry->nv.vidx, entry->nv.vlen);
        if (ret != XQC_OK) {
            xqc_log(dt->log, XQC_LOG_ERROR, "|dequeue value error|ret:%d|vidx:%ui|vlen:%ui|", ret,
                    entry->nv.vidx, entry->nv.vlen);
            return ret;
        }
    }

    return XQC_OK;
}


xqc_int_t
xqc_dtable_pop_entry(xqc_dtable_t *dt)
{
    xqc_int_t ret = XQC_OK;

    xqc_dtable_entry_t *entry = xqc_rarray_front(dt->entries);
    if (entry == NULL) {
        xqc_log(dt->log, XQC_LOG_ERROR, "|get first entry error|");
        return -XQC_QPACK_DYNAMIC_TABLE_VOID_ENTRY;
    }

    /* still referred, shall not be popped */
    if (entry->abs_index >= dt->min_ref) {
        xqc_log(dt->log, XQC_LOG_DEBUG, "|entry referred|idx:%ui|min_ref:%ui|", entry->abs_index,
                dt->min_ref);
        return -XQC_QPACK_DYNAMIC_TABLE_REFERRED;
    }

    xqc_log_event(dt->log, QPACK_DYNAMIC_TABLE_UPDATED, XQC_LOG_DTABLE_EVICTED, entry->abs_index);
    /* remove name and value from ring memory */
    ret = xqc_dtable_dequeue_nv(dt, entry);
    if (ret != XQC_OK) {
        xqc_log(dt->log, XQC_LOG_ERROR, "|dequeue nv error|ret:%d|", ret);
        return ret;
    }

    /* remove from 2d hash table */
    ret = xqc_2d_hash_table_remove(dt->ht2d, entry->nv.nidx, entry->nv.vidx, entry);
    if (ret != XQC_OK) {
        xqc_log(dt->log, XQC_LOG_ERROR, "|remove from 2d hash error|ret:%d|", ret);
        return ret;
    }

    /* pop entry from ring array */
    ret = xqc_rarray_pop_front(dt->entries);
    if (ret != XQC_OK) {
        xqc_log(dt->log, XQC_LOG_ERROR, "|pop from rarray error|ret:%d|", ret);
        return ret;
    }

    dt->used -= xqc_dtable_entry_size(entry->nv.nlen, entry->nv.vlen);
    dt->first_idx++;    /* increase index of first entry */

    return XQC_OK;
}


xqc_dtable_entry_t *
xqc_dtable_get_entry_by_abs_idx(xqc_dtable_t *dt, uint64_t idx)
{
    /* idx is invalid */
    if (idx < dt->first_idx) {
        return NULL;
    }

    return xqc_rarray_get(dt->entries, idx - dt->first_idx);
}


/* evict entries for space */
xqc_int_t
xqc_dtable_make_space(xqc_dtable_t *dt, size_t space)
{
    xqc_int_t ret = XQC_OK;

    uint64_t ori_first = dt->first_idx;
    uint64_t ori_end = dt->insert_cnt;

    /* can't make a space larger than capacity */
    if (space > dt->capacity) {
        xqc_log(dt->log, XQC_LOG_ERROR, "|space exceed capacity|capacity:%uz|space:%uz|",
                dt->capacity, space);
        return -XQC_QPACK_DYNAMIC_TABLE_NOT_ENOUGH;
    }

    /* 
     * if there is not enough unused memory, continue to check if it is possible
     * to make space by evicting entries.
     * NOTICE: if min_ref is unlimited, all entries can be evicted.
     */
    if (dt->capacity - dt->used < space && dt->min_ref != XQC_INVALID_INDEX) {
        xqc_dtable_entry_t *first_entry = xqc_rarray_front(dt->entries);
        if (NULL == first_entry) {
            xqc_log(dt->log, XQC_LOG_ERROR, "|can't find first entry|");
            return -XQC_QPACK_DYNAMIC_TABLE_VOID_ENTRY;
        }

        xqc_dtable_entry_t *entry_min_ref = xqc_dtable_get_entry_by_abs_idx(dt, dt->min_ref);
        if (NULL == entry_min_ref) {
            xqc_log(dt->log, XQC_LOG_ERROR, "|can't find min referred entry|idx:%ui", dt->min_ref);
            return -XQC_QPACK_DYNAMIC_TABLE_VOID_ENTRY;
        }

        size_t nv_len = entry_min_ref->sum - first_entry->sum;
        size_t available = dt->capacity - dt->used + nv_len;
        if (available < space) {
            xqc_log(dt->log, XQC_LOG_DEBUG, "|space exceed available|available:%uz|space:%uz|",
                    available, space);
            return -XQC_QPACK_DYNAMIC_TABLE_NOT_ENOUGH;
        }
    }

    /* make space for new entry, entries that are not referred will be deleted */
    while (space > dt->capacity - dt->used) {
        ret = xqc_dtable_pop_entry(dt);
        if (ret != XQC_OK) {
            xqc_log(dt->log, XQC_LOG_DEBUG, "|pop entry error|ret:%d|", ret);
            return ret;
        }
    }

    return XQC_OK;
}


xqc_int_t
xqc_dtable_add(xqc_dtable_t *dt, unsigned char *name, uint64_t nlen, unsigned char *value,
    uint64_t vlen, uint64_t *idx)
{
    /* name is not allowed to be empty */
    if (NULL == name || 0 == nlen) {
        xqc_log(dt->log, XQC_LOG_ERROR, "|input name invalid|");
        return -XQC_EPARAM;
    }

    xqc_int_t ret = XQC_OK;
    size_t space = xqc_dtable_entry_size(nlen, vlen);

    /*
     * MUST make sure that needed space won't exceed capacity, 
     * or it might cause FATAL state error after pop failure
     */
    if (space > dt->capacity) {
        xqc_log(dt->log, XQC_LOG_ERROR, "|entry too large|space:%zu|cap:%zu|", space, dt->capacity);
        return -XQC_ELIMIT;
    }

    /* make space for new entry, old entries will be deleted */
    ret = xqc_dtable_make_space(dt, space);
    if (ret != XQC_OK) {
        xqc_log(dt->log, XQC_LOG_INFO, "|unable to make space|ret:%d|", ret);
        return ret;
    }

    /* get element from ring array, shall always get an entry */
    xqc_dtable_entry_t *entry = (xqc_dtable_entry_t *)xqc_rarray_push(dt->entries);
    if (entry == NULL) {
        xqc_log(dt->log, XQC_LOG_ERROR, "|get new entry error|");
        return -XQC_QPACK_DYNAMIC_TABLE_VOID_ENTRY;
    }
    memset(entry, 0, sizeof(xqc_dtable_entry_t));
    entry->abs_index = dt->insert_cnt;

    /* store name-value into ring memory */
    ret = xqc_dtable_enqueue_nv(dt, entry, name, nlen, value, vlen);
    if (ret != XQC_OK) {
        xqc_log(dt->log, XQC_LOG_ERROR, "|enqueue entry error|ret:%d|", ret);
        return ret;
    }

    /* insert into 2d hash table.  */
    uint64_t nhash = xqc_hash_string(name, nlen);
    uint64_t vhash = xqc_dtable_make_value_hash(value, vlen);
    ret = xqc_2d_hash_table_add(dt->ht2d, nhash, vhash, entry);
    if (ret != XQC_OK) {
        xqc_log(dt->log, XQC_LOG_ERROR, "|add entry to 2dht error|ret:%d|", ret);
        return ret;
    }

    entry->nhash = nhash;
    entry->vhash = vhash;
    entry->sum = dt->byte_sum;

    dt->insert_cnt++;
    dt->used += space;
    dt->byte_sum += space;

    *idx = entry->abs_index;    /* return absolute index */

    xqc_log(dt->log, XQC_LOG_DEBUG, "|dtable add entry|idx:%ui|name:%*s|value:%*s|", *idx,
            (size_t) xqc_min(nlen, 1024), name, (size_t) xqc_min(vlen, 1024), value);
    xqc_log_event(dt->log, QPACK_DYNAMIC_TABLE_UPDATED, XQC_LOG_DTABLE_INSERTED, *idx,
                  nlen, name, vlen, value);
    return ret;
}


xqc_int_t
xqc_dtable_get_nv(xqc_dtable_t *dt, uint64_t idx, 
    xqc_var_buf_t *name_buf, xqc_var_buf_t *value_buf)
{
    xqc_dtable_entry_t *entry = xqc_dtable_get_entry_by_abs_idx(dt, idx);
    if (NULL == entry) {
        xqc_log(dt->log, XQC_LOG_ERROR, "|get entry error|idx:%ui|first_idx:%ui|insert_count:%ui|",
                idx, dt->first_idx, dt->insert_cnt);
        return -XQC_QPACK_DYNAMIC_TABLE_VOID_ENTRY;
    }

    xqc_int_t ret = XQC_OK;

    /* get name, which is a MUST */
    if (name_buf == NULL) {
        xqc_log(dt->log, XQC_LOG_ERROR, "|input param error|");
        return -XQC_EPARAM;
    }

    if (entry->nv.nlen > 0) {
        ret = xqc_var_buf_save_prepare(name_buf, entry->nv.nlen + 1);
        if (ret != XQC_OK) {
            xqc_log(dt->log, XQC_LOG_ERROR, "|prepare name buf error|");
            return ret;
        }

        ret = xqc_ring_mem_copy(dt->rmem, entry->nv.nidx, entry->nv.nlen,
                                name_buf->data, name_buf->buf_len);
        if (ret != XQC_OK) {
            xqc_log(dt->log, XQC_LOG_ERROR, "|copy name error|ret:%d|nidx:%ui|", ret,
                    entry->nv.nidx);
            return ret;
        }

        name_buf->data_len = entry->nv.nlen;   /* don't count the terminator */
        name_buf->data[name_buf->data_len] = '\0';
    }

    /* get value, which is allowed to be NULL if caller don't need value */
    if (value_buf == NULL) {
        return XQC_OK;
    }

    if (entry->nv.vlen > 0) {
        ret = xqc_var_buf_save_prepare(value_buf, entry->nv.vlen + 1);
        if (ret != XQC_OK) {
            xqc_log(dt->log, XQC_LOG_ERROR, "|prepare value buf error|");
            return ret;
        }

        ret = xqc_ring_mem_copy(dt->rmem, entry->nv.vidx, entry->nv.vlen,
                                value_buf->data, value_buf->buf_len);
        if (XQC_OK != ret) {
            xqc_log(dt->log, XQC_LOG_ERROR, "|copy value error|ret:%d|vidx:%ui|", ret,
                    entry->nv.vidx);
            return ret;
        }

        value_buf->data_len = entry->nv.vlen;   /* don't count the terminator */
        value_buf->data[value_buf->data_len] = '\0';
    }

    return ret;
}


xqc_nv_ref_type_t
xqc_dtable_lookup(xqc_dtable_t *dt, unsigned char *name, size_t nlen,
    unsigned char *value, size_t vlen, uint64_t *idx)
{
    /* nothing in dtable, nothing to refer */
    if (dt->used == 0) {
        return XQC_NV_REF_NONE;
    }

    uint64_t nhash = xqc_hash_string(name, nlen);
    uint64_t vhash = xqc_dtable_make_value_hash(value, vlen);

    /* lookup name-value from 2d hash table */
    xqc_dtable_entry_t *entry = NULL;
    xqc_nv_ref_type_t ret = (xqc_nv_ref_type_t)xqc_2d_hash_lookup(dt->ht2d, nhash, name,
        nlen, vhash, value, vlen, (void **)&entry);
    if (ret != XQC_NV_REF_NONE) {
        *idx = entry->abs_index;
    }

    return ret;
}


xqc_int_t
xqc_dtable_set_min_ref(xqc_dtable_t *dt, uint64_t ref)
{
    if (ref == dt->min_ref) {
        return XQC_OK;
    }

    xqc_dtable_entry_t *entry = (xqc_dtable_entry_t *)xqc_rarray_front(dt->entries);
    if (entry == NULL) {
        xqc_log(dt->log, XQC_LOG_ERROR, "|dtable empty|");
        return -XQC_QPACK_DYNAMIC_TABLE_VOID_ENTRY;
    }

    uint64_t sidx = entry->abs_index;
    uint64_t eidx = sidx + xqc_rarray_size(dt->entries);

    /* make sure that referred index is valid */
    if (ref != XQC_INVALID_INDEX && (ref < sidx || ref >= eidx)) {
        xqc_log(dt->log, XQC_LOG_ERROR, "|referred index error|ref:%ui|sidx:%ui|eidx:%ui|",
                ref, sidx, eidx);
        return -XQC_QPACK_DYNAMIC_TABLE_VOID_ENTRY;
    }

    dt->min_ref = ref;
    return XQC_OK;
}


xqc_int_t
xqc_dtable_set_capacity(xqc_dtable_t *dt, uint64_t capacity)
{
    xqc_int_t ret = XQC_OK;

    /* 
     * capacity shrinks, pop entries first. 
     * (used size in dtable is not equal to which in ring memory) 
     */
    if (capacity < dt->capacity) {
        ret = xqc_dtable_make_space(dt, dt->capacity - capacity);
        if (ret != XQC_OK) {
            xqc_log(dt->log, XQC_LOG_ERROR, "|make space error|ret:%d|", ret);
            return ret;
        }
    }

    ret = xqc_ring_mem_resize(dt->rmem, capacity);
    if (ret != XQC_OK) {
        xqc_log(dt->log, XQC_LOG_ERROR, "|resize rmem error|ret:%d|", ret);
        return ret;
    }

    uint64_t max_entry_cnt = xqc_dtable_max_entry_cnt(capacity);
    ret = xqc_rarray_resize(dt->entries, max_entry_cnt);
    if (ret != XQC_OK) {
        xqc_log(dt->log, XQC_LOG_ERROR, "|resize rarray error|ret:%d|", ret);
        return ret;
    }

    dt->capacity = capacity;

    return XQC_OK;
}


xqc_int_t
xqc_dtable_prepare_dup(xqc_dtable_t *dt, uint64_t idx, size_t space)
{
    xqc_int_t ret = XQC_OK; /* for make space */
    xqc_int_t res = XQC_OK; /* for set min_ref */

    /* protect the duplicated entry, or itself might be popped */
    uint64_t ori_min_ref = dt->min_ref;
    if (idx < ori_min_ref) {
        res = xqc_dtable_set_min_ref(dt, idx);
        if (res != XQC_OK) {
            xqc_log(dt->log, XQC_LOG_ERROR, "|set min ref error|res:%d|idx:%ui|", res, idx);
            return res;
        }
    }

    /* make space for new entry, entries that are not referred will be deleted */
    ret = xqc_dtable_make_space(dt, space);
    if (ret != XQC_OK) {
        /* if make space fails, dtalbe shall recover its min_ref */
        xqc_log(dt->log, XQC_LOG_DEBUG, "|unable to make space for duplicate|ret:%d|", ret);
    }

    /* recover min_ref, no matter success or failure */
    if (idx < ori_min_ref) {
        res = xqc_dtable_set_min_ref(dt, ori_min_ref);
        if (res != XQC_OK) {
            xqc_log(dt->log, XQC_LOG_ERROR, "|recover min ref error|res:%d|idx:%ui|", res, idx);
            return res;
        }
    }

    return ret;
}


xqc_int_t
xqc_dtable_duplicate(xqc_dtable_t *dt, uint64_t idx, uint64_t *new_idx)
{
    xqc_int_t ret = XQC_OK;

    xqc_log(dt->log, XQC_LOG_DEBUG, "|dup|idx:%ui|min_ref:%ui|", idx, dt->min_ref);

    /* get entry with specified abs idx */
    xqc_dtable_entry_t *entry = xqc_dtable_get_entry_by_abs_idx(dt, idx);
    if (entry == NULL) {
        xqc_log(dt->log, XQC_LOG_ERROR, "|can't get entry with idx|idx:%ui|first:%ui|end:%ui|", 
                idx, dt->first_idx, dt->insert_cnt);
        return -XQC_QPACK_DYNAMIC_TABLE_VOID_ENTRY;
    }

    /* check if there is enough space */
    size_t space = xqc_dtable_entry_size(entry->nv.nlen, entry->nv.vlen);
    if (xqc_dtable_prepare_dup(dt, idx, space) != XQC_OK) {
        xqc_log(dt->log, XQC_LOG_INFO, "|prepare for duplicate failed|");
        return -XQC_ELIMIT;
    }

    /* get new entry from rarray */
    xqc_dtable_entry_t *new_entry = (xqc_dtable_entry_t *)xqc_rarray_push(dt->entries);
    if (new_entry == NULL) {
        xqc_log(dt->log, XQC_LOG_ERROR, "|push new entry in rarray error|");
        return -XQC_QPACK_DYNAMIC_TABLE_VOID_ENTRY;
    }
    memset(new_entry, 0, sizeof(xqc_dtable_entry_t));
    new_entry->abs_index = dt->insert_cnt;
    new_entry->sum = dt->byte_sum;

    /* duplicate name first */
    ret = xqc_ring_mem_duplicate(
        dt->rmem, entry->nv.nidx, entry->nv.nlen, &new_entry->nv.nidx);
    if (XQC_OK != ret) {
        xqc_log(dt->log, XQC_LOG_ERROR, "|duplicate name error|ret:%d", ret);
        return ret;
    }
    new_entry->nv.nlen = entry->nv.nlen;
    new_entry->nhash = entry->nhash;

    /* duplicate value */
    ret = xqc_ring_mem_duplicate(
        dt->rmem, entry->nv.vidx, entry->nv.vlen, &new_entry->nv.vidx);
    if (XQC_OK != ret) {
        xqc_log(dt->log, XQC_LOG_ERROR, "|duplicate value error|ret:%d", ret);
        return ret;
    }
    new_entry->nv.vlen = entry->nv.vlen;
    new_entry->vhash = entry->vhash;

    /* insert into 2d hash table */
    ret = xqc_2d_hash_table_add(dt->ht2d, new_entry->nhash, new_entry->vhash, new_entry);
    if (XQC_OK != ret) {
        xqc_log(dt->log, XQC_LOG_ERROR, "|duplicate 2dht error|ret:%d", ret);
        return ret;
    }

    /* assign absolute index */
    dt->insert_cnt++;
    dt->used += space;
    dt->byte_sum += space;

    *new_idx = new_entry->abs_index;

    return XQC_OK;
}


uint64_t
xqc_dtable_get_insert_cnt(xqc_dtable_t *dt)
{
    return dt->insert_cnt;
}


xqc_int_t
xqc_dtable_is_entry_draining(xqc_dtable_t *dt, uint64_t idx, xqc_bool_t *draining)
{
    *draining = XQC_FALSE;

    xqc_dtable_entry_t *entry = xqc_dtable_get_entry_by_abs_idx(dt, idx);
    if (entry == NULL) {
        xqc_log(dt->log, XQC_LOG_ERROR, "|empty dtable|");
        return -XQC_EPARAM;
    }

    /* the front 512 bytes or 1/8 of capacity is thought to be draining */
    size_t safe_offset = dt->capacity - xqc_min(512, dt->capacity / 8);
    if (dt->byte_sum - entry->sum > safe_offset) {
        *draining = XQC_TRUE;
    }

    return XQC_OK;
}

void
xqc_log_QPACK_STATE_UPDATED_callback(xqc_log_t *log, const char *func, ...)
{
    va_list args;
    va_start(args, func);
    xqc_int_t type = va_arg(args, xqc_int_t);
    xqc_dtable_t *dt = va_arg(args, xqc_dtable_t*);
    uint64_t krc = va_arg(args, uint64_t);
    if (type == XQC_LOG_DECODER_EVENT) {
        xqc_log_implement(log, QPACK_STATE_UPDATED, func, "|encoder|dtable_cap:%ui|dtable_size:%ui"
                          "|know_received_count:%ui|insert_count:%ui|", dt->capacity, dt->used,
                          krc, dt->insert_cnt);
    } else {
        xqc_log_implement(log, QPACK_STATE_UPDATED, func,
                          "|decoder|dtable_cap:%ui|dtable_size:%ui|insert_count:%ui|",
                          dt->capacity, dt->used, dt->insert_cnt);
    }
    va_end(args);
}
