/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 *
 * @brief xqc_ring_mem_t isa ring memory used to store bytes in a continuous buf with fixed capacity.
 * every inserted memory block got an unique index (xqc_ring_mem_idx_t), which acts as the handler
 * of a memory block.
 * the index is monotone increasing. this class use two monotone increasing numbers, sidx and eidx,
 * to remember the allocation status of index, and calculate the begin and end offset of used buf.
 */

#include "xqc_ring_mem.h"


typedef struct xqc_ring_mem_s {
    /* original memory */
    uint8_t            *buf;

    /* bytes of memory allocated, which is the upper limit of xqc_ring_mem_t */
    size_t              capacity;

    /* transfer relative offset to absolute index */
    size_t              mask;

    /* bytes used */
    uint64_t            used;

    /* the begin absolute index, which is a monotone increasing number */
    xqc_ring_mem_idx_t  sidx;

    /* the end absolute index, which is a monotone increasing number */
    xqc_ring_mem_idx_t  eidx;

} xqc_ring_mem_s;


xqc_ring_mem_t *
xqc_ring_mem_create(size_t sz)
{
    xqc_ring_mem_t *rmem = xqc_calloc(1, sizeof(xqc_ring_mem_t));
    if (NULL == rmem) {
        return NULL;
    }

    /* make buffer size power of 2 */
    uint64_t msize = 0;
    if (sz != 0) {
        msize = xqc_pow2_upper(sz);
        rmem->buf = (uint8_t *)xqc_malloc(msize);
        if (rmem->buf == NULL) {
            xqc_free(rmem);
            return NULL;
        }
    }

    rmem->capacity = msize;
    rmem->mask = msize - 1;
    rmem->used = 0;
    rmem->sidx = 0;
    rmem->eidx = 0;

    return rmem;
}

void
xqc_ring_mem_free(xqc_ring_mem_t *rmem)
{
    if (rmem->buf) {
        xqc_free(rmem->buf);
    }

    xqc_free(rmem);
}


xqc_int_t
xqc_ring_mem_resize(xqc_ring_mem_t *rmem, size_t cap)
{
    xqc_int_t ret;

    /* make sure the saved data shall not be lost */
    if (cap < rmem->used) {
        return -XQC_EPARAM;

    } else if (cap <= rmem->capacity) {
        /* nothing to do if capacity not change or smaller */
        return XQC_OK;
    }

    uint64_t mcap = xqc_pow2_upper(cap);
    uint8_t *buf = (uint8_t *)xqc_malloc(mcap);
    if (buf == NULL) {
        return -XQC_EMALLOC;
    }

    /* copy data if there are used bytes */
    if (rmem->capacity != 0) {
        uint64_t mask_new = mcap - 1;
        uint64_t soffset_new = rmem->sidx & mask_new;
        uint64_t eoffset_new = rmem->eidx & mask_new;
        if (soffset_new < eoffset_new) {
            /* bytes are continuous in new buffer */
            ret = xqc_ring_mem_copy(rmem, rmem->sidx, rmem->used,
                                    buf + soffset_new, mcap - soffset_new);
            if (ret != XQC_OK) {
                xqc_free(buf);
                return ret;
            }

        } else {
            /* bytes are truncated in new buffer */
            uint64_t soffset_ori = rmem->sidx & rmem->mask;
            uint64_t eoffset_ori = rmem->eidx & rmem->mask;
            if (soffset_ori < eoffset_ori) {
                /* bytes are continuous in original buffer while truncated in new buffer */
                size_t sz = mcap - soffset_new;
                xqc_memcpy(buf + soffset_new, rmem->buf + soffset_ori, sz);
                xqc_memcpy(buf, rmem->buf + soffset_ori + sz, rmem->used - sz);

            } else {
                /* bytes are both truncated in new and original buffer */
                size_t new_sz1 = mcap - soffset_new;    /* size of first block in new buffer */
                size_t ori_sz1 = mcap - soffset_ori;    /* size of first block in original buffer */
                if (new_sz1 >= ori_sz1) {
                    /* the first block of new buffer is larger than original buffer */
                    xqc_memcpy(buf + soffset_new, rmem->buf + soffset_ori, ori_sz1);
                    xqc_memcpy(buf + soffset_new + ori_sz1, rmem->buf, new_sz1 - ori_sz1);
                    xqc_memcpy(buf, rmem->buf + new_sz1 - ori_sz1, rmem->used - new_sz1);

                } else {
                    /* the first block of new buffer is smaller than original buffer */
                    xqc_memcpy(buf + soffset_new, rmem->buf + soffset_ori, new_sz1);
                    xqc_memcpy(buf, rmem->buf + soffset_ori + new_sz1, ori_sz1 - new_sz1);
                    xqc_memcpy(buf + ori_sz1 - new_sz1, rmem->buf, rmem->used - ori_sz1);
                }
            }
        }

        xqc_free(rmem->buf);
    }

    rmem->buf = buf;
    rmem->capacity = mcap;
    rmem->mask = mcap - 1;

    return XQC_OK;
}


size_t
xqc_ring_mem_used_size(xqc_ring_mem_t *rmem)
{
    return rmem->used;
}


xqc_int_t
xqc_ring_mem_copy(xqc_ring_mem_t *rmem, xqc_ring_mem_idx_t idx, 
    size_t len, uint8_t *buf, size_t sz)
{
    if (sz < len) {
        return -XQC_ENOBUF;
    }

    /* compare range using sidx and eidx of rmem is convenient and safe */
    if (idx < rmem->sidx || idx >= rmem->eidx) {
        return -XQC_EPARAM;
    }

    uint64_t soffset = idx & (rmem->mask);          /* start offset */
    uint64_t eoffset = (idx + len) & (rmem->mask);  /* end offset */

    /* if eoffset equals soffset, it means a truncation happened */
    if (eoffset > soffset) {
        /* stored in a continuous memory block, copy directly */
        memcpy(buf, rmem->buf + soffset, len);

    } else {
        /* stored in two truncated memory blocks, copy from each */
        memcpy(buf, rmem->buf + soffset, rmem->capacity - soffset);
        memcpy(buf + rmem->capacity - soffset, rmem->buf, eoffset);
    }

    return XQC_OK;
}


xqc_int_t 
xqc_ring_mem_enqueue(xqc_ring_mem_t *rmem, uint8_t *data, size_t len, xqc_ring_mem_idx_t *idx)
{
    /* make sure there is enough space to store the memory block */
    if (len > rmem->capacity - rmem->used) {
        return -XQC_ELIMIT;
    }

    /* the end index is the index of new memory block */
    *idx = rmem->eidx;

    uint64_t soffset = rmem->eidx & (rmem->mask);           /* start offset of writing */
    uint64_t eoffset = (rmem->eidx + len) & rmem->mask;     /* end offset of writing */
    if (eoffset > soffset) {
        memcpy(rmem->buf + soffset, data, len);

    } else {
        memcpy(rmem->buf + soffset, data, rmem->capacity - soffset);
        memcpy(rmem->buf,  data + rmem->capacity - soffset, eoffset);
    }

    rmem->eidx += len;
    rmem->used += len;

    return XQC_OK;
}


xqc_int_t
xqc_ring_mem_dequeue(xqc_ring_mem_t *rmem, xqc_ring_mem_idx_t idx, size_t len)
{
    /* FIFO, must dequeue from start */
    if (rmem->sidx != idx || rmem->used < len) {
        return -XQC_EPARAM;
    }

    rmem->sidx += len;
    rmem->used -= len;

    return XQC_OK;
}


xqc_int_t
xqc_ring_mem_undo(xqc_ring_mem_t *rmem, xqc_ring_mem_idx_t idx, size_t len)
{
    if (idx < rmem->sidx) {
        /* undo dequeue */
        if (len > rmem->capacity - rmem->used
            || idx != rmem->sidx - len)
        {
            return -XQC_EPARAM;
        }

        rmem->sidx = idx;
        rmem->used += len;

    } else {
        /* undo enqueue */
        if (rmem->used < len
            || idx != rmem->eidx - len)
        {
            return -XQC_EPARAM;
        }

        rmem->eidx = idx;
        rmem->used -= len;
    }

    return XQC_OK;
}


int
xqc_ring_mem_cmp(xqc_ring_mem_t *rmem, xqc_ring_mem_idx_t idx, uint8_t *data, size_t len)
{
    if (idx < rmem->sidx || idx + len > rmem->eidx) {
        return -XQC_EPARAM;
    }

    uint64_t soffset = idx & rmem->mask;
    uint64_t eoffset = (idx + len) & (rmem->mask);

    int ret = 0;
    /* if soffset equals to eoffset, it means truncation */
    if (soffset < eoffset) {
        /* continuous memory block */
        ret = memcmp(rmem->buf + soffset, data, len);

    } else {
        /* truncated memory block */
        if (memcmp(rmem->buf + soffset, data, rmem->capacity - soffset) == 0
            && memcmp(rmem->buf, data + rmem->capacity - soffset, eoffset) == 0)
        {
            ret = 0;

        } else {
            ret = -1;
        }
    }

    return ret;
}


xqc_bool_t
xqc_ring_mem_can_duplicate(xqc_ring_mem_t *rmem, xqc_ring_mem_idx_t ori_idx, size_t len)
{
    if (rmem->used + len > rmem->capacity) {
        return XQC_FALSE;
    }

    return XQC_TRUE;
}


xqc_int_t
xqc_ring_mem_duplicate(xqc_ring_mem_t *rmem, xqc_ring_mem_idx_t ori_idx, size_t len,
    xqc_ring_mem_idx_t *new_idx)
{
    xqc_int_t ret = XQC_OK;

    if (len == 0 || ori_idx == XQC_RING_MEM_INVALID_IDX) {
        return XQC_OK;
    }

    if (ori_idx < rmem->sidx || ori_idx + len > rmem->eidx) {
        return -XQC_EPARAM;
    }

    /* make sure enough memory remains */
    if (xqc_ring_mem_can_duplicate(rmem, ori_idx, len) == XQC_FALSE) {
        return -XQC_ENOBUF;
    }

    /* the start and end offsets of original memory block */
    uint64_t soffset_ori = ori_idx & rmem->mask;
    uint64_t eoffset_ori = (ori_idx + len) & rmem->mask;

    /* the start and end offsets of duplicated memory block */
    xqc_ring_mem_idx_t sidx_dup = rmem->eidx;
    xqc_ring_mem_idx_t eidx_dup = rmem->eidx + len;
    uint64_t soffset_dup = sidx_dup & rmem->mask;
    uint64_t eoffset_dup = eidx_dup & rmem->mask;

    /* make sure the duplicated memory block won't overwrite other memory blocks */
    if (eoffset_dup > soffset_dup) {
        /* continuous memory block, will overwrite nothing */
        if (eoffset_ori > soffset_ori) {
            /* stored in a continuous memory block, copy directly */
            memmove(rmem->buf + soffset_dup, rmem->buf + soffset_ori, len);

        } else {
            /* original memory block is truncated, copy from each */
            size_t first_blk_size = rmem->capacity - soffset_ori;
            memmove(rmem->buf + soffset_dup, rmem->buf + soffset_ori, first_blk_size);
            memmove(rmem->buf + soffset_dup + first_blk_size, rmem->buf, len - first_blk_size);
        }

    } else {
        /* 
         * it is impossible that 2 truncation exist in one ring mem. Hence, if
         * the duplicated memory block is truncated, the original memory block
         * will always be continuous.
         */
        size_t first_blk_size = rmem->capacity - soffset_dup;
        memmove(rmem->buf + soffset_dup, rmem->buf + soffset_ori, first_blk_size);
        memmove(rmem->buf, rmem->buf + soffset_ori + first_blk_size, len - first_blk_size);
    }

    rmem->used += len;
    rmem->eidx = eidx_dup;
    *new_idx = sidx_dup;

    return XQC_OK;
}
