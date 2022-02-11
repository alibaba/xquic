/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_ring_array.h"


typedef struct xqc_rarray_s {
    /* continuous memory of array, buf_size = cap * esize. this would be NULL if capacity is 0 */
    uint8_t        *buf;

    /* size of element */
    uint64_t        esize;

    /* capacity of array, aka, the max count of elements */
    uint64_t        cap;

    /* total count of elements stored in ring array */
    uint64_t        count;

    /* the index offset of first element */
    uint64_t        offset;

    /* the final size of buf is power of 2, mask is used to retrieve node */
    uint64_t        mask;

} xqc_rarray_s;



xqc_rarray_t *
xqc_rarray_create(size_t cap, size_t esize)
{
    xqc_rarray_t *ra = xqc_calloc(1, sizeof(xqc_rarray_t));
    if (ra == NULL) {
        return NULL;
    }

    uint64_t array_cap = 0;
    if (esize != 0) {
        array_cap = xqc_pow2_upper(cap);
        ra->buf = xqc_malloc(array_cap * esize);
        if (ra->buf == NULL) {
            xqc_free(ra);
            return NULL;
        }
    }

    ra->cap = array_cap;
    ra->esize = esize;
    ra->mask = array_cap - 1;
    ra->offset = 0;
    ra->count = 0;

    return ra;
}


void
xqc_rarray_destroy(xqc_rarray_t *ra)
{
    if (ra->buf) {
        xqc_free(ra->buf);
    }

    xqc_free(ra);
}


/* check if the offset of element is legal. offset MUST be in range [0, capacity) */
static inline xqc_bool_t
xqc_rarray_check_range(xqc_rarray_t *ra, uint64_t offset)
{
    uint64_t eoffset = (ra->offset + ra->count) & ra->mask; /* end offset of rarray */
    if (ra->offset >= eoffset) {
        /*
         * input offset is always in range [0, capacity), if rollover,
         * ra->offset equals to eoffset, only if offset not exceed capacity,
         * it is always in range.
         */
        return offset >= ra->offset || offset < eoffset;

    } else {
        return offset >= ra->offset && offset < eoffset;
    }
}

void *
xqc_rarray_get(xqc_rarray_t *ra, uint64_t idx)
{
    if (ra == NULL || idx >= ra->cap) {
        return NULL;
    }

    /* check if idx is available */
    uint64_t offset = (idx + ra->offset) & ra->mask;
    if (xqc_rarray_check_range(ra, offset) == XQC_FALSE) {
        return NULL;
    }

    return ra->buf + offset * ra->esize;
}


size_t
xqc_rarray_size(xqc_rarray_t *ra)
{
    return ra->count;
}


void *
xqc_rarray_front(xqc_rarray_t *ra)
{
    if (ra->count == 0) {
        return NULL;
    }

    return (ra->buf + ra->offset * ra->esize);
}


void *
xqc_rarray_push(xqc_rarray_t *ra)
{
    if (ra->count >= ra->cap) {
        return NULL;
    }

    void *buf = ra->buf + ((ra->offset + ra->count) & ra->mask) * ra->esize;
    ra->count++;
    return buf;
}


xqc_int_t
xqc_rarray_pop_front(xqc_rarray_t *ra)
{
    if (ra->count == 0) {
        return XQC_ERROR;
    }

    /* 
     * even all elements are pop, offset will not be reset,
     * and new insertion will continue from offset 
     */
    ra->offset = (ra->offset + 1) & ra->mask;
    ra->count--;

    return XQC_OK;
}


xqc_int_t
xqc_rarray_pop_back(xqc_rarray_t *ra)
{
    if (ra->count == 0) {
        return XQC_ERROR;
    }

    ra->count--;
    return XQC_OK;
}


xqc_int_t
xqc_rarray_resize(xqc_rarray_t *ra, uint64_t cap)
{
    if (cap < ra->count) {
        return -XQC_EPARAM;

    } else if (cap <= ra->cap) {
        /* new capacity is smaller, do nothing */
        return XQC_OK;
    }

    uint64_t array_cap = xqc_pow2_upper(cap);
    uint8_t *buf = xqc_malloc(array_cap * ra->esize);
    if (buf == NULL) {
        return -XQC_EMALLOC;
    }

    if (ra->cap != 0) {
        /* copy data from original buf to the begin of new buf */
        uint64_t end = (ra->offset + ra->count) & ra->mask; /* end index */
        if (end >= ra->offset) {
            memcpy(buf, ra->buf + ra->offset * ra->esize, ra->count * ra->esize);

        } else {
            memcpy(buf, ra->buf + ra->offset * ra->esize, (ra->cap - ra->offset) * ra->esize);
            memcpy(buf + (ra->cap - ra->offset) * ra->esize, ra->buf, end * ra->esize);
        }

        xqc_free(ra->buf);
    }

    ra->buf = buf;
    ra->cap = array_cap;
    ra->mask = array_cap - 1;
    ra->offset = 0;

    return XQC_OK;
}
