/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <stdint.h>
#include "src/http3/xqc_var_buf.h"

xqc_int_t
xqc_var_buf_set_limit(xqc_var_buf_t *buf, uint64_t limit);

xqc_var_buf_t *
xqc_var_buf_create(size_t capacity)
{
    xqc_var_buf_t *p = xqc_malloc(sizeof(xqc_var_buf_t));
    if (p == NULL) {
        return NULL;
    }

    if (capacity == 0) {
        capacity = 1;
    }

    p->data = xqc_malloc(capacity);

    p->buf_len = capacity;
    p->data_len = 0;
    p->consumed_len = 0;
    p->fin_flag = 0;
    p->limit = SIZE_MAX;

    return p;
}


xqc_var_buf_t *
xqc_var_buf_create_with_limit(size_t capacity, size_t limit)
{
    xqc_var_buf_t *p = xqc_var_buf_create(capacity);
    if (p == NULL) {
        return NULL;
    }

    xqc_var_buf_set_limit(p, limit);

    return p;
}


void
xqc_var_buf_clear(xqc_var_buf_t *buf)
{
    buf->data_len = 0;
    buf->consumed_len = 0;
    buf->fin_flag = 0;
}


void
xqc_var_buf_free(xqc_var_buf_t *buf)
{
    if (buf) {
        if (buf->data) {
            xqc_free(buf->data);
            buf->data = NULL;
            buf->buf_len = 0;
        }

        xqc_free(buf);
    }
}


xqc_int_t
xqc_var_buf_realloc(xqc_var_buf_t *buf, size_t cap)
{
    /* limit of buf shall never be 0 */
    if (buf->limit == 0) {
        buf->limit = SIZE_MAX;
    }

    if (cap > buf->limit) {
        return -XQC_EMALLOC;
    }

    uint64_t capacity = xqc_pow2_upper(cap);
    if (capacity > buf->limit) {
        capacity = buf->limit;
    }

    unsigned char *new_data = xqc_malloc(capacity);
    if (NULL == new_data) {
        return -XQC_EMALLOC;
    }

    if (buf->data != NULL && buf->buf_len > 0) {
        if (buf->data_len > 0) {
            memcpy(new_data, buf->data, buf->data_len);
        }
        if (buf->data != NULL) {
            xqc_free(buf->data);
        }
    }

    buf->data = new_data;
    buf->buf_len = capacity;

    return XQC_OK;
}

xqc_int_t
xqc_var_buf_reduce(xqc_var_buf_t *buf)
{
    uint64_t capacity = xqc_pow2_upper(buf->data_len - buf->consumed_len);
    if (capacity > buf->limit) {
        return -XQC_EMALLOC;
    }

    unsigned char *new_data = xqc_malloc(capacity);
    if (NULL == new_data) {
        return -XQC_EMALLOC;
    }

    if (buf->data != NULL && buf->buf_len > 0) {
        if (buf->data_len - buf->consumed_len > 0) {
            memcpy(new_data, buf->data + buf->consumed_len, buf->data_len - buf->consumed_len);
        }
        xqc_free(buf->data);
    }

    buf->data = new_data;
    buf->buf_len = capacity;
    buf->data_len -= buf->consumed_len;
    buf->consumed_len = 0;

    return XQC_OK;
}

xqc_int_t
xqc_var_buf_set_limit(xqc_var_buf_t *buf, uint64_t limit)
{
    /* can't shrink more */
    if (limit < buf->data_len) {
        return XQC_ERROR;
    }

    buf->limit = limit;
    if (limit < buf->buf_len) {
        /* shrink if limit is smaller than allocated */
        return xqc_var_buf_realloc(buf, limit);

    } else {
        return XQC_OK;
    }
}


xqc_int_t
xqc_var_buf_save_prepare(xqc_var_buf_t *buf, size_t data_len)
{
    xqc_var_buf_t *dest = buf;
    while (dest->data_len + data_len > dest->buf_len) {
        xqc_int_t ret = xqc_var_buf_realloc(dest, dest->data_len + data_len);
        if (ret != XQC_OK) {
            return ret;
        }
    }

    return XQC_OK;
}


unsigned char *
xqc_var_buf_take_over(xqc_var_buf_t *buf)
{
    unsigned char* buffer = buf->data;
    buf->buf_len = 0;
    buf->data_len = 0;
    buf->consumed_len = 0;
    buf->fin_flag = 0;
    buf->data = NULL;
    return buffer;
}


xqc_int_t
xqc_var_buf_save_data(xqc_var_buf_t *buf, const uint8_t *data, size_t data_len)
{
    if (data_len == 0) {
        return XQC_OK;
    }
    xqc_int_t ret = xqc_var_buf_save_prepare(buf, data_len);
    if (ret != XQC_OK) {
        return ret;
    }

    memcpy(buf->data + buf->data_len, data, data_len);
    buf->data_len += data_len;
    return XQC_OK;
}


xqc_list_buf_t *
xqc_list_buf_create(xqc_var_buf_t *buf)
{
    xqc_list_buf_t *list_buf = (xqc_list_buf_t *)xqc_malloc(sizeof(xqc_list_buf_t));
    if (list_buf == NULL) {
        return NULL;
    }

    xqc_init_list_head(&list_buf->list_head);
    list_buf->buf = buf;

    return list_buf;
}


void
xqc_list_buf_free(xqc_list_buf_t *list_buf)
{
    xqc_list_del(&list_buf->list_head);
    xqc_var_buf_free(list_buf->buf);
    xqc_free(list_buf);
}


void
xqc_list_buf_list_free(xqc_list_head_t *head_list)
{
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, head_list) {
        xqc_list_buf_t *list_buf = xqc_list_entry(pos, xqc_list_buf_t, list_head);
        xqc_list_buf_free(list_buf);
    }
}


xqc_int_t
xqc_list_buf_to_tail(xqc_list_head_t *phead, xqc_var_buf_t *buf)
{
    xqc_list_buf_t *list_buf = xqc_list_buf_create(buf);
    if (list_buf == NULL) {
        return XQC_ERROR;
    }

    xqc_list_add_tail(&list_buf->list_head, phead);

    return XQC_OK;
}
