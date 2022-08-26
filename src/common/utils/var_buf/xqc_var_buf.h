/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_H3_H_
#define _XQC_H3_H_

#include "src/common/xqc_common_inc.h"
#include "src/http3/xqc_h3_defs.h"


typedef struct xqc_var_buf_s {
    /* buffer */
    unsigned char  *data;

    /* the size of buffer */
    size_t          buf_len;

    /* used length */
    size_t          data_len;

    /* length processed */
    size_t          consumed_len;

    /* finish flag */
    uint8_t         fin_flag;

    /* limit of memory malloc, if set to 0, regarded as infinite */
    size_t          limit;
} xqc_var_buf_t;

typedef struct xqc_list_buf_s {
    xqc_list_head_t list_head;
    xqc_var_buf_t  *buf;
} xqc_list_buf_t;

/**
 * @brief create variable buffer
 */
xqc_var_buf_t *xqc_var_buf_create(size_t capacity);

/**
 * @brief create variable buffer with a memory limit
 */
xqc_var_buf_t *xqc_var_buf_create_with_limit(size_t capacity, size_t limit);

/**
 * @brief reset variable buffer, with memory not freed
 */
void xqc_var_buf_clear(xqc_var_buf_t *buf);

/**
 * @brief destroy variable buffer
 */
void xqc_var_buf_free(xqc_var_buf_t *buf);

/**
 * @brief realloc buffer
 */
xqc_int_t xqc_var_buf_realloc(xqc_var_buf_t *buf, size_t cap);

/**
 * @brief reduce memory to minimum requirement
 */
xqc_int_t xqc_var_buf_reduce(xqc_var_buf_t *buf);

/**
 * @brief take over buffer from xqc_var_buf_t
 */
unsigned char *xqc_var_buf_take_over(xqc_var_buf_t *buf);

/**
 * @brief save data to variable buffer
 */
xqc_int_t xqc_var_buf_save_data(xqc_var_buf_t *buf, const uint8_t *data, size_t data_len);

/**
 * @brief prepare memory for saving data
 */
xqc_int_t xqc_var_buf_save_prepare(xqc_var_buf_t *buf, size_t data_len);


/**
 * @brief list buf functions
 */
xqc_list_buf_t *xqc_list_buf_create(xqc_var_buf_t *buf);
void xqc_list_buf_free(xqc_list_buf_t *list_buf);
void xqc_list_buf_list_free(xqc_list_head_t *head_list);
xqc_int_t xqc_list_buf_to_tail(xqc_list_head_t *phead, xqc_var_buf_t *buf);

#endif
