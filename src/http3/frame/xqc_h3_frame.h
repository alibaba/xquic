/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_H3_FRAME_H_
#define _XQC_H3_FRAME_H_

#include <xquic/xqc_http3.h>
#include "src/http3/frame/xqc_h3_frame_defs.h"

typedef union xqc_h3_frame_payload_s {
    xqc_h3_frame_headers_t        headers;
    xqc_h3_frame_data_t           data;
    xqc_h3_frame_cancel_push_t    cancel_push;
    xqc_h3_frame_settings_t       settings;
    xqc_h3_frame_push_promise_t   push_promise;
    xqc_h3_frame_goaway_t         goaway;
    xqc_h3_frame_max_push_id_t    max_push_id;
} xqc_h3_frame_pl_t;


typedef struct xqc_h3_frame_s {
    xqc_h3_frm_type_t   type;
    uint64_t            len;
    uint64_t            consumed_len;
    xqc_h3_frame_pl_t   frame_payload;
} xqc_h3_frame_t;


typedef enum {
    XQC_H3_FRM_STATE_TYPE = 0,
    XQC_H3_FRM_STATE_LEN,
    XQC_H3_FRM_STATE_PAYLOAD,
    XQC_H3_FRM_STATE_END,
} xqc_h3_frame_state_t;


typedef struct xqc_h3_frame_pctx_s {
    /* frame parsing state */
    xqc_h3_frame_state_t        state;

    /* frame temp/final result */
    xqc_h3_frame_t              frame;
    xqc_discrete_vint_pctx_t    pctx;
} xqc_h3_frame_pctx_t;


/**
 * parse one h3 frame from buffer, caller might need to call this method multiple times,
 * until the returned value is 0 or equal to the input buffer length
 * @param pos, the start of buffer
 * @param sz, length of input buffer
 * @param pctx, the parse context
 * @return XQC_ERROR for failure, >= 0 for bytes consumed
 */
ssize_t xqc_h3_frm_parse(const unsigned char *pos, size_t sz, xqc_h3_frame_pctx_t *pctx);


/**
 * @brief parse SETTINGS frame
 * @param data input data
 * @param user_data 
 * @return ssize_t 
 */
ssize_t xqc_h3_frm_parse_setting(xqc_var_buf_t *data, void *user_data);

/**
 * write a frame to buffer
 */

xqc_int_t xqc_h3_frm_write_headers(xqc_list_head_t *send_buf, xqc_var_buf_t *encoded_field_section,
    uint8_t fin);

xqc_int_t xqc_h3_frm_write_data(xqc_list_head_t *send_buf, unsigned char *data, size_t size,
    uint8_t fin);

xqc_int_t xqc_h3_frm_write_cancel_push(xqc_list_head_t *send_buf, uint64_t push_id, uint8_t fin);

xqc_int_t xqc_h3_frm_write_settings(xqc_list_head_t *send_buf, xqc_h3_conn_settings_t *setting,
    uint8_t fin);

xqc_int_t xqc_h3_frm_write_push_promise(xqc_list_head_t *send_buf, uint64_t push_id, 
    xqc_var_buf_t *encoded_field_section, uint8_t fin);

xqc_int_t xqc_h3_frm_write_goaway(xqc_list_head_t *send_buf, uint64_t push_id, uint8_t fin);

xqc_int_t xqc_h3_frm_write_max_push_id(xqc_list_head_t *send_buf, uint64_t push_id, uint8_t fin);

void xqc_h3_frm_reset_pctx(xqc_h3_frame_pctx_t *pctx);

#endif
