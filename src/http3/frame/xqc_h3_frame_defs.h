/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_H3_FRAME_DEFS_H_
#define _XQC_H3_FRAME_DEFS_H_

#include "src/http3/xqc_var_buf.h"


typedef enum xqc_h3_frm_type_s {
    XQC_H3_FRM_DATA             = 0x00,
    XQC_H3_FRM_HEADERS          = 0x01,
    XQC_H3_FRM_CANCEL_PUSH      = 0x03,
    XQC_H3_FRM_SETTINGS         = 0x04,
    XQC_H3_FRM_PUSH_PROMISE     = 0x05,
    XQC_H3_FRM_GOAWAY           = 0x07,
    XQC_H3_FRM_MAX_PUSH_ID      = 0x0d,
    XQC_H3_FRM_UNKNOWN          = UINT64_MAX,
} xqc_h3_frm_type_t;


typedef struct xqc_h3_frm_data_s {
} xqc_h3_frame_data_t;

typedef struct xqc_h3_frm_headers_s {
} xqc_h3_frame_headers_t;

typedef struct xqc_h3_frm_cancel_push_s {
    xqc_discrete_vint_pctx_t push_id;
}xqc_h3_frame_cancel_push_t;

typedef struct xqc_h3_setting_s {
    xqc_discrete_vint_pctx_t identifier;
    xqc_discrete_vint_pctx_t value;
} xqc_h3_setting_t;

#define MAX_SETTING_ENTRY 16

typedef struct xqc_h3_frm_settings_s {
    xqc_var_buf_t           *setting;
} xqc_h3_frame_settings_t;

typedef struct xqc_h3_frm_push_promise_t {
    xqc_discrete_vint_pctx_t push_id;
    xqc_var_buf_t           *encoded_field_section;
    uint8_t                  count;
} xqc_h3_frame_push_promise_t;

typedef struct xqc_h3_frm_goaway_t {
    xqc_discrete_vint_pctx_t stream_id;
} xqc_h3_frame_goaway_t;

typedef struct xqc_h3_frm_max_push_id_t {
    xqc_discrete_vint_pctx_t push_id;
} xqc_h3_frame_max_push_id_t;

#endif