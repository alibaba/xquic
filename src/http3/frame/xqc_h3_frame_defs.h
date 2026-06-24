/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_H3_FRAME_DEFS_H_
#define _XQC_H3_FRAME_DEFS_H_

#include "src/common/utils/var_buf/xqc_var_buf.h"


typedef enum xqc_h3_frm_type_s {
    XQC_H3_FRM_DATA                 = 0x00,
    XQC_H3_FRM_HEADERS              = 0x01,
    XQC_H3_FRM_CANCEL_PUSH          = 0x03,
    XQC_H3_FRM_SETTINGS             = 0x04,
    XQC_H3_FRM_PUSH_PROMISE         = 0x05,
    XQC_H3_FRM_GOAWAY               = 0x07,
    XQC_H3_FRM_MAX_PUSH_ID          = 0x0d,

    /* extension */
    XQC_H3_EXT_FRM_BIDI_STREAM_TYPE = 0x20,

    XQC_H3_FRM_UNKNOWN              = UINT64_MAX,
} xqc_h3_frm_type_t;


typedef struct xqc_h3_frm_data_s {
    char reserved;
} xqc_h3_frame_data_t;

typedef struct xqc_h3_frm_headers_s {
    char reserved;
} xqc_h3_frame_headers_t;

typedef struct xqc_h3_frm_cancel_push_s {
    xqc_discrete_int_pctx_t push_id;
}xqc_h3_frame_cancel_push_t;

typedef struct xqc_h3_setting_s {
    xqc_discrete_int_pctx_t identifier;
    xqc_discrete_int_pctx_t value;
} xqc_h3_setting_t;

#define MAX_SETTING_ENTRY 16

/*
 * RFC 9114 Section 7.2.4: receive-side SETTINGS frame size cap.
 * Each setting entry is a pair of varints (max 8+8=16 bytes).
 * With MAX_SETTING_ENTRY=16, theoretical max is 256 bytes.
 * 4096 provides ~16x headroom for future extensions while
 * preventing unbounded allocation from malicious frame->len.
 */
#define XQC_H3_SETTINGS_MAX_FRAME_SIZE      4096

/*
 * PUSH_PROMISE encoded field section receive-side cap.
 * The payload carries QPACK-encoded response headers.
 * XQC_H3_MAX_FIELD_SECTION_SIZE defaults to 32KB (decoded),
 * but users may configure larger values. 256KB ensures no
 * false rejection of legitimate push promises while still
 * bounding memory: even 1000 connections x 256KB = 256MB.
 */
#define XQC_H3_PUSH_PROMISE_MAX_PAYLOAD_SIZE (256 * 1024)

typedef struct xqc_h3_frm_settings_s {
    xqc_var_buf_t           *setting;
} xqc_h3_frame_settings_t;

typedef struct xqc_h3_frm_push_promise_t {
    xqc_discrete_int_pctx_t  push_id;
    xqc_var_buf_t           *encoded_field_section;
    uint8_t                  count;
} xqc_h3_frame_push_promise_t;

typedef struct xqc_h3_frm_goaway_t {
    xqc_discrete_int_pctx_t stream_id;
} xqc_h3_frame_goaway_t;

typedef struct xqc_h3_frm_max_push_id_t {
    xqc_discrete_int_pctx_t push_id;
} xqc_h3_frame_max_push_id_t;

typedef struct xqc_h3_ext_frm_bidi_stream_type_s {
    xqc_discrete_int_pctx_t stream_type;
} xqc_h3_ext_frame_bidi_stream_type_t;

#endif