/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_H3_CTX_H
#define XQC_H3_CTX_H

#include <xquic/xqc_http3.h>


/* 应用层注册回调，放到engine */
typedef struct xqc_h3_ctx_s {
    xqc_h3_callbacks_t  h3_cbs;
    xqc_h3_conn_settings_t h3c_def_local_settings;
} xqc_h3_ctx_t;

xqc_int_t xqc_h3_ctx_get_app_callbacks(xqc_engine_t *engine, char *alpn, 
    size_t alpn_len, xqc_h3_callbacks_t **h3_cbs);

xqc_int_t xqc_h3_ctx_get_default_conn_settings(xqc_engine_t *engine, char *alpn, 
    size_t alpn_len, xqc_h3_conn_settings_t **settings);


#endif
