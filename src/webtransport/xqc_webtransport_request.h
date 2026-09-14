/**
 * xqc_webtransport_request.h
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */
#ifndef XQC_WEBTRANSPORT_REQUEST_H
#define XQC_WEBTRANSPORT_REQUEST_H

#include "src/common/utils/var_buf/xqc_var_buf.h"
#include "src/common/xqc_hash.h"
#include "src/common/xqc_str_hash.h"
#include "src/http3/xqc_h3_defs.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/transport/xqc_conn.h"
#include <xquic/xqc_http3.h>
#include <xquic/xqc_webtransport.h>


#ifdef __cplusplus
extern "C" {
#endif

typedef struct xqc_wt_request_s {   // 本质上是封装了一下h3_request + 解析了请求
    xqc_wt_conn_t        *wt_conn;
    xqc_h3_stream_t      *h3_stream;
    xqc_h3_request_t     *h3_request;
    xqc_bool_t            is_header_recv;
    xqc_wt_session_t     *wt_session;

    void                 *user_data;
    char                 *request_stream_id;
    xqc_str_hash_table_t *request_headers;

    char                 *request_parameters;
    uint16_t              request_parameters_len;

    uint32_t              header_sent;
    uint32_t              header_recv;
    size_t                send_body_len;
    size_t                recv_body_len;

} xqc_wt_request_t;   // inner interface

void xqc_wt_request_parse_request_parameter(
    xqc_wt_request_t *wt_request);   // 这里是解析了请求的参数

xqc_wt_request_t *xqc_wt_request_create(xqc_log_t *log);   // 这里注意 headers 和 map 的初始化

void              xqc_wt_request_destroy(xqc_wt_request_t *wt_request);

char             *xqc_wt_request_table_find(xqc_wt_request_t *wt_request, const char *key);

int xqc_wt_h3_request_read_notify(xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag,
    void *stream_user_data);

#ifdef __cplusplus
}
#endif

#endif
