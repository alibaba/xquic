/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */

#ifndef XQC_WEBTRANSPORT_H3_STREAM_H
#define XQC_WEBTRANSPORT_H3_STREAM_H

#include "src/http3/xqc_h3_extension.h"

typedef struct xqc_wt_stream_base_s xqc_wt_stream_base_t;

void xqc_wt_h3_stream_callbacks(xqc_h3_extension_ops_t *ops);

xqc_h3_stream_t *xqc_wt_h3_stream_create(xqc_h3_conn_t *h3c,
    xqc_bool_t bidi);

xqc_wt_stream_base_t *xqc_wt_h3_stream_get(xqc_h3_stream_t *h3s);
xqc_int_t xqc_wt_h3_stream_set(xqc_h3_stream_t *h3s,
    xqc_wt_stream_base_t *stream);

xqc_int_t xqc_wt_h3_stream_set_read_paused(xqc_h3_stream_t *h3s,
    xqc_bool_t paused);
void xqc_wt_h3_stream_detach(xqc_h3_stream_t *h3s);

#endif
