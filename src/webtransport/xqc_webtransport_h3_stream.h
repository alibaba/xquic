/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */

#ifndef XQC_WEBTRANSPORT_H3_STREAM_H
#define XQC_WEBTRANSPORT_H3_STREAM_H

#include <xquic/xqc_webtransport.h>

typedef struct xqc_wt_stream_base_s xqc_wt_stream_base_t;

extern const xqc_stream_callbacks_t xqc_wt_h3_stream_callbacks;

void *xqc_wt_h3_stream_context(xqc_h3_stream_t *h3s);
xqc_bool_t xqc_wt_h3_stream_is_raw(xqc_h3_stream_t *h3s);
xqc_int_t xqc_wt_h3_stream_read(xqc_h3_stream_t *h3s,
    void *conn_ctx, unsigned char *data, size_t data_len, uint8_t fin);
xqc_int_t xqc_wt_h3_stream_prepare_read(xqc_h3_stream_t *h3s);
void xqc_wt_h3_stream_close(xqc_h3_stream_t *h3s);
void xqc_wt_h3_stream_clear(xqc_wt_conn_t *conn);

xqc_h3_stream_t *xqc_wt_h3_stream_create(xqc_h3_conn_t *h3c,
    xqc_bool_t bidi);

xqc_wt_stream_base_t *xqc_wt_h3_stream_get(xqc_h3_stream_t *h3s);
xqc_int_t xqc_wt_h3_stream_set(xqc_h3_stream_t *h3s,
    xqc_wt_stream_base_t *stream);

xqc_int_t xqc_wt_h3_stream_set_read_paused(xqc_h3_stream_t *h3s,
    xqc_bool_t paused);
void xqc_wt_h3_stream_detach(xqc_h3_stream_t *h3s);
void xqc_wt_h3_stream_notify_stop(xqc_h3_stream_t *h3s);
xqc_int_t xqc_wt_h3_stream_reset(xqc_h3_stream_t *h3s, uint64_t error,
    const unsigned char *prefix, size_t prefix_len);

#endif
