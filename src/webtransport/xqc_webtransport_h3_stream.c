/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */

#include "src/webtransport/xqc_webtransport_h3_stream.h"
#include "src/webtransport/xqc_webtransport_stream.h"
#include "src/webtransport/xqc_webtransport_wire.h"
#include "src/common/xqc_malloc.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_stream.h"

typedef struct {
    xqc_wt_stream_base_t   *stream;
    xqc_var_buf_t         *recv_buf;
    unsigned char          prefix[8];
    size_t                 prefix_len;
    unsigned               callback_depth;
    xqc_bool_t             paused;
    xqc_bool_t             detached;
    xqc_bool_t             closed;
} xqc_wt_h3_stream_t;

static xqc_wt_h3_stream_t *xqc_wt_h3_stream_allocate(
    xqc_h3_stream_t *h3s);
static void xqc_wt_h3_stream_release(xqc_wt_h3_stream_t *adapter);
static xqc_int_t xqc_wt_h3_stream_input_result(xqc_h3_stream_t *h3s,
    xqc_int_t result);
static xqc_int_t xqc_wt_h3_stream_receive(xqc_h3_stream_t *h3s,
    xqc_wt_h3_stream_t *adapter, void *conn_ctx,
    const unsigned char *data, size_t data_len, uint8_t fin);
static xqc_int_t xqc_wt_h3_stream_read(xqc_h3_stream_t *h3s,
    void *conn_ctx, unsigned char *data, size_t data_len, uint8_t fin);
static xqc_int_t xqc_wt_h3_stream_prepare_read(xqc_h3_stream_t *h3s,
    void *stream_ctx);
static xqc_int_t xqc_wt_h3_stream_write(xqc_h3_stream_t *h3s,
    void *stream_ctx);
static void xqc_wt_h3_stream_closing(xqc_h3_stream_t *h3s,
    xqc_int_t error, void *stream_ctx);
static void xqc_wt_h3_stream_close(xqc_h3_stream_t *h3s,
    void *stream_ctx);

static xqc_wt_h3_stream_t *
xqc_wt_h3_stream_allocate(xqc_h3_stream_t *h3s)
{
    xqc_wt_h3_stream_t *adapter = h3s->extension_data;
    if (adapter == NULL) {
        adapter = xqc_calloc(1, sizeof(*adapter));
        h3s->extension_data = adapter;
    }
    return adapter;
}

static void
xqc_wt_h3_stream_release(xqc_wt_h3_stream_t *adapter)
{
    if (--adapter->callback_depth == 0 && adapter->closed) {
        xqc_free(adapter);
    }
}

static xqc_int_t
xqc_wt_h3_stream_input_result(xqc_h3_stream_t *h3s, xqc_int_t result)
{
    if (result >= XQC_OK) {
        return result;
    }
    /* Retain the H3 parser's error classification for raw stream input. */
    xqc_int_t error = xqc_stream_is_uni(h3s->stream_id)
        ? -XQC_H3_EPROC_CONTROL : -XQC_H3_EPROC_REQUEST;
    XQC_H3_CONN_ERR(h3s->h3c, H3_FRAME_ERROR, error);
    return error;
}

xqc_wt_stream_base_t *
xqc_wt_h3_stream_get(xqc_h3_stream_t *h3s)
{
    xqc_wt_h3_stream_t *adapter = h3s ? h3s->extension_data : NULL;
    return adapter && !adapter->detached && !adapter->closed
        ? adapter->stream : NULL;
}

xqc_int_t
xqc_wt_h3_stream_set(xqc_h3_stream_t *h3s,
    xqc_wt_stream_base_t *stream)
{
    if (h3s == NULL || stream == NULL) {
        return -XQC_EPARAM;
    }
    xqc_wt_h3_stream_t *adapter = xqc_wt_h3_stream_allocate(h3s);
    if (adapter == NULL) {
        return -XQC_EMALLOC;
    }
    if (adapter->detached || adapter->closed || adapter->stream) {
        return -XQC_ESTATE;
    }
    adapter->stream = stream;
    h3s->type = XQC_H3_STREAM_TYPE_EXTENSION;
    return XQC_OK;
}

xqc_int_t
xqc_wt_h3_stream_set_read_paused(xqc_h3_stream_t *h3s,
    xqc_bool_t paused)
{
    if (h3s == NULL || paused > XQC_TRUE) {
        return -XQC_EPARAM;
    }
    xqc_wt_h3_stream_t *adapter = h3s->extension_data;
    if (adapter == NULL || adapter->detached || adapter->closed
        || h3s->type != XQC_H3_STREAM_TYPE_EXTENSION || h3s->stream == NULL)
    {
        return -XQC_ESTATE;
    }
    adapter->paused = paused;
    if (paused) {
        xqc_stream_shutdown_read(h3s->stream);

    } else {
        xqc_stream_ready_to_read(h3s->stream);
    }
    return XQC_OK;
}

void
xqc_wt_h3_stream_detach(xqc_h3_stream_t *h3s)
{
    xqc_wt_h3_stream_t *adapter = h3s ? h3s->extension_data : NULL;
    if (adapter == NULL) {
        return;
    }
    /* Keep the raw-stream tombstone until H3 releases its stream object. */
    adapter->detached = XQC_TRUE;
    adapter->stream = NULL;
    adapter->paused = XQC_FALSE;
    xqc_var_buf_free(adapter->recv_buf);
    adapter->recv_buf = NULL;
}

static xqc_int_t
xqc_wt_h3_stream_receive(xqc_h3_stream_t *h3s,
    xqc_wt_h3_stream_t *adapter, void *conn_ctx,
    const unsigned char *data, size_t data_len, uint8_t fin)
{
    if (adapter->detached || adapter->closed) {
        return XQC_OK;
    }
    ssize_t consumed = -XQC_EAGAIN;
    if (!adapter->paused && adapter->recv_buf == NULL) {
        consumed = xqc_wt_stream_read(h3s, conn_ctx,
            data ? data : (const unsigned char *)"", data_len, fin);
        if (adapter->detached || adapter->closed) {
            return XQC_OK;
        }
        if (consumed == (ssize_t)data_len
            && !(fin && adapter->paused && adapter->stream
                 && !adapter->stream->recv_fin))
        {
            return XQC_OK;
        }
        if (consumed < 0 && consumed != -XQC_EAGAIN) {
            return consumed;
        }
        if (consumed > (ssize_t)data_len) {
            return -XQC_EPARAM;
        }
    }
    if (consumed < 0) {
        consumed = 0;
    }
    size_t remaining = data_len - consumed;
    if (adapter->recv_buf == NULL) {
        size_t limit = h3s->h3c->max_blocked_buf_per_stream;
        if (limit == 0) {
            limit = XQC_H3_STREAM_MAX_BLOCKED_BUF_SIZE_DEFAULT;
        }
        adapter->recv_buf = xqc_var_buf_create_with_limit(
            xqc_min((size_t)XQC_DATA_BUF_SIZE_4K, limit), limit);
        if (adapter->recv_buf == NULL) {
            return -XQC_EMALLOC;
        }
    }
    xqc_int_t ret = xqc_var_buf_save_data(adapter->recv_buf,
        remaining ? data + consumed : NULL, remaining);
    if (ret != XQC_OK) {
        return ret;
    }
    adapter->recv_buf->fin_flag |= fin;
    return xqc_wt_h3_stream_set_read_paused(h3s, XQC_TRUE);
}

static xqc_int_t
xqc_wt_h3_stream_read(xqc_h3_stream_t *h3s, void *conn_ctx,
    unsigned char *data, size_t data_len, uint8_t fin)
{
    /* A fragmented native H3 stream-type frame already belongs to H3. */
    if (!xqc_stream_is_uni(h3s->stream_id)
        && h3s->pctx.frame_pctx.state != XQC_H3_FRM_STATE_TYPE)
    {
        return xqc_h3_stream_process_in(h3s, data, data_len, fin);
    }
    if (h3s->type != XQC_H3_STREAM_TYPE_UNKNOWN
        && (h3s->type != XQC_H3_STREAM_TYPE_EXTENSION
            || h3s->extension_data == NULL))
    {
        return xqc_h3_stream_process_in(h3s, data, data_len, fin);
    }
    if (data_len == 0 && h3s->extension_data == NULL
        && h3s->type == XQC_H3_STREAM_TYPE_UNKNOWN)
    {
        return xqc_h3_stream_process_in(h3s, data, data_len, fin);
    }
    xqc_wt_h3_stream_t *adapter = xqc_wt_h3_stream_allocate(h3s);
    if (adapter == NULL) {
        return -XQC_EMALLOC;
    }
    adapter->callback_depth++;
    if (h3s->type == XQC_H3_STREAM_TYPE_EXTENSION) {
        xqc_int_t ret = xqc_wt_h3_stream_receive(h3s, adapter, conn_ctx,
                                               data, data_len, fin);
        xqc_wt_h3_stream_release(adapter);
        return xqc_wt_h3_stream_input_result(h3s, ret);
    }

    /* draft-ietf-webtrans-http3-07 Sections 4.1 and 4.2. */
    size_t used = 0;
    size_t length = adapter->prefix_len
        ? (size_t)1 << (adapter->prefix[0] >> 6) : 1;
    while (used < data_len && adapter->prefix_len < length) {
        adapter->prefix[adapter->prefix_len++] = data[used++];
        length = (size_t)1 << (adapter->prefix[0] >> 6);
    }
    if (adapter->prefix_len < length) {
        if (!fin) {
            xqc_wt_h3_stream_release(adapter);
            return XQC_OK;
        }
        if (!xqc_stream_is_uni(h3s->stream_id)) {
            xqc_wt_h3_stream_release(adapter);
            return xqc_wt_h3_stream_input_result(h3s,
                                                 -XQC_H3_DECODE_ERROR);
        }
        /* An unfinished uni type still belongs to the ordinary H3 parser. */
        unsigned char prefix[8];
        size_t prefix_len = adapter->prefix_len;
        xqc_memcpy(prefix, adapter->prefix, prefix_len);
        h3s->extension_data = NULL;
        adapter->closed = XQC_TRUE;
        xqc_wt_h3_stream_release(adapter);
        return xqc_h3_stream_process_in(h3s, prefix, prefix_len, fin);
    }
    uint64_t type = adapter->prefix[0] & 0x3f;
    for (size_t i = 1; i < length; i++) {
        type = (type << 8) | adapter->prefix[i];
    }
    xqc_bool_t uni = xqc_stream_is_uni(h3s->stream_id);
    if (type == (uni ? XQC_WT_STREAM_TYPE_UNIDIRECTIONAL
                    : XQC_WT_STREAM_TYPE_BIDIRECTIONAL))
    {
        h3s->type = XQC_H3_STREAM_TYPE_EXTENSION;
        xqc_int_t ret = xqc_wt_h3_stream_receive(h3s, adapter, conn_ctx,
            data_len > used ? data + used : NULL, data_len - used, fin);
        xqc_wt_h3_stream_release(adapter);
        return xqc_wt_h3_stream_input_result(h3s, ret);
    }

    unsigned char prefix[8];
    xqc_memcpy(prefix, adapter->prefix, length);
    h3s->extension_data = NULL;
    adapter->closed = XQC_TRUE;
    xqc_wt_h3_stream_release(adapter);

    xqc_int_t ret = xqc_h3_stream_process_in(h3s, prefix, length,
                                            XQC_FALSE);
    if (ret != XQC_OK) {
        return ret;
    }
    return xqc_h3_stream_process_in(h3s,
        data_len > used ? data + used : prefix + length,
        data_len - used, fin);
}

static xqc_int_t
xqc_wt_h3_stream_prepare_read(xqc_h3_stream_t *h3s, void *stream_ctx)
{
    xqc_wt_h3_stream_t *adapter = stream_ctx;
    if (adapter == NULL || adapter->detached || adapter->closed) {
        return XQC_OK;
    }
    if (adapter->paused) {
        return -XQC_EAGAIN;
    }
    xqc_var_buf_t *buf = adapter->recv_buf;
    if (buf == NULL) {
        return XQC_OK;
    }
    adapter->callback_depth++;
    size_t remaining = buf->data_len - buf->consumed_len;
    ssize_t consumed = xqc_wt_stream_read(h3s, h3s->h3c->extension_data,
        buf->data + buf->consumed_len, remaining, buf->fin_flag);
    xqc_int_t ret = XQC_OK;
    if (adapter->closed || adapter->detached || adapter->recv_buf != buf) {
        xqc_wt_h3_stream_release(adapter);
        return XQC_OK;
    }
    if (consumed < 0 && consumed != -XQC_EAGAIN) {
        ret = consumed;

    } else if (consumed > (ssize_t)remaining) {
        ret = -XQC_EPARAM;

    } else {
        if (consumed >= 0) {
            buf->consumed_len += consumed;
        }
        if (consumed != -XQC_EAGAIN
            && buf->consumed_len == buf->data_len)
        {
            adapter->recv_buf = NULL;
            xqc_var_buf_free(buf);

        } else {
            ret = xqc_wt_h3_stream_set_read_paused(h3s, XQC_TRUE);
        }
        if (ret == XQC_OK && adapter->paused) {
            ret = -XQC_EAGAIN;
        }
    }
    xqc_wt_h3_stream_release(adapter);
    return ret;
}

static xqc_int_t
xqc_wt_h3_stream_write(xqc_h3_stream_t *h3s, void *stream_ctx)
{
    xqc_wt_h3_stream_t *adapter = stream_ctx;
    if (adapter == NULL || adapter->closed || adapter->detached) {
        return XQC_OK;
    }
    adapter->callback_depth++;
    xqc_int_t ret = xqc_wt_stream_write(h3s, adapter->stream);
    xqc_wt_h3_stream_release(adapter);
    return ret;
}

static void
xqc_wt_h3_stream_closing(xqc_h3_stream_t *h3s, xqc_int_t error,
    void *stream_ctx)
{
    xqc_wt_h3_stream_t *adapter = stream_ctx;
    if (adapter == NULL || adapter->closed || adapter->detached) {
        return;
    }
    adapter->callback_depth++;
    xqc_wt_stream_closing(h3s, error, adapter->stream);
    xqc_wt_h3_stream_release(adapter);
}

static void
xqc_wt_h3_stream_close(xqc_h3_stream_t *h3s, void *stream_ctx)
{
    xqc_wt_h3_stream_t *adapter = stream_ctx;
    if (adapter == NULL || adapter->closed) {
        return;
    }
    adapter->closed = XQC_TRUE;
    adapter->callback_depth++;
    xqc_wt_stream_close(h3s, adapter->stream);
    h3s->extension_data = NULL;
    xqc_var_buf_free(adapter->recv_buf);
    adapter->recv_buf = NULL;
    xqc_wt_h3_stream_release(adapter);
}

xqc_h3_stream_t *
xqc_wt_h3_stream_create(xqc_h3_conn_t *h3c, xqc_bool_t bidi)
{
    if (h3c == NULL || h3c->extension_ops == NULL) {
        return NULL;
    }
    xqc_stream_t *stream = xqc_stream_create_with_direction(h3c->conn,
        bidi ? XQC_STREAM_BIDI : XQC_STREAM_UNI, NULL);
    if (stream == NULL) {
        return NULL;
    }
    xqc_h3_stream_t *h3s = xqc_h3_stream_create(h3c, stream,
        XQC_H3_STREAM_TYPE_EXTENSION, NULL);
    if (h3s == NULL) {
        xqc_destroy_stream(stream);
        return NULL;
    }
    if (xqc_wt_h3_stream_allocate(h3s) == NULL) {
        xqc_destroy_stream(stream);
        return NULL;
    }
    return h3s;
}

void
xqc_wt_h3_stream_callbacks(xqc_h3_extension_ops_t *ops)
{
    ops->stream_read = xqc_wt_h3_stream_read;
    ops->stream_prepare_read = xqc_wt_h3_stream_prepare_read;
    ops->stream_write = xqc_wt_h3_stream_write;
    ops->stream_closing = xqc_wt_h3_stream_closing;
    ops->stream_close = xqc_wt_h3_stream_close;
}
