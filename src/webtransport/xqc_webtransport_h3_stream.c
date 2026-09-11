/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */

#include "src/webtransport/xqc_webtransport_h3_stream.h"
#include "src/webtransport/xqc_webtransport_conn.h"
#include "src/webtransport/xqc_webtransport_stream.h"
#include "src/webtransport/xqc_webtransport_wire.h"
#include "src/common/xqc_malloc.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_stream.h"

typedef struct {
    xqc_list_head_t         list;
    xqc_h3_stream_t        *h3s;
    xqc_wt_stream_base_t   *stream;
    xqc_var_buf_t         *recv_buf;
    unsigned char          prefix[8];
    size_t                 prefix_len;
    unsigned char          reset_prefix[16];
    size_t                 reset_prefix_len;
    size_t                 reset_prefix_sent;
    uint64_t               reset_error;
    xqc_bool_t             reset_pending;
    xqc_bool_t             stop_received;
    xqc_bool_t             stop_pending;
    unsigned               callback_depth;
    xqc_bool_t             raw;
    xqc_bool_t             paused;
    xqc_bool_t             detached;
    xqc_bool_t             closed;
} xqc_wt_h3_stream_t;

static xqc_wt_h3_stream_t *xqc_wt_h3_stream_allocate(
    xqc_h3_stream_t *h3s);
static void xqc_wt_h3_stream_release(xqc_wt_h3_stream_t *adapter);
static xqc_int_t xqc_wt_h3_stream_flush_reset(xqc_wt_h3_stream_t *adapter);
static xqc_int_t xqc_wt_h3_read_ordinary(xqc_stream_t *stream,
    xqc_h3_stream_t *h3s);
static xqc_int_t xqc_wt_h3_stream_input_result(xqc_h3_stream_t *h3s,
    xqc_int_t result);
static xqc_int_t xqc_wt_h3_stream_receive(xqc_h3_stream_t *h3s,
    xqc_wt_h3_stream_t *adapter, void *conn_ctx,
    const unsigned char *data, size_t data_len, uint8_t fin);
static xqc_int_t xqc_wt_h3_stream_create_notify(xqc_stream_t *stream,
    void *user_data);
static xqc_int_t xqc_wt_h3_stream_read_notify(xqc_stream_t *stream,
    void *user_data);
static xqc_int_t xqc_wt_h3_stream_write_notify(xqc_stream_t *stream,
    void *user_data);
static void xqc_wt_h3_stream_closing_notify(xqc_stream_t *stream,
    xqc_int_t error, void *user_data);
static void xqc_wt_h3_stream_stop_sending_notify(xqc_stream_t *stream,
    uint64_t error, void *user_data);
static xqc_int_t xqc_wt_h3_stream_close_notify(xqc_stream_t *stream,
    void *user_data);

static xqc_int_t
xqc_wt_h3_stream_flush_reset(xqc_wt_h3_stream_t *adapter)
{
    xqc_stream_t *stream = adapter->h3s->stream;
    if (adapter->reset_prefix_sent < adapter->reset_prefix_len) {
        ssize_t n = xqc_stream_send(stream,
            adapter->reset_prefix + adapter->reset_prefix_sent,
            adapter->reset_prefix_len - adapter->reset_prefix_sent, 0);
        if (n < 0) {
            return n == -XQC_EAGAIN ? XQC_OK : (xqc_int_t)n;
        }
        adapter->reset_prefix_sent += n;
        if (adapter->reset_prefix_sent < adapter->reset_prefix_len) {
            return XQC_OK;
        }
    }
    /* A deferred peer STOP may already have reset with its own error. */
    xqc_int_t ret = stream->reset_at.send_state == XQC_RESET_AT_SENT
        ? XQC_OK : xqc_stream_reset(stream, adapter->reset_error);
    if (ret == XQC_OK) {
        adapter->reset_pending = XQC_FALSE;
        xqc_wt_h3_stream_notify_stop(adapter->h3s);
    }
    return ret;
}

xqc_int_t
xqc_wt_h3_stream_reset(xqc_h3_stream_t *h3s, uint64_t error,
    const unsigned char *prefix, size_t prefix_len)
{
    xqc_wt_h3_stream_t *adapter = xqc_wt_h3_stream_context(h3s);
    if (!adapter || prefix_len > sizeof(adapter->reset_prefix)) {
        return -XQC_EPARAM;
    }
    if (!adapter->reset_pending) {
        /* Own the remaining header even after the session callback frees WT. */
        memcpy(adapter->reset_prefix, prefix, prefix_len);
        adapter->reset_prefix_len = prefix_len;
        adapter->reset_prefix_sent = 0;
        adapter->reset_error = error;
        adapter->reset_pending = XQC_TRUE;
    }
    adapter->callback_depth++;
    xqc_int_t ret = xqc_wt_h3_stream_flush_reset(adapter);
    xqc_wt_h3_stream_release(adapter);
    return ret;
}

void *
xqc_wt_h3_stream_context(xqc_h3_stream_t *h3s)
{
    xqc_wt_conn_t *conn = h3s ? xqc_wt_create_conn(h3s->h3c) : NULL;
    if (conn == NULL) {
        return NULL;
    }
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &conn->h3_streams) {
        xqc_wt_h3_stream_t *adapter = xqc_list_entry(pos,
            xqc_wt_h3_stream_t, list);
        if (adapter->h3s == h3s) {
            return adapter;
        }
    }
    return NULL;
}

xqc_bool_t
xqc_wt_h3_stream_is_raw(xqc_h3_stream_t *h3s)
{
    xqc_wt_h3_stream_t *adapter = xqc_wt_h3_stream_context(h3s);
    return adapter && adapter->raw;
}

static xqc_wt_h3_stream_t *
xqc_wt_h3_stream_allocate(xqc_h3_stream_t *h3s)
{
    xqc_wt_h3_stream_t *adapter = xqc_wt_h3_stream_context(h3s);
    if (adapter == NULL) {
        xqc_wt_conn_t *conn = h3s ? xqc_wt_create_conn(h3s->h3c) : NULL;
        if (conn == NULL) {
            return NULL;
        }
        adapter = xqc_calloc(1, sizeof(*adapter));
        if (adapter) {
            adapter->h3s = h3s;
            xqc_list_add_tail(&adapter->list, &conn->h3_streams);
        }
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
    xqc_wt_h3_stream_t *adapter = xqc_wt_h3_stream_context(h3s);
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
    adapter->raw = XQC_TRUE;
    if (h3s->stream) {
        h3s->stream->stream_if =
            (xqc_stream_callbacks_t *)&xqc_wt_h3_stream_callbacks;
    }
    return XQC_OK;
}

xqc_int_t
xqc_wt_h3_stream_set_read_paused(xqc_h3_stream_t *h3s,
    xqc_bool_t paused)
{
    if (h3s == NULL || paused > XQC_TRUE) {
        return -XQC_EPARAM;
    }
    xqc_wt_h3_stream_t *adapter = xqc_wt_h3_stream_context(h3s);
    if (adapter == NULL || adapter->detached || adapter->closed
        || !adapter->raw || h3s->stream == NULL)
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
    xqc_wt_h3_stream_t *adapter = xqc_wt_h3_stream_context(h3s);
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

xqc_int_t
xqc_wt_h3_stream_read(xqc_h3_stream_t *h3s, void *conn_ctx,
    unsigned char *data, size_t data_len, uint8_t fin)
{
    if (fin) {
        h3s->flags |= XQC_HTTP3_STREAM_FLAG_READ_EOF;
    }
    xqc_wt_h3_stream_t *adapter = xqc_wt_h3_stream_context(h3s);
    /* A fragmented native H3 stream-type frame already belongs to H3. */
    if (adapter == NULL && (h3s->type != XQC_H3_STREAM_TYPE_UNKNOWN
        || (!xqc_stream_is_uni(h3s->stream_id)
            && h3s->pctx.frame_pctx.state != XQC_H3_FRM_STATE_TYPE)))
    {
        if (h3s->stream) {
            h3s->stream->stream_if =
                (xqc_stream_callbacks_t *)&h3_stream_callbacks;
        }
        return xqc_h3_stream_process_in(h3s, data, data_len, fin);
    }
    if (data_len == 0 && adapter == NULL) {
        if (fin && h3s->stream) {
            h3s->stream->stream_if =
                (xqc_stream_callbacks_t *)&h3_stream_callbacks;
        }
        return xqc_h3_stream_process_in(h3s, data, data_len, fin);
    }
    adapter = xqc_wt_h3_stream_allocate(h3s);
    if (adapter == NULL) {
        return -XQC_EMALLOC;
    }
    adapter->callback_depth++;
    if (adapter->raw) {
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
        xqc_list_del_init(&adapter->list);
        adapter->closed = XQC_TRUE;
        xqc_wt_h3_stream_release(adapter);
        if (h3s->stream) {
            h3s->stream->stream_if =
                (xqc_stream_callbacks_t *)&h3_stream_callbacks;
        }
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
        adapter->raw = XQC_TRUE;
        xqc_int_t ret = xqc_wt_h3_stream_receive(h3s, adapter, conn_ctx,
            data_len > used ? data + used : NULL, data_len - used, fin);
        xqc_wt_h3_stream_release(adapter);
        return xqc_wt_h3_stream_input_result(h3s, ret);
    }

    unsigned char prefix[8];
    xqc_memcpy(prefix, adapter->prefix, length);
    xqc_list_del_init(&adapter->list);
    adapter->closed = XQC_TRUE;
    xqc_wt_h3_stream_release(adapter);
    if (h3s->stream) {
        h3s->stream->stream_if = (xqc_stream_callbacks_t *)&h3_stream_callbacks;
    }

    xqc_int_t ret = xqc_h3_stream_process_in(h3s, prefix, length,
                                            XQC_FALSE);
    if (ret != XQC_OK) {
        return ret;
    }
    return xqc_h3_stream_process_in(h3s,
        data_len > used ? data + used : prefix + length,
        data_len - used, fin);
}

xqc_int_t
xqc_wt_h3_stream_prepare_read(xqc_h3_stream_t *h3s)
{
    xqc_wt_h3_stream_t *adapter = xqc_wt_h3_stream_context(h3s);
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
    ssize_t consumed = xqc_wt_stream_read(h3s, xqc_wt_create_conn(h3s->h3c),
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

void
xqc_wt_h3_stream_close(xqc_h3_stream_t *h3s)
{
    xqc_wt_h3_stream_t *adapter = xqc_wt_h3_stream_context(h3s);
    if (adapter == NULL || adapter->closed) {
        return;
    }
    adapter->closed = XQC_TRUE;
    adapter->callback_depth++;
    xqc_wt_stream_close(h3s, adapter->stream);
    xqc_list_del_init(&adapter->list);
    xqc_var_buf_free(adapter->recv_buf);
    adapter->recv_buf = NULL;
    xqc_wt_h3_stream_release(adapter);
}

xqc_h3_stream_t *
xqc_wt_h3_stream_create(xqc_h3_conn_t *h3c, xqc_bool_t bidi)
{
    if (h3c == NULL || xqc_wt_create_conn(h3c) == NULL) {
        return NULL;
    }
    xqc_stream_t *stream = xqc_stream_create_with_direction(h3c->conn,
        bidi ? XQC_STREAM_BIDI : XQC_STREAM_UNI, NULL);
    if (stream == NULL) {
        return NULL;
    }
    xqc_h3_stream_t *h3s = xqc_h3_stream_create(h3c, stream,
        XQC_H3_STREAM_TYPE_UNKNOWN, NULL);
    if (h3s == NULL) {
        xqc_destroy_stream(stream);
        return NULL;
    }
    xqc_wt_h3_stream_t *adapter = xqc_wt_h3_stream_allocate(h3s);
    if (adapter == NULL) {
        xqc_destroy_stream(stream);
        return NULL;
    }
    adapter->raw = XQC_TRUE;
    stream->stream_if =
        (xqc_stream_callbacks_t *)&xqc_wt_h3_stream_callbacks;
    return h3s;
}

void
xqc_wt_h3_stream_clear(xqc_wt_conn_t *conn)
{
    while (!xqc_list_empty(&conn->h3_streams)) {
        xqc_wt_h3_stream_t *adapter = xqc_list_entry(
            conn->h3_streams.next, xqc_wt_h3_stream_t, list);
        xqc_wt_h3_stream_close(adapter->h3s);
    }
}

static xqc_int_t
xqc_wt_h3_stream_create_notify(xqc_stream_t *stream, void *user_data)
{
    return h3_stream_callbacks.stream_create_notify(stream, user_data);
}

static xqc_int_t
xqc_wt_h3_read_ordinary(xqc_stream_t *stream, xqc_h3_stream_t *h3s)
{
    xqc_int_t ret = h3_stream_callbacks.stream_read_notify(stream, h3s);
    if (h3s->type == XQC_H3_STREAM_TYPE_CONTROL) {
        /* Keep only the control stream wrapped to observe H3 GOAWAY. */
        stream->stream_if =
            (xqc_stream_callbacks_t *)&xqc_wt_h3_stream_callbacks;
        xqc_wt_conn_notify_goaway(xqc_wt_create_conn(h3s->h3c));
    }
    return ret;
}

static xqc_int_t
xqc_wt_h3_stream_read_notify(xqc_stream_t *stream, void *user_data)
{
    xqc_h3_conn_t *h3c = stream->stream_conn->proto_data;
    xqc_wt_conn_t *conn = xqc_wt_create_conn(h3c);
    if (conn == NULL) {
        stream->stream_if = (xqc_stream_callbacks_t *)&h3_stream_callbacks;
        return h3_stream_callbacks.stream_read_notify(stream, user_data);
    }
    xqc_h3_stream_t *h3s = user_data;
    if (h3s == NULL) {
        h3s = xqc_h3_stream_create(h3c, stream,
            XQC_H3_STREAM_TYPE_UNKNOWN, NULL);
        if (h3s == NULL) {
            return -XQC_H3_ECREATE_STREAM;
        }
    }
    xqc_wt_h3_stream_t *adapter = xqc_wt_h3_stream_context(h3s);
    if (adapter == NULL && h3s->type != XQC_H3_STREAM_TYPE_UNKNOWN) {
        stream->stream_if = (xqc_stream_callbacks_t *)&h3_stream_callbacks;
        return xqc_wt_h3_read_ordinary(stream, h3s);
    }
    if (h3s->flags & XQC_HTTP3_STREAM_IN_READING) {
        return XQC_OK;
    }
    h3s->flags |= XQC_HTTP3_STREAM_IN_READING;
    xqc_int_t ret = xqc_wt_h3_stream_prepare_read(h3s);
    if (ret != XQC_OK) {
        if (ret == -XQC_EAGAIN) {
            xqc_stream_shutdown_read(stream);
        }
        h3s->flags &= ~XQC_HTTP3_STREAM_IN_READING;
        return ret == -XQC_EAGAIN ? XQC_OK
            : xqc_wt_h3_stream_input_result(h3s, ret);
    }

    unsigned char data[XQC_DATA_BUF_SIZE_4K];
    uint8_t fin = 0;
    for (;;) {
        adapter = xqc_wt_h3_stream_context(h3s);
        if (adapter && adapter->paused) {
            xqc_stream_shutdown_read(stream);
            break;
        }
        size_t capacity = sizeof(data);
        if (adapter == NULL || !adapter->raw) {
            /* Leave all ordinary HTTP payload in QUIC for H3 to read. */
            capacity = adapter && adapter->prefix_len
                ? ((size_t)1 << (adapter->prefix[0] >> 6))
                  - adapter->prefix_len : 1;
        }
        ssize_t read = xqc_stream_recv(stream, data, capacity, &fin);
        if (read < 0) {
            /* H3 also consumes receive-reset/error notifications here. */
            ret = XQC_OK;
            break;
        }
        ret = xqc_wt_h3_stream_read(h3s, conn, data, read, fin);
        if (ret != XQC_OK) {
            break;
        }
        if (stream->stream_if == &h3_stream_callbacks) {
            h3s->flags &= ~XQC_HTTP3_STREAM_IN_READING;
            return xqc_wt_h3_read_ordinary(stream, h3s);
        }
        if (fin || (capacity == sizeof(data) && read < capacity)) {
            break;
        }
    }
    h3s->flags &= ~XQC_HTTP3_STREAM_IN_READING;
    return ret;
}

static xqc_int_t
xqc_wt_h3_stream_write_notify(xqc_stream_t *stream, void *user_data)
{
    xqc_h3_stream_t *h3s = user_data;
    xqc_wt_h3_stream_t *adapter = xqc_wt_h3_stream_context(h3s);
    if (adapter && adapter->reset_pending) {
        adapter->callback_depth++;
        xqc_int_t ret = xqc_wt_h3_stream_flush_reset(adapter);
        xqc_wt_h3_stream_release(adapter);
        return ret;
    }
    if (adapter == NULL) {
        if (h3s && h3s->type != XQC_H3_STREAM_TYPE_UNKNOWN) {
            stream->stream_if = (xqc_stream_callbacks_t *)&h3_stream_callbacks;
        }
        return h3_stream_callbacks.stream_write_notify(stream, user_data);
    }
    if (adapter->closed || adapter->detached || !adapter->raw) {
        return XQC_OK;
    }
    adapter->callback_depth++;
    xqc_int_t ret = xqc_wt_stream_write(h3s, adapter->stream);
    xqc_wt_h3_stream_release(adapter);
    return ret;
}

static void
xqc_wt_h3_stream_closing_notify(xqc_stream_t *stream,
    xqc_int_t error, void *user_data)
{
    xqc_h3_stream_t *h3s = user_data;
    xqc_wt_h3_stream_t *adapter = xqc_wt_h3_stream_context(h3s);
    if (adapter == NULL) {
        h3_stream_callbacks.stream_closing_notify(stream, error, user_data);
        return;
    }
    if (adapter->closed || adapter->detached || !adapter->raw) {
        return;
    }
    adapter->callback_depth++;
    xqc_wt_stream_closing(h3s, error, adapter->stream);
    xqc_wt_h3_stream_release(adapter);
}

static xqc_int_t
xqc_wt_h3_stream_close_notify(xqc_stream_t *stream, void *user_data)
{
    if (stream->stream_flag & XQC_STREAM_FLAG_HAS_H3) {
        xqc_wt_h3_stream_close(user_data);
    }
    return h3_stream_callbacks.stream_close_notify(stream, user_data);
}

void
xqc_wt_h3_stream_notify_stop(xqc_h3_stream_t *h3s)
{
    xqc_wt_h3_stream_t *adapter = xqc_wt_h3_stream_context(h3s);
    if (!adapter || adapter->closed || adapter->detached || !adapter->raw
        || !adapter->stop_pending || !h3s->stream
        || h3s->stream->reset_at.send_state == XQC_RESET_AT_PENDING)
    {
        return;
    }
    adapter->stop_pending = XQC_FALSE;
    adapter->callback_depth++;
    xqc_wt_stream_notify_closing(adapter->stream, XQC_TRUE);
    xqc_wt_h3_stream_release(adapter);
}

static void
xqc_wt_h3_stream_stop_sending_notify(xqc_stream_t *stream,
    uint64_t error, void *user_data)
{
    xqc_wt_h3_stream_t *adapter = xqc_wt_h3_stream_context(user_data);
    if (!adapter || adapter->closed || adapter->detached || !adapter->raw
        || adapter->stop_received)
    {
        return;
    }
    adapter->stop_received = XQC_TRUE;
    adapter->stop_pending = XQC_TRUE;
    xqc_wt_h3_stream_notify_stop(user_data);
}

const xqc_stream_callbacks_t xqc_wt_h3_stream_callbacks = {
    .stream_create_notify = xqc_wt_h3_stream_create_notify,
    .stream_read_notify = xqc_wt_h3_stream_read_notify,
    .stream_write_notify = xqc_wt_h3_stream_write_notify,
    .stream_closing_notify = xqc_wt_h3_stream_closing_notify,
    .stream_stop_sending_notify = xqc_wt_h3_stream_stop_sending_notify,
    .stream_close_notify = xqc_wt_h3_stream_close_notify,
};
