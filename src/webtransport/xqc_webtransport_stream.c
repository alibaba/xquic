/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include <limits.h>
#include "src/webtransport/xqc_webtransport_stream.h"
#include "src/webtransport/xqc_webtransport_session.h"
#include "src/webtransport/xqc_webtransport_conn.h"
#include "src/webtransport/xqc_webtransport_wire.h"
#include "src/common/xqc_malloc.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/webtransport/xqc_webtransport_h3_stream.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_send_queue.h"

/* draft-ietf-webtrans-http3-07, Sections 4.3 and 4.4. */
#define XQC_WT_APP_ERROR_FIRST UINT64_C(0x52e4a40fa8db)
#define XQC_WT_SESSION_GONE UINT64_C(0x170d7b68)
#define XQC_WT_BUFFERED_STREAM_REJECTED UINT64_C(0x3994bd84)
#define XQC_WT_PENDING_STREAM_MAX 64

static ssize_t xqc_wt_raw_send(xqc_h3_stream_t *stream,
    const unsigned char *data, size_t len, uint8_t fin);
static xqc_int_t xqc_wt_raw_reset(xqc_h3_stream_t *stream, uint64_t error);
static xqc_int_t xqc_wt_raw_stop(xqc_h3_stream_t *stream, uint64_t error);
static xqc_int_t xqc_wt_raw_pause(xqc_h3_stream_t *stream,
    xqc_bool_t paused);
static void xqc_wt_stream_release(xqc_wt_stream_base_t *stream);
static void xqc_wt_stream_terminate(xqc_wt_stream_base_t *stream);
static xqc_int_t xqc_wt_stream_send_data(xqc_wt_stream_base_t *stream,
    void *data, uint32_t len, int fin);
static xqc_int_t xqc_wt_stream_do_send(xqc_wt_stream_base_t *stream,
    void *data, uint32_t len, int fin);
static xqc_int_t xqc_wt_stream_cancel(xqc_wt_stream_base_t *stream,
    uint32_t error, xqc_bool_t stop);
static xqc_int_t xqc_wt_stream_pause(xqc_wt_stream_base_t *stream,
    xqc_bool_t paused);
static xqc_wt_stream_base_t *xqc_wt_stream_allocate(
    xqc_h3_stream_t *h3_stream, xqc_bool_t bidi, xqc_bool_t outgoing);
static void xqc_wt_stream_attach(xqc_wt_stream_base_t *stream,
    xqc_wt_session_t *session, void *user_data);
static void *xqc_wt_session_open_stream(xqc_wt_session_t *session,
    void *user_data, int *err, xqc_bool_t bidi);

static const xqc_wt_stream_io_ops_t xqc_wt_h3_stream_io = {
    xqc_wt_raw_send,
    xqc_wt_raw_reset,
    xqc_wt_raw_stop,
    xqc_wt_raw_pause,
    xqc_wt_h3_stream_detach,
};

static ssize_t
xqc_wt_raw_send(xqc_h3_stream_t *stream, const unsigned char *data,
    size_t len, uint8_t fin)
{
    return xqc_stream_send(stream->stream, (unsigned char *)data, len, fin);
}

static xqc_int_t
xqc_wt_raw_reset(xqc_h3_stream_t *h3_stream, uint64_t error)
{
    xqc_stream_t *stream = h3_stream->stream;
    xqc_wt_stream_base_t *wt = xqc_wt_h3_stream_get(h3_stream);
    if (wt && wt->session && wt->session->wt_conn->negotiated_version
                                == XQC_WEBTRANSPORT_DRAFT_VERSION_16
        && wt->prefix_sent < wt->prefix_len)
    {
        return xqc_wt_h3_stream_reset(h3_stream, error,
            wt->prefix + wt->prefix_sent, wt->prefix_len - wt->prefix_sent);
    }
    return xqc_stream_reset(stream, error);
}

static xqc_int_t
xqc_wt_raw_stop(xqc_h3_stream_t *h3_stream, uint64_t error)
{
    xqc_stream_t *stream = h3_stream->stream;
    xqc_connection_t *conn = stream->stream_conn;
    if (stream->stream_flag & XQC_STREAM_FLAG_STOP_SENDING_SENT) {
        return XQC_OK;
    }
    if (stream->stream_state_recv >= XQC_RECV_STREAM_ST_DATA_RECVD) {
        return XQC_OK;
    }
    xqc_int_t ret = xqc_write_stop_sending_to_packet(conn, stream, error);
    if (ret == XQC_OK) {
        stream->stream_flag |= XQC_STREAM_FLAG_STOP_SENDING_SENT;
        xqc_engine_remove_wakeup_queue(conn->engine, conn);
        xqc_engine_add_active_queue(conn->engine, conn);
    }
    return ret;
}

static xqc_int_t
xqc_wt_raw_pause(xqc_h3_stream_t *stream, xqc_bool_t paused)
{
    xqc_wt_h3_stream_set_read_paused(stream, paused);
    return XQC_OK;
}

static xqc_wt_stream_base_t *
xqc_wt_stream_allocate(xqc_h3_stream_t *h3_stream, xqc_bool_t bidi,
    xqc_bool_t outgoing)
{
    xqc_wt_stream_base_t *stream = xqc_calloc(1,
        bidi ? sizeof(xqc_wt_bidistream_t) : sizeof(xqc_wt_unistream_t));
    if (stream == NULL) {
        return NULL;
    }
    xqc_init_list_head(&stream->list);
    stream->h3_stream = h3_stream;
    stream->io = &xqc_wt_h3_stream_io;
    stream->id = h3_stream->stream_id;
    stream->bidi = bidi;
    stream->outgoing = outgoing;
    stream->can_send = bidi || outgoing;
    stream->can_recv = bidi || !outgoing;
    if (xqc_wt_h3_stream_set(h3_stream, stream) != XQC_OK) {
        xqc_free(stream);
        return NULL;
    }
    return stream;
}

static void
xqc_wt_stream_attach(xqc_wt_stream_base_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    if (stream->listed) {
        xqc_list_del_init(&stream->list);
    }
    stream->session = session;
    stream->session_id = session->sessionID;
    stream->session_id_complete = XQC_TRUE;
    stream->user_data = user_data ? user_data
        : xqc_wt_session_get_callback_user_data(session);
    xqc_list_add_tail(&stream->list, &session->stream_list);
    stream->listed = XQC_TRUE;
    if (!stream->outgoing && stream->can_send && stream->h3_stream->stream
        && session->wt_conn->negotiated_version
            == XQC_WEBTRANSPORT_DRAFT_VERSION_16)
    {
        /* The reverse direction of a peer-created bidi stream has no header. */
        xqc_stream_set_reliable_size(stream->h3_stream->stream, 0);
    }
}

xqc_wt_stream_base_t *
xqc_wt_stream_bind(xqc_wt_session_t *session, xqc_h3_stream_t *h3_stream,
    xqc_bool_t bidi, xqc_bool_t outgoing, void *user_data)
{
    if (session == NULL || h3_stream == NULL
        || !xqc_wt_session_is_writable(session)
        || xqc_wt_h3_stream_get(h3_stream) != NULL)
    {
        return NULL;
    }
    xqc_wt_stream_base_t *stream =
        xqc_wt_stream_allocate(h3_stream, bidi, outgoing);
    if (stream == NULL) {
        return NULL;
    }
    xqc_wt_stream_attach(stream, session, user_data);
    if (outgoing) {
        /* draft-ietf-webtrans-http3-07 Sections 4.1 and 4.2. */
        unsigned char *end = xqc_put_varint(stream->prefix,
            bidi ? XQC_WT_STREAM_TYPE_BIDIRECTIONAL
                 : XQC_WT_STREAM_TYPE_UNIDIRECTIONAL);
        end = xqc_put_varint(end, session->sessionID);
        stream->prefix_len = end - stream->prefix;
        if (h3_stream->stream && session->wt_conn->negotiated_version
                                    == XQC_WEBTRANSPORT_DRAFT_VERSION_16)
        {
            /* draft-ietf-webtrans-http3-16 §4.4: preserve the full header. */
            if (xqc_stream_set_reliable_size(h3_stream->stream,
                                             stream->prefix_len) != XQC_OK)
            {
                xqc_list_del_init(&stream->list);
                xqc_wt_h3_stream_detach(h3_stream);
                xqc_free(stream);
                return NULL;
            }
        }
    }
    return stream;
}

static void
xqc_wt_stream_release(xqc_wt_stream_base_t *stream)
{
    if (--stream->callback_depth == 0 && stream->closed) {
        xqc_free(stream);
    }
}

xqc_int_t
xqc_wt_stream_notify_create(xqc_wt_stream_base_t *stream)
{
    const xqc_webtransport_stream_callbacks_t *cbs =
        xqc_wt_session_get_stream_callbacks(stream->session);
    xqc_int_t ret = XQC_OK;
    stream->callback_depth++;
    if (stream->bidi && cbs->wt_bidistream_create_notify) {
        ret = cbs->wt_bidistream_create_notify((xqc_wt_bidistream_t *)stream,
            stream->session, stream->user_data);
    } else if (!stream->bidi && cbs->wt_unistream_create_notify) {
        ret = cbs->wt_unistream_create_notify((xqc_wt_unistream_t *)stream,
            stream->session, stream->user_data);
    }
    if (stream->closed && ret == XQC_OK) {
        ret = -XQC_ESTATE;
    }
    xqc_wt_stream_release(stream);
    return ret;
}

ssize_t
xqc_wt_stream_notify_read(xqc_wt_stream_base_t *stream,
    const unsigned char *data, size_t len, uint8_t fin)
{
    if (stream->closed || !stream->can_recv || stream->recv_reset) {
        return -XQC_ESTATE;
    }
    if (stream->read_paused) {
        return -XQC_EAGAIN;
    }
    if (len == 0 && (!fin || stream->recv_fin)) {
        return 0;
    }
    const xqc_webtransport_stream_callbacks_t *cbs =
        xqc_wt_session_get_stream_callbacks(stream->session);
    xqc_bool_t previous_fin = stream->recv_fin;
    stream->recv_fin = fin || previous_fin;
    stream->callback_depth++;
    xqc_int_t ret = XQC_OK;
    if (stream->bidi && cbs->wt_bidistream_read_notify) {
        ret = cbs->wt_bidistream_read_notify((xqc_wt_bidistream_t *)stream,
            stream->session, (void *)data, len, stream->user_data);
    } else if (!stream->bidi && cbs->wt_unistream_read_notify) {
        ret = cbs->wt_unistream_read_notify((xqc_wt_unistream_t *)stream,
            stream->session, (void *)data, len, stream->user_data);
    }
    if (ret == -XQC_EAGAIN && !stream->closed) {
        stream->recv_fin = previous_fin;
        stream->read_paused = XQC_TRUE;
    }
    xqc_wt_stream_release(stream);
    return ret < 0 ? ret : (ssize_t)len;
}

static xqc_int_t
xqc_wt_stream_send_data(xqc_wt_stream_base_t *stream, void *data,
    uint32_t len, int fin)
{
    if (stream == NULL) {
        return -XQC_EPARAM;
    }
    /* A deferred STOP_SENDING may notify the application during send. */
    stream->callback_depth++;
    xqc_int_t ret = xqc_wt_stream_do_send(stream, data, len, fin);
    xqc_wt_stream_release(stream);
    return ret;
}

static xqc_int_t
xqc_wt_stream_do_send(xqc_wt_stream_base_t *stream, void *data,
    uint32_t len, int fin)
{
    if (stream == NULL || (data == NULL && len != 0)
        || len > INT32_MAX || (fin != 0 && fin != 1))
    {
        return -XQC_EPARAM;
    }
    if (stream->closed || !stream->can_send || stream->send_fin
        || stream->send_reset || !xqc_wt_session_is_writable(stream->session))
    {
        return -XQC_ESTATE;
    }
    if (stream->prefix_sent < stream->prefix_len) {
        ssize_t ret = stream->io->send(stream->h3_stream,
            stream->prefix + stream->prefix_sent,
            stream->prefix_len - stream->prefix_sent, 0);
        if (ret < 0) {
            return (xqc_int_t)ret;
        }
        stream->prefix_sent += ret;
        if (stream->prefix_sent < stream->prefix_len) {
            return -XQC_EAGAIN;
        }
    }
    if (stream->closed || stream->send_reset) {
        return -XQC_ESTATE;
    }
    if (len == 0 && !fin) {
        return 0;
    }
    /* Prefix progress is retained separately from application-byte counts. */
    ssize_t ret = stream->io->send(stream->h3_stream, data, len, fin);
    if (ret == len && fin) {
        stream->send_fin = XQC_TRUE;
    }
    return (xqc_int_t)ret;
}

static xqc_int_t
xqc_wt_stream_cancel(xqc_wt_stream_base_t *stream, uint32_t error,
    xqc_bool_t stop)
{
    if (stream == NULL) {
        return -XQC_EPARAM;
    }
    if (stream->closed || (stop ? !stream->can_recv : !stream->can_send)) {
        return -XQC_ESTATE;
    }
    if (stop ? stream->recv_reset : stream->send_reset) {
        return XQC_OK;
    }
    /* draft-ietf-webtrans-http3-07 Section 4.3 reserves every 31st code. */
    uint64_t wire_error = XQC_WT_APP_ERROR_FIRST + error + error / 0x1e;
    stream->callback_depth++;
    xqc_int_t ret = stop ? stream->io->stop(stream->h3_stream, wire_error)
                        : stream->io->reset(stream->h3_stream, wire_error);
    if (ret == XQC_OK && !stream->closed) {
        if (stop) {
            stream->recv_reset = XQC_TRUE;
        } else {
            stream->send_reset = XQC_TRUE;
        }
    }
    xqc_wt_stream_release(stream);
    return ret;
}

static xqc_int_t
xqc_wt_stream_pause(xqc_wt_stream_base_t *stream, xqc_bool_t paused)
{
    if (stream == NULL || paused > XQC_TRUE) {
        return -XQC_EPARAM;
    }
    if (stream->closed || !stream->can_recv || stream->recv_reset) {
        return -XQC_ESTATE;
    }
    stream->read_paused = paused;
    return stream->io->pause(stream->h3_stream, paused);
}

void
xqc_wt_stream_notify_closing(xqc_wt_stream_base_t *stream,
    xqc_bool_t stop_sending)
{
    if (stream == NULL || stream->closed || stream->session == NULL) {
        return;
    }
    stream->stop_sending = stop_sending;
    if (stop_sending) {
        stream->send_reset = XQC_TRUE;
    } else {
        stream->recv_reset = XQC_TRUE;
    }
    const xqc_webtransport_stream_callbacks_t *cbs =
        xqc_wt_session_get_stream_callbacks(stream->session);
    stream->callback_depth++;
    if (stream->bidi && cbs->wt_bidistream_closing_notify) {
        cbs->wt_bidistream_closing_notify((xqc_wt_bidistream_t *)stream,
            stream->session, stream->user_data);
    } else if (!stream->bidi && cbs->wt_unistream_closing_notify) {
        cbs->wt_unistream_closing_notify((xqc_wt_unistream_t *)stream,
            stream->session, stream->user_data);
    }
    xqc_wt_stream_release(stream);
}

void
xqc_wt_stream_notify_close(xqc_wt_stream_base_t *stream)
{
    if (stream == NULL || stream->closed) {
        return;
    }
    stream->closed = XQC_TRUE;
    if (stream->listed) {
        xqc_list_del_init(&stream->list);
        stream->listed = XQC_FALSE;
    }
    stream->io->detach(stream->h3_stream);
    stream->callback_depth++;
    if (stream->session != NULL) {
        const xqc_webtransport_stream_callbacks_t *cbs =
            xqc_wt_session_get_stream_callbacks(stream->session);
        if (stream->bidi && cbs->wt_bidistream_close_notify) {
            cbs->wt_bidistream_close_notify((xqc_wt_bidistream_t *)stream,
                stream->session, stream->user_data);
        } else if (!stream->bidi && cbs->wt_unistream_close_notify) {
            cbs->wt_unistream_close_notify((xqc_wt_unistream_t *)stream,
                stream->session, stream->user_data);
        }
    }
    if (stream->legacy_close) {
        stream->legacy_close();
    }
    if (stream->legacy_recv_close
        && stream->legacy_recv_close != stream->legacy_close)
    {
        stream->legacy_recv_close();
    }
    xqc_wt_stream_release(stream);
}

static void
xqc_wt_stream_terminate(xqc_wt_stream_base_t *stream)
{
    stream->callback_depth++;
    if (stream->can_send && !stream->send_fin && !stream->send_reset) {
        stream->io->reset(stream->h3_stream, XQC_WT_SESSION_GONE);
    }
    if (!stream->closed && stream->can_recv
        && !stream->recv_fin && !stream->recv_reset)
    {
        stream->io->stop(stream->h3_stream, XQC_WT_SESSION_GONE);
    }
    xqc_wt_stream_notify_close(stream);
    xqc_wt_stream_release(stream);
}

void
xqc_wt_session_close_streams(xqc_wt_session_t *session)
{
    while (!xqc_list_empty(&session->stream_list)) {
        xqc_wt_stream_base_t *stream = xqc_list_entry(
            session->stream_list.next, xqc_wt_stream_base_t, list);
        xqc_wt_stream_terminate(stream);
    }
}

ssize_t
xqc_wt_stream_read(xqc_h3_stream_t *h3_stream, void *conn_ctx,
    const unsigned char *data, size_t len, uint8_t fin)
{
    xqc_wt_conn_t *conn = conn_ctx;
    xqc_wt_stream_base_t *stream = xqc_wt_h3_stream_get(h3_stream);
    size_t consumed = 0;
    if (stream == NULL) {
        size_t pending = 0;
        xqc_list_head_t *pos;
        xqc_list_for_each(pos, &conn->pending_streams) {
            pending++;
        }
        if (pending >= XQC_WT_PENDING_STREAM_MAX) {
            xqc_wt_raw_stop(h3_stream, XQC_WT_BUFFERED_STREAM_REJECTED);
            xqc_wt_h3_stream_detach(h3_stream);
            return (ssize_t)len;
        }
        xqc_bool_t bidi = !xqc_stream_is_uni(h3_stream->stream_id);
        stream = xqc_wt_stream_allocate(h3_stream, bidi, XQC_FALSE);
        if (stream == NULL) {
            return -XQC_EMALLOC;
        }
        xqc_list_add_tail(&stream->list, &conn->pending_streams);
        stream->listed = XQC_TRUE;
    }
    while (!stream->session_id_complete && consumed < len) {
        unsigned char byte = data[consumed++];
        if (stream->session_prefix_len == 0) {
            stream->session_prefix_need = (size_t)1 << (byte >> 6);
        }
        stream->session_prefix[stream->session_prefix_len++] = byte;
        if (stream->session_prefix_len == stream->session_prefix_need) {
            xqc_vint_read(stream->session_prefix,
                stream->session_prefix + stream->session_prefix_len,
                &stream->session_id);
            stream->session_id_complete = XQC_TRUE;
            if ((stream->session_id & 3) != 0) {
                /* draft-ietf-webtrans-http3-16 §4: Session ID is a client bidi. */
                if (conn->negotiated_version
                    == XQC_WEBTRANSPORT_DRAFT_VERSION_16)
                {
                    XQC_H3_CONN_ERR(conn->h3_conn, H3_ID_ERROR,
                                    -XQC_H3_DECODE_ERROR);
                }
                xqc_wt_stream_terminate(stream);
                return (ssize_t)len;
            }
        }
    }
    if (!stream->session_id_complete) {
        if (fin) {
            xqc_wt_stream_terminate(stream);
        }
        return (ssize_t)consumed;
    }
    if (stream->session == NULL) {
        xqc_wt_session_t *session =
            xqc_wt_conn_find_session(conn, stream->session_id);
        if (session == NULL || !xqc_wt_session_is_writable(session)) {
            stream->io->pause(h3_stream, XQC_TRUE);
            return consumed ? (ssize_t)consumed : -XQC_EAGAIN;
        }
        xqc_wt_stream_attach(stream, session, NULL);
        if (xqc_wt_stream_notify_create(stream) != XQC_OK) {
            if (xqc_wt_h3_stream_get(h3_stream) != NULL) {
                xqc_wt_stream_terminate(xqc_wt_h3_stream_get(h3_stream));
            }
            return (ssize_t)len;
        }
    }
    ssize_t ret = xqc_wt_stream_notify_read(stream,
        data + consumed, len - consumed, fin);
    if (ret < 0) {
        return consumed ? (ssize_t)consumed : ret;
    }
    return consumed + ret;
}

xqc_int_t
xqc_wt_stream_write(xqc_h3_stream_t *h3_stream, void *stream_ctx)
{
    xqc_wt_stream_base_t *stream = stream_ctx;
    if (stream == NULL || stream->closed || stream->session == NULL
        || stream->send_fin || stream->send_reset)
    {
        return XQC_OK;
    }
    const xqc_webtransport_stream_callbacks_t *cbs =
        xqc_wt_session_get_stream_callbacks(stream->session);
    xqc_int_t ret = XQC_OK;
    stream->callback_depth++;
    if (stream->prefix_sent < stream->prefix_len
        && stream->session->wt_conn->negotiated_version
            == XQC_WEBTRANSPORT_DRAFT_VERSION_16)
    {
        ret = xqc_wt_stream_send_data(stream, NULL, 0, 0);
        if (ret < 0 || stream->closed || stream->send_reset) {
            xqc_wt_stream_release(stream);
            return ret == -XQC_EAGAIN || ret == -XQC_ESTATE ? XQC_OK : ret;
        }
    }
    if (stream->bidi && cbs->wt_bidistream_write_notify) {
        ret = cbs->wt_bidistream_write_notify((xqc_wt_bidistream_t *)stream,
            stream->session, stream->user_data);
    } else if (!stream->bidi && cbs->wt_unistream_write_notify) {
        ret = cbs->wt_unistream_write_notify((xqc_wt_unistream_t *)stream,
            stream->session, stream->user_data);
    }
    xqc_wt_stream_release(stream);
    return ret;
}

void
xqc_wt_stream_closing(xqc_h3_stream_t *h3_stream, xqc_int_t error,
    void *stream_ctx)
{
    /* The legacy transport closing callback currently reports RESET_STREAM. */
    xqc_wt_stream_notify_closing(stream_ctx, XQC_FALSE);
}

void
xqc_wt_stream_close(xqc_h3_stream_t *h3_stream, void *stream_ctx)
{
    xqc_wt_stream_notify_close(stream_ctx);
}

void
xqc_wt_conn_resume_streams(xqc_wt_conn_t *conn)
{
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &conn->pending_streams) {
        xqc_wt_stream_base_t *stream =
            xqc_list_entry(pos, xqc_wt_stream_base_t, list);
        if (!stream->session_id_complete) {
            continue;
        }
        xqc_wt_session_t *session =
            xqc_wt_conn_find_session(conn, stream->session_id);
        if (session != NULL && xqc_wt_session_is_writable(session)) {
            xqc_h3_stream_t *h3_stream = stream->h3_stream;
            xqc_wt_stream_attach(stream, session, NULL);
            if (xqc_wt_stream_notify_create(stream) == XQC_OK) {
                xqc_wt_h3_stream_set_read_paused(h3_stream, XQC_FALSE);
            } else if (xqc_wt_h3_stream_get(h3_stream) != NULL) {
                xqc_wt_stream_terminate(xqc_wt_h3_stream_get(h3_stream));
            }
        }
    }
}

void
xqc_wt_conn_close_pending_streams(xqc_wt_conn_t *conn)
{
    while (!xqc_list_empty(&conn->pending_streams)) {
        xqc_wt_stream_base_t *stream = xqc_list_entry(
            conn->pending_streams.next, xqc_wt_stream_base_t, list);
        xqc_wt_stream_terminate(stream);
    }
}

static void *
xqc_wt_session_open_stream(xqc_wt_session_t *session, void *user_data,
    int *err, xqc_bool_t bidi)
{
    if (err) {
        *err = -XQC_ESTATE;
    }
    if (!xqc_wt_session_is_writable(session)) {
        return NULL;
    }
    xqc_h3_stream_t *h3_stream = xqc_wt_h3_stream_create(
        xqc_wt_session_get_h3_conn(session), bidi);
    if (h3_stream == NULL) {
        if (err) {
            *err = -XQC_ESTREAM_BLOCKED;
        }
        return NULL;
    }
    xqc_wt_stream_base_t *stream =
        xqc_wt_stream_bind(session, h3_stream, bidi, XQC_TRUE, user_data);
    if (stream == NULL) {
        xqc_wt_h3_stream_detach(h3_stream);
        xqc_wt_raw_reset(h3_stream, XQC_WT_SESSION_GONE);
        if (err) {
            *err = -XQC_EMALLOC;
        }
        return NULL;
    }
    xqc_int_t ret = xqc_wt_stream_notify_create(stream);
    if (ret != XQC_OK) {
        if (xqc_wt_h3_stream_get(h3_stream) != NULL) {
            xqc_wt_stream_terminate(xqc_wt_h3_stream_get(h3_stream));
        }
        if (err) {
            *err = ret;
        }
        return NULL;
    }
    if (err) {
        *err = XQC_OK;
    }
    return stream;
}

xqc_wt_unistream_t *
xqc_wt_session_create_uni_stream(xqc_wt_session_t *session,
    void *user_data, int *err)
{
    return xqc_wt_session_open_stream(session, user_data, err, XQC_FALSE);
}

xqc_wt_bidistream_t *
xqc_wt_session_create_bidi_stream(xqc_wt_session_t *session,
    void *user_data, int *err)
{
    return xqc_wt_session_open_stream(session, user_data, err, XQC_TRUE);
}

xqc_wt_unistream_t *
xqc_wt_create_unistream(xqc_wt_unistream_type_t type,
    xqc_wt_session_t *session, wt_stream_close_func_pt close_func,
    xqc_h3_stream_t *h3_stream)
{
    if (type != XQC_WT_STREAM_TYPE_SEND && type != XQC_WT_STREAM_TYPE_RECV) {
        return NULL;
    }
    xqc_wt_stream_base_t *stream = xqc_wt_stream_bind(session, h3_stream,
        XQC_FALSE, type == XQC_WT_STREAM_TYPE_SEND, NULL);
    if (stream) {
        stream->legacy_close = close_func;
    }
    return (xqc_wt_unistream_t *)stream;
}

xqc_wt_bidistream_t *
xqc_wt_create_bidistream(xqc_h3_stream_t *h3_stream,
    xqc_wt_session_t *session, wt_stream_close_func_pt send_close_func,
    wt_stream_close_func_pt recv_close_func, xqc_bool_t passive_created)
{
    xqc_wt_stream_base_t *stream = xqc_wt_stream_bind(session, h3_stream,
        XQC_TRUE, !passive_created, NULL);
    if (stream) {
        stream->legacy_close = send_close_func;
        stream->legacy_recv_close = recv_close_func;
    }
    return (xqc_wt_bidistream_t *)stream;
}

xqc_int_t
xqc_wt_bidistream_send(xqc_wt_bidistream_t *stream, void *data,
    uint32_t len, int fin)
{
    return xqc_wt_stream_send_data((xqc_wt_stream_base_t *)stream,
        data, len, fin);
}

xqc_int_t
xqc_wt_bidistream_reset(xqc_wt_bidistream_t *stream, uint32_t error)
{
    return xqc_wt_stream_cancel((xqc_wt_stream_base_t *)stream, error,
        XQC_FALSE);
}

xqc_int_t
xqc_wt_bidistream_stop_sending(xqc_wt_bidistream_t *stream,
    uint32_t error)
{
    return xqc_wt_stream_cancel((xqc_wt_stream_base_t *)stream, error,
        XQC_TRUE);
}

xqc_int_t
xqc_wt_bidistream_set_read_paused(xqc_wt_bidistream_t *stream,
    xqc_bool_t paused)
{
    return xqc_wt_stream_pause((xqc_wt_stream_base_t *)stream, paused);
}

xqc_bool_t
xqc_wt_bidistream_closing_is_stop_sending(xqc_wt_bidistream_t *stream)
{
    return stream ? stream->base.stop_sending : XQC_FALSE;
}

xqc_stream_id_t
xqc_wt_bidistream_id(xqc_wt_bidistream_t *stream)
{
    return stream ? stream->base.id : UINT64_MAX;
}

xqc_bool_t
xqc_wt_bidistream_get_recv_fin(xqc_wt_bidistream_t *stream)
{
    return stream ? stream->base.recv_fin : XQC_FALSE;
}

xqc_int_t
xqc_wt_unistream_send(xqc_wt_unistream_t *stream, void *data,
    uint32_t len, int fin)
{
    return xqc_wt_stream_send_data((xqc_wt_stream_base_t *)stream,
        data, len, fin);
}

xqc_int_t
xqc_wt_unistream_reset(xqc_wt_unistream_t *stream, uint32_t error)
{
    return xqc_wt_stream_cancel((xqc_wt_stream_base_t *)stream, error,
        XQC_FALSE);
}

xqc_int_t
xqc_wt_unistream_stop_sending(xqc_wt_unistream_t *stream,
    uint32_t error)
{
    return xqc_wt_stream_cancel((xqc_wt_stream_base_t *)stream, error,
        XQC_TRUE);
}

xqc_int_t
xqc_wt_unistream_set_read_paused(xqc_wt_unistream_t *stream,
    xqc_bool_t paused)
{
    return xqc_wt_stream_pause((xqc_wt_stream_base_t *)stream, paused);
}

xqc_bool_t
xqc_wt_unistream_closing_is_stop_sending(xqc_wt_unistream_t *stream)
{
    return stream ? stream->base.stop_sending : XQC_FALSE;
}

xqc_stream_id_t
xqc_wt_unistream_id(xqc_wt_unistream_t *stream)
{
    return stream ? stream->base.id : UINT64_MAX;
}

xqc_bool_t
xqc_wt_unistream_get_recv_fin(xqc_wt_unistream_t *stream)
{
    return stream ? stream->base.recv_fin : XQC_FALSE;
}

xqc_int_t
xqc_wt_unistream_close(xqc_wt_unistream_t *stream)
{
    if (stream == NULL) {
        return -XQC_EPARAM;
    }
    xqc_wt_stream_terminate(&stream->base);
    return XQC_OK;
}

void
xqc_wt_unistream_destroy(xqc_wt_unistream_t *stream)
{
    if (stream) {
        xqc_wt_stream_terminate(&stream->base);
    }
}

xqc_int_t
xqc_wt_bidistream_destroy(xqc_wt_bidistream_t *stream)
{
    if (stream == NULL) {
        return -XQC_EPARAM;
    }
    xqc_wt_stream_terminate(&stream->base);
    return XQC_OK;
}

xqc_h3_stream_t *
xqc_wt_unistream_get_h3_stream(xqc_wt_unistream_t *stream)
{
    return stream ? stream->base.h3_stream : NULL;
}

xqc_h3_stream_t *
xqc_wt_bidistream_get_h3_stream(xqc_wt_bidistream_t *stream)
{
    return stream ? stream->base.h3_stream : NULL;
}

uint64_t
xqc_wt_unistream_getid(xqc_wt_unistream_t *stream)
{
    return xqc_wt_unistream_id(stream);
}

void
xqc_wt_unistream_set_sessionID(xqc_wt_unistream_t *stream,
    uint64_t session_id)
{
    if (stream != NULL && stream->base.session == NULL) {
        stream->base.session_id = session_id;
    }
}
