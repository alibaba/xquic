/**
 * xqc_webtransport_ctx.c
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */
#include "xqc_webtransport_ctx.h"
#include "src/http3/xqc_h3_ctx.h"
#include "src/common/xqc_id_hash.h"
#include "src/http3/frame/xqc_h3_frame_defs.h"
#include "src/http3/xqc_h3_request.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/http3/xqc_h3_ext_bytestream.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/common/xqc_common.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_datagram.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_stream.h"
#include "xqc_webtransport_conn.h"
#include "xqc_webtransport_request.h"
#include "xqc_webtransport_stream.h"
#include "xqc_webtransport_session.h"
#include "xqc_webtransport_wire.h"
#include "xquic/xquic.h"

#define XQC_WT_PENDING_STREAM_BYTES_MAX 65536
#define XQC_WT_BROWSER_DGRAM_FALLBACK_MSS 1200

static void *
xqc_wt_conn_app_user_data(xqc_wt_conn_t *wt_conn)
{
    return wt_conn ? wt_conn->user_data : NULL;
}

static xqc_wt_conn_t *
xqc_wt_conn_from_h3(xqc_h3_conn_t *h3_conn)
{
    return h3_conn ? (xqc_wt_conn_t *)h3_conn->wt_conn : NULL;
}

static xqc_int_t
xqc_wt_notify_unistream_read(xqc_wt_ctx_t *wt_ctx, xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *data, size_t data_len, uint8_t fin)
{
    if (wt_ctx == NULL || wt_ctx->stream_cbs.wt_unistream_read_notify == NULL) {
        return XQC_OK;
    }
    return wt_ctx->stream_cbs.wt_unistream_read_notify(stream, session, data,
        data_len, fin, xqc_wt_conn_app_user_data(session ? session->wt_conn : NULL));
}

static xqc_int_t
xqc_wt_notify_bidistream_read(xqc_wt_ctx_t *wt_ctx, xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *data, size_t data_len, uint8_t fin)
{
    if (wt_ctx == NULL || wt_ctx->stream_cbs.wt_bidistream_read_notify == NULL) {
        return XQC_OK;
    }
    return wt_ctx->stream_cbs.wt_bidistream_read_notify(stream, session, data,
        data_len, fin, xqc_wt_conn_app_user_data(session ? session->wt_conn : NULL));
}

static xqc_int_t
xqc_wt_notify_bidistream_create_once(xqc_wt_ctx_t *wt_ctx,
    xqc_wt_bidistream_t *stream, xqc_wt_session_t *session)
{
    if (wt_ctx == NULL || stream == NULL || session == NULL
        || stream->create_notified
        || wt_ctx->stream_cbs.wt_bidistream_create_notify == NULL)
    {
        return XQC_OK;
    }

    xqc_int_t ret = wt_ctx->stream_cbs.wt_bidistream_create_notify(stream,
        session, xqc_wt_conn_app_user_data(session->wt_conn));
    if (ret < 0) {
        return ret;
    }
    stream->create_notified = XQC_TRUE;
    return XQC_OK;
}

static void
xqc_wt_apply_browser_dgram_fallback(xqc_h3_stream_t *h3_stream)
{
    if (h3_stream == NULL || h3_stream->h3c == NULL
        || h3_stream->h3c->conn == NULL)
    {
        return;
    }

    xqc_h3_conn_t *h3c = h3_stream->h3c;
    xqc_connection_t *conn = h3c->conn;
    xqc_h3_conn_settings_t *local = &h3c->local_h3_conn_settings;
    xqc_h3_conn_settings_t *peer = &h3c->peer_h3_conn_settings;

    if (local->webtransport_mode != XQC_WT_MODE_BROWSER_COMPAT
        || !peer->h3_datagram_present || !peer->h3_datagram
        || conn->remote_settings.max_datagram_frame_size != 0)
    {
        return;
    }

    conn->remote_settings.max_datagram_frame_size =
        XQC_WT_BROWSER_DGRAM_FALLBACK_MSS;
    xqc_datagram_record_mss(conn);
    xqc_log(h3_stream->log, XQC_LOG_INFO,
        "|wt browser dgram fallback|max_datagram_frame_size:%ui|",
        (unsigned int)conn->remote_settings.max_datagram_frame_size);
}

static size_t
xqc_wt_pending_dgram_count_max(xqc_wt_conn_t *wt_conn)
{
    return wt_conn && wt_conn->wt_ctx && wt_conn->wt_ctx->pending_dgram_count_max
        ? wt_conn->wt_ctx->pending_dgram_count_max
        : XQC_WEBTRANSPORT_DEFAULT_PENDING_DGRAM_COUNT_MAX;
}

static size_t
xqc_wt_pending_dgram_bytes_max(xqc_wt_conn_t *wt_conn)
{
    return wt_conn && wt_conn->wt_ctx && wt_conn->wt_ctx->pending_dgram_bytes_max
        ? wt_conn->wt_ctx->pending_dgram_bytes_max
        : XQC_WEBTRANSPORT_DEFAULT_PENDING_DGRAM_BYTES_MAX;
}

static xqc_int_t
xqc_wt_buffer_append(xqc_wt_buffer_list_t *list, const uint8_t *data,
    size_t data_len, size_t *total)
{
    if (data_len == 0) {
        return XQC_OK;
    }
    if (list == NULL || data == NULL || total == NULL
        || data_len > XQC_WT_PENDING_STREAM_BYTES_MAX
        || *total > XQC_WT_PENDING_STREAM_BYTES_MAX - data_len)
    {
        return -XQC_ELIMIT;
    }

    xqc_wt_buffer_t *buf = xqc_calloc(1, sizeof(xqc_wt_buffer_t));
    if (buf == NULL) {
        return -XQC_EMALLOC;
    }
    buf->data = xqc_malloc(data_len);
    if (buf->data == NULL) {
        xqc_free(buf);
        return -XQC_EMALLOC;
    }
    memcpy(buf->data, data, data_len);
    buf->capacity = data_len;
    buf->len = data_len;

    if (list->tail) {
        list->tail->next = buf;
    } else {
        list->head = buf;
    }
    list->tail = buf;
    *total += data_len;
    return XQC_OK;
}

static void
xqc_wt_buffer_list_release(xqc_wt_buffer_list_t *list, size_t *total)
{
    if (list == NULL) {
        return;
    }
    xqc_wt_buffer_t *node = list->head;
    while (node) {
        xqc_wt_buffer_t *next = node->next;
        xqc_free(node->data);
        xqc_free(node);
        node = next;
    }
    list->head = NULL;
    list->tail = NULL;
    if (total) {
        *total = 0;
    }
}

static xqc_wt_pending_stream_t *
xqc_wt_conn_find_pending_stream(xqc_wt_conn_t *wt_conn, uint64_t stream_id,
    xqc_wt_session_t **owner_session)
{
    if (owner_session) {
        *owner_session = NULL;
    }
    if (wt_conn == NULL) {
        return NULL;
    }

    if (wt_conn->sessions) {
        for (int i = 0; i < wt_conn->sessions->count; i++) {
            xqc_id_hash_node_t *node = wt_conn->sessions->list[i];
            while (node) {
                xqc_wt_session_t *session =
                    (xqc_wt_session_t *)node->element.value;
                if (session && session->pending_unistreams) {
                    xqc_wt_pending_stream_t *ps =
                        (xqc_wt_pending_stream_t *)xqc_id_hash_find(
                            session->pending_unistreams, stream_id);
                    if (ps) {
                        if (owner_session) {
                            *owner_session = session;
                        }
                        return ps;
                    }
                }
                node = node->next;
            }
        }
    }

    if (wt_conn->wt_session && wt_conn->wt_session->pending_unistreams) {
        xqc_wt_pending_stream_t *ps =
            (xqc_wt_pending_stream_t *)xqc_id_hash_find(
                wt_conn->wt_session->pending_unistreams, stream_id);
        if (ps) {
            if (owner_session) {
                *owner_session = wt_conn->wt_session;
            }
            return ps;
        }
    }

    if (wt_conn->pending_streams) {
        xqc_wt_pending_stream_t *ps =
            (xqc_wt_pending_stream_t *)xqc_id_hash_find(
                wt_conn->pending_streams, stream_id);
        return ps;
    }

    return NULL;
}

static xqc_int_t
xqc_wt_conn_add_pending_stream(xqc_wt_conn_t *wt_conn, uint64_t stream_id,
    xqc_wt_pending_stream_t *ps)
{
    if (wt_conn == NULL || wt_conn->pending_streams == NULL || ps == NULL) {
        return -XQC_EPARAM;
    }

    xqc_id_hash_element_t element = { stream_id, ps };
    return xqc_id_hash_add(wt_conn->pending_streams, element);
}

static xqc_int_t
xqc_wt_conn_move_pending_stream(xqc_wt_conn_t *wt_conn, xqc_wt_session_t *from,
    xqc_wt_session_t *to, uint64_t stream_id, xqc_wt_pending_stream_t *ps)
{
    if (to == NULL || ps == NULL) {
        return -XQC_EPARAM;
    }
    if (from == to) {
        return XQC_OK;
    }
    if (to->pending_unistreams == NULL) {
        return -XQC_EPARAM;
    }

    xqc_id_hash_table_t *from_table = from ? from->pending_unistreams
        : (wt_conn ? wt_conn->pending_streams : NULL);
    if (from_table == NULL) {
        return -XQC_EPARAM;
    }

    if (xqc_id_hash_delete(from_table, stream_id) != XQC_OK) {
        return XQC_ERROR;
    }

    xqc_id_hash_element_t element = { stream_id, ps };
    if (xqc_id_hash_add(to->pending_unistreams, element) != XQC_OK) {
        xqc_id_hash_add(from_table, element);
        return XQC_ERROR;
    }

    return XQC_OK;
}

static ssize_t
xqc_wt_read_session_id_prefix(uint8_t *header_buf, size_t *header_len,
    const uint8_t *data, size_t data_len, uint64_t *session_id)
{
    if (header_buf == NULL || header_len == NULL || session_id == NULL) {
        return -XQC_EPARAM;
    }

    size_t copied = 0;
    while (*header_len < sizeof(uint64_t) && copied < data_len) {
        header_buf[*header_len] = data[copied];
        (*header_len)++;
        copied++;

        uint64_t value = 0;
        int n = xqc_vint_read(header_buf, header_buf + *header_len, &value);
        if (n > 0) {
            *session_id = value;
            return (ssize_t)copied;
        }
    }

    return *header_len == sizeof(uint64_t) ? -XQC_H3_DECODE_ERROR : -XQC_EAGAIN;
}

static void
xqc_wt_flush_pending_stream_data(xqc_wt_session_t *session,
    xqc_wt_ctx_t *wt_ctx)
{
    if (session == NULL || wt_ctx == NULL || session->pending_unistreams == NULL) {
        return;
    }

    for (int i = 0; i < session->pending_unistreams->count; i++) {
        xqc_id_hash_node_t *node = session->pending_unistreams->list[i];
        while (node) {
            xqc_wt_pending_stream_t *ps =
                (xqc_wt_pending_stream_t *)node->element.value;
            if (ps && ps->type == XQC_WT_PENDING_UNISTREAM && ps->stream) {
                xqc_wt_unistream_t *uni = (xqc_wt_unistream_t *)ps->stream;
                if (uni->session_id == session->session_id
                    && (uni->pending_bytes || uni->pending_fin))
                {
                    xqc_wt_buffer_t *buf = uni->pending_recv.head;
                    while (buf) {
                        xqc_wt_notify_unistream_read(wt_ctx, uni, session,
                            buf->data, buf->len, 0);
                        buf = buf->next;
                    }
                    if (uni->pending_fin
                        && wt_ctx->stream_cbs.wt_unistream_read_notify)
                    {
                        uni->fin.recv_fin = XQC_TRUE;
                        xqc_wt_notify_unistream_read(wt_ctx, uni, session,
                            NULL, 0, 1);
                    }
                    xqc_wt_buffer_list_release(&uni->pending_recv,
                        &uni->pending_bytes);
                    uni->pending_fin = XQC_FALSE;
                }
            } else if (ps && ps->type == XQC_WT_PENDING_BIDISTREAM
                       && ps->stream)
            {
                xqc_wt_bidistream_t *bidi = (xqc_wt_bidistream_t *)ps->stream;
                if (bidi->session_id == session->session_id
                    && (bidi->pending_bytes || bidi->pending_fin))
                {
                    xqc_wt_buffer_t *buf = bidi->pending_recv.head;
                    while (buf) {
                        xqc_wt_notify_bidistream_read(wt_ctx, bidi, session,
                            buf->data, buf->len, 0);
                        buf = buf->next;
                    }
                    if (bidi->pending_fin
                        && wt_ctx->stream_cbs.wt_bidistream_read_notify)
                    {
                        bidi->recv_fin = XQC_TRUE;
                        xqc_wt_notify_bidistream_read(wt_ctx, bidi, session,
                            NULL, 0, 1);
                    }
                    xqc_wt_buffer_list_release(&bidi->pending_recv,
                        &bidi->pending_bytes);
                    bidi->pending_fin = XQC_FALSE;
                }
            }
            node = node->next;
        }
    }
}

static void xqc_wt_reject_buffered_stream(xqc_h3_stream_t *h3_stream,
    xqc_bool_t bidi);
static void xqc_wt_remove_pending_stream(xqc_wt_conn_t *wt_conn,
    xqc_wt_session_t *owner_session, uint64_t stream_id);
static void xqc_wt_pending_stream_destroy(xqc_wt_pending_stream_t *ps);

static void
xqc_wt_move_conn_pending_streams_for_session(xqc_wt_conn_t *wt_conn,
    xqc_wt_session_t *session, xqc_wt_ctx_t *wt_ctx)
{
    if (wt_conn == NULL || session == NULL || wt_conn->pending_streams == NULL) {
        return;
    }

    for (int i = 0; i < wt_conn->pending_streams->count; i++) {
        xqc_id_hash_node_t *node = wt_conn->pending_streams->list[i];
        while (node) {
            xqc_id_hash_node_t *next = node->next;
            uint64_t stream_id = node->element.hash;
            xqc_wt_pending_stream_t *ps =
                (xqc_wt_pending_stream_t *)node->element.value;
            uint64_t ps_session_id = UINT64_MAX;
            if (ps && ps->type == XQC_WT_PENDING_UNISTREAM && ps->stream) {
                xqc_wt_unistream_t *uni = (xqc_wt_unistream_t *)ps->stream;
                ps_session_id = uni->session_id;
                if (ps_session_id == session->session_id) {
                    if (xqc_wt_conn_move_pending_stream(wt_conn, NULL, session,
                            stream_id, ps) == XQC_OK)
                    {
                        uni->session = session;
                        if (wt_ctx && wt_ctx->stream_cbs.wt_unistream_create_notify) {
                            xqc_int_t create_ret =
                                wt_ctx->stream_cbs.wt_unistream_create_notify(
                                    uni, session,
                                    xqc_wt_conn_app_user_data(wt_conn));
                            if (create_ret < 0) {
                                xqc_wt_reject_buffered_stream(uni->h3_stream,
                                    XQC_FALSE);
                                xqc_wt_remove_pending_stream(wt_conn, session,
                                    stream_id);
                                xqc_wt_pending_stream_destroy(ps);
                                node = next;
                                continue;
                            }
                        }
                        if (!uni->flow_counted
                            && xqc_wt_session_on_incoming_stream(session,
                                XQC_FALSE) == XQC_OK)
                        {
                            uni->flow_counted = XQC_TRUE;
                        }
                        xqc_wt_session_on_incoming_data(session,
                            (uint64_t)uni->pending_bytes);
                    }
                }
            } else if (ps && ps->type == XQC_WT_PENDING_BIDISTREAM && ps->stream) {
                xqc_wt_bidistream_t *bidi = (xqc_wt_bidistream_t *)ps->stream;
                ps_session_id = bidi->session_id;
                if (ps_session_id == session->session_id) {
                    if (xqc_wt_conn_move_pending_stream(wt_conn, NULL, session,
                            stream_id, ps) == XQC_OK)
                    {
                        bidi->session = session;
                        xqc_int_t create_ret =
                            xqc_wt_notify_bidistream_create_once(wt_ctx, bidi,
                                session);
                        if (create_ret < 0) {
                            xqc_wt_reject_buffered_stream(bidi->h3_stream,
                                XQC_TRUE);
                            xqc_wt_remove_pending_stream(wt_conn, session,
                                stream_id);
                            xqc_wt_pending_stream_destroy(ps);
                            node = next;
                            continue;
                        }
                        if (!bidi->flow_counted
                            && xqc_wt_session_on_incoming_stream(session,
                                XQC_TRUE) == XQC_OK)
                        {
                            bidi->flow_counted = XQC_TRUE;
                        }
                        xqc_wt_session_on_incoming_data(session,
                            (uint64_t)bidi->pending_bytes);
                    }
                }
            }
            node = next;
        }
    }
}

static xqc_int_t
xqc_wt_buffer_pending_dgram(xqc_wt_conn_t *wt_conn, uint64_t session_id,
    const void *payload, size_t payload_len, void *user_data,
    uint64_t recv_time)
{
    if (wt_conn == NULL || (payload == NULL && payload_len > 0)) {
        return -XQC_EPARAM;
    }
    size_t count_max = xqc_wt_pending_dgram_count_max(wt_conn);
    size_t bytes_max = xqc_wt_pending_dgram_bytes_max(wt_conn);
    if (wt_conn->pending_dgram_count >= count_max
        || payload_len > bytes_max
        || wt_conn->pending_dgram_bytes > bytes_max - payload_len)
    {
        wt_conn->pending_dgram_overflow_dropped++;
        return -XQC_ELIMIT;
    }

    xqc_wt_pending_dgram_t *node =
        xqc_calloc(1, sizeof(xqc_wt_pending_dgram_t));
    if (node == NULL) {
        return -XQC_EMALLOC;
    }
    node->data = xqc_malloc(payload_len ? payload_len : 1);
    if (node->data == NULL) {
        xqc_free(node);
        return -XQC_EMALLOC;
    }
    if (payload_len > 0) {
        memcpy(node->data, payload, payload_len);
    }
    node->data_len = payload_len;
    node->session_id = session_id;
    node->user_data = user_data;
    node->recv_time = recv_time;

    if (wt_conn->pending_dgram_tail) {
        wt_conn->pending_dgram_tail->next = node;
    } else {
        wt_conn->pending_dgram_head = node;
    }
    wt_conn->pending_dgram_tail = node;
    wt_conn->pending_dgram_count++;
    wt_conn->pending_dgram_bytes += payload_len;
    wt_conn->pending_dgram_buffered++;
    return XQC_OK;
}

static void
xqc_wt_flush_pending_dgrams(xqc_wt_conn_t *wt_conn, xqc_wt_session_t *session,
    xqc_wt_ctx_t *wt_ctx)
{
    if (wt_conn == NULL || session == NULL || wt_ctx == NULL
        || wt_ctx->dgram_cbs.dgram_read_notify == NULL)
    {
        return;
    }

    xqc_wt_pending_dgram_t *prev = NULL;
    xqc_wt_pending_dgram_t *node = wt_conn->pending_dgram_head;
    while (node) {
        xqc_wt_pending_dgram_t *next = node->next;
        if (node->session_id == session->session_id) {
            wt_ctx->dgram_cbs.dgram_read_notify(session, node->data,
                node->data_len, xqc_wt_conn_app_user_data(wt_conn),
                node->recv_time);
            if (prev) {
                prev->next = next;
            } else {
                wt_conn->pending_dgram_head = next;
            }
            if (wt_conn->pending_dgram_tail == node) {
                wt_conn->pending_dgram_tail = prev;
            }
            wt_conn->pending_dgram_count--;
            wt_conn->pending_dgram_bytes -= node->data_len;
            xqc_free(node->data);
            xqc_free(node);
        } else {
            prev = node;
        }
        node = next;
    }
}

static void
xqc_wt_establish_session(xqc_wt_session_t *session, xqc_wt_ctx_t *wt_ctx)
{
    if (session == NULL || wt_ctx == NULL) {
        return;
    }

    xqc_wt_apply_browser_dgram_fallback(session->h3_stream);

    if (xqc_wt_session_mark_established(session) == XQC_OK) {
        xqc_wt_move_conn_pending_streams_for_session(session->wt_conn, session,
            wt_ctx);
        xqc_wt_flush_pending_stream_data(session, wt_ctx);
        xqc_wt_flush_pending_dgrams(session->wt_conn, session, wt_ctx);
    }
}

xqc_wt_ctx_t *
xqc_wt_ctx_get_by_engine(xqc_engine_t *engine)
{
    const char *alpns[] = { XQC_ALPN_H3, XQC_ALPN_H3_29, XQC_ALPN_H3_EXT };
    for (size_t i = 0; i < sizeof(alpns) / sizeof(alpns[0]); i++) {
        xqc_h3_ctx_t *h3_ctx = xqc_engine_get_alpn_ctx(engine,
            alpns[i], strlen(alpns[i]));
        if (h3_ctx && h3_ctx->ext_ctx) {
            return (xqc_wt_ctx_t *)h3_ctx->ext_ctx;
        }
    }
    return NULL;
}

static xqc_wt_ctx_t *
xqc_wt_ctx_get_by_h3_alpn(xqc_h3_conn_t *h3_conn)
{
    if (h3_conn == NULL || h3_conn->conn == NULL
        || h3_conn->conn->engine == NULL || h3_conn->conn->alpn == NULL)
    {
        return NULL;
    }

    xqc_h3_ctx_t *h3_ctx = xqc_engine_get_alpn_ctx(h3_conn->conn->engine,
        h3_conn->conn->alpn, h3_conn->conn->alpn_len);
    return h3_ctx ? (xqc_wt_ctx_t *)h3_ctx->ext_ctx : NULL;
}

static xqc_h3_callbacks_t *
xqc_wt_orig_h3_cbs(xqc_h3_conn_t *h3_conn)
{
    if (h3_conn == NULL || h3_conn->conn == NULL
        || h3_conn->conn->engine == NULL || h3_conn->conn->alpn == NULL)
    {
        return NULL;
    }

    xqc_h3_ctx_t *h3_ctx = xqc_engine_get_alpn_ctx(h3_conn->conn->engine,
        h3_conn->conn->alpn, h3_conn->conn->alpn_len);
    return h3_ctx && h3_ctx->wt_has_orig_h3_cbs
        ? &h3_ctx->wt_orig_h3_cbs
        : NULL;
}

xqc_wt_ctx_t *
xqc_wt_get_ctx_by_h3conn(xqc_h3_conn_t *h3_conn)
{
    xqc_wt_conn_t *wt_conn = xqc_wt_conn_from_h3(h3_conn);
    if (wt_conn && wt_conn->wt_ctx) {
        return wt_conn->wt_ctx;
    }
    /* fallback: retrieve from engine alpn ctx */
    return xqc_wt_ctx_get_by_h3_alpn(h3_conn);
}

xqc_wt_ctx_t *
xqc_wt_get_ctx_by_conn(xqc_connection_t *conn)
{
    xqc_h3_conn_t *h3_conn = conn ? (xqc_h3_conn_t *)conn->proto_data : NULL;
    xqc_wt_conn_t *wt_conn = xqc_wt_conn_from_h3(h3_conn);
    if (wt_conn && wt_conn->wt_ctx) {
        return wt_conn->wt_ctx;
    }
    if (h3_conn) {
        return xqc_wt_ctx_get_by_h3_alpn(h3_conn);
    }
    return NULL;
}

static void
xqc_wt_close_invalid_dgram_conn(xqc_connection_t *conn)
{
    if (conn) {
        xqc_conn_close_with_error(conn, H3_ID_ERROR);
    }
}

static void
xqc_wt_drop_buffer_overflow_dgram(xqc_wt_conn_t *wt_conn, uint64_t session_id,
    size_t payload_len)
{
    if (wt_conn && wt_conn->h3_conn) {
        xqc_log(wt_conn->h3_conn->log, XQC_LOG_WARN,
                "|drop pending WT datagram|session_id:%ui|payload_len:%uz|",
                session_id, payload_len);
    }
}

static xqc_int_t
xqc_wt_reset_rejected_connect_stream(xqc_h3_stream_t *h3_stream)
{
    if (h3_stream == NULL || h3_stream->h3c == NULL
        || h3_stream->h3c->conn == NULL || h3_stream->stream == NULL)
    {
        return -XQC_EPARAM;
    }

    return xqc_write_reset_stream_to_packet(h3_stream->h3c->conn,
        h3_stream->stream, H3_REQUEST_REJECTED,
        h3_stream->stream->stream_send_offset);
}

static void
xqc_wt_abort_closed_session_stream(xqc_h3_stream_t *h3_stream,
    xqc_bool_t bidi)
{
    if (h3_stream == NULL || h3_stream->h3c == NULL
        || h3_stream->h3c->conn == NULL || h3_stream->stream == NULL
        || h3_stream->h3c->conn->conn_state >= XQC_CONN_STATE_CLOSING)
    {
        return;
    }

    if (bidi) {
        xqc_write_reset_stream_at_to_packet(h3_stream->h3c->conn,
            h3_stream->stream, XQC_WT_ERROR_SESSION_GONE,
            h3_stream->stream->stream_send_offset,
            h3_stream->stream->stream_send_offset);
    }
    xqc_write_stop_sending_to_packet(h3_stream->h3c->conn,
        h3_stream->stream, XQC_WT_ERROR_SESSION_GONE);
}

static void
xqc_wt_reject_buffered_stream(xqc_h3_stream_t *h3_stream, xqc_bool_t bidi)
{
    if (h3_stream == NULL || h3_stream->h3c == NULL
        || h3_stream->h3c->conn == NULL || h3_stream->stream == NULL
        || h3_stream->h3c->conn->conn_state >= XQC_CONN_STATE_CLOSING)
    {
        return;
    }

    if (bidi) {
        xqc_write_reset_stream_at_to_packet(h3_stream->h3c->conn,
            h3_stream->stream, XQC_WT_ERROR_BUFFERED_STREAM_REJECTED,
            h3_stream->stream->stream_send_offset,
            h3_stream->stream->stream_send_offset);
    }
    xqc_write_stop_sending_to_packet(h3_stream->h3c->conn,
        h3_stream->stream, XQC_WT_ERROR_BUFFERED_STREAM_REJECTED);
}

static void
xqc_wt_remove_pending_stream(xqc_wt_conn_t *wt_conn,
    xqc_wt_session_t *owner_session, uint64_t stream_id)
{
    if (owner_session && owner_session->pending_unistreams) {
        xqc_id_hash_delete(owner_session->pending_unistreams, stream_id);
        return;
    }
    if (wt_conn && wt_conn->pending_streams) {
        xqc_id_hash_delete(wt_conn->pending_streams, stream_id);
    }
}

static void
xqc_wt_pending_stream_destroy(xqc_wt_pending_stream_t *ps)
{
    if (ps == NULL) {
        return;
    }
    if (ps->type == XQC_WT_PENDING_BIDISTREAM) {
        xqc_wt_bidistream_t *bidi = (xqc_wt_bidistream_t *)ps->stream;
        if (bidi) {
            xqc_wt_stream_buffer_list_release(&bidi->pending_recv);
            xqc_wt_bidistream_destroy(bidi);
        }
    } else {
        xqc_wt_unistream_t *uni = (xqc_wt_unistream_t *)ps->stream;
        if (uni) {
            xqc_wt_stream_buffer_list_release(&uni->pending_recv);
            if (uni->type == XQC_WT_STREAM_TYPE_SEND && uni->stream.send_stream) {
                xqc_free(uni->stream.send_stream);
            } else if (uni->type == XQC_WT_STREAM_TYPE_RECV && uni->stream.recv_stream) {
                xqc_free(uni->stream.recv_stream);
            }
            xqc_free(uni);
        }
    }
    xqc_free(ps);
}

static xqc_wt_unistream_t *
xqc_wt_create_pending_recv_unistream(xqc_h3_stream_t *h3_stream)
{
    if (h3_stream == NULL) {
        return NULL;
    }
    xqc_wt_unistream_t *uni = xqc_calloc(1, sizeof(xqc_wt_unistream_t));
    if (uni == NULL) {
        return NULL;
    }
    uni->type = XQC_WT_STREAM_TYPE_RECV;
    uni->stream.recv_stream = xqc_wt_create_recv_stream_passive(h3_stream, NULL);
    if (uni->stream.recv_stream == NULL) {
        xqc_free(uni);
        return NULL;
    }
    uni->h3_stream = h3_stream;
    uni->conn = h3_stream->h3c ? h3_stream->h3c->conn : NULL;
    uni->packet_parsed_flag = XQC_FALSE;
    return uni;
}

static xqc_wt_bidistream_t *
xqc_wt_create_pending_recv_bidistream(xqc_h3_stream_t *h3_stream)
{
    if (h3_stream == NULL) {
        return NULL;
    }
    xqc_wt_bidistream_t *bidi = xqc_calloc(1, sizeof(xqc_wt_bidistream_t));
    if (bidi == NULL) {
        return NULL;
    }
    bidi->h3_stream = h3_stream;
    bidi->send_stream = xqc_calloc(1, sizeof(xqc_wt_send_stream_t));
    if (bidi->send_stream == NULL) {
        xqc_free(bidi);
        return NULL;
    }
    bidi->send_stream->h3_stream = h3_stream;
    bidi->send_stream->stream = h3_stream->stream;
    bidi->send_stream->send_header_flag = XQC_TRUE;
    bidi->recv_stream = xqc_wt_create_recv_stream_passive(h3_stream, NULL);
    if (bidi->recv_stream == NULL) {
        xqc_free(bidi->send_stream);
        xqc_free(bidi);
        return NULL;
    }
    bidi->packet_parsed_flag = XQC_FALSE;
    return bidi;
}

static void
xqc_wt_handle_h3_datagram_payload(xqc_connection_t *conn, xqc_wt_ctx_t *wt_ctx,
    xqc_wt_conn_t *wt_conn, const void *data, size_t data_len,
    void *user_data, uint64_t recv_time)
{
    if (conn == NULL || wt_ctx == NULL || wt_conn == NULL) {
        return;
    }

    const uint8_t *buf = (const uint8_t *)data;
    size_t         len = data_len;
    uint64_t       session_id = 0;
    ssize_t        consumed   = xqc_wt_decode_h3_datagram_session_id(buf, len,
        &session_id);

    if (consumed <= 0 || (size_t)consumed > len) {
        xqc_wt_close_invalid_dgram_conn(conn);
        return;
    }

    xqc_wt_session_t *wt_session = NULL;
    const void       *payload    = buf + consumed;
    size_t            payload_len = len - (size_t)consumed;

    wt_session = xqc_wt_conn_find_session(wt_conn, session_id);
    if (wt_session == NULL) {
        if (xqc_wt_conn_is_closed_session(wt_conn, session_id)) {
            return;
        }
        if (xqc_wt_conn_can_buffer_unknown_session(wt_conn, session_id)) {
            xqc_int_t buf_ret = xqc_wt_buffer_pending_dgram(wt_conn,
                session_id, payload, payload_len, user_data, recv_time);
            if (buf_ret < 0) {
                xqc_wt_drop_buffer_overflow_dgram(wt_conn, session_id,
                    payload_len);
            }
            return;
        }
        wt_conn->unknown_session_dgram_rejected++;
        xqc_wt_close_invalid_dgram_conn(conn);
        return;
    }

    if (wt_session->terminated) {
        return;
    }
    if (!wt_session->established) {
        xqc_int_t buf_ret = xqc_wt_buffer_pending_dgram(wt_conn, session_id,
            payload, payload_len, user_data, recv_time);
        if (buf_ret < 0) {
            xqc_wt_drop_buffer_overflow_dgram(wt_conn, session_id, payload_len);
        }
        return;
    }

    /* call application callback if registered */
    if (wt_session && wt_ctx->dgram_cbs.dgram_read_notify) {
        wt_ctx->dgram_cbs.dgram_read_notify(wt_session, payload, payload_len,
            xqc_wt_conn_app_user_data(wt_conn), recv_time);
    }
}

/* WT settings IDs (see src/http3/xqc_h3_defs.h):
 *   XQC_H3_SETTINGS_ENABLE_CONNECT_PROTOCOL      = 0x08       (RFC 9220)
 *   XQC_H3_SETTINGS_H3_DATAGRAM                  = 0x33       (RFC 9297)
 *   XQC_H3_SETTINGS_WT_ENABLED                    = 0x2c7cf000 (draft-15)
 *   XQC_H3_SETTINGS_WT_INITIAL_MAX_STREAMS_UNI    = 0x2b64     (draft-15)
 *   XQC_H3_SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI   = 0x2b65     (draft-15)
 *   XQC_H3_SETTINGS_WT_INITIAL_MAX_DATA           = 0x2b61     (draft-15)
 */

int
xqc_wt_h3_conn_create_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *h3c_user_data)
{
    xqc_wt_ctx_t *wt_ctx = xqc_wt_ctx_get_by_h3_alpn(h3_conn);
    if (wt_ctx == NULL) {
        return XQC_OK;
    }
    xqc_wt_conn_t *wt_conn = xqc_wt_conn_create(h3_conn);
    if (wt_conn == NULL) {
        return -XQC_EMALLOC;
    }
    xqc_h3_callbacks_t *orig = xqc_wt_orig_h3_cbs(h3_conn);
    if (orig && orig->h3c_cbs.h3_conn_create_notify) {
        int ret = orig->h3c_cbs.h3_conn_create_notify(h3_conn, cid,
            h3c_user_data);
        if (ret != XQC_OK) {
            xqc_wt_conn_close(wt_conn);
            return ret;
        }
    }
    xqc_connection_t *conn = xqc_h3_conn_get_xqc_conn(h3_conn);
    wt_conn->wt_ctx = wt_ctx;
    wt_conn->user_data = xqc_h3_conn_get_user_data(h3_conn);
    wt_conn->py_handle = conn->engine->user_data;  /* py_client_t* or py_server_t* */
    xqc_wt_conn_set_dgram_mss(wt_conn, XQC_WEBTRANSPORT_DEFAULT_DGRAM_MSS);
    h3_conn->wt_conn = wt_conn;

    xqc_h3_conn_get_peer_addr(h3_conn, (struct sockaddr *)&wt_conn->peer_addr,
        sizeof(wt_conn->peer_addr), &wt_conn->peer_addrlen);

    memcpy(&wt_conn->cid, cid, sizeof(*cid));

    return 0;
}

int
xqc_wt_h3_request_create_notify(xqc_h3_request_t *h3_request, void *h3s_user_data)
{
    xqc_h3_conn_t *h3_conn       = (h3_request && h3_request->h3_stream)
        ? h3_request->h3_stream->h3c
        : NULL;
    if (h3_conn == NULL) {
        return XQC_ERROR;
    }
    xqc_wt_request_t *wt_request = xqc_wt_request_create(h3_conn->log);
    if (wt_request == NULL) {
        return XQC_ERROR;
    }
    wt_request->h3_request       = h3_request;
    wt_request->is_header_recv   = XQC_FALSE;

    xqc_wt_conn_t *wt_conn = xqc_wt_conn_from_h3(h3_conn);
    wt_request->wt_conn    = wt_conn;
    wt_request->app_user_data = h3s_user_data;

    if (h3_conn->conn && h3_conn->conn->conn_type == XQC_CONN_TYPE_CLIENT) {
        xqc_stream_id_t h3_stream_id = h3_request->h3_stream
            ? h3_request->h3_stream->stream_id
            : 0;
        xqc_wt_session_t *wt_session =
            xqc_wt_session_init(h3_stream_id, wt_conn, h3_request->h3_stream);
        if (wt_session == NULL) {
            xqc_wt_request_destroy(wt_request);
            return -XQC_EMALLOC;
        }
        wt_session->h3_request = h3_request;
        wt_request->user_data = (void *)wt_session;
    }

    xqc_h3_request_set_user_data(h3_request, wt_request);

    return 0;
}

int
check_str_equal(const char *str1, const char *str2)
{
    if (str1 == NULL || str2 == NULL) {
        return 0;
    }
    return strcmp(str1, str2) == 0;
}

static xqc_bool_t
xqc_wt_header_value_equal(xqc_http_headers_t *headers, const char *name,
    const char *value)
{
    size_t name_len = strlen(name);
    size_t value_len = strlen(value);
    if (headers == NULL) {
        return XQC_FALSE;
    }
    for (int i = 0; i < headers->count; i++) {
        xqc_http_header_t *header = &headers->headers[i];
        if (header->name.iov_len == name_len
            && memcmp(header->name.iov_base, name, name_len) == 0
            && header->value.iov_len == value_len
            && memcmp(header->value.iov_base, value, value_len) == 0)
        {
            return XQC_TRUE;
        }
    }
    return XQC_FALSE;
}

static xqc_bool_t
xqc_wt_request_is_webtransport(xqc_h3_request_t *h3_request)
{
    if (h3_request == NULL) {
        return XQC_FALSE;
    }
    xqc_http_headers_t *headers =
        &h3_request->h3_header[XQC_H3_REQUEST_HEADER];
    return xqc_wt_header_value_equal(headers, ":method", "CONNECT")
        && (xqc_wt_header_value_equal(headers, ":protocol", "webtransport-h3")
            || xqc_wt_header_value_equal(headers, ":protocol", "webtransport"));
}

static int
xqc_wt_forward_h3_request_create(xqc_wt_request_t *wt_request,
    xqc_wt_ctx_t *wt_ctx)
{
    xqc_h3_callbacks_t *orig = xqc_wt_orig_h3_cbs(
        wt_request->h3_request->h3_stream->h3c);
    if (wt_request == NULL || wt_request->h3_request == NULL
        || orig == NULL || orig->h3r_cbs.h3_request_create_notify == NULL
        || wt_request->passthrough_create_done)
    {
        return XQC_OK;
    }

    xqc_h3_request_set_user_data(wt_request->h3_request,
        wt_request->app_user_data);
    int ret = orig->h3r_cbs.h3_request_create_notify(wt_request->h3_request,
        wt_request->app_user_data);
    wt_request->app_user_data = wt_request->h3_request->user_data;
    xqc_h3_request_set_user_data(wt_request->h3_request, wt_request);
    wt_request->passthrough_create_done = XQC_TRUE;
    return ret;
}

static int
xqc_wt_forward_h3_request_read(xqc_wt_request_t *wt_request,
    xqc_wt_ctx_t *wt_ctx, xqc_request_notify_flag_t flag)
{
    xqc_h3_callbacks_t *orig = xqc_wt_orig_h3_cbs(
        wt_request->h3_request->h3_stream->h3c);
    if (orig == NULL || orig->h3r_cbs.h3_request_read_notify == NULL) {
        return XQC_OK;
    }
    return orig->h3r_cbs.h3_request_read_notify(wt_request->h3_request, flag,
        wt_request->app_user_data);
}

static xqc_int_t
xqc_wt_create_server_session_for_request(xqc_wt_request_t *wt_request)
{
    if (wt_request == NULL || wt_request->user_data != NULL) {
        return XQC_OK;
    }
    xqc_h3_request_t *h3_request = wt_request->h3_request;
    xqc_h3_stream_t *h3_stream = h3_request ? h3_request->h3_stream : NULL;
    xqc_stream_id_t h3_stream_id = h3_stream ? h3_stream->stream_id : 0;
    xqc_wt_session_t *wt_session =
        xqc_wt_session_init(h3_stream_id, wt_request->wt_conn, h3_stream);
    if (wt_session == NULL) {
        return -XQC_EMALLOC;
    }
    wt_session->h3_request = h3_request;
    wt_request->user_data = wt_session;
    return XQC_OK;
}

static xqc_bool_t
xqc_wt_peer_satisfies_draft15_requirements(xqc_h3_stream_t *h3_stream)
{
    if (h3_stream == NULL || h3_stream->h3c == NULL
        || h3_stream->h3c->conn == NULL)
    {
        return XQC_FALSE;
    }

    xqc_h3_conn_settings_t *peer = &h3_stream->h3c->peer_h3_conn_settings;
    xqc_connection_t *conn = h3_stream->h3c->conn;

    if (!peer->wt_enabled_present || !peer->enable_webtransport
        || !peer->enable_connect_protocol_present
        || !peer->enable_connect_protocol
        || !peer->h3_datagram_present || !peer->h3_datagram)
    {
        return XQC_FALSE;
    }

    if (conn->remote_settings.max_datagram_frame_size == 0
        || !conn->remote_settings.reset_stream_at)
    {
        return XQC_FALSE;
    }

    return XQC_TRUE;
}

static xqc_bool_t
xqc_wt_local_requires_draft15_strict(xqc_h3_conn_t *h3c)
{
    if (h3c == NULL) {
        return XQC_FALSE;
    }
    return h3c->local_h3_conn_settings.webtransport_mode
           == XQC_WT_MODE_DRAFT15_STRICT;
}

static xqc_int_t
xqc_wt_client_check_draft15_requirements(xqc_h3_stream_t *h3_stream,
    xqc_bool_t wait_for_settings)
{
    if (h3_stream == NULL || h3_stream->h3c == NULL) {
        return -XQC_EPARAM;
    }
    if (!xqc_wt_local_requires_draft15_strict(h3_stream->h3c)) {
        return XQC_OK;
    }
    if (!(h3_stream->h3c->flags & XQC_H3_CONN_FLAG_SETTINGS_RECVED)) {
        return wait_for_settings ? -XQC_EAGAIN : -H3_MISSING_SETTINGS;
    }
    if (!xqc_wt_peer_satisfies_draft15_requirements(h3_stream)) {
        xqc_h3_conn_settings_t *peer = &h3_stream->h3c->peer_h3_conn_settings;
        xqc_connection_t *conn = h3_stream->h3c->conn;
        xqc_log(h3_stream->log, XQC_LOG_ERROR,
                "|reject webtransport client request|missing_requirements|settings:%ui|wt:%ui/%ui|connect:%ui/%ui|dgram:%ui/%ui|fc:%ui%ui%ui|max_dgram:%ui|reset_at:%ui|",
                (unsigned int)(h3_stream->h3c->flags & XQC_H3_CONN_FLAG_SETTINGS_RECVED),
                (unsigned int)peer->enable_webtransport,
                (unsigned int)peer->wt_enabled_present,
                (unsigned int)peer->enable_connect_protocol,
                (unsigned int)peer->enable_connect_protocol_present,
                (unsigned int)peer->h3_datagram,
                (unsigned int)peer->h3_datagram_present,
                (unsigned int)peer->wt_initial_max_streams_uni_present,
                (unsigned int)peer->wt_initial_max_streams_bidi_present,
                (unsigned int)peer->wt_initial_max_data_present,
                conn ? (unsigned int)conn->remote_settings.max_datagram_frame_size : 0,
                conn ? (unsigned int)conn->remote_settings.reset_stream_at : 0);
        return -XQC_EPROTO;
    }
    return XQC_OK;
}

int
xqc_wt_process_request_headers(xqc_wt_request_t *wt_request, xqc_wt_ctx_t *wt_ctx,
    xqc_http_headers_t *headers)
{
    xqc_wt_session_t *session = (xqc_wt_session_t *)(wt_request->user_data);
    xqc_connection_t *conn = session && session->wt_conn && session->wt_conn->h3_conn
        ? session->wt_conn->h3_conn->conn : NULL;
    xqc_conn_type_t type = conn ? conn->conn_type : XQC_CONN_TYPE_CLIENT;

    if (wt_ctx->session_cbs.webtransport_session_create_notify) {
        if (type == XQC_CONN_TYPE_CLIENT && session) {
            char *status = xqc_wt_request_table_find(wt_request, ":status");
            if (status && status[0] == '2') {
                xqc_int_t req_ret = xqc_wt_client_check_draft15_requirements(
                    session->h3_stream, XQC_FALSE);
                if (req_ret != XQC_OK) {
                    return req_ret;
                }
                xqc_wt_establish_session(session, wt_ctx);
            }
        }
        void *h3c_user_data = session ? xqc_wt_conn_app_user_data(session->wt_conn) : NULL;
        int ret = wt_ctx->session_cbs.webtransport_session_create_notify(session,
            headers, NULL, h3c_user_data);
        if (session && type == XQC_CONN_TYPE_SERVER && ret == 1) {
            xqc_wt_establish_session(session, wt_ctx);
        }
        return ret;
    }
    return XQC_OK;
}

static void
xqc_wt_reject_request_session(xqc_wt_request_t *wt_request)
{
    xqc_wt_session_t *session = wt_request
        ? (xqc_wt_session_t *)wt_request->user_data : NULL;
    if (session) {
        wt_request->user_data = NULL;
        xqc_wt_session_close(session);
    }
}

int
xqc_wt_h3_request_read_notify(xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag,
    void *strm_user_data)
{
    unsigned char     fin        = 0;
    xqc_wt_request_t *wt_request = (xqc_wt_request_t *)strm_user_data;

    xqc_wt_ctx_t    *wt_ctx    = NULL;
    xqc_h3_stream_t *h3_stream = h3_request ? h3_request->h3_stream : NULL;

    if (h3_stream == NULL) {
        return XQC_ERROR;
    }

    wt_ctx = xqc_wt_get_ctx_by_h3conn(h3_stream->h3c);

    // assert(wt_ctx != NULL);
    if (wt_request == NULL) {
        return XQC_ERROR;
    }
    if (wt_request->passthrough) {
        return xqc_wt_forward_h3_request_read(wt_request, wt_ctx, flag);
    }
    if ((flag & XQC_REQ_NOTIFY_READ_HEADER)
        && h3_stream->h3c->conn->conn_type == XQC_CONN_TYPE_SERVER
        && xqc_wt_orig_h3_cbs(h3_stream->h3c) != NULL
        && !xqc_wt_request_is_webtransport(h3_request))
    {
        wt_request->passthrough = XQC_TRUE;
        int ret = xqc_wt_forward_h3_request_create(wt_request, wt_ctx);
        if (ret != XQC_OK) {
            return ret;
        }
        return xqc_wt_forward_h3_request_read(wt_request, wt_ctx, flag);
    }

    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        xqc_http_headers_t *headers = xqc_h3_request_recv_headers(h3_request, &fin);
        if (headers == NULL) {
            return XQC_ERROR;
        }
        for (int i = 0; i < headers->count; i++) {
            char *name  = (char *)headers->headers[i].name.iov_base;
            char *value = (char *)headers->headers[i].value.iov_base;
            size_t name_len = headers->headers[i].name.iov_len;
            size_t value_len = headers->headers[i].value.iov_len;
            if (name_len == 5 && memcmp(name, ":path", 5) == 0) {
                // to process "?"
                // like "127.0.0.1/publish?stream_id=1"
                if (xqc_wt_request_table_find(wt_request, ":path") == NULL)
                    xqc_wt_request_table_insert_len(wt_request, name, name_len,
                        value, value_len);
            }
            xqc_wt_request_table_insert_len(wt_request, name, name_len,
                value, value_len);
        }

        xqc_conn_type_t conn_type = h3_stream->h3c->conn->conn_type;

        if (conn_type == XQC_CONN_TYPE_SERVER) {
            for (int i = 0; i < headers->count; i++) {
                char *name = (char *)headers->headers[i].name.iov_base;
                char *value = (char *)headers->headers[i].value.iov_base;
                size_t name_len = headers->headers[i].name.iov_len;
                size_t value_len = headers->headers[i].value.iov_len;
                xqc_log(h3_stream->log, XQC_LOG_DEBUG,
                        "|wt request header|%*s:%*s|",
                        name_len, name, value_len, value);
            }
        }

        if (conn_type == XQC_CONN_TYPE_CLIENT) {
            /* client: let the WT layer distinguish 2xx establishment from
             * non-2xx CONNECT rejection. */
            char *status = xqc_wt_request_table_find(wt_request, ":status");
            if (status != NULL) {
                return xqc_wt_process_request_headers(wt_request, wt_ctx, headers);
            }
            return XQC_OK;
        }

        /* server side: check for Extended CONNECT request */
        xqc_int_t session_ret = xqc_wt_create_server_session_for_request(wt_request);
        if (session_ret != XQC_OK) {
            return session_ret;
        }
        if (!(h3_stream->h3c->flags & XQC_H3_CONN_FLAG_SETTINGS_RECVED)) {
            return -H3_MISSING_SETTINGS;
        }

        char *request_name = xqc_wt_request_table_find(wt_request, ":method");
        if (request_name == NULL || !check_str_equal(request_name, "CONNECT")) {
            return XQC_ERROR;
        }

        request_name = xqc_wt_request_table_find(wt_request, ":protocol");
        xqc_h3_conn_settings_t *local_settings_for_protocol =
            &h3_stream->h3c->local_h3_conn_settings;
        xqc_bool_t strict_protocol =
            local_settings_for_protocol->webtransport_mode
                == XQC_WT_MODE_DRAFT15_STRICT;
        if (request_name == NULL || !check_str_equal(request_name, "webtransport-h3"))
        {
            if (!strict_protocol && request_name
                && check_str_equal(request_name, "webtransport"))
            {
                goto wt_protocol_ok;
            }
            xqc_log(h3_stream->log, XQC_LOG_ERROR,
                    "|reject webtransport request|bad_protocol:%s|",
                    request_name ? request_name : "(null)");
            return XQC_ERROR;
        }
wt_protocol_ok:

        request_name = xqc_wt_request_table_find(wt_request, ":scheme");
        if (request_name == NULL || !check_str_equal(request_name, "https")) {
            return XQC_ERROR;
        }

        request_name = xqc_wt_request_table_find(wt_request, ":authority");
        if (request_name == NULL) {
            return XQC_ERROR;
        }

        request_name = xqc_wt_request_table_find(wt_request, ":path");
        if (request_name == NULL) {
            return XQC_ERROR;
        }

        const char *status_value = "200";
        xqc_http_header_t response_header_status_protocol[] = {
            {
                .name  = {.iov_base = (void *)":status", .iov_len = 7},
                .value = {.iov_base = (void *)status_value, .iov_len = 3},
                .flags = 0,
            },
        };

        xqc_http_headers_t response_headers = {
            .headers = response_header_status_protocol,
            .count   = 1,
        };

        char *path = xqc_wt_request_table_find(wt_request, ":path");

        if (wt_request->header_sent == 0) {
            int accepted = 1;
            int reject_status = 404;
            xqc_h3_conn_settings_t *local_settings =
                h3_stream && h3_stream->h3c
                    ? &h3_stream->h3c->local_h3_conn_settings : NULL;
            xqc_h3_conn_settings_t *peer_settings =
                h3_stream && h3_stream->h3c
                    ? &h3_stream->h3c->peer_h3_conn_settings : NULL;
            if (local_settings
                && local_settings->webtransport_mode == XQC_WT_MODE_DRAFT15_STRICT
                && (!peer_settings
                    || !xqc_wt_peer_satisfies_draft15_requirements(h3_stream)))
            {
                xqc_connection_t *qc = h3_stream && h3_stream->h3c
                    ? h3_stream->h3c->conn : NULL;
                xqc_log(h3_stream->log, XQC_LOG_ERROR,
                    "|reject webtransport request|missing_requirements|settings:%ui|wt:%ui/%ui|connect:%ui/%ui|dgram:%ui/%ui|fc:%ui%ui%ui|max_dgram:%ui|reset_at:%ui|",
                    (unsigned int)(h3_stream->h3c->flags & XQC_H3_CONN_FLAG_SETTINGS_RECVED),
                    peer_settings ? (unsigned int)peer_settings->enable_webtransport : 0,
                    peer_settings ? (unsigned int)peer_settings->wt_enabled_present : 0,
                    peer_settings ? (unsigned int)peer_settings->enable_connect_protocol : 0,
                    peer_settings ? (unsigned int)peer_settings->enable_connect_protocol_present : 0,
                    peer_settings ? (unsigned int)peer_settings->h3_datagram : 0,
                    peer_settings ? (unsigned int)peer_settings->h3_datagram_present : 0,
                    peer_settings ? (unsigned int)peer_settings->wt_initial_max_streams_uni_present : 0,
                    peer_settings ? (unsigned int)peer_settings->wt_initial_max_streams_bidi_present : 0,
                    peer_settings ? (unsigned int)peer_settings->wt_initial_max_data_present : 0,
                    qc ? (unsigned int)qc->remote_settings.max_datagram_frame_size : 0,
                    qc ? (unsigned int)qc->remote_settings.reset_stream_at : 0);
                accepted = 0;
                reject_status = 400;
            }
            xqc_wt_session_t *session =
                (xqc_wt_session_t *)wt_request->user_data;
            xqc_wt_conn_t *wt_conn = wt_request->wt_conn;
            if (accepted && session && wt_conn && !session->flow_control_enabled
                && xqc_wt_conn_has_active_session_without_fc(wt_conn, session))
            {
                xqc_int_t reset_ret = xqc_wt_reset_rejected_connect_stream(h3_stream);
                xqc_wt_reject_request_session(wt_request);
                return reset_ret < 0 ? reset_ret : XQC_OK;
            }
            if (accepted && wt_ctx->session_cbs.webtransport_will_create_session_notify) {
                int ret = wt_ctx->session_cbs.webtransport_will_create_session_notify(headers,
                    &response_headers);
                if (ret != 1) {
                    accepted = 0;
                    if (ret >= 100 && ret <= 599) {
                        reject_status = ret;
                    }
                }
            }

            if (accepted && wt_ctx->session_cbs.webtransport_session_create_notify) {
                int ret = xqc_wt_process_request_headers(wt_request, wt_ctx, headers);
                accepted = (ret == 1);
                if (!accepted && ret >= 100 && ret <= 599) {
                    reject_status = ret;
                }
            }
            if (accepted && !wt_ctx->session_cbs.webtransport_session_create_notify) {
                xqc_wt_establish_session(session, wt_ctx);
            }

            char status_buf[4] = "404";
            if (!accepted) {
                snprintf(status_buf, sizeof(status_buf), "%03d", reject_status);
                response_header_status_protocol[0].value.iov_base = (void *)status_buf;
                xqc_wt_reject_request_session(wt_request);
            }

            ssize_t ret = xqc_h3_request_send_headers(h3_request, &response_headers,
                accepted ? 0 : 1);
            if (ret < 0) {
                return ret;
            }
            wt_request->header_sent = 1;
            return XQC_OK;
        }
    } else if (flag & XQC_REQ_NOTIFY_READ_BODY) {
        /* body data on the CONNECT stream may contain capsules (RFC 9297).
         * Capsules may span multiple DATA frames, so we maintain a reassembly
         * buffer (wt_request->capsule_buf) for incomplete capsules. */
        xqc_wt_session_t *body_session =
            (xqc_wt_session_t *)wt_request->user_data;
        char    recv_buf[4096];
        ssize_t read     = 0;
        ssize_t read_sum = 0;
        do {
            read = xqc_h3_request_recv_body(h3_request,
                (unsigned char *)recv_buf, sizeof(recv_buf), &fin);
            if (read == -XQC_EAGAIN) {
                break;
            } else if (read < 0) {
                return 0;
            }

            read_sum += read;
            wt_request->recv_body_len += read;

            if (read <= 0) {
                continue;
            }
            if (body_session && body_session->close_capsule_received) {
                return -H3_MESSAGE_ERROR;
            }

            /* merge with any leftover from previous call */
            const uint8_t *parse_buf;
            size_t         parse_len;
            uint8_t       *merged = NULL;

            #define XQC_WT_CAPSULE_BUF_MAX  65536  /* 64 KB */
            if (wt_request->capsule_buf_len > 0) {
                size_t total = wt_request->capsule_buf_len + (size_t)read;
                if (total > XQC_WT_CAPSULE_BUF_MAX) {
                    xqc_free(wt_request->capsule_buf);
                    wt_request->capsule_buf     = NULL;
                    wt_request->capsule_buf_len = 0;
                    return -XQC_ELIMIT;
                }
                merged = xqc_malloc(total);
                if (merged == NULL) {
                    return -XQC_EMALLOC;
                }
                memcpy(merged, wt_request->capsule_buf, wt_request->capsule_buf_len);
                memcpy(merged + wt_request->capsule_buf_len, recv_buf, (size_t)read);
                parse_buf = merged;
                parse_len = total;

                xqc_free(wt_request->capsule_buf);
                wt_request->capsule_buf     = NULL;
                wt_request->capsule_buf_len = 0;
            } else {
                parse_buf = (const uint8_t *)recv_buf;
                parse_len = (size_t)read;
            }

            /* parse capsules from the buffer */
            const uint8_t *p   = parse_buf;
            size_t         rem = parse_len;
            while (rem > 0) {
                uint64_t capsule_type = 0;
                uint64_t payload_len  = 0;
                ssize_t  hdr_len = xqc_wt_decode_capsule_header(p, rem,
                    &capsule_type, &payload_len);
                if (hdr_len <= 0 || (size_t)hdr_len + payload_len > rem) {
                    break; /* incomplete capsule header or payload */
                }

                const uint8_t *payload = p + hdr_len;

                if (capsule_type == XQC_WT_CAPSULE_CLOSE_SESSION) {
                    uint32_t       close_code = 0;
                    const uint8_t *reason     = NULL;
                    size_t         reason_len = 0;
                    ssize_t close_ret = xqc_wt_decode_close_session_capsule(
                        payload, (size_t)payload_len,
                        &close_code, &reason, &reason_len);
                    if (close_ret < 0) {
                        if (merged) {
                            xqc_free(merged);
                        }
                        return close_ret;
                    }

                    xqc_wt_session_t *session = (xqc_wt_session_t *)wt_request->user_data;
                    if (session) {
                        xqc_int_t close_state_ret =
                            xqc_wt_session_receive_close_capsule(session,
                                close_code, reason, reason_len);
                        if (close_state_ret < 0) {
                            if (merged) {
                                xqc_free(merged);
                            }
                            return close_state_ret;
                        }
                        /* notify application of session close */
                        if (wt_ctx
                            && wt_ctx->session_cbs.webtransport_session_close_notify)
                        {
                            void *h3c_user_data = session->wt_conn
                                ? xqc_wt_conn_app_user_data(session->wt_conn)
                                : NULL;
                            wt_ctx->session_cbs.webtransport_session_close_notify(
                                session, NULL, NULL, h3c_user_data);
                        }
                    }
                } else if (capsule_type == XQC_WT_CAPSULE_DRAIN_SESSION) {
                    xqc_wt_session_t *session = (xqc_wt_session_t *)wt_request->user_data;
                    if (session) {
                        session->drain_received = XQC_TRUE;
                    }
                } else if (capsule_type == XQC_WT_CAPSULE_MAX_STREAM_DATA
                           || capsule_type == XQC_WT_CAPSULE_STREAM_DATA_BLOCKED)
                {
                    xqc_wt_session_t *session = (xqc_wt_session_t *)wt_request->user_data;
                    if (session) {
                        xqc_int_t fc_ret = xqc_wt_session_flow_error(session);
                        if (fc_ret < 0) {
                            if (merged) {
                                xqc_free(merged);
                            }
                            return fc_ret;
                        }
                    }
                } else if (capsule_type == XQC_WT_CAPSULE_MAX_STREAMS_BIDI
                           || capsule_type == XQC_WT_CAPSULE_MAX_STREAMS_UNI
                           || capsule_type == XQC_WT_CAPSULE_MAX_DATA
                           || capsule_type == XQC_WT_CAPSULE_STREAMS_BLOCKED_BIDI
                           || capsule_type == XQC_WT_CAPSULE_STREAMS_BLOCKED_UNI
                           || capsule_type == XQC_WT_CAPSULE_DATA_BLOCKED)
                {
                    xqc_wt_session_t *session = (xqc_wt_session_t *)wt_request->user_data;
                    if (session == NULL || !session->flow_control_enabled) {
                        p   += (size_t)hdr_len + (size_t)payload_len;
                        rem -= (size_t)hdr_len + (size_t)payload_len;
                        if (body_session && body_session->close_capsule_received
                            && rem > 0)
                        {
                            if (merged) {
                                xqc_free(merged);
                            }
                            return -H3_MESSAGE_ERROR;
                        }
                        continue;
                    }
                    uint64_t value = 0;
                    ssize_t consumed = xqc_wt_decode_flow_control_capsule_value(
                        payload, (size_t)payload_len, &value);
                    if (consumed < 0) {
                        if (merged) {
                            xqc_free(merged);
                        }
                        return consumed;
                    }
                    xqc_int_t fc_ret = XQC_OK;
                    if (capsule_type == XQC_WT_CAPSULE_MAX_STREAMS_BIDI) {
                        fc_ret = xqc_wt_session_update_peer_max_streams(
                            session, XQC_TRUE, value);
                    } else if (capsule_type == XQC_WT_CAPSULE_MAX_STREAMS_UNI) {
                        fc_ret = xqc_wt_session_update_peer_max_streams(
                            session, XQC_FALSE, value);
                    } else if (capsule_type == XQC_WT_CAPSULE_MAX_DATA) {
                        fc_ret = xqc_wt_session_update_peer_max_data(session, value);
                    } else if (capsule_type == XQC_WT_CAPSULE_STREAMS_BLOCKED_BIDI
                               || capsule_type == XQC_WT_CAPSULE_STREAMS_BLOCKED_UNI
                               || capsule_type == XQC_WT_CAPSULE_DATA_BLOCKED)
                    {
                        fc_ret = xqc_wt_session_handle_blocked_capsule(
                            session, capsule_type, value);
                    }
                    if (fc_ret < 0) {
                        if (merged) {
                            xqc_free(merged);
                        }
                        return fc_ret;
                    }
                }
                p   += (size_t)hdr_len + (size_t)payload_len;
                rem -= (size_t)hdr_len + (size_t)payload_len;
                if (body_session && body_session->close_capsule_received
                    && rem > 0)
                {
                    if (merged) {
                        xqc_free(merged);
                    }
                    return -H3_MESSAGE_ERROR;
                }
            }

            /* save any incomplete capsule data for the next callback */
            if (rem > 0) {
                wt_request->capsule_buf = xqc_malloc(rem);
                if (wt_request->capsule_buf) {
                    memcpy(wt_request->capsule_buf, p, rem);
                    wt_request->capsule_buf_len = rem;
                }
            }

            if (merged) {
                xqc_free(merged);
            }
        } while (read > 0 && !fin);

        return XQC_OK;
    }

    return XQC_OK;
}

int
xqc_wt_h3_request_write_notify(xqc_h3_request_t *h3_request, void *strm_user_data)
{
    xqc_wt_request_t *wt_request = (xqc_wt_request_t *)strm_user_data;
    xqc_h3_stream_t *h3_stream = h3_request ? h3_request->h3_stream : NULL;
    xqc_wt_ctx_t *wt_ctx = h3_stream ? xqc_wt_get_ctx_by_h3conn(h3_stream->h3c)
                                     : NULL;
    xqc_h3_callbacks_t *orig = xqc_wt_orig_h3_cbs(h3_stream ? h3_stream->h3c : NULL);
    if (wt_request && wt_request->passthrough
        && orig && orig->h3r_cbs.h3_request_write_notify)
    {
        return orig->h3r_cbs.h3_request_write_notify(h3_request,
            wt_request->app_user_data);
    }
    return XQC_OK;
}

int
xqc_wt_h3_request_close_notify(xqc_h3_request_t *h3_request, void *strm_user_data)
{
    xqc_wt_request_t *wt_request = (xqc_wt_request_t *)strm_user_data;
    if (wt_request == NULL) {
        return 0;
    }
    /* clear user_data to prevent double-free if called again during teardown */
    xqc_h3_request_set_user_data(h3_request, NULL);

    xqc_h3_stream_t *h3_stream = h3_request ? h3_request->h3_stream : NULL;
    if (h3_stream == NULL) {
        xqc_wt_request_destroy(wt_request);
        return 0;
    }

    xqc_h3_conn_t *h3_conn = h3_stream->h3c;
    xqc_wt_ctx_t  *wt_ctx  = xqc_wt_get_ctx_by_h3conn(h3_conn);

    if (wt_request->passthrough) {
        xqc_h3_callbacks_t *orig = xqc_wt_orig_h3_cbs(h3_conn);
        if (orig && orig->h3r_cbs.h3_request_close_notify) {
            orig->h3r_cbs.h3_request_close_notify(h3_request,
                wt_request->app_user_data);
        }
        xqc_wt_request_destroy(wt_request);
        return 0;
    }

    xqc_wt_session_t *session = (xqc_wt_session_t *)wt_request->user_data;
    wt_request->user_data = NULL;  /* prevent double-close */
    if (session) {
        if (!session->close_capsule_received && !session->close_capsule_sent) {
            session->close_capsule_received = XQC_TRUE;
            session->close_error_code = 0;
        }
        xqc_bool_t abort_streams = XQC_TRUE;
        if (h3_conn == NULL || h3_conn->conn == NULL
            || h3_conn->conn->conn_state >= XQC_CONN_STATE_CLOSING)
        {
            abort_streams = XQC_FALSE;
        }
        xqc_wt_session_mark_terminated(session, abort_streams);
        if (wt_ctx && wt_ctx->session_cbs.webtransport_session_close_notify) {
            void *h3c_user_data = session->wt_conn
                ? xqc_wt_conn_app_user_data(session->wt_conn)
                : NULL;
            wt_ctx->session_cbs.webtransport_session_close_notify(
                session, NULL, NULL, h3c_user_data);
        }
        xqc_wt_session_close(session);
    }

    xqc_wt_request_destroy(wt_request);

    return 0;
}

int
xqc_wt_h3_conn_close_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *h3c_user_data)
{
    xqc_wt_conn_t *wt_conn = xqc_wt_conn_from_h3(h3_conn);
    if (wt_conn) {
        xqc_h3_callbacks_t *orig = xqc_wt_orig_h3_cbs(h3_conn);
        if (orig && orig->h3c_cbs.h3_conn_close_notify) {
            orig->h3c_cbs.h3_conn_close_notify(h3_conn, cid,
                xqc_wt_conn_app_user_data(wt_conn));
        }
        if (cid && h3_conn && h3_conn->conn && h3_conn->conn->engine) {
            xqc_log(h3_conn->log, XQC_LOG_DEBUG,
                    "|wt h3 conn close|cid:%s|",
                    xqc_scid_str(h3_conn->conn->engine, cid));
        }
        h3_conn->wt_conn = NULL;
        xqc_wt_conn_close(wt_conn);
    }
    return 0;
}

int
xqc_wt_h3_frame_paser_notify(int frame_type, xqc_h3_conn_t *h3_conn, xqc_h3_stream_t *h3_stream,
    const unsigned char *pos, size_t sz, int *ret, int *fin)
{
    if (frame_type == XQC_H3_FRM_HEADERS) {
        return 0;
    }
    if (frame_type == XQC_WT_STREAM_TYPE_BIDIRECTIONAL) {
        return 0;
    }
    return 1;
}

int xqc_wt_unknown_bidistream_notify(int stream_type, xqc_h3_conn_t *h3_conn,
    xqc_h3_stream_t *h3_stream, int *ret);
int xqc_wt_unknown_bidistream_recvdata_notify(xqc_h3_conn_t *h3_conn,
    xqc_h3_stream_t *h3_stream, uint8_t *data, size_t size, uint8_t fin,
    int *ret);

int
xqc_wt_unknown_unistream_notify(int stream_type, xqc_h3_conn_t *h3_conn,
    xqc_h3_stream_t *h3_stream, int *ret)
{
    if (stream_type != XQC_H3_STREAM_TYPE_WT_UNI) {
        return 0;
    }
    xqc_wt_conn_t *wt_conn = xqc_wt_conn_from_h3(h3_conn);
    if (wt_conn == NULL) {
        *ret = -XQC_EPARAM;
        return 0;
    }

    xqc_wt_ctx_t *wt_ctx = xqc_wt_get_ctx_by_h3conn(h3_conn);
    if (wt_ctx == NULL) {
        *ret = -XQC_EPARAM;
        return 0;
    }

    xqc_wt_session_t *wt_session = wt_conn->wt_session;
    xqc_wt_unistream_t *wt_unistream = wt_session
        ? xqc_wt_create_unistream(XQC_WT_STREAM_TYPE_RECV, wt_session, NULL,
            h3_stream)
        : xqc_wt_create_pending_recv_unistream(h3_stream);
    if (wt_unistream == NULL) {
        *ret = -XQC_EMALLOC;
        return 0;
    }

    xqc_int_t add_ret = XQC_OK;
    if (wt_session) {
        add_ret = xqc_wt_session_add_pendingstream(wt_session, h3_stream,
            wt_unistream, XQC_WT_PENDING_UNISTREAM);
    } else {
        xqc_wt_pending_stream_t *ps = xqc_malloc(sizeof(xqc_wt_pending_stream_t));
        if (ps == NULL) {
            add_ret = -XQC_EMALLOC;
        } else {
            ps->type = XQC_WT_PENDING_UNISTREAM;
            ps->stream = wt_unistream;
            add_ret = xqc_wt_conn_add_pending_stream(wt_conn,
                h3_stream->stream->stream_id, ps);
            if (add_ret != XQC_OK) {
                xqc_free(ps);
            }
        }
    }
    if (add_ret != XQC_OK) {
        xqc_wt_stream_buffer_list_release(&wt_unistream->pending_recv);
        if (wt_unistream->type == XQC_WT_STREAM_TYPE_SEND
            && wt_unistream->stream.send_stream)
        {
            xqc_free(wt_unistream->stream.send_stream);
        } else if (wt_unistream->type == XQC_WT_STREAM_TYPE_RECV
                   && wt_unistream->stream.recv_stream)
        {
            xqc_free(wt_unistream->stream.recv_stream);
        }
        xqc_free(wt_unistream);
        *ret = add_ret;
        return 0;
    }

    *ret = 0;

    return 1;
}

int
xqc_wt_unknown_unistream_recvdata_notify(xqc_h3_conn_t *h3_conn,
    xqc_h3_stream_t *h3_stream, uint8_t *data, size_t size, uint8_t fin,
    int *ret)
{
    xqc_wt_conn_t    *wt_conn    = xqc_wt_conn_from_h3(h3_conn);
    if (wt_conn == NULL) {
        return 0;
    }
    xqc_wt_ctx_t     *wt_ctx     = xqc_wt_get_ctx_by_h3conn(h3_conn);

    uint64_t stream_id = h3_stream && h3_stream->stream
        ? h3_stream->stream->stream_id : 0;
    xqc_wt_session_t *owner_session = NULL;
    xqc_wt_session_t *wt_session = NULL;
    xqc_wt_pending_stream_t *ps =
        xqc_wt_conn_find_pending_stream(wt_conn, stream_id, &owner_session);
    if (ps == NULL) {
        if (ret) {
            *ret = XQC_ERROR;
        }
        return XQC_ERROR;
    }
    xqc_wt_unistream_t *wt_unistream = (xqc_wt_unistream_t *)(ps->stream);

    int      nread      = 0;
    uint64_t session_id = wt_unistream->session_id;
    xqc_bool_t first_parse = XQC_FALSE;
    if (wt_unistream->packet_parsed_flag == XQC_FALSE) {
        ssize_t consumed = xqc_wt_read_session_id_prefix(
            wt_unistream->recv_header_buf, &wt_unistream->recv_header_len,
            data, size, &session_id);
        if (consumed == -XQC_EAGAIN) {
            if (ret) {
                *ret = (int)size;
            }
            return 1;
        }
        if (consumed < 0) {
            if (ret) {
                *ret = (int)consumed;
            }
            return 1;
        }
        nread = (int)consumed;

        wt_unistream->packet_parsed_flag = XQC_TRUE;
        first_parse = XQC_TRUE;
    }
    wt_unistream->session_id = session_id;

    wt_session = xqc_wt_conn_find_session(wt_conn, session_id);
    if (wt_session == NULL) {
        if (xqc_wt_conn_is_closed_session(wt_conn, session_id)) {
            xqc_wt_abort_closed_session_stream(h3_stream, XQC_FALSE);
            if (owner_session && owner_session->pending_unistreams) {
                xqc_id_hash_delete(owner_session->pending_unistreams, stream_id);
            } else if (wt_conn->pending_streams) {
                xqc_id_hash_delete(wt_conn->pending_streams, stream_id);
            }
            xqc_wt_pending_stream_destroy(ps);
            if (ret) {
                *ret = (int)size;
            }
            return 1;
        }
        if (xqc_wt_conn_can_buffer_unknown_session(wt_conn, session_id)) {
            if (size > (size_t)nread || fin) {
                xqc_int_t buf_ret = xqc_wt_buffer_append(
                    &wt_unistream->pending_recv,
                    size > (size_t)nread ? data + nread : NULL,
                    size > (size_t)nread ? size - nread : 0,
                    &wt_unistream->pending_bytes);
                if (fin) {
                    wt_unistream->pending_fin = XQC_TRUE;
                    wt_unistream->fin.recv_fin = XQC_FALSE;
                }
                if (buf_ret < 0) {
                    if (buf_ret == -XQC_ELIMIT) {
                        xqc_wt_reject_buffered_stream(h3_stream, XQC_FALSE);
                        xqc_wt_remove_pending_stream(wt_conn, owner_session,
                            stream_id);
                        xqc_wt_pending_stream_destroy(ps);
                        if (ret) {
                            *ret = (int)size;
                        }
                        return 1;
                    }
                    if (ret) {
                        *ret = buf_ret;
                    }
                    return 1;
                }
            }
            if (ret) {
                *ret = (int)size;
            }
            return 1;
        }
        xqc_conn_close_with_error(xqc_h3_conn_get_xqc_conn(h3_conn), H3_ID_ERROR);
        if (ret) {
            *ret = -H3_ID_ERROR;
        }
        return 1;
    }
    if (xqc_wt_conn_move_pending_stream(wt_conn, owner_session, wt_session,
            stream_id, ps) != XQC_OK)
    {
        if (ret) {
            *ret = XQC_ERROR;
        }
        return 1;
    }
    wt_unistream->session = wt_session;
    if (first_parse && wt_ctx && wt_ctx->stream_cbs.wt_unistream_create_notify) {
        xqc_int_t create_ret = wt_ctx->stream_cbs.wt_unistream_create_notify(
            wt_unistream, wt_session, xqc_wt_conn_app_user_data(wt_conn));
        if (create_ret < 0) {
            xqc_wt_reject_buffered_stream(h3_stream, XQC_FALSE);
            xqc_wt_remove_pending_stream(wt_conn, wt_session, stream_id);
            xqc_wt_pending_stream_destroy(ps);
            if (ret) {
                *ret = create_ret;
            }
            return 1;
        }
    }
    if (!wt_unistream->flow_counted) {
        xqc_int_t fc_ret = xqc_wt_session_on_incoming_stream(wt_session, XQC_FALSE);
        wt_unistream->flow_counted = XQC_TRUE;
        if (fc_ret < 0) {
            if (ret) {
                *ret = fc_ret;
            }
            return 1;
        }
    }
    if (fin) {
        wt_unistream->fin.recv_fin = XQC_TRUE;
    }

    if (size > (size_t)nread || fin) {
        xqc_int_t fc_ret = xqc_wt_session_on_incoming_data(wt_session,
            (uint64_t)(size > (size_t)nread ? size - (size_t)nread : 0));
        if (fc_ret < 0) {
            if (ret) {
                *ret = fc_ret;
            }
            return 1;
        }
        if (!wt_session->established) {
            xqc_int_t buf_ret = xqc_wt_buffer_append(
                &wt_unistream->pending_recv,
                size > (size_t)nread ? data + nread : NULL,
                size > (size_t)nread ? size - nread : 0,
                &wt_unistream->pending_bytes);
            if (fin) {
                wt_unistream->pending_fin = XQC_TRUE;
                wt_unistream->fin.recv_fin = XQC_FALSE;
            }
            if (buf_ret == -XQC_ELIMIT) {
                xqc_wt_reject_buffered_stream(h3_stream, XQC_FALSE);
                xqc_wt_remove_pending_stream(wt_conn, wt_session, stream_id);
                xqc_wt_pending_stream_destroy(ps);
                if (ret) {
                    *ret = (int)size;
                }
                return 1;
            }
            if (ret) {
                *ret = buf_ret < 0 ? buf_ret : (int)size;
            }
            return 1;
        }
        xqc_int_t cb_ret = xqc_wt_notify_unistream_read(wt_ctx, wt_unistream,
            wt_session, size > (size_t)nread ? data + nread : NULL,
            size > (size_t)nread ? size - nread : 0, fin);
        if (cb_ret < 0) {
            if (ret) {
                *ret = cb_ret;
            }
            return 1;
        }
        nread = (int)size;
    }

    if (ret) {
        *ret = nread;
        return 1;
    }
    return 0;
}

/* public wrappers called from H3 layer for WT uni streams */
void
xqc_wt_h3_uni_stream_closing(xqc_h3_conn_t *h3c, xqc_h3_stream_t *h3s,
    xqc_int_t err_code)
{
    (void)err_code;
    xqc_wt_conn_t *wt_conn = xqc_wt_conn_from_h3(h3c);
    xqc_wt_ctx_t *wt_ctx = xqc_wt_get_ctx_by_h3conn(h3c);
    if (wt_conn == NULL || wt_ctx == NULL
        || wt_ctx->stream_cbs.wt_unistream_closing_notify == NULL
        || h3s == NULL || h3s->stream == NULL)
    {
        return;
    }

    xqc_wt_session_t *session = NULL;
    xqc_wt_pending_stream_t *ps = xqc_wt_conn_find_pending_stream(wt_conn,
        h3s->stream->stream_id, &session);
    if (ps == NULL || ps->type != XQC_WT_PENDING_UNISTREAM
        || ps->stream == NULL)
    {
        return;
    }

    wt_ctx->stream_cbs.wt_unistream_closing_notify(
        (xqc_wt_unistream_t *)ps->stream, session,
        xqc_wt_conn_app_user_data(wt_conn));
}

void
xqc_wt_h3_uni_stream_created(xqc_h3_conn_t *h3c,
    xqc_h3_stream_t *h3s, int *ret)
{
    xqc_wt_unknown_unistream_notify(XQC_WT_STREAM_TYPE_UNIDIRECTIONAL, h3c, h3s, ret);
}

void
xqc_wt_h3_uni_stream_recv(xqc_h3_conn_t *h3c,
    xqc_h3_stream_t *h3s, uint8_t *data, size_t size, uint8_t fin, int *ret)
{
    xqc_wt_unknown_unistream_recvdata_notify(h3c, h3s, data, size, fin, ret);
}

void
xqc_wt_h3_bidi_stream_created(xqc_h3_conn_t *h3c,
    xqc_h3_stream_t *h3s, int *ret)
{
    xqc_wt_unknown_bidistream_notify(XQC_WT_STREAM_TYPE_BIDIRECTIONAL,
        h3c, h3s, ret);
}

void
xqc_wt_h3_bidi_stream_recv(xqc_h3_conn_t *h3c,
    xqc_h3_stream_t *h3s, uint8_t *data, size_t size, uint8_t fin,
    int *ret)
{
    xqc_wt_unknown_bidistream_recvdata_notify(h3c, h3s, data, size, fin, ret);
}

int
xqc_wt_unknown_bidistream_notify(int stream_type, xqc_h3_conn_t *h3_conn,
    xqc_h3_stream_t *h3_stream, int *ret)
{
    xqc_wt_conn_t *wt_conn = xqc_wt_conn_from_h3(h3_conn);
    if (wt_conn == NULL) {
        return 0;
    }

    xqc_wt_ctx_t *wt_ctx = xqc_wt_get_ctx_by_h3conn(h3_conn);

    xqc_wt_session_t *wt_session = wt_conn->wt_session;
    if (h3_stream->pctx.frame_pctx.frame.type
        == (xqc_h3_frm_type_t)XQC_WT_STREAM_TYPE_BIDIRECTIONAL)
    {
        xqc_wt_session_t *owner = xqc_wt_conn_find_session(
            wt_conn, h3_stream->pctx.frame_pctx.frame.len);
        if (owner) {
            wt_session = owner;
        }
    }
    xqc_wt_bidistream_t *wt_bidistream = wt_session
        ? xqc_wt_create_bidistream(h3_stream, wt_session, NULL, NULL, XQC_TRUE)
        : xqc_wt_create_pending_recv_bidistream(h3_stream);
    if (wt_bidistream == NULL) {
        return 0;
    }
    wt_bidistream->packet_parsed_flag = XQC_FALSE;
    if (wt_session) {
        wt_bidistream->session_id = wt_session->session_id;
        wt_bidistream->session = wt_session;
    }

    xqc_int_t add_ret = XQC_OK;
    if (wt_session) {
        add_ret = xqc_wt_session_add_pendingstream(wt_session, h3_stream,
            wt_bidistream, XQC_WT_PENDING_BIDISTREAM);
    } else {
        xqc_wt_pending_stream_t *ps = xqc_malloc(sizeof(xqc_wt_pending_stream_t));
        if (ps == NULL) {
            add_ret = -XQC_EMALLOC;
        } else {
            ps->type = XQC_WT_PENDING_BIDISTREAM;
            ps->stream = wt_bidistream;
            add_ret = xqc_wt_conn_add_pending_stream(wt_conn,
                h3_stream->stream->stream_id, ps);
            if (add_ret != XQC_OK) {
                xqc_free(ps);
            }
        }
    }
    if (add_ret != XQC_OK) {
        xqc_wt_stream_buffer_list_release(&wt_bidistream->pending_recv);
        xqc_wt_bidistream_destroy(wt_bidistream);
        return 0;
    }

    return 0;
}

int
xqc_wt_unknown_bidistream_recvdata_notify(xqc_h3_conn_t *h3_conn, xqc_h3_stream_t *h3_stream,
    uint8_t *data, size_t size, uint8_t fin, int *ret)
{
    xqc_wt_conn_t    *wt_conn    = xqc_wt_conn_from_h3(h3_conn);
    if (wt_conn == NULL) {
        if (ret) { *ret = size; }
        return 1;
    }
    xqc_wt_ctx_t     *wt_ctx     = NULL;

    wt_ctx = xqc_wt_get_ctx_by_h3conn(h3_conn);

    uint64_t stream_id = h3_stream && h3_stream->stream
        ? h3_stream->stream->stream_id : 0;
    xqc_wt_session_t *owner_session = NULL;
    xqc_wt_pending_stream_t *ps =
        xqc_wt_conn_find_pending_stream(wt_conn, stream_id, &owner_session);
    if (ps == NULL) {
        return XQC_ERROR;
    }
    xqc_wt_bidistream_t *wt_bidistream = (xqc_wt_bidistream_t *)(ps->stream);

    int      nread      = 0;
    uint64_t session_id = wt_bidistream->session_id;

    if (wt_bidistream->packet_parsed_flag == XQC_FALSE) {
        ssize_t consumed = xqc_wt_read_session_id_prefix(
            wt_bidistream->recv_header_buf, &wt_bidistream->recv_header_len,
            data, size, &session_id);
        if (consumed == -XQC_EAGAIN) {
            if (ret) {
                *ret = (int)size;
            }
            return 1;
        }
        if (consumed < 0) {
            if (ret) {
                *ret = (int)consumed;
            }
            return 1;
        }
        nread = (int)consumed;
        wt_bidistream->packet_parsed_flag = XQC_TRUE;
        wt_bidistream->session_id          = session_id;
    }

    xqc_wt_session_t *wt_session = xqc_wt_conn_find_session(wt_conn, session_id);
    if (wt_session == NULL) {
        if (xqc_wt_conn_is_closed_session(wt_conn, session_id)) {
            xqc_wt_abort_closed_session_stream(h3_stream, XQC_TRUE);
            if (owner_session && owner_session->pending_unistreams) {
                xqc_id_hash_delete(owner_session->pending_unistreams, stream_id);
            } else if (wt_conn->pending_streams) {
                xqc_id_hash_delete(wt_conn->pending_streams, stream_id);
            }
            xqc_wt_pending_stream_destroy(ps);
            if (ret) {
                *ret = (int)size;
            }
            return 1;
        }
        if (xqc_wt_conn_can_buffer_unknown_session(wt_conn, session_id)) {
            if (size > (size_t)nread || fin) {
                xqc_int_t buf_ret = xqc_wt_buffer_append(
                    &wt_bidistream->pending_recv, data + nread,
                    size > (size_t)nread ? size - nread : 0,
                    &wt_bidistream->pending_bytes);
                if (fin) {
                    wt_bidistream->pending_fin = XQC_TRUE;
                    wt_bidistream->recv_fin = XQC_FALSE;
                }
                if (buf_ret < 0) {
                    if (buf_ret == -XQC_ELIMIT) {
                        xqc_wt_reject_buffered_stream(h3_stream, XQC_TRUE);
                        xqc_wt_remove_pending_stream(wt_conn, owner_session,
                            stream_id);
                        xqc_wt_pending_stream_destroy(ps);
                        if (ret) {
                            *ret = (int)size;
                        }
                        return 1;
                    }
                    if (ret) {
                        *ret = buf_ret;
                    }
                    return 1;
                }
            }
            if (ret) {
                *ret = (int)size;
            }
            return 1;
        }
        xqc_conn_close_with_error(xqc_h3_conn_get_xqc_conn(h3_conn), H3_ID_ERROR);
        if (ret) {
            *ret = -H3_ID_ERROR;
        }
        return 1;
    }
    if (xqc_wt_conn_move_pending_stream(wt_conn, owner_session, wt_session,
            stream_id, ps) != XQC_OK)
    {
        if (ret) {
            *ret = XQC_ERROR;
        }
        return 1;
    }
    wt_bidistream->session = wt_session;
    xqc_int_t create_ret = xqc_wt_notify_bidistream_create_once(wt_ctx,
        wt_bidistream, wt_session);
    if (create_ret < 0) {
        xqc_wt_reject_buffered_stream(h3_stream, XQC_TRUE);
        xqc_wt_remove_pending_stream(wt_conn, wt_session, stream_id);
        xqc_wt_pending_stream_destroy(ps);
        if (ret) {
            *ret = create_ret;
        }
        return 1;
    }
    if (!wt_bidistream->flow_counted) {
        xqc_int_t fc_ret = xqc_wt_session_on_incoming_stream(wt_session, XQC_TRUE);
        wt_bidistream->flow_counted = XQC_TRUE;
        if (fc_ret < 0) {
            if (ret) {
                *ret = fc_ret;
            }
            return 1;
        }
    }

    /* Propagate FIN to bidistream so application callback can detect stream end */
    if (fin) {
        wt_bidistream->recv_fin = XQC_TRUE;
    }

    if (size > (size_t)nread || fin) {
        xqc_int_t fc_ret = xqc_wt_session_on_incoming_data(wt_session,
            (uint64_t)(size > (size_t)nread ? size - (size_t)nread : 0));
        if (fc_ret < 0) {
            if (ret) {
                *ret = fc_ret;
            }
            return 1;
        }
        if (!wt_session->established) {
            xqc_int_t buf_ret = xqc_wt_buffer_append(
                &wt_bidistream->pending_recv, data + nread,
                size > (size_t)nread ? size - nread : 0,
                &wt_bidistream->pending_bytes);
            if (fin) {
                wt_bidistream->pending_fin = XQC_TRUE;
                wt_bidistream->recv_fin = XQC_FALSE;
            }
            if (buf_ret == -XQC_ELIMIT) {
                xqc_wt_reject_buffered_stream(h3_stream, XQC_TRUE);
                xqc_wt_remove_pending_stream(wt_conn, wt_session, stream_id);
                xqc_wt_pending_stream_destroy(ps);
                if (ret) {
                    *ret = (int)size;
                }
                return 1;
            }
            if (ret) {
                *ret = buf_ret < 0 ? buf_ret : (int)size;
            }
            return 1;
        }
        xqc_int_t cb_ret = xqc_wt_notify_bidistream_read(wt_ctx, wt_bidistream,
            wt_session, size > (size_t)nread ? data + nread : NULL,
            size > (size_t)nread ? size - nread : 0, fin);
        if (cb_ret < 0) {
            if (ret) {
                *ret = cb_ret;
            }
            return 1;
        }
        nread = (int)size;
    }

    if (ret) {
        *ret = nread;
        return 1;
    }
    return 0;
}

void
xqc_wt_handshake_finished_notify(xqc_h3_conn_t *h3_conn, void *h3c_user_data)
{
    xqc_wt_conn_t *wt_conn = xqc_wt_conn_from_h3(h3_conn);
    if (wt_conn == NULL) {
        return;
    }
    xqc_wt_ctx_t *wt_ctx = xqc_wt_get_ctx_by_h3conn(h3_conn);
    if (wt_ctx == NULL) {
        return;
    }
    xqc_h3_callbacks_t *orig = xqc_wt_orig_h3_cbs(h3_conn);
    if (orig && orig->h3c_cbs.h3_conn_handshake_finished) {
        orig->h3c_cbs.h3_conn_handshake_finished(h3_conn,
            xqc_wt_conn_app_user_data(wt_conn));
    }
    if (wt_ctx->session_cbs.webtransport_conn_handshake_finished_notify) {
        wt_ctx->session_cbs.webtransport_conn_handshake_finished_notify(wt_conn,
            xqc_wt_conn_app_user_data(wt_conn));
    }
}

/* H3 ext datagram callback — forward to application or echo as fallback */
static void
wt_h3_dgram_read_notify(xqc_h3_conn_t *conn, const void *data, size_t data_len,
    void *user_data, uint64_t recv_time)
{
    xqc_wt_conn_t *wt_conn = xqc_wt_conn_from_h3(conn);
    xqc_wt_ctx_t  *wt_ctx  = xqc_wt_get_ctx_by_h3conn(conn);
    xqc_wt_handle_h3_datagram_payload(xqc_h3_conn_get_xqc_conn(conn), wt_ctx,
        wt_conn, data, data_len, user_data, recv_time);
}

static void
wt_h3_dgram_write_notify(xqc_h3_conn_t *conn, void *user_data)
{
    xqc_wt_conn_t *wt_conn = xqc_wt_conn_from_h3(conn);
    xqc_wt_ctx_t  *wt_ctx  = xqc_wt_get_ctx_by_h3conn(conn);
    if (wt_conn == NULL || wt_ctx == NULL
        || wt_ctx->dgram_cbs.dgram_write_notify == NULL
        || wt_conn->sessions == NULL)
    {
        return;
    }

    for (int i = 0; i < wt_conn->sessions->count; i++) {
        xqc_id_hash_node_t *node = wt_conn->sessions->list[i];
        while (node) {
            xqc_wt_session_t *session =
                (xqc_wt_session_t *)node->element.value;
            if (session && session->established && !session->terminated) {
                wt_ctx->dgram_cbs.dgram_write_notify(session,
                    xqc_wt_conn_app_user_data(wt_conn));
            }
            node = node->next;
        }
    }
}

static int
wt_h3_dgram_lost_notify(xqc_h3_conn_t *conn, uint64_t dgram_id,
    void *user_data)
{
    xqc_wt_conn_t *wt_conn = xqc_wt_conn_from_h3(conn);
    xqc_wt_ctx_t  *wt_ctx  = xqc_wt_get_ctx_by_h3conn(conn);
    xqc_wt_session_t *session = xqc_wt_conn_find_dgram_session(wt_conn,
        dgram_id);
    if (wt_ctx && wt_ctx->dgram_cbs.dgram_lost_notify && session) {
        return wt_ctx->dgram_cbs.dgram_lost_notify(session, dgram_id,
            xqc_wt_conn_app_user_data(wt_conn));
    }
    return 0;
}

static void
wt_h3_dgram_acked_notify(xqc_h3_conn_t *conn, uint64_t dgram_id,
    void *user_data)
{
    xqc_wt_conn_t *wt_conn = xqc_wt_conn_from_h3(conn);
    xqc_wt_ctx_t  *wt_ctx  = xqc_wt_get_ctx_by_h3conn(conn);
    xqc_wt_session_t *session = xqc_wt_conn_find_dgram_session(wt_conn,
        dgram_id);
    if (wt_ctx && wt_ctx->dgram_cbs.dgram_acked_notify && session) {
        wt_ctx->dgram_cbs.dgram_acked_notify(session, dgram_id,
            xqc_wt_conn_app_user_data(wt_conn));
    }
    xqc_wt_conn_unregister_dgram_session(wt_conn, dgram_id);
}

static void
wt_h3_dgram_mss_updated_notify(xqc_h3_conn_t *conn, size_t mss,
    void *user_data)
{
    xqc_wt_conn_t *wt_conn = xqc_wt_conn_from_h3(conn);
    xqc_wt_ctx_t  *wt_ctx  = xqc_wt_get_ctx_by_h3conn(conn);
    if (wt_conn == NULL) {
        return;
    }
    xqc_wt_conn_set_dgram_mss(wt_conn, mss);
    if (wt_ctx == NULL || wt_ctx->dgram_cbs.dgram_mss_updated_notify == NULL
        || wt_conn->sessions == NULL)
    {
        return;
    }

    for (int i = 0; i < wt_conn->sessions->count; i++) {
        xqc_id_hash_node_t *node = wt_conn->sessions->list[i];
        while (node) {
            xqc_wt_session_t *session =
                (xqc_wt_session_t *)node->element.value;
            if (session && session->established && !session->terminated) {
                wt_ctx->dgram_cbs.dgram_mss_updated_notify(session, mss,
                    xqc_wt_conn_app_user_data(wt_conn));
            }
            node = node->next;
        }
    }
}

/* bytestream callbacks for WebTransport bidi streams */
static xqc_int_t
wt_bs_create_notify(xqc_h3_ext_bytestream_t *h3_ext_bs, void *bs_user_data)
{
    xqc_h3_conn_t   *h3_conn   = xqc_h3_ext_bytestream_get_h3_conn(h3_ext_bs);
    xqc_h3_stream_t *h3_stream = xqc_h3_ext_bytestream_get_h3_stream(h3_ext_bs);
    if (h3_conn == NULL || h3_stream == NULL) {
        return 0;
    }

    if ((h3_stream->flags & XQC_HTTP3_STREAM_FLAG_WT_BIDI)
        && h3_stream->stream)
    {
        return 0;
    }

    /* Create the WT bidistream object and register it in the session's
     * pending_unistreams so that xqc_wt_unknown_bidistream_recvdata_notify
     * can find it when data arrives via the bypass path. */
    int wt_ret = 0;
    xqc_wt_unknown_bidistream_notify(XQC_WT_STREAM_TYPE_BIDIRECTIONAL,
        h3_conn, h3_stream, &wt_ret);

    return 0;
}

static xqc_int_t
wt_bs_close_notify(xqc_h3_ext_bytestream_t *h3_ext_bs, void *bs_user_data)
{
    xqc_h3_conn_t   *h3_conn   = xqc_h3_ext_bytestream_get_h3_conn(h3_ext_bs);
    xqc_h3_stream_t *h3_stream = xqc_h3_ext_bytestream_get_h3_stream(h3_ext_bs);
    if (h3_conn == NULL || h3_stream == NULL || h3_stream->stream == NULL) {
        return 0;
    }

    xqc_wt_conn_t *wt_conn = xqc_wt_conn_from_h3(h3_conn);
    if (wt_conn == NULL) {
        return 0;
    }

    uint64_t stream_id = h3_stream->stream->stream_id;
    xqc_wt_session_t *wt_session = NULL;
    xqc_wt_pending_stream_t *ps =
        xqc_wt_conn_find_pending_stream(wt_conn, stream_id, &wt_session);
    if (ps == NULL) {
        return 0;
    }

    xqc_wt_ctx_t *wt_ctx = xqc_wt_get_ctx_by_h3conn(h3_conn);
    if (wt_session && wt_session->pending_unistreams) {
        xqc_id_hash_delete(wt_session->pending_unistreams, stream_id);
    } else if (wt_conn->pending_streams) {
        xqc_id_hash_delete(wt_conn->pending_streams, stream_id);
    }

    if (ps->type == XQC_WT_PENDING_BIDISTREAM) {
        xqc_wt_bidistream_t *bidi = (xqc_wt_bidistream_t *)ps->stream;
            if (bidi) {
                if (wt_ctx && wt_ctx->stream_cbs.wt_bidistream_close_notify) {
                    wt_ctx->stream_cbs.wt_bidistream_close_notify(
                        bidi, wt_session, xqc_wt_conn_app_user_data(wt_conn));
                }
            xqc_wt_stream_buffer_list_release(&bidi->pending_recv);
            xqc_wt_bidistream_destroy(bidi);
        }
    } else {
        xqc_wt_unistream_t *uni = (xqc_wt_unistream_t *)ps->stream;
            if (uni) {
                if (wt_ctx && wt_ctx->stream_cbs.wt_unistream_close_notify) {
                    wt_ctx->stream_cbs.wt_unistream_close_notify(
                        uni, wt_session, xqc_wt_conn_app_user_data(wt_conn));
                }
            xqc_wt_stream_buffer_list_release(&uni->pending_recv);
            if (uni->type == XQC_WT_STREAM_TYPE_SEND && uni->stream.send_stream) {
                xqc_free(uni->stream.send_stream);
            } else if (uni->type == XQC_WT_STREAM_TYPE_RECV && uni->stream.recv_stream) {
                xqc_free(uni->stream.recv_stream);
            }
            xqc_free(uni);
        }
    }
    xqc_free(ps);

    return 0;
}

static int
wt_bs_read_notify(xqc_h3_ext_bytestream_t *h3_ext_bs,
    const void *data, size_t data_len, uint8_t fin, void *bs_user_data,
    uint64_t data_recv_time)
{
    xqc_h3_conn_t   *h3_conn   = xqc_h3_ext_bytestream_get_h3_conn(h3_ext_bs);
    xqc_h3_stream_t  *h3_stream = xqc_h3_ext_bytestream_get_h3_stream(h3_ext_bs);
    if (h3_conn == NULL || h3_stream == NULL) {
        return 0;
    }

    /* Skip empty non-FIN frames (no data, no signal) */
    if ((data == NULL || data_len == 0) && !fin) {
        return 0;
    }

    /* Delegate to the WT bidi recvdata handler, which parses the session_id
     * from the raw payload and dispatches to the application callback. */
    int ret = 0;
    xqc_wt_unknown_bidistream_recvdata_notify(h3_conn, h3_stream,
        (uint8_t *)data, data_len, fin, &ret);

    return ret < 0 ? ret : 0;
}

static xqc_int_t
wt_bs_write_notify(xqc_h3_ext_bytestream_t *h3_ext_bs, void *bs_user_data)
{
    return 0;
}


xqc_int_t
xqc_wt_engine_set_default_settings_for_alpn(xqc_engine_t *engine,
    const char *alpn, size_t alpn_len, xqc_wt_mode_t mode,
    uint64_t wt_initial_max_streams_uni,
    uint64_t wt_initial_max_streams_bidi,
    uint64_t wt_initial_max_data, xqc_bool_t enable_webtransport,
    xqc_bool_t h3_datagram, xqc_bool_t enable_connect_protocol)
{
    if (engine == NULL || alpn == NULL || alpn_len == 0) {
        return -XQC_EPARAM;
    }

    xqc_h3_ctx_t *h3_ctx = xqc_engine_get_alpn_ctx(engine, alpn, alpn_len);
    if (h3_ctx == NULL) {
        return -XQC_ESTATE;
    }

    h3_ctx->h3c_def_local_settings.webtransport_mode = mode;
    h3_ctx->h3c_def_local_settings.enable_webtransport = enable_webtransport;
    h3_ctx->h3c_def_local_settings.wt_initial_max_streams_uni =
        wt_initial_max_streams_uni;
    h3_ctx->h3c_def_local_settings.wt_initial_max_streams_bidi =
        wt_initial_max_streams_bidi;
    h3_ctx->h3c_def_local_settings.wt_initial_max_data =
        wt_initial_max_data;
    if (h3_ctx->h3c_def_local_settings.webtransport_max_sessions == 0) {
        h3_ctx->h3c_def_local_settings.webtransport_max_sessions = 1;
    }
    h3_ctx->h3c_def_local_settings.h3_datagram = h3_datagram;
    h3_ctx->h3c_def_local_settings.enable_connect_protocol =
        enable_connect_protocol;

    return XQC_OK;
}

xqc_int_t
xqc_wt_engine_set_default_settings(xqc_engine_t *engine, xqc_wt_mode_t mode,
    uint64_t wt_initial_max_streams_uni,
    uint64_t wt_initial_max_streams_bidi,
    uint64_t wt_initial_max_data, xqc_bool_t enable_webtransport,
    xqc_bool_t h3_datagram, xqc_bool_t enable_connect_protocol)
{
    const char *alpns[] = { XQC_ALPN_H3, XQC_ALPN_H3_29, XQC_ALPN_H3_EXT };
    xqc_int_t ret = XQC_OK;
    xqc_bool_t applied = XQC_FALSE;
    for (size_t i = 0; i < sizeof(alpns) / sizeof(alpns[0]); i++) {
        xqc_int_t one_ret = xqc_wt_engine_set_default_settings_for_alpn(engine,
            alpns[i], strlen(alpns[i]), mode, wt_initial_max_streams_uni,
            wt_initial_max_streams_bidi, wt_initial_max_data,
            enable_webtransport, h3_datagram, enable_connect_protocol);
        if (one_ret == XQC_OK) {
            applied = XQC_TRUE;
        } else if (one_ret != -XQC_ESTATE) {
            ret = one_ret;
        }
    }
    return applied ? ret : -XQC_ESTATE;
}

xqc_int_t
xqc_wt_ctx_set_pending_datagram_policy(xqc_engine_t *engine,
    const xqc_webtransport_pending_dgram_policy_t *policy)
{
    xqc_wt_ctx_t *wt_ctx = xqc_wt_ctx_get_by_engine(engine);
    if (wt_ctx == NULL || policy == NULL) {
        return -XQC_EPARAM;
    }

    wt_ctx->unknown_session_dgram_window = policy->unknown_session_window;
    wt_ctx->pending_dgram_count_max = policy->max_count
        ? policy->max_count
        : XQC_WEBTRANSPORT_DEFAULT_PENDING_DGRAM_COUNT_MAX;
    wt_ctx->pending_dgram_bytes_max = policy->max_bytes
        ? policy->max_bytes
        : XQC_WEBTRANSPORT_DEFAULT_PENDING_DGRAM_BYTES_MAX;

    return XQC_OK;
}

xqc_int_t
xqc_wt_ctx_init_for_alpns(xqc_engine_t *engine,
    xqc_webtransport_dgram_callbacks_t *wt_dgram_cbs,
    xqc_webtransport_session_callbacks_t *wt_session_cbs,
    xqc_webtransport_stream_callbacks_t  *wt_stream_cbs,
    uint64_t max_sessions, const char **alpns, size_t alpn_count)
{
    xqc_wt_ctx_t *wt_ctx = (xqc_wt_ctx_t *)xqc_calloc(1, sizeof(xqc_wt_ctx_t));
    if (wt_ctx == NULL) {
        return -XQC_EMALLOC;
    }
    if (wt_dgram_cbs)   wt_ctx->dgram_cbs   = *wt_dgram_cbs;
    if (wt_session_cbs) wt_ctx->session_cbs = *wt_session_cbs;
    if (wt_stream_cbs)  wt_ctx->stream_cbs  = *wt_stream_cbs;
    wt_ctx->max_sessions = max_sessions;
    wt_ctx->unknown_session_dgram_window =
        XQC_WEBTRANSPORT_DEFAULT_UNKNOWN_SESSION_DGRAM_WINDOW;
    wt_ctx->pending_dgram_count_max =
        XQC_WEBTRANSPORT_DEFAULT_PENDING_DGRAM_COUNT_MAX;
    wt_ctx->pending_dgram_bytes_max =
        XQC_WEBTRANSPORT_DEFAULT_PENDING_DGRAM_BYTES_MAX;

    xqc_h3_callbacks_t h3_cbs = {
        .h3c_cbs =
            {
                .h3_conn_create_notify      = xqc_wt_h3_conn_create_notify,
                .h3_conn_close_notify       = xqc_wt_h3_conn_close_notify,
                .h3_conn_handshake_finished = xqc_wt_handshake_finished_notify,
            },
        .h3r_cbs =
            {
                .h3_request_create_notify            = xqc_wt_h3_request_create_notify,
                .h3_request_close_notify             = xqc_wt_h3_request_close_notify,
                .h3_request_read_notify              = xqc_wt_h3_request_read_notify,
                .h3_request_write_notify             = xqc_wt_h3_request_write_notify,
                .h3_request_closing_notify           = NULL,
            },
        .h3_ext_bs_cbs =
            {
                .bs_create_notify = wt_bs_create_notify,
                .bs_close_notify  = wt_bs_close_notify,
                .bs_read_notify   = wt_bs_read_notify,
                .bs_write_notify  = wt_bs_write_notify,
            },
        .h3_ext_dgram_cbs =
            {
                .dgram_read_notify        = wt_h3_dgram_read_notify,
                .dgram_write_notify       = wt_h3_dgram_write_notify,
                .dgram_acked_notify       = wt_h3_dgram_acked_notify,
                .dgram_lost_notify        = wt_h3_dgram_lost_notify,
                .dgram_mss_updated_notify = wt_h3_dgram_mss_updated_notify,
            },
    };
    const char *default_alpns[] = { XQC_ALPN_H3, XQC_ALPN_H3_29, XQC_ALPN_H3_EXT };
    const char **selected_alpns = alpns ? alpns : default_alpns;
    size_t selected_count = alpns ? alpn_count
        : sizeof(default_alpns) / sizeof(default_alpns[0]);

    for (size_t a = 0; a < selected_count; a++) {
        const char *alpn = selected_alpns[a];
        if (alpn == NULL) {
            xqc_free(wt_ctx);
            return -XQC_EPARAM;
        }
        size_t alpn_len = strlen(alpn);
        xqc_h3_ctx_t *h3_ctx = xqc_engine_get_alpn_ctx(engine, alpn, alpn_len);
        if (h3_ctx) {
            if (!h3_ctx->wt_has_orig_h3_cbs) {
                h3_ctx->wt_orig_h3_cbs = h3_ctx->h3_cbs;
                h3_ctx->wt_has_orig_h3_cbs = XQC_TRUE;
            }
            h3_ctx->h3_cbs = h3_cbs;
        } else {
            int ret = xqc_h3_ctx_init_for_alpn(engine, alpn, alpn_len, &h3_cbs);
            if (ret != XQC_OK) {
                xqc_free(wt_ctx);
                return ret;
            }
            h3_ctx = xqc_engine_get_alpn_ctx(engine, alpn, alpn_len);
        }
        if (h3_ctx) {
            h3_ctx->ext_ctx = wt_ctx;
            xqc_wt_engine_set_default_settings_for_alpn(engine, alpn, alpn_len,
                XQC_WT_MODE_DRAFT15_STRICT,
                wt_ctx->max_sessions > 0 ? wt_ctx->max_sessions : 1024,
                wt_ctx->max_sessions > 0 ? wt_ctx->max_sessions : 1024,
                16 * 1024 * 1024, 1, 1, 1);
            h3_ctx->h3c_def_local_settings.webtransport_max_sessions =
                wt_ctx->max_sessions > 0 ? wt_ctx->max_sessions : 1;
        }
    }

    return XQC_OK;
}

xqc_int_t
xqc_wt_ctx_init(xqc_engine_t *engine, xqc_webtransport_dgram_callbacks_t *wt_dgram_cbs,
    xqc_webtransport_session_callbacks_t *wt_session_cbs,
    xqc_webtransport_stream_callbacks_t  *wt_stream_cbs,
    uint64_t max_sessions)
{
    return xqc_wt_ctx_init_for_alpns(engine, wt_dgram_cbs, wt_session_cbs,
        wt_stream_cbs, max_sessions, NULL, 0);
}


xqc_int_t
xqc_wt_client_open_session(xqc_engine_t *engine, const xqc_cid_t *cid,
    const char *path, const char *authority, void *user_data)
{
    if (engine == NULL || cid == NULL || path == NULL) {
        return -XQC_EPARAM;
    }

    xqc_connection_t *conn = xqc_engine_get_conn_by_scid(engine, cid);
    xqc_h3_conn_t    *h3c  = conn ? (xqc_h3_conn_t *)conn->proto_data : NULL;
    if (h3c == NULL) {
        return -XQC_ESTATE;
    }

    xqc_wt_conn_t *wt_conn = xqc_wt_conn_from_h3(h3c);
    xqc_h3_request_t *h3_request = wt_conn ? wt_conn->pending_client_connect : NULL;
    if (h3_request == NULL) {
        h3_request = xqc_h3_request_create(engine, cid, NULL, user_data);
        if (h3_request == NULL) {
            return -XQC_ECREATE_STREAM;
        }
        if (wt_conn) {
            wt_conn->pending_client_connect = h3_request;
        }
        xqc_conn_continue_send(engine, cid);
        xqc_engine_main_logic(engine);
        return -XQC_EAGAIN;
    }

    if (h3_request->h3_stream == NULL) {
        return -XQC_ESTATE;
    }

    xqc_int_t req_ret = xqc_wt_client_check_draft15_requirements(
        h3_request->h3_stream, XQC_TRUE);
    if (req_ret != XQC_OK) {
        return req_ret;
    }

    /* send Extended CONNECT headers (RFC 9220) */
    const char *auth = authority ? authority : "localhost";
    xqc_http_header_t headers[] = {
        {.name  = {.iov_base = (void *)":method",    .iov_len = 7},
         .value = {.iov_base = (void *)"CONNECT",    .iov_len = 7}},
        {.name  = {.iov_base = (void *)":protocol",  .iov_len = 9},
         .value = {.iov_base = (void *)"webtransport-h3", .iov_len = 15}},
        {.name  = {.iov_base = (void *)":scheme",    .iov_len = 7},
         .value = {.iov_base = (void *)"https",      .iov_len = 5}},
        {.name  = {.iov_base = (void *)":authority",  .iov_len = 10},
         .value = {.iov_base = (void *)auth,          .iov_len = strlen(auth)}},
        {.name  = {.iov_base = (void *)":path",      .iov_len = 5},
         .value = {.iov_base = (void *)path,          .iov_len = strlen(path)}},
    };

    xqc_http_headers_t hdrs = {.headers = headers, .count = 5};
    ssize_t ret = xqc_h3_request_send_headers(h3_request, &hdrs, 0);
    if (ret < 0) {
        return (xqc_int_t)ret;
    }
    if (wt_conn) {
        wt_conn->pending_client_connect = NULL;
    }

    return XQC_OK;
}


/*
 * Create a WT bidi stream without sending data.
 * Reserves one outgoing bidi slot in session flow control, creates the
 * underlying QUIC stream, H3 bytestream wrapper, and WT bidistream object,
 * then registers the stream as pending.  The caller can later send data
 * via xqc_wt_bidistream_send().
 */
xqc_wt_bidistream_t *
xqc_wt_session_create_bidi_stream(xqc_wt_session_t *session)
{
    if (session == NULL || session->wt_conn == NULL) {
        return NULL;
    }
    xqc_h3_conn_t *h3c = session->wt_conn->h3_conn;
    if (h3c == NULL) {
        return NULL;
    }

    /* reserve one bidi stream slot, no data bytes yet */
    xqc_wt_flow_reservation_t reservation = {0};
    xqc_int_t ret = xqc_wt_session_reserve_outgoing(session, XQC_TRUE,
        XQC_TRUE, 0, &reservation);
    if (ret < 0) {
        return NULL;
    }

    /* create a QUIC bidi stream for WT data */
    xqc_connection_t *conn = xqc_h3_conn_get_xqc_conn(h3c);
    xqc_stream_t *stream = xqc_stream_create_with_direction(conn,
        XQC_STREAM_BIDI, NULL);
    if (stream == NULL) {
        xqc_wt_session_rollback_outgoing(session, &reservation);
        return NULL;
    }

    /*
     * Create H3 stream and mark as WT type BEFORE any data is sent.
     * This ensures the H3 layer knows about this stream before any
     * flow control or retransmit callbacks fire.
     */
    xqc_h3_stream_t *h3s = (xqc_h3_stream_t *)stream->user_data;
    if (h3s == NULL) {
        /* BYTESTEAM type: H3 layer routes to process_bytestream.
         * WT_BIDI flag: bytestream bypasses H3 frame parser. */
        h3s = xqc_h3_stream_create(h3c, stream,
                                    XQC_H3_STREAM_TYPE_BYTESTEAM, NULL);
        if (h3s) {
            stream->user_data = h3s;
        }

    } else if (h3s->type == XQC_H3_STREAM_TYPE_UNKNOWN) {
        h3s->type = XQC_H3_STREAM_TYPE_BYTESTEAM;
    }

    if (h3s) {
        h3s->flags |= XQC_HTTP3_STREAM_FLAG_WT_BIDI;
        if (h3s->h3_ext_bs == NULL) {
            h3s->h3_ext_bs = xqc_h3_ext_bytestream_create_passive(
                h3c, h3s, NULL);
        }
    }

    xqc_wt_bidistream_t *wt_bidi =
        xqc_wt_create_bidistream(h3s, session, NULL, NULL, XQC_FALSE);
    if (wt_bidi == NULL) {
        xqc_destroy_stream(stream);
        xqc_wt_session_rollback_outgoing(session, &reservation);
        return NULL;
    }

    ret = xqc_wt_session_add_pendingstream(session, h3s, wt_bidi,
        XQC_WT_PENDING_BIDISTREAM);
    if (ret < 0) {
        xqc_wt_bidistream_destroy(wt_bidi);
        xqc_destroy_stream(stream);
        xqc_wt_session_rollback_outgoing(session, &reservation);
        return NULL;
    }

    xqc_wt_session_commit_outgoing(session, &reservation);
    return wt_bidi;
}


ssize_t
xqc_wt_session_send_bidi(xqc_wt_session_t *session,
    const void *data, size_t data_len, int fin)
{
    /* create the bidi stream (reserves stream slot, no data reserved) */
    xqc_wt_bidistream_t *wt_bidi =
        xqc_wt_session_create_bidi_stream(session);
    if (wt_bidi == NULL) {
        return -XQC_ECREATE_STREAM;
    }

    /* send data; bidistream_send handles its own data flow reservation */
    xqc_int_t ret = xqc_wt_bidistream_send(wt_bidi, (void *)data,
        (uint32_t)data_len, fin);
    if (ret < 0) {
        xqc_wt_bidistream_destroy(wt_bidi);
        return ret;
    }

    return (ssize_t)ret;
}

const xqc_cid_t *
xqc_webtransport_connect(xqc_engine_t *engine, const xqc_conn_settings_t *conn_settings,
    const unsigned char *token, unsigned token_len, const char *server_host, int no_crypto_flag,
    const xqc_conn_ssl_config_t *conn_ssl_config, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *user_data)
{
    /* use standard h3 ALPN via xqc_h3_connect (RFC 9220) */
    return xqc_h3_connect(engine, conn_settings, token, token_len, server_host, no_crypto_flag,
        conn_ssl_config, peer_addr, peer_addrlen, user_data);
}
