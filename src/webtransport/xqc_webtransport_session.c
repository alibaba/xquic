/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include "src/webtransport/xqc_webtransport_session.h"
#include "src/webtransport/xqc_webtransport_conn.h"
#include "src/webtransport/xqc_webtransport_stream.h"
#include "src/webtransport/xqc_webtransport_request_adapter.h"
#include "src/webtransport/xqc_webtransport_wire.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_request.h"
#include "src/common/xqc_malloc.h"

#define XQC_WT_CLOSE_CAPSULE 0x2843
#define XQC_WT_DRAIN_CAPSULE 0x78ae
#define XQC_WT_MAX_STREAM_DATA_CAPSULE 0x190b4d3e
#define XQC_WT_STREAM_DATA_BLOCKED_CAPSULE 0x190b4d42

static xqc_bool_t xqc_wt_valid_utf8(const unsigned char *data, size_t len);
static xqc_int_t xqc_wt_capsule_complete(xqc_wt_session_t *session);

static xqc_bool_t
xqc_wt_valid_utf8(const unsigned char *data, size_t len)
{
    for (size_t i = 0; i < len;) {
        uint32_t code = data[i++];
        if (code < 0x80) {
            continue;
        }
        unsigned count;
        uint32_t minimum;
        if (code >= 0xc2 && code <= 0xdf) {
            count = 1;
            minimum = 0x80;
            code &= 0x1f;
        } else if (code >= 0xe0 && code <= 0xef) {
            count = 2;
            minimum = 0x800;
            code &= 0x0f;
        } else if (code >= 0xf0 && code <= 0xf4) {
            count = 3;
            minimum = 0x10000;
            code &= 0x07;
        } else {
            return XQC_FALSE;
        }
        if (len - i < count) {
            return XQC_FALSE;
        }
        while (count--) {
            unsigned char byte = data[i++];
            if ((byte & 0xc0) != 0x80) {
                return XQC_FALSE;
            }
            code = (code << 6) | (byte & 0x3f);
        }
        if (code < minimum || code > 0x10ffff
            || (code >= 0xd800 && code <= 0xdfff))
        {
            return XQC_FALSE;
        }
    }
    return XQC_TRUE;
}

xqc_wt_session_t *
xqc_wt_session_init(uint64_t id, xqc_wt_conn_t *conn,
    xqc_h3_stream_t *stream)
{
    if (!conn || (id & 3)) {
        return NULL;
    }
    xqc_wt_session_t *session = xqc_calloc(1, sizeof(*session));
    if (!session) {
        return NULL;
    }
    session->sessionID = id;
    session->wt_conn = conn;
    session->h3_stream = stream;
    session->request = stream ? stream->h3r : NULL;
    xqc_init_list_head(&session->stream_list);
    xqc_init_list_head(&session->conn_list);
    if (xqc_wt_conn_register_session(conn, session) != XQC_OK) {
        xqc_free(session);
        return NULL;
    }
    return session;
}

xqc_h3_conn_t *
xqc_wt_session_get_h3_conn(xqc_wt_session_t *session)
{
    return session && session->wt_conn ? session->wt_conn->h3_conn : NULL;
}

xqc_connection_t *
xqc_wt_session_get_conn(xqc_wt_session_t *session)
{
    xqc_h3_conn_t *conn = xqc_wt_session_get_h3_conn(session);
    return conn ? conn->conn : NULL;
}

xqc_h3_stream_t *
xqc_wt_session_get_h3_stream(xqc_wt_session_t *session)
{
    return session ? session->h3_stream : NULL;
}

xqc_bool_t
xqc_wt_session_is_writable(xqc_wt_session_t *session)
{
    return session && session->open && !session->closed
        && !session->wt_conn->closing;
}

const xqc_webtransport_stream_callbacks_t *
xqc_wt_session_get_stream_callbacks(xqc_wt_session_t *session)
{
    return &session->wt_conn->ctx->stream_cbs;
}

void *
xqc_wt_session_get_callback_user_data(xqc_wt_session_t *session)
{
    xqc_h3_conn_t *h3c = xqc_wt_session_get_h3_conn(session);
    return h3c ? xqc_h3_conn_get_user_data(h3c) : NULL;
}

void
xqc_wt_session_notify_closed(xqc_wt_session_t *session)
{
    if (!session || session->close_notified) {
        return;
    }
    session->closed = XQC_TRUE;
    session->close_notified = XQC_TRUE;
    xqc_wt_session_close_streams(session);
    xqc_wt_ctx_t *ctx = session->wt_conn->ctx;
    if ((session->open || session->client)
        && ctx->session_cbs.webtransport_session_close_notify)
    {
        ctx->session_cbs.webtransport_session_close_notify(session, NULL,
            &session->wt_conn->cid,
            xqc_wt_session_get_callback_user_data(session));
    }
}

void
xqc_wt_session_destroy(xqc_wt_session_t *session)
{
    if (!session) {
        return;
    }
    xqc_wt_session_notify_closed(session);
    if (session->request) {
        xqc_wt_request_adapter_detach(session->request);
    }
    xqc_wt_conn_unregister_session(session->wt_conn, session->sessionID);
    xqc_free(session->client_authority);
    xqc_free(session);
}

xqc_webtransport_draft_version_t
xqc_wt_session_get_draft_version(xqc_wt_session_t *session)
{
    return session && session->wt_conn
        ? session->wt_conn->negotiated_version : 0;
}

unsigned
xqc_wt_session_get_response_status(xqc_wt_session_t *session)
{
    return session ? session->response_status : 0;
}

uint32_t
xqc_wt_session_get_close_error_code(xqc_wt_session_t *session)
{
    return session ? session->close_error : 0;
}

const char *
xqc_wt_session_get_close_reason(xqc_wt_session_t *session)
{
    return session ? session->close_reason : NULL;
}

xqc_int_t
xqc_wt_session_flush(xqc_wt_session_t *session)
{
    if (!session || !session->request) {
        return -XQC_ESTATE;
    }
    if (session->request->h3_stream->flags & XQC_HTTP3_STREAM_FLAG_FIN_SENT) {
        session->send_fin = XQC_FALSE;
        return session->send_len ? -XQC_ESTATE : XQC_OK;
    }
    if (session->send_offset == session->send_len && !session->send_fin) {
        return XQC_OK;
    }
    ssize_t sent = xqc_h3_request_send_body(session->request,
        session->send_buf + session->send_offset,
        session->send_len - session->send_offset, session->send_fin);
    if (sent < 0) {
        return sent == -XQC_EAGAIN ? XQC_OK : (xqc_int_t)sent;
    }
    session->send_offset += sent;
    if (session->send_offset == session->send_len) {
        session->send_offset = 0;
        session->send_len = 0;
        session->send_fin = XQC_FALSE;
    }
    return XQC_OK;
}

xqc_int_t
xqc_wt_session_close_with_error(xqc_wt_session_t *session,
    uint32_t error, const char *reason, size_t reason_len)
{
    if (!session || (!reason && reason_len)
        || reason_len > XQC_WT_CLOSE_REASON_MAX
        || !xqc_wt_valid_utf8((const unsigned char *)reason, reason_len))
    {
        return -XQC_EPARAM;
    }
    if (session->closed) {
        return XQC_OK;
    }
    if (!session->open) {
        return -XQC_ESTATE;
    }
    if (session->send_len) {
        return -XQC_EAGAIN;
    }
    /* draft-ietf-webtrans-http3-07 §5 and -16 §6: CLOSE capsule then FIN. */
    session->close_error = error;
    if (reason_len) {
        memcpy(session->close_reason, reason, reason_len);
    }
    session->close_reason[reason_len] = '\0';
    size_t n = xqc_wt_encode_session_id(XQC_WT_CLOSE_CAPSULE,
        session->send_buf, sizeof(session->send_buf));
    n += xqc_wt_encode_session_id(4 + reason_len, session->send_buf + n,
                                 sizeof(session->send_buf) - n);
    for (size_t i = 0; i < 4; i++) {
        session->send_buf[n++] = (unsigned char)(error >> (24 - 8 * i));
    }
    memcpy(session->send_buf + n, session->close_reason, reason_len);
    session->send_len = n + reason_len;
    session->send_fin = XQC_TRUE;
    session->closed = XQC_TRUE;
    xqc_wt_session_close_streams(session);
    return xqc_wt_session_flush(session);
}

xqc_int_t
xqc_wt_session_close(xqc_wt_session_t *session)
{
    return xqc_wt_session_close_with_error(session, 0, NULL, 0);
}

xqc_int_t
xqc_wt_session_drain(xqc_wt_session_t *session)
{
    if (!xqc_wt_session_is_writable(session)) {
        return -XQC_ESTATE;
    }
    if (session->draining) {
        return XQC_OK;
    }
    if (session->send_len) {
        return -XQC_EAGAIN;
    }
    size_t n = xqc_wt_encode_session_id(XQC_WT_DRAIN_CAPSULE,
        session->send_buf, sizeof(session->send_buf));
    session->send_buf[n++] = 0;
    session->send_len = n;
    session->draining = XQC_TRUE;
    return xqc_wt_session_flush(session);
}

static xqc_int_t
xqc_wt_capsule_complete(xqc_wt_session_t *session)
{
    if (session->capsule_type == XQC_WT_CLOSE_CAPSULE) {
        /* draft-ietf-webtrans-http3-16 §6: invalid UTF-8 is a message error. */
        if (!xqc_wt_valid_utf8(session->recv_buf + 4, session->recv_len - 4)) {
            return -XQC_H3_DECODE_ERROR;
        }
        session->close_error = 0;
        for (size_t i = 0; i < 4; i++) {
            session->close_error = (session->close_error << 8)
                | session->recv_buf[i];
        }
        memcpy(session->close_reason, session->recv_buf + 4,
               session->recv_len - 4);
        session->close_reason[session->recv_len - 4] = '\0';
        session->closed = XQC_TRUE;
        session->peer_closed = XQC_TRUE;
        xqc_wt_session_close_streams(session);

    } else if (session->capsule_type == XQC_WT_DRAIN_CAPSULE
               && !session->draining)
    {
        xqc_wt_session_notify_draining(session);
    }
    session->capsule_body = XQC_FALSE;
    session->recv_header_len = 0;
    session->recv_len = 0;
    return XQC_OK;
}

void
xqc_wt_session_notify_draining(xqc_wt_session_t *session)
{
    if (session->draining) {
        return;
    }
    session->draining = XQC_TRUE;
    xqc_wt_ctx_t *ctx = session->wt_conn->ctx;
    if (ctx->session_cbs.webtransport_session_drain_notify) {
        ctx->session_cbs.webtransport_session_drain_notify(session,
            xqc_wt_session_get_callback_user_data(session));
    }
}

xqc_int_t
xqc_wt_session_recv_capsules(xqc_wt_session_t *session,
    const unsigned char *data, size_t len, xqc_bool_t fin)
{
    if (!session || (!data && len)) {
        return -XQC_EPARAM;
    }
    for (size_t i = 0; i < len;) {
        if (session->peer_closed) {
            return -XQC_H3_DECODE_ERROR;
        }
        if (!session->capsule_body) {
            session->recv_header[session->recv_header_len++] = data[i++];
            size_t type_len = 1U << (session->recv_header[0] >> 6);
            if (session->recv_header_len <= type_len) {
                continue;
            }
            size_t length_len = 1U
                << (session->recv_header[type_len] >> 6);
            if (session->recv_header_len < type_len + length_len) {
                continue;
            }
            xqc_wt_decode_session_id(session->recv_header, type_len,
                                     &session->capsule_type);
            xqc_wt_decode_session_id(session->recv_header + type_len,
                length_len, &session->capsule_remaining);
            /* draft-ietf-webtrans-http3-16 §5.4 forbids H2 stream limits. */
            if (session->wt_conn->negotiated_version
                    == XQC_WEBTRANSPORT_DRAFT_VERSION_16
                && (session->capsule_type == XQC_WT_MAX_STREAM_DATA_CAPSULE
                    || session->capsule_type
                        == XQC_WT_STREAM_DATA_BLOCKED_CAPSULE))
            {
                return -XQC_H3_DECODE_ERROR;
            }
            if ((session->capsule_type == XQC_WT_CLOSE_CAPSULE
                 && (session->capsule_remaining < 4
                     || session->capsule_remaining > 4 + XQC_WT_CLOSE_REASON_MAX))
                || (session->capsule_type == XQC_WT_DRAIN_CAPSULE
                    && session->capsule_remaining != 0))
            {
                return -XQC_H3_DECODE_ERROR;
            }
            session->capsule_body = XQC_TRUE;
        }
        if (session->capsule_remaining) {
            size_t n = xqc_min((uint64_t)(len - i),
                               session->capsule_remaining);
            if (session->capsule_type == XQC_WT_CLOSE_CAPSULE) {
                memcpy(session->recv_buf + session->recv_len, data + i, n);
                session->recv_len += n;
            }
            i += n;
            session->capsule_remaining -= n;
        }
        if (session->capsule_remaining == 0) {
            xqc_int_t ret = xqc_wt_capsule_complete(session);
            if (ret != XQC_OK) {
                return ret;
            }
        }
    }
    if (fin) {
        if (session->capsule_body || session->recv_header_len) {
            return -XQC_H3_DECODE_ERROR;
        }
        session->closed = XQC_TRUE;
        session->peer_closed = XQC_TRUE;
        xqc_wt_session_close_streams(session);
        session->send_fin = XQC_TRUE;
        return session->request ? xqc_wt_session_flush(session) : XQC_OK;
    }
    return XQC_OK;
}
