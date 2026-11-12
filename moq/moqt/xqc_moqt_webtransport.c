/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include "include/moq/xqc_moqt_webtransport.h"
#include "xqc_moqt_session.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/webtransport/xqc_webtransport_conn.h"
#include "src/webtransport/xqc_webtransport_stream.h"
#include "src/webtransport/xqc_webtransport_request_adapter.h"

static void xqc_moqt_wt_session_closed(xqc_wt_session_t *wt, void *data);

static xqc_int_t
xqc_moqt_wt_created(xqc_wt_stream_base_t *wt)
{
    xqc_moqt_session_t *s = wt->session->binding_data;
    xqc_moqt_stream_t *st = xqc_moqt_stream_allocate(s,
                                                     wt->h3_stream->stream);
    if (!st) {
        return -XQC_EMALLOC;
    }
    st->wt_stream = wt;
    wt->user_data = st;
    return XQC_OK;
}

static xqc_int_t
xqc_moqt_wt_read(xqc_wt_stream_base_t *wt, const uint8_t *data, size_t len)
{
    xqc_moqt_stream_t *st = wt->user_data;
    if (!st) {
        return XQC_OK;
    }
    st->reading = 1;
    size_t offset = 0;
    do {
        if (st->session->closed || st->discarded) {
            break;
        }
        size_t amount = xqc_min(len - offset, XQC_MOQT_READ_CHUNK);
        amount = xqc_min(amount, XQC_MOQT_RX_LIMIT - st->rx.data_len);
        if (!amount && len != offset) {
            if (st->kind == XQC_MOQT_STREAM_FETCH
                || st->kind == XQC_MOQT_STREAM_SUBGROUP)
            {
                xqc_moqt_stream_cancel(st, XQC_MOQT_RESET_EXCESSIVE_LOAD);
            } else {
                xqc_moqt_session_close(st->session, XQC_MOQT_INTERNAL_ERROR);
            }
            break;
        }
        xqc_int_t ret = xqc_moqt_stream_input(st,
            amount ? data + offset : NULL, amount,
            wt->recv_fin && offset + amount == len);
        offset += amount;
        if (ret != XQC_OK) {
            break;
        }
    } while (offset < len);
    st->reading = 0;
    if (!st->active && !st->writing && !st->transport_stream) {
        xqc_moqt_stream_callbacks.stream_close_notify(NULL, st);
    }
    /* MoQT errors close this WT session; H3 can carry other sessions. */
    return XQC_OK;
}

static xqc_int_t
xqc_moqt_wt_write(xqc_wt_stream_base_t *wt)
{
    if (wt->user_data) {
        xqc_moqt_stream_flush(wt->user_data);
    }
    return XQC_OK;
}

static xqc_int_t
xqc_moqt_wt_closing(xqc_wt_stream_base_t *wt)
{
    xqc_moqt_stream_t *st = wt->user_data;
    if (!st || st->session->closed) {
        return XQC_OK;
    }
    uint64_t error = wt->recv_error_valid ? wt->recv_error_code
                                        : XQC_MOQT_RESET_SESSION_CLOSED;
    if (st->kind == XQC_MOQT_STREAM_CONTROL) {
        xqc_moqt_session_close(st->session, XQC_MOQT_PROTOCOL_VIOLATION);
    } else if (st->kind == XQC_MOQT_STREAM_REQUEST) {
        xqc_moqt_request_cancel(&st->state.request, error);
    } else {
        xqc_moqt_stream_cancel(st, error);
    }
    return XQC_OK;
}

static xqc_int_t
xqc_moqt_wt_closed(xqc_wt_stream_base_t *wt)
{
    xqc_moqt_stream_t *st = wt->user_data;
    wt->user_data = NULL;
    if (st) {
        if (!st->session->closed
            && ((wt->can_send && !wt->send_fin && !wt->send_reset)
                || (wt->can_recv && !wt->recv_fin && !wt->recv_reset)))
        {
            /* Transport teardown is not a peer FIN/reset of a MoQT control. */
            xqc_moqt_wt_session_closed(wt->session, st->session);
        }
        st->wt_stream = NULL;
        st->transport_stream = NULL;
        xqc_moqt_stream_callbacks.stream_close_notify(NULL, st);
    }
    return XQC_OK;
}

/* WT exposes distinct typed callbacks for its two raw stream directions. */
#define XQC_MOQT_WT_CALLBACKS(name, type)                                      \
    static xqc_int_t name##_create(type *st, xqc_wt_session_t *s, void *data)   \
    { return xqc_moqt_wt_created((void *)st); }                                \
    static xqc_int_t name##_write(type *st, xqc_wt_session_t *s, void *data)    \
    { return xqc_moqt_wt_write((void *)st); }                                  \
    static xqc_int_t name##_close(type *st, xqc_wt_session_t *s, void *data)    \
    { return xqc_moqt_wt_closed((void *)st); }                                 \
    static xqc_int_t name##_closing(type *st, xqc_wt_session_t *s, void *data)  \
    { return xqc_moqt_wt_closing((void *)st); }                                \
    static xqc_int_t name##_read(type *st, xqc_wt_session_t *s, void *bytes,    \
        size_t len, void *data)                                              \
    { return xqc_moqt_wt_read((void *)st, bytes, len); }

XQC_MOQT_WT_CALLBACKS(xqc_moqt_wt_uni, xqc_wt_unistream_t)
XQC_MOQT_WT_CALLBACKS(xqc_moqt_wt_bidi, xqc_wt_bidistream_t)
#undef XQC_MOQT_WT_CALLBACKS

static void
xqc_moqt_wt_datagram(xqc_wt_session_t *wt, const void *bytes, size_t len,
    void *data, uint64_t timestamp)
{
    xqc_moqt_datagram_input(data, bytes, len);
}

static void
xqc_moqt_wt_datagram_write(xqc_wt_session_t *wt, void *data)
{
    xqc_moqt_datagram_writable(data);
}

static void
xqc_moqt_wt_session_closed(xqc_wt_session_t *wt, void *data)
{
    xqc_moqt_session_t *s = data;
    s->wt_close_pending = 0;
    s->wt_session = NULL;
    if (s->timer >= 0) {
        xqc_conn_unregister_gp_timer(s->conn, s->timer);
        s->timer = -1;
    }
    xqc_moqt_notify_closed(s, xqc_wt_session_get_close_error_code(wt));
}

static void
xqc_moqt_wt_session_writable(xqc_wt_session_t *wt, void *data)
{
    xqc_moqt_session_t *s = data;
    if (!s->wt_close_pending) {
        return;
    }
    s->wt_close_pending = 0;
    xqc_int_t ret = xqc_wt_session_close_with_error(wt, s->wt_close_error,
                                                    NULL, 0);
    if (ret == -XQC_EAGAIN) {
        s->wt_close_pending = 1;
    } else if (ret < 0) {
        xqc_wt_request_fail(wt, H3_INTERNAL_ERROR);
    }
}

static const xqc_wt_session_binding_t xqc_moqt_wt_binding = {
    .stream_cbs = {
        .wt_unistream_create_notify = xqc_moqt_wt_uni_create,
        .wt_unistream_read_notify = xqc_moqt_wt_uni_read,
        .wt_unistream_write_notify = xqc_moqt_wt_uni_write,
        .wt_unistream_close_notify = xqc_moqt_wt_uni_close,
        .wt_unistream_closing_notify = xqc_moqt_wt_uni_closing,
        .wt_bidistream_create_notify = xqc_moqt_wt_bidi_create,
        .wt_bidistream_read_notify = xqc_moqt_wt_bidi_read,
        .wt_bidistream_write_notify = xqc_moqt_wt_bidi_write,
        .wt_bidistream_close_notify = xqc_moqt_wt_bidi_close,
        .wt_bidistream_closing_notify = xqc_moqt_wt_bidi_closing,
    },
    .dgram_cbs = {
        .dgram_read_notify = xqc_moqt_wt_datagram,
        .dgram_write_notify = xqc_moqt_wt_datagram_write,
    },
    .closed = xqc_moqt_wt_session_closed,
    .writable = xqc_moqt_wt_session_writable,
};

xqc_moqt_session_t *
xqc_moqt_session_create_webtransport(xqc_wt_session_t *wt,
    const xqc_moqt_config_t *config, const xqc_moqt_callbacks_t *callbacks,
    void *data)
{
    if (!xqc_wt_session_is_writable(wt) || wt->binding
        || !xqc_list_empty(&wt->stream_list)
        || wt->wt_conn->negotiated_version != XQC_WEBTRANSPORT_DRAFT_VERSION_16
        || !wt->application_protocol
        || strcmp(wt->application_protocol, XQC_MOQT_ALPN_DRAFT_22))
    {
        return NULL;
    }
    xqc_h3_conn_t *h3 = xqc_wt_session_get_h3_conn(wt);
    xqc_moqt_session_t *s = xqc_moqt_session_create_transport(h3->conn,
        config, callbacks, data, XQC_TRUE);
    if (s) {
        s->wt_session = wt;
        wt->binding = &xqc_moqt_wt_binding;
        wt->binding_data = s;
    }
    return s;
}

void
xqc_moqt_webtransport_close(xqc_moqt_session_t *s, uint64_t error)
{
    s->wt_close_error = error <= UINT32_MAX ? error : XQC_MOQT_INTERNAL_ERROR;
    s->wt_close_pending = 1;
    xqc_wt_session_t *wt = s->wt_session;
    if (wt->send_len) {
        if (xqc_wt_session_flush(wt) < 0) {
            xqc_wt_request_fail(wt, H3_INTERNAL_ERROR);
        }
    } else {
        xqc_moqt_wt_session_writable(wt, s);
    }
}

void
xqc_moqt_webtransport_detach(xqc_moqt_session_t *s)
{
    xqc_wt_session_t *wt = s->wt_session;
    if (!wt) {
        return;
    }
    if (!wt->closed) {
        xqc_moqt_webtransport_close(s, XQC_MOQT_NO_ERROR);
        if (!wt->closed) {
            /* Destruction cannot leave callbacks pointing at freed state. */
            xqc_wt_request_fail(wt, H3_INTERNAL_ERROR);
        }
    }
    wt->binding = NULL;
    wt->binding_data = NULL;
    s->wt_session = NULL;
}
