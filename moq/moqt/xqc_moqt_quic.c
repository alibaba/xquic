/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */

#include "include/moq/xqc_moqt.h"
#include "src/common/xqc_str.h"
#include "xqc_moqt_session.h"
#include "src/transport/xqc_stream.h"

xqc_int_t
xqc_moqt_config_init(xqc_moqt_config_t *config, xqc_moqt_version_t version)
{
    if (config == NULL || version != XQC_MOQT_VERSION_DRAFT_22) {
        return -XQC_EPARAM;
    }

    xqc_memzero(config, sizeof(*config));
    config->version = version;
    config->max_streams = XQC_MOQT_DEFAULT_STREAMS;
    config->max_buffered_bytes = XQC_MOQT_DEFAULT_BUFFERED_BYTES;
    config->timeout = XQC_MOQT_DEFAULT_TIMEOUT;
    return XQC_OK;
}

const char *
xqc_moqt_config_alpn(const xqc_moqt_config_t *config)
{
    return config != NULL && config->version == XQC_MOQT_VERSION_DRAFT_22
        ? XQC_MOQT_ALPN_DRAFT_22 : NULL;
}

xqc_int_t
xqc_moqt_init_alpn(xqc_engine_t *engine, const xqc_moqt_config_t *config,
    const xqc_conn_callbacks_t *conn_cbs)
{
    const char                 *alpn = xqc_moqt_config_alpn(config);
    xqc_app_proto_callbacks_t   callbacks;

    if (engine == NULL || alpn == NULL || conn_cbs == NULL) {
        return -XQC_EPARAM;
    }

    xqc_memzero(&callbacks, sizeof(callbacks));
    callbacks.conn_cbs = *conn_cbs;
    callbacks.stream_cbs = xqc_moqt_stream_callbacks;
    callbacks.dgram_cbs = xqc_moqt_datagram_callbacks;
    return xqc_engine_register_alpn(engine, alpn, strlen(alpn),
                                    &callbacks, NULL);
}

const xqc_cid_t *
xqc_moqt_connect(xqc_engine_t *engine, const xqc_moqt_config_t *config,
    const xqc_conn_settings_t *settings, const unsigned char *token,
    unsigned token_len, const char *server_host,
    const xqc_conn_ssl_config_t *ssl_config, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *user_data)
{
    const char  *alpn = xqc_moqt_config_alpn(config);

    /* Draft-22 section 6.2 requires Native QUIC DATAGRAM support. */
    if (engine == NULL
        || alpn == NULL
        || settings == NULL
        || settings->max_datagram_frame_size == 0
        || ssl_config == NULL)
    {
        return NULL;
    }

    /* No implicit reuse of legacy resumption state (draft-22 section 6.3.1). */
    if (ssl_config->session_ticket_data != NULL
        || ssl_config->session_ticket_len != 0
        || ssl_config->transport_parameter_data != NULL
        || ssl_config->transport_parameter_data_len != 0)
    {
        return NULL;
    }

    return xqc_connect(engine, settings, token, token_len, server_host,
                       XQC_FALSE, ssl_config, peer_addr, peer_addrlen,
                       alpn, user_data);
}

xqc_moqt_stream_t *
xqc_moqt_stream_allocate(xqc_moqt_session_t *s, xqc_stream_t *transport)
{
    if (s == NULL || s->closed) {
        return NULL;
    }
    if (s->stream_count == s->config.max_streams) {
        xqc_moqt_session_close(s, XQC_MOQT_INTERNAL_ERROR);
        return NULL;
    }
    xqc_moqt_stream_t *st = xqc_calloc(1, sizeof(*st));
    if (st == NULL) {
        xqc_moqt_session_close(s, XQC_MOQT_INTERNAL_ERROR);
        return NULL;
    }
    st->session = s;
    st->transport_stream = transport;
    st->next = s->streams;
    s->streams = st;
    s->stream_count++;
    xqc_init_list_head(&st->tx);
    if (xqc_stream_is_recv_only(s->conn->conn_type, xqc_stream_id(transport))) {
        st->deadline = xqc_monotonic_timestamp() + s->config.timeout;
        xqc_moqt_timer_update(s);
    }
    if (xqc_stream_get_direction(transport) == XQC_STREAM_BIDI && !s->ready) {
        /* Section 6.3 permits refusing streams received before SETUP. */
        st->discarded = 1;
        if (!s->webtransport) {
            xqc_stream_close(transport);
        }
    }
    return st;
}

static xqc_int_t
xqc_moqt_stream_created(xqc_stream_t *transport, void *data)
{
    xqc_moqt_session_t *s = xqc_get_conn_alp_user_data_by_stream(transport);
    xqc_moqt_stream_t *st = xqc_moqt_stream_allocate(s, transport);
    if (st == NULL) {
        return -XQC_EPARAM;
    }
    xqc_stream_set_user_data(transport, st);
    return XQC_OK;
}

static xqc_int_t
xqc_moqt_stream_read(xqc_stream_t *transport, void *data)
{
    xqc_moqt_stream_t *st = data;
    uint8_t buf[XQC_MOQT_READ_CHUNK], fin = 0;
    if (st == NULL) {
        return -XQC_EPARAM;
    }
    if (st->reading) {
        return XQC_OK;
    }
    xqc_int_t ret = XQC_OK;
    st->reading = 1;
    while (!st->session->closed && !st->discarded) {
        size_t cap = xqc_min(sizeof(buf), XQC_MOQT_RX_LIMIT - st->rx.data_len);
        if (cap == 0 && st->kind == XQC_MOQT_STREAM_FETCH) {
            xqc_moqt_stream_cancel(st, XQC_MOQT_RESET_EXCESSIVE_LOAD);
            break;
        }
        ssize_t n = xqc_stream_recv(transport, buf, cap, &fin);
        if (n == -XQC_EAGAIN) {
            break;
        }
        if (n < 0) {
            if (st->kind == XQC_MOQT_STREAM_CONTROL) {
                xqc_moqt_session_close(st->session,
                                       XQC_MOQT_PROTOCOL_VIOLATION);
            } else if (st->kind == XQC_MOQT_STREAM_REQUEST) {
                xqc_moqt_request_cancel(&st->state.request,
                                        transport->stream_err);
            } else if ((st->kind == XQC_MOQT_STREAM_SUBGROUP
                           || st->kind == XQC_MOQT_STREAM_FETCH))
            {
                xqc_moqt_stream_cancel(st, transport->stream_err);
            }
            /* A handled peer reset is not a transport callback failure. */
            ret = n == -XQC_ESTREAM_RESET ? XQC_OK : (xqc_int_t)n;
            break;
        }
        ret = xqc_moqt_stream_input(st, buf, n, fin);
        if (ret != XQC_OK || fin || n == 0) {
            break;
        }
    }
    st->reading = 0;
    if (!st->writing && !st->active && st->transport_stream == NULL) {
        xqc_moqt_stream_callbacks.stream_close_notify(NULL, st);
    }
    return ret;
}

static xqc_int_t
xqc_moqt_stream_write(xqc_stream_t *transport, void *data)
{
    return data == NULL ? -XQC_EPARAM : xqc_moqt_stream_flush(data);
}

static void
xqc_moqt_stream_reset(xqc_stream_t *transport, xqc_int_t error, void *data)
{
    xqc_moqt_stream_t *st = data;
    if (transport->stream_state_recv >= XQC_RECV_STREAM_ST_RESET_RECVD) {
        /* Consume RESET even after local cancellation stopped data parsing. */
        uint8_t fin;
        xqc_stream_recv(transport, NULL, 0, &fin);
    }
    if (st != NULL && st->kind == XQC_MOQT_STREAM_CONTROL) {
        xqc_moqt_session_close(st->session, XQC_MOQT_PROTOCOL_VIOLATION);
    } else if (st != NULL && st->kind == XQC_MOQT_STREAM_REQUEST) {
        xqc_moqt_request_cancel(&st->state.request, transport->stream_err);
    } else if (st != NULL
               && (st->kind == XQC_MOQT_STREAM_SUBGROUP
                   || st->kind == XQC_MOQT_STREAM_FETCH))
    {
        xqc_moqt_stream_cancel(st, transport->stream_err);
    }
}

static void
xqc_moqt_stream_stop(xqc_stream_t *transport, uint64_t error, void *data)
{
    xqc_moqt_stream_t *st = data;
    if (st != NULL && st->kind == XQC_MOQT_STREAM_REQUEST) {
        xqc_moqt_request_cancel(&st->state.request, error);
    } else if (st != NULL
               && (st->kind == XQC_MOQT_STREAM_SUBGROUP
                   || st->kind == XQC_MOQT_STREAM_FETCH))
    {
        xqc_moqt_stream_cancel(st, error);
    } else {
        xqc_moqt_stream_reset(transport, 0, data);
    }
}

static xqc_int_t
xqc_moqt_stream_closed(xqc_stream_t *transport, void *data)
{
    xqc_moqt_stream_t *st = data;
    if (st == NULL) {
        return XQC_OK;
    }
    xqc_moqt_session_t *s = st->session;
    if (!s->closed && st->kind == XQC_MOQT_STREAM_CONTROL
        && s->conn->conn_state < XQC_CONN_STATE_CLOSING)
    {
        /* Section 6.3: a control stream cannot FIN/reset during the session. */
        xqc_moqt_session_close(s, XQC_MOQT_PROTOCOL_VIOLATION);
    }
    if (transport != NULL) {
        xqc_stream_set_user_data(transport, NULL);
        st->transport_stream = NULL;
    }
    if (st->reading || st->writing || st->active) {
        return XQC_OK;
    }
    /* Early FETCH data/FIN remains bounded and owned until FETCH_OK. */
    if (!s->closed
        && !st->discarded
        && st->kind == XQC_MOQT_STREAM_FETCH
        && st->state.data.fetch != NULL)
    {
        if (!st->state.data.fetch->ready) {
            return XQC_OK;
        }
    }
    st->discarded = 1;
    /* Reentrant callbacks may release other streams while this one closes. */
    st->writing = 1;
    if (st->kind == XQC_MOQT_STREAM_REQUEST) {
        xqc_moqt_request_closed(&st->state.request);
    } else if ((st->kind == XQC_MOQT_STREAM_SUBGROUP
                   || st->kind == XQC_MOQT_STREAM_FETCH))
    {
        xqc_moqt_subgroup_closed(st);
    }
    if (s->control_rx == st) {
        s->control_rx = NULL;
    }
    if (s->control_tx == st) {
        s->control_tx = NULL;
    }
    xqc_moqt_stream_t **link = &s->streams;
    while (*link != st) {
        link = &(*link)->next;
    }
    *link = st->next;
    s->stream_count--;
    s->buffered_bytes -= st->rx.buf_len;
    xqc_free(st->rx.data);
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &st->tx) {
        xqc_list_buf_t *entry = xqc_list_entry(pos, xqc_list_buf_t, list_head);
        xqc_moqt_dequeue(s, entry);
    }
    xqc_free(st);
    return XQC_OK;
}

static void
xqc_moqt_datagram_read(xqc_connection_t *conn, void *data,
    const void *bytes, size_t len, uint64_t timestamp)
{
    xqc_moqt_datagram_input(data, bytes, len);
}

static void
xqc_moqt_datagram_write(xqc_connection_t *conn, void *data)
{
    xqc_moqt_datagram_writable(data);
}

const xqc_stream_callbacks_t xqc_moqt_stream_callbacks = {
    .stream_create_notify = xqc_moqt_stream_created,
    .stream_read_notify = xqc_moqt_stream_read,
    .stream_write_notify = xqc_moqt_stream_write,
    .stream_close_notify = xqc_moqt_stream_closed,
    .stream_closing_notify = xqc_moqt_stream_reset,
    .stream_stop_sending_notify = xqc_moqt_stream_stop,
};

const xqc_datagram_callbacks_t xqc_moqt_datagram_callbacks = {
    .datagram_read_notify = xqc_moqt_datagram_read,
    .datagram_write_notify = xqc_moqt_datagram_write,
};
