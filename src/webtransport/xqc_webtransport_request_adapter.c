/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include "src/webtransport/xqc_webtransport_request_adapter.h"
#include "src/webtransport/xqc_webtransport_conn.h"
#include "src/webtransport/xqc_webtransport_session.h"
#include "src/webtransport/xqc_webtransport_stream.h"
#include "src/webtransport/xqc_webtransport_dgram.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_request.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_packet_out.h"
#include "src/common/xqc_malloc.h"

static xqc_bool_t xqc_wt_header_is(const xqc_http_header_t *header,
    const char *name, const char *value);
static xqc_int_t xqc_wt_response(xqc_h3_request_t *request,
    const char *status);
static xqc_int_t xqc_wt_request_headers(xqc_h3_request_t *request,
    void *data, const xqc_http_headers_t *headers);
static xqc_int_t xqc_wt_accept_session(xqc_wt_session_t *session);
static xqc_int_t xqc_wt_client_response(xqc_wt_session_t *session);
static xqc_int_t xqc_wt_notify_ready(xqc_wt_session_t *session,
    xqc_http_headers_t *headers);
static xqc_wt_session_t *xqc_wt_request_session(xqc_h3_request_t *request);
static xqc_int_t xqc_wt_adapter_create(xqc_h3_request_t *request,
    void *user_data);
static xqc_int_t xqc_wt_adapter_classify(xqc_h3_request_t *request,
    xqc_request_notify_flag_t flags, void *user_data);
static xqc_int_t xqc_wt_adapter_read(xqc_h3_request_t *request,
    xqc_request_notify_flag_t flags, void *user_data);
static xqc_int_t xqc_wt_adapter_write(xqc_h3_request_t *request,
    void *user_data);
static void xqc_wt_adapter_closing(xqc_h3_request_t *request,
    xqc_int_t error, void *user_data);
static xqc_int_t xqc_wt_adapter_close(xqc_h3_request_t *request,
    void *user_data);

static xqc_h3_request_callbacks_t xqc_wt_pending_callbacks = {
    .h3_request_read_notify = xqc_wt_adapter_classify,
};

static xqc_h3_request_callbacks_t xqc_wt_session_callbacks = {
    .h3_request_read_notify = xqc_wt_adapter_read,
    .h3_request_write_notify = xqc_wt_adapter_write,
    .h3_request_closing_notify = xqc_wt_adapter_closing,
    .h3_request_close_notify = xqc_wt_adapter_close,
};

static xqc_h3_request_callbacks_t xqc_wt_closed_callbacks;

void
xqc_wt_request_adapter_init(xqc_wt_conn_t *conn)
{
    conn->app_request_callbacks = conn->h3_conn->h3_request_callbacks;
    conn->h3_conn->h3_request_callbacks.h3_request_create_notify =
        xqc_wt_adapter_create;
}

void
xqc_wt_request_adapter_detach(xqc_h3_request_t *request)
{
    request->request_if = &xqc_wt_closed_callbacks;
}

static xqc_wt_session_t *
xqc_wt_request_session(xqc_h3_request_t *request)
{
    return xqc_wt_conn_find_session(xqc_wt_create_conn(request->h3_stream->h3c),
                                   request->h3_stream->stream_id);
}

static xqc_int_t
xqc_wt_adapter_create(xqc_h3_request_t *request, void *user_data)
{
    xqc_h3_stream_t *stream = request->h3_stream;
    xqc_bool_t incoming = (stream->stream_id & 1)
        != (stream->h3c->conn->conn_type == XQC_CONN_TYPE_SERVER);
    if (incoming) {
        /* Classify CONNECT before creating ordinary application state. */
        request->request_if = &xqc_wt_pending_callbacks;
        return XQC_OK;
    }
    xqc_wt_conn_t *conn = xqc_wt_create_conn(stream->h3c);
    if (conn->client_creating) {
        request->request_if = &xqc_wt_session_callbacks;
        return XQC_OK;
    }
    return conn->app_request_callbacks.h3_request_create_notify
        ? conn->app_request_callbacks.h3_request_create_notify(request,
            user_data) : XQC_OK;
}

static xqc_int_t
xqc_wt_adapter_classify(xqc_h3_request_t *request,
    xqc_request_notify_flag_t flags, void *user_data)
{
    if (!(flags & XQC_REQ_NOTIFY_READ_HEADER)) {
        return XQC_OK;
    }
    xqc_wt_conn_t *conn = xqc_wt_create_conn(request->h3_stream->h3c);
    xqc_int_t ret = xqc_wt_request_headers(request, conn,
        &request->h3_header[XQC_H3_REQUEST_HEADER]);
    if (ret < 0) {
        return ret;
    }
    if (ret > 0) {
        request->request_if = &xqc_wt_session_callbacks;
        return xqc_wt_adapter_read(request, flags, user_data);
    }
    request->request_if = &request->h3_stream->h3c->h3_request_callbacks;
    if (conn->app_request_callbacks.h3_request_create_notify) {
        conn->app_request_callbacks.h3_request_create_notify(request,
            user_data);
    }
    return request->request_if->h3_request_read_notify
        ? request->request_if->h3_request_read_notify(request, flags,
            request->user_data) : XQC_OK;
}

static xqc_int_t
xqc_wt_adapter_read(xqc_h3_request_t *request,
    xqc_request_notify_flag_t flags, void *user_data)
{
    return xqc_wt_request_read(request, flags,
                               xqc_wt_request_session(request));
}

static xqc_int_t
xqc_wt_adapter_write(xqc_h3_request_t *request, void *user_data)
{
    xqc_wt_session_t *session = xqc_wt_request_session(request);
    if (session && session->client && !session->request_sent) {
        return xqc_wt_client_send_request(session);
    }
    return session ? xqc_wt_session_flush(session) : XQC_OK;
}

void
xqc_wt_request_fail(xqc_wt_session_t *session, uint64_t error)
{
    session->closed = XQC_TRUE;
    session->close_error = (uint32_t)error;
    xqc_wt_session_close_streams(session);
    xqc_stream_t *stream = session->request->h3_stream->stream;
    xqc_write_stop_sending_to_packet(stream->stream_conn, stream, error);
    xqc_stream_reset(stream, error);
    xqc_wt_session_notify_closed(session);
}

xqc_wt_session_t *
xqc_wt_client_open_session(xqc_h3_conn_t *h3c, const char *authority,
    const char *path, const char *origin, int *err)
{
    if (err) {
        *err = -XQC_EPARAM;
    }
    if (!authority || !*authority || !path || path[0] != '/') {
        return NULL;
    }
    size_t alen = strlen(authority) + 1, plen = strlen(path) + 1;
    size_t olen = origin ? strlen(origin) + 1 : 0;
    if (alen > 4096 || plen > 4096 || olen > 4096) {
        return NULL;
    }
    xqc_wt_conn_t *conn = xqc_wt_create_conn(h3c);
    if (err) {
        *err = -XQC_ESTATE;
    }
    if (!conn || conn->closing || !h3c->conn
        || h3c->conn->conn_type != XQC_CONN_TYPE_CLIENT
        || (h3c->flags & XQC_H3_CONN_FLAG_GOAWAY_RECVD)
        || (conn->settings_received && !xqc_wt_conn_requirements_met(conn)))
    {
        return NULL;
    }
    size_t limit = conn->ctx->settings.max_sessions_count;
    if (conn->negotiated_version == XQC_WEBTRANSPORT_DRAFT_VERSION_7) {
        limit = xqc_min(limit, conn->peer_max_sessions);
    }
    if (conn->session_count >= limit) {
        return NULL;
    }
    char *strings = xqc_malloc(alen + plen + olen);
    if (!strings) {
        if (err) {
            *err = -XQC_EMALLOC;
        }
        return NULL;
    }
    memcpy(strings, authority, alen);
    memcpy(strings + alen, path, plen);
    if (olen) {
        memcpy(strings + alen + plen, origin, olen);
    }
    conn->client_creating = XQC_TRUE;
    xqc_h3_request_t *request = xqc_h3_request_create(h3c->conn->engine,
        &conn->cid, NULL, NULL);
    conn->client_creating = XQC_FALSE;
    if (!request) {
        xqc_free(strings);
        if (err) {
            *err = -XQC_ESTREAM_BLOCKED;
        }
        return NULL;
    }
    xqc_wt_session_t *session = xqc_wt_session_init(
        request->h3_stream->stream_id, conn, request->h3_stream);
    if (!session) {
        xqc_wt_request_adapter_detach(request);
        xqc_h3_request_close(request);
        xqc_free(strings);
        if (err) {
            *err = -XQC_EMALLOC;
        }
        return NULL;
    }
    session->client = XQC_TRUE;
    session->client_authority = strings;
    session->client_path = strings + alen;
    session->client_origin = olen ? strings + alen + plen : NULL;
    xqc_wt_client_send_request(session);
    if (err) {
        *err = XQC_OK;
    }
    return session;
}

xqc_int_t
xqc_wt_client_send_request(xqc_wt_session_t *session)
{
    xqc_wt_conn_t *conn = session->wt_conn;
    if (!session->client || session->request_sent || session->closed
        || !conn->settings_received
        || !(conn->h3_conn->conn->conn_flag & XQC_CONN_FLAG_TLS_HSK_COMPLETED))
    {
        return XQC_OK;
    }
    /* draft-ietf-webtrans-http3-16 §§3.1, 3.2: SETTINGS and no 0-RTT CONNECT. */
    if (conn->h3_conn->flags & XQC_H3_CONN_FLAG_GOAWAY_RECVD) {
        xqc_wt_request_fail(session, H3_REQUEST_REJECTED);
        return XQC_OK;
    }
    if (!xqc_wt_conn_requirements_met(conn)) {
        xqc_wt_request_fail(session, XQC_WT_REQUIREMENTS_NOT_MET);
        return XQC_OK;
    }
    const char *names[] = {":method", ":scheme", ":authority", ":path",
                           ":protocol", "origin"};
    const char *values[] = {"CONNECT", "https", session->client_authority,
        session->client_path, conn->negotiated_version
            == XQC_WEBTRANSPORT_DRAFT_VERSION_16
            ? "webtransport-h3" : "webtransport", session->client_origin};
    xqc_http_header_t fields[6] = {0};
    xqc_http_headers_t headers = {
        .headers = fields,
        .count = session->client_origin ? 6 : 5,
    };
    for (size_t i = 0; i < headers.count; i++) {
        fields[i].name.iov_base = (void *)names[i];
        fields[i].name.iov_len = strlen(names[i]);
        fields[i].value.iov_base = (void *)values[i];
        fields[i].value.iov_len = strlen(values[i]);
    }
    ssize_t ret = xqc_h3_request_send_headers(session->request, &headers, 0);
    if (ret == -XQC_EAGAIN) {
        return XQC_OK;
    }
    if (ret < 0) {
        xqc_wt_request_fail(session, H3_INTERNAL_ERROR);
        return XQC_OK;
    }
    session->request_sent = XQC_TRUE;
    xqc_free(session->client_authority);
    session->client_authority = NULL;
    session->client_path = NULL;
    session->client_origin = NULL;
    return XQC_OK;
}

static void
xqc_wt_adapter_closing(xqc_h3_request_t *request, xqc_int_t error,
    void *user_data)
{
    xqc_wt_session_t *session = xqc_wt_request_session(request);
    if (session) {
        session->closed = XQC_TRUE;
        session->close_error = (uint32_t)error;
        xqc_wt_session_close_streams(session);
    }
}

static xqc_int_t
xqc_wt_adapter_close(xqc_h3_request_t *request, void *user_data)
{
    xqc_wt_session_destroy(xqc_wt_request_session(request));
    return XQC_OK;
}

static xqc_bool_t
xqc_wt_header_is(const xqc_http_header_t *header, const char *name,
    const char *value)
{
    return header->name.iov_len == strlen(name)
        && memcmp(header->name.iov_base, name, strlen(name)) == 0
        && (!value || (header->value.iov_len == strlen(value)
            && memcmp(header->value.iov_base, value, strlen(value)) == 0));
}

static xqc_int_t
xqc_wt_response(xqc_h3_request_t *request, const char *status)
{
    xqc_http_header_t header = {
        .name = {(void *)":status", 7},
        .value = {(void *)status, 3},
    };
    xqc_http_headers_t response = {.headers = &header, .count = 1};
    ssize_t ret = xqc_h3_request_send_headers(request, &response, 1);
    return ret < 0 ? (xqc_int_t)ret : XQC_OK;
}

static xqc_int_t
xqc_wt_request_headers(xqc_h3_request_t *request, void *data,
    const xqc_http_headers_t *headers)
{
    xqc_wt_conn_t *conn = data;
    xqc_bool_t wt = XQC_FALSE;
    for (size_t i = 0; i < headers->count; i++) {
        wt |= xqc_wt_header_is(&headers->headers[i], ":protocol",
                              "webtransport");
        wt |= xqc_wt_header_is(&headers->headers[i], ":protocol",
                              "webtransport-h3");
    }
    if (!wt) {
        return 0;
    }
    if (conn->session_count >= conn->ctx->settings.max_sessions_count
        && conn->ctx->settings.draft_version
            == XQC_WEBTRANSPORT_DRAFT_VERSION_7)
    {
        xqc_int_t ret = xqc_wt_response(request, "429");
        return ret < 0 ? ret : 1;
    }
    if (conn->session_count >= 64) {
        xqc_stream_reset(request->h3_stream->stream, H3_REQUEST_REJECTED);
        return 1;
    }
    xqc_wt_session_t *session = xqc_wt_session_init(
        request->h3_stream->stream_id, conn, request->h3_stream);
    if (!session) {
        return -XQC_EMALLOC;
    }
    return 1;
}

static xqc_int_t
xqc_wt_accept_session(xqc_wt_session_t *session)
{
    xqc_wt_conn_t *conn = session->wt_conn;
    unsigned char fin = 0;
    xqc_http_headers_t *headers =
        xqc_h3_request_recv_headers(session->request, &fin);
    if (!headers) {
        return -XQC_H3_DECODE_ERROR;
    }
    unsigned method = 0, protocol = 0, scheme = 0, authority = 0, path = 0;
    for (size_t i = 0; i < headers->count; i++) {
        xqc_http_header_t *header = &headers->headers[i];
        method += xqc_wt_header_is(header, ":method", "CONNECT");
        protocol += xqc_wt_header_is(header, ":protocol",
            conn->negotiated_version == XQC_WEBTRANSPORT_DRAFT_VERSION_16
                ? "webtransport-h3" : "webtransport");
        scheme += xqc_wt_header_is(header, ":scheme", "https");
        authority += xqc_wt_header_is(header, ":authority", NULL)
            && header->value.iov_len > 0;
        path += xqc_wt_header_is(header, ":path", NULL)
            && header->value.iov_len > 0;
    }
    if (method != 1 || protocol != 1 || scheme != 1 || authority != 1
        || path != 1 || fin || !xqc_wt_conn_requirements_met(conn))
    {
        session->closed = XQC_TRUE;
        if (conn->negotiated_version == XQC_WEBTRANSPORT_DRAFT_VERSION_16) {
            xqc_wt_request_fail(session, H3_MESSAGE_ERROR);
            return XQC_OK;
        }
        return xqc_wt_response(session->request, "400");
    }
    if (conn->negotiated_version == XQC_WEBTRANSPORT_DRAFT_VERSION_16) {
        xqc_list_head_t *pos;
        xqc_list_for_each(pos, &conn->session_list) {
            xqc_wt_session_t *other = xqc_list_entry(pos,
                xqc_wt_session_t, conn_list);
            if (other != session && other->open && !other->closed) {
                /* draft-ietf-webtrans-http3-16 §5.1: pooling is disabled. */
                xqc_wt_request_fail(session, H3_REQUEST_REJECTED);
                return XQC_OK;
            }
        }
    }
    xqc_http_header_t header = {
        .name = {(void *)":status", 7},
        .value = {(void *)"200", 3},
    };
    xqc_http_headers_t response = {.headers = &header, .count = 1};
    xqc_webtransport_session_callbacks_t *cbs = &conn->ctx->session_cbs;
    if (!cbs->webtransport_will_create_session_notify
        || cbs->webtransport_will_create_session_notify(headers, &response)
            != 1)
    {
        session->closed = XQC_TRUE;
        return xqc_wt_response(session->request, "403");
    }
    xqc_bool_t accepted = XQC_FALSE;
    for (size_t i = 0; i < response.count; i++) {
        xqc_http_header_t *h = &response.headers[i];
        if (xqc_wt_header_is(h, ":status", NULL) && h->value.iov_len == 3) {
            accepted = ((const char *)h->value.iov_base)[0] == '2';
        }
    }
    ssize_t ret = xqc_h3_request_send_headers(session->request, &response,
                                             !accepted);
    if (ret < 0) {
        return (xqc_int_t)ret;
    }
    if (!accepted) {
        session->closed = XQC_TRUE;
        return XQC_OK;
    }
    session->response_status = 200;
    return xqc_wt_notify_ready(session, headers);
}

static xqc_int_t
xqc_wt_notify_ready(xqc_wt_session_t *session, xqc_http_headers_t *headers)
{
    xqc_wt_conn_t *conn = session->wt_conn;
    xqc_webtransport_session_callbacks_t *cbs = &conn->ctx->session_cbs;
    session->open = XQC_TRUE;
    if (cbs->webtransport_session_create_notify) {
        xqc_int_t ret = cbs->webtransport_session_create_notify(session, headers,
            &conn->cid, xqc_wt_session_get_callback_user_data(session));
        if (ret != XQC_OK) {
            return xqc_wt_session_close_with_error(session, 1, NULL, 0);
        }
    }
    xqc_wt_conn_resume_streams(conn);
    xqc_wt_dgram_resume(session);
    return XQC_OK;
}

static xqc_int_t
xqc_wt_client_response(xqc_wt_session_t *session)
{
    uint8_t fin = 0;
    xqc_http_headers_t *headers =
        xqc_h3_request_recv_headers(session->request, &fin);
    if (!headers) {
        return XQC_OK;
    }
    unsigned status = 0, count = 0;
    for (size_t i = 0; i < headers->count; i++) {
        xqc_http_header_t *header = &headers->headers[i];
        if (xqc_wt_header_is(header, ":status", NULL)) {
            count++;
            const unsigned char *value = header->value.iov_base;
            if (header->value.iov_len != 3 || value[0] < '1'
                || value[0] > '5' || value[1] < '0' || value[1] > '9'
                || value[2] < '0' || value[2] > '9')
            {
                xqc_wt_request_fail(session, H3_MESSAGE_ERROR);
                return XQC_OK;
            }
            status = (value[0] - '0') * 100 + (value[1] - '0') * 10
                + value[2] - '0';
        }
    }
    if (count != 1) {
        xqc_wt_request_fail(session, H3_MESSAGE_ERROR);
        return XQC_OK;
    }
    if (status < 200) {
        return XQC_OK;
    }
    session->response_status = status;
    if (status >= 300) {
        /* Never follow redirects or report a rejected CONNECT as ready. */
        session->closed = XQC_TRUE;
        session->send_fin = XQC_TRUE;
        xqc_int_t ret = xqc_wt_session_flush(session);
        xqc_wt_session_notify_closed(session);
        return ret;
    }
    if (!xqc_wt_conn_requirements_met(session->wt_conn)) {
        xqc_wt_request_fail(session, H3_MESSAGE_ERROR);
        return XQC_OK;
    }
    xqc_int_t ret = xqc_wt_notify_ready(session, headers);
    if (ret == XQC_OK && fin) {
        return xqc_wt_session_recv_capsules(session, NULL, 0, XQC_TRUE);
    }
    return ret;
}

xqc_int_t
xqc_wt_request_read(xqc_h3_request_t *request,
    xqc_request_notify_flag_t flags, void *data)
{
    xqc_wt_session_t *session = data;
    if (!session || (!session->open && session->closed)) {
        return XQC_OK;
    }
    if (!session->wt_conn->settings_received) {
        return XQC_OK;
    }
    if (!session->open) {
        xqc_int_t ret = session->client ? xqc_wt_client_response(session)
                                       : xqc_wt_accept_session(session);
        if (ret != XQC_OK || !session->open) {
            return ret;
        }
    }
    if (flags & XQC_REQ_NOTIFY_READ_BODY) {
        unsigned char buffer[4096], fin = 0;
        do {
            ssize_t n = xqc_h3_request_recv_body(request, buffer,
                                                sizeof(buffer), &fin);
            if (n == -XQC_EAGAIN) {
                break;
            }
            if (n < 0) {
                return (xqc_int_t)n;
            }
            xqc_int_t ret = xqc_wt_session_recv_capsules(session, buffer,
                                                        n, fin);
            if (ret != XQC_OK) {
                xqc_wt_request_fail(session, H3_MESSAGE_ERROR);
                return XQC_OK;
            }
            if (n == 0 || fin) {
                break;
            }
        } while (1);
    }
    if (flags & XQC_REQ_NOTIFY_READ_EMPTY_FIN) {
        xqc_int_t ret = xqc_wt_session_recv_capsules(session, NULL, 0,
                                                   XQC_TRUE);
        if (ret != XQC_OK) {
            xqc_wt_request_fail(session, H3_MESSAGE_ERROR);
        }
    }
    return XQC_OK;
}
