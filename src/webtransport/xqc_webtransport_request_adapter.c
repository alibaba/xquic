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
#include "src/common/xqc_str.h"

#define XQC_WT_ALPN_ERROR UINT64_C(0x0817b3dd)
#define XQC_WT_PROTOCOL_MAX 1024
#define XQC_WT_PROTOCOL_LIST_MAX 4096

static xqc_bool_t xqc_wt_header_is(const xqc_http_header_t *header,
    const char *name, const char *value);
static xqc_int_t xqc_wt_response(xqc_h3_request_t *request,
    const char *status);
static xqc_int_t xqc_wt_request_headers(xqc_h3_request_t *request,
    void *data, const xqc_http_headers_t *headers);
static xqc_int_t xqc_wt_accept_session(xqc_wt_session_t *session);
static xqc_int_t xqc_wt_client_response(xqc_wt_session_t *session);
static char *xqc_wt_encode_protocols(const char *const *protocols,
    size_t count, int *err);
static xqc_bool_t xqc_wt_protocols_length(const char *const *protocols,
    size_t count, size_t *length);
static xqc_bool_t xqc_wt_protocol_string(const unsigned char **pos,
    const unsigned char *end, char *output, size_t capacity);
static xqc_bool_t xqc_wt_protocol_parameters(const unsigned char **cursor,
    const unsigned char *end);
static xqc_bool_t xqc_wt_protocol_parameter_value(const unsigned char **pos,
    const unsigned char *end);
static xqc_int_t xqc_wt_negotiate_protocol(xqc_wt_session_t *session,
    const xqc_http_headers_t *headers);
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

static xqc_bool_t
xqc_wt_protocols_length(const char *const *protocols, size_t count,
    size_t *length)
{
    *length = 0;
    if ((!protocols && count) || count > XQC_WT_PROTOCOL_LIST_MAX / 4) {
        return XQC_FALSE;
    }
    for (size_t i = 0; i < count; i++) {
        if (!protocols[i]) {
            return XQC_FALSE;
        }
        size_t n = 0;
        for (; protocols[i][n]; n++) {
            unsigned char c = protocols[i][n];
            if (n == XQC_WT_PROTOCOL_MAX || c < 0x20 || c > 0x7e) {
                return XQC_FALSE;
            }
            *length += c == '"' || c == '\\' ? 2 : 1;
        }
        *length += i ? 4 : 2;
        if (*length > XQC_WT_PROTOCOL_LIST_MAX) {
            return XQC_FALSE;
        }
    }
    return XQC_TRUE;
}

/* draft-ietf-webtrans-http3-16 Section 3.3; RFC 9651 Sections 4.1, 4.2. */
static char *
xqc_wt_encode_protocols(const char *const *protocols, size_t count, int *err)
{
    size_t length;
    if (err) {
        *err = -XQC_EPARAM;
    }
    if (!xqc_wt_protocols_length(protocols, count, &length)) {
        return NULL;
    }
    char *encoded = xqc_malloc(length + 1);
    if (!encoded) {
        if (err) {
            *err = -XQC_EMALLOC;
        }
        return NULL;
    }
    char *p = encoded;
    for (size_t i = 0; i < count; i++) {
        if (i) {
            *p++ = ',';
            *p++ = ' ';
        }
        *p++ = '"';
        for (const char *v = protocols[i]; *v; v++) {
            if (*v == '"' || *v == '\\') {
                *p++ = '\\';
            }
            *p++ = *v;
        }
        *p++ = '"';
    }
    *p = '\0';
    return encoded;
}

static xqc_bool_t
xqc_wt_protocol_string(const unsigned char **pos, const unsigned char *end,
    char *output, size_t capacity)
{
    const unsigned char *p = *pos;
    size_t n = 0;
    if (p == end || *p++ != '"') {
        return XQC_FALSE;
    }
    while (p < end) {
        unsigned char c = *p++;
        if (c == '"') {
            if (output) {
                output[n] = '\0';
            }
            *pos = p;
            return XQC_TRUE;
        }
        if (c == '\\') {
            if (p == end || (*p != '\\' && *p != '"')) {
                return XQC_FALSE;
            }
            c = *p++;
        }
        if (c < 0x20 || c > 0x7e || (output && n + 1 >= capacity)) {
            return XQC_FALSE;
        }
        if (output) {
            output[n++] = c;
        }
    }
    return XQC_FALSE;
}

static xqc_bool_t
xqc_wt_protocol_parameter_value(const unsigned char **pos,
    const unsigned char *end)
{
    const unsigned char *p = *pos;
    if (p == end) {
        return XQC_FALSE;
    }
    if (*p == '"') {
        return xqc_wt_protocol_string(pos, end, NULL, 0);
    }
    if (*p == '%') {
        unsigned char decoded[XQC_WT_PROTOCOL_LIST_MAX];
        size_t n = 0;
        if (++p == end || *p++ != '"') {
            return XQC_FALSE;
        }
        while (p < end && *p != '"') {
            unsigned char c = *p++;
            if (c < 0x20 || c > 0x7e) {
                return XQC_FALSE;
            }
            if (c == '%') {
                unsigned value = 0;
                for (unsigned i = 0; i < 2; i++) {
                    if (p == end || !((*p >= '0' && *p <= '9')
                        || (*p >= 'a' && *p <= 'f')))
                    {
                        return XQC_FALSE;
                    }
                    value = value * 16 + (*p <= '9'
                        ? *p - '0' : *p - 'a' + 10);
                    p++;
                }
                c = value;
            }
            if (n == sizeof(decoded)) {
                return XQC_FALSE;
            }
            decoded[n++] = c;
        }
        if (p == end || !xqc_wt_valid_utf8(decoded, n)) {
            return XQC_FALSE;
        }
        *pos = p + 1;
        return XQC_TRUE;
    }
    if (*p == '?') {
        if (++p == end || (*p != '0' && *p != '1')) {
            return XQC_FALSE;
        }
        *pos = p + 1;
        return XQC_TRUE;
    }
    if (*p == ':') {
        size_t digits = 0, padding = 0;
        for (p++; p < end && *p != ':'; p++) {
            if (*p == '=') {
                padding++;
            } else if (!padding && ((*p >= 'a' && *p <= 'z')
                || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9')
                || *p == '+' || *p == '/'))
            {
                digits++;
            } else {
                return XQC_FALSE;
            }
        }
        if (p == end || digits % 4 == 1 || padding > 2
            || (padding && (digits + padding) % 4 != 0))
        {
            return XQC_FALSE;
        }
        *pos = p + 1;
        return XQC_TRUE;
    }
    if ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z')
        || *p == '*')
    {
        do {
            p++;
        } while (p < end && ((*p >= 'A' && *p <= 'Z')
            || (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9')
            || (*p && strchr("!#$%&'*+-.^_`|~:/", *p))));
        *pos = p;
        return XQC_TRUE;
    }
    xqc_bool_t date = *p == '@';
    if (date && ++p == end) {
        return XQC_FALSE;
    }
    if (*p == '-') {
        p++;
    }
    size_t digits = 0;
    while (p < end && *p >= '0' && *p <= '9') {
        p++;
        digits++;
    }
    if (!digits || digits > 15) {
        return XQC_FALSE;
    }
    if (p < end && *p == '.') {
        if (date || digits > 12) {
            return XQC_FALSE;
        }
        digits = 0;
        for (p++; p < end && *p >= '0' && *p <= '9'; p++) {
            digits++;
        }
        if (!digits || digits > 3) {
            return XQC_FALSE;
        }
    }
    *pos = p;
    return XQC_TRUE;
}

static xqc_bool_t
xqc_wt_protocol_parameters(const unsigned char **cursor,
    const unsigned char *end)
{
    const unsigned char *pos = *cursor;
    while (pos < end && *pos == ';') {
        pos++;
        while (pos < end && *pos == ' ') {
            pos++;
        }
        if (pos == end || !((*pos >= 'a' && *pos <= 'z') || *pos == '*')) {
            return XQC_FALSE;
        }
        do {
            pos++;
        } while (pos < end && ((*pos >= 'a' && *pos <= 'z')
            || (*pos >= '0' && *pos <= '9') || *pos == '_'
            || *pos == '-' || *pos == '.' || *pos == '*'));
        if (pos < end && *pos == '=') {
            pos++;
            if (!xqc_wt_protocol_parameter_value(&pos, end)) {
                return XQC_FALSE;
            }
        }
    }
    *cursor = pos;
    return XQC_TRUE;
}

xqc_int_t
xqc_wt_select_application_protocol(const xqc_http_headers_t *headers,
    const char *const *protocols, size_t protocol_count,
    const char **selected)
{
    static const char name[] = "wt-available-protocols";
    unsigned char list[XQC_WT_PROTOCOL_LIST_MAX];
    size_t length, fields = 0;
    const char *match = NULL;

    if (!selected) {
        return -XQC_EPARAM;
    }
    *selected = NULL;
    if (!headers || (headers->count && !headers->headers)
        || !xqc_wt_protocols_length(protocols, protocol_count, &length))
    {
        return -XQC_EPARAM;
    }
    length = 0;
    /* RFC 9651 Section 4.2 combines all field lines before parsing. */
    for (size_t i = 0; i < headers->count; i++) {
        const xqc_http_header_t *header = &headers->headers[i];
        if (header->name.iov_len && !header->name.iov_base) {
            return -XQC_EPARAM;
        }
        if (header->name.iov_len != sizeof(name) - 1) {
            continue;
        }
        const unsigned char *key = header->name.iov_base;
        size_t n = 0;
        while (n < sizeof(name) - 1 && xqc_tolower(key[n]) == name[n]) {
            n++;
        }
        if (n != sizeof(name) - 1) {
            continue;
        }
        if (fields++) {
            if (sizeof(list) - length < 2) {
                return -XQC_EPARAM;
            }
            list[length++] = ',';
            list[length++] = ' ';
        }
        n = header->value.iov_len;
        if (n > sizeof(list) - length || (n && !header->value.iov_base)) {
            return -XQC_EPARAM;
        }
        if (n) {
            memcpy(list + length, header->value.iov_base, n);
            length += n;
        }
    }
    const unsigned char *pos = list, *end = list + length;
    while (pos < end && *pos == ' ') {
        pos++;
    }
    while (pos < end) {
        char offered[XQC_WT_PROTOCOL_MAX + 1];
        if (!xqc_wt_protocol_string(&pos, end, offered, sizeof(offered))
            || !xqc_wt_protocol_parameters(&pos, end))
        {
            return -XQC_EPARAM;
        }
        for (size_t i = 0; !match && i < protocol_count; i++) {
            if (!strcmp(offered, protocols[i])) {
                match = protocols[i];
            }
        }
        while (pos < end && (*pos == ' ' || *pos == '\t')) {
            pos++;
        }
        if (pos == end) {
            break;
        }
        if (*pos++ != ',') {
            return -XQC_EPARAM;
        }
        while (pos < end && (*pos == ' ' || *pos == '\t')) {
            pos++;
        }
        if (pos == end) {
            return -XQC_EPARAM;
        }
    }
    /* draft-16 Section 3.3: a malformed suffix invalidates the whole field. */
    *selected = match;
    return match ? 1 : 0;
}

static xqc_int_t
xqc_wt_negotiate_protocol(xqc_wt_session_t *session,
    const xqc_http_headers_t *headers)
{
    if (!session->client_protocols) {
        return XQC_OK;
    }
    const xqc_http_header_t *protocol = NULL;
    for (size_t i = 0; i < headers->count; i++) {
        if (xqc_wt_header_is(&headers->headers[i], "wt-protocol", NULL)) {
            if (protocol) {
                return -XQC_EPARAM;
            }
            protocol = &headers->headers[i];
        }
    }
    if (!protocol || !protocol->value.iov_base
        || protocol->value.iov_len > XQC_WT_PROTOCOL_LIST_MAX)
    {
        return -XQC_EPARAM;
    }
    const unsigned char *p = protocol->value.iov_base;
    const unsigned char *end = p + protocol->value.iov_len;
    while (p < end && *p == ' ') {
        p++;
    }
    char selected[XQC_WT_PROTOCOL_MAX + 1];
    if (!xqc_wt_protocol_string(&p, end, selected, sizeof(selected))
        || !xqc_wt_protocol_parameters(&p, end))
    {
        return -XQC_EPARAM;
    }
    while (p < end && *p == ' ') {
        p++;
    }
    if (p != end) {
        return -XQC_EPARAM;
    }
    p = (const unsigned char *)session->client_protocols;
    end = p + strlen(session->client_protocols);
    while (p < end) {
        char offered[XQC_WT_PROTOCOL_MAX + 1];
        if (!xqc_wt_protocol_string(&p, end, offered, sizeof(offered))) {
            return -XQC_EPARAM;
        }
        if (strcmp(offered, selected) == 0) {
            size_t n = strlen(selected) + 1;
            session->application_protocol = xqc_malloc(n);
            if (!session->application_protocol) {
                return -XQC_EMALLOC;
            }
            memcpy(session->application_protocol, selected, n);
            return XQC_OK;
        }
        if (p < end) {
            p += 2;
        }
    }
    return -XQC_EPARAM;
}

xqc_wt_session_t *
xqc_wt_client_open_session(xqc_h3_conn_t *h3c, const char *authority,
    const char *path, const char *origin, int *err)
{
    return xqc_wt_client_open_session_with_protocols(h3c, authority, path,
        origin, NULL, 0, err);
}

xqc_wt_session_t *
xqc_wt_client_open_session_with_protocols(xqc_h3_conn_t *h3c,
    const char *authority, const char *path, const char *origin,
    const char *const *protocols, size_t protocol_count, int *err)
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
    } else if (!conn->settings_received || !conn->flow_control_enabled) {
        limit = 1;
    }
    if (xqc_wt_conn_active_session_count(conn) >= limit) {
        return NULL;
    }
    char *encoded_protocols = NULL;
    if (protocol_count) {
        encoded_protocols = xqc_wt_encode_protocols(protocols,
            protocol_count, err);
        if (!encoded_protocols) {
            return NULL;
        }
    }
    char *strings = xqc_malloc(alen + plen + olen);
    if (!strings) {
        xqc_free(encoded_protocols);
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
        xqc_free(encoded_protocols);
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
        xqc_free(encoded_protocols);
        if (err) {
            *err = -XQC_EMALLOC;
        }
        return NULL;
    }
    session->client = XQC_TRUE;
    session->client_authority = strings;
    session->client_path = strings + alen;
    session->client_origin = olen ? strings + alen + plen : NULL;
    session->client_protocols = encoded_protocols;
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
                           ":protocol", "origin", "wt-available-protocols"};
    const char *values[] = {"CONNECT", "https", session->client_authority,
        session->client_path, conn->negotiated_version
            == XQC_WEBTRANSPORT_DRAFT_VERSION_16
            ? "webtransport-h3" : "webtransport", session->client_origin,
        session->client_protocols};
    xqc_http_header_t fields[7] = {0};
    xqc_http_headers_t headers = {
        .headers = fields,
    };
    for (size_t i = 0; i < 7; i++) {
        if (!values[i]) {
            continue;
        }
        xqc_http_header_t *field = &fields[headers.count++];
        field->name.iov_base = (void *)names[i];
        field->name.iov_len = strlen(names[i]);
        field->value.iov_base = (void *)values[i];
        field->value.iov_len = strlen(values[i]);
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
    if (xqc_wt_conn_active_session_count(conn)
            >= conn->ctx->settings.max_sessions_count
        && conn->ctx->settings.draft_version
            == XQC_WEBTRANSPORT_DRAFT_VERSION_7)
    {
        xqc_int_t ret = xqc_wt_response(request, "429");
        return ret < 0 ? ret : 1;
    }
    if ((conn->ctx->settings.max_sessions_count > 1
         && xqc_wt_conn_active_session_count(conn)
            >= conn->ctx->settings.max_sessions_count)
        || conn->session_count >= 64)
    {
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
            if (other != session && other->open && !other->closed
                && !conn->flow_control_enabled)
            {
                /* draft-ietf-webtrans-http3-16 §5.1. */
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
    xqc_int_t protocol_ret = xqc_wt_negotiate_protocol(session, headers);
    if (protocol_ret != XQC_OK) {
        xqc_wt_request_fail(session, protocol_ret == -XQC_EMALLOC
            ? H3_INTERNAL_ERROR : XQC_WT_ALPN_ERROR);
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
                xqc_wt_request_fail(session,
                    ret == -XQC_WT_FLOW_CONTROL_ERROR
                        ? XQC_WT_FLOW_CONTROL_ERROR : H3_MESSAGE_ERROR);
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
            xqc_wt_request_fail(session,
                ret == -XQC_WT_FLOW_CONTROL_ERROR
                    ? XQC_WT_FLOW_CONTROL_ERROR : H3_MESSAGE_ERROR);
        }
    }
    return XQC_OK;
}
