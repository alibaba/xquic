/* Copyright (c) 2026, Alibaba Group Holding Limited. */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "xqc_wt_echo_client.h"
#include "xqc_wt_echo_server.h"

#define XQC_WT_INTEROP_PATH_MAX 1024
#define XQC_WT_INTEROP_PROTOCOL_MAX 1024

typedef struct {
    char    line[XQC_WT_INTEROP_PATH_MAX + 6];
    size_t  length;
    int     complete;
} xqc_wt_interop_header_t;

static int xqc_wt_interop_valid_path(const char *path);
static int xqc_wt_interop_header_feed(xqc_wt_interop_header_t *header,
    const void *data, size_t length, int fin, int push, size_t *consumed);

static int
xqc_wt_interop_valid_path(const char *path)
{
    const char *start = path;
    size_t length = strlen(path);

    if (!length || length > XQC_WT_INTEROP_PATH_MAX) {
        return 0;
    }
    for (const char *p = path; ; p++) {
        unsigned char ch = *p;
        if (ch == '/' || ch == '\0') {
            size_t part = p - start;
            if (!part || part > 255 || (part == 1 && start[0] == '.')
                || (part == 2 && start[0] == '.' && start[1] == '.'))
            {
                return 0;
            }
            if (!ch) {
                return 1;
            }
            start = p + 1;

        } else if (!((ch >= 'a' && ch <= 'z')
                     || (ch >= 'A' && ch <= 'Z')
                     || (ch >= '0' && ch <= '9')
                     || ch == '.' || ch == '_' || ch == '-'))
        {
            return 0;
        }
    }
}

static int
xqc_wt_interop_header_feed(xqc_wt_interop_header_t *header,
    const void *data, size_t length, int fin, int push, size_t *consumed)
{
    const unsigned char *bytes = data;
    const char *prefix = push ? "PUSH " : "GET ";
    size_t prefix_length = strlen(prefix);

    *consumed = 0;
    if (header->complete) {
        return 1;
    }
    while (*consumed < length) {
        unsigned char ch = bytes[(*consumed)++];
        if (push && ch == '\n') {
            header->complete = 1;
            break;
        }
        if (ch < 0x20 || ch > 0x7e
            || header->length == sizeof(header->line) - 1)
        {
            return -1;
        }
        header->line[header->length++] = ch;
    }
    header->line[header->length] = '\0';
    if (!push && fin) {
        header->complete = 1;
    }
    if (!header->complete) {
        return fin ? -1 : 0;
    }
    if (header->length <= prefix_length
        || memcmp(header->line, prefix, prefix_length)
        || !xqc_wt_interop_valid_path(header->line + prefix_length))
    {
        return -1;
    }
    return 1;
}

#define XQC_WT_INTEROP_FILES_MAX 256
#define XQC_WT_INTEROP_STREAMS_MAX 64
#define XQC_WT_INTEROP_DATAGRAM_MAX 1200
#define XQC_WT_INTEROP_BUFFER_SIZE (64 * 1024)

typedef struct xqc_wt_interop_stream_s xqc_wt_interop_stream_t;

struct xqc_wt_interop_stream_s {
    xqc_wt_interop_stream_t *next;
    void                   *stream;
    xqc_wt_session_t        *session;
    xqc_wt_interop_header_t  header;
    size_t                  length;
    size_t                  offset;
    uint64_t                transferred;
    int                     file;
    int                     request_index;
    int                     sending;
    int                     sent;
    int                     bidirectional;
    int                     complete;
    unsigned char           pending[];
};

typedef struct {
    size_t         length;
    unsigned char  data[XQC_WT_INTEROP_DATAGRAM_MAX];
} xqc_wt_interop_datagram_t;

typedef struct {
    xqc_wt_session_t       *session;
    xqc_wt_interop_stream_t *streams;
    char                   *protocol_storage;
    char                   *requests_storage;
    const char             *protocols[32];
    size_t                  protocol_count;
    const char             *selected;
    char                    encoded[2 * XQC_WT_INTEROP_PROTOCOL_MAX + 3];
    xqc_http_header_t       response[2];
    char                   endpoint[256];
    const char             *files[XQC_WT_INTEROP_FILES_MAX];
    int                     received[XQC_WT_INTEROP_FILES_MAX];
    size_t                  file_count;
    size_t                  completed;
    size_t                  stream_count;
    int                     root;
    int                     directory;
    int                     server;
    int                     handshake;
    int                     mode;
    const char             *case_name;
    xqc_wt_interop_datagram_t datagrams[XQC_WT_INTEROP_FILES_MAX];
    size_t                  datagram_head;
    size_t                  datagram_count;
    int                     failed;
    int                     success;
    int                     stopped;
    void                  (*schedule_send)(void *user_data);
    void                  (*finished)(void *user_data);
    void                   *user_data;
} xqc_wt_interop_t;

/* The interop cases use one session in one connection. */
static xqc_wt_interop_t xqc_wt_interop;

static void xqc_wt_interop_fail(const char *operation, int error);
static int xqc_wt_interop_blocked(int error);
static int xqc_wt_interop_open_file(int directory, const char *path,
    int output);
static int xqc_wt_interop_write_protocol(const char *protocol);
static int xqc_wt_interop_header_name(const xqc_http_header_t *header,
    const char *name);
static int xqc_wt_interop_accept(xqc_http_headers_t *headers,
    xqc_http_headers_t *response);
static int xqc_wt_interop_ready(xqc_wt_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *user_data);
static int xqc_wt_interop_closed(xqc_wt_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *user_data);
static void xqc_wt_interop_complete(void);
static void xqc_wt_interop_handshake(xqc_h3_conn_t *connection,
    void *user_data);
static xqc_wt_interop_stream_t *xqc_wt_interop_find(void *stream);
static xqc_wt_interop_stream_t *xqc_wt_interop_allocate(
    xqc_wt_session_t *session);
static void xqc_wt_interop_free_stream(xqc_wt_interop_stream_t *state);
static xqc_int_t xqc_wt_interop_flush(xqc_wt_interop_stream_t *state);
static xqc_int_t xqc_wt_interop_send(xqc_wt_session_t *session,
    const char *filename, int push, int request_index);
static xqc_int_t xqc_wt_interop_stream_create(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *user_data);
static xqc_int_t xqc_wt_interop_stream_write(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *user_data);
static xqc_int_t xqc_wt_interop_stream_read(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *data, size_t length, void *user_data);
static xqc_int_t xqc_wt_interop_stream_close(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *user_data);
static xqc_int_t xqc_wt_interop_stream_closing(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *user_data);
static int xqc_wt_interop_configure(int server);
static void xqc_wt_interop_pass(void);
static int xqc_wt_interop_directory(void);
static int xqc_wt_interop_receive_file(xqc_wt_interop_stream_t *state,
    const char *filename, const void *data, size_t length, int fin,
    int datagram);
static xqc_int_t xqc_wt_interop_receive(void *stream, const void *data,
    size_t length, int fin);
static xqc_int_t xqc_wt_interop_bidi_create(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *user_data);
static xqc_int_t xqc_wt_interop_bidi_write(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *user_data);
static xqc_int_t xqc_wt_interop_bidi_read(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *data, size_t length, void *user_data);
static xqc_int_t xqc_wt_interop_bidi_close(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *user_data);
static xqc_int_t xqc_wt_interop_bidi_closing(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *user_data);
static int xqc_wt_interop_datagram_queue(const void *data, size_t length);
static int xqc_wt_interop_datagram_request(xqc_wt_session_t *session);
static void xqc_wt_interop_datagram_write(xqc_wt_session_t *session,
    void *user_data);
static void xqc_wt_interop_datagram_read(xqc_wt_session_t *session,
    const void *data, size_t length, void *user_data, uint64_t recv_time);
static int xqc_wt_interop_requests(const char *authority, const char *path);
static xqc_int_t xqc_wt_interop_init(xqc_engine_t *engine,
    int draft_version, int server, void (*schedule_send)(void *user_data),
    void (*finished)(void *user_data), void *user_data);

static void
xqc_wt_interop_fail(const char *operation, int error)
{
    xqc_wt_interop_t *ctx = &xqc_wt_interop;

    if (ctx->failed || ctx->stopped) {
        return;
    }
    fprintf(stderr, "WT INTEROP FAIL: %s error=%d\n", operation, error);
    ctx->failed = 1;
    if (ctx->session) {
        xqc_wt_session_close_with_error(ctx->session, 1, "interop error", 13);
        ctx->schedule_send(ctx->user_data);
    }
    if (ctx->finished) {
        ctx->finished(ctx->user_data);
    }
}

static int
xqc_wt_interop_blocked(int error)
{
    return error == -XQC_EAGAIN || error == -XQC_ECONN_BLOCKED
        || error == -XQC_ESTREAM_BLOCKED;
}

static int
xqc_wt_interop_open_file(int directory, const char *path, int output)
{
    char copy[XQC_WT_INTEROP_PATH_MAX + 1];
    char *component, *next;
    int current, child;

    if (!xqc_wt_interop_valid_path(path)) {
        return -1;
    }
    strcpy(copy, path);
    current = dup(directory);
    if (current < 0) {
        return -1;
    }
    component = copy;
    while ((next = strchr(component, '/')) != NULL) {
        *next++ = '\0';
        if (output && mkdirat(current, component, 0755) < 0
            && errno != EEXIST)
        {
            close(current);
            return -1;
        }
        child = openat(current, component,
                       O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        close(current);
        if (child < 0) {
            return -1;
        }
        current = child;
        component = next;
    }
    child = openat(current, component, O_NOFOLLOW
                   | (output ? O_WRONLY | O_CREAT | O_EXCL : O_RDONLY), 0644);
    close(current);
    if (child >= 0) {
        struct stat status;
        if (fstat(child, &status) < 0 || !S_ISREG(status.st_mode)) {
            close(child);
            return -1;
        }
    }
    return child;
}

static int
xqc_wt_interop_write_protocol(const char *protocol)
{
    xqc_wt_interop_t *ctx = &xqc_wt_interop;
    const char *root = getenv("XQC_WT_DOWNLOADS");
    int directory, file, result;
    size_t length = strlen(protocol);

    directory = open(root ? root : "/downloads",
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (directory < 0) {
        return -1;
    }
    file = xqc_wt_interop_open_file(directory, "negotiated_protocol.txt", 1);
    close(directory);
    if (file < 0) {
        return -1;
    }
    result = write(file, protocol, length) == (ssize_t) length ? 0 : -1;
    if (close(file) < 0) {
        result = -1;
    }
    if (!result) {
        printf("WT negotiated protocol: %s role=%s\n", protocol,
               ctx->server ? "server" : "client");
    }
    return result;
}

static int
xqc_wt_interop_header_name(const xqc_http_header_t *header,
    const char *name)
{
    return header->name.iov_len == strlen(name)
        && !memcmp(header->name.iov_base, name, strlen(name));
}

static int
xqc_wt_interop_accept(xqc_http_headers_t *headers,
    xqc_http_headers_t *response)
{
    xqc_wt_interop_t *ctx = &xqc_wt_interop;
    const xqc_http_header_t *path = NULL;
    size_t written = 0;

    for (size_t i = 0; i < headers->count; i++) {
        const xqc_http_header_t *header = &headers->headers[i];
        if (xqc_wt_interop_header_name(header, ":path")) {
            if (path) {
                return 0;
            }
            path = header;
        }
    }
    if (ctx->session || !path || path->value.iov_len < 2
        || path->value.iov_len > sizeof(ctx->endpoint)
        || ((const char *) path->value.iov_base)[0] != '/')
    {
        fprintf(stderr, "WT INTEROP reject: invalid endpoint\n");
        return 0;
    }
    memcpy(ctx->endpoint, (const char *) path->value.iov_base + 1,
           path->value.iov_len - 1);
    ctx->endpoint[path->value.iov_len - 1] = '\0';
    if (!xqc_wt_interop_valid_path(ctx->endpoint)
        || strchr(ctx->endpoint, '/'))
    {
        fprintf(stderr, "WT INTEROP reject: unsafe endpoint\n");
        return 0;
    }
    if (xqc_wt_select_application_protocol(headers, ctx->protocols,
            ctx->protocol_count, &ctx->selected) != 1)
    {
        fprintf(stderr, "WT INTEROP reject: no application protocol\n");
        return 0;
    }
    if (xqc_wt_interop_directory()) {
        fprintf(stderr, "WT INTEROP reject: endpoint directory missing\n");
        return 0;
    }
    ctx->encoded[written++] = '"';
    for (const char *p = ctx->selected; *p; p++) {
        if (*p == '"' || *p == '\\') {
            ctx->encoded[written++] = '\\';
        }
        ctx->encoded[written++] = *p;
    }
    ctx->encoded[written++] = '"';
    ctx->response[0] = (xqc_http_header_t) {
        .name = {(void *) ":status", 7},
        .value = {(void *) "200", 3},
    };
    ctx->response[1] = (xqc_http_header_t) {
        .name = {(void *) "wt-protocol", 11},
        .value = {ctx->encoded, written},
    };
    response->headers = ctx->response;
    response->count = 2;
    return 1;
}

static void
xqc_wt_interop_pass(void)
{
    xqc_wt_interop_t *ctx = &xqc_wt_interop;

    ctx->success = 1;
    if (!ctx->handshake && !ctx->mode) {
        printf("WT INTEROP PASS: case=transfer files=%zu peer_close=1\n",
               ctx->completed);
    } else {
        printf("WT INTEROP PASS: case=%s files=%zu all_fin=%d\n",
               ctx->case_name, ctx->completed, ctx->mode != 3);
    }
    if (ctx->finished) {
        ctx->finished(ctx->user_data);
    }
}

static void
xqc_wt_interop_complete(void)
{
    xqc_wt_interop_t *ctx = &xqc_wt_interop;
    int result;

    if ((ctx->handshake && ctx->server) || ctx->success || ctx->failed) {
        return;
    }
    result = xqc_wt_session_close_with_error(ctx->session, 0,
                                            "interop complete", 16);
    if (result != XQC_OK) {
        xqc_wt_interop_fail("session close", result);
        return;
    }
    ctx->schedule_send(ctx->user_data);
    xqc_wt_interop_pass();
}

static void
xqc_wt_interop_handshake(xqc_h3_conn_t *connection, void *user_data)
{
    printf("WT handshake complete\n");
}

static int
xqc_wt_interop_ready(xqc_wt_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *user_data)
{
    xqc_wt_interop_t *ctx = &xqc_wt_interop;
    const char *protocol;

    ctx->session = session;
    protocol = ctx->server ? ctx->selected
        : xqc_wt_session_get_application_protocol(session);
    if (!protocol || !*protocol) {
        xqc_wt_interop_fail("missing negotiated protocol", XQC_ERROR);
        return XQC_ERROR;
    }
    printf("WT ready: draft=%d status=%u endpoint=/%s\n",
           xqc_wt_session_get_draft_version(session)
               == XQC_WEBTRANSPORT_DRAFT_VERSION_16 ? 16 : 7,
           xqc_wt_session_get_response_status(session), ctx->endpoint);
    if (ctx->handshake) {
        if (xqc_wt_interop_write_protocol(protocol)) {
            xqc_wt_interop_fail("save negotiated protocol", errno);
            return XQC_ERROR;
        }
        xqc_wt_interop_complete();

    } else if (ctx->mode) {
        if (ctx->server && xqc_wt_interop_requests(NULL, NULL)) {
            xqc_wt_interop_fail("invalid REQUESTS", XQC_ERROR);
            return XQC_ERROR;
        }
        if (ctx->mode == 3) {
            return xqc_wt_interop_datagram_request(session);
        }
        for (size_t i = 0; i < ctx->file_count; i++) {
            if (xqc_wt_interop_send(session, ctx->files[i], 0, i)) {
                return XQC_ERROR;
            }
        }
    }
    return XQC_OK;
}

static int
xqc_wt_interop_closed(xqc_wt_session_t *session,
    xqc_http_headers_t *headers, const xqc_cid_t *cid, void *user_data)
{
    xqc_wt_interop_t *ctx = &xqc_wt_interop;
    uint32_t code = xqc_wt_session_get_close_error_code(session);
    int pending = ctx->datagram_count != 0;

    printf("WT closed: status=%u code=%" PRIu32 "\n",
           xqc_wt_session_get_response_status(session), code);
    ctx->session = NULL;
    for (xqc_wt_interop_stream_t *s = ctx->streams; s; s = s->next) {
        pending |= !s->complete;
    }
    if ((!ctx->server || ctx->mode) && !ctx->success && !ctx->stopped) {
        if (!ctx->handshake && !ctx->mode && !ctx->failed && !code
            && ctx->completed && !pending)
        {
            xqc_wt_interop_pass();
        } else {
            xqc_wt_interop_fail("session closed before completion", XQC_ERROR);
        }
    }
    while (ctx->streams) {
        xqc_wt_interop_free_stream(ctx->streams);
    }
    ctx->datagram_count = 0;
    ctx->datagram_head = 0;
    if (ctx->directory >= 0) {
        close(ctx->directory);
        ctx->directory = -1;
    }
    return XQC_OK;
}

static xqc_wt_interop_stream_t *
xqc_wt_interop_find(void *stream)
{
    xqc_wt_interop_stream_t *state = xqc_wt_interop.streams;

    while (state && state->stream != stream) {
        state = state->next;
    }
    return state;
}

static xqc_wt_interop_stream_t *
xqc_wt_interop_allocate(xqc_wt_session_t *session)
{
    if (xqc_wt_interop.stream_count == XQC_WT_INTEROP_STREAMS_MAX) {
        return NULL;
    }
    xqc_wt_interop_stream_t *state = calloc(1,
        sizeof(*state) + XQC_WT_INTEROP_BUFFER_SIZE);

    if (state) {
        state->session = session;
        state->file = -1;
        state->request_index = -1;
        state->next = xqc_wt_interop.streams;
        xqc_wt_interop.streams = state;
        xqc_wt_interop.stream_count++;
    }
    return state;
}

static void
xqc_wt_interop_free_stream(xqc_wt_interop_stream_t *state)
{
    xqc_wt_interop_stream_t **link = &xqc_wt_interop.streams;

    while (*link && *link != state) {
        link = &(*link)->next;
    }
    if (*link) {
        *link = state->next;
        xqc_wt_interop.stream_count--;
    }
    if (state->file >= 0) {
        close(state->file);
    }
    free(state);
}

static xqc_int_t
xqc_wt_interop_flush(xqc_wt_interop_stream_t *state)
{
    xqc_wt_interop_t *ctx = &xqc_wt_interop;

    while (state->sending && !state->sent && !ctx->failed) {
        if (state->offset == state->length && state->file >= 0) {
            ssize_t bytes = read(state->file, state->pending,
                                 XQC_WT_INTEROP_BUFFER_SIZE);
            if (bytes < 0) {
                if (errno == EINTR) {
                    continue;
                }
                xqc_wt_interop_fail("read source file", errno);
                return XQC_ERROR;
            }
            state->length = bytes;
            state->offset = 0;
            if (!bytes) {
                close(state->file);
                state->file = -1;
            }
        }
        size_t remaining = state->length - state->offset;
        int fin = remaining == 0 && state->file < 0;
        int result = state->bidirectional
            ? xqc_wt_bidistream_send(state->stream,
                state->pending + state->offset, remaining, fin)
            : xqc_wt_unistream_send(state->stream,
                state->pending + state->offset, remaining, fin);
        if (result < 0) {
            if (xqc_wt_interop_blocked(result)) {
                ctx->schedule_send(ctx->user_data);
                return XQC_OK;
            }
            xqc_wt_interop_fail("stream send", result);
            return result;
        }
        if ((size_t) result > remaining) {
            xqc_wt_interop_fail("invalid short write", result);
            return XQC_ERROR;
        }
        state->offset += result;
        state->transferred += result;
        if (fin) {
            state->sent = 1;
            state->complete = !state->bidirectional || !ctx->mode;
            printf("WT %s sent: id=%" PRIu64 " bytes=%" PRIu64 " fin=1\n",
                   state->bidirectional ? "bidi" : "uni",
                   (uint64_t) (state->bidirectional
                       ? xqc_wt_bidistream_id(state->stream)
                       : xqc_wt_unistream_id(state->stream)),
                   state->transferred);
            if (!ctx->mode) {
                ctx->completed++;
            }
            state->transferred = 0;

        } else if (!result) {
            break;
        }
    }
    ctx->schedule_send(ctx->user_data);
    return XQC_OK;
}

static xqc_int_t
xqc_wt_interop_send(xqc_wt_session_t *session, const char *filename,
    int push, int request_index)
{
    xqc_wt_interop_stream_t *state = xqc_wt_interop_allocate(session);
    int error;
    void *stream;

    if (!state) {
        xqc_wt_interop_fail("allocate send state", -XQC_EMALLOC);
        return -XQC_EMALLOC;
    }
    state->sending = 1;
    state->bidirectional = xqc_wt_interop.mode == 2;
    state->request_index = request_index;
    state->length = snprintf((char *) state->pending, XQC_WT_INTEROP_BUFFER_SIZE,
                              push ? "PUSH %s\n" : "GET %s", filename);
    if (push) {
        state->file = xqc_wt_interop_open_file(xqc_wt_interop.directory,
                                               filename, 0);
        if (state->file < 0) {
            xqc_wt_interop_free_stream(state);
            xqc_wt_interop_fail("open requested file", errno);
            return XQC_ERROR;
        }
    }
    stream = state->bidirectional
        ? (void *) xqc_wt_session_create_bidi_stream(session, state, &error)
        : (void *) xqc_wt_session_create_uni_stream(session, state, &error);
    if (!stream) {
        /* A failed creation may already have delivered the close callback. */
        xqc_wt_interop_stream_t *current = xqc_wt_interop.streams;
        while (current && current != state) {
            current = current->next;
        }
        if (current) {
            xqc_wt_interop_free_stream(current);
        }
        xqc_wt_interop_fail("create stream", error);
        return error;
    }
    return xqc_wt_interop_flush(state);
}

static xqc_int_t
xqc_wt_interop_stream_create(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    xqc_wt_interop_stream_t *state = xqc_wt_interop.streams;

    /* Incoming streams inherit connection data, not application stream data. */
    while (state && state != user_data) {
        state = state->next;
    }

    if (!state) {
        state = xqc_wt_interop_allocate(session);
    }
    if (!state) {
        return -XQC_EMALLOC;
    }
    state->stream = stream;
    return XQC_OK;
}

static xqc_int_t
xqc_wt_interop_stream_write(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    xqc_wt_interop_stream_t *state = xqc_wt_interop_find(stream);

    return state ? xqc_wt_interop_flush(state) : XQC_OK;
}

static int
xqc_wt_interop_receive_file(xqc_wt_interop_stream_t *state,
    const char *filename, const void *data, size_t length, int fin,
    int datagram)
{
    xqc_wt_interop_t *ctx = &xqc_wt_interop;

    if (state->file < 0) {
        for (size_t i = 0; filename && i < ctx->file_count; i++) {
            if (!strcmp(filename, ctx->files[i])) {
                if (datagram && ctx->received[i] == 2) {
                    return XQC_OK;
                }
                state->request_index = i;
                break;
            }
        }
        int index = state->request_index;
        if (index < 0 || (size_t) index >= ctx->file_count
            || ctx->received[index]
            || (datagram && (size_t) index != ctx->completed))
        {
            xqc_wt_interop_fail("unsolicited or duplicate PUSH", XQC_ERROR);
            return XQC_ERROR;
        }
        ctx->received[index] = 1;
        state->file = xqc_wt_interop_open_file(ctx->directory,
                                               ctx->files[index], 1);
        if (state->file < 0) {
            xqc_wt_interop_fail("open download file", errno);
            return XQC_ERROR;
        }
    }
    for (size_t consumed = 0; consumed < length;) {
        ssize_t bytes = write(state->file,
            (const unsigned char *) data + consumed, length - consumed);
        if (bytes < 0 && errno == EINTR) {
            continue;
        }
        if (bytes <= 0) {
            xqc_wt_interop_fail("write download file", errno);
            return XQC_ERROR;
        }
        consumed += bytes;
        state->transferred += bytes;
    }
    if (fin) {
        int result = close(state->file);
        state->file = -1;
        if (result < 0) {
            xqc_wt_interop_fail("close download file", errno);
            return XQC_ERROR;
        }
        state->complete = 1;
        ctx->received[state->request_index] = 2;
        ctx->completed++;
        printf("WT file received: %s bytes=%" PRIu64 " %s=1\n",
               ctx->files[state->request_index], state->transferred,
               datagram ? "datagram" : "fin");
        if (ctx->completed == ctx->file_count) {
            xqc_wt_interop_complete();

        } else if (datagram) {
            return xqc_wt_interop_datagram_request(ctx->session);
        }
    }
    return XQC_OK;
}

static xqc_int_t
xqc_wt_interop_receive(void *stream, const void *data, size_t length, int fin)
{
    xqc_wt_interop_t *ctx = &xqc_wt_interop;
    xqc_wt_interop_stream_t *state = xqc_wt_interop_find(stream);
    size_t consumed = 0;

    if (!state || state->complete || ctx->failed || ctx->handshake
        || (state->sending && (!state->bidirectional || !ctx->mode))
        || (ctx->mode && ctx->mode != (state->bidirectional ? 2 : 1)))
    {
        xqc_wt_interop_fail("unexpected stream data", XQC_ERROR);
        return XQC_ERROR;
    }
    if (ctx->mode && state->bidirectional) {
        return xqc_wt_interop_receive_file(state, NULL, data, length, fin, 0);
    }
    if (!state->header.complete) {
        int result = xqc_wt_interop_header_feed(&state->header,
            data, length, fin, ctx->mode != 0, &consumed);
        if (result < 0) {
            xqc_wt_interop_fail("invalid GET or PUSH header", XQC_ERROR);
            return XQC_ERROR;
        }
        if (!result) {
            return XQC_OK;
        }
        if (!ctx->mode) {
            const char *filename = state->header.line + 4;
            if (!state->bidirectional) {
                state->complete = 1;
                return xqc_wt_interop_send(state->session, filename, 1, -1);
            }
            state->file = xqc_wt_interop_open_file(ctx->directory,
                                                   filename, 0);
            if (state->file < 0) {
                xqc_wt_interop_fail("open requested file", errno);
                return XQC_ERROR;
            }
            state->sending = 1;
            return xqc_wt_interop_flush(state);
        }
    }
    return xqc_wt_interop_receive_file(state, state->header.line + 5,
        (const unsigned char *) data + consumed, length - consumed, fin, 0);
}

static xqc_int_t
xqc_wt_interop_stream_read(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *data, size_t length, void *user_data)
{
    return xqc_wt_interop_receive(stream, data, length,
                                   xqc_wt_unistream_get_recv_fin(stream));
}

static xqc_int_t
xqc_wt_interop_stream_close(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    xqc_wt_interop_stream_t *state = xqc_wt_interop_find(stream);

    if (state) {
        if (!state->complete && !xqc_wt_interop.stopped
            && xqc_wt_interop.session)
        {
            xqc_wt_interop_fail("stream closed before FIN", XQC_ERROR);
        }
        /* Session close can synchronously close streams inside send/read. */
        state->stream = NULL;
        if (state->file >= 0) {
            close(state->file);
            state->file = -1;
        }
    }
    return XQC_OK;
}

static xqc_int_t
xqc_wt_interop_stream_closing(xqc_wt_unistream_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    xqc_wt_interop_fail("stream reset or stopped", XQC_ERROR);
    return XQC_OK;
}

static xqc_int_t
xqc_wt_interop_bidi_create(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    int result = xqc_wt_interop_stream_create((void *) stream,
                                             session, user_data);
    if (result == XQC_OK) {
        xqc_wt_interop_find(stream)->bidirectional = 1;
    }
    return result;
}

static xqc_int_t
xqc_wt_interop_bidi_write(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    return xqc_wt_interop_stream_write((void *) stream, session, user_data);
}

static xqc_int_t
xqc_wt_interop_bidi_read(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *data, size_t length, void *user_data)
{
    return xqc_wt_interop_receive(stream, data, length,
                                   xqc_wt_bidistream_get_recv_fin(stream));
}

static xqc_int_t
xqc_wt_interop_bidi_close(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    return xqc_wt_interop_stream_close((void *) stream, session, user_data);
}

static xqc_int_t
xqc_wt_interop_bidi_closing(xqc_wt_bidistream_t *stream,
    xqc_wt_session_t *session, void *user_data)
{
    return xqc_wt_interop_stream_closing((void *) stream, session, user_data);
}

static int
xqc_wt_interop_datagram_queue(const void *data, size_t length)
{
    xqc_wt_interop_t *ctx = &xqc_wt_interop;
    xqc_wt_interop_datagram_t *item;

    if (length > XQC_WT_INTEROP_DATAGRAM_MAX
        || ctx->datagram_count == XQC_WT_INTEROP_FILES_MAX)
    {
        xqc_wt_interop_fail("datagram queue bound", XQC_ERROR);
        return XQC_ERROR;
    }
    item = &ctx->datagrams[(ctx->datagram_head + ctx->datagram_count)
                           % XQC_WT_INTEROP_FILES_MAX];
    item->length = length;
    memcpy(item->data, data, length);
    ctx->datagram_count++;
    return XQC_OK;
}

static int
xqc_wt_interop_datagram_request(xqc_wt_session_t *session)
{
    xqc_wt_interop_t *ctx = &xqc_wt_interop;
    char request[XQC_WT_INTEROP_PATH_MAX + 5];

    if (ctx->failed || ctx->success || ctx->stopped
        || ctx->completed >= ctx->file_count)
    {
        return XQC_OK;
    }
    /* One outstanding GET avoids bursts of small packets in the simulator. */
    int length = snprintf(request, sizeof(request),
                           "GET %s", ctx->files[ctx->completed]);
    if (xqc_wt_interop_datagram_queue(request, length)) {
        return XQC_ERROR;
    }
    xqc_wt_interop_datagram_write(session, NULL);
    return ctx->failed ? XQC_ERROR : XQC_OK;
}

static void
xqc_wt_interop_datagram_write(xqc_wt_session_t *session, void *user_data)
{
    xqc_wt_interop_t *ctx = &xqc_wt_interop;

    if (!ctx->datagram_count || ctx->failed || ctx->success) {
        return;
    }
    while (ctx->datagram_count && !ctx->failed) {
        xqc_wt_interop_datagram_t *item =
            &ctx->datagrams[ctx->datagram_head];
        int result = xqc_wt_session_datagram_send(session, item->data,
                                                   item->length, NULL);
        if (result != XQC_OK) {
            if (!xqc_wt_interop_blocked(result)) {
                xqc_wt_interop_fail("datagram send", result);
            }
            break;
        }
        /* Sending may synchronously close the session and clear the queue. */
        if (!ctx->datagram_count || ctx->session != session) {
            return;
        }
        ctx->datagram_head = (ctx->datagram_head + 1)
            % XQC_WT_INTEROP_FILES_MAX;
        ctx->datagram_count--;
        if (!ctx->mode) {
            ctx->completed++;
        }
    }
    ctx->schedule_send(ctx->user_data);
}

static void
xqc_wt_interop_datagram_read(xqc_wt_session_t *session,
    const void *data, size_t length, void *user_data, uint64_t recv_time)
{
    xqc_wt_interop_t *ctx = &xqc_wt_interop;
    xqc_wt_interop_header_t header = {0};
    size_t consumed;

    if (ctx->failed || ctx->success) {
        return;
    }
    if (ctx->handshake || (ctx->mode && ctx->mode != 3)
        || length > XQC_WT_INTEROP_DATAGRAM_MAX
        || xqc_wt_interop_header_feed(&header, data, length, 1,
            ctx->mode != 0, &consumed) != 1)
    {
        xqc_wt_interop_fail("invalid datagram", XQC_ERROR);
        return;
    }
    if (ctx->mode) {
        xqc_wt_interop_stream_t state = {.file = -1, .request_index = -1};
        xqc_wt_interop_receive_file(&state, header.line + 5,
            (const unsigned char *) data + consumed, length - consumed, 1, 1);
        if (state.file >= 0) {
            close(state.file);
        }
        return;
    }
    unsigned char response[XQC_WT_INTEROP_DATAGRAM_MAX + 1];
    const char *filename = header.line + 4;
    int file = xqc_wt_interop_open_file(ctx->directory, filename, 0);
    if (file < 0) {
        xqc_wt_interop_fail("open requested file", errno);
        return;
    }
    size_t used = snprintf((char *) response, sizeof(response),
                            "PUSH %s\n", filename);
    while (used < sizeof(response)) {
        ssize_t bytes = read(file, response + used, sizeof(response) - used);
        if (bytes < 0 && errno == EINTR) {
            continue;
        }
        if (bytes <= 0) {
            if (bytes < 0) {
                xqc_wt_interop_fail("read source file", errno);
            }
            break;
        }
        used += bytes;
    }
    close(file);
    if (!ctx->failed && !xqc_wt_interop_datagram_queue(response, used)) {
        xqc_wt_interop_datagram_write(session, NULL);
    }
}

static int
xqc_wt_interop_directory(void)
{
    xqc_wt_interop_t *ctx = &xqc_wt_interop;

    if (ctx->mode && mkdirat(ctx->root, ctx->endpoint, 0755) < 0
        && errno != EEXIST)
    {
        return -1;
    }
    ctx->directory = openat(ctx->root, ctx->endpoint,
                            O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    return ctx->directory < 0 ? -1 : 0;
}

static int
xqc_wt_interop_configure(int server)
{
    xqc_wt_interop_t *ctx = &xqc_wt_interop;
    const char *protocols = getenv("PROTOCOLS");
    const char *testcase = getenv("TESTCASE");
    const char *role = getenv("ROLE");
    const char *directory;
    char *save;

    if (!protocols || !*protocols || !testcase || !role
        || strcmp(role, server ? "server" : "client"))
    {
        return -1;
    }
    ctx->handshake = !strcmp(testcase, "handshake");
    ctx->case_name = ctx->handshake ? "handshake" : "transfer";
    if (!ctx->handshake && strcmp(testcase, "transfer")) {
        const char *types[] = {"unidirectional", "bidirectional", "datagram"};
        const char *names[][2] = {{"UR", "US"}, {"BR", "BS"}, {"DR", "DS"}};
        char expected[64];
        for (int i = 0; i < 3; i++) {
            snprintf(expected, sizeof(expected), "transfer-%s-%s",
                     types[i], server ? "send" : "receive");
            if (!strcmp(testcase, expected)) {
                ctx->mode = i + 1;
                ctx->case_name = names[i][server];
            }
        }
        if (!ctx->mode) {
            return -1;
        }
    }
    int source = !ctx->handshake && !ctx->mode;
    directory = getenv(source ? "XQC_WT_WWW" : "XQC_WT_DOWNLOADS");
    if (ctx->handshake && server) {
        directory = getenv("XQC_WT_WWW");
        source = 1;
    }
    ctx->protocol_storage = strdup(protocols);
    if (!ctx->protocol_storage) {
        return -1;
    }
    for (char *p = strtok_r(ctx->protocol_storage, " ", &save); p;
         p = strtok_r(NULL, " ", &save))
    {
        if (ctx->protocol_count == 32
            || strlen(p) > XQC_WT_INTEROP_PROTOCOL_MAX)
        {
            return -1;
        }
        for (const unsigned char *ch = (const unsigned char *) p; *ch; ch++) {
            if (*ch < 0x21 || *ch > 0x7e) {
                return -1;
            }
        }
        ctx->protocols[ctx->protocol_count++] = p;
    }
    if (!ctx->protocol_count) {
        return -1;
    }
    ctx->root = open(directory ? directory : source ? "/www" : "/downloads",
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    return ctx->root < 0 ? -1 : 0;
}

static int
xqc_wt_interop_requests(const char *authority, const char *path)
{
    xqc_wt_interop_t *ctx = &xqc_wt_interop;
    const char *requests = getenv("REQUESTS");
    char *save;
    size_t count = 0;

    if (!requests || ctx->requests_storage) {
        return -1;
    }
    if (!ctx->server) {
        size_t length = strlen(path);
        if (length < 2 || length > sizeof(ctx->endpoint) || path[0] != '/'
            || !xqc_wt_interop_valid_path(path + 1) || strchr(path + 1, '/'))
        {
            return -1;
        }
        strcpy(ctx->endpoint, path + 1);
    }
    size_t endpoint_length = strlen(ctx->endpoint);
    ctx->requests_storage = strdup(requests);
    if (!ctx->requests_storage) {
        return -1;
    }
    for (char *url = strtok_r(ctx->requests_storage, " ", &save); url;
         url = strtok_r(NULL, " ", &save))
    {
        const char *file = url;
        count++;
        if (!ctx->server) {
            size_t length = strlen(authority);
            if (strncmp(url, "https://", 8)
                || strncmp(url + 8, authority, length)
                || url[8 + length] != '/')
            {
                return -1;
            }
            file += 9 + length;
        }
        if (strncmp(file, ctx->endpoint, endpoint_length)
            || (file[endpoint_length] && file[endpoint_length] != '/'))
        {
            return -1;
        }
        file += endpoint_length;
        if (*file == '/') {
            file++;
        }
        if (!ctx->mode) {
            if (*file) {
                return -1;
            }
            continue;
        }
        if (!xqc_wt_interop_valid_path(file)
            || ctx->file_count == XQC_WT_INTEROP_FILES_MAX)
        {
            return -1;
        }
        for (size_t i = 0; i < ctx->file_count; i++) {
            if (!strcmp(file, ctx->files[i])) {
                return -1;
            }
        }
        ctx->files[ctx->file_count++] = file;
    }
    if ((ctx->mode && !ctx->file_count) || !count) {
        return -1;
    }
    if (!ctx->server && !ctx->handshake && xqc_wt_interop_directory()) {
        return -1;
    }
    return 0;
}

static xqc_int_t
xqc_wt_interop_init(xqc_engine_t *engine, int draft_version, int server,
    void (*schedule_send)(void *user_data), void (*finished)(void *user_data),
    void *user_data)
{
    xqc_wt_interop_t *ctx = &xqc_wt_interop;
    xqc_webtransport_dgram_callbacks_t datagram_callbacks = {
        .dgram_read_notify = xqc_wt_interop_datagram_read,
        .dgram_write_notify = xqc_wt_interop_datagram_write,
    };
    xqc_webtransport_session_callbacks_t session_callbacks = {
        .webtransport_will_create_session_notify = xqc_wt_interop_accept,
        .webtransport_session_create_notify = xqc_wt_interop_ready,
        .webtransport_session_close_notify = xqc_wt_interop_closed,
        .webtransport_conn_handshake_finished_notify =
            xqc_wt_interop_handshake,
    };
    xqc_webtransport_stream_callbacks_t stream_callbacks = {
        .wt_unistream_create_notify = xqc_wt_interop_stream_create,
        .wt_unistream_write_notify = xqc_wt_interop_stream_write,
        .wt_unistream_read_notify = xqc_wt_interop_stream_read,
        .wt_unistream_close_notify = xqc_wt_interop_stream_close,
        .wt_unistream_closing_notify = xqc_wt_interop_stream_closing,
        .wt_bidistream_create_notify = xqc_wt_interop_bidi_create,
        .wt_bidistream_write_notify = xqc_wt_interop_bidi_write,
        .wt_bidistream_read_notify = xqc_wt_interop_bidi_read,
        .wt_bidistream_close_notify = xqc_wt_interop_bidi_close,
        .wt_bidistream_closing_notify = xqc_wt_interop_bidi_closing,
    };
    xqc_webtransport_conn_settings_t settings = {
        .max_sessions_count = 1,
        .draft_version = draft_version == 7
            ? XQC_WEBTRANSPORT_DRAFT_VERSION_7
            : XQC_WEBTRANSPORT_DRAFT_VERSION_16,
        .max_bidi_streams = 16,
        .max_uni_streams = 64,
        .init_recv_window = 8 * 1024 * 1024,
        .enable_datagram = 1,
    };
    int result;

    memset(ctx, 0, sizeof(*ctx));
    ctx->root = -1;
    ctx->directory = -1;
    ctx->server = server;
    ctx->schedule_send = schedule_send;
    ctx->finished = finished;
    ctx->user_data = user_data;
    if (xqc_wt_interop_configure(server)) {
        fprintf(stderr, "WT INTEROP invalid environment or root directory\n");
        return XQC_ERROR;
    }
    result = xqc_wt_ctx_init(engine, &datagram_callbacks,
                             &session_callbacks, &stream_callbacks);
    if (result != XQC_OK) {
        return result;
    }
    /* The runner's 200 GET datagrams can precede the CONNECT response. */
    result = xqc_wt_ctx_set_pending_datagram_policy(engine,
        XQC_WEBTRANSPORT_DEFAULT_UNKNOWN_SESSION_DGRAM_WINDOW,
        XQC_WT_INTEROP_FILES_MAX,
        XQC_WT_INTEROP_FILES_MAX * XQC_WT_INTEROP_DATAGRAM_MAX);
    return result == XQC_OK
        ? xqc_wt_engine_set_default_settings(engine, &settings) : result;
}

xqc_int_t
xqc_demo_wt_init(xqc_engine_t *engine, int draft_version,
    void (*schedule_send)(void *user_data), void *user_data)
{
    return xqc_wt_interop_init(engine, draft_version, 1,
                                schedule_send, NULL, user_data);
}

xqc_int_t
xqc_demo_wt_client_init(xqc_engine_t *engine, int draft_version,
    int case_id, void (*schedule_send)(void *user_data),
    void (*finished)(void *user_data), void *user_data)
{
    return xqc_wt_interop_init(engine, draft_version, 0,
                                schedule_send, finished, user_data);
}

xqc_int_t
xqc_demo_wt_client_open(xqc_h3_conn_t *h3_conn,
    const char *authority, const char *path, const char *origin)
{
    xqc_wt_interop_t *ctx = &xqc_wt_interop;
    int error;

    if (xqc_wt_interop_requests(authority, path)) {
        xqc_wt_interop_fail("invalid REQUESTS", XQC_ERROR);
        return XQC_ERROR;
    }
    ctx->session = xqc_wt_client_open_session_with_protocols(h3_conn,
        authority, path, origin, ctx->protocols, ctx->protocol_count, &error);
    if (!ctx->session) {
        xqc_wt_interop_fail("open session", error);
        return error;
    }
    ctx->schedule_send(ctx->user_data);
    return XQC_OK;
}

int
xqc_demo_wt_client_finish(void)
{
    xqc_wt_interop_t *ctx = &xqc_wt_interop;

    ctx->stopped = 1;
    if (!ctx->success && !ctx->failed) {
        fprintf(stderr, "WT INTEROP FAIL: timeout before completion\n");
    }
    if (ctx->root >= 0) {
        close(ctx->root);
        ctx->root = -1;
    }
    free(ctx->requests_storage);
    ctx->requests_storage = NULL;
    free(ctx->protocol_storage);
    ctx->protocol_storage = NULL;
    return ctx->success && !ctx->failed ? 0 : 1;
}

xqc_int_t
xqc_demo_wt_client_conn_closing(xqc_connection_t *conn,
    const xqc_cid_t *cid, xqc_int_t error, void *user_data)
{
    if (!xqc_wt_interop.success && !xqc_wt_interop.stopped) {
        xqc_wt_interop_fail("connection closed before completion", error);
    }
    return XQC_OK;
}
