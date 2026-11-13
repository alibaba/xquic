/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */

#include "xqc_moqt_session.h"
#include "xqc_moqt_codec.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/transport/xqc_engine.h"

#define XQC_MOQT_PERCENT_ESCAPE_LEN 3

typedef enum {
    XQC_MOQT_TOKEN_DELETE,
    XQC_MOQT_TOKEN_REGISTER,
    XQC_MOQT_TOKEN_USE_ALIAS,
    XQC_MOQT_TOKEN_USE_VALUE,
} xqc_moqt_token_action_t;


/* RFC 3986 sections 2.2-2.3: ASCII URI octets, including pct-encoded. */
static xqc_int_t
xqc_moqt_uri_check_chars(const uint8_t *p, size_t len, const char *extra)
{
    for (size_t i = 0; i < len; i++) {
        unsigned c = p[i];
        if ((c >= 'a'
                && c <= 'z')
            || (c >= 'A'
                && c <= 'Z')
            || (c >= '0'
                && c <= '9')
            || (c != 0
                && (strchr("-._~!$&'()*+,;=", c)
                    || strchr(extra, c))))
        {
            continue;
        }
        if (c != '%' || len - i < XQC_MOQT_PERCENT_ESCAPE_LEN) {
            return XQC_ERROR;
        }
        for (size_t j = 1; j < XQC_MOQT_PERCENT_ESCAPE_LEN; j++) {
            c = p[i + j];
            if (!((c >= '0'
                        && c <= '9')
                    || (c >= 'A'
                        && c <= 'F')
                    || (c >= 'a'
                        && c <= 'f')))
            {
                return XQC_ERROR;
            }
        }
        i += XQC_MOQT_PERCENT_ESCAPE_LEN - 1;
    }
    return XQC_OK;
}

static xqc_int_t
xqc_moqt_authority_check(const struct iovec *value)
{
    const uint8_t *p = value->iov_base;
    size_t len = value->iov_len;
    const uint8_t *at = len ? memchr(p, '@', len) : NULL;
    if (at != NULL) {
        if (xqc_moqt_uri_check_chars(p, at - p, ":") != XQC_OK) {
            return XQC_ERROR;
        }
        len -= at + 1 - p;
        p = at + 1;
    }
    size_t host_len = 0;
    if (len && p[0] == '[') {
        const uint8_t *end = memchr(p, ']', len);
        if (end == NULL) {
            return XQC_ERROR;
        }
        host_len = end + 1 - p;
        size_t literal_len = host_len - 2;
        if (literal_len && (p[1] == 'v' || p[1] == 'V')) {
            size_t dot = 2;
            while (dot < host_len - 1 && p[dot] != '.') {
                unsigned c = p[dot++];
                if (!((c >= '0'
                            && c <= '9')
                        || (c >= 'a'
                            && c <= 'f')
                        || (c >= 'A'
                            && c <= 'F')))
                {
                    return XQC_ERROR;
                }
            }
            if (dot == 2
                || dot + 1 >= host_len - 1
                || xqc_moqt_uri_check_chars(p + dot + 1,
                                            host_len - dot - 2, ":") != XQC_OK
                || memchr(p + dot + 1, '%', host_len - dot - 2))
            {
                return XQC_ERROR;
            }

        } else {
            char literal[INET6_ADDRSTRLEN];
            struct in6_addr addr;
            if (literal_len >= sizeof(literal)) {
                return XQC_ERROR;
            }
            xqc_memcpy(literal, p + 1, literal_len);
            literal[literal_len] = '\0';
            if (inet_pton(AF_INET6, literal, &addr) != 1) {
                return XQC_ERROR;
            }
        }

    } else {
        while (host_len < len && p[host_len] != ':') {
            host_len++;
        }
        if (xqc_moqt_uri_check_chars(p, host_len, "") != XQC_OK) {
            return XQC_ERROR;
        }
    }
    /* Draft-22 section 6.1: the moqt URI cannot have an empty host. */
    if (host_len == 0) {
        return XQC_ERROR;
    }
    if (host_len == len) {
        return XQC_OK;
    }
    if (p[host_len++] != ':') {
        return XQC_ERROR;
    }
    for (; host_len < len; host_len++) {
        if (p[host_len] < '0' || p[host_len] > '9') {
            return XQC_ERROR;
        }
    }
    return XQC_OK;
}

uint64_t
xqc_moqt_token_decode(const struct iovec *bytes, xqc_int_t from_client,
    xqc_int_t setup, xqc_moqt_token_t *token)
{
    const uint8_t *p = bytes->iov_base, *end = p + bytes->iov_len;
    uint64_t action, alias;
    xqc_int_t n = xqc_vi64_read(p, end, &action);
    if (n < 0 || action > XQC_MOQT_TOKEN_USE_VALUE) {
        return XQC_MOQT_KEY_VALUE_FORMATTING_ERROR;
    }
    p += n;
    if (action != XQC_MOQT_TOKEN_USE_VALUE) {
        n = xqc_vi64_read(p, end, &alias);
        if (n < 0) {
            return XQC_MOQT_KEY_VALUE_FORMATTING_ERROR;
        }
        p += n;
        if (action != XQC_MOQT_TOKEN_REGISTER) {
            if (p != end) {
                return XQC_MOQT_KEY_VALUE_FORMATTING_ERROR;
            }
            return setup && from_client ? XQC_MOQT_PROTOCOL_VIOLATION
                               : XQC_MOQT_UNKNOWN_AUTH_TOKEN_ALIAS;
        }
    }
    if (action == XQC_MOQT_TOKEN_REGISTER && !setup) {
        return XQC_MOQT_AUTH_TOKEN_CACHE_OVERFLOW;
    }
    n = xqc_vi64_read(p, end, &token->type);
    if (n < 0) {
        return XQC_MOQT_KEY_VALUE_FORMATTING_ERROR;
    }
    token->value.iov_base = (void *)(p + n);
    token->value.iov_len = end - p - n;
    /* Section 9.1.4: zero cache downgrades SETUP REGISTER to USE_VALUE. */
    return XQC_MOQT_NO_ERROR;
}

/* Section 8.9 permits repetition only for distinct token type/value. */
xqc_int_t
xqc_moqt_token_check(const xqc_moqt_token_t *tokens, size_t count,
    const xqc_moqt_token_t *token)
{
    for (size_t i = 0; i < count; i++) {
        if (tokens[i].type == token->type
            && tokens[i].value.iov_len == token->value.iov_len
            && !xqc_memcmp(tokens[i].value.iov_base,
                           token->value.iov_base, token->value.iov_len))
        {
            return XQC_ERROR;
        }
    }
    return XQC_OK;
}

static uint64_t
xqc_moqt_setup_decode(const struct iovec *body, xqc_int_t from_client,
    xqc_bool_t webtransport,
    xqc_moqt_setup_t *setup, xqc_moqt_kv_t *options, xqc_moqt_token_t *tokens)
{
    size_t pos = 0;
    uint64_t previous = 0;
    xqc_memzero(setup, sizeof(*setup));
    setup->options = options;
    setup->tokens = tokens;
    while (pos < body->iov_len) {
        if (setup->option_count == XQC_MOQT_MAX_OPTIONS) {
            return XQC_MOQT_INTERNAL_ERROR;
        }
        xqc_moqt_kv_t *kv = &options[setup->option_count];
        xqc_int_t n = xqc_moqt_kv_decode((uint8_t *)body->iov_base + pos,
                                         body->iov_len - pos, previous, kv);
        if (n < 0) {
            return XQC_MOQT_KEY_VALUE_FORMATTING_ERROR;
        }
        if (setup->option_count
            && kv->type == previous
            && kv->type != XQC_MOQT_OPT_AUTHORIZATION_TOKEN
            && (kv->type == XQC_MOQT_OPT_PATH
                || (kv->type >= XQC_MOQT_OPT_MAX_AUTH_TOKEN_CACHE
                    && kv->type <= XQC_MOQT_OPT_MAX_REQUEST_UPDATES)))
        {
            return XQC_MOQT_PROTOCOL_VIOLATION;
        }
        previous = kv->type;
        setup->option_count++;
        pos += n;
        switch (kv->type) {
        /* Draft-22 9.1.1/9.1.2: CONNECT already carries WT authority/path. */
        case XQC_MOQT_OPT_PATH:
            if (!from_client || webtransport) {
                return XQC_MOQT_INVALID_PATH;
            }
            if ((kv->value.bytes.iov_len
                    && ((uint8_t *)kv->value.bytes.iov_base)[0] != '/'
                    && ((uint8_t *)kv->value.bytes.iov_base)[0] != '?')
                || xqc_moqt_uri_check_chars(kv->value.bytes.iov_base,
                                            kv->value.bytes.iov_len, "/?:@")
                   != XQC_OK)
            {
                return XQC_MOQT_MALFORMED_PATH;
            }
            break;
        case XQC_MOQT_OPT_AUTHORITY:
            if (!from_client || webtransport) {
                return XQC_MOQT_INVALID_AUTHORITY;
            }
            if (xqc_moqt_authority_check(&kv->value.bytes) != XQC_OK) {
                return XQC_MOQT_MALFORMED_AUTHORITY;
            }
            break;
        case XQC_MOQT_OPT_AUTHORIZATION_TOKEN: {
            xqc_moqt_token_t *token = &tokens[setup->token_count];
            uint64_t error = xqc_moqt_token_decode(&kv->value.bytes,
                                                   from_client, 1, token);
            if (error) {
                return error;
            }
            if (xqc_moqt_token_check(tokens, setup->token_count, token)
                != XQC_OK)
            {
                return XQC_MOQT_MALFORMED_AUTH_TOKEN;
            }
            setup->token_count++;
            break;
        }
        case XQC_MOQT_OPT_MAX_AUTH_TOKEN_CACHE:
            setup->limits.max_auth_token_cache = kv->value.integer;
            break;
        case XQC_MOQT_OPT_MAX_FILTER_RANGES:
            setup->limits.max_filter_ranges = kv->value.integer;
            break;
        case XQC_MOQT_OPT_MAX_REQUEST_UPDATES:
            setup->limits.max_request_updates = kv->value.integer;
            break;
        default:
            break;
        }
    }
    return XQC_MOQT_NO_ERROR;
}

void
xqc_moqt_notify_closed(xqc_moqt_session_t *s, uint64_t error)
{
    if (!s->closed) {
        s->closed = 1;
        if (s->callbacks.on_closed != NULL) {
            s->callbacks.on_closed(s, error, s->user_data);
        }
    }
}

void
xqc_moqt_session_close(xqc_moqt_session_t *s, uint64_t error)
{
    if (s == NULL || s->closed) {
        return;
    }
#ifdef XQC_ENABLE_WEBTRANSPORT
    if (s->webtransport) {
        if (error > UINT32_MAX) {
            error = XQC_MOQT_INTERNAL_ERROR;
        }
        xqc_moqt_notify_closed(s, error);
        xqc_moqt_webtransport_close(s, error);
        return;
    }
#endif
    xqc_conn_close_with_error(s->conn, error);
    /* close_with_error records the error; wake an otherwise idle connection. */
    xqc_engine_remove_wakeup_queue(s->conn->engine, s->conn);
    xqc_engine_add_active_queue(s->conn->engine, s->conn);
    xqc_engine_wakeup_once(s->conn->engine);
    xqc_moqt_notify_closed(s, error);
}

static void
xqc_moqt_ready(xqc_moqt_session_t *s)
{
    if (!s->closed
        && !s->ready
        && s->started
        && s->setup_sent
        && s->setup_received)
    {
        s->ready = 1;
        s->setup_deadline = 0;
        if (s->callbacks.on_ready != NULL) {
            s->callbacks.on_ready(s, s->user_data);
        }
    }
}

xqc_var_buf_t *
xqc_moqt_buffer_create(xqc_moqt_session_t *s, size_t len, size_t overhead)
{
    if (overhead > s->config.max_buffered_bytes - s->buffered_bytes
        || len > s->config.max_buffered_bytes - s->buffered_bytes - overhead)
    {
        return NULL;
    }
    xqc_var_buf_t *buf = xqc_var_buf_create(len);
    if (buf != NULL) {
        s->buffered_bytes += buf->buf_len + overhead;
    }
    return buf;
}

void
xqc_moqt_buffer_free(xqc_moqt_session_t *s, xqc_var_buf_t *buf,
    size_t overhead)
{
    if (buf != NULL) {
        s->buffered_bytes -= buf->buf_len + overhead;
        xqc_var_buf_free(buf);
    }
}

xqc_int_t
xqc_moqt_queue(xqc_moqt_session_t *s, xqc_list_head_t *head,
    xqc_var_buf_t *buf)
{
    if (sizeof(xqc_list_buf_t)
        > s->config.max_buffered_bytes - s->buffered_bytes
        || xqc_list_buf_to_tail(head, buf) != XQC_OK)
    {
        return -XQC_EMALLOC;
    }
    s->buffered_bytes += sizeof(xqc_list_buf_t);
    return XQC_OK;
}

void
xqc_moqt_dequeue(xqc_moqt_session_t *s, xqc_list_buf_t *entry)
{
    s->buffered_bytes -= entry->buf->buf_len + XQC_MOQT_TX_OVERHEAD;
    xqc_list_buf_free(entry);
}

xqc_moqt_stream_t *
xqc_moqt_streams_hold(xqc_moqt_session_t *s)
{
    for (xqc_moqt_stream_t *st = s->streams; st != NULL; st = st->next) {
        st->active++;
    }
    return s->streams;
}

void
xqc_moqt_streams_release(xqc_moqt_stream_t *head)
{
    for (xqc_moqt_stream_t *st = head, *next; st != NULL; st = next) {
        next = st->next;
        st->active--;
        if (!st->active
            && !st->reading
            && !st->writing
            && st->transport_stream == NULL)
        {
            xqc_moqt_stream_callbacks.stream_close_notify(NULL, st);
        }
    }
}

static xqc_int_t
xqc_moqt_stream_flush_one(xqc_moqt_stream_t *stream)
{
    xqc_moqt_session_t *s = stream->session;
    xqc_int_t ret = XQC_OK;
    if (stream->writing
        || stream->discarded
        || stream->transport_stream == NULL)
    {
        return XQC_OK;
    }
    stream->active++;
    stream->writing = 1;
    while (!s->closed && !xqc_list_empty(&stream->tx)) {
        xqc_list_buf_t *entry = xqc_list_entry(stream->tx.next,
                                               xqc_list_buf_t, list_head);
        xqc_var_buf_t *buf = entry->buf;
        /* Section 5.2: fragments retain the Object header submission time. */
        if (stream->kind == XQC_MOQT_STREAM_SUBGROUP
            && xqc_moqt_object_is_expired(stream, entry->timestamp,
                                           xqc_monotonic_timestamp()))
        {
            xqc_moqt_stream_cancel(stream, XQC_MOQT_RESET_DELIVERY_TIMEOUT);
            ret = -XQC_EEXPIRED;
            break;
        }
        size_t len = buf->data_len - buf->consumed_len;
        if (stream->kind == XQC_MOQT_STREAM_FETCH
            && stream->state.data.reset_pending)
        {
            /* A cancelled Fill sends only its identifying reliable prefix. */
            size_t prefix = stream->state.data.prefix_length
                            - xqc_moqt_transport_offset(stream);
            len = xqc_min(len, prefix);
        }
        ssize_t n = xqc_moqt_transport_send(
            stream,
            buf->data + buf->consumed_len, len,
            buf->fin_flag);
        if (n == -XQC_EAGAIN
            || (n == 0
                && buf->data_len != buf->consumed_len))
        {
            stream->tx_blocked = 1;
            break;
        }
        if (n < 0) {
            if (stream->kind == XQC_MOQT_STREAM_REQUEST) {
                xqc_moqt_request_cancel(&stream->state.request,
                                        XQC_MOQT_RESET_INTERNAL_ERROR);
            } else if (stream->kind == XQC_MOQT_STREAM_SUBGROUP
                       || stream->kind == XQC_MOQT_STREAM_FETCH)
            {
                xqc_moqt_stream_cancel(stream, XQC_MOQT_RESET_INTERNAL_ERROR);
            } else {
                xqc_moqt_session_close(s, XQC_MOQT_INTERNAL_ERROR);
            }
            ret = (xqc_int_t)n;
            break;
        }
        buf->consumed_len += n;
        if (buf->consumed_len == buf->data_len) {
            if (buf->fin_flag) {
                stream->tx_fin_sent = 1;
            }
            xqc_moqt_dequeue(s, entry);
            if (stream == s->control_tx && !s->setup_sent) {
                s->setup_sent = 1;
                xqc_moqt_ready(s);
            }
        }
        break;
    }
    if (stream->kind == XQC_MOQT_STREAM_SUBGROUP
        || stream->kind == XQC_MOQT_STREAM_FETCH)
    {
        if (stream->state.data.reset_pending
            && stream->transport_stream != NULL
            && xqc_moqt_transport_offset(stream)
               >= stream->state.data.prefix_length)
        {
            stream->state.data.reset_pending = 0;
            xqc_moqt_stream_cancel(stream, stream->state.data.error);
        } else if (stream->tx_fin_sent) {
            xqc_moqt_subgroup_notify(stream);
        }
    }
    stream->writing = 0;
    stream->active--;
    if (!stream->active
        && !stream->reading
        && stream->transport_stream == NULL)
    {
        xqc_moqt_stream_callbacks.stream_close_notify(NULL, stream);
    }
    return ret;
}

/* Section 5.1: compare queued objects without copying a scheduling entity. */
xqc_int_t
xqc_moqt_data_compare(const xqc_moqt_subscription_t *a,
    const xqc_moqt_object_t *oa, const xqc_moqt_fetch_t *fa,
    const xqc_moqt_subscription_t *b, const xqc_moqt_object_t *ob,
    const xqc_moqt_fetch_t *fb)
{
    uint8_t pa = fa != NULL ? fa->info.subscriber_priority
                            : a->subscriber_priority;
    uint8_t pb = fb != NULL ? fb->info.subscriber_priority
                            : b->subscriber_priority;
    if (pa != pb) {
        return pa < pb ? -1 : 1;
    }
    if (oa->priority != ob->priority) {
        return oa->priority < ob->priority ? -1 : 1;
    }
    if (a == NULL || a != b) {
        return 0;
    }
    if (oa->group_id != ob->group_id) {
        uint8_t order_a = fa != NULL ? fa->info.group_order : a->group_order;
        uint8_t order_b = fb != NULL ? fb->info.group_order : b->group_order;
        if (order_a != order_b) {
            /* Section 5.1.2: live precedes a differently ordered Fill. */
            return fa == NULL ? -1 : fb == NULL ? 1 : 0;
        }
        xqc_int_t ascending = oa->group_id < ob->group_id;
        return ascending == (order_a == XQC_MOQT_GROUP_ASCENDING)
            ? -1 : 1;
    }
    if ((fa != NULL) != (fb != NULL)) {
        /* Rule 4: same-group Fill precedes live, including Datagrams. */
        return fa != NULL ? -1 : 1;
    }
    if (oa->datagram != ob->datagram) {
        return oa->datagram ? -1 : 1;
    }
    uint64_t id_a = oa->datagram ? oa->object_id : oa->subgroup_id;
    uint64_t id_b = ob->datagram ? ob->object_id : ob->subgroup_id;
    return id_a < id_b ? -1 : id_a != id_b;
}

static xqc_moqt_stream_t *
xqc_moqt_stream_next(xqc_moqt_session_t *s)
{
    xqc_moqt_stream_t *best = NULL;
    for (xqc_moqt_stream_t *st = s->streams; st != NULL; st = st->next) {
        /* Skip closed, reentrant or already-blocked candidates this round. */
        if (st->discarded || st->writing || st->tx_blocked) {
            continue;
        }
        /* A candidate needs both a transport stream and queued bytes. */
        if (st->transport_stream == NULL || xqc_list_empty(&st->tx)) {
            continue;
        }
        if (st->kind == XQC_MOQT_STREAM_SUBGROUP
            && (st->state.data.subscription == NULL
                || (!st->state.data.has_object
                    && !st->tx_fin)))
        {
            continue;
        }
        if (st->kind == XQC_MOQT_STREAM_FETCH) {
            /* A released Fetch has no delivery policy to schedule. */
            if (st->state.data.fetch == NULL) {
                continue;
            }
            /* A reset-only Fill must send its identifying header too. */
            if (!st->state.data.has_object
                && !st->tx_fin
                && !st->state.data.reset_pending)
            {
                continue;
            }
        }
        xqc_moqt_stream_kind_t kind = st->kind == XQC_MOQT_STREAM_FETCH
            ? XQC_MOQT_STREAM_SUBGROUP : st->kind;
        xqc_moqt_stream_kind_t best_kind = best == NULL
            ? XQC_MOQT_STREAM_UNCLASSIFIED
            : best->kind == XQC_MOQT_STREAM_FETCH
              ? XQC_MOQT_STREAM_SUBGROUP : best->kind;
        xqc_int_t order = 0;
        if (best != NULL
            && kind == best_kind
            && kind == XQC_MOQT_STREAM_SUBGROUP)
        {
            xqc_moqt_data_stream_t *a = &st->state.data;
            xqc_moqt_data_stream_t *b = &best->state.data;
            xqc_moqt_subscription_t *sa = a->fetch != NULL
                ? a->fetch->subscription : a->subscription;
            xqc_moqt_subscription_t *sb = b->fetch != NULL
                ? b->fetch->subscription : b->subscription;
            order = xqc_moqt_data_compare(sa, &a->object, a->fetch,
                                           sb, &b->object, b->fetch);
        }
        /* CONTROL precedes REQUEST, which precedes object data. */
        if (best == NULL || kind < best_kind) {
            best = st;
            continue;
        }
        /* A later stream class cannot displace the selected earlier class. */
        if (kind != best_kind) {
            continue;
        }
        /* Within a class, prefer data priority, then the oldest turn. */
        if (order < 0 || (order == 0 && st->tx_order < best->tx_order)) {
            best = st;
        }
    }
    return best;
}

xqc_int_t
xqc_moqt_stream_flush(xqc_moqt_stream_t *stream)
{
    xqc_moqt_session_t *s = stream->session;
    if (s->flushing || s->closed) {
        return XQC_OK;
    }
    s->flushing = 1;
    xqc_moqt_stream_t *head = xqc_moqt_streams_hold(s);
    for (xqc_moqt_stream_t *st = head; st != NULL; st = st->next) {
        st->tx_blocked = 0;
    }
    xqc_int_t ret = XQC_OK;
    xqc_moqt_stream_t *st;
    while (!s->closed && (st = xqc_moqt_stream_next(s)) != NULL) {
        if (s->tx_order == UINT64_MAX) {
            s->tx_order = 0;
            for (xqc_moqt_stream_t *p = s->streams; p != NULL; p = p->next) {
                p->tx_order = 0;
            }
        }
        st->tx_order = ++s->tx_order;
        xqc_int_t result = xqc_moqt_stream_flush_one(st);
        if (result < 0) {
            ret = result;
        }
    }
    s->flushing = 0;
    for (xqc_moqt_stream_t *st = head; st != NULL; st = st->next) {
        /* Retry notifications apply only to live object data streams. */
        if (s->closed
            || st->discarded
            || (st->kind != XQC_MOQT_STREAM_SUBGROUP
                && st->kind != XQC_MOQT_STREAM_FETCH))
        {
            continue;
        }
        /* Retry rejected data after draining accepted bytes, before FIN. */
        if (!st->state.data.blocked || st->tx_fin || !xqc_list_empty(&st->tx)) {
            continue;
        }
        st->state.data.blocked = 0;
        if (s->callbacks.on_writable != NULL) {
            s->callbacks.on_writable(s, st, s->user_data);
        }
    }
    xqc_moqt_datagram_writable(s);
    xqc_moqt_streams_release(head);
    return ret;
}

static uint64_t
xqc_moqt_control_message(xqc_moqt_stream_t *stream,
    const xqc_moqt_message_t *msg)
{
    xqc_moqt_session_t *s = stream->session;
    if (!s->setup_received) {
        if (msg->type != XQC_MOQT_MSG_SETUP) {
            return XQC_MOQT_PROTOCOL_VIOLATION;
        }
        xqc_moqt_kv_t options[XQC_MOQT_MAX_OPTIONS];
        xqc_moqt_token_t tokens[XQC_MOQT_MAX_OPTIONS];
        xqc_moqt_setup_t setup;
        uint64_t error = xqc_moqt_setup_decode(
            &msg->body, s->conn->conn_type == XQC_CONN_TYPE_SERVER,
            s->webtransport,
            &setup, options, tokens);
        if (error) {
            return error;
        }
        error = s->callbacks.on_setup(s, &setup, s->user_data);
        if (!error && !s->closed) {
            s->peer_limits = setup.limits;
            s->setup_received = 1;
            xqc_moqt_ready(s);
        }
        return error;
    }
    if (msg->type != XQC_MOQT_MSG_GOAWAY || s->goaway_received) {
        return XQC_MOQT_PROTOCOL_VIOLATION;
    }
    const uint8_t *p = msg->body.iov_base, *end = p + msg->body.iov_len;
    uint64_t len, timeout;
    xqc_int_t n = xqc_vi64_read(p, end, &len);
    if (n < 0
        || len > XQC_MOQT_GOAWAY_MAX_URI
        || (s->conn->conn_type == XQC_CONN_TYPE_SERVER
            && len != 0))
    {
        return XQC_MOQT_PROTOCOL_VIOLATION;
    }
    p += n;
    if (len > (size_t)(end - p)) {
        return XQC_MOQT_PROTOCOL_VIOLATION;
    }
    struct iovec uri = {(void *)p, (size_t)len};
    p += len;
    n = xqc_vi64_read(p, end, &timeout);
    if (n < 0 || p + n != end) {
        return XQC_MOQT_PROTOCOL_VIOLATION;
    }
    s->goaway_received = 1;
    if (s->callbacks.on_goaway != NULL) {
        s->callbacks.on_goaway(s, &uri, timeout, s->user_data);
    }
    return XQC_MOQT_NO_ERROR;
}

static xqc_int_t
xqc_moqt_stream_input_bytes(xqc_moqt_stream_t *stream, const uint8_t *data,
    size_t len, uint8_t fin)
{
    xqc_moqt_session_t *s = stream->session;
    xqc_var_buf_t *rx = &stream->rx;
    uint64_t error = XQC_MOQT_PROTOCOL_VIOLATION;
    if (s->closed
        || stream->discarded
        || stream->kind == XQC_MOQT_STREAM_PADDING)
    {
        return XQC_OK;
    }
    xqc_int_t request = stream->kind == XQC_MOQT_STREAM_REQUEST
        || (stream->transport_stream != NULL
            && xqc_stream_get_direction(stream->transport_stream)
               == XQC_STREAM_BIDI);
    if (len && stream->deadline == 0) {
        stream->deadline = xqc_monotonic_timestamp() + s->config.timeout;
    }
    size_t limit = xqc_min(XQC_MOQT_RX_LIMIT, s->config.max_buffered_bytes
        - (s->buffered_bytes - rx->buf_len));
    if (len > limit - rx->data_len) {
        error = XQC_MOQT_INTERNAL_ERROR;
        goto fail;
    }
    if (len > rx->buf_len - rx->data_len) {
        size_t old_cap = rx->buf_len;
        rx->limit = limit;
        if (xqc_var_buf_realloc(rx, rx->data_len + len) != XQC_OK) {
            error = XQC_MOQT_INTERNAL_ERROR;
            goto fail;
        }
        s->buffered_bytes += rx->buf_len - old_cap;
    }
    if (len) {
        xqc_memcpy(rx->data + rx->data_len, data, len);
        rx->data_len += len;
    }
    while (rx->data_len && !s->closed && !stream->discarded) {
        if (stream->kind == XQC_MOQT_STREAM_SUBGROUP
            || stream->kind == XQC_MOQT_STREAM_FETCH)
        {
            break;
        }
        if (!request && stream->kind == XQC_MOQT_STREAM_UNCLASSIFIED) {
            uint64_t type;
            xqc_int_t n = xqc_vi64_read(rx->data, rx->data + rx->data_len,
                                        &type);
            if (n < 0) {
                break;
            }
            if (type == XQC_MOQT_PADDING_STREAM) {
                stream->kind = XQC_MOQT_STREAM_PADDING;
                rx->data_len = 0;
                stream->deadline = 0;
                break;
            }
            if (type == XQC_MOQT_FETCH_STREAM) {
                stream->kind = XQC_MOQT_STREAM_FETCH;
                if (!s->ready) {
                    xqc_moqt_stream_cancel(stream, XQC_MOQT_RESET_CANCELLED);
                    return XQC_OK;
                }
                break;
            }
            if (type <= XQC_MOQT_SUBGROUP_TYPE_MAX
                && (type & XQC_MOQT_SUBGROUP_FIXED_MASK)
                   == XQC_MOQT_SUBGROUP_FIXED_BITS
                && (type & XQC_MOQT_SUBGROUP_MODE_MASK)
                   != XQC_MOQT_SUBGROUP_MODE_MASK)
            {
                stream->kind = XQC_MOQT_STREAM_SUBGROUP;
                if (!s->ready) {
                    xqc_moqt_stream_cancel(stream, XQC_MOQT_RESET_CANCELLED);
                    return XQC_OK;
                }
            }
            if (stream->kind == XQC_MOQT_STREAM_SUBGROUP) {
                break;
            }
            if (type != XQC_MOQT_MSG_SETUP || s->control_rx != NULL) {
                goto fail;
            }
            stream->kind = XQC_MOQT_STREAM_CONTROL;
            s->control_rx = stream;
        }
        if (fin && !request) {
            goto fail;
        }
        xqc_moqt_message_t msg;
        xqc_int_t n = xqc_moqt_frame_decode(rx->data, rx->data_len, &msg);
        if (n == -XQC_EAGAIN) {
            break;
        }
        if (n < 0) {
            goto fail;
        }
        error = request
            ? xqc_moqt_request_input(stream, rx->data, n)
            : xqc_moqt_control_message(stream, &msg);
        if (error) {
            goto fail;
        }
        rx->data_len -= n;
        memmove(rx->data, rx->data + n, rx->data_len);
        stream->deadline = rx->data_len
            ? xqc_monotonic_timestamp() + s->config.timeout : 0;
        error = XQC_MOQT_PROTOCOL_VIOLATION;
    }
    if (stream->kind == XQC_MOQT_STREAM_SUBGROUP
        || stream->kind == XQC_MOQT_STREAM_FETCH)
    {
        xqc_int_t ret = xqc_moqt_subgroup_input(stream, fin);
        xqc_moqt_timer_update(s);
        return ret;
    }
    if (fin && stream->kind == XQC_MOQT_STREAM_REQUEST && !s->closed) {
        xqc_moqt_request_fin(&stream->state.request);

    } else if (fin && stream->kind != XQC_MOQT_STREAM_PADDING && !s->closed) {
        goto fail;
    }
    xqc_moqt_timer_update(s);
    return XQC_OK;
fail:
    if (error == XQC_MOQT_INTERNAL_ERROR
        && stream->kind == XQC_MOQT_STREAM_FETCH)
    {
        xqc_moqt_stream_cancel(stream, XQC_MOQT_RESET_EXCESSIVE_LOAD);
        return -XQC_EMALLOC;
    }
    if (error == XQC_MOQT_INTERNAL_ERROR
        && stream->kind == XQC_MOQT_STREAM_REQUEST)
    {
        xqc_moqt_request_cancel(&stream->state.request,
                                XQC_MOQT_RESET_EXCESSIVE_LOAD);
        return -XQC_EMALLOC;
    }
    xqc_moqt_session_close(s, error);
    return -XQC_EILLEGAL_FRAME;
}

xqc_int_t
xqc_moqt_stream_input(xqc_moqt_stream_t *st, const uint8_t *data,
    size_t len, uint8_t fin)
{
    st->active++;
    xqc_int_t ret = xqc_moqt_stream_input_bytes(st, data, len, fin);
    st->active--;
    if (!st->active
        && !st->reading
        && !st->writing
        && st->transport_stream == NULL)
    {
        xqc_moqt_stream_callbacks.stream_close_notify(NULL, st);
    }
    return ret;
}

void
xqc_moqt_timer_update(xqc_moqt_session_t *s)
{
    if (s->closed) {
        return;
    }
    xqc_usec_t next = s->setup_deadline;
    if (s->goaway_deadline && (!next || s->goaway_deadline < next)) {
        next = s->goaway_deadline;
    }
    for (xqc_moqt_stream_t *st = s->streams; st != NULL; st = st->next) {
        if (st->kind == XQC_MOQT_STREAM_REQUEST) {
            xqc_moqt_request_t *r = &st->state.request;
            if (r->response_deadline
                && (!next
                    || r->response_deadline < next))
            {
                next = r->response_deadline;
            }
            if (r->goaway_deadline && (!next || r->goaway_deadline < next)) {
                next = r->goaway_deadline;
            }
        }
        if (st->kind == XQC_MOQT_STREAM_SUBGROUP) {
            xqc_usec_t delivery = xqc_moqt_subgroup_deadline(st);
            if (delivery && (!next || delivery < next)) {
                next = delivery;
            }
        }
        if (st->deadline && (!next || st->deadline < next)) {
            next = st->deadline;
        }
    }
    for (xqc_moqt_subscription_t *sub = s->subscriptions; sub != NULL;
         sub = sub->next)
    {
        if (sub->close_deadline && (!next || sub->close_deadline < next)) {
            next = sub->close_deadline;
        }
    }
    for (xqc_moqt_fetch_t *f = s->fetches; f != NULL; f = f->next) {
        if (f->deadline && (!next || f->deadline < next)) {
            next = f->deadline;
        }
    }
    if (next) {
        xqc_conn_gp_timer_set(s->conn, s->timer, next);
    }
}

void
xqc_moqt_session_timeout(xqc_gp_timer_id_t id, xqc_usec_t now, void *data)
{
    xqc_moqt_session_t *s = data;
    if (s->closed) {
        return;
    }
    if (s->goaway_deadline && now >= s->goaway_deadline) {
        /* Section 9.2: the advertised session drain deadline has elapsed. */
        xqc_moqt_session_close(s, XQC_MOQT_NO_ERROR);
        return;
    }
    if (s->setup_deadline && now >= s->setup_deadline) {
        xqc_moqt_session_close(s, XQC_MOQT_CONTROL_MESSAGE_TIMEOUT);
        return;
    }
    /* A callback may cancel another stream or its orphaned Subscription. */
    xqc_moqt_stream_t *head = xqc_moqt_streams_hold(s);
    xqc_moqt_subscription_t *subs = xqc_moqt_subscriptions_hold(s);
    for (xqc_moqt_stream_t *st = head, *next; st != NULL; st = next) {
        next = st->next;
        if (st->kind == XQC_MOQT_STREAM_REQUEST) {
            xqc_moqt_request_t *r = &st->state.request;
            if ((st->deadline
                    && now >= st->deadline)
                || (r->response_deadline
                    && now >= r->response_deadline)
                || (r->goaway_deadline
                    && now >= r->goaway_deadline))
            {
                xqc_moqt_request_cancel(r, XQC_MOQT_RESET_CANCELLED);
            }
        } else if (st->kind == XQC_MOQT_STREAM_SUBGROUP) {
            xqc_usec_t delivery = xqc_moqt_subgroup_deadline(st);
            if (delivery && now >= delivery) {
                xqc_moqt_stream_cancel(st, XQC_MOQT_RESET_DELIVERY_TIMEOUT);
            } else if (st->deadline && now >= st->deadline) {
                xqc_moqt_stream_cancel(st, XQC_MOQT_RESET_CANCELLED);
            }
        } else if (st->kind == XQC_MOQT_STREAM_FETCH) {
            if (st->deadline && now >= st->deadline) {
                if (st->state.data.reset_pending) {
                    /* Cannot silently discard an unidentifiable Fill reset. */
                    xqc_moqt_session_close(s, XQC_MOQT_INTERNAL_ERROR);
                    break;
                }
                xqc_moqt_stream_cancel(st, XQC_MOQT_RESET_CANCELLED);
            }
        } else if (st->deadline && now >= st->deadline) {
            xqc_moqt_session_close(s, XQC_MOQT_CONTROL_MESSAGE_TIMEOUT);
            break;
        }
    }
    for (xqc_moqt_subscription_t *sub = subs; sub != NULL; sub = sub->next) {
        if (sub->close_deadline && now >= sub->close_deadline) {
            xqc_moqt_subscription_close(sub);
        }
    }
    /* Restart after callbacks, which may cancel another orphaned Fetch. */
    for (;;) {
        xqc_moqt_fetch_t *f = s->fetches;
        while (f != NULL && (!f->deadline || now < f->deadline)) {
            f = f->next;
        }
        if (f == NULL) {
            break;
        }
        xqc_moqt_fetch_cancel(f, XQC_MOQT_RESET_CANCELLED);
    }
    xqc_moqt_timer_update(s);
    xqc_moqt_subscriptions_release(subs);
    xqc_moqt_streams_release(head);
}

static xqc_int_t
xqc_moqt_session_check_params(xqc_connection_t *conn,
    const xqc_moqt_config_t *config, const xqc_moqt_callbacks_t *callbacks,
    xqc_bool_t webtransport)
{
    /* No connection logger is available for a NULL connection. */
    if (conn == NULL) {
        return XQC_ERROR;
    }

    const char *reason = NULL;
    const char *alpn = xqc_moqt_config_alpn(config);
    const xqc_stream_callbacks_t *cbs = &conn->app_proto_cbs.stream_cbs;
    if (config == NULL) {
        reason = "config is NULL";
    } else if (alpn == NULL) {
        reason = "unsupported protocol version";
    } else if (!webtransport
               && (conn->alpn == NULL || strcmp(conn->alpn, alpn) != 0))
    {
        reason = "connection ALPN does not match configured version";
    } else if (!webtransport
               && (conn->proto_data != NULL || conn->dgram_data != NULL))
    {
        reason = "connection already has application data";
    } else if (callbacks == NULL || callbacks->on_setup == NULL) {
        reason = "on_setup callback is required";
    } else if (config->max_streams < XQC_MOQT_CONTROL_STREAM_COUNT) {
        reason = "max_streams cannot hold both control streams";
    } else if (config->max_buffered_bytes < XQC_MOQT_TX_OVERHEAD) {
        reason = "max_buffered_bytes cannot hold a TX queue entry";
    } else if (config->timeout == 0) {
        reason = "timeout must be nonzero";
    } else if (config->timeout > UINT64_MAX - xqc_monotonic_timestamp()) {
        reason = "timeout overflows the deadline";
    } else if (config->setup_option_count > XQC_MOQT_MAX_OPTIONS) {
        reason = "too many SETUP options";
    } else if (config->setup_option_count && config->setup_options == NULL) {
        reason = "SETUP options are NULL with a nonzero count";
    } else if (!webtransport && cbs->stream_read_notify
               != xqc_moqt_stream_callbacks.stream_read_notify)
    {
        reason = "stream_read_notify is not the MoQT adapter";
    } else if (!webtransport && cbs->stream_create_notify
               != xqc_moqt_stream_callbacks.stream_create_notify)
    {
        reason = "stream_create_notify is not the MoQT adapter";
    } else if (!webtransport && cbs->stream_close_notify
               != xqc_moqt_stream_callbacks.stream_close_notify)
    {
        reason = "stream_close_notify is not the MoQT adapter";
    } else if (!webtransport && cbs->stream_write_notify
               != xqc_moqt_stream_callbacks.stream_write_notify)
    {
        reason = "stream_write_notify is not the MoQT adapter";
    } else if (!webtransport && cbs->stream_closing_notify
               != xqc_moqt_stream_callbacks.stream_closing_notify)
    {
        reason = "stream_closing_notify is not the MoQT adapter";
    } else if (!webtransport && cbs->stream_stop_sending_notify
               != xqc_moqt_stream_callbacks.stream_stop_sending_notify)
    {
        reason = "stream_stop_sending_notify is not the MoQT adapter";
    } else if (!webtransport
               && conn->app_proto_cbs.dgram_cbs.datagram_read_notify
               != xqc_moqt_datagram_callbacks.datagram_read_notify)
    {
        reason = "datagram_read_notify is not the MoQT adapter";
    }
    if (reason != NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|invalid session params|%s|",
                reason);
        return XQC_ERROR;
    }
    return XQC_OK;
}

xqc_moqt_session_t *
xqc_moqt_session_create_transport(xqc_connection_t *conn,
    const xqc_moqt_config_t *config, const xqc_moqt_callbacks_t *callbacks,
    void *user_data, xqc_bool_t webtransport)
{
    if (xqc_moqt_session_check_params(conn, config, callbacks, webtransport)
        != XQC_OK)
    {
        return NULL;
    }
    xqc_moqt_session_t *s = xqc_calloc(1, sizeof(*s));
    if (s == NULL) {
        return NULL;
    }
    s->conn = conn;
    s->webtransport = webtransport;
    s->next_request_id = conn->conn_type == XQC_CONN_TYPE_CLIENT
        ? XQC_MOQT_CLIENT_FIRST_REQUEST_ID : XQC_MOQT_SERVER_FIRST_REQUEST_ID;
    s->config = *config;
    s->config.setup_options = NULL;
    s->config.setup_option_count = 0;
    s->callbacks = *callbacks;
    s->user_data = user_data;
    xqc_moqt_kv_t options[XQC_MOQT_MAX_OPTIONS];
    size_t count = config->setup_option_count, len = 0;
    if (count) {
        xqc_memcpy(options, config->setup_options, count * sizeof(*options));
    }
    /* A missing local update limit defaults to 16; zero stays unlimited. */
    size_t insert = 0;
    while (insert < count
           && options[insert].type < XQC_MOQT_OPT_MAX_REQUEST_UPDATES)
    {
        insert++;
    }
    if (insert == count
        || options[insert].type != XQC_MOQT_OPT_MAX_REQUEST_UPDATES)
    {
        if (count == XQC_MOQT_MAX_OPTIONS) {
            goto fail;
        }
        memmove(options + insert + 1, options + insert,
                    (count - insert) * sizeof(*options));
        options[insert].type = XQC_MOQT_OPT_MAX_REQUEST_UPDATES;
        options[insert].value.integer = XQC_MOQT_DEFAULT_REQUEST_UPDATES;
        count++;
    }
    uint64_t previous = 0;
    for (size_t i = 0; i < count; i++) {
        xqc_int_t n = xqc_moqt_kv_encode(&options[i], previous, NULL, 0);
        if (n < 0 || (size_t)n > XQC_MOQT_MESSAGE_MAX_BODY - len) {
            goto fail;
        }
        len += n;
        previous = options[i].type;
    }
    size_t header = xqc_vi64_len(XQC_MOQT_MSG_SETUP) + sizeof(uint16_t);
    s->setup = xqc_moqt_buffer_create(s, header + len, sizeof(xqc_var_buf_t));
    if (s->setup == NULL) {
        goto fail;
    }
    uint8_t *p = s->setup->data + header;
    struct iovec body = {p, len};
    previous = 0;
    for (size_t i = 0; i < count; i++) {
        xqc_int_t n = xqc_moqt_kv_encode(&options[i], previous, p, len);
        p += n;
        len -= n;
        previous = options[i].type;
    }
    s->setup->data_len = p - s->setup->data;
    xqc_moqt_message_t msg = {XQC_MOQT_MSG_SETUP, body};
    xqc_moqt_frame_encode(&msg, s->setup->data, s->setup->data_len);
    xqc_moqt_token_t tokens[XQC_MOQT_MAX_OPTIONS];
    xqc_moqt_setup_t setup;
    if (xqc_moqt_setup_decode(
        &body, conn->conn_type == XQC_CONN_TYPE_CLIENT, webtransport,
        &setup, options, tokens)
        || setup.limits.max_auth_token_cache
        || setup.limits.max_filter_ranges)
    {
        goto fail;
    }
    s->local_limits = setup.limits;
    s->timer = xqc_conn_register_gp_timer(conn, "moqt",
                                          xqc_moqt_session_timeout, s);
    if (s->timer < 0) {
        goto fail;
    }
    s->setup_deadline = xqc_monotonic_timestamp() + config->timeout;
    xqc_moqt_timer_update(s);
    if (!webtransport) {
        xqc_conn_set_alp_user_data(conn, s);
        xqc_datagram_set_user_data(conn, s);
    }
    return s;
fail:
    xqc_moqt_buffer_free(s, s->setup, sizeof(xqc_var_buf_t));
    xqc_free(s);
    return NULL;
}

xqc_int_t
xqc_moqt_session_start(xqc_moqt_session_t *s)
{
    if (s == NULL
        || s->closed
        || s->started
        || !(s->conn->conn_flag & XQC_CONN_FLAG_HANDSHAKE_COMPLETED))
    {
        return -XQC_EPARAM;
    }
    if (!s->conn->local_settings.max_datagram_frame_size
        || !s->conn->remote_settings.max_datagram_frame_size)
    {
        xqc_moqt_session_close(s, XQC_MOQT_PROTOCOL_VIOLATION);
        return -XQC_EPARAM;
    }
    xqc_moqt_stream_t *stream = xqc_moqt_transport_open(s, XQC_STREAM_UNI);
    if (stream == NULL || s->closed) {
        xqc_moqt_session_close(s, XQC_MOQT_INTERNAL_ERROR);
        return -XQC_EMALLOC;
    }
    /* The adapter allocates the context in stream_create_notify. */
    s->control_tx = stream;
    s->control_tx->kind = XQC_MOQT_STREAM_CONTROL;
    if (xqc_moqt_queue(s, &s->control_tx->tx, s->setup) != XQC_OK) {
        xqc_moqt_session_close(s, XQC_MOQT_INTERNAL_ERROR);
        return -XQC_EMALLOC;
    }
    s->setup = NULL;
    s->started = 1;
    return xqc_moqt_stream_flush(s->control_tx);
}

xqc_int_t
xqc_moqt_session_goaway(xqc_moqt_session_t *s, const struct iovec *uri,
    uint64_t timeout_ms)
{
    xqc_usec_t now = xqc_monotonic_timestamp();
    if (s == NULL
        || !s->ready
        || s->closed
        || s->goaway_sent
        || uri == NULL
        || uri->iov_len > XQC_MOQT_GOAWAY_MAX_URI
        || (uri->iov_len
            && (uri->iov_base == NULL
                || s->conn->conn_type == XQC_CONN_TYPE_CLIENT))
        || timeout_ms > (UINT64_MAX - now) / XQC_MOQT_MICROS_PER_MILLISECOND)
    {
        return -XQC_EPARAM;
    }
    size_t len = xqc_vi64_len(uri->iov_len) + uri->iov_len
                 + xqc_vi64_len(timeout_ms);
    size_t header = xqc_vi64_len(XQC_MOQT_MSG_GOAWAY) + sizeof(uint16_t);
    xqc_var_buf_t *buf = xqc_moqt_buffer_create(s, header + len,
                                                sizeof(xqc_var_buf_t));
    if (buf == NULL) {
        return -XQC_EMALLOC;
    }
    uint8_t *p = buf->data + header, *end = p + len;
    p += xqc_vi64_write(p, end, uri->iov_len);
    if (uri->iov_len) {
        xqc_memcpy(p, uri->iov_base, uri->iov_len);
        p += uri->iov_len;
    }
    p += xqc_vi64_write(p, end, timeout_ms);
    buf->data_len = p - buf->data;
    xqc_moqt_message_t msg = {XQC_MOQT_MSG_GOAWAY,
        {buf->data + header, len}};
    xqc_moqt_frame_encode(&msg, buf->data, buf->data_len);
    if (xqc_moqt_queue(s, &s->control_tx->tx, buf) != XQC_OK) {
        xqc_moqt_buffer_free(s, buf, sizeof(xqc_var_buf_t));
        return -XQC_EMALLOC;
    }
    s->goaway_sent = 1;
    s->goaway_deadline = timeout_ms
        ? now + timeout_ms * XQC_MOQT_MICROS_PER_MILLISECOND : 0;
    xqc_moqt_timer_update(s);
    return xqc_moqt_stream_flush(s->control_tx);
}

void
xqc_moqt_session_destroy(xqc_moqt_session_t *s)
{
    if (s == NULL) {
        return;
    }
    xqc_moqt_notify_closed(s, xqc_conn_get_errno(s->conn));
#ifdef XQC_ENABLE_WEBTRANSPORT
    if (s->webtransport) {
        xqc_moqt_webtransport_detach(s);
    }
#endif
    if (s->timer >= 0) {
        xqc_conn_unregister_gp_timer(s->conn, s->timer);
    }
    while (s->streams != NULL) {
        xqc_moqt_stream_t *st = s->streams;
        xqc_moqt_stream_callbacks.stream_close_notify(st->transport_stream, st);
    }
    while (s->subscriptions != NULL) {
        xqc_moqt_subscription_cancel(s->subscriptions,
                                     XQC_MOQT_RESET_SESSION_CLOSED);
    }
    while (s->fetches != NULL) {
        xqc_moqt_fetch_cancel(s->fetches, XQC_MOQT_RESET_SESSION_CLOSED);
    }
    xqc_moqt_buffer_free(s, s->setup, sizeof(xqc_var_buf_t));
    if (!s->webtransport) {
        xqc_conn_set_alp_user_data(s->conn, NULL);
        xqc_datagram_set_user_data(s->conn, NULL);
    }
    xqc_free(s);
}

xqc_moqt_session_t *
xqc_moqt_session_create(xqc_connection_t *conn,
    const xqc_moqt_config_t *config, const xqc_moqt_callbacks_t *callbacks,
    void *data)
{
    return xqc_moqt_session_create_transport(conn, config, callbacks, data,
                                             XQC_FALSE);
}
