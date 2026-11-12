/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include "xqc_moqt_session.h"
#include "xqc_moqt_codec.h"
#include "src/transport/xqc_stream.h"

/* Unlike ACK history, request history must never evict an old ID (6.4.2.1). */
static uint64_t
xqc_moqt_record_id(xqc_moqt_session_t *s, uint64_t id)
{
    unsigned peer = s->conn->conn_type == XQC_CONN_TYPE_CLIENT
        ? XQC_MOQT_SERVER_FIRST_REQUEST_ID : XQC_MOQT_CLIENT_FIRST_REQUEST_ID;
    if ((id & XQC_MOQT_REQUEST_ID_PARITY_MASK) != peer) {
        return XQC_MOQT_INVALID_REQUEST_ID;
    }
    id /= XQC_MOQT_REQUEST_ID_STEP;
    size_t i = 0;
    while (i < s->request_id_ranges && s->request_ids[i].high < id) {
        i++;
    }
    if (i < s->request_id_ranges && s->request_ids[i].low <= id) {
        return XQC_MOQT_INVALID_REQUEST_ID;
    }
    if (i && s->request_ids[i - 1].high + 1 == id) {
        s->request_ids[i - 1].high = id;
        if (i < s->request_id_ranges && s->request_ids[i].low == id + 1) {
            s->request_ids[i - 1].high = s->request_ids[i].high;
            memmove(s->request_ids + i, s->request_ids + i + 1,
                (--s->request_id_ranges - i) * sizeof(s->request_ids[0]));
        }
    } else if (i < s->request_id_ranges && s->request_ids[i].low == id + 1) {
        s->request_ids[i].low = id;
    } else {
        if (s->request_id_ranges == XQC_MOQT_REQUEST_ID_RANGES) {
            return XQC_MOQT_INTERNAL_ERROR;
        }
        memmove(s->request_ids + i + 1, s->request_ids + i,
                (s->request_id_ranges++ - i) * sizeof(s->request_ids[0]));
        s->request_ids[i].low = s->request_ids[i].high = id;
    }
    return XQC_MOQT_NO_ERROR;
}

static void
xqc_moqt_copy_bytes(xqc_var_buf_t *buf, struct iovec *bytes)
{
    if (bytes->iov_len) {
        xqc_memcpy(buf->data + buf->data_len, bytes->iov_base, bytes->iov_len);
    }
    bytes->iov_base = buf->data + buf->data_len;
    buf->data_len += bytes->iov_len;
}

/* One owned snapshot; names/parameters continue to use the existing views. */
static xqc_var_buf_t *
xqc_moqt_request_snapshot(xqc_moqt_session_t *s,
    const xqc_moqt_message_t *message)
{
    size_t len = sizeof(*message) + message->track_name.iov_len
                 + message->properties.iov_len;
    for (size_t i = 0; i < message->track_namespace.count; i++) {
        len += message->track_namespace.fields[i].iov_len;
    }
    for (size_t i = 0; i < message->parameter_count; i++) {
        len += message->parameters[i].length;
    }
    xqc_var_buf_t *buf = xqc_moqt_buffer_create(s, len, sizeof(*buf));
    if (buf == NULL) {
        return NULL;
    }
    xqc_moqt_message_t *m = (void *)buf->data;
    *m = *message;
    buf->data_len = sizeof(*m);
    xqc_memzero(&m->body, sizeof(m->body));
    xqc_memzero(&m->reason, sizeof(m->reason));
    xqc_memzero(&m->uri, sizeof(m->uri));
    for (size_t i = 0; i < m->track_namespace.count; i++) {
        xqc_moqt_copy_bytes(buf, &m->track_namespace.fields[i]);
    }
    xqc_moqt_copy_bytes(buf, &m->track_name);
    xqc_moqt_copy_bytes(buf, &m->properties);
    for (size_t i = 0; i < m->parameter_count; i++) {
        struct iovec bytes = {m->parameters[i].value, m->parameters[i].length};
        xqc_moqt_copy_bytes(buf, &bytes);
        m->parameters[i].value = bytes.iov_base;
    }
    return buf;
}

static xqc_int_t
xqc_moqt_merge(xqc_moqt_message_t *state, const xqc_moqt_message_t *update)
{
    xqc_moq_message_parameter_t merged[XQC_MOQT_MAX_PARAMETERS];
    size_t i = 0, j = 0, count = 0;
    while (i < state->parameter_count || j < update->parameter_count) {
        const xqc_moq_message_parameter_t *p;
        if (j == update->parameter_count
            || (i < state->parameter_count
                && state->parameters[i].type < update->parameters[j].type))
        {
            p = &state->parameters[i++];
        } else {
            p = &update->parameters[j++];
            while (i < state->parameter_count
                   && state->parameters[i].type == p->type)
            {
                i++;
            }
        }
        /* Section 9.20.15: fill is per-message, not sticky state. */
        if (p->type == XQC_MOQT_PARAM_FILL_PARAMETERS) {
            continue;
        }
        if (p->type == XQC_MOQT_PARAM_TRACK_NAMESPACE_PREFIX) {
            if (xqc_moqt_name_decode(p->value, p->length,
                                     &state->track_namespace, NULL) < 0)
            {
                return -XQC_EPARAM;
            }
            continue;
        }
        if (count == XQC_MOQT_MAX_PARAMETERS) {
            return -XQC_ELIMIT;
        }
        merged[count++] = *p;
    }
    xqc_memcpy(state->parameters, merged, count * sizeof(merged[0]));
    state->parameter_count = count;
    return XQC_OK;
}

/* Draft-22 sections 4.2/9.5.2: only same-type discovery interests overlap. */
static xqc_int_t
xqc_moqt_namespace_overlap(xqc_moqt_request_t *r,
    const xqc_moqt_namespace_t *prefix)
{
    if (r->initial_type != XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE) {
        return 0;
    }
    for (xqc_moqt_stream_t *st = r->stream->session->streams; st != NULL;
         st = st->next)
    {
        if (st->kind != XQC_MOQT_STREAM_REQUEST || st->discarded) {
            continue;
        }
        xqc_moqt_request_t *other = &st->state.request;
        if (other == r
            || other->local != r->local
            || other->initial_type != r->initial_type
            || !other->established
            || other->failed
            || (other->local ? st->rx_fin : st->tx_fin))
        {
            continue;
        }
        const xqc_moqt_message_t *state = (void *)other->state->data;
        if (xqc_moqt_namespace_prefix(prefix, &state->track_namespace)
            || xqc_moqt_namespace_prefix(&state->track_namespace, prefix))
        {
            return 1;
        }
    }
    return 0;
}

static void
xqc_moqt_namespace_remove(xqc_moqt_request_t *r, xqc_list_buf_t *entry)
{
    xqc_moqt_session_t *s = r->stream->session;
    xqc_moqt_namespace_t name;
    xqc_moqt_name_decode(entry->buf->data, entry->buf->data_len, &name, NULL);
    /* Remove before a callback can cancel/re-enter; retain borrowed bytes. */
    xqc_list_del_init(&entry->list_head);
    if (r->local && s->callbacks.on_namespace != NULL) {
        s->callbacks.on_namespace(r, &name, XQC_FALSE, s->user_data);
    }
    xqc_moqt_dequeue(s, entry);
}

static void
xqc_moqt_namespaces_clear(xqc_moqt_request_t *r)
{
    while (!xqc_list_empty(&r->namespaces)) {
        xqc_moqt_namespace_remove(r, xqc_list_entry(r->namespaces.next,
                                                    xqc_list_buf_t,
                                                    list_head));
    }
}

/* Prepare an atomic set change before queuing a notification on the wire. */
static xqc_int_t
xqc_moqt_namespace_prepare(xqc_moqt_request_t *r,
    const xqc_moqt_message_t *m, xqc_list_buf_t **entry, xqc_bool_t *added)
{
    const xqc_moqt_message_t *state = (void *)r->state->data;
    xqc_moqt_namespace_t name = state->track_namespace;
    const xqc_moqt_namespace_t *suffix = &m->track_namespace;
    *entry = NULL;
    *added = XQC_FALSE;
    if (suffix->count > XQC_MOQT_NAMESPACE_MAX_FIELDS - name.count) {
        return -XQC_EPARAM;
    }
    xqc_memcpy(name.fields + name.count, suffix->fields,
                suffix->count * sizeof(suffix->fields[0]));
    name.count += suffix->count;
    xqc_int_t n = xqc_moqt_name_encode(&name, NULL, NULL, 0);
    if (n < 0) {
        return -XQC_EPARAM;
    }
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &r->namespaces) {
        xqc_list_buf_t *item = xqc_list_entry(pos, xqc_list_buf_t, list_head);
        xqc_moqt_namespace_t known;
        xqc_moqt_name_decode(item->buf->data, item->buf->data_len, &known,
                             NULL);
        if (known.count == name.count
            && xqc_moqt_namespace_prefix(&known, &name))
        {
            *entry = item;
            return XQC_OK;
        }
    }
    if (m->type == XQC_MOQT_MSG_NAMESPACE_DONE) {
        return -XQC_EPARAM;
    }
    xqc_moqt_session_t *s = r->stream->session;
    xqc_var_buf_t *buf = xqc_moqt_buffer_create(s, n, sizeof(*buf));
    if (buf == NULL) {
        return -XQC_EMALLOC;
    }
    xqc_moqt_name_encode(&name, NULL, buf->data, n);
    buf->data_len = n;
    if (xqc_moqt_queue(s, &r->namespaces, buf) != XQC_OK) {
        xqc_moqt_buffer_free(s, buf, sizeof(*buf));
        return -XQC_EMALLOC;
    }
    *entry = xqc_list_entry(r->namespaces.prev, xqc_list_buf_t, list_head);
    *added = XQC_TRUE;
    return XQC_OK;
}

static void
xqc_moqt_namespace_notify(xqc_moqt_request_t *r, xqc_list_buf_t *entry,
    xqc_bool_t added, uint64_t type)
{
    xqc_moqt_session_t *s = r->stream->session;
    if (type == XQC_MOQT_MSG_NAMESPACE_DONE) {
        xqc_moqt_namespace_remove(r, entry);
    } else if (added && r->local && s->callbacks.on_namespace != NULL) {
        xqc_moqt_namespace_t name;
        xqc_moqt_name_decode(entry->buf->data, entry->buf->data_len, &name,
                             NULL);
        /* A reentrant cancellation can free entry; borrow from a snapshot. */
        uint8_t bytes[XQC_MOQT_NAME_MAX_LEN];
        size_t offset = 0;
        for (size_t i = 0; i < name.count; i++) {
            xqc_memcpy(bytes + offset, name.fields[i].iov_base,
                        name.fields[i].iov_len);
            name.fields[i].iov_base = bytes + offset;
            offset += name.fields[i].iov_len;
        }
        s->callbacks.on_namespace(r, &name, XQC_TRUE, s->user_data);
    }
}

static xqc_int_t
xqc_moqt_commit_update(xqc_moqt_request_t *r, xqc_list_head_t *head,
    const xqc_moqt_message_t *reply)
{
    xqc_list_buf_t *entry = xqc_list_entry(head->next, xqc_list_buf_t,
                                           list_head);
    xqc_moqt_message_t candidate = *(xqc_moqt_message_t *)r->state->data;
    xqc_moqt_session_t *s = r->stream->session;
    if (xqc_moqt_merge(&candidate, (void *)entry->buf->data) != XQC_OK) {
        return -XQC_ELIMIT;
    }
    xqc_var_buf_t *state = xqc_moqt_request_snapshot(s, &candidate);
    if (state == NULL) {
        return -XQC_EMALLOC;
    }
    if (xqc_moqt_subscription_apply(r, reply) != XQC_MOQT_NO_ERROR
        || xqc_moqt_subscription_apply(r, (void *)entry->buf->data)
           != XQC_MOQT_NO_ERROR
        || xqc_moqt_fetch_apply(r, (void *)entry->buf->data)
           != XQC_MOQT_NO_ERROR)
    {
        xqc_moqt_buffer_free(s, state, sizeof(*state));
        return -XQC_EPARAM;
    }
    if (xqc_moqt_fill_apply(r, &candidate, (void *)entry->buf->data,
                            reply) != XQC_MOQT_NO_ERROR)
    {
        xqc_moqt_buffer_free(s, state, sizeof(*state));
        return -XQC_EPARAM;
    }
    xqc_moqt_buffer_free(s, r->state, sizeof(*r->state));
    r->state = state;
    xqc_moqt_dequeue(s, entry);
    return XQC_OK;
}

static void
xqc_moqt_request_init(xqc_moqt_stream_t *st, const xqc_moqt_message_t *m,
    xqc_int_t local)
{
    xqc_moqt_request_t *r = &st->state.request;
    st->kind = XQC_MOQT_STREAM_REQUEST;
    r->stream = st;
    r->initial_type = m->type;
    r->initial_request_id = m->request_id;
    r->local = local;
    xqc_init_list_head(&r->sent_updates);
    xqc_init_list_head(&r->received_updates);
    xqc_init_list_head(&r->namespaces);
}

xqc_int_t
xqc_moqt_is_local_publisher(const xqc_moqt_request_t *r)
{
    return r->initial_type == XQC_MOQT_MSG_PUBLISH ? r->local
           : r->initial_type == XQC_MOQT_MSG_SUBSCRIBE && !r->local;
}

static uint64_t
xqc_moqt_response_type(uint64_t initial)
{
    return initial == XQC_MOQT_MSG_SUBSCRIBE ? XQC_MOQT_MSG_SUBSCRIBE_OK
           : initial == XQC_MOQT_MSG_FETCH ? XQC_MOQT_MSG_FETCH_OK
           : XQC_MOQT_MSG_REQUEST_OK;
}

static xqc_int_t
xqc_moqt_is_update_allowed(const xqc_moqt_request_t *r, xqc_int_t sending)
{
    xqc_int_t initiator = sending ? r->local : !r->local;
    return r->initial_type != XQC_MOQT_MSG_TRACK_STATUS
           && (initiator || (r->initial_type == XQC_MOQT_MSG_PUBLISH
                             && r->responded));
}

uint64_t
xqc_moqt_request_id(const xqc_moqt_request_t *request)
{
    return request->initial_request_id;
}

static void
xqc_moqt_assign_id(xqc_moqt_session_t *s, xqc_moqt_message_t *m)
{
    m->request_id = s->next_request_id;
    if (s->next_request_id > UINT64_MAX - XQC_MOQT_REQUEST_ID_STEP) {
        s->request_ids_exhausted = 1;
    } else {
        s->next_request_id += XQC_MOQT_REQUEST_ID_STEP;
    }
}

static xqc_int_t
xqc_moqt_request_queue(xqc_moqt_request_t *r, const xqc_moqt_message_t *m,
    uint64_t context)
{
    xqc_moqt_session_t *s = r->stream->session;
    xqc_int_t n = xqc_moqt_message_encode(m, context, NULL, 0);
    if (n < 0) {
        return n;
    }
    xqc_var_buf_t *buf = xqc_moqt_buffer_create(s, n, sizeof(*buf));
    if (buf == NULL) {
        return -XQC_EMALLOC;
    }
    xqc_moqt_message_encode(m, context, buf->data, n);
    buf->data_len = n;
    xqc_int_t ret = xqc_moqt_queue(s, &r->stream->tx, buf);
    if (ret != XQC_OK) {
        xqc_moqt_buffer_free(s, buf, sizeof(*buf));
    }
    return ret;
}

xqc_moqt_request_t *
xqc_moqt_request_open(xqc_moqt_session_t *s, const xqc_moqt_message_t *message)
{
    if (s == NULL
        || !s->ready
        || s->closed
        || s->goaway_sent
        || s->goaway_received
        || s->request_ids_exhausted
        || message == NULL
        || !xqc_moqt_is_initial_request(message->type)
        || xqc_moqt_message_encode(message, message->type, NULL, 0) < 0)
    {
        return NULL;
    }
    xqc_moqt_message_t m = *message;
    xqc_moqt_assign_id(s, &m);
    xqc_var_buf_t *state = xqc_moqt_request_snapshot(s, &m);
    if (state == NULL) {
        return NULL;
    }
    xqc_stream_t *transport = xqc_stream_create_with_direction(s->conn,
                                                               XQC_STREAM_BIDI,
                                                               NULL);
    if (transport == NULL || s->closed) {
        xqc_moqt_buffer_free(s, state, sizeof(*state));
        return NULL;
    }
    xqc_moqt_stream_t *st = transport->user_data;
    xqc_moqt_request_init(st, &m, 1);
    xqc_moqt_request_t *r = &st->state.request;
    r->state = state;
    if (xqc_moqt_subscription_create(r, &m) != XQC_MOQT_NO_ERROR
        || xqc_moqt_fetch_create(r, &m) != XQC_MOQT_NO_ERROR)
    {
        xqc_moqt_request_cancel(r, XQC_MOQT_RESET_EXCESSIVE_LOAD);
        return NULL;
    }
    if (m.type == XQC_MOQT_MSG_PUBLISH) {
        m.track_alias = r->subscription->track_alias;
        ((xqc_moqt_message_t *)r->state->data)->track_alias = m.track_alias;
    }
    if (xqc_moqt_request_queue(r, &m, m.type) != XQC_OK) {
        xqc_moqt_request_cancel(r, XQC_MOQT_RESET_EXCESSIVE_LOAD);
        return NULL;
    }
    r->response_deadline = xqc_monotonic_timestamp()
                                   + s->config.timeout;
    xqc_moqt_timer_update(s);
    /* The stream owns this handle until on_request_closed returns. */
    st->active++;
    xqc_moqt_stream_flush(st);
    xqc_int_t usable = !s->closed && !st->discarded
                       && st->transport_stream != NULL;
    st->active--;
    if (!st->active
        && !st->reading
        && !st->writing
        && st->transport_stream == NULL)
    {
        xqc_moqt_stream_callbacks.stream_close_notify(NULL, st);
    }
    return usable ? r : NULL;
}

xqc_int_t
xqc_moqt_request_finish(xqc_moqt_request_t *r)
{
    if (r == NULL
        || r->stream->session->closed
        || r->stream->discarded
        || r->stream->tx_fin
        || (!r->failed
            && ((!r->local
                    && !r->responded)
                || r->pending_received_updates
                || (xqc_moqt_is_local_publisher(r)
                    && !r->done_sent))))
    {
        return -XQC_EPARAM;
    }
    xqc_moqt_stream_t *st = r->stream;
    xqc_moqt_session_t *s = st->session;
    xqc_var_buf_t *buf = xqc_moqt_buffer_create(s, 0, sizeof(*buf));
    if (buf == NULL) {
        return -XQC_EMALLOC;
    }
    buf->fin_flag = 1;
    if (xqc_moqt_queue(s, &st->tx, buf) != XQC_OK) {
        xqc_moqt_buffer_free(s, buf, sizeof(*buf));
        return -XQC_EMALLOC;
    }
    st->tx_fin = 1;
    if (!r->local) {
        xqc_moqt_namespaces_clear(r);
    }
    return xqc_moqt_stream_flush(st);
}

void
xqc_moqt_request_cancel(xqc_moqt_request_t *r, uint64_t error)
{
    if (r == NULL || r->stream->discarded) {
        return;
    }
    xqc_moqt_stream_t *st = r->stream;
    xqc_int_t writing = st->writing;
    st->writing = 1;
    r->failed = r->has_error = 1;
    r->error.context = XQC_MOQT_ERROR_RESET;
    r->error.code = error;
    r->error.normalized_code = xqc_moqt_error_normalize(r->error.context,
                                                        error);
    r->response_deadline = r->goaway_deadline = st->deadline = 0;
    st->discarded = 1;
    xqc_moqt_namespaces_clear(r);
    if (r->subscription != NULL) {
        xqc_moqt_subscription_cancel(r->subscription, error);
    }
    if (r->fetch != NULL) {
        xqc_moqt_fetch_cancel(r->fetch, error);
    }
    if (st->transport_stream != NULL) {
        xqc_stream_close_with_error(st->transport_stream, error);
    }
    st->writing = writing;
    if (!st->reading
        && !st->writing
        && !st->active
        && st->transport_stream == NULL)
    {
        xqc_moqt_stream_callbacks.stream_close_notify(NULL, st);
    }
}

/* Section 9.5.1: stop delivery before reporting UPDATE_FAILED. */
static void
xqc_moqt_update_failed(xqc_moqt_request_t *r)
{
    xqc_moqt_fetch_complete(r->fetch, &r->error);
    if (xqc_moqt_is_local_publisher(r) && r->established && !r->done_sent) {
        xqc_moqt_message_t done;
        xqc_memzero(&done, sizeof(done));
        done.type = XQC_MOQT_MSG_PUBLISH_DONE;
        done.error.code = XQC_MOQT_PUBLISH_UPDATE_FAILED;
        xqc_moqt_request_send(r, &done);
    }
    if (!r->stream->tx_fin) {
        xqc_moqt_request_finish(r);
    }
}

/* Section 3.4: an OK/notification snapshots the publisher's known Largest. */
static xqc_int_t
xqc_moqt_largest_append(xqc_moqt_request_t *r, xqc_moqt_message_t *m,
    uint8_t *bytes)
{
    xqc_moqt_subscription_t *sub = r->subscription;
    if (sub == NULL
        || !sub->track->local_publisher
        || !sub->track->has_largest)
    {
        return XQC_OK;
    }
    if (m->type != XQC_MOQT_MSG_SUBSCRIBE_OK
        && m->type != XQC_MOQT_MSG_REQUEST_OK
        && m->type != XQC_MOQT_MSG_PUBLISH_STATE_NOTIFY)
    {
        return XQC_OK;
    }
    if (m->parameter_count > XQC_MOQT_MAX_PARAMETERS) {
        return -XQC_ELIMIT;
    }
    size_t i = 0;
    while (i < m->parameter_count
           && m->parameters[i].type < XQC_MOQT_PARAM_LARGEST_OBJECT)
    {
        i++;
    }
    if (i < m->parameter_count
        && m->parameters[i].type == XQC_MOQT_PARAM_LARGEST_OBJECT)
    {
        return XQC_OK;
    }
    if (m->parameter_count == XQC_MOQT_MAX_PARAMETERS) {
        return -XQC_ELIMIT;
    }
    xqc_moqt_location_t *largest = &sub->track->largest;
    uint8_t *end = bytes + 2 * XQC_VI64_MAX_LEN;
    xqc_int_t n = xqc_vi64_write(bytes, end, largest->group_id);
    n += xqc_vi64_write(bytes + n, end, largest->object_id);
    memmove(m->parameters + i + 1, m->parameters + i,
            (m->parameter_count++ - i) * sizeof(m->parameters[0]));
    m->parameters[i] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_LARGEST_OBJECT, n, bytes};
    return XQC_OK;
}

static xqc_int_t
xqc_moqt_request_send_message(xqc_moqt_request_t *r,
    const xqc_moqt_message_t *message)
{
    if (r == NULL
        || message == NULL
        || r->stream->session->closed
        || r->stream->discarded
        || r->stream->tx_fin)
    {
        return -XQC_EPARAM;
    }
    xqc_moqt_stream_t *st = r->stream;
    xqc_moqt_session_t *s = st->session;
    xqc_moqt_message_t m = *message;
    uint64_t context = r->initial_type;
    xqc_int_t response = m.type == XQC_MOQT_MSG_REQUEST_OK
                         || m.type == XQC_MOQT_MSG_REQUEST_ERROR
                         || m.type == XQC_MOQT_MSG_SUBSCRIBE_OK
                         || m.type == XQC_MOQT_MSG_FETCH_OK;
    xqc_int_t update = m.type == XQC_MOQT_MSG_REQUEST_UPDATE;
    xqc_int_t initial_response = !r->local && !r->responded;
    xqc_var_buf_t *pending = NULL;
    xqc_list_buf_t *namespace_entry = NULL;
    xqc_bool_t namespace_added = XQC_FALSE;
    xqc_int_t notification = m.type == XQC_MOQT_MSG_NAMESPACE
                             || m.type == XQC_MOQT_MSG_NAMESPACE_DONE;
    uint8_t largest[2 * XQC_VI64_MAX_LEN];
    xqc_usec_t goaway_deadline = 0;
    if (response) {
        if (r->failed || (!initial_response && !r->pending_received_updates)) {
            return -XQC_EPARAM;
        }
        context = initial_response ? r->initial_type
                                   : XQC_MOQT_MSG_REQUEST_UPDATE;
        m.request_id = r->initial_request_id;
        if (!initial_response) {
            xqc_list_buf_t *entry = xqc_list_entry(r->received_updates.next,
                                                   xqc_list_buf_t, list_head);
            m.request_id = ((xqc_moqt_message_t *)entry->buf->data)->request_id;
        }
        if (m.type != XQC_MOQT_MSG_REQUEST_ERROR
            && m.type != xqc_moqt_response_type(context))
        {
            return -XQC_EPARAM;
        }
        if (m.type == XQC_MOQT_MSG_REQUEST_ERROR
            && m.uri.iov_len
            && s->conn->conn_type == XQC_CONN_TYPE_CLIENT)
        {
            return -XQC_EPARAM;
        }
    } else if (update) {
        if (r->failed
            || !xqc_moqt_is_update_allowed(r, 1)
            || s->request_ids_exhausted
            || r->goaway_received
            || (s->peer_limits.max_request_updates
                && r->pending_sent_updates
                   >= s->peer_limits.max_request_updates))
        {
            return -XQC_EAGAIN;
        }
        xqc_moqt_assign_id(s, &m);
        /* UPDATE has no name fields; only its parameters are retained. */
        xqc_memzero(&m.track_namespace, sizeof(m.track_namespace));
        xqc_memzero(&m.track_name, sizeof(m.track_name));
    } else if (notification) {
        if (r->initial_type != XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE
            || r->local
            || !r->established
            || r->failed)
        {
            return -XQC_EPARAM;
        }
    } else if (m.type == XQC_MOQT_MSG_PUBLISH_STATE_NOTIFY
               || m.type == XQC_MOQT_MSG_PUBLISH_DONE)
    {
        if (!r->established
            || !xqc_moqt_is_local_publisher(r)
            || r->done_sent
            || (r->failed
                && m.type != XQC_MOQT_MSG_PUBLISH_DONE))
        {
            return -XQC_EPARAM;
        }
    } else if (m.type == XQC_MOQT_MSG_GOAWAY) {
        if (r->failed
            || r->goaway_sent
            || !r->responded
            || (m.uri.iov_len
                && s->conn->conn_type == XQC_CONN_TYPE_CLIENT))
        {
            return -XQC_EPARAM;
        }
        xqc_usec_t now = xqc_monotonic_timestamp();
        if (m.timeout_ms > (UINT64_MAX - now)
                               / XQC_MOQT_MICROS_PER_MILLISECOND)
        {
            return -XQC_ELIMIT;
        }
        goaway_deadline = m.timeout_ms
            ? now + m.timeout_ms * XQC_MOQT_MICROS_PER_MILLISECOND : 0;
    } else {
        return -XQC_EPARAM;
    }
    if (m.type == XQC_MOQT_MSG_PUBLISH_DONE && r->subscription != NULL) {
        /* A ready Fill must have a data stream before the final count. */
        for (xqc_moqt_fetch_t *f = s->fetches; f != NULL; f = f->next) {
            if (f->subscription == r->subscription
                && !f->closed
                && (!f->ready
                    || !f->opened))
            {
                return -XQC_EAGAIN;
            }
        }
        /* Section 9.9: all opened streams must be FIN/reset and drained. */
        for (xqc_moqt_stream_t *data = s->streams; data != NULL;
             data = data->next)
        {
            if (data->discarded) {
                continue;
            }
            xqc_moqt_subscription_t *sub = NULL;
            if (data->kind == XQC_MOQT_STREAM_SUBGROUP) {
                sub = data->state.data.subscription;
            } else if (data->kind == XQC_MOQT_STREAM_FETCH
                       && data->state.data.fetch != NULL)
            {
                sub = data->state.data.fetch->subscription;
            }
            if (sub == r->subscription
                && (!data->tx_fin_sent
                    || !xqc_list_empty(&data->tx)))
            {
                return -XQC_EAGAIN;
            }
        }
        m.stream_count = r->subscription->stream_count;
    }
    if (m.type == XQC_MOQT_MSG_SUBSCRIBE_OK && r->subscription != NULL) {
        m.track_alias = r->subscription->track_alias;
    }
    if (response
        && m.type == XQC_MOQT_MSG_REQUEST_OK
        && r->initial_type == XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE)
    {
        xqc_moqt_message_t candidate = *(xqc_moqt_message_t *)r->state->data;
        if (!initial_response) {
            xqc_list_buf_t *entry = xqc_list_entry(r->received_updates.next,
                                                   xqc_list_buf_t, list_head);
            if (xqc_moqt_merge(&candidate, (void *)entry->buf->data)
                != XQC_OK)
            {
                return -XQC_ELIMIT;
            }
        }
        if (xqc_moqt_namespace_overlap(r, &candidate.track_namespace)) {
            xqc_memzero(&m, sizeof(m));
            m.type = XQC_MOQT_MSG_REQUEST_ERROR;
            m.error.code = XQC_MOQT_REQUEST_PREFIX_OVERLAP;
        }
    }
    if (initial_response
        && m.type == XQC_MOQT_MSG_REQUEST_OK
        && r->initial_type == XQC_MOQT_MSG_TRACK_STATUS)
    {
        const xqc_moqt_message_t *state = (void *)r->state->data;
        for (size_t i = 0; i < state->parameter_count; i++) {
            if (state->parameters[i].type == XQC_MOQT_PARAM_INCLUDE_PROPERTIES
                && state->parameters[i].value[0] == 0)
            {
                xqc_memzero(&m.properties, sizeof(m.properties));
            }
        }
    }
    if (xqc_moqt_largest_append(r, &m, largest) != XQC_OK
        || xqc_moqt_message_encode(&m, context, NULL, 0) < 0)
    {
        return -XQC_EPARAM;
    }
    if (update) {
        pending = xqc_moqt_request_snapshot(s, &m);
        if (pending == NULL
            || xqc_moqt_queue(s, &r->sent_updates, pending) != XQC_OK)
        {
            xqc_moqt_buffer_free(s, pending, sizeof(*pending));
            return -XQC_EMALLOC;
        }
    }
    if (notification) {
        xqc_int_t ret = xqc_moqt_namespace_prepare(r, &m, &namespace_entry,
                                                   &namespace_added);
        if (ret != XQC_OK) {
            return ret;
        }
    }
    xqc_int_t ret = xqc_moqt_request_queue(r, &m, context);
    if (ret != XQC_OK) {
        if (namespace_added) {
            xqc_moqt_dequeue(s, namespace_entry);
        }
        if (pending != NULL) {
            xqc_moqt_dequeue(s, xqc_list_entry(r->sent_updates.prev,
                                               xqc_list_buf_t, list_head));
        }
        return ret;
    }
    if (notification) {
        xqc_moqt_namespace_notify(r, namespace_entry, namespace_added, m.type);
    }
    if (update && xqc_moqt_fetch_create(r, &m) != XQC_MOQT_NO_ERROR) {
        xqc_moqt_dequeue(s, xqc_list_entry(st->tx.prev,
                                           xqc_list_buf_t, list_head));
        xqc_moqt_dequeue(s, xqc_list_entry(r->sent_updates.prev,
                                           xqc_list_buf_t, list_head));
        return -XQC_EMALLOC;
    }
    if ((initial_response
            && response
            && m.type != XQC_MOQT_MSG_REQUEST_ERROR)
        || m.type == XQC_MOQT_MSG_PUBLISH_STATE_NOTIFY)
    {
        uint64_t error = xqc_moqt_subscription_apply(r, &m);
        if (!error) {
            error = xqc_moqt_fetch_apply(r, &m);
        }
        if (!error && initial_response) {
            error = xqc_moqt_fill_apply(r, (void *)r->state->data,
                                        (void *)r->state->data, &m);
        }
        if (error != XQC_MOQT_NO_ERROR) {
            xqc_moqt_dequeue(s, xqc_list_entry(st->tx.prev,
                                               xqc_list_buf_t, list_head));
            /* A pending peer PUBLISH can conflict when another is accepted. */
            if (error == XQC_MOQT_DUPLICATE_TRACK_ALIAS) {
                xqc_moqt_session_close(s, error);
            }
            return -XQC_EPARAM;
        }
    }
    if (r->subscription != NULL && m.type == XQC_MOQT_MSG_REQUEST_ERROR) {
        r->subscription->stopped = 1;
        xqc_moqt_subscription_data_update(r->subscription);
        xqc_moqt_fill_cancel(r->subscription);
    }
    if (response) {
        if (m.type == XQC_MOQT_MSG_REQUEST_ERROR) {
            r->failed = r->has_error = 1;
            r->error.context = XQC_MOQT_ERROR_REQUEST;
            r->error.code = m.error.code;
            r->error.normalized_code = xqc_moqt_error_normalize(
                r->error.context, m.error.code);
        } else if (!initial_response) {
            if (xqc_moqt_commit_update(r, &r->received_updates, &m) != XQC_OK) {
                xqc_moqt_request_cancel(r, XQC_MOQT_RESET_EXCESSIVE_LOAD);
                return -XQC_EMALLOC;
            }
            r->pending_received_updates--;
        }
        if (initial_response && m.type != XQC_MOQT_MSG_REQUEST_ERROR) {
            r->established = 1;
        }
        r->responded = 1;
    } else if (update) {
        r->pending_sent_updates++;
        if (!r->response_deadline) {
            r->response_deadline = xqc_monotonic_timestamp()
                                   + s->config.timeout;
        }
    } else if (m.type == XQC_MOQT_MSG_PUBLISH_DONE) {
        r->done_sent = 1;
        xqc_moqt_subscription_done(r->subscription, &m);
    } else if (m.type == XQC_MOQT_MSG_GOAWAY) {
        r->goaway_sent = 1;
        r->goaway_deadline = goaway_deadline;
    }
    if (response && m.type != XQC_MOQT_MSG_REQUEST_ERROR) {
        xqc_moqt_fetch_ready(r, m.request_id);
    }
    xqc_moqt_timer_update(s);
    if (m.type == XQC_MOQT_MSG_REQUEST_ERROR) {
        xqc_moqt_update_failed(r);
    } else if (m.type == XQC_MOQT_MSG_PUBLISH_DONE
               || (response
                   && r->initial_type == XQC_MOQT_MSG_TRACK_STATUS))
    {
        xqc_moqt_request_finish(r);
    }
    return xqc_moqt_stream_flush(st);
}

xqc_int_t
xqc_moqt_request_send(xqc_moqt_request_t *r, const xqc_moqt_message_t *message)
{
    if (r == NULL) {
        return -XQC_EPARAM;
    }
    xqc_moqt_stream_t *st = r->stream;
    st->active++;
    xqc_int_t ret = xqc_moqt_request_send_message(r, message);
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

static xqc_int_t
xqc_moqt_authorize(xqc_moqt_request_t *r, const xqc_moqt_message_t *m,
    uint64_t *session_error, uint64_t *request_error)
{
    xqc_moqt_session_t *s = r->stream->session;
    xqc_moqt_message_t candidate = *(xqc_moqt_message_t *)r->state->data;
    if (m->type == XQC_MOQT_MSG_REQUEST_UPDATE) {
        xqc_list_head_t *pos;
        xqc_list_for_each(pos, &r->received_updates) {
            xqc_list_buf_t *entry = xqc_list_entry(pos, xqc_list_buf_t,
                                                   list_head);
            if (xqc_moqt_merge(&candidate, (void *)entry->buf->data)
                != XQC_OK)
            {
                *request_error = XQC_MOQT_REQUEST_EXCESSIVE_LOAD;
                return XQC_ERROR;
            }
        }
        if (xqc_moqt_merge(&candidate, m) != XQC_OK) {
            *request_error = XQC_MOQT_REQUEST_EXCESSIVE_LOAD;
            return XQC_ERROR;
        }
    }
    xqc_moqt_token_t tokens[XQC_MOQT_MAX_PARAMETERS];
    size_t token_count = 0;
    uint64_t rejected = XQC_MOQT_NO_ERROR;
    for (size_t i = 0; i < m->parameter_count; i++) {
        const xqc_moq_message_parameter_t *p = &m->parameters[i];
        if (p->type == XQC_MOQT_PARAM_AUTHORIZATION_TOKEN) {
            uint64_t len;
            xqc_int_t n = xqc_vi64_read(p->value, p->value + p->length, &len);
            struct iovec value = {p->value + n, len};
            xqc_moqt_token_t *token = &tokens[token_count];
            *session_error = xqc_moqt_token_decode(
                &value,
                s->conn->conn_type == XQC_CONN_TYPE_SERVER, 0, token);
            if (*session_error) {
                return XQC_ERROR;
            }
            if (xqc_moqt_token_check(tokens, token_count, token) != XQC_OK) {
                rejected = XQC_MOQT_REQUEST_MALFORMED_AUTH_TOKEN;
            }
            token_count++;
        } else if (p->type == XQC_MOQT_PARAM_FILL_PARAMETERS) {
            xqc_moqt_message_t fill;
            if (xqc_moqt_fill_parameters_decode(p, &fill) != XQC_OK) {
                *session_error = XQC_MOQT_PROTOCOL_VIOLATION;
                return XQC_ERROR;
            }
            for (size_t j = 0; j < fill.parameter_count; j++) {
                if (fill.parameters[j].type >= XQC_MOQT_PARAM_SUBGROUP_FILTER
                    && fill.parameters[j].type
                       <= XQC_MOQT_PARAM_OBJECT_PROPERTY_FILTER)
                {
                    rejected = XQC_MOQT_REQUEST_INVALID_FILTER;
                }
            }
        } else if (p->type >= XQC_MOQT_PARAM_SUBGROUP_FILTER
                   && p->type <= XQC_MOQT_PARAM_TRACK_PROPERTY_FILTER)
        {
            /* Sections 3.3.2/9.1.6: this baseline advertises zero ranges. */
            rejected = XQC_MOQT_REQUEST_INVALID_FILTER;
        }
    }
    if (rejected) {
        *request_error = rejected;
        return XQC_ERROR;
    }
    if (candidate.track_namespace.count) {
        struct iovec *first = &candidate.track_namespace.fields[0];
        if ((first->iov_len == 1
                && !xqc_memcmp(first->iov_base, ".", 1))
            || (first->iov_len == sizeof(".session") - 1
                && !xqc_memcmp(first->iov_base, ".session", first->iov_len)))
        {
            *request_error = XQC_MOQT_REQUEST_DOES_NOT_EXIST;
            return XQC_ERROR;
        }
    }
    if (xqc_moqt_namespace_overlap(r, &candidate.track_namespace)) {
        *request_error = XQC_MOQT_REQUEST_PREFIX_OVERLAP;
        return XQC_ERROR;
    }
    if (s->callbacks.on_authorize == NULL) {
        return XQC_ERROR;
    }
    return s->callbacks.on_authorize(r, m, &candidate, request_error,
                                     s->user_data);
}

uint64_t
xqc_moqt_request_input(xqc_moqt_stream_t *st, const uint8_t *data, size_t len)
{
    xqc_moqt_session_t *s = st->session;
    xqc_moqt_request_t *r = &st->state.request;
    xqc_int_t initial = st->kind != XQC_MOQT_STREAM_REQUEST;
    uint64_t context = initial ? 0 : r->initial_type;
    xqc_moqt_message_t m;
    if (!initial && (!r->local || r->responded) && r->pending_sent_updates) {
        context = XQC_MOQT_MSG_REQUEST_UPDATE;
    }
    /* Update decoding uses the operation type; responses use FIFO context. */
    xqc_moqt_message_t frame;
    xqc_memzero(&frame, sizeof(frame));
    xqc_moqt_frame_decode(data, len, &frame);
    if (frame.type == XQC_MOQT_MSG_REQUEST_UPDATE
        || frame.type == XQC_MOQT_MSG_NAMESPACE
        || frame.type == XQC_MOQT_MSG_NAMESPACE_DONE)
    {
        context = initial ? 0 : r->initial_type;
    }
    if (xqc_moqt_message_decode(data, len, context, &m) < 0) {
        return XQC_MOQT_PROTOCOL_VIOLATION;
    }
    xqc_int_t update = m.type == XQC_MOQT_MSG_REQUEST_UPDATE;
    if (initial || update) {
        if ((initial
                && !xqc_moqt_is_initial_request(m.type))
            || (!initial
                && (!xqc_moqt_is_update_allowed(r, 0)
                    || r->failed)))
        {
            return XQC_MOQT_PROTOCOL_VIOLATION;
        }
        uint64_t error = xqc_moqt_record_id(s, m.request_id);
        if (error) {
            return error;
        }
        if (initial) {
            xqc_moqt_request_init(st, &m, 0);
            r->state = xqc_moqt_request_snapshot(s, &m);
            if (r->state == NULL) {
                xqc_moqt_request_cancel(r, XQC_MOQT_RESET_EXCESSIVE_LOAD);
                return XQC_MOQT_NO_ERROR;
            }
            error = xqc_moqt_subscription_create(r, &m);
            if (!error) {
                error = xqc_moqt_fetch_create(r, &m);
            }
            if (error == XQC_MOQT_INTERNAL_ERROR) {
                xqc_moqt_request_cancel(r, XQC_MOQT_RESET_EXCESSIVE_LOAD);
                return XQC_MOQT_NO_ERROR;
            }
            if (error) {
                return error;
            }
        } else if (s->local_limits.max_request_updates
                   && r->pending_received_updates
                      >= s->local_limits.max_request_updates)
        {
            return XQC_MOQT_TOO_MANY_REQUEST_UPDATES;
        }
        uint64_t request_error = XQC_MOQT_REQUEST_UNAUTHORIZED;
        xqc_int_t rejected = xqc_moqt_authorize(r, &m, &error, &request_error)
                             != XQC_OK;
        if (error || s->closed || st->discarded) {
            return error;
        }
        if (update) {
            xqc_var_buf_t *pending = xqc_moqt_request_snapshot(s, &m);
            if (pending == NULL
                || xqc_moqt_queue(s, &r->received_updates, pending) != XQC_OK)
            {
                xqc_moqt_buffer_free(s, pending, sizeof(*pending));
                xqc_moqt_request_cancel(r, XQC_MOQT_RESET_EXCESSIVE_LOAD);
                return XQC_MOQT_NO_ERROR;
            }
            r->pending_received_updates++;
        }
        if (update
            && !rejected
            && xqc_moqt_fetch_create(r, &m) != XQC_MOQT_NO_ERROR)
        {
            xqc_moqt_request_cancel(r, XQC_MOQT_RESET_EXCESSIVE_LOAD);
            return XQC_MOQT_NO_ERROR;
        }
        if (!rejected
            && (s->callbacks.on_message == NULL
                || m.type == XQC_MOQT_MSG_SUBSCRIBE_TRACKS))
        {
            rejected = 1;
            request_error = XQC_MOQT_REQUEST_NOT_SUPPORTED;
        }
        if (rejected) {
            xqc_moqt_message_t response;
            xqc_memzero(&response, sizeof(response));
            response.type = XQC_MOQT_MSG_REQUEST_ERROR;
            response.error.code = request_error;
            if (xqc_moqt_request_send(r, &response) != XQC_OK) {
                xqc_moqt_request_cancel(r, XQC_MOQT_RESET_EXCESSIVE_LOAD);
            }
            return XQC_MOQT_NO_ERROR;
        }
    } else if (m.type == XQC_MOQT_MSG_REQUEST_OK
               || m.type == XQC_MOQT_MSG_REQUEST_ERROR
               || m.type == XQC_MOQT_MSG_SUBSCRIBE_OK
               || m.type == XQC_MOQT_MSG_FETCH_OK)
    {
        xqc_int_t first = r->local && !r->responded;
        if (r->failed
            || (!first
                && !r->pending_sent_updates)
            || (m.type != XQC_MOQT_MSG_REQUEST_ERROR
                && m.type != xqc_moqt_response_type(context))
            || (m.type == XQC_MOQT_MSG_REQUEST_ERROR
                && m.uri.iov_len
                && s->conn->conn_type == XQC_CONN_TYPE_SERVER))
        {
            return XQC_MOQT_PROTOCOL_VIOLATION;
        }
        m.request_id = r->initial_request_id;
        if (!first) {
            xqc_list_buf_t *entry = xqc_list_entry(r->sent_updates.next,
                                                   xqc_list_buf_t, list_head);
            m.request_id = ((xqc_moqt_message_t *)entry->buf->data)->request_id;
        }
        if (m.type == XQC_MOQT_MSG_REQUEST_ERROR) {
            r->failed = r->has_error = 1;
            r->error = m.error;
            r->response_deadline = 0;
        } else if (!first) {
            if (xqc_moqt_commit_update(r, &r->sent_updates, &m) != XQC_OK) {
                xqc_moqt_request_cancel(r, XQC_MOQT_RESET_EXCESSIVE_LOAD);
                return XQC_MOQT_NO_ERROR;
            }
            r->pending_sent_updates--;
        }
        if (first && m.type != XQC_MOQT_MSG_REQUEST_ERROR) {
            uint64_t error = xqc_moqt_subscription_apply(r, &m);
            if (!error) {
                error = xqc_moqt_fetch_apply(r, &m);
            }
            if (!error) {
                error = xqc_moqt_fill_apply(r, (void *)r->state->data,
                                            (void *)r->state->data, &m);
            }
            if (error) {
                return error;
            }
            r->established = 1;
        }
        r->responded = 1;
        if (!r->pending_sent_updates) {
            r->response_deadline = 0;
        }
    } else if (m.type == XQC_MOQT_MSG_NAMESPACE
               || m.type == XQC_MOQT_MSG_NAMESPACE_DONE)
    {
        if (r->initial_type != XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE
            || !r->local
            || !r->established
            || r->failed)
        {
            return XQC_MOQT_PROTOCOL_VIOLATION;
        }
        xqc_list_buf_t *entry;
        xqc_bool_t added;
        xqc_int_t ret = xqc_moqt_namespace_prepare(r, &m, &entry, &added);
        if (ret == -XQC_EMALLOC) {
            xqc_moqt_request_cancel(r, XQC_MOQT_RESET_EXCESSIVE_LOAD);
            return XQC_MOQT_NO_ERROR;
        }
        if (ret != XQC_OK) {
            return XQC_MOQT_PROTOCOL_VIOLATION;
        }
        xqc_moqt_namespace_notify(r, entry, added, m.type);
    } else if (m.type == XQC_MOQT_MSG_PUBLISH_STATE_NOTIFY
               || m.type == XQC_MOQT_MSG_PUBLISH_DONE)
    {
        if (!r->established
            || xqc_moqt_is_local_publisher(r)
            || (r->initial_type != XQC_MOQT_MSG_SUBSCRIBE
                && r->initial_type != XQC_MOQT_MSG_PUBLISH)
            || r->done_received)
        {
            return XQC_MOQT_PROTOCOL_VIOLATION;
        }
        if (m.type == XQC_MOQT_MSG_PUBLISH_DONE) {
            r->done_received = r->has_error = 1;
            r->error = m.error;
        } else {
            uint64_t error = xqc_moqt_subscription_apply(r, &m);
            if (error) {
                return error;
            }
        }
    } else if (m.type == XQC_MOQT_MSG_GOAWAY) {
        if (!r->responded
            || r->goaway_received
            || (m.uri.iov_len
                && s->conn->conn_type == XQC_CONN_TYPE_SERVER))
        {
            return XQC_MOQT_PROTOCOL_VIOLATION;
        }
        r->goaway_received = 1;
    } else {
        return XQC_MOQT_PROTOCOL_VIOLATION;
    }
    if (r->subscription != NULL && m.type == XQC_MOQT_MSG_REQUEST_ERROR) {
        r->subscription->stopped = 1;
        xqc_moqt_subscription_data_update(r->subscription);
        xqc_moqt_fill_cancel(r->subscription);
    }
    if (s->callbacks.on_message != NULL && !s->closed && !st->discarded) {
        s->callbacks.on_message(r, &m, s->user_data);
    }
    if (!s->closed && !st->discarded) {
        if (m.type == XQC_MOQT_MSG_FETCH_OK
            || m.type == XQC_MOQT_MSG_SUBSCRIBE_OK
            || m.type == XQC_MOQT_MSG_REQUEST_OK)
        {
            xqc_moqt_fetch_ready(r, m.request_id);
        }
    }
    if (m.type == XQC_MOQT_MSG_REQUEST_ERROR && !s->closed && !st->discarded) {
        xqc_moqt_update_failed(r);
    }
    if (m.type == XQC_MOQT_MSG_PUBLISH_DONE && !s->closed && !st->discarded) {
        xqc_moqt_subscription_done(r->subscription, &m);
    }
    return XQC_MOQT_NO_ERROR;
}

void
xqc_moqt_request_fin(xqc_moqt_request_t *r)
{
    xqc_moqt_stream_t *st = r->stream;
    st->rx_fin = 1;
    if (r->local) {
        xqc_moqt_namespaces_clear(r);
    }
    if (st->rx.data_len
        || (!r->failed
            && ((r->local
                    && !r->responded)
                || r->pending_sent_updates
                || (r->responded
                    && !xqc_moqt_is_local_publisher(r)
                    && !r->done_received
                    && (r->initial_type == XQC_MOQT_MSG_SUBSCRIBE
                        || r->initial_type == XQC_MOQT_MSG_PUBLISH)))))
    {
        xqc_moqt_request_cancel(r, XQC_MOQT_RESET_CANCELLED);
    } else if (r->local && !st->tx_fin && r->responded) {
        xqc_moqt_request_finish(r);
    }
}

void
xqc_moqt_request_closed(xqc_moqt_request_t *r)
{
    xqc_moqt_session_t *s = r->stream->session;
    if (s->closed && !r->has_error) {
        r->has_error = 1;
        r->error.context = XQC_MOQT_ERROR_SESSION;
        r->error.code = xqc_conn_get_errno(s->conn);
        r->error.normalized_code = r->error.code;
    }
    xqc_moqt_namespaces_clear(r);
    if (s->callbacks.on_request_closed != NULL) {
        s->callbacks.on_request_closed(r, r->has_error ? &r->error : NULL,
                                       s->user_data);
    }
    xqc_moqt_subscription_release(r);
    xqc_moqt_fetch_release(r);
    xqc_moqt_buffer_free(s, r->state, sizeof(*r->state));
    xqc_list_head_t *heads[] = {&r->sent_updates, &r->received_updates};
    for (size_t i = 0; i < sizeof(heads) / sizeof(heads[0]); i++) {
        while (!xqc_list_empty(heads[i])) {
            xqc_moqt_dequeue(s, xqc_list_entry(heads[i]->next,
                                               xqc_list_buf_t, list_head));
        }
    }
}
