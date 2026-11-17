/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include "xqc_moqt_relay.h"
#include "src/common/xqc_time.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"

struct xqc_webtransport_session_s;
static xqc_moqt_relay_peer_t *xqc_moqt_relay_peer_create_internal(
    xqc_moqt_relay_t *r, xqc_connection_t *conn,
    struct xqc_webtransport_session_s *wt, const xqc_moqt_config_t *config,
    const struct iovec *scope, void *data, xqc_bool_t draft07_compat);

void *
xqc_moqt_relay_alloc(xqc_moqt_relay_t *r, size_t size)
{
    if (size > r->config.max_bytes - r->stats.bytes) {
        r->stats.rejected++;
        return NULL;
    }
    void *p = xqc_calloc(1, size);
    if (p != NULL) {
        r->stats.bytes += size;
    }
    return p;
}

void
xqc_moqt_relay_free(xqc_moqt_relay_t *r, void *p, size_t size)
{
    if (p != NULL) {
        r->stats.bytes -= size;
        xqc_free(p);
    }
}

xqc_var_buf_t *
xqc_moqt_relay_buffer(xqc_moqt_relay_t *r, const void *data, size_t size)
{
    if (size > r->config.max_bytes - r->stats.bytes
        || sizeof(xqc_var_buf_t) > r->config.max_bytes - r->stats.bytes - size)
    {
        r->stats.rejected++;
        return NULL;
    }
    xqc_var_buf_t *buf = xqc_var_buf_create(size);
    if (buf != NULL) {
        r->stats.bytes += sizeof(*buf) + size;
        if (data != NULL && size) {
            xqc_memcpy(buf->data, data, size);
        }
        buf->data_len = size;
    }
    return buf;
}

void
xqc_moqt_relay_buffer_free(xqc_moqt_relay_t *r, xqc_var_buf_t *buf)
{
    if (buf != NULL) {
        r->stats.bytes -= sizeof(*buf) + buf->buf_len;
        xqc_var_buf_free(buf);
    }
}

xqc_var_buf_t *
xqc_moqt_relay_message_copy(xqc_moqt_relay_peer_t *peer,
    const xqc_moqt_message_t *m, uint64_t context)
{
    xqc_moqt_version_t version = XQC_MOQT_VERSION_DRAFT_22;
    size_t prefix = 0;
    xqc_int_t len = xqc_moqt_message_encode(m, context, NULL, 0);
    if (len < 0
        && xqc_moqt_session_version(peer->session) == XQC_MOQT_VERSION_DRAFT_23)
    {
        /* Reserved types 0 and 1 tag draft-23-only relay state. */
        version = XQC_MOQT_VERSION_DRAFT_23;
        prefix = 1;
        if (m->type == XQC_MOQT_MSG_FETCH_OK) {
            prefix += xqc_vi64_len(m->end_group) + xqc_vi64_len(m->end_object);
        }
        len = xqc_moqt_message_encode_version(version, m, context, NULL, 0);
    }
    if (len < 0) {
        return NULL;
    }
    xqc_var_buf_t *buf = xqc_moqt_relay_buffer(peer->relay, NULL, prefix + len);
    if (buf != NULL) {
        if (prefix) {
            buf->data[0] = m->type == XQC_MOQT_MSG_FETCH_OK ? 1 : 0;
            if (prefix > 1) {
                uint8_t *p = buf->data + 1, *end = buf->data + prefix;
                p += xqc_vi64_write(p, end, m->end_group);
                xqc_vi64_write(p, end, m->end_object);
            }
        }
        xqc_moqt_message_encode_version(version, m, context, buf->data + prefix,
                                         len);
    }
    return buf;
}

xqc_int_t
xqc_moqt_relay_message_read(const xqc_var_buf_t *buf, uint64_t context,
    xqc_moqt_message_t *m)
{
    if (buf == NULL || buf->data_len == 0) {
        return -XQC_EPARAM;
    }
    if (buf->data[0] > 1) {
        return xqc_moqt_message_decode(buf->data, buf->data_len, context, m);
    }
    const uint8_t *p = buf->data + 1, *end = buf->data + buf->data_len;
    uint64_t group = 0, object = 0;
    if (buf->data[0] == 1) {
        xqc_int_t n = xqc_vi64_read(p, end, &group);
        if (n < 0) {
            return -XQC_EILLEGAL_FRAME;
        }
        p += n;
        n = xqc_vi64_read(p, end, &object);
        if (n < 0) {
            return -XQC_EILLEGAL_FRAME;
        }
        p += n;
    }
    xqc_int_t ret = xqc_moqt_message_decode_version(XQC_MOQT_VERSION_DRAFT_23,
        p, end - p, context, m);
    if (ret > 0) {
        m->end_group = group;
        m->end_object = object;
        ret += p - buf->data;
    }
    return ret;
}

xqc_usec_t
xqc_moqt_relay_deadline(xqc_usec_t now, uint64_t ms, xqc_usec_t maximum)
{
    xqc_usec_t duration = maximum;
    if (ms <= maximum / XQC_MOQT_MICROS_PER_MILLISECOND) {
        duration = ms * XQC_MOQT_MICROS_PER_MILLISECOND;
    }
    return duration > UINT64_MAX - now ? UINT64_MAX : now + duration;
}

static uint64_t
xqc_moqt_relay_parameter(const xqc_moqt_message_t *m, uint64_t type,
    uint64_t fallback)
{
    for (size_t i = 0; i < m->parameter_count; i++) {
        const xqc_moq_message_parameter_t *p = &m->parameters[i];
        if (p->type == type) {
            uint64_t value;
            if (xqc_vi64_read(p->value, p->value + p->length, &value) > 0) {
                return value;
            }
        }
    }
    return fallback;
}

static xqc_int_t
xqc_moqt_relay_scope_equal(const xqc_var_buf_t *a, const xqc_var_buf_t *b)
{
    return a->data_len == b->data_len
        && (!a->data_len || !xqc_memcmp(a->data, b->data, a->data_len));
}

static xqc_moqt_relay_track_t *
xqc_moqt_relay_track_get(xqc_moqt_relay_peer_t *peer,
    const xqc_moqt_message_t *m)
{
    xqc_moqt_relay_t *r = peer->relay;
    xqc_int_t len = xqc_moqt_name_encode(&m->track_namespace,
                                         &m->track_name, NULL, 0);
    if (len < 0) {
        return NULL;
    }
    xqc_var_buf_t *name = xqc_moqt_relay_buffer(r, NULL, len);
    if (name == NULL) {
        return NULL;
    }
    xqc_moqt_name_encode(&m->track_namespace, &m->track_name, name->data, len);
    xqc_moqt_relay_track_t *t = r->tracks;
    while (t != NULL) {
        if (xqc_moqt_relay_scope_equal(t->scope, peer->scope)
            && xqc_moqt_relay_scope_equal(t->name, name))
        {
            xqc_moqt_relay_buffer_free(r, name);
            t->references++;
            return t;
        }
        t = t->next;
    }
    t = xqc_moqt_relay_alloc(r, sizeof(*t));
    if (t != NULL) {
        t->scope = xqc_moqt_relay_buffer(r, peer->scope->data,
                                         peer->scope->data_len);
        if (t->scope == NULL) {
            xqc_moqt_relay_free(r, t, sizeof(*t));
            t = NULL;
        }
    }
    if (t == NULL) {
        xqc_moqt_relay_buffer_free(r, name);
        return NULL;
    }
    t->name = name;
    t->references = 1;
    t->next = r->tracks;
    r->tracks = t;
    return t;
}

static xqc_moqt_relay_request_t *
xqc_moqt_relay_request_find(xqc_moqt_relay_peer_t *peer,
    xqc_moqt_request_t *request)
{
    for (xqc_moqt_relay_request_t *q = peer->relay->requests;
         q != NULL; q = q->next)
    {
        if (q->peer == peer && q->request == request) {
            return q;
        }
    }
    return NULL;
}

xqc_moqt_relay_request_t *
xqc_moqt_relay_subscription_find(xqc_moqt_relay_peer_t *peer,
    xqc_moqt_subscription_t *subscription)
{
    if (subscription == NULL) {
        return NULL;
    }
    for (xqc_moqt_relay_request_t *q = peer->relay->requests;
         q != NULL; q = q->next)
    {
        if (q->peer == peer && q->subscription == subscription) {
            return q;
        }
    }
    return NULL;
}

static xqc_moqt_relay_request_t *
xqc_moqt_relay_request_create(xqc_moqt_relay_peer_t *peer,
    xqc_moqt_request_t *request, const xqc_moqt_message_t *m)
{
    xqc_moqt_relay_t *r = peer->relay;
    if (r->stats.requests == r->config.max_requests) {
        r->stats.rejected++;
        return NULL;
    }
    if (m->type == XQC_MOQT_MSG_PUBLISH && r->next_publication == UINT64_MAX) {
        return NULL;
    }
    xqc_moqt_relay_request_t *q = xqc_moqt_relay_alloc(r, sizeof(*q));
    if (q == NULL) {
        return NULL;
    }
    q->state = xqc_moqt_relay_message_copy(peer, m, 0);
    if (q->state == NULL) {
        xqc_moqt_relay_free(r, q, sizeof(*q));
        return NULL;
    }
    if (!xqc_moqt_is_namespace_request(m->type)) {
        q->track = xqc_moqt_relay_track_get(peer, m);
        if (q->track == NULL) {
            xqc_moqt_relay_buffer_free(r, q->state);
            xqc_moqt_relay_free(r, q, sizeof(*q));
            return NULL;
        }
    }
    q->operation_started = xqc_monotonic_timestamp();
    q->type = m->type;
    q->group_pending = UINT64_MAX;
    if (m->type == XQC_MOQT_MSG_PUBLISH) {
        q->publication_id = ++r->next_publication;
    }
    q->peer = peer;
    q->request = request;
    q->subscription = xqc_moqt_request_subscription(request);
    q->forward = xqc_moqt_relay_parameter(m, XQC_MOQT_PARAM_FORWARD, 1) != 0;
    q->next = r->requests;
    r->requests = q;
    r->stats.requests++;
    return q;
}

static void
xqc_moqt_relay_error(xqc_moqt_request_t *request, uint64_t code)
{
    xqc_moqt_message_t m;
    xqc_memzero(&m, sizeof(m));
    m.type = XQC_MOQT_MSG_REQUEST_ERROR;
    m.error.code = code;
    if (xqc_moqt_request_send(request, &m) != XQC_OK) {
        xqc_moqt_request_cancel(request, XQC_MOQT_RESET_EXCESSIVE_LOAD);
    }
}

static void
xqc_moqt_relay_cancel_dependents(xqc_moqt_relay_request_t *q, uint64_t code)
{
    xqc_moqt_relay_t *r = q->peer->relay;
    for (xqc_moqt_relay_request_t *up = r->requests; up; up = up->next) {
        if (up->parent == q) {
            xqc_moqt_relay_stop(up, code);
        }
    }
    for (xqc_moqt_relay_fetch_t *f = r->fetches; f; f = f->next) {
        if (f->downstream == q || f->upstream == q) {
            xqc_moqt_relay_fetch_stop(f, code);
        }
    }
}

void
xqc_moqt_relay_stop(xqc_moqt_relay_request_t *q, uint64_t code)
{
    if (q == NULL || q->stopped) {
        return;
    }
    /* Set first: native cancellation may synchronously call back. */
    q->stopped = 1;
    q->deadline = 0;
    xqc_moqt_relay_cancel_dependents(q, code);
    /* Native Session teardown owns this peer; do not requeue its connection. */
    if (q->peer->closed) {
        return;
    }
    if (q->subscription != NULL) {
        xqc_moqt_subscription_cancel(q->subscription, code);
    }
    if (q->request != NULL) {
        xqc_moqt_request_cancel(q->request, code);
    }
}

static void
xqc_moqt_relay_reject(xqc_moqt_relay_request_t *q, uint64_t code)
{
    q->stopped = 1;
    q->deadline = 0;
    /* Let REQUEST_ERROR/FIN drain instead of resetting its response bytes. */
    if (q->request != NULL) {
        xqc_moqt_relay_error(q->request, code);
    }
    xqc_moqt_relay_cancel_dependents(q, XQC_MOQT_RESET_CANCELLED);
}

/* An incoming credential never becomes an outgoing credential implicitly. */
static xqc_int_t
xqc_moqt_relay_forward_message(xqc_moqt_relay_peer_t *peer,
    xqc_moqt_message_t *m)
{
    size_t count = 0;
    for (size_t i = 0; i < m->parameter_count; i++) {
        if (m->parameters[i].type != XQC_MOQT_PARAM_AUTHORIZATION_TOKEN
            && m->parameters[i].type != XQC_MOQT_PARAM_FILL_PARAMETERS
            && m->parameters[i].type != XQC_MOQT_PARAM_SUBSCRIBE_TRACKS_ID
            && !xqc_moqt_is_range_filter(m->parameters[i].type))
        {
            m->parameters[count++] = m->parameters[i];
        }
    }
    m->parameter_count = count;
    return peer->relay->callbacks.on_forward(peer, m, peer->user_data);
}

static xqc_int_t
xqc_moqt_relay_namespace_matches(xqc_moqt_relay_request_t *source,
    xqc_moqt_relay_request_t *destination)
{
    /* RFC 9000 §10.2.2: draining can precede the Session close callback. */
    if (!source->registered || source->peer->closed
        || xqc_moqt_session_is_closing(source->peer->session))
    {
        return XQC_FALSE;
    }
    if (source->peer == destination->peer
        || !xqc_moqt_relay_scope_equal(source->peer->scope,
                                       destination->peer->scope))
    {
        return XQC_FALSE;
    }
    xqc_moqt_message_t ns, track;
    xqc_moqt_relay_message_read(source->state, 0, &ns);
    xqc_moqt_relay_message_read(destination->state, 0, &track);
    if (destination->type == XQC_MOQT_MSG_SUBSCRIBE_TRACKS
        && xqc_moqt_namespace_prefix(&track.track_namespace,
                                     &ns.track_namespace))
    {
        return XQC_TRUE;
    }
    return xqc_moqt_namespace_prefix(&ns.track_namespace,
                                     &track.track_namespace);
}

static xqc_int_t
xqc_moqt_relay_source_exists(xqc_moqt_relay_t *r,
    const xqc_moqt_relay_request_t *source)
{
    for (xqc_moqt_relay_request_t *q = r->requests; q != NULL; q = q->next) {
        if (q != source
            && q->registered
            && xqc_moqt_relay_scope_equal(q->peer->scope, source->peer->scope))
        {
            xqc_moqt_message_t a, b;
            xqc_moqt_relay_message_read(q->state, 0, &a);
            xqc_moqt_relay_message_read(source->state, 0, &b);
            if (a.track_namespace.count == b.track_namespace.count
                && xqc_moqt_namespace_prefix(&a.track_namespace,
                                             &b.track_namespace))
            {
                return XQC_TRUE;
            }
        }
    }
    return XQC_FALSE;
}

static void
xqc_moqt_relay_namespace_notify(xqc_moqt_relay_request_t *watch,
    xqc_moqt_relay_request_t *source, xqc_bool_t available)
{
    if (watch->stopped || !watch->established || watch->request == NULL) {
        return;
    }
    if (watch->peer == source->peer
        || !xqc_moqt_relay_scope_equal(watch->peer->scope, source->peer->scope))
    {
        return;
    }
    xqc_moqt_message_t prefix, ns;
    xqc_moqt_relay_message_read(watch->state, 0, &prefix);
    xqc_moqt_relay_message_read(source->state, 0, &ns);
    if (!xqc_moqt_namespace_prefix(&prefix.track_namespace,
                                   &ns.track_namespace))
    {
        return;
    }
    xqc_moqt_message_t m;
    xqc_memzero(&m, sizeof(m));
    m.type = available ? XQC_MOQT_MSG_NAMESPACE : XQC_MOQT_MSG_NAMESPACE_DONE;
    m.track_namespace.count = ns.track_namespace.count
                             - prefix.track_namespace.count;
    for (size_t i = 0; i < m.track_namespace.count; i++) {
        m.track_namespace.fields[i] = ns.track_namespace.fields[
            prefix.track_namespace.count + i];
    }
    if (xqc_moqt_request_send(watch->request, &m) != XQC_OK) {
        xqc_moqt_relay_stop(watch, XQC_MOQT_RESET_EXCESSIVE_LOAD);
    }
}

static void
xqc_moqt_relay_namespace_changed(xqc_moqt_relay_request_t *source,
    xqc_bool_t available)
{
    xqc_moqt_relay_t *r = source->peer->relay;
    if (xqc_moqt_relay_source_exists(r, source)) {
        return;
    }
    for (xqc_moqt_relay_request_t *q = r->requests; q != NULL; q = q->next) {
        if (q->type == XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE && !q->upstream) {
            xqc_moqt_relay_namespace_notify(q, source, available);
        }
    }
}

static xqc_int_t
xqc_moqt_relay_largest(xqc_moqt_message_t *m,
    const xqc_moqt_subscription_t *subscription, uint8_t *bytes)
{
    xqc_moqt_location_t location;
    if (xqc_moqt_subscription_largest(subscription, &location) != XQC_OK) {
        return XQC_OK;
    }
    size_t pos = 0;
    while (pos < m->parameter_count
           && m->parameters[pos].type < XQC_MOQT_PARAM_LARGEST_OBJECT)
    {
        pos++;
    }
    if (pos == m->parameter_count
        || m->parameters[pos].type != XQC_MOQT_PARAM_LARGEST_OBJECT)
    {
        if (m->parameter_count == XQC_MOQT_MAX_PARAMETERS) {
            return XQC_ERROR;
        }
        for (size_t i = m->parameter_count; i > pos; i--) {
            m->parameters[i] = m->parameters[i - 1];
        }
        m->parameter_count++;
    }
    uint8_t *end = bytes + 2 * XQC_VI64_MAX_LEN;
    size_t len = xqc_vi64_write(bytes, end, location.group_id);
    len += xqc_vi64_write(bytes + len, end, location.object_id);
    m->parameters[pos] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_LARGEST_OBJECT, len, bytes};
    return XQC_OK;
}

static xqc_bool_t
xqc_moqt_relay_direct_delivery(const xqc_moqt_relay_request_t *up,
    const xqc_moqt_relay_request_t *down)
{
    return up->type == XQC_MOQT_MSG_PUBLISH && up->upstream && up->established
        && !up->stopped && !down->upstream && down->established
        && !down->stopped && up->track == down->track
        && down->subscription != NULL
        && (down->type != XQC_MOQT_MSG_PUBLISH || down->selected == up);
}

static void
xqc_moqt_relay_response(xqc_moqt_relay_request_t *down,
    const xqc_moqt_message_t *source)
{
    if (down->request == NULL || down->stopped) {
        return;
    }
    xqc_moqt_relay_t *r = down->peer->relay;
    if (down->resuming) {
        /* Draft-22 §§3.1.1, 9.5: confirm after direct sources resume. */
        for (xqc_moqt_relay_request_t *up = r->requests; up; up = up->next) {
            if (xqc_moqt_relay_direct_delivery(up, down)
                && (!up->forward || up->waiting_update))
            {
                return;
            }
        }
    }
    xqc_moqt_message_t m = *source;
    if (down->waiting_update) {
        m.type = XQC_MOQT_MSG_REQUEST_OK;
    } else if (down->type == XQC_MOQT_MSG_SUBSCRIBE) {
        m.type = XQC_MOQT_MSG_SUBSCRIBE_OK;
    } else if (down->type == XQC_MOQT_MSG_FETCH) {
        m.type = XQC_MOQT_MSG_FETCH_OK;
    } else {
        m.type = XQC_MOQT_MSG_REQUEST_OK;
    }
    size_t count = 0;
    for (size_t i = 0; i < m.parameter_count; i++) {
        uint64_t type = m.parameters[i].type;
        if (m.type == XQC_MOQT_MSG_FETCH_OK) {
            continue;
        }
        if (type == XQC_MOQT_PARAM_LARGEST_OBJECT
            || (type == XQC_MOQT_PARAM_EXPIRES
                && down->type != XQC_MOQT_MSG_TRACK_STATUS))
        {
            m.parameters[count++] = m.parameters[i];
        }
    }
    m.parameter_count = count;
    uint8_t largest[2 * XQC_VI64_MAX_LEN];
    if (down->selected != NULL
        && down->selected->type == XQC_MOQT_MSG_PUBLISH)
    {
        /* Direct PUBLISH may have advanced since its initial message. */
        xqc_moqt_relay_largest(&m, down->selected->subscription, largest);
    }
    /* Track properties remain byte-for-byte views; the endpoint copies them. */
    if (xqc_moqt_request_send(down->request, &m) != XQC_OK) {
        xqc_moqt_relay_stop(down, XQC_MOQT_RESET_EXCESSIVE_LOAD);
        return;
    }
    if (down->candidate != NULL) {
        xqc_moqt_relay_buffer_free(r, down->state);
        down->state = down->candidate;
        down->candidate = NULL;
        xqc_moqt_message_t state;
        xqc_moqt_relay_message_read(down->state, 0, &state);
        down->forward = xqc_moqt_relay_parameter(&state,
            XQC_MOQT_PARAM_FORWARD, 1) != 0;
    }
    down->established = 1;
    down->waiting_update = 0;
    down->resuming = 0;
    down->deadline = 0;
    xqc_moqt_relay_buffer_free(r, down->update);
    down->update = NULL;
}

static xqc_int_t
xqc_moqt_relay_open_upstream(xqc_moqt_relay_request_t *down,
    xqc_moqt_relay_peer_t *peer)
{
    xqc_moqt_relay_t *r = peer->relay;
    for (xqc_moqt_relay_request_t *q = r->requests; q != NULL; q = q->next) {
        if (q->peer != peer || q->stopped) {
            continue;
        }
        if (q->parent == down) {
            return XQC_OK;
        }
        /* Draft-22 §7.6: reuse this peer's established exact-Track grant. */
        if (down->type == XQC_MOQT_MSG_SUBSCRIBE && q->upstream
            && q->type == XQC_MOQT_MSG_PUBLISH && q->track == down->track
            && q->established)
        {
            return XQC_OK;
        }
    }
    xqc_moqt_message_t m;
    xqc_moqt_relay_message_read(down->state, 0, &m);
    return xqc_moqt_relay_request_open(down, peer, &m) != NULL
        ? XQC_OK : XQC_ERROR;
}

xqc_moqt_relay_request_t *
xqc_moqt_relay_request_open(xqc_moqt_relay_request_t *down,
    xqc_moqt_relay_peer_t *peer, xqc_moqt_message_t *m)
{
    if (xqc_moqt_relay_forward_message(peer, m) != XQC_OK) {
        return NULL;
    }
    xqc_moqt_relay_request_t *up = xqc_moqt_relay_request_create(peer,
                                                                 NULL, m);
    if (up == NULL) {
        return NULL;
    }
    up->parent = down;
    up->upstream = 1;
    up->request = xqc_moqt_request_open(peer->session, m);
    if (up->request == NULL) {
        up->stopped = 1;
        return NULL;
    }
    up->subscription = xqc_moqt_request_subscription(up->request);
    return up;
}

static void
xqc_moqt_relay_route(xqc_moqt_relay_request_t *down)
{
    xqc_moqt_relay_t *r = down->peer->relay;
    /* Draft-22 §9.9: transport drainage does not reopen a completed grant. */
    if (down->stopped || down->upstream || down->peer->closed
        || down->ending || down->ended)
    {
        return;
    }
    if (down->type != XQC_MOQT_MSG_SUBSCRIBE
        && down->type != XQC_MOQT_MSG_FETCH
        && down->type != XQC_MOQT_MSG_TRACK_STATUS)
    {
        return;
    }
    xqc_bool_t found = XQC_FALSE;
    for (xqc_moqt_relay_request_t *source = r->requests; source != NULL;
         source = source->next)
    {
        /* A downstream Pc is a delivery, never a publisher route. */
        if (!source->upstream && source->type == XQC_MOQT_MSG_PUBLISH) {
            continue;
        }
        /* A direct PUBLISH authorizes this Track, not its whole namespace. */
        if (source->type == XQC_MOQT_MSG_PUBLISH
            && source->track == down->track
            && source->established
            && !source->stopped)
        {
            if (source->peer != down->peer) {
                if (down->type == XQC_MOQT_MSG_SUBSCRIBE
                    || down->type == XQC_MOQT_MSG_TRACK_STATUS)
                {
                    found = XQC_TRUE;
                    if (down->established) {
                        continue;
                    }
                    xqc_moqt_message_t m;
                    xqc_moqt_relay_message_read(source->state, 0, &m);
                    down->selected = source;
                    xqc_moqt_relay_response(down, &m);
                    /* Draft-22 §9.13: status uses the established Track. */
                    if (down->type == XQC_MOQT_MSG_TRACK_STATUS) {
                        return;
                    }
                } else {
                    if (xqc_moqt_relay_open_upstream(down, source->peer)
                        == XQC_OK)
                    {
                        found = XQC_TRUE;
                        /* Draft-22 §3.2: the request fixes the live edge. */
                        if (source->history != NULL
                            && down->history_source == NULL
                            && xqc_moqt_subscription_largest(
                                source->subscription,
                                &down->history_largest) == XQC_OK)
                        {
                            down->history_source = source;
                        }
                    }
                }
            }
        }
        if (xqc_moqt_relay_namespace_matches(source, down)) {
            if (xqc_moqt_relay_open_upstream(down, source->peer) != XQC_OK) {
                /* Section 7.6: never silently drop an admitted publisher. */
                if (down->established) {
                    xqc_moqt_relay_stop(down, XQC_MOQT_RESET_EXCESSIVE_LOAD);
                } else {
                    xqc_moqt_relay_reject(down,
                                          XQC_MOQT_REQUEST_EXCESSIVE_LOAD);
                }
                return;
            }
            found = XQC_TRUE;
        }
        /* FETCH/STATUS use one publisher; no speculative End Location. */
        if (found && down->type != XQC_MOQT_MSG_SUBSCRIBE) {
            break;
        }
    }
    if (!found && !down->established
        && (!down->deadline || down->type != XQC_MOQT_MSG_SUBSCRIBE))
    {
        xqc_moqt_relay_reject(down, XQC_MOQT_REQUEST_DOES_NOT_EXIST);
    } else if (found && !down->established && !down->deadline) {
        /* A publisher that never responds cannot retain a pending route. */
        down->deadline = xqc_moqt_relay_deadline(down->operation_started,
                                                 UINT64_MAX, r->config.timeout);
    }
}

static void
xqc_moqt_relay_publish(xqc_moqt_relay_request_t *watch,
    xqc_moqt_relay_request_t *source)
{
    if (source->type != XQC_MOQT_MSG_PUBLISH || !source->upstream) {
        return;
    }
    if (!source->established || source->stopped
        || source->peer == watch->peer)
    {
        return;
    }
    if (!xqc_moqt_relay_scope_equal(source->peer->scope, watch->peer->scope)) {
        return;
    }
    xqc_moqt_message_t interest, publication;
    xqc_moqt_relay_message_read(watch->state, 0, &interest);
    xqc_moqt_relay_message_read(source->state, 0, &publication);
    if (!xqc_moqt_namespace_prefix(&interest.track_namespace,
                                   &publication.track_namespace))
    {
        return;
    }
    /* Store the same independent-hop FORWARD that endpoint enumeration uses. */
    uint8_t forward;
    if (xqc_moqt_publish_forward(&publication, &interest, &forward) != XQC_OK) {
        xqc_moqt_request_skip(watch->request, source->publication_id,
                              &publication);
        return;
    }
    uint8_t largest[2 * XQC_VI64_MAX_LEN];
    if (xqc_moqt_relay_largest(&publication, source->subscription, largest)
        != XQC_OK)
    {
        xqc_moqt_relay_stop(watch, XQC_MOQT_RESET_EXCESSIVE_LOAD);
        return;
    }
    /* Destination policy authorizes this concrete Track, not just St. */
    if (xqc_moqt_relay_forward_message(watch->peer, &publication) != XQC_OK) {
        return;
    }
    xqc_moqt_relay_t *r = watch->peer->relay;
    for (xqc_moqt_relay_request_t *down = r->requests; down;
         down = down->next)
    {
        if (down->type != XQC_MOQT_MSG_SUBSCRIBE || down->upstream) {
            continue;
        }
        if (down->peer != watch->peer || down->track != source->track) {
            continue;
        }
        if (!down->established && !down->stopped) {
            /* Section 7.6: pending SUB takes this publication, not St. */
            xqc_moqt_request_skip(watch->request, source->publication_id,
                                  &publication);
            return;
        }
    }
    if (r->stats.requests == r->config.max_requests) {
        xqc_moqt_request_skip(watch->request, source->publication_id,
                              &publication);
        return;
    }
    xqc_moqt_request_t *request = NULL;
    xqc_int_t ret = xqc_moqt_request_publish(watch->request,
        source->publication_id, &publication, &request);
    if (ret != XQC_OK || request == NULL) {
        return;
    }
    xqc_moqt_relay_request_t *down = xqc_moqt_relay_request_create(
        watch->peer, request, &publication);
    if (down == NULL) {
        xqc_moqt_request_cancel(request, XQC_MOQT_RESET_EXCESSIVE_LOAD);
        return;
    }
    /* Pc survives St; only its source and delivery control its lifetime. */
    down->selected = source;
    down->forward = watch->forward;
}

static void
xqc_moqt_relay_tracks(xqc_moqt_relay_request_t *watch)
{
    if (watch->type != XQC_MOQT_MSG_SUBSCRIBE_TRACKS || watch->upstream) {
        return;
    }
    if (!watch->established || watch->stopped || watch->request == NULL) {
        return;
    }
    xqc_moqt_relay_t *r = watch->peer->relay;
    for (xqc_moqt_relay_request_t *source = r->requests; source;
         source = source->next)
    {
        if (watch->stopped || watch->request == NULL) {
            return;
        }
        xqc_moqt_relay_publish(watch, source);
        if (!xqc_moqt_relay_namespace_matches(source, watch)) {
            continue;
        }
        xqc_moqt_relay_request_t *up = r->requests;
        while (up != NULL) {
            if (up->type == XQC_MOQT_MSG_SUBSCRIBE_TRACKS && up->upstream
                && up->peer == source->peer && !up->stopped)
            {
                break;
            }
            up = up->next;
        }
        if (up == NULL) {
            /* One authorized prefix per peer avoids overlapping upstream St. */
            xqc_moqt_message_t m;
            xqc_memzero(&m, sizeof(m));
            m.type = XQC_MOQT_MSG_SUBSCRIBE_TRACKS;
            up = xqc_moqt_relay_request_open(watch, source->peer, &m);
            if (up != NULL) {
                up->parent = NULL;
            }
        }
    }
}

void
xqc_moqt_relay_routes(xqc_moqt_relay_t *r)
{
    /* Record St skips before SUBSCRIBE_OK clears the pending state. */
    for (xqc_moqt_relay_request_t *q = r->requests; q != NULL; q = q->next) {
        xqc_moqt_relay_tracks(q);
    }
    for (xqc_moqt_relay_request_t *q = r->requests; q != NULL; q = q->next) {
        xqc_moqt_relay_route(q);
    }
}

static uint64_t
xqc_moqt_relay_setup(xqc_moqt_session_t *session,
    const xqc_moqt_setup_t *setup, void *data)
{
    xqc_moqt_relay_peer_t *peer = data;
    return peer->relay->callbacks.on_setup(peer, setup, peer->user_data);
}

static xqc_int_t
xqc_moqt_relay_authorize(xqc_moqt_request_t *request,
    const xqc_moqt_message_t *m, const xqc_moqt_message_t *candidate,
    uint64_t *error, void *data)
{
    xqc_moqt_relay_peer_t *peer = data;
    xqc_moqt_relay_t *r = peer->relay;
    if (r->callbacks.on_authorize(peer, m, candidate, error, peer->user_data)
        != XQC_OK)
    {
        return XQC_ERROR;
    }
    if (m->type == XQC_MOQT_MSG_REQUEST_UPDATE) {
        xqc_moqt_relay_request_t *q =
            xqc_moqt_relay_request_find(peer, request);
        if (q == NULL || q->waiting_update || q->candidate != NULL) {
            *error = XQC_MOQT_REQUEST_EXCESSIVE_LOAD;
            return XQC_ERROR;
        }
        q->candidate = xqc_moqt_relay_message_copy(q->peer, candidate, 0);
        if (q->candidate == NULL) {
            *error = XQC_MOQT_REQUEST_EXCESSIVE_LOAD;
            return XQC_ERROR;
        }
    }
    return XQC_OK;
}

static void
xqc_moqt_relay_queue_new_group(xqc_moqt_relay_request_t *down,
    const xqc_moqt_message_t *message)
{
    uint64_t group = xqc_moqt_relay_parameter(message,
        XQC_MOQT_PARAM_NEW_GROUP_REQUEST, UINT64_MAX);
    if (group == UINT64_MAX || !down->established || down->stopped
        || down->subscription == NULL)
    {
        return;
    }
    xqc_moqt_relay_t *r = down->peer->relay;
    for (xqc_moqt_relay_request_t *up = r->requests; up; up = up->next) {
        if (!up->upstream || up->type != XQC_MOQT_MSG_PUBLISH
            || up->track != down->track || up->stopped || !up->established
            || up->peer == down->peer
            || (down->type == XQC_MOQT_MSG_PUBLISH && down->selected != up)
            || !xqc_moqt_subscription_dynamic_groups(up->subscription))
        {
            continue;
        }
        if (up->group_pending == UINT64_MAX || group > up->group_pending) {
            up->group_pending = group;
        }
    }
}

static xqc_bool_t
xqc_moqt_relay_request_new_group(xqc_moqt_relay_request_t *up,
    xqc_moqt_location_t *largest, xqc_bool_t *has_largest)
{
    if (up->group_pending == UINT64_MAX) {
        return XQC_FALSE;
    }
    *has_largest = xqc_moqt_subscription_largest(up->subscription, largest)
        == XQC_OK;
    /* Draft-22 §9.20.19: OK alone does not clear an outstanding demand. */
    if (*has_largest && (!up->group_had_largest
                         || largest->group_id > up->group_at_request))
    {
        up->group_outstanding = 0;
    }
    if ((up->group_pending && *has_largest
         && up->group_pending <= largest->group_id)
        || (up->group_outstanding && up->group_pending <= up->group_requested))
    {
        up->group_pending = UINT64_MAX;
        return XQC_FALSE;
    }
    return XQC_TRUE;
}

static void
xqc_moqt_relay_pause_sources(xqc_moqt_relay_t *r)
{
    for (xqc_moqt_relay_request_t *up = r->requests; up; up = up->next) {
        if (up->type != XQC_MOQT_MSG_PUBLISH
            || !up->upstream
            || !up->established
            || up->stopped)
        {
            continue;
        }
        xqc_bool_t forward = up->history_duration
            && xqc_moqt_session_version(up->peer->session)
               == XQC_MOQT_VERSION_DRAFT_23;
        for (xqc_moqt_relay_request_t *down = r->requests;
             down != NULL; down = down->next)
        {
            if (xqc_moqt_relay_direct_delivery(up, down)) {
                forward |= down->forward || down->resuming;
            }
        }
        if (up->waiting_update
            || (forward == up->forward && up->group_pending == UINT64_MAX))
        {
            continue;
        }
        uint8_t value = forward;
        xqc_moqt_message_t m = {.type = XQC_MOQT_MSG_REQUEST_UPDATE};
        if (forward != up->forward) {
            m.parameters[m.parameter_count++] = (xqc_moq_message_parameter_t){
                XQC_MOQT_PARAM_FORWARD, 1, &value};
        }
        xqc_moqt_location_t largest = {0};
        xqc_bool_t has_largest;
        xqc_bool_t new_group = xqc_moqt_relay_request_new_group(up, &largest,
                                                              &has_largest);
        uint8_t group[XQC_VI64_MAX_LEN];
        if (new_group) {
            size_t len = xqc_vi64_write(group, group + sizeof(group),
                                        up->group_pending);
            m.parameters[m.parameter_count++] = (xqc_moq_message_parameter_t){
                XQC_MOQT_PARAM_NEW_GROUP_REQUEST, len, group};
            if (xqc_moqt_relay_forward_message(up->peer, &m) != XQC_OK) {
                up->group_pending = UINT64_MAX;
                new_group = XQC_FALSE;
                m = (xqc_moqt_message_t){.type = XQC_MOQT_MSG_REQUEST_UPDATE};
                if (forward != up->forward) {
                    m.parameter_count = 1;
                    m.parameters[0] = (xqc_moq_message_parameter_t){
                        XQC_MOQT_PARAM_FORWARD, 1, &value};
                }
            }
        }
        if (!m.parameter_count) {
            continue;
        }
        if (up->request == NULL
            || xqc_moqt_request_send(up->request, &m) != XQC_OK)
        {
            xqc_moqt_relay_stop(up, XQC_MOQT_RESET_EXCESSIVE_LOAD);
        } else {
            up->forward = forward;
            up->waiting_update = 1;
            if (new_group) {
                up->group_requested = up->group_pending;
                up->group_pending = UINT64_MAX;
                up->group_at_request = largest.group_id;
                up->group_had_largest = has_largest;
                up->group_outstanding = 1;
            }
        }
    }
    for (xqc_moqt_relay_request_t *down = r->requests; down;
         down = down->next)
    {
        if (!down->resuming || down->stopped || down->pending) {
            continue;
        }
        xqc_moqt_message_t response = {.type = XQC_MOQT_MSG_REQUEST_OK};
        if (down->response != NULL
            && xqc_moqt_relay_message_read(down->response,
                XQC_MOQT_MSG_REQUEST_UPDATE, &response) < 0)
        {
            xqc_moqt_relay_stop(down, XQC_MOQT_RESET_EXCESSIVE_LOAD);
            continue;
        }
        xqc_moqt_relay_response(down, &response);
    }
}

static xqc_bool_t
xqc_moqt_relay_live_source(const xqc_moqt_relay_request_t *down,
    const xqc_moqt_relay_request_t *up)
{
    return up->upstream && up->track == down->track && up->subscription != NULL
        && (down->type == XQC_MOQT_MSG_PUBLISH ? up == down->selected
             : up->parent == down || up->parent == NULL);
}

static void
xqc_moqt_relay_end_subscription(xqc_moqt_relay_request_t *down)
{
    down->awaiting_done = 0;
    down->ending = 1;
    down->deadline = xqc_moqt_relay_deadline(xqc_monotonic_timestamp(),
        UINT64_MAX, down->peer->relay->config.timeout);
}

void
xqc_moqt_relay_malformed(xqc_moqt_relay_request_t *source)
{
    xqc_moqt_relay_t *r = source->peer->relay;
    r->stats.malformed++;

    /* Draft-22 §12.1: send PUBLISH_DONE on established downstreams. */
    for (xqc_moqt_relay_request_t *q = r->requests; q; q = q->next) {
        if (q->track == source->track && !q->upstream && !q->peer->closed
            && !q->stopped && !q->ended && q->established
            && q->request != NULL && q->subscription != NULL)
        {
            q->done_code = XQC_MOQT_PUBLISH_MALFORMED_TRACK;
            q->resuming = 0;
            xqc_moqt_relay_end_subscription(q);
        }
    }

    /* Draft-22 §9.9: close unfinished data streams before PUBLISH_DONE. */
    for (xqc_moqt_relay_stream_t *st = r->streams; st; st = st->next) {
        if (st->downstream->track == source->track && st->downstream->ending
            && st->fetch == NULL && st->output != NULL
            && (st->input != NULL || st->finishing))
        {
            xqc_moqt_stream_cancel(st->output, XQC_MOQT_RESET_MALFORMED_TRACK);
        }
    }
    for (xqc_moqt_relay_request_t *q = r->requests; q; q = q->next) {
        if (q->track != source->track || q->ended) {
            continue;
        }
        if (q->ending) {
            xqc_moqt_relay_cancel_dependents(q, XQC_MOQT_RESET_MALFORMED_TRACK);
        } else {
            xqc_moqt_relay_stop(q, XQC_MOQT_RESET_MALFORMED_TRACK);
        }
    }
}

static void
xqc_moqt_relay_update(xqc_moqt_relay_request_t *q,
    const xqc_moqt_message_t *message)
{
    xqc_moqt_relay_t *r = q->peer->relay;
    q->operation_started = xqc_monotonic_timestamp();
    q->waiting_update = 1;
    q->resuming = !q->forward && q->subscription != NULL
        && xqc_moqt_relay_parameter(message, XQC_MOQT_PARAM_FORWARD, 0) != 0;
    xqc_moqt_relay_buffer_free(r, q->response);
    q->response = NULL;
    q->update = xqc_moqt_relay_message_copy(q->peer, message, q->type);
    if (q->update == NULL) {
        xqc_moqt_relay_stop(q, XQC_MOQT_RESET_EXCESSIVE_LOAD);
        return;
    }
    if (q->type == XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE
        || q->type == XQC_MOQT_MSG_PUBLISH_NAMESPACE
        || q->type == XQC_MOQT_MSG_SUBSCRIBE_TRACKS)
    {
        xqc_moqt_message_t m;
        xqc_memzero(&m, sizeof(m));
        m.type = XQC_MOQT_MSG_REQUEST_OK;
        xqc_moqt_relay_response(q, &m);
        xqc_moqt_relay_tracks(q);
        if (q->type == XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE) {
            for (xqc_moqt_relay_request_t *source = r->requests;
                 source != NULL; source = source->next)
            {
                if (source->registered) {
                    xqc_moqt_relay_namespace_notify(q, source, XQC_TRUE);
                }
            }
        }
        return;
    }
    q->deadline = xqc_moqt_relay_deadline(xqc_monotonic_timestamp(),
                                          UINT64_MAX, r->config.timeout);
    xqc_moqt_relay_queue_new_group(q, message);
    for (xqc_moqt_relay_request_t *up = r->requests; up; up = up->next) {
        if (up->parent != q || up->stopped) {
            continue;
        }
        /* Existing Fill FETCH snapshots are independent of a live update. */
        if (up->type != XQC_MOQT_MSG_SUBSCRIBE) {
            continue;
        }
        /* The same publisher already supplies this Track on PUBLISH. */
        if (!up->established && q->selected != NULL
            && q->selected->type == XQC_MOQT_MSG_PUBLISH
            && q->selected->established && !q->selected->stopped
            && up->peer == q->selected->peer)
        {
            xqc_moqt_relay_stop(up, XQC_MOQT_RESET_CANCELLED);
            continue;
        }
        /* Other publishers can still establish and receive this update. */
        q->pending++;
        if (!up->established) {
            continue;
        }
        xqc_moqt_message_t m = *message;
        if (up->request == NULL
            || xqc_moqt_relay_forward_message(up->peer, &m) != XQC_OK
            || xqc_moqt_request_send(up->request, &m) != XQC_OK)
        {
            q->pending--;
            xqc_moqt_relay_stop(up, XQC_MOQT_RESET_EXCESSIVE_LOAD);
        } else {
            up->waiting_update = 1;
        }
    }
    if (!q->pending) {
        /* Direct PUBLISH already supplies the Track; pause is aggregated. */
        xqc_moqt_message_t m;
        xqc_memzero(&m, sizeof(m));
        m.type = XQC_MOQT_MSG_REQUEST_OK;
        xqc_moqt_relay_response(q, &m);
    }
    xqc_moqt_relay_pause_sources(r);
}

static void
xqc_moqt_relay_upstream_response(xqc_moqt_relay_request_t *up,
    const xqc_moqt_message_t *m)
{
    xqc_moqt_relay_t *r = up->peer->relay;
    xqc_moqt_relay_request_t *down = up->parent;
    if (up->type == XQC_MOQT_MSG_SUBSCRIBE_TRACKS
        || (up->type == XQC_MOQT_MSG_PUBLISH && !up->upstream))
    {
        if (m->type == XQC_MOQT_MSG_REQUEST_ERROR) {
            xqc_moqt_relay_stop(up, XQC_MOQT_RESET_CANCELLED);
        } else {
            up->established = 1;
        }
        xqc_moqt_relay_pause_sources(r);
        return;
    }
    if (up->fetch != NULL
        && up->fetch->downstream->type != XQC_MOQT_MSG_FETCH)
    {
        xqc_moqt_relay_fetch_response(up, m);
        return;
    }
    xqc_bool_t updated = up->waiting_update;
    up->waiting_update = 0;
    if (down == NULL) {
        if (m->type == XQC_MOQT_MSG_REQUEST_ERROR) {
            xqc_moqt_relay_stop(up, XQC_MOQT_RESET_CANCELLED);
        }
        xqc_moqt_relay_pause_sources(r);
        return;
    }
    if (down->stopped) {
        xqc_moqt_relay_stop(up, XQC_MOQT_RESET_CANCELLED);
        return;
    }
    if (m->type == XQC_MOQT_MSG_REQUEST_ERROR) {
        up->stopped = 1;
        xqc_moqt_message_t cached;
        if (down->type == XQC_MOQT_MSG_FETCH && !down->established
            && m->error.normalized_code == XQC_MOQT_REQUEST_NOT_SUPPORTED
            && xqc_moqt_relay_history_answer(down, &cached))
        {
            xqc_moqt_relay_response(down, &cached);
            return;
        }
        /* Initial responses also hold a slot in an in-flight update. */
        if (down->waiting_update && down->pending) {
            down->pending--;
        }
        xqc_moqt_relay_request_t *remaining = NULL;
        for (xqc_moqt_relay_request_t *other = r->requests;
             other != NULL; other = other->next)
        {
            if (!other->stopped && (other->parent == down
                || (down->established && xqc_moqt_relay_live_source(down,
                                                                  other))))
            {
                remaining = other;
            }
        }
        if (!remaining && down->request != NULL) {
            if (down->awaiting_done && !down->waiting_update) {
                xqc_moqt_relay_end_subscription(down);
            } else if (!down->established || down->waiting_update) {
                xqc_moqt_relay_reject(down, m->error.normalized_code);
            } else {
                xqc_moqt_relay_stop(down, XQC_MOQT_RESET_CANCELLED);
            }
        } else if (remaining != NULL
                   && down->waiting_update
                   && !down->pending)
        {
            /* A failed source must not withhold an accepted healthy grant. */
            xqc_moqt_message_t response;
            if (xqc_moqt_relay_message_read(down->response,
                XQC_MOQT_MSG_REQUEST_UPDATE, &response) >= 0)
            {
                xqc_moqt_relay_response(down, &response);
            }
        }
        return;
    }
    up->established = 1;
    down->awaiting_done = 0;
    if (!updated) {
        xqc_moqt_relay_buffer_free(r, up->response);
        up->response = xqc_moqt_relay_message_copy(up->peer, m, up->type);
    }
    if (up->response == NULL) {
        xqc_moqt_relay_stop(up, XQC_MOQT_RESET_EXCESSIVE_LOAD);
        return;
    }
    if (!down->established) {
        /* Section 7.4: the upstream has committed Established before this. */
        down->selected = up;
        xqc_moqt_relay_response(down, m);
    } else if (updated) {
        if (down->pending) {
            down->pending--;
        }
        /* Keep the last successful update separately from Track properties. */
        xqc_moqt_relay_buffer_free(r, down->response);
        down->response = xqc_moqt_relay_message_copy(
            up->peer, m, XQC_MOQT_MSG_REQUEST_UPDATE);
        if (down->response == NULL) {
            xqc_moqt_relay_stop(down, XQC_MOQT_RESET_EXCESSIVE_LOAD);
            return;
        }
        down->selected = up;
        if (down->waiting_update && !down->pending) {
            xqc_moqt_relay_response(down, m);
        }
    } else if (down->waiting_update) {
        xqc_moqt_message_t update;
        xqc_moqt_relay_message_read(down->update, down->type, &update);
        if (xqc_moqt_relay_forward_message(up->peer, &update) != XQC_OK
            || xqc_moqt_request_send(up->request, &update) != XQC_OK)
        {
            if (down->pending) {
                down->pending--;
            }
            xqc_moqt_relay_stop(up, XQC_MOQT_RESET_EXCESSIVE_LOAD);
            /* A late source failure must not strand an accepted update. */
            if (!down->pending
                && xqc_moqt_relay_message_read(down->response,
                    XQC_MOQT_MSG_REQUEST_UPDATE, &update) >= 0)
            {
                xqc_moqt_relay_response(down, &update);
            }
        } else {
            up->waiting_update = 1;
        }
    }
}

static void
xqc_moqt_relay_message(xqc_moqt_request_t *request,
    const xqc_moqt_message_t *m, void *data)
{
    xqc_moqt_relay_peer_t *peer = data;
    xqc_moqt_relay_t *r = peer->relay;
    xqc_moqt_relay_request_t *q = xqc_moqt_relay_request_find(peer, request);
    if (xqc_moqt_is_initial_request(m->type)) {
        q = xqc_moqt_relay_request_create(peer, request, m);
        if (q == NULL) {
            xqc_moqt_relay_error(request, XQC_MOQT_REQUEST_EXCESSIVE_LOAD);
            return;
        }
        xqc_moqt_message_t response;
        xqc_memzero(&response, sizeof(response));
        response.type = XQC_MOQT_MSG_REQUEST_OK;
        switch (m->type) {
        case XQC_MOQT_MSG_PUBLISH_NAMESPACE:
            xqc_moqt_relay_response(q, &response);
            if (!q->stopped) {
                q->registered = 1;
                xqc_moqt_relay_namespace_changed(q, XQC_TRUE);
                xqc_moqt_relay_routes(r);
            }
            break;
        case XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE:
            xqc_moqt_relay_response(q, &response);
            for (xqc_moqt_relay_request_t *source = r->requests;
                 source != NULL; source = source->next)
            {
                if (source->registered) {
                    xqc_moqt_relay_namespace_notify(q, source, XQC_TRUE);
                }
            }
            break;
        case XQC_MOQT_MSG_SUBSCRIBE_TRACKS:
            xqc_moqt_relay_response(q, &response);
            xqc_moqt_relay_tracks(q);
            xqc_moqt_relay_pause_sources(r);
            break;
        case XQC_MOQT_MSG_PUBLISH:
            q->upstream = 1;
            xqc_moqt_relay_history_enable(q, m);
            xqc_moqt_relay_response(q, &response);
            xqc_moqt_relay_routes(r);
            xqc_moqt_relay_pause_sources(r);
            break;
        case XQC_MOQT_MSG_SUBSCRIBE: {
            uint64_t ms = xqc_moqt_relay_parameter(m,
                XQC_MOQT_PARAM_RENDEZVOUS_TIMEOUT, 0);
            if (ms) {
                q->deadline = xqc_moqt_relay_deadline(
                    xqc_monotonic_timestamp(), ms, r->config.timeout);
            }
            xqc_moqt_relay_route(q);
            xqc_moqt_relay_queue_new_group(q, m);
            xqc_moqt_relay_pause_sources(r);
            break;
        }
        case XQC_MOQT_MSG_FETCH: {
            uint64_t ms = xqc_moqt_relay_parameter(m,
                XQC_MOQT_PARAM_FILL_TIMEOUT, UINT64_MAX);
            q->deadline = xqc_moqt_relay_deadline(q->operation_started, ms,
                                                  r->config.timeout);
            if (!ms) {
                xqc_moqt_relay_reject(q, XQC_MOQT_REQUEST_TIMEOUT);
            } else {
                xqc_moqt_relay_route(q);
            }
            break;
        }
        case XQC_MOQT_MSG_TRACK_STATUS:
            xqc_moqt_relay_route(q);
            break;
        default:
            xqc_moqt_relay_error(request, XQC_MOQT_REQUEST_NOT_SUPPORTED);
            q->stopped = 1;
            break;
        }
        return;
    }
    if (q == NULL || q->stopped || q->ending || q->ended) {
        return;
    }
    switch (m->type) {
    case XQC_MOQT_MSG_REQUEST_UPDATE:
        xqc_moqt_relay_update(q, m);
        break;
    case XQC_MOQT_MSG_SUBSCRIBE_OK:
    case XQC_MOQT_MSG_FETCH_OK:
    case XQC_MOQT_MSG_REQUEST_OK:
    case XQC_MOQT_MSG_REQUEST_ERROR:
        xqc_moqt_relay_upstream_response(q, m);
        break;
    case XQC_MOQT_MSG_PUBLISH_STATE_NOTIFY:
        for (xqc_moqt_relay_request_t *down = r->requests;
             down != NULL; down = down->next)
        {
            /* Section 9.10: state notifications apply only to subscriptions. */
            if (down->subscription == NULL) {
                continue;
            }
            if (down->upstream || !down->established || down->stopped) {
                continue;
            }
            /* Independent upstream grants cannot update another subscriber. */
            if (q->parent != NULL && q->parent != down) {
                continue;
            }
            if (down->type == XQC_MOQT_MSG_PUBLISH && down->selected != q) {
                continue;
            }
            if (down->track == q->track && down->request != NULL) {
                if (xqc_moqt_request_send(down->request, m) != XQC_OK) {
                    xqc_moqt_relay_stop(down, XQC_MOQT_RESET_EXCESSIVE_LOAD);
                }
            }
        }
        break;
    case XQC_MOQT_MSG_PUBLISH_DONE:
        /* Keep delivery until the endpoint has drained the announced count. */
        break;
    case XQC_MOQT_MSG_GOAWAY:
        /* Application-selected reconnection does not move other peers. */
        break;
    default:
        break;
    }
}

static void
xqc_moqt_relay_publish_skipped(xqc_moqt_request_t *request,
    const xqc_moqt_namespace_t *name, const struct iovec *track_name,
    void *data)
{
    xqc_moqt_relay_peer_t *peer = data;
    xqc_moqt_relay_t *r = peer->relay;
    if (r->next_publication == UINT64_MAX) {
        xqc_moqt_request_cancel(request, XQC_MOQT_RESET_EXCESSIVE_LOAD);
        return;
    }
    uint64_t id = ++r->next_publication;
    for (xqc_moqt_relay_request_t *watch = r->requests; watch;
         watch = watch->next)
    {
        if (watch->type != XQC_MOQT_MSG_SUBSCRIBE_TRACKS || watch->upstream) {
            continue;
        }
        if (!watch->established || watch->stopped || watch->request == NULL) {
            continue;
        }
        if (watch->peer == peer
            || !xqc_moqt_relay_scope_equal(watch->peer->scope, peer->scope))
        {
            continue;
        }
        xqc_moqt_message_t m;
        xqc_memzero(&m, sizeof(m));
        m.type = XQC_MOQT_MSG_PUBLISH;
        m.track_namespace = *name;
        m.track_name = *track_name;
        if (xqc_moqt_relay_forward_message(watch->peer, &m) == XQC_OK) {
            xqc_moqt_request_skip(watch->request, id, &m);
        }
    }
}

static void
xqc_moqt_relay_request_closed(xqc_moqt_request_t *request,
    const xqc_moqt_error_t *error, void *data)
{
    xqc_moqt_relay_peer_t *peer = data;
    xqc_moqt_relay_request_t *q = xqc_moqt_relay_request_find(peer, request);
    if (q == NULL) {
        return;
    }
    q->request = NULL;
    if (q->type == XQC_MOQT_MSG_SUBSCRIBE_TRACKS) {
        q->stopped = 1;
    }
    if (q->registered) {
        q->registered = 0;
        xqc_moqt_relay_namespace_changed(q, XQC_FALSE);
    }
    if (error != NULL && error->context != XQC_MOQT_ERROR_PUBLISH_DONE) {
        xqc_moqt_relay_stop(q, XQC_MOQT_RESET_CANCELLED);
    }
}

static void
xqc_moqt_relay_subscription_closed(xqc_moqt_subscription_t *subscription,
    const xqc_moqt_error_t *error, void *data)
{
    xqc_moqt_relay_peer_t *peer = data;
    xqc_moqt_relay_t *r = peer->relay;
    xqc_moqt_relay_request_t *q = xqc_moqt_relay_subscription_find(peer,
        subscription);
    if (q == NULL) {
        return;
    }
    xqc_bool_t malformed = q->upstream && !q->stopped && error != NULL
        && error->context == XQC_MOQT_ERROR_RESET
        && error->normalized_code == XQC_MOQT_RESET_MALFORMED_TRACK;
    q->subscription = NULL;
    q->stopped = 1;
    if (malformed) {
        xqc_moqt_relay_malformed(q);
    }
    for (xqc_moqt_relay_request_t *other = r->requests;
         other != NULL; other = other->next)
    {
        if (other->parent == q) {
            xqc_moqt_relay_stop(other, XQC_MOQT_RESET_CANCELLED);
        }
    }
    if (q->upstream && !malformed) {
        for (xqc_moqt_relay_request_t *down = r->requests;
             down != NULL; down = down->next)
        {
            /* Live source loss does not terminate independent history. */
            if (down->subscription == NULL) {
                continue;
            }
            if (down->upstream || down->track != q->track || down->stopped
                || down->ending || down->ended)
            {
                continue;
            }
            if (q->parent != NULL && q->parent != down) {
                continue;
            }
            if (down->type == XQC_MOQT_MSG_PUBLISH && down->selected != q) {
                continue;
            }
            xqc_bool_t remaining = XQC_FALSE, established = XQC_FALSE;
            for (xqc_moqt_relay_request_t *up = r->requests;
                 up != NULL; up = up->next)
            {
                if (!up->stopped && xqc_moqt_relay_live_source(down, up)) {
                    remaining = XQC_TRUE;
                    established |= up->established;
                }
            }
            if (!established && (error == NULL
                || error->context == XQC_MOQT_ERROR_PUBLISH_DONE))
            {
                /* Draft-22 §9.9: preserve completion across pending sources. */
                down->awaiting_done = 1;
                down->done_code = error == NULL ? XQC_MOQT_PUBLISH_TRACK_ENDED
                                                : error->normalized_code;
            }
            if (!remaining) {
                if (down->awaiting_done && down->waiting_update) {
                    xqc_moqt_relay_reject(down, XQC_MOQT_REQUEST_TIMEOUT);
                } else if (down->awaiting_done) {
                    xqc_moqt_relay_end_subscription(down);
                } else {
                    xqc_moqt_relay_stop(down,
                                        error->context == XQC_MOQT_ERROR_RESET
                                        ? error->normalized_code
                                        : XQC_MOQT_RESET_SESSION_CLOSED);
                }
            }
        }
    }
    xqc_moqt_relay_pause_sources(r);
}

static void
xqc_moqt_relay_closed(xqc_moqt_session_t *session, uint64_t error, void *data)
{
    xqc_moqt_relay_peer_t *peer = data;
    peer->closed = 1;
    for (xqc_moqt_relay_request_t *q = peer->relay->requests;
         q != NULL; q = q->next)
    {
        if (q->peer == peer) {
            if (q->registered) {
                q->registered = 0;
                xqc_moqt_relay_namespace_changed(q, XQC_FALSE);
            }
            xqc_moqt_relay_stop(q, XQC_MOQT_RESET_SESSION_CLOSED);
        }
    }
    if (peer->relay->callbacks.on_closed != NULL) {
        peer->relay->callbacks.on_closed(peer, error, peer->user_data);
    }
}

void
xqc_moqt_relay_config_init(xqc_moqt_relay_config_t *config)
{
    *config = (xqc_moqt_relay_config_t){XQC_MOQT_RELAY_DEFAULT_PEERS,
        XQC_MOQT_RELAY_DEFAULT_REQUESTS, XQC_MOQT_RELAY_DEFAULT_STREAMS,
        XQC_MOQT_RELAY_DEFAULT_BYTES, XQC_MOQT_RELAY_DEFAULT_TIMEOUT};
}

xqc_moqt_relay_t *
xqc_moqt_relay_create(const xqc_moqt_relay_config_t *config,
    const xqc_moqt_relay_callbacks_t *callbacks)
{
    if (config == NULL || callbacks == NULL) {
        return NULL;
    }
    /* Finite object counts and bytes are independent admission gates. */
    if (!config->max_peers || !config->max_requests || !config->max_streams) {
        return NULL;
    }
    if (config->max_bytes < sizeof(xqc_moqt_relay_t) || !config->timeout) {
        return NULL;
    }
    /* Relay policy must be explicit on both incoming and outgoing hops. */
    if (callbacks->on_setup == NULL
        || callbacks->on_authorize == NULL
        || callbacks->on_forward == NULL)
    {
        return NULL;
    }
    xqc_moqt_relay_t *r = xqc_calloc(1, sizeof(*r));
    if (r != NULL) {
        r->config = *config;
        r->callbacks = *callbacks;
        r->stats.bytes = sizeof(*r);
    }
    return r;
}

static xqc_moqt_relay_peer_t *
xqc_moqt_relay_peer_create_internal(xqc_moqt_relay_t *r,
    xqc_connection_t *conn, struct xqc_webtransport_session_s *wt,
    const xqc_moqt_config_t *config, const struct iovec *scope, void *data,
    xqc_bool_t draft07_compat)
{
    if (r == NULL || scope == NULL || config == NULL) {
        return NULL;
    }
    if (config->setup_option_count > XQC_MOQT_MAX_OPTIONS
        || (config->setup_option_count && config->setup_options == NULL))
    {
        return NULL;
    }
    if (r->stats.peers == r->config.max_peers
        || scope->iov_len > XQC_MOQT_NAME_MAX_LEN
        || (scope->iov_len && scope->iov_base == NULL))
    {
        return NULL;
    }
    xqc_moqt_relay_peer_t *peer = xqc_moqt_relay_alloc(r, sizeof(*peer));
    if (peer == NULL) {
        return NULL;
    }
    peer->scope = xqc_moqt_relay_buffer(r, scope->iov_base, scope->iov_len);
    if (peer->scope == NULL) {
        xqc_moqt_relay_free(r, peer, sizeof(*peer));
        return NULL;
    }
    peer->relay = r;
    peer->user_data = data;
    xqc_moqt_callbacks_t callbacks = {
        .on_setup = xqc_moqt_relay_setup,
        .on_closed = xqc_moqt_relay_closed,
        .on_authorize = xqc_moqt_relay_authorize,
        .on_message = xqc_moqt_relay_message,
        .on_request_closed = xqc_moqt_relay_request_closed,
        .on_publish_skipped = xqc_moqt_relay_publish_skipped,
        .on_subscription_closed = xqc_moqt_relay_subscription_closed,
        .on_fetch_ready = xqc_moqt_relay_fetch_ready,
        .on_fetch_closed = xqc_moqt_relay_fetch_closed,
        .on_object = xqc_moqt_relay_object,
        .on_stream_closed = xqc_moqt_relay_stream_closed,
        .on_writable = xqc_moqt_relay_writable,
    };
    xqc_moqt_config_t endpoint = *config;
    xqc_moqt_kv_t options[XQC_MOQT_MAX_OPTIONS];
    size_t count = 0;
    for (size_t i = 0; i < config->setup_option_count; i++) {
        if (config->setup_options[i].type != XQC_MOQT_OPT_MAX_REQUEST_UPDATES) {
            if (count == XQC_MOQT_MAX_OPTIONS - 1) {
                xqc_moqt_relay_buffer_free(r, peer->scope);
                xqc_moqt_relay_free(r, peer, sizeof(*peer));
                return NULL;
            }
            options[count++] = config->setup_options[i];
        }
    }
    size_t pos = count;
    while (pos && options[pos - 1].type > XQC_MOQT_OPT_MAX_REQUEST_UPDATES) {
        options[pos] = options[pos - 1];
        pos--;
    }
    options[pos].type = XQC_MOQT_OPT_MAX_REQUEST_UPDATES;
    options[pos].value.integer = XQC_MOQT_RELAY_UPDATE_CREDIT;
    endpoint.setup_options = options;
    endpoint.setup_option_count = count + 1;
#ifdef XQC_ENABLE_WEBTRANSPORT
    if (wt != NULL) {
        peer->session = draft07_compat
            ? xqc_moqt_session_create_webtransport_compat(wt, &endpoint,
                &callbacks, peer)
            : xqc_moqt_session_create_webtransport(wt, &endpoint,
                &callbacks, peer);
    } else
#endif
    {
        peer->session = xqc_moqt_session_create(conn, &endpoint, &callbacks,
                                                peer);
    }
    if (peer->session == NULL) {
        xqc_moqt_relay_buffer_free(r, peer->scope);
        xqc_moqt_relay_free(r, peer, sizeof(*peer));
        return NULL;
    }
    peer->next = r->peers;
    r->peers = peer;
    r->stats.peers++;
    return peer;
}

xqc_moqt_relay_peer_t *
xqc_moqt_relay_peer_create(xqc_moqt_relay_t *r, xqc_connection_t *conn,
    const xqc_moqt_config_t *config, const struct iovec *scope, void *data)
{
    return xqc_moqt_relay_peer_create_internal(r, conn, NULL, config, scope,
                                                data, XQC_FALSE);
}

#ifdef XQC_ENABLE_WEBTRANSPORT
xqc_moqt_relay_peer_t *
xqc_moqt_relay_peer_create_webtransport(xqc_moqt_relay_t *r,
    xqc_wt_session_t *wt, const xqc_moqt_config_t *config,
    const struct iovec *scope, void *data)
{
    if (wt == NULL) {
        return NULL;
    }
    return xqc_moqt_relay_peer_create_internal(r, NULL, wt, config, scope, data,
                                                XQC_FALSE);
}

xqc_moqt_relay_peer_t *
xqc_moqt_relay_peer_create_webtransport_compat(xqc_moqt_relay_t *r,
    xqc_wt_session_t *wt, const xqc_moqt_config_t *config,
    const struct iovec *scope, void *data)
{
    if (wt == NULL) {
        return NULL;
    }
    return xqc_moqt_relay_peer_create_internal(r, NULL, wt, config, scope, data,
                                                XQC_TRUE);
}
#endif

xqc_moqt_session_t *
xqc_moqt_relay_peer_session(xqc_moqt_relay_peer_t *peer)
{
    return peer == NULL ? NULL : peer->session;
}

void
xqc_moqt_relay_peer_destroy(xqc_moqt_relay_peer_t *peer)
{
    if (peer != NULL && peer->session != NULL) {
        xqc_moqt_session_t *session = peer->session;
        peer->session = NULL;
        peer->closed = 1;
        xqc_moqt_session_destroy(session);
    }
}

static xqc_int_t
xqc_moqt_relay_request_is_referenced(xqc_moqt_relay_t *r,
    xqc_moqt_relay_request_t *q)
{
    for (xqc_moqt_relay_request_t *other = r->requests;
         other != NULL; other = other->next)
    {
        if (other->parent == q || other->history_source == q) {
            return XQC_TRUE;
        }
    }
    for (xqc_moqt_relay_fetch_t *f = r->fetches; f != NULL; f = f->next) {
        if (f->upstream == q || f->downstream == q || f->history_owner == q) {
            return XQC_TRUE;
        }
    }
    for (xqc_moqt_relay_stream_t *st = r->streams; st != NULL; st = st->next) {
        if (st->upstream == q || st->downstream == q) {
            return XQC_TRUE;
        }
    }
    return XQC_FALSE;
}

xqc_usec_t
xqc_moqt_relay_process(xqc_moqt_relay_t *r, xqc_usec_t now)
{
    if (r == NULL) {
        return 0;
    }
    xqc_usec_t next = xqc_moqt_relay_history_collect(r, now);
    for (xqc_moqt_relay_request_t *q = r->requests; q != NULL; q = q->next) {
        if (q->type == XQC_MOQT_MSG_SUBSCRIBE_TRACKS
            && q->upstream && !q->stopped)
        {
            xqc_bool_t needed = XQC_FALSE;
            for (xqc_moqt_relay_request_t *watch = r->requests; watch;
                 watch = watch->next)
            {
                if (watch->type != XQC_MOQT_MSG_SUBSCRIBE_TRACKS
                    || watch->upstream || watch->stopped)
                {
                    continue;
                }
                needed |= watch->request != NULL && watch->peer != q->peer
                    && xqc_moqt_relay_scope_equal(watch->peer->scope,
                                                  q->peer->scope);
            }
            if (!needed) {
                xqc_moqt_relay_stop(q, XQC_MOQT_RESET_CANCELLED);
            }
        }
        if (!q->deadline || q->stopped) {
            continue;
        }
        if (q->ending && q->request != NULL) {
            xqc_moqt_message_t done;
            xqc_memzero(&done, sizeof(done));
            done.type = XQC_MOQT_MSG_PUBLISH_DONE;
            done.error.code = q->done_code;
            xqc_int_t ret = xqc_moqt_request_send(q->request, &done);
            if (ret == XQC_OK) {
                q->ending = 0;
                q->ended = 1;
                q->deadline = 0;
                continue;
            }
            if (ret != -XQC_EAGAIN) {
                xqc_moqt_relay_stop(q, XQC_MOQT_RESET_TOO_FAR_BEHIND);
                continue;
            }
            xqc_usec_t retry = now > UINT64_MAX - XQC_MOQT_RELAY_RETRY_US
                ? UINT64_MAX : now + XQC_MOQT_RELAY_RETRY_US;
            if (!next || retry < next) {
                next = retry;
            }
        }
        if (q->deadline <= now) {
            r->stats.timeouts++;
            if (q->ending) {
                xqc_moqt_relay_stop(q, XQC_MOQT_RESET_TOO_FAR_BEHIND);
            } else {
                xqc_moqt_relay_reject(q, XQC_MOQT_REQUEST_TIMEOUT);
            }
        } else if (!next || q->deadline < next) {
            next = q->deadline;
        }
    }
    for (xqc_moqt_relay_fetch_t *f = r->fetches; f != NULL; f = f->next) {
        if (f->closed || !f->deadline) {
            continue;
        }
        if (f->timed_out || f->deadline <= now) {
            xqc_moqt_relay_fetch_expire(f, now);
            if (!f->closed && f->deadline != 0) {
                xqc_usec_t delay = xqc_min(f->deadline - now,
                                           XQC_MOQT_RELAY_RETRY_US);
                if (!next || now + delay < next) {
                    next = now + delay;
                }
            }
        } else if (!next || f->deadline < next) {
            next = f->deadline;
        }
    }
    xqc_moqt_relay_pause_sources(r);
    xqc_moqt_relay_stream_t **stream = &r->streams;
    while (*stream != NULL) {
        xqc_moqt_relay_stream_t *st = *stream;
        if (st->input != NULL || st->output != NULL) {
            stream = &st->next;
            continue;
        }
        *stream = st->next;
        r->stats.streams--;
        xqc_moqt_relay_free(r, st, sizeof(*st));
    }
    xqc_moqt_relay_fetch_t **fetch = &r->fetches;
    while (*fetch != NULL) {
        xqc_moqt_relay_fetch_t *f = *fetch;
        xqc_bool_t referenced = XQC_FALSE;
        for (xqc_moqt_relay_stream_t *st = r->streams; st; st = st->next) {
            referenced |= st->fetch == f;
        }
        if (f->input != NULL || f->output != NULL || referenced) {
            fetch = &f->next;
            continue;
        }
        *fetch = f->next;
        if (f->upstream != NULL) {
            f->upstream->fetch = NULL;
        }
        xqc_moqt_relay_history_release(f);
        xqc_moqt_relay_free(r, f, sizeof(*f));
    }
    xqc_moqt_relay_request_t **request = &r->requests;
    while (*request != NULL) {
        xqc_moqt_relay_request_t *q = *request;
        if (q->request != NULL || q->subscription != NULL
            || xqc_moqt_relay_request_is_referenced(r, q))
        {
            request = &q->next;
            continue;
        }
        *request = q->next;
        for (xqc_moqt_relay_request_t *other = r->requests;
             other != NULL; other = other->next)
        {
            if (other->selected == q) {
                other->selected = NULL;
            }
        }
        if (q->track != NULL) {
            q->track->references--;
        }
        xqc_moqt_relay_buffer_free(r, q->state);
        xqc_moqt_relay_buffer_free(r, q->response);
        xqc_moqt_relay_buffer_free(r, q->candidate);
        xqc_moqt_relay_buffer_free(r, q->update);
        xqc_moqt_relay_history_clear(q);
        r->stats.requests--;
        xqc_moqt_relay_free(r, q, sizeof(*q));
    }
    xqc_moqt_relay_track_t **track = &r->tracks;
    while (*track != NULL) {
        xqc_moqt_relay_track_t *t = *track;
        if (t->references) {
            track = &t->next;
            continue;
        }
        *track = t->next;
        xqc_moqt_relay_buffer_free(r, t->name);
        xqc_moqt_relay_buffer_free(r, t->scope);
        xqc_moqt_relay_free(r, t, sizeof(*t));
    }
    xqc_moqt_relay_peer_t **peer = &r->peers;
    while (*peer != NULL) {
        xqc_moqt_relay_peer_t *p = *peer;
        xqc_bool_t referenced = XQC_FALSE;
        for (xqc_moqt_relay_request_t *q = r->requests; q; q = q->next) {
            referenced |= q->peer == p;
        }
        if (p->session != NULL || referenced) {
            peer = &p->next;
            continue;
        }
        *peer = p->next;
        r->stats.peers--;
        xqc_moqt_relay_buffer_free(r, p->scope);
        xqc_moqt_relay_free(r, p, sizeof(*p));
    }
    return next;
}

const xqc_moqt_relay_stats_t *
xqc_moqt_relay_stats(const xqc_moqt_relay_t *relay)
{
    return relay == NULL ? NULL : &relay->stats;
}

void
xqc_moqt_relay_destroy(xqc_moqt_relay_t *r)
{
    if (r == NULL) {
        return;
    }
    for (xqc_moqt_relay_peer_t *p = r->peers; p != NULL; p = p->next) {
        xqc_moqt_relay_peer_destroy(p);
    }
    /* Child mappings precede their parents; collection may expose a parent. */
    while (r->stats.requests || r->stats.streams || r->stats.peers) {
        xqc_moqt_relay_process(r, UINT64_MAX);
    }
    xqc_free(r);
}
