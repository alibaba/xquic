/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include "xqc_moqt_relay.h"
#include "src/common/xqc_time.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"

static void
xqc_moqt_relay_stream_finish(xqc_moqt_relay_stream_t *st)
{
    if (st->output == NULL || st->closed) {
        return;
    }
    xqc_int_t ret = xqc_moqt_stream_finish(st->output);
    st->finishing = ret == -XQC_EAGAIN;
    if (ret != XQC_OK && ret != -XQC_EAGAIN) {
        xqc_moqt_stream_cancel(st->output, XQC_MOQT_RESET_EXCESSIVE_LOAD);
    }
}

static xqc_moqt_relay_stream_t *
xqc_moqt_relay_stream_get(xqc_moqt_relay_request_t *up,
    xqc_moqt_relay_request_t *down, xqc_moqt_stream_t *input,
    xqc_moqt_relay_fetch_t *fetch)
{
    xqc_moqt_relay_t *r = up->peer->relay;
    for (xqc_moqt_relay_stream_t *st = r->streams; st; st = st->next) {
        if (st->input == input && st->downstream == down && !st->closed) {
            return st;
        }
    }
    if (r->stats.streams == r->config.max_streams) {
        return NULL;
    }
    xqc_moqt_relay_stream_t *st = xqc_moqt_relay_alloc(r, sizeof(*st));
    if (st == NULL) {
        return NULL;
    }
    st->input = input;
    st->upstream = up;
    st->downstream = down;
    st->fetch = fetch;
    st->next = r->streams;
    r->streams = st;
    r->stats.streams++;
    return st;
}

void
xqc_moqt_relay_fetch_stop(xqc_moqt_relay_fetch_t *f, uint64_t code)
{
    if (f->closed) {
        return;
    }
    f->closed = 1;
    f->deadline = 0;
    if (f->input != NULL && !f->upstream->peer->closed) {
        xqc_moqt_fetch_cancel(f->input, code);
    }
    if (f->output != NULL && !f->downstream->peer->closed) {
        xqc_moqt_fetch_cancel(f->output, code);
    }
    if (f->upstream != NULL) {
        xqc_moqt_relay_stop(f->upstream, code);
    }
}

static xqc_moqt_relay_request_t *
xqc_moqt_relay_fetch_request_find(xqc_moqt_relay_peer_t *peer,
    xqc_moqt_fetch_t *fetch, xqc_moqt_subscription_t *subscription)
{
    if (subscription != NULL) {
        return xqc_moqt_relay_subscription_find(peer, subscription);
    }
    for (xqc_moqt_relay_request_t *q = peer->relay->requests; q; q = q->next) {
        if (q->peer == peer && q->request != NULL
            && xqc_moqt_request_fetch(q->request) == fetch)
        {
            return q;
        }
    }
    return NULL;
}

static xqc_int_t
xqc_moqt_relay_fill_open(xqc_moqt_relay_fetch_t *f)
{
    xqc_moqt_relay_request_t *down = f->downstream;
    const xqc_moqt_fetch_info_t *info = xqc_moqt_fetch_info(f->output);
    xqc_moqt_message_t m;
    xqc_moqt_relay_message_read(down->state, 0, &m);
    m.type = XQC_MOQT_MSG_FETCH;
    m.parameter_count = 0;
    xqc_memzero(&m.properties, sizeof(m.properties));
    uint64_t fields[] = {XQC_MOQT_FILTER_ABSOLUTE_RANGE,
        info->start.group_id, info->start.object_id,
        info->end.group_id - info->start.group_id, info->end.object_id};
    uint8_t filter[sizeof(fields) / sizeof(fields[0]) * XQC_VI64_MAX_LEN];
    size_t len = 0;
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        len += xqc_vi64_write(filter + len, filter + sizeof(filter), fields[i]);
    }
    uint8_t order = info->group_order;
    uint8_t priority = info->subscriber_priority;
    xqc_usec_t now = xqc_monotonic_timestamp();
    xqc_usec_t remaining = now < f->deadline ? f->deadline - now : 0;
    uint8_t timeout[XQC_VI64_MAX_LEN];
    xqc_int_t timeout_length = xqc_vi64_write(timeout,
        timeout + sizeof(timeout), remaining / XQC_MOQT_MICROS_PER_MILLISECOND);
    /* Message Parameters are delta encoded in increasing type order. */
    m.parameters[m.parameter_count++] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_FILL_TIMEOUT, timeout_length, timeout};
    m.parameters[m.parameter_count++] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_SUBSCRIBER_PRIORITY, 1, &priority};
    m.parameters[m.parameter_count++] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_LOCATION_FILTER, len, filter};
    m.parameters[m.parameter_count++] = (xqc_moq_message_parameter_t){
        XQC_MOQT_PARAM_GROUP_ORDER, 1, &order};
    if (down->selected == NULL || down->selected->peer->closed) {
        return XQC_ERROR;
    }
    f->upstream = xqc_moqt_relay_request_open(down,
                                              down->selected->peer, &m);
    if (f->upstream == NULL) {
        return XQC_ERROR;
    }
    f->upstream->fetch = f;
    return XQC_OK;
}

void
xqc_moqt_relay_fetch_ready(xqc_moqt_fetch_t *fetch,
    xqc_moqt_subscription_t *subscription, void *data)
{
    xqc_moqt_relay_peer_t *peer = data;
    xqc_moqt_relay_t *r = peer->relay;
    xqc_moqt_relay_request_t *q = xqc_moqt_relay_fetch_request_find(peer,
        fetch, subscription);
    if (q == NULL || q->stopped) {
        xqc_moqt_fetch_cancel(fetch, XQC_MOQT_RESET_CANCELLED);
        return;
    }
    if (q->upstream) {
        if (q->fetch == NULL || q->fetch->closed) {
            xqc_moqt_fetch_cancel(fetch, XQC_MOQT_RESET_CANCELLED);
        } else {
            q->fetch->input = fetch;
        }
        return;
    }
    xqc_moqt_relay_fetch_t *f = xqc_moqt_relay_alloc(r, sizeof(*f));
    if (f == NULL) {
        xqc_moqt_fetch_cancel(fetch, XQC_MOQT_RESET_EXCESSIVE_LOAD);
        return;
    }
    f->downstream = q;
    f->output = fetch;
    const xqc_moqt_fetch_info_t *info = xqc_moqt_fetch_info(fetch);
    f->deadline = xqc_moqt_relay_deadline(q->operation_started,
        info->has_fill_timeout ? info->fill_timeout : UINT64_MAX,
        r->config.timeout);
    f->next = r->fetches;
    r->fetches = f;
    f->stream = xqc_moqt_fetch_open(fetch);
    if (f->stream == NULL) {
        xqc_moqt_relay_fetch_stop(f, XQC_MOQT_RESET_EXCESSIVE_LOAD);
        return;
    }
    if (f->deadline <= xqc_monotonic_timestamp()) {
        /* Section 9.20.5: no cache and no remaining time means timed-out. */
        xqc_moqt_object_t range;
        xqc_memzero(&range, sizeof(range));
        range.group_id = info->end.group_id;
        range.object_id = info->end.object_id;
        range.range = XQC_MOQT_RANGE_TIMEOUT;
        if (xqc_moqt_stream_send_object(f->stream, &range) == XQC_OK) {
            xqc_moqt_stream_finish(f->stream);
            f->deadline = 0;
        } else {
            xqc_moqt_relay_fetch_stop(f, XQC_MOQT_RESET_DELIVERY_TIMEOUT);
        }
        return;
    }
    if (subscription != NULL) {
        if (xqc_moqt_relay_fill_open(f) != XQC_OK) {
            xqc_moqt_relay_fetch_stop(f, XQC_MOQT_RESET_UNKNOWN_OBJECT_STATUS);
        }
    } else {
        f->upstream = q->selected;
        if (f->upstream == NULL) {
            xqc_moqt_relay_fetch_stop(f, XQC_MOQT_RESET_UNKNOWN_OBJECT_STATUS);
        } else {
            f->upstream->fetch = f;
        }
    }
}

void
xqc_moqt_relay_fetch_response(xqc_moqt_relay_request_t *up,
    const xqc_moqt_message_t *m)
{
    xqc_moqt_relay_fetch_t *f = up->fetch;
    if (f->closed) {
        xqc_moqt_relay_stop(up, XQC_MOQT_RESET_CANCELLED);
        return;
    }
    if (m->type != XQC_MOQT_MSG_FETCH_OK) {
        xqc_moqt_relay_fetch_stop(f, XQC_MOQT_RESET_UNKNOWN_OBJECT_STATUS);
        return;
    }
    const xqc_moqt_fetch_info_t *info = xqc_moqt_fetch_info(f->output);
    /* A smaller source snapshot cannot silently truncate the promised Fill. */
    if (m->end_group != info->end.group_id
        || m->end_object != info->end.object_id)
    {
        xqc_moqt_relay_fetch_stop(f, XQC_MOQT_RESET_UNKNOWN_OBJECT_STATUS);
        return;
    }
    up->established = 1;
    up->response = xqc_moqt_relay_message_copy(up->peer->relay, m, up->type);
    if (up->response == NULL) {
        xqc_moqt_relay_fetch_stop(f, XQC_MOQT_RESET_EXCESSIVE_LOAD);
    }
}

void
xqc_moqt_relay_fetch_closed(xqc_moqt_fetch_t *fetch,
    const xqc_moqt_error_t *error, void *data)
{
    xqc_moqt_relay_peer_t *peer = data;
    for (xqc_moqt_relay_fetch_t *f = peer->relay->fetches; f; f = f->next) {
        if (f->input == fetch) {
            f->input = NULL;
            if (error != NULL) {
                xqc_moqt_relay_fetch_stop(f, error->normalized_code);
            }
        } else if (f->output == fetch) {
            f->output = NULL;
            f->stream = NULL;
            xqc_moqt_relay_fetch_stop(f, error == NULL
                ? XQC_MOQT_RESET_CANCELLED : error->normalized_code);
        }
    }
}

static xqc_int_t
xqc_moqt_relay_seen(const xqc_moqt_relay_request_t *down,
    const xqc_moqt_object_t *object)
{
    for (size_t i = 0; i < down->recent_count; i++) {
        if (down->recent[i].group_id == object->group_id
            && down->recent[i].object_id == object->object_id)
        {
            return XQC_TRUE;
        }
    }
    return XQC_FALSE;
}

static void
xqc_moqt_relay_remember(xqc_moqt_relay_request_t *down,
    const xqc_moqt_object_t *object)
{
    down->recent[down->recent_index] = (xqc_moqt_location_t){
        object->group_id, object->object_id};
    down->recent_index = (down->recent_index + 1) % XQC_MOQT_RELAY_HISTORY;
    if (down->recent_count < XQC_MOQT_RELAY_HISTORY) {
        down->recent_count++;
    }
}

static xqc_int_t
xqc_moqt_relay_object_check(xqc_moqt_relay_track_t *track,
    const xqc_moqt_object_t *object, const uint8_t *digest)
{
    if (object->range != XQC_MOQT_RANGE_NONE
        || object->status != XQC_MOQT_OBJECT_NORMAL)
    {
        return XQC_OK;
    }
    for (size_t i = 0; i < XQC_MOQT_RELAY_HISTORY; i++) {
        const xqc_moqt_relay_object_t *seen = &track->recent[i];
        if (!seen->valid || seen->object.group_id != object->group_id
            || seen->object.object_id != object->object_id)
        {
            continue;
        }
        /* Section 7.1: delivery identity must survive every hop. */
        if (seen->object.datagram != object->datagram
            || seen->object.subgroup_id != object->subgroup_id
            || seen->object.priority != object->priority)
        {
            return XQC_ERROR;
        }
        if (seen->object.payload_length != object->payload_length
            || xqc_memcmp(seen->digest, digest, SHA256_DIGEST_LENGTH))
        {
            return XQC_ERROR;
        }
        return XQC_OK;
    }
    xqc_moqt_relay_object_t *seen = &track->recent[track->recent_index];
    track->recent_index = (track->recent_index + 1) % XQC_MOQT_RELAY_HISTORY;
    seen->object = *object;
    xqc_memzero(&seen->object.payload, sizeof(seen->object.payload));
    xqc_memzero(&seen->object.properties, sizeof(seen->object.properties));
    xqc_memcpy(seen->digest, digest, SHA256_DIGEST_LENGTH);
    seen->valid = 1;
    return XQC_OK;
}

static void
xqc_moqt_relay_malformed(xqc_moqt_relay_request_t *up)
{
    xqc_moqt_relay_t *r = up->peer->relay;
    r->stats.malformed++;
    /* Track error isolation: unrelated tracks and sessions keep running. */
    for (xqc_moqt_relay_request_t *q = r->requests; q; q = q->next) {
        if (q->track == up->track) {
            xqc_moqt_relay_stop(q, XQC_MOQT_RESET_MALFORMED_TRACK);
        }
    }
}

static void
xqc_moqt_relay_slow(xqc_moqt_relay_request_t *down)
{
    down->peer->relay->stats.slow_subscribers++;
    xqc_moqt_relay_stop(down, XQC_MOQT_RESET_TOO_FAR_BEHIND);
}

static uint64_t
xqc_moqt_relay_cache_duration(const struct iovec *properties)
{
    uint64_t duration = UINT64_MAX, previous = 0;
    size_t pos = 0;
    const uint8_t *data = properties->iov_base;
    while (pos < properties->iov_len) {
        xqc_moqt_kv_t kv;
        xqc_int_t n = xqc_moqt_kv_decode(data + pos,
            properties->iov_len - pos, previous, &kv);
        if (n < 0) {
            return 0;
        }
        pos += n;
        previous = kv.type;
        if (kv.type == XQC_MOQT_PROPERTY_MAX_CACHE_DURATION) {
            duration = kv.value.integer;
        } else if (kv.type == XQC_MOQT_PROPERTY_IMMUTABLE) {
            uint64_t nested = xqc_moqt_relay_cache_duration(&kv.value.bytes);
            duration = xqc_min(duration, nested);
        }
    }
    return duration;
}

static xqc_bool_t
xqc_moqt_relay_object_expired(xqc_moqt_relay_request_t *up,
    xqc_usec_t received)
{
    xqc_moqt_message_t m;
    const xqc_var_buf_t *buf = up->type == XQC_MOQT_MSG_PUBLISH
        ? up->state : up->response;
    if (xqc_moqt_relay_message_read(buf, up->type, &m) < 0) {
        return XQC_FALSE;
    }
    uint64_t duration = xqc_moqt_relay_cache_duration(&m.properties);
    xqc_usec_t now = xqc_monotonic_timestamp();
    if (duration > UINT64_MAX / XQC_MOQT_MICROS_PER_MILLISECOND) {
        return XQC_FALSE;
    }
    return now >= received
           && now - received > duration * XQC_MOQT_MICROS_PER_MILLISECOND;
}

static void
xqc_moqt_relay_fragment(xqc_moqt_relay_stream_t *st,
    const xqc_moqt_object_t *object)
{
    xqc_moqt_relay_t *r = st->upstream->peer->relay;
    if (st->closed || st->downstream->stopped) {
        return;
    }
    if (!object->payload_offset) {
        st->received = xqc_moqt_stream_object_received_at(st->input);
        if (!st->received) {
            st->received = xqc_monotonic_timestamp();
        }
        SHA256_Init(&st->hash);
        st->skipping = st->fetch == NULL
                       && xqc_moqt_relay_seen(st->downstream, object);
        if (st->skipping) {
            r->stats.duplicates++;
        } else if (xqc_moqt_relay_object_expired(st->upstream, st->received)) {
            r->stats.expired++;
            if (st->fetch != NULL) {
                xqc_moqt_relay_fetch_stop(st->fetch,
                                          XQC_MOQT_RESET_UNKNOWN_OBJECT_STATUS);
                return;
            }
            st->skipping = 1;
        }
        if (st->skipping) {
            if (st->output != NULL) {
                /* A skipped record cannot leave a falsely contiguous stream. */
                xqc_moqt_stream_t *output = st->output;
                st->output = NULL;
                xqc_moqt_stream_cancel(output,
                                       XQC_MOQT_RESET_UNKNOWN_OBJECT_STATUS);
            }
        }
    }
    SHA256_Update(&st->hash, object->payload.iov_base, object->payload.iov_len);
    xqc_bool_t complete = object->payload_offset + object->payload.iov_len
                          == object->payload_length;
    if (complete) {
        uint8_t digest[SHA256_DIGEST_LENGTH];
        SHA256_Final(digest, &st->hash);
        if (xqc_moqt_relay_object_check(st->upstream->track, object, digest)
            != XQC_OK)
        {
            xqc_moqt_relay_malformed(st->upstream);
            return;
        }
    }
    if (st->skipping) {
        return;
    }
    if (st->output == NULL) {
        if (st->fetch != NULL) {
            st->output = st->fetch->stream;
        } else {
            st->output = xqc_moqt_subgroup_open(st->downstream->subscription,
                object->group_id, object->subgroup_id, object->priority,
                object->first_in_subgroup,
                xqc_moqt_stream_end_of_group(st->input));
        }
    }
    xqc_moqt_object_t fragment = *object;
    if (fragment.payload_offset) {
        xqc_memzero(&fragment.properties, sizeof(fragment.properties));
    }
    fragment.end_of_group = 0;
    xqc_int_t ret = st->output == NULL ? -XQC_EMALLOC
        : xqc_moqt_stream_send_object(st->output, &fragment);
    if (ret != XQC_OK) {
        if (st->fetch != NULL) {
            xqc_moqt_relay_fetch_stop(st->fetch, XQC_MOQT_RESET_TOO_FAR_BEHIND);
        } else {
            xqc_moqt_relay_slow(st->downstream);
        }
        return;
    }
    if (complete) {
        r->stats.forwarded++;
        if (st->fetch == NULL) {
            xqc_moqt_relay_remember(st->downstream, object);
        }
    }
}

void
xqc_moqt_relay_object(xqc_moqt_subscription_t *subscription,
    xqc_moqt_stream_t *input, const xqc_moqt_object_t *object, void *data)
{
    xqc_moqt_relay_peer_t *peer = data;
    xqc_moqt_relay_t *r = peer->relay;
    xqc_moqt_fetch_t *fetch = xqc_moqt_stream_fetch(input);
    if (fetch != NULL) {
        for (xqc_moqt_relay_fetch_t *f = r->fetches; f; f = f->next) {
            if (f->input == fetch && !f->closed) {
                xqc_moqt_relay_stream_t *st = xqc_moqt_relay_stream_get(
                    f->upstream, f->downstream, input, f);
                if (st == NULL) {
                    xqc_moqt_relay_fetch_stop(f, XQC_MOQT_RESET_EXCESSIVE_LOAD);
                } else {
                    xqc_moqt_relay_fragment(st, object);
                }
                return;
            }
        }
        return;
    }
    xqc_moqt_relay_request_t *up = xqc_moqt_relay_subscription_find(peer,
        subscription);
    if (up == NULL || !up->upstream || up->stopped) {
        return;
    }
    xqc_usec_t received = xqc_monotonic_timestamp();
    xqc_bool_t checked = XQC_FALSE;
    xqc_moqt_location_t location = {object->group_id, object->object_id};
    for (xqc_moqt_relay_request_t *down = r->requests;
         down != NULL; down = down->next)
    {
        if (down->upstream || down->track != up->track || down->stopped) {
            continue;
        }
        /* One subscription cannot expand another subscriber's grant. */
        if (up->parent != NULL && up->parent != down) {
            continue;
        }
        /* A discovered Pc maps to one publication instance, not all sources. */
        if (down->type == XQC_MOQT_MSG_PUBLISH && down->selected != up) {
            continue;
        }
        if (!xqc_moqt_subscription_is_matching(down->subscription, &location)) {
            continue;
        }
        if (xqc_moqt_subscription_object_is_obsolete(down->subscription,
                                                     object))
        {
            continue;
        }
        if (input == NULL) {
            /* Section 2.1.2: known absence wins over late normal data. */
            if (!checked) {
                uint8_t digest[SHA256_DIGEST_LENGTH];
                SHA256(object->payload.iov_base, object->payload.iov_len,
                       digest);
                if (xqc_moqt_relay_object_check(up->track, object, digest)
                    != XQC_OK)
                {
                    xqc_moqt_relay_malformed(up);
                    return;
                }
                checked = XQC_TRUE;
            }
            if (xqc_moqt_relay_object_expired(up, received)) {
                r->stats.expired++;
                continue;
            }
            if (xqc_moqt_relay_seen(down, object)) {
                r->stats.duplicates++;
                continue;
            }
            if (xqc_moqt_datagram_send(down->subscription, object) != XQC_OK) {
                xqc_moqt_relay_slow(down);
            } else {
                xqc_moqt_relay_remember(down, object);
                r->stats.forwarded++;
            }
        } else {
            xqc_moqt_relay_stream_t *st = xqc_moqt_relay_stream_get(up,
                down, input, NULL);
            if (st == NULL) {
                xqc_moqt_relay_slow(down);
            } else {
                xqc_moqt_relay_fragment(st, object);
            }
        }
    }
}

void
xqc_moqt_relay_stream_closed(xqc_moqt_stream_t *stream,
    const xqc_moqt_object_t *last, const xqc_moqt_error_t *error, void *data)
{
    xqc_moqt_relay_peer_t *peer = data;
    /* An empty FETCH still has a FIN/reset to forward, without on_object. */
    xqc_moqt_fetch_t *input = xqc_moqt_stream_fetch(stream);
    for (xqc_moqt_relay_fetch_t *f = peer->relay->fetches; f; f = f->next) {
        if (input != NULL && f->input == input && !f->closed) {
            xqc_moqt_relay_stream_t *st = xqc_moqt_relay_stream_get(
                f->upstream, f->downstream, stream, f);
            if (st == NULL) {
                xqc_moqt_relay_fetch_stop(f, XQC_MOQT_RESET_EXCESSIVE_LOAD);
            } else {
                st->output = f->stream;
            }
            break;
        }
    }
    for (xqc_moqt_relay_stream_t *st = peer->relay->streams;
         st != NULL; st = st->next)
    {
        if (st->input == stream) {
            st->input = NULL;
            if (error != NULL) {
                if (st->output != NULL) {
                    xqc_moqt_stream_cancel(st->output, error->normalized_code);
                }
            } else {
                xqc_moqt_relay_stream_finish(st);
            }
        } else if (st->output == stream) {
            st->output = NULL;
            st->closed = 1;
        }
    }
    for (xqc_moqt_relay_fetch_t *f = peer->relay->fetches; f; f = f->next) {
        if (f->stream == stream) {
            f->stream = NULL;
        }
    }
}

void
xqc_moqt_relay_writable(xqc_moqt_session_t *session,
    xqc_moqt_stream_t *stream, void *data)
{
    xqc_moqt_relay_peer_t *peer = data;
    for (xqc_moqt_relay_stream_t *st = peer->relay->streams;
         st != NULL; st = st->next)
    {
        if (st->output == stream && st->finishing) {
            xqc_moqt_relay_stream_finish(st);
        }
    }
}
