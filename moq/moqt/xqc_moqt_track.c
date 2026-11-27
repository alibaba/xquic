/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include "xqc_moqt_session.h"
#include "xqc_moqt_codec.h"

xqc_int_t
xqc_moqt_location_compare(const xqc_moqt_location_t *a,
    const xqc_moqt_location_t *b)
{
    if (a->group_id != b->group_id) {
        return a->group_id < b->group_id ? -1 : 1;
    }
    return a->object_id < b->object_id ? -1 : a->object_id > b->object_id;
}

xqc_int_t
xqc_moqt_track_properties_read(const struct iovec *bytes,
    xqc_moqt_track_t *defaults, size_t *count)
{
    const uint8_t *data = bytes->iov_base;
    size_t pos = 0;
    uint64_t previous = 0;
    while (pos < bytes->iov_len) {
        xqc_moqt_kv_t kv;
        xqc_int_t n = xqc_moqt_kv_decode(data + pos, bytes->iov_len - pos,
                                         previous, &kv);
        if (n < 0 || ++*count > XQC_MOQT_MAX_OPTIONS) {
            return XQC_ERROR;
        }
        previous = kv.type;
        pos += n;
        switch (kv.type) {
        case XQC_MOQT_PROPERTY_IMMUTABLE:
            /* Section 10.7: one budget bounds both lists and nesting. */
            if (xqc_moqt_track_properties_read(&kv.value.bytes, defaults,
                                               count) != XQC_OK)
            {
                return XQC_ERROR;
            }
            break;
        case XQC_MOQT_PROPERTY_OBJECT_TIMEOUT:
            defaults->object_timeout = kv.value.integer;
            break;
        case XQC_MOQT_PROPERTY_SUBGROUP_TIMEOUT:
            defaults->subgroup_timeout = kv.value.integer;
            break;
        case XQC_MOQT_PROPERTY_PUBLISHER_PRIORITY:
            if (kv.value.integer > UINT8_MAX) {
                return XQC_ERROR;
            }
            defaults->publisher_priority = kv.value.integer;
            break;
        case XQC_MOQT_PROPERTY_GROUP_ORDER:
            if (kv.value.integer < XQC_MOQT_GROUP_ASCENDING
                || kv.value.integer > XQC_MOQT_GROUP_DESCENDING)
            {
                return XQC_ERROR;
            }
            defaults->group_order = kv.value.integer;
            break;
        default:
            break;
        }
    }
    return XQC_OK;
}

xqc_int_t
xqc_moqt_location_filter_apply(xqc_moqt_location_t *start,
    xqc_moqt_location_t *end_location, xqc_int_t *exclusive,
    const xqc_moq_message_parameter_t *parameter,
    const xqc_moqt_location_t *largest, xqc_int_t has_largest)
{
    uint64_t fields[XQC_MOQT_LOCATION_FILTER_MAX_FIELDS] = {0};
    const uint8_t *p = parameter->value, *end = p + parameter->length;
    size_t count = 0;
    while (p < end) {
        if (count == XQC_MOQT_LOCATION_FILTER_MAX_FIELDS) {
            return XQC_ERROR;
        }
        xqc_int_t n = xqc_vi64_read(p, end, &fields[count++]);
        if (n < 0) {
            return XQC_ERROR;
        }
        p += n;
    }
    xqc_memzero(start, sizeof(*start));
    end_location->group_id = end_location->object_id = UINT64_MAX;
    *exclusive = 0;
    switch (fields[0]) {
    case XQC_MOQT_FILTER_NONE:
        break;
    case XQC_MOQT_FILTER_RELATIVE_START:
        /* Section 9.20.9: saturate G + 1 - delta without overflow. */
        if (has_largest) {
            start->group_id = fields[1] == 0
                ? largest->group_id + (largest->group_id != UINT64_MAX)
                : largest->group_id >= fields[1] - 1
                  ? largest->group_id - (fields[1] - 1) : 0;
        }
        break;
    case XQC_MOQT_FILTER_ABSOLUTE_START:
    case XQC_MOQT_FILTER_GROUP_END:
    case XQC_MOQT_FILTER_ABSOLUTE_RANGE:
        start->group_id = fields[1];
        start->object_id = fields[2];
        if (fields[0] >= XQC_MOQT_FILTER_GROUP_END) {
            if (fields[3] > UINT64_MAX - fields[1]) {
                return XQC_ERROR;
            }
            end_location->group_id = fields[1] + fields[3];
        }
        if (fields[0] == XQC_MOQT_FILTER_ABSOLUTE_RANGE) {
            end_location->object_id = fields[4];
        }
        break;
    case XQC_MOQT_FILTER_NEXT_OBJECT:
        if (has_largest) {
            *start = *largest;
            *exclusive = 1;
        }
        break;
    default:
        return XQC_ERROR;
    }
    return XQC_OK;
}

static uint64_t
xqc_moqt_track_alias_check(const xqc_moqt_subscription_t *sub)
{
    if (sub->track->local_publisher) {
        return XQC_MOQT_NO_ERROR;
    }
    xqc_moqt_session_t *s = sub->request->stream->session;
    for (xqc_moqt_subscription_t *other = s->subscriptions; other != NULL;
         other = other->next)
    {
        if (other != sub
            && other->established
            && !other->stopped
            && !other->track->local_publisher
            && other->track != sub->track
            && other->track_alias == sub->track_alias)
        {
            return XQC_MOQT_DUPLICATE_TRACK_ALIAS;
        }
    }
    return XQC_MOQT_NO_ERROR;
}

uint64_t
xqc_moqt_subscription_apply(xqc_moqt_request_t *r,
    const xqc_moqt_message_t *m)
{
    xqc_moqt_subscription_t *sub = r->subscription;
    if (sub == NULL) {
        return XQC_MOQT_NO_ERROR;
    }
    xqc_moqt_subscription_t candidate = *sub;
    xqc_moqt_track_t *track = sub->track;
    xqc_moqt_location_t largest = track->largest;
    xqc_int_t has_largest = track->has_largest;
    xqc_moqt_track_t defaults = *track;
    if (m->type == XQC_MOQT_MSG_PUBLISH
        || m->type == XQC_MOQT_MSG_SUBSCRIBE_OK)
    {
        defaults.publisher_priority = XQC_MOQT_DEFAULT_PRIORITY;
    }
    size_t count = 0;
    if (xqc_moqt_track_properties_read(&m->properties, &defaults,
                                       &count) != XQC_OK)
    {
        return XQC_MOQT_PROTOCOL_VIOLATION;
    }
    for (size_t i = 0; i < m->parameter_count; i++) {
        const xqc_moq_message_parameter_t *p = &m->parameters[i];
        if (p->type == XQC_MOQT_PARAM_LARGEST_OBJECT) {
            xqc_moqt_location_t location;
            const uint8_t *end = p->value + p->length;
            xqc_int_t n = xqc_vi64_read(p->value, end, &location.group_id);
            if (n < 0 || xqc_vi64_read(p->value + n, end,
                                       &location.object_id) < 0)
            {
                return XQC_MOQT_PROTOCOL_VIOLATION;
            }
            if (!has_largest || xqc_moqt_location_compare(&location,
                                                          &largest) > 0)
            {
                largest = location;
                has_largest = 1;
            }
        }
    }
    xqc_int_t establish = !r->responded
        && (m->type == XQC_MOQT_MSG_SUBSCRIBE_OK
            || m->type == XQC_MOQT_MSG_REQUEST_OK);
    if (m->type == XQC_MOQT_MSG_PUBLISH
        || m->type == XQC_MOQT_MSG_SUBSCRIBE_OK)
    {
        if (!track->local_publisher) {
            candidate.track_alias = m->track_alias;
        }
    }
    if (establish || m->type == XQC_MOQT_MSG_PUBLISH) {
        uint64_t error = xqc_moqt_track_alias_check(&candidate);
        if (error) {
            return error;
        }
    }
    /* Resolve the initial join point once, when the initial OK is committed. */
    const xqc_moqt_message_t *initial = (void *)r->state->data;
    const xqc_moqt_message_t *messages[] = {establish ? initial : m, m};
    size_t message_count = establish ? 2 : 1;
    for (size_t j = 0; j < message_count; j++) {
        for (size_t i = 0; i < messages[j]->parameter_count; i++) {
            const xqc_moq_message_parameter_t *p = &messages[j]->parameters[i];
            switch (p->type) {
            case XQC_MOQT_PARAM_OBJECT_DELIVERY_TIMEOUT:
            case XQC_MOQT_PARAM_SUBGROUP_DELIVERY_TIMEOUT: {
                uint64_t value;
                if (xqc_vi64_read(p->value, p->value + p->length, &value) < 0) {
                    return XQC_MOQT_PROTOCOL_VIOLATION;
                }
                if (p->type == XQC_MOQT_PARAM_OBJECT_DELIVERY_TIMEOUT) {
                    candidate.object_timeout = value;
                } else {
                    candidate.subgroup_timeout = value;
                }
                break;
            }
            case XQC_MOQT_PARAM_FORWARD:
                candidate.forward = p->value[0];
                break;
            case XQC_MOQT_PARAM_SUBSCRIBER_PRIORITY:
                candidate.subscriber_priority = p->value[0];
                break;
            case XQC_MOQT_PARAM_GROUP_ORDER:
                candidate.group_order = p->value[0];
                candidate.group_order_set = 1;
                break;
            case XQC_MOQT_PARAM_LOCATION_FILTER: {
                xqc_int_t exclusive;
                if (xqc_moqt_location_filter_apply(
                    &candidate.start, &candidate.end, &exclusive, p,
                    &largest, has_largest) != XQC_OK)
                {
                    return XQC_MOQT_PROTOCOL_VIOLATION;
                }
                candidate.start_exclusive = exclusive;
                break;
            }
            default:
                break;
            }
        }
    }
    if (!candidate.established && !candidate.group_order_set) {
        candidate.group_order = defaults.group_order;
    }
    if (m->type == XQC_MOQT_MSG_PUBLISH
        || m->type == XQC_MOQT_MSG_SUBSCRIBE_OK)
    {
        candidate.publisher_priority = defaults.publisher_priority;
    }
    candidate.established |= establish;
    *sub = candidate;
    track->largest = largest;
    track->has_largest = has_largest;
    track->publisher_priority = defaults.publisher_priority;
    track->group_order = defaults.group_order;
    track->object_timeout = defaults.object_timeout;
    track->subgroup_timeout = defaults.subgroup_timeout;
    /* Section 9.9: only established aliases make counts ambiguous. */
    for (xqc_moqt_subscription_t *other = sub->session->subscriptions;
         sub->established && other != NULL; other = other->next)
    {
        if (other == sub || !other->established || other->closed) {
            continue;
        }
        if (other->track == track && other->track_alias == sub->track_alias) {
            sub->shared_alias = other->shared_alias = 1;
        }
    }
    xqc_moqt_session_t *s = sub->session;
    xqc_moqt_subscription_t *head = xqc_moqt_subscriptions_hold(s);
    xqc_moqt_subscription_data_update(sub);
    xqc_moqt_timer_update(s);
    xqc_moqt_subscriptions_release(head);
    return XQC_MOQT_NO_ERROR;
}

xqc_moqt_track_t *
xqc_moqt_track_get(xqc_moqt_session_t *s, const xqc_moqt_message_t *m,
    xqc_int_t publisher)
{
    xqc_int_t n = xqc_moqt_name_encode(&m->track_namespace, &m->track_name,
                                       NULL, 0);
    xqc_var_buf_t *name = xqc_moqt_buffer_create(
        s, n, sizeof(*name) + sizeof(xqc_moqt_track_t));
    if (name == NULL) {
        return NULL;
    }
    xqc_moqt_name_encode(&m->track_namespace, &m->track_name, name->data, n);
    name->data_len = n;
    xqc_moqt_track_t *track = s->tracks;
    while (track != NULL) {
        if (track->local_publisher == publisher
            && track->name->data_len == n
            && xqc_memcmp(track->name->data, name->data, n) == 0)
        {
            break;
        }
        track = track->next;
    }
    if (track != NULL) {
        xqc_moqt_buffer_free(s, name, sizeof(*name) + sizeof(*track));
    } else {
        track = xqc_calloc(1, sizeof(*track));
        if (track == NULL) {
            xqc_moqt_buffer_free(s, name, sizeof(*name) + sizeof(*track));
            return NULL;
        }
        track->name = name;
        track->local_publisher = publisher;
        track->publisher_priority = XQC_MOQT_DEFAULT_PRIORITY;
        track->group_order = XQC_MOQT_GROUP_ASCENDING;
        track->next = s->tracks;
        s->tracks = track;
    }
    track->references++;
    return track;
}

uint64_t
xqc_moqt_subscription_create(xqc_moqt_request_t *r,
    const xqc_moqt_message_t *m)
{
    if (m->type != XQC_MOQT_MSG_SUBSCRIBE && m->type != XQC_MOQT_MSG_PUBLISH) {
        return XQC_MOQT_NO_ERROR;
    }
    xqc_moqt_session_t *s = r->stream->session;
    xqc_int_t publisher = xqc_moqt_is_local_publisher(r);
    if ((publisher
            && s->track_aliases_exhausted)
        || sizeof(xqc_moqt_subscription_t)
           > s->config.max_buffered_bytes - s->buffered_bytes)
    {
        return XQC_MOQT_INTERNAL_ERROR;
    }
    xqc_moqt_track_t *track = xqc_moqt_track_get(s, m, publisher);
    if (track == NULL) {
        return XQC_MOQT_INTERNAL_ERROR;
    }
    xqc_moqt_subscription_t *sub = NULL;
    if (sizeof(*sub) <= s->config.max_buffered_bytes - s->buffered_bytes) {
        sub = xqc_calloc(1, sizeof(*sub));
    }
    if (sub == NULL) {
        xqc_moqt_track_release(s, track);
        return XQC_MOQT_INTERNAL_ERROR;
    }
    s->buffered_bytes += sizeof(*sub);
    sub->request = r;
    sub->session = s;
    sub->track = track;
    sub->forward = 1;
    sub->subscriber_priority = XQC_MOQT_DEFAULT_PRIORITY;
    sub->group_order = track->group_order;
    sub->end.group_id = sub->end.object_id = UINT64_MAX;
    if (publisher) {
        sub->track_alias = s->next_track_alias;
        if (s->next_track_alias == UINT64_MAX) {
            s->track_aliases_exhausted = 1;
        } else {
            s->next_track_alias++;
        }
    }
    sub->next = s->subscriptions;
    s->subscriptions = r->subscription = sub;
    uint64_t error = xqc_moqt_subscription_apply(r, m);
    if (error) {
        xqc_moqt_subscription_release(r);
    }
    return error;
}

xqc_moqt_subscription_t *
xqc_moqt_request_subscription(const xqc_moqt_request_t *r)
{
    return r == NULL ? NULL : r->subscription;
}

xqc_int_t
xqc_moqt_subscription_is_matching(const xqc_moqt_subscription_t *sub,
    const xqc_moqt_location_t *location)
{
    xqc_int_t start = xqc_moqt_location_compare(location, &sub->start);
    return sub->established && !sub->stopped && sub->forward
           && (start > 0 || (start == 0 && !sub->start_exclusive))
           && xqc_moqt_location_compare(location, &sub->end) <= 0;
}

/* Free only after callbacks/iteration release their borrowed references. */
void
xqc_moqt_subscription_free(xqc_moqt_subscription_t *sub)
{
    if (!sub->closed || sub->active) {
        return;
    }
    xqc_moqt_session_t *s = sub->session;
    xqc_moqt_subscription_t **link = &s->subscriptions;
    while (*link != sub) {
        link = &(*link)->next;
    }
    *link = sub->next;
    xqc_moqt_track_release(s, sub->track);
    s->buffered_bytes -= sizeof(*sub);
    xqc_free(sub);
}

xqc_moqt_subscription_t *
xqc_moqt_subscriptions_hold(xqc_moqt_session_t *s)
{
    for (xqc_moqt_subscription_t *sub = s->subscriptions; sub != NULL;
         sub = sub->next)
    {
        sub->active++;
    }
    return s->subscriptions;
}

void
xqc_moqt_subscriptions_release(xqc_moqt_subscription_t *head)
{
    for (xqc_moqt_subscription_t *sub = head, *next; sub != NULL; sub = next) {
        next = sub->next;
        sub->active--;
        xqc_moqt_subscription_free(sub);
    }
}

void
xqc_moqt_subscription_close(xqc_moqt_subscription_t *sub)
{
    if (sub->closed) {
        return;
    }
    sub->active++;
    sub->closed = sub->stopped = 1;
    sub->close_deadline = 0;
    if (sub->request != NULL) {
        sub->request->subscription = NULL;
        sub->request = NULL;
    }
    xqc_moqt_subscription_data_update(sub);
    xqc_moqt_fill_cancel(sub);
    if (sub->session->callbacks.on_subscription_closed != NULL) {
        sub->session->callbacks.on_subscription_closed(
            sub, &sub->error, sub->session->user_data);
    }
    sub->active--;
    xqc_moqt_subscription_free(sub);
}

void
xqc_moqt_subscription_cancel(xqc_moqt_subscription_t *sub, uint64_t error)
{
    if (sub == NULL || sub->closed) {
        return;
    }
    xqc_moqt_stream_t *head = xqc_moqt_streams_hold(sub->session);
    xqc_moqt_request_t *r = sub->request;
    sub->error.context = XQC_MOQT_ERROR_RESET;
    sub->error.code = error;
    sub->error.normalized_code = xqc_moqt_error_normalize(
        XQC_MOQT_ERROR_RESET, error);
    xqc_moqt_subscription_close(sub);
    if (r != NULL) {
        xqc_moqt_request_cancel(r, error);
    }
    xqc_moqt_streams_release(head);
}

void
xqc_moqt_subscription_check_done(xqc_moqt_subscription_t *sub)
{
    if (sub->closed || !sub->done) {
        return;
    }
    if (sub->track->local_publisher) {
        for (xqc_moqt_fetch_t *f = sub->session->fetches; f != NULL;
             f = f->next)
        {
            if (f->subscription == sub) {
                return;
            }
        }
        /* Keep policy alive until already-finished streams are delivered. */
        for (xqc_moqt_stream_t *st = sub->session->streams; st != NULL;
             st = st->next)
        {
            if (st->kind == XQC_MOQT_STREAM_SUBGROUP
                && st->state.data.subscription == sub)
            {
                return;
            }
        }
    } else {
        /* Unknown counts and shared Alias use the local bounded wait. */
        if (sub->shared_alias || sub->expected_streams == UINT64_MAX) {
            return;
        }
        if (sub->finished_streams < sub->expected_streams) {
            return;
        }
    }
    xqc_moqt_subscription_close(sub);
}

void
xqc_moqt_subscription_done(xqc_moqt_subscription_t *sub,
    const xqc_moqt_message_t *m)
{
    if (sub == NULL || sub->closed) {
        return;
    }
    sub->done = 1;
    sub->expected_streams = m->stream_count;
    sub->error.context = XQC_MOQT_ERROR_PUBLISH_DONE;
    sub->error.code = m->error.code;
    sub->error.normalized_code = xqc_moqt_error_normalize(
        XQC_MOQT_ERROR_PUBLISH_DONE, m->error.code);
    if (sub->track->local_publisher) {
        sub->stopped = 1;
    } else {
        xqc_usec_t now = xqc_monotonic_timestamp();
        sub->close_deadline = sub->session->config.timeout > UINT64_MAX - now
            ? UINT64_MAX : now + sub->session->config.timeout;
    }
    xqc_moqt_timer_update(sub->session);
    xqc_moqt_subscription_check_done(sub);
}

void
xqc_moqt_subscription_release(xqc_moqt_request_t *r)
{
    xqc_moqt_subscription_t *sub = r->subscription;
    if (sub == NULL) {
        return;
    }
    r->subscription = NULL;
    sub->request = NULL;
    /* Section 9.9: request closure does not discard late delivery. */
    if (!sub->done || sub->session->closed) {
        xqc_moqt_subscription_cancel(sub, sub->session->closed
            ? XQC_MOQT_RESET_SESSION_CLOSED : XQC_MOQT_RESET_CANCELLED);
    } else {
        xqc_moqt_subscription_check_done(sub);
    }
}

void
xqc_moqt_track_release(xqc_moqt_session_t *s, xqc_moqt_track_t *track)
{
    if (--track->references == 0) {
        xqc_moqt_track_t **t = &s->tracks;
        while (*t != track) {
            t = &(*t)->next;
        }
        *t = track->next;
        xqc_moqt_buffer_free(s, track->name,
                             sizeof(*track->name) + sizeof(*track));
        xqc_free(track);
    }
}
