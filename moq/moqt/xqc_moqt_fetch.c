/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include "xqc_moqt_session.h"
#include "src/transport/xqc_stream.h"

static void
xqc_moqt_fetch_free(xqc_moqt_fetch_t *f)
{
    if (!f->closed || f->active || f->stream != NULL) {
        return;
    }
    xqc_moqt_session_t *s = f->session;
    xqc_moqt_fetch_t **link = &s->fetches;
    while (*link != f) {
        link = &(*link)->next;
    }
    *link = f->next;
    xqc_moqt_subscription_t *sub = f->subscription;
    xqc_moqt_track_release(s, f->track);
    s->buffered_bytes -= sizeof(*f);
    xqc_free(f);
    if (sub != NULL) {
        xqc_moqt_subscription_check_done(sub);
        sub->active--;
        xqc_moqt_subscription_free(sub);
    }
}

xqc_moqt_fetch_t *
xqc_moqt_request_fetch(const xqc_moqt_request_t *r)
{
    return r == NULL ? NULL : r->fetch;
}

const xqc_moqt_fetch_info_t *
xqc_moqt_fetch_info(const xqc_moqt_fetch_t *f)
{
    return f == NULL ? NULL : &f->info;
}

xqc_moqt_fetch_t *
xqc_moqt_stream_fetch(const xqc_moqt_stream_t *st)
{
    return st != NULL && st->kind == XQC_MOQT_STREAM_FETCH
        ? st->state.data.fetch : NULL;
}

uint64_t
xqc_moqt_fetch_create(xqc_moqt_request_t *r, const xqc_moqt_message_t *m)
{
    xqc_moqt_subscription_t *sub = r->subscription;
    if (sub != NULL) {
        size_t i = 0;
        while (i < m->parameter_count
               && m->parameters[i].type != XQC_MOQT_PARAM_FILL_PARAMETERS)
        {
            i++;
        }
        if (i == m->parameter_count) {
            return XQC_MOQT_NO_ERROR;
        }
    } else if (m->type != XQC_MOQT_MSG_FETCH) {
        return XQC_MOQT_NO_ERROR;
    }
    xqc_moqt_session_t *s = r->stream->session;
    xqc_moqt_fetch_t *f;
    if (sizeof(*f) > s->config.max_buffered_bytes - s->buffered_bytes) {
        return XQC_MOQT_INTERNAL_ERROR;
    }
    f = xqc_calloc(1, sizeof(*f));
    if (f == NULL) {
        return XQC_MOQT_INTERNAL_ERROR;
    }
    s->buffered_bytes += sizeof(*f);
    if (sub != NULL) {
        f->track = sub->track;
        f->track->references++;
    } else {
        f->track = xqc_moqt_track_get(s, (void *)r->state->data, !r->local);
    }
    if (f->track == NULL) {
        s->buffered_bytes -= sizeof(*f);
        xqc_free(f);
        return XQC_MOQT_INTERNAL_ERROR;
    }
    f->session = s;
    if (sub != NULL) {
        f->subscription = sub;
        sub->active++;
    } else {
        f->request = r;
        r->fetch = f;
    }
    f->info.request_id = m->request_id;
    f->info.group_order = f->track->group_order;
    f->info.subscriber_priority = XQC_MOQT_DEFAULT_PRIORITY;
    f->next = s->fetches;
    s->fetches = f;
    return XQC_MOQT_NO_ERROR;
}

uint64_t
xqc_moqt_fetch_apply(xqc_moqt_request_t *r, const xqc_moqt_message_t *m)
{
    xqc_moqt_fetch_t *f = r->fetch;
    if (f == NULL || f->closed) {
        return XQC_MOQT_NO_ERROR;
    }
    xqc_moqt_fetch_info_t info = f->info;
    xqc_moqt_track_t defaults = *f->track;
    size_t count = 0;
    if (xqc_moqt_track_properties_read(&m->properties, &defaults,
                                       &count) != XQC_OK)
    {
        return XQC_MOQT_PROTOCOL_VIOLATION;
    }
    const xqc_moqt_message_t *parameters = m;
    xqc_moqt_location_t requested_end = {UINT64_MAX, UINT64_MAX};
    if (m->type == XQC_MOQT_MSG_FETCH_OK) {
        info.end.group_id = m->end_group;
        info.end.object_id = m->end_object;
        info.end_of_track = m->end_of_track;
        info.group_order = defaults.group_order;
        parameters = (void *)r->state->data;
    }
    xqc_int_t exclusive = 0;
    for (size_t i = 0; i < parameters->parameter_count; i++) {
        const xqc_moq_message_parameter_t *p = &parameters->parameters[i];
        switch (p->type) {
        case XQC_MOQT_PARAM_SUBSCRIBER_PRIORITY:
            info.subscriber_priority = p->value[0];
            break;
        case XQC_MOQT_PARAM_GROUP_ORDER:
            info.group_order = p->value[0];
            break;
        case XQC_MOQT_PARAM_FILL_TIMEOUT:
            if (xqc_vi64_read(p->value, p->value + p->length,
                               &info.fill_timeout) < 0)
            {
                return XQC_MOQT_PROTOCOL_VIOLATION;
            }
            info.has_fill_timeout = 1;
            break;
        case XQC_MOQT_PARAM_LOCATION_FILTER:
            if (xqc_moqt_location_filter_apply(&info.start, &requested_end,
                &exclusive, p, &info.end, 1) != XQC_OK)
            {
                return XQC_MOQT_PROTOCOL_VIOLATION;
            }
            break;
        default:
            break;
        }
    }
    if (m->type == XQC_MOQT_MSG_FETCH_OK) {
        /* Section 9.12: the inclusive end cannot exceed the request range. */
        if (xqc_moqt_location_compare(&info.end, &requested_end) > 0) {
            return XQC_MOQT_PROTOCOL_VIOLATION;
        }
        /* No Objects or a start beyond Largest requires INVALID_RANGE. */
        xqc_int_t order = xqc_moqt_location_compare(&info.start, &info.end);
        if (order > 0 || (order == 0 && exclusive)) {
            return XQC_MOQT_PROTOCOL_VIOLATION;
        }
        if (exclusive) {
            /* NextObject always starts beyond the response's Largest. */
            return XQC_MOQT_PROTOCOL_VIOLATION;
        }
        if (info.end_of_track) {
            /* EOT cannot exclude an Object already published on this Track. */
            if (f->track->has_largest
                && xqc_moqt_location_compare(&f->track->largest,
                                               &info.end) > 0)
            {
                return XQC_MOQT_PROTOCOL_VIOLATION;
            }
            /* An existing earlier bound must not be widened by FETCH_OK. */
            if (!f->track->has_end
                || xqc_moqt_location_compare(&info.end, &f->track->end) < 0)
            {
                f->track->end = info.end;
                f->track->has_end = f->track->end_inclusive = 1;
            }
        }
        f->track->publisher_priority = defaults.publisher_priority;
        f->track->group_order = defaults.group_order;
        f->track->object_timeout = defaults.object_timeout;
        f->track->subgroup_timeout = defaults.subgroup_timeout;
    }
    f->info = info;
    f->confirmed |= m->type == XQC_MOQT_MSG_FETCH_OK;
    return XQC_MOQT_NO_ERROR;
}

/* Section 3.4: the response snapshot, never later live data, bounds a Fill. */
uint64_t
xqc_moqt_fill_apply(xqc_moqt_request_t *r, const xqc_moqt_message_t *state,
    const xqc_moqt_message_t *trigger, const xqc_moqt_message_t *reply)
{
    if (r->subscription == NULL) {
        return XQC_MOQT_NO_ERROR;
    }
    xqc_moqt_fetch_t *f = r->stream->session->fetches;
    while (f != NULL && (f->subscription != r->subscription
                         || f->info.request_id != trigger->request_id))
    {
        f = f->next;
    }
    if (f == NULL || f->confirmed || f->closed) {
        return XQC_MOQT_NO_ERROR;
    }
    xqc_moqt_message_t inner;
    xqc_memzero(&inner, sizeof(inner));
    for (size_t i = 0; i < trigger->parameter_count; i++) {
        if (trigger->parameters[i].type == XQC_MOQT_PARAM_FILL_PARAMETERS
            && xqc_moqt_fill_parameters_decode(&trigger->parameters[i],
                                               &inner) != XQC_OK)
        {
            return XQC_MOQT_PROTOCOL_VIOLATION;
        }
    }
    xqc_moqt_location_t largest = {0, 0};
    xqc_int_t has_largest = 0;
    for (size_t i = 0; i < reply->parameter_count; i++) {
        const xqc_moq_message_parameter_t *p = &reply->parameters[i];
        if (p->type == XQC_MOQT_PARAM_LARGEST_OBJECT) {
            const uint8_t *end = p->value + p->length;
            xqc_int_t n = xqc_vi64_read(p->value, end, &largest.group_id);
            if (n < 0
                || xqc_vi64_read(p->value + n, end,
                                       &largest.object_id) < 0)
            {
                return XQC_MOQT_PROTOCOL_VIOLATION;
            }
            has_largest = 1;
        }
    }
    xqc_moqt_fetch_info_t info = f->info;
    info.group_order = f->subscription->group_order;
    info.subscriber_priority = f->subscription->subscriber_priority;
    const xqc_moq_message_parameter_t *filter = NULL;
    const xqc_moqt_message_t *scopes[] = {state, &inner};
    for (size_t j = 0; j < sizeof(scopes) / sizeof(scopes[0]); j++) {
        for (size_t i = 0; i < scopes[j]->parameter_count; i++) {
            const xqc_moq_message_parameter_t *p = &scopes[j]->parameters[i];
            switch (p->type) {
            case XQC_MOQT_PARAM_LOCATION_FILTER:
                filter = p;
                break;
            case XQC_MOQT_PARAM_SUBSCRIBER_PRIORITY:
                info.subscriber_priority = p->value[0];
                break;
            case XQC_MOQT_PARAM_GROUP_ORDER:
                info.group_order = p->value[0];
                break;
            case XQC_MOQT_PARAM_FILL_TIMEOUT:
                xqc_vi64_read(p->value, p->value + p->length,
                               &info.fill_timeout);
                info.has_fill_timeout = 1;
                break;
            default:
                break;
            }
        }
    }
    xqc_moqt_location_t end = {UINT64_MAX, UINT64_MAX};
    xqc_int_t exclusive = 0;
    if (filter != NULL
        && xqc_moqt_location_filter_apply(&info.start, &end, &exclusive,
                                          filter, &largest, has_largest)
           != XQC_OK)
    {
        return XQC_MOQT_PROTOCOL_VIOLATION;
    }
    info.end = xqc_moqt_location_compare(&end, &largest) < 0 ? end : largest;
    xqc_int_t empty = xqc_moqt_location_compare(&info.start, &info.end) > 0;
    /* NextObject is beyond this Fill's inclusive Largest boundary. */
    if (exclusive) {
        empty = 1;
    }
    if (!f->subscription->forward || !has_largest || empty) {
        /* No delivery handle was exposed; suppress rather than notify ready. */
        f->closed = 1;
        if (f->stream != NULL) {
            xqc_moqt_stream_cancel(f->stream, XQC_MOQT_RESET_CANCELLED);
        } else {
            xqc_moqt_fetch_free(f);
        }
        return XQC_MOQT_NO_ERROR;
    }
    f->info = info;
    f->confirmed = 1;
    return XQC_MOQT_NO_ERROR;
}

void
xqc_moqt_fill_cancel(xqc_moqt_subscription_t *sub)
{
    for (;;) {
        xqc_moqt_fetch_t *f = sub->session->fetches;
        while (f != NULL && (f->subscription != sub || f->closed)) {
            f = f->next;
        }
        if (f == NULL) {
            return;
        }
        xqc_moqt_fetch_cancel(f, XQC_MOQT_RESET_CANCELLED);
    }
}

void
xqc_moqt_fetch_complete(xqc_moqt_fetch_t *f, const xqc_moqt_error_t *error)
{
    if (f == NULL || f->closed) {
        return;
    }
    f->active++;
    f->closed = 1;
    f->deadline = 0;
    if (f->request != NULL) {
        f->request->fetch = NULL;
        f->request = NULL;
    }
    if (error != NULL && f->stream != NULL) {
        xqc_moqt_stream_cancel(f->stream, error->context == XQC_MOQT_ERROR_RESET
            ? error->code : XQC_MOQT_RESET_CANCELLED);
    }
    if (f->session->callbacks.on_fetch_closed != NULL) {
        f->session->callbacks.on_fetch_closed(f, error, f->session->user_data);
    }
    f->active--;
    xqc_moqt_fetch_free(f);
}

void
xqc_moqt_fetch_cancel(xqc_moqt_fetch_t *f, uint64_t code)
{
    if (f == NULL || f->closed) {
        return;
    }
    f->active++;
    xqc_moqt_request_t *r = f->request;
    /* Section 3.4.1: an accepted Fill failure still identifies its stream. */
    if (f->subscription != NULL && f->ready && !f->opened) {
        /* Only the publisher creates a missing Fill data stream. */
        if (f->track->local_publisher && !f->session->closed) {
            if (xqc_moqt_fetch_open(f) == NULL) {
                xqc_moqt_session_close(f->session, XQC_MOQT_INTERNAL_ERROR);
            }
        }
    }
    xqc_moqt_error_t error = {XQC_MOQT_ERROR_RESET, code,
        xqc_moqt_error_normalize(XQC_MOQT_ERROR_RESET, code)};
    xqc_moqt_stream_t *head = xqc_moqt_streams_hold(f->session);
    xqc_moqt_fetch_complete(f, &error);
    if (r != NULL) {
        xqc_moqt_request_cancel(r, code);
    }
    xqc_moqt_streams_release(head);
    f->active--;
    xqc_moqt_fetch_free(f);
}

void
xqc_moqt_fetch_release(xqc_moqt_request_t *r)
{
    xqc_moqt_fetch_t *f = r->fetch;
    if (f == NULL) {
        return;
    }
    r->fetch = NULL;
    f->request = NULL;
    /* Section 3.2.2: request FIN is independent of data delivery. */
    if (!f->ready || f->session->closed || r->has_error) {
        xqc_moqt_fetch_cancel(f, XQC_MOQT_RESET_CANCELLED);
    }
}

void
xqc_moqt_fetch_stream_closed(xqc_moqt_stream_t *st)
{
    xqc_moqt_fetch_t *f = st->state.data.fetch;
    if (f != NULL) {
        st->state.data.fetch = NULL;
        f->stream = NULL;
        xqc_moqt_fetch_free(f);
    }
}

void
xqc_moqt_fetch_ready(xqc_moqt_request_t *r, uint64_t id)
{
    xqc_moqt_fetch_t *f = r->fetch;
    if (f == NULL && r->subscription != NULL) {
        f = r->stream->session->fetches;
        while (f != NULL && (f->subscription != r->subscription
                             || f->info.request_id != id))
        {
            f = f->next;
        }
    }
    if (f == NULL || !f->confirmed || f->ready || f->closed) {
        return;
    }
    f->active++;
    f->ready = 1;
    f->deadline = xqc_monotonic_timestamp() + f->session->config.timeout;
    if (f->session->callbacks.on_fetch_ready != NULL) {
        f->session->callbacks.on_fetch_ready(f, f->subscription,
                                             f->session->user_data);
    } else if (f->subscription != NULL && f->track->local_publisher) {
        xqc_moqt_fetch_cancel(f, XQC_MOQT_RESET_INTERNAL_ERROR);
    }
    if (f->stream != NULL && !f->closed && !f->track->local_publisher) {
        xqc_moqt_stream_input(f->stream, NULL, 0, f->stream->rx_fin);
    }
    xqc_moqt_timer_update(f->session);
    f->active--;
    xqc_moqt_fetch_free(f);
}

xqc_int_t
xqc_moqt_fetch_contains(const xqc_moqt_fetch_t *f,
    const xqc_moqt_object_t *object)
{
    if (f == NULL || !f->ready || f->closed) {
        return XQC_ERROR;
    }
    xqc_moqt_location_t location = {object->group_id, object->object_id};
    return xqc_moqt_location_compare(&location, &f->info.start) >= 0
        && xqc_moqt_location_compare(&location, &f->info.end) <= 0
        ? XQC_OK : XQC_ERROR;
}

xqc_int_t
xqc_moqt_fetch_attach(xqc_moqt_stream_t *st)
{
    xqc_var_buf_t *rx = &st->rx;
    uint64_t type, id;
    xqc_int_t n = xqc_vi64_read(rx->data, rx->data + rx->data_len, &type);
    if (n < 0) {
        return -XQC_EAGAIN;
    }
    xqc_int_t m = xqc_vi64_read(rx->data + n, rx->data + rx->data_len, &id);
    if (m < 0) {
        return -XQC_EAGAIN;
    }
    xqc_moqt_fetch_t *f = st->session->fetches;
    while (f != NULL
        && (f->track->local_publisher || f->info.request_id != id))
    {
        f = f->next;
    }
    if (f == NULL) {
        /* A cancelled interest may already have released its handle. */
        xqc_moqt_stream_cancel(st, XQC_MOQT_RESET_CANCELLED);
        return XQC_OK;
    }
    /* Section 3.2.2: exactly one data stream per FETCH Request ID. */
    if (f->opened) {
        return -XQC_EILLEGAL_FRAME;
    }
    f->stream = st;
    f->opened = 1;
    if (f->subscription != NULL) {
        f->subscription->stream_count++;
    }
    st->state.data.fetch = f;
    st->state.data.track = f->track;
    f->track->references++;
    st->state.data.prefix_length = n + m;
    rx->data_len -= n + m;
    memmove(rx->data, rx->data + n + m, rx->data_len);
    return XQC_OK;
}

xqc_moqt_stream_t *
xqc_moqt_fetch_open(xqc_moqt_fetch_t *f)
{
    if (f == NULL || !f->ready || f->closed || f->opened) {
        return NULL;
    }
    xqc_moqt_session_t *s = f->session;
    if (!f->track->local_publisher || s->closed) {
        return NULL;
    }
    size_t len = xqc_vi64_len(XQC_MOQT_FETCH_STREAM)
                 + xqc_vi64_len(f->info.request_id);
    xqc_var_buf_t *buf = xqc_moqt_buffer_create(s, len, sizeof(*buf));
    if (buf == NULL) {
        return NULL;
    }
    uint8_t *end = buf->data + len;
    uint8_t *p = buf->data + xqc_vi64_write(buf->data, end,
                                           XQC_MOQT_FETCH_STREAM);
    xqc_vi64_write(p, end, f->info.request_id);
    buf->data_len = len;
    xqc_stream_t *transport = xqc_stream_create_with_direction(s->conn,
                                                               XQC_STREAM_UNI,
                                                               NULL);
    if (transport == NULL || s->closed) {
        xqc_moqt_buffer_free(s, buf, sizeof(*buf));
        return NULL;
    }
    xqc_moqt_stream_t *st = transport->user_data;
    st->kind = XQC_MOQT_STREAM_FETCH;
    st->state.data.fetch = f;
    st->state.data.track = f->track;
    st->state.data.prefix_length = len;
    f->track->references++;
    f->stream = st;
    f->opened = 1;
    if (f->subscription != NULL) {
        f->subscription->stream_count++;
    }
    if (xqc_moqt_queue(s, &st->tx, buf) != XQC_OK) {
        xqc_moqt_buffer_free(s, buf, sizeof(*buf));
        xqc_moqt_stream_cancel(st, XQC_MOQT_RESET_EXCESSIVE_LOAD);
        return NULL;
    }
    return st;
}
