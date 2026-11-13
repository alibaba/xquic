/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include "xqc_moqt_session.h"
#include "xqc_moqt_codec.h"
#include "src/transport/xqc_stream.h"

#define XQC_MOQT_PROPERTY_PRIOR_GROUP_GAP  0x3c
#define XQC_MOQT_PROPERTY_PRIOR_OBJECT_GAP 0x3e
#define XQC_MOQT_PROPERTY_MANDATORY_FIRST  0x4000
#define XQC_MOQT_PROPERTY_MANDATORY_LAST   0x7fff
#define XQC_MOQT_SEEN_IMMUTABLE            0x01u
#define XQC_MOQT_SEEN_GROUP_GAP            0x02u
#define XQC_MOQT_SEEN_OBJECT_GAP           0x04u

/* Sections 3.7, 10.7-10.9: Object properties can invalidate only this Track. */
static xqc_int_t
xqc_moqt_object_properties_check(xqc_moqt_track_t *track,
    xqc_moqt_group_t *g, const xqc_moqt_object_t *o, const struct iovec *bytes,
    size_t *count, unsigned *seen, xqc_moqt_data_stream_t *delivery)
{
    const uint8_t *data = bytes->iov_base;
    size_t pos = 0;
    uint64_t previous = 0;
    while (pos < bytes->iov_len) {
        xqc_moqt_kv_t kv;
        xqc_int_t n = xqc_moqt_kv_decode(data + pos, bytes->iov_len - pos,
                                         previous, &kv);
        if (n < 0
            || ++*count > XQC_MOQT_MAX_OPTIONS
            || (kv.type >= XQC_MOQT_PROPERTY_MANDATORY_FIRST
                && kv.type <= XQC_MOQT_PROPERTY_MANDATORY_LAST))
        {
            return XQC_ERROR;
        }
        previous = kv.type;
        pos += n;
        switch (kv.type) {
        case XQC_MOQT_PROPERTY_IMMUTABLE:
            if (*seen & XQC_MOQT_SEEN_IMMUTABLE) {
                return XQC_ERROR;
            }
            *seen |= XQC_MOQT_SEEN_IMMUTABLE;
            if (xqc_moqt_object_properties_check(
                track, g, o, &kv.value.bytes, count, seen, delivery) != XQC_OK)
            {
                return XQC_ERROR;
            }
            break;
        case XQC_MOQT_PROPERTY_OBJECT_TIMEOUT:
        case XQC_MOQT_PROPERTY_SUBGROUP_TIMEOUT:
            /* Section 5.2: only FIRST_OBJECT overrides Track defaults. */
            if (delivery != NULL && (o->first_in_subgroup || o->datagram)) {
                if (kv.type == XQC_MOQT_PROPERTY_OBJECT_TIMEOUT) {
                    delivery->object_timeout = kv.value.integer;
                    delivery->has_object_timeout = 1;
                } else {
                    delivery->subgroup_timeout = kv.value.integer;
                    delivery->has_subgroup_timeout = 1;
                }
            }
            break;
        case XQC_MOQT_PROPERTY_PRIOR_GROUP_GAP:
            if ((*seen & XQC_MOQT_SEEN_GROUP_GAP)
                || kv.value.integer > o->group_id
                || (g->has_prior_group_gap
                    && g->prior_group_gap != kv.value.integer)
                || (track->has_largest
                    && track->largest.group_id < o->group_id
                    && track->largest.group_id
                       >= o->group_id - kv.value.integer))
            {
                return XQC_ERROR;
            }
            for (const xqc_moqt_group_t *known = &track->group; known != NULL;
                 known = known == &track->group ? track->groups : known->next)
            {
                if (known->valid
                    && known->has_largest
                    && known->group_id < o->group_id
                    && known->group_id >= o->group_id - kv.value.integer)
                {
                    return XQC_ERROR;
                }
            }
            *seen |= XQC_MOQT_SEEN_GROUP_GAP;
            g->prior_group_gap = kv.value.integer;
            g->has_prior_group_gap = 1;
            break;
        case XQC_MOQT_PROPERTY_PRIOR_OBJECT_GAP:
            if ((*seen & XQC_MOQT_SEEN_OBJECT_GAP)
                || kv.value.integer > o->object_id
                || (g->has_largest
                    && g->largest_object < o->object_id
                    && g->largest_object >= o->object_id - kv.value.integer))
            {
                return XQC_ERROR;
            }
            *seen |= XQC_MOQT_SEEN_OBJECT_GAP;
            g->gap_start = o->object_id - kv.value.integer;
            g->gap_end = o->object_id;
            g->has_gap = 1;
            break;
        default:
            /* Ordinary unknown properties remain in the borrowed wire view. */
            break;
        }
    }
    return XQC_OK;
}

static xqc_int_t
xqc_moqt_object_is_obsolete(const xqc_moqt_track_t *track,
    const xqc_moqt_group_t *g, const xqc_moqt_object_t *o)
{
    /* Status objects carry boundary information and must still be processed. */
    if (o->status != XQC_MOQT_OBJECT_NORMAL || o->range) {
        return 0;
    }

    /* Section 2.1.2: the Track end is the first non-existent location. */
    xqc_moqt_location_t location = {o->group_id, o->object_id};
    xqc_int_t end = xqc_moqt_location_compare(&location, &track->end);
    if (track->has_end && (end > 0 || (end == 0 && !track->end_inclusive))) {
        return 1;
    }

    /* A Group boundary applies only to objects in that same Group. */
    if (!g->valid || g->group_id != o->group_id || !g->has_end) {
        return 0;
    }

    /* Objects beyond either kind of Group endpoint are known not to exist. */
    if (o->object_id > g->end_object) {
        return 1;
    }

    /* END_GROUP excludes its own ID; END_OF_GROUP on a Normal includes it. */
    return o->object_id == g->end_object && !g->end_inclusive;
}

/* Caller checks a copy, then commits only when receive/send has succeeded. */
static xqc_int_t
xqc_moqt_object_apply(xqc_moqt_track_t *track, xqc_moqt_group_t *g,
    const xqc_moqt_object_t *o, xqc_moqt_data_stream_t *delivery)
{
    for (const xqc_moqt_group_t *known = &track->group; known != NULL;
         known = known == &track->group ? track->groups : known->next)
    {
        if (known->valid
            && known->has_prior_group_gap
            && o->group_id < known->group_id
            && o->group_id >= known->group_id - known->prior_group_gap)
        {
            return XQC_ERROR;
        }
    }
    if (!g->valid || g->group_id != o->group_id) {
        xqc_memzero(g, sizeof(*g));
        g->group_id = o->group_id;
        g->valid = 1;
        if (track->has_largest && track->largest.group_id == o->group_id) {
            g->largest_object = track->largest.object_id;
            g->has_largest = 1;
        }
    }
    if (g->has_gap
        && o->status == XQC_MOQT_OBJECT_NORMAL
        && o->object_id >= g->gap_start
        && o->object_id < g->gap_end)
    {
        return XQC_ERROR;
    }
    size_t count = 0;
    unsigned seen = 0;
    if (xqc_moqt_object_properties_check(track, g, o, &o->properties, &count,
                                         &seen, delivery) != XQC_OK)
    {
        return XQC_ERROR;
    }
    xqc_moqt_location_t location = {o->group_id, o->object_id};
    if (o->status == XQC_MOQT_OBJECT_END_TRACK) {
        if (track->has_largest
            && xqc_moqt_location_compare(&track->largest, &location) >= 0)
        {
            return XQC_ERROR;
        }
        if (!track->has_end
            || xqc_moqt_location_compare(&location, &track->end) < 0)
        {
            track->end = location;
            track->has_end = 1;
            track->end_inclusive = 0;
        }
    }
    if (o->end_of_group || o->status == XQC_MOQT_OBJECT_END_GROUP) {
        if (g->has_largest
            && (g->largest_object > o->object_id
                || (g->largest_object == o->object_id
                    && !o->end_of_group)))
        {
            return XQC_ERROR;
        }
        if (!g->has_end
            || o->object_id < g->end_object
            || (o->object_id == g->end_object
                && !o->end_of_group))
        {
            g->end_object = o->object_id;
            g->end_inclusive = o->end_of_group;
            g->has_end = 1;
        }
    }
    /* Section 2.1.2: late delivery does not overturn known non-existence. */
    if (o->status == XQC_MOQT_OBJECT_NORMAL
        && !xqc_moqt_object_is_obsolete(track, g, o))
    {
        if (!g->has_largest || o->object_id > g->largest_object) {
            g->largest_object = o->object_id;
            g->has_largest = 1;
        }
        if (!track->has_largest
            || xqc_moqt_location_compare(&location, &track->largest) > 0)
        {
            track->largest = location;
            track->has_largest = 1;
        }
    }
    return XQC_OK;
}

static xqc_moqt_group_t *
xqc_moqt_group_find(xqc_moqt_track_t *track, uint64_t id)
{
    for (xqc_moqt_group_t *g = track->groups; g != NULL; g = g->next) {
        if (g->group_id == id) {
            return g;
        }
    }
    return &track->group;
}

static void
xqc_moqt_object_dispatch(xqc_moqt_session_t *s, xqc_moqt_track_t *track,
    uint64_t alias, uint64_t flags, const xqc_moqt_object_t *object,
    xqc_moqt_stream_t *stream, xqc_int_t malformed, xqc_int_t obsolete)
{
    xqc_moqt_stream_t *head = xqc_moqt_streams_hold(s);
    xqc_moqt_subscription_t *subscriptions = xqc_moqt_subscriptions_hold(s);
    xqc_moqt_location_t location = {object->group_id, object->object_id};
    for (xqc_moqt_subscription_t *sub = subscriptions;
         sub != NULL && !s->closed; sub = sub->next)
    {
        if (sub->closed || sub->track != track) {
            continue;
        }
        if (malformed) {
            xqc_moqt_subscription_cancel(sub, XQC_MOQT_RESET_MALFORMED_TRACK);
        } else if (!obsolete
                   && sub->track_alias == alias
                   && xqc_moqt_subscription_is_matching(sub, &location)
                   && s->callbacks.on_object != NULL)
        {
            xqc_moqt_object_t view = *object;
            if (stream == NULL
                && (flags & XQC_MOQT_DATAGRAM_DEFAULT_PRIORITY))
            {
                view.priority = sub->publisher_priority;
            }
            s->callbacks.on_object(sub, stream, &view, s->user_data);
        }
    }
    /* Malformed Track properties invalidate every interest in that Track. */
    while (malformed) {
        xqc_moqt_fetch_t *f = s->fetches;
        while (f != NULL && (f->closed || f->track != track)) {
            f = f->next;
        }
        if (f == NULL) {
            break;
        }
        xqc_moqt_fetch_cancel(f, XQC_MOQT_RESET_MALFORMED_TRACK);
    }
    xqc_moqt_subscriptions_release(subscriptions);
    xqc_moqt_streams_release(head);
}

xqc_bool_t
xqc_moqt_subscription_object_is_obsolete(const xqc_moqt_subscription_t *sub,
    const xqc_moqt_object_t *object)
{
    return sub != NULL && object != NULL
        && xqc_moqt_object_is_obsolete(sub->track,
            xqc_moqt_group_find(sub->track, object->group_id), object);
}

void
xqc_moqt_datagram_input(xqc_moqt_session_t *s, const uint8_t *data, size_t len)
{
    if (s == NULL || s->closed) {
        return;
    }
    uint64_t alias, flags;
    xqc_moqt_object_t object;
    if (xqc_moqt_datagram_decode(data, len, &alias, &flags, &object) < 0) {
        xqc_moqt_session_close(s, XQC_MOQT_PROTOCOL_VIOLATION);
        return;
    }
    if (flags == XQC_MOQT_PADDING_DATAGRAM || !s->ready) {
        return;
    }
    xqc_moqt_subscription_t *sub = s->subscriptions;
    while (sub != NULL && (sub->track->local_publisher || !sub->established
        || sub->stopped || sub->track_alias != alias))
    {
        sub = sub->next;
    }
    if (sub == NULL) {
        return;
    }
    xqc_moqt_track_t *track = sub->track;
    xqc_moqt_track_t candidate = *track;
    xqc_moqt_group_t *group = xqc_moqt_group_find(track, object.group_id);
    xqc_moqt_group_t updated = *group;
    xqc_int_t malformed = xqc_moqt_object_apply(
        &candidate, &updated, &object, NULL) != XQC_OK;
    xqc_int_t obsolete = xqc_moqt_object_is_obsolete(track, group, &object);
    if (!malformed) {
        *track = candidate;
        *group = updated;
    }
    xqc_moqt_object_dispatch(s, track, alias, flags, &object, NULL,
                             malformed, obsolete);
}

static xqc_int_t
xqc_moqt_datagram_is_blocked(const xqc_moqt_session_t *s,
    const xqc_moqt_subscription_t *sub, const xqc_moqt_object_t *o)
{
    for (xqc_moqt_stream_t *st = s->streams; st != NULL; st = st->next) {
        /* A closed or detached stream cannot delay a Datagram. */
        if (st->discarded || st->transport_stream == NULL) {
            continue;
        }
        /* Only queued bytes that can pass flow control compete for sending. */
        if ((s->conn->conn_flag & XQC_CONN_FLAG_DATA_BLOCKED)
            || (st->transport_stream->stream_flag
                & XQC_STREAM_FLAG_DATA_BLOCKED)
            || xqc_list_empty(&st->tx))
        {
            continue;
        }
        /* Control and request bytes take precedence over object data. */
        if (st->kind == XQC_MOQT_STREAM_CONTROL
            || st->kind == XQC_MOQT_STREAM_REQUEST)
        {
            return 1;
        }
        /* Submitted Fetch and Subgroup Objects share the same scheduler. */
        if (st->kind != XQC_MOQT_STREAM_SUBGROUP
            && st->kind != XQC_MOQT_STREAM_FETCH)
        {
            continue;
        }
        xqc_moqt_data_stream_t *d = &st->state.data;
        if (sub != NULL && d->has_object) {
            xqc_moqt_subscription_t *owner = d->fetch != NULL
                ? d->fetch->subscription : d->subscription;
            if (xqc_moqt_data_compare(owner, &d->object, d->fetch,
                                      sub, o, NULL) < 0)
            {
                return 1;
            }
        }
    }
    return 0;
}

void
xqc_moqt_datagram_writable(xqc_moqt_session_t *s)
{
    if (s != NULL
        && !s->closed
        && s->datagram_blocked
        && !xqc_moqt_datagram_is_blocked(s, NULL, NULL))
    {
        s->datagram_blocked = 0;
        if (s->callbacks.on_writable != NULL) {
            s->callbacks.on_writable(s, NULL, s->user_data);
        }
    }
}

static uint64_t
xqc_moqt_timeout_min(uint64_t publisher, uint64_t subscriber)
{
    return publisher && subscriber ? xqc_min(publisher, subscriber)
                                   : xqc_max(publisher, subscriber);
}

xqc_int_t
xqc_moqt_object_is_expired(xqc_moqt_stream_t *st,
    xqc_usec_t submitted, xqc_usec_t now)
{
    xqc_moqt_data_stream_t *d = &st->state.data;
    if (submitted == 0 || d->subscription == NULL || now < submitted) {
        return 0;
    }
    uint64_t limit = xqc_moqt_timeout_min(d->has_object_timeout
        ? d->object_timeout : d->track->object_timeout,
        d->subscription->object_timeout);
    return limit && (now - submitted) / XQC_MOQT_MICROS_PER_MILLISECOND
                   >= limit;
}

xqc_usec_t
xqc_moqt_subgroup_deadline(xqc_moqt_stream_t *st)
{
    xqc_moqt_data_stream_t *d = &st->state.data;
    /* FIN notification does not mean all bytes have been acknowledged. */
    if (!d->finish_time || d->subscription == NULL || st->discarded) {
        return 0;
    }
    if (st->transport_stream == NULL
        || st->transport_stream->stream_state_send
           == XQC_SEND_STREAM_ST_DATA_RECVD)
    {
        return 0;
    }
    uint64_t limit = xqc_moqt_timeout_min(d->has_subgroup_timeout
        ? d->subgroup_timeout : d->track->subgroup_timeout,
        d->subscription->subgroup_timeout);
    if (!limit) {
        return 0;
    }
    if (limit > (UINT64_MAX - d->finish_time)
                    / XQC_MOQT_MICROS_PER_MILLISECOND)
    {
        return UINT64_MAX;
    }
    return d->finish_time + limit * XQC_MOQT_MICROS_PER_MILLISECOND;
}

xqc_int_t
xqc_moqt_datagram_send(xqc_moqt_subscription_t *sub, const xqc_moqt_object_t *o)
{
    if (sub == NULL || o == NULL) {
        return -XQC_EPARAM;
    }
    xqc_moqt_session_t *s = sub->session;
    xqc_moqt_location_t location = {o->group_id, o->object_id};
    xqc_moqt_group_t *group = xqc_moqt_group_find(sub->track, o->group_id);
    /* Publishing requires an established session and the publisher role. */
    if (s->closed || !s->ready || !sub->track->local_publisher) {
        return -XQC_EPARAM;
    }
    /* The Object must remain inside the subscription and known boundaries. */
    if (!xqc_moqt_subscription_is_matching(sub, &location)
        || xqc_moqt_object_is_obsolete(sub->track, group, o))
    {
        return -XQC_EPARAM;
    }
    xqc_int_t len = xqc_moqt_datagram_encode(sub->track_alias, o, NULL, 0);
    if (len < 0) {
        return len;
    }
    xqc_moqt_track_t candidate = *sub->track;
    xqc_moqt_group_t updated = *group;
    xqc_usec_t submitted = xqc_monotonic_timestamp();
    xqc_moqt_data_stream_t policy;
    xqc_memzero(&policy, sizeof(policy));
    if (xqc_moqt_object_apply(&candidate, &updated, o, &policy) != XQC_OK) {
        return -XQC_EPARAM;
    }
    if ((size_t)len > xqc_moqt_transport_mss(s)) {
        return -XQC_EDGRAM_TOO_LARGE;
    }
    if (xqc_moqt_datagram_is_blocked(s, sub, o)) {
        s->datagram_blocked = 1;
        return -XQC_EAGAIN;
    }
    xqc_var_buf_t *buf = xqc_moqt_buffer_create(s, len, sizeof(*buf));
    if (buf == NULL) {
        return -XQC_EMALLOC;
    }
    xqc_moqt_datagram_encode(sub->track_alias, o, buf->data, len);
    uint64_t object_limit = xqc_moqt_timeout_min(policy.has_object_timeout
        ? policy.object_timeout : sub->track->object_timeout,
        sub->object_timeout);
    uint64_t subgroup_limit = xqc_moqt_timeout_min(policy.has_subgroup_timeout
        ? policy.subgroup_timeout : sub->track->subgroup_timeout,
        sub->subgroup_timeout);
    uint64_t limit = xqc_moqt_timeout_min(object_limit, subgroup_limit);
    if (limit
        && (xqc_monotonic_timestamp() - submitted)
                 / XQC_MOQT_MICROS_PER_MILLISECOND >= limit)
    {
        xqc_moqt_buffer_free(s, buf, sizeof(*buf));
        return -XQC_EEXPIRED;
    }
    xqc_moqt_stream_t *head = xqc_moqt_streams_hold(s);
    xqc_moqt_subscription_t *subscriptions = xqc_moqt_subscriptions_hold(s);
    xqc_int_t ret = xqc_moqt_transport_datagram(s, buf->data, len);
    xqc_moqt_buffer_free(s, buf, sizeof(*buf));
    if (ret == XQC_OK) {
        sub->track->largest = candidate.largest;
        sub->track->has_largest = candidate.has_largest;
        sub->track->end = candidate.end;
        sub->track->has_end = candidate.has_end;
        *group = updated;
    } else if (ret == -XQC_EAGAIN) {
        s->datagram_blocked = 1;
    }
    xqc_moqt_subscriptions_release(subscriptions);
    xqc_moqt_streams_release(head);
    return ret;
}

static void
xqc_moqt_subgroup_release(xqc_moqt_stream_t *st)
{
    xqc_moqt_data_stream_t *d = &st->state.data;
    xqc_moqt_session_t *s = st->session;
    xqc_moqt_subgroup_t *sg = d->subgroup;
    if (sg != NULL && --sg->references == 0) {
        xqc_moqt_group_t *g = sg->group;
        xqc_moqt_subgroup_t **link = &g->subgroups;
        while (*link != sg) {
            link = &(*link)->next;
        }
        *link = sg->next;
        s->buffered_bytes -= sizeof(*sg);
        xqc_free(sg);
        if (g->subgroups == NULL) {
            xqc_moqt_group_t **link = &d->track->groups;
            while (*link != g) {
                link = &(*link)->next;
            }
            *link = g->next;
            d->track->group = *g;
            d->track->group.next = NULL;
            s->buffered_bytes -= sizeof(*g);
            xqc_free(g);
        }
    }
    d->subgroup = NULL;
}

/* Section 12.1: per-stream deltas do not replace shared Subgroup bounds. */
static xqc_int_t
xqc_moqt_subgroup_apply(xqc_moqt_stream_t *st, const xqc_moqt_object_t *o,
    xqc_int_t fin)
{
    xqc_moqt_data_stream_t *d = &st->state.data;
    xqc_moqt_track_t *track = d->track, candidate = *track;
    xqc_moqt_group_t *g = xqc_moqt_group_find(track, o->group_id);
    xqc_moqt_group_t group = *g;
    xqc_moqt_subgroup_t *sg = group.valid && group.group_id == o->group_id
        ? group.subgroups : NULL;
    while (sg != NULL && sg->subgroup_id != o->subgroup_id) {
        sg = sg->next;
    }
    xqc_moqt_subgroup_t subgroup;
    if (sg != NULL) {
        subgroup = *sg;
    } else {
        xqc_memzero(&subgroup, sizeof(subgroup));
        subgroup.subgroup_id = o->subgroup_id;
        subgroup.priority = o->priority;
    }
    /* Every stream for the same Subgroup must use the same priority. */
    if (subgroup.priority != o->priority) {
        return -XQC_EPARAM;
    }

    /* A known first Object excludes all smaller IDs in this Subgroup. */
    if (subgroup.has_first && o->object_id < subgroup.first) {
        return -XQC_EPARAM;
    }

    /* A known final Object excludes all larger IDs in this Subgroup. */
    if (subgroup.has_last && o->object_id > subgroup.last) {
        return -XQC_EPARAM;
    }

    /* FIRST_OBJECT cannot exclude an Object observed on another stream. */
    if (o->first_in_subgroup
        && subgroup.has_object
        && o->object_id > subgroup.minimum)
    {
        return -XQC_EPARAM;
    }

    /* Repeated FIRST_OBJECT claims must identify the same Object. */
    if (o->first_in_subgroup
        && subgroup.has_first
        && o->object_id != subgroup.first)
    {
        return -XQC_EPARAM;
    }

    /* FIN cannot place the final Object before one already observed. */
    if (fin && subgroup.has_object && o->object_id < subgroup.maximum) {
        return -XQC_EPARAM;
    }

    /* Normal FINs on different streams must agree on the final Object. */
    if (fin && subgroup.has_last && o->object_id != subgroup.last) {
        return -XQC_EPARAM;
    }

    xqc_moqt_data_stream_t policy = *d;
    if (xqc_moqt_object_apply(&candidate, &group, o, &policy) != XQC_OK) {
        return -XQC_EPARAM;
    }
    if (!subgroup.has_object) {
        subgroup.minimum = subgroup.maximum = o->object_id;
    }
    subgroup.minimum = xqc_min(subgroup.minimum, o->object_id);
    subgroup.maximum = xqc_max(subgroup.maximum, o->object_id);
    subgroup.has_object = 1;
    if (o->first_in_subgroup) {
        subgroup.first = o->object_id;
        subgroup.has_first = 1;
    }
    if (fin) {
        subgroup.last = o->object_id;
        subgroup.has_last = 1;
    }
    xqc_moqt_session_t *s = st->session;
    xqc_int_t new_group = g == &track->group;
    size_t needed = (new_group ? sizeof(*g) : 0) + (sg ? 0 : sizeof(*sg));
    if (needed > s->config.max_buffered_bytes - s->buffered_bytes) {
        return -XQC_EMALLOC;
    }
    if (new_group) {
        g = xqc_calloc(1, sizeof(*g));
        if (g == NULL) {
            return -XQC_EMALLOC;
        }
    }
    if (sg == NULL) {
        sg = xqc_calloc(1, sizeof(*sg));
        if (sg == NULL) {
            if (new_group) {
                xqc_free(g);
            }
            return -XQC_EMALLOC;
        }
        subgroup.next = group.subgroups;
        group.subgroups = sg;
    }
    if (new_group) {
        group.next = track->groups;
        track->groups = g;
    }
    *g = group;
    *sg = subgroup;
    sg->group = g;
    if (d->subgroup != sg) {
        sg->references++;
        xqc_moqt_subgroup_release(st);
        d->subgroup = sg;
    }
    s->buffered_bytes += needed;
    /* Section 3.2: historical FETCH delivery does not advance live Largest. */
    if (st->kind != XQC_MOQT_STREAM_FETCH) {
        track->largest = candidate.largest;
        track->has_largest = candidate.has_largest;
    }
    track->end = candidate.end;
    track->has_end = candidate.has_end;
    track->end_inclusive = candidate.end_inclusive;
    d->object_timeout = policy.object_timeout;
    d->subgroup_timeout = policy.subgroup_timeout;
    d->has_object_timeout = policy.has_object_timeout;
    d->has_subgroup_timeout = policy.has_subgroup_timeout;
    return XQC_OK;
}

static xqc_int_t
xqc_moqt_fetch_object_apply(xqc_moqt_stream_t *st, const xqc_moqt_object_t *o)
{
    /* Range records describe gaps; they are not objects in a Subgroup. */
    if (o->range != XQC_MOQT_RANGE_NONE) {
        return XQC_OK;
    }
    if (!o->datagram) {
        return xqc_moqt_subgroup_apply(st, o, 0);
    }
    xqc_moqt_track_t *track = st->state.data.track, candidate = *track;
    xqc_moqt_group_t *g = xqc_moqt_group_find(track, o->group_id), group = *g;
    if (xqc_moqt_object_apply(&candidate, &group, o, NULL) != XQC_OK) {
        return -XQC_EPARAM;
    }
    *g = group;
    return XQC_OK;
}

void
xqc_moqt_subgroup_notify(xqc_moqt_stream_t *st)
{
    xqc_moqt_data_stream_t *d = &st->state.data;
    if (d->notified) {
        return;
    }
    d->notified = 1;
    st->deadline = 0;
    xqc_moqt_subscription_t *head = xqc_moqt_subscriptions_hold(st->session);
    if (st->kind == XQC_MOQT_STREAM_SUBGROUP
        && d->track != NULL
        && !d->track->local_publisher)
    {
        for (xqc_moqt_subscription_t *sub = head; sub != NULL;
             sub = sub->next)
        {
            if (!sub->closed
                && sub->track == d->track
                && sub->track_alias == d->track_alias)
            {
                sub->finished_streams++;
            }
        }
    }
    if (st->kind == XQC_MOQT_STREAM_FETCH
        && d->fetch != NULL
        && d->fetch->subscription != NULL
        && !d->track->local_publisher)
    {
        d->fetch->subscription->finished_streams++;
    }
    xqc_moqt_object_t last = d->object;
    xqc_memzero(&last.properties, sizeof(last.properties));
    xqc_memzero(&last.payload, sizeof(last.payload));
    last.end_of_group = st->rx_fin && (d->flags & XQC_MOQT_SUBGROUP_END_GROUP);
    xqc_moqt_error_t error = {XQC_MOQT_ERROR_RESET, d->error,
        xqc_moqt_error_normalize(XQC_MOQT_ERROR_RESET, d->error)};
    if (st->session->callbacks.on_stream_closed != NULL) {
        st->session->callbacks.on_stream_closed(
            st,
            d->has_object ? &last : NULL, d->has_error ? &error : NULL,
            st->session->user_data);
    }
    if (st->kind == XQC_MOQT_STREAM_FETCH) {
        xqc_moqt_fetch_complete(d->fetch, d->has_error ? &error : NULL);
    }
    for (xqc_moqt_subscription_t *sub = head; sub != NULL; sub = sub->next) {
        xqc_moqt_subscription_check_done(sub);
    }
    xqc_moqt_subscriptions_release(head);
}

void
xqc_moqt_stream_cancel(xqc_moqt_stream_t *st, uint64_t error)
{
    if (st == NULL
        || st->discarded
        || (st->kind != XQC_MOQT_STREAM_SUBGROUP
            && st->kind != XQC_MOQT_STREAM_FETCH))
    {
        return;
    }
    xqc_moqt_data_stream_t *d = &st->state.data;
    if (st->kind == XQC_MOQT_STREAM_FETCH
        && d->fetch != NULL
        && d->fetch->subscription != NULL
        && d->track->local_publisher)
    {
        /* Section 3.4.1: a Fill failure must identify its trigger first. */
        if (!st->session->closed
            && st->transport_stream != NULL
            && st->transport_stream->stream_state_send
               < XQC_SEND_STREAM_ST_RESET_SENT
            && xqc_moqt_transport_offset(st) < d->prefix_length)
        {
            if (!d->reset_pending) {
                d->reset_pending = 1;
                d->error = error;
                st->deadline = xqc_monotonic_timestamp()
                               + st->session->config.timeout;
                xqc_moqt_timer_update(st->session);
            }
            xqc_moqt_stream_flush(st);
            return;
        }
    }
    st->active++;
    st->discarded = 1;
    st->state.data.error = error;
    st->state.data.has_error = 1;
    if (st->transport_stream != NULL) {
        xqc_moqt_transport_reset(st, error);
    }
    xqc_moqt_subgroup_notify(st);
    st->active--;
    if (!st->active
        && !st->reading
        && !st->writing
        && st->transport_stream == NULL)
    {
        xqc_moqt_stream_callbacks.stream_close_notify(NULL, st);
    }
}

void
xqc_moqt_subgroup_closed(xqc_moqt_stream_t *st)
{
    xqc_moqt_data_stream_t *d = &st->state.data;
    xqc_moqt_session_t *s = st->session;
    if (!d->notified) {
        xqc_int_t unconfirmed = st->kind == XQC_MOQT_STREAM_FETCH
            && (d->fetch == NULL || !d->fetch->ready || s->closed);
        if ((!st->rx_fin && !st->tx_fin_sent) || unconfirmed) {
            d->has_error = 1;
            d->error = XQC_MOQT_RESET_SESSION_CLOSED;
        }
        xqc_moqt_subgroup_notify(st);
    }
    xqc_moqt_subgroup_release(st);
    xqc_moqt_fetch_stream_closed(st);
    if (d->subscription != NULL) {
        xqc_moqt_subscription_t *sub = d->subscription;
        d->subscription = NULL;
        xqc_moqt_subscription_check_done(sub);
    }
    if (d->track != NULL) {
        xqc_moqt_track_release(s, d->track);
    }
}

void
xqc_moqt_subscription_data_update(xqc_moqt_subscription_t *sub)
{
    xqc_moqt_session_t *s = sub->session;
    xqc_moqt_stream_t *head = xqc_moqt_streams_hold(s);
    for (xqc_moqt_stream_t *st = head; st != NULL; st = st->next) {
        if (st->kind != XQC_MOQT_STREAM_SUBGROUP) {
            continue;
        }
        xqc_moqt_data_stream_t *d = &st->state.data;
        xqc_moqt_location_t location = {d->object.group_id,
                                        d->object.object_id};
        if (d->subscription == sub) {
            if (st->discarded) {
                if (sub->closed) {
                    d->subscription = NULL;
                }
                continue;
            }
            /* DONE keeps already-finished streams and their ACK timers. */
            if (sub->done && !sub->closed) {
                continue;
            }
            if (!sub->stopped
                && sub->forward
                && (!d->has_object
                    || xqc_moqt_subscription_is_matching(sub, &location)))
            {
                continue;
            }
            /* A paused subscription still owns the FIN-to-ACK deadline. */
            if (st->tx_fin_sent && !sub->closed) {
                continue;
            }
            d->subscription = NULL;
            if (sub->closed || !st->tx_fin_sent) {
                xqc_moqt_stream_cancel(st, XQC_MOQT_RESET_CANCELLED);
            }
        } else if (d->track == sub->track
                   && !d->track->local_publisher
                   && d->track_alias == sub->track_alias
                   && !st->rx_fin)
        {
            xqc_moqt_subscription_t *other = s->subscriptions;
            while (other != NULL) {
                /* Another established interest may still need this Alias. */
                if (other->track == d->track
                    && other->track_alias == d->track_alias
                    && other->established
                    && other->forward)
                {
                    /* Keep the stream only while that interest accepts it. */
                    if (!other->stopped
                        && (!d->has_object
                            || xqc_moqt_subscription_is_matching(other,
                                                                 &location)))
                    {
                        break;
                    }
                }
                other = other->next;
            }
            if (other == NULL) {
                xqc_moqt_stream_cancel(st, XQC_MOQT_RESET_CANCELLED);
            }
        }
    }
    xqc_moqt_streams_release(head);
}

xqc_int_t
xqc_moqt_subgroup_input(xqc_moqt_stream_t *st, uint8_t fin)
{
    xqc_moqt_session_t *s = st->session;
    xqc_moqt_data_stream_t *d = &st->state.data;
    xqc_var_buf_t *rx = &st->rx;
    if (st->kind == XQC_MOQT_STREAM_FETCH) {
        if (d->track == NULL) {
            xqc_int_t ret = xqc_moqt_fetch_attach(st);
            if (ret == -XQC_EAGAIN && !fin) {
                return XQC_OK;
            }
            if (ret < 0) {
                goto malformed;
            }
            if (st->discarded) {
                return XQC_OK;
            }
        }
        st->rx_fin = fin;
        /* Section 3.2.2: retain bounded data, including FIN, until FETCH_OK. */
        if (!d->fetch->ready) {
            return XQC_OK;
        }
        d->fetch->deadline = xqc_monotonic_timestamp() + s->config.timeout;
    }
    if (d->track == NULL) {
        xqc_int_t n = xqc_moqt_subgroup_header_decode(
            rx->data, rx->data_len,
            &d->track_alias, &d->flags, &d->object);
        if (n == -XQC_EAGAIN && !fin) {
            return XQC_OK;
        }
        if (n < 0) {
            goto malformed;
        }
        xqc_moqt_subscription_t *sub = s->subscriptions;
        while (sub != NULL && (sub->track->local_publisher || !sub->established
            || sub->stopped || sub->track_alias != d->track_alias))
        {
            sub = sub->next;
        }
        if (sub == NULL) {
            xqc_moqt_stream_cancel(st, XQC_MOQT_RESET_CANCELLED);
            return XQC_OK;
        }
        d->track = sub->track;
        d->track->references++;
        for (xqc_moqt_subscription_t *other = s->subscriptions; other != NULL;
             other = other->next)
        {
            if (!other->closed
                && other->track == d->track
                && other->track_alias == d->track_alias)
            {
                other->stream_count++;
            }
        }
        if (d->flags & XQC_MOQT_SUBGROUP_DEFAULT_PRIORITY) {
            d->object.priority = sub->publisher_priority;
        }
        rx->data_len -= n;
        memmove(rx->data, rx->data + n, rx->data_len);
    }
    while (rx->data_len && !st->discarded && !s->closed) {
        if (!d->object_header) {
            if (!d->object_time) {
                d->object_time = xqc_monotonic_timestamp();
            }
            xqc_moqt_object_t object = d->object;
            xqc_int_t n = st->kind == XQC_MOQT_STREAM_FETCH
                ? xqc_moqt_fetch_header_decode(rx->data, rx->data_len,
                    d->fetch->info.group_order, &d->history, &object)
                : xqc_moqt_object_header_decode(rx->data, rx->data_len,
                    d->flags, d->has_object ? &d->object : NULL, &object);
            if (n == -XQC_EAGAIN) {
                break;
            }
            if (n < 0) {
                goto malformed;
            }
            if (st->kind == XQC_MOQT_STREAM_FETCH
                && xqc_moqt_fetch_contains(d->fetch, &object) != XQC_OK)
            {
                goto malformed;
            }
            d->object = object;
            d->header_length = n;
            d->properties_offset = object.properties.iov_len
                ? (uint8_t *)object.properties.iov_base - rx->data : 0;
            d->object_header = 1;
        }
        xqc_moqt_object_t *o = &d->object;
        size_t len = xqc_min(rx->data_len - d->header_length,
                             o->payload_length - o->payload_offset);
        if (len == 0 && o->payload_length != 0) {
            break;
        }
        o->properties.iov_base = o->properties.iov_len
            ? rx->data + d->properties_offset : NULL;
        xqc_int_t malformed = 0;
        if (o->payload_offset == 0) {
            xqc_int_t ret = st->kind == XQC_MOQT_STREAM_FETCH
                ? xqc_moqt_fetch_object_apply(st, o)
                : xqc_moqt_subgroup_apply(st, o, 0);
            if (ret == -XQC_EMALLOC) {
                xqc_moqt_stream_cancel(st, XQC_MOQT_RESET_EXCESSIVE_LOAD);
                return XQC_OK;
            }
            malformed = ret != XQC_OK;
            d->has_object = 1;
        }
        o->payload.iov_base = rx->data + d->header_length;
        o->payload.iov_len = len;
        xqc_int_t obsolete = xqc_moqt_object_is_obsolete(
            d->track,
            xqc_moqt_group_find(d->track, o->group_id), o);
        if (st->kind == XQC_MOQT_STREAM_FETCH && !malformed) {
            if (s->callbacks.on_object != NULL && !obsolete) {
                s->callbacks.on_object(d->fetch->subscription, st, o,
                                        s->user_data);
            }
        } else {
            xqc_moqt_object_dispatch(s, d->track, d->track_alias, d->flags,
                                     o, st, malformed, obsolete);
        }
        o->payload_offset += len;
        rx->data_len -= len;
        memmove(rx->data + d->header_length,
                rx->data + d->header_length + len,
                rx->data_len - d->header_length);
        if (o->payload_offset == o->payload_length) {
            rx->data_len -= d->header_length;
            memmove(rx->data, rx->data + d->header_length, rx->data_len);
            d->object_header = 0;
            d->object_time = 0;
            xqc_memzero(&o->properties, sizeof(o->properties));
            xqc_memzero(&o->payload, sizeof(o->payload));
        }
        if (malformed) {
            xqc_moqt_stream_cancel(st, XQC_MOQT_RESET_MALFORMED_TRACK);
            return XQC_OK;
        }
    }
    if (fin && !st->discarded && !s->closed) {
        if (rx->data_len || d->object_header) {
            goto malformed;
        }
        if (d->has_object && st->kind == XQC_MOQT_STREAM_SUBGROUP) {
            xqc_moqt_object_t last = d->object;
            last.end_of_group = !!(d->flags & XQC_MOQT_SUBGROUP_END_GROUP);
            if (xqc_moqt_subgroup_apply(st, &last, 1) != XQC_OK) {
                xqc_moqt_object_dispatch(s, d->track, d->track_alias, d->flags,
                                         &last, st, 1, 0);
                xqc_moqt_stream_cancel(st, XQC_MOQT_RESET_MALFORMED_TRACK);
                return XQC_OK;
            }
        }
        st->rx_fin = 1;
        xqc_moqt_subgroup_notify(st);
    }
    st->deadline = !st->discarded && rx->data_len
        ? xqc_monotonic_timestamp() + s->config.timeout : 0;
    return XQC_OK;
malformed:
    xqc_moqt_session_close(s, XQC_MOQT_PROTOCOL_VIOLATION);
    return -XQC_EILLEGAL_FRAME;
}

xqc_bool_t
xqc_moqt_stream_end_of_group(const xqc_moqt_stream_t *st)
{
    return st != NULL && st->kind == XQC_MOQT_STREAM_SUBGROUP
           && (st->state.data.flags & XQC_MOQT_SUBGROUP_END_GROUP);
}

xqc_usec_t
xqc_moqt_stream_object_received_at(const xqc_moqt_stream_t *st)
{
    if (st == NULL
        || (st->kind != XQC_MOQT_STREAM_SUBGROUP
            && st->kind != XQC_MOQT_STREAM_FETCH))
    {
        return 0;
    }
    return st->state.data.object_time;
}

xqc_moqt_stream_t *
xqc_moqt_subgroup_open(xqc_moqt_subscription_t *sub, uint64_t group_id,
    uint64_t subgroup_id, uint8_t priority, xqc_bool_t first_in_subgroup,
    xqc_bool_t end_of_group)
{
    /* Only the established publisher can open a Subgroup stream. */
    if (sub == NULL || !sub->track->local_publisher || !sub->established) {
        return NULL;
    }
    /* Paused or stopped subscriptions cannot start new delivery. */
    if (!sub->forward || sub->stopped) {
        return NULL;
    }
    xqc_moqt_session_t *s = sub->session;
    if (!s->ready || s->closed) {
        return NULL;
    }
    xqc_moqt_object_t o;
    xqc_memzero(&o, sizeof(o));
    o.group_id = group_id;
    o.subgroup_id = subgroup_id;
    o.priority = priority;
    uint64_t flags = XQC_MOQT_SUBGROUP_FIXED_BITS
        | XQC_MOQT_SUBGROUP_PROPERTIES | XQC_MOQT_SUBGROUP_EXPLICIT_ID;
    if (first_in_subgroup) {
        flags |= XQC_MOQT_SUBGROUP_FIRST_OBJECT;
    }
    if (end_of_group) {
        flags |= XQC_MOQT_SUBGROUP_END_GROUP;
    }
    xqc_int_t len = xqc_moqt_subgroup_header_encode(sub->track_alias, flags,
                                                    &o, NULL, 0);
    xqc_var_buf_t *buf = xqc_moqt_buffer_create(s, len, sizeof(*buf));
    if (buf == NULL) {
        return NULL;
    }
    xqc_moqt_subgroup_header_encode(sub->track_alias, flags, &o,
                                    buf->data, len);
    buf->data_len = len;
    xqc_moqt_stream_t *st = xqc_moqt_transport_open(s, XQC_STREAM_UNI);
    if (st == NULL || s->closed) {
        xqc_moqt_buffer_free(s, buf, sizeof(*buf));
        return NULL;
    }
    st->kind = XQC_MOQT_STREAM_SUBGROUP;
    xqc_moqt_data_stream_t *d = &st->state.data;
    d->object = o;
    d->flags = flags;
    d->track_alias = sub->track_alias;
    d->track = sub->track;
    d->track->references++;
    d->subscription = sub;
    d->prefix_length = len;
    if (sub->stream_count != UINT64_MAX) {
        sub->stream_count++;
    }
    if (xqc_moqt_queue(s, &st->tx, buf) != XQC_OK) {
        xqc_moqt_buffer_free(s, buf, sizeof(*buf));
        xqc_moqt_stream_cancel(st, XQC_MOQT_RESET_EXCESSIVE_LOAD);
        return NULL;
    }
    /* Keep the header queued until an object/FIN supplies a data candidate. */
    return st;
}

xqc_int_t
xqc_moqt_stream_send_object(xqc_moqt_stream_t *st, const xqc_moqt_object_t *o)
{
    /* Object fragments require an Object view and a Subgroup stream. */
    if (st == NULL
        || o == NULL
        || (st->kind != XQC_MOQT_STREAM_SUBGROUP
            && st->kind != XQC_MOQT_STREAM_FETCH))
    {
        return -XQC_EPARAM;
    }
    /* Closing or finishing the stream prevents any further submissions. */
    if (st->session->closed
        || st->discarded
        || st->tx_fin
        || st->state.data.reset_pending)
    {
        return -XQC_EPARAM;
    }
    xqc_moqt_data_stream_t *d = &st->state.data;
    xqc_moqt_location_t location = {o->group_id, o->object_id};
    if (d->finish_time) {
        return -XQC_EPARAM;
    }
    if (st->kind == XQC_MOQT_STREAM_FETCH) {
        if (xqc_moqt_fetch_contains(d->fetch, o) != XQC_OK
            || !d->track->local_publisher)
        {
            return -XQC_EPARAM;
        }
    } else {
        /* The subscription must still accept this Object location. */
        if (d->subscription == NULL
            || !xqc_moqt_subscription_is_matching(d->subscription, &location))
        {
            return -XQC_EPARAM;
        }
        /* Delivery mode and Subgroup identity stay fixed on live streams. */
        if (o->datagram
            || o->group_id != d->object.group_id
            || o->subgroup_id != d->object.subgroup_id
            || o->priority != d->object.priority)
        {
            return -XQC_EPARAM;
        }
    }
    /* Check the offset before subtracting it to bound the fragment length. */
    if (o->payload_offset > o->payload_length
        || o->payload.iov_len > o->payload_length - o->payload_offset)
    {
        return -XQC_EPARAM;
    }
    /* Non-empty payload requires actual bytes and a fragment that advances. */
    if ((o->payload.iov_len
            && o->payload.iov_base == NULL)
        || (o->payload_length
            && !o->payload.iov_len))
    {
        return -XQC_EPARAM;
    }
    /* The stream's END_OF_GROUP flag takes effect only with FIN. */
    if (o->end_of_group) {
        return -XQC_EPARAM;
    }
    xqc_usec_t submitted = xqc_monotonic_timestamp();
    xqc_int_t continuation = d->has_object
        && d->object.payload_offset != d->object.payload_length;
    xqc_int_t header = 0;
    if (continuation) {
        /* Continue the same Object at the next unsubmitted byte offset. */
        if (o->object_id != d->object.object_id
            || o->status != d->object.status
            || o->payload_length != d->object.payload_length
            || o->payload_offset != d->object.payload_offset)
        {
            return -XQC_EPARAM;
        }
        /* A fragment cannot change the FETCH record's identity or mode. */
        if (o->group_id != d->object.group_id
            || o->subgroup_id != d->object.subgroup_id
            || o->datagram != d->object.datagram
            || o->range != d->object.range)
        {
            return -XQC_EPARAM;
        }
        /* Priority belongs to the Object, not its individual fragments. */
        if (o->priority != d->object.priority) {
            return -XQC_EPARAM;
        }
        /* Properties are sent once; FIRST_OBJECT cannot change mid-Object. */
        if (o->properties.iov_len
            || o->first_in_subgroup != d->object.first_in_subgroup)
        {
            return -XQC_EPARAM;
        }
    } else {
        if (o->payload_offset
            || o->first_in_subgroup
            != (!d->has_object
                && !!(d->flags & XQC_MOQT_SUBGROUP_FIRST_OBJECT)))
        {
            return -XQC_EPARAM;
        }
        header = st->kind == XQC_MOQT_STREAM_FETCH
            ? xqc_moqt_fetch_header_encode(d->fetch->info.group_order,
                &d->history, o, NULL, 0)
            : xqc_moqt_object_header_encode(d->flags,
                d->has_object ? &d->object : NULL, o, NULL, 0);
        if (header < 0) {
            return header;
        }
        if (xqc_moqt_object_is_obsolete(
            d->track,
            xqc_moqt_group_find(d->track, o->group_id), o))
        {
            return -XQC_EPARAM;
        }
    }
    xqc_moqt_session_t *s = st->session;
    size_t available = s->config.max_buffered_bytes - s->buffered_bytes;
    if ((size_t)header + XQC_MOQT_TX_OVERHEAD > available
        || o->payload.iov_len > available - header - XQC_MOQT_TX_OVERHEAD)
    {
        d->blocked = 1;
        return -XQC_EAGAIN;
    }
    size_t len = header + o->payload.iov_len;
    xqc_var_buf_t *buf = xqc_moqt_buffer_create(s, len, sizeof(*buf));
    if (buf == NULL) {
        return -XQC_EMALLOC;
    }
    if (header) {
        if (st->kind == XQC_MOQT_STREAM_FETCH) {
            xqc_moqt_fetch_header_encode(d->fetch->info.group_order,
                &d->history, o, buf->data, header);
        } else {
            xqc_moqt_object_header_encode(d->flags,
                d->has_object ? &d->object : NULL, o, buf->data, header);
        }
    }
    if (o->payload.iov_len) {
        xqc_memcpy(buf->data + header, o->payload.iov_base, o->payload.iov_len);
    }
    buf->data_len = len;
    if (xqc_moqt_queue(s, &st->tx, buf) != XQC_OK) {
        xqc_moqt_buffer_free(s, buf, sizeof(*buf));
        return -XQC_EMALLOC;
    }
    if (!continuation) {
        xqc_int_t ret = st->kind == XQC_MOQT_STREAM_FETCH
            ? xqc_moqt_fetch_object_apply(st, o)
            : xqc_moqt_subgroup_apply(st, o, 0);
        if (ret != XQC_OK) {
            xqc_moqt_dequeue(s, xqc_list_entry(st->tx.prev,
                                               xqc_list_buf_t, list_head));
            return ret;
        }
    }
    if (!continuation) {
        if (st->kind == XQC_MOQT_STREAM_FETCH) {
            xqc_moqt_fetch_history_update(&d->history, o);
        }
        d->object_time = submitted;
    }
    xqc_list_buf_t *entry = xqc_list_entry(st->tx.prev,
                                           xqc_list_buf_t, list_head);
    entry->timestamp = d->object_time;
    d->object = *o;
    d->object.payload_offset += o->payload.iov_len;
    xqc_memzero(&d->object.properties, sizeof(d->object.properties));
    xqc_memzero(&d->object.payload, sizeof(d->object.payload));
    d->has_object = 1;
    return xqc_moqt_stream_flush(st);
}

xqc_int_t
xqc_moqt_stream_finish(xqc_moqt_stream_t *st)
{
    /* This finish operation applies only to Subgroup streams. */
    if (st == NULL
        || (st->kind != XQC_MOQT_STREAM_SUBGROUP
            && st->kind != XQC_MOQT_STREAM_FETCH))
    {
        return -XQC_EPARAM;
    }
    /* FIN can be submitted only once, before stream or session closure. */
    if (st->session->closed
        || st->discarded
        || st->tx_fin
        || st->state.data.reset_pending)
    {
        return -XQC_EPARAM;
    }
    xqc_moqt_data_stream_t *d = &st->state.data;
    if ((d->subscription == NULL
            && d->fetch == NULL)
        || !d->track->local_publisher
        || d->object.payload_offset != d->object.payload_length)
    {
        return -XQC_EPARAM;
    }
    xqc_moqt_session_t *s = st->session;
    /* Section 5.2: first application notification starts the ACK deadline. */
    if (!d->finish_time) {
        d->finish_time = xqc_monotonic_timestamp();
        xqc_moqt_timer_update(s);
    }
    xqc_var_buf_t *buf = xqc_moqt_buffer_create(s, 0, sizeof(*buf));
    if (buf == NULL) {
        d->blocked = 1;
        return -XQC_EAGAIN;
    }
    buf->fin_flag = 1;
    if (xqc_moqt_queue(s, &st->tx, buf) != XQC_OK) {
        xqc_moqt_buffer_free(s, buf, sizeof(*buf));
        return -XQC_EMALLOC;
    }
    if (d->has_object && st->kind == XQC_MOQT_STREAM_SUBGROUP) {
        xqc_moqt_object_t last = d->object;
        last.end_of_group = !!(d->flags & XQC_MOQT_SUBGROUP_END_GROUP);
        xqc_int_t ret = xqc_moqt_subgroup_apply(st, &last, 1);
        if (ret != XQC_OK) {
            xqc_moqt_dequeue(s, xqc_list_entry(st->tx.prev,
                                               xqc_list_buf_t, list_head));
            return ret;
        }
    }
    st->tx_fin = 1;
    return xqc_moqt_stream_flush(st);
}
