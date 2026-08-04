#include <string.h>

#include "src/common/xqc_malloc.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "moq/moq_transport/xqc_moq_message.h"
#include "moq/moq_transport/xqc_moq_namespace.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_stream.h"

static xqc_int_t
xqc_moq_namespace_tuple_field_equal(const xqc_moq_track_ns_field_t *a, const xqc_moq_track_ns_field_t *b)
{
    if (a == NULL || b == NULL) {
        return 0;
    }
    if (a->len != b->len) {
        return 0;
    }
    if (a->len == 0) {
        return 1;
    }
    if (a->data == NULL || b->data == NULL) {
        return 0;
    }
    return memcmp(a->data, b->data, a->len) == 0;
}

xqc_int_t
xqc_moq_namespace_tuple_equal(const xqc_moq_track_ns_field_t *a, uint64_t na,
    const xqc_moq_track_ns_field_t *b, uint64_t nb)
{
    if (na != nb) {
        return 0;
    }
    if (na == 0) {
        return 1;
    }
    if (a == NULL || b == NULL) {
        return 0;
    }
    for (uint64_t i = 0; i < na; i++) {
        if (!xqc_moq_namespace_tuple_field_equal(&a[i], &b[i])) {
            return 0;
        }
    }
    return 1;
}

xqc_int_t
xqc_moq_namespace_tuple_is_prefix(const xqc_moq_track_ns_field_t *a, uint64_t na,
    const xqc_moq_track_ns_field_t *b, uint64_t nb)
{
    if (na > nb || (na > 0 && a == NULL) || (nb > 0 && b == NULL)) {
        return 0;
    }
    if (na == 0) {
        return 1;
    }
    for (uint64_t i = 0; i < na; i++) {
        if (!xqc_moq_namespace_tuple_field_equal(&a[i], &b[i])) {
            return 0;
        }
    }
    return 1;
}

xqc_int_t
xqc_moq_namespace_tuple_overlaps(const xqc_moq_track_ns_field_t *a, uint64_t na,
    const xqc_moq_track_ns_field_t *b, uint64_t nb)
{
    return xqc_moq_namespace_tuple_is_prefix(a, na, b, nb)
        || xqc_moq_namespace_tuple_is_prefix(b, nb, a, na);
}

xqc_int_t
xqc_moq_namespace_update_overlaps(
    xqc_moq_session_t *session, xqc_moq_stream_t *stream,
    const xqc_moq_namespace_prefix_t *candidate)
{
    if (session == NULL || stream == NULL || candidate == NULL) {
        return 0;
    }

    if (stream->request_type == XQC_MOQ_MSG_SUBSCRIBE_TRACKS) {
        xqc_list_head_t *pos;
        xqc_list_for_each(pos, &session->peer_request_stream_list) {
            xqc_moq_stream_t *other =
                xqc_list_entry(pos, xqc_moq_stream_t,
                               request_list_member);
            if (other == stream || !other->peer_request
                || other->request_type != XQC_MOQ_MSG_SUBSCRIBE_TRACKS
                || !other->subscribe_tracks_active
                || other->tracks_subscription == NULL)
            {
                continue;
            }
            if (xqc_moq_namespace_tuple_overlaps(
                    candidate->prefix_tuple, candidate->prefix_num,
                    other->tracks_subscription->prefix_tuple,
                    other->tracks_subscription->prefix_num))
            {
                return 1;
            }
        }
        return 0;
    }

    if (stream->request_type == XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE) {
        xqc_list_head_t *lists[] = {
            &session->peer_subscribe_namespace_list,
            &session->peer_ns_pending_inbound_list,
        };
        for (size_t i = 0; i < sizeof(lists) / sizeof(lists[0]); i++) {
            xqc_list_head_t *pos;
            xqc_list_for_each(pos, lists[i]) {
                xqc_moq_namespace_prefix_t *other =
                    xqc_list_entry(pos, xqc_moq_namespace_prefix_t,
                                   list_member);
                if (other->request_id == stream->request_id) {
                    continue;
                }
                if (xqc_moq_namespace_tuple_overlaps(
                        candidate->prefix_tuple,
                        candidate->prefix_num,
                        other->prefix_tuple, other->prefix_num))
                {
                    return 1;
                }
            }
        }
    }
    return 0;
}

xqc_moq_track_ns_field_t *
xqc_moq_namespace_tuple_copy(const xqc_moq_track_ns_field_t *src, uint64_t num)
{
    if (src == NULL || num == 0) {
        return NULL;
    }

    xqc_moq_track_ns_field_t *dst = xqc_calloc(num, sizeof(xqc_moq_track_ns_field_t));
    if (dst == NULL) {
        return NULL;
    }
    for (uint64_t i = 0; i < num; i++) {
        dst[i].len = src[i].len;
        if (src[i].len > 0 && src[i].data != NULL) {
            dst[i].data = xqc_calloc(1, src[i].len + 1);
            if (dst[i].data == NULL) {
                xqc_moq_namespace_tuple_free(dst, num);
                return NULL;
            }
            memcpy(dst[i].data, src[i].data, src[i].len);
        }
    }
    return dst;
}

xqc_moq_track_ns_field_t *
xqc_moq_namespace_tuple_concat(
    const xqc_moq_track_ns_field_t *prefix, uint64_t prefix_num,
    const xqc_moq_track_ns_field_t *suffix, uint64_t suffix_num)
{
    if ((prefix_num > 0 && prefix == NULL)
        || (suffix_num > 0 && suffix == NULL)
        || prefix_num > UINT64_MAX - suffix_num
        || prefix_num + suffix_num == 0)
    {
        return NULL;
    }

    uint64_t total_num = prefix_num + suffix_num;
    xqc_moq_track_ns_field_t *joined =
        xqc_calloc(total_num, sizeof(*joined));
    if (joined == NULL) {
        return NULL;
    }

    for (uint64_t i = 0; i < total_num; i++) {
        const xqc_moq_track_ns_field_t *source =
            i < prefix_num ? &prefix[i] : &suffix[i - prefix_num];
        joined[i].len = source->len;
        if (source->len == 0 || source->data == NULL) {
            xqc_moq_namespace_tuple_free(joined, total_num);
            return NULL;
        }
        joined[i].data = xqc_malloc(source->len);
        if (joined[i].data == NULL) {
            xqc_moq_namespace_tuple_free(joined, total_num);
            return NULL;
        }
        memcpy(joined[i].data, source->data, source->len);
    }
    return joined;
}

void
xqc_moq_namespace_tuple_free(xqc_moq_track_ns_field_t *tuple, uint64_t num)
{
    if (tuple == NULL) {
        return;
    }
    for (uint64_t i = 0; i < num; i++) {
        xqc_free(tuple[i].data);
        tuple[i].data = NULL;
        tuple[i].len = 0;
    }
    xqc_free(tuple);
}

xqc_moq_namespace_prefix_t *
xqc_moq_namespace_prefix_create_copy(const xqc_moq_track_ns_field_t *prefix_tuple, uint64_t prefix_num)
{
    if (prefix_num > 0 && prefix_tuple == NULL) {
        return NULL;
    }

    xqc_moq_namespace_prefix_t *namespace_prefix = xqc_calloc(1, sizeof(*namespace_prefix));
    if (namespace_prefix == NULL) {
        return NULL;
    }
    xqc_init_list_head(&namespace_prefix->list_member);
    xqc_init_list_head(&namespace_prefix->advertised_namespace_list);
    namespace_prefix->prefix_num = prefix_num;
    if (prefix_num > 0) {
        namespace_prefix->prefix_tuple =
            xqc_moq_namespace_tuple_copy(prefix_tuple, prefix_num);
        if (namespace_prefix->prefix_tuple == NULL) {
            xqc_free(namespace_prefix);
            return NULL;
        }
    }
    return namespace_prefix;
}

xqc_moq_namespace_prefix_t *
xqc_moq_namespace_prefix_create_serialized(
    const uint8_t *serialized, size_t serialized_len)
{
    if (serialized == NULL || serialized_len == 0) {
        return NULL;
    }

    const uint8_t *pos = serialized;
    const uint8_t *end = serialized + serialized_len;
    uint64_t field_count = 0;
    xqc_int_t ret = xqc_vi64_read(pos, end, &field_count);
    if (ret < 0 || field_count > XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS) {
        return NULL;
    }
    pos += ret;

    xqc_moq_track_ns_field_t *fields = NULL;
    if (field_count > 0) {
        fields = xqc_calloc((size_t)field_count, sizeof(*fields));
        if (fields == NULL) {
            return NULL;
        }
    }
    for (uint64_t i = 0; i < field_count; i++) {
        uint64_t field_len = 0;
        ret = xqc_vi64_read(pos, end, &field_len);
        if (ret < 0) {
            xqc_free(fields);
            return NULL;
        }
        pos += ret;
        if (field_len == 0 || field_len > (uint64_t)(end - pos)) {
            xqc_free(fields);
            return NULL;
        }
        fields[i].len = (size_t)field_len;
        fields[i].data = (unsigned char *)pos;
        pos += field_len;
    }
    if (pos != end) {
        xqc_free(fields);
        return NULL;
    }

    xqc_moq_namespace_prefix_t *prefix =
        xqc_moq_namespace_prefix_create_copy(fields, field_count);
    xqc_free(fields);
    return prefix;
}

void
xqc_moq_namespace_prefix_destroy(xqc_moq_namespace_prefix_t *prefix)
{
    if (prefix == NULL) {
        return;
    }
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &prefix->advertised_namespace_list) {
        xqc_moq_namespace_advertisement_t *namespace_advertisement =
            xqc_list_entry(pos, xqc_moq_namespace_advertisement_t, list_member);
        xqc_list_del(pos);
        xqc_moq_namespace_advertisement_destroy(namespace_advertisement);
    }
    xqc_moq_namespace_tuple_free(prefix->prefix_tuple, prefix->prefix_num);
    prefix->prefix_tuple = NULL;
    prefix->prefix_num = 0;
    xqc_free(prefix);
}

xqc_moq_namespace_advertisement_t *
xqc_moq_namespace_prefix_find_advertised(
    xqc_moq_namespace_prefix_t *prefix,
    const xqc_moq_track_ns_field_t *track_namespace_tuple,
    uint64_t track_namespace_num)
{
    if (prefix == NULL || track_namespace_tuple == NULL
        || track_namespace_num == 0)
    {
        return NULL;
    }

    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &prefix->advertised_namespace_list) {
        xqc_moq_namespace_advertisement_t *advertisement =
            xqc_list_entry(pos, xqc_moq_namespace_advertisement_t,
                           list_member);
        if (xqc_moq_namespace_tuple_equal(
                track_namespace_tuple, track_namespace_num,
                advertisement->track_namespace_tuple,
                advertisement->track_namespace_num))
        {
            return advertisement;
        }
    }
    return NULL;
}

xqc_int_t
xqc_moq_namespace_prefix_add_advertised(
    xqc_moq_namespace_prefix_t *prefix,
    const xqc_moq_track_ns_field_t *track_namespace_tuple,
    uint64_t track_namespace_num)
{
    if (prefix == NULL || track_namespace_tuple == NULL
        || track_namespace_num == 0)
    {
        return -XQC_EPARAM;
    }
    if (xqc_moq_namespace_prefix_find_advertised(
            prefix, track_namespace_tuple, track_namespace_num) != NULL)
    {
        return XQC_OK;
    }

    xqc_moq_namespace_advertisement_t *advertisement =
        xqc_moq_namespace_advertisement_create_copy(
            track_namespace_tuple, track_namespace_num);
    if (advertisement == NULL) {
        return -XQC_EMALLOC;
    }
    xqc_list_add_tail(&advertisement->list_member,
                      &prefix->advertised_namespace_list);
    return XQC_OK;
}

xqc_int_t
xqc_moq_namespace_prefix_remove_advertised(
    xqc_moq_namespace_prefix_t *prefix,
    const xqc_moq_track_ns_field_t *track_namespace_tuple,
    uint64_t track_namespace_num)
{
    xqc_moq_namespace_advertisement_t *advertisement =
        xqc_moq_namespace_prefix_find_advertised(
            prefix, track_namespace_tuple, track_namespace_num);
    if (advertisement == NULL) {
        return 0;
    }
    xqc_list_del_init(&advertisement->list_member);
    xqc_moq_namespace_advertisement_destroy(advertisement);
    return 1;
}

xqc_moq_namespace_advertisement_t *
xqc_moq_namespace_advertisement_create_copy(const xqc_moq_track_ns_field_t *track_namespace_tuple,
    uint64_t track_namespace_num)
{
    if (track_namespace_tuple == NULL || track_namespace_num == 0) {
        return NULL;
    }

    xqc_moq_namespace_advertisement_t *namespace_advertisement =
        xqc_calloc(1, sizeof(*namespace_advertisement));
    if (namespace_advertisement == NULL) {
        return NULL;
    }
    xqc_init_list_head(&namespace_advertisement->list_member);
    xqc_init_list_head(&namespace_advertisement->advertised_track_list);
    namespace_advertisement->request_id = XQC_MOQ_INVALID_ID;
    namespace_advertisement->track_namespace_num = track_namespace_num;
    namespace_advertisement->track_namespace_tuple =
        xqc_moq_namespace_tuple_copy(track_namespace_tuple, track_namespace_num);
    if (namespace_advertisement->track_namespace_tuple == NULL) {
        xqc_free(namespace_advertisement);
        return NULL;
    }
    namespace_advertisement->track_refcnt = 0;
    return namespace_advertisement;
}

void
xqc_moq_namespace_advertisement_destroy(xqc_moq_namespace_advertisement_t *namespace_advertisement)
{
    if (namespace_advertisement == NULL) {
        return;
    }

    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &namespace_advertisement->advertised_track_list) {
        xqc_moq_advertised_track_t *advertised_track =
            xqc_list_entry(pos, xqc_moq_advertised_track_t, list_member);
        xqc_list_del(pos);
        xqc_free(advertised_track);
    }
    xqc_moq_namespace_tuple_free(namespace_advertisement->track_namespace_tuple,
                                 namespace_advertisement->track_namespace_num);
    namespace_advertisement->track_namespace_tuple = NULL;
    namespace_advertisement->track_namespace_num = 0;
    namespace_advertisement->track_refcnt = 0;
    xqc_free(namespace_advertisement);
}

xqc_moq_track_ns_field_t *
xqc_moq_namespace_tuple_from_string(const char *ns, size_t len)
{
    if (ns == NULL) {
        return NULL;
    }
    if (len == 0) {
        len = strlen(ns);
    }
    xqc_moq_track_ns_field_t *tuple = xqc_calloc(1, sizeof(xqc_moq_track_ns_field_t));
    if (tuple == NULL) {
        return NULL;
    }
    tuple[0].len = len;
    tuple[0].data = xqc_calloc(1, len + 1);
    if (tuple[0].data == NULL) {
        xqc_free(tuple);
        return NULL;
    }
    memcpy(tuple[0].data, ns, len);
    return tuple;
}

char *
xqc_moq_namespace_tuple_join(const xqc_moq_track_ns_field_t *tuple, uint64_t num)
{
    if (tuple == NULL || num == 0) {
        return NULL;
    }
    size_t total = 0;
    for (uint64_t i = 0; i < num; i++) {
        total += tuple[i].len;
        if (i > 0) {
            total += 1;
        }
    }
    char *result = xqc_calloc(1, total + 1);
    if (result == NULL) {
        return NULL;
    }
    size_t offset = 0;
    for (uint64_t i = 0; i < num; i++) {
        if (i > 0) {
            result[offset++] = '/';
        }
        if (tuple[i].len > 0 && tuple[i].data != NULL) {
            memcpy(result + offset, tuple[i].data, tuple[i].len);
            offset += tuple[i].len;
        }
    }
    return result;
}
