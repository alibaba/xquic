#include <string.h>

#include "src/common/xqc_malloc.h"
#include "moq/moq_transport/xqc_moq_namespace.h"

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
    if (a == NULL || b == NULL || na == 0 || nb == 0) {
        return 0;
    }
    if (na != nb) {
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
    if (a == NULL || b == NULL || na == 0 || nb == 0 || na > nb) {
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
xqc_moq_namespace_tuple_overlaps(const xqc_moq_track_ns_field_t *a, uint64_t na,
    const xqc_moq_track_ns_field_t *b, uint64_t nb)
{
    return xqc_moq_namespace_tuple_is_prefix(a, na, b, nb)
        || xqc_moq_namespace_tuple_is_prefix(b, nb, a, na);
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
    if (prefix_tuple == NULL || prefix_num == 0) {
        return NULL;
    }

    xqc_moq_namespace_prefix_t *namespace_prefix = xqc_calloc(1, sizeof(*namespace_prefix));
    if (namespace_prefix == NULL) {
        return NULL;
    }
    xqc_init_list_head(&namespace_prefix->list_member);
    xqc_init_list_head(&namespace_prefix->advertised_namespace_list);
    namespace_prefix->prefix_num = prefix_num;
    namespace_prefix->prefix_tuple = xqc_moq_namespace_tuple_copy(prefix_tuple, prefix_num);
    if (namespace_prefix->prefix_tuple == NULL) {
        xqc_free(namespace_prefix);
        return NULL;
    }
    return namespace_prefix;
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
