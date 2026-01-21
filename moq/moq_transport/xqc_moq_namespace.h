#ifndef _XQC_MOQ_NAMESPACE_H_INCLUDED_
#define _XQC_MOQ_NAMESPACE_H_INCLUDED_

#include "src/common/xqc_list.h"
#include "moq/xqc_moq.h"

typedef struct xqc_moq_namespace_prefix_s {
    xqc_list_head_t              list_member;
    uint64_t                     prefix_num;
    xqc_moq_track_ns_field_t     *prefix_tuple;
    /* Namespaces currently advertised for this active prefix subscription. */
    xqc_list_head_t              advertised_namespace_list;
} xqc_moq_namespace_prefix_t;

typedef struct xqc_moq_namespace_advertisement_s {
    xqc_list_head_t              list_member;
    uint64_t                     track_namespace_num;
    xqc_moq_track_ns_field_t     *track_namespace_tuple;
    uint64_t                     track_refcnt;
    /*
     * Tracks that have been counted (refcnt++) for this namespace advertisement.
     * Used to make refresh/on_track_added idempotent and to avoid refcnt drift.
     */
    xqc_list_head_t              advertised_track_list;
} xqc_moq_namespace_advertisement_t;

typedef struct xqc_moq_advertised_track_s {
    xqc_list_head_t              list_member;
    xqc_moq_track_t              *track;
} xqc_moq_advertised_track_t;

xqc_int_t xqc_moq_namespace_tuple_equal(const xqc_moq_track_ns_field_t *a, uint64_t na,
    const xqc_moq_track_ns_field_t *b, uint64_t nb);

xqc_int_t xqc_moq_namespace_tuple_is_prefix(const xqc_moq_track_ns_field_t *a, uint64_t na,
    const xqc_moq_track_ns_field_t *b, uint64_t nb);

xqc_int_t xqc_moq_namespace_tuple_overlaps(const xqc_moq_track_ns_field_t *a, uint64_t na,
    const xqc_moq_track_ns_field_t *b, uint64_t nb);

xqc_moq_track_ns_field_t *xqc_moq_namespace_tuple_copy(const xqc_moq_track_ns_field_t *src, uint64_t num);

void xqc_moq_namespace_tuple_free(xqc_moq_track_ns_field_t *tuple, uint64_t num);

xqc_moq_namespace_prefix_t *xqc_moq_namespace_prefix_create_copy(
    const xqc_moq_track_ns_field_t *prefix_tuple, uint64_t prefix_num);

void xqc_moq_namespace_prefix_destroy(xqc_moq_namespace_prefix_t *prefix);

xqc_moq_namespace_advertisement_t *xqc_moq_namespace_advertisement_create_copy(
    const xqc_moq_track_ns_field_t *track_namespace_tuple, uint64_t track_namespace_num);

void xqc_moq_namespace_advertisement_destroy(xqc_moq_namespace_advertisement_t *namespace_advertisement);

#endif /* _XQC_MOQ_NAMESPACE_H_INCLUDED_ */
