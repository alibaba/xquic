/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */

#ifndef _XQC_MOQT_CODEC_H_INCLUDED_
#define _XQC_MOQT_CODEC_H_INCLUDED_

#include <moq/xqc_moqt.h>

#define XQC_MOQT_MICROS_PER_MILLISECOND 1000

/* Track properties shared by endpoints and relays (sections 10.3/10.7). */
#define XQC_MOQT_PROPERTY_MAX_CACHE_DURATION 0x04
#define XQC_MOQT_PROPERTY_IMMUTABLE 0x0b

xqc_int_t xqc_moqt_is_initial_request(uint64_t type);
xqc_int_t xqc_moqt_is_namespace_request(uint64_t type);
xqc_int_t xqc_moqt_fill_parameters_decode(
    const xqc_moq_message_parameter_t *parameter, xqc_moqt_message_t *message);
uint64_t xqc_moqt_error_normalize(xqc_moqt_error_context_t context,
    uint64_t code);

/*
 * Return bytes written/consumed, or a negative XQC error. Encoders accept
 * (NULL, 0) for sizing; inputs must not overlap output except as noted below.
 * Short output returns -XQC_ENOBUF, incomplete input -XQC_EAGAIN, malformed
 * input -XQC_EILLEGAL_FRAME, invalid local arguments -XQC_EPARAM.
 * Failure leaves outputs unchanged. Decoded views borrow input storage.
 */

/*
 * Framing only; the handler validates and exhausts the body. frame_encode also
 * accepts a body already placed at buf + encoded header length (in-place).
 */
xqc_int_t xqc_moqt_frame_encode(const xqc_moqt_message_t *msg, uint8_t *buf,
    size_t cap);
xqc_int_t xqc_moqt_frame_decode(const uint8_t *buf, size_t len,
    xqc_moqt_message_t *msg);

/* A NULL name selects namespace-only encoding/decoding. */
xqc_int_t xqc_moqt_name_encode(const xqc_moqt_namespace_t *ns,
    const struct iovec *name, uint8_t *buf, size_t cap);
xqc_int_t xqc_moqt_name_decode(const uint8_t *buf, size_t len,
    xqc_moqt_namespace_t *ns, struct iovec *name);

/* Inputs must be valid namespace views; matching is by complete fields. */
xqc_int_t xqc_moqt_namespace_prefix(const xqc_moqt_namespace_t *prefix,
    const xqc_moqt_namespace_t *ns);

/*
 * Section 8.3 KVP, not section 9.20 Message Parameters. Caller bounds the
 * sequence, supplies the previous type (initially 0), and checks context-
 * specific duplicates/known values. An odd type carries bytes, even a vi64.
 */
xqc_int_t xqc_moqt_kv_encode(const xqc_moqt_kv_t *kv, uint64_t previous_type,
    uint8_t *buf, size_t cap);
xqc_int_t xqc_moqt_kv_decode(const uint8_t *buf, size_t len,
    uint64_t previous_type, xqc_moqt_kv_t *kv);

#define XQC_MOQT_DATAGRAM_PROPERTIES       0x01u
#define XQC_MOQT_DATAGRAM_END_GROUP        0x02u
#define XQC_MOQT_DATAGRAM_ZERO_OBJECT      0x04u
#define XQC_MOQT_DATAGRAM_DEFAULT_PRIORITY 0x08u
#define XQC_MOQT_DATAGRAM_STATUS           0x20u
#define XQC_MOQT_DATAGRAM_FLAGS            0x2fu
#define XQC_MOQT_PADDING_DATAGRAM          0x132b3e29

#define XQC_MOQT_SUBGROUP_PROPERTIES       0x01u
#define XQC_MOQT_SUBGROUP_FIRST_ID         0x02u
#define XQC_MOQT_SUBGROUP_EXPLICIT_ID      0x04u
#define XQC_MOQT_SUBGROUP_MODE_MASK        0x06u
#define XQC_MOQT_SUBGROUP_END_GROUP        0x08u
#define XQC_MOQT_SUBGROUP_FIXED_BITS       0x10u
#define XQC_MOQT_SUBGROUP_DEFAULT_PRIORITY 0x20u
#define XQC_MOQT_SUBGROUP_FIRST_OBJECT     0x40u
#define XQC_MOQT_SUBGROUP_TYPE_MAX         0x7fu
#define XQC_MOQT_SUBGROUP_FIXED_MASK       0x90u

/* Section 11.3: headers only; payload is consumed incrementally by Stream. */
xqc_int_t xqc_moqt_subgroup_header_decode(const uint8_t *buf, size_t len,
    uint64_t *alias, uint64_t *flags, xqc_moqt_object_t *object);
xqc_int_t xqc_moqt_subgroup_header_encode(uint64_t alias, uint64_t flags,
    const xqc_moqt_object_t *object, uint8_t *buf, size_t cap);
xqc_int_t xqc_moqt_object_header_decode(const uint8_t *buf, size_t len,
    uint64_t flags, const xqc_moqt_object_t *previous,
    xqc_moqt_object_t *object);
xqc_int_t xqc_moqt_object_header_encode(uint64_t flags,
    const xqc_moqt_object_t *previous, const xqc_moqt_object_t *object,
    uint8_t *buf, size_t cap);

/*
 * Whole datagrams: malformed/truncated input is -XQC_EILLEGAL_FRAME.
 * Padding succeeds with only flags set. Object properties are checked by
 * the Track handler, since their errors have a different scope.
 */
xqc_int_t xqc_moqt_datagram_decode(const uint8_t *buf, size_t len,
    uint64_t *alias, uint64_t *flags, xqc_moqt_object_t *object);
xqc_int_t xqc_moqt_datagram_encode(uint64_t alias,
    const xqc_moqt_object_t *object, uint8_t *buf, size_t cap);

/* Section 11.4: Range records do not replace actual-object history. */
typedef struct {
    xqc_moqt_location_t    location;
    uint64_t               subgroup_id;
    uint8_t                priority;
    unsigned               has_location:1;
    unsigned               has_subgroup:1;
    unsigned               has_priority:1;
} xqc_moqt_fetch_history_t;

/* Flags and at most one Group, Subgroup and Object ID each. */
#define XQC_MOQT_FETCH_HEADER_FIELDS 4
#define XQC_MOQT_FETCH_SUBGROUP_MASK 0x03u
#define XQC_MOQT_FETCH_SUBGROUP_PREVIOUS 0x01u
#define XQC_MOQT_FETCH_SUBGROUP_NEXT 0x02u
#define XQC_MOQT_FETCH_SUBGROUP_EXPLICIT 0x03u
#define XQC_MOQT_FETCH_OBJECT 0x04u
#define XQC_MOQT_FETCH_GROUP 0x08u
#define XQC_MOQT_FETCH_PRIORITY 0x10u
#define XQC_MOQT_FETCH_PROPERTIES 0x20u
#define XQC_MOQT_FETCH_DATAGRAM 0x40u
#define XQC_MOQT_FETCH_RANGE_MIN 0x80u
#define XQC_MOQT_FETCH_NONEXISTENT 0x8cu
#define XQC_MOQT_FETCH_UNKNOWN 0x10cu
#define XQC_MOQT_FETCH_TIMEOUT 0x20cu

xqc_int_t xqc_moqt_fetch_header_decode(const uint8_t *buf, size_t len,
    uint8_t order, xqc_moqt_fetch_history_t *history,
    xqc_moqt_object_t *object);
xqc_int_t xqc_moqt_fetch_header_encode(uint8_t order,
    const xqc_moqt_fetch_history_t *history, const xqc_moqt_object_t *object,
    uint8_t *buf, size_t cap);
void xqc_moqt_fetch_history_update(xqc_moqt_fetch_history_t *history,
    const xqc_moqt_object_t *object);

#endif /* _XQC_MOQT_CODEC_H_INCLUDED_ */
