/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */

#include "xqc_moqt_codec.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"

#define XQC_MOQT_KV_BYTES_BIT 1u

static xqc_int_t xqc_moqt_message_type_valid(uint64_t type);

static xqc_int_t
xqc_moqt_message_type_valid(uint64_t type)
{
    switch (type) {
    case XQC_MOQT_MSG_SETUP:
    case XQC_MOQT_MSG_GOAWAY:
    case XQC_MOQT_MSG_REQUEST_UPDATE:
    case XQC_MOQT_MSG_REQUEST_OK:
    case XQC_MOQT_MSG_REQUEST_ERROR:
    case XQC_MOQT_MSG_SUBSCRIBE:
    case XQC_MOQT_MSG_SUBSCRIBE_OK:
    case XQC_MOQT_MSG_PUBLISH:
    case XQC_MOQT_MSG_PUBLISH_DONE:
    case XQC_MOQT_MSG_PUBLISH_STATE_NOTIFY:
    case XQC_MOQT_MSG_FETCH:
    case XQC_MOQT_MSG_FETCH_OK:
    case XQC_MOQT_MSG_TRACK_STATUS:
    case XQC_MOQT_MSG_PUBLISH_NAMESPACE:
    case XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE:
    case XQC_MOQT_MSG_NAMESPACE:
    case XQC_MOQT_MSG_NAMESPACE_DONE:
    case XQC_MOQT_MSG_SUBSCRIBE_TRACKS:
    case XQC_MOQT_MSG_PUBLISH_SKIPPED:
        return 1;
    default:
        return 0;
    }
}

xqc_int_t
xqc_moqt_frame_encode(const xqc_moqt_message_t *msg, uint8_t *buf, size_t cap)
{
    if (msg == NULL
        || !xqc_moqt_message_type_valid(msg->type)
        || msg->body.iov_len > XQC_MOQT_MESSAGE_MAX_BODY
        || (msg->body.iov_len
            && msg->body.iov_base == NULL)
        || (buf == NULL
            && cap))
    {
        return -XQC_EPARAM;
    }

    size_t len = xqc_vi64_len(msg->type) + sizeof(uint16_t)
                 + msg->body.iov_len;
    if (buf == NULL) {
        return (xqc_int_t)len;
    }
    if (cap < len) {
        return -XQC_ENOBUF;
    }

    uint8_t *p = buf + xqc_vi64_write(buf, buf + len, msg->type);
    p = xqc_put_uint16be(p, (uint16_t)msg->body.iov_len);
    if (msg->body.iov_len && msg->body.iov_base != p) {
        xqc_memcpy(p, msg->body.iov_base, msg->body.iov_len);
    }
    return (xqc_int_t)len;
}

xqc_int_t
xqc_moqt_frame_decode(const uint8_t *buf, size_t len, xqc_moqt_message_t *msg)
{
    if (msg == NULL || (buf == NULL && len)) {
        return -XQC_EPARAM;
    }
    if (len == 0) {
        return -XQC_EAGAIN;
    }

    uint64_t type;
    xqc_int_t n = xqc_vi64_read(buf, buf + len, &type);
    if (n < 0) {
        return -XQC_EAGAIN;
    }
    /* Section 9: unknown and legacy reserved types cannot be skipped. */
    if (!xqc_moqt_message_type_valid(type)) {
        return -XQC_EILLEGAL_FRAME;
    }
    if (len - n < sizeof(uint16_t)) {
        return -XQC_EAGAIN;
    }

    uint16_t body_len;
    xqc_memcpy(&body_len, buf + n, sizeof(body_len));
    body_len = ntohs(body_len);
    size_t header_len = n + sizeof(body_len);
    if (len - header_len < body_len) {
        return -XQC_EAGAIN;
    }

    msg->type = type;
    msg->body.iov_base = (void *)(buf + header_len);
    msg->body.iov_len = body_len;
    return (xqc_int_t)(header_len + body_len);
}

xqc_int_t
xqc_moqt_name_encode(const xqc_moqt_namespace_t *ns, const struct iovec *name,
    uint8_t *buf, size_t cap)
{
    if (ns == NULL
        || ns->count > XQC_MOQT_NAMESPACE_MAX_FIELDS
        || (buf == NULL
            && cap))
    {
        return -XQC_EPARAM;
    }

    size_t bytes = 0;
    size_t len = xqc_vi64_len(ns->count);
    for (size_t i = 0; i < ns->count; i++) {
        const struct iovec *field = &ns->fields[i];
        if (field->iov_len == 0
            || field->iov_base == NULL
            || field->iov_len > XQC_MOQT_NAME_MAX_LEN - bytes)
        {
            return -XQC_EPARAM;
        }
        bytes += field->iov_len;
        len += xqc_vi64_len(field->iov_len) + field->iov_len;
    }
    if (name != NULL) {
        if ((name->iov_len
                && name->iov_base == NULL)
            || name->iov_len > XQC_MOQT_NAME_MAX_LEN - bytes)
        {
            return -XQC_EPARAM;
        }
        len += xqc_vi64_len(name->iov_len) + name->iov_len;
    }
    if (buf == NULL) {
        return (xqc_int_t)len;
    }
    if (cap < len) {
        return -XQC_ENOBUF;
    }

    uint8_t *p = buf + xqc_vi64_write(buf, buf + len, ns->count);
    for (size_t i = 0; i < ns->count + (name != NULL); i++) {
        const struct iovec *field = i < ns->count ? &ns->fields[i] : name;
        p += xqc_vi64_write(p, buf + len, field->iov_len);
        if (field->iov_len) {
            xqc_memcpy(p, field->iov_base, field->iov_len);
            p += field->iov_len;
        }
    }
    return (xqc_int_t)len;
}

xqc_int_t
xqc_moqt_name_decode(const uint8_t *buf, size_t len, xqc_moqt_namespace_t *ns,
    struct iovec *name)
{
    if (ns == NULL || (buf == NULL && len)) {
        return -XQC_EPARAM;
    }
    if (len == 0) {
        return -XQC_EAGAIN;
    }

    uint64_t count;
    xqc_int_t n = xqc_vi64_read(buf, buf + len, &count);
    if (n < 0) {
        return -XQC_EAGAIN;
    }
    /* Section 8.7 limits count and payload bytes, not the encoded length. */
    if (count > XQC_MOQT_NAMESPACE_MAX_FIELDS) {
        return -XQC_EILLEGAL_FRAME;
    }

    xqc_moqt_namespace_t result = {0};
    struct iovec track_name = {0};
    result.count = (size_t)count;
    size_t pos = (size_t)n;
    size_t bytes = 0;
    for (size_t i = 0; i < result.count + (name != NULL); i++) {
        uint64_t field_len;
        n = xqc_vi64_read(buf + pos, buf + len, &field_len);
        if (n < 0) {
            return -XQC_EAGAIN;
        }
        pos += n;
        if ((i < result.count
                && field_len == 0)
            || field_len > XQC_MOQT_NAME_MAX_LEN - bytes)
        {
            return -XQC_EILLEGAL_FRAME;
        }
        if (field_len > len - pos) {
            return -XQC_EAGAIN;
        }
        struct iovec *field = i < result.count
                             ? &result.fields[i] : &track_name;
        field->iov_base = (void *)(buf + pos);
        field->iov_len = (size_t)field_len;
        bytes += (size_t)field_len;
        pos += (size_t)field_len;
    }
    *ns = result;
    if (name != NULL) {
        *name = track_name;
    }
    return (xqc_int_t)pos;
}

xqc_int_t
xqc_moqt_namespace_prefix(const xqc_moqt_namespace_t *prefix,
    const xqc_moqt_namespace_t *ns)
{
    if (prefix->count > ns->count) {
        return 0;
    }
    for (size_t i = 0; i < prefix->count; i++) {
        if (prefix->fields[i].iov_len != ns->fields[i].iov_len
            || xqc_memcmp(prefix->fields[i].iov_base, ns->fields[i].iov_base,
                          prefix->fields[i].iov_len))
        {
            return 0;
        }
    }
    return 1;
}

xqc_int_t
xqc_moqt_kv_encode(const xqc_moqt_kv_t *kv, uint64_t previous_type,
    uint8_t *buf, size_t cap)
{
    if (kv == NULL || kv->type < previous_type || (buf == NULL && cap)) {
        return -XQC_EPARAM;
    }

    size_t len = xqc_vi64_len(kv->type - previous_type);
    if (kv->type & XQC_MOQT_KV_BYTES_BIT) {
        if (kv->value.bytes.iov_len > XQC_MOQT_KV_MAX_VALUE
            || (kv->value.bytes.iov_len
                && kv->value.bytes.iov_base == NULL))
        {
            return -XQC_EPARAM;
        }
        len += xqc_vi64_len(kv->value.bytes.iov_len)
               + kv->value.bytes.iov_len;

    } else {
        len += xqc_vi64_len(kv->value.integer);
    }
    if (buf == NULL) {
        return (xqc_int_t)len;
    }
    if (cap < len) {
        return -XQC_ENOBUF;
    }

    uint8_t *p = buf + xqc_vi64_write(buf, buf + len, kv->type - previous_type);
    if (kv->type & XQC_MOQT_KV_BYTES_BIT) {
        p += xqc_vi64_write(p, buf + len, kv->value.bytes.iov_len);
        if (kv->value.bytes.iov_len) {
            xqc_memcpy(p, kv->value.bytes.iov_base, kv->value.bytes.iov_len);
        }

    } else {
        xqc_vi64_write(p, buf + len, kv->value.integer);
    }
    return (xqc_int_t)len;
}

xqc_int_t
xqc_moqt_kv_decode(const uint8_t *buf, size_t len, uint64_t previous_type,
    xqc_moqt_kv_t *kv)
{
    if (kv == NULL || (buf == NULL && len)) {
        return -XQC_EPARAM;
    }
    if (len == 0) {
        return -XQC_EAGAIN;
    }

    uint64_t delta, value;
    xqc_int_t n = xqc_vi64_read(buf, buf + len, &delta);
    if (n < 0) {
        return -XQC_EAGAIN;
    }
    if (delta > UINT64_MAX - previous_type) {
        return -XQC_EILLEGAL_FRAME;
    }

    size_t pos = (size_t)n;
    n = xqc_vi64_read(buf + pos, buf + len, &value);
    if (n < 0) {
        return -XQC_EAGAIN;
    }
    pos += n;
    xqc_moqt_kv_t result = {0};
    result.type = previous_type + delta;
    if (result.type & XQC_MOQT_KV_BYTES_BIT) {
        if (value > XQC_MOQT_KV_MAX_VALUE) {
            return -XQC_EILLEGAL_FRAME;
        }
        if (value > len - pos) {
            return -XQC_EAGAIN;
        }
        result.value.bytes.iov_base = (void *)(buf + pos);
        result.value.bytes.iov_len = (size_t)value;
        pos += (size_t)value;

    } else {
        result.value.integer = value;
    }
    *kv = result;
    return (xqc_int_t)pos;
}

/* Draft-22 section 11.2.1: flags are vi64, including non-minimal encodings. */
xqc_int_t
xqc_moqt_datagram_decode(const uint8_t *buf, size_t len, uint64_t *alias,
    uint64_t *flags, xqc_moqt_object_t *object)
{
    if (alias == NULL || flags == NULL || object == NULL) {
        return -XQC_EPARAM;
    }
    if (buf == NULL || len == 0 || len > INT32_MAX) {
        return -XQC_EILLEGAL_FRAME;
    }
    const uint8_t *p = buf, *end = p + len;
    uint64_t type, track_alias;
    xqc_int_t n = xqc_vi64_read(p, end, &type);
    if (n < 0) {
        return -XQC_EILLEGAL_FRAME;
    }
    p += n;
    if (type == XQC_MOQT_PADDING_DATAGRAM) {
        *flags = type;
        return (xqc_int_t)len;
    }
    if ((type & ~XQC_MOQT_DATAGRAM_FLAGS)
        || ((type & XQC_MOQT_DATAGRAM_STATUS)
            && (type & XQC_MOQT_DATAGRAM_END_GROUP)))
    {
        return -XQC_EILLEGAL_FRAME;
    }
    xqc_moqt_object_t o;
    xqc_memzero(&o, sizeof(o));
    uint64_t *fields[] = {&track_alias, &o.group_id, &o.object_id};
    size_t count = sizeof(fields) / sizeof(fields[0]);
    if (type & XQC_MOQT_DATAGRAM_ZERO_OBJECT) {
        count--;
    }
    for (size_t i = 0; i < count; i++) {
        n = xqc_vi64_read(p, end, fields[i]);
        if (n < 0) {
            return -XQC_EILLEGAL_FRAME;
        }
        p += n;
    }
    if (!(type & XQC_MOQT_DATAGRAM_DEFAULT_PRIORITY)) {
        if (p == end) {
            return -XQC_EILLEGAL_FRAME;
        }
        o.priority = *p++;
    }
    if (type & XQC_MOQT_DATAGRAM_PROPERTIES) {
        uint64_t length;
        n = xqc_vi64_read(p, end, &length);
        if (n < 0 || length == 0 || length > (size_t)(end - p - n)) {
            return -XQC_EILLEGAL_FRAME;
        }
        p += n;
        o.properties.iov_base = (void *)p;
        o.properties.iov_len = length;
        p += length;
    }
    if (type & XQC_MOQT_DATAGRAM_STATUS) {
        uint64_t status;
        n = xqc_vi64_read(p, end, &status);
        if (n < 0
            || p + n != end
            || (status != XQC_MOQT_OBJECT_NORMAL
                && status != XQC_MOQT_OBJECT_END_GROUP
                && status != XQC_MOQT_OBJECT_END_TRACK)
            || (status != XQC_MOQT_OBJECT_NORMAL
                && o.properties.iov_len))
        {
            return -XQC_EILLEGAL_FRAME;
        }
        o.status = status;
    } else {
        o.payload.iov_base = (void *)p;
        o.payload.iov_len = end - p;
        o.payload_length = o.payload.iov_len;
    }
    o.datagram = 1;
    o.end_of_group = !!(type & XQC_MOQT_DATAGRAM_END_GROUP);
    *alias = track_alias;
    *flags = type;
    *object = o;
    return (xqc_int_t)len;
}

xqc_int_t
xqc_moqt_datagram_encode(uint64_t alias, const xqc_moqt_object_t *o,
    uint8_t *buf, size_t cap)
{
    if (o == NULL
        || !o->datagram
        || o->payload_offset
        || o->payload_length != o->payload.iov_len
        || (o->payload.iov_len
            && o->payload.iov_base == NULL)
        || (o->properties.iov_len
            && o->properties.iov_base == NULL)
        || o->properties.iov_len > XQC_MOQT_MESSAGE_MAX_BODY
        || (o->status != XQC_MOQT_OBJECT_NORMAL
            && o->status != XQC_MOQT_OBJECT_END_GROUP
            && o->status != XQC_MOQT_OBJECT_END_TRACK)
        || (o->status != XQC_MOQT_OBJECT_NORMAL
            && (o->properties.iov_len
                || o->payload.iov_len
                || o->end_of_group))
        || (buf == NULL
            && cap))
    {
        return -XQC_EPARAM;
    }
    /* Range endpoints belong only to FETCH serialization. */
    if (o->range) {
        return -XQC_EPARAM;
    }
    uint64_t flags = o->properties.iov_len ? XQC_MOQT_DATAGRAM_PROPERTIES : 0;
    if (o->end_of_group) {
        flags |= XQC_MOQT_DATAGRAM_END_GROUP;
    } else if (o->payload.iov_len == 0) {
        flags |= XQC_MOQT_DATAGRAM_STATUS;
    }
    uint64_t fields[] = {flags, alias, o->group_id, o->object_id};
    size_t len = sizeof(o->priority);
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        len += xqc_vi64_len(fields[i]);
    }
    if (o->properties.iov_len) {
        len += xqc_vi64_len(o->properties.iov_len) + o->properties.iov_len;
    }
    if (flags & XQC_MOQT_DATAGRAM_STATUS) {
        len += xqc_vi64_len(o->status);
    }
    if (o->payload.iov_len > INT32_MAX - len) {
        return -XQC_ELIMIT;
    }
    len += o->payload.iov_len;
    if (buf == NULL) {
        return (xqc_int_t)len;
    }
    if (cap < len) {
        return -XQC_ENOBUF;
    }
    uint8_t *p = buf, *end = buf + len;
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        p += xqc_vi64_write(p, end, fields[i]);
    }
    *p++ = o->priority;
    if (o->properties.iov_len) {
        p += xqc_vi64_write(p, end, o->properties.iov_len);
        xqc_memcpy(p, o->properties.iov_base, o->properties.iov_len);
        p += o->properties.iov_len;
    }
    if (flags & XQC_MOQT_DATAGRAM_STATUS) {
        xqc_vi64_write(p, end, o->status);
    } else if (o->payload.iov_len) {
        xqc_memcpy(p, o->payload.iov_base, o->payload.iov_len);
    }
    return (xqc_int_t)len;
}

xqc_int_t
xqc_moqt_subgroup_header_decode(const uint8_t *buf, size_t len,
    uint64_t *alias, uint64_t *flags, xqc_moqt_object_t *object)
{
    if (len == 0) {
        return -XQC_EAGAIN;
    }
    const uint8_t *p = buf, *end = p + len;
    uint64_t type, track_alias;
    xqc_int_t n = xqc_vi64_read(p, end, &type);
    if (n < 0) {
        return -XQC_EAGAIN;
    }
    if (type > XQC_MOQT_SUBGROUP_TYPE_MAX
        || (type & XQC_MOQT_SUBGROUP_FIXED_MASK) != XQC_MOQT_SUBGROUP_FIXED_BITS
        || (type & XQC_MOQT_SUBGROUP_MODE_MASK) == XQC_MOQT_SUBGROUP_MODE_MASK)
    {
        return -XQC_EILLEGAL_FRAME;
    }
    p += n;
    xqc_moqt_object_t o;
    xqc_memzero(&o, sizeof(o));
    uint64_t *fields[] = {&track_alias, &o.group_id, &o.subgroup_id};
    size_t count = sizeof(fields) / sizeof(fields[0]);
    if (!(type & XQC_MOQT_SUBGROUP_EXPLICIT_ID)) {
        count--;
    }
    for (size_t i = 0; i < count; i++) {
        n = xqc_vi64_read(p, end, fields[i]);
        if (n < 0) {
            return -XQC_EAGAIN;
        }
        p += n;
    }
    if (!(type & XQC_MOQT_SUBGROUP_DEFAULT_PRIORITY)) {
        if (p == end) {
            return -XQC_EAGAIN;
        }
        o.priority = *p++;
    }
    *alias = track_alias;
    *flags = type;
    *object = o;
    return (xqc_int_t)(p - buf);
}

xqc_int_t
xqc_moqt_subgroup_header_encode(uint64_t alias, uint64_t flags,
    const xqc_moqt_object_t *o, uint8_t *buf, size_t cap)
{
    uint64_t fields[] = {flags, alias, o->group_id, o->subgroup_id};
    size_t count = sizeof(fields) / sizeof(fields[0]);
    if (!(flags & XQC_MOQT_SUBGROUP_EXPLICIT_ID)) {
        count--;
    }
    size_t len = !(flags & XQC_MOQT_SUBGROUP_DEFAULT_PRIORITY);
    for (size_t i = 0; i < count; i++) {
        len += xqc_vi64_len(fields[i]);
    }
    if (buf == NULL) {
        return (xqc_int_t)len;
    }
    if (cap < len) {
        return -XQC_ENOBUF;
    }
    uint8_t *p = buf, *end = buf + len;
    for (size_t i = 0; i < count; i++) {
        p += xqc_vi64_write(p, end, fields[i]);
    }
    if (!(flags & XQC_MOQT_SUBGROUP_DEFAULT_PRIORITY)) {
        *p = o->priority;
    }
    return (xqc_int_t)len;
}

xqc_int_t
xqc_moqt_object_header_decode(const uint8_t *buf, size_t len,
    uint64_t flags, const xqc_moqt_object_t *previous,
    xqc_moqt_object_t *object)
{
    if (len == 0) {
        return -XQC_EAGAIN;
    }
    const uint8_t *p = buf, *end = buf + len;
    xqc_moqt_object_t o = *object;
    uint64_t delta, length, status;
    xqc_int_t n = xqc_vi64_read(p, end, &delta);
    if (n < 0) {
        return -XQC_EAGAIN;
    }
    if (previous != NULL && delta >= UINT64_MAX - previous->object_id) {
        return -XQC_EILLEGAL_FRAME;
    }
    o.object_id = previous == NULL ? delta : previous->object_id + delta + 1;
    o.first_in_subgroup = previous == NULL
        && (flags & XQC_MOQT_SUBGROUP_FIRST_OBJECT);
    if (previous == NULL && (flags & XQC_MOQT_SUBGROUP_FIRST_ID)) {
        o.subgroup_id = o.object_id;
    }
    p += n;
    o.properties.iov_base = NULL;
    o.properties.iov_len = 0;
    if (flags & XQC_MOQT_SUBGROUP_PROPERTIES) {
        n = xqc_vi64_read(p, end, &length);
        if (n < 0) {
            return -XQC_EAGAIN;
        }
        if (length > XQC_MOQT_KV_MAX_VALUE) {
            return -XQC_EILLEGAL_FRAME;
        }
        p += n;
        if (length > (size_t)(end - p)) {
            return -XQC_EAGAIN;
        }
        o.properties.iov_base = (void *)p;
        o.properties.iov_len = length;
        p += length;
    }
    n = xqc_vi64_read(p, end, &o.payload_length);
    if (n < 0) {
        return -XQC_EAGAIN;
    }
    p += n;
    o.status = XQC_MOQT_OBJECT_NORMAL;
    if (o.payload_length == 0) {
        n = xqc_vi64_read(p, end, &status);
        if (n < 0) {
            return -XQC_EAGAIN;
        }
        /* Subgroup streams carry Normal, End Group or End Track status. */
        if (status != XQC_MOQT_OBJECT_NORMAL
            && status != XQC_MOQT_OBJECT_END_GROUP
            && status != XQC_MOQT_OBJECT_END_TRACK)
        {
            return -XQC_EILLEGAL_FRAME;
        }
        /* Status-only boundary markers cannot carry Object properties. */
        if (status != XQC_MOQT_OBJECT_NORMAL && o.properties.iov_len) {
            return -XQC_EILLEGAL_FRAME;
        }
        o.status = status;
        p += n;
    }
    o.payload_offset = 0;
    o.payload.iov_base = NULL;
    o.payload.iov_len = 0;
    o.end_of_group = 0;
    *object = o;
    return (xqc_int_t)(p - buf);
}

xqc_int_t
xqc_moqt_object_header_encode(uint64_t flags,
    const xqc_moqt_object_t *previous, const xqc_moqt_object_t *o,
    uint8_t *buf, size_t cap)
{
    /* A Datagram cannot be encoded as a stream Object. */
    if (o->datagram || o->range) {
        return -XQC_EPARAM;
    }
    /* Per-stream delta encoding requires strictly increasing Object IDs. */
    if (previous != NULL && o->object_id <= previous->object_id) {
        return -XQC_EPARAM;
    }
    /* Property bytes must fit the wire limit and have valid storage. */
    if (o->properties.iov_len > XQC_MOQT_KV_MAX_VALUE
        || (o->properties.iov_len
            && o->properties.iov_base == NULL))
    {
        return -XQC_EPARAM;
    }
    /* Properties require the corresponding Subgroup header flag. */
    if (!(flags & XQC_MOQT_SUBGROUP_PROPERTIES) && o->properties.iov_len) {
        return -XQC_EPARAM;
    }
    /* Only the statuses permitted on Subgroup streams can be sent. */
    if (o->status != XQC_MOQT_OBJECT_NORMAL
        && o->status != XQC_MOQT_OBJECT_END_GROUP
        && o->status != XQC_MOQT_OBJECT_END_TRACK)
    {
        return -XQC_EPARAM;
    }
    /* Boundary status markers have neither payload nor properties. */
    if (o->status != XQC_MOQT_OBJECT_NORMAL
        && (o->payload_length
            || o->properties.iov_len))
    {
        return -XQC_EPARAM;
    }
    uint64_t delta = previous == NULL ? o->object_id
        : o->object_id - previous->object_id - 1;
    size_t len = xqc_vi64_len(delta) + xqc_vi64_len(o->payload_length);
    if (flags & XQC_MOQT_SUBGROUP_PROPERTIES) {
        len += xqc_vi64_len(o->properties.iov_len) + o->properties.iov_len;
    }
    if (o->payload_length == 0) {
        len += xqc_vi64_len(o->status);
    }
    if (buf == NULL) {
        return (xqc_int_t)len;
    }
    if (cap < len) {
        return -XQC_ENOBUF;
    }
    uint8_t *p = buf, *end = buf + len;
    p += xqc_vi64_write(p, end, delta);
    if (flags & XQC_MOQT_SUBGROUP_PROPERTIES) {
        p += xqc_vi64_write(p, end, o->properties.iov_len);
        if (o->properties.iov_len) {
            xqc_memcpy(p, o->properties.iov_base, o->properties.iov_len);
            p += o->properties.iov_len;
        }
    }
    p += xqc_vi64_write(p, end, o->payload_length);
    if (o->payload_length == 0) {
        xqc_vi64_write(p, end, o->status);
    }
    return (xqc_int_t)len;
}

void
xqc_moqt_fetch_history_update(xqc_moqt_fetch_history_t *h,
    const xqc_moqt_object_t *o)
{
    h->location.group_id = o->group_id;
    h->location.object_id = o->object_id;
    h->has_location = 1;
    if (!o->range) {
        h->subgroup_id = o->subgroup_id;
        h->has_subgroup = !o->datagram;
        h->priority = o->priority;
        h->has_priority = 1;
    }
}

static xqc_int_t
xqc_moqt_fetch_order_check(uint8_t order,
    const xqc_moqt_fetch_history_t *h, const xqc_moqt_object_t *o)
{
    if (!h->has_location) {
        return XQC_OK;
    }
    if (o->group_id == h->location.group_id) {
        return o->object_id > h->location.object_id ? XQC_OK : XQC_ERROR;
    }
    return (o->group_id > h->location.group_id)
           == (order == XQC_MOQT_GROUP_ASCENDING) ? XQC_OK : XQC_ERROR;
}

xqc_int_t
xqc_moqt_fetch_header_decode(const uint8_t *buf, size_t len, uint8_t order,
    xqc_moqt_fetch_history_t *h, xqc_moqt_object_t *object)
{
    if (!len) {
        return -XQC_EAGAIN;
    }
    const uint8_t *p = buf, *end = buf + len;
    uint64_t flags, delta;
    xqc_int_t n = xqc_vi64_read(p, end, &flags);
    if (n < 0) {
        return -XQC_EAGAIN;
    }
    p += n;
    xqc_moqt_object_t o;
    xqc_memzero(&o, sizeof(o));
    if (flags >= XQC_MOQT_FETCH_RANGE_MIN) {
        switch (flags) {
        case XQC_MOQT_FETCH_NONEXISTENT:
            o.range = XQC_MOQT_RANGE_NONEXISTENT;
            break;
        case XQC_MOQT_FETCH_UNKNOWN:
            o.range = XQC_MOQT_RANGE_UNKNOWN;
            break;
        case XQC_MOQT_FETCH_TIMEOUT:
            o.range = XQC_MOQT_RANGE_TIMEOUT;
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
        }
        /* Section 11.4.1.2: Range endpoints carry absolute locations. */
        n = xqc_vi64_read(p, end, &o.group_id);
        if (n < 0) {
            return -XQC_EAGAIN;
        }
        p += n;
        n = xqc_vi64_read(p, end, &o.object_id);
        if (n < 0) {
            return -XQC_EAGAIN;
        }
        p += n;
    } else {
        /* First record cannot inherit a location that does not exist. */
        if (!h->has_location
            && (flags & (XQC_MOQT_FETCH_GROUP | XQC_MOQT_FETCH_OBJECT))
               != (XQC_MOQT_FETCH_GROUP | XQC_MOQT_FETCH_OBJECT))
        {
            return -XQC_EILLEGAL_FRAME;
        }
        o.group_id = h->location.group_id;
        if (flags & XQC_MOQT_FETCH_GROUP) {
            n = xqc_vi64_read(p, end, &delta);
            if (n < 0) {
                return -XQC_EAGAIN;
            }
            p += n;
            if (!h->has_location) {
                o.group_id = delta;
            } else if (order == XQC_MOQT_GROUP_ASCENDING) {
                if (delta >= UINT64_MAX - o.group_id) {
                    return -XQC_EILLEGAL_FRAME;
                }
                o.group_id += delta + 1;
            } else {
                if (delta >= o.group_id) {
                    return -XQC_EILLEGAL_FRAME;
                }
                o.group_id -= delta + 1;
            }
        }
        o.datagram = !!(flags & XQC_MOQT_FETCH_DATAGRAM);
        if (!o.datagram) {
            uint64_t mode = flags & XQC_MOQT_FETCH_SUBGROUP_MASK;
            if (mode == XQC_MOQT_FETCH_SUBGROUP_EXPLICIT) {
                n = xqc_vi64_read(p, end, &o.subgroup_id);
                if (n < 0) {
                    return -XQC_EAGAIN;
                }
                p += n;
            } else if (mode) {
                if (!h->has_subgroup) {
                    return -XQC_EILLEGAL_FRAME;
                }
                o.subgroup_id = h->subgroup_id;
                if (mode == XQC_MOQT_FETCH_SUBGROUP_NEXT) {
                    if (o.subgroup_id == UINT64_MAX) {
                        return -XQC_EILLEGAL_FRAME;
                    }
                    o.subgroup_id++;
                }
            }
        }
        delta = 1;
        if (flags & XQC_MOQT_FETCH_OBJECT) {
            n = xqc_vi64_read(p, end, &delta);
            if (n < 0) {
                return -XQC_EAGAIN;
            }
            p += n;
        }
        if ((flags & XQC_MOQT_FETCH_OBJECT) && (flags & XQC_MOQT_FETCH_GROUP)) {
            o.object_id = delta;
        } else {
            if (delta > UINT64_MAX - h->location.object_id) {
                return -XQC_EILLEGAL_FRAME;
            }
            o.object_id = h->location.object_id + delta;
        }
        if (flags & XQC_MOQT_FETCH_PRIORITY) {
            if (p == end) {
                return -XQC_EAGAIN;
            }
            o.priority = *p++;
        } else {
            if (!h->has_priority) {
                return -XQC_EILLEGAL_FRAME;
            }
            o.priority = h->priority;
        }
        if (flags & XQC_MOQT_FETCH_PROPERTIES) {
            uint64_t length;
            n = xqc_vi64_read(p, end, &length);
            if (n < 0) {
                return -XQC_EAGAIN;
            }
            p += n;
            if (length > XQC_MOQT_KV_MAX_VALUE) {
                return -XQC_EILLEGAL_FRAME;
            }
            if (length > (size_t)(end - p)) {
                return -XQC_EAGAIN;
            }
            o.properties.iov_base = (void *)p;
            o.properties.iov_len = length;
            p += length;
        }
        n = xqc_vi64_read(p, end, &o.payload_length);
        if (n < 0) {
            return -XQC_EAGAIN;
        }
        p += n;
    }
    if (xqc_moqt_fetch_order_check(order, h, &o) != XQC_OK) {
        return -XQC_EILLEGAL_FRAME;
    }
    xqc_moqt_fetch_history_update(h, &o);
    *object = o;
    return (xqc_int_t)(p - buf);
}

xqc_int_t
xqc_moqt_fetch_header_encode(uint8_t order,
    const xqc_moqt_fetch_history_t *h, const xqc_moqt_object_t *o,
    uint8_t *buf, size_t cap)
{
    if (xqc_moqt_fetch_order_check(order, h, o) != XQC_OK) {
        return -XQC_EPARAM;
    }
    /* FETCH has neither Object Status nor Subgroup boundary flags. */
    if (o->status != XQC_MOQT_OBJECT_NORMAL
        || o->end_of_group
        || o->first_in_subgroup)
    {
        return -XQC_EPARAM;
    }
    /* Only the three defined range indicators may be serialized. */
    if (o->range < XQC_MOQT_RANGE_NONE || o->range > XQC_MOQT_RANGE_TIMEOUT) {
        return -XQC_EPARAM;
    }
    /* Range endpoints do not carry Object payload or properties. */
    if (o->range && (o->payload_length || o->properties.iov_len)) {
        return -XQC_EPARAM;
    }
    if (o->properties.iov_len > XQC_MOQT_KV_MAX_VALUE
        || (o->properties.iov_len
            && o->properties.iov_base == NULL))
    {
        return -XQC_EPARAM;
    }
    uint64_t flags = XQC_MOQT_FETCH_OBJECT | XQC_MOQT_FETCH_PRIORITY;
    uint64_t fields[XQC_MOQT_FETCH_HEADER_FIELDS];
    size_t count = 1;
    if (o->range) {
        const uint64_t ranges[] = {0, XQC_MOQT_FETCH_NONEXISTENT,
            XQC_MOQT_FETCH_UNKNOWN, XQC_MOQT_FETCH_TIMEOUT};
        flags = ranges[o->range];
        fields[count++] = o->group_id;
        fields[count++] = o->object_id;
    } else {
        if (!h->has_location || o->group_id != h->location.group_id) {
            flags |= XQC_MOQT_FETCH_GROUP;
            fields[count++] = !h->has_location ? o->group_id
                : order == XQC_MOQT_GROUP_ASCENDING
                  ? o->group_id - h->location.group_id - 1
                  : h->location.group_id - o->group_id - 1;
        }
        if (o->datagram) {
            flags |= XQC_MOQT_FETCH_DATAGRAM;
        } else {
            flags |= XQC_MOQT_FETCH_SUBGROUP_EXPLICIT;
            fields[count++] = o->subgroup_id;
        }
        fields[count++] = flags & XQC_MOQT_FETCH_GROUP ? o->object_id
            : o->object_id - h->location.object_id;
        if (o->properties.iov_len) {
            flags |= XQC_MOQT_FETCH_PROPERTIES;
        }
    }
    fields[0] = flags;
    size_t len = 0;
    for (size_t i = 0; i < count; i++) {
        len += xqc_vi64_len(fields[i]);
    }
    if (!o->range) {
        len += sizeof(o->priority) + xqc_vi64_len(o->payload_length);
        if (flags & XQC_MOQT_FETCH_PROPERTIES) {
            len += xqc_vi64_len(o->properties.iov_len) + o->properties.iov_len;
        }
    }
    if (buf == NULL) {
        return (xqc_int_t)len;
    }
    if (len > cap) {
        return -XQC_ENOBUF;
    }
    uint8_t *p = buf, *end = buf + len;
    for (size_t i = 0; i < count; i++) {
        p += xqc_vi64_write(p, end, fields[i]);
    }
    if (!o->range) {
        *p++ = o->priority;
        if (flags & XQC_MOQT_FETCH_PROPERTIES) {
            p += xqc_vi64_write(p, end, o->properties.iov_len);
            xqc_memcpy(p, o->properties.iov_base, o->properties.iov_len);
            p += o->properties.iov_len;
        }
        xqc_vi64_write(p, end, o->payload_length);
    }
    return (xqc_int_t)len;
}
