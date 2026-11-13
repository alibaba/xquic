/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include "xqc_moqt_codec.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"

/* Internal scope, never serialized as a message type. */
#define XQC_MOQT_PARAMETER_SCOPE_FILL UINT64_MAX

static xqc_int_t
xqc_moqt_read_uint(const uint8_t **p, const uint8_t *end, uint64_t *value)
{
    xqc_int_t n = xqc_vi64_read(*p, end, value);
    if (n < 0) {
        return XQC_ERROR;
    }
    *p += n;
    return XQC_OK;
}

static xqc_int_t
xqc_moqt_read_bytes(const uint8_t **p, const uint8_t *end,
    struct iovec *value, size_t limit)
{
    uint64_t len;
    if (xqc_moqt_read_uint(p, end, &len) != XQC_OK
        || len > limit
        || len > (size_t)(end - *p))
    {
        return XQC_ERROR;
    }
    value->iov_base = (void *)*p;
    value->iov_len = len;
    *p += len;
    return XQC_OK;
}

/* The public encoder validates and sizes the whole body before any write. */
static void
xqc_moqt_write_uint(uint8_t *buf, size_t *pos, uint64_t value)
{
    size_t n = xqc_vi64_len(value);
    if (buf != NULL) {
        xqc_vi64_write(buf + *pos, buf + *pos + n, value);
    }
    *pos += n;
}

static xqc_int_t
xqc_moqt_write_bytes(uint8_t *buf, size_t *pos, const struct iovec *value,
    size_t limit)
{
    if (value->iov_len > limit || (value->iov_len && value->iov_base == NULL)) {
        return XQC_ERROR;
    }
    xqc_moqt_write_uint(buf, pos, value->iov_len);
    if (buf != NULL && value->iov_len) {
        xqc_memcpy(buf + *pos, value->iov_base, value->iov_len);
    }
    *pos += value->iov_len;
    return XQC_OK;
}

xqc_int_t
xqc_moqt_is_initial_request(uint64_t type)
{
    switch (type) {
    case XQC_MOQT_MSG_SUBSCRIBE:
    case XQC_MOQT_MSG_PUBLISH:
    case XQC_MOQT_MSG_FETCH:
    case XQC_MOQT_MSG_TRACK_STATUS:
    case XQC_MOQT_MSG_PUBLISH_NAMESPACE:
    case XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE:
    case XQC_MOQT_MSG_SUBSCRIBE_TRACKS:
        return 1;
    default:
        return 0;
    }
}

xqc_int_t
xqc_moqt_is_namespace_request(uint64_t type)
{
    return type == XQC_MOQT_MSG_PUBLISH_NAMESPACE
           || type == XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE
           || type == XQC_MOQT_MSG_SUBSCRIBE_TRACKS;
}

static xqc_int_t
xqc_moqt_is_parameter_allowed(uint64_t p, uint64_t type, uint64_t context)
{
    if (context == XQC_MOQT_PARAMETER_SCOPE_FILL) {
        /* Section 9.20.15: nested parameters have a separate allowlist. */
        switch (p) {
        case XQC_MOQT_PARAM_FILL_TIMEOUT:
        case XQC_MOQT_PARAM_SUBSCRIBER_PRIORITY:
        case XQC_MOQT_PARAM_LOCATION_FILTER:
        case XQC_MOQT_PARAM_GROUP_ORDER:
        case XQC_MOQT_PARAM_SUBGROUP_FILTER:
        case XQC_MOQT_PARAM_OBJECTID_FILTER:
        case XQC_MOQT_PARAM_PRIORITY_FILTER:
        case XQC_MOQT_PARAM_OBJECT_PROPERTY_FILTER:
            return 1;
        default:
            return 0;
        }
    }
    xqc_int_t update = type == XQC_MOQT_MSG_REQUEST_UPDATE;
    xqc_int_t subscribe = type == XQC_MOQT_MSG_SUBSCRIBE;
    xqc_int_t publish = type == XQC_MOQT_MSG_PUBLISH;
    xqc_int_t fetch = type == XQC_MOQT_MSG_FETCH;
    xqc_int_t tracks = type == XQC_MOQT_MSG_SUBSCRIBE_TRACKS;
    xqc_int_t status = type == XQC_MOQT_MSG_TRACK_STATUS;
    xqc_int_t sub_update = update && (context == XQC_MOQT_MSG_SUBSCRIBE
                                     || context == XQC_MOQT_MSG_PUBLISH);
    xqc_int_t ok = type == XQC_MOQT_MSG_REQUEST_OK;
    switch (p) {
    case XQC_MOQT_PARAM_AUTHORIZATION_TOKEN:
        return xqc_moqt_is_initial_request(type) || update;
    case XQC_MOQT_PARAM_OBJECT_DELIVERY_TIMEOUT:
    case XQC_MOQT_PARAM_SUBGROUP_DELIVERY_TIMEOUT:
        return subscribe || publish || sub_update;
    case XQC_MOQT_PARAM_RENDEZVOUS_TIMEOUT:
        return subscribe;
    case XQC_MOQT_PARAM_EXPIRES:
        return publish || type == XQC_MOQT_MSG_SUBSCRIBE_OK
               || (ok && context != XQC_MOQT_MSG_TRACK_STATUS);
    case XQC_MOQT_PARAM_LARGEST_OBJECT:
        return publish || type == XQC_MOQT_MSG_SUBSCRIBE_OK
               || type == XQC_MOQT_MSG_PUBLISH_STATE_NOTIFY
               || (ok && (context == XQC_MOQT_MSG_TRACK_STATUS
                          || context == XQC_MOQT_MSG_REQUEST_UPDATE));
    case XQC_MOQT_PARAM_FILL_TIMEOUT:
        return fetch;
    case XQC_MOQT_PARAM_FORWARD:
        return subscribe || publish || tracks || sub_update
               || (update && context == XQC_MOQT_MSG_SUBSCRIBE_TRACKS)
               || type == XQC_MOQT_MSG_PUBLISH_STATE_NOTIFY;
    case XQC_MOQT_PARAM_SUBSCRIBER_PRIORITY:
        return subscribe || publish || fetch || sub_update
               || (update && context == XQC_MOQT_MSG_FETCH);
    case XQC_MOQT_PARAM_LOCATION_FILTER:
        return subscribe || publish || fetch || sub_update
               || type == XQC_MOQT_MSG_PUBLISH_STATE_NOTIFY;
    case XQC_MOQT_PARAM_GROUP_ORDER:
        return subscribe || publish || fetch || tracks;
    case XQC_MOQT_PARAM_FILL_PARAMETERS:
    case XQC_MOQT_PARAM_NEW_GROUP_REQUEST:
        return subscribe || sub_update;
    case XQC_MOQT_PARAM_SUBGROUP_FILTER:
    case XQC_MOQT_PARAM_OBJECTID_FILTER:
    case XQC_MOQT_PARAM_PRIORITY_FILTER:
    case XQC_MOQT_PARAM_OBJECT_PROPERTY_FILTER:
        return subscribe || fetch || tracks || sub_update;
    case XQC_MOQT_PARAM_TRACK_PROPERTY_FILTER:
        return tracks || (update && context == XQC_MOQT_MSG_SUBSCRIBE_TRACKS);
    case XQC_MOQT_PARAM_TRACK_NAMESPACE_PREFIX:
        return update && (context == XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE
                          || context == XQC_MOQT_MSG_SUBSCRIBE_TRACKS);
    case XQC_MOQT_PARAM_INCLUDE_PROPERTIES:
        return subscribe || fetch || tracks || status;
    default:
        return 0;
    }
}

/* Return the encoded value length; parameters are not odd/even KVPs. */
static xqc_int_t
xqc_moqt_parameter_length(uint64_t type, const uint8_t *data, size_t len)
{
    const uint8_t *p = data, *end = data + len;
    uint64_t value, group = 0;
    switch (type) {
    case XQC_MOQT_PARAM_FORWARD:
    case XQC_MOQT_PARAM_SUBSCRIBER_PRIORITY:
    case XQC_MOQT_PARAM_GROUP_ORDER:
    case XQC_MOQT_PARAM_INCLUDE_PROPERTIES:
        if (len == 0
            || (type == XQC_MOQT_PARAM_GROUP_ORDER
                && (p[0] < XQC_MOQT_GROUP_ASCENDING
                    || p[0] > XQC_MOQT_GROUP_DESCENDING))
            || ((type == XQC_MOQT_PARAM_FORWARD
                    || type == XQC_MOQT_PARAM_INCLUDE_PROPERTIES)
                && p[0] > 1))
        {
            return -XQC_EILLEGAL_FRAME;
        }
        return sizeof(uint8_t);
    case XQC_MOQT_PARAM_TRACK_NAMESPACE_PREFIX: {
        xqc_moqt_namespace_t ns;
        return xqc_moqt_name_decode(p, len, &ns, NULL);
    }
    case XQC_MOQT_PARAM_AUTHORIZATION_TOKEN:
    case XQC_MOQT_PARAM_FILL_PARAMETERS:
    case XQC_MOQT_PARAM_SUBGROUP_FILTER:
    case XQC_MOQT_PARAM_OBJECTID_FILTER:
    case XQC_MOQT_PARAM_PRIORITY_FILTER:
    case XQC_MOQT_PARAM_OBJECT_PROPERTY_FILTER:
    case XQC_MOQT_PARAM_TRACK_PROPERTY_FILTER:
        if (xqc_moqt_read_uint(&p, end, &value) != XQC_OK
            || value > (size_t)(end - p))
        {
            return -XQC_EILLEGAL_FRAME;
        }
        return (xqc_int_t)(p - data + value);
    case XQC_MOQT_PARAM_LOCATION_FILTER: {
        if (xqc_moqt_read_uint(&p, end, &value) != XQC_OK
            || value > XQC_MOQT_FILTER_NEXT_OBJECT)
        {
            return -XQC_EILLEGAL_FRAME;
        }
        unsigned count = value == XQC_MOQT_FILTER_NEXT_OBJECT ? 0 : value;
        for (unsigned i = 0; i < count; i++) {
            if (xqc_moqt_read_uint(&p, end, &value) != XQC_OK) {
                return -XQC_EILLEGAL_FRAME;
            }
            if (i == 0) {
                group = value;
            }
            if (i == XQC_MOQT_FILTER_GROUP_END - 1
                && value > UINT64_MAX - group)
            {
                return -XQC_EILLEGAL_FRAME;
            }
        }
        break;
    }
    case XQC_MOQT_PARAM_LARGEST_OBJECT:
        if (xqc_moqt_read_uint(&p, end, &value) != XQC_OK) {
            return -XQC_EILLEGAL_FRAME;
        }
        /* fall through */
    default:
        if (xqc_moqt_read_uint(&p, end, &value) != XQC_OK) {
            return -XQC_EILLEGAL_FRAME;
        }
        break;
    }
    return (xqc_int_t)(p - data);
}

static xqc_int_t
xqc_moqt_parameters_decode(const uint8_t **p, const uint8_t *end,
    xqc_moqt_message_t *m, uint64_t context, xqc_int_t counted)
{
    uint64_t count = XQC_MOQT_MAX_PARAMETERS, previous = 0;
    if (counted
        && (xqc_moqt_read_uint(p, end, &count) != XQC_OK
            || count > XQC_MOQT_MAX_PARAMETERS))
    {
        return XQC_ERROR;
    }
    m->parameter_count = 0;
    for (size_t i = 0; i < count && (counted || *p < end); i++) {
        uint64_t delta;
        if (xqc_moqt_read_uint(p, end, &delta) != XQC_OK
            || delta > UINT64_MAX - previous)
        {
            return XQC_ERROR;
        }
        uint64_t type = previous + delta;
        if (!xqc_moqt_is_parameter_allowed(type, m->type, context)
            || (i
                && delta == 0
                && type != XQC_MOQT_PARAM_AUTHORIZATION_TOKEN))
        {
            return XQC_ERROR;
        }
        xqc_int_t n = xqc_moqt_parameter_length(type, *p, end - *p);
        if (n < 0) {
            return XQC_ERROR;
        }
        m->parameters[i].type = type;
        m->parameters[i].value = (uint8_t *)*p;
        m->parameters[i].length = n;
        if (type == XQC_MOQT_PARAM_FILL_PARAMETERS) {
            xqc_moqt_message_t fill;
            if (xqc_moqt_fill_parameters_decode(&m->parameters[i], &fill)
                != XQC_OK)
            {
                return XQC_ERROR;
            }
        }
        *p += n;
        previous = type;
        m->parameter_count++;
    }
    return XQC_OK;
}

xqc_int_t
xqc_moqt_fill_parameters_decode(const xqc_moq_message_parameter_t *parameter,
    xqc_moqt_message_t *message)
{
    const uint8_t *p = parameter->value;
    const uint8_t *end = p + parameter->length;
    uint64_t len;
    if (xqc_moqt_read_uint(&p, end, &len) != XQC_OK
        || len != (size_t)(end - p))
    {
        return XQC_ERROR;
    }
    xqc_memzero(message, sizeof(*message));
    if (xqc_moqt_parameters_decode(&p, end, message,
                                   XQC_MOQT_PARAMETER_SCOPE_FILL, 0) != XQC_OK)
    {
        return XQC_ERROR;
    }
    return p == end ? XQC_OK : XQC_ERROR;
}

static xqc_int_t
xqc_moqt_parameters_encode(uint8_t *buf, size_t *pos,
    const xqc_moqt_message_t *m, uint64_t context)
{
    uint64_t previous = 0;
    if (m->parameter_count > XQC_MOQT_MAX_PARAMETERS) {
        return XQC_ERROR;
    }
    xqc_moqt_write_uint(buf, pos, m->parameter_count);
    for (size_t i = 0; i < m->parameter_count; i++) {
        const xqc_moq_message_parameter_t *p = &m->parameters[i];
        if (p->type < previous
            || !xqc_moqt_is_parameter_allowed(p->type, m->type, context)
            || (i
                && p->type == previous
                && p->type != XQC_MOQT_PARAM_AUTHORIZATION_TOKEN)
            || p->value == NULL
            || p->length > XQC_MOQT_MESSAGE_MAX_BODY)
        {
            return XQC_ERROR;
        }
        xqc_int_t n = xqc_moqt_parameter_length(p->type, p->value, p->length);
        if (n < 0 || (size_t)n != p->length) {
            return XQC_ERROR;
        }
        if (p->type == XQC_MOQT_PARAM_FILL_PARAMETERS) {
            xqc_moqt_message_t fill;
            if (xqc_moqt_fill_parameters_decode(p, &fill) != XQC_OK) {
                return XQC_ERROR;
            }
        }
        xqc_moqt_write_uint(buf, pos, p->type - previous);
        if (buf != NULL) {
            xqc_memcpy(buf + *pos, p->value, n);
        }
        *pos += n;
        previous = p->type;
    }
    return XQC_OK;
}

static xqc_int_t
xqc_moqt_properties_check(const uint8_t *data, size_t len)
{
    uint64_t previous = 0;
    size_t pos = 0, count = 0;
    if (len > XQC_MOQT_MESSAGE_MAX_BODY || (len && data == NULL)) {
        return XQC_ERROR;
    }
    while (pos < len) {
        xqc_moqt_kv_t kv;
        xqc_int_t n = xqc_moqt_kv_decode(data + pos, len - pos, previous, &kv);
        if (n < 0 || ++count > XQC_MOQT_MAX_OPTIONS) {
            return XQC_ERROR;
        }
        previous = kv.type;
        pos += n;
    }
    return XQC_OK;
}

/* Draft-22 sections 9.3-9.20: each failed field stops the body immediately. */
static xqc_int_t
xqc_moqt_message_body_decode(xqc_moqt_message_t *m, uint64_t context)
{
    const uint8_t *p = m->body.iov_base, *end = p + m->body.iov_len;
    xqc_int_t parameters = 0, properties = 0, n;
    if (xqc_moqt_is_initial_request(m->type)) {
        if (xqc_moqt_read_uint(&p, end, &m->request_id) != XQC_OK) {
            return XQC_ERROR;
        }
        struct iovec *name = xqc_moqt_is_namespace_request(m->type)
                             ? NULL : &m->track_name;
        n = xqc_moqt_name_decode(p, end - p, &m->track_namespace, name);
        if (n < 0) {
            return XQC_ERROR;
        }
        p += n;
        if (m->type == XQC_MOQT_MSG_PUBLISH) {
            if (xqc_moqt_read_uint(&p, end, &m->track_alias) != XQC_OK) {
                return XQC_ERROR;
            }
            properties = 1;
        }
        parameters = 1;
    } else {
        switch (m->type) {
        case XQC_MOQT_MSG_REQUEST_UPDATE:
            if (xqc_moqt_read_uint(&p, end, &m->request_id) != XQC_OK) {
                return XQC_ERROR;
            }
            parameters = 1;
            break;
        case XQC_MOQT_MSG_SUBSCRIBE_OK:
            if (xqc_moqt_read_uint(&p, end, &m->track_alias) != XQC_OK) {
                return XQC_ERROR;
            }
            properties = parameters = 1;
            break;
        case XQC_MOQT_MSG_REQUEST_OK:
            properties = context == XQC_MOQT_MSG_TRACK_STATUS;
            parameters = 1;
            break;
        case XQC_MOQT_MSG_FETCH_OK:
            if (p == end || *p > 1) {
                return XQC_ERROR;
            }
            m->end_of_track = *p++;
            if (xqc_moqt_read_uint(&p, end, &m->end_group) != XQC_OK
                || xqc_moqt_read_uint(&p, end, &m->end_object) != XQC_OK)
            {
                return XQC_ERROR;
            }
            properties = parameters = 1;
            break;
        case XQC_MOQT_MSG_REQUEST_ERROR:
            if (xqc_moqt_read_uint(&p, end, &m->error.code) != XQC_OK
                || xqc_moqt_read_uint(&p, end, &m->retry_interval) != XQC_OK
                || xqc_moqt_read_bytes(&p, end, &m->reason,
                                       XQC_MOQT_MAX_REASON) != XQC_OK)
            {
                return XQC_ERROR;
            }
            if (m->error.code == XQC_MOQT_REQUEST_REDIRECT) {
                if (context == XQC_MOQT_MSG_REQUEST_UPDATE
                    || xqc_moqt_read_bytes(&p, end, &m->uri,
                                           XQC_MOQT_MESSAGE_MAX_BODY)
                       != XQC_OK)
                {
                    return XQC_ERROR;
                }
                n = xqc_moqt_name_decode(p, end - p, &m->track_namespace,
                                         &m->track_name);
                if (n < 0
                    || (xqc_moqt_is_namespace_request(context)
                        && m->track_name.iov_len))
                {
                    return XQC_ERROR;
                }
                p += n;
            }
            m->error.context = XQC_MOQT_ERROR_REQUEST;
            m->error.normalized_code = xqc_moqt_error_normalize(
                m->error.context, m->error.code);
            break;
        case XQC_MOQT_MSG_NAMESPACE:
        case XQC_MOQT_MSG_NAMESPACE_DONE:
        case XQC_MOQT_MSG_PUBLISH_SKIPPED:
            if (context != (m->type == XQC_MOQT_MSG_PUBLISH_SKIPPED
                            ? XQC_MOQT_MSG_SUBSCRIBE_TRACKS
                            : XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE))
            {
                return XQC_ERROR;
            }
            n = xqc_moqt_name_decode(p, end - p, &m->track_namespace,
                m->type == XQC_MOQT_MSG_PUBLISH_SKIPPED ? &m->track_name
                                                       : NULL);
            if (n < 0) {
                return XQC_ERROR;
            }
            p += n;
            break;
        case XQC_MOQT_MSG_PUBLISH_STATE_NOTIFY:
            parameters = 1;
            break;
        case XQC_MOQT_MSG_PUBLISH_DONE:
            if (xqc_moqt_read_uint(&p, end, &m->error.code) != XQC_OK
                || xqc_moqt_read_uint(&p, end, &m->stream_count) != XQC_OK
                || xqc_moqt_read_bytes(&p, end, &m->reason,
                                       XQC_MOQT_MAX_REASON) != XQC_OK)
            {
                return XQC_ERROR;
            }
            m->error.context = XQC_MOQT_ERROR_PUBLISH_DONE;
            m->error.normalized_code = xqc_moqt_error_normalize(
                m->error.context, m->error.code);
            break;
        case XQC_MOQT_MSG_GOAWAY:
            if (xqc_moqt_read_bytes(&p, end, &m->uri,
                                    XQC_MOQT_GOAWAY_MAX_URI) != XQC_OK
                || xqc_moqt_read_uint(&p, end, &m->timeout_ms) != XQC_OK)
            {
                return XQC_ERROR;
            }
            break;
        default:
            return XQC_ERROR;
        }
    }
    if (parameters
        && xqc_moqt_parameters_decode(&p, end, m, context, 1) != XQC_OK)
    {
        return XQC_ERROR;
    }
    if (!properties) {
        return p == end ? XQC_OK : XQC_ERROR;
    }
    if (xqc_moqt_properties_check(p, end - p) != XQC_OK) {
        return XQC_ERROR;
    }
    m->properties.iov_base = (void *)p;
    m->properties.iov_len = end - p;
    return XQC_OK;
}

static xqc_int_t
xqc_moqt_message_body_encode(const xqc_moqt_message_t *m, uint64_t context,
    uint8_t *buf, size_t cap)
{
    size_t pos = 0;
    xqc_int_t parameters = 0, properties = 0, n;
    if (xqc_moqt_is_initial_request(m->type)) {
        xqc_moqt_write_uint(buf, &pos, m->request_id);
        const struct iovec *name = xqc_moqt_is_namespace_request(m->type)
                                   ? NULL : &m->track_name;
        n = xqc_moqt_name_encode(&m->track_namespace, name,
                                 buf ? buf + pos : NULL, buf ? cap - pos : 0);
        if (n < 0) {
            return XQC_ERROR;
        }
        pos += n;
        if (m->type == XQC_MOQT_MSG_PUBLISH) {
            xqc_moqt_write_uint(buf, &pos, m->track_alias);
            properties = 1;
        }
        parameters = 1;
    } else {
        switch (m->type) {
        case XQC_MOQT_MSG_REQUEST_UPDATE:
            xqc_moqt_write_uint(buf, &pos, m->request_id);
            parameters = 1;
            break;
        case XQC_MOQT_MSG_SUBSCRIBE_OK:
            xqc_moqt_write_uint(buf, &pos, m->track_alias);
            properties = parameters = 1;
            break;
        case XQC_MOQT_MSG_REQUEST_OK:
            properties = context == XQC_MOQT_MSG_TRACK_STATUS;
            parameters = 1;
            break;
        case XQC_MOQT_MSG_FETCH_OK:
            if (m->end_of_track > 1) {
                return XQC_ERROR;
            }
            if (buf != NULL) {
                buf[pos] = m->end_of_track;
            }
            pos += sizeof(m->end_of_track);
            xqc_moqt_write_uint(buf, &pos, m->end_group);
            xqc_moqt_write_uint(buf, &pos, m->end_object);
            properties = parameters = 1;
            break;
        case XQC_MOQT_MSG_REQUEST_ERROR:
            xqc_moqt_write_uint(buf, &pos, m->error.code);
            xqc_moqt_write_uint(buf, &pos, m->retry_interval);
            if (xqc_moqt_write_bytes(buf, &pos, &m->reason,
                                     XQC_MOQT_MAX_REASON) != XQC_OK)
            {
                return XQC_ERROR;
            }
            if (m->error.code == XQC_MOQT_REQUEST_REDIRECT) {
                if (context == XQC_MOQT_MSG_REQUEST_UPDATE
                    || xqc_moqt_write_bytes(buf, &pos, &m->uri,
                                            XQC_MOQT_MESSAGE_MAX_BODY)
                       != XQC_OK)
                {
                    return XQC_ERROR;
                }
                n = xqc_moqt_name_encode(&m->track_namespace, &m->track_name,
                                         buf ? buf + pos : NULL,
                                         buf ? cap - pos : 0);
                if (n < 0
                    || (xqc_moqt_is_namespace_request(context)
                        && m->track_name.iov_len))
                {
                    return XQC_ERROR;
                }
                pos += n;
            }
            break;
        case XQC_MOQT_MSG_NAMESPACE:
        case XQC_MOQT_MSG_NAMESPACE_DONE:
        case XQC_MOQT_MSG_PUBLISH_SKIPPED:
            if (context != (m->type == XQC_MOQT_MSG_PUBLISH_SKIPPED
                            ? XQC_MOQT_MSG_SUBSCRIBE_TRACKS
                            : XQC_MOQT_MSG_SUBSCRIBE_NAMESPACE))
            {
                return XQC_ERROR;
            }
            n = xqc_moqt_name_encode(&m->track_namespace,
                m->type == XQC_MOQT_MSG_PUBLISH_SKIPPED ? &m->track_name
                                                       : NULL,
                buf ? buf + pos : NULL, buf ? cap - pos : 0);
            if (n < 0) {
                return XQC_ERROR;
            }
            pos += n;
            break;
        case XQC_MOQT_MSG_PUBLISH_STATE_NOTIFY:
            parameters = 1;
            break;
        case XQC_MOQT_MSG_PUBLISH_DONE:
            xqc_moqt_write_uint(buf, &pos, m->error.code);
            xqc_moqt_write_uint(buf, &pos, m->stream_count);
            if (xqc_moqt_write_bytes(buf, &pos, &m->reason,
                                     XQC_MOQT_MAX_REASON) != XQC_OK)
            {
                return XQC_ERROR;
            }
            break;
        case XQC_MOQT_MSG_GOAWAY:
            if (xqc_moqt_write_bytes(buf, &pos, &m->uri,
                                     XQC_MOQT_GOAWAY_MAX_URI) != XQC_OK)
            {
                return XQC_ERROR;
            }
            xqc_moqt_write_uint(buf, &pos, m->timeout_ms);
            break;
        default:
            return XQC_ERROR;
        }
    }
    if (parameters
        && xqc_moqt_parameters_encode(buf, &pos, m, context) != XQC_OK)
    {
        return XQC_ERROR;
    }
    if ((!properties
            && m->properties.iov_len)
        || xqc_moqt_properties_check(m->properties.iov_base,
                                     m->properties.iov_len) != XQC_OK)
    {
        return XQC_ERROR;
    }
    if (buf != NULL && m->properties.iov_len) {
        xqc_memcpy(buf + pos, m->properties.iov_base, m->properties.iov_len);
    }
    pos += m->properties.iov_len;
    return pos > XQC_MOQT_MESSAGE_MAX_BODY ? XQC_ERROR : (xqc_int_t)pos;
}

uint64_t
xqc_moqt_error_normalize(xqc_moqt_error_context_t context, uint64_t code)
{
    if (context == XQC_MOQT_ERROR_PUBLISH_DONE) {
        switch (code) {
        case XQC_MOQT_PUBLISH_INTERNAL_ERROR:
        case XQC_MOQT_PUBLISH_UNAUTHORIZED:
        case XQC_MOQT_PUBLISH_TRACK_ENDED:
        case XQC_MOQT_PUBLISH_GOING_AWAY:
        case XQC_MOQT_PUBLISH_TOO_FAR_BEHIND:
        case XQC_MOQT_PUBLISH_EXPIRED:
        case XQC_MOQT_PUBLISH_UPDATE_FAILED:
        case XQC_MOQT_PUBLISH_EXCESSIVE_LOAD:
        case XQC_MOQT_PUBLISH_MALFORMED_TRACK:
            return code;
        default:
            return XQC_MOQT_PUBLISH_INTERNAL_ERROR;
        }
    }
    if (context == XQC_MOQT_ERROR_RESET) {
        return code <= XQC_MOQT_RESET_EXPIRED_AUTH_TOKEN
               || code == XQC_MOQT_RESET_EXCESSIVE_LOAD
               || code == XQC_MOQT_RESET_MALFORMED_TRACK
               ? code : XQC_MOQT_RESET_INTERNAL_ERROR;
    }
    switch (code) {
    case XQC_MOQT_REQUEST_INTERNAL_ERROR:
    case XQC_MOQT_REQUEST_UNAUTHORIZED:
    case XQC_MOQT_REQUEST_TIMEOUT:
    case XQC_MOQT_REQUEST_NOT_SUPPORTED:
    case XQC_MOQT_REQUEST_MALFORMED_AUTH_TOKEN:
    case XQC_MOQT_REQUEST_EXPIRED_AUTH_TOKEN:
    case XQC_MOQT_REQUEST_GOING_AWAY:
    case XQC_MOQT_REQUEST_EXCESSIVE_LOAD:
    case XQC_MOQT_REQUEST_DOES_NOT_EXIST:
    case XQC_MOQT_REQUEST_INVALID_RANGE:
    case XQC_MOQT_REQUEST_MALFORMED_TRACK:
    case XQC_MOQT_REQUEST_UNINTERESTED:
    case XQC_MOQT_REQUEST_PREFIX_OVERLAP:
    case XQC_MOQT_REQUEST_NAMESPACE_TOO_LARGE:
    case XQC_MOQT_REQUEST_UNSUPPORTED_EXTENSION:
    case XQC_MOQT_REQUEST_REDIRECT:
    case XQC_MOQT_REQUEST_CONFLICTING_FILTERS:
    case XQC_MOQT_REQUEST_INVALID_FILTER:
        return code;
    default:
        return XQC_MOQT_REQUEST_INTERNAL_ERROR;
    }
}

xqc_int_t
xqc_moqt_message_encode(const xqc_moqt_message_t *message, uint64_t context,
    uint8_t *buf, size_t cap)
{
    if (message == NULL || (buf == NULL && cap)) {
        return -XQC_EPARAM;
    }
    xqc_int_t len = xqc_moqt_message_body_encode(message, context, NULL, 0);
    if (len < 0) {
        return -XQC_EPARAM;
    }
    size_t header = xqc_vi64_len(message->type) + sizeof(uint16_t);
    if (buf == NULL) {
        return (xqc_int_t)(header + len);
    }
    if (cap < header + len) {
        return -XQC_ENOBUF;
    }
    xqc_moqt_message_body_encode(message, context, buf + header, len);
    xqc_moqt_message_t m = *message;
    m.body.iov_base = buf + header;
    m.body.iov_len = len;
    return xqc_moqt_frame_encode(&m, buf, cap);
}

xqc_int_t
xqc_moqt_message_decode(const uint8_t *buf, size_t len, uint64_t context,
    xqc_moqt_message_t *message)
{
    if (message == NULL) {
        return -XQC_EPARAM;
    }
    xqc_moqt_message_t m;
    xqc_memzero(&m, sizeof(m));
    xqc_int_t n = xqc_moqt_frame_decode(buf, len, &m);
    if (n < 0) {
        return n;
    }
    if (xqc_moqt_message_body_decode(&m, context) != XQC_OK) {
        return -XQC_EILLEGAL_FRAME;
    }
    *message = m;
    return n;
}

xqc_int_t
xqc_moqt_retry_deadline(uint64_t interval, xqc_usec_t now,
    xqc_usec_t *deadline)
{
    if (interval == 0 || deadline == NULL) {
        return -XQC_EPARAM;
    }
    if (interval - 1 > (UINT64_MAX - now) / XQC_MOQT_MICROS_PER_MILLISECOND) {
        return -XQC_ELIMIT;
    }
    *deadline = now + (interval - 1) * XQC_MOQT_MICROS_PER_MILLISECOND;
    return XQC_OK;
}
