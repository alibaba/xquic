#include "moq/moq_transport/draft18/xqc_moq_d18_data.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_int.h"
#include "moq/moq_transport/xqc_moq_session.h"

#include <limits.h>

#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/common/xqc_malloc.h"
#include "moq/moq_transport/xqc_moq_message_handler.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_transport/xqc_moq_subscribe.h"
#include "moq/moq_transport/xqc_moq_track.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_params.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_properties.h"

static xqc_int_t xqc_moq_d18_encode_data_len(xqc_moq_msg_base_t *base);
static xqc_int_t xqc_moq_d18_encode_data(xqc_moq_msg_base_t *base,
    uint8_t *buf, size_t buf_cap);
static xqc_int_t xqc_moq_d18_decode_subgroup_header(uint8_t *buf,
    size_t buf_len, uint8_t stream_fin, xqc_moq_decode_msg_ctx_t *ctx,
    xqc_moq_msg_base_t *base, xqc_int_t *finish, xqc_int_t *wait);
static xqc_int_t xqc_moq_d18_decode_subgroup_object(uint8_t *buf,
    size_t buf_len, uint8_t stream_fin, xqc_moq_decode_msg_ctx_t *ctx,
    xqc_moq_msg_base_t *base, xqc_int_t *finish, xqc_int_t *wait);
static xqc_int_t xqc_moq_d18_decode_fetch_object(uint8_t *buf,
    size_t buf_len, uint8_t stream_fin, xqc_moq_decode_msg_ctx_t *ctx,
    xqc_moq_msg_base_t *base, xqc_int_t *finish, xqc_int_t *wait);
static void xqc_moq_d18_on_subgroup(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, xqc_moq_msg_base_t *base);
static void xqc_moq_d18_on_fetch_object(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, xqc_moq_msg_base_t *base);

static xqc_moq_msg_type_t
xqc_moq_d18_subgroup_type(void)
{
    return (xqc_moq_msg_type_t)XQC_MOQ_INTERNAL_SUBGROUP;
}

static xqc_moq_msg_type_t
xqc_moq_d18_fetch_object_type(void)
{
    return (xqc_moq_msg_type_t)XQC_MOQ_D18_STREAM_TYPE_FETCH;
}

static xqc_bool_t
xqc_moq_d18_status_valid(uint64_t status)
{
    return status == XQC_MOQ_OBJ_STATUS_NORMAL
        || status == XQC_MOQ_OBJ_STATUS_GROUP_END
        || status == XQC_MOQ_OBJ_STATUS_TRACK_END;
}

static xqc_int_t
xqc_moq_d18_validate_properties(const uint8_t *wire, size_t wire_len)
{
    xqc_moq_d18_properties_t *properties = NULL;
    xqc_moq_d18_property_result_t ret = xqc_moq_d18_properties_parse(
        XQC_MOQ_D18_PROPERTY_SCOPE_OBJECT, wire, wire_len, &properties);
    if (ret != XQC_MOQ_D18_PROPERTY_OK) {
        return ret == XQC_MOQ_D18_PROPERTY_NO_MEMORY
            ? -XQC_EMALLOC : -XQC_EPROTO;
    }
    xqc_moq_d18_properties_destroy(properties);
    return XQC_OK;
}

static xqc_int_t
xqc_moq_d18_read_vi64(const uint8_t *buf, size_t buf_len,
    size_t *processed, uint64_t *value)
{
    xqc_int_t ret = xqc_moq_d18_int_read(buf + *processed,
                                  buf + buf_len, value);
    if (ret < 0) {
        return ret;
    }
    *processed += (size_t)ret;
    return XQC_OK;
}

static xqc_int_t
xqc_moq_d18_wait_or_error(uint8_t stream_fin, xqc_int_t processed,
    xqc_int_t *wait)
{
    if (stream_fin) {
        return -XQC_EPROTO;
    }
    *wait = 1;
    return processed;
}

void
xqc_moq_d18_object_free_fields(xqc_moq_object_t *object)
{
    if (object == NULL) {
        return;
    }
    xqc_free(object->object_properties);
    xqc_free(object->payload);
    object->object_properties = NULL;
    object->payload = NULL;
    object->object_properties_len = 0;
    object->payload_len = 0;
}

xqc_moq_d18_data_msg_t *
xqc_moq_d18_data_msg_create(void)
{
    return xqc_calloc(1, sizeof(xqc_moq_d18_data_msg_t));
}

void
xqc_moq_d18_data_msg_destroy(void *data)
{
    xqc_moq_d18_data_msg_t *msg = data;
    if (msg == NULL) {
        return;
    }
    xqc_moq_d18_object_free_fields(&msg->object);
    xqc_free(msg);
}

void
xqc_moq_d18_subgroup_header_init(xqc_moq_msg_base_t *base)
{
    base->type = xqc_moq_d18_subgroup_type;
    base->encode_len = xqc_moq_d18_encode_data_len;
    base->encode = xqc_moq_d18_encode_data;
    base->decode = xqc_moq_d18_decode_subgroup_header;
    base->on_msg = xqc_moq_d18_on_subgroup;
}

void
xqc_moq_d18_subgroup_object_init(xqc_moq_msg_base_t *base)
{
    base->type = xqc_moq_d18_subgroup_type;
    base->encode_len = xqc_moq_d18_encode_data_len;
    base->encode = xqc_moq_d18_encode_data;
    base->decode = xqc_moq_d18_decode_subgroup_object;
    base->on_msg = xqc_moq_d18_on_subgroup;
}

void
xqc_moq_d18_fetch_object_init(xqc_moq_msg_base_t *base)
{
    base->type = xqc_moq_d18_fetch_object_type;
    base->encode_len = xqc_moq_d18_encode_data_len;
    base->encode = xqc_moq_d18_encode_data;
    base->decode = xqc_moq_d18_decode_fetch_object;
    base->on_msg = xqc_moq_d18_on_fetch_object;
}

void
xqc_moq_d18_data_msg_set_previous(xqc_moq_d18_data_msg_t *msg,
    uint64_t group_id, uint64_t object_id, uint64_t subgroup_id,
    uint8_t priority, uint8_t valid)
{
    msg->previous_group_id = group_id;
    msg->previous_object_id = object_id;
    msg->previous_subgroup_id = subgroup_id;
    msg->previous_priority = priority;
    msg->previous_valid = valid;
}

void
xqc_moq_d18_data_msg_inherit_subgroup(xqc_moq_d18_data_msg_t *msg,
    const xqc_moq_d18_data_msg_t *header)
{
    msg->subgroup_wire_type = header->subgroup_wire_type;
    msg->subgroup_id_mode = header->subgroup_id_mode;
    msg->properties_present = header->properties_present;
    msg->default_priority = header->default_priority;
    msg->first_object = header->first_object;
    msg->end_of_group = header->end_of_group;
    msg->object.track_alias = header->object.track_alias;
    msg->object.group_id = header->object.group_id;
    msg->object.subgroup_id = header->object.subgroup_id;
    msg->object.publisher_priority_set =
        header->object.publisher_priority_set;
    msg->object.publisher_priority = header->object.publisher_priority;
}

static xqc_int_t
xqc_moq_d18_copy_properties(xqc_moq_d18_data_msg_t *msg,
    const uint8_t *buf, size_t len)
{
    if (len == 0) {
        return XQC_OK;
    }
    if (msg->object.object_properties == NULL) {
        msg->object.object_properties = xqc_malloc(len);
        if (msg->object.object_properties == NULL) {
            return -XQC_EMALLOC;
        }
    }
    size_t remaining = len - (size_t)msg->properties_received;
    xqc_memcpy(msg->object.object_properties + msg->properties_received,
               buf, remaining);
    msg->properties_received += remaining;
    return XQC_OK;
}

static xqc_int_t
xqc_moq_d18_finish_subgroup_object_id(xqc_moq_d18_data_msg_t *msg)
{
    uint64_t delta = msg->object.object_id_delta;
    if (!msg->previous_valid) {
        msg->object.object_id = delta;
        return XQC_OK;
    }
    if (delta >= UINT64_MAX - msg->previous_object_id) {
        return -XQC_EPROTO;
    }
    msg->object.object_id = msg->previous_object_id + delta + 1;
    return XQC_OK;
}

static xqc_int_t
xqc_moq_d18_decode_properties(uint8_t *buf, size_t buf_len,
    size_t *processed, uint8_t stream_fin, xqc_moq_d18_data_msg_t *msg,
    xqc_int_t *wait)
{
    size_t remaining = (size_t)msg->object.object_properties_len
        - (size_t)msg->properties_received;
    size_t available = buf_len - *processed;
    size_t copy = remaining < available ? remaining : available;
    if (copy > 0) {
        xqc_memcpy(msg->object.object_properties + msg->properties_received,
                   buf + *processed, copy);
        msg->properties_received += copy;
        *processed += copy;
    }
    if (msg->properties_received < msg->object.object_properties_len) {
        return xqc_moq_d18_wait_or_error(
            stream_fin, (xqc_int_t)*processed, wait);
    }
    return xqc_moq_d18_validate_properties(
        msg->object.object_properties,
        (size_t)msg->object.object_properties_len);
}

static xqc_int_t
xqc_moq_d18_decode_payload(uint8_t *buf, size_t buf_len,
    size_t *processed, uint8_t stream_fin, xqc_moq_d18_data_msg_t *msg,
    xqc_int_t *finish, xqc_int_t *wait)
{
    size_t remaining = (size_t)msg->object.payload_len
        - (size_t)msg->payload_received;
    size_t available = buf_len - *processed;
    size_t copy = remaining < available ? remaining : available;
    if (copy > 0) {
        uint8_t *payload = xqc_realloc(
            msg->object.payload, (size_t)msg->payload_received + copy);
        if (payload == NULL) {
            return -XQC_EMALLOC;
        }
        msg->object.payload = payload;
        xqc_memcpy(msg->object.payload + msg->payload_received,
                   buf + *processed, copy);
        msg->payload_received += copy;
        *processed += copy;
    }
    if (msg->payload_received < msg->object.payload_len) {
        return xqc_moq_d18_wait_or_error(
            stream_fin, (xqc_int_t)*processed, wait);
    }
    msg->has_object = 1;
    msg->record_kind = XQC_MOQ_D18_RECORD_OBJECT;
    msg->fin_received = stream_fin && *processed == buf_len;
    msg->object.end_of_stream = msg->fin_received;
    *finish = 1;
    return (xqc_int_t)*processed;
}

static xqc_int_t
xqc_moq_d18_decode_subgroup_body(uint8_t *buf, size_t buf_len,
    uint8_t stream_fin, xqc_moq_decode_msg_ctx_t *ctx,
    xqc_moq_d18_data_msg_t *msg, xqc_int_t *finish, xqc_int_t *wait,
    xqc_int_t state_base)
{
    size_t processed = 0;
    xqc_int_t ret;
    uint64_t value;

    switch (ctx->cur_field_idx - state_base) {
    case 0:
        ret = xqc_moq_d18_read_vi64(buf, buf_len, &processed, &value);
        if (ret != XQC_OK) {
            return xqc_moq_d18_wait_or_error(
                stream_fin, (xqc_int_t)processed, wait);
        }
        msg->object.object_id_delta = value;
        ret = xqc_moq_d18_finish_subgroup_object_id(msg);
        if (ret != XQC_OK) {
            return ret;
        }
        if (msg->subgroup_id_mode == 1 && !msg->previous_valid) {
            msg->object.subgroup_id = msg->object.object_id;
        }
        ctx->cur_field_idx = state_base + 1;
        /* fall through */
    case 1:
        if (msg->properties_present) {
            ret = xqc_moq_d18_read_vi64(
                buf, buf_len, &processed,
                &msg->object.object_properties_len);
            if (ret != XQC_OK) {
                return xqc_moq_d18_wait_or_error(
                    stream_fin, (xqc_int_t)processed, wait);
            }
            if (msg->object.object_properties_len > XQC_MOQ_MAX_OBJECT_LEN) {
                return -XQC_ELIMIT;
            }
            msg->object.object_properties_present = 1;
            if (msg->object.object_properties_len > 0) {
                msg->object.object_properties = xqc_malloc(
                    (size_t)msg->object.object_properties_len);
                if (msg->object.object_properties == NULL) {
                    return -XQC_EMALLOC;
                }
                ctx->cur_field_idx = state_base + 2;
                goto subgroup_properties;
            }
        }
        ctx->cur_field_idx = state_base + 3;
        /* fall through */
    case 3:
payload_length:
        ret = xqc_moq_d18_read_vi64(
            buf, buf_len, &processed, &msg->object.payload_len);
        if (ret != XQC_OK) {
            return xqc_moq_d18_wait_or_error(
                stream_fin, (xqc_int_t)processed, wait);
        }
        if (msg->object.payload_len > XQC_MOQ_MAX_OBJECT_LEN) {
            return -XQC_ELIMIT;
        }
        ctx->cur_field_idx = state_base + 4;
        /* fall through */
    case 4:
        if (msg->object.payload_len == 0) {
            ret = xqc_moq_d18_read_vi64(
                buf, buf_len, &processed, &msg->object.status);
            if (ret != XQC_OK) {
                return xqc_moq_d18_wait_or_error(
                    stream_fin, (xqc_int_t)processed, wait);
            }
            if (!xqc_moq_d18_status_valid(msg->object.status)
                || (msg->object.status != XQC_MOQ_OBJ_STATUS_NORMAL
                    && msg->object.object_properties_len > 0))
            {
                return -XQC_EPROTO;
            }
            msg->has_object = 1;
            msg->record_kind = XQC_MOQ_D18_RECORD_OBJECT;
            msg->fin_received = stream_fin && processed == buf_len;
            msg->object.end_of_stream = msg->fin_received;
            *finish = 1;
            return (xqc_int_t)processed;
        }
        msg->object.status = XQC_MOQ_OBJ_STATUS_NORMAL;
        return xqc_moq_d18_decode_payload(
            buf, buf_len, &processed, stream_fin, msg, finish, wait);

    case 2:
subgroup_properties:
        ret = xqc_moq_d18_decode_properties(
            buf, buf_len, &processed, stream_fin, msg, wait);
        if (ret < 0 || *wait) {
            return ret < 0 ? ret : (xqc_int_t)processed;
        }
        ctx->cur_field_idx = state_base + 3;
        goto payload_length;

    default:
        return -XQC_EPROTO;
    }
}

static xqc_bool_t
xqc_moq_d18_subgroup_type_valid(uint64_t type)
{
    return type <= 0x7f && (type & XQC_MOQ_D18_SUBGROUP_BASE) != 0
        && (type & XQC_MOQ_D18_SUBGROUP_ID_MASK)
            != XQC_MOQ_D18_SUBGROUP_ID_MASK;
}

static xqc_int_t
xqc_moq_d18_decode_subgroup_header(uint8_t *buf, size_t buf_len,
    uint8_t stream_fin, xqc_moq_decode_msg_ctx_t *ctx,
    xqc_moq_msg_base_t *base, xqc_int_t *finish, xqc_int_t *wait)
{
    xqc_moq_d18_data_msg_t *msg = (xqc_moq_d18_data_msg_t *)base;
    size_t processed = 0;
    xqc_int_t ret;
    *finish = 0;
    *wait = 0;

    if (ctx->cur_field_idx == 0) {
        msg->subgroup_wire_type = ctx->cur_msg_type;
        if (!xqc_moq_d18_subgroup_type_valid(msg->subgroup_wire_type)) {
            return -XQC_EPROTO;
        }
        msg->subgroup_id_mode =
            (uint8_t)((msg->subgroup_wire_type
                       & XQC_MOQ_D18_SUBGROUP_ID_MASK) >> 1);
        msg->properties_present =
            (msg->subgroup_wire_type & XQC_MOQ_D18_SUBGROUP_PROPERTIES) != 0;
        msg->default_priority =
            (msg->subgroup_wire_type
             & XQC_MOQ_D18_SUBGROUP_DEFAULT_PRIORITY) != 0;
        msg->first_object =
            (msg->subgroup_wire_type & XQC_MOQ_D18_SUBGROUP_FIRST_OBJECT) != 0;
        msg->end_of_group =
            (msg->subgroup_wire_type & XQC_MOQ_D18_SUBGROUP_END_OF_GROUP) != 0;
    }

    switch (ctx->cur_field_idx) {
    case 0:
        ret = xqc_moq_d18_read_vi64(
            buf, buf_len, &processed, &msg->object.track_alias);
        if (ret != XQC_OK) {
            return xqc_moq_d18_wait_or_error(
                stream_fin, (xqc_int_t)processed, wait);
        }
        ctx->cur_field_idx = 1;
        /* fall through */
    case 1:
        ret = xqc_moq_d18_read_vi64(
            buf, buf_len, &processed, &msg->object.group_id);
        if (ret != XQC_OK) {
            return xqc_moq_d18_wait_or_error(
                stream_fin, (xqc_int_t)processed, wait);
        }
        ctx->cur_field_idx = 2;
        /* fall through */
    case 2:
        if (msg->subgroup_id_mode == 2) {
            ret = xqc_moq_d18_read_vi64(
                buf, buf_len, &processed, &msg->object.subgroup_id);
            if (ret != XQC_OK) {
                return xqc_moq_d18_wait_or_error(
                    stream_fin, (xqc_int_t)processed, wait);
            }
        } else {
            msg->object.subgroup_id = 0;
        }
        ctx->cur_field_idx = 3;
        /* fall through */
    case 3:
        if (!msg->default_priority) {
            if (processed == buf_len) {
                return xqc_moq_d18_wait_or_error(
                    stream_fin, (xqc_int_t)processed, wait);
            }
            msg->object.publisher_priority = buf[processed++];
            msg->object.publisher_priority_set = 1;
        }
        msg->header_complete = 1;
        msg->object.first_of_subgroup = msg->first_object;
        msg->object.end_of_group = msg->end_of_group;
        ctx->cur_field_idx = 4;
        if (processed == buf_len) {
            if (stream_fin) {
                if (msg->subgroup_id_mode == 1) {
                    return -XQC_EPROTO;
                }
                msg->fin_received = 1;
                *finish = 1;
                return (xqc_int_t)processed;
            }
            *wait = 1;
            return (xqc_int_t)processed;
        }
        /* fall through */
    default:
        ret = xqc_moq_d18_decode_subgroup_body(
            buf + processed, buf_len - processed, stream_fin, ctx,
            msg, finish, wait, 4);
        return ret < 0 ? ret : (xqc_int_t)processed + ret;
    }
}

static xqc_int_t
xqc_moq_d18_decode_subgroup_object(uint8_t *buf, size_t buf_len,
    uint8_t stream_fin, xqc_moq_decode_msg_ctx_t *ctx,
    xqc_moq_msg_base_t *base, xqc_int_t *finish, xqc_int_t *wait)
{
    *finish = 0;
    *wait = 0;
    return xqc_moq_d18_decode_subgroup_body(
        buf, buf_len, stream_fin, ctx,
        (xqc_moq_d18_data_msg_t *)base, finish, wait, 0);
}

static xqc_int_t
xqc_moq_d18_fetch_group_id(xqc_moq_d18_data_msg_t *msg,
    uint64_t encoded, uint64_t *group_id)
{
    if (!msg->previous_valid) {
        *group_id = encoded;
        return XQC_OK;
    }
    if (encoded == UINT64_MAX) {
        return -XQC_EPROTO;
    }
    uint64_t step = encoded + 1;
    if (msg->group_order == XQC_MOQ_GROUP_ORDER_DESCENDING) {
        if (msg->previous_group_id < step) {
            return -XQC_EPROTO;
        }
        *group_id = msg->previous_group_id - step;
        return XQC_OK;
    }
    if (msg->previous_group_id > UINT64_MAX - step) {
        return -XQC_EPROTO;
    }
    *group_id = msg->previous_group_id + step;
    return XQC_OK;
}

static xqc_int_t
xqc_moq_d18_decode_fetch_object(uint8_t *buf, size_t buf_len,
    uint8_t stream_fin, xqc_moq_decode_msg_ctx_t *ctx,
    xqc_moq_msg_base_t *base, xqc_int_t *finish, xqc_int_t *wait)
{
    xqc_moq_d18_data_msg_t *msg = (xqc_moq_d18_data_msg_t *)base;
    size_t processed = 0;
    xqc_int_t ret;
    uint64_t value;
    uint8_t has_group;
    uint8_t has_object;
    uint8_t subgroup_mode;
    *finish = 0;
    *wait = 0;

    switch (ctx->cur_field_idx) {
    case 0:
        ret = xqc_moq_d18_read_vi64(
            buf, buf_len, &processed, &msg->serialization_flags);
        if (ret != XQC_OK) {
            return xqc_moq_d18_wait_or_error(
                stream_fin, (xqc_int_t)processed, wait);
        }
        if (msg->serialization_flags == XQC_MOQ_D18_FETCH_RANGE_MISSING) {
            msg->record_kind = XQC_MOQ_D18_RECORD_MISSING_RANGE;
        } else if (msg->serialization_flags
                   == XQC_MOQ_D18_FETCH_RANGE_UNKNOWN)
        {
            msg->record_kind = XQC_MOQ_D18_RECORD_UNKNOWN_RANGE;
        } else if (msg->serialization_flags <= 0x7f) {
            msg->record_kind = XQC_MOQ_D18_RECORD_OBJECT;
        } else {
            return -XQC_EPROTO;
        }
        if (!msg->previous_valid
            && ((msg->serialization_flags & XQC_MOQ_D18_FETCH_GROUP_ID) == 0
                || (msg->serialization_flags
                    & XQC_MOQ_D18_FETCH_OBJECT_ID) == 0))
        {
            return -XQC_EPROTO;
        }
        if (msg->record_kind == XQC_MOQ_D18_RECORD_OBJECT
            && !msg->previous_actual_valid
            && ((msg->serialization_flags & XQC_MOQ_D18_FETCH_PRIORITY) == 0
                || ((msg->serialization_flags
                     & XQC_MOQ_D18_FETCH_DATAGRAM) == 0
                    && (msg->serialization_flags
                        & XQC_MOQ_D18_FETCH_SUBGROUP_MASK) == 1)
                || ((msg->serialization_flags
                     & XQC_MOQ_D18_FETCH_DATAGRAM) == 0
                    && (msg->serialization_flags
                        & XQC_MOQ_D18_FETCH_SUBGROUP_MASK) == 2)))
        {
            return -XQC_EPROTO;
        }
        ctx->cur_field_idx = 1;
        /* fall through */
    case 1:
        has_group = msg->record_kind != XQC_MOQ_D18_RECORD_OBJECT
            || (msg->serialization_flags & XQC_MOQ_D18_FETCH_GROUP_ID) != 0;
        if (has_group) {
            ret = xqc_moq_d18_read_vi64(buf, buf_len, &processed, &value);
            if (ret != XQC_OK) {
                return xqc_moq_d18_wait_or_error(
                    stream_fin, (xqc_int_t)processed, wait);
            }
            ret = xqc_moq_d18_fetch_group_id(
                msg, value, &msg->object.group_id);
            if (ret != XQC_OK) {
                return ret;
            }
        } else {
            if (!msg->previous_valid) {
                return -XQC_EPROTO;
            }
            msg->object.group_id = msg->previous_group_id;
        }
        ctx->cur_field_idx = 2;
        /* fall through */
    case 2:
        if (msg->record_kind != XQC_MOQ_D18_RECORD_OBJECT) {
            ctx->cur_field_idx = 3;
            goto object_id;
        }
        subgroup_mode = (uint8_t)(msg->serialization_flags
            & XQC_MOQ_D18_FETCH_SUBGROUP_MASK);
        if ((msg->serialization_flags & XQC_MOQ_D18_FETCH_DATAGRAM) != 0) {
            msg->object.forwarding_preference = XQC_MOQ_FORWARDING_DATAGRAM;
            msg->object.subgroup_id = 0;
        } else if (subgroup_mode == 0) {
            msg->object.forwarding_preference = XQC_MOQ_FORWARDING_SUBGROUP;
            msg->object.subgroup_id = 0;
        } else if (subgroup_mode == 1) {
            if (!msg->previous_actual_valid) {
                return -XQC_EPROTO;
            }
            msg->object.forwarding_preference = XQC_MOQ_FORWARDING_SUBGROUP;
            msg->object.subgroup_id = msg->previous_subgroup_id;
        } else if (subgroup_mode == 2) {
            if (!msg->previous_actual_valid
                || msg->previous_subgroup_id == UINT64_MAX)
            {
                return -XQC_EPROTO;
            }
            msg->object.forwarding_preference = XQC_MOQ_FORWARDING_SUBGROUP;
            msg->object.subgroup_id = msg->previous_subgroup_id + 1;
        } else {
            ret = xqc_moq_d18_read_vi64(
                buf, buf_len, &processed, &msg->object.subgroup_id);
            if (ret != XQC_OK) {
                return xqc_moq_d18_wait_or_error(
                    stream_fin, (xqc_int_t)processed, wait);
            }
            msg->object.forwarding_preference = XQC_MOQ_FORWARDING_SUBGROUP;
        }
        ctx->cur_field_idx = 3;
        /* fall through */
    case 3:
object_id:
        has_group = msg->record_kind != XQC_MOQ_D18_RECORD_OBJECT
            || (msg->serialization_flags & XQC_MOQ_D18_FETCH_GROUP_ID) != 0;
        has_object = msg->record_kind != XQC_MOQ_D18_RECORD_OBJECT
            || (msg->serialization_flags & XQC_MOQ_D18_FETCH_OBJECT_ID) != 0;
        if (has_object) {
            ret = xqc_moq_d18_read_vi64(buf, buf_len, &processed, &value);
            if (ret != XQC_OK) {
                return xqc_moq_d18_wait_or_error(
                    stream_fin, (xqc_int_t)processed, wait);
            }
            if (has_group || !msg->previous_valid) {
                msg->object.object_id = value;
            } else {
                if (msg->previous_object_id > UINT64_MAX - value) {
                    return -XQC_EPROTO;
                }
                msg->object.object_id = msg->previous_object_id + value;
            }
        } else {
            if (!msg->previous_valid
                || msg->previous_object_id == UINT64_MAX)
            {
                return -XQC_EPROTO;
            }
            msg->object.object_id = msg->previous_object_id + 1;
        }
        if (msg->record_kind != XQC_MOQ_D18_RECORD_OBJECT) {
            msg->fin_received = stream_fin && processed == buf_len;
            msg->object.end_of_stream = msg->fin_received;
            *finish = 1;
            return (xqc_int_t)processed;
        }
        ctx->cur_field_idx = 4;
        /* fall through */
    case 4:
        if ((msg->serialization_flags & XQC_MOQ_D18_FETCH_PRIORITY) != 0) {
            if (processed == buf_len) {
                return xqc_moq_d18_wait_or_error(
                    stream_fin, (xqc_int_t)processed, wait);
            }
            msg->object.publisher_priority = buf[processed++];
            msg->object.publisher_priority_set = 1;
        } else {
            if (!msg->previous_actual_valid) {
                return -XQC_EPROTO;
            }
            msg->object.publisher_priority = msg->previous_priority;
            msg->object.publisher_priority_set = 1;
        }
        ctx->cur_field_idx = 5;
        /* fall through */
    case 5:
        if ((msg->serialization_flags & XQC_MOQ_D18_FETCH_PROPERTIES) != 0) {
            ret = xqc_moq_d18_read_vi64(
                buf, buf_len, &processed,
                &msg->object.object_properties_len);
            if (ret != XQC_OK) {
                return xqc_moq_d18_wait_or_error(
                    stream_fin, (xqc_int_t)processed, wait);
            }
            if (msg->object.object_properties_len > XQC_MOQ_MAX_OBJECT_LEN) {
                return -XQC_ELIMIT;
            }
            msg->object.object_properties_present = 1;
            if (msg->object.object_properties_len > 0) {
                msg->object.object_properties = xqc_malloc(
                    (size_t)msg->object.object_properties_len);
                if (msg->object.object_properties == NULL) {
                    return -XQC_EMALLOC;
                }
                ctx->cur_field_idx = 6;
                goto fetch_properties;
            }
        }
        ctx->cur_field_idx = 7;
        /* fall through */
    case 7:
fetch_payload_length:
        ret = xqc_moq_d18_read_vi64(
            buf, buf_len, &processed, &msg->object.payload_len);
        if (ret != XQC_OK) {
            return xqc_moq_d18_wait_or_error(
                stream_fin, (xqc_int_t)processed, wait);
        }
        if (msg->object.payload_len > XQC_MOQ_MAX_OBJECT_LEN) {
            return -XQC_ELIMIT;
        }
        msg->object.status = XQC_MOQ_OBJ_STATUS_NORMAL;
        ctx->cur_field_idx = 8;
        if (msg->object.payload_len == 0) {
            msg->has_object = 1;
            msg->fin_received = stream_fin && processed == buf_len;
            msg->object.end_of_stream = msg->fin_received;
            *finish = 1;
            return (xqc_int_t)processed;
        }
        /* fall through */
    case 8:
        return xqc_moq_d18_decode_payload(
            buf, buf_len, &processed, stream_fin, msg, finish, wait);

    case 6:
fetch_properties:
        ret = xqc_moq_d18_decode_properties(
            buf, buf_len, &processed, stream_fin, msg, wait);
        if (ret < 0 || *wait) {
            return ret < 0 ? ret : (xqc_int_t)processed;
        }
        ctx->cur_field_idx = 7;
        goto fetch_payload_length;

    default:
        return -XQC_EPROTO;
    }
}

static xqc_int_t
xqc_moq_d18_object_validate_for_write(const xqc_moq_object_t *object,
    uint8_t fetch)
{
    if (object == NULL
        || (object->payload_len > 0 && object->payload == NULL)
        || object->payload_len > XQC_MOQ_MAX_OBJECT_LEN
        || object->object_properties_len > XQC_MOQ_MAX_OBJECT_LEN
        || (object->object_properties_len > 0
            && object->object_properties == NULL)
        || !xqc_moq_d18_status_valid(object->status)
        || (object->status != XQC_MOQ_OBJ_STATUS_NORMAL
            && (object->payload_len > 0
                || object->object_properties_len > 0))
        || (fetch && object->status != XQC_MOQ_OBJ_STATUS_NORMAL))
    {
        return -XQC_EPARAM;
    }
    return xqc_moq_d18_validate_properties(
        object->object_properties,
        (size_t)object->object_properties_len);
}

xqc_int_t
xqc_moq_d18_prepare_subgroup_message(xqc_moq_d18_data_msg_t *msg,
    const xqc_moq_object_t *object, uint8_t include_header)
{
    xqc_int_t ret = xqc_moq_d18_object_validate_for_write(object, 0);
    if (msg == NULL || ret != XQC_OK) {
        return msg == NULL ? -XQC_EPARAM : ret;
    }
    xqc_moq_msg_base_t base = msg->msg_base;
    uint64_t subgroup_wire_type = msg->subgroup_wire_type;
    uint64_t previous_group_id = msg->previous_group_id;
    uint64_t previous_object_id = msg->previous_object_id;
    uint64_t previous_subgroup_id = msg->previous_subgroup_id;
    uint64_t header_track_alias = msg->object.track_alias;
    uint64_t header_group_id = msg->object.group_id;
    uint64_t header_subgroup_id = msg->object.subgroup_id;
    uint8_t previous_priority = msg->previous_priority;
    uint8_t previous_valid = msg->previous_valid;
    uint8_t previous_actual_valid = msg->previous_actual_valid;
    uint8_t subgroup_id_mode = msg->subgroup_id_mode;
    uint8_t header_properties_present = msg->properties_present;
    uint8_t header_default_priority = msg->default_priority;
    xqc_memzero(msg, sizeof(*msg));
    msg->msg_base = base;
    msg->subgroup_wire_type = subgroup_wire_type;
    msg->previous_group_id = previous_group_id;
    msg->previous_object_id = previous_object_id;
    msg->previous_subgroup_id = previous_subgroup_id;
    msg->previous_priority = previous_priority;
    msg->previous_valid = previous_valid;
    msg->previous_actual_valid = previous_actual_valid;
    msg->subgroup_id_mode = subgroup_id_mode;
    msg->object = *object;
    msg->record_kind = XQC_MOQ_D18_RECORD_OBJECT;
    msg->has_object = 1;
    msg->include_subgroup_header = include_header;
    msg->properties_present = include_header
        ? (object->object_properties_present
           || object->object_properties_len > 0)
        : header_properties_present;
    msg->first_object = object->first_of_subgroup;
    msg->end_of_group = object->end_of_group;
    msg->default_priority = !object->publisher_priority_set;
    if (include_header) {
        msg->subgroup_id_mode = 2;
        msg->subgroup_wire_type = XQC_MOQ_D18_SUBGROUP_BASE | 0x04;
        if (msg->properties_present) {
            msg->subgroup_wire_type |= XQC_MOQ_D18_SUBGROUP_PROPERTIES;
        }
        if (msg->end_of_group) {
            msg->subgroup_wire_type |= XQC_MOQ_D18_SUBGROUP_END_OF_GROUP;
        }
        if (msg->default_priority) {
            msg->subgroup_wire_type |= XQC_MOQ_D18_SUBGROUP_DEFAULT_PRIORITY;
        }
        if (msg->first_object) {
            msg->subgroup_wire_type |= XQC_MOQ_D18_SUBGROUP_FIRST_OBJECT;
        }
        msg->object.object_id_delta = object->object_id;
    } else {
        if (msg->subgroup_wire_type == 0
            || (!msg->properties_present
                && object->object_properties_len > 0)
            || !msg->previous_valid
            || object->track_alias != header_track_alias
            || object->group_id != header_group_id
            || object->subgroup_id != header_subgroup_id
            || object->object_id <= msg->previous_object_id)
        {
            return -XQC_EPARAM;
        }
        msg->default_priority = header_default_priority;
        msg->object.object_id_delta =
            object->object_id - msg->previous_object_id - 1;
    }
    return XQC_OK;
}

xqc_int_t
xqc_moq_d18_prepare_fetch_object(xqc_moq_d18_data_msg_t *msg,
    const xqc_moq_object_t *object)
{
    xqc_int_t ret = xqc_moq_d18_object_validate_for_write(object, 1);
    if (msg == NULL || ret != XQC_OK) {
        return msg == NULL ? -XQC_EPARAM : ret;
    }
    msg->object = *object;
    msg->record_kind = XQC_MOQ_D18_RECORD_OBJECT;
    msg->has_object = 1;
    uint64_t flags = 0;
    if (object->forwarding_preference == XQC_MOQ_FORWARDING_DATAGRAM) {
        flags |= XQC_MOQ_D18_FETCH_DATAGRAM;
    } else if (msg->previous_actual_valid
               && object->subgroup_id == msg->previous_subgroup_id)
    {
        flags |= 0x01;
    } else if (msg->previous_actual_valid
               && msg->previous_subgroup_id != UINT64_MAX
               && object->subgroup_id == msg->previous_subgroup_id + 1)
    {
        flags |= 0x02;
    } else if (object->subgroup_id != 0) {
        flags |= 0x03;
    }
    if (!msg->previous_valid || object->group_id != msg->previous_group_id) {
        flags |= XQC_MOQ_D18_FETCH_GROUP_ID | XQC_MOQ_D18_FETCH_OBJECT_ID;
        if (!msg->previous_valid) {
            msg->encoded_group_id = object->group_id;
        } else if (msg->group_order == XQC_MOQ_GROUP_ORDER_DESCENDING) {
            if (object->group_id >= msg->previous_group_id) {
                return -XQC_EPARAM;
            }
            msg->encoded_group_id =
                msg->previous_group_id - object->group_id - 1;
        } else {
            if (object->group_id <= msg->previous_group_id) {
                return -XQC_EPARAM;
            }
            msg->encoded_group_id =
                object->group_id - msg->previous_group_id - 1;
        }
        msg->encoded_object_id = object->object_id;
    } else if (object->object_id != msg->previous_object_id + 1) {
        if (object->object_id <= msg->previous_object_id) {
            return -XQC_EPARAM;
        }
        flags |= XQC_MOQ_D18_FETCH_OBJECT_ID;
        msg->encoded_object_id =
            object->object_id - msg->previous_object_id;
    }
    if (!msg->previous_actual_valid
        || object->publisher_priority != msg->previous_priority)
    {
        flags |= XQC_MOQ_D18_FETCH_PRIORITY;
    }
    if (object->object_properties_present
        || object->object_properties_len > 0)
    {
        flags |= XQC_MOQ_D18_FETCH_PROPERTIES;
    }
    msg->serialization_flags = flags;
    return XQC_OK;
}

xqc_int_t
xqc_moq_d18_prepare_fetch_range(xqc_moq_d18_data_msg_t *msg,
    uint64_t group_id, uint64_t object_id, uint8_t unknown)
{
    if (msg == NULL || unknown > 1) {
        return -XQC_EPARAM;
    }
    msg->record_kind = unknown
        ? XQC_MOQ_D18_RECORD_UNKNOWN_RANGE
        : XQC_MOQ_D18_RECORD_MISSING_RANGE;
    msg->serialization_flags = unknown
        ? XQC_MOQ_D18_FETCH_RANGE_UNKNOWN
        : XQC_MOQ_D18_FETCH_RANGE_MISSING;
    msg->object.group_id = group_id;
    msg->object.object_id = object_id;
    if (!msg->previous_valid) {
        msg->encoded_group_id = group_id;
    } else if (msg->group_order == XQC_MOQ_GROUP_ORDER_DESCENDING) {
        if (group_id >= msg->previous_group_id) {
            return -XQC_EPARAM;
        }
        msg->encoded_group_id = msg->previous_group_id - group_id - 1;
    } else {
        if (group_id <= msg->previous_group_id) {
            return -XQC_EPARAM;
        }
        msg->encoded_group_id = group_id - msg->previous_group_id - 1;
    }
    msg->encoded_object_id = object_id;
    return XQC_OK;
}

static size_t
xqc_moq_d18_subgroup_encoded_len(const xqc_moq_d18_data_msg_t *msg)
{
    size_t len = 0;
    if (msg->include_subgroup_header) {
        len += xqc_moq_d18_int_len(msg->subgroup_wire_type)
            + xqc_moq_d18_int_len(msg->object.track_alias)
            + xqc_moq_d18_int_len(msg->object.group_id)
            + xqc_moq_d18_int_len(msg->object.subgroup_id);
        if (!msg->default_priority) {
            len++;
        }
    }
    len += xqc_moq_d18_int_len(msg->object.object_id_delta);
    if (msg->properties_present) {
        len += xqc_moq_d18_int_len(msg->object.object_properties_len)
            + (size_t)msg->object.object_properties_len;
    }
    len += xqc_moq_d18_int_len(msg->object.payload_len);
    if (msg->object.payload_len == 0) {
        len += xqc_moq_d18_int_len(msg->object.status);
    } else {
        len += (size_t)msg->object.payload_len;
    }
    return len;
}

static size_t
xqc_moq_d18_fetch_encoded_len(const xqc_moq_d18_data_msg_t *msg)
{
    size_t len = xqc_moq_d18_int_len(msg->serialization_flags);
    if (msg->record_kind != XQC_MOQ_D18_RECORD_OBJECT) {
        return len + xqc_moq_d18_int_len(msg->encoded_group_id)
            + xqc_moq_d18_int_len(msg->encoded_object_id);
    }
    if ((msg->serialization_flags & XQC_MOQ_D18_FETCH_GROUP_ID) != 0) {
        len += xqc_moq_d18_int_len(msg->encoded_group_id);
    }
    if ((msg->serialization_flags & XQC_MOQ_D18_FETCH_DATAGRAM) == 0
        && (msg->serialization_flags & XQC_MOQ_D18_FETCH_SUBGROUP_MASK) == 3)
    {
        len += xqc_moq_d18_int_len(msg->object.subgroup_id);
    }
    if ((msg->serialization_flags & XQC_MOQ_D18_FETCH_OBJECT_ID) != 0) {
        len += xqc_moq_d18_int_len(msg->encoded_object_id);
    }
    if ((msg->serialization_flags & XQC_MOQ_D18_FETCH_PRIORITY) != 0) {
        len++;
    }
    if ((msg->serialization_flags & XQC_MOQ_D18_FETCH_PROPERTIES) != 0) {
        len += xqc_moq_d18_int_len(msg->object.object_properties_len)
            + (size_t)msg->object.object_properties_len;
    }
    return len + xqc_moq_d18_int_len(msg->object.payload_len)
        + (size_t)msg->object.payload_len;
}

static xqc_int_t
xqc_moq_d18_encode_data_len(xqc_moq_msg_base_t *base)
{
    xqc_moq_d18_data_msg_t *msg = (xqc_moq_d18_data_msg_t *)base;
    size_t len = msg->record_kind == XQC_MOQ_D18_RECORD_NONE
            || msg->subgroup_wire_type != 0
        ? xqc_moq_d18_subgroup_encoded_len(msg)
        : xqc_moq_d18_fetch_encoded_len(msg);
    return len > INT_MAX ? -XQC_ELIMIT : (xqc_int_t)len;
}

static xqc_int_t
xqc_moq_d18_encode_data(xqc_moq_msg_base_t *base,
    uint8_t *buf, size_t buf_cap)
{
    xqc_moq_d18_data_msg_t *msg = (xqc_moq_d18_data_msg_t *)base;
    xqc_int_t required = xqc_moq_d18_encode_data_len(base);
    if (required < 0 || (size_t)required > buf_cap) {
        return required < 0 ? required : -XQC_EILLEGAL_FRAME;
    }
    uint8_t *p = buf;
    if (msg->subgroup_wire_type != 0) {
        if (msg->include_subgroup_header) {
            p = xqc_moq_d18_int_write(p, msg->subgroup_wire_type);
            p = xqc_moq_d18_int_write(p, msg->object.track_alias);
            p = xqc_moq_d18_int_write(p, msg->object.group_id);
            p = xqc_moq_d18_int_write(p, msg->object.subgroup_id);
            if (!msg->default_priority) {
                *p++ = msg->object.publisher_priority;
            }
        }
        p = xqc_moq_d18_int_write(p, msg->object.object_id_delta);
        if (msg->properties_present) {
            p = xqc_moq_d18_int_write(p, msg->object.object_properties_len);
            if (msg->object.object_properties_len > 0) {
                xqc_memcpy(p, msg->object.object_properties,
                           (size_t)msg->object.object_properties_len);
                p += msg->object.object_properties_len;
            }
        }
        p = xqc_moq_d18_int_write(p, msg->object.payload_len);
        if (msg->object.payload_len == 0) {
            p = xqc_moq_d18_int_write(p, msg->object.status);
        } else {
            xqc_memcpy(p, msg->object.payload,
                       (size_t)msg->object.payload_len);
            p += msg->object.payload_len;
        }
        return (xqc_int_t)(p - buf);
    }

    p = xqc_moq_d18_int_write(p, msg->serialization_flags);
    if (msg->record_kind != XQC_MOQ_D18_RECORD_OBJECT) {
        p = xqc_moq_d18_int_write(p, msg->encoded_group_id);
        p = xqc_moq_d18_int_write(p, msg->encoded_object_id);
        return (xqc_int_t)(p - buf);
    }
    if ((msg->serialization_flags & XQC_MOQ_D18_FETCH_GROUP_ID) != 0) {
        p = xqc_moq_d18_int_write(p, msg->encoded_group_id);
    }
    if ((msg->serialization_flags & XQC_MOQ_D18_FETCH_DATAGRAM) == 0
        && (msg->serialization_flags & XQC_MOQ_D18_FETCH_SUBGROUP_MASK) == 3)
    {
        p = xqc_moq_d18_int_write(p, msg->object.subgroup_id);
    }
    if ((msg->serialization_flags & XQC_MOQ_D18_FETCH_OBJECT_ID) != 0) {
        p = xqc_moq_d18_int_write(p, msg->encoded_object_id);
    }
    if ((msg->serialization_flags & XQC_MOQ_D18_FETCH_PRIORITY) != 0) {
        *p++ = msg->object.publisher_priority;
    }
    if ((msg->serialization_flags & XQC_MOQ_D18_FETCH_PROPERTIES) != 0) {
        p = xqc_moq_d18_int_write(p, msg->object.object_properties_len);
        if (msg->object.object_properties_len > 0) {
            xqc_memcpy(p, msg->object.object_properties,
                       (size_t)msg->object.object_properties_len);
            p += msg->object.object_properties_len;
        }
    }
    p = xqc_moq_d18_int_write(p, msg->object.payload_len);
    if (msg->object.payload_len > 0) {
        xqc_memcpy(p, msg->object.payload, (size_t)msg->object.payload_len);
        p += msg->object.payload_len;
    }
    return (xqc_int_t)(p - buf);
}

static xqc_int_t
xqc_moq_d18_datagram_len(const xqc_moq_object_t *object,
    uint64_t *type_out)
{
    xqc_int_t ret = xqc_moq_d18_object_validate_for_write(object, 0);
    if (ret != XQC_OK || object->track_alias == XQC_MOQ_INVALID_ID) {
        return ret != XQC_OK ? ret : -XQC_EPARAM;
    }
    uint8_t status = object->payload_len == 0;
    uint64_t type = status ? XQC_MOQ_D18_DGRAM_STATUS : 0;
    if (object->object_properties_len > 0) {
        type |= XQC_MOQ_D18_DGRAM_PROPERTIES;
    }
    if (!status && object->end_of_group) {
        type |= XQC_MOQ_D18_DGRAM_END_OF_GROUP;
    }
    if (object->object_id == 0) {
        type |= XQC_MOQ_D18_DGRAM_ZERO_OBJECT_ID;
    }
    if (!object->publisher_priority_set) {
        type |= XQC_MOQ_D18_DGRAM_DEFAULT_PRIORITY;
    }
    size_t len = xqc_moq_d18_int_len(type)
        + xqc_moq_d18_int_len(object->track_alias)
        + xqc_moq_d18_int_len(object->group_id);
    if (object->object_id != 0) {
        len += xqc_moq_d18_int_len(object->object_id);
    }
    if (object->publisher_priority_set) {
        len++;
    }
    if (object->object_properties_len > 0) {
        len += xqc_moq_d18_int_len(object->object_properties_len)
            + (size_t)object->object_properties_len;
    }
    len += status ? xqc_moq_d18_int_len(object->status)
                  : (size_t)object->payload_len;
    *type_out = type;
    return len > INT_MAX ? -XQC_ELIMIT : (xqc_int_t)len;
}

xqc_int_t
xqc_moq_d18_object_datagram_encode_len(const xqc_moq_object_t *object)
{
    uint64_t type = 0;
    return xqc_moq_d18_datagram_len(object, &type);
}

xqc_int_t
xqc_moq_d18_object_datagram_encode(const xqc_moq_object_t *object,
    uint8_t *buf, size_t buf_cap)
{
    uint64_t type = 0;
    xqc_int_t len = xqc_moq_d18_datagram_len(object, &type);
    if (len < 0 || buf == NULL || (size_t)len > buf_cap) {
        return len < 0 ? len : -XQC_EPARAM;
    }
    uint8_t *p = xqc_moq_d18_int_write(buf, type);
    p = xqc_moq_d18_int_write(p, object->track_alias);
    p = xqc_moq_d18_int_write(p, object->group_id);
    if (object->object_id != 0) {
        p = xqc_moq_d18_int_write(p, object->object_id);
    }
    if (object->publisher_priority_set) {
        *p++ = object->publisher_priority;
    }
    if (object->object_properties_len > 0) {
        p = xqc_moq_d18_int_write(p, object->object_properties_len);
        xqc_memcpy(p, object->object_properties,
                   (size_t)object->object_properties_len);
        p += object->object_properties_len;
    }
    if ((type & XQC_MOQ_D18_DGRAM_STATUS) != 0) {
        p = xqc_moq_d18_int_write(p, object->status);
    } else if (object->payload_len > 0) {
        xqc_memcpy(p, object->payload, (size_t)object->payload_len);
        p += object->payload_len;
    }
    return (xqc_int_t)(p - buf);
}

xqc_int_t
xqc_moq_d18_object_datagram_decode(const uint8_t *buf, size_t buf_len,
    xqc_moq_object_t *object)
{
    if (buf == NULL || buf_len == 0 || object == NULL) {
        return -XQC_EPARAM;
    }
    size_t processed = 0;
    uint64_t type;
    if (xqc_moq_d18_read_vi64(buf, buf_len, &processed, &type) != XQC_OK
        || type > 0x2f || (type > 0x0f && type < 0x20)
        || ((type & XQC_MOQ_D18_DGRAM_STATUS) != 0
            && (type & XQC_MOQ_D18_DGRAM_END_OF_GROUP) != 0))
    {
        return -XQC_EPROTO;
    }
    xqc_memzero(object, sizeof(*object));
    if (xqc_moq_d18_read_vi64(
            buf, buf_len, &processed, &object->track_alias) != XQC_OK
        || xqc_moq_d18_read_vi64(
            buf, buf_len, &processed, &object->group_id) != XQC_OK)
    {
        return -XQC_EPROTO;
    }
    if ((type & XQC_MOQ_D18_DGRAM_ZERO_OBJECT_ID) == 0
        && xqc_moq_d18_read_vi64(
            buf, buf_len, &processed, &object->object_id) != XQC_OK)
    {
        return -XQC_EPROTO;
    }
    if ((type & XQC_MOQ_D18_DGRAM_DEFAULT_PRIORITY) == 0) {
        if (processed == buf_len) {
            return -XQC_EPROTO;
        }
        object->publisher_priority = buf[processed++];
        object->publisher_priority_set = 1;
    }
    if ((type & XQC_MOQ_D18_DGRAM_PROPERTIES) != 0) {
        uint64_t properties_len;
        if (xqc_moq_d18_read_vi64(
                buf, buf_len, &processed, &properties_len) != XQC_OK
            || properties_len == 0 || properties_len > buf_len - processed)
        {
            return -XQC_EPROTO;
        }
        object->object_properties = xqc_malloc((size_t)properties_len);
        if (object->object_properties == NULL) {
            return -XQC_EMALLOC;
        }
        xqc_memcpy(object->object_properties,
                   buf + processed, (size_t)properties_len);
        object->object_properties_len = properties_len;
        object->object_properties_present = 1;
        processed += properties_len;
        xqc_int_t ret = xqc_moq_d18_validate_properties(
            object->object_properties, (size_t)properties_len);
        if (ret != XQC_OK) {
            xqc_moq_d18_object_free_fields(object);
            return ret;
        }
    }
    if ((type & XQC_MOQ_D18_DGRAM_STATUS) != 0) {
        if (xqc_moq_d18_read_vi64(
                buf, buf_len, &processed, &object->status) != XQC_OK
            || processed != buf_len
            || !xqc_moq_d18_status_valid(object->status)
            || (object->status != XQC_MOQ_OBJ_STATUS_NORMAL
                && object->object_properties_len > 0))
        {
            xqc_moq_d18_object_free_fields(object);
            return -XQC_EPROTO;
        }
    } else {
        object->status = XQC_MOQ_OBJ_STATUS_NORMAL;
        object->payload_len = buf_len - processed;
        if (object->payload_len > XQC_MOQ_MAX_OBJECT_LEN) {
            xqc_moq_d18_object_free_fields(object);
            return -XQC_ELIMIT;
        }
        if (object->payload_len > 0) {
            object->payload = xqc_malloc((size_t)object->payload_len);
            if (object->payload == NULL) {
                xqc_moq_d18_object_free_fields(object);
                return -XQC_EMALLOC;
            }
            xqc_memcpy(object->payload, buf + processed,
                       (size_t)object->payload_len);
        }
        object->end_of_group =
            (type & XQC_MOQ_D18_DGRAM_END_OF_GROUP) != 0;
    }
    object->forwarding_preference = XQC_MOQ_FORWARDING_DATAGRAM;
    return XQC_OK;
}

xqc_int_t
xqc_moq_d18_decode_datagram(xqc_moq_session_t *session,
    const uint8_t *data, size_t data_len)
{
    xqc_moq_object_t object;
    xqc_int_t ret = xqc_moq_d18_object_datagram_decode(
        data, data_len, &object);
    if (ret != XQC_OK) {
        return ret;
    }
    xqc_moq_on_datagram_object(session, &object);
    xqc_moq_d18_object_free_fields(&object);
    return XQC_OK;
}

xqc_bool_t
xqc_moq_d18_subgroup_header_ready(const xqc_moq_d18_data_msg_t *msg)
{
    return msg != NULL && msg->header_complete
        && (msg->subgroup_id_mode != 1 || msg->has_object);
}

xqc_int_t
xqc_moq_d18_on_subgroup_header(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, xqc_moq_d18_data_msg_t *msg)
{
    if (session == NULL || stream == NULL || msg == NULL
        || !xqc_moq_d18_subgroup_header_ready(msg))
    {
        return -XQC_EPARAM;
    }
    if (stream->subgroup_header_valid) {
        return XQC_OK;
    }
    stream->subgroup_header.track_alias = msg->object.track_alias;
    stream->subgroup_header.group_id = msg->object.group_id;
    stream->subgroup_header.subgroup_id = msg->object.subgroup_id;
    stream->subgroup_header.subgroup_type =
        (uint8_t)msg->subgroup_wire_type;
    stream->subgroup_header.subgroup_priority =
        msg->object.publisher_priority;
    stream->subgroup_header.subgroup_id_mode = msg->subgroup_id_mode;
    stream->subgroup_header.properties_present = msg->properties_present;
    stream->subgroup_header.default_priority = msg->default_priority;
    stream->subgroup_header.first_object = msg->first_object;
    stream->subgroup_header.end_of_group = msg->end_of_group;
    stream->subgroup_header_valid = 1;
    xqc_moq_track_t *track = xqc_moq_find_track_by_alias(
        session, msg->object.track_alias, XQC_MOQ_TRACK_FOR_SUB);
    if (track == NULL) {
        return XQC_OK;
    }
    return xqc_moq_track_on_recv_stream(
        track, stream, msg->object.group_id,
        msg->has_object ? msg->object.object_id : 0,
        msg->object.subgroup_id);
}

static void
xqc_moq_d18_on_subgroup(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, xqc_moq_msg_base_t *base)
{
    xqc_moq_d18_data_msg_t *msg = (xqc_moq_d18_data_msg_t *)base;
    if (msg->include_subgroup_header || msg->header_complete) {
        if (xqc_moq_d18_subgroup_header_ready(msg)
            && xqc_moq_d18_on_subgroup_header(session, stream, msg) != XQC_OK)
        {
            xqc_moq_session_error(
                session, XQC_MOQ_D18_PROTOCOL_VIOLATION,
                "invalid draft-18 subgroup header");
            return;
        }
    }
    if (!msg->has_object) {
        return;
    }
    stream->subgroup_prev_object_id = msg->object.object_id;
    stream->subgroup_prev_object_id_valid = 1;
    msg->object.forwarding_preference = XQC_MOQ_FORWARDING_SUBGROUP;
    xqc_moq_on_object(session, stream, &msg->object);
}

static void
xqc_moq_d18_on_fetch_object(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, xqc_moq_msg_base_t *base)
{
    xqc_moq_d18_data_msg_t *msg = (xqc_moq_d18_data_msg_t *)base;
    stream->d18_fetch_previous_valid = 1;
    stream->d18_fetch_previous_group_id = msg->object.group_id;
    stream->d18_fetch_previous_object_id = msg->object.object_id;
    if (msg->record_kind == XQC_MOQ_D18_RECORD_OBJECT) {
        stream->d18_fetch_previous_actual_valid = 1;
        stream->d18_fetch_previous_subgroup_id = msg->object.subgroup_id;
        stream->d18_fetch_previous_priority = msg->object.publisher_priority;
        if (session->session_callbacks_ext.on_fetch_object != NULL) {
            xqc_moq_session_callback_enter(session);
            session->session_callbacks_ext.on_fetch_object(
                session->user_session, stream->request_id, &msg->object);
            xqc_moq_session_callback_leave(session);
        }
    } else if (session->session_callbacks_ext.on_fetch_range != NULL) {
        xqc_moq_session_callback_enter(session);
        session->session_callbacks_ext.on_fetch_range(
            session->user_session, stream->request_id,
            msg->object.group_id, msg->object.object_id,
            msg->record_kind == XQC_MOQ_D18_RECORD_UNKNOWN_RANGE,
            msg->fin_received);
        xqc_moq_session_callback_leave(session);
    }
}

uint8_t
xqc_moq_d18_group_order_from_params(
    const xqc_moq_message_parameter_t *params, size_t params_num)
{
    for (size_t i = 0; i < params_num; i++) {
        if (params[i].type == XQC_MOQ_D18_PARAM_GROUP_ORDER
            && params[i].is_integer
            && params[i].int_value == XQC_MOQ_GROUP_ORDER_DESCENDING)
        {
            return XQC_MOQ_GROUP_ORDER_DESCENDING;
        }
    }
    return XQC_MOQ_GROUP_ORDER_ASCENDING;
}
