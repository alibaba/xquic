#include "moq/moq_transport/draft18/xqc_moq_d18_params.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_int.h"

#include <limits.h>

#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/common/xqc_malloc.h"
#include "moq/moq_transport/xqc_moq_message.h"

#define XQC_MOQ_D18_PARAM_SCOPE(context) \
    (UINT64_C(1) << (context))

#define XQC_MOQ_D18_PARAM_SCOPES_2(first, second) \
    (XQC_MOQ_D18_PARAM_SCOPE(first) | XQC_MOQ_D18_PARAM_SCOPE(second))

#define XQC_MOQ_D18_PARAM_SCOPES_3(first, second, third) \
    (XQC_MOQ_D18_PARAM_SCOPES_2(first, second) \
     | XQC_MOQ_D18_PARAM_SCOPE(third))

static const xqc_moq_d18_param_spec_t xqc_moq_d18_param_specs[] = {
    {
        XQC_MOQ_D18_PARAM_OBJECT_DELIVERY_TIMEOUT,
        XQC_MOQ_D18_PARAM_SCOPES_3(
            XQC_MOQ_D18_PARAM_CONTEXT_PUBLISH_OK,
            XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE,
            XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_SUBSCRIBE),
        XQC_MOQ_D18_PARAM_ENCODING_VI64,
        0,
    },
    {
        XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN,
        XQC_MOQ_D18_PARAM_SCOPE(XQC_MOQ_D18_PARAM_CONTEXT_PUBLISH)
        | XQC_MOQ_D18_PARAM_SCOPE(XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE)
        | XQC_MOQ_D18_PARAM_SCOPE(
            XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_SUBSCRIBE)
        | XQC_MOQ_D18_PARAM_SCOPE(
            XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_FETCH)
        | XQC_MOQ_D18_PARAM_SCOPE(
            XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_NAMESPACE)
        | XQC_MOQ_D18_PARAM_SCOPE(
            XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE_NAMESPACE)
        | XQC_MOQ_D18_PARAM_SCOPE(
            XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE_TRACKS)
        | XQC_MOQ_D18_PARAM_SCOPE(
            XQC_MOQ_D18_PARAM_CONTEXT_PUBLISH_NAMESPACE)
        | XQC_MOQ_D18_PARAM_SCOPE(
            XQC_MOQ_D18_PARAM_CONTEXT_TRACK_STATUS)
        | XQC_MOQ_D18_PARAM_SCOPE(XQC_MOQ_D18_PARAM_CONTEXT_FETCH),
        XQC_MOQ_D18_PARAM_ENCODING_BYTES,
        1,
    },
    {
        XQC_MOQ_D18_PARAM_RENDEZVOUS_TIMEOUT,
        XQC_MOQ_D18_PARAM_SCOPE(XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE),
        XQC_MOQ_D18_PARAM_ENCODING_VI64,
        0,
    },
    {
        XQC_MOQ_D18_PARAM_SUBGROUP_DELIVERY_TIMEOUT,
        XQC_MOQ_D18_PARAM_SCOPES_3(
            XQC_MOQ_D18_PARAM_CONTEXT_PUBLISH_OK,
            XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE,
            XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_SUBSCRIBE),
        XQC_MOQ_D18_PARAM_ENCODING_VI64,
        0,
    },
    {
        XQC_MOQ_D18_PARAM_EXPIRES,
        XQC_MOQ_D18_PARAM_SCOPE(XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE_OK)
        | XQC_MOQ_D18_PARAM_SCOPE(XQC_MOQ_D18_PARAM_CONTEXT_PUBLISH)
        | XQC_MOQ_D18_PARAM_SCOPE(XQC_MOQ_D18_PARAM_CONTEXT_PUBLISH_OK)
        | XQC_MOQ_D18_PARAM_SCOPE(
            XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_OK),
        XQC_MOQ_D18_PARAM_ENCODING_VI64,
        0,
    },
    {
        XQC_MOQ_D18_PARAM_LARGEST_OBJECT,
        XQC_MOQ_D18_PARAM_SCOPE(XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE_OK)
        | XQC_MOQ_D18_PARAM_SCOPE(XQC_MOQ_D18_PARAM_CONTEXT_PUBLISH)
        | XQC_MOQ_D18_PARAM_SCOPE(
            XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_OK)
        | XQC_MOQ_D18_PARAM_SCOPE(
            XQC_MOQ_D18_PARAM_CONTEXT_TRACK_STATUS_OK),
        XQC_MOQ_D18_PARAM_ENCODING_LOCATION,
        0,
    },
    {
        XQC_MOQ_D18_PARAM_FILL_TIMEOUT,
        XQC_MOQ_D18_PARAM_SCOPE(XQC_MOQ_D18_PARAM_CONTEXT_FETCH),
        XQC_MOQ_D18_PARAM_ENCODING_VI64,
        0,
    },
    {
        XQC_MOQ_D18_PARAM_FORWARD,
        XQC_MOQ_D18_PARAM_SCOPE(XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE)
        | XQC_MOQ_D18_PARAM_SCOPE(
            XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_SUBSCRIBE)
        | XQC_MOQ_D18_PARAM_SCOPE(XQC_MOQ_D18_PARAM_CONTEXT_PUBLISH)
        | XQC_MOQ_D18_PARAM_SCOPE(XQC_MOQ_D18_PARAM_CONTEXT_PUBLISH_OK)
        | XQC_MOQ_D18_PARAM_SCOPE(
            XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE_TRACKS),
        XQC_MOQ_D18_PARAM_ENCODING_U8,
        0,
    },
    {
        XQC_MOQ_D18_PARAM_SUBSCRIBER_PRIORITY,
        XQC_MOQ_D18_PARAM_SCOPE(XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE)
        | XQC_MOQ_D18_PARAM_SCOPE(XQC_MOQ_D18_PARAM_CONTEXT_FETCH)
        | XQC_MOQ_D18_PARAM_SCOPE(
            XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_SUBSCRIBE)
        | XQC_MOQ_D18_PARAM_SCOPE(
            XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_FETCH)
        | XQC_MOQ_D18_PARAM_SCOPE(XQC_MOQ_D18_PARAM_CONTEXT_PUBLISH_OK),
        XQC_MOQ_D18_PARAM_ENCODING_U8,
        0,
    },
    {
        XQC_MOQ_D18_PARAM_SUBSCRIPTION_FILTER,
        XQC_MOQ_D18_PARAM_SCOPES_3(
            XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE,
            XQC_MOQ_D18_PARAM_CONTEXT_PUBLISH_OK,
            XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_SUBSCRIBE),
        XQC_MOQ_D18_PARAM_ENCODING_BYTES,
        0,
    },
    {
        XQC_MOQ_D18_PARAM_GROUP_ORDER,
        XQC_MOQ_D18_PARAM_SCOPES_3(
            XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE,
            XQC_MOQ_D18_PARAM_CONTEXT_PUBLISH_OK,
            XQC_MOQ_D18_PARAM_CONTEXT_FETCH),
        XQC_MOQ_D18_PARAM_ENCODING_U8,
        0,
    },
    {
        XQC_MOQ_D18_PARAM_NEW_GROUP_REQUEST,
        XQC_MOQ_D18_PARAM_SCOPES_3(
            XQC_MOQ_D18_PARAM_CONTEXT_PUBLISH_OK,
            XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE,
            XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_SUBSCRIBE),
        XQC_MOQ_D18_PARAM_ENCODING_VI64,
        0,
    },
    {
        XQC_MOQ_D18_PARAM_TRACK_NAMESPACE_PREFIX,
        XQC_MOQ_D18_PARAM_SCOPE(
            XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_NAMESPACE),
        XQC_MOQ_D18_PARAM_ENCODING_TRACK_NAMESPACE,
        0,
    },
};

xqc_moq_d18_param_result_t
xqc_moq_d18_param_lookup(uint64_t type, xqc_moq_d18_param_spec_t *spec)
{
    if (spec == NULL) {
        return XQC_MOQ_D18_PARAM_INVALID_ARGUMENT;
    }
    for (size_t i = 0;
         i < sizeof(xqc_moq_d18_param_specs)
             / sizeof(xqc_moq_d18_param_specs[0]);
         i++)
    {
        if (xqc_moq_d18_param_specs[i].type == type) {
            *spec = xqc_moq_d18_param_specs[i];
            return XQC_MOQ_D18_PARAM_OK;
        }
    }
    return XQC_MOQ_D18_PARAM_UNKNOWN;
}

xqc_moq_d18_param_result_t
xqc_moq_d18_param_check(uint64_t type,
    xqc_moq_d18_param_context_t context, size_t previous_occurrences,
    uint64_t integer_value, uint8_t has_integer_value)
{
    if (context >= XQC_MOQ_D18_PARAM_CONTEXT_COUNT) {
        return XQC_MOQ_D18_PARAM_INVALID_ARGUMENT;
    }

    xqc_moq_d18_param_spec_t spec;
    xqc_moq_d18_param_result_t ret =
        xqc_moq_d18_param_lookup(type, &spec);
    if (ret != XQC_MOQ_D18_PARAM_OK) {
        return ret;
    }
    if ((spec.context_mask & XQC_MOQ_D18_PARAM_SCOPE(context)) == 0) {
        return XQC_MOQ_D18_PARAM_INVALID_SCOPE;
    }
    if (previous_occurrences > 0 && !spec.repeatable) {
        return XQC_MOQ_D18_PARAM_DUPLICATE;
    }
    if (!has_integer_value) {
        return XQC_MOQ_D18_PARAM_OK;
    }
    if (spec.encoding == XQC_MOQ_D18_PARAM_ENCODING_U8
        && integer_value > UINT8_MAX)
    {
        return XQC_MOQ_D18_PARAM_INVALID_VALUE;
    }
    if (type == XQC_MOQ_D18_PARAM_FORWARD && integer_value > 1) {
        return XQC_MOQ_D18_PARAM_INVALID_VALUE;
    }
    if (type == XQC_MOQ_D18_PARAM_GROUP_ORDER
        && integer_value != 1 && integer_value != 2)
    {
        return XQC_MOQ_D18_PARAM_INVALID_VALUE;
    }
    return XQC_MOQ_D18_PARAM_OK;
}

static xqc_moq_d18_param_result_t
xqc_moq_d18_param_read_vi64(const uint8_t **pos, const uint8_t *end,
    uint64_t *value)
{
    xqc_int_t ret = xqc_moq_d18_int_read(*pos, end, value);
    if (ret < 0) {
        return XQC_MOQ_D18_PARAM_FORMATTING;
    }
    *pos += ret;
    return XQC_MOQ_D18_PARAM_OK;
}

static xqc_moq_d18_param_result_t
xqc_moq_d18_param_copy_value(xqc_moq_message_parameter_t *param,
    const uint8_t *value, size_t value_len)
{
    param->length = value_len;
    if (value_len == 0) {
        return XQC_MOQ_D18_PARAM_OK;
    }
    param->value = xqc_malloc(value_len);
    if (param->value == NULL) {
        return XQC_MOQ_D18_PARAM_NO_MEMORY;
    }
    xqc_memcpy(param->value, value, value_len);
    return XQC_MOQ_D18_PARAM_OK;
}

static xqc_moq_d18_param_result_t
xqc_moq_d18_param_parse_namespace(const uint8_t **pos,
    const uint8_t *end)
{
    uint64_t field_count = 0;
    xqc_moq_d18_param_result_t ret =
        xqc_moq_d18_param_read_vi64(pos, end, &field_count);
    if (ret != XQC_MOQ_D18_PARAM_OK) {
        return ret;
    }
    if (field_count > XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS) {
        return XQC_MOQ_D18_PARAM_PROTOCOL_VIOLATION;
    }

    size_t total_value_len = 0;
    for (uint64_t i = 0; i < field_count; i++) {
        uint64_t field_len = 0;
        ret = xqc_moq_d18_param_read_vi64(pos, end, &field_len);
        if (ret != XQC_MOQ_D18_PARAM_OK) {
            return ret;
        }
        if (field_len == 0
            || field_len > XQC_MOQ_MAX_FULL_TRACK_NAME_LEN
            || total_value_len
                > XQC_MOQ_MAX_FULL_TRACK_NAME_LEN - field_len)
        {
            return XQC_MOQ_D18_PARAM_PROTOCOL_VIOLATION;
        }
        if ((uint64_t)(end - *pos) < field_len) {
            return XQC_MOQ_D18_PARAM_FORMATTING;
        }
        *pos += field_len;
        total_value_len += field_len;
    }
    return XQC_MOQ_D18_PARAM_OK;
}

static xqc_moq_d18_param_result_t
xqc_moq_d18_param_decode_namespace(const uint8_t **pos,
    const uint8_t *end, xqc_moq_message_parameter_t *param)
{
    const uint8_t *start = *pos;
    xqc_moq_d18_param_result_t ret =
        xqc_moq_d18_param_parse_namespace(pos, end);
    if (ret != XQC_MOQ_D18_PARAM_OK) {
        return ret;
    }
    return xqc_moq_d18_param_copy_value(
        param, start, (size_t)(*pos - start));
}

xqc_moq_d18_param_result_t
xqc_moq_d18_params_decode(const uint8_t **pos, const uint8_t *end,
    xqc_moq_d18_param_context_t context,
    xqc_moq_message_parameter_t *params, size_t params_num)
{
    if (pos == NULL || *pos == NULL || end == NULL || *pos > end
        || (params_num > 0 && params == NULL)
        || context >= XQC_MOQ_D18_PARAM_CONTEXT_COUNT)
    {
        return XQC_MOQ_D18_PARAM_INVALID_ARGUMENT;
    }

    uint64_t previous_type = 0;
    size_t previous_occurrences = 0;
    for (size_t i = 0; i < params_num; i++) {
        uint64_t delta_type = 0;
        xqc_moq_d18_param_result_t ret =
            xqc_moq_d18_param_read_vi64(pos, end, &delta_type);
        if (ret != XQC_MOQ_D18_PARAM_OK) {
            return ret;
        }
        if (UINT64_MAX - previous_type < delta_type) {
            return XQC_MOQ_D18_PARAM_PROTOCOL_VIOLATION;
        }
        uint64_t type = previous_type + delta_type;
        if (i > 0 && type == previous_type) {
            previous_occurrences++;
        } else {
            previous_occurrences = 0;
        }

        xqc_moq_d18_param_spec_t spec;
        ret = xqc_moq_d18_param_lookup(type, &spec);
        if (ret != XQC_MOQ_D18_PARAM_OK) {
            return ret;
        }
        ret = xqc_moq_d18_param_check(
            type, context, previous_occurrences, 0, 0);
        if (ret != XQC_MOQ_D18_PARAM_OK) {
            return ret;
        }

        xqc_moq_message_parameter_t *param = &params[i];
        param->type = type;
        param->length = 0;
        param->value = NULL;
        param->is_integer = 0;
        param->int_value = 0;

        if (spec.encoding == XQC_MOQ_D18_PARAM_ENCODING_U8) {
            if (*pos >= end) {
                return XQC_MOQ_D18_PARAM_FORMATTING;
            }
            param->is_integer = 1;
            param->int_value = **pos;
            (*pos)++;
            ret = xqc_moq_d18_param_check(
                type, context, previous_occurrences,
                param->int_value, 1);

        } else if (spec.encoding == XQC_MOQ_D18_PARAM_ENCODING_VI64) {
            param->is_integer = 1;
            ret = xqc_moq_d18_param_read_vi64(
                pos, end, &param->int_value);

        } else if (spec.encoding
                   == XQC_MOQ_D18_PARAM_ENCODING_LOCATION)
        {
            const uint8_t *value_start = *pos;
            uint64_t group = 0;
            uint64_t object = 0;
            ret = xqc_moq_d18_param_read_vi64(pos, end, &group);
            if (ret == XQC_MOQ_D18_PARAM_OK) {
                ret = xqc_moq_d18_param_read_vi64(pos, end, &object);
            }
            if (ret == XQC_MOQ_D18_PARAM_OK) {
                ret = xqc_moq_d18_param_copy_value(
                    param, value_start, (size_t)(*pos - value_start));
            }

        } else if (spec.encoding
                   == XQC_MOQ_D18_PARAM_ENCODING_BYTES)
        {
            uint64_t value_len = 0;
            ret = xqc_moq_d18_param_read_vi64(pos, end, &value_len);
            if (ret == XQC_MOQ_D18_PARAM_OK && value_len > UINT16_MAX) {
                ret = XQC_MOQ_D18_PARAM_PROTOCOL_VIOLATION;
            }
            if (ret == XQC_MOQ_D18_PARAM_OK
                && (uint64_t)(end - *pos) < value_len)
            {
                ret = XQC_MOQ_D18_PARAM_FORMATTING;
            }
            if (ret == XQC_MOQ_D18_PARAM_OK) {
                ret = xqc_moq_d18_param_copy_value(
                    param, *pos, (size_t)value_len);
                *pos += value_len;
            }

        } else {
            ret = xqc_moq_d18_param_decode_namespace(pos, end, param);
        }
        if (ret != XQC_MOQ_D18_PARAM_OK) {
            return ret;
        }
        previous_type = type;
    }
    return XQC_MOQ_D18_PARAM_OK;
}

static xqc_moq_d18_param_result_t
xqc_moq_d18_param_add_encoded_len(size_t *total, size_t addition)
{
    if (SIZE_MAX - *total < addition) {
        return XQC_MOQ_D18_PARAM_INVALID_VALUE;
    }
    *total += addition;
    return XQC_MOQ_D18_PARAM_OK;
}

static xqc_moq_d18_param_result_t
xqc_moq_d18_param_validate_serialized_value(
    const xqc_moq_message_parameter_t *param,
    xqc_moq_d18_param_encoding_t encoding, size_t *value_len)
{
    if (encoding == XQC_MOQ_D18_PARAM_ENCODING_U8
        || encoding == XQC_MOQ_D18_PARAM_ENCODING_VI64)
    {
        if (!param->is_integer || param->value != NULL
            || param->length != 0)
        {
            return XQC_MOQ_D18_PARAM_INVALID_VALUE;
        }
        *value_len = encoding == XQC_MOQ_D18_PARAM_ENCODING_U8
            ? 1 : (size_t)xqc_moq_d18_int_len(param->int_value);
        return XQC_MOQ_D18_PARAM_OK;
    }

    if (param->is_integer
        || (param->length > 0 && param->value == NULL))
    {
        return XQC_MOQ_D18_PARAM_INVALID_VALUE;
    }
    size_t serialized_len = (size_t)param->length;
    if ((uint64_t)serialized_len != param->length) {
        return XQC_MOQ_D18_PARAM_INVALID_VALUE;
    }

    if (encoding == XQC_MOQ_D18_PARAM_ENCODING_BYTES) {
        if (param->length > UINT16_MAX) {
            return XQC_MOQ_D18_PARAM_INVALID_VALUE;
        }
        *value_len = (size_t)xqc_moq_d18_int_len(param->length)
            + serialized_len;
        return XQC_MOQ_D18_PARAM_OK;
    }

    if (serialized_len == 0) {
        return XQC_MOQ_D18_PARAM_FORMATTING;
    }
    const uint8_t *pos = param->value;
    const uint8_t *end = param->value + serialized_len;
    if (encoding == XQC_MOQ_D18_PARAM_ENCODING_LOCATION) {
        uint64_t group = 0;
        uint64_t object = 0;
        xqc_moq_d18_param_result_t ret =
            xqc_moq_d18_param_read_vi64(&pos, end, &group);
        if (ret == XQC_MOQ_D18_PARAM_OK) {
            ret = xqc_moq_d18_param_read_vi64(&pos, end, &object);
        }
        if (ret != XQC_MOQ_D18_PARAM_OK || pos != end) {
            return XQC_MOQ_D18_PARAM_FORMATTING;
        }

    } else {
        xqc_moq_d18_param_result_t ret =
            xqc_moq_d18_param_parse_namespace(&pos, end);
        if (ret != XQC_MOQ_D18_PARAM_OK) {
            return ret;
        }
        if (pos != end) {
            return XQC_MOQ_D18_PARAM_FORMATTING;
        }
    }

    *value_len = serialized_len;
    return XQC_MOQ_D18_PARAM_OK;
}

xqc_moq_d18_param_result_t
xqc_moq_d18_params_encoded_len(xqc_moq_d18_param_context_t context,
    const xqc_moq_message_parameter_t *params, size_t params_num,
    size_t *encoded_len)
{
    if (encoded_len == NULL
        || (params_num > 0 && params == NULL)
        || context >= XQC_MOQ_D18_PARAM_CONTEXT_COUNT)
    {
        return XQC_MOQ_D18_PARAM_INVALID_ARGUMENT;
    }

    size_t total = 0;
    uint64_t previous_type = 0;
    size_t previous_occurrences = 0;
    for (size_t i = 0; i < params_num; i++) {
        const xqc_moq_message_parameter_t *param = &params[i];
        if (i > 0 && param->type < previous_type) {
            return XQC_MOQ_D18_PARAM_INVALID_VALUE;
        }
        if (i > 0 && param->type == previous_type) {
            previous_occurrences++;
        } else {
            previous_occurrences = 0;
        }

        xqc_moq_d18_param_spec_t spec;
        xqc_moq_d18_param_result_t ret =
            xqc_moq_d18_param_lookup(param->type, &spec);
        if (ret != XQC_MOQ_D18_PARAM_OK) {
            return ret;
        }
        ret = xqc_moq_d18_param_check(
            param->type, context, previous_occurrences,
            param->int_value, param->is_integer);
        if (ret != XQC_MOQ_D18_PARAM_OK) {
            return ret;
        }

        size_t value_len = 0;
        ret = xqc_moq_d18_param_validate_serialized_value(
            param, spec.encoding, &value_len);
        if (ret != XQC_MOQ_D18_PARAM_OK) {
            return ret;
        }

        uint64_t delta_type = param->type - previous_type;
        ret = xqc_moq_d18_param_add_encoded_len(
            &total, (size_t)xqc_moq_d18_int_len(delta_type));
        if (ret == XQC_MOQ_D18_PARAM_OK) {
            ret = xqc_moq_d18_param_add_encoded_len(&total, value_len);
        }
        if (ret != XQC_MOQ_D18_PARAM_OK) {
            return ret;
        }
        previous_type = param->type;
    }

    *encoded_len = total;
    return XQC_MOQ_D18_PARAM_OK;
}

xqc_moq_d18_param_result_t
xqc_moq_d18_params_encode(uint8_t **pos, const uint8_t *end,
    xqc_moq_d18_param_context_t context,
    const xqc_moq_message_parameter_t *params, size_t params_num)
{
    if (pos == NULL || *pos == NULL || end == NULL || *pos > end) {
        return XQC_MOQ_D18_PARAM_INVALID_ARGUMENT;
    }

    size_t encoded_len = 0;
    xqc_moq_d18_param_result_t ret = xqc_moq_d18_params_encoded_len(
        context, params, params_num, &encoded_len);
    if (ret != XQC_MOQ_D18_PARAM_OK) {
        return ret;
    }
    if ((size_t)(end - *pos) < encoded_len) {
        return XQC_MOQ_D18_PARAM_FORMATTING;
    }

    uint8_t *write_pos = *pos;
    uint64_t previous_type = 0;
    for (size_t i = 0; i < params_num; i++) {
        const xqc_moq_message_parameter_t *param = &params[i];
        xqc_moq_d18_param_spec_t spec;
        ret = xqc_moq_d18_param_lookup(param->type, &spec);
        if (ret != XQC_MOQ_D18_PARAM_OK) {
            return ret;
        }

        write_pos = xqc_moq_d18_int_write(
            write_pos, param->type - previous_type);
        if (spec.encoding == XQC_MOQ_D18_PARAM_ENCODING_U8) {
            *write_pos++ = (uint8_t)param->int_value;

        } else if (spec.encoding == XQC_MOQ_D18_PARAM_ENCODING_VI64) {
            write_pos = xqc_moq_d18_int_write(write_pos, param->int_value);

        } else if (spec.encoding == XQC_MOQ_D18_PARAM_ENCODING_BYTES) {
            write_pos = xqc_moq_d18_int_write(write_pos, param->length);
            if (param->length > 0) {
                xqc_memcpy(write_pos, param->value, param->length);
                write_pos += param->length;
            }

        } else if (param->length > 0) {
            xqc_memcpy(write_pos, param->value, param->length);
            write_pos += param->length;
        }
        previous_type = param->type;
    }

    *pos = write_pos;
    return XQC_MOQ_D18_PARAM_OK;
}
