#include "moq/moq_transport/draft18/xqc_moq_d18_kv.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_int.h"

#include <string.h>

#include "src/common/utils/vint/xqc_variable_len_int.h"

static xqc_moq_d18_kv_result_t
xqc_moq_d18_kv_visit(const xqc_moq_d18_kv_view_t *item,
    xqc_moq_d18_kv_visitor_pt visitor, void *user_data)
{
    if (visitor == NULL) {
        return XQC_MOQ_D18_KV_OK;
    }
    if (visitor(item, user_data) != XQC_MOQ_D18_KV_OK) {
        return XQC_MOQ_D18_KV_VISITOR_ERROR;
    }
    return XQC_MOQ_D18_KV_OK;
}

xqc_moq_d18_kv_result_t
xqc_moq_d18_kv_parse(const uint8_t *block, size_t block_len,
    xqc_moq_d18_kv_visitor_pt visitor, void *user_data)
{
    return xqc_moq_d18_kv_parse_ex(block, block_len, visitor, user_data,
                                   NULL);
}

static xqc_moq_d18_kv_result_t
xqc_moq_d18_kv_fail(xqc_moq_d18_kv_error_t *error,
    xqc_moq_d18_kv_result_t result, uint64_t type, uint8_t has_type)
{
    if (error != NULL) {
        error->result = result;
        error->type = type;
        error->has_type = has_type;
    }
    return result;
}

xqc_moq_d18_kv_result_t
xqc_moq_d18_kv_parse_ex(const uint8_t *block, size_t block_len,
    xqc_moq_d18_kv_visitor_pt visitor, void *user_data,
    xqc_moq_d18_kv_error_t *error)
{
    if (error != NULL) {
        memset(error, 0, sizeof(*error));
        error->result = XQC_MOQ_D18_KV_OK;
    }
    if (block_len == 0) {
        return XQC_MOQ_D18_KV_OK;
    }
    if (block == NULL) {
        return xqc_moq_d18_kv_fail(error,
            XQC_MOQ_D18_KV_INVALID_ARGUMENT, 0, 0);
    }

    const uint8_t *pos = block;
    const uint8_t *end = block + block_len;
    uint64_t previous_type = 0;

    while (pos < end) {
        const uint8_t *encoded = pos;
        uint64_t delta_type = 0;
        int ret = xqc_moq_d18_int_read(pos, end, &delta_type);
        if (ret < 0) {
            return xqc_moq_d18_kv_fail(error,
                XQC_MOQ_D18_KV_TRUNCATED, 0, 0);
        }
        pos += ret;
        if (UINT64_MAX - previous_type < delta_type) {
            return xqc_moq_d18_kv_fail(error,
                XQC_MOQ_D18_KV_TYPE_OVERFLOW, 0, 0);
        }

        xqc_moq_d18_kv_view_t item = {
            .type = previous_type + delta_type,
        };
        if (item.type & 1) {
            uint64_t length = 0;
            ret = xqc_moq_d18_int_read(pos, end, &length);
            if (ret < 0) {
                return xqc_moq_d18_kv_fail(error,
                    XQC_MOQ_D18_KV_TRUNCATED, item.type, 1);
            }
            pos += ret;
            if (length > XQC_MOQ_D18_KV_MAX_BYTES) {
                return xqc_moq_d18_kv_fail(error,
                    XQC_MOQ_D18_KV_VALUE_TOO_LARGE, item.type, 1);
            }
            if ((uint64_t)(end - pos) < length) {
                return xqc_moq_d18_kv_fail(error,
                    XQC_MOQ_D18_KV_TRUNCATED, item.type, 1);
            }
            item.is_bytes = 1;
            item.bytes = pos;
            item.bytes_len = (size_t)length;
            pos += length;

        } else {
            ret = xqc_moq_d18_int_read(pos, end, &item.integer);
            if (ret < 0) {
                return xqc_moq_d18_kv_fail(error,
                    XQC_MOQ_D18_KV_TRUNCATED, item.type, 1);
            }
            pos += ret;
        }

        item.encoded = encoded;
        item.encoded_len = (size_t)(pos - encoded);

        xqc_moq_d18_kv_result_t visit_ret =
            xqc_moq_d18_kv_visit(&item, visitor, user_data);
        if (visit_ret != XQC_MOQ_D18_KV_OK) {
            return xqc_moq_d18_kv_fail(error, visit_ret, item.type, 1);
        }
        previous_type = item.type;
    }

    return XQC_MOQ_D18_KV_OK;
}

static xqc_moq_d18_kv_result_t
xqc_moq_d18_kv_writer_validate(uint8_t **pos, const uint8_t *end,
    uint64_t *previous_type, uint64_t type)
{
    if (pos == NULL || *pos == NULL || end == NULL || previous_type == NULL
        || end < *pos)
    {
        return XQC_MOQ_D18_KV_INVALID_ARGUMENT;
    }
    if (type < *previous_type) {
        return XQC_MOQ_D18_KV_OUT_OF_ORDER;
    }
    return XQC_MOQ_D18_KV_OK;
}

xqc_moq_d18_kv_result_t
xqc_moq_d18_kv_write_integer(uint8_t **pos, const uint8_t *end,
    uint64_t *previous_type, uint64_t type, uint64_t value)
{
    xqc_moq_d18_kv_result_t ret =
        xqc_moq_d18_kv_writer_validate(pos, end, previous_type, type);
    if (ret != XQC_MOQ_D18_KV_OK || (type & 1)) {
        return ret == XQC_MOQ_D18_KV_OK
            ? XQC_MOQ_D18_KV_INVALID_ARGUMENT : ret;
    }

    uint64_t delta_type = type - *previous_type;
    size_t needed = xqc_moq_d18_int_len(delta_type) + xqc_moq_d18_int_len(value);
    if ((size_t)(end - *pos) < needed) {
        return XQC_MOQ_D18_KV_NO_SPACE;
    }

    uint8_t *next = xqc_moq_d18_int_write(*pos, delta_type);
    next = xqc_moq_d18_int_write(next, value);
    *pos = next;
    *previous_type = type;
    return XQC_MOQ_D18_KV_OK;
}

xqc_moq_d18_kv_result_t
xqc_moq_d18_kv_write_bytes(uint8_t **pos, const uint8_t *end,
    uint64_t *previous_type, uint64_t type, const uint8_t *value,
    size_t value_len)
{
    xqc_moq_d18_kv_result_t ret =
        xqc_moq_d18_kv_writer_validate(pos, end, previous_type, type);
    if (ret != XQC_MOQ_D18_KV_OK || !(type & 1)
        || (value_len > 0 && value == NULL))
    {
        return ret == XQC_MOQ_D18_KV_OK
            ? XQC_MOQ_D18_KV_INVALID_ARGUMENT : ret;
    }
    if (value_len > XQC_MOQ_D18_KV_MAX_BYTES) {
        return XQC_MOQ_D18_KV_VALUE_TOO_LARGE;
    }

    uint64_t delta_type = type - *previous_type;
    size_t needed = xqc_moq_d18_int_len(delta_type) + xqc_moq_d18_int_len(value_len)
        + value_len;
    if ((size_t)(end - *pos) < needed) {
        return XQC_MOQ_D18_KV_NO_SPACE;
    }

    uint8_t *next = xqc_moq_d18_int_write(*pos, delta_type);
    next = xqc_moq_d18_int_write(next, value_len);
    if (value_len > 0) {
        memcpy(next, value, value_len);
        next += value_len;
    }
    *pos = next;
    *previous_type = type;
    return XQC_MOQ_D18_KV_OK;
}
