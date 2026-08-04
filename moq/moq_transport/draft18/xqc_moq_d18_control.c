#include "moq/moq_transport/draft18/xqc_moq_d18_control.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_int.h"

#include <limits.h>

#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/common/xqc_malloc.h"
#include "moq/moq_transport/xqc_moq_message_handler.h"
#include "moq/moq_transport/xqc_moq_namespace.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_properties.h"

#define XQC_MOQ_D18_MAX_STREAM_COUNT ((UINT64_C(1) << 62) - 1)

typedef struct {
    xqc_moq_publish_done_msg_t msg;
    uint8_t                   *payload;
    size_t                    payload_len;
    size_t                    payload_processed;
} xqc_moq_d18_publish_done_storage_t;

static xqc_moq_msg_type_t
xqc_moq_d18_request_update_type(void)
{
    return (xqc_moq_msg_type_t)XQC_MOQ_D18_MSG_REQUEST_UPDATE;
}

static xqc_moq_msg_type_t
xqc_moq_d18_publish_blocked_type(void)
{
    return (xqc_moq_msg_type_t)XQC_MOQ_D18_MSG_PUBLISH_BLOCKED;
}

static xqc_moq_msg_type_t
xqc_moq_d18_publish_done_type(void)
{
    return (xqc_moq_msg_type_t)XQC_MOQ_D18_MSG_PUBLISH_DONE;
}

static xqc_moq_msg_type_t
xqc_moq_d18_goaway_type(void)
{
    return (xqc_moq_msg_type_t)XQC_MOQ_D18_MSG_GOAWAY;
}

static const xqc_moq_msg_base_t xqc_moq_d18_request_update_base = {
    .type = xqc_moq_d18_request_update_type,
    .encode_len = xqc_moq_d18_request_update_encode_len,
    .encode = xqc_moq_d18_request_update_encode,
    .decode = xqc_moq_d18_request_update_decode,
    .on_msg = xqc_moq_on_request_update,
};

static const xqc_moq_msg_base_t xqc_moq_d18_publish_blocked_base = {
    .type = xqc_moq_d18_publish_blocked_type,
    .encode_len = xqc_moq_d18_publish_blocked_encode_len,
    .encode = xqc_moq_d18_publish_blocked_encode,
    .decode = xqc_moq_d18_publish_blocked_decode,
    .on_msg = xqc_moq_on_publish_blocked,
};

static const xqc_moq_msg_base_t xqc_moq_d18_publish_done_base = {
    .type = xqc_moq_d18_publish_done_type,
    .encode_len = xqc_moq_d18_publish_done_encode_len,
    .encode = xqc_moq_d18_publish_done_encode,
    .decode = xqc_moq_d18_publish_done_decode,
    .on_msg = xqc_moq_on_publish_done,
};

static const xqc_moq_msg_base_t xqc_moq_d18_goaway_base = {
    .type = xqc_moq_d18_goaway_type,
    .encode_len = xqc_moq_d18_goaway_encode_len,
    .encode = xqc_moq_d18_goaway_encode,
    .decode = xqc_moq_d18_goaway_decode,
    .on_msg = xqc_moq_on_goaway_draft18,
};

static uint8_t *
xqc_moq_d18_write_length(uint8_t *pos, size_t length)
{
    pos[0] = (uint8_t)(length >> 8);
    pos[1] = (uint8_t)length;
    return pos + XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
}

static xqc_int_t
xqc_moq_d18_frame_len(xqc_moq_msg_type_t type, size_t payload_len)
{
    size_t header_len = xqc_moq_d18_int_len(type) + XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    if (payload_len > UINT16_MAX || payload_len > (size_t)INT64_MAX - header_len) {
        return -XQC_ELIMIT;
    }
    return (xqc_int_t)(header_len + payload_len);
}

static int
xqc_moq_d18_utf8_valid(const uint8_t *value, size_t len)
{
    size_t i = 0;
    while (i < len) {
        uint8_t first = value[i++];
        if (first <= 0x7f) {
            continue;
        }

        uint32_t codepoint = 0;
        size_t continuation = 0;
        uint32_t minimum = 0;
        if (first >= 0xc2 && first <= 0xdf) {
            codepoint = first & 0x1f;
            continuation = 1;
            minimum = 0x80;
        } else if (first >= 0xe0 && first <= 0xef) {
            codepoint = first & 0x0f;
            continuation = 2;
            minimum = 0x800;
        } else if (first >= 0xf0 && first <= 0xf4) {
            codepoint = first & 0x07;
            continuation = 3;
            minimum = 0x10000;
        } else {
            return 0;
        }
        if (continuation > len - i) {
            return 0;
        }
        for (size_t j = 0; j < continuation; j++) {
            uint8_t next = value[i++];
            if ((next & 0xc0) != 0x80) {
                return 0;
            }
            codepoint = (codepoint << 6) | (next & 0x3f);
        }
        if (codepoint < minimum || codepoint > 0x10ffff
            || (codepoint >= 0xd800 && codepoint <= 0xdfff))
        {
            return 0;
        }
    }
    return 1;
}

static xqc_int_t
xqc_moq_d18_validate_namespace(uint64_t count,
    const xqc_moq_track_ns_field_t *fields, size_t *total_len)
{
    if (total_len == NULL || count > XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS
        || (count > 0 && fields == NULL))
    {
        return -XQC_EPARAM;
    }

    size_t total = 0;
    for (uint64_t i = 0; i < count; i++) {
        if (fields[i].len == 0 || fields[i].len > XQC_MOQ_MAX_NAME_LEN
            || fields[i].data == NULL
            || total > XQC_MOQ_MAX_FULL_TRACK_NAME_LEN - fields[i].len)
        {
            return -XQC_EPARAM;
        }
        total += fields[i].len;
    }
    *total_len = total;
    return XQC_OK;
}

static xqc_int_t
xqc_moq_d18_buffer_payload(uint8_t *buf, size_t len, uint8_t fin,
    xqc_moq_decode_msg_ctx_t *ctx, uint8_t **payload, size_t *payload_len,
    size_t *payload_processed, xqc_int_t *finish, xqc_int_t *wait_more,
    uint8_t *ready)
{
    if (ctx == NULL || payload == NULL || payload_len == NULL
        || payload_processed == NULL || finish == NULL || wait_more == NULL
        || ready == NULL || (len > 0 && buf == NULL))
    {
        return -XQC_EPARAM;
    }

    xqc_int_t processed = 0;
    *finish = 0;
    *wait_more = 0;
    *ready = 0;
    if (ctx->cur_field_idx == 0) {
        if (len < XQC_MOQ_MSG_LENGTH_FIXED_SIZE) {
            if (fin) {
                return -XQC_EILLEGAL_FRAME;
            }
            *wait_more = 1;
            return 0;
        }
        size_t declared = ((size_t)buf[0] << 8) | buf[1];
        if (declared > 0) {
            *payload = xqc_malloc(declared);
            if (*payload == NULL) {
                return -XQC_EMALLOC;
            }
        }
        *payload_len = declared;
        *payload_processed = 0;
        ctx->msg_declared_length = declared;
        ctx->payload_processed = 0;
        ctx->cur_field_idx = 1;
        processed = XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    }

    size_t remaining = *payload_len - *payload_processed;
    size_t available = len - (size_t)processed;
    size_t to_copy = available < remaining ? available : remaining;
    if (to_copy > 0) {
        xqc_memcpy(*payload + *payload_processed, buf + processed, to_copy);
        *payload_processed += to_copy;
        ctx->payload_processed = (xqc_int_t)*payload_processed;
        processed += (xqc_int_t)to_copy;
    }
    if (*payload_processed != *payload_len) {
        if (fin) {
            return -XQC_EILLEGAL_FRAME;
        }
        *wait_more = 1;
        return processed;
    }
    *ready = 1;
    return processed;
}

static xqc_int_t
xqc_moq_d18_read_vi64(const uint8_t **pos, const uint8_t *end,
    uint64_t *value)
{
    int ret = xqc_moq_d18_int_read(*pos, end, value);
    if (ret < 0) {
        return -XQC_EILLEGAL_FRAME;
    }
    *pos += ret;
    return XQC_OK;
}

static void
xqc_moq_d18_payload_complete(uint8_t **payload, size_t *payload_len,
    size_t *payload_processed, xqc_moq_decode_msg_ctx_t *ctx,
    xqc_int_t *finish)
{
    xqc_free(*payload);
    *payload = NULL;
    *payload_len = 0;
    *payload_processed = 0;
    ctx->payload_processed = 0;
    *finish = 1;
}

void *
xqc_moq_d18_request_update_create(void)
{
    xqc_moq_request_update_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    if (msg != NULL) {
        xqc_moq_d18_request_update_init_handler(
            &msg->msg_base,
            XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_SUBSCRIBE);
    }
    return msg;
}

void
xqc_moq_d18_request_update_clear(xqc_moq_request_update_msg_t *msg)
{
    if (msg == NULL) {
        return;
    }
    if (msg->params != NULL) {
        xqc_moq_msg_free_params(msg->params, (xqc_int_t)msg->params_num);
    }
    msg->params = NULL;
    msg->params_num = 0;
    for (size_t i = 0; i < msg->request_auth.count; i++) {
        xqc_free(msg->request_auth.tokens[i].token_value);
    }
    xqc_free(msg->request_auth.tokens);
    msg->request_auth.tokens = NULL;
    msg->request_auth.count = 0;
    xqc_free(msg->payload);
    msg->payload = NULL;
    msg->payload_len = 0;
    msg->payload_processed = 0;
}

void
xqc_moq_d18_request_update_free(void *msg)
{
    xqc_moq_request_update_msg_t *update = msg;
    if (update != NULL) {
        xqc_moq_d18_request_update_clear(update);
        xqc_free(update);
    }
}

void
xqc_moq_d18_request_update_init_handler(xqc_moq_msg_base_t *base,
    xqc_moq_d18_param_context_t context)
{
    xqc_moq_request_update_msg_t *msg =
        (xqc_moq_request_update_msg_t *)base;
    *base = xqc_moq_d18_request_update_base;
    msg->d18_param_context = (uint8_t)context;
    msg->d18_error_code = XQC_MOQ_D18_NO_ERROR;
}

xqc_int_t
xqc_moq_d18_request_update_encode_len(xqc_moq_msg_base_t *base)
{
    if (base == NULL) {
        return -XQC_EPARAM;
    }
    xqc_moq_request_update_msg_t *msg =
        (xqc_moq_request_update_msg_t *)base;
    if (msg->params_num > XQC_MOQ_MAX_PARAMS
        || msg->d18_param_context >= XQC_MOQ_D18_PARAM_CONTEXT_COUNT)
    {
        return -XQC_EPARAM;
    }
    size_t params_len = 0;
    if (xqc_moq_d18_params_encoded_len(
            (xqc_moq_d18_param_context_t)msg->d18_param_context,
            msg->params, (size_t)msg->params_num, &params_len)
        != XQC_MOQ_D18_PARAM_OK)
    {
        return -XQC_EPARAM;
    }
    size_t payload_len = xqc_moq_d18_int_len(msg->request_id)
        + xqc_moq_d18_int_len(msg->params_num) + params_len;
    return xqc_moq_d18_frame_len(base->type(), payload_len);
}

xqc_int_t
xqc_moq_d18_request_update_encode(xqc_moq_msg_base_t *base,
    uint8_t *buf, size_t cap)
{
    if (base == NULL || (cap > 0 && buf == NULL)) {
        return -XQC_EPARAM;
    }
    xqc_int_t frame_len = xqc_moq_d18_request_update_encode_len(base);
    if (frame_len < 0) {
        return frame_len;
    }
    if ((size_t)frame_len > cap) {
        return -XQC_ENOBUF;
    }
    xqc_moq_request_update_msg_t *msg =
        (xqc_moq_request_update_msg_t *)base;
    size_t header_len = xqc_moq_d18_int_len(base->type())
        + XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    uint8_t *pos = xqc_moq_d18_int_write(buf, base->type());
    pos = xqc_moq_d18_write_length(pos, (size_t)frame_len - header_len);
    pos = xqc_moq_d18_int_write(pos, msg->request_id);
    pos = xqc_moq_d18_int_write(pos, msg->params_num);
    if (xqc_moq_d18_params_encode(&pos, buf + frame_len,
            (xqc_moq_d18_param_context_t)msg->d18_param_context,
            msg->params, (size_t)msg->params_num)
        != XQC_MOQ_D18_PARAM_OK)
    {
        return -XQC_EPARAM;
    }
    return (xqc_int_t)(pos - buf);
}

xqc_int_t
xqc_moq_d18_request_update_decode(uint8_t *buf, size_t len, uint8_t fin,
    xqc_moq_decode_msg_ctx_t *ctx, xqc_moq_msg_base_t *base,
    xqc_int_t *finish, xqc_int_t *wait_more)
{
    if (base == NULL) {
        return -XQC_EPARAM;
    }
    xqc_moq_request_update_msg_t *msg =
        (xqc_moq_request_update_msg_t *)base;
    if (msg->d18_param_context >= XQC_MOQ_D18_PARAM_CONTEXT_COUNT) {
        msg->d18_error_code = XQC_MOQ_D18_PROTOCOL_VIOLATION;
        return -XQC_EPROTO;
    }

    uint8_t ready = 0;
    xqc_int_t processed = xqc_moq_d18_buffer_payload(
        buf, len, fin, ctx, &msg->payload, &msg->payload_len,
        &msg->payload_processed, finish, wait_more, &ready);
    if (processed < 0 || !ready) {
        return processed;
    }

    const uint8_t *pos = msg->payload;
    const uint8_t *end = msg->payload + msg->payload_len;
    if (xqc_moq_d18_read_vi64(&pos, end, &msg->request_id) != XQC_OK
        || xqc_moq_d18_read_vi64(&pos, end, &msg->params_num) != XQC_OK)
    {
        msg->d18_error_code = XQC_MOQ_D18_PROTOCOL_VIOLATION;
        return -XQC_EILLEGAL_FRAME;
    }
    if (msg->params_num > XQC_MOQ_MAX_PARAMS) {
        msg->d18_error_code = XQC_MOQ_D18_PROTOCOL_VIOLATION;
        return -XQC_ELIMIT;
    }
    if (msg->params_num > 0) {
        msg->params = xqc_moq_msg_alloc_params((xqc_int_t)msg->params_num);
        if (msg->params == NULL) {
            msg->d18_error_code = XQC_MOQ_D18_INTERNAL_ERROR;
            return -XQC_EMALLOC;
        }
        xqc_moq_d18_param_result_t ret = xqc_moq_d18_params_decode(
            &pos, end,
            (xqc_moq_d18_param_context_t)msg->d18_param_context,
            msg->params, (size_t)msg->params_num);
        if (ret != XQC_MOQ_D18_PARAM_OK) {
            if (ret == XQC_MOQ_D18_PARAM_NO_MEMORY) {
                msg->d18_error_code = XQC_MOQ_D18_INTERNAL_ERROR;
                return -XQC_EMALLOC;
            }
            msg->d18_error_code = ret == XQC_MOQ_D18_PARAM_FORMATTING
                ? XQC_MOQ_D18_KEY_VALUE_FORMATTING_ERROR
                : XQC_MOQ_D18_PROTOCOL_VIOLATION;
            return ret == XQC_MOQ_D18_PARAM_FORMATTING
                ? -XQC_EILLEGAL_FRAME : -XQC_EPROTO;
        }
    }
    if (pos != end) {
        msg->d18_error_code = XQC_MOQ_D18_KEY_VALUE_FORMATTING_ERROR;
        return -XQC_EILLEGAL_FRAME;
    }
    msg->d18_error_code = XQC_MOQ_D18_NO_ERROR;
    xqc_moq_d18_payload_complete(&msg->payload, &msg->payload_len,
        &msg->payload_processed, ctx, finish);
    return processed;
}

void *
xqc_moq_d18_publish_blocked_create(void)
{
    xqc_moq_publish_blocked_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    if (msg != NULL) {
        xqc_moq_d18_publish_blocked_init_handler(&msg->msg_base);
    }
    return msg;
}

void
xqc_moq_d18_publish_blocked_clear(xqc_moq_publish_blocked_msg_t *msg)
{
    if (msg == NULL) {
        return;
    }
    if (msg->track_namespace_suffix != NULL) {
        for (uint64_t i = 0; i < msg->track_namespace_suffix_num; i++) {
            xqc_free(msg->track_namespace_suffix[i].data);
        }
    }
    xqc_free(msg->track_namespace_suffix);
    msg->track_namespace_suffix = NULL;
    msg->track_namespace_suffix_num = 0;
    xqc_free(msg->track_name);
    msg->track_name = NULL;
    msg->track_name_len = 0;
    xqc_free(msg->payload);
    msg->payload = NULL;
    msg->payload_len = 0;
    msg->payload_processed = 0;
}

void
xqc_moq_d18_publish_blocked_free(void *msg)
{
    xqc_moq_publish_blocked_msg_t *blocked = msg;
    if (blocked != NULL) {
        xqc_moq_d18_publish_blocked_clear(blocked);
        xqc_free(blocked);
    }
}

void
xqc_moq_d18_publish_blocked_init_handler(xqc_moq_msg_base_t *base)
{
    *base = xqc_moq_d18_publish_blocked_base;
}

xqc_int_t
xqc_moq_d18_publish_blocked_encode_len(xqc_moq_msg_base_t *base)
{
    if (base == NULL) {
        return -XQC_EPARAM;
    }
    xqc_moq_publish_blocked_msg_t *msg =
        (xqc_moq_publish_blocked_msg_t *)base;
    size_t namespace_len = 0;
    if (xqc_moq_d18_validate_namespace(msg->track_namespace_suffix_num,
            msg->track_namespace_suffix, &namespace_len) != XQC_OK
        || msg->track_name_len == 0
        || msg->track_name_len > XQC_MOQ_MAX_NAME_LEN
        || msg->track_name == NULL
        || namespace_len
            > XQC_MOQ_MAX_FULL_TRACK_NAME_LEN - msg->track_name_len)
    {
        return -XQC_EPARAM;
    }

    size_t payload_len =
        xqc_moq_track_namespace_tuple_encode_len_vi64(
            msg->track_namespace_suffix_num,
            msg->track_namespace_suffix)
        + xqc_moq_d18_int_len(msg->track_name_len) + msg->track_name_len;
    return xqc_moq_d18_frame_len(base->type(), payload_len);
}

xqc_int_t
xqc_moq_d18_publish_blocked_encode(xqc_moq_msg_base_t *base,
    uint8_t *buf, size_t cap)
{
    if (base == NULL || (cap > 0 && buf == NULL)) {
        return -XQC_EPARAM;
    }
    xqc_int_t frame_len = xqc_moq_d18_publish_blocked_encode_len(base);
    if (frame_len < 0) {
        return frame_len;
    }
    if ((size_t)frame_len > cap) {
        return -XQC_ENOBUF;
    }
    xqc_moq_publish_blocked_msg_t *msg =
        (xqc_moq_publish_blocked_msg_t *)base;
    size_t header_len = xqc_moq_d18_int_len(base->type())
        + XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    uint8_t *pos = xqc_moq_d18_int_write(buf, base->type());
    pos = xqc_moq_d18_write_length(pos, (size_t)frame_len - header_len);
    pos = xqc_moq_track_namespace_tuple_encode_vi64(pos,
        msg->track_namespace_suffix_num, msg->track_namespace_suffix);
    pos = xqc_moq_d18_int_write(pos, msg->track_name_len);
    xqc_memcpy(pos, msg->track_name, msg->track_name_len);
    pos += msg->track_name_len;
    return (xqc_int_t)(pos - buf);
}

xqc_int_t
xqc_moq_d18_publish_blocked_decode(uint8_t *buf, size_t len, uint8_t fin,
    xqc_moq_decode_msg_ctx_t *ctx, xqc_moq_msg_base_t *base,
    xqc_int_t *finish, xqc_int_t *wait_more)
{
    if (base == NULL) {
        return -XQC_EPARAM;
    }
    xqc_moq_publish_blocked_msg_t *msg =
        (xqc_moq_publish_blocked_msg_t *)base;
    uint8_t ready = 0;
    xqc_int_t processed = xqc_moq_d18_buffer_payload(
        buf, len, fin, ctx, &msg->payload, &msg->payload_len,
        &msg->payload_processed, finish, wait_more, &ready);
    if (processed < 0 || !ready) {
        return processed;
    }

    const uint8_t *pos = msg->payload;
    const uint8_t *end = msg->payload + msg->payload_len;
    if (xqc_moq_d18_read_vi64(&pos, end,
            &msg->track_namespace_suffix_num) != XQC_OK)
    {
        return -XQC_EILLEGAL_FRAME;
    }
    if (msg->track_namespace_suffix_num
        > XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS)
    {
        return -XQC_EPROTO;
    }
    if (msg->track_namespace_suffix_num > 0) {
        msg->track_namespace_suffix = xqc_calloc(
            msg->track_namespace_suffix_num,
            sizeof(*msg->track_namespace_suffix));
        if (msg->track_namespace_suffix == NULL) {
            return -XQC_EMALLOC;
        }
    }

    size_t namespace_len = 0;
    for (uint64_t i = 0; i < msg->track_namespace_suffix_num; i++) {
        uint64_t field_len = 0;
        if (xqc_moq_d18_read_vi64(&pos, end, &field_len) != XQC_OK) {
            return -XQC_EILLEGAL_FRAME;
        }
        if (field_len == 0 || field_len > XQC_MOQ_MAX_NAME_LEN
            || namespace_len
                > XQC_MOQ_MAX_FULL_TRACK_NAME_LEN - field_len)
        {
            return -XQC_EPROTO;
        }
        if ((uint64_t)(end - pos) < field_len) {
            return -XQC_EILLEGAL_FRAME;
        }
        msg->track_namespace_suffix[i].data = xqc_malloc(field_len);
        if (msg->track_namespace_suffix[i].data == NULL) {
            return -XQC_EMALLOC;
        }
        msg->track_namespace_suffix[i].len = (size_t)field_len;
        xqc_memcpy(msg->track_namespace_suffix[i].data, pos, field_len);
        pos += field_len;
        namespace_len += (size_t)field_len;
    }

    uint64_t track_name_len = 0;
    if (xqc_moq_d18_read_vi64(&pos, end, &track_name_len) != XQC_OK) {
        return -XQC_EILLEGAL_FRAME;
    }
    if (track_name_len == 0 || track_name_len > XQC_MOQ_MAX_NAME_LEN
        || namespace_len
            > XQC_MOQ_MAX_FULL_TRACK_NAME_LEN - track_name_len)
    {
        return -XQC_EPROTO;
    }
    if ((uint64_t)(end - pos) < track_name_len) {
        return -XQC_EILLEGAL_FRAME;
    }
    msg->track_name = xqc_calloc(1, (size_t)track_name_len + 1);
    if (msg->track_name == NULL) {
        return -XQC_EMALLOC;
    }
    msg->track_name_len = (size_t)track_name_len;
    xqc_memcpy(msg->track_name, pos, msg->track_name_len);
    pos += msg->track_name_len;
    if (pos != end) {
        return -XQC_EILLEGAL_FRAME;
    }
    xqc_moq_d18_payload_complete(&msg->payload, &msg->payload_len,
        &msg->payload_processed, ctx, finish);
    return processed;
}

void *
xqc_moq_d18_publish_done_create(void)
{
    xqc_moq_d18_publish_done_storage_t *storage =
        xqc_calloc(1, sizeof(*storage));
    if (storage != NULL) {
        xqc_moq_d18_publish_done_init_handler(&storage->msg.msg_base);
    }
    return storage;
}

void
xqc_moq_d18_publish_done_clear(xqc_moq_publish_done_msg_t *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_d18_publish_done_storage_t *storage =
        (xqc_moq_d18_publish_done_storage_t *)msg;
    xqc_free(msg->reason_phrase);
    msg->reason_phrase = NULL;
    msg->reason_phrase_len = 0;
    xqc_free(storage->payload);
    storage->payload = NULL;
    storage->payload_len = 0;
    storage->payload_processed = 0;
}

void
xqc_moq_d18_publish_done_free(void *msg)
{
    xqc_moq_publish_done_msg_t *done = msg;
    if (done != NULL) {
        xqc_moq_d18_publish_done_clear(done);
        xqc_free(done);
    }
}

void
xqc_moq_d18_publish_done_init_handler(xqc_moq_msg_base_t *base)
{
    *base = xqc_moq_d18_publish_done_base;
}

xqc_int_t
xqc_moq_d18_publish_done_encode_len(xqc_moq_msg_base_t *base)
{
    if (base == NULL) {
        return -XQC_EPARAM;
    }
    xqc_moq_publish_done_msg_t *msg =
        (xqc_moq_publish_done_msg_t *)base;
    if (msg->stream_count > XQC_MOQ_D18_MAX_STREAM_COUNT
        || msg->reason_phrase_len > XQC_MOQ_MAX_REASON_PHRASE_LEN
        || (msg->reason_phrase_len > 0 && msg->reason_phrase == NULL)
        || !xqc_moq_d18_utf8_valid(
            (const uint8_t *)msg->reason_phrase, msg->reason_phrase_len))
    {
        return -XQC_EPARAM;
    }
    size_t payload_len = xqc_moq_d18_int_len(msg->status_code)
        + xqc_moq_d18_int_len(msg->stream_count)
        + xqc_moq_d18_int_len(msg->reason_phrase_len)
        + msg->reason_phrase_len;
    return xqc_moq_d18_frame_len(base->type(), payload_len);
}

xqc_int_t
xqc_moq_d18_publish_done_encode(xqc_moq_msg_base_t *base,
    uint8_t *buf, size_t cap)
{
    if (base == NULL || (cap > 0 && buf == NULL)) {
        return -XQC_EPARAM;
    }
    xqc_int_t frame_len = xqc_moq_d18_publish_done_encode_len(base);
    if (frame_len < 0) {
        return frame_len;
    }
    if ((size_t)frame_len > cap) {
        return -XQC_ENOBUF;
    }
    xqc_moq_publish_done_msg_t *msg =
        (xqc_moq_publish_done_msg_t *)base;
    size_t header_len = xqc_moq_d18_int_len(base->type())
        + XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    uint8_t *pos = xqc_moq_d18_int_write(buf, base->type());
    pos = xqc_moq_d18_write_length(pos, (size_t)frame_len - header_len);
    pos = xqc_moq_d18_int_write(pos, msg->status_code);
    pos = xqc_moq_d18_int_write(pos, msg->stream_count);
    pos = xqc_moq_d18_int_write(pos, msg->reason_phrase_len);
    if (msg->reason_phrase_len > 0) {
        xqc_memcpy(pos, msg->reason_phrase, msg->reason_phrase_len);
        pos += msg->reason_phrase_len;
    }
    return (xqc_int_t)(pos - buf);
}

xqc_int_t
xqc_moq_d18_publish_done_decode(uint8_t *buf, size_t len, uint8_t fin,
    xqc_moq_decode_msg_ctx_t *ctx, xqc_moq_msg_base_t *base,
    xqc_int_t *finish, xqc_int_t *wait_more)
{
    if (base == NULL) {
        return -XQC_EPARAM;
    }
    xqc_moq_d18_publish_done_storage_t *storage =
        (xqc_moq_d18_publish_done_storage_t *)base;
    xqc_moq_publish_done_msg_t *msg = &storage->msg;
    uint8_t ready = 0;
    xqc_int_t processed = xqc_moq_d18_buffer_payload(
        buf, len, fin, ctx, &storage->payload, &storage->payload_len,
        &storage->payload_processed, finish, wait_more, &ready);
    if (processed < 0 || !ready) {
        return processed;
    }

    const uint8_t *pos = storage->payload;
    const uint8_t *end = storage->payload + storage->payload_len;
    uint64_t reason_len = 0;
    if (xqc_moq_d18_read_vi64(&pos, end, &msg->status_code) != XQC_OK
        || xqc_moq_d18_read_vi64(&pos, end, &msg->stream_count) != XQC_OK
        || xqc_moq_d18_read_vi64(&pos, end, &reason_len) != XQC_OK)
    {
        return -XQC_EILLEGAL_FRAME;
    }
    if (msg->stream_count > XQC_MOQ_D18_MAX_STREAM_COUNT
        || reason_len > XQC_MOQ_MAX_REASON_PHRASE_LEN)
    {
        return -XQC_EPROTO;
    }
    if ((uint64_t)(end - pos) < reason_len) {
        return -XQC_EILLEGAL_FRAME;
    }
    if (!xqc_moq_d18_utf8_valid(pos, (size_t)reason_len)) {
        return -XQC_EPROTO;
    }
    msg->reason_phrase = xqc_calloc(1, (size_t)reason_len + 1);
    if (msg->reason_phrase == NULL) {
        return -XQC_EMALLOC;
    }
    msg->reason_phrase_len = (size_t)reason_len;
    if (reason_len > 0) {
        xqc_memcpy(msg->reason_phrase, pos, (size_t)reason_len);
        pos += reason_len;
    }
    if (pos != end) {
        return -XQC_EILLEGAL_FRAME;
    }
    xqc_moq_d18_payload_complete(&storage->payload, &storage->payload_len,
        &storage->payload_processed, ctx, finish);
    return processed;
}

void *
xqc_moq_d18_goaway_create(void)
{
    xqc_moq_d18_goaway_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    if (msg != NULL) {
        xqc_moq_d18_request_goaway_init_handler(&msg->msg_base);
    }
    return msg;
}

void
xqc_moq_d18_goaway_clear(xqc_moq_d18_goaway_msg_t *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_free(msg->new_session_uri);
    msg->new_session_uri = NULL;
    msg->new_session_uri_len = 0;
    xqc_free(msg->payload);
    msg->payload = NULL;
    msg->payload_len = 0;
    msg->payload_processed = 0;
}

void
xqc_moq_d18_goaway_free(void *msg)
{
    xqc_moq_d18_goaway_msg_t *goaway = msg;
    if (goaway != NULL) {
        xqc_moq_d18_goaway_clear(goaway);
        xqc_free(goaway);
    }
}

void
xqc_moq_d18_control_goaway_init_handler(xqc_moq_msg_base_t *base)
{
    xqc_moq_d18_goaway_msg_t *msg = (xqc_moq_d18_goaway_msg_t *)base;
    *base = xqc_moq_d18_goaway_base;
    msg->has_request_id = 1;
}

void
xqc_moq_d18_request_goaway_init_handler(xqc_moq_msg_base_t *base)
{
    xqc_moq_d18_goaway_msg_t *msg = (xqc_moq_d18_goaway_msg_t *)base;
    *base = xqc_moq_d18_goaway_base;
    msg->has_request_id = 0;
}

xqc_int_t
xqc_moq_d18_goaway_encode_len(xqc_moq_msg_base_t *base)
{
    if (base == NULL) {
        return -XQC_EPARAM;
    }
    xqc_moq_d18_goaway_msg_t *msg = (xqc_moq_d18_goaway_msg_t *)base;
    if (msg->has_request_id > 1
        || msg->new_session_uri_len > XQC_MOQ_MAX_GOAWAY_URI_LEN
        || (msg->new_session_uri_len > 0 && msg->new_session_uri == NULL))
    {
        return -XQC_EPARAM;
    }
    size_t payload_len = xqc_moq_d18_int_len(msg->new_session_uri_len)
        + msg->new_session_uri_len + xqc_moq_d18_int_len(msg->timeout_ms);
    if (msg->has_request_id) {
        payload_len += xqc_moq_d18_int_len(msg->request_id);
    }
    return xqc_moq_d18_frame_len(base->type(), payload_len);
}

xqc_int_t
xqc_moq_d18_goaway_encode(xqc_moq_msg_base_t *base,
    uint8_t *buf, size_t cap)
{
    if (base == NULL || (cap > 0 && buf == NULL)) {
        return -XQC_EPARAM;
    }
    xqc_int_t frame_len = xqc_moq_d18_goaway_encode_len(base);
    if (frame_len < 0) {
        return frame_len;
    }
    if ((size_t)frame_len > cap) {
        return -XQC_ENOBUF;
    }
    xqc_moq_d18_goaway_msg_t *msg = (xqc_moq_d18_goaway_msg_t *)base;
    size_t header_len = xqc_moq_d18_int_len(base->type())
        + XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    uint8_t *pos = xqc_moq_d18_int_write(buf, base->type());
    pos = xqc_moq_d18_write_length(pos, (size_t)frame_len - header_len);
    pos = xqc_moq_d18_int_write(pos, msg->new_session_uri_len);
    if (msg->new_session_uri_len > 0) {
        xqc_memcpy(pos, msg->new_session_uri, msg->new_session_uri_len);
        pos += msg->new_session_uri_len;
    }
    pos = xqc_moq_d18_int_write(pos, msg->timeout_ms);
    if (msg->has_request_id) {
        pos = xqc_moq_d18_int_write(pos, msg->request_id);
    }
    return (xqc_int_t)(pos - buf);
}

xqc_int_t
xqc_moq_d18_goaway_decode(uint8_t *buf, size_t len, uint8_t fin,
    xqc_moq_decode_msg_ctx_t *ctx, xqc_moq_msg_base_t *base,
    xqc_int_t *finish, xqc_int_t *wait_more)
{
    if (base == NULL) {
        return -XQC_EPARAM;
    }
    xqc_moq_d18_goaway_msg_t *msg = (xqc_moq_d18_goaway_msg_t *)base;
    uint8_t ready = 0;
    xqc_int_t processed = xqc_moq_d18_buffer_payload(
        buf, len, fin, ctx, &msg->payload, &msg->payload_len,
        &msg->payload_processed, finish, wait_more, &ready);
    if (processed < 0 || !ready) {
        return processed;
    }

    const uint8_t *pos = msg->payload;
    const uint8_t *end = msg->payload + msg->payload_len;
    uint64_t uri_len = 0;
    if (xqc_moq_d18_read_vi64(&pos, end, &uri_len) != XQC_OK) {
        return -XQC_EILLEGAL_FRAME;
    }
    if (uri_len > XQC_MOQ_MAX_GOAWAY_URI_LEN) {
        return -XQC_EPROTO;
    }
    if ((uint64_t)(end - pos) < uri_len) {
        return -XQC_EILLEGAL_FRAME;
    }
    msg->new_session_uri = xqc_calloc(1, (size_t)uri_len + 1);
    if (msg->new_session_uri == NULL) {
        return -XQC_EMALLOC;
    }
    msg->new_session_uri_len = (size_t)uri_len;
    if (uri_len > 0) {
        xqc_memcpy(msg->new_session_uri, pos, (size_t)uri_len);
        pos += uri_len;
    }
    if (xqc_moq_d18_read_vi64(&pos, end, &msg->timeout_ms) != XQC_OK) {
        return -XQC_EILLEGAL_FRAME;
    }
    if (msg->has_request_id
        && xqc_moq_d18_read_vi64(&pos, end, &msg->request_id) != XQC_OK)
    {
        return -XQC_EILLEGAL_FRAME;
    }
    if (pos != end) {
        return -XQC_EILLEGAL_FRAME;
    }
    xqc_moq_d18_payload_complete(&msg->payload, &msg->payload_len,
        &msg->payload_processed, ctx, finish);
    return processed;
}

static xqc_moq_msg_type_t
xqc_moq_d18_fetch_type(void)
{
    return (xqc_moq_msg_type_t)XQC_MOQ_D18_MSG_FETCH;
}

static xqc_moq_msg_type_t
xqc_moq_d18_fetch_ok_type(void)
{
    return (xqc_moq_msg_type_t)XQC_MOQ_D18_MSG_FETCH_OK;
}

static xqc_moq_msg_type_t
xqc_moq_d18_track_status_type(void)
{
    return (xqc_moq_msg_type_t)XQC_MOQ_D18_MSG_TRACK_STATUS;
}

static const xqc_moq_msg_base_t xqc_moq_d18_fetch_base = {
    .type = xqc_moq_d18_fetch_type,
    .encode_len = xqc_moq_d18_fetch_encode_len,
    .encode = xqc_moq_d18_fetch_encode,
    .decode = xqc_moq_d18_fetch_decode,
    .on_msg = xqc_moq_on_fetch,
};

static const xqc_moq_msg_base_t xqc_moq_d18_fetch_ok_base = {
    .type = xqc_moq_d18_fetch_ok_type,
    .encode_len = xqc_moq_d18_fetch_ok_encode_len,
    .encode = xqc_moq_d18_fetch_ok_encode,
    .decode = xqc_moq_d18_fetch_ok_decode,
    .on_msg = xqc_moq_on_fetch_ok,
};

static const xqc_moq_msg_base_t xqc_moq_d18_track_status_base = {
    .type = xqc_moq_d18_track_status_type,
    .encode_len = xqc_moq_d18_track_status_encode_len,
    .encode = xqc_moq_d18_track_status_encode,
    .decode = xqc_moq_d18_track_status_decode,
    .on_msg = xqc_moq_on_track_status,
};

static xqc_moq_msg_type_t
xqc_moq_d18_fetch_header_type(void)
{
    return (xqc_moq_msg_type_t)XQC_MOQ_D18_STREAM_TYPE_FETCH;
}

static const xqc_moq_msg_base_t xqc_moq_d18_fetch_header_base = {
    .type = xqc_moq_d18_fetch_header_type,
    .encode_len = xqc_moq_d18_fetch_header_encode_len,
    .encode = xqc_moq_d18_fetch_header_encode,
    .decode = xqc_moq_d18_fetch_header_decode,
    .on_msg = xqc_moq_on_fetch_header,
};

static xqc_int_t
xqc_moq_d18_params_len(xqc_moq_d18_param_context_t context,
    const xqc_moq_message_parameter_t *params, uint64_t params_num,
    size_t *encoded_len)
{
    if (params_num > XQC_MOQ_MAX_PARAMS || encoded_len == NULL) {
        return -XQC_EPARAM;
    }
    return xqc_moq_d18_params_encoded_len(
        context, params, (size_t)params_num, encoded_len)
        == XQC_MOQ_D18_PARAM_OK ? XQC_OK : -XQC_EPARAM;
}

static xqc_int_t
xqc_moq_d18_params_write(uint8_t **pos, const uint8_t *end,
    xqc_moq_d18_param_context_t context,
    const xqc_moq_message_parameter_t *params, uint64_t params_num)
{
    return xqc_moq_d18_params_encode(
        pos, end, context, params, (size_t)params_num)
        == XQC_MOQ_D18_PARAM_OK ? XQC_OK : -XQC_EPARAM;
}

static xqc_int_t
xqc_moq_d18_params_read(const uint8_t **pos, const uint8_t *end,
    xqc_moq_d18_param_context_t context, uint64_t params_num,
    xqc_moq_message_parameter_t **params)
{
    if (params == NULL || params_num > XQC_MOQ_MAX_PARAMS) {
        return -XQC_EILLEGAL_FRAME;
    }
    if (params_num == 0) {
        *params = NULL;
        return XQC_OK;
    }
    *params = xqc_moq_msg_alloc_params((xqc_int_t)params_num);
    if (*params == NULL) {
        return -XQC_EMALLOC;
    }
    xqc_moq_d18_param_result_t result = xqc_moq_d18_params_decode(
        pos, end, context, *params, (size_t)params_num);
    if (result == XQC_MOQ_D18_PARAM_OK) {
        return XQC_OK;
    }
    if (result == XQC_MOQ_D18_PARAM_NO_MEMORY) {
        return -XQC_EMALLOC;
    }
    return result == XQC_MOQ_D18_PARAM_FORMATTING
        ? -XQC_EILLEGAL_FRAME : -XQC_EPROTO;
}

static xqc_int_t
xqc_moq_d18_read_full_track_name(const uint8_t **pos, const uint8_t *end,
    uint64_t *namespace_num, xqc_moq_track_ns_field_t **namespace_tuple,
    char **track_name, size_t *track_name_len)
{
    uint64_t count = 0;
    if (xqc_moq_d18_read_vi64(pos, end, &count) != XQC_OK
        || count == 0 || count > XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS)
    {
        return -XQC_EILLEGAL_FRAME;
    }
    xqc_moq_track_ns_field_t *tuple = xqc_calloc(count, sizeof(*tuple));
    if (tuple == NULL) {
        return -XQC_EMALLOC;
    }
    size_t full_len = 0;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t field_len = 0;
        if (xqc_moq_d18_read_vi64(pos, end, &field_len) != XQC_OK
            || field_len == 0 || field_len > XQC_MOQ_MAX_NAME_LEN
            || (uint64_t)(end - *pos) < field_len
            || full_len > XQC_MOQ_MAX_FULL_TRACK_NAME_LEN - field_len)
        {
            xqc_moq_namespace_tuple_free(tuple, count);
            return -XQC_EILLEGAL_FRAME;
        }
        tuple[i].data = xqc_malloc((size_t)field_len);
        if (tuple[i].data == NULL) {
            xqc_moq_namespace_tuple_free(tuple, count);
            return -XQC_EMALLOC;
        }
        tuple[i].len = (size_t)field_len;
        xqc_memcpy(tuple[i].data, *pos, (size_t)field_len);
        *pos += field_len;
        full_len += (size_t)field_len;
    }

    uint64_t name_len = 0;
    if (xqc_moq_d18_read_vi64(pos, end, &name_len) != XQC_OK
        || name_len > XQC_MOQ_MAX_NAME_LEN
        || (uint64_t)(end - *pos) < name_len
        || full_len > XQC_MOQ_MAX_FULL_TRACK_NAME_LEN - name_len)
    {
        xqc_moq_namespace_tuple_free(tuple, count);
        return -XQC_EILLEGAL_FRAME;
    }
    char *name = xqc_calloc(1, (size_t)name_len + 1);
    if (name == NULL) {
        xqc_moq_namespace_tuple_free(tuple, count);
        return -XQC_EMALLOC;
    }
    if (name_len > 0) {
        xqc_memcpy(name, *pos, (size_t)name_len);
        *pos += name_len;
    }
    *namespace_num = count;
    *namespace_tuple = tuple;
    *track_name = name;
    *track_name_len = (size_t)name_len;
    return XQC_OK;
}

static xqc_int_t
xqc_moq_d18_full_track_name_len(uint64_t namespace_num,
    const xqc_moq_track_ns_field_t *namespace_tuple,
    const char *track_name, size_t track_name_len, size_t *encoded_len)
{
    size_t namespace_len = 0;
    if (namespace_num == 0 || track_name_len > XQC_MOQ_MAX_NAME_LEN
        || (track_name_len > 0 && track_name == NULL)
        || xqc_moq_d18_validate_namespace(
            namespace_num, namespace_tuple, &namespace_len) != XQC_OK
        || namespace_len > XQC_MOQ_MAX_FULL_TRACK_NAME_LEN - track_name_len)
    {
        return -XQC_EPARAM;
    }
    xqc_int_t tuple_len = xqc_moq_track_namespace_tuple_encode_len_vi64(
        namespace_num, namespace_tuple);
    if (tuple_len < 0) {
        return tuple_len;
    }
    *encoded_len = (size_t)tuple_len + xqc_moq_d18_int_len(track_name_len)
        + track_name_len;
    return XQC_OK;
}

static uint8_t *
xqc_moq_d18_write_full_track_name(uint8_t *pos, uint64_t namespace_num,
    const xqc_moq_track_ns_field_t *namespace_tuple,
    const char *track_name, size_t track_name_len)
{
    pos = xqc_moq_track_namespace_tuple_encode_vi64(
        pos, namespace_num, namespace_tuple);
    pos = xqc_moq_d18_int_write(pos, track_name_len);
    if (track_name_len > 0) {
        xqc_memcpy(pos, track_name, track_name_len);
        pos += track_name_len;
    }
    return pos;
}

void *
xqc_moq_d18_fetch_create(void)
{
    xqc_moq_fetch_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    if (msg != NULL) {
        xqc_moq_d18_fetch_init_handler(&msg->msg_base);
    }
    return msg;
}

void
xqc_moq_d18_fetch_free(void *ptr)
{
    xqc_moq_fetch_msg_t *msg = ptr;
    if (msg == NULL) {
        return;
    }
    xqc_moq_namespace_tuple_free(
        msg->track_namespace_tuple, msg->track_namespace_num);
    xqc_free(msg->track_name);
    xqc_moq_msg_free_params(msg->params, (xqc_int_t)msg->params_num);
    xqc_free(msg->payload);
    xqc_free(msg);
}

void
xqc_moq_d18_fetch_init_handler(xqc_moq_msg_base_t *base)
{
    *base = xqc_moq_d18_fetch_base;
}

xqc_int_t
xqc_moq_d18_fetch_encode_len(xqc_moq_msg_base_t *base)
{
    if (base == NULL) {
        return -XQC_EPARAM;
    }
    xqc_moq_fetch_msg_t *msg = (xqc_moq_fetch_msg_t *)base;
    size_t params_len = 0;
    if (msg->fetch_type < XQC_MOQ_FETCH_STANDALONE
        || msg->fetch_type > XQC_MOQ_FETCH_JOINING_ABSOLUTE
        || xqc_moq_d18_params_len(XQC_MOQ_D18_PARAM_CONTEXT_FETCH,
            msg->params, msg->params_num, &params_len) != XQC_OK)
    {
        return -XQC_EPARAM;
    }
    size_t payload_len = xqc_moq_d18_int_len(msg->request_id)
        + xqc_moq_d18_int_len(msg->fetch_type);
    if (msg->fetch_type == XQC_MOQ_FETCH_STANDALONE) {
        size_t name_len = 0;
        if (xqc_moq_d18_full_track_name_len(
                msg->track_namespace_num, msg->track_namespace_tuple,
                msg->track_name, msg->track_name_len, &name_len) != XQC_OK)
        {
            return -XQC_EPARAM;
        }
        payload_len += name_len
            + xqc_moq_d18_int_len(msg->start_group_id)
            + xqc_moq_d18_int_len(msg->start_object_id)
            + xqc_moq_d18_int_len(msg->end_group_id)
            + xqc_moq_d18_int_len(msg->end_object_id);
    } else {
        payload_len += xqc_moq_d18_int_len(msg->joining_request_id)
            + xqc_moq_d18_int_len(msg->joining_start);
    }
    payload_len += xqc_moq_d18_int_len(msg->params_num) + params_len;
    return xqc_moq_d18_frame_len(
        (xqc_moq_msg_type_t)XQC_MOQ_D18_MSG_FETCH, payload_len);
}

xqc_int_t
xqc_moq_d18_fetch_encode(xqc_moq_msg_base_t *base,
    uint8_t *buf, size_t cap)
{
    xqc_int_t length = xqc_moq_d18_fetch_encode_len(base);
    if (length < 0 || (size_t)length > cap || (length > 0 && buf == NULL)) {
        return length < 0 ? length : -XQC_EILLEGAL_FRAME;
    }
    xqc_moq_fetch_msg_t *msg = (xqc_moq_fetch_msg_t *)base;
    uint8_t *pos = xqc_moq_d18_int_write(buf, XQC_MOQ_D18_MSG_FETCH);
    size_t payload_len = (size_t)length - (size_t)(pos - buf)
        - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    pos = xqc_moq_d18_write_length(pos, payload_len);
    pos = xqc_moq_d18_int_write(pos, msg->request_id);
    pos = xqc_moq_d18_int_write(pos, msg->fetch_type);
    if (msg->fetch_type == XQC_MOQ_FETCH_STANDALONE) {
        pos = xqc_moq_d18_write_full_track_name(pos,
            msg->track_namespace_num, msg->track_namespace_tuple,
            msg->track_name, msg->track_name_len);
        pos = xqc_moq_d18_int_write(pos, msg->start_group_id);
        pos = xqc_moq_d18_int_write(pos, msg->start_object_id);
        pos = xqc_moq_d18_int_write(pos, msg->end_group_id);
        pos = xqc_moq_d18_int_write(pos, msg->end_object_id);
    } else {
        pos = xqc_moq_d18_int_write(pos, msg->joining_request_id);
        pos = xqc_moq_d18_int_write(pos, msg->joining_start);
    }
    pos = xqc_moq_d18_int_write(pos, msg->params_num);
    xqc_int_t ret = xqc_moq_d18_params_write(&pos, buf + cap,
        XQC_MOQ_D18_PARAM_CONTEXT_FETCH, msg->params, msg->params_num);
    return ret == XQC_OK ? (xqc_int_t)(pos - buf) : ret;
}

xqc_int_t
xqc_moq_d18_fetch_decode(uint8_t *buf, size_t len, uint8_t fin,
    xqc_moq_decode_msg_ctx_t *ctx, xqc_moq_msg_base_t *base,
    xqc_int_t *finish, xqc_int_t *wait_more)
{
    xqc_moq_fetch_msg_t *msg = (xqc_moq_fetch_msg_t *)base;
    uint8_t ready = 0;
    xqc_int_t processed = xqc_moq_d18_buffer_payload(
        buf, len, fin, ctx, &msg->payload, &msg->payload_len,
        &msg->payload_processed, finish, wait_more, &ready);
    if (processed < 0 || !ready) {
        return processed;
    }
    const uint8_t *pos = msg->payload;
    const uint8_t *end = pos + msg->payload_len;
    uint64_t fetch_type = 0;
    xqc_int_t ret = xqc_moq_d18_read_vi64(&pos, end, &msg->request_id);
    if (ret != XQC_OK
        || xqc_moq_d18_read_vi64(&pos, end, &fetch_type) != XQC_OK
        || fetch_type < XQC_MOQ_FETCH_STANDALONE
        || fetch_type > XQC_MOQ_FETCH_JOINING_ABSOLUTE)
    {
        return -XQC_EILLEGAL_FRAME;
    }
    msg->fetch_type = (xqc_moq_fetch_type_t)fetch_type;
    if (msg->fetch_type == XQC_MOQ_FETCH_STANDALONE) {
        ret = xqc_moq_d18_read_full_track_name(&pos, end,
            &msg->track_namespace_num, &msg->track_namespace_tuple,
            &msg->track_name, &msg->track_name_len);
        if (ret != XQC_OK
            || xqc_moq_d18_read_vi64(&pos, end, &msg->start_group_id) != XQC_OK
            || xqc_moq_d18_read_vi64(&pos, end, &msg->start_object_id) != XQC_OK
            || xqc_moq_d18_read_vi64(&pos, end, &msg->end_group_id) != XQC_OK
            || xqc_moq_d18_read_vi64(&pos, end, &msg->end_object_id) != XQC_OK)
        {
            return ret != XQC_OK ? ret : -XQC_EILLEGAL_FRAME;
        }
    } else if (xqc_moq_d18_read_vi64(
                   &pos, end, &msg->joining_request_id) != XQC_OK
               || xqc_moq_d18_read_vi64(
                   &pos, end, &msg->joining_start) != XQC_OK)
    {
        return -XQC_EILLEGAL_FRAME;
    }
    if (xqc_moq_d18_read_vi64(&pos, end, &msg->params_num) != XQC_OK
        || msg->params_num > XQC_MOQ_MAX_PARAMS)
    {
        return -XQC_EILLEGAL_FRAME;
    }
    ret = xqc_moq_d18_params_read(&pos, end,
        XQC_MOQ_D18_PARAM_CONTEXT_FETCH, msg->params_num, &msg->params);
    if (ret != XQC_OK || pos != end) {
        return ret != XQC_OK ? ret : -XQC_EILLEGAL_FRAME;
    }
    xqc_moq_d18_payload_complete(&msg->payload, &msg->payload_len,
        &msg->payload_processed, ctx, finish);
    return processed;
}

void *
xqc_moq_d18_fetch_ok_create(void)
{
    xqc_moq_fetch_ok_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    if (msg != NULL) {
        xqc_moq_d18_fetch_ok_init_handler(&msg->msg_base);
    }
    return msg;
}

void
xqc_moq_d18_fetch_ok_free(void *ptr)
{
    xqc_moq_fetch_ok_msg_t *msg = ptr;
    if (msg == NULL) {
        return;
    }
    xqc_moq_msg_free_params(msg->params, (xqc_int_t)msg->params_num);
    xqc_free(msg->track_properties);
    xqc_free(msg->payload);
    xqc_free(msg);
}

void
xqc_moq_d18_fetch_ok_init_handler(xqc_moq_msg_base_t *base)
{
    *base = xqc_moq_d18_fetch_ok_base;
}

static xqc_int_t
xqc_moq_d18_track_properties_validate(const uint8_t *properties, size_t len)
{
    xqc_moq_d18_properties_t *parsed = NULL;
    xqc_moq_d18_property_result_t result = xqc_moq_d18_properties_parse(
        XQC_MOQ_D18_PROPERTY_SCOPE_TRACK, properties, len, &parsed);
    if (result != XQC_MOQ_D18_PROPERTY_OK) {
        return -XQC_EPARAM;
    }
    xqc_moq_d18_properties_destroy(parsed);
    return XQC_OK;
}

xqc_int_t
xqc_moq_d18_fetch_ok_encode_len(xqc_moq_msg_base_t *base)
{
    if (base == NULL) {
        return -XQC_EPARAM;
    }
    xqc_moq_fetch_ok_msg_t *msg = (xqc_moq_fetch_ok_msg_t *)base;
    size_t params_len = 0;
    if (msg->end_of_track > 1
        || xqc_moq_d18_params_len(XQC_MOQ_D18_PARAM_CONTEXT_FETCH_OK,
            msg->params, msg->params_num, &params_len) != XQC_OK
        || xqc_moq_d18_track_properties_validate(
            msg->track_properties, msg->track_properties_len) != XQC_OK)
    {
        return -XQC_EPARAM;
    }
    size_t payload_len = 1 + xqc_moq_d18_int_len(msg->end_group_id)
        + xqc_moq_d18_int_len(msg->end_object_id)
        + xqc_moq_d18_int_len(msg->params_num) + params_len
        + msg->track_properties_len;
    return xqc_moq_d18_frame_len(
        (xqc_moq_msg_type_t)XQC_MOQ_D18_MSG_FETCH_OK, payload_len);
}

xqc_int_t
xqc_moq_d18_fetch_ok_encode(xqc_moq_msg_base_t *base,
    uint8_t *buf, size_t cap)
{
    xqc_int_t length = xqc_moq_d18_fetch_ok_encode_len(base);
    if (length < 0 || (size_t)length > cap || (length > 0 && buf == NULL)) {
        return length < 0 ? length : -XQC_EILLEGAL_FRAME;
    }
    xqc_moq_fetch_ok_msg_t *msg = (xqc_moq_fetch_ok_msg_t *)base;
    uint8_t *pos = xqc_moq_d18_int_write(buf, XQC_MOQ_D18_MSG_FETCH_OK);
    size_t payload_len = (size_t)length - (size_t)(pos - buf)
        - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    pos = xqc_moq_d18_write_length(pos, payload_len);
    *pos++ = msg->end_of_track;
    pos = xqc_moq_d18_int_write(pos, msg->end_group_id);
    pos = xqc_moq_d18_int_write(pos, msg->end_object_id);
    pos = xqc_moq_d18_int_write(pos, msg->params_num);
    xqc_int_t ret = xqc_moq_d18_params_write(&pos, buf + cap,
        XQC_MOQ_D18_PARAM_CONTEXT_FETCH_OK, msg->params, msg->params_num);
    if (ret != XQC_OK) {
        return ret;
    }
    if (msg->track_properties_len > 0) {
        xqc_memcpy(pos, msg->track_properties, msg->track_properties_len);
        pos += msg->track_properties_len;
    }
    return (xqc_int_t)(pos - buf);
}

xqc_int_t
xqc_moq_d18_fetch_ok_decode(uint8_t *buf, size_t len, uint8_t fin,
    xqc_moq_decode_msg_ctx_t *ctx, xqc_moq_msg_base_t *base,
    xqc_int_t *finish, xqc_int_t *wait_more)
{
    xqc_moq_fetch_ok_msg_t *msg = (xqc_moq_fetch_ok_msg_t *)base;
    uint8_t ready = 0;
    xqc_int_t processed = xqc_moq_d18_buffer_payload(
        buf, len, fin, ctx, &msg->payload, &msg->payload_len,
        &msg->payload_processed, finish, wait_more, &ready);
    if (processed < 0 || !ready) {
        return processed;
    }
    const uint8_t *pos = msg->payload;
    const uint8_t *end = pos + msg->payload_len;
    if (pos == end || (*pos != 0 && *pos != 1)) {
        return -XQC_EILLEGAL_FRAME;
    }
    msg->end_of_track = *pos++;
    if (xqc_moq_d18_read_vi64(&pos, end, &msg->end_group_id) != XQC_OK
        || xqc_moq_d18_read_vi64(&pos, end, &msg->end_object_id) != XQC_OK
        || xqc_moq_d18_read_vi64(&pos, end, &msg->params_num) != XQC_OK
        || msg->params_num > XQC_MOQ_MAX_PARAMS)
    {
        return -XQC_EILLEGAL_FRAME;
    }
    xqc_int_t ret = xqc_moq_d18_params_read(&pos, end,
        XQC_MOQ_D18_PARAM_CONTEXT_FETCH_OK, msg->params_num, &msg->params);
    if (ret != XQC_OK) {
        return ret;
    }
    msg->track_properties_len = (size_t)(end - pos);
    if (xqc_moq_d18_track_properties_validate(
            pos, msg->track_properties_len) != XQC_OK)
    {
        return -XQC_EPROTO;
    }
    if (msg->track_properties_len > 0) {
        msg->track_properties = xqc_malloc(msg->track_properties_len);
        if (msg->track_properties == NULL) {
            return -XQC_EMALLOC;
        }
        xqc_memcpy(msg->track_properties, pos, msg->track_properties_len);
    }
    xqc_moq_d18_payload_complete(&msg->payload, &msg->payload_len,
        &msg->payload_processed, ctx, finish);
    return processed;
}

void *
xqc_moq_d18_track_status_create(void)
{
    xqc_moq_track_status_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    if (msg != NULL) {
        xqc_moq_d18_track_status_init_handler(&msg->msg_base);
    }
    return msg;
}

void
xqc_moq_d18_track_status_free(void *ptr)
{
    xqc_moq_track_status_msg_t *msg = ptr;
    if (msg == NULL) {
        return;
    }
    xqc_moq_namespace_tuple_free(
        msg->track_namespace_tuple, msg->track_namespace_num);
    xqc_free(msg->track_name);
    xqc_moq_msg_free_params(msg->params, (xqc_int_t)msg->params_num);
    xqc_free(msg->payload);
    xqc_free(msg);
}

void
xqc_moq_d18_track_status_init_handler(xqc_moq_msg_base_t *base)
{
    *base = xqc_moq_d18_track_status_base;
}

xqc_int_t
xqc_moq_d18_track_status_encode_len(xqc_moq_msg_base_t *base)
{
    if (base == NULL) {
        return -XQC_EPARAM;
    }
    xqc_moq_track_status_msg_t *msg = (xqc_moq_track_status_msg_t *)base;
    size_t name_len = 0;
    size_t params_len = 0;
    if (xqc_moq_d18_full_track_name_len(
            msg->track_namespace_num, msg->track_namespace_tuple,
            msg->track_name, msg->track_name_len, &name_len) != XQC_OK
        || xqc_moq_d18_params_len(XQC_MOQ_D18_PARAM_CONTEXT_TRACK_STATUS,
            msg->params, msg->params_num, &params_len) != XQC_OK)
    {
        return -XQC_EPARAM;
    }
    size_t payload_len = xqc_moq_d18_int_len(msg->request_id) + name_len
        + xqc_moq_d18_int_len(msg->params_num) + params_len;
    return xqc_moq_d18_frame_len(
        (xqc_moq_msg_type_t)XQC_MOQ_D18_MSG_TRACK_STATUS, payload_len);
}

xqc_int_t
xqc_moq_d18_track_status_encode(xqc_moq_msg_base_t *base,
    uint8_t *buf, size_t cap)
{
    xqc_int_t length = xqc_moq_d18_track_status_encode_len(base);
    if (length < 0 || (size_t)length > cap || (length > 0 && buf == NULL)) {
        return length < 0 ? length : -XQC_EILLEGAL_FRAME;
    }
    xqc_moq_track_status_msg_t *msg = (xqc_moq_track_status_msg_t *)base;
    uint8_t *pos = xqc_moq_d18_int_write(buf, XQC_MOQ_D18_MSG_TRACK_STATUS);
    size_t payload_len = (size_t)length - (size_t)(pos - buf)
        - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    pos = xqc_moq_d18_write_length(pos, payload_len);
    pos = xqc_moq_d18_int_write(pos, msg->request_id);
    pos = xqc_moq_d18_write_full_track_name(pos,
        msg->track_namespace_num, msg->track_namespace_tuple,
        msg->track_name, msg->track_name_len);
    pos = xqc_moq_d18_int_write(pos, msg->params_num);
    xqc_int_t ret = xqc_moq_d18_params_write(&pos, buf + cap,
        XQC_MOQ_D18_PARAM_CONTEXT_TRACK_STATUS,
        msg->params, msg->params_num);
    return ret == XQC_OK ? (xqc_int_t)(pos - buf) : ret;
}

xqc_int_t
xqc_moq_d18_track_status_decode(uint8_t *buf, size_t len, uint8_t fin,
    xqc_moq_decode_msg_ctx_t *ctx, xqc_moq_msg_base_t *base,
    xqc_int_t *finish, xqc_int_t *wait_more)
{
    xqc_moq_track_status_msg_t *msg = (xqc_moq_track_status_msg_t *)base;
    uint8_t ready = 0;
    xqc_int_t processed = xqc_moq_d18_buffer_payload(
        buf, len, fin, ctx, &msg->payload, &msg->payload_len,
        &msg->payload_processed, finish, wait_more, &ready);
    if (processed < 0 || !ready) {
        return processed;
    }
    const uint8_t *pos = msg->payload;
    const uint8_t *end = pos + msg->payload_len;
    xqc_int_t ret = xqc_moq_d18_read_vi64(&pos, end, &msg->request_id);
    if (ret != XQC_OK) {
        return ret;
    }
    ret = xqc_moq_d18_read_full_track_name(&pos, end,
        &msg->track_namespace_num, &msg->track_namespace_tuple,
        &msg->track_name, &msg->track_name_len);
    if (ret != XQC_OK
        || xqc_moq_d18_read_vi64(&pos, end, &msg->params_num) != XQC_OK
        || msg->params_num > XQC_MOQ_MAX_PARAMS)
    {
        return ret != XQC_OK ? ret : -XQC_EILLEGAL_FRAME;
    }
    ret = xqc_moq_d18_params_read(&pos, end,
        XQC_MOQ_D18_PARAM_CONTEXT_TRACK_STATUS,
        msg->params_num, &msg->params);
    if (ret != XQC_OK || pos != end) {
        return ret != XQC_OK ? ret : -XQC_EILLEGAL_FRAME;
    }
    xqc_moq_d18_payload_complete(&msg->payload, &msg->payload_len,
        &msg->payload_processed, ctx, finish);
    return processed;
}

void *
xqc_moq_d18_fetch_header_create(void)
{
    xqc_moq_fetch_header_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    if (msg != NULL) {
        xqc_moq_d18_fetch_header_init_handler(&msg->msg_base);
    }
    return msg;
}

void
xqc_moq_d18_fetch_header_free(void *msg)
{
    xqc_free(msg);
}

void
xqc_moq_d18_fetch_header_init_handler(xqc_moq_msg_base_t *base)
{
    *base = xqc_moq_d18_fetch_header_base;
}

xqc_int_t
xqc_moq_d18_fetch_header_encode_len(xqc_moq_msg_base_t *base)
{
    if (base == NULL) {
        return -XQC_EPARAM;
    }
    xqc_moq_fetch_header_msg_t *msg = (xqc_moq_fetch_header_msg_t *)base;
    return (xqc_int_t)(xqc_moq_d18_int_len(XQC_MOQ_D18_STREAM_TYPE_FETCH)
        + xqc_moq_d18_int_len(msg->request_id));
}

xqc_int_t
xqc_moq_d18_fetch_header_encode(xqc_moq_msg_base_t *base,
    uint8_t *buf, size_t cap)
{
    xqc_int_t length = xqc_moq_d18_fetch_header_encode_len(base);
    if (length < 0 || (size_t)length > cap || (length > 0 && buf == NULL)) {
        return length < 0 ? length : -XQC_ENOBUF;
    }
    xqc_moq_fetch_header_msg_t *msg = (xqc_moq_fetch_header_msg_t *)base;
    uint8_t *pos = xqc_moq_d18_int_write(buf, XQC_MOQ_D18_STREAM_TYPE_FETCH);
    pos = xqc_moq_d18_int_write(pos, msg->request_id);
    return (xqc_int_t)(pos - buf);
}

xqc_int_t
xqc_moq_d18_fetch_header_decode(uint8_t *buf, size_t len, uint8_t fin,
    xqc_moq_decode_msg_ctx_t *ctx, xqc_moq_msg_base_t *base,
    xqc_int_t *finish, xqc_int_t *wait_more)
{
    (void)ctx;
    if (base == NULL || finish == NULL || wait_more == NULL
        || (len > 0 && buf == NULL))
    {
        return -XQC_EPARAM;
    }
    *finish = 0;
    *wait_more = 0;
    xqc_moq_fetch_header_msg_t *msg = (xqc_moq_fetch_header_msg_t *)base;
    xqc_int_t ret = xqc_moq_d18_int_read(buf, buf + len, &msg->request_id);
    if (ret < 0) {
        if (fin) {
            return -XQC_EILLEGAL_FRAME;
        }
        *wait_more = 1;
        return 0;
    }
    msg->fin_received = fin && (size_t)ret == len;
    *finish = 1;
    return ret;
}
