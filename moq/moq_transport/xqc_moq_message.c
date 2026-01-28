#include "moq/moq_transport/xqc_moq_message.h"
#include "moq/moq_transport/xqc_moq_message_handler.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"

static xqc_moq_msg_func_map_t moq_msg_func_map[] = {
    {XQC_MOQ_MSG_OBJECT_STREAM,        xqc_moq_msg_create_object_stream,    xqc_moq_msg_free_object_stream   },
    {XQC_MOQ_MSG_SUBGROUP,             xqc_moq_msg_create_subgroup,         xqc_moq_msg_free_subgroup        },
//    {XQC_MOQ_MSG_OBJECT_DATAGRAM,      NULL,                                NULL                             },
    {XQC_MOQ_MSG_SUBSCRIBE_UPDATE,     xqc_moq_msg_create_subscribe_update, xqc_moq_msg_free_subscribe_update},
    {XQC_MOQ_MSG_SUBSCRIBE,            xqc_moq_msg_create_subscribe,        xqc_moq_msg_free_subscribe       },
    {XQC_MOQ_MSG_SUBSCRIBE_OK,         xqc_moq_msg_create_subscribe_ok,     xqc_moq_msg_free_subscribe_ok    },
    {XQC_MOQ_MSG_SUBSCRIBE_ERROR,      xqc_moq_msg_create_subscribe_error,  xqc_moq_msg_free_subscribe_error },
    {XQC_MOQ_MSG_UNSUBSCRIBE,          xqc_moq_msg_create_unsubscribe,      xqc_moq_msg_free_unsubscribe     },
    {XQC_MOQ_MSG_PUBLISH,              xqc_moq_msg_create_publish,          xqc_moq_msg_free_publish         },
    {XQC_MOQ_MSG_PUBLISH_OK,           xqc_moq_msg_create_publish_ok,       xqc_moq_msg_free_publish_ok      },
    {XQC_MOQ_MSG_PUBLISH_ERROR,        xqc_moq_msg_create_publish_error,    xqc_moq_msg_free_publish_error   },
    {XQC_MOQ_MSG_PUBLISH_DONE,         xqc_moq_msg_create_publish_done,     xqc_moq_msg_free_publish_done    },
    {XQC_MOQ_MSG_PUBLISH_NAMESPACE,        xqc_moq_msg_create_publish_namespace,
                                          xqc_moq_msg_free_publish_namespace },
    {XQC_MOQ_MSG_PUBLISH_NAMESPACE_OK,     xqc_moq_msg_create_publish_namespace_ok,
                                          xqc_moq_msg_free_publish_namespace_ok },
    {XQC_MOQ_MSG_PUBLISH_NAMESPACE_ERROR,  xqc_moq_msg_create_publish_namespace_error,
                                          xqc_moq_msg_free_publish_namespace_error },
    {XQC_MOQ_MSG_PUBLISH_NAMESPACE_DONE,   xqc_moq_msg_create_publish_namespace_done,
                                          xqc_moq_msg_free_publish_namespace_done },
    {XQC_MOQ_MSG_PUBLISH_NAMESPACE_CANCEL, xqc_moq_msg_create_publish_namespace_cancel,
                                          xqc_moq_msg_free_publish_namespace_cancel },
    {XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE,       xqc_moq_msg_create_subscribe_namespace,
                                           xqc_moq_msg_free_subscribe_namespace },
    {XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE_OK,    xqc_moq_msg_create_subscribe_namespace_ok,
                                           xqc_moq_msg_free_subscribe_namespace_ok },
    {XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE_ERROR, xqc_moq_msg_create_subscribe_namespace_error,
                                           xqc_moq_msg_free_subscribe_namespace_error },
    {XQC_MOQ_MSG_UNSUBSCRIBE_NAMESPACE,     xqc_moq_msg_create_unsubscribe_namespace,
                                           xqc_moq_msg_free_unsubscribe_namespace },
//    {XQC_MOQ_MSG_TRACK_STATUS_REQUEST, NULL,                                NULL                             },
//    {XQC_MOQ_MSG_TRACK_STATUS,         NULL,                                NULL                             },
//    {XQC_MOQ_MSG_GOAWAY,               NULL,                                NULL                             },
    {XQC_MOQ_MSG_CLIENT_SETUP_V14,     xqc_moq_msg_create_client_setup_v14, xqc_moq_msg_free_client_setup_v14},
    {XQC_MOQ_MSG_SERVER_SETUP_V14,     xqc_moq_msg_create_server_setup_v14, xqc_moq_msg_free_server_setup_v14},
    {XQC_MOQ_MSG_CLIENT_SETUP,         xqc_moq_msg_create_client_setup,     xqc_moq_msg_free_client_setup    },
    {XQC_MOQ_MSG_SERVER_SETUP,         xqc_moq_msg_create_server_setup,     xqc_moq_msg_free_server_setup    },
    {XQC_MOQ_MSG_STREAM_HEADER_TRACK,  xqc_moq_msg_create_track_header,     xqc_moq_msg_free_track_header    },
//    {XQC_MOQ_MSG_STREAM_HEADER_GROUP,  NULL,                                NULL                             },
    {XQC_MOQ_MSG_TRACK_STREAM_OBJECT,  xqc_moq_msg_create_track_stream_obj, xqc_moq_msg_free_track_stream_obj},
//    {XQC_MOQ_MSG_GROUP_STREAM_OBJECT,  NULL,                                NULL                             },
};

const xqc_moq_msg_base_t client_setup_base = {
    .type       = xqc_moq_msg_client_setup_type,
    .encode_len = xqc_moq_msg_encode_client_setup_len,
    .encode     = xqc_moq_msg_encode_client_setup,
    .decode     = xqc_moq_msg_decode_client_setup,
    .on_msg     = xqc_moq_on_client_setup,
};

const xqc_moq_msg_base_t server_setup_base = {
    .type       = xqc_moq_msg_server_setup_type,
    .encode_len = xqc_moq_msg_encode_server_setup_len,
    .encode     = xqc_moq_msg_encode_server_setup,
    .decode     = xqc_moq_msg_decode_server_setup,
    .on_msg     = xqc_moq_on_server_setup,
};

const xqc_moq_msg_base_t client_setup_v14_base = {
    .type       = xqc_moq_msg_client_setup_v14_type,
    .encode_len = xqc_moq_msg_encode_client_setup_v14_len,
    .encode     = xqc_moq_msg_encode_client_setup_v14,
    .decode     = xqc_moq_msg_decode_client_setup_v14,
    .on_msg     = xqc_moq_on_client_setup_v14,
};

const xqc_moq_msg_base_t server_setup_v14_base = {
    .type       = xqc_moq_msg_server_setup_v14_type,
    .encode_len = xqc_moq_msg_encode_server_setup_v14_len,
    .encode     = xqc_moq_msg_encode_server_setup_v14,
    .decode     = xqc_moq_msg_decode_server_setup_v14,
    .on_msg     = xqc_moq_on_server_setup_v14,
};

const xqc_moq_msg_base_t subscribe_base = {
    .type       = xqc_moq_msg_subscribe_type,
    .encode_len = xqc_moq_msg_encode_subscribe_len,
    .encode     = xqc_moq_msg_encode_subscribe,
    .decode     = xqc_moq_msg_decode_subscribe,
    .on_msg     = xqc_moq_on_subscribe,
};

const xqc_moq_msg_base_t unsubscribe_base = {
    .type       = xqc_moq_msg_unsubscribe_type,
    .encode_len = xqc_moq_msg_encode_unsubscribe_len,
    .encode     = xqc_moq_msg_encode_unsubscribe,
    .decode     = xqc_moq_msg_decode_unsubscribe,
    .on_msg     = xqc_moq_on_unsubscribe,
};

const xqc_moq_msg_base_t subscribe_update_base = {
    .type       = xqc_moq_msg_subscribe_update_type,
    .encode_len = xqc_moq_msg_encode_subscribe_update_len,
    .encode     = xqc_moq_msg_encode_subscribe_update,
    .decode     = xqc_moq_msg_decode_subscribe_update,
    .on_msg     = xqc_moq_on_subscribe_update,
};

const xqc_moq_msg_base_t subscribe_ok_base = {
    .type       = xqc_moq_msg_subscribe_ok_type,
    .encode_len = xqc_moq_msg_encode_subscribe_ok_len,
    .encode     = xqc_moq_msg_encode_subscribe_ok,
    .decode     = xqc_moq_msg_decode_subscribe_ok,
    .on_msg     = xqc_moq_on_subscribe_ok,
};

const xqc_moq_msg_base_t subscribe_error_base = {
    .type       = xqc_moq_msg_subscribe_error_type,
    .encode_len = xqc_moq_msg_encode_subscribe_error_len,
    .encode     = xqc_moq_msg_encode_subscribe_error,
    .decode     = xqc_moq_msg_decode_subscribe_error,
    .on_msg     = xqc_moq_on_subscribe_error,
};

const xqc_moq_msg_base_t publish_base = {
    .type       = xqc_moq_msg_publish_type,
    .encode_len = xqc_moq_msg_encode_publish_len,
    .encode     = xqc_moq_msg_encode_publish,
    .decode     = xqc_moq_msg_decode_publish,
    .on_msg     = xqc_moq_on_publish,
};

const xqc_moq_msg_base_t publish_ok_base = {
    .type       = xqc_moq_msg_publish_ok_type,
    .encode_len = xqc_moq_msg_encode_publish_ok_len,
    .encode     = xqc_moq_msg_encode_publish_ok,
    .decode     = xqc_moq_msg_decode_publish_ok,
    .on_msg     = xqc_moq_on_publish_ok,
};

const xqc_moq_msg_base_t publish_error_base = {
    .type       = xqc_moq_msg_publish_error_type,
    .encode_len = xqc_moq_msg_encode_publish_error_len,
    .encode     = xqc_moq_msg_encode_publish_error,
    .decode     = xqc_moq_msg_decode_publish_error,
    .on_msg     = xqc_moq_on_publish_error,
};

const xqc_moq_msg_base_t publish_done_base = {
    .type       = xqc_moq_msg_publish_done_type,
    .encode_len = xqc_moq_msg_encode_publish_done_len,
    .encode     = xqc_moq_msg_encode_publish_done,
    .decode     = xqc_moq_msg_decode_publish_done,
    .on_msg     = xqc_moq_on_publish_done,
};

const xqc_moq_msg_base_t publish_namespace_base = {
    .type       = xqc_moq_msg_publish_namespace_type,
    .encode_len = xqc_moq_msg_encode_publish_namespace_len,
    .encode     = xqc_moq_msg_encode_publish_namespace,
    .decode     = xqc_moq_msg_decode_publish_namespace,
    .on_msg     = xqc_moq_on_publish_namespace,
};

const xqc_moq_msg_base_t publish_namespace_ok_base = {
    .type       = xqc_moq_msg_publish_namespace_ok_type,
    .encode_len = xqc_moq_msg_encode_publish_namespace_ok_len,
    .encode     = xqc_moq_msg_encode_publish_namespace_ok,
    .decode     = xqc_moq_msg_decode_publish_namespace_ok,
    .on_msg     = xqc_moq_on_publish_namespace_ok,
};

const xqc_moq_msg_base_t publish_namespace_error_base = {
    .type       = xqc_moq_msg_publish_namespace_error_type,
    .encode_len = xqc_moq_msg_encode_publish_namespace_error_len,
    .encode     = xqc_moq_msg_encode_publish_namespace_error,
    .decode     = xqc_moq_msg_decode_publish_namespace_error,
    .on_msg     = xqc_moq_on_publish_namespace_error,
};

const xqc_moq_msg_base_t publish_namespace_done_base = {
    .type       = xqc_moq_msg_publish_namespace_done_type,
    .encode_len = xqc_moq_msg_encode_publish_namespace_done_len,
    .encode     = xqc_moq_msg_encode_publish_namespace_done,
    .decode     = xqc_moq_msg_decode_publish_namespace_done,
    .on_msg     = xqc_moq_on_publish_namespace_done,
};

const xqc_moq_msg_base_t publish_namespace_cancel_base = {
    .type       = xqc_moq_msg_publish_namespace_cancel_type,
    .encode_len = xqc_moq_msg_encode_publish_namespace_cancel_len,
    .encode     = xqc_moq_msg_encode_publish_namespace_cancel,
    .decode     = xqc_moq_msg_decode_publish_namespace_cancel,
    .on_msg     = xqc_moq_on_publish_namespace_cancel,
};

const xqc_moq_msg_base_t subscribe_namespace_base = {
    .type       = xqc_moq_msg_subscribe_namespace_type,
    .encode_len = xqc_moq_msg_encode_subscribe_namespace_len,
    .encode     = xqc_moq_msg_encode_subscribe_namespace,
    .decode     = xqc_moq_msg_decode_subscribe_namespace,
    .on_msg     = xqc_moq_on_subscribe_namespace,
};

const xqc_moq_msg_base_t subscribe_namespace_ok_base = {
    .type       = xqc_moq_msg_subscribe_namespace_ok_type,
    .encode_len = xqc_moq_msg_encode_subscribe_namespace_ok_len,
    .encode     = xqc_moq_msg_encode_subscribe_namespace_ok,
    .decode     = xqc_moq_msg_decode_subscribe_namespace_ok,
    .on_msg     = xqc_moq_on_subscribe_namespace_ok,
};

const xqc_moq_msg_base_t subscribe_namespace_error_base = {
    .type       = xqc_moq_msg_subscribe_namespace_error_type,
    .encode_len = xqc_moq_msg_encode_subscribe_namespace_error_len,
    .encode     = xqc_moq_msg_encode_subscribe_namespace_error,
    .decode     = xqc_moq_msg_decode_subscribe_namespace_error,
    .on_msg     = xqc_moq_on_subscribe_namespace_error,
};

const xqc_moq_msg_base_t unsubscribe_namespace_base = {
    .type       = xqc_moq_msg_unsubscribe_namespace_type,
    .encode_len = xqc_moq_msg_encode_unsubscribe_namespace_len,
    .encode     = xqc_moq_msg_encode_unsubscribe_namespace,
    .decode     = xqc_moq_msg_decode_unsubscribe_namespace,
    .on_msg     = xqc_moq_on_unsubscribe_namespace,
};

const xqc_moq_msg_base_t object_stream_base = {
    .type       = xqc_moq_msg_object_stream_type,
    .encode_len = xqc_moq_msg_encode_object_stream_len,
    .encode     = xqc_moq_msg_encode_object_stream,
    .decode     = xqc_moq_msg_decode_object_stream,
    .on_msg     = xqc_moq_on_object_stream,
};

const xqc_moq_msg_base_t subgroup_base = {
    .type       = xqc_moq_msg_subgroup_type,
    .encode_len = xqc_moq_msg_encode_subgroup_len,
    .encode     = xqc_moq_msg_encode_subgroup,
    .decode     = xqc_moq_msg_decode_subgroup,
    .on_msg     = xqc_moq_on_subgroup,
};

const xqc_moq_msg_base_t track_stream_obj_base = {
    .type       = xqc_moq_msg_track_stream_obj_type,
    .encode_len = xqc_moq_msg_encode_track_stream_obj_len,
    .encode     = xqc_moq_msg_encode_track_stream_obj,
    .decode     = xqc_moq_msg_decode_track_stream_obj,
    .on_msg     = xqc_moq_on_track_stream_obj,
};

const xqc_moq_msg_base_t track_header_base = {
    .type       = xqc_moq_msg_track_header_type,
    .encode_len = xqc_moq_msg_encode_track_header_len,
    .encode     = xqc_moq_msg_encode_track_header,
    .decode     = xqc_moq_msg_decode_track_header,
    .on_msg     = xqc_moq_on_track_header,
};



void
xqc_moq_msg_free(xqc_moq_msg_type_t type, void *msg)
{
    if (msg == NULL) {
        return;
    }
    for (xqc_int_t i = 0; i < sizeof(moq_msg_func_map) / sizeof(moq_msg_func_map[0]); i++) {
        if (moq_msg_func_map[i].type == type) {
            return moq_msg_func_map[i].free(msg);
        }
    }
}

void xqc_moq_msg_set_object_by_object(xqc_moq_object_t *obj, xqc_moq_object_stream_msg_t *msg)
{
    obj->subscribe_id = msg->subscribe_id;
    obj->track_alias = msg->track_alias;
    obj->group_id = msg->group_id;
    obj->object_id = msg->object_id;
    obj->subgroup_id = msg->subgroup_id;
    obj->object_id_delta = msg->object_id_delta;
    obj->send_order = msg->send_order;
    obj->status = msg->status;
    obj->ext_params_num = msg->ext_params_num;
    obj->ext_params = msg->ext_params;
    obj->payload = msg->payload;
    obj->payload_len = msg->payload_len;
    obj->custom_id_flag = 0;
}

void xqc_moq_msg_set_object_by_track(xqc_moq_object_t *obj, xqc_moq_stream_header_track_msg_t *header,
    xqc_moq_track_stream_obj_msg_t *msg)
{
    obj->subscribe_id = header->subscribe_id;
    obj->track_alias = header->track_alias;
    obj->send_order = header->send_order;
    obj->group_id = msg->group_id;
    obj->object_id = msg->object_id;
    obj->subgroup_id = 0;
    obj->object_id_delta = 0;
    obj->status = msg->status;
    obj->ext_params_num = 0;
    obj->ext_params = NULL;
    obj->payload = msg->payload;
    obj->payload_len = msg->payload_len;
    obj->custom_id_flag = 0;
}

void xqc_moq_msg_set_object_by_group(xqc_moq_object_t *obj, xqc_moq_stream_header_group_msg_t *header,
    xqc_moq_group_stream_obj_msg_t *msg)
{
    obj->subscribe_id = header->subscribe_id;
    obj->track_alias = header->track_alias;
    obj->send_order = header->send_order;
    obj->group_id = header->group_id;
    obj->object_id = msg->object_id;
    obj->subgroup_id = 0;
    obj->object_id_delta = 0;
    obj->status = msg->status;
    obj->ext_params_num = 0;
    obj->ext_params = NULL;
    obj->payload = msg->payload;
    obj->payload_len = msg->payload_len;
    obj->custom_id_flag = 0;
}


static uint8_t *
xqc_moq_put_u8(uint8_t *p, uint8_t n)
{
    *p++ = n;
    return p;
}


static xqc_int_t
xqc_moq_read_u8(const uint8_t *buf, size_t buf_len, xqc_int_t *processed, uint8_t *val)
{
    if ((size_t)(*processed) >= buf_len) {
        return -1;
    }
    *val = buf[*processed];
    *processed += 1;
    return 1;
}


static uint64_t
xqc_moq_param_bytes_to_uint(const xqc_moq_message_parameter_t *param)
{
    if (param == NULL || param->value == NULL || param->length == 0) {
        return 0;
    }
    uint64_t val = 0;
    xqc_int_t bytes = param->length > 8 ? 8 : param->length;
    for (xqc_int_t i = 0; i < bytes; i++) {
        val |= ((uint64_t)param->value[i]) << (i * 8);
    }
    return val;
}

static xqc_int_t
xqc_moq_param_int_octets(uint64_t value)
{
    xqc_int_t len = 1;
    while ((value >> (len * 8)) && len < 8) {
        len++;
    }
    return len;
}


static void
xqc_moq_param_store_integer(xqc_moq_message_parameter_t *param, uint64_t value)
{
    if (param == NULL) {
        return;
    }
    if (param->value) {
        xqc_free(param->value);
        param->value = NULL;
    }
    param->length = 0;
    param->is_integer = 1;
    param->int_value = value;
}

static void
xqc_moq_param_write_uint_bytes(uint8_t *dst, xqc_int_t len, uint64_t value)
{
    for (xqc_int_t i = 0; i < len; i++) {
        dst[i] = (uint8_t)((value >> (i * 8)) & 0xFF);
    }
}

void *
xqc_moq_msg_create(xqc_moq_msg_type_t type)
{
    for (xqc_int_t i = 0; i < sizeof(moq_msg_func_map) / sizeof(moq_msg_func_map[0]); i++) {
        if (moq_msg_func_map[i].type == type) {
            return moq_msg_func_map[i].create();
        }
    }
    return NULL;
}

xqc_int_t
xqc_moq_msg_decode_type(uint8_t *buf, size_t buf_len, xqc_moq_msg_type_t *type, xqc_int_t *wait_more_data)
{
    uint64_t val;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    ret = xqc_vint_read(buf, buf + buf_len, &val);
    if (ret < 0) {
        *wait_more_data = 1;
        return processed;
    }

    processed += ret;

    if (val > XQC_MOQ_MSG_STREAM_HEADER_GROUP) {
        return -XQC_EILLEGAL_FRAME;
    }
    *type = val;
    return processed;
}

void
xqc_moq_decode_msg_ctx_reset(xqc_moq_decode_msg_ctx_t *ctx)
{
    xqc_memzero(ctx, sizeof(*ctx));
}

void
xqc_moq_decode_params_ctx_reset(xqc_moq_decode_params_ctx_t *ctx)
{
    xqc_memzero(ctx, sizeof(*ctx));
}

xqc_moq_message_parameter_t *
xqc_moq_msg_alloc_params(xqc_int_t params_num)
{
    return xqc_calloc(params_num, sizeof(xqc_moq_message_parameter_t));
}

void
xqc_moq_msg_free_params(xqc_moq_message_parameter_t *params, xqc_int_t params_num)
{
    for (xqc_int_t i = 0; i < params_num; i++) {
        if (params[i].value) {
            xqc_free(params[i].value);
            params[i].value = NULL;
        }
        params[i].length = 0;
    }
    xqc_free(params);
}

xqc_int_t
xqc_moq_msg_encode_params_len(xqc_moq_message_parameter_t *params, xqc_int_t params_num)
{
    xqc_int_t len = 0;
    xqc_moq_message_parameter_t *param;
    for (xqc_int_t i = 0; i < params_num; i++) {
        param = &params[i];
        len += xqc_put_varint_len(param->type);
        if (param->is_integer && (param->value == NULL || param->length == 0)) {
            xqc_int_t ilen = xqc_moq_param_int_octets(param->int_value);
            len += xqc_put_varint_len(ilen);
            len += ilen;
        } else {
            len += xqc_put_varint_len(param->length);
            if (param->length > 0) {
                len += param->length;
            }
        }
    }
    return len;
}

//return encoded or error
xqc_int_t
xqc_moq_msg_encode_params(xqc_moq_message_parameter_t *params, xqc_int_t params_num, uint8_t *buf, size_t buf_cap)
{
    uint8_t *p = buf;
    xqc_moq_message_parameter_t *param;

    if (xqc_moq_msg_encode_params_len(params, params_num) > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    for (xqc_int_t i = 0; i < params_num; i++) {
        param = &params[i];
        p = xqc_put_varint(p, param->type);
        if (param->is_integer && (param->value == NULL || param->length == 0)) {
            xqc_int_t ilen = xqc_moq_param_int_octets(param->int_value);
            p = xqc_put_varint(p, ilen);
            xqc_moq_param_write_uint_bytes(p, ilen, param->int_value);
            p += ilen;
        } else {
            p = xqc_put_varint(p, param->length);
            if (param->length > 0 && param->value) {
                xqc_memcpy(p, param->value, param->length);
                p += param->length;
            }
        }
    }

    return p - buf;
}



static xqc_int_t
xqc_moq_msg_encode_params_len_v14(xqc_moq_message_parameter_t *params, xqc_int_t params_num)
{
    xqc_int_t len = 0;
    xqc_moq_message_parameter_t *param;
    for (xqc_int_t i = 0; i < params_num; i++) {
        param = &params[i];
        len += xqc_put_varint_len(param->type);
        if ((param->type & 0x1) || param->type == XQC_MOQ_PARAM_EXTDATA) {
            len += xqc_put_varint_len(param->length);
            len += param->length;
        } else {
            uint64_t value = param->is_integer ? param->int_value : xqc_moq_param_bytes_to_uint(param);
            len += xqc_put_varint_len(value);
        }
    }
    return len;
}

static xqc_int_t
xqc_moq_msg_encode_params_v14(xqc_moq_message_parameter_t *params, xqc_int_t params_num,
    uint8_t *buf, size_t buf_cap)
{
    uint8_t *p = buf;
    xqc_moq_message_parameter_t *param;
    xqc_int_t need = xqc_moq_msg_encode_params_len_v14(params, params_num);
    if (need > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    for (xqc_int_t i = 0; i < params_num; i++) {
        param = &params[i];
        p = xqc_put_varint(p, param->type);
        if ((param->type & 0x1) || param->type == XQC_MOQ_PARAM_EXTDATA) {
            p = xqc_put_varint(p, param->length);
            if (param->length > 0 && param->value) {
                xqc_memcpy(p, param->value, param->length);
                p += param->length;
            }
        } else {
            uint64_t value = param->is_integer ? param->int_value : xqc_moq_param_bytes_to_uint(param);
            p = xqc_put_varint(p, value);
        }
    }
    return p - buf;
}

static xqc_int_t
xqc_moq_msg_decode_params_v14(uint8_t *buf, size_t buf_len, xqc_moq_decode_params_ctx_t *ctx,
    xqc_moq_message_parameter_t *params, xqc_int_t params_num, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    *finish = 0;
    *wait_more_data = 0;

    while (ctx->cur_param_idx < params_num) {
        xqc_moq_message_parameter_t *param = &params[ctx->cur_param_idx];
        switch (ctx->cur_field_idx) {
        case 0:
            ret = xqc_vint_read(buf + processed, buf + buf_len, &param->type);
            if (ret < 0) {
                *wait_more_data = 1;
                return processed;
            }
            processed += ret;
            if ((param->type & 0x1) || param->type == XQC_MOQ_PARAM_EXTDATA) {
                ctx->cur_field_idx = 1;
            } else {
                ctx->cur_field_idx = 3;
            }
            break;
        case 1:
            ret = xqc_vint_read(buf + processed, buf + buf_len, &param->length);
            if (ret < 0) {
                *wait_more_data = 1;
                return processed;
            }
            processed += ret;
            if (param->length > XQC_MOQ_MAX_PARAM_VALUE_LEN) {
                return -XQC_ELIMIT;
            }
            if (param->length == 0) {
                param->value = NULL;
                param->is_integer = 0;
                param->int_value = 0;
                ctx->cur_param_idx++;
                ctx->cur_field_idx = 0;
                if (ctx->cur_param_idx == params_num) {
                    *finish = 1;
                    return processed;
                }
                break;
            }
            param->value = xqc_malloc(param->length);
            if (param->value == NULL) {
                return -XQC_EMALLOC;
            }
            param->is_integer = 0;
            param->int_value = 0;
            ctx->value_processed = 0;
            ctx->cur_field_idx = 2;
            break;
        case 2: {
            xqc_int_t need = param->length - ctx->value_processed;
            xqc_int_t remain = buf_len - processed;
            if (remain == 0) {
                *wait_more_data = 1;
                return processed;
            }
            xqc_int_t copy = remain < need ? remain : need;
            xqc_memcpy(param->value + ctx->value_processed, buf + processed, copy);
            ctx->value_processed += copy;
            processed += copy;
            if (ctx->value_processed == param->length) {
                ctx->value_processed = 0;
                ctx->cur_field_idx = 0;
                ctx->cur_param_idx++;
                if (ctx->cur_param_idx == params_num) {
                    *finish = 1;
                    return processed;
                }
            } else {
                *wait_more_data = 1;
                return processed;
            }
            break;
        }
        case 3: {
            uint64_t value = 0;
            ret = xqc_vint_read(buf + processed, buf + buf_len, &value);
            if (ret < 0) {
                *wait_more_data = 1;
                return processed;
            }
            processed += ret;
            xqc_moq_param_store_integer(param, value);
            ctx->cur_field_idx = 0;
            ctx->cur_param_idx++;
            if (ctx->cur_param_idx == params_num) {
                *finish = 1;
                return processed;
            }
            break;
        }
        default:
            return -XQC_EILLEGAL_FRAME;
        }
    }

    return processed;
}

xqc_int_t
xqc_moq_msg_decode_one_param(uint8_t *buf, size_t buf_len, xqc_moq_decode_params_ctx_t *ctx,
    xqc_moq_message_parameter_t *param, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    *finish = 0;
    *wait_more_data = 0;

    switch (ctx->cur_field_idx) {
        case 0: //Parameter Type (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &param->type);
            if (ret < 0) {
                *wait_more_data = 1;
                return processed;
            }
            processed += ret;
            param->is_integer = 0;
            param->int_value = 0;

            DEBUG_PRINTF("====>param[%d] type:%d\n",ctx->cur_param_idx, (int)param->type);
            if (param->type > XQC_MOQ_PARAM_EXTDATA) {
                return -XQC_EILLEGAL_FRAME;
            }

            ctx->cur_field_idx = 1;
        case 1: //Parameter Length (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &param->length);
            if (ret < 0) {
                *wait_more_data = 1;
                return processed;
            }
            processed += ret;

            DEBUG_PRINTF("====>length:%d\n",(int)param->length);
            if (param->length <= 0) {
                return -XQC_EILLEGAL_FRAME;
            }
            if (param->length > XQC_MOQ_MAX_PARAM_VALUE_LEN) {
                return -XQC_ELIMIT;
            }
            param->value = xqc_realloc(param->value, param->length);
            ctx->value_processed = 0;

            ctx->cur_field_idx = 2;
        case 2: //Parameter Value (..)
            if (buf_len - processed == 0) {
                *wait_more_data = 1;
                return processed;
            }

            if (param->length - ctx->value_processed <= buf_len - processed) {
                xqc_memcpy(param->value + ctx->value_processed, buf + processed,
                           param->length - ctx->value_processed);
                processed += param->length - ctx->value_processed;

                DEBUG_PRINTF("====>value:");
                for (int i = 0; i < param->length; i++)
                    DEBUG_PRINTF("0x%x ", param->value[i]);
                DEBUG_PRINTF("\n");

                *finish = 1;

                ctx->value_processed = 0;
                ctx->cur_field_idx = 0;
                return processed;
            } else {
                xqc_memcpy(param->value + ctx->value_processed, buf + processed, buf_len - processed);
                ctx->value_processed += buf_len - processed;
                processed += buf_len - processed;

                *wait_more_data = 1;

                return processed;
            }
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }
}

xqc_int_t
xqc_moq_msg_decode_params(uint8_t *buf, size_t buf_len, xqc_moq_decode_params_ctx_t *ctx,
    xqc_moq_message_parameter_t *params, xqc_int_t params_num, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_int_t params_finish = 0;
    *finish = 0;
    *wait_more_data = 0;

    for (; ctx->cur_param_idx < params_num; ctx->cur_param_idx++) {
        xqc_moq_message_parameter_t *param = &params[ctx->cur_param_idx];
        ret = xqc_moq_msg_decode_one_param(buf + processed, buf_len - processed, ctx, param, &params_finish, wait_more_data);
        if (ret < 0) {
            return ret;
        }
        processed += ret;
        if (*wait_more_data == 1) {
            return processed;
        }
        if (params_finish == 1) {
            if (ctx->cur_param_idx == params_num - 1) {
                *finish = 1;
                /* Reset param ctx when decode params finish */
                xqc_moq_decode_params_ctx_reset(ctx);
                return processed;
            }
        }
    }
    return processed;
}

uint8_t * xqc_moq_put_varint_length(uint8_t *buf, size_t length)
{
    buf[0] = (uint8_t)((length >> 8) & 0xff);
    buf[1] = (uint8_t)(length & 0xff);
    return buf + XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
}


xqc_int_t 
xqc_moq_length_read(uint8_t *buf, uint8_t* end, uint64_t *length)
{
    if (end - buf < 2 || buf == NULL || buf + 1 == NULL) {
        return -1;
    }

    uint64_t value = 0;

    value = (uint16_t)buf[0] << 8;
    value |= (uint16_t)buf[1];

    *length = value;

    return 2; // FIXED length
}

/**
 * CLIENT_SETUP Message
 */

void *
xqc_moq_msg_create_client_setup()
{
    xqc_moq_client_setup_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_client_setup_init_handler(&msg->msg_base);
    return msg;
}

void
xqc_moq_msg_free_client_setup(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_client_setup_msg_t *client_setup = (xqc_moq_client_setup_msg_t*)msg;
    xqc_free(client_setup->versions);
    xqc_moq_msg_free_params(client_setup->params, client_setup->params_num);
    xqc_free(client_setup);
}

xqc_moq_msg_type_t
xqc_moq_msg_client_setup_type()
{
    return XQC_MOQ_MSG_CLIENT_SETUP;
}

void
xqc_moq_msg_client_setup_init_handler(xqc_moq_msg_base_t *msg_base)
{
    *msg_base = client_setup_base;
}

xqc_int_t
xqc_moq_msg_encode_client_setup_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_client_setup_msg_t *client_setup = (xqc_moq_client_setup_msg_t*)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_CLIENT_SETUP);
    len += xqc_put_varint_len(client_setup->versions_num);
    for (xqc_int_t i = 0; i < client_setup->versions_num; i++) {
        len += xqc_put_varint_len(client_setup->versions[i]);
    }
    len += xqc_put_varint_len(client_setup->params_num);
    len += xqc_moq_msg_encode_params_len(client_setup->params, client_setup->params_num);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_client_setup(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_client_setup_msg_t *client_setup = (xqc_moq_client_setup_msg_t*)msg_base;
    if (xqc_moq_msg_encode_client_setup_len(msg_base) > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_CLIENT_SETUP);
    p = xqc_put_varint(p, client_setup->versions_num);
    for (int i = 0; i < client_setup->versions_num; i++) {
        p = xqc_put_varint(p, client_setup->versions[i]);
    }
    p = xqc_put_varint(p, client_setup->params_num);

    ret = xqc_moq_msg_encode_params(client_setup->params, client_setup->params_num, p, buf + buf_cap - p);
    if (ret < 0) {
        return ret;
    }
    p += ret;

    return p - buf;
}

//return processed or error
xqc_int_t
xqc_moq_msg_decode_client_setup(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base,
    xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_int_t param_finish = 0;
    xqc_moq_client_setup_msg_t *client_setup = (xqc_moq_client_setup_msg_t *)msg_base;
    xqc_moq_decode_params_ctx_t *params_ctx = &msg_ctx->decode_params_ctx;
    switch (msg_ctx->cur_field_idx) {
        case 0: //Number of Supported Versions (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &client_setup->versions_num);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            DEBUG_PRINTF("==>versions_num:%d\n",(int)client_setup->versions_num);
            if (client_setup->versions_num > XQC_MOQ_MAX_VERSIONS || client_setup->versions_num <= 0) {
                return -XQC_ELIMIT;
            }
            client_setup->versions = xqc_calloc(client_setup->versions_num, sizeof(uint64_t));

            msg_ctx->cur_field_idx = 1;
        case 1: //Supported Version (i) ...
            for (; msg_ctx->cur_array_idx < client_setup->versions_num; msg_ctx->cur_array_idx++) {
                ret = xqc_vint_read(buf + processed, buf + buf_len,
                                    &client_setup->versions[msg_ctx->cur_array_idx]);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
                DEBUG_PRINTF("====>version:0x%x\n",(int)client_setup->versions[msg_ctx->cur_array_idx]);
            }
            if (*wait_more_data == 1) {
                break;
            }
            msg_ctx->cur_field_idx = 2;
            msg_ctx->cur_array_idx = 0;
        case 2: //Number of Parameters (i) ...
            ret = xqc_vint_read(buf + processed, buf + buf_len, &client_setup->params_num);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>params_num:%d\n",(int)client_setup->params_num);

            if (client_setup->params_num == 0) {
                *finish = 1;
                break;
            }
            if (client_setup->params_num > XQC_MOQ_MAX_PARAMS) {
                return -XQC_ELIMIT;
            }
            client_setup->params = xqc_moq_msg_alloc_params(client_setup->params_num);

            msg_ctx->cur_field_idx = 3;
        case 3: //Setup Parameters (..) ...
            ret = xqc_moq_msg_decode_params_v14(buf + processed, buf_len - processed, params_ctx,
                                            client_setup->params, client_setup->params_num,
                                            &param_finish, wait_more_data);
            if (ret < 0) {
                return ret;
            }
            processed += ret;
            if (*wait_more_data == 1) {
                break;
            }
            if (param_finish == 1) {
                *finish = 1;
            }
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

/**
 * SERVER_SETUP Message
 */

void *
xqc_moq_msg_create_server_setup()
{
    xqc_moq_server_setup_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_server_setup_init_handler(&msg->msg_base);
    return msg;
}

void
xqc_moq_msg_free_server_setup(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_server_setup_msg_t *server_setup = (xqc_moq_server_setup_msg_t*)msg;
    xqc_moq_msg_free_params(server_setup->params, server_setup->params_num);
    xqc_free(server_setup);
}

xqc_moq_msg_type_t
xqc_moq_msg_server_setup_type()
{
    return XQC_MOQ_MSG_SERVER_SETUP;
}

void
xqc_moq_msg_server_setup_init_handler(xqc_moq_msg_base_t *msg_base)
{
    *msg_base = server_setup_base;
}

xqc_int_t
xqc_moq_msg_encode_server_setup_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_server_setup_msg_t *server_setup = (xqc_moq_server_setup_msg_t*)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_SERVER_SETUP);
    len += xqc_put_varint_len(server_setup->version);
    len += xqc_put_varint_len(server_setup->params_num);
    len += xqc_moq_msg_encode_params_len(server_setup->params, server_setup->params_num);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_server_setup(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_server_setup_msg_t *server_setup = (xqc_moq_server_setup_msg_t*)msg_base;
    if (xqc_moq_msg_encode_server_setup_len(msg_base) > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_SERVER_SETUP);
    p = xqc_put_varint(p, server_setup->version);
    p = xqc_put_varint(p, server_setup->params_num);

    ret = xqc_moq_msg_encode_params(server_setup->params, server_setup->params_num, p, buf + buf_cap - p);
    if (ret < 0) {
        return ret;
    }
    p += ret;

    return p - buf;
}

//return processed or error
xqc_int_t
xqc_moq_msg_decode_server_setup(uint8_t *buf, size_t buf_len, uint8_t stream_fin, xqc_moq_decode_msg_ctx_t *msg_ctx,
    xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_int_t param_finish = 0;
    xqc_moq_server_setup_msg_t *server_setup = (xqc_moq_server_setup_msg_t *)msg_base;
    xqc_moq_decode_params_ctx_t *params_ctx = &msg_ctx->decode_params_ctx;
    switch (msg_ctx->cur_field_idx) {
        case 0: //Selected Version (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &server_setup->version);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            DEBUG_PRINTF("==>version:0x%x\n",(int)server_setup->version);

            msg_ctx->cur_field_idx = 1;
        case 1: //Number of Parameters (i) ...
            ret = xqc_vint_read(buf + processed, buf + buf_len, &server_setup->params_num);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>params_num:%d\n",(int)server_setup->params_num);

            if (server_setup->params_num == 0) {
                *finish = 1;
                break;
            }
            if (server_setup->params_num > XQC_MOQ_MAX_PARAMS) {
                return -XQC_ELIMIT;
            }
            server_setup->params = xqc_moq_msg_alloc_params(server_setup->params_num);

            msg_ctx->cur_field_idx = 2;
        case 2: //Setup Parameters (..) ...
            ret = xqc_moq_msg_decode_params(buf + processed, buf_len - processed, params_ctx,
                                            server_setup->params, server_setup->params_num,
                                            &param_finish, wait_more_data);
            if (ret < 0) {
                return ret;
            }
            processed += ret;
            if (*wait_more_data == 1) {
                break;
            }
            if (param_finish == 1) {
                *finish = 1;
            }
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

void *
xqc_moq_msg_create_client_setup_v14()
{
    xqc_moq_client_setup_v14_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    if (msg == NULL) {
        return NULL;
    }
    xqc_moq_msg_client_setup_v14_init_handler(&msg->msg_base);
    return msg;
}

void
xqc_moq_msg_free_client_setup_v14(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_client_setup_v14_msg_t *client_setup = (xqc_moq_client_setup_v14_msg_t*)msg;
    xqc_free(client_setup->versions);
    xqc_moq_msg_free_params(client_setup->params, client_setup->params_num);
    xqc_free(client_setup);
}

xqc_moq_msg_type_t
xqc_moq_msg_client_setup_v14_type()
{
    return XQC_MOQ_MSG_CLIENT_SETUP_V14;
}

void
xqc_moq_msg_client_setup_v14_init_handler(xqc_moq_msg_base_t *msg_base)
{
    *msg_base = client_setup_v14_base;
}

xqc_int_t
xqc_moq_msg_encode_client_setup_v14_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_client_setup_v14_msg_t *client_setup = (xqc_moq_client_setup_v14_msg_t*)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_CLIENT_SETUP_V14);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(client_setup->versions_num);
    for (xqc_int_t i = 0; i < client_setup->versions_num; i++) {
        len += xqc_put_varint_len(client_setup->versions[i]);
    }
    len += xqc_put_varint_len(client_setup->params_num);
    len += xqc_moq_msg_encode_params_len_v14(client_setup->params, client_setup->params_num);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_client_setup_v14(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_moq_client_setup_v14_msg_t *client_setup = (xqc_moq_client_setup_v14_msg_t*)msg_base;
    xqc_int_t length = xqc_moq_msg_encode_client_setup_v14_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    length = length - xqc_put_varint_len(XQC_MOQ_MSG_CLIENT_SETUP_V14) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_CLIENT_SETUP_V14);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, client_setup->versions_num);
    for (int i = 0; i < client_setup->versions_num; i++) {
        p = xqc_put_varint(p, client_setup->versions[i]);
    }
    p = xqc_put_varint(p, client_setup->params_num);

    xqc_int_t ret = xqc_moq_msg_encode_params_v14(client_setup->params, client_setup->params_num,
                                              p, buf + buf_cap - p);
    if (ret < 0) {
        return ret;
    }
    p += ret;

    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_client_setup_v14(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base,
    xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_int_t param_finish = 0;
    xqc_moq_client_setup_v14_msg_t *client_setup = (xqc_moq_client_setup_v14_msg_t *)msg_base;
    xqc_moq_decode_params_ctx_t *params_ctx = &msg_ctx->decode_params_ctx;
    uint64_t length = 0;

    switch (msg_ctx->cur_field_idx) {
        case 0:
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &length);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1:
            ret = xqc_vint_read(buf + processed, buf + buf_len, &client_setup->versions_num);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            if (client_setup->versions_num > XQC_MOQ_MAX_VERSIONS || client_setup->versions_num <= 0) {
                return -XQC_ELIMIT;
            }
            client_setup->versions = xqc_calloc(client_setup->versions_num, sizeof(uint64_t));
            msg_ctx->cur_field_idx = 2;
        case 2:
            for (; msg_ctx->cur_array_idx < client_setup->versions_num; msg_ctx->cur_array_idx++) {
                ret = xqc_vint_read(buf + processed, buf + buf_len,
                                    &client_setup->versions[msg_ctx->cur_array_idx]);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
            }
            if (*wait_more_data == 1) {
                break;
            }
            msg_ctx->cur_field_idx = 3;
            msg_ctx->cur_array_idx = 0;
        case 3:
            ret = xqc_vint_read(buf + processed, buf + buf_len, &client_setup->params_num);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            if (client_setup->params_num == 0) {
                *finish = 1;
                msg_ctx->cur_field_idx = 5;
                break;
            }
            if (client_setup->params_num > XQC_MOQ_MAX_PARAMS) {
                return -XQC_ELIMIT;
            }
            client_setup->params = xqc_moq_msg_alloc_params(client_setup->params_num);
            msg_ctx->cur_field_idx = 4;
        case 4:
            ret = xqc_moq_msg_decode_params_v14(buf + processed, buf_len - processed, params_ctx,
                                            client_setup->params, client_setup->params_num,
                                            &param_finish, wait_more_data);
            if (ret < 0) {
                return ret;
            }
            processed += ret;
            if (*wait_more_data == 1) {
                break;
            }
            if (param_finish == 1) {
                *finish = 1;
                msg_ctx->cur_field_idx = 5;
            }
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

void *
xqc_moq_msg_create_server_setup_v14()
{
    xqc_moq_server_setup_v14_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    if (msg == NULL) {
        return NULL;
    }
    xqc_moq_msg_server_setup_v14_init_handler(&msg->msg_base);
    return msg;
}

void
xqc_moq_msg_free_server_setup_v14(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_server_setup_v14_msg_t *server_setup = (xqc_moq_server_setup_v14_msg_t*)msg;
    xqc_moq_msg_free_params(server_setup->params, server_setup->params_num);
    xqc_free(server_setup);
}

xqc_moq_msg_type_t
xqc_moq_msg_server_setup_v14_type()
{
    return XQC_MOQ_MSG_SERVER_SETUP_V14;
}

void
xqc_moq_msg_server_setup_v14_init_handler(xqc_moq_msg_base_t *msg_base)
{
    *msg_base = server_setup_v14_base;
}

xqc_int_t
xqc_moq_msg_encode_server_setup_v14_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_server_setup_v14_msg_t *server_setup = (xqc_moq_server_setup_v14_msg_t*)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_SERVER_SETUP_V14);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(server_setup->selected_version);
    len += xqc_put_varint_len(server_setup->params_num);
    len += xqc_moq_msg_encode_params_len_v14(server_setup->params, server_setup->params_num);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_server_setup_v14(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_moq_server_setup_v14_msg_t *server_setup = (xqc_moq_server_setup_v14_msg_t*)msg_base;
    xqc_int_t length = xqc_moq_msg_encode_server_setup_v14_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    length = length - xqc_put_varint_len(XQC_MOQ_MSG_SERVER_SETUP_V14) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_SERVER_SETUP_V14);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, server_setup->selected_version);
    p = xqc_put_varint(p, server_setup->params_num);

    xqc_int_t ret = xqc_moq_msg_encode_params_v14(server_setup->params, server_setup->params_num,
                                              p, buf + buf_cap - p);
    if (ret < 0) {
        return ret;
    }
    p += ret;

    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_server_setup_v14(uint8_t *buf, size_t buf_len, uint8_t stream_fin, xqc_moq_decode_msg_ctx_t *msg_ctx,
    xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_int_t param_finish = 0;
    xqc_moq_server_setup_v14_msg_t *server_setup = (xqc_moq_server_setup_v14_msg_t *)msg_base;
    xqc_moq_decode_params_ctx_t *params_ctx = &msg_ctx->decode_params_ctx;
    uint64_t length = 0;

    switch (msg_ctx->cur_field_idx) {
        case 0: // length 
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &length);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;

        case 1: // number of versions(i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &server_setup->selected_version);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 2;

        case 2: // number of parameters(i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &server_setup->params_num);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            if (server_setup->params_num == 0) {
                *finish = 1;
                msg_ctx->cur_field_idx = 2;
                break;
            }
            if (server_setup->params_num > XQC_MOQ_MAX_PARAMS) {
                return -XQC_ELIMIT;
            }
            server_setup->params = xqc_moq_msg_alloc_params(server_setup->params_num);
            msg_ctx->cur_field_idx = 3;
        case 3:
            ret = xqc_moq_msg_decode_params_v14(buf + processed, buf_len - processed, params_ctx,
                                            server_setup->params, server_setup->params_num,
                                            &param_finish, wait_more_data);
            if (ret < 0) {
                return ret;
            }
            processed += ret;
            if (*wait_more_data == 1) {
                break;
            }
            if (param_finish == 1) {
                *finish = 1;
                msg_ctx->cur_field_idx = 2;
            }
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}


/**
 * SUBSCRIBE Message
 */

static xqc_int_t
xqc_moq_track_namespace_tuple_encode_len(uint64_t track_namespace_num,
    const xqc_moq_track_ns_field_t *track_namespace_tuple)
{
    xqc_int_t len = 0;

    len += xqc_put_varint_len(track_namespace_num);
    for (uint64_t i = 0; i < track_namespace_num; i++) {
        len += xqc_put_varint_len(track_namespace_tuple[i].len);
        len += track_namespace_tuple[i].len;
    }
    return len;
}

static uint8_t *
xqc_moq_track_namespace_tuple_encode(uint8_t *p, uint64_t track_namespace_num,
    const xqc_moq_track_ns_field_t *track_namespace_tuple)
{
    p = xqc_put_varint(p, track_namespace_num);
    for (uint64_t i = 0; i < track_namespace_num; i++) {
        p = xqc_put_varint(p, track_namespace_tuple[i].len);
        if (track_namespace_tuple[i].len > 0 && track_namespace_tuple[i].data != NULL) {
            xqc_memcpy(p, track_namespace_tuple[i].data, track_namespace_tuple[i].len);
            p += track_namespace_tuple[i].len;
        }
    }
    return p;
}

static xqc_int_t
xqc_moq_track_namespace_tuple_validate_and_sum(uint64_t track_namespace_num,
    const xqc_moq_track_ns_field_t *track_namespace_tuple, size_t *track_namespace_total_len)
{
    size_t total_len = 0;

    if (track_namespace_tuple == NULL || track_namespace_num == 0 || track_namespace_total_len == NULL) {
        return -XQC_EPARAM;
    }
    if (track_namespace_num > XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS) {
        return -XQC_ELIMIT;
    }

    for (uint64_t i = 0; i < track_namespace_num; i++) {
        if (track_namespace_tuple[i].len > XQC_MOQ_MAX_NAME_LEN) {
            return -XQC_ELIMIT;
        }
        if (total_len > XQC_MOQ_MAX_FULL_TRACK_NAME_LEN - track_namespace_tuple[i].len) {
            return -XQC_ELIMIT;
        }
        total_len += track_namespace_tuple[i].len;
    }

    *track_namespace_total_len = total_len;
    return XQC_OK;
}

void *
xqc_moq_msg_create_subscribe()
{
    xqc_moq_subscribe_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_subscribe_init_handler(&msg->msg_base);
    return msg;
}

void
xqc_moq_msg_free_subscribe(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_subscribe_msg_t *subscribe = (xqc_moq_subscribe_msg_t*)msg;
    if (subscribe->track_namespace_tuple) {
        for (uint64_t i = 0; i < subscribe->track_namespace_num; i++) {
            if (subscribe->track_namespace_tuple[i].data) {
                xqc_free(subscribe->track_namespace_tuple[i].data);
                subscribe->track_namespace_tuple[i].data = NULL;
                subscribe->track_namespace_tuple[i].len = 0;
            }
        }
        xqc_free(subscribe->track_namespace_tuple);
        subscribe->track_namespace_tuple = NULL;
        subscribe->track_namespace_num = 0;
    }
    xqc_free(subscribe->track_name);
    xqc_moq_msg_free_params(subscribe->params, subscribe->params_num);
    xqc_free(subscribe);
}

xqc_moq_msg_type_t
xqc_moq_msg_subscribe_type()
{
    return XQC_MOQ_MSG_SUBSCRIBE;
}

void
xqc_moq_msg_subscribe_init_handler(xqc_moq_msg_base_t *msg_base)
{
    *msg_base = subscribe_base;
}

xqc_int_t
xqc_moq_msg_encode_subscribe_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_subscribe_msg_t *subscribe = (xqc_moq_subscribe_msg_t*)msg_base;
    size_t track_name_len = subscribe->track_name_len;

    size_t track_namespace_len = 0;
    if (xqc_moq_track_namespace_tuple_validate_and_sum(subscribe->track_namespace_num,
            subscribe->track_namespace_tuple, &track_namespace_len) != XQC_OK)
    {
        return -XQC_EPARAM;
    }
    len += xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(subscribe->subscribe_id);
    len += xqc_moq_track_namespace_tuple_encode_len(subscribe->track_namespace_num,
                                                    subscribe->track_namespace_tuple);
    len += xqc_put_varint_len(track_name_len);
    len += track_name_len;
    len += XQC_MOQ_SUBSCRIBER_PRIORITY_FIXED_SIZE;
    len += XQC_MOQ_GROUP_ORDER_FIXED_SIZE;
    len += XQC_MOQ_FORWARD_FIXED_SIZE;
    len += xqc_put_varint_len(subscribe->filter_type);
    if (subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_START
        || subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
        len += xqc_put_varint_len(subscribe->start_group_id);
        len += xqc_put_varint_len(subscribe->start_object_id);
    }
    if (subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
        len += xqc_put_varint_len(subscribe->end_group_id);
        len += xqc_put_varint_len(subscribe->end_object_id);
    }
    len += xqc_put_varint_len(subscribe->params_num);
    len += xqc_moq_msg_encode_params_len(subscribe->params, subscribe->params_num);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_subscribe(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_subscribe_msg_t *subscribe = (xqc_moq_subscribe_msg_t*)msg_base;

    if (subscribe->track_name_len > 0 && subscribe->track_name == NULL) {
        return -XQC_EPARAM;
    }
    if (subscribe->track_name_len > XQC_MOQ_MAX_NAME_LEN) {
        return -XQC_ELIMIT;
    }
    size_t track_name_len = subscribe->track_name_len;

    size_t track_namespace_len = 0;
    if (xqc_moq_track_namespace_tuple_validate_and_sum(subscribe->track_namespace_num,
            subscribe->track_namespace_tuple, &track_namespace_len) != XQC_OK)
    {
        return -XQC_EPARAM;
    }
    subscribe->track_namespace_len = track_namespace_len;
    if (track_namespace_len > XQC_MOQ_MAX_FULL_TRACK_NAME_LEN - track_name_len) {
        return -XQC_ELIMIT;
    }

    xqc_int_t length = xqc_moq_msg_encode_subscribe_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    length = length - xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_SUBSCRIBE);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, subscribe->subscribe_id);
    p = xqc_moq_track_namespace_tuple_encode(p, subscribe->track_namespace_num,
                                             subscribe->track_namespace_tuple);
    p = xqc_put_varint(p, track_name_len);
    if (track_name_len > 0) {
        xqc_memcpy(p, subscribe->track_name, track_name_len);
        p += track_name_len;
    }
    p = xqc_moq_put_u8(p, subscribe->subscriber_priority);
    p = xqc_moq_put_u8(p, subscribe->group_order);
    p = xqc_moq_put_u8(p, subscribe->forward);
    p = xqc_put_varint(p, subscribe->filter_type);
    if (subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_START
        || subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
        p = xqc_put_varint(p, subscribe->start_group_id);
        p = xqc_put_varint(p, subscribe->start_object_id);
    }
    if (subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
        p = xqc_put_varint(p, subscribe->end_group_id);
        p = xqc_put_varint(p, subscribe->end_object_id);
    }
    p = xqc_put_varint(p, subscribe->params_num);
    ret = xqc_moq_msg_encode_params(subscribe->params, subscribe->params_num, p, buf + buf_cap - p);
    if (ret < 0) {
        return ret;
    }
    p += ret;

    return p - buf;
}

//return processed or error
xqc_int_t
xqc_moq_msg_decode_subscribe(uint8_t *buf, size_t buf_len, uint8_t stream_fin, xqc_moq_decode_msg_ctx_t *msg_ctx,
    xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_int_t param_finish = 0;
    uint64_t val = 0;
    xqc_moq_subscribe_msg_t *subscribe = (xqc_moq_subscribe_msg_t *)msg_base;
    xqc_moq_decode_params_ctx_t *params_ctx = &msg_ctx->decode_params_ctx;
    switch (msg_ctx->cur_field_idx) {
        case 0: // Length (16)
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &val);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1: //Subscribe ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>subscribe_id:%d\n",(int)subscribe->subscribe_id);
            msg_ctx->cur_field_idx = 2;
        case 2: //Track Namespace tuple count
            if (subscribe->track_namespace_num == 0) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->track_namespace_num);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
                if (subscribe->track_namespace_num == 0) {
                    return -MOQ_PROTOCOL_VIOLATION;
                }
                if (subscribe->track_namespace_num > XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS) {
                    return -MOQ_PROTOCOL_VIOLATION;
                }
                msg_ctx->cur_array_idx = 0;
                msg_ctx->str_processed = 0;
                msg_ctx->tuple_elem_len = 0;
                msg_ctx->tuple_elem_len_ready = 0;
                subscribe->track_namespace_len = 0;
                if (subscribe->track_namespace_tuple == NULL) {
                    subscribe->track_namespace_tuple =
                        xqc_calloc(subscribe->track_namespace_num, sizeof(xqc_moq_track_ns_field_t));
                    if (subscribe->track_namespace_tuple == NULL) {
                        return -XQC_EMALLOC;
                    }
                }
            }
            msg_ctx->cur_field_idx = 3;
        case 3: //Track Namespace (tuple)
            for (; msg_ctx->cur_array_idx < subscribe->track_namespace_num; msg_ctx->cur_array_idx++) {
                xqc_moq_track_ns_field_t *field =
                    &subscribe->track_namespace_tuple[msg_ctx->cur_array_idx];

                if (!msg_ctx->tuple_elem_len_ready) {
                    ret = xqc_vint_read(buf + processed, buf + buf_len, &msg_ctx->tuple_elem_len);
                    if (ret < 0) {
                        *wait_more_data = 1;
                        break;
                    }
                    processed += ret;
                    msg_ctx->tuple_elem_len_ready = 1;
                    if (msg_ctx->tuple_elem_len > XQC_MOQ_MAX_NAME_LEN) {
                        return -XQC_ELIMIT;
                    }
                    field->len = msg_ctx->tuple_elem_len;
                    if (subscribe->track_namespace_len > XQC_MOQ_MAX_FULL_TRACK_NAME_LEN - field->len) {
                        return -MOQ_PROTOCOL_VIOLATION;
                    }
                    subscribe->track_namespace_len += field->len;
                    if (field->data == NULL && field->len > 0) {
                        field->data = xqc_calloc(1, field->len + 1);
                        if (field->data == NULL) {
                            return -XQC_EMALLOC;
                        }
                    }
                }

                if (processed == buf_len) {
                    *wait_more_data = 1;
                    break;
                }

                size_t field_remaining = (msg_ctx->tuple_elem_len - msg_ctx->str_processed);
                size_t buf_remaining = buf_len - processed;
                size_t copy_len = field_remaining < buf_remaining ? field_remaining : buf_remaining;

                if (copy_len > 0 && field->data != NULL) {
                    xqc_memcpy(field->data + msg_ctx->str_processed, buf + processed, copy_len);
                    msg_ctx->str_processed += copy_len;
                    processed += copy_len;
                }

                if (msg_ctx->str_processed < msg_ctx->tuple_elem_len) {
                    *wait_more_data = 1;
                    break;
                }

                msg_ctx->str_processed = 0;
                msg_ctx->tuple_elem_len_ready = 0;
                msg_ctx->tuple_elem_len = 0;
            }

            if (*wait_more_data == 1) {
                break;
            }

            msg_ctx->cur_field_idx = 4;
        case 4: //Track Name (b)
            if (subscribe->track_name_len == 0) {
                uint64_t track_name_len = 0;
                ret = xqc_vint_read(buf + processed, buf + buf_len, &track_name_len);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                subscribe->track_name_len = track_name_len;
                DEBUG_PRINTF("==>name_len:%d\n",(int)subscribe->track_name_len);
                processed += ret;
            }
            if (subscribe->track_name == NULL) {
                if (subscribe->track_name_len > XQC_MOQ_MAX_NAME_LEN) {
                    return -XQC_ELIMIT;
                }
                if (subscribe->track_namespace_len > XQC_MOQ_MAX_FULL_TRACK_NAME_LEN - subscribe->track_name_len) {
                    return -MOQ_PROTOCOL_VIOLATION;
                }
                subscribe->track_name = xqc_calloc(1, subscribe->track_name_len + 1);
            }
            if (processed == buf_len) {
                *wait_more_data = 1;
                break;
            } else if (subscribe->track_name_len - msg_ctx->str_processed <= buf_len - processed) {
                xqc_memcpy(subscribe->track_name + msg_ctx->str_processed, buf + processed,
                           subscribe->track_name_len - msg_ctx->str_processed);
                processed += subscribe->track_name_len - msg_ctx->str_processed;
                msg_ctx->str_processed = 0; //track_name finish
            } else {
                xqc_memcpy(subscribe->track_name + msg_ctx->str_processed, buf + processed,
                           buf_len - processed);
                msg_ctx->str_processed += buf_len - processed;
                processed += buf_len - processed;
                *wait_more_data = 1;
                break;
            }
            DEBUG_PRINTF("==>track_name:%s\n",subscribe->track_name);
            msg_ctx->cur_field_idx = 5;
        case 5: //Subscriber priority (8)
            ret = xqc_moq_read_u8(buf, buf_len, &processed, &subscribe->subscriber_priority);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            msg_ctx->cur_field_idx = 6;
        case 6: //Group order (8)
            ret = xqc_moq_read_u8(buf, buf_len, &processed, &subscribe->group_order);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            msg_ctx->cur_field_idx = 7;
        case 7: //Forward (8)
            ret = xqc_moq_read_u8(buf, buf_len, &processed, &subscribe->forward);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            msg_ctx->cur_field_idx = 8;
        case 8: //Filter Type (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->filter_type);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            if (subscribe->filter_type == XQC_MOQ_FILTER_LAST_GROUP
                || subscribe->filter_type == XQC_MOQ_FILTER_LAST_OBJECT) {
                msg_ctx->cur_field_idx = 13;
                goto idx_params;
            } else if (subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_START
                       || subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
                msg_ctx->cur_field_idx = 9;
            } else {
                return -XQC_EPARAM;
            }
        case 9: //StartGroup (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->start_group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>start_group_id:%d\n",(int)subscribe->start_group_id);
            msg_ctx->cur_field_idx = 10;
        case 10: //StartObject (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->start_object_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>start_object_id:%d\n",(int)subscribe->start_object_id);
            if (subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
                msg_ctx->cur_field_idx = 11;
            } else {
                msg_ctx->cur_field_idx = 13;
                goto idx_params;
            }
        case 11: //EndGroup (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->end_group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>end_group_id:%d\n",(int)subscribe->end_group_id);
            msg_ctx->cur_field_idx = 12;
        case 12: //EndObject (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->end_object_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>end_object_id:%d\n",(int)subscribe->end_object_id);
            msg_ctx->cur_field_idx = 13;
        case 13: //Number of Parameters (i)
        idx_params:
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->params_num);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>params_num:%d\n",(int)subscribe->params_num);

            if (subscribe->params_num == 0) {
                *finish = 1;
                break;
            }
            if (subscribe->params_num > XQC_MOQ_MAX_PARAMS) {
                return -XQC_ELIMIT;
            }
            subscribe->params = xqc_moq_msg_alloc_params(subscribe->params_num);

            msg_ctx->cur_field_idx = 14;
        case 14: //Subscribe Parameters (..) ...
            ret = xqc_moq_msg_decode_params(buf + processed, buf_len - processed, params_ctx,
                                            subscribe->params, subscribe->params_num,
                                            &param_finish, wait_more_data);
            if (ret < 0) {
                return ret;
            }
            processed += ret;
            if (*wait_more_data == 1) {
                break;
            }
            if (param_finish == 1) {
                *finish = 1;
            }
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

/**
 * SUBSCRIBE_UPDATE Message
 */

void *
xqc_moq_msg_create_subscribe_update()
{
    xqc_moq_subscribe_update_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_subscribe_update_init_handler(&msg->msg_base);
    return msg;
}

void
xqc_moq_msg_free_subscribe_update(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_subscribe_update_msg_t *subscribe_update = (xqc_moq_subscribe_update_msg_t*)msg;
    xqc_moq_msg_free_params(subscribe_update->params, subscribe_update->params_num);
    xqc_free(subscribe_update);
}

xqc_moq_msg_type_t
xqc_moq_msg_subscribe_update_type()
{
    return XQC_MOQ_MSG_SUBSCRIBE_UPDATE;
}

void
xqc_moq_msg_subscribe_update_init_handler(xqc_moq_msg_base_t *msg_base)
{
    *msg_base = subscribe_update_base;
}

xqc_int_t
xqc_moq_msg_encode_subscribe_update_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_subscribe_update_msg_t *subscribe_update = (xqc_moq_subscribe_update_msg_t*)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE_UPDATE);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(subscribe_update->request_id);
    len += xqc_put_varint_len(subscribe_update->subscribe_id);
    len += xqc_put_varint_len(subscribe_update->start_group_id);
    len += xqc_put_varint_len(subscribe_update->start_object_id);
    len += xqc_put_varint_len(subscribe_update->end_group_id);
    len += XQC_MOQ_SUBSCRIBER_PRIORITY_FIXED_SIZE;
    len += XQC_MOQ_FORWARD_FIXED_SIZE;
    len += xqc_put_varint_len(subscribe_update->params_num);
    len += xqc_moq_msg_encode_params_len_v14(subscribe_update->params, subscribe_update->params_num);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_subscribe_update(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_subscribe_update_msg_t *subscribe_update = (xqc_moq_subscribe_update_msg_t*)msg_base;
    xqc_int_t length = xqc_moq_msg_encode_subscribe_update_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_SUBSCRIBE_UPDATE);
    length = length - xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE_UPDATE) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, subscribe_update->request_id);
    p = xqc_put_varint(p, subscribe_update->subscribe_id);
    p = xqc_put_varint(p, subscribe_update->start_group_id);
    p = xqc_put_varint(p, subscribe_update->start_object_id);
    p = xqc_put_varint(p, subscribe_update->end_group_id);
    p = xqc_moq_put_u8(p, subscribe_update->subscriber_priority);
    p = xqc_moq_put_u8(p, subscribe_update->forward);
    p = xqc_put_varint(p, subscribe_update->params_num);
    ret = xqc_moq_msg_encode_params_v14(subscribe_update->params, subscribe_update->params_num, p, buf + buf_cap - p);
    if (ret < 0) {
        return ret;
    }
    p += ret;

    return p - buf;
}

//return processed or error
xqc_int_t
xqc_moq_msg_decode_subscribe_update(uint8_t *buf, size_t buf_len, uint8_t stream_fin, xqc_moq_decode_msg_ctx_t *msg_ctx,
    xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_int_t param_finish = 0;
    uint64_t length = 0;
    xqc_moq_subscribe_update_msg_t *subscribe_update = (xqc_moq_subscribe_update_msg_t *)msg_base;
    xqc_moq_decode_params_ctx_t *params_ctx = &msg_ctx->decode_params_ctx;
    switch (msg_ctx->cur_field_idx) {
        case 0: //Length (16)
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &length);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1: //Request ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_update->request_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>request_id:%d\n",(int)subscribe_update->request_id);
            msg_ctx->cur_field_idx = 2;
        case 2: //Subscription Request ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_update->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>subscribe_id:%d\n",(int)subscribe_update->subscribe_id);
            msg_ctx->cur_field_idx = 3;
        case 3: //Start Location - Group (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_update->start_group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>start_group_id:%d\n",(int)subscribe_update->start_group_id);
            msg_ctx->cur_field_idx = 4;
        case 4: //Start Location - Object (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_update->start_object_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>start_object_id:%d\n",(int)subscribe_update->start_object_id);
            msg_ctx->cur_field_idx = 5;
        case 5: //End Group (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_update->end_group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>end_group_id:%d\n",(int)subscribe_update->end_group_id);
            msg_ctx->cur_field_idx = 6;
        case 6: //Subscriber Priority (8)
            ret = xqc_moq_read_u8(buf, buf_len, &processed, &subscribe_update->subscriber_priority);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            msg_ctx->cur_field_idx = 7;
        case 7: //Forward (8)
            ret = xqc_moq_read_u8(buf, buf_len, &processed, &subscribe_update->forward);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            if (subscribe_update->forward != 0 && subscribe_update->forward != 1) {
                return -XQC_EPARAM;
            }
            msg_ctx->cur_field_idx = 8;
        case 8: //Number of Parameters (i) ...
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_update->params_num);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>params_num:%d\n",(int)subscribe_update->params_num);

            if (subscribe_update->params_num == 0) {
                *finish = 1;
                break;
            }
            if (subscribe_update->params_num > XQC_MOQ_MAX_PARAMS) {
                return -XQC_ELIMIT;
            }
            subscribe_update->params = xqc_moq_msg_alloc_params(subscribe_update->params_num);

            msg_ctx->cur_field_idx = 9;
        case 9: //subscribe_update Parameters (..) ...
            ret = xqc_moq_msg_decode_params_v14(buf + processed, buf_len - processed, params_ctx,
                                            subscribe_update->params, subscribe_update->params_num,
                                            &param_finish, wait_more_data);
            if (ret < 0) {
                return ret;
            }
            processed += ret;
            if (*wait_more_data == 1) {
                break;
            }
            if (param_finish == 1) {
                *finish = 1;
            }
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

/**
 * SUBSCRIBE_OK Message
 */

void *
xqc_moq_msg_create_subscribe_ok()
{
    xqc_moq_subscribe_ok_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_subscribe_ok_init_handler(&msg->msg_base);
    return msg;
}

void
xqc_moq_msg_free_subscribe_ok(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_subscribe_ok_msg_t *subscribe_ok = (xqc_moq_subscribe_ok_msg_t*)msg;
    xqc_moq_msg_free_params(subscribe_ok->params, subscribe_ok->params_num);
    xqc_free(subscribe_ok);
}

xqc_moq_msg_type_t
xqc_moq_msg_subscribe_ok_type()
{
    return XQC_MOQ_MSG_SUBSCRIBE_OK;
}

void
xqc_moq_msg_subscribe_ok_init_handler(xqc_moq_msg_base_t *msg_base)
{
    *msg_base = subscribe_ok_base;
}

xqc_int_t
xqc_moq_msg_encode_subscribe_ok_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_subscribe_ok_msg_t *subscribe_ok = (xqc_moq_subscribe_ok_msg_t*)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE_OK);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(subscribe_ok->subscribe_id);
    len += xqc_put_varint_len(subscribe_ok->track_alias);
    len += xqc_put_varint_len(subscribe_ok->expire_ms);
    len += XQC_MOQ_GROUP_ORDER_FIXED_SIZE;
    len += XQC_MOQ_CONTENT_EXIST_FIXED_SIZE;
    if (subscribe_ok->content_exist == 1) {
        len += xqc_put_varint_len(subscribe_ok->largest_group_id);
        len += xqc_put_varint_len(subscribe_ok->largest_object_id);
    }
    len += xqc_put_varint_len(subscribe_ok->params_num);
    len += xqc_moq_msg_encode_params_len_v14(subscribe_ok->params, subscribe_ok->params_num);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_subscribe_ok(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_subscribe_ok_msg_t *subscribe_ok = (xqc_moq_subscribe_ok_msg_t*)msg_base;
    xqc_int_t length = xqc_moq_msg_encode_subscribe_ok_len(msg_base); 
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    length = length - xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE_OK) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE; 
    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_SUBSCRIBE_OK);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, subscribe_ok->subscribe_id);
    p = xqc_put_varint(p, subscribe_ok->track_alias);
    p = xqc_put_varint(p, subscribe_ok->expire_ms);
    p = xqc_moq_put_u8(p, subscribe_ok->group_order);
    p = xqc_moq_put_u8(p, subscribe_ok->content_exist);
    if (subscribe_ok->content_exist == 1) {
        p = xqc_put_varint(p, subscribe_ok->largest_group_id);
        p = xqc_put_varint(p, subscribe_ok->largest_object_id);
    }
    p = xqc_put_varint(p, subscribe_ok->params_num);
    ret = xqc_moq_msg_encode_params_v14(subscribe_ok->params, subscribe_ok->params_num,
                                    p, buf + buf_cap - p);
    if (ret < 0) {
        return ret;
    }
    p += ret;

    return p - buf;
}

//return processed or error
xqc_int_t
xqc_moq_msg_decode_subscribe_ok(uint8_t *buf, size_t buf_len, uint8_t stream_fin, xqc_moq_decode_msg_ctx_t *msg_ctx,
    xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_int_t param_finish = 0;
    uint64_t length = 0;
    xqc_moq_subscribe_ok_msg_t *subscribe_ok = (xqc_moq_subscribe_ok_msg_t *)msg_base;
    xqc_moq_decode_params_ctx_t *params_ctx = &msg_ctx->decode_params_ctx;
    switch (msg_ctx->cur_field_idx) {
        case 0: //Length (16)
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &length);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1: //Subscribe ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_ok->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            DEBUG_PRINTF("==>subscribe_id:%d\n",(int)subscribe_ok->subscribe_id);

            msg_ctx->cur_field_idx = 2;
        case 2: //Track Alias (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_ok->track_alias);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            DEBUG_PRINTF("==>track_alias:%d\n",(int)subscribe_ok->track_alias);

            msg_ctx->cur_field_idx = 3;
        case 3: //Expires (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_ok->expire_ms);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            DEBUG_PRINTF("==>expires:%d\n",(int)subscribe_ok->expire_ms);

            msg_ctx->cur_field_idx = 4;
        case 4: //Group Order (8)
            ret = xqc_moq_read_u8(buf, buf_len, &processed, &subscribe_ok->group_order);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            if (subscribe_ok->group_order == 0) {
                return -XQC_EILLEGAL_FRAME;
            }
            msg_ctx->cur_field_idx = 5;
        case 5: //ContentExists (8)
            ret = xqc_moq_read_u8(buf, buf_len, &processed, &subscribe_ok->content_exist);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }

            DEBUG_PRINTF("==>content_exist:%d\n",(int)subscribe_ok->content_exist);

            if (subscribe_ok->content_exist > 1) {
                return -XQC_EILLEGAL_FRAME;
            }

            if (subscribe_ok->content_exist == 0) {
                msg_ctx->cur_field_idx = 8;
                goto idx_params;
            }
            msg_ctx->cur_field_idx = 6;
        case 6: //[Largest Group ID (i)]
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_ok->largest_group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            DEBUG_PRINTF("==>largest_group_id:%d\n",(int)subscribe_ok->largest_group_id);

            msg_ctx->cur_field_idx = 7;
        case 7: //[Largest Object ID (i)]
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_ok->largest_object_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            DEBUG_PRINTF("==>largest_object_id:%d\n",(int)subscribe_ok->largest_object_id);

            msg_ctx->cur_field_idx = 8;
        case 8: //Number of Parameters (i)
        idx_params:
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_ok->params_num);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            DEBUG_PRINTF("==>params_num:%d\n",(int)subscribe_ok->params_num);

            if (subscribe_ok->params_num == 0) {
                *finish = 1;
                break;
            }
            if (subscribe_ok->params_num > XQC_MOQ_MAX_PARAMS) {
                return -XQC_ELIMIT;
            }
            if (subscribe_ok->params == NULL) {
                subscribe_ok->params = xqc_moq_msg_alloc_params(subscribe_ok->params_num);
            }
            msg_ctx->cur_field_idx = 9;
        case 9: //Parameters
            ret = xqc_moq_msg_decode_params(buf + processed, buf_len - processed, params_ctx,
                                            subscribe_ok->params, subscribe_ok->params_num,
                                            &param_finish, wait_more_data);
            if (ret < 0) {
                return ret;
            }
            processed += ret;
            if (*wait_more_data == 1) {
                break;
            }
            if (param_finish == 1) {
                *finish = 1;
            }
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}


/**
 * SUBSCRIBE_ERROR Message
 */

void *
xqc_moq_msg_create_subscribe_error()
{
    xqc_moq_subscribe_error_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_subscribe_error_init_handler(&msg->msg_base);
    return msg;
}

void
xqc_moq_msg_free_subscribe_error(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_subscribe_error_msg_t *subscribe_error = (xqc_moq_subscribe_error_msg_t*)msg;
    xqc_free(subscribe_error->reason_phrase);
    xqc_free(subscribe_error);
}

xqc_moq_msg_type_t
xqc_moq_msg_subscribe_error_type()
{
    return XQC_MOQ_MSG_SUBSCRIBE_ERROR;
}

void
xqc_moq_msg_subscribe_error_init_handler(xqc_moq_msg_base_t *msg_base)
{
    *msg_base = subscribe_error_base;
}

xqc_int_t
xqc_moq_msg_encode_subscribe_error_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_subscribe_error_msg_t *subscribe_error = (xqc_moq_subscribe_error_msg_t*)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE_ERROR);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(subscribe_error->subscribe_id);
    len += xqc_put_varint_len(subscribe_error->error_code);
    len += xqc_put_varint_len(subscribe_error->reason_phrase_len);
    len += subscribe_error->reason_phrase_len;
    len += xqc_put_varint_len(subscribe_error->track_alias);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_subscribe_error(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_subscribe_error_msg_t *subscribe_error = (xqc_moq_subscribe_error_msg_t*)msg_base;
    xqc_int_t length = xqc_moq_msg_encode_subscribe_error_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    uint8_t *p = buf;
    length = length - xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE_ERROR) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    p = xqc_put_varint(p, XQC_MOQ_MSG_SUBSCRIBE_ERROR);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, subscribe_error->subscribe_id);
    p = xqc_put_varint(p, subscribe_error->error_code);
    p = xqc_put_varint(p, subscribe_error->reason_phrase_len);
    if (subscribe_error->reason_phrase_len > 0) {
        xqc_memcpy(p, subscribe_error->reason_phrase, subscribe_error->reason_phrase_len);
        p += subscribe_error->reason_phrase_len;
    }
    p = xqc_put_varint(p, subscribe_error->track_alias);
    return p - buf;
}

//return processed or error
xqc_int_t
xqc_moq_msg_decode_subscribe_error(uint8_t *buf, size_t buf_len, uint8_t stream_fin, xqc_moq_decode_msg_ctx_t *msg_ctx,
    xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_int_t param_finish = 0;
    xqc_moq_subscribe_error_msg_t *subscribe_error = (xqc_moq_subscribe_error_msg_t *)msg_base;
    uint64_t length = 0;
    switch (msg_ctx->cur_field_idx) {
        case 0: // Length (i)
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &length);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1: //Subscribe ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_error->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            DEBUG_PRINTF("==>subscribe_id:%d\n",(int)subscribe_error->subscribe_id);

            msg_ctx->cur_field_idx = 2;
        case 2: //Error Code (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_error->error_code);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            DEBUG_PRINTF("==>error_code:%d\n",(int)subscribe_error->error_code);

            msg_ctx->cur_field_idx = 3;
        case 3: //Reason Phrase (b)
            if (subscribe_error->reason_phrase_len == 0) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, (uint64_t *)&subscribe_error->reason_phrase_len);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                DEBUG_PRINTF("==>reason_phrase_len:%d\n",(int)subscribe_error->reason_phrase_len);
                processed += ret;
            }
            if (subscribe_error->reason_phrase_len == 0) {
                msg_ctx->cur_field_idx = 4;
                goto subscribe_error_idx4;
            }
            if (subscribe_error->reason_phrase == NULL) {
                if (subscribe_error->reason_phrase_len > XQC_MOQ_MAX_NAME_LEN) {
                    return -XQC_ELIMIT;
                }
                subscribe_error->reason_phrase = xqc_calloc(1, subscribe_error->reason_phrase_len + 1);
            }
            if (processed == buf_len) {
                *wait_more_data = 1;
                break;
            } else if (subscribe_error->reason_phrase_len - msg_ctx->str_processed <= buf_len - processed) {
                xqc_memcpy(subscribe_error->reason_phrase + msg_ctx->str_processed, buf + processed,
                           subscribe_error->reason_phrase_len - msg_ctx->str_processed);
                processed += subscribe_error->reason_phrase_len - msg_ctx->str_processed;
                msg_ctx->str_processed = 0; //reason_phrase finish
            } else {
                xqc_memcpy(subscribe_error->reason_phrase + msg_ctx->str_processed, buf + processed,
                           buf_len - processed);
                msg_ctx->str_processed += buf_len - processed;
                processed += buf_len - processed;
                *wait_more_data = 1;
                break;
            }
            DEBUG_PRINTF("==>reason_phrase:%s\n",subscribe_error->reason_phrase);
            msg_ctx->cur_field_idx = 4;
        case 4: //Track Alias (i)
            subscribe_error_idx4:
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_error->track_alias);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            DEBUG_PRINTF("==>track_alias:%d\n",(int)subscribe_error->track_alias);

            *finish = 1;
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

/**
 * PUBLISH Message
 */

void *
xqc_moq_msg_create_publish()
{
    xqc_moq_publish_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_publish_init_handler(&msg->msg_base);
    return msg;
}

void
xqc_moq_msg_free_publish(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_publish_msg_t *publish = (xqc_moq_publish_msg_t*)msg;
    if (publish->track_namespace_tuple) {
        for (uint64_t i = 0; i < publish->track_namespace_num; i++) {
            if (publish->track_namespace_tuple[i].data) {
                xqc_free(publish->track_namespace_tuple[i].data);
                publish->track_namespace_tuple[i].data = NULL;
                publish->track_namespace_tuple[i].len = 0;
            }
        }
        xqc_free(publish->track_namespace_tuple);
        publish->track_namespace_tuple = NULL;
        publish->track_namespace_num = 0;
    }
    xqc_free(publish->track_name);
    publish->track_name = NULL;
    xqc_moq_msg_free_params(publish->params, publish->params_num);
    publish->params = NULL;
    xqc_free(publish);
}

xqc_moq_msg_type_t
xqc_moq_msg_publish_type()
{
    return XQC_MOQ_MSG_PUBLISH;
}

void
xqc_moq_msg_publish_init_handler(xqc_moq_msg_base_t *msg_base)
{
    *msg_base = publish_base;
}

xqc_int_t
xqc_moq_msg_encode_publish_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_publish_msg_t *publish = (xqc_moq_publish_msg_t*)msg_base;
    size_t track_name_len = publish->track_name_len;

    size_t track_namespace_len = 0;
    if (xqc_moq_track_namespace_tuple_validate_and_sum(publish->track_namespace_num,
            publish->track_namespace_tuple, &track_namespace_len) != XQC_OK)
    {
        return -XQC_EPARAM;
    }
    len += xqc_put_varint_len(XQC_MOQ_MSG_PUBLISH);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(publish->subscribe_id);
    len += xqc_moq_track_namespace_tuple_encode_len(publish->track_namespace_num,
                                                    publish->track_namespace_tuple);
    len += xqc_put_varint_len(track_name_len);
    len += track_name_len;
    len += xqc_put_varint_len(publish->track_alias);
    len += XQC_MOQ_GROUP_ORDER_FIXED_SIZE;
    len += XQC_MOQ_CONTENT_EXIST_FIXED_SIZE;
    if (publish->content_exist == 1) {
        len += xqc_put_varint_len(publish->largest_group_id);
        len += xqc_put_varint_len(publish->largest_object_id);
    }
    len += XQC_MOQ_FORWARD_FIXED_SIZE;
    len += xqc_put_varint_len(publish->params_num);
    len += xqc_moq_msg_encode_params_len_v14(publish->params, publish->params_num);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_publish(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_publish_msg_t *publish = (xqc_moq_publish_msg_t*)msg_base;

    if (publish->track_name_len > 0 && publish->track_name == NULL) {
        return -XQC_EPARAM;
    }
    if (publish->track_name_len > XQC_MOQ_MAX_NAME_LEN) {
        return -XQC_ELIMIT;
    }
    xqc_int_t track_name_len = publish->track_name_len;

    size_t track_namespace_len = 0;
    if (xqc_moq_track_namespace_tuple_validate_and_sum(publish->track_namespace_num,
            publish->track_namespace_tuple, &track_namespace_len) != XQC_OK)
    {
        return -XQC_EPARAM;
    }
    publish->track_namespace_len = track_namespace_len;
    if (track_namespace_len > XQC_MOQ_MAX_FULL_TRACK_NAME_LEN - (size_t)track_name_len) {
        return -XQC_ELIMIT;
    }

    xqc_int_t length = xqc_moq_msg_encode_publish_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    length = length - xqc_put_varint_len(XQC_MOQ_MSG_PUBLISH) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_PUBLISH);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, publish->subscribe_id);
    p = xqc_moq_track_namespace_tuple_encode(p, publish->track_namespace_num,
                                             publish->track_namespace_tuple);
    p = xqc_put_varint(p, track_name_len);
    if (track_name_len > 0) {
        xqc_memcpy(p, publish->track_name, track_name_len);
        p += track_name_len;
    }
    p = xqc_put_varint(p, publish->track_alias);
    p = xqc_moq_put_u8(p, publish->group_order);
    p = xqc_moq_put_u8(p, publish->content_exist);
    if (publish->content_exist == 1) {
        p = xqc_put_varint(p, publish->largest_group_id);
        p = xqc_put_varint(p, publish->largest_object_id);
    }
    p = xqc_moq_put_u8(p, publish->forward);
    p = xqc_put_varint(p, publish->params_num);
    ret = xqc_moq_msg_encode_params_v14(publish->params, publish->params_num, p, buf + buf_cap - p);
    if (ret < 0) {
        return ret;
    }
    p += ret;

    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_publish(uint8_t *buf, size_t buf_len, uint8_t stream_fin, xqc_moq_decode_msg_ctx_t *msg_ctx,
    xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_int_t param_finish = 0;
    xqc_moq_publish_msg_t *publish = (xqc_moq_publish_msg_t *)msg_base;
    xqc_moq_decode_params_ctx_t *params_ctx = &msg_ctx->decode_params_ctx;
    uint64_t length = 0;

    switch (msg_ctx->cur_field_idx) {
        case 0: // length
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &length);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1: //Request ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 2;
        case 2: //Track Namespace (tuple)
            if (publish->track_namespace_num == 0) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, &publish->track_namespace_num);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
                if (publish->track_namespace_num == 0) {
                    return -MOQ_PROTOCOL_VIOLATION;
                }
                if (publish->track_namespace_num > XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS) {
                    return -MOQ_PROTOCOL_VIOLATION;
                }
                msg_ctx->cur_array_idx = 0;
                msg_ctx->str_processed = 0;
                msg_ctx->tuple_elem_len = 0;
                msg_ctx->tuple_elem_len_ready = 0;
                publish->track_namespace_len = 0;
                if (publish->track_namespace_tuple == NULL) {
                    publish->track_namespace_tuple =
                        xqc_calloc(publish->track_namespace_num, sizeof(xqc_moq_track_ns_field_t));
                    if (publish->track_namespace_tuple == NULL) {
                        return -XQC_EMALLOC;
                    }
                }
            }
            for (; msg_ctx->cur_array_idx < publish->track_namespace_num; msg_ctx->cur_array_idx++) {
                xqc_moq_track_ns_field_t *field =
                    &publish->track_namespace_tuple[msg_ctx->cur_array_idx];

                if (!msg_ctx->tuple_elem_len_ready) {
                    ret = xqc_vint_read(buf + processed, buf + buf_len, &msg_ctx->tuple_elem_len);
                    if (ret < 0) {
                        *wait_more_data = 1;
                        break;
                    }
                    processed += ret;
                    msg_ctx->tuple_elem_len_ready = 1;
                    if (msg_ctx->tuple_elem_len > XQC_MOQ_MAX_NAME_LEN) {
                        return -XQC_ELIMIT;
                    }
                    field->len = msg_ctx->tuple_elem_len;
                    if (publish->track_namespace_len > XQC_MOQ_MAX_FULL_TRACK_NAME_LEN - field->len) {
                        return -MOQ_PROTOCOL_VIOLATION;
                    }
                    publish->track_namespace_len += field->len;
                    if (field->data == NULL && field->len > 0) {
                        field->data = xqc_calloc(1, field->len + 1);
                        if (field->data == NULL) {
                            return -XQC_EMALLOC;
                        }
                    }
                }

                if (processed == buf_len) {
                    *wait_more_data = 1;
                    break;
                }

                xqc_int_t field_remaining = msg_ctx->tuple_elem_len - msg_ctx->str_processed;
                xqc_int_t buf_remaining = buf_len - processed;
                xqc_int_t copy_len = field_remaining < buf_remaining ? field_remaining : buf_remaining;

                if (copy_len > 0 && field->data != NULL) {
                    xqc_memcpy(field->data + msg_ctx->str_processed, buf + processed, copy_len);
                    msg_ctx->str_processed += copy_len;
                    processed += copy_len;
                }

                if (msg_ctx->str_processed < msg_ctx->tuple_elem_len) {
                    *wait_more_data = 1;
                    break;
                }

                msg_ctx->str_processed = 0;
                msg_ctx->tuple_elem_len_ready = 0;
                msg_ctx->tuple_elem_len = 0;
            }

            if (*wait_more_data == 1) {
                break;
            }
            msg_ctx->cur_field_idx = 3;
        case 3: //Track Name (b)
            if (publish->track_name_len == 0) {
                uint64_t track_name_len = 0;
                ret = xqc_vint_read(buf + processed, buf + buf_len, &track_name_len);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                publish->track_name_len = track_name_len;
                processed += ret;
            }
            if (publish->track_name == NULL) {
                if (publish->track_name_len == 0 || publish->track_name_len > XQC_MOQ_MAX_NAME_LEN) {
                    return -XQC_ELIMIT;
                }
                if (publish->track_namespace_len > XQC_MOQ_MAX_FULL_TRACK_NAME_LEN - publish->track_name_len) {
                    return -MOQ_PROTOCOL_VIOLATION;
                }
                publish->track_name = xqc_calloc(1, publish->track_name_len + 1);
            }
            if (processed == buf_len) {
                *wait_more_data = 1;
                break;
            } else if (publish->track_name_len - msg_ctx->str_processed <= buf_len - processed) {
                xqc_memcpy(publish->track_name + msg_ctx->str_processed, buf + processed,
                           publish->track_name_len - msg_ctx->str_processed);
                processed += publish->track_name_len - msg_ctx->str_processed;
                msg_ctx->str_processed = 0;
            } else {
                xqc_memcpy(publish->track_name + msg_ctx->str_processed, buf + processed,
                           buf_len - processed);
                msg_ctx->str_processed += buf_len - processed;
                processed += buf_len - processed;
                *wait_more_data = 1;
                break;
            }
            msg_ctx->cur_field_idx = 4;
        case 4: //Track Alias (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish->track_alias);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 5;
        case 5: //Group Order (8)
            ret = xqc_moq_read_u8(buf, buf_len, &processed, &publish->group_order);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            msg_ctx->cur_field_idx = 6;
        case 6: //Content Exists (8)
            ret = xqc_moq_read_u8(buf, buf_len, &processed, &publish->content_exist);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            if (publish->content_exist == 1) {
                msg_ctx->cur_field_idx = 7;
            } else {
                msg_ctx->cur_field_idx = 9;
                goto idx9;
            }
        case 7: //Largest Group ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish->largest_group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 8;
        case 8: //Largest Object ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish->largest_object_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 9;
        case 9: //Forward (8)
            idx9:
            ret = xqc_moq_read_u8(buf, buf_len, &processed, &publish->forward);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            msg_ctx->cur_field_idx = 10;
        case 10: //Number of Parameters (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish->params_num);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            if (publish->params_num == 0) {
                *finish = 1;
                break;
            }
            if (publish->params_num > XQC_MOQ_MAX_PARAMS) {
                return -XQC_ELIMIT;
            }
            publish->params = xqc_moq_msg_alloc_params(publish->params_num);
            msg_ctx->cur_field_idx = 11;
        case 11: //Parameters
            ret = xqc_moq_msg_decode_params_v14(buf + processed, buf_len - processed, params_ctx,
                                            publish->params, publish->params_num,
                                            &param_finish, wait_more_data);
            if (ret < 0) {
                return ret;
            }
            processed += ret;
            if (*wait_more_data == 1) {
                break;
            }
            if (param_finish == 1) {
                *finish = 1;
            }
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

/**
 * PUBLISH_OK Message
 */

void *
xqc_moq_msg_create_publish_ok()
{
    xqc_moq_publish_ok_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_publish_ok_init_handler(&msg->msg_base);
    return msg;
}

void
xqc_moq_msg_free_publish_ok(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_publish_ok_msg_t *publish_ok = (xqc_moq_publish_ok_msg_t*)msg;
    xqc_moq_msg_free_params(publish_ok->params, publish_ok->params_num);
    xqc_free(publish_ok);
}

xqc_moq_msg_type_t
xqc_moq_msg_publish_ok_type()
{
    return XQC_MOQ_MSG_PUBLISH_OK;
}

void
xqc_moq_msg_publish_ok_init_handler(xqc_moq_msg_base_t *msg_base)
{
    *msg_base = publish_ok_base;
}

xqc_int_t
xqc_moq_msg_encode_publish_ok_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_publish_ok_msg_t *publish_ok = (xqc_moq_publish_ok_msg_t*)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_PUBLISH_OK);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(publish_ok->subscribe_id);
    len += XQC_MOQ_FORWARD_FIXED_SIZE;
    len += XQC_MOQ_SUBSCRIBER_PRIORITY_FIXED_SIZE;
    len += XQC_MOQ_GROUP_ORDER_FIXED_SIZE;
    len += xqc_put_varint_len(publish_ok->filter_type);
    if (publish_ok->filter_type == XQC_MOQ_FILTER_ABSOLUTE_START
        || publish_ok->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
        len += xqc_put_varint_len(publish_ok->start_group_id);
        len += xqc_put_varint_len(publish_ok->start_object_id);
    }
    if (publish_ok->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
        len += xqc_put_varint_len(publish_ok->end_group_id);
    }
    len += xqc_put_varint_len(publish_ok->params_num);
    len += xqc_moq_msg_encode_params_len(publish_ok->params, publish_ok->params_num);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_publish_ok(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_publish_ok_msg_t *publish_ok = (xqc_moq_publish_ok_msg_t*)msg_base;
    xqc_int_t length = xqc_moq_msg_encode_publish_ok_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    length = length - xqc_put_varint_len(XQC_MOQ_MSG_PUBLISH_OK) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_PUBLISH_OK);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, publish_ok->subscribe_id);
    p = xqc_moq_put_u8(p, publish_ok->forward);
    p = xqc_moq_put_u8(p, publish_ok->subscriber_priority);
    p = xqc_moq_put_u8(p, publish_ok->group_order);
    p = xqc_put_varint(p, publish_ok->filter_type);
    if (publish_ok->filter_type == XQC_MOQ_FILTER_ABSOLUTE_START
        || publish_ok->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
        p = xqc_put_varint(p, publish_ok->start_group_id);
        p = xqc_put_varint(p, publish_ok->start_object_id);
    }
    if (publish_ok->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
        p = xqc_put_varint(p, publish_ok->end_group_id);
    }
    p = xqc_put_varint(p, publish_ok->params_num);
    ret = xqc_moq_msg_encode_params(publish_ok->params, publish_ok->params_num, p, buf + buf_cap - p);
    if (ret < 0) {
        return ret;
    }
    p += ret;

    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_publish_ok(uint8_t *buf, size_t buf_len, uint8_t stream_fin, xqc_moq_decode_msg_ctx_t *msg_ctx,
    xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_int_t param_finish = 0;
    xqc_moq_publish_ok_msg_t *publish_ok = (xqc_moq_publish_ok_msg_t *)msg_base;
    xqc_moq_decode_params_ctx_t *params_ctx = &msg_ctx->decode_params_ctx;
    uint64_t length = 0;

    switch (msg_ctx->cur_field_idx) {
        case 0: // Length (i)
            ret = xqc_moq_length_read(buf+processed, buf + buf_len, &length);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1: //Request ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish_ok->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 2;
        case 2: //Forward (8)
            ret = xqc_moq_read_u8(buf, buf_len, &processed, &publish_ok->forward);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            msg_ctx->cur_field_idx = 3;
        case 3: //Subscriber Priority (8)
            ret = xqc_moq_read_u8(buf, buf_len, &processed, &publish_ok->subscriber_priority);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            msg_ctx->cur_field_idx = 4;
        case 4: //Group Order (8)
            ret = xqc_moq_read_u8(buf, buf_len, &processed, &publish_ok->group_order);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            msg_ctx->cur_field_idx = 5;
        case 5: //Filter Type (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish_ok->filter_type);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            if (publish_ok->filter_type == XQC_MOQ_FILTER_ABSOLUTE_START
                || publish_ok->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
                msg_ctx->cur_field_idx = 6;
            } else {
                msg_ctx->cur_field_idx = 9;
                goto publish_ok_idx9;
            }
        case 6: //Start Group (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish_ok->start_group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 7;
        case 7: //Start Object (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish_ok->start_object_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            if (publish_ok->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
                msg_ctx->cur_field_idx = 8;
            } else {
                msg_ctx->cur_field_idx = 9;
                goto publish_ok_idx9;
            }
        case 8: //End Group (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish_ok->end_group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 9;
        case 9: //Parameters Num (i)
publish_ok_idx9:
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish_ok->params_num);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            if (publish_ok->params_num == 0) {
                *finish = 1;
                break;
            }
            if (publish_ok->params_num > XQC_MOQ_MAX_PARAMS) {
                return -XQC_ELIMIT;
            }
            publish_ok->params = xqc_moq_msg_alloc_params(publish_ok->params_num);
            msg_ctx->cur_field_idx = 10;
        case 10: //Parameters (..)
            ret = xqc_moq_msg_decode_params_v14(buf + processed, buf_len - processed, params_ctx,
                                            publish_ok->params, publish_ok->params_num,
                                            &param_finish, wait_more_data);
            if (ret < 0) {
                return ret;
            }
            processed += ret;
            if (*wait_more_data == 1) {
                break;
            }
            if (param_finish == 1) {
                *finish = 1;
            }
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

/**
 * PUBLISH_ERROR Message
 */

void *
xqc_moq_msg_create_publish_error()
{
    xqc_moq_publish_error_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_publish_error_init_handler(&msg->msg_base);
    return msg;
}

void
xqc_moq_msg_free_publish_error(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_publish_error_msg_t *publish_error = (xqc_moq_publish_error_msg_t*)msg;
    xqc_free(publish_error->reason_phrase);
    xqc_free(publish_error);
}

xqc_moq_msg_type_t
xqc_moq_msg_publish_error_type()
{
    return XQC_MOQ_MSG_PUBLISH_ERROR;
}

void
xqc_moq_msg_publish_error_init_handler(xqc_moq_msg_base_t *msg_base)
{
    *msg_base = publish_error_base;
}

xqc_int_t
xqc_moq_msg_encode_publish_error_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_publish_error_msg_t *publish_error = (xqc_moq_publish_error_msg_t*)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_PUBLISH_ERROR);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(publish_error->subscribe_id);
    len += xqc_put_varint_len(publish_error->error_code);
    len += xqc_put_varint_len(publish_error->reason_phrase_len);
    len += publish_error->reason_phrase_len;
    return len;
}

xqc_int_t
xqc_moq_msg_encode_publish_error(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_moq_publish_error_msg_t *publish_error = (xqc_moq_publish_error_msg_t*)msg_base;
    xqc_int_t length = xqc_moq_msg_encode_publish_error_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    uint8_t *p = buf;
    length = length - xqc_put_varint_len(XQC_MOQ_MSG_PUBLISH_ERROR) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    p = xqc_put_varint(p, XQC_MOQ_MSG_PUBLISH_ERROR);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, publish_error->subscribe_id);
    p = xqc_put_varint(p, publish_error->error_code);
    p = xqc_put_varint(p, publish_error->reason_phrase_len);
    if (publish_error->reason_phrase_len > 0) {
        xqc_memcpy(p, publish_error->reason_phrase, publish_error->reason_phrase_len);
        p += publish_error->reason_phrase_len;
    }

    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_publish_error(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_moq_publish_error_msg_t *publish_error = (xqc_moq_publish_error_msg_t*)msg_base;
    uint64_t length = 0;
    switch (msg_ctx->cur_field_idx) {
        case 0: // Length (i)
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &length);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1: //Request ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish_error->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 2;
        case 2: //Error Code (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish_error->error_code);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 3;
        case 3: //Reason Phrase (b)
            if (publish_error->reason_phrase_len == 0) {
                uint64_t reason_phrase_len = 0;
                ret = xqc_vint_read(buf + processed, buf + buf_len, &reason_phrase_len);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                publish_error->reason_phrase_len = reason_phrase_len;
                processed += ret;
            }
            if (publish_error->reason_phrase_len == 0) {
                *finish = 1;
                break;
            }
            if (publish_error->reason_phrase == NULL) {
                if (publish_error->reason_phrase_len > XQC_MOQ_MAX_NAME_LEN) {
                    return -XQC_ELIMIT;
                }
                publish_error->reason_phrase = xqc_calloc(1, publish_error->reason_phrase_len + 1);
            }
            if (processed == buf_len) {
                *wait_more_data = 1;
                break;
            } else if (publish_error->reason_phrase_len - msg_ctx->str_processed <= buf_len - processed) {
                xqc_memcpy(publish_error->reason_phrase + msg_ctx->str_processed, buf + processed,
                           publish_error->reason_phrase_len - msg_ctx->str_processed);
                processed += publish_error->reason_phrase_len - msg_ctx->str_processed;
                msg_ctx->str_processed = 0;
            } else {
                xqc_memcpy(publish_error->reason_phrase + msg_ctx->str_processed, buf + processed,
                           buf_len - processed);
                msg_ctx->str_processed += buf_len - processed;
                processed += buf_len - processed;
                *wait_more_data = 1;
                break;
            }
            *finish = 1;
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

/**
 * PUBLISH_DONE Message
 */

void *
xqc_moq_msg_create_publish_done()
{
    xqc_moq_publish_done_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_publish_done_init_handler(&msg->msg_base);
    return msg;
}

void
xqc_moq_msg_free_publish_done(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_publish_done_msg_t *publish_done = (xqc_moq_publish_done_msg_t*)msg;
    xqc_free(publish_done->reason_phrase);
    xqc_free(publish_done);
}

xqc_moq_msg_type_t
xqc_moq_msg_publish_done_type()
{
    return XQC_MOQ_MSG_PUBLISH_DONE;
}

void
xqc_moq_msg_publish_done_init_handler(xqc_moq_msg_base_t *msg_base)
{
    *msg_base = publish_done_base;
}

xqc_int_t
xqc_moq_msg_encode_publish_done_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_publish_done_msg_t *publish_done = (xqc_moq_publish_done_msg_t*)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_PUBLISH_DONE);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(publish_done->subscribe_id);
    len += xqc_put_varint_len(publish_done->status_code);
    len += xqc_put_varint_len(publish_done->stream_count);
    len += xqc_put_varint_len(publish_done->reason_phrase_len);
    len += publish_done->reason_phrase_len;
    return len;
}

xqc_int_t
xqc_moq_msg_encode_publish_done(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t length = 0;
    xqc_moq_publish_done_msg_t *publish_done = (xqc_moq_publish_done_msg_t*)msg_base;
    length = xqc_moq_msg_encode_publish_done_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    length = length - xqc_put_varint_len(XQC_MOQ_MSG_PUBLISH_DONE) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_PUBLISH_DONE);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, publish_done->subscribe_id);
    p = xqc_put_varint(p, publish_done->status_code);
    p = xqc_put_varint(p, publish_done->stream_count);
    p = xqc_put_varint(p, publish_done->reason_phrase_len);
    xqc_memcpy(p, publish_done->reason_phrase, publish_done->reason_phrase_len);
    p += publish_done->reason_phrase_len;

    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_publish_done(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    uint64_t length = 0;
    xqc_moq_publish_done_msg_t *publish_done = (xqc_moq_publish_done_msg_t*)msg_base;
    switch (msg_ctx->cur_field_idx) {
        case 0: //Length (16)
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &length);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1: //Request ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish_done->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 2;
        case 2: //Status Code (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish_done->status_code);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 3;
        case 3: //Stream Count (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish_done->stream_count);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 4;
        case 4: //Reason Phrase (b)
            if (publish_done->reason_phrase_len == 0) {
                uint64_t reason_phrase_len = 0;
                ret = xqc_vint_read(buf + processed, buf + buf_len, &reason_phrase_len);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                publish_done->reason_phrase_len = reason_phrase_len;
                processed += ret;
            }
            if (publish_done->reason_phrase == NULL) {
                if (publish_done->reason_phrase_len > XQC_MOQ_MAX_NAME_LEN) {
                    return -XQC_ELIMIT;
                }
                publish_done->reason_phrase = xqc_calloc(1, publish_done->reason_phrase_len + 1);
            }
            if (processed == buf_len) {
                *wait_more_data = 1;
                break;
            } else if (publish_done->reason_phrase_len - msg_ctx->str_processed <= buf_len - processed) {
                xqc_memcpy(publish_done->reason_phrase + msg_ctx->str_processed, buf + processed,
                           publish_done->reason_phrase_len - msg_ctx->str_processed);
                processed += publish_done->reason_phrase_len - msg_ctx->str_processed;
                msg_ctx->str_processed = 0;
            } else {
                xqc_memcpy(publish_done->reason_phrase + msg_ctx->str_processed, buf + processed,
                           buf_len - processed);
                msg_ctx->str_processed += buf_len - processed;
                processed += buf_len - processed;
                *wait_more_data = 1;
                break;
            }
            *finish = 1;
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

/**
 * PUBLISH_NAMESPACE Message
 */

void *
xqc_moq_msg_create_publish_namespace()
{
    xqc_moq_publish_namespace_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_publish_namespace_init_handler(&msg->msg_base);
    return msg;
}

void
xqc_moq_msg_free_publish_namespace(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_publish_namespace_msg_t *publish_namespace = (xqc_moq_publish_namespace_msg_t *)msg;
    if (publish_namespace->track_namespace_tuple) {
        for (uint64_t i = 0; i < publish_namespace->track_namespace_num; i++) {
            if (publish_namespace->track_namespace_tuple[i].data) {
                xqc_free(publish_namespace->track_namespace_tuple[i].data);
                publish_namespace->track_namespace_tuple[i].data = NULL;
                publish_namespace->track_namespace_tuple[i].len = 0;
            }
        }
        xqc_free(publish_namespace->track_namespace_tuple);
        publish_namespace->track_namespace_tuple = NULL;
        publish_namespace->track_namespace_num = 0;
    }
    xqc_moq_msg_free_params(publish_namespace->params, publish_namespace->params_num);
    xqc_free(publish_namespace);
}

xqc_moq_msg_type_t
xqc_moq_msg_publish_namespace_type()
{
    return XQC_MOQ_MSG_PUBLISH_NAMESPACE;
}

void
xqc_moq_msg_publish_namespace_init_handler(xqc_moq_msg_base_t *msg_base)
{
    *msg_base = publish_namespace_base;
}

xqc_int_t
xqc_moq_msg_encode_publish_namespace_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_publish_namespace_msg_t *publish_namespace = (xqc_moq_publish_namespace_msg_t *)msg_base;
    size_t track_namespace_len = 0;
    if (xqc_moq_track_namespace_tuple_validate_and_sum(publish_namespace->track_namespace_num,
            publish_namespace->track_namespace_tuple, &track_namespace_len) != XQC_OK)
    {
        return -XQC_EPARAM;
    }

    len += xqc_put_varint_len(XQC_MOQ_MSG_PUBLISH_NAMESPACE);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(publish_namespace->request_id);
    len += xqc_moq_track_namespace_tuple_encode_len(publish_namespace->track_namespace_num,
                                                    publish_namespace->track_namespace_tuple);
    len += xqc_put_varint_len(publish_namespace->params_num);
    len += xqc_moq_msg_encode_params_len_v14(publish_namespace->params, publish_namespace->params_num);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_publish_namespace(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_publish_namespace_msg_t *publish_namespace = (xqc_moq_publish_namespace_msg_t *)msg_base;
    size_t track_namespace_len = 0;
    if (xqc_moq_track_namespace_tuple_validate_and_sum(publish_namespace->track_namespace_num,
            publish_namespace->track_namespace_tuple, &track_namespace_len) != XQC_OK)
    {
        return -XQC_EPARAM;
    }
    publish_namespace->track_namespace_len = track_namespace_len;

    xqc_int_t length = xqc_moq_msg_encode_publish_namespace_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    length = length - xqc_put_varint_len(XQC_MOQ_MSG_PUBLISH_NAMESPACE) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_PUBLISH_NAMESPACE);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, publish_namespace->request_id);
    p = xqc_moq_track_namespace_tuple_encode(p, publish_namespace->track_namespace_num,
                                             publish_namespace->track_namespace_tuple);
    p = xqc_put_varint(p, publish_namespace->params_num);
    ret = xqc_moq_msg_encode_params_v14(publish_namespace->params, publish_namespace->params_num,
                                        p, buf + buf_cap - p);
    if (ret < 0) {
        return ret;
    }
    p += ret;
    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_publish_namespace(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base,
    xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_int_t param_finish = 0;
    uint64_t length = 0;
    xqc_moq_publish_namespace_msg_t *publish_namespace = (xqc_moq_publish_namespace_msg_t *)msg_base;
    xqc_moq_decode_params_ctx_t *params_ctx = &msg_ctx->decode_params_ctx;

    switch (msg_ctx->cur_field_idx) {
        case 0: /* Length (16) */
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &length);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1: /* Request ID (i) */
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish_namespace->request_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 2;
        case 2: /* Track Namespace tuple count */
            if (publish_namespace->track_namespace_num == 0) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, &publish_namespace->track_namespace_num);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
                if (publish_namespace->track_namespace_num == 0) {
                    return -MOQ_PROTOCOL_VIOLATION;
                }
                if (publish_namespace->track_namespace_num > XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS) {
                    return -MOQ_PROTOCOL_VIOLATION;
                }
                msg_ctx->cur_array_idx = 0;
                msg_ctx->str_processed = 0;
                msg_ctx->tuple_elem_len = 0;
                msg_ctx->tuple_elem_len_ready = 0;
                publish_namespace->track_namespace_len = 0;
                if (publish_namespace->track_namespace_tuple == NULL) {
                    publish_namespace->track_namespace_tuple =
                        xqc_calloc(publish_namespace->track_namespace_num, sizeof(xqc_moq_track_ns_field_t));
                    if (publish_namespace->track_namespace_tuple == NULL) {
                        return -XQC_EMALLOC;
                    }
                }
            }
            msg_ctx->cur_field_idx = 3;
        case 3: /* Track Namespace (tuple) */
            for (; msg_ctx->cur_array_idx < publish_namespace->track_namespace_num; msg_ctx->cur_array_idx++) {
                xqc_moq_track_ns_field_t *field =
                    &publish_namespace->track_namespace_tuple[msg_ctx->cur_array_idx];

                if (!msg_ctx->tuple_elem_len_ready) {
                    ret = xqc_vint_read(buf + processed, buf + buf_len, &msg_ctx->tuple_elem_len);
                    if (ret < 0) {
                        *wait_more_data = 1;
                        break;
                    }
                    processed += ret;
                    msg_ctx->tuple_elem_len_ready = 1;
                    if (msg_ctx->tuple_elem_len > XQC_MOQ_MAX_NAME_LEN) {
                        return -XQC_ELIMIT;
                    }
                    field->len = msg_ctx->tuple_elem_len;
                    if (publish_namespace->track_namespace_len
                        > XQC_MOQ_MAX_FULL_TRACK_NAME_LEN - field->len)
                    {
                        return -MOQ_PROTOCOL_VIOLATION;
                    }
                    publish_namespace->track_namespace_len += field->len;
                    if (field->data == NULL && field->len > 0) {
                        field->data = xqc_calloc(1, field->len + 1);
                        if (field->data == NULL) {
                            return -XQC_EMALLOC;
                        }
                    }
                }

                if (processed == buf_len) {
                    *wait_more_data = 1;
                    break;
                }

                size_t field_remaining = (msg_ctx->tuple_elem_len - msg_ctx->str_processed);
                size_t buf_remaining = buf_len - processed;
                size_t copy_len = field_remaining < buf_remaining ? field_remaining : buf_remaining;

                if (copy_len > 0 && field->data != NULL) {
                    xqc_memcpy(field->data + msg_ctx->str_processed, buf + processed, copy_len);
                    msg_ctx->str_processed += copy_len;
                    processed += copy_len;
                }

                if (msg_ctx->str_processed < msg_ctx->tuple_elem_len) {
                    *wait_more_data = 1;
                    break;
                }

                msg_ctx->str_processed = 0;
                msg_ctx->tuple_elem_len_ready = 0;
                msg_ctx->tuple_elem_len = 0;
            }

            if (*wait_more_data == 1) {
                break;
            }

            msg_ctx->cur_field_idx = 4;
        case 4: /* Number of Parameters (i) */
            if (publish_namespace->params_num == 0) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, &publish_namespace->params_num);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
                if (publish_namespace->params_num == 0) {
                    *finish = 1;
                    break;
                }
                if (publish_namespace->params_num > XQC_MOQ_MAX_PARAMS) {
                    return -XQC_ELIMIT;
                }
                publish_namespace->params = xqc_moq_msg_alloc_params(publish_namespace->params_num);
                if (publish_namespace->params == NULL) {
                    return -XQC_EMALLOC;
                }
            }
            msg_ctx->cur_field_idx = 5;
        case 5:
            ret = xqc_moq_msg_decode_params_v14(buf + processed, buf_len - processed, params_ctx,
                                                publish_namespace->params, publish_namespace->params_num,
                                                &param_finish, wait_more_data);
            if (ret < 0) {
                return ret;
            }
            processed += ret;
            if (*wait_more_data == 1) {
                break;
            }
            if (param_finish == 1) {
                *finish = 1;
            }
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

/**
 * PUBLISH_NAMESPACE_OK Message
 */

void *
xqc_moq_msg_create_publish_namespace_ok()
{
    xqc_moq_publish_namespace_ok_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_publish_namespace_ok_init_handler(&msg->msg_base);
    return msg;
}

void
xqc_moq_msg_free_publish_namespace_ok(void *msg)
{
    xqc_free(msg);
}

xqc_moq_msg_type_t
xqc_moq_msg_publish_namespace_ok_type()
{
    return XQC_MOQ_MSG_PUBLISH_NAMESPACE_OK;
}

void
xqc_moq_msg_publish_namespace_ok_init_handler(xqc_moq_msg_base_t *msg_base)
{
    *msg_base = publish_namespace_ok_base;
}

xqc_int_t
xqc_moq_msg_encode_publish_namespace_ok_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_publish_namespace_ok_msg_t *ok = (xqc_moq_publish_namespace_ok_msg_t *)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_PUBLISH_NAMESPACE_OK);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(ok->request_id);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_publish_namespace_ok(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_moq_publish_namespace_ok_msg_t *ok = (xqc_moq_publish_namespace_ok_msg_t *)msg_base;
    xqc_int_t length = xqc_moq_msg_encode_publish_namespace_ok_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }
    length = length - xqc_put_varint_len(XQC_MOQ_MSG_PUBLISH_NAMESPACE_OK) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_PUBLISH_NAMESPACE_OK);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, ok->request_id);
    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_publish_namespace_ok(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base,
    xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    uint64_t length = 0;
    xqc_moq_publish_namespace_ok_msg_t *ok = (xqc_moq_publish_namespace_ok_msg_t *)msg_base;

    switch (msg_ctx->cur_field_idx) {
        case 0:
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &length);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1:
            ret = xqc_vint_read(buf + processed, buf + buf_len, &ok->request_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            *finish = 1;
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

/**
 * PUBLISH_NAMESPACE_ERROR Message
 */

void *
xqc_moq_msg_create_publish_namespace_error()
{
    xqc_moq_publish_namespace_error_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_publish_namespace_error_init_handler(&msg->msg_base);
    return msg;
}

void
xqc_moq_msg_free_publish_namespace_error(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_publish_namespace_error_msg_t *err = (xqc_moq_publish_namespace_error_msg_t *)msg;
    xqc_free(err->reason_phrase);
    xqc_free(err);
}

xqc_moq_msg_type_t
xqc_moq_msg_publish_namespace_error_type()
{
    return XQC_MOQ_MSG_PUBLISH_NAMESPACE_ERROR;
}

void
xqc_moq_msg_publish_namespace_error_init_handler(xqc_moq_msg_base_t *msg_base)
{
    *msg_base = publish_namespace_error_base;
}

xqc_int_t
xqc_moq_msg_encode_publish_namespace_error_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_publish_namespace_error_msg_t *err = (xqc_moq_publish_namespace_error_msg_t *)msg_base;
    size_t reason_len = err->reason_phrase_len;
    if (reason_len == 0 && err->reason_phrase != NULL) {
        reason_len = strlen(err->reason_phrase);
    }
    len += xqc_put_varint_len(XQC_MOQ_MSG_PUBLISH_NAMESPACE_ERROR);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(err->request_id);
    len += xqc_put_varint_len(err->error_code);
    len += xqc_put_varint_len(reason_len);
    len += reason_len;
    return len;
}

xqc_int_t
xqc_moq_msg_encode_publish_namespace_error(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_moq_publish_namespace_error_msg_t *err = (xqc_moq_publish_namespace_error_msg_t *)msg_base;
    size_t reason_len = err->reason_phrase_len;
    if (reason_len == 0 && err->reason_phrase != NULL) {
        reason_len = strlen(err->reason_phrase);
    }

    xqc_int_t length = xqc_moq_msg_encode_publish_namespace_error_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }
    length = length - xqc_put_varint_len(XQC_MOQ_MSG_PUBLISH_NAMESPACE_ERROR) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_PUBLISH_NAMESPACE_ERROR);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, err->request_id);
    p = xqc_put_varint(p, err->error_code);
    p = xqc_put_varint(p, reason_len);
    if (reason_len > 0 && err->reason_phrase) {
        xqc_memcpy(p, err->reason_phrase, reason_len);
        p += reason_len;
    }
    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_publish_namespace_error(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base,
    xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    uint64_t length = 0;
    xqc_moq_publish_namespace_error_msg_t *err = (xqc_moq_publish_namespace_error_msg_t *)msg_base;

    switch (msg_ctx->cur_field_idx) {
        case 0:
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &length);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1:
            ret = xqc_vint_read(buf + processed, buf + buf_len, &err->request_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 2;
        case 2:
            ret = xqc_vint_read(buf + processed, buf + buf_len, &err->error_code);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 3;
        case 3:
            if (err->reason_phrase_len == 0) {
                uint64_t reason_phrase_len = 0;
                ret = xqc_vint_read(buf + processed, buf + buf_len, &reason_phrase_len);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                err->reason_phrase_len = reason_phrase_len;
                processed += ret;
            }
            if (err->reason_phrase == NULL) {
                if (err->reason_phrase_len > XQC_MOQ_MAX_NAME_LEN) {
                    return -XQC_ELIMIT;
                }
                err->reason_phrase = xqc_calloc(1, err->reason_phrase_len + 1);
                if (err->reason_phrase == NULL) {
                    return -XQC_EMALLOC;
                }
            }
            if (processed == buf_len) {
                *wait_more_data = 1;
                break;
            } else if (err->reason_phrase_len - msg_ctx->str_processed <= buf_len - processed) {
                xqc_memcpy(err->reason_phrase + msg_ctx->str_processed, buf + processed,
                           err->reason_phrase_len - msg_ctx->str_processed);
                processed += err->reason_phrase_len - msg_ctx->str_processed;
                msg_ctx->str_processed = 0;
            } else {
                xqc_memcpy(err->reason_phrase + msg_ctx->str_processed, buf + processed, buf_len - processed);
                msg_ctx->str_processed += buf_len - processed;
                processed += buf_len - processed;
                *wait_more_data = 1;
                break;
            }
            *finish = 1;
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

/**
 * PUBLISH_NAMESPACE_DONE Message
 */

void *
xqc_moq_msg_create_publish_namespace_done()
{
    xqc_moq_publish_namespace_done_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_publish_namespace_done_init_handler(&msg->msg_base);
    return msg;
}

void
xqc_moq_msg_free_publish_namespace_done(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_publish_namespace_done_msg_t *done = (xqc_moq_publish_namespace_done_msg_t *)msg;
    if (done->track_namespace_tuple) {
        for (uint64_t i = 0; i < done->track_namespace_num; i++) {
            if (done->track_namespace_tuple[i].data) {
                xqc_free(done->track_namespace_tuple[i].data);
                done->track_namespace_tuple[i].data = NULL;
                done->track_namespace_tuple[i].len = 0;
            }
        }
        xqc_free(done->track_namespace_tuple);
        done->track_namespace_tuple = NULL;
        done->track_namespace_num = 0;
    }
    xqc_free(done);
}

xqc_moq_msg_type_t
xqc_moq_msg_publish_namespace_done_type()
{
    return XQC_MOQ_MSG_PUBLISH_NAMESPACE_DONE;
}

void
xqc_moq_msg_publish_namespace_done_init_handler(xqc_moq_msg_base_t *msg_base)
{
    *msg_base = publish_namespace_done_base;
}

xqc_int_t
xqc_moq_msg_encode_publish_namespace_done_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_publish_namespace_done_msg_t *done = (xqc_moq_publish_namespace_done_msg_t *)msg_base;
    size_t track_namespace_len = 0;
    if (xqc_moq_track_namespace_tuple_validate_and_sum(done->track_namespace_num,
            done->track_namespace_tuple, &track_namespace_len) != XQC_OK)
    {
        return -XQC_EPARAM;
    }

    len += xqc_put_varint_len(XQC_MOQ_MSG_PUBLISH_NAMESPACE_DONE);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_moq_track_namespace_tuple_encode_len(done->track_namespace_num,
                                                    done->track_namespace_tuple);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_publish_namespace_done(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_moq_publish_namespace_done_msg_t *done = (xqc_moq_publish_namespace_done_msg_t *)msg_base;
    size_t track_namespace_len = 0;
    if (xqc_moq_track_namespace_tuple_validate_and_sum(done->track_namespace_num,
            done->track_namespace_tuple, &track_namespace_len) != XQC_OK)
    {
        return -XQC_EPARAM;
    }
    done->track_namespace_len = track_namespace_len;

    xqc_int_t length = xqc_moq_msg_encode_publish_namespace_done_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }
    length = length - xqc_put_varint_len(XQC_MOQ_MSG_PUBLISH_NAMESPACE_DONE) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_PUBLISH_NAMESPACE_DONE);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_moq_track_namespace_tuple_encode(p, done->track_namespace_num,
                                             done->track_namespace_tuple);
    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_publish_namespace_done(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base,
    xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    uint64_t length = 0;
    xqc_moq_publish_namespace_done_msg_t *done = (xqc_moq_publish_namespace_done_msg_t *)msg_base;

    switch (msg_ctx->cur_field_idx) {
        case 0:
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &length);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1:
            if (done->track_namespace_num == 0) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, &done->track_namespace_num);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
                if (done->track_namespace_num == 0) {
                    return -MOQ_PROTOCOL_VIOLATION;
                }
                if (done->track_namespace_num > XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS) {
                    return -MOQ_PROTOCOL_VIOLATION;
                }
                msg_ctx->cur_array_idx = 0;
                msg_ctx->str_processed = 0;
                msg_ctx->tuple_elem_len = 0;
                msg_ctx->tuple_elem_len_ready = 0;
                done->track_namespace_len = 0;
                if (done->track_namespace_tuple == NULL) {
                    done->track_namespace_tuple = xqc_calloc(done->track_namespace_num, sizeof(xqc_moq_track_ns_field_t));
                    if (done->track_namespace_tuple == NULL) {
                        return -XQC_EMALLOC;
                    }
                }
            }
            msg_ctx->cur_field_idx = 2;
        case 2:
            for (; msg_ctx->cur_array_idx < done->track_namespace_num; msg_ctx->cur_array_idx++) {
                xqc_moq_track_ns_field_t *field = &done->track_namespace_tuple[msg_ctx->cur_array_idx];

                if (!msg_ctx->tuple_elem_len_ready) {
                    ret = xqc_vint_read(buf + processed, buf + buf_len, &msg_ctx->tuple_elem_len);
                    if (ret < 0) {
                        *wait_more_data = 1;
                        break;
                    }
                    processed += ret;
                    msg_ctx->tuple_elem_len_ready = 1;
                    if (msg_ctx->tuple_elem_len > XQC_MOQ_MAX_NAME_LEN) {
                        return -XQC_ELIMIT;
                    }
                    field->len = msg_ctx->tuple_elem_len;
                    if (done->track_namespace_len > XQC_MOQ_MAX_FULL_TRACK_NAME_LEN - field->len) {
                        return -MOQ_PROTOCOL_VIOLATION;
                    }
                    done->track_namespace_len += field->len;
                    if (field->data == NULL && field->len > 0) {
                        field->data = xqc_calloc(1, field->len + 1);
                        if (field->data == NULL) {
                            return -XQC_EMALLOC;
                        }
                    }
                }

                if (processed == buf_len) {
                    *wait_more_data = 1;
                    break;
                }

                size_t field_remaining = (msg_ctx->tuple_elem_len - msg_ctx->str_processed);
                size_t buf_remaining = buf_len - processed;
                size_t copy_len = field_remaining < buf_remaining ? field_remaining : buf_remaining;

                if (copy_len > 0 && field->data != NULL) {
                    xqc_memcpy(field->data + msg_ctx->str_processed, buf + processed, copy_len);
                    msg_ctx->str_processed += copy_len;
                    processed += copy_len;
                }

                if (msg_ctx->str_processed < msg_ctx->tuple_elem_len) {
                    *wait_more_data = 1;
                    break;
                }

                msg_ctx->str_processed = 0;
                msg_ctx->tuple_elem_len_ready = 0;
                msg_ctx->tuple_elem_len = 0;
            }

            if (*wait_more_data == 1) {
                break;
            }

            *finish = 1;
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

/**
 * PUBLISH_NAMESPACE_CANCEL Message
 */

void *
xqc_moq_msg_create_publish_namespace_cancel()
{
    xqc_moq_publish_namespace_cancel_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_publish_namespace_cancel_init_handler(&msg->msg_base);
    return msg;
}

void
xqc_moq_msg_free_publish_namespace_cancel(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_publish_namespace_cancel_msg_t *cancel = (xqc_moq_publish_namespace_cancel_msg_t *)msg;
    if (cancel->track_namespace_tuple) {
        for (uint64_t i = 0; i < cancel->track_namespace_num; i++) {
            if (cancel->track_namespace_tuple[i].data) {
                xqc_free(cancel->track_namespace_tuple[i].data);
                cancel->track_namespace_tuple[i].data = NULL;
                cancel->track_namespace_tuple[i].len = 0;
            }
        }
        xqc_free(cancel->track_namespace_tuple);
        cancel->track_namespace_tuple = NULL;
        cancel->track_namespace_num = 0;
    }
    cancel->track_namespace_len = 0;
    xqc_free(cancel->reason_phrase);
    xqc_free(cancel);
}

xqc_moq_msg_type_t
xqc_moq_msg_publish_namespace_cancel_type()
{
    return XQC_MOQ_MSG_PUBLISH_NAMESPACE_CANCEL;
}

void
xqc_moq_msg_publish_namespace_cancel_init_handler(xqc_moq_msg_base_t *msg_base)
{
    *msg_base = publish_namespace_cancel_base;
}

xqc_int_t
xqc_moq_msg_encode_publish_namespace_cancel_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_publish_namespace_cancel_msg_t *cancel = (xqc_moq_publish_namespace_cancel_msg_t *)msg_base;
    size_t track_namespace_len = 0;
    if (xqc_moq_track_namespace_tuple_validate_and_sum(cancel->track_namespace_num,
            cancel->track_namespace_tuple, &track_namespace_len) != XQC_OK)
    {
        return -XQC_EPARAM;
    }
    size_t reason_len = cancel->reason_phrase_len;
    if (reason_len == 0 && cancel->reason_phrase != NULL) {
        reason_len = strlen(cancel->reason_phrase);
    }

    len += xqc_put_varint_len(XQC_MOQ_MSG_PUBLISH_NAMESPACE_CANCEL);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_moq_track_namespace_tuple_encode_len(cancel->track_namespace_num,
                                                    cancel->track_namespace_tuple);
    len += xqc_put_varint_len(cancel->error_code);
    len += xqc_put_varint_len(reason_len);
    len += reason_len;
    return len;
}

xqc_int_t
xqc_moq_msg_encode_publish_namespace_cancel(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_moq_publish_namespace_cancel_msg_t *cancel = (xqc_moq_publish_namespace_cancel_msg_t *)msg_base;
    size_t track_namespace_len = 0;
    if (xqc_moq_track_namespace_tuple_validate_and_sum(cancel->track_namespace_num,
            cancel->track_namespace_tuple, &track_namespace_len) != XQC_OK)
    {
        return -XQC_EPARAM;
    }
    cancel->track_namespace_len = track_namespace_len;
    size_t reason_len = cancel->reason_phrase_len;
    if (reason_len == 0 && cancel->reason_phrase != NULL) {
        reason_len = strlen(cancel->reason_phrase);
    }

    xqc_int_t length = xqc_moq_msg_encode_publish_namespace_cancel_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }
    length = length - xqc_put_varint_len(XQC_MOQ_MSG_PUBLISH_NAMESPACE_CANCEL) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_PUBLISH_NAMESPACE_CANCEL);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_moq_track_namespace_tuple_encode(p, cancel->track_namespace_num,
                                             cancel->track_namespace_tuple);
    p = xqc_put_varint(p, cancel->error_code);
    p = xqc_put_varint(p, reason_len);
    if (reason_len > 0 && cancel->reason_phrase) {
        xqc_memcpy(p, cancel->reason_phrase, reason_len);
        p += reason_len;
    }
    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_publish_namespace_cancel(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base,
    xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    uint64_t length = 0;
    xqc_moq_publish_namespace_cancel_msg_t *cancel = (xqc_moq_publish_namespace_cancel_msg_t *)msg_base;

    switch (msg_ctx->cur_field_idx) {
        case 0:
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &length);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1:
            if (cancel->track_namespace_num == 0) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, &cancel->track_namespace_num);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
                if (cancel->track_namespace_num == 0) {
                    return -MOQ_PROTOCOL_VIOLATION;
                }
                if (cancel->track_namespace_num > XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS) {
                    return -MOQ_PROTOCOL_VIOLATION;
                }
                msg_ctx->cur_array_idx = 0;
                msg_ctx->str_processed = 0;
                msg_ctx->tuple_elem_len = 0;
                msg_ctx->tuple_elem_len_ready = 0;
                cancel->track_namespace_len = 0;
                if (cancel->track_namespace_tuple == NULL) {
                    cancel->track_namespace_tuple = xqc_calloc(cancel->track_namespace_num, sizeof(xqc_moq_track_ns_field_t));
                    if (cancel->track_namespace_tuple == NULL) {
                        return -XQC_EMALLOC;
                    }
                }
            }
            msg_ctx->cur_field_idx = 2;
        case 2:
            for (; msg_ctx->cur_array_idx < cancel->track_namespace_num; msg_ctx->cur_array_idx++) {
                xqc_moq_track_ns_field_t *field = &cancel->track_namespace_tuple[msg_ctx->cur_array_idx];

                if (!msg_ctx->tuple_elem_len_ready) {
                    ret = xqc_vint_read(buf + processed, buf + buf_len, &msg_ctx->tuple_elem_len);
                    if (ret < 0) {
                        *wait_more_data = 1;
                        break;
                    }
                    processed += ret;
                    msg_ctx->tuple_elem_len_ready = 1;
                    if (msg_ctx->tuple_elem_len > XQC_MOQ_MAX_NAME_LEN) {
                        return -XQC_ELIMIT;
                    }
                    field->len = msg_ctx->tuple_elem_len;
                    if (cancel->track_namespace_len > XQC_MOQ_MAX_FULL_TRACK_NAME_LEN - field->len) {
                        return -MOQ_PROTOCOL_VIOLATION;
                    }
                    cancel->track_namespace_len += field->len;
                    if (field->data == NULL && field->len > 0) {
                        field->data = xqc_calloc(1, field->len + 1);
                        if (field->data == NULL) {
                            return -XQC_EMALLOC;
                        }
                    }
                }

                if (processed == buf_len) {
                    *wait_more_data = 1;
                    break;
                }

                size_t field_remaining = (msg_ctx->tuple_elem_len - msg_ctx->str_processed);
                size_t buf_remaining = buf_len - processed;
                size_t copy_len = field_remaining < buf_remaining ? field_remaining : buf_remaining;

                if (copy_len > 0 && field->data != NULL) {
                    xqc_memcpy(field->data + msg_ctx->str_processed, buf + processed, copy_len);
                    msg_ctx->str_processed += copy_len;
                    processed += copy_len;
                }

                if (msg_ctx->str_processed < msg_ctx->tuple_elem_len) {
                    *wait_more_data = 1;
                    break;
                }

                msg_ctx->str_processed = 0;
                msg_ctx->tuple_elem_len_ready = 0;
                msg_ctx->tuple_elem_len = 0;
            }

            if (*wait_more_data == 1) {
                break;
            }

            msg_ctx->cur_field_idx = 3;
        case 3:
            ret = xqc_vint_read(buf + processed, buf + buf_len, &cancel->error_code);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 4;
        case 4:
            if (cancel->reason_phrase_len == 0) {
                uint64_t reason_phrase_len = 0;
                ret = xqc_vint_read(buf + processed, buf + buf_len, &reason_phrase_len);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                cancel->reason_phrase_len = reason_phrase_len;
                processed += ret;
            }
            if (cancel->reason_phrase == NULL) {
                if (cancel->reason_phrase_len > XQC_MOQ_MAX_NAME_LEN) {
                    return -XQC_ELIMIT;
                }
                cancel->reason_phrase = xqc_calloc(1, cancel->reason_phrase_len + 1);
                if (cancel->reason_phrase == NULL) {
                    return -XQC_EMALLOC;
                }
            }
            if (processed == buf_len) {
                *wait_more_data = 1;
                break;
            } else if (cancel->reason_phrase_len - msg_ctx->str_processed <= buf_len - processed) {
                xqc_memcpy(cancel->reason_phrase + msg_ctx->str_processed, buf + processed,
                           cancel->reason_phrase_len - msg_ctx->str_processed);
                processed += cancel->reason_phrase_len - msg_ctx->str_processed;
                msg_ctx->str_processed = 0;
            } else {
                xqc_memcpy(cancel->reason_phrase + msg_ctx->str_processed, buf + processed, buf_len - processed);
                msg_ctx->str_processed += buf_len - processed;
                processed += buf_len - processed;
                *wait_more_data = 1;
                break;
            }
            *finish = 1;
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

/**
 * SUBSCRIBE_NAMESPACE Message
 */

void *
xqc_moq_msg_create_subscribe_namespace()
{
    xqc_moq_subscribe_namespace_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_subscribe_namespace_init_handler(&msg->msg_base);
    return msg;
}

void
xqc_moq_msg_free_subscribe_namespace(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_subscribe_namespace_msg_t *sub = (xqc_moq_subscribe_namespace_msg_t *)msg;
    if (sub->track_namespace_tuple) {
        for (uint64_t i = 0; i < sub->track_namespace_num; i++) {
            if (sub->track_namespace_tuple[i].data) {
                xqc_free(sub->track_namespace_tuple[i].data);
                sub->track_namespace_tuple[i].data = NULL;
                sub->track_namespace_tuple[i].len = 0;
            }
        }
        xqc_free(sub->track_namespace_tuple);
        sub->track_namespace_tuple = NULL;
        sub->track_namespace_num = 0;
    }
    sub->track_namespace_len = 0;
    xqc_moq_msg_free_params(sub->params, sub->params_num);
    xqc_free(sub);
}

xqc_moq_msg_type_t
xqc_moq_msg_subscribe_namespace_type()
{
    return XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE;
}

void
xqc_moq_msg_subscribe_namespace_init_handler(xqc_moq_msg_base_t *msg_base)
{
    *msg_base = subscribe_namespace_base;
}

xqc_int_t
xqc_moq_msg_encode_subscribe_namespace_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_subscribe_namespace_msg_t *sub = (xqc_moq_subscribe_namespace_msg_t *)msg_base;
    size_t track_namespace_len = 0;
    if (xqc_moq_track_namespace_tuple_validate_and_sum(sub->track_namespace_num,
            sub->track_namespace_tuple, &track_namespace_len) != XQC_OK)
    {
        return -XQC_EPARAM;
    }

    len += xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(sub->request_id);
    len += xqc_moq_track_namespace_tuple_encode_len(sub->track_namespace_num,
                                                    sub->track_namespace_tuple);
    len += xqc_put_varint_len(sub->params_num);
    len += xqc_moq_msg_encode_params_len_v14(sub->params, sub->params_num);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_subscribe_namespace(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_subscribe_namespace_msg_t *sub = (xqc_moq_subscribe_namespace_msg_t *)msg_base;
    size_t track_namespace_len = 0;
    if (xqc_moq_track_namespace_tuple_validate_and_sum(sub->track_namespace_num,
            sub->track_namespace_tuple, &track_namespace_len) != XQC_OK)
    {
        return -XQC_EPARAM;
    }
    sub->track_namespace_len = track_namespace_len;

    xqc_int_t length = xqc_moq_msg_encode_subscribe_namespace_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }
    length = length - xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, sub->request_id);
    p = xqc_moq_track_namespace_tuple_encode(p, sub->track_namespace_num,
                                             sub->track_namespace_tuple);
    p = xqc_put_varint(p, sub->params_num);
    ret = xqc_moq_msg_encode_params_v14(sub->params, sub->params_num, p, buf + buf_cap - p);
    if (ret < 0) {
        return ret;
    }
    p += ret;
    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_subscribe_namespace(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base,
    xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_int_t param_finish = 0;
    uint64_t length = 0;
    xqc_moq_subscribe_namespace_msg_t *sub = (xqc_moq_subscribe_namespace_msg_t *)msg_base;
    xqc_moq_decode_params_ctx_t *params_ctx = &msg_ctx->decode_params_ctx;

    switch (msg_ctx->cur_field_idx) {
        case 0:
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &length);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1:
            ret = xqc_vint_read(buf + processed, buf + buf_len, &sub->request_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 2;
        case 2:
            if (sub->track_namespace_num == 0) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, &sub->track_namespace_num);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
                if (sub->track_namespace_num == 0) {
                    return -MOQ_PROTOCOL_VIOLATION;
                }
                if (sub->track_namespace_num > XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS) {
                    return -MOQ_PROTOCOL_VIOLATION;
                }
                msg_ctx->cur_array_idx = 0;
                msg_ctx->str_processed = 0;
                msg_ctx->tuple_elem_len = 0;
                msg_ctx->tuple_elem_len_ready = 0;
                sub->track_namespace_len = 0;
                if (sub->track_namespace_tuple == NULL) {
                    sub->track_namespace_tuple = xqc_calloc(sub->track_namespace_num, sizeof(xqc_moq_track_ns_field_t));
                    if (sub->track_namespace_tuple == NULL) {
                        return -XQC_EMALLOC;
                    }
                }
            }
            msg_ctx->cur_field_idx = 3;
        case 3:
            for (; msg_ctx->cur_array_idx < sub->track_namespace_num; msg_ctx->cur_array_idx++) {
                xqc_moq_track_ns_field_t *field = &sub->track_namespace_tuple[msg_ctx->cur_array_idx];

                if (!msg_ctx->tuple_elem_len_ready) {
                    ret = xqc_vint_read(buf + processed, buf + buf_len, &msg_ctx->tuple_elem_len);
                    if (ret < 0) {
                        *wait_more_data = 1;
                        break;
                    }
                    processed += ret;
                    msg_ctx->tuple_elem_len_ready = 1;
                    if (msg_ctx->tuple_elem_len > XQC_MOQ_MAX_NAME_LEN) {
                        return -XQC_ELIMIT;
                    }
                    field->len = msg_ctx->tuple_elem_len;
                    if (sub->track_namespace_len > XQC_MOQ_MAX_FULL_TRACK_NAME_LEN - field->len) {
                        return -MOQ_PROTOCOL_VIOLATION;
                    }
                    sub->track_namespace_len += field->len;
                    if (field->data == NULL && field->len > 0) {
                        field->data = xqc_calloc(1, field->len + 1);
                        if (field->data == NULL) {
                            return -XQC_EMALLOC;
                        }
                    }
                }

                if (processed == buf_len) {
                    *wait_more_data = 1;
                    break;
                }

                size_t field_remaining = (msg_ctx->tuple_elem_len - msg_ctx->str_processed);
                size_t buf_remaining = buf_len - processed;
                size_t copy_len = field_remaining < buf_remaining ? field_remaining : buf_remaining;

                if (copy_len > 0 && field->data != NULL) {
                    xqc_memcpy(field->data + msg_ctx->str_processed, buf + processed, copy_len);
                    msg_ctx->str_processed += copy_len;
                    processed += copy_len;
                }

                if (msg_ctx->str_processed < msg_ctx->tuple_elem_len) {
                    *wait_more_data = 1;
                    break;
                }

                msg_ctx->str_processed = 0;
                msg_ctx->tuple_elem_len_ready = 0;
                msg_ctx->tuple_elem_len = 0;
            }

            if (*wait_more_data == 1) {
                break;
            }

            msg_ctx->cur_field_idx = 4;
        case 4:
            if (sub->params_num == 0) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, &sub->params_num);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
                if (sub->params_num == 0) {
                    *finish = 1;
                    break;
                }
                if (sub->params_num > XQC_MOQ_MAX_PARAMS) {
                    return -XQC_ELIMIT;
                }
                sub->params = xqc_moq_msg_alloc_params(sub->params_num);
                if (sub->params == NULL) {
                    return -XQC_EMALLOC;
                }
            }
            msg_ctx->cur_field_idx = 5;
        case 5:
            ret = xqc_moq_msg_decode_params_v14(buf + processed, buf_len - processed, params_ctx,
                                                sub->params, sub->params_num, &param_finish, wait_more_data);
            if (ret < 0) {
                return ret;
            }
            processed += ret;
            if (*wait_more_data == 1) {
                break;
            }
            if (param_finish == 1) {
                *finish = 1;
            }
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

/**
 * SUBSCRIBE_NAMESPACE_OK Message
 */

void *
xqc_moq_msg_create_subscribe_namespace_ok()
{
    xqc_moq_subscribe_namespace_ok_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_subscribe_namespace_ok_init_handler(&msg->msg_base);
    return msg;
}

void
xqc_moq_msg_free_subscribe_namespace_ok(void *msg)
{
    xqc_free(msg);
}

xqc_moq_msg_type_t
xqc_moq_msg_subscribe_namespace_ok_type()
{
    return XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE_OK;
}

void
xqc_moq_msg_subscribe_namespace_ok_init_handler(xqc_moq_msg_base_t *msg_base)
{
    *msg_base = subscribe_namespace_ok_base;
}

xqc_int_t
xqc_moq_msg_encode_subscribe_namespace_ok_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_subscribe_namespace_ok_msg_t *ok = (xqc_moq_subscribe_namespace_ok_msg_t *)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE_OK);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(ok->request_id);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_subscribe_namespace_ok(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_moq_subscribe_namespace_ok_msg_t *ok = (xqc_moq_subscribe_namespace_ok_msg_t *)msg_base;
    xqc_int_t length = xqc_moq_msg_encode_subscribe_namespace_ok_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }
    length = length - xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE_OK) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE_OK);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, ok->request_id);
    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_subscribe_namespace_ok(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base,
    xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    uint64_t length = 0;
    xqc_moq_subscribe_namespace_ok_msg_t *ok = (xqc_moq_subscribe_namespace_ok_msg_t *)msg_base;

    switch (msg_ctx->cur_field_idx) {
        case 0:
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &length);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1:
            ret = xqc_vint_read(buf + processed, buf + buf_len, &ok->request_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            *finish = 1;
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

/**
 * SUBSCRIBE_NAMESPACE_ERROR Message
 */

void *
xqc_moq_msg_create_subscribe_namespace_error()
{
    xqc_moq_subscribe_namespace_error_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_subscribe_namespace_error_init_handler(&msg->msg_base);
    return msg;
}

void
xqc_moq_msg_free_subscribe_namespace_error(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_subscribe_namespace_error_msg_t *err = (xqc_moq_subscribe_namespace_error_msg_t *)msg;
    xqc_free(err->reason_phrase);
    xqc_free(err);
}

xqc_moq_msg_type_t
xqc_moq_msg_subscribe_namespace_error_type()
{
    return XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE_ERROR;
}

void
xqc_moq_msg_subscribe_namespace_error_init_handler(xqc_moq_msg_base_t *msg_base)
{
    *msg_base = subscribe_namespace_error_base;
}

xqc_int_t
xqc_moq_msg_encode_subscribe_namespace_error_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_subscribe_namespace_error_msg_t *err = (xqc_moq_subscribe_namespace_error_msg_t *)msg_base;
    size_t reason_len = err->reason_phrase_len;
    if (reason_len == 0 && err->reason_phrase != NULL) {
        reason_len = strlen(err->reason_phrase);
    }

    len += xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE_ERROR);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(err->request_id);
    len += xqc_put_varint_len(err->error_code);
    len += xqc_put_varint_len(reason_len);
    len += reason_len;
    return len;
}

xqc_int_t
xqc_moq_msg_encode_subscribe_namespace_error(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_moq_subscribe_namespace_error_msg_t *err = (xqc_moq_subscribe_namespace_error_msg_t *)msg_base;
    size_t reason_len = err->reason_phrase_len;
    if (reason_len == 0 && err->reason_phrase != NULL) {
        reason_len = strlen(err->reason_phrase);
    }

    xqc_int_t length = xqc_moq_msg_encode_subscribe_namespace_error_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }
    length = length - xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE_ERROR) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE_ERROR);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, err->request_id);
    p = xqc_put_varint(p, err->error_code);
    p = xqc_put_varint(p, reason_len);
    if (reason_len > 0 && err->reason_phrase) {
        xqc_memcpy(p, err->reason_phrase, reason_len);
        p += reason_len;
    }
    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_subscribe_namespace_error(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base,
    xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    uint64_t length = 0;
    xqc_moq_subscribe_namespace_error_msg_t *err = (xqc_moq_subscribe_namespace_error_msg_t *)msg_base;

    switch (msg_ctx->cur_field_idx) {
        case 0:
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &length);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1:
            ret = xqc_vint_read(buf + processed, buf + buf_len, &err->request_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 2;
        case 2:
            ret = xqc_vint_read(buf + processed, buf + buf_len, &err->error_code);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 3;
        case 3:
            if (err->reason_phrase_len == 0) {
                uint64_t reason_phrase_len = 0;
                ret = xqc_vint_read(buf + processed, buf + buf_len, &reason_phrase_len);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                err->reason_phrase_len = reason_phrase_len;
                processed += ret;
            }
            if (err->reason_phrase == NULL) {
                if (err->reason_phrase_len > XQC_MOQ_MAX_NAME_LEN) {
                    return -XQC_ELIMIT;
                }
                err->reason_phrase = xqc_calloc(1, err->reason_phrase_len + 1);
                if (err->reason_phrase == NULL) {
                    return -XQC_EMALLOC;
                }
            }
            if (processed == buf_len) {
                *wait_more_data = 1;
                break;
            } else if (err->reason_phrase_len - msg_ctx->str_processed <= buf_len - processed) {
                xqc_memcpy(err->reason_phrase + msg_ctx->str_processed, buf + processed,
                           err->reason_phrase_len - msg_ctx->str_processed);
                processed += err->reason_phrase_len - msg_ctx->str_processed;
                msg_ctx->str_processed = 0;
            } else {
                xqc_memcpy(err->reason_phrase + msg_ctx->str_processed, buf + processed, buf_len - processed);
                msg_ctx->str_processed += buf_len - processed;
                processed += buf_len - processed;
                *wait_more_data = 1;
                break;
            }
            *finish = 1;
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

/**
 * UNSUBSCRIBE_NAMESPACE Message
 */

void *
xqc_moq_msg_create_unsubscribe_namespace()
{
    xqc_moq_unsubscribe_namespace_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_unsubscribe_namespace_init_handler(&msg->msg_base);
    return msg;
}

void
xqc_moq_msg_free_unsubscribe_namespace(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_unsubscribe_namespace_msg_t *unsub = (xqc_moq_unsubscribe_namespace_msg_t *)msg;
    if (unsub->track_namespace_tuple) {
        for (uint64_t i = 0; i < unsub->track_namespace_num; i++) {
            if (unsub->track_namespace_tuple[i].data) {
                xqc_free(unsub->track_namespace_tuple[i].data);
                unsub->track_namespace_tuple[i].data = NULL;
                unsub->track_namespace_tuple[i].len = 0;
            }
        }
        xqc_free(unsub->track_namespace_tuple);
        unsub->track_namespace_tuple = NULL;
        unsub->track_namespace_num = 0;
    }
    unsub->track_namespace_len = 0;
    xqc_free(unsub);
}

xqc_moq_msg_type_t
xqc_moq_msg_unsubscribe_namespace_type()
{
    return XQC_MOQ_MSG_UNSUBSCRIBE_NAMESPACE;
}

void
xqc_moq_msg_unsubscribe_namespace_init_handler(xqc_moq_msg_base_t *msg_base)
{
    *msg_base = unsubscribe_namespace_base;
}

xqc_int_t
xqc_moq_msg_encode_unsubscribe_namespace_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_unsubscribe_namespace_msg_t *unsub = (xqc_moq_unsubscribe_namespace_msg_t *)msg_base;
    size_t track_namespace_len = 0;
    if (xqc_moq_track_namespace_tuple_validate_and_sum(unsub->track_namespace_num,
            unsub->track_namespace_tuple, &track_namespace_len) != XQC_OK)
    {
        return -XQC_EPARAM;
    }

    len += xqc_put_varint_len(XQC_MOQ_MSG_UNSUBSCRIBE_NAMESPACE);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_moq_track_namespace_tuple_encode_len(unsub->track_namespace_num,
                                                    unsub->track_namespace_tuple);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_unsubscribe_namespace(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_moq_unsubscribe_namespace_msg_t *unsub = (xqc_moq_unsubscribe_namespace_msg_t *)msg_base;
    size_t track_namespace_len = 0;
    if (xqc_moq_track_namespace_tuple_validate_and_sum(unsub->track_namespace_num,
            unsub->track_namespace_tuple, &track_namespace_len) != XQC_OK)
    {
        return -XQC_EPARAM;
    }
    unsub->track_namespace_len = track_namespace_len;

    xqc_int_t length = xqc_moq_msg_encode_unsubscribe_namespace_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }
    length = length - xqc_put_varint_len(XQC_MOQ_MSG_UNSUBSCRIBE_NAMESPACE) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_UNSUBSCRIBE_NAMESPACE);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_moq_track_namespace_tuple_encode(p, unsub->track_namespace_num,
                                             unsub->track_namespace_tuple);
    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_unsubscribe_namespace(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base,
    xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    uint64_t length = 0;
    xqc_moq_unsubscribe_namespace_msg_t *unsub = (xqc_moq_unsubscribe_namespace_msg_t *)msg_base;

    switch (msg_ctx->cur_field_idx) {
        case 0:
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &length);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1:
            if (unsub->track_namespace_num == 0) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, &unsub->track_namespace_num);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
                if (unsub->track_namespace_num == 0) {
                    return -MOQ_PROTOCOL_VIOLATION;
                }
                if (unsub->track_namespace_num > XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS) {
                    return -MOQ_PROTOCOL_VIOLATION;
                }
                msg_ctx->cur_array_idx = 0;
                msg_ctx->str_processed = 0;
                msg_ctx->tuple_elem_len = 0;
                msg_ctx->tuple_elem_len_ready = 0;
                unsub->track_namespace_len = 0;
                if (unsub->track_namespace_tuple == NULL) {
                    unsub->track_namespace_tuple = xqc_calloc(unsub->track_namespace_num, sizeof(xqc_moq_track_ns_field_t));
                    if (unsub->track_namespace_tuple == NULL) {
                        return -XQC_EMALLOC;
                    }
                }
            }
            msg_ctx->cur_field_idx = 2;
        case 2:
            for (; msg_ctx->cur_array_idx < unsub->track_namespace_num; msg_ctx->cur_array_idx++) {
                xqc_moq_track_ns_field_t *field = &unsub->track_namespace_tuple[msg_ctx->cur_array_idx];

                if (!msg_ctx->tuple_elem_len_ready) {
                    ret = xqc_vint_read(buf + processed, buf + buf_len, &msg_ctx->tuple_elem_len);
                    if (ret < 0) {
                        *wait_more_data = 1;
                        break;
                    }
                    processed += ret;
                    msg_ctx->tuple_elem_len_ready = 1;
                    if (msg_ctx->tuple_elem_len > XQC_MOQ_MAX_NAME_LEN) {
                        return -XQC_ELIMIT;
                    }
                    field->len = msg_ctx->tuple_elem_len;
                    if (unsub->track_namespace_len > XQC_MOQ_MAX_FULL_TRACK_NAME_LEN - field->len) {
                        return -MOQ_PROTOCOL_VIOLATION;
                    }
                    unsub->track_namespace_len += field->len;
                    if (field->data == NULL && field->len > 0) {
                        field->data = xqc_calloc(1, field->len + 1);
                        if (field->data == NULL) {
                            return -XQC_EMALLOC;
                        }
                    }
                }

                if (processed == buf_len) {
                    *wait_more_data = 1;
                    break;
                }

                size_t field_remaining = (msg_ctx->tuple_elem_len - msg_ctx->str_processed);
                size_t buf_remaining = buf_len - processed;
                size_t copy_len = field_remaining < buf_remaining ? field_remaining : buf_remaining;

                if (copy_len > 0 && field->data != NULL) {
                    xqc_memcpy(field->data + msg_ctx->str_processed, buf + processed, copy_len);
                    msg_ctx->str_processed += copy_len;
                    processed += copy_len;
                }

                if (msg_ctx->str_processed < msg_ctx->tuple_elem_len) {
                    *wait_more_data = 1;
                    break;
                }

                msg_ctx->str_processed = 0;
                msg_ctx->tuple_elem_len_ready = 0;
                msg_ctx->tuple_elem_len = 0;
            }

            if (*wait_more_data == 1) {
                break;
            }

            *finish = 1;
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

void *
xqc_moq_msg_create_unsubscribe()
{
    xqc_moq_unsubscribe_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_unsubscribe_init_handler(&msg->msg_base);
    return msg;
}

void
xqc_moq_msg_free_unsubscribe(void *msg)
{
    xqc_free(msg);
}

xqc_moq_msg_type_t
xqc_moq_msg_unsubscribe_type()
{
    return XQC_MOQ_MSG_UNSUBSCRIBE;
}

void
xqc_moq_msg_unsubscribe_init_handler(xqc_moq_msg_base_t *msg_base)
{
    *msg_base = unsubscribe_base;
}

xqc_int_t
xqc_moq_msg_encode_unsubscribe_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_moq_unsubscribe_msg_t *unsubscribe = (xqc_moq_unsubscribe_msg_t*)msg_base;
    xqc_int_t len = 0;
    len += xqc_put_varint_len(XQC_MOQ_MSG_UNSUBSCRIBE);
    len += XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    len += xqc_put_varint_len(unsubscribe->subscribe_id);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_unsubscribe(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_moq_unsubscribe_msg_t *unsubscribe = (xqc_moq_unsubscribe_msg_t*)msg_base;
    xqc_int_t length = xqc_moq_msg_encode_unsubscribe_len(msg_base);
    if (length > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    uint8_t *p = buf;
    length = length - xqc_put_varint_len(XQC_MOQ_MSG_UNSUBSCRIBE) - XQC_MOQ_MSG_LENGTH_FIXED_SIZE;
    p = xqc_put_varint(p, XQC_MOQ_MSG_UNSUBSCRIBE);
    p = xqc_moq_put_varint_length(p, length);
    p = xqc_put_varint(p, unsubscribe->subscribe_id);
    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_unsubscribe(uint8_t *buf, size_t buf_len, uint8_t stream_fin, xqc_moq_decode_msg_ctx_t *msg_ctx,
    xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_moq_unsubscribe_msg_t *unsubscribe = (xqc_moq_unsubscribe_msg_t*)msg_base;
    uint64_t length = 0;

    switch (msg_ctx->cur_field_idx) {
        case 0: // Length (i)
            ret = xqc_moq_length_read(buf + processed, buf + buf_len, &length);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1: // Subscribe ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &unsubscribe->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>unsubscribe subscribe_id:%d\n", (int)unsubscribe->subscribe_id);
            msg_ctx->cur_field_idx = 2;
            *finish = 1;
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}


/**
 * OBJECT_STREAM Message
 */

void *
xqc_moq_msg_create_object_stream()
{
    xqc_moq_object_stream_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_object_stream_init_handler(&msg->msg_base);
    return msg;
}

void
xqc_moq_msg_free_object_stream(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_object_stream_msg_t *object_stream = (xqc_moq_object_stream_msg_t *)msg;
    if (object_stream->ext_params) {
        xqc_moq_msg_free_params(object_stream->ext_params, object_stream->ext_params_num);
        object_stream->ext_params = NULL;
        object_stream->ext_params_num = 0;
    }
    if (object_stream->ext_buf) {
        xqc_free(object_stream->ext_buf);
        object_stream->ext_buf = NULL;
        object_stream->ext_len = 0;
        object_stream->ext_bytes_received = 0;
    }
    xqc_free(object_stream->payload);
    xqc_free(object_stream);
}

xqc_moq_msg_type_t
xqc_moq_msg_object_stream_type()
{
    return XQC_MOQ_MSG_OBJECT_STREAM;
}

void
xqc_moq_msg_object_stream_init_handler(xqc_moq_msg_base_t *msg_base)
{
    *msg_base = object_stream_base;
}

xqc_int_t
xqc_moq_msg_encode_object_stream_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_object_stream_msg_t *object = (xqc_moq_object_stream_msg_t*)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_OBJECT_STREAM);
    len += xqc_put_varint_len(object->subscribe_id);
    len += xqc_put_varint_len(object->track_alias);
    len += xqc_put_varint_len(object->group_id);
    len += xqc_put_varint_len(object->object_id);
    len += xqc_put_varint_len(object->send_order);
    len += xqc_put_varint_len(object->status);
    len += object->payload_len;

    return len;
}

xqc_int_t
xqc_moq_msg_encode_object_stream(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_moq_object_stream_msg_t *object = (xqc_moq_object_stream_msg_t*)msg_base;
    if (xqc_moq_msg_encode_object_stream_len(msg_base) > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_OBJECT_STREAM);
    p = xqc_put_varint(p, object->subscribe_id);
    p = xqc_put_varint(p, object->track_alias);
    p = xqc_put_varint(p, object->group_id);
    p = xqc_put_varint(p, object->object_id);
    p = xqc_put_varint(p, object->send_order);
    p = xqc_put_varint(p, object->status);

    xqc_memcpy(p, object->payload, object->payload_len);
    p += object->payload_len;
    return p - buf;
}

//return processed or error
xqc_int_t
xqc_moq_msg_decode_object_stream(uint8_t *buf, size_t buf_len, uint8_t stream_fin, xqc_moq_decode_msg_ctx_t *msg_ctx,
    xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_moq_object_stream_msg_t *object = (xqc_moq_object_stream_msg_t *)msg_base;
    switch (msg_ctx->cur_field_idx) {
        case 0: //Subscribe ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &object->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>subscribe_id:%d\n",(int)object->subscribe_id);
            msg_ctx->cur_field_idx = 1;
        case 1: //Track Alias (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &object->track_alias);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>track_alias:%d\n",(int)object->track_alias);
            msg_ctx->cur_field_idx = 2;
        case 2: //Group ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &object->group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>group_id:%d\n",(int)object->group_id);
            msg_ctx->cur_field_idx = 3;
        case 3: //Object ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &object->object_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>object_id:%d\n",(int)object->object_id);
            msg_ctx->cur_field_idx = 4;
        case 4: //Object Send Order (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &object->send_order);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>send_order:%d\n",(int)object->send_order);
            msg_ctx->cur_field_idx = 5;
        case 5: //Object Status (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &object->status);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>status:%d\n",(int)object->status);
            msg_ctx->cur_field_idx = 6;
        case 6: //Object Payload (..)
            if (buf_len - processed == 0) {
                *wait_more_data = 1;
                break;
            }
            object->payload_len = msg_ctx->payload_processed + buf_len - processed;
            if (object->payload_len > XQC_MOQ_MAX_OBJECT_LEN) {
                return -XQC_ELIMIT;
            }
            object->payload = xqc_realloc(object->payload, object->payload_len);
            xqc_memcpy(object->payload + msg_ctx->payload_processed, buf + processed, buf_len - processed);
            msg_ctx->payload_processed += buf_len - processed;
            processed += buf_len - processed;
            if (stream_fin == 1) {
                *finish = 1;
            } else {
                *wait_more_data = 1;
            }
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

void *
xqc_moq_msg_create_subgroup()
{
    xqc_moq_subgroup_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_subgroup_init_handler(&msg->msg_base);
    return msg;
}

void
xqc_moq_msg_free_subgroup(void *msg)
{
    xqc_moq_msg_free_object_stream(msg);
}

xqc_moq_msg_type_t
xqc_moq_msg_subgroup_type()
{
    return XQC_MOQ_MSG_SUBGROUP;
}

void
xqc_moq_msg_subgroup_init_handler(xqc_moq_msg_base_t *msg_base)
{
    *msg_base = subgroup_base;
}

static xqc_bool_t
xqc_moq_msg_subgroup_has_id(uint8_t type)
{
    return (type & 0x04) != 0;
}

/* Whether this subgroup type encodes Object Header Extensions. */
static xqc_bool_t
xqc_moq_msg_subgroup_has_ext(uint8_t type)
{
    /* Per Table 7 in moq-transport: the lowest bit indicates whether
     * extension headers are present for Objects in this subgroup. */
    return (type & 0x01) != 0;
}

static xqc_int_t
xqc_moq_msg_subgroup_parse_ext_params(xqc_moq_subgroup_msg_t *object)
{
    size_t ext_processed = 0;
    xqc_int_t params_num = 0;
    xqc_int_t ret = 0;

    while (ext_processed < object->ext_len) {
        uint64_t type = 0;
        uint64_t length = 0;

        ret = xqc_vint_read(object->ext_buf + ext_processed,
                            object->ext_buf + object->ext_len, &type);
        if (ret < 0) {
            return ret;
        }
        ext_processed += ret;

        if (type & 0x1) {
            ret = xqc_vint_read(object->ext_buf + ext_processed,
                                object->ext_buf + object->ext_len, &length);
            if (ret < 0) {
                return ret;
            }
            ext_processed += ret;
            if (length > XQC_MOQ_MAX_PARAM_VALUE_LEN) {
                return -XQC_ELIMIT;
            }
            if (ext_processed + length > object->ext_len) {
                return -XQC_EILLEGAL_FRAME;
            }
            ext_processed += length;
        } else {
            ret = xqc_vint_read(object->ext_buf + ext_processed,
                                object->ext_buf + object->ext_len, &length);
            if (ret < 0) {
                return ret;
            }
            ext_processed += ret;
        }

        params_num++;
        if (params_num > XQC_MOQ_MAX_PARAMS) {
            return -XQC_ELIMIT;
        }
    }

    if (ext_processed != object->ext_len) {
        return -XQC_EILLEGAL_FRAME;
    }

    if (params_num == 0) {
        xqc_free(object->ext_buf);
        object->ext_buf = NULL;
        object->ext_len = 0;
        object->ext_bytes_received = 0;
        object->ext_params = NULL;
        object->ext_params_num = 0;
        return XQC_OK;
    }

    xqc_moq_decode_params_ctx_t params_ctx;
    xqc_int_t params_finish = 0;
    xqc_int_t params_wait = 0;

    object->ext_params = xqc_moq_msg_alloc_params(params_num);
    if (object->ext_params == NULL) {
        return -XQC_EMALLOC;
    }
    object->ext_params_num = params_num;

    xqc_moq_decode_params_ctx_reset(&params_ctx);
    ret = xqc_moq_msg_decode_params_v14(object->ext_buf, object->ext_len,
                                        &params_ctx,
                                        object->ext_params,
                                        object->ext_params_num,
                                        &params_finish, &params_wait);
    if (ret < 0 || params_finish == 0 || params_wait != 0) {
        return -XQC_EILLEGAL_FRAME;
    }

    xqc_free(object->ext_buf);
    object->ext_buf = NULL;
    object->ext_len = 0;
    object->ext_bytes_received = 0;

    return XQC_OK;
}

xqc_int_t
xqc_moq_msg_encode_subgroup_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_subgroup_msg_t *object = (xqc_moq_subgroup_msg_t*)msg_base;
    uint8_t subgroup_type = object->subgroup_type ? object->subgroup_type : XQC_MOQ_SUBGROUP_TYPE_WITH_ID;
    xqc_bool_t has_subgroup_id = xqc_moq_msg_subgroup_has_id(subgroup_type);
    uint64_t object_delta = object->object_id_delta;
    xqc_bool_t has_ext = xqc_moq_msg_subgroup_has_ext(subgroup_type);

    len += xqc_put_varint_len(subgroup_type);
    len += xqc_put_varint_len(object->track_alias);
    len += xqc_put_varint_len(object->group_id);
    if (has_subgroup_id) {
        len += xqc_put_varint_len(object->subgroup_id);
    }
    len += XQC_MOQ_SUBGROUP_PRIORITY_FIXED_SIZE;
    len += xqc_put_varint_len(object_delta);
    if (has_ext) {
        uint64_t ext_len = 0;
        if (object->ext_params && object->ext_params_num > 0) {
            ext_len = xqc_moq_msg_encode_params_len_v14(object->ext_params,
                                                        object->ext_params_num);
        }
        len += xqc_put_varint_len(ext_len);
        len += ext_len;
    }
    len += xqc_put_varint_len(object->payload_len);
    if (object->payload_len == 0) {
        len += xqc_put_varint_len(object->status);
    } else {
        len += object->payload_len;
    }
    return len;
}

xqc_int_t
xqc_moq_msg_append_subgroup_object_len(xqc_moq_subgroup_msg_t *object)
{
    xqc_int_t len = 0;
    uint64_t object_delta = object->object_id_delta;
    xqc_bool_t has_ext = xqc_moq_msg_subgroup_has_ext(object->subgroup_type);

    len += xqc_put_varint_len(object_delta);

    if (has_ext) {
        uint64_t ext_len = 0;
        if (object->ext_params && object->ext_params_num > 0) {
            ext_len = xqc_moq_msg_encode_params_len_v14(object->ext_params,
                                                        (xqc_int_t)object->ext_params_num);
        }
        len += xqc_put_varint_len(ext_len);
        len += (xqc_int_t)ext_len;
    }

    len += xqc_put_varint_len(object->payload_len);
    if (object->payload_len == 0) {
        len += xqc_put_varint_len(object->status);
    } else {
        len += (xqc_int_t)object->payload_len;
    }

    return len;
}

xqc_int_t
xqc_moq_msg_append_subgroup_object(xqc_moq_subgroup_msg_t *object, uint8_t *buf, size_t buf_cap)
{
    uint8_t *p = buf;
    uint8_t *end = buf + buf_cap;
    uint64_t object_delta = object->object_id_delta;
    xqc_bool_t has_ext = xqc_moq_msg_subgroup_has_ext(object->subgroup_type);

    if (buf_cap == 0) {
        return -XQC_EILLEGAL_FRAME;
    }

    p = xqc_put_varint(p, object_delta);

    if (has_ext) {
        uint64_t ext_len = 0;
        if (object->ext_params && object->ext_params_num > 0) {
            ext_len = xqc_moq_msg_encode_params_len_v14(object->ext_params,
                                                        (xqc_int_t)object->ext_params_num);
        }
        p = xqc_put_varint(p, ext_len);
        if (ext_len > 0) {
            xqc_int_t ret = xqc_moq_msg_encode_params_v14(object->ext_params,
                                                          (xqc_int_t)object->ext_params_num,
                                                          p, end - p);
            if (ret < 0) {
                return ret;
            }
            p += ret;
        }
    }

    p = xqc_put_varint(p, object->payload_len);
    if (object->payload_len == 0) {
        p = xqc_put_varint(p, object->status);
    } else {
        if (end - p < object->payload_len) {
            return -XQC_EILLEGAL_FRAME;
        }
        xqc_memcpy(p, object->payload, object->payload_len);
        p += object->payload_len;
    }

    return p - buf;
}

xqc_int_t
xqc_moq_msg_encode_subgroup(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_moq_subgroup_msg_t *object = (xqc_moq_subgroup_msg_t*)msg_base;
    uint8_t subgroup_type = object->subgroup_type ? object->subgroup_type : XQC_MOQ_SUBGROUP_TYPE_WITH_ID;
    xqc_bool_t has_subgroup_id = xqc_moq_msg_subgroup_has_id(subgroup_type);
    uint64_t object_delta = object->object_id_delta;
    xqc_bool_t has_ext = xqc_moq_msg_subgroup_has_ext(subgroup_type);

    if (xqc_moq_msg_encode_subgroup_len(msg_base) > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    uint8_t *p = buf;
    p = xqc_put_varint(p, subgroup_type);
    p = xqc_put_varint(p, object->track_alias);
    p = xqc_put_varint(p, object->group_id);
    if (has_subgroup_id) {
        p = xqc_put_varint(p, object->subgroup_id);
    }
    p = xqc_moq_put_u8(p, object->subgroup_priority);
    p = xqc_put_varint(p, object_delta);
    if (has_ext) {
        uint64_t ext_len = 0;
        if (object->ext_params && object->ext_params_num > 0) {
            ext_len = xqc_moq_msg_encode_params_len_v14(object->ext_params,
                                                        object->ext_params_num);
        }
        p = xqc_put_varint(p, ext_len);
            if (ext_len > 0) {
                xqc_int_t ret = xqc_moq_msg_encode_params_v14(object->ext_params,
                                                          object->ext_params_num,
                                                          p, buf + buf_cap - p);
                if (ret < 0) {
                    return ret;
                }
                p += ret;
            }
    }
    p = xqc_put_varint(p, object->payload_len);
    if (object->payload_len == 0) {
        p = xqc_put_varint(p, object->status);
    } else {
        xqc_memcpy(p, object->payload, object->payload_len);
        p += object->payload_len;
    }
    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_subgroup(uint8_t *buf, size_t buf_len, uint8_t stream_fin, xqc_moq_decode_msg_ctx_t *msg_ctx,
    xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_moq_subgroup_msg_t *object = (xqc_moq_subgroup_msg_t*)msg_base;
    xqc_bool_t has_subgroup_id = 0;
    xqc_bool_t has_ext = 0;

    switch (msg_ctx->cur_field_idx) {
        case 0: // track alias
            object->subgroup_type = msg_ctx->cur_msg_type;
            ret = xqc_vint_read(buf + processed, buf + buf_len, &object->track_alias);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1: // group id
            ret = xqc_vint_read(buf + processed, buf + buf_len, &object->group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 2;
        case 2: // subgroup id (optional)
            has_subgroup_id = xqc_moq_msg_subgroup_has_id(object->subgroup_type);
            if (has_subgroup_id) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, &object->subgroup_id);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
            }
            msg_ctx->cur_field_idx = 3;
        case 3: // priority
            ret = xqc_moq_read_u8(buf, buf_len, &processed, &object->subgroup_priority);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            msg_ctx->cur_field_idx = 4;
        case 4: // object delta
            ret = xqc_vint_read(buf + processed, buf + buf_len, &object->object_id_delta);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            object->object_id = object->object_id_delta;
            msg_ctx->cur_field_idx = 5;
        case 5: // extension headers length (if present)
            has_ext = xqc_moq_msg_subgroup_has_ext(object->subgroup_type);
            if (has_ext) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, &object->ext_len);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
                if (object->ext_len > XQC_MOQ_MAX_OBJECT_LEN) {
                    return -XQC_ELIMIT;
                }
                if (object->ext_len == 0) {
                    msg_ctx->cur_field_idx = 7;
                    break;
                }
                if (object->ext_buf == NULL) {
                    object->ext_buf = xqc_malloc(object->ext_len);
                    if (object->ext_buf == NULL) {
                        return -XQC_EMALLOC;
                    }
                }
                object->ext_bytes_received = 0;
                msg_ctx->cur_field_idx = 6;
                break;
            } else {
                object->ext_len = 0;
                msg_ctx->cur_field_idx = 7;
                goto idx7;
            }
        case 6: // extension headers block (if any)
            has_ext = xqc_moq_msg_subgroup_has_ext(object->subgroup_type);
            if (has_ext && object->ext_len > 0) {
                if (buf_len - processed == 0) {
                    *wait_more_data = 1;
                    break;
                }
                size_t remaining = object->ext_len - object->ext_bytes_received;
                size_t available = buf_len - processed;
                size_t copy = remaining < available ? remaining : available;
                xqc_memcpy(object->ext_buf + object->ext_bytes_received, buf + processed, copy);
                object->ext_bytes_received += copy;
                processed += copy;
                if (object->ext_bytes_received < object->ext_len) {
                    *wait_more_data = 1;
                    break;
                }

                ret = xqc_moq_msg_subgroup_parse_ext_params(object);
                if (ret < 0) {
                    return ret;
                }

                msg_ctx->cur_field_idx = 7;
                break;
            } else {
                msg_ctx->cur_field_idx = 7;
            }
        case 7: // payload length
            idx7:
            ret = xqc_vint_read(buf + processed, buf + buf_len, &object->payload_len);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            if (object->payload_len > XQC_MOQ_MAX_OBJECT_LEN) {
                return -XQC_ELIMIT;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 8;
        case 8: // payload or status
            if (object->payload_len == 0) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, &object->status);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
                *finish = 1;
                msg_ctx->payload_processed = 0;
                break;
            }

            if (buf_len - processed == 0) {
                *wait_more_data = 1;
                break;
            }
            size_t remaining = object->payload_len - msg_ctx->payload_processed;
            size_t available = buf_len - processed;
            size_t copy = remaining < available ? remaining : available;
            object->payload = xqc_realloc(object->payload, msg_ctx->payload_processed + copy);
            xqc_memcpy(object->payload + msg_ctx->payload_processed, buf + processed, copy);
            msg_ctx->payload_processed += copy;
            processed += copy;
            if (msg_ctx->payload_processed == object->payload_len) {
                *finish = 1;
                msg_ctx->payload_processed = 0;
            } else {
                *wait_more_data = 1;
            }
            break;
        default:
            break;
    }

    if (*finish && stream_fin == 0 && object->payload_len == 0) {
        // nothing extra
    } else if (*finish == 0 && stream_fin == 1 && object->payload_len > 0 &&
               msg_ctx->payload_processed != 0 &&
               msg_ctx->payload_processed == object->payload_len) {
        *finish = 1;
        msg_ctx->payload_processed = 0;
    }

    return processed;
}

/**
 * STREAM_HEADER_TRACK Object
 */

void *
xqc_moq_msg_create_track_stream_obj()
{
    xqc_moq_track_stream_obj_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_track_stream_obj_init_handler(&msg->msg_base);
    return msg;
}

void
xqc_moq_msg_free_track_stream_obj(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_track_stream_obj_msg_t *track_stream_obj = (xqc_moq_track_stream_obj_msg_t *)msg;
    xqc_free(track_stream_obj->payload);
    xqc_free(track_stream_obj);
}

xqc_moq_msg_type_t
xqc_moq_msg_track_stream_obj_type()
{
    return XQC_MOQ_MSG_TRACK_STREAM_OBJECT;
}

void
xqc_moq_msg_track_stream_obj_init_handler(xqc_moq_msg_base_t *msg_base)
{
    *msg_base = track_stream_obj_base;
}

xqc_int_t
xqc_moq_msg_encode_track_stream_obj_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_track_stream_obj_msg_t *object = (xqc_moq_track_stream_obj_msg_t*)msg_base;
    //len += xqc_put_varint_len(XQC_MOQ_MSG_TRACK_STREAM_OBJECT); No type on the wire
    len += xqc_put_varint_len(object->group_id);
    len += xqc_put_varint_len(object->object_id);
    len += xqc_put_varint_len(object->payload_len);
    if (object->payload_len == 0) {
        len += xqc_put_varint_len(object->status);
    } else {
        len += object->payload_len;
    }
    return len;
}

xqc_int_t
xqc_moq_msg_encode_track_stream_obj(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_moq_track_stream_obj_msg_t *object = (xqc_moq_track_stream_obj_msg_t*)msg_base;
    if (xqc_moq_msg_encode_track_stream_obj_len(msg_base) > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    uint8_t *p = buf;
    //p = xqc_put_varint(p, XQC_MOQ_MSG_TRACK_STREAM_OBJECT); No type on the wire
    p = xqc_put_varint(p, object->group_id);
    p = xqc_put_varint(p, object->object_id);
    p = xqc_put_varint(p, object->payload_len);
    if (object->payload_len == 0) {
        p = xqc_put_varint(p, object->status);
    } else {
        xqc_memcpy(p, object->payload, object->payload_len);
        p += object->payload_len;
    }
    return p - buf;
}

//return processed or error
xqc_int_t
xqc_moq_msg_decode_track_stream_obj(uint8_t *buf, size_t buf_len, uint8_t stream_fin, xqc_moq_decode_msg_ctx_t *msg_ctx,
    xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_moq_track_stream_obj_msg_t *object = (xqc_moq_track_stream_obj_msg_t *)msg_base;
    switch (msg_ctx->cur_field_idx) {
        case 0: //Group ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &object->group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>group_id:%d\n",(int)object->group_id);
            msg_ctx->cur_field_idx = 1;
        case 1: //Object ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &object->object_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>object_id:%d\n",(int)object->object_id);
            msg_ctx->cur_field_idx = 2;
        case 2: //Object Payload Length (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &object->payload_len);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            if (object->payload_len) {
                object->payload = xqc_realloc(object->payload, object->payload_len);
            }
            DEBUG_PRINTF("==>payload_len:%d\n",(int)object->payload_len);
            msg_ctx->cur_field_idx = 3;
        case 3: //Object Status (i)
            if (object->payload_len == 0) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, &object->status);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
                DEBUG_PRINTF("==>status:%d\n", (int) object->status);
            }
            msg_ctx->cur_field_idx = 4;
        case 4: //Object Payload (..)
            if (object->payload_len == 0) {
                *finish = 1;
                break;
            }

            if (processed == buf_len) {
                *wait_more_data = 1;
                break;
            } else if (object->payload_len - msg_ctx->payload_processed <= buf_len - processed) {
                xqc_memcpy(object->payload + msg_ctx->payload_processed, buf + processed,
                           object->payload_len - msg_ctx->payload_processed);
                processed += object->payload_len - msg_ctx->payload_processed;
                *finish = 1;
            } else {
                xqc_memcpy(object->payload + msg_ctx->payload_processed, buf + processed,
                           buf_len - processed);
                msg_ctx->payload_processed += buf_len - processed;
                processed += buf_len - processed;
                *wait_more_data = 1;
                break;
            }
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}

/**
 * STREAM_HEADER_TRACK Message
 */

void *
xqc_moq_msg_create_track_header()
{
    xqc_moq_stream_header_track_msg_t *msg = xqc_calloc(1, sizeof(*msg));
    xqc_moq_msg_track_header_init_handler(&msg->msg_base);
    return msg;
}

void
xqc_moq_msg_free_track_header(void *msg)
{
    if (msg == NULL) {
        return;
    }
    xqc_moq_stream_header_track_msg_t *track_header = (xqc_moq_stream_header_track_msg_t *)msg;
    xqc_free(track_header);
}

xqc_moq_msg_type_t
xqc_moq_msg_track_header_type()
{
    return XQC_MOQ_MSG_STREAM_HEADER_TRACK;
}

void
xqc_moq_msg_track_header_init_handler(xqc_moq_msg_base_t *msg_base)
{
    *msg_base = track_header_base;
}

xqc_int_t
xqc_moq_msg_encode_track_header_len(xqc_moq_msg_base_t *msg_base)
{
    xqc_int_t len = 0;
    xqc_moq_stream_header_track_msg_t *track_header = (xqc_moq_stream_header_track_msg_t *)msg_base;
    len += xqc_put_varint_len(XQC_MOQ_MSG_STREAM_HEADER_TRACK);
    len += xqc_put_varint_len(track_header->subscribe_id);
    len += xqc_put_varint_len(track_header->track_alias);
    len += xqc_put_varint_len(track_header->send_order);

    return len;
}

xqc_int_t
xqc_moq_msg_encode_track_header(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_moq_stream_header_track_msg_t *track_header = (xqc_moq_stream_header_track_msg_t *)msg_base;
    if (xqc_moq_msg_encode_track_header_len(msg_base) > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_STREAM_HEADER_TRACK);
    p = xqc_put_varint(p, track_header->subscribe_id);
    p = xqc_put_varint(p, track_header->track_alias);
    p = xqc_put_varint(p, track_header->send_order);

    return p - buf;
}

xqc_int_t
xqc_moq_msg_decode_track_header(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data)
{
    *finish = 0;
    *wait_more_data = 0;
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    xqc_moq_stream_header_track_msg_t *track_header = (xqc_moq_stream_header_track_msg_t *)msg_base;
    switch (msg_ctx->cur_field_idx) {
        case 0: //Subscribe ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &track_header->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>subscribe_id:%d\n",(int)track_header->subscribe_id);
            msg_ctx->cur_field_idx = 1;
        case 1: //Track Alias (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &track_header->track_alias);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>track_alias:%d\n",(int)track_header->track_alias);
            msg_ctx->cur_field_idx = 2;
        case 2: //Object Send Order (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &track_header->send_order);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>send_order:%d\n",(int)track_header->send_order);

            *finish = 1;
            break;
        default:
            return -XQC_EILLEGAL_FRAME;
    }

    return processed;
}
