#include "moq/moq_transport/xqc_moq_message.h"
#include "moq/moq_transport/xqc_moq_message_handler.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"

static xqc_moq_msg_func_map_t moq_msg_func_map[] = {
    {XQC_MOQ_MSG_OBJECT_STREAM,        xqc_moq_msg_create_object_stream,    xqc_moq_msg_free_object_stream   },
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
//    {XQC_MOQ_MSG_ANNOUNCE,             NULL,                                NULL                             },
//    {XQC_MOQ_MSG_ANNOUNCE_OK,          NULL,                                NULL                             },
//    {XQC_MOQ_MSG_ANNOUNCE_ERROR,       NULL,                                NULL                             },
//    {XQC_MOQ_MSG_UNANNOUNCE,           NULL,                                NULL                             },
//    {XQC_MOQ_MSG_UNSUBSCRIBE,          NULL,                                NULL                             },
//    {XQC_MOQ_MSG_SUBSCRIBE_DONE,       NULL,                                NULL                             },
//    {XQC_MOQ_MSG_ANNOUNCE_CANCEL,      NULL,                                NULL                             },
//    {XQC_MOQ_MSG_TRACK_STATUS_REQUEST, NULL,                                NULL                             },
//    {XQC_MOQ_MSG_TRACK_STATUS,         NULL,                                NULL                             },
//    {XQC_MOQ_MSG_GOAWAY,               NULL,                                NULL                             },
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

const xqc_moq_msg_base_t object_stream_base = {
    .type       = xqc_moq_msg_object_stream_type,
    .encode_len = xqc_moq_msg_encode_object_stream_len,
    .encode     = xqc_moq_msg_encode_object_stream,
    .decode     = xqc_moq_msg_decode_object_stream,
    .on_msg     = xqc_moq_on_object_stream,
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
    obj->send_order = msg->send_order;
    obj->status = msg->status;
    obj->payload = msg->payload;
    obj->payload_len = msg->payload_len;
}

void xqc_moq_msg_set_object_by_track(xqc_moq_object_t *obj, xqc_moq_stream_header_track_msg_t *header,
    xqc_moq_track_stream_obj_msg_t *msg)
{
    obj->subscribe_id = header->subscribe_id;
    obj->track_alias = header->track_alias;
    obj->send_order = header->send_order;
    obj->group_id = msg->group_id;
    obj->object_id = msg->object_id;
    obj->status = msg->status;
    obj->payload = msg->payload;
    obj->payload_len = msg->payload_len;
}

void xqc_moq_msg_set_object_by_group(xqc_moq_object_t *obj, xqc_moq_stream_header_group_msg_t *header,
    xqc_moq_group_stream_obj_msg_t *msg)
{
    obj->subscribe_id = header->subscribe_id;
    obj->track_alias = header->track_alias;
    obj->send_order = header->send_order;
    obj->group_id = header->group_id;
    obj->object_id = msg->object_id;
    obj->status = msg->status;
    obj->payload = msg->payload;
    obj->payload_len = msg->payload_len;
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
        xqc_free(params[i].value);
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
        len += xqc_put_varint_len(param->length);
        if (param->length > 0) {
            len += param->length;
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
        p = xqc_put_varint(p, param->length);
        if (param->length > 0) {
            xqc_memcpy(p, param->value, param->length);
            p += param->length;
        }
    }

    return p - buf;
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
            ret = xqc_moq_msg_decode_params(buf + processed, buf_len - processed, params_ctx,
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


/**
 * SUBSCRIBE Message
 */

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
    xqc_free(subscribe->track_namespace);
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
    len += xqc_put_varint_len(XQC_MOQ_MSG_SUBSCRIBE);
    len += xqc_put_varint_len(subscribe->subscribe_id);
    len += xqc_put_varint_len(subscribe->track_alias);
    len += xqc_put_varint_len(subscribe->track_namespace_len);
    len += subscribe->track_namespace_len;
    len += xqc_put_varint_len(subscribe->track_name_len);
    len += subscribe->track_name_len;
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
    if (xqc_moq_msg_encode_subscribe_len(msg_base) > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_SUBSCRIBE);
    p = xqc_put_varint(p, subscribe->subscribe_id);
    p = xqc_put_varint(p, subscribe->track_alias);
    p = xqc_put_varint(p, subscribe->track_namespace_len);
    xqc_memcpy(p, subscribe->track_namespace, subscribe->track_namespace_len);
    p += subscribe->track_namespace_len;
    p = xqc_put_varint(p, subscribe->track_name_len);
    xqc_memcpy(p, subscribe->track_name, subscribe->track_name_len);
    p += subscribe->track_name_len;
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
        case 0: //Subscribe ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>subscribe_id:%d\n",(int)subscribe->subscribe_id);
            msg_ctx->cur_field_idx = 1;
        case 1: //Track Alias (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->track_alias);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>track_alias:%d\n",(int)subscribe->track_alias);
            msg_ctx->cur_field_idx = 2;
        case 2: //Track Namespace (b)
            if (subscribe->track_namespace_len == 0) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, (uint64_t *)&subscribe->track_namespace_len);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                DEBUG_PRINTF("==>namespace_len:%d\n",(int)subscribe->track_namespace_len);
                processed += ret;
            }
            if (subscribe->track_namespace == NULL) {
                if (subscribe->track_namespace_len > XQC_MOQ_MAX_NAME_LEN) {
                    return -XQC_ELIMIT;
                }
                subscribe->track_namespace = xqc_calloc(1, subscribe->track_namespace_len + 1);
            }
            if (processed == buf_len) {
                *wait_more_data = 1;
                break;
            } else if (subscribe->track_namespace_len - msg_ctx->str_processed <= buf_len - processed) {
                xqc_memcpy(subscribe->track_namespace + msg_ctx->str_processed, buf + processed,
                           subscribe->track_namespace_len - msg_ctx->str_processed);
                processed += subscribe->track_namespace_len - msg_ctx->str_processed;
                msg_ctx->str_processed = 0; //track_namespace finish
            } else {
                xqc_memcpy(subscribe->track_namespace + msg_ctx->str_processed, buf + processed,
                           buf_len - processed);
                msg_ctx->str_processed += buf_len - processed;
                processed += buf_len - processed;
                *wait_more_data = 1;
                break;
            }
            DEBUG_PRINTF("==>track_namespace:%s\n",subscribe->track_namespace);
            msg_ctx->cur_field_idx = 3;
        case 3: //Track Name (b)
            if (subscribe->track_name_len == 0) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, (uint64_t *)&subscribe->track_name_len);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                DEBUG_PRINTF("==>name_len:%d\n",(int)subscribe->track_name_len);
                processed += ret;
            }
            if (subscribe->track_name == NULL) {
                if (subscribe->track_name_len > XQC_MOQ_MAX_NAME_LEN) {
                    return -XQC_ELIMIT;
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
            msg_ctx->cur_field_idx = 4;
        case 4: //Filter Type (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->filter_type);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>filter_type:%d\n",(int)subscribe->filter_type);
            if (subscribe->filter_type == XQC_MOQ_FILTER_LAST_GROUP
                || subscribe->filter_type == XQC_MOQ_FILTER_LAST_OBJECT) {
                msg_ctx->cur_field_idx = 9;
                goto idx9;
            } else if (subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_START
                       || subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
                msg_ctx->cur_field_idx = 5;
            } else {
                return -XQC_EPARAM;
            }
        case 5: //StartGroup (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->start_group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>start_group_id:%d\n",(int)subscribe->start_group_id);
            msg_ctx->cur_field_idx = 6;
        case 6: //StartObject (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->start_object_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>start_object_id:%d\n",(int)subscribe->start_object_id);
            if (subscribe->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
                msg_ctx->cur_field_idx = 7;
            } else {
                msg_ctx->cur_field_idx = 9;
                goto idx9;
            }
        case 7: //EndGroup (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->end_group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>end_group_id:%d\n",(int)subscribe->end_group_id);
            msg_ctx->cur_field_idx = 8;
        case 8: //EndObject (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe->end_object_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>end_object_id:%d\n",(int)subscribe->end_object_id);
            msg_ctx->cur_field_idx = 9;
        case 9: //Number of Parameters (i) ...
        idx9:
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

            msg_ctx->cur_field_idx = 10;
        case 10: //Subscribe Parameters (..) ...
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
    len += xqc_put_varint_len(subscribe_update->subscribe_id);
    len += xqc_put_varint_len(subscribe_update->start_group_id);
    len += xqc_put_varint_len(subscribe_update->start_object_id);
    len += xqc_put_varint_len(subscribe_update->end_group_id);
    len += xqc_put_varint_len(subscribe_update->end_object_id);
    len += xqc_put_varint_len(subscribe_update->params_num);
    len += xqc_moq_msg_encode_params_len(subscribe_update->params, subscribe_update->params_num);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_subscribe_update(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_subscribe_update_msg_t *subscribe_update = (xqc_moq_subscribe_update_msg_t*)msg_base;
    if (xqc_moq_msg_encode_subscribe_update_len(msg_base) > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_SUBSCRIBE_UPDATE);
    p = xqc_put_varint(p, subscribe_update->subscribe_id);
    p = xqc_put_varint(p, subscribe_update->start_group_id);
    p = xqc_put_varint(p, subscribe_update->start_object_id);
    p = xqc_put_varint(p, subscribe_update->end_group_id);
    p = xqc_put_varint(p, subscribe_update->end_object_id);
    p = xqc_put_varint(p, subscribe_update->params_num);
    ret = xqc_moq_msg_encode_params(subscribe_update->params, subscribe_update->params_num, p, buf + buf_cap - p);
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
    uint64_t val = 0;
    xqc_moq_subscribe_update_msg_t *subscribe_update = (xqc_moq_subscribe_update_msg_t *)msg_base;
    xqc_moq_decode_params_ctx_t *params_ctx = &msg_ctx->decode_params_ctx;
    switch (msg_ctx->cur_field_idx) {
        case 0: //subscribe_update ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_update->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>subscribe_id:%d\n",(int)subscribe_update->subscribe_id);
            msg_ctx->cur_field_idx = 1;
        case 1: //StartGroup (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_update->start_group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>start_group_id:%d\n",(int)subscribe_update->start_group_id);
            msg_ctx->cur_field_idx = 2;
        case 2: //StartObject (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_update->start_object_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>start_object_id:%d\n",(int)subscribe_update->start_object_id);
            msg_ctx->cur_field_idx = 3;
        case 3: //EndGroup (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_update->end_group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>end_group_id:%d\n",(int)subscribe_update->end_group_id);
            msg_ctx->cur_field_idx = 4;
        case 4: //EndObject (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_update->end_object_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>end_object_id:%d\n",(int)subscribe_update->end_object_id);
            msg_ctx->cur_field_idx = 5;
        case 5: //Number of Parameters (i) ...
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

            msg_ctx->cur_field_idx = 6;
        case 6: //subscribe_update Parameters (..) ...
            ret = xqc_moq_msg_decode_params(buf + processed, buf_len - processed, params_ctx,
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
    len += xqc_put_varint_len(subscribe_ok->subscribe_id);
    len += xqc_put_varint_len(subscribe_ok->expire_ms);
    len += xqc_put_varint_len(subscribe_ok->content_exist);
    if (subscribe_ok->content_exist == 1) {
        len += xqc_put_varint_len(subscribe_ok->largest_group_id);
        len += xqc_put_varint_len(subscribe_ok->largest_object_id);
    }
    return len;
}

xqc_int_t
xqc_moq_msg_encode_subscribe_ok(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_subscribe_ok_msg_t *subscribe_ok = (xqc_moq_subscribe_ok_msg_t*)msg_base;
    if (xqc_moq_msg_encode_subscribe_ok_len(msg_base) > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_SUBSCRIBE_OK);
    p = xqc_put_varint(p, subscribe_ok->subscribe_id);
    p = xqc_put_varint(p, subscribe_ok->expire_ms);
    p = xqc_put_varint(p, subscribe_ok->content_exist);
    if (subscribe_ok->content_exist == 1) {
        p = xqc_put_varint(p, subscribe_ok->largest_group_id);
        p = xqc_put_varint(p, subscribe_ok->largest_object_id);
    }

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
    xqc_moq_subscribe_ok_msg_t *subscribe_ok = (xqc_moq_subscribe_ok_msg_t *)msg_base;
    switch (msg_ctx->cur_field_idx) {
        case 0: //Subscribe ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_ok->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            DEBUG_PRINTF("==>subscribe_id:%d\n",(int)subscribe_ok->subscribe_id);

            msg_ctx->cur_field_idx = 1;
        case 1: //Expires (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_ok->expire_ms);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            DEBUG_PRINTF("==>expires:%d\n",(int)subscribe_ok->expire_ms);

            msg_ctx->cur_field_idx = 2;
        case 2: //ContentExists (f)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_ok->content_exist);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            DEBUG_PRINTF("==>content_exist:%d\n",(int)subscribe_ok->content_exist);

            if (subscribe_ok->content_exist == 0) {
                *finish = 1;
                break;
            }
            msg_ctx->cur_field_idx = 3;
        case 3: //[Largest Group ID (i)]
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_ok->largest_group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            DEBUG_PRINTF("==>largest_group_id:%d\n",(int)subscribe_ok->largest_group_id);

            msg_ctx->cur_field_idx = 4;
        case 4: //[Largest Object ID (i)]
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_ok->largest_object_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            DEBUG_PRINTF("==>largest_object_id:%d\n",(int)subscribe_ok->largest_object_id);

            *finish = 1;
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
    if (xqc_moq_msg_encode_subscribe_error_len(msg_base) > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_SUBSCRIBE_ERROR);
    p = xqc_put_varint(p, subscribe_error->subscribe_id);
    p = xqc_put_varint(p, subscribe_error->error_code);
    p = xqc_put_varint(p, subscribe_error->reason_phrase_len);
    xqc_memcpy(p, subscribe_error->reason_phrase, subscribe_error->reason_phrase_len);
    p += subscribe_error->reason_phrase_len;
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
    switch (msg_ctx->cur_field_idx) {
        case 0: //Subscribe ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_error->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            DEBUG_PRINTF("==>subscribe_id:%d\n",(int)subscribe_error->subscribe_id);

            msg_ctx->cur_field_idx = 1;
        case 1: //Error Code (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &subscribe_error->error_code);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;

            DEBUG_PRINTF("==>error_code:%d\n",(int)subscribe_error->error_code);

            msg_ctx->cur_field_idx = 2;
        case 2: //Reason Phrase (b)
            if (subscribe_error->reason_phrase_len == 0) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, (uint64_t *)&subscribe_error->reason_phrase_len);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                DEBUG_PRINTF("==>reason_phrase_len:%d\n",(int)subscribe_error->reason_phrase_len);
                processed += ret;
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
            msg_ctx->cur_field_idx = 3;
        case 3: //Track Alias (i)
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
    xqc_free(publish->track_namespace);
    publish->track_namespace = NULL;
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
    len += xqc_put_varint_len(XQC_MOQ_MSG_PUBLISH);
    len += xqc_put_varint_len(publish->subscribe_id);
    len += xqc_put_varint_len(publish->track_namespace_len);
    len += publish->track_namespace_len;
    len += xqc_put_varint_len(publish->track_name_len);
    len += publish->track_name_len;
    len += xqc_put_varint_len(publish->track_alias);
    len += xqc_put_varint_len(publish->group_order);
    len += xqc_put_varint_len(publish->content_exist);
    if (publish->content_exist == 1) {
        len += xqc_put_varint_len(publish->largest_group_id);
        len += xqc_put_varint_len(publish->largest_object_id);
    }
    len += xqc_put_varint_len(publish->forward);
    len += xqc_put_varint_len(publish->params_num);
    len += xqc_moq_msg_encode_params_len(publish->params, publish->params_num);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_publish(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_int_t ret = 0;
    xqc_moq_publish_msg_t *publish = (xqc_moq_publish_msg_t*)msg_base;
    if (xqc_moq_msg_encode_publish_len(msg_base) > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_PUBLISH);
    p = xqc_put_varint(p, publish->subscribe_id);
    p = xqc_put_varint(p, publish->track_namespace_len);
    xqc_memcpy(p, publish->track_namespace, publish->track_namespace_len);
    p += publish->track_namespace_len;
    p = xqc_put_varint(p, publish->track_name_len);
    xqc_memcpy(p, publish->track_name, publish->track_name_len);
    p += publish->track_name_len;
    p = xqc_put_varint(p, publish->track_alias);
    p = xqc_put_varint(p, publish->group_order);
    p = xqc_put_varint(p, publish->content_exist);
    if (publish->content_exist == 1) {
        p = xqc_put_varint(p, publish->largest_group_id);
        p = xqc_put_varint(p, publish->largest_object_id);
    }
    p = xqc_put_varint(p, publish->forward);
    p = xqc_put_varint(p, publish->params_num);
    ret = xqc_moq_msg_encode_params(publish->params, publish->params_num, p, buf + buf_cap - p);
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
    uint64_t val = 0;
    xqc_moq_publish_msg_t *publish = (xqc_moq_publish_msg_t *)msg_base;
    xqc_moq_decode_params_ctx_t *params_ctx = &msg_ctx->decode_params_ctx;
    switch (msg_ctx->cur_field_idx) {
        case 0: //Request ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1: //Track Namespace (b)
            if (publish->track_namespace_len == 0) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, (uint64_t*)&publish->track_namespace_len);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
            }
            if (publish->track_namespace == NULL) {
                if (publish->track_namespace_len == 0 || publish->track_namespace_len > XQC_MOQ_MAX_NAME_LEN) {
                    return -XQC_ELIMIT;
                }
                publish->track_namespace = xqc_calloc(1, publish->track_namespace_len + 1);
            }
            if (processed == buf_len) {
                *wait_more_data = 1;
                break;
            } else if (publish->track_namespace_len - msg_ctx->str_processed <= buf_len - processed) {
                xqc_memcpy(publish->track_namespace + msg_ctx->str_processed, buf + processed,
                           publish->track_namespace_len - msg_ctx->str_processed);
                processed += publish->track_namespace_len - msg_ctx->str_processed;
                msg_ctx->str_processed = 0;
            } else {
                xqc_memcpy(publish->track_namespace + msg_ctx->str_processed, buf + processed,
                           buf_len - processed);
                msg_ctx->str_processed += buf_len - processed;
                processed += buf_len - processed;
                *wait_more_data = 1;
                break;
            }
            msg_ctx->cur_field_idx = 2;
        case 2: //Track Name (b)
            if (publish->track_name_len == 0) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, (uint64_t*)&publish->track_name_len);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
            }
            if (publish->track_name == NULL) {
                if (publish->track_name_len == 0 || publish->track_name_len > XQC_MOQ_MAX_NAME_LEN) {
                    return -XQC_ELIMIT;
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
            msg_ctx->cur_field_idx = 3;
        case 3: //Track Alias (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish->track_alias);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 4;
        case 4: //Group Order (8)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &val);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            if (val > UINT8_MAX) {
                return -XQC_EILLEGAL_FRAME;
            }
            publish->group_order = (uint8_t)val;
            processed += ret;
            msg_ctx->cur_field_idx = 5;
        case 5: //Content Exists (8)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &val);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            if (val > UINT8_MAX) {
                return -XQC_EILLEGAL_FRAME;
            }
            publish->content_exist = (uint8_t)val;
            processed += ret;
            if (publish->content_exist == 1) {
                msg_ctx->cur_field_idx = 6;
            } else {
                msg_ctx->cur_field_idx = 8;
                goto publish_idx8;
            }
        case 6: //Largest Group ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish->largest_group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 7;
        case 7: //Largest Object ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish->largest_object_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 8;
        case 8: //Forward (8)
publish_idx8:
            ret = xqc_vint_read(buf + processed, buf + buf_len, &val);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            if (val > UINT8_MAX) {
                return -XQC_EILLEGAL_FRAME;
            }
            publish->forward = (uint8_t)val;
            processed += ret;
            msg_ctx->cur_field_idx = 9;
        case 9: //Number of Parameters (i)
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
            msg_ctx->cur_field_idx = 10;
        case 10: //Parameters
            ret = xqc_moq_msg_decode_params(buf + processed, buf_len - processed, params_ctx,
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
    len += xqc_put_varint_len(publish_ok->subscribe_id);
    len += xqc_put_varint_len(publish_ok->forward);
    len += xqc_put_varint_len(publish_ok->subscriber_priority);
    len += xqc_put_varint_len(publish_ok->group_order);
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
    if (xqc_moq_msg_encode_publish_ok_len(msg_base) > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_PUBLISH_OK);
    p = xqc_put_varint(p, publish_ok->subscribe_id);
    p = xqc_put_varint(p, publish_ok->forward);
    p = xqc_put_varint(p, publish_ok->subscriber_priority);
    p = xqc_put_varint(p, publish_ok->group_order);
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
    uint64_t val = 0;
    xqc_moq_publish_ok_msg_t *publish_ok = (xqc_moq_publish_ok_msg_t *)msg_base;
    xqc_moq_decode_params_ctx_t *params_ctx = &msg_ctx->decode_params_ctx;
    switch (msg_ctx->cur_field_idx) {
        case 0: //Request ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish_ok->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1: //Forward (8)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &val);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            if (val > UINT8_MAX) {
                return -XQC_EILLEGAL_FRAME;
            }
            publish_ok->forward = (uint8_t)val;
            processed += ret;
            msg_ctx->cur_field_idx = 2;
        case 2: //Subscriber Priority (8)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &val);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            if (val > UINT8_MAX) {
                return -XQC_EILLEGAL_FRAME;
            }
            publish_ok->subscriber_priority = (uint8_t)val;
            processed += ret;
            msg_ctx->cur_field_idx = 3;
        case 3: //Group Order (8)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &val);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            if (val > UINT8_MAX) {
                return -XQC_EILLEGAL_FRAME;
            }
            publish_ok->group_order = (uint8_t)val;
            processed += ret;
            msg_ctx->cur_field_idx = 4;
        case 4: //Filter Type (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish_ok->filter_type);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            if (publish_ok->filter_type == XQC_MOQ_FILTER_ABSOLUTE_START
                || publish_ok->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
                msg_ctx->cur_field_idx = 5;
            } else {
                msg_ctx->cur_field_idx = 8;
                goto publish_ok_idx8;
            }
        case 5: //Start Group (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish_ok->start_group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 6;
        case 6: //Start Object (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish_ok->start_object_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            if (publish_ok->filter_type == XQC_MOQ_FILTER_ABSOLUTE_RANGE) {
                msg_ctx->cur_field_idx = 7;
            } else {
                msg_ctx->cur_field_idx = 8;
                goto publish_ok_idx8;
            }
        case 7: //End Group (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish_ok->end_group_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 8;
        case 8: //Parameters Num (i)
publish_ok_idx8:
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
            msg_ctx->cur_field_idx = 9;
        case 9: //Parameters (..)
            ret = xqc_moq_msg_decode_params(buf + processed, buf_len - processed, params_ctx,
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
    if (xqc_moq_msg_encode_publish_error_len(msg_base) > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_PUBLISH_ERROR);
    p = xqc_put_varint(p, publish_error->subscribe_id);
    p = xqc_put_varint(p, publish_error->error_code);
    p = xqc_put_varint(p, publish_error->reason_phrase_len);
    xqc_memcpy(p, publish_error->reason_phrase, publish_error->reason_phrase_len);
    p += publish_error->reason_phrase_len;

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
    switch (msg_ctx->cur_field_idx) {
        case 0: //Request ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish_error->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1: //Error Code (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish_error->error_code);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 2;
        case 2: //Reason Phrase (b)
            if (publish_error->reason_phrase_len == 0) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, (uint64_t*)&publish_error->reason_phrase_len);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
                processed += ret;
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
    xqc_moq_publish_done_msg_t *publish_done = (xqc_moq_publish_done_msg_t*)msg_base;
    if (xqc_moq_msg_encode_publish_done_len(msg_base) > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_PUBLISH_DONE);
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
    xqc_moq_publish_done_msg_t *publish_done = (xqc_moq_publish_done_msg_t*)msg_base;
    switch (msg_ctx->cur_field_idx) {
        case 0: //Request ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish_done->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 1;
        case 1: //Status Code (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish_done->status_code);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 2;
        case 2: //Stream Count (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &publish_done->stream_count);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            msg_ctx->cur_field_idx = 3;
        case 3: //Reason Phrase (b)
            if (publish_done->reason_phrase_len == 0) {
                ret = xqc_vint_read(buf + processed, buf + buf_len, (uint64_t*)&publish_done->reason_phrase_len);
                if (ret < 0) {
                    *wait_more_data = 1;
                    break;
                }
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
    len += xqc_put_varint_len(unsubscribe->subscribe_id);
    return len;
}

xqc_int_t
xqc_moq_msg_encode_unsubscribe(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap)
{
    xqc_moq_unsubscribe_msg_t *unsubscribe = (xqc_moq_unsubscribe_msg_t*)msg_base;
    if (xqc_moq_msg_encode_unsubscribe_len(msg_base) > buf_cap) {
        return -XQC_EILLEGAL_FRAME;
    }

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_MOQ_MSG_UNSUBSCRIBE);
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

    switch (msg_ctx->cur_field_idx) {
        case 0: // Subscribe ID (i)
            ret = xqc_vint_read(buf + processed, buf + buf_len, &unsubscribe->subscribe_id);
            if (ret < 0) {
                *wait_more_data = 1;
                break;
            }
            processed += ret;
            DEBUG_PRINTF("==>unsubscribe subscribe_id:%d\n", (int)unsubscribe->subscribe_id);
            msg_ctx->cur_field_idx = 1;
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