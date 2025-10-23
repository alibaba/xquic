#ifndef _XQC_MOQ_MESSAGE_H_INCLUDED_
#define _XQC_MOQ_MESSAGE_H_INCLUDED_

#include "moq/xqc_moq.h"

#define XQC_MOQ_MAX_PARAMS          10
#define XQC_MOQ_MAX_VERSIONS        10
#define XQC_MOQ_MAX_OBJECT_LEN      (10 * 1024 * 1024)
#define XQC_MOQ_MAX_PARAM_VALUE_LEN 4096
#define XQC_MOQ_MAX_NAME_LEN        1024
#define XQC_MOQ_MAX_AUTH_LEN        1024

typedef enum {
    XQC_MOQ_PARAM_ROLE              = 0x00,
    XQC_MOQ_PARAM_PATH              = 0x01,
    XQC_MOQ_PARAM_AUTH              = 0x02,
    XQC_MOQ_PARAM_EXTDATA           = 0xA0,
} xqc_moq_param_type_t;

typedef enum {
    XQC_MOQ_DECODE_MSG_TYPE,
    XQC_MOQ_DECODE_MSG,
} xqc_moq_decode_state_t;

typedef struct xqc_moq_object_s {
    uint64_t                    subscribe_id;
    uint64_t                    track_alias;
    uint64_t                    group_id;
    uint64_t                    object_id;
    uint64_t                    send_order;
    uint64_t                    status;
    uint8_t                     *payload;
    uint64_t                    payload_len;
} xqc_moq_object_t;

typedef struct {
    xqc_int_t                   cur_param_idx; //Params[idx]
    xqc_int_t                   cur_field_idx; //0:Type, 1:Length, 2:Value
    xqc_int_t                   value_processed;
} xqc_moq_decode_params_ctx_t;

typedef struct xqc_moq_decode_msg_ctx_s {
    xqc_moq_decode_state_t      cur_decode_state;
    xqc_moq_msg_type_t          cur_msg_type;
    void                        *cur_decode_msg;
    xqc_int_t                   cur_field_idx;
    xqc_int_t                   cur_array_idx;
    xqc_int_t                   payload_processed;
    xqc_int_t                   str_processed;
    xqc_moq_decode_params_ctx_t decode_params_ctx;
} xqc_moq_decode_msg_ctx_t;

typedef void (*xqc_moq_msg_init_handler_pt)(xqc_moq_msg_base_t *msg_base);

typedef struct {
    xqc_moq_msg_type_t type;
    void* (*create)();
    void (*free)(void *);
} xqc_moq_msg_func_map_t;

typedef struct xqc_moq_client_setup_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    versions_num;
    uint64_t                    *versions;
    uint64_t                    params_num;
    xqc_moq_message_parameter_t *params;
} xqc_moq_client_setup_msg_t;

typedef struct xqc_moq_server_setup_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    version;
    uint64_t                    params_num;
    xqc_moq_message_parameter_t *params;
} xqc_moq_server_setup_msg_t;

typedef struct xqc_moq_object_stream_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    subscribe_id;
    uint64_t                    track_alias;
    uint64_t                    group_id;
    uint64_t                    object_id;
    uint64_t                    send_order;
    uint64_t                    status;
    uint8_t                     *payload;
    uint64_t                    payload_len;
} xqc_moq_object_stream_msg_t;

typedef struct xqc_moq_object_datagram_msg_s {
    xqc_moq_msg_base_t          msg_base;
} xqc_moq_object_datagram_msg_t;

typedef struct xqc_moq_stream_header_track_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    subscribe_id;
    uint64_t                    track_alias;
    uint64_t                    send_order;
} xqc_moq_stream_header_track_msg_t;

typedef struct xqc_moq_track_stream_obj_msg_s {
    xqc_moq_msg_base_t          msg_base;
    xqc_moq_stream_header_track_msg_t track_header;
    uint64_t                    group_id;
    uint64_t                    object_id;
    uint64_t                    payload_len;
    uint64_t                    status;
    uint8_t                     *payload;
} xqc_moq_track_stream_obj_msg_t;

typedef struct xqc_moq_stream_header_group_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    subscribe_id;
    uint64_t                    track_alias;
    uint64_t                    group_id;
    uint64_t                    send_order;
} xqc_moq_stream_header_group_msg_t;

typedef struct xqc_moq_group_stream_obj_msg_s {
    xqc_moq_msg_base_t          msg_base;
    xqc_moq_stream_header_group_msg_t group_header;
    uint64_t                    object_id;
    uint64_t                    payload_len;
    uint64_t                    status;
    uint8_t                     *payload;
} xqc_moq_group_stream_obj_msg_t;

typedef struct xqc_moq_announce_msg_s {
    xqc_moq_msg_base_t          msg_base;
} xqc_moq_announce_msg_t;

typedef struct xqc_moq_announce_ok_msg_s {
    xqc_moq_msg_base_t          msg_base;
} xqc_moq_announce_ok_msg_t;

typedef struct xqc_moq_announce_error_msg_s {
    xqc_moq_msg_base_t          msg_base;
} xqc_moq_announce_error_msg_t;

typedef struct xqc_moq_unannounce_msg_s {
    xqc_moq_msg_base_t          msg_base;
} xqc_moq_unannounce_msg_t;

typedef struct xqc_moq_subscribe_update_msg_s {
    xqc_moq_msg_base_t          msg_base;
    uint64_t                    subscribe_id;
    uint64_t                    start_group_id;
    uint64_t                    start_object_id;
    uint64_t                    end_group_id;
    uint64_t                    end_object_id;
    uint64_t                    params_num;
    xqc_moq_message_parameter_t *params;
} xqc_moq_subscribe_update_msg_t;

typedef struct xqc_moq_unsubscribe_msg_s {
    xqc_moq_msg_base_t          msg_base;
} xqc_moq_unsubscribe_msg_t;

typedef struct xqc_moq_subscribe_done_msg_s {
    xqc_moq_msg_base_t          msg_base;
} xqc_moq_subscribe_done_msg_t;

typedef struct xqc_moq_goaway_msg_s {
    xqc_moq_msg_base_t          msg_base;
} xqc_moq_goaway_msg_t;

void *xqc_moq_msg_create(xqc_moq_msg_type_t type);

void xqc_moq_msg_free(xqc_moq_msg_type_t type, void *msg);

void xqc_moq_msg_set_object_by_object(xqc_moq_object_t *obj, xqc_moq_object_stream_msg_t *msg);

void xqc_moq_msg_set_object_by_track(xqc_moq_object_t *obj, xqc_moq_stream_header_track_msg_t *header,
    xqc_moq_track_stream_obj_msg_t *msg);

void xqc_moq_msg_set_object_by_group(xqc_moq_object_t *obj, xqc_moq_stream_header_group_msg_t *header,
    xqc_moq_group_stream_obj_msg_t *msg);

xqc_int_t xqc_moq_msg_decode_type(uint8_t *buf, size_t buf_len, xqc_moq_msg_type_t *type, xqc_int_t *wait_more_data);

void xqc_moq_decode_msg_ctx_reset(xqc_moq_decode_msg_ctx_t *ctx);

void xqc_moq_decode_params_ctx_reset(xqc_moq_decode_params_ctx_t *ctx);

xqc_moq_message_parameter_t *xqc_moq_msg_alloc_params(xqc_int_t params_num);

void xqc_moq_msg_free_params(xqc_moq_message_parameter_t *params, xqc_int_t params_num);

xqc_int_t xqc_moq_msg_encode_params_len(xqc_moq_message_parameter_t *params, xqc_int_t params_num);

xqc_int_t xqc_moq_msg_encode_params(xqc_moq_message_parameter_t *params, xqc_int_t params_num, uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_params(uint8_t *buf, size_t buf_len, xqc_moq_decode_params_ctx_t *ctx,
    xqc_moq_message_parameter_t *params, xqc_int_t params_num, xqc_int_t *finish, xqc_int_t *wait_more_data);

void *xqc_moq_msg_create_client_setup();

void xqc_moq_msg_free_client_setup(void *msg);

xqc_moq_msg_type_t xqc_moq_msg_client_setup_type();

void xqc_moq_msg_client_setup_init_handler(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_client_setup_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_client_setup(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_client_setup(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data);

void *xqc_moq_msg_create_server_setup();

void xqc_moq_msg_free_server_setup(void *msg);

xqc_moq_msg_type_t xqc_moq_msg_server_setup_type();

void xqc_moq_msg_server_setup_init_handler(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_server_setup_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_server_setup(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_server_setup(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data);

void *xqc_moq_msg_create_subscribe();

void xqc_moq_msg_free_subscribe(void *msg);

xqc_moq_msg_type_t xqc_moq_msg_subscribe_type();

void xqc_moq_msg_subscribe_init_handler(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_subscribe_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_subscribe(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_subscribe(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data);

void *xqc_moq_msg_create_subscribe_update();

void xqc_moq_msg_free_subscribe_update(void *msg);

xqc_moq_msg_type_t xqc_moq_msg_subscribe_update_type();

void xqc_moq_msg_subscribe_update_init_handler(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_subscribe_update_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_subscribe_update(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_subscribe_update(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data);

void *xqc_moq_msg_create_subscribe_ok();

void xqc_moq_msg_free_subscribe_ok(void *msg);

xqc_moq_msg_type_t xqc_moq_msg_subscribe_ok_type();

void xqc_moq_msg_subscribe_ok_init_handler(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_subscribe_ok_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_subscribe_ok(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_subscribe_ok(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data);

void *xqc_moq_msg_create_subscribe_error();

void xqc_moq_msg_free_subscribe_error(void *msg);

xqc_moq_msg_type_t xqc_moq_msg_subscribe_error_type();

void xqc_moq_msg_subscribe_error_init_handler(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_subscribe_error_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_subscribe_error(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_subscribe_error(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data);

void *xqc_moq_msg_create_object_stream();

void xqc_moq_msg_free_object_stream(void *msg);

xqc_moq_msg_type_t xqc_moq_msg_object_stream_type();

void xqc_moq_msg_object_stream_init_handler(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_object_stream_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_object_stream(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_object_stream(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data);

void *xqc_moq_msg_create_track_stream_obj();

void xqc_moq_msg_free_track_stream_obj(void *msg);

xqc_moq_msg_type_t xqc_moq_msg_track_stream_obj_type();

void xqc_moq_msg_track_stream_obj_init_handler(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_track_stream_obj_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_track_stream_obj(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_track_stream_obj(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data);

void *xqc_moq_msg_create_track_header();

void xqc_moq_msg_free_track_header(void *msg);

xqc_moq_msg_type_t xqc_moq_msg_track_header_type();

void xqc_moq_msg_track_header_init_handler(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_track_header_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_track_header(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_track_header(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data);

#endif /* _XQC_MOQ_MESSAGE_H_INCLUDED_ */
