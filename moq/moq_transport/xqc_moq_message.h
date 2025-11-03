#ifndef _XQC_MOQ_MESSAGE_H_INCLUDED_
#define _XQC_MOQ_MESSAGE_H_INCLUDED_

#include "moq/xqc_moq.h"
#include <stdint.h>

#define XQC_MOQ_MAX_PARAMS 10
#define XQC_MOQ_MAX_VERSIONS 10
#define XQC_MOQ_MAX_OBJECT_LEN (10 * 1024 * 1024)
#define XQC_MOQ_MAX_PARAM_VALUE_LEN 4096
#define XQC_MOQ_MAX_NAME_LEN 1024
#define XQC_MOQ_MAX_AUTH_LEN 1024
#define XQC_MOQ_GROUP_ORDER_SIZE 1
#define XQC_MOQ_CONTENT_EXISTS_SIZE 1
#define XQC_MOQ_FORWARD_SIZE 1
#define XQC_MOQ_PUB_PRIORITY_SIZE 1
#define XQC_MOQ_SUB_PRIORITY_SIZE 1
#define XQC_MOQ_MAX_REASON_LEN 1024
#define XQC_MOQ_MSG_LENGTH_FIXED_SIZE                                          \
  2 //  2 fixed bytes remained for message length, added in moq-12

typedef enum {
  XQC_MOQ_PARAM_ROLE = 0x00,
  XQC_MOQ_PARAM_PATH = 0x01,
  // former name is XQC_MOQ_PARAM_MAX_SUBSCRIBE_ID before moq-11
  // now we use XQC_MOQ_PARAM_MAX_REQUEST_ID in moq-11 and later
  XQC_MOQ_PARAM_MAX_REQUEST_ID = 0x02,
  XQC_MOQ_PARAM_AUTHORIZATION_TOKEN = 0x03,
  XQC_MOQ_PARAM_MAX_AUTH_TOKEN_CACHE_SIZE = 0x04,
  // XQC_MOQ_PARAM_EXTDATA = 0xA0,
  XQC_MOQ_PARAM_EXTDATA_v05 = 0xA0,
  XQC_MOQ_PARAM_EXTDATA_v11 = 0xA1,

} xqc_moq_param_type_t;

typedef enum {
  XQC_MOQ_STREAM_TYPE_CTL = 0,     // control stream
  XQC_MOQ_STREAM_TYPE_DATA = 1,    // data stream
  XQC_MOQ_STREAM_TYPE_UNKNOWN = 2, // unknown but usually error
} xqc_moq_stream_type_t;

typedef enum {
  XQC_MOQ_VERSION_SPE_PARAM_AUTH = 0x02,
  XQC_MOQ_VERSION_SPE_PARAM_DELIVERY_TIMEOUT = 0x03,
  XQC_MOQ_VERSION_SPE_PARAM_MAX_CACHE_DURATION = 0x04,
} xqc_moq_version_spe_param_type_t;

typedef enum {
  XQC_MOQ_DECODE_MSG_TYPE,
  XQC_MOQ_DECODE_MSG,
} xqc_moq_decode_state_t;

typedef struct xqc_moq_object_s {
  uint64_t subscribe_id;
  uint64_t track_alias;
  uint64_t group_id;
  uint64_t object_id;
  uint64_t send_order;
  uint64_t status;
  const uint8_t *extension_header;
  uint64_t extension_header_len;
  uint8_t *payload;
  uint64_t payload_len;
} xqc_moq_object_t;

typedef struct {
  xqc_int_t cur_param_idx; // Params[idx]
  xqc_int_t cur_field_idx; // 0:Type, 1:Length, 2:Value
  xqc_int_t value_processed;
} xqc_moq_decode_params_ctx_t;

typedef struct xqc_moq_decode_msg_ctx_s {
  xqc_moq_decode_state_t cur_decode_state;
  xqc_moq_msg_type_t cur_msg_type;
  void *cur_decode_msg;
  xqc_int_t cur_field_idx;
  xqc_int_t cur_array_idx;
  xqc_int_t payload_processed;
  xqc_int_t str_processed;
  xqc_moq_decode_params_ctx_t decode_params_ctx;
} xqc_moq_decode_msg_ctx_t;

typedef void (*xqc_moq_msg_init_handler_pt)(xqc_moq_msg_base_t *msg_base,
                                            xqc_moq_session_t *session);

typedef struct {
  xqc_int_t type;
  void *(*create)(xqc_moq_session_t *session);
  void (*free)(void *);
} xqc_moq_msg_ctl_stream_func_map_t;

typedef struct {
  xqc_int_t type;
  void *(*create)(xqc_moq_session_t *session);
  void (*free)(void *);
} xqc_moq_msg_data_stream_func_map_t;

typedef struct xqc_moq_client_setup_msg_s {
  xqc_moq_msg_base_t msg_base;
  uint64_t versions_num;
  uint64_t *versions;
  uint64_t params_num;
  xqc_moq_message_parameter_t *params;
} xqc_moq_client_setup_msg_t;

typedef struct xqc_moq_server_setup_msg_s {
  xqc_moq_msg_base_t msg_base;
  uint64_t version;
  uint64_t params_num;
  xqc_moq_message_parameter_t *params;
} xqc_moq_server_setup_msg_t;

typedef struct xqc_moq_object_stream_msg_s {
  xqc_moq_msg_base_t msg_base;
  uint64_t subscribe_id;
  uint64_t track_alias;
  uint64_t group_id;
  uint64_t object_id;
  uint64_t send_order;
  uint64_t status;
  uint8_t *payload;
  uint64_t payload_len;
} xqc_moq_object_stream_msg_t;

// typedef struct xqc_moq_object_datagram_msg_s {
//     xqc_moq_msg_base_t          msg_base;
// } xqc_moq_object_datagram_msg_t;

typedef struct xqc_moq_stream_header_track_msg_s {
  xqc_moq_msg_base_t msg_base;
  uint64_t subscribe_id;
  uint64_t track_alias;
  uint64_t send_order;
} xqc_moq_stream_header_track_msg_t;

typedef struct xqc_moq_track_stream_obj_msg_s {
  xqc_moq_msg_base_t msg_base;
  xqc_moq_stream_header_track_msg_t track_header;
  uint64_t group_id;
  uint64_t object_id;
  uint64_t payload_len;
  uint64_t status;
  uint8_t *payload;
} xqc_moq_track_stream_obj_msg_t;

typedef struct xqc_moq_stream_header_group_msg_s {
  xqc_moq_msg_base_t msg_base;
  uint64_t subscribe_id;
  uint64_t track_alias;
  uint64_t group_id;
  uint64_t send_order;
} xqc_moq_stream_header_group_msg_t;

typedef struct xqc_moq_group_stream_obj_msg_s {
  xqc_moq_msg_base_t msg_base;
  xqc_moq_stream_header_group_msg_t group_header;
  uint64_t object_id;
  uint64_t payload_len;
  uint64_t status;
  uint8_t *payload;
} xqc_moq_group_stream_obj_msg_t;

typedef enum {
  XQC_MOQ_TRACK_STATUS_CODE_IN_PROGRESS = 0x00,
  XQC_MOQ_TRACK_STATUS_CODE_NOT_EXIST = 0x01,
  XQC_MOQ_TRACK_STATUS_CODE_NOT_STARTED = 0x02,
  XQC_MOQ_TRACK_STATUS_CODE_FINISHED = 0x03,
  XQC_MOQ_TRACK_STATUS_CODE_RELAY = 0x04,
} XQC_MOQ_TRACK_STATUS_CODE;

typedef enum {
  XQC_MOQ_FETCH_TYPE_STANDALONE = 0x1,
  XQC_MOQ_FETCH_TYPE_JOINING = 0x2,
} xqc_moq_fetch_type_t;

typedef struct xqc_moq_fetch_range_s {
  xqc_moq_msg_track_namespace_t *track_namespace;
  uint64_t start_group_id;
  uint64_t start_object_id;
  uint64_t end_group_id;
  uint64_t end_object_id;
} xqc_moq_fetch_range_t;

typedef struct xqc_moq_fetch_joining_fetch_range_s {
  uint64_t joining_subscribe_id;
  uint64_t preceding_group_offset;
} xqc_moq_fetch_joining_fetch_range_t;

typedef struct xqc_moq_fetch_msg_s {
  xqc_moq_msg_base_t msg_base;
  uint64_t subscribe_id;
  uint64_t subscriber_priority;
  uint64_t group_order;
  xqc_moq_fetch_type_t fetch_type;
  xqc_moq_fetch_range_t *fetch_ranges; // only available for fetch_type ==
                                       // XQC_MOQ_FETCH_TYPE_STANDALONE
  xqc_moq_fetch_joining_fetch_range_t
      *fetch_joining_fetch_range; // only available for fetch_type ==
                                  // XQC_MOQ_FETCH_TYPE_JOINING
  uint64_t params_num;
  xqc_moq_message_parameter_t *params;
} xqc_moq_fetch_msg_t;


typedef struct xqc_moq_subscribe_update_msg_s_v05 {
  xqc_moq_msg_base_t msg_base;
  uint64_t subscribe_id;
  uint64_t start_group_id;
  uint64_t start_object_id;
  uint64_t end_group_id;
  uint64_t end_object_id;
  uint64_t params_num;
  xqc_moq_message_parameter_t *params;
} xqc_moq_subscribe_update_msg_t_v05;

typedef struct xqc_moq_subscribe_update_msg_s_v13{
  xqc_moq_msg_base_t msg_base;
  uint64_t subscribe_id;
  uint64_t start_group_id;
  uint64_t start_object_id;
  uint64_t end_group;
  uint8_t  subscriber_priority;
  uint8_t  forward;
  uint64_t params_num;
  xqc_moq_message_parameter_t *params;
} xqc_moq_subscribe_update_msg_t_v13;

typedef struct xqc_moq_unsubscribe_msg_s {
  xqc_moq_msg_base_t msg_base;
  uint64_t subscribe_id;
} xqc_moq_unsubscribe_msg_t;

typedef struct xqc_moq_subscribe_done_msg_s {
  xqc_moq_msg_base_t msg_base;
  uint64_t subscribe_id;
  xqc_moq_subscribe_done_status_t status_code;
  uint64_t stream_count;
  uint64_t reason_len;
  char *reason;
} xqc_moq_subscribe_done_msg_t;

typedef struct xqc_moq_goaway_msg_s {
  xqc_moq_msg_base_t msg_base;
  uint64_t new_URI_len;
  char *new_URI;
} xqc_moq_goaway_msg_t;

typedef struct xqc_moq_max_request_id_msg_s {
  xqc_moq_msg_base_t msg_base;
  uint64_t length;
  uint64_t max_request_id;
} xqc_moq_max_request_id_msg_t;

typedef struct xqc_moq_requests_blocked_msg_s {
  xqc_moq_msg_base_t msg_base;
  uint64_t length;
  uint64_t max_request_id;
} xqc_moq_requests_blocked_msg_t;

typedef struct xqc_moq_subscribe_namespace_ok_msg_s {
  xqc_moq_msg_base_t msg_base;
  uint64_t request_id;
} xqc_moq_subscribe_namespace_ok_msg_t;

void *xqc_moq_msg_create(xqc_moq_msg_type_t type,
                         xqc_moq_stream_type_t stream_type,
                         xqc_moq_session_t *session);

void xqc_moq_msg_free(xqc_moq_msg_type_t type, void *msg);

void xqc_moq_msg_free_data_stream(xqc_moq_msg_type_t type, void *msg);

void xqc_moq_msg_free_track_namespace(xqc_moq_msg_track_namespace_t *namespace);

xqc_int_t
xqc_moq_msg_encode_track_namespace(xqc_moq_msg_track_namespace_t *namespace,
                                   uint8_t *buf, size_t buf_len);

xqc_int_t xqc_moq_msg_encode_track_namespace_len(
    xqc_moq_msg_track_namespace_t *namespace);

xqc_int_t xqc_moq_msg_decode_track_namespace(uint8_t *buf, size_t buf_len,
    xqc_moq_decode_params_ctx_t *params_ctx, xqc_moq_msg_track_namespace_t *ns,
    xqc_int_t *finish, xqc_int_t *wait_more_data);

void xqc_moq_msg_set_object_by_object(xqc_moq_object_t *obj,
                                      xqc_moq_object_stream_msg_t *msg);

void xqc_moq_msg_set_object_by_subgroup_object(
    xqc_moq_object_t *obj, xqc_moq_subgroup_object_msg_t *msg);

void xqc_moq_msg_set_object_by_track(xqc_moq_object_t *obj,
                                     xqc_moq_stream_header_track_msg_t *header,
                                     xqc_moq_track_stream_obj_msg_t *msg);

void xqc_moq_msg_set_object_by_group(xqc_moq_object_t *obj,
                                     xqc_moq_stream_header_group_msg_t *header,
                                     xqc_moq_group_stream_obj_msg_t *msg);

xqc_int_t xqc_moq_msg_decode_type(uint8_t *buf, size_t buf_len,
                                  xqc_moq_msg_type_t *type,
                                  xqc_int_t *wait_more_data);

void xqc_moq_decode_msg_ctx_reset(xqc_moq_decode_msg_ctx_t *ctx);

void xqc_moq_decode_params_ctx_reset(xqc_moq_decode_params_ctx_t *ctx);

xqc_moq_message_parameter_t *xqc_moq_msg_alloc_params(xqc_int_t params_num);

void xqc_moq_msg_free_params(xqc_moq_message_parameter_t *params,
                             xqc_int_t params_num);

xqc_int_t xqc_moq_msg_encode_params_len(xqc_moq_message_parameter_t *params,
                                        xqc_int_t params_num);

xqc_int_t xqc_moq_msg_encode_params(xqc_moq_message_parameter_t *params,
                                    xqc_int_t params_num, uint8_t *buf,
                                    size_t buf_cap);

xqc_int_t xqc_moq_msg_encode_params_v11(xqc_moq_message_parameter_t *params,
                                    xqc_int_t params_num, uint8_t *buf,
                                    size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_params(uint8_t *buf, size_t buf_len,
                                    xqc_moq_decode_params_ctx_t *ctx,
                                    xqc_moq_message_parameter_t *params,
                                    xqc_int_t params_num, xqc_int_t *finish,
                                    xqc_int_t *wait_more_data);

void *xqc_moq_msg_create_client_setup(xqc_moq_session_t *session);

void xqc_moq_msg_free_client_setup(void *msg);

xqc_int_t xqc_moq_msg_client_setup_type();

void xqc_moq_msg_client_setup_init_handler(xqc_moq_msg_base_t *msg_base,
                                           xqc_moq_session_t *session);

xqc_int_t xqc_moq_msg_encode_client_setup_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_client_setup(xqc_moq_msg_base_t *msg_base,
                                          uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_client_setup(uint8_t *buf, size_t buf_len,
                                          uint8_t stream_fin,
                                          xqc_moq_decode_msg_ctx_t *msg_ctx,
                                          xqc_moq_msg_base_t *msg_base,
                                          xqc_int_t *finish,
                                          xqc_int_t *wait_more_data);

xqc_int_t xqc_moq_msg_encode_client_setup_len_v05(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_client_setup_v05(xqc_moq_msg_base_t *msg_base,
                                              uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_client_setup_v05(uint8_t *buf, size_t buf_len,
                                              uint8_t stream_fin,
                                              xqc_moq_decode_msg_ctx_t *msg_ctx,
                                              xqc_moq_msg_base_t *msg_base,
                                              xqc_int_t *finish,
                                              xqc_int_t *wait_more_data);

void *xqc_moq_msg_create_server_setup(xqc_moq_session_t *session);

void xqc_moq_msg_free_server_setup(void *msg);

xqc_int_t xqc_moq_msg_server_setup_type();

void xqc_moq_msg_server_setup_init_handler(xqc_moq_msg_base_t *msg_base,
                                           xqc_moq_session_t *session);

xqc_int_t xqc_moq_msg_encode_server_setup_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_server_setup(xqc_moq_msg_base_t *msg_base,
                                          uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_server_setup(uint8_t *buf, size_t buf_len,
                                          uint8_t stream_fin,
                                          xqc_moq_decode_msg_ctx_t *msg_ctx,
                                          xqc_moq_msg_base_t *msg_base,
                                          xqc_int_t *finish,
                                          xqc_int_t *wait_more_data);

// void *xqc_moq_msg_create_subscribe(xqc_moq_session_t *session);

void *xqc_moq_msg_create_subscribe_v05(xqc_moq_session_t *session);

void *xqc_moq_msg_create_subscribe_v13(xqc_moq_session_t *session);

void xqc_moq_msg_free_subscribe(void *msg);

void xqc_moq_msg_free_subscribe_v05(void *msg);

void xqc_moq_msg_free_subscribe_v13(void *msg);

xqc_int_t xqc_moq_msg_subscribe_type();

void xqc_moq_msg_subscribe_init_handler(xqc_moq_msg_base_t *msg_base,
                                        xqc_moq_session_t *session);

xqc_int_t xqc_moq_msg_encode_subscribe_len_v13(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_subscribe_v13(xqc_moq_msg_base_t *msg_base,
                                       uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_subscribe_v13(uint8_t *buf, size_t buf_len,
                                       uint8_t stream_fin,
                                       xqc_moq_decode_msg_ctx_t *msg_ctx,
                                       xqc_moq_msg_base_t *msg_base,
                                       xqc_int_t *finish,
                                       xqc_int_t *wait_more_data);

xqc_int_t xqc_moq_msg_encode_subscribe_len_v05(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_subscribe_v05(xqc_moq_msg_base_t *msg_base,
                                           uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_subscribe_v05(uint8_t *buf, size_t buf_len,
                                           uint8_t stream_fin,
                                           xqc_moq_decode_msg_ctx_t *msg_ctx,
                                           xqc_moq_msg_base_t *msg_base,
                                           xqc_int_t *finish,
                                           xqc_int_t *wait_more_data);

void *xqc_moq_msg_create_subscribe_update_v05(xqc_moq_session_t *session);

void *xqc_moq_msg_create_subscribe_update_v13(xqc_moq_session_t *session);

void xqc_moq_msg_free_subscribe_update_v05(void *msg);

void xqc_moq_msg_free_subscribe_update_v13(void *msg);

xqc_int_t xqc_moq_msg_subscribe_update_type();

void xqc_moq_msg_subscribe_update_init_handler(xqc_moq_msg_base_t *msg_base,
                                               xqc_moq_session_t *session);

xqc_int_t xqc_moq_msg_encode_subscribe_update_len_v05(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_subscribe_update_len_v13(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_subscribe_update_v05(xqc_moq_msg_base_t *msg_base,
                                              uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_encode_subscribe_update_v13(xqc_moq_msg_base_t *msg_base,
                                              uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_subscribe_update_v05(uint8_t *buf, size_t buf_len,
                                              uint8_t stream_fin,
                                              xqc_moq_decode_msg_ctx_t *msg_ctx,
                                              xqc_moq_msg_base_t *msg_base,
                                              xqc_int_t *finish,
                                              xqc_int_t *wait_more_data);

xqc_int_t xqc_moq_msg_decode_subscribe_update_v13(uint8_t *buf, size_t buf_len,
                                              uint8_t stream_fin,
                                              xqc_moq_decode_msg_ctx_t *msg_ctx,
                                              xqc_moq_msg_base_t *msg_base,
                                              xqc_int_t *finish,
                                              xqc_int_t *wait_more_data);

void *xqc_moq_msg_create_subscribe_ok(xqc_moq_session_t *session);

void xqc_moq_msg_free_subscribe_ok(void *msg);

xqc_int_t xqc_moq_msg_subscribe_ok_type();

void xqc_moq_msg_subscribe_ok_init_handler(xqc_moq_msg_base_t *msg_base,
                                           xqc_moq_session_t *session);

xqc_int_t xqc_moq_msg_encode_subscribe_ok_len_v11(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_subscribe_ok_v11(xqc_moq_msg_base_t *msg_base,
                                          uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_subscribe_ok_v11(uint8_t *buf, size_t buf_len,
                                          uint8_t stream_fin,
                                          xqc_moq_decode_msg_ctx_t *msg_ctx,
                                          xqc_moq_msg_base_t *msg_base,
                                          xqc_int_t *finish,
                                          xqc_int_t *wait_more_data);

xqc_int_t xqc_moq_msg_encode_subscribe_ok_len_v05(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_subscribe_ok_v05(xqc_moq_msg_base_t *msg_base,
                                              uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_subscribe_ok_v05(uint8_t *buf, size_t buf_len,
                                              uint8_t stream_fin,
                                              xqc_moq_decode_msg_ctx_t *msg_ctx,
                                              xqc_moq_msg_base_t *msg_base,
                                              xqc_int_t *finish,
                                              xqc_int_t *wait_more_data);

void *xqc_moq_msg_create_subscribe_error(xqc_moq_session_t *session);

void xqc_moq_msg_free_subscribe_error(void *msg);

xqc_int_t xqc_moq_msg_subscribe_error_type();

void xqc_moq_msg_subscribe_error_init_handler(xqc_moq_msg_base_t *msg_base,
                                              xqc_moq_session_t *session);

xqc_int_t xqc_moq_msg_encode_subscribe_error_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_subscribe_error(xqc_moq_msg_base_t *msg_base,
                                             uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_subscribe_error(uint8_t *buf, size_t buf_len,
                                             uint8_t stream_fin,
                                             xqc_moq_decode_msg_ctx_t *msg_ctx,
                                             xqc_moq_msg_base_t *msg_base,
                                             xqc_int_t *finish,
                                             xqc_int_t *wait_more_data);

/* PUBLISH Message */
void *xqc_moq_msg_create_publish(xqc_moq_session_t *session);

void xqc_moq_msg_free_publish(void *msg);

xqc_int_t xqc_moq_msg_publish_type();

void xqc_moq_msg_publish_init_handler(xqc_moq_msg_base_t *msg_base,
                                      xqc_moq_session_t *session);

xqc_int_t xqc_moq_msg_encode_publish_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_publish(xqc_moq_msg_base_t *msg_base,
                                     uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_publish(uint8_t *buf, size_t buf_len,
                                     uint8_t stream_fin,
                                     xqc_moq_decode_msg_ctx_t *msg_ctx,
                                     xqc_moq_msg_base_t *msg_base,
                                     xqc_int_t *finish,
                                     xqc_int_t *wait_more_data);

/* PUBLISH_OK Message */
void *xqc_moq_msg_create_publish_ok(xqc_moq_session_t *session);

void xqc_moq_msg_free_publish_ok(void *msg);

xqc_int_t xqc_moq_msg_publish_ok_type();

void xqc_moq_msg_publish_ok_init_handler(xqc_moq_msg_base_t *msg_base,
                                         xqc_moq_session_t *session);

xqc_int_t xqc_moq_msg_encode_publish_ok_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_publish_ok(xqc_moq_msg_base_t *msg_base,
                                        uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_publish_ok(uint8_t *buf, size_t buf_len,
                                        uint8_t stream_fin,
                                        xqc_moq_decode_msg_ctx_t *msg_ctx,
                                        xqc_moq_msg_base_t *msg_base,
                                        xqc_int_t *finish,
                                        xqc_int_t *wait_more_data);

/* PUBLISH_ERROR Message */
void *xqc_moq_msg_create_publish_error(xqc_moq_session_t *session);

void xqc_moq_msg_free_publish_error(void *msg);

xqc_int_t xqc_moq_msg_publish_error_type();

void xqc_moq_msg_publish_error_init_handler(xqc_moq_msg_base_t *msg_base,
                                            xqc_moq_session_t *session);

xqc_int_t xqc_moq_msg_encode_publish_error_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_publish_error(xqc_moq_msg_base_t *msg_base,
                                           uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_publish_error(uint8_t *buf, size_t buf_len,
                                           uint8_t stream_fin,
                                           xqc_moq_decode_msg_ctx_t *msg_ctx,
                                           xqc_moq_msg_base_t *msg_base,
                                           xqc_int_t *finish,
                                           xqc_int_t *wait_more_data);

void *xqc_moq_msg_create_object_stream(xqc_moq_session_t *session);

void xqc_moq_msg_free_object_stream(void *msg);

xqc_int_t xqc_moq_msg_object_stream_type();

void xqc_moq_msg_object_stream_init_handler(xqc_moq_msg_base_t *msg_base,
                                            xqc_moq_session_t *session);

xqc_int_t xqc_moq_msg_encode_object_stream_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_object_stream(xqc_moq_msg_base_t *msg_base,
                                           uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_object_stream(uint8_t *buf, size_t buf_len,
                                           uint8_t stream_fin,
                                           xqc_moq_decode_msg_ctx_t *msg_ctx,
                                           xqc_moq_msg_base_t *msg_base,
                                           xqc_int_t *finish,
                                           xqc_int_t *wait_more_data);

void *xqc_moq_msg_create_track_stream_obj(xqc_moq_session_t *session);

void xqc_moq_msg_free_track_stream_obj(void *msg);

xqc_int_t xqc_moq_msg_track_stream_obj_type();

void xqc_moq_msg_track_stream_obj_init_handler(xqc_moq_msg_base_t *msg_base,
                                               xqc_moq_session_t *session);

xqc_int_t xqc_moq_msg_encode_track_stream_obj_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_track_stream_obj(xqc_moq_msg_base_t *msg_base,
                                              uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_track_stream_obj(uint8_t *buf, size_t buf_len,
                                              uint8_t stream_fin,
                                              xqc_moq_decode_msg_ctx_t *msg_ctx,
                                              xqc_moq_msg_base_t *msg_base,
                                              xqc_int_t *finish,
                                              xqc_int_t *wait_more_data);

void *xqc_moq_msg_create_track_header(xqc_moq_session_t *session);

void xqc_moq_msg_free_track_header(void *msg);

xqc_int_t xqc_moq_msg_track_header_type();

void xqc_moq_msg_track_header_init_handler(xqc_moq_msg_base_t *msg_base,
                                           xqc_moq_session_t *session);

xqc_int_t xqc_moq_msg_encode_track_header_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_track_header(xqc_moq_msg_base_t *msg_base,
                                          uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_track_header(uint8_t *buf, size_t buf_len,
                                          uint8_t stream_fin,
                                          xqc_moq_decode_msg_ctx_t *msg_ctx,
                                          xqc_moq_msg_base_t *msg_base,
                                          xqc_int_t *finish,
                                          xqc_int_t *wait_more_data);

/* PUBLISH_NAMESPACE prototypes */
void *xqc_moq_msg_create_publish_namespace(xqc_moq_session_t *session);
void xqc_moq_msg_free_publish_namespace(void *msg);
int xqc_moq_msg_publish_namespace_type();
void xqc_moq_msg_publish_namespace_init_handler(xqc_moq_msg_base_t *msg_base,
                                               xqc_moq_session_t *session);
int xqc_moq_msg_encode_publish_namespace_len(xqc_moq_msg_base_t *msg_base);
int xqc_moq_msg_encode_publish_namespace(xqc_moq_msg_base_t *msg_base,
                                        uint8_t *buf, size_t buf_cap);
int xqc_moq_msg_decode_publish_namespace(uint8_t *buf, size_t buf_len,
                                        uint8_t stream_fin,
                                        xqc_moq_decode_msg_ctx_t *msg_ctx,
                                        xqc_moq_msg_base_t *msg_base,
                                        xqc_int_t *finish, xqc_int_t *wait_more_data);

void *xqc_moq_msg_create_publish_namespace_done(xqc_moq_session_t *session);
void xqc_moq_msg_free_publish_namespace_done(void *msg);
int xqc_moq_msg_publish_namespace_done_type();
void xqc_moq_msg_publish_namespace_done_init_handler(xqc_moq_msg_base_t *msg_base,
                                                    xqc_moq_session_t *session);
int xqc_moq_msg_encode_publish_namespace_done_len(xqc_moq_msg_base_t *msg_base);
int xqc_moq_msg_encode_publish_namespace_done(xqc_moq_msg_base_t *msg_base,
                                             uint8_t *buf, size_t buf_cap);
int xqc_moq_msg_decode_publish_namespace_done(uint8_t *buf, size_t buf_len,
                                             uint8_t stream_fin,
                                             xqc_moq_decode_msg_ctx_t *msg_ctx,
                                             xqc_moq_msg_base_t *msg_base,
                                             xqc_int_t *finish, xqc_int_t *wait_more_data);

xqc_int_t xqc_moq_msg_max_request_id_type();

void *xqc_moq_msg_create_max_request_id(xqc_moq_session_t *session);

void xqc_moq_msg_free_max_request_id(void *msg);

void xqc_moq_msg_max_request_id_init_handler(xqc_moq_msg_base_t *msg_base,
                                             xqc_moq_session_t *session);

xqc_int_t xqc_moq_msg_encode_max_request_id_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_max_request_id(xqc_moq_msg_base_t *msg_base,
                                            uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_max_request_id(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data);

void *xqc_moq_msg_create_requests_blocked(xqc_moq_session_t *session);

void xqc_moq_msg_free_requests_blocked(void *msg);

xqc_int_t xqc_moq_msg_requests_blocked_type();

void xqc_moq_msg_requests_blocked_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session);

xqc_int_t xqc_moq_msg_encode_requests_blocked_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_requests_blocked(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_requests_blocked(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data);

void xqc_moq_on_requests_blocked(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base);

uint8_t *xqc_moq_put_varint_length(uint8_t *buf, size_t length);

xqc_int_t xqc_moq_msg_subgroup_type();

xqc_int_t xqc_moq_msg_subgroup_object_type();

// helper function for SUBGROUP_HEADER type
xqc_bool_t xqc_moq_subgroup_has_subgroup_id_field(uint64_t type);
xqc_bool_t xqc_moq_subgroup_has_extensions(uint64_t type);
xqc_bool_t xqc_moq_subgroup_has_end_of_group(uint64_t type);
uint64_t xqc_moq_subgroup_get_subgroup_id(uint64_t type, uint64_t first_object_id);
xqc_bool_t xqc_moq_subgroup_is_valid_type(uint64_t type);

/**
 *  Recommend the SUBGROUP_HEADER type based on the needs
 * @param need_extensions 0 without extensions, 1 with extensions
 * @param need_end_of_group 0 without end of group, 1 with end of group
 * @param need_explicit_subgroup_id 0 without explicit subgroup id, 1 with explicit subgroup id
 * @return recommended SUBGROUP_HEADER type
 */
uint64_t xqc_moq_subgroup_recommend_type(xqc_bool_t need_extensions, 
                                         xqc_bool_t need_end_of_group, 
                                         xqc_bool_t need_explicit_subgroup_id);

void xqc_moq_msg_subgroup_init_handler(xqc_moq_msg_base_t *msg_base,
                                       xqc_moq_session_t *session);

void xqc_moq_msg_subgroup_object_init_handler(xqc_moq_msg_base_t *msg_base,
                                              xqc_moq_session_t *session);

xqc_int_t xqc_moq_msg_encode_subgroup_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_subgroup(xqc_moq_msg_base_t *msg_base,
                                      uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_encode_subgroup_object_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_subgroup_object(xqc_moq_msg_base_t *msg_base,
                                             uint8_t *buf, size_t buf_cap);

void *xqc_moq_msg_create_announce(xqc_moq_session_t *session);

void xqc_moq_msg_free_announce(void *msg);

xqc_int_t xqc_moq_msg_announce_type();

void xqc_moq_msg_announce_init_handler(xqc_moq_msg_base_t *msg_base,
                                       xqc_moq_session_t *session);

xqc_int_t xqc_moq_msg_encode_announce_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_announce(xqc_moq_msg_base_t *msg_base,
                                      uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_announce_ok_type();

void xqc_moq_msg_announce_ok_init_handler(xqc_moq_msg_base_t *msg_base,
                                          xqc_moq_session_t *session);

xqc_int_t xqc_moq_msg_encode_announce_ok_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_announce_ok(xqc_moq_msg_base_t *msg_base,
                                         uint8_t *buf, size_t buf_cap);

void *xqc_moq_msg_create_announce_ok(xqc_moq_session_t *session);

xqc_int_t xqc_moq_msg_decode_announce_ok(uint8_t *buf, size_t buf_len,
                                         uint8_t stream_fin,
                                         xqc_moq_decode_msg_ctx_t *msg_ctx,
                                         xqc_moq_msg_base_t *msg_base,
                                         xqc_int_t *finish,
                                         xqc_int_t *wait_more_data);

void xqc_moq_on_announce_ok(xqc_moq_session_t *session,
                            xqc_moq_stream_t *moq_stream,
                            xqc_moq_msg_base_t *msg_base);

void xqc_moq_msg_free_announce_ok(void *msg);

void *xqc_moq_msg_create_announce_error(xqc_moq_session_t *session);

void xqc_moq_msg_free_announce_error(void *msg);

void xqc_moq_msg_announce_error_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session);

xqc_int_t xqc_moq_msg_encode_announce_error_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_announce_error(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_announce_error(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, 
    xqc_int_t *wait_more_data);

void xqc_moq_on_announce_error(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream,
    xqc_moq_msg_base_t *msg_base);

void *xqc_moq_msg_create_unsubscribe(xqc_moq_session_t *session);

xqc_int_t xqc_moq_msg_unsubscribe_type();

void xqc_moq_msg_unsubscribe_init_handler(xqc_moq_msg_base_t *msg_base,
                                          xqc_moq_session_t *session);

xqc_int_t xqc_moq_msg_decode_unsubscribe(uint8_t *buf, size_t buf_len,
                                         uint8_t stream_fin,
                                         xqc_moq_decode_msg_ctx_t *msg_ctx,
                                         xqc_moq_msg_base_t *msg_base,
                                         xqc_int_t *finish,
                                         xqc_int_t *wait_more_data);

xqc_int_t xqc_moq_msg_encode_unsubscribe_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_unsubscribe(xqc_moq_msg_base_t *msg_base,
                                         uint8_t *buf, size_t buf_cap);

void xqc_moq_on_unsubscribe(xqc_moq_session_t *session,
                            xqc_moq_stream_t *moq_stream,
                            xqc_moq_msg_base_t *msg_base);

void xqc_moq_msg_free_unsubscribe(void *msg);

void *xqc_moq_msg_create_subgroup(xqc_moq_session_t *session);

void xqc_moq_msg_free_subgroup(void *msg);

void *xqc_moq_msg_create_subgroup_object(xqc_moq_session_t *session);

void xqc_moq_msg_free_subgroup_object(void *msg);

void *xqc_moq_msg_create_subgroup_object_ext(xqc_moq_session_t *session);

void xqc_moq_msg_free_subgroup_object_ext(void *msg);

xqc_int_t xqc_moq_msg_decode_subgroup(uint8_t *buf, size_t buf_len,
                                      uint8_t stream_fin,
                                      xqc_moq_decode_msg_ctx_t *msg_ctx,
                                      xqc_moq_msg_base_t *msg_base,
                                      xqc_int_t *finish,
                                      xqc_int_t *wait_more_data);

xqc_int_t xqc_moq_msg_decode_subgroup_object(uint8_t *buf, size_t buf_len,
                                             uint8_t stream_fin,
                                             xqc_moq_decode_msg_ctx_t *msg_ctx,
                                             xqc_moq_msg_base_t *msg_base,
                                             xqc_int_t *finish,
                                             xqc_int_t *wait_more_data);

void xqc_moq_msg_fetch_init_handler(xqc_moq_msg_base_t *msg_base,
                                    xqc_moq_session_t *session);

xqc_int_t xqc_moq_msg_fetch_type();

xqc_int_t xqc_moq_msg_encode_fetch_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_fetch(xqc_moq_msg_base_t *msg_base, uint8_t *buf,
                                   size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_fetch(uint8_t *buf, size_t buf_len,
                                   uint8_t stream_fin,
                                   xqc_moq_decode_msg_ctx_t *msg_ctx,
                                   xqc_moq_msg_base_t *msg_base,
                                   xqc_int_t *finish,
                                   xqc_int_t *wait_more_data);

void xqc_moq_msg_free_fetch(void *msg);

xqc_int_t xqc_moq_msg_decode_announce(uint8_t *buf, size_t buf_len,
                                      uint8_t stream_fin,
                                      xqc_moq_decode_msg_ctx_t *msg_ctx,
                                      xqc_moq_msg_base_t *msg_base,
                                      xqc_int_t *finish,
                                      xqc_int_t *wait_more_data);

void xqc_moq_msg_subscribe_done_init_handler(xqc_moq_msg_base_t *msg_base,
                                             xqc_moq_session_t *session);

xqc_int_t xqc_moq_msg_subscribe_done_type();

xqc_int_t xqc_moq_msg_encode_subscribe_done_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_subscribe_done(xqc_moq_msg_base_t *msg_base,
                                            uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_subscribe_done(uint8_t *buf, size_t buf_len,
                                            uint8_t stream_fin,
                                            xqc_moq_decode_msg_ctx_t *msg_ctx,
                                            xqc_moq_msg_base_t *msg_base,
                                            xqc_int_t *finish,
                                            xqc_int_t *wait_more_data);

void *xqc_moq_msg_create_subscribe_done(xqc_moq_session_t *session);

void xqc_moq_msg_free_subscribe_done(void *msg);

xqc_int_t xqc_moq_msg_track_status_request_type();

void xqc_moq_msg_track_status_request_init_handler(xqc_moq_msg_base_t *msg_base,
                                                   xqc_moq_session_t *session);

xqc_int_t
xqc_moq_msg_encode_track_status_request_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_track_status_request(xqc_moq_msg_base_t *msg_base,
                                                  uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_track_status_request(
    uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base,
    xqc_int_t *finish, xqc_int_t *wait_more_data);

void xqc_moq_on_track_status_request(xqc_moq_session_t *session,
                                     xqc_moq_stream_t *moq_stream,
                                     xqc_moq_msg_base_t *msg_base);

void xqc_moq_msg_free_track_status_request(void *msg);

void xqc_moq_msg_free_track_status(void *msg);

void *xqc_moq_msg_create_track_status(xqc_moq_session_t *session);
void *xqc_moq_msg_create_track_status_ok(xqc_moq_session_t *session);
void *xqc_moq_msg_create_track_status_error(xqc_moq_session_t *session);

void xqc_moq_msg_track_status_init_handler(xqc_moq_msg_base_t *msg_base,
                                           xqc_moq_session_t *session);

xqc_int_t xqc_moq_msg_encode_track_status_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_track_status(xqc_moq_msg_base_t *msg_base,
                                          uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_track_status(uint8_t *buf, size_t buf_len,
                                          uint8_t stream_fin,
                                          xqc_moq_decode_msg_ctx_t *msg_ctx,
                                          xqc_moq_msg_base_t *msg_base,
                                          xqc_int_t *finish,
                                          xqc_int_t *wait_more_data);

void xqc_moq_on_track_status(xqc_moq_session_t *session,
                             xqc_moq_stream_t *moq_stream,
                             xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_track_status_type();
xqc_int_t xqc_moq_msg_track_status_ok_type();
xqc_int_t xqc_moq_msg_track_status_error_type();

void xqc_moq_msg_track_status_ok_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session);
void xqc_moq_msg_track_status_error_init_handler(xqc_moq_msg_base_t *msg_base, xqc_moq_session_t *session);

xqc_int_t xqc_moq_msg_encode_track_status_ok_len(xqc_moq_msg_base_t *msg_base);
xqc_int_t xqc_moq_msg_encode_track_status_ok(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap);
xqc_int_t xqc_moq_msg_decode_track_status_ok(uint8_t *buf, size_t buf_len, uint8_t stream_fin, 
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data);

xqc_int_t xqc_moq_msg_encode_track_status_error_len(xqc_moq_msg_base_t *msg_base);
xqc_int_t xqc_moq_msg_encode_track_status_error(xqc_moq_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap);
xqc_int_t xqc_moq_msg_decode_track_status_error(uint8_t *buf, size_t buf_len, uint8_t stream_fin, 
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base, xqc_int_t *finish, xqc_int_t *wait_more_data);

void xqc_moq_on_track_status_ok(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base);
void xqc_moq_on_track_status_error(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream, xqc_moq_msg_base_t *msg_base);

void xqc_moq_msg_free_track_status_ok(void *msg);
void xqc_moq_msg_free_track_status_error(void *msg);

void xqc_moq_msg_goaway_init_handler(xqc_moq_msg_base_t *msg_base,
                                     xqc_moq_session_t *session);

void *xqc_moq_msg_create_goaway(xqc_moq_session_t *session);

void xqc_moq_msg_free_goaway(void *msg);

xqc_int_t xqc_moq_msg_goaway_type();

xqc_int_t xqc_moq_msg_encode_goaway_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_goaway(xqc_moq_msg_base_t *msg_base, uint8_t *buf,
                                    size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_goaway(uint8_t *buf, size_t buf_len,
                                    uint8_t stream_fin,
                                    xqc_moq_decode_msg_ctx_t *msg_ctx,
                                    xqc_moq_msg_base_t *msg_base,
                                    xqc_int_t *finish,
                                    xqc_int_t *wait_more_data);

void xqc_moq_on_goaway(xqc_moq_session_t *session, xqc_moq_stream_t *moq_stream,
                       xqc_moq_msg_base_t *msg_base);

void *xqc_moq_msg_create_fetch(xqc_moq_session_t *session);

void xqc_moq_msg_fetch_init_handler(xqc_moq_msg_base_t *msg_base,
                                    xqc_moq_session_t *session);

xqc_int_t xqc_moq_msg_fetch_type();

xqc_int_t xqc_moq_msg_encode_fetch_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_fetch(xqc_moq_msg_base_t *msg_base, uint8_t *buf,
                                   size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_fetch(uint8_t *buf, size_t buf_len,
                                   uint8_t stream_fin,
                                   xqc_moq_decode_msg_ctx_t *msg_ctx,
                                   xqc_moq_msg_base_t *msg_base,
                                   xqc_int_t *finish,
                                   xqc_int_t *wait_more_data);

void xqc_moq_msg_free_fetch(void *msg);

void *xqc_moq_msg_create_subscribe_namespace(xqc_moq_session_t *session);

void xqc_moq_msg_subscribe_namespace_init_handler(xqc_moq_msg_base_t *msg_base,
                                                  xqc_moq_session_t *session);

xqc_int_t xqc_moq_msg_subscribe_namespace_type();

xqc_int_t
xqc_moq_msg_encode_subscribe_namespace_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_subscribe_namespace(xqc_moq_msg_base_t *msg_base,
                                                 uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_subscribe_namespace(
    uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base,
    xqc_int_t *finish, xqc_int_t *wait_more_data);

void xqc_moq_msg_free_subscribe_namespace(void *msg);

void *xqc_moq_msg_create_subscribe_namespace_ok(xqc_moq_session_t *session);

void xqc_moq_msg_subscribe_namespace_ok_init_handler(xqc_moq_msg_base_t *msg_base,
                                                    xqc_moq_session_t *session);

xqc_int_t xqc_moq_msg_subscribe_namespace_ok_type();

xqc_int_t
xqc_moq_msg_encode_subscribe_namespace_ok_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_subscribe_namespace_ok(xqc_moq_msg_base_t *msg_base,
                                                   uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_subscribe_namespace_ok(
    uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base,
    xqc_int_t *finish, xqc_int_t *wait_more_data);

void xqc_moq_on_subscribe_namespace_ok(xqc_moq_session_t *session,
                                      xqc_moq_stream_t *moq_stream,
                                      xqc_moq_msg_base_t *msg_base);

void xqc_moq_msg_free_subscribe_namespace_ok(void *msg);

xqc_int_t xqc_moq_msg_subgroup_object_ext_type();

xqc_int_t
xqc_moq_msg_encode_subgroup_object_ext_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_subgroup_object_ext(xqc_moq_msg_base_t *msg_base,
                                                 uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_subgroup_object_ext(
    uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base,
    xqc_int_t *finish, xqc_int_t *wait_more_data);

/* init handler for subgroup_object_ext */
void xqc_moq_msg_subgroup_object_ext_init_handler(xqc_moq_msg_base_t *msg_base,
                                                  xqc_moq_session_t *session);

void xqc_moq_msg_unsubscribe_namespace_init_handler(xqc_moq_msg_base_t *msg_base,
                                                    xqc_moq_session_t *session);
                                                    
xqc_int_t xqc_moq_msg_unsubscribe_namespace_type();

xqc_int_t xqc_moq_msg_encode_unsubscribe_namespace_len(xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_msg_encode_unsubscribe_namespace(xqc_moq_msg_base_t *msg_base,
                                                   uint8_t *buf, size_t buf_cap);

xqc_int_t xqc_moq_msg_decode_unsubscribe_namespace(uint8_t *buf, size_t buf_len, uint8_t stream_fin,
    xqc_moq_decode_msg_ctx_t *msg_ctx, xqc_moq_msg_base_t *msg_base,
    xqc_int_t *finish, xqc_int_t *wait_more_data);

void xqc_moq_msg_free_unsubscribe_namespace(void *msg);

void xqc_moq_on_unsubscribe_namespace(xqc_moq_session_t *session,
                                      xqc_moq_stream_t *moq_stream,
                                      xqc_moq_msg_base_t *msg_base);

#endif /* _XQC_MOQ_MESSAGE_H_INCLUDED_ */
