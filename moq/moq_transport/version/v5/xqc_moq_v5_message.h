#ifndef _XQC_MOQ_V5_MESSAGE_H_INCLUDED_
#define _XQC_MOQ_V5_MESSAGE_H_INCLUDED_

#include "moq/moq_transport/xqc_moq_message.h"

typedef xqc_moq_msg_type_t xqc_moq_v5_msg_type_t;
typedef xqc_moq_msg_base_t xqc_moq_v5_msg_base_t;

enum {
    XQC_MOQ_V5_MSG_ANNOUNCE        = 0x06,
    XQC_MOQ_V5_MSG_ANNOUNCE_OK     = 0x07,
    XQC_MOQ_V5_MSG_ANNOUNCE_ERROR  = 0x08,
    XQC_MOQ_V5_MSG_UNANNOUNCE      = 0x09,
    XQC_MOQ_V5_MSG_SUBSCRIBE_DONE  = 0x0b,
    XQC_MOQ_V5_MSG_ANNOUNCE_CANCEL = 0x0c,
};

typedef struct {
    xqc_moq_v5_msg_base_t       msg_base;
    char                        *track_namespace;
    size_t                      track_namespace_len;
    uint64_t                    params_num;
    xqc_moq_message_parameter_t *params;
} xqc_moq_v5_announce_msg_t;

typedef struct {
    xqc_moq_v5_msg_base_t       msg_base;
    char                        *track_namespace;
    size_t                      track_namespace_len;
} xqc_moq_v5_namespace_msg_t;

typedef struct {
    xqc_moq_v5_msg_base_t       msg_base;
    char                        *track_namespace;
    size_t                      track_namespace_len;
    uint64_t                    error_code;
    char                        *reason_phrase;
    size_t                      reason_phrase_len;
} xqc_moq_v5_announce_error_msg_t;

typedef struct {
    xqc_moq_v5_msg_base_t       msg_base;
    uint64_t                    subscribe_id;
    uint64_t                    status_code;
    char                        *reason_phrase;
    size_t                      reason_phrase_len;
    uint8_t                     content_exist;
    uint64_t                    final_group;
    uint64_t                    final_object;
} xqc_moq_v5_subscribe_done_msg_t;

typedef struct {
    xqc_moq_v5_msg_base_t       msg_base;
    char                        *track_namespace;
    size_t                      track_namespace_len;
    char                        *track_name;
    size_t                      track_name_len;
} xqc_moq_v5_track_status_request_msg_t;

typedef struct {
    xqc_moq_v5_msg_base_t       msg_base;
    char                        *track_namespace;
    size_t                      track_namespace_len;
    char                        *track_name;
    size_t                      track_name_len;
    uint64_t                    status_code;
    uint64_t                    last_group_id;
    uint64_t                    last_object_id;
} xqc_moq_v5_track_status_msg_t;

#define XQC_MOQ_V5_DECLARE_CODEC(name)                                    \
    void *xqc_moq_v5_create_##name(void);                                 \
    void xqc_moq_v5_destroy_##name(void *msg);                            \
    xqc_moq_v5_msg_type_t xqc_moq_v5_msg_##name##_type(void);             \
    void xqc_moq_v5_msg_##name##_init_handler(                            \
        xqc_moq_v5_msg_base_t *msg_base);                                 \
    xqc_int_t xqc_moq_v5_msg_encode_##name##_len(                         \
        xqc_moq_v5_msg_base_t *msg_base);                                 \
    xqc_int_t xqc_moq_v5_msg_encode_##name(                               \
        xqc_moq_v5_msg_base_t *msg_base, uint8_t *buf, size_t buf_cap);   \
    xqc_int_t xqc_moq_v5_msg_decode_##name(                               \
        uint8_t *buf, size_t buf_len, uint8_t stream_fin,                 \
        xqc_moq_decode_msg_ctx_t *msg_ctx,                                \
        xqc_moq_v5_msg_base_t *msg_base, xqc_int_t *finish,               \
        xqc_int_t *wait_more_data)

XQC_MOQ_V5_DECLARE_CODEC(client_setup);
XQC_MOQ_V5_DECLARE_CODEC(server_setup);
XQC_MOQ_V5_DECLARE_CODEC(subscribe);
XQC_MOQ_V5_DECLARE_CODEC(subscribe_update);
XQC_MOQ_V5_DECLARE_CODEC(subscribe_ok);
XQC_MOQ_V5_DECLARE_CODEC(subscribe_error);
XQC_MOQ_V5_DECLARE_CODEC(unsubscribe);
XQC_MOQ_V5_DECLARE_CODEC(goaway);
XQC_MOQ_V5_DECLARE_CODEC(announce);
XQC_MOQ_V5_DECLARE_CODEC(announce_ok);
XQC_MOQ_V5_DECLARE_CODEC(announce_error);
XQC_MOQ_V5_DECLARE_CODEC(unannounce);
XQC_MOQ_V5_DECLARE_CODEC(subscribe_done);
XQC_MOQ_V5_DECLARE_CODEC(announce_cancel);
XQC_MOQ_V5_DECLARE_CODEC(track_status_request);
XQC_MOQ_V5_DECLARE_CODEC(track_status);
XQC_MOQ_V5_DECLARE_CODEC(object_stream);
XQC_MOQ_V5_DECLARE_CODEC(track_stream_obj);
XQC_MOQ_V5_DECLARE_CODEC(track_header);

#undef XQC_MOQ_V5_DECLARE_CODEC

#endif
