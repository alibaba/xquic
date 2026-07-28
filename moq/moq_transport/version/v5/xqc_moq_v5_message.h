#ifndef _XQC_MOQ_V5_MESSAGE_H_INCLUDED_
#define _XQC_MOQ_V5_MESSAGE_H_INCLUDED_

#include "moq/moq_transport/xqc_moq_message.h"

typedef xqc_moq_msg_type_t xqc_moq_v5_msg_type_t;
typedef xqc_moq_msg_base_t xqc_moq_v5_msg_base_t;

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
XQC_MOQ_V5_DECLARE_CODEC(object_stream);
XQC_MOQ_V5_DECLARE_CODEC(track_stream_obj);
XQC_MOQ_V5_DECLARE_CODEC(track_header);

#undef XQC_MOQ_V5_DECLARE_CODEC

#endif
