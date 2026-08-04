#ifndef _XQC_MOQ_D18_CONTROL_H_INCLUDED_
#define _XQC_MOQ_D18_CONTROL_H_INCLUDED_

#include "moq/moq_transport/draft18/xqc_moq_d18_defs.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_params.h"
#include "moq/moq_transport/xqc_moq_message.h"

void *xqc_moq_d18_request_update_create(void);
void xqc_moq_d18_request_update_free(void *msg);
void xqc_moq_d18_request_update_clear(xqc_moq_request_update_msg_t *msg);
void xqc_moq_d18_request_update_init_handler(
    xqc_moq_msg_base_t *base, xqc_moq_d18_param_context_t context);
xqc_int_t xqc_moq_d18_request_update_encode_len(xqc_moq_msg_base_t *base);
xqc_int_t xqc_moq_d18_request_update_encode(
    xqc_moq_msg_base_t *base, uint8_t *buf, size_t cap);
xqc_int_t xqc_moq_d18_request_update_decode(
    uint8_t *buf, size_t len, uint8_t fin,
    xqc_moq_decode_msg_ctx_t *ctx, xqc_moq_msg_base_t *base,
    xqc_int_t *finish, xqc_int_t *wait_more);

void *xqc_moq_d18_publish_blocked_create(void);
void xqc_moq_d18_publish_blocked_free(void *msg);
void xqc_moq_d18_publish_blocked_clear(xqc_moq_publish_blocked_msg_t *msg);
void xqc_moq_d18_publish_blocked_init_handler(xqc_moq_msg_base_t *base);
xqc_int_t xqc_moq_d18_publish_blocked_encode_len(xqc_moq_msg_base_t *base);
xqc_int_t xqc_moq_d18_publish_blocked_encode(
    xqc_moq_msg_base_t *base, uint8_t *buf, size_t cap);
xqc_int_t xqc_moq_d18_publish_blocked_decode(
    uint8_t *buf, size_t len, uint8_t fin,
    xqc_moq_decode_msg_ctx_t *ctx, xqc_moq_msg_base_t *base,
    xqc_int_t *finish, xqc_int_t *wait_more);

void *xqc_moq_d18_publish_done_create(void);
void xqc_moq_d18_publish_done_free(void *msg);
void xqc_moq_d18_publish_done_clear(xqc_moq_publish_done_msg_t *msg);
void xqc_moq_d18_publish_done_init_handler(xqc_moq_msg_base_t *base);
xqc_int_t xqc_moq_d18_publish_done_encode_len(xqc_moq_msg_base_t *base);
xqc_int_t xqc_moq_d18_publish_done_encode(
    xqc_moq_msg_base_t *base, uint8_t *buf, size_t cap);
xqc_int_t xqc_moq_d18_publish_done_decode(
    uint8_t *buf, size_t len, uint8_t fin,
    xqc_moq_decode_msg_ctx_t *ctx, xqc_moq_msg_base_t *base,
    xqc_int_t *finish, xqc_int_t *wait_more);

void *xqc_moq_d18_goaway_create(void);
void xqc_moq_d18_goaway_free(void *msg);
void xqc_moq_d18_goaway_clear(xqc_moq_d18_goaway_msg_t *msg);
void xqc_moq_d18_control_goaway_init_handler(xqc_moq_msg_base_t *base);
void xqc_moq_d18_request_goaway_init_handler(xqc_moq_msg_base_t *base);
xqc_int_t xqc_moq_d18_goaway_encode_len(xqc_moq_msg_base_t *base);
xqc_int_t xqc_moq_d18_goaway_encode(
    xqc_moq_msg_base_t *base, uint8_t *buf, size_t cap);
xqc_int_t xqc_moq_d18_goaway_decode(
    uint8_t *buf, size_t len, uint8_t fin,
    xqc_moq_decode_msg_ctx_t *ctx, xqc_moq_msg_base_t *base,
    xqc_int_t *finish, xqc_int_t *wait_more);

void *xqc_moq_d18_fetch_create(void);
void xqc_moq_d18_fetch_free(void *msg);
void xqc_moq_d18_fetch_init_handler(xqc_moq_msg_base_t *base);
xqc_int_t xqc_moq_d18_fetch_encode_len(xqc_moq_msg_base_t *base);
xqc_int_t xqc_moq_d18_fetch_encode(
    xqc_moq_msg_base_t *base, uint8_t *buf, size_t cap);
xqc_int_t xqc_moq_d18_fetch_decode(
    uint8_t *buf, size_t len, uint8_t fin,
    xqc_moq_decode_msg_ctx_t *ctx, xqc_moq_msg_base_t *base,
    xqc_int_t *finish, xqc_int_t *wait_more);

void *xqc_moq_d18_fetch_ok_create(void);
void xqc_moq_d18_fetch_ok_free(void *msg);
void xqc_moq_d18_fetch_ok_init_handler(xqc_moq_msg_base_t *base);
xqc_int_t xqc_moq_d18_fetch_ok_encode_len(xqc_moq_msg_base_t *base);
xqc_int_t xqc_moq_d18_fetch_ok_encode(
    xqc_moq_msg_base_t *base, uint8_t *buf, size_t cap);
xqc_int_t xqc_moq_d18_fetch_ok_decode(
    uint8_t *buf, size_t len, uint8_t fin,
    xqc_moq_decode_msg_ctx_t *ctx, xqc_moq_msg_base_t *base,
    xqc_int_t *finish, xqc_int_t *wait_more);

void *xqc_moq_d18_track_status_create(void);
void xqc_moq_d18_track_status_free(void *msg);
void xqc_moq_d18_track_status_init_handler(xqc_moq_msg_base_t *base);
xqc_int_t xqc_moq_d18_track_status_encode_len(xqc_moq_msg_base_t *base);
xqc_int_t xqc_moq_d18_track_status_encode(
    xqc_moq_msg_base_t *base, uint8_t *buf, size_t cap);
xqc_int_t xqc_moq_d18_track_status_decode(
    uint8_t *buf, size_t len, uint8_t fin,
    xqc_moq_decode_msg_ctx_t *ctx, xqc_moq_msg_base_t *base,
    xqc_int_t *finish, xqc_int_t *wait_more);

void *xqc_moq_d18_fetch_header_create(void);
void xqc_moq_d18_fetch_header_free(void *msg);
void xqc_moq_d18_fetch_header_init_handler(xqc_moq_msg_base_t *base);
xqc_int_t xqc_moq_d18_fetch_header_encode_len(xqc_moq_msg_base_t *base);
xqc_int_t xqc_moq_d18_fetch_header_encode(
    xqc_moq_msg_base_t *base, uint8_t *buf, size_t cap);
xqc_int_t xqc_moq_d18_fetch_header_decode(
    uint8_t *buf, size_t len, uint8_t fin,
    xqc_moq_decode_msg_ctx_t *ctx, xqc_moq_msg_base_t *base,
    xqc_int_t *finish, xqc_int_t *wait_more);

#endif /* _XQC_MOQ_D18_CONTROL_H_INCLUDED_ */
