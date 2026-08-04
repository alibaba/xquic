#ifndef _XQC_MOQ_D18_SETUP_H_INCLUDED_
#define _XQC_MOQ_D18_SETUP_H_INCLUDED_

#include <stddef.h>
#include <stdint.h>

typedef enum {
    XQC_MOQ_D18_SETUP_OPTION_PATH = 0x01,
    XQC_MOQ_D18_SETUP_OPTION_AUTHORIZATION_TOKEN = 0x03,
    XQC_MOQ_D18_SETUP_OPTION_MAX_AUTH_TOKEN_CACHE_SIZE = 0x04,
    XQC_MOQ_D18_SETUP_OPTION_AUTHORITY = 0x05,
    XQC_MOQ_D18_SETUP_OPTION_MOQT_IMPLEMENTATION = 0x07,
} xqc_moq_d18_setup_option_type_t;

typedef enum {
    XQC_MOQ_D18_SETUP_OK = 0,
    XQC_MOQ_D18_SETUP_INVALID_ARGUMENT = -1,
    XQC_MOQ_D18_SETUP_PROTOCOL_VIOLATION = -2,
    XQC_MOQ_D18_SETUP_FORMATTING = -3,
    XQC_MOQ_D18_SETUP_DUPLICATE = -4,
    XQC_MOQ_D18_SETUP_NO_MEMORY = -5,
    XQC_MOQ_D18_SETUP_NO_SPACE = -6,
    XQC_MOQ_D18_SETUP_INVALID_PATH = -7,
    XQC_MOQ_D18_SETUP_MALFORMED_PATH = -8,
    XQC_MOQ_D18_SETUP_INVALID_AUTHORITY = -9,
    XQC_MOQ_D18_SETUP_MALFORMED_AUTHORITY = -10,
} xqc_moq_d18_setup_result_t;

typedef struct {
    const uint8_t *data;
    size_t len;
    uint8_t present;
} xqc_moq_d18_bytes_view_t;

typedef struct {
    xqc_moq_d18_bytes_view_t path;
    xqc_moq_d18_bytes_view_t authority;
    xqc_moq_d18_bytes_view_t implementation;
    xqc_moq_d18_bytes_view_t *authorization_tokens;
    size_t authorization_token_count;
    size_t authorization_token_capacity;
    uint64_t max_auth_token_cache_size;
    uint8_t has_max_auth_token_cache_size;
    uint8_t owns_authorization_tokens;
} xqc_moq_d18_setup_options_t;

typedef enum {
    XQC_MOQ_D18_SETUP_SENDER_CLIENT,
    XQC_MOQ_D18_SETUP_SENDER_SERVER,
} xqc_moq_d18_setup_sender_t;

typedef enum {
    XQC_MOQ_D18_SETUP_TRANSPORT_NATIVE_QUIC,
    XQC_MOQ_D18_SETUP_TRANSPORT_WEBTRANSPORT,
} xqc_moq_d18_setup_transport_t;

void xqc_moq_d18_setup_options_init(
    xqc_moq_d18_setup_options_t *options);

void xqc_moq_d18_setup_options_destroy(
    xqc_moq_d18_setup_options_t *options);

xqc_moq_d18_setup_result_t xqc_moq_d18_setup_options_decode(
    const uint8_t *block, size_t block_len,
    xqc_moq_d18_setup_options_t *options);

xqc_moq_d18_setup_result_t xqc_moq_d18_setup_options_encoded_length(
    const xqc_moq_d18_setup_options_t *options, size_t *encoded_len);

xqc_moq_d18_setup_result_t xqc_moq_d18_setup_options_encode(
    const xqc_moq_d18_setup_options_t *options, uint8_t *buf,
    size_t buf_cap, size_t *written);

xqc_moq_d18_setup_result_t xqc_moq_d18_setup_options_validate(
    const xqc_moq_d18_setup_options_t *options,
    xqc_moq_d18_setup_sender_t sender,
    xqc_moq_d18_setup_transport_t transport);

uint64_t xqc_moq_d18_setup_result_session_error(
    xqc_moq_d18_setup_result_t result);

#endif /* _XQC_MOQ_D18_SETUP_H_INCLUDED_ */
