#ifndef _XQC_MOQ_D18_AUTH_H_INCLUDED_
#define _XQC_MOQ_D18_AUTH_H_INCLUDED_

#include <stddef.h>
#include <stdint.h>

#include "src/common/xqc_list.h"

typedef enum {
    XQC_MOQ_D18_AUTH_DELETE = 0x00,
    XQC_MOQ_D18_AUTH_REGISTER = 0x01,
    XQC_MOQ_D18_AUTH_USE_ALIAS = 0x02,
    XQC_MOQ_D18_AUTH_USE_VALUE = 0x03,
} xqc_moq_d18_auth_alias_type_t;

typedef enum {
    XQC_MOQ_D18_AUTH_OK = 0,
    XQC_MOQ_D18_AUTH_INVALID_ARGUMENT = -1,
    XQC_MOQ_D18_AUTH_FORMATTING = -2,
    XQC_MOQ_D18_AUTH_NO_SPACE = -3,
    XQC_MOQ_D18_AUTH_NO_MEMORY = -4,
    XQC_MOQ_D18_AUTH_DUPLICATE_ALIAS = -5,
    XQC_MOQ_D18_AUTH_UNKNOWN_ALIAS = -6,
    XQC_MOQ_D18_AUTH_CACHE_OVERFLOW = -7,
    XQC_MOQ_D18_AUTH_PROTOCOL_VIOLATION = -8,
    XQC_MOQ_D18_AUTH_MALFORMED_TOKEN = -9,
    XQC_MOQ_D18_AUTH_EXPIRED_TOKEN = -10,
} xqc_moq_d18_auth_result_t;

typedef struct {
    uint64_t alias_type;
    uint64_t token_alias;
    uint64_t token_type;
    const uint8_t *token_value;
    size_t token_value_len;
    uint8_t has_alias;
    uint8_t has_token_type;
} xqc_moq_d18_auth_token_t;

typedef struct {
    xqc_list_head_t entries;
    uint64_t max_size;
    uint64_t current_size;
} xqc_moq_d18_auth_cache_t;

xqc_moq_d18_auth_result_t xqc_moq_d18_auth_token_decode(
    const uint8_t *buf, size_t buf_len, xqc_moq_d18_auth_token_t *token);

xqc_moq_d18_auth_result_t xqc_moq_d18_auth_token_encoded_length(
    const xqc_moq_d18_auth_token_t *token, size_t *encoded_len);

xqc_moq_d18_auth_result_t xqc_moq_d18_auth_token_encode(
    const xqc_moq_d18_auth_token_t *token, uint8_t *buf, size_t buf_cap,
    size_t *written);

void xqc_moq_d18_auth_cache_init(xqc_moq_d18_auth_cache_t *cache,
    uint64_t max_size);

void xqc_moq_d18_auth_cache_destroy(xqc_moq_d18_auth_cache_t *cache);

xqc_moq_d18_auth_result_t xqc_moq_d18_auth_cache_apply(
    xqc_moq_d18_auth_cache_t *cache,
    const xqc_moq_d18_auth_token_t *token, uint8_t in_setup,
    uint8_t receiver_is_server, xqc_moq_d18_auth_token_t *resolved,
    uint8_t *registered);

xqc_moq_d18_auth_result_t xqc_moq_d18_auth_cache_mark_expired(
    xqc_moq_d18_auth_cache_t *cache, uint64_t alias);

#endif /* _XQC_MOQ_D18_AUTH_H_INCLUDED_ */
