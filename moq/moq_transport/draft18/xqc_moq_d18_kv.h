#ifndef _XQC_MOQ_D18_KV_H_INCLUDED_
#define _XQC_MOQ_D18_KV_H_INCLUDED_

#include <stddef.h>
#include <stdint.h>

#define XQC_MOQ_D18_KV_MAX_BYTES UINT16_MAX

typedef enum {
    XQC_MOQ_D18_KV_OK = 0,
    XQC_MOQ_D18_KV_INVALID_ARGUMENT = -1,
    XQC_MOQ_D18_KV_TRUNCATED = -2,
    XQC_MOQ_D18_KV_TYPE_OVERFLOW = -3,
    XQC_MOQ_D18_KV_VALUE_TOO_LARGE = -4,
    XQC_MOQ_D18_KV_OUT_OF_ORDER = -5,
    XQC_MOQ_D18_KV_NO_SPACE = -6,
    XQC_MOQ_D18_KV_VISITOR_ERROR = -7,
} xqc_moq_d18_kv_result_t;

typedef struct {
    uint64_t type;
    uint8_t is_bytes;
    uint64_t integer;
    const uint8_t *bytes;
    size_t bytes_len;
    const uint8_t *encoded;
    size_t encoded_len;
} xqc_moq_d18_kv_view_t;

typedef xqc_moq_d18_kv_result_t (*xqc_moq_d18_kv_visitor_pt)(
    const xqc_moq_d18_kv_view_t *item, void *user_data);

typedef struct {
    xqc_moq_d18_kv_result_t result;
    uint64_t type;
    uint8_t has_type;
} xqc_moq_d18_kv_error_t;

xqc_moq_d18_kv_result_t xqc_moq_d18_kv_parse(
    const uint8_t *block, size_t block_len,
    xqc_moq_d18_kv_visitor_pt visitor, void *user_data);

xqc_moq_d18_kv_result_t xqc_moq_d18_kv_parse_ex(
    const uint8_t *block, size_t block_len,
    xqc_moq_d18_kv_visitor_pt visitor, void *user_data,
    xqc_moq_d18_kv_error_t *error);

xqc_moq_d18_kv_result_t xqc_moq_d18_kv_write_integer(
    uint8_t **pos, const uint8_t *end, uint64_t *previous_type,
    uint64_t type, uint64_t value);

xqc_moq_d18_kv_result_t xqc_moq_d18_kv_write_bytes(
    uint8_t **pos, const uint8_t *end, uint64_t *previous_type,
    uint64_t type, const uint8_t *value, size_t value_len);

#endif /* _XQC_MOQ_D18_KV_H_INCLUDED_ */
