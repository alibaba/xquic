#ifndef _XQC_MOQ_D18_PARAMS_H_INCLUDED_
#define _XQC_MOQ_D18_PARAMS_H_INCLUDED_

#include <stddef.h>
#include <stdint.h>

#include "moq/xqc_moq.h"

typedef enum {
    XQC_MOQ_D18_PARAM_OBJECT_DELIVERY_TIMEOUT = 0x02,
    XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN = 0x03,
    XQC_MOQ_D18_PARAM_RENDEZVOUS_TIMEOUT = 0x04,
    XQC_MOQ_D18_PARAM_SUBGROUP_DELIVERY_TIMEOUT = 0x06,
    XQC_MOQ_D18_PARAM_EXPIRES = 0x08,
    XQC_MOQ_D18_PARAM_LARGEST_OBJECT = 0x09,
    XQC_MOQ_D18_PARAM_FILL_TIMEOUT = 0x0A,
    XQC_MOQ_D18_PARAM_FORWARD = 0x10,
    XQC_MOQ_D18_PARAM_SUBSCRIBER_PRIORITY = 0x20,
    XQC_MOQ_D18_PARAM_SUBSCRIPTION_FILTER = 0x21,
    XQC_MOQ_D18_PARAM_GROUP_ORDER = 0x22,
    XQC_MOQ_D18_PARAM_NEW_GROUP_REQUEST = 0x32,
    XQC_MOQ_D18_PARAM_TRACK_NAMESPACE_PREFIX = 0x34,
} xqc_moq_d18_param_type_t;

typedef enum {
    XQC_MOQ_D18_PARAM_ENCODING_VI64,
    XQC_MOQ_D18_PARAM_ENCODING_U8,
    XQC_MOQ_D18_PARAM_ENCODING_LOCATION,
    XQC_MOQ_D18_PARAM_ENCODING_BYTES,
    XQC_MOQ_D18_PARAM_ENCODING_TRACK_NAMESPACE,
} xqc_moq_d18_param_encoding_t;

typedef enum {
    XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE,
    XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE_OK,
    XQC_MOQ_D18_PARAM_CONTEXT_PUBLISH,
    XQC_MOQ_D18_PARAM_CONTEXT_PUBLISH_OK,
    XQC_MOQ_D18_PARAM_CONTEXT_FETCH,
    XQC_MOQ_D18_PARAM_CONTEXT_FETCH_OK,
    XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_SUBSCRIBE,
    XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_FETCH,
    XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_NAMESPACE,
    XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_OK,
    XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE_NAMESPACE,
    XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE_TRACKS,
    XQC_MOQ_D18_PARAM_CONTEXT_PUBLISH_NAMESPACE,
    XQC_MOQ_D18_PARAM_CONTEXT_TRACK_STATUS,
    XQC_MOQ_D18_PARAM_CONTEXT_TRACK_STATUS_OK,
    XQC_MOQ_D18_PARAM_CONTEXT_COUNT,
} xqc_moq_d18_param_context_t;

typedef enum {
    XQC_MOQ_D18_PARAM_OK = 0,
    XQC_MOQ_D18_PARAM_INVALID_ARGUMENT = -1,
    XQC_MOQ_D18_PARAM_UNKNOWN = -2,
    XQC_MOQ_D18_PARAM_INVALID_SCOPE = -3,
    XQC_MOQ_D18_PARAM_DUPLICATE = -4,
    XQC_MOQ_D18_PARAM_INVALID_VALUE = -5,
    XQC_MOQ_D18_PARAM_FORMATTING = -6,
    XQC_MOQ_D18_PARAM_PROTOCOL_VIOLATION = -7,
    XQC_MOQ_D18_PARAM_NO_MEMORY = -8,
} xqc_moq_d18_param_result_t;

typedef struct {
    uint64_t type;
    uint64_t context_mask;
    xqc_moq_d18_param_encoding_t encoding;
    uint8_t repeatable;
} xqc_moq_d18_param_spec_t;

xqc_moq_d18_param_result_t xqc_moq_d18_param_lookup(
    uint64_t type, xqc_moq_d18_param_spec_t *spec);

xqc_moq_d18_param_result_t xqc_moq_d18_param_check(
    uint64_t type, xqc_moq_d18_param_context_t context,
    size_t previous_occurrences, uint64_t integer_value,
    uint8_t has_integer_value);

xqc_moq_d18_param_result_t xqc_moq_d18_params_decode(
    const uint8_t **pos, const uint8_t *end,
    xqc_moq_d18_param_context_t context,
    xqc_moq_message_parameter_t *params, size_t params_num);

xqc_moq_d18_param_result_t xqc_moq_d18_params_encoded_len(
    xqc_moq_d18_param_context_t context,
    const xqc_moq_message_parameter_t *params, size_t params_num,
    size_t *encoded_len);

xqc_moq_d18_param_result_t xqc_moq_d18_params_encode(
    uint8_t **pos, const uint8_t *end,
    xqc_moq_d18_param_context_t context,
    const xqc_moq_message_parameter_t *params, size_t params_num);

#endif /* _XQC_MOQ_D18_PARAMS_H_INCLUDED_ */
