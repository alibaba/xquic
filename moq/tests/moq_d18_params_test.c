#include <stdio.h>
#include <string.h>

#include "src/common/xqc_malloc.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_params.h"

#define XQC_TEST_ASSERT(expr) \
    do { \
        if (!(expr)) { \
            fprintf(stderr, "assert failed: %s:%d: %s\n", \
                    __FILE__, __LINE__, #expr); \
            return -1; \
        } \
    } while (0)

typedef struct {
    uint64_t type;
    xqc_moq_d18_param_encoding_t encoding;
    xqc_moq_d18_param_context_t allowed;
    xqc_moq_d18_param_context_t denied;
    uint8_t repeatable;
} xqc_test_param_case_t;

static const xqc_test_param_case_t xqc_test_param_cases[] = {
    {
        XQC_MOQ_D18_PARAM_OBJECT_DELIVERY_TIMEOUT,
        XQC_MOQ_D18_PARAM_ENCODING_VI64,
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE,
        XQC_MOQ_D18_PARAM_CONTEXT_FETCH,
        0,
    },
    {
        XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN,
        XQC_MOQ_D18_PARAM_ENCODING_BYTES,
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE,
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE_OK,
        1,
    },
    {
        XQC_MOQ_D18_PARAM_RENDEZVOUS_TIMEOUT,
        XQC_MOQ_D18_PARAM_ENCODING_VI64,
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE,
        XQC_MOQ_D18_PARAM_CONTEXT_PUBLISH,
        0,
    },
    {
        XQC_MOQ_D18_PARAM_SUBGROUP_DELIVERY_TIMEOUT,
        XQC_MOQ_D18_PARAM_ENCODING_VI64,
        XQC_MOQ_D18_PARAM_CONTEXT_PUBLISH_OK,
        XQC_MOQ_D18_PARAM_CONTEXT_FETCH,
        0,
    },
    {
        XQC_MOQ_D18_PARAM_EXPIRES,
        XQC_MOQ_D18_PARAM_ENCODING_VI64,
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE_OK,
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE,
        0,
    },
    {
        XQC_MOQ_D18_PARAM_LARGEST_OBJECT,
        XQC_MOQ_D18_PARAM_ENCODING_LOCATION,
        XQC_MOQ_D18_PARAM_CONTEXT_TRACK_STATUS_OK,
        XQC_MOQ_D18_PARAM_CONTEXT_TRACK_STATUS,
        0,
    },
    {
        XQC_MOQ_D18_PARAM_FILL_TIMEOUT,
        XQC_MOQ_D18_PARAM_ENCODING_VI64,
        XQC_MOQ_D18_PARAM_CONTEXT_FETCH,
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE,
        0,
    },
    {
        XQC_MOQ_D18_PARAM_FORWARD,
        XQC_MOQ_D18_PARAM_ENCODING_U8,
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE_TRACKS,
        XQC_MOQ_D18_PARAM_CONTEXT_FETCH,
        0,
    },
    {
        XQC_MOQ_D18_PARAM_SUBSCRIBER_PRIORITY,
        XQC_MOQ_D18_PARAM_ENCODING_U8,
        XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_FETCH,
        XQC_MOQ_D18_PARAM_CONTEXT_PUBLISH,
        0,
    },
    {
        XQC_MOQ_D18_PARAM_SUBSCRIPTION_FILTER,
        XQC_MOQ_D18_PARAM_ENCODING_BYTES,
        XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_SUBSCRIBE,
        XQC_MOQ_D18_PARAM_CONTEXT_FETCH,
        0,
    },
    {
        XQC_MOQ_D18_PARAM_GROUP_ORDER,
        XQC_MOQ_D18_PARAM_ENCODING_U8,
        XQC_MOQ_D18_PARAM_CONTEXT_PUBLISH_OK,
        XQC_MOQ_D18_PARAM_CONTEXT_PUBLISH,
        0,
    },
    {
        XQC_MOQ_D18_PARAM_NEW_GROUP_REQUEST,
        XQC_MOQ_D18_PARAM_ENCODING_VI64,
        XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_SUBSCRIBE,
        XQC_MOQ_D18_PARAM_CONTEXT_FETCH,
        0,
    },
    {
        XQC_MOQ_D18_PARAM_TRACK_NAMESPACE_PREFIX,
        XQC_MOQ_D18_PARAM_ENCODING_TRACK_NAMESPACE,
        XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_NAMESPACE,
        XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_SUBSCRIBE,
        0,
    },
};

static int
xqc_test_parameter_registry(void)
{
    XQC_TEST_ASSERT(sizeof(xqc_test_param_cases)
                    / sizeof(xqc_test_param_cases[0]) == 13);
    for (size_t i = 0;
         i < sizeof(xqc_test_param_cases) / sizeof(xqc_test_param_cases[0]);
         i++)
    {
        const xqc_test_param_case_t *test_case = &xqc_test_param_cases[i];
        xqc_moq_d18_param_spec_t spec;
        XQC_TEST_ASSERT(xqc_moq_d18_param_lookup(
            test_case->type, &spec) == XQC_MOQ_D18_PARAM_OK);
        XQC_TEST_ASSERT(spec.type == test_case->type);
        XQC_TEST_ASSERT(spec.encoding == test_case->encoding);
        XQC_TEST_ASSERT(spec.repeatable == test_case->repeatable);
        XQC_TEST_ASSERT(xqc_moq_d18_param_check(
            test_case->type, test_case->allowed, 0, 0, 0)
            == XQC_MOQ_D18_PARAM_OK);
        XQC_TEST_ASSERT(xqc_moq_d18_param_check(
            test_case->type, test_case->denied, 0, 0, 0)
            == XQC_MOQ_D18_PARAM_INVALID_SCOPE);
    }

    xqc_moq_d18_param_spec_t spec;
    XQC_TEST_ASSERT(xqc_moq_d18_param_lookup(
        0x7f, &spec) == XQC_MOQ_D18_PARAM_UNKNOWN);
    return 0;
}

static int
xqc_test_parameter_repetition_and_values(void)
{
    XQC_TEST_ASSERT(xqc_moq_d18_param_check(
        XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN,
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, 1, 0, 0)
        == XQC_MOQ_D18_PARAM_OK);
    XQC_TEST_ASSERT(xqc_moq_d18_param_check(
        XQC_MOQ_D18_PARAM_OBJECT_DELIVERY_TIMEOUT,
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, 1, 0, 0)
        == XQC_MOQ_D18_PARAM_DUPLICATE);

    XQC_TEST_ASSERT(xqc_moq_d18_param_check(
        XQC_MOQ_D18_PARAM_FORWARD,
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, 0, 0, 1)
        == XQC_MOQ_D18_PARAM_OK);
    XQC_TEST_ASSERT(xqc_moq_d18_param_check(
        XQC_MOQ_D18_PARAM_FORWARD,
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, 0, 1, 1)
        == XQC_MOQ_D18_PARAM_OK);
    XQC_TEST_ASSERT(xqc_moq_d18_param_check(
        XQC_MOQ_D18_PARAM_FORWARD,
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, 0, 2, 1)
        == XQC_MOQ_D18_PARAM_INVALID_VALUE);

    XQC_TEST_ASSERT(xqc_moq_d18_param_check(
        XQC_MOQ_D18_PARAM_GROUP_ORDER,
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, 0, 1, 1)
        == XQC_MOQ_D18_PARAM_OK);
    XQC_TEST_ASSERT(xqc_moq_d18_param_check(
        XQC_MOQ_D18_PARAM_GROUP_ORDER,
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, 0, 2, 1)
        == XQC_MOQ_D18_PARAM_OK);
    XQC_TEST_ASSERT(xqc_moq_d18_param_check(
        XQC_MOQ_D18_PARAM_GROUP_ORDER,
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, 0, 0, 1)
        == XQC_MOQ_D18_PARAM_INVALID_VALUE);
    XQC_TEST_ASSERT(xqc_moq_d18_param_check(
        XQC_MOQ_D18_PARAM_GROUP_ORDER,
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, 0, 3, 1)
        == XQC_MOQ_D18_PARAM_INVALID_VALUE);

    XQC_TEST_ASSERT(xqc_moq_d18_param_check(
        XQC_MOQ_D18_PARAM_SUBSCRIBER_PRIORITY,
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, 0, 255, 1)
        == XQC_MOQ_D18_PARAM_OK);
    return 0;
}

static void
xqc_test_free_params(xqc_moq_message_parameter_t *params, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        xqc_free(params[i].value);
    }
}

static int
xqc_test_parameter_decode_vectors(void)
{
    static const uint8_t subscribe[] = {
        0x02, 0x81, 0x2c,
        0x01, 0x04, 0x03, 0x02, 'a', 'b',
        0x00, 0x04, 0x03, 0x04, 'c', 'd',
        0x0d, 0x01,
        0x10, 0x80,
        0x02, 0x02,
    };
    static const uint8_t largest_object[] = {
        0x09, 0x07, 0x0b,
    };
    static const uint8_t namespace_prefix[] = {
        0x34, 0x02, 0x01, 'a', 0x02, 'b', 'c',
    };
    xqc_moq_message_parameter_t params[6] = {0};
    const uint8_t *pos = subscribe;

    XQC_TEST_ASSERT(xqc_moq_d18_params_decode(
        &pos, subscribe + sizeof(subscribe),
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, params, 6)
        == XQC_MOQ_D18_PARAM_OK);
    XQC_TEST_ASSERT(pos == subscribe + sizeof(subscribe));
    XQC_TEST_ASSERT(params[0].type
                    == XQC_MOQ_D18_PARAM_OBJECT_DELIVERY_TIMEOUT);
    XQC_TEST_ASSERT(params[0].is_integer == 1);
    XQC_TEST_ASSERT(params[0].int_value == 300);
    XQC_TEST_ASSERT(params[1].type
                    == XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN);
    XQC_TEST_ASSERT(params[1].length == 4);
    XQC_TEST_ASSERT(memcmp(params[1].value, "\x03\x02" "ab", 4) == 0);
    XQC_TEST_ASSERT(params[2].type
                    == XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN);
    XQC_TEST_ASSERT(memcmp(params[2].value, "\x03\x04" "cd", 4) == 0);
    XQC_TEST_ASSERT(params[3].int_value == 1);
    XQC_TEST_ASSERT(params[4].int_value == 128);
    XQC_TEST_ASSERT(params[5].int_value == 2);
    xqc_test_free_params(params, 6);

    memset(params, 0, sizeof(params));
    pos = largest_object;
    XQC_TEST_ASSERT(xqc_moq_d18_params_decode(
        &pos, largest_object + sizeof(largest_object),
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE_OK, params, 1)
        == XQC_MOQ_D18_PARAM_OK);
    XQC_TEST_ASSERT(params[0].type == XQC_MOQ_D18_PARAM_LARGEST_OBJECT);
    XQC_TEST_ASSERT(params[0].length == 2);
    XQC_TEST_ASSERT(memcmp(params[0].value, "\x07\x0b", 2) == 0);
    xqc_test_free_params(params, 1);

    memset(params, 0, sizeof(params));
    pos = namespace_prefix;
    XQC_TEST_ASSERT(xqc_moq_d18_params_decode(
        &pos, namespace_prefix + sizeof(namespace_prefix),
        XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_NAMESPACE, params, 1)
        == XQC_MOQ_D18_PARAM_OK);
    XQC_TEST_ASSERT(params[0].type
                    == XQC_MOQ_D18_PARAM_TRACK_NAMESPACE_PREFIX);
    XQC_TEST_ASSERT(params[0].length == sizeof(namespace_prefix) - 1);
    XQC_TEST_ASSERT(memcmp(params[0].value, namespace_prefix + 1,
                           params[0].length) == 0);
    xqc_test_free_params(params, 1);
    return 0;
}

static xqc_moq_d18_param_result_t
xqc_test_decode_one(const uint8_t *encoded, size_t encoded_len,
    xqc_moq_d18_param_context_t context, size_t count)
{
    xqc_moq_message_parameter_t params[2] = {0};
    const uint8_t *pos = encoded;
    xqc_moq_d18_param_result_t result = xqc_moq_d18_params_decode(
        &pos, encoded + encoded_len, context, params, count);
    xqc_test_free_params(params, 2);
    return result;
}

static int
xqc_test_parameter_decode_rejections(void)
{
    static const uint8_t overflow[] = {
        0x02, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    static const uint8_t unknown[] = {0x7f};
    static const uint8_t duplicate[] = {0x02, 0x00, 0x00, 0x01};
    static const uint8_t wrong_scope[] = {0x0a, 0x00};
    static const uint8_t invalid_forward[] = {0x10, 0x02};
    static const uint8_t invalid_group_low[] = {0x22, 0x00};
    static const uint8_t invalid_group_high[] = {0x22, 0x03};
    static const uint8_t truncated_vi64[] = {0x02};
    static const uint8_t truncated_u8[] = {0x10};
    static const uint8_t truncated_location[] = {0x09, 0x01};
    static const uint8_t truncated_bytes[] = {0x03, 0x02, 'a'};
    static const uint8_t oversized_bytes[] = {0x03, 0xc1, 0x00, 0x00};
    static const uint8_t namespace_too_many[] = {0x34, 0x21};
    static const uint8_t namespace_empty_field[] = {0x34, 0x01, 0x00};
    static const uint8_t namespace_truncated[] = {
        0x34, 0x01, 0x02, 'a',
    };

    XQC_TEST_ASSERT(xqc_test_decode_one(
        overflow, sizeof(overflow),
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, 2)
        == XQC_MOQ_D18_PARAM_PROTOCOL_VIOLATION);
    XQC_TEST_ASSERT(xqc_test_decode_one(
        unknown, sizeof(unknown),
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, 1)
        == XQC_MOQ_D18_PARAM_UNKNOWN);
    XQC_TEST_ASSERT(xqc_test_decode_one(
        duplicate, sizeof(duplicate),
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, 2)
        == XQC_MOQ_D18_PARAM_DUPLICATE);
    XQC_TEST_ASSERT(xqc_test_decode_one(
        wrong_scope, sizeof(wrong_scope),
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, 1)
        == XQC_MOQ_D18_PARAM_INVALID_SCOPE);
    XQC_TEST_ASSERT(xqc_test_decode_one(
        invalid_forward, sizeof(invalid_forward),
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, 1)
        == XQC_MOQ_D18_PARAM_INVALID_VALUE);
    XQC_TEST_ASSERT(xqc_test_decode_one(
        invalid_group_low, sizeof(invalid_group_low),
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, 1)
        == XQC_MOQ_D18_PARAM_INVALID_VALUE);
    XQC_TEST_ASSERT(xqc_test_decode_one(
        invalid_group_high, sizeof(invalid_group_high),
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, 1)
        == XQC_MOQ_D18_PARAM_INVALID_VALUE);
    XQC_TEST_ASSERT(xqc_test_decode_one(
        truncated_vi64, sizeof(truncated_vi64),
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, 1)
        == XQC_MOQ_D18_PARAM_FORMATTING);
    XQC_TEST_ASSERT(xqc_test_decode_one(
        truncated_u8, sizeof(truncated_u8),
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, 1)
        == XQC_MOQ_D18_PARAM_FORMATTING);
    XQC_TEST_ASSERT(xqc_test_decode_one(
        truncated_location, sizeof(truncated_location),
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE_OK, 1)
        == XQC_MOQ_D18_PARAM_FORMATTING);
    XQC_TEST_ASSERT(xqc_test_decode_one(
        truncated_bytes, sizeof(truncated_bytes),
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, 1)
        == XQC_MOQ_D18_PARAM_FORMATTING);
    XQC_TEST_ASSERT(xqc_test_decode_one(
        oversized_bytes, sizeof(oversized_bytes),
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, 1)
        == XQC_MOQ_D18_PARAM_PROTOCOL_VIOLATION);
    XQC_TEST_ASSERT(xqc_test_decode_one(
        namespace_too_many, sizeof(namespace_too_many),
        XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_NAMESPACE, 1)
        == XQC_MOQ_D18_PARAM_PROTOCOL_VIOLATION);
    XQC_TEST_ASSERT(xqc_test_decode_one(
        namespace_empty_field, sizeof(namespace_empty_field),
        XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_NAMESPACE, 1)
        == XQC_MOQ_D18_PARAM_PROTOCOL_VIOLATION);
    XQC_TEST_ASSERT(xqc_test_decode_one(
        namespace_truncated, sizeof(namespace_truncated),
        XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_NAMESPACE, 1)
        == XQC_MOQ_D18_PARAM_FORMATTING);
    return 0;
}

static int
xqc_test_parameter_encode_vectors(void)
{
    static uint8_t token_one[] = {0x03, 0x02, 'a', 'b'};
    static uint8_t token_two[] = {0x03, 0x04, 'c', 'd'};
    static const uint8_t expected_subscribe[] = {
        0x02, 0x81, 0x2c,
        0x01, 0x04, 0x03, 0x02, 'a', 'b',
        0x00, 0x04, 0x03, 0x04, 'c', 'd',
        0x0d, 0x01,
        0x10, 0x80,
        0x02, 0x02,
    };
    static uint8_t location[] = {0x07, 0x0b};
    static const uint8_t expected_location[] = {0x09, 0x07, 0x0b};
    static uint8_t namespace_prefix[] = {
        0x02, 0x01, 'a', 0x02, 'b', 'c',
    };
    static const uint8_t expected_namespace[] = {
        0x34, 0x02, 0x01, 'a', 0x02, 'b', 'c',
    };
    xqc_moq_message_parameter_t subscribe[6] = {
        {
            .type = XQC_MOQ_D18_PARAM_OBJECT_DELIVERY_TIMEOUT,
            .is_integer = 1,
            .int_value = 300,
        },
        {
            .type = XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN,
            .length = sizeof(token_one),
            .value = token_one,
        },
        {
            .type = XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN,
            .length = sizeof(token_two),
            .value = token_two,
        },
        {
            .type = XQC_MOQ_D18_PARAM_FORWARD,
            .is_integer = 1,
            .int_value = 1,
        },
        {
            .type = XQC_MOQ_D18_PARAM_SUBSCRIBER_PRIORITY,
            .is_integer = 1,
            .int_value = 128,
        },
        {
            .type = XQC_MOQ_D18_PARAM_GROUP_ORDER,
            .is_integer = 1,
            .int_value = 2,
        },
    };
    uint8_t encoded[64] = {0};
    size_t encoded_len = 0;
    uint8_t *pos = encoded;

    XQC_TEST_ASSERT(xqc_moq_d18_params_encoded_len(
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, subscribe, 6,
        &encoded_len) == XQC_MOQ_D18_PARAM_OK);
    XQC_TEST_ASSERT(encoded_len == sizeof(expected_subscribe));
    XQC_TEST_ASSERT(xqc_moq_d18_params_encode(
        &pos, encoded + sizeof(encoded),
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, subscribe, 6)
        == XQC_MOQ_D18_PARAM_OK);
    XQC_TEST_ASSERT(pos == encoded + sizeof(expected_subscribe));
    XQC_TEST_ASSERT(memcmp(encoded, expected_subscribe,
                           sizeof(expected_subscribe)) == 0);

    xqc_moq_message_parameter_t decoded[6] = {0};
    const uint8_t *read_pos = encoded;
    XQC_TEST_ASSERT(xqc_moq_d18_params_decode(
        &read_pos, pos, XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE,
        decoded, 6) == XQC_MOQ_D18_PARAM_OK);
    XQC_TEST_ASSERT(read_pos == pos);
    XQC_TEST_ASSERT(decoded[0].int_value == 300);
    XQC_TEST_ASSERT(decoded[1].length == sizeof(token_one));
    XQC_TEST_ASSERT(memcmp(decoded[1].value, token_one,
                           sizeof(token_one)) == 0);
    XQC_TEST_ASSERT(decoded[2].length == sizeof(token_two));
    XQC_TEST_ASSERT(memcmp(decoded[2].value, token_two,
                           sizeof(token_two)) == 0);
    XQC_TEST_ASSERT(decoded[3].int_value == 1);
    XQC_TEST_ASSERT(decoded[4].int_value == 128);
    XQC_TEST_ASSERT(decoded[5].int_value == 2);
    xqc_test_free_params(decoded, 6);

    xqc_moq_message_parameter_t largest_object = {
        .type = XQC_MOQ_D18_PARAM_LARGEST_OBJECT,
        .length = sizeof(location),
        .value = location,
    };
    memset(encoded, 0, sizeof(encoded));
    pos = encoded;
    XQC_TEST_ASSERT(xqc_moq_d18_params_encoded_len(
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE_OK, &largest_object, 1,
        &encoded_len) == XQC_MOQ_D18_PARAM_OK);
    XQC_TEST_ASSERT(encoded_len == sizeof(expected_location));
    XQC_TEST_ASSERT(xqc_moq_d18_params_encode(
        &pos, encoded + sizeof(encoded),
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE_OK, &largest_object, 1)
        == XQC_MOQ_D18_PARAM_OK);
    XQC_TEST_ASSERT(pos == encoded + sizeof(expected_location));
    XQC_TEST_ASSERT(memcmp(encoded, expected_location,
                           sizeof(expected_location)) == 0);

    xqc_moq_message_parameter_t prefix = {
        .type = XQC_MOQ_D18_PARAM_TRACK_NAMESPACE_PREFIX,
        .length = sizeof(namespace_prefix),
        .value = namespace_prefix,
    };
    memset(encoded, 0, sizeof(encoded));
    pos = encoded;
    XQC_TEST_ASSERT(xqc_moq_d18_params_encoded_len(
        XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_NAMESPACE,
        &prefix, 1, &encoded_len) == XQC_MOQ_D18_PARAM_OK);
    XQC_TEST_ASSERT(encoded_len == sizeof(expected_namespace));
    XQC_TEST_ASSERT(xqc_moq_d18_params_encode(
        &pos, encoded + sizeof(encoded),
        XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_NAMESPACE,
        &prefix, 1) == XQC_MOQ_D18_PARAM_OK);
    XQC_TEST_ASSERT(pos == encoded + sizeof(expected_namespace));
    XQC_TEST_ASSERT(memcmp(encoded, expected_namespace,
                           sizeof(expected_namespace)) == 0);
    return 0;
}

static int
xqc_test_parameter_encode_rejections(void)
{
    static uint8_t one_byte[] = {0x01};
    static uint8_t malformed_namespace[] = {0x01, 0x00};
    xqc_moq_message_parameter_t descending[2] = {
        {
            .type = XQC_MOQ_D18_PARAM_RENDEZVOUS_TIMEOUT,
            .is_integer = 1,
            .int_value = 1,
        },
        {
            .type = XQC_MOQ_D18_PARAM_OBJECT_DELIVERY_TIMEOUT,
            .is_integer = 1,
            .int_value = 1,
        },
    };
    xqc_moq_message_parameter_t duplicate[2] = {
        {
            .type = XQC_MOQ_D18_PARAM_OBJECT_DELIVERY_TIMEOUT,
            .is_integer = 1,
            .int_value = 1,
        },
        {
            .type = XQC_MOQ_D18_PARAM_OBJECT_DELIVERY_TIMEOUT,
            .is_integer = 1,
            .int_value = 2,
        },
    };
    xqc_moq_message_parameter_t wrong_scope = {
        .type = XQC_MOQ_D18_PARAM_FILL_TIMEOUT,
        .is_integer = 1,
        .int_value = 1,
    };
    xqc_moq_message_parameter_t integer_as_bytes = {
        .type = XQC_MOQ_D18_PARAM_OBJECT_DELIVERY_TIMEOUT,
        .length = sizeof(one_byte),
        .value = one_byte,
    };
    xqc_moq_message_parameter_t bytes_as_integer = {
        .type = XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN,
        .is_integer = 1,
        .int_value = 1,
    };
    xqc_moq_message_parameter_t invalid_forward = {
        .type = XQC_MOQ_D18_PARAM_FORWARD,
        .is_integer = 1,
        .int_value = 2,
    };
    xqc_moq_message_parameter_t invalid_group_order = {
        .type = XQC_MOQ_D18_PARAM_GROUP_ORDER,
        .is_integer = 1,
        .int_value = 0,
    };
    xqc_moq_message_parameter_t malformed_location = {
        .type = XQC_MOQ_D18_PARAM_LARGEST_OBJECT,
        .length = sizeof(one_byte),
        .value = one_byte,
    };
    xqc_moq_message_parameter_t empty_location = {
        .type = XQC_MOQ_D18_PARAM_LARGEST_OBJECT,
    };
    xqc_moq_message_parameter_t oversized_bytes = {
        .type = XQC_MOQ_D18_PARAM_AUTHORIZATION_TOKEN,
        .length = (uint64_t)UINT16_MAX + 1,
        .value = one_byte,
    };
    xqc_moq_message_parameter_t malformed_prefix = {
        .type = XQC_MOQ_D18_PARAM_TRACK_NAMESPACE_PREFIX,
        .length = sizeof(malformed_namespace),
        .value = malformed_namespace,
    };
    xqc_moq_message_parameter_t empty_prefix = {
        .type = XQC_MOQ_D18_PARAM_TRACK_NAMESPACE_PREFIX,
    };
    size_t encoded_len = 0;

    XQC_TEST_ASSERT(xqc_moq_d18_params_encoded_len(
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, descending, 2,
        &encoded_len) == XQC_MOQ_D18_PARAM_INVALID_VALUE);
    XQC_TEST_ASSERT(xqc_moq_d18_params_encoded_len(
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, duplicate, 2,
        &encoded_len) == XQC_MOQ_D18_PARAM_DUPLICATE);
    XQC_TEST_ASSERT(xqc_moq_d18_params_encoded_len(
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, &wrong_scope, 1,
        &encoded_len) == XQC_MOQ_D18_PARAM_INVALID_SCOPE);
    XQC_TEST_ASSERT(xqc_moq_d18_params_encoded_len(
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, &integer_as_bytes, 1,
        &encoded_len) == XQC_MOQ_D18_PARAM_INVALID_VALUE);
    XQC_TEST_ASSERT(xqc_moq_d18_params_encoded_len(
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, &bytes_as_integer, 1,
        &encoded_len) == XQC_MOQ_D18_PARAM_INVALID_VALUE);
    XQC_TEST_ASSERT(xqc_moq_d18_params_encoded_len(
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, &invalid_forward, 1,
        &encoded_len) == XQC_MOQ_D18_PARAM_INVALID_VALUE);
    XQC_TEST_ASSERT(xqc_moq_d18_params_encoded_len(
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, &invalid_group_order, 1,
        &encoded_len) == XQC_MOQ_D18_PARAM_INVALID_VALUE);
    XQC_TEST_ASSERT(xqc_moq_d18_params_encoded_len(
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE_OK, &malformed_location, 1,
        &encoded_len) == XQC_MOQ_D18_PARAM_FORMATTING);
    XQC_TEST_ASSERT(xqc_moq_d18_params_encoded_len(
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE_OK, &empty_location, 1,
        &encoded_len) == XQC_MOQ_D18_PARAM_FORMATTING);
    XQC_TEST_ASSERT(xqc_moq_d18_params_encoded_len(
        XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE, &oversized_bytes, 1,
        &encoded_len) == XQC_MOQ_D18_PARAM_INVALID_VALUE);
    XQC_TEST_ASSERT(xqc_moq_d18_params_encoded_len(
        XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_NAMESPACE,
        &malformed_prefix, 1, &encoded_len)
        == XQC_MOQ_D18_PARAM_PROTOCOL_VIOLATION);
    XQC_TEST_ASSERT(xqc_moq_d18_params_encoded_len(
        XQC_MOQ_D18_PARAM_CONTEXT_REQUEST_UPDATE_NAMESPACE,
        &empty_prefix, 1, &encoded_len)
        == XQC_MOQ_D18_PARAM_FORMATTING);

    xqc_moq_message_parameter_t forward = {
        .type = XQC_MOQ_D18_PARAM_FORWARD,
        .is_integer = 1,
        .int_value = 1,
    };
    uint8_t encoded[2] = {0};
    uint8_t *pos = encoded;
    XQC_TEST_ASSERT(xqc_moq_d18_params_encode(
        &pos, encoded + 1, XQC_MOQ_D18_PARAM_CONTEXT_SUBSCRIBE,
        &forward, 1) == XQC_MOQ_D18_PARAM_FORMATTING);
    XQC_TEST_ASSERT(pos == encoded);
    return 0;
}

int
main(void)
{
    if (xqc_test_parameter_registry() != 0
        || xqc_test_parameter_repetition_and_values() != 0
        || xqc_test_parameter_decode_vectors() != 0
        || xqc_test_parameter_decode_rejections() != 0
        || xqc_test_parameter_encode_vectors() != 0
        || xqc_test_parameter_encode_rejections() != 0)
    {
        return 1;
    }
    printf("moq_d18_params_test: PASS\n");
    return 0;
}
