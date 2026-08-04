#include <stdio.h>
#include <string.h>

#include "moq/moq_transport/draft18/xqc_moq_d18_auth.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_kv.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_setup.h"
#include "moq/moq_transport/xqc_moq_session.h"

#define XQC_TEST_ASSERT(expr) \
    do { \
        if (!(expr)) { \
            fprintf(stderr, "assert failed: %s:%d: %s\n", \
                    __FILE__, __LINE__, #expr); \
            return -1; \
        } \
    } while (0)

#define XQC_TEST_MAX_ITEMS 8

typedef struct {
    xqc_moq_d18_kv_view_t items[XQC_TEST_MAX_ITEMS];
    size_t count;
    xqc_moq_d18_kv_result_t visitor_result;
} xqc_test_kv_collector_t;

static xqc_moq_d18_kv_result_t
xqc_test_collect_kv(const xqc_moq_d18_kv_view_t *item, void *user_data)
{
    xqc_test_kv_collector_t *collector = user_data;
    if (collector->visitor_result != XQC_MOQ_D18_KV_OK) {
        return collector->visitor_result;
    }
    if (collector->count >= XQC_TEST_MAX_ITEMS) {
        return XQC_MOQ_D18_KV_VISITOR_ERROR;
    }
    collector->items[collector->count++] = *item;
    return XQC_MOQ_D18_KV_OK;
}

static int
xqc_test_kv_parse_golden_vector(void)
{
    static const uint8_t valid[] = {
        0x01, 0x01, '/',
        0x03, 0x40,
        0x01, 0x09, 'r', 'e', 'l', 'a', 'y', ':', '4', '4', '3',
    };
    xqc_test_kv_collector_t collector = {0};

    XQC_TEST_ASSERT(xqc_moq_d18_kv_parse(valid, sizeof(valid),
        xqc_test_collect_kv, &collector) == XQC_MOQ_D18_KV_OK);
    XQC_TEST_ASSERT(collector.count == 3);
    XQC_TEST_ASSERT(collector.items[0].type == 0x01);
    XQC_TEST_ASSERT(collector.items[0].is_bytes == 1);
    XQC_TEST_ASSERT(collector.items[0].bytes_len == 1);
    XQC_TEST_ASSERT(collector.items[0].bytes[0] == '/');
    XQC_TEST_ASSERT(collector.items[1].type == 0x04);
    XQC_TEST_ASSERT(collector.items[1].is_bytes == 0);
    XQC_TEST_ASSERT(collector.items[1].integer == 64);
    XQC_TEST_ASSERT(collector.items[2].type == 0x05);
    XQC_TEST_ASSERT(collector.items[2].is_bytes == 1);
    XQC_TEST_ASSERT(collector.items[2].bytes_len == 9);
    XQC_TEST_ASSERT(memcmp(collector.items[2].bytes, "relay:443", 9) == 0);

    XQC_TEST_ASSERT(xqc_moq_d18_kv_parse(NULL, 0, xqc_test_collect_kv,
        &collector) == XQC_MOQ_D18_KV_OK);
    XQC_TEST_ASSERT(collector.count == 3);
    return 0;
}

static int
xqc_test_kv_parse_malformed_vectors(void)
{
    static const uint8_t truncated_delta[] = {0x80};
    static const uint8_t truncated_integer[] = {0x00, 0x80};
    static const uint8_t truncated_length[] = {0x01, 0x80};
    static const uint8_t truncated_bytes[] = {0x01, 0x02, 'a'};
    static const uint8_t oversized_bytes[] = {
        0x01, 0xc1, 0x00, 0x00,
    };
    static const uint8_t overflow[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x01,
    };
    xqc_test_kv_collector_t collector = {0};

    XQC_TEST_ASSERT(xqc_moq_d18_kv_parse(truncated_delta,
        sizeof(truncated_delta), xqc_test_collect_kv, &collector)
        == XQC_MOQ_D18_KV_TRUNCATED);
    XQC_TEST_ASSERT(xqc_moq_d18_kv_parse(truncated_integer,
        sizeof(truncated_integer), xqc_test_collect_kv, &collector)
        == XQC_MOQ_D18_KV_TRUNCATED);
    XQC_TEST_ASSERT(xqc_moq_d18_kv_parse(truncated_length,
        sizeof(truncated_length), xqc_test_collect_kv, &collector)
        == XQC_MOQ_D18_KV_TRUNCATED);
    XQC_TEST_ASSERT(xqc_moq_d18_kv_parse(truncated_bytes,
        sizeof(truncated_bytes), xqc_test_collect_kv, &collector)
        == XQC_MOQ_D18_KV_TRUNCATED);
    XQC_TEST_ASSERT(xqc_moq_d18_kv_parse(oversized_bytes,
        sizeof(oversized_bytes), xqc_test_collect_kv, &collector)
        == XQC_MOQ_D18_KV_VALUE_TOO_LARGE);
    XQC_TEST_ASSERT(xqc_moq_d18_kv_parse(overflow, sizeof(overflow),
        xqc_test_collect_kv, &collector)
        == XQC_MOQ_D18_KV_TYPE_OVERFLOW);

    collector.visitor_result = XQC_MOQ_D18_KV_VISITOR_ERROR;
    XQC_TEST_ASSERT(xqc_moq_d18_kv_parse((const uint8_t *)"\0\0", 2,
        xqc_test_collect_kv, &collector)
        == XQC_MOQ_D18_KV_VISITOR_ERROR);
    return 0;
}

static int
xqc_test_kv_write_golden_vector(void)
{
    static const uint8_t expected[] = {
        0x01, 0x01, '/',
        0x03, 0x40,
        0x01, 0x09, 'r', 'e', 'l', 'a', 'y', ':', '4', '4', '3',
    };
    uint8_t buf[64] = {0};
    uint8_t *pos = buf;
    uint64_t previous_type = 0;

    XQC_TEST_ASSERT(xqc_moq_d18_kv_write_bytes(&pos, buf + sizeof(buf),
        &previous_type, 0x01, (const uint8_t *)"/", 1)
        == XQC_MOQ_D18_KV_OK);
    XQC_TEST_ASSERT(xqc_moq_d18_kv_write_integer(&pos, buf + sizeof(buf),
        &previous_type, 0x04, 64) == XQC_MOQ_D18_KV_OK);
    XQC_TEST_ASSERT(xqc_moq_d18_kv_write_bytes(&pos, buf + sizeof(buf),
        &previous_type, 0x05, (const uint8_t *)"relay:443", 9)
        == XQC_MOQ_D18_KV_OK);
    XQC_TEST_ASSERT((size_t)(pos - buf) == sizeof(expected));
    XQC_TEST_ASSERT(memcmp(buf, expected, sizeof(expected)) == 0);
    return 0;
}

static int
xqc_test_kv_writer_rejections_do_not_mutate(void)
{
    uint8_t buf[16] = {0};
    uint8_t *pos = buf;
    uint64_t previous_type = 4;

    XQC_TEST_ASSERT(xqc_moq_d18_kv_write_integer(&pos, buf + sizeof(buf),
        &previous_type, 2, 0) == XQC_MOQ_D18_KV_OUT_OF_ORDER);
    XQC_TEST_ASSERT(pos == buf);
    XQC_TEST_ASSERT(previous_type == 4);
    XQC_TEST_ASSERT(xqc_moq_d18_kv_write_integer(&pos, buf + sizeof(buf),
        &previous_type, 5, 0) == XQC_MOQ_D18_KV_INVALID_ARGUMENT);
    XQC_TEST_ASSERT(pos == buf);
    XQC_TEST_ASSERT(previous_type == 4);
    XQC_TEST_ASSERT(xqc_moq_d18_kv_write_bytes(&pos, buf + sizeof(buf),
        &previous_type, 6, NULL, 0)
        == XQC_MOQ_D18_KV_INVALID_ARGUMENT);
    XQC_TEST_ASSERT(pos == buf);
    XQC_TEST_ASSERT(previous_type == 4);

    XQC_TEST_ASSERT(xqc_moq_d18_kv_write_integer(&pos, buf + 1,
        &previous_type, 4, 64) == XQC_MOQ_D18_KV_NO_SPACE);
    XQC_TEST_ASSERT(pos == buf);
    XQC_TEST_ASSERT(previous_type == 4);

    XQC_TEST_ASSERT(xqc_moq_d18_kv_write_integer(&pos, buf + sizeof(buf),
        &previous_type, 4, 0) == XQC_MOQ_D18_KV_OK);
    XQC_TEST_ASSERT(previous_type == 4);
    XQC_TEST_ASSERT(pos - buf == 2);
    return 0;
}

static int
xqc_test_setup_decode_known_options(void)
{
    static const uint8_t encoded[] = {
        0x01, 0x01, '/',
        0x03, 0x40,
        0x01, 0x09, 'r', 'e', 'l', 'a', 'y', ':', '4', '4', '3',
    };
    xqc_moq_d18_setup_options_t options;

    xqc_moq_d18_setup_options_init(&options);
    XQC_TEST_ASSERT(xqc_moq_d18_setup_options_decode(encoded,
        sizeof(encoded), &options) == XQC_MOQ_D18_SETUP_OK);
    XQC_TEST_ASSERT(options.path.present == 1);
    XQC_TEST_ASSERT(options.path.len == 1);
    XQC_TEST_ASSERT(options.path.data[0] == '/');
    XQC_TEST_ASSERT(options.has_max_auth_token_cache_size == 1);
    XQC_TEST_ASSERT(options.max_auth_token_cache_size == 64);
    XQC_TEST_ASSERT(options.authority.present == 1);
    XQC_TEST_ASSERT(options.authority.len == 9);
    XQC_TEST_ASSERT(memcmp(options.authority.data, "relay:443", 9) == 0);
    XQC_TEST_ASSERT(options.authorization_token_count == 0);
    xqc_moq_d18_setup_options_destroy(&options);
    return 0;
}

static int
xqc_test_setup_repeated_authorization_tokens(void)
{
    static const uint8_t encoded[] = {
        0x03, 0x01, 'a',
        0x00, 0x02, 'b', 'c',
    };
    xqc_moq_d18_setup_options_t options;

    xqc_moq_d18_setup_options_init(&options);
    XQC_TEST_ASSERT(xqc_moq_d18_setup_options_decode(encoded,
        sizeof(encoded), &options) == XQC_MOQ_D18_SETUP_OK);
    XQC_TEST_ASSERT(options.authorization_token_count == 2);
    XQC_TEST_ASSERT(options.authorization_tokens[0].len == 1);
    XQC_TEST_ASSERT(options.authorization_tokens[0].data[0] == 'a');
    XQC_TEST_ASSERT(options.authorization_tokens[1].len == 2);
    XQC_TEST_ASSERT(memcmp(options.authorization_tokens[1].data,
                           "bc", 2) == 0);
    xqc_moq_d18_setup_options_destroy(&options);
    return 0;
}

static int
xqc_test_setup_duplicate_rules(void)
{
    static const uint8_t duplicate_path[] = {
        0x01, 0x01, '/',
        0x00, 0x01, 'x',
    };
    static const uint8_t duplicate_max_cache[] = {
        0x04, 0x01,
        0x00, 0x02,
    };
    static const uint8_t duplicate_authority[] = {
        0x05, 0x01, 'a',
        0x00, 0x01, 'b',
    };
    static const uint8_t duplicate_implementation[] = {
        0x07, 0x01, 'a',
        0x00, 0x01, 'b',
    };
    static const uint8_t duplicate_unknown[] = {
        0x09, 0x01, 'a',
        0x00, 0x01, 'b',
        0x01, 0x01,
        0x00, 0x02,
    };
    xqc_moq_d18_setup_options_t options;

    xqc_moq_d18_setup_options_init(&options);
    XQC_TEST_ASSERT(xqc_moq_d18_setup_options_decode(duplicate_path,
        sizeof(duplicate_path), &options) == XQC_MOQ_D18_SETUP_DUPLICATE);
    XQC_TEST_ASSERT(xqc_moq_d18_setup_options_decode(duplicate_max_cache,
        sizeof(duplicate_max_cache), &options)
        == XQC_MOQ_D18_SETUP_DUPLICATE);
    XQC_TEST_ASSERT(xqc_moq_d18_setup_options_decode(duplicate_authority,
        sizeof(duplicate_authority), &options)
        == XQC_MOQ_D18_SETUP_DUPLICATE);
    XQC_TEST_ASSERT(xqc_moq_d18_setup_options_decode(
        duplicate_implementation, sizeof(duplicate_implementation), &options)
        == XQC_MOQ_D18_SETUP_DUPLICATE);
    XQC_TEST_ASSERT(xqc_moq_d18_setup_options_decode(duplicate_unknown,
        sizeof(duplicate_unknown), &options) == XQC_MOQ_D18_SETUP_OK);
    xqc_moq_d18_setup_options_destroy(&options);
    return 0;
}

static int
xqc_test_setup_structural_error_mapping(void)
{
    static const uint8_t truncated_path[] = {0x01, 0x01};
    static const uint8_t truncated_max_cache[] = {0x04, 0x80};
    static const uint8_t truncated_unknown[] = {0x09, 0x01};
    static const uint8_t oversized_path[] = {
        0x01, 0xc1, 0x00, 0x00,
    };
    xqc_moq_d18_setup_options_t options;

    xqc_moq_d18_setup_options_init(&options);
    XQC_TEST_ASSERT(xqc_moq_d18_setup_options_decode(truncated_path,
        sizeof(truncated_path), &options) == XQC_MOQ_D18_SETUP_FORMATTING);
    XQC_TEST_ASSERT(xqc_moq_d18_setup_options_decode(truncated_max_cache,
        sizeof(truncated_max_cache), &options)
        == XQC_MOQ_D18_SETUP_FORMATTING);
    XQC_TEST_ASSERT(xqc_moq_d18_setup_options_decode(truncated_unknown,
        sizeof(truncated_unknown), &options)
        == XQC_MOQ_D18_SETUP_PROTOCOL_VIOLATION);
    XQC_TEST_ASSERT(xqc_moq_d18_setup_options_decode(oversized_path,
        sizeof(oversized_path), &options)
        == XQC_MOQ_D18_SETUP_PROTOCOL_VIOLATION);
    xqc_moq_d18_setup_options_destroy(&options);
    return 0;
}

static int
xqc_test_setup_typed_writer_roundtrip(void)
{
    static const uint8_t expected[] = {
        0x01, 0x01, '/',
        0x02, 0x01, 'a',
        0x00, 0x02, 'b', 'c',
        0x01, 0x40,
        0x01, 0x09, 'r', 'e', 'l', 'a', 'y', ':', '4', '4', '3',
        0x02, 0x09, 'x', 'q', 'u', 'i', 'c', '/', '0', '.', '1',
    };
    xqc_moq_d18_bytes_view_t tokens[] = {
        {(const uint8_t *)"a", 1, 1},
        {(const uint8_t *)"bc", 2, 1},
    };
    xqc_moq_d18_setup_options_t options;
    xqc_moq_d18_setup_options_t decoded;
    uint8_t buf[128] = {0};
    size_t encoded_len = 0;
    size_t written = 0;

    xqc_moq_d18_setup_options_init(&options);
    options.path = (xqc_moq_d18_bytes_view_t){
        (const uint8_t *)"/", 1, 1,
    };
    options.authorization_tokens = tokens;
    options.authorization_token_count = 2;
    options.authorization_token_capacity = 2;
    options.has_max_auth_token_cache_size = 1;
    options.max_auth_token_cache_size = 64;
    options.authority = (xqc_moq_d18_bytes_view_t){
        (const uint8_t *)"relay:443", 9, 1,
    };
    options.implementation = (xqc_moq_d18_bytes_view_t){
        (const uint8_t *)"xquic/0.1", 9, 1,
    };

    XQC_TEST_ASSERT(xqc_moq_d18_setup_options_encoded_length(
        &options, &encoded_len) == XQC_MOQ_D18_SETUP_OK);
    XQC_TEST_ASSERT(encoded_len == sizeof(expected));
    XQC_TEST_ASSERT(xqc_moq_d18_setup_options_encode(&options, buf,
        sizeof(buf), &written) == XQC_MOQ_D18_SETUP_OK);
    XQC_TEST_ASSERT(written == sizeof(expected));
    XQC_TEST_ASSERT(memcmp(buf, expected, sizeof(expected)) == 0);

    xqc_moq_d18_setup_options_init(&decoded);
    XQC_TEST_ASSERT(xqc_moq_d18_setup_options_decode(buf, written,
        &decoded) == XQC_MOQ_D18_SETUP_OK);
    XQC_TEST_ASSERT(decoded.authorization_token_count == 2);
    XQC_TEST_ASSERT(decoded.max_auth_token_cache_size == 64);
    XQC_TEST_ASSERT(decoded.implementation.len == 9);
    xqc_moq_d18_setup_options_destroy(&decoded);
    return 0;
}

static int
xqc_test_setup_path_syntax(void)
{
    static const char *valid[] = {
        "",
        "/",
        "/live/track",
        "/live?q=one/two?three",
        "?query-only",
        "/percent%20encoded",
    };
    static const char *invalid[] = {
        "relative",
        "/fragment#local",
        "/bad path",
        "/control\x1f",
        "/percent%2",
        "/percent%xx",
        "/raw[bracket]",
    };
    xqc_moq_d18_setup_options_t options;

    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); i++) {
        xqc_moq_d18_setup_options_init(&options);
        options.path = (xqc_moq_d18_bytes_view_t){
            (const uint8_t *)valid[i], strlen(valid[i]), 1,
        };
        XQC_TEST_ASSERT(xqc_moq_d18_setup_options_validate(&options,
            XQC_MOQ_D18_SETUP_SENDER_CLIENT,
            XQC_MOQ_D18_SETUP_TRANSPORT_NATIVE_QUIC)
            == XQC_MOQ_D18_SETUP_OK);
    }
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        xqc_moq_d18_setup_options_init(&options);
        options.path = (xqc_moq_d18_bytes_view_t){
            (const uint8_t *)invalid[i], strlen(invalid[i]), 1,
        };
        XQC_TEST_ASSERT(xqc_moq_d18_setup_options_validate(&options,
            XQC_MOQ_D18_SETUP_SENDER_CLIENT,
            XQC_MOQ_D18_SETUP_TRANSPORT_NATIVE_QUIC)
            == XQC_MOQ_D18_SETUP_MALFORMED_PATH);
    }
    return 0;
}

static int
xqc_test_setup_authority_syntax(void)
{
    static const char *valid[] = {
        "relay.example",
        "relay.example:443",
        "user:pass@relay.example",
        "[::1]",
        "[2001:db8::1]:443",
        "[v1.fe80]:443",
        "percent%2dhost.example:",
    };
    static const char *invalid[] = {
        "",
        ":443",
        "user@:443",
        "two@@relay.example",
        "relay.example/path",
        "relay.example?query",
        "relay.example#fragment",
        "relay example",
        "percent%2",
        "[::1",
        "[1:2:3]:443",
        "[v.fe80]:443",
        "[::1]extra",
        "relay.example:port",
        "relay.example:65536",
    };
    xqc_moq_d18_setup_options_t options;

    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); i++) {
        xqc_moq_d18_setup_options_init(&options);
        options.authority = (xqc_moq_d18_bytes_view_t){
            (const uint8_t *)valid[i], strlen(valid[i]), 1,
        };
        XQC_TEST_ASSERT(xqc_moq_d18_setup_options_validate(&options,
            XQC_MOQ_D18_SETUP_SENDER_CLIENT,
            XQC_MOQ_D18_SETUP_TRANSPORT_NATIVE_QUIC)
            == XQC_MOQ_D18_SETUP_OK);
    }
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        xqc_moq_d18_setup_options_init(&options);
        options.authority = (xqc_moq_d18_bytes_view_t){
            (const uint8_t *)invalid[i], strlen(invalid[i]), 1,
        };
        XQC_TEST_ASSERT(xqc_moq_d18_setup_options_validate(&options,
            XQC_MOQ_D18_SETUP_SENDER_CLIENT,
            XQC_MOQ_D18_SETUP_TRANSPORT_NATIVE_QUIC)
            == XQC_MOQ_D18_SETUP_MALFORMED_AUTHORITY);
    }
    return 0;
}

static int
xqc_test_setup_option_scope(void)
{
    xqc_moq_d18_setup_options_t options;

    xqc_moq_d18_setup_options_init(&options);
    options.path = (xqc_moq_d18_bytes_view_t){
        (const uint8_t *)"/", 1, 1,
    };
    XQC_TEST_ASSERT(xqc_moq_d18_setup_options_validate(&options,
        XQC_MOQ_D18_SETUP_SENDER_SERVER,
        XQC_MOQ_D18_SETUP_TRANSPORT_NATIVE_QUIC)
        == XQC_MOQ_D18_SETUP_INVALID_PATH);
    XQC_TEST_ASSERT(xqc_moq_d18_setup_options_validate(&options,
        XQC_MOQ_D18_SETUP_SENDER_CLIENT,
        XQC_MOQ_D18_SETUP_TRANSPORT_WEBTRANSPORT)
        == XQC_MOQ_D18_SETUP_INVALID_PATH);

    xqc_moq_d18_setup_options_init(&options);
    options.authority = (xqc_moq_d18_bytes_view_t){
        (const uint8_t *)"relay.example", 13, 1,
    };
    XQC_TEST_ASSERT(xqc_moq_d18_setup_options_validate(&options,
        XQC_MOQ_D18_SETUP_SENDER_SERVER,
        XQC_MOQ_D18_SETUP_TRANSPORT_NATIVE_QUIC)
        == XQC_MOQ_D18_SETUP_INVALID_AUTHORITY);
    XQC_TEST_ASSERT(xqc_moq_d18_setup_options_validate(&options,
        XQC_MOQ_D18_SETUP_SENDER_CLIENT,
        XQC_MOQ_D18_SETUP_TRANSPORT_WEBTRANSPORT)
        == XQC_MOQ_D18_SETUP_INVALID_AUTHORITY);

    xqc_moq_d18_setup_options_init(&options);
    XQC_TEST_ASSERT(xqc_moq_d18_setup_options_validate(&options,
        XQC_MOQ_D18_SETUP_SENDER_CLIENT,
        XQC_MOQ_D18_SETUP_TRANSPORT_NATIVE_QUIC)
        == XQC_MOQ_D18_SETUP_OK);
    XQC_TEST_ASSERT(xqc_moq_d18_setup_options_validate(&options,
        XQC_MOQ_D18_SETUP_SENDER_SERVER,
        XQC_MOQ_D18_SETUP_TRANSPORT_NATIVE_QUIC)
        == XQC_MOQ_D18_SETUP_OK);
    return 0;
}

static int
xqc_test_setup_result_error_mapping(void)
{
    XQC_TEST_ASSERT(xqc_moq_d18_setup_result_session_error(
        XQC_MOQ_D18_SETUP_PROTOCOL_VIOLATION)
        == XQC_MOQ_D18_PROTOCOL_VIOLATION);
    XQC_TEST_ASSERT(xqc_moq_d18_setup_result_session_error(
        XQC_MOQ_D18_SETUP_DUPLICATE)
        == XQC_MOQ_D18_PROTOCOL_VIOLATION);
    XQC_TEST_ASSERT(xqc_moq_d18_setup_result_session_error(
        XQC_MOQ_D18_SETUP_FORMATTING)
        == XQC_MOQ_D18_KEY_VALUE_FORMATTING_ERROR);
    XQC_TEST_ASSERT(xqc_moq_d18_setup_result_session_error(
        XQC_MOQ_D18_SETUP_NO_MEMORY) == XQC_MOQ_D18_INTERNAL_ERROR);
    XQC_TEST_ASSERT(xqc_moq_d18_setup_result_session_error(
        XQC_MOQ_D18_SETUP_INVALID_PATH) == XQC_MOQ_D18_INVALID_PATH);
    XQC_TEST_ASSERT(xqc_moq_d18_setup_result_session_error(
        XQC_MOQ_D18_SETUP_MALFORMED_PATH) == XQC_MOQ_D18_MALFORMED_PATH);
    XQC_TEST_ASSERT(xqc_moq_d18_setup_result_session_error(
        XQC_MOQ_D18_SETUP_INVALID_AUTHORITY)
        == XQC_MOQ_D18_INVALID_AUTHORITY);
    XQC_TEST_ASSERT(xqc_moq_d18_setup_result_session_error(
        XQC_MOQ_D18_SETUP_MALFORMED_AUTHORITY)
        == XQC_MOQ_D18_MALFORMED_AUTHORITY);
    return 0;
}

static int
xqc_test_session_retains_peer_setup_metadata(void)
{
    uint8_t path[] = "/live";
    uint8_t authority[] = "relay.example";
    uint8_t implementation[] = "peer/1.0";
    xqc_moq_d18_setup_options_t options;
    xqc_moq_session_t session = {0};

    xqc_moq_d18_setup_options_init(&options);
    options.path = (xqc_moq_d18_bytes_view_t){
        path, sizeof(path) - 1, 1,
    };
    options.authority = (xqc_moq_d18_bytes_view_t){
        authority, sizeof(authority) - 1, 1,
    };
    options.implementation = (xqc_moq_d18_bytes_view_t){
        implementation, sizeof(implementation) - 1, 1,
    };
    options.has_max_auth_token_cache_size = 1;
    options.max_auth_token_cache_size = 4096;

    XQC_TEST_ASSERT(xqc_moq_session_store_peer_setup_options(
        &session, &options) == 0);
    XQC_TEST_ASSERT(session.peer_setup_path_present == 1);
    XQC_TEST_ASSERT(session.peer_setup_path_len == sizeof(path) - 1);
    XQC_TEST_ASSERT(memcmp(session.peer_setup_path, path,
                           sizeof(path) - 1) == 0);
    XQC_TEST_ASSERT(session.peer_setup_authority_present == 1);
    XQC_TEST_ASSERT(session.peer_setup_authority_len
                    == sizeof(authority) - 1);
    XQC_TEST_ASSERT(memcmp(session.peer_setup_authority, authority,
                           sizeof(authority) - 1) == 0);
    XQC_TEST_ASSERT(session.peer_setup_implementation_present == 1);
    XQC_TEST_ASSERT(session.peer_setup_implementation_len
                    == sizeof(implementation) - 1);
    XQC_TEST_ASSERT(session.peer_max_auth_token_cache_size == 4096);
    XQC_TEST_ASSERT(session.peer_has_max_auth_token_cache_size == 1);

    path[1] = 'X';
    authority[0] = 'X';
    implementation[0] = 'X';
    XQC_TEST_ASSERT(session.peer_setup_path[1] == 'l');
    XQC_TEST_ASSERT(session.peer_setup_authority[0] == 'r');
    XQC_TEST_ASSERT(session.peer_setup_implementation[0] == 'p');

    xqc_moq_session_clear_peer_setup_options(&session);
    XQC_TEST_ASSERT(session.peer_setup_path == NULL);
    XQC_TEST_ASSERT(session.peer_setup_authority == NULL);
    XQC_TEST_ASSERT(session.peer_setup_implementation == NULL);
    XQC_TEST_ASSERT(session.peer_setup_path_present == 0);
    return 0;
}

static int
xqc_test_auth_token_codec(void)
{
    static const uint8_t encoded[][5] = {
        {0x00, 0x07},
        {0x01, 0x07, 0x02, 'a', 'b'},
        {0x02, 0x07},
        {0x03, 0x02, 'a', 'b'},
    };
    static const size_t encoded_len[] = {2, 5, 2, 4};
    xqc_moq_d18_auth_token_t token;
    uint8_t buf[16] = {0};

    for (uint64_t alias_type = XQC_MOQ_D18_AUTH_DELETE;
         alias_type <= XQC_MOQ_D18_AUTH_USE_VALUE; alias_type++)
    {
        XQC_TEST_ASSERT(xqc_moq_d18_auth_token_decode(encoded[alias_type],
            encoded_len[alias_type], &token) == XQC_MOQ_D18_AUTH_OK);
        XQC_TEST_ASSERT(token.alias_type == alias_type);
        if (alias_type == XQC_MOQ_D18_AUTH_DELETE
            || alias_type == XQC_MOQ_D18_AUTH_USE_ALIAS)
        {
            XQC_TEST_ASSERT(token.has_alias == 1);
            XQC_TEST_ASSERT(token.token_alias == 7);
            XQC_TEST_ASSERT(token.has_token_type == 0);
            XQC_TEST_ASSERT(token.token_value_len == 0);

        } else if (alias_type == XQC_MOQ_D18_AUTH_REGISTER) {
            XQC_TEST_ASSERT(token.has_alias == 1);
            XQC_TEST_ASSERT(token.token_alias == 7);
            XQC_TEST_ASSERT(token.has_token_type == 1);
            XQC_TEST_ASSERT(token.token_type == 2);
            XQC_TEST_ASSERT(token.token_value_len == 2);
            XQC_TEST_ASSERT(memcmp(token.token_value, "ab", 2) == 0);

        } else {
            XQC_TEST_ASSERT(token.has_alias == 0);
            XQC_TEST_ASSERT(token.has_token_type == 1);
            XQC_TEST_ASSERT(token.token_type == 2);
            XQC_TEST_ASSERT(token.token_value_len == 2);
            XQC_TEST_ASSERT(memcmp(token.token_value, "ab", 2) == 0);
        }

        size_t length = 0;
        size_t written = 0;
        XQC_TEST_ASSERT(xqc_moq_d18_auth_token_encoded_length(
            &token, &length) == XQC_MOQ_D18_AUTH_OK);
        XQC_TEST_ASSERT(length == encoded_len[alias_type]);
        XQC_TEST_ASSERT(xqc_moq_d18_auth_token_encode(&token, buf,
            sizeof(buf), &written) == XQC_MOQ_D18_AUTH_OK);
        XQC_TEST_ASSERT(written == encoded_len[alias_type]);
        XQC_TEST_ASSERT(memcmp(buf, encoded[alias_type], written) == 0);
    }
    return 0;
}

static int
xqc_test_auth_token_malformed(void)
{
    static const uint8_t unknown_type[] = {0x04};
    static const uint8_t truncated_delete[] = {0x00};
    static const uint8_t truncated_register_alias[] = {0x01};
    static const uint8_t truncated_register_type[] = {0x01, 0x07};
    static const uint8_t truncated_use_alias[] = {0x02};
    static const uint8_t truncated_use_value[] = {0x03};
    static const uint8_t trailing_delete[] = {0x00, 0x07, 0x00};
    static const uint8_t trailing_use_alias[] = {0x02, 0x07, 0x00};
    xqc_moq_d18_auth_token_t token;
    size_t length = 0;
    size_t written = 0;
    uint8_t buf[16] = {0};

#define XQC_TEST_AUTH_FORMATTING(value) \
    XQC_TEST_ASSERT(xqc_moq_d18_auth_token_decode( \
        (value), sizeof(value), &token) == XQC_MOQ_D18_AUTH_FORMATTING)

    XQC_TEST_ASSERT(xqc_moq_d18_auth_token_decode(NULL, 0, &token)
                    == XQC_MOQ_D18_AUTH_FORMATTING);
    XQC_TEST_AUTH_FORMATTING(unknown_type);
    XQC_TEST_AUTH_FORMATTING(truncated_delete);
    XQC_TEST_AUTH_FORMATTING(truncated_register_alias);
    XQC_TEST_AUTH_FORMATTING(truncated_register_type);
    XQC_TEST_AUTH_FORMATTING(truncated_use_alias);
    XQC_TEST_AUTH_FORMATTING(truncated_use_value);
    XQC_TEST_AUTH_FORMATTING(trailing_delete);
    XQC_TEST_AUTH_FORMATTING(trailing_use_alias);
#undef XQC_TEST_AUTH_FORMATTING

    memset(&token, 0, sizeof(token));
    token.alias_type = XQC_MOQ_D18_AUTH_USE_VALUE;
    token.has_token_type = 1;
    token.token_type = 2;
    token.token_value_len = 1;
    XQC_TEST_ASSERT(xqc_moq_d18_auth_token_encoded_length(
        &token, &length) == XQC_MOQ_D18_AUTH_INVALID_ARGUMENT);
    XQC_TEST_ASSERT(xqc_moq_d18_auth_token_encode(&token, buf,
        sizeof(buf), &written) == XQC_MOQ_D18_AUTH_INVALID_ARGUMENT);
    return 0;
}

static xqc_moq_d18_auth_token_t
xqc_test_auth_token(uint64_t alias_type, uint64_t alias,
    uint64_t token_type, const char *value)
{
    xqc_moq_d18_auth_token_t token = {
        .alias_type = alias_type,
        .token_alias = alias,
        .token_type = token_type,
        .token_value = (const uint8_t *)value,
        .token_value_len = value == NULL ? 0 : strlen(value),
        .has_alias = alias_type != XQC_MOQ_D18_AUTH_USE_VALUE,
        .has_token_type = alias_type == XQC_MOQ_D18_AUTH_REGISTER
            || alias_type == XQC_MOQ_D18_AUTH_USE_VALUE,
    };
    return token;
}

static int
xqc_test_auth_cache_lifecycle(void)
{
    xqc_moq_d18_auth_cache_t cache;
    xqc_moq_d18_auth_token_t resolved;
    uint8_t registered = 0;
    xqc_moq_d18_auth_token_t token = xqc_test_auth_token(
        XQC_MOQ_D18_AUTH_REGISTER, 7, 2, "ab");

    xqc_moq_d18_auth_cache_init(&cache, 64);
    XQC_TEST_ASSERT(xqc_moq_d18_auth_cache_apply(&cache, &token, 0, 0,
        &resolved, &registered) == XQC_MOQ_D18_AUTH_OK);
    XQC_TEST_ASSERT(registered == 1);
    XQC_TEST_ASSERT(cache.current_size == 18);
    XQC_TEST_ASSERT(resolved.token_type == 2);
    XQC_TEST_ASSERT(resolved.token_value_len == 2);
    XQC_TEST_ASSERT(memcmp(resolved.token_value, "ab", 2) == 0);

    XQC_TEST_ASSERT(xqc_moq_d18_auth_cache_apply(&cache, &token, 0, 0,
        &resolved, &registered) == XQC_MOQ_D18_AUTH_DUPLICATE_ALIAS);
    XQC_TEST_ASSERT(cache.current_size == 18);

    token = xqc_test_auth_token(
        XQC_MOQ_D18_AUTH_USE_ALIAS, 7, 0, NULL);
    XQC_TEST_ASSERT(xqc_moq_d18_auth_cache_apply(&cache, &token, 0, 0,
        &resolved, &registered) == XQC_MOQ_D18_AUTH_OK);
    XQC_TEST_ASSERT(registered == 0);
    XQC_TEST_ASSERT(resolved.token_type == 2);
    XQC_TEST_ASSERT(memcmp(resolved.token_value, "ab", 2) == 0);

    token = xqc_test_auth_token(XQC_MOQ_D18_AUTH_DELETE, 7, 0, NULL);
    XQC_TEST_ASSERT(xqc_moq_d18_auth_cache_apply(&cache, &token, 0, 0,
        &resolved, &registered) == XQC_MOQ_D18_AUTH_OK);
    XQC_TEST_ASSERT(cache.current_size == 0);

    token = xqc_test_auth_token(
        XQC_MOQ_D18_AUTH_USE_ALIAS, 7, 0, NULL);
    XQC_TEST_ASSERT(xqc_moq_d18_auth_cache_apply(&cache, &token, 0, 0,
        &resolved, &registered) == XQC_MOQ_D18_AUTH_UNKNOWN_ALIAS);
    token = xqc_test_auth_token(XQC_MOQ_D18_AUTH_DELETE, 7, 0, NULL);
    XQC_TEST_ASSERT(xqc_moq_d18_auth_cache_apply(&cache, &token, 0, 0,
        &resolved, &registered) == XQC_MOQ_D18_AUTH_UNKNOWN_ALIAS);

    token = xqc_test_auth_token(
        XQC_MOQ_D18_AUTH_REGISTER, 7, 2, "ab");
    XQC_TEST_ASSERT(xqc_moq_d18_auth_cache_apply(&cache, &token, 0, 0,
        &resolved, &registered) == XQC_MOQ_D18_AUTH_OK);
    XQC_TEST_ASSERT(cache.current_size == 18);
    xqc_moq_d18_auth_cache_destroy(&cache);
    XQC_TEST_ASSERT(cache.current_size == 0);
    XQC_TEST_ASSERT(xqc_list_empty(&cache.entries));
    return 0;
}

static int
xqc_test_auth_cache_setup_rules(void)
{
    xqc_moq_d18_auth_cache_t cache;
    xqc_moq_d18_auth_token_t resolved;
    uint8_t registered = 0;
    xqc_moq_d18_auth_token_t token = xqc_test_auth_token(
        XQC_MOQ_D18_AUTH_REGISTER, 7, 2, "ab");

    xqc_moq_d18_auth_cache_init(&cache, 17);
    XQC_TEST_ASSERT(xqc_moq_d18_auth_cache_apply(&cache, &token, 0, 0,
        &resolved, &registered) == XQC_MOQ_D18_AUTH_CACHE_OVERFLOW);
    XQC_TEST_ASSERT(cache.current_size == 0);

    XQC_TEST_ASSERT(xqc_moq_d18_auth_cache_apply(&cache, &token, 1, 1,
        &resolved, &registered) == XQC_MOQ_D18_AUTH_OK);
    XQC_TEST_ASSERT(registered == 0);
    XQC_TEST_ASSERT(cache.current_size == 0);
    XQC_TEST_ASSERT(resolved.alias_type == XQC_MOQ_D18_AUTH_USE_VALUE);
    XQC_TEST_ASSERT(resolved.has_alias == 0);
    XQC_TEST_ASSERT(resolved.token_type == 2);

    token = xqc_test_auth_token(
        XQC_MOQ_D18_AUTH_USE_ALIAS, 7, 0, NULL);
    XQC_TEST_ASSERT(xqc_moq_d18_auth_cache_apply(&cache, &token, 1, 1,
        &resolved, &registered)
        == XQC_MOQ_D18_AUTH_PROTOCOL_VIOLATION);
    token = xqc_test_auth_token(XQC_MOQ_D18_AUTH_DELETE, 7, 0, NULL);
    XQC_TEST_ASSERT(xqc_moq_d18_auth_cache_apply(&cache, &token, 1, 1,
        &resolved, &registered)
        == XQC_MOQ_D18_AUTH_PROTOCOL_VIOLATION);

    token = xqc_test_auth_token(
        XQC_MOQ_D18_AUTH_USE_VALUE, 0, 2, "ab");
    XQC_TEST_ASSERT(xqc_moq_d18_auth_cache_apply(&cache, &token, 0, 0,
        &resolved, &registered) == XQC_MOQ_D18_AUTH_OK);
    XQC_TEST_ASSERT(cache.current_size == 0);
    XQC_TEST_ASSERT(registered == 0);
    xqc_moq_d18_auth_cache_destroy(&cache);
    return 0;
}

static void
xqc_test_session_auth_init(xqc_moq_session_t *session, uint64_t limit)
{
    memset(session, 0, sizeof(*session));
    xqc_moq_d18_auth_cache_init(&session->peer_auth_cache, limit);
}

static void
xqc_test_session_auth_destroy(xqc_moq_session_t *session)
{
    xqc_moq_session_clear_peer_setup_auth_tokens(session);
    xqc_moq_d18_auth_cache_destroy(&session->peer_auth_cache);
}

static int
xqc_test_session_processes_setup_auth_tokens(void)
{
    uint8_t use_value[] = {0x03, 0x02, 'a', 'b'};
    uint8_t register_value[] = {
        0x01, 0x07, 0x04, 'c', 'd',
    };
    xqc_moq_d18_bytes_view_t tokens[] = {
        {use_value, sizeof(use_value), 1},
        {register_value, sizeof(register_value), 1},
    };
    xqc_moq_d18_setup_options_t options;
    xqc_moq_session_t session;
    uint64_t token_type = 0;
    const uint8_t *token_value = NULL;
    size_t token_value_len = 0;

    xqc_moq_d18_setup_options_init(&options);
    options.authorization_tokens = tokens;
    options.authorization_token_count = 2;

    xqc_test_session_auth_init(&session, 0);
    XQC_TEST_ASSERT(xqc_moq_session_process_peer_setup_auth(
        &session, &options, 1) == XQC_MOQ_D18_NO_ERROR);
    XQC_TEST_ASSERT(session.peer_auth_cache.current_size == 0);
    XQC_TEST_ASSERT(xqc_moq_session_get_peer_setup_auth_token_count(
        &session) == 2);
    XQC_TEST_ASSERT(xqc_moq_session_get_peer_setup_auth_token(
        &session, 0, &token_type, &token_value, &token_value_len)
        == XQC_OK);
    XQC_TEST_ASSERT(token_type == 2);
    XQC_TEST_ASSERT(token_value_len == 2);
    XQC_TEST_ASSERT(memcmp(token_value, "ab", 2) == 0);
    XQC_TEST_ASSERT(xqc_moq_session_get_peer_setup_auth_token(
        &session, 1, &token_type, &token_value, &token_value_len)
        == XQC_OK);
    XQC_TEST_ASSERT(token_type == 4);
    XQC_TEST_ASSERT(token_value_len == 2);
    XQC_TEST_ASSERT(memcmp(token_value, "cd", 2) == 0);
    use_value[2] = 'X';
    register_value[3] = 'Y';
    XQC_TEST_ASSERT(xqc_moq_session_get_peer_setup_auth_token(
        &session, 0, &token_type, &token_value, &token_value_len)
        == XQC_OK);
    XQC_TEST_ASSERT(memcmp(token_value, "ab", 2) == 0);
    XQC_TEST_ASSERT(xqc_moq_session_get_peer_setup_auth_token(
        &session, 1, &token_type, &token_value, &token_value_len)
        == XQC_OK);
    XQC_TEST_ASSERT(memcmp(token_value, "cd", 2) == 0);
    XQC_TEST_ASSERT(xqc_moq_session_get_peer_setup_auth_token(
        &session, 2, &token_type, &token_value, &token_value_len)
        == -XQC_EPARAM);
    xqc_test_session_auth_destroy(&session);

    use_value[2] = 'a';
    register_value[3] = 'c';
    xqc_test_session_auth_init(&session, 64);
    XQC_TEST_ASSERT(xqc_moq_session_process_peer_setup_auth(
        &session, &options, 1) == XQC_MOQ_D18_NO_ERROR);
    XQC_TEST_ASSERT(session.peer_auth_cache.current_size == 18);
    XQC_TEST_ASSERT(xqc_moq_session_get_peer_setup_auth_token_count(
        &session) == 2);
    xqc_test_session_auth_destroy(&session);
    return 0;
}

static uint64_t
xqc_test_process_one_setup_token(const uint8_t *encoded, size_t encoded_len,
    uint64_t cache_limit, uint8_t receiver_is_server)
{
    xqc_moq_d18_bytes_view_t token = {encoded, encoded_len, 1};
    xqc_moq_d18_setup_options_t options;
    xqc_moq_session_t session;

    xqc_moq_d18_setup_options_init(&options);
    options.authorization_tokens = &token;
    options.authorization_token_count = 1;
    xqc_test_session_auth_init(&session, cache_limit);
    uint64_t error = xqc_moq_session_process_peer_setup_auth(
        &session, &options, receiver_is_server);
    xqc_test_session_auth_destroy(&session);
    return error;
}

static int
xqc_test_session_setup_auth_error_mapping(void)
{
    static const uint8_t malformed[] = {0x03};
    static const uint8_t use_alias[] = {0x02, 0x07};
    static const uint8_t delete_alias[] = {0x00, 0x07};

    XQC_TEST_ASSERT(xqc_test_process_one_setup_token(
        malformed, sizeof(malformed), 64, 0)
        == XQC_MOQ_D18_KEY_VALUE_FORMATTING_ERROR);
    XQC_TEST_ASSERT(xqc_test_process_one_setup_token(
        use_alias, sizeof(use_alias), 64, 0)
        == XQC_MOQ_D18_UNKNOWN_AUTH_TOKEN_ALIAS);
    XQC_TEST_ASSERT(xqc_test_process_one_setup_token(
        use_alias, sizeof(use_alias), 64, 1)
        == XQC_MOQ_D18_PROTOCOL_VIOLATION);
    XQC_TEST_ASSERT(xqc_test_process_one_setup_token(
        delete_alias, sizeof(delete_alias), 64, 1)
        == XQC_MOQ_D18_PROTOCOL_VIOLATION);

    XQC_TEST_ASSERT(xqc_moq_session_auth_result_error(
        XQC_MOQ_D18_AUTH_CACHE_OVERFLOW)
        == XQC_MOQ_D18_AUTH_TOKEN_CACHE_OVERFLOW);
    XQC_TEST_ASSERT(xqc_moq_session_auth_result_error(
        XQC_MOQ_D18_AUTH_DUPLICATE_ALIAS)
        == XQC_MOQ_D18_DUPLICATE_AUTH_TOKEN_ALIAS);
    return 0;
}

static int
xqc_test_session_rejects_duplicate_setup_auth_values(void)
{
    static const uint8_t register_value[] = {
        0x01, 0x07, 0x02, 'a', 'b',
    };
    static const uint8_t register_duplicate_alias[] = {
        0x01, 0x07, 0x02, 'c', 'd',
    };
    static const uint8_t use_alias[] = {0x02, 0x07};
    static const uint8_t use_value_other[] = {0x03, 0x02, 'c', 'd'};
    xqc_moq_d18_bytes_view_t duplicate_alias_tokens[] = {
        {register_value, sizeof(register_value), 1},
        {register_duplicate_alias, sizeof(register_duplicate_alias), 1},
    };
    xqc_moq_d18_bytes_view_t duplicate_tokens[] = {
        {register_value, sizeof(register_value), 1},
        {use_alias, sizeof(use_alias), 1},
    };
    xqc_moq_d18_bytes_view_t distinct_tokens[] = {
        {register_value, sizeof(register_value), 1},
        {use_value_other, sizeof(use_value_other), 1},
    };
    xqc_moq_d18_setup_options_t options;
    xqc_moq_session_t session;
    uint64_t token_type = 0;
    const uint8_t *token_value = NULL;
    size_t token_value_len = 0;

    xqc_moq_d18_setup_options_init(&options);
    options.authorization_tokens = duplicate_alias_tokens;
    options.authorization_token_count = 2;
    xqc_test_session_auth_init(&session, 64);
    XQC_TEST_ASSERT(xqc_moq_session_process_peer_setup_auth(
        &session, &options, 0) == XQC_MOQ_D18_DUPLICATE_AUTH_TOKEN_ALIAS);
    XQC_TEST_ASSERT(xqc_moq_session_get_peer_setup_auth_token_count(
        &session) == 0);
    xqc_test_session_auth_destroy(&session);

    options.authorization_tokens = duplicate_tokens;
    options.authorization_token_count = 2;
    xqc_test_session_auth_init(&session, 64);
    XQC_TEST_ASSERT(xqc_moq_session_process_peer_setup_auth(
        &session, &options, 0) == XQC_MOQ_D18_PROTOCOL_VIOLATION);
    XQC_TEST_ASSERT(xqc_moq_session_get_peer_setup_auth_token_count(
        &session) == 0);
    xqc_test_session_auth_destroy(&session);

    options.authorization_tokens = distinct_tokens;
    xqc_test_session_auth_init(&session, 64);
    XQC_TEST_ASSERT(xqc_moq_session_process_peer_setup_auth(
        &session, &options, 0) == XQC_MOQ_D18_NO_ERROR);
    XQC_TEST_ASSERT(xqc_moq_session_get_peer_setup_auth_token_count(
        &session) == 2);
    XQC_TEST_ASSERT(xqc_moq_session_get_peer_setup_auth_token(
        &session, 1, &token_type, &token_value, &token_value_len)
        == XQC_OK);
    XQC_TEST_ASSERT(token_type == 2);
    XQC_TEST_ASSERT(token_value_len == 2);
    XQC_TEST_ASSERT(memcmp(token_value, "cd", 2) == 0);
    xqc_test_session_auth_destroy(&session);
    return 0;
}

static int
xqc_test_draft18_setup_config_wire(void)
{
    static const uint8_t expected[] = {
        0x01, 0x01, '/',
        0x02, 0x04, 0x03, 0x02, 'a', 'b',
        0x00, 0x04, 0x03, 0x04, 'c', 'd',
        0x01, 0x40,
        0x01, 0x09, 'r', 'e', 'l', 'a', 'y', ':', '4', '4', '3',
        0x02, 0x09, 'x', 'q', 'u', 'i', 'c', '/', '1', '.', '0',
    };
    static const uint8_t first_value[] = {'a', 'b'};
    static const uint8_t second_value[] = {'c', 'd'};
    xqc_moq_draft18_auth_token_t auth_tokens[] = {
        {
            .alias_type = XQC_MOQ_DRAFT18_AUTH_USE_VALUE,
            .token_type = 2,
            .token_value = first_value,
            .token_value_len = sizeof(first_value),
        },
        {
            .alias_type = XQC_MOQ_DRAFT18_AUTH_USE_VALUE,
            .token_type = 4,
            .token_value = second_value,
            .token_value_len = sizeof(second_value),
        },
    };
    xqc_moq_draft18_setup_config_t config = {
        .authority = "relay:443",
        .path = "/",
        .implementation = "xquic/1.0",
        .has_max_auth_token_cache_size = 1,
        .max_auth_token_cache_size = 64,
        .authorization_tokens = auth_tokens,
        .authorization_token_count = 2,
    };
    uint8_t *encoded = NULL;
    size_t encoded_len = 0;

    XQC_TEST_ASSERT(xqc_moq_session_encode_draft18_setup_config(
        &config, XQC_MOQ_D18_SETUP_SENDER_CLIENT,
        XQC_MOQ_D18_SETUP_TRANSPORT_NATIVE_QUIC,
        &encoded, &encoded_len) == XQC_OK);
    XQC_TEST_ASSERT(encoded_len == sizeof(expected));
    XQC_TEST_ASSERT(memcmp(encoded, expected, sizeof(expected)) == 0);

    xqc_moq_d18_setup_options_t decoded;
    xqc_moq_d18_auth_token_t decoded_token;
    xqc_moq_d18_setup_options_init(&decoded);
    XQC_TEST_ASSERT(xqc_moq_d18_setup_options_decode(
        encoded, encoded_len, &decoded) == XQC_MOQ_D18_SETUP_OK);
    XQC_TEST_ASSERT(decoded.authorization_token_count == 2);
    XQC_TEST_ASSERT(xqc_moq_d18_auth_token_decode(
        decoded.authorization_tokens[0].data,
        decoded.authorization_tokens[0].len,
        &decoded_token) == XQC_MOQ_D18_AUTH_OK);
    XQC_TEST_ASSERT(decoded_token.alias_type
                    == XQC_MOQ_D18_AUTH_USE_VALUE);
    XQC_TEST_ASSERT(decoded_token.token_type == 2);
    XQC_TEST_ASSERT(memcmp(decoded_token.token_value, "ab", 2) == 0);
    xqc_moq_d18_setup_options_destroy(&decoded);
    xqc_free(encoded);
    return 0;
}

static int
xqc_test_draft18_setup_config_rejections(void)
{
    uint8_t large_value[XQC_MOQ_D18_KV_MAX_BYTES] = {0};
    xqc_moq_draft18_auth_token_t token = {
        .alias_type = XQC_MOQ_DRAFT18_AUTH_DELETE,
        .token_alias = 7,
    };
    xqc_moq_draft18_setup_config_t config = {
        .authority = "relay:443",
        .path = "/",
        .authorization_tokens = &token,
        .authorization_token_count = 1,
    };
    uint8_t *encoded = NULL;
    size_t encoded_len = 0;

    XQC_TEST_ASSERT(xqc_moq_session_encode_draft18_setup_config(
        &config, XQC_MOQ_D18_SETUP_SENDER_CLIENT,
        XQC_MOQ_D18_SETUP_TRANSPORT_NATIVE_QUIC,
        &encoded, &encoded_len) == -XQC_EPARAM);
    token.alias_type = XQC_MOQ_DRAFT18_AUTH_USE_ALIAS;
    XQC_TEST_ASSERT(xqc_moq_session_encode_draft18_setup_config(
        &config, XQC_MOQ_D18_SETUP_SENDER_CLIENT,
        XQC_MOQ_D18_SETUP_TRANSPORT_NATIVE_QUIC,
        &encoded, &encoded_len) == -XQC_EPARAM);

    config.authorization_token_count = 0;
    config.path = "relative";
    XQC_TEST_ASSERT(xqc_moq_session_encode_draft18_setup_config(
        &config, XQC_MOQ_D18_SETUP_SENDER_CLIENT,
        XQC_MOQ_D18_SETUP_TRANSPORT_NATIVE_QUIC,
        &encoded, &encoded_len) == -XQC_EPARAM);
    config.path = "/";
    config.authority = "two@@relay";
    XQC_TEST_ASSERT(xqc_moq_session_encode_draft18_setup_config(
        &config, XQC_MOQ_D18_SETUP_SENDER_CLIENT,
        XQC_MOQ_D18_SETUP_TRANSPORT_NATIVE_QUIC,
        &encoded, &encoded_len) == -XQC_EPARAM);

    config.authority = "relay:443";
    config.authorization_tokens = NULL;
    config.authorization_token_count = 1;
    XQC_TEST_ASSERT(xqc_moq_session_encode_draft18_setup_config(
        &config, XQC_MOQ_D18_SETUP_SENDER_CLIENT,
        XQC_MOQ_D18_SETUP_TRANSPORT_NATIVE_QUIC,
        &encoded, &encoded_len) == -XQC_EPARAM);

    token.alias_type = XQC_MOQ_DRAFT18_AUTH_USE_VALUE;
    token.token_type = 2;
    token.token_value = large_value;
    token.token_value_len = sizeof(large_value);
    config.authorization_tokens = &token;
    XQC_TEST_ASSERT(xqc_moq_session_encode_draft18_setup_config(
        &config, XQC_MOQ_D18_SETUP_SENDER_CLIENT,
        XQC_MOQ_D18_SETUP_TRANSPORT_NATIVE_QUIC,
        &encoded, &encoded_len) == -XQC_ELIMIT);

    token.alias_type = XQC_MOQ_DRAFT18_AUTH_REGISTER;
    token.token_alias = 7;
    token.token_value = (const uint8_t *)"ab";
    token.token_value_len = 2;
    config.authority = NULL;
    config.path = NULL;
    config.implementation = "xquic/1.0";
    XQC_TEST_ASSERT(xqc_moq_session_encode_draft18_setup_config(
        &config, XQC_MOQ_D18_SETUP_SENDER_SERVER,
        XQC_MOQ_D18_SETUP_TRANSPORT_NATIVE_QUIC,
        &encoded, &encoded_len) == XQC_OK);
    xqc_free(encoded);
    encoded = NULL;
    config.path = "/";
    XQC_TEST_ASSERT(xqc_moq_session_encode_draft18_setup_config(
        &config, XQC_MOQ_D18_SETUP_SENDER_SERVER,
        XQC_MOQ_D18_SETUP_TRANSPORT_NATIVE_QUIC,
        &encoded, &encoded_len) == -XQC_EPARAM);
    return 0;
}

int
main(void)
{
    if (xqc_test_kv_parse_golden_vector() != 0
        || xqc_test_kv_parse_malformed_vectors() != 0
        || xqc_test_kv_write_golden_vector() != 0
        || xqc_test_kv_writer_rejections_do_not_mutate() != 0
        || xqc_test_setup_decode_known_options() != 0
        || xqc_test_setup_repeated_authorization_tokens() != 0
        || xqc_test_setup_duplicate_rules() != 0
        || xqc_test_setup_structural_error_mapping() != 0
        || xqc_test_setup_typed_writer_roundtrip() != 0
        || xqc_test_setup_path_syntax() != 0
        || xqc_test_setup_authority_syntax() != 0
        || xqc_test_setup_option_scope() != 0
        || xqc_test_setup_result_error_mapping() != 0
        || xqc_test_session_retains_peer_setup_metadata() != 0
        || xqc_test_auth_token_codec() != 0
        || xqc_test_auth_token_malformed() != 0
        || xqc_test_auth_cache_lifecycle() != 0
        || xqc_test_auth_cache_setup_rules() != 0
        || xqc_test_session_processes_setup_auth_tokens() != 0
        || xqc_test_session_setup_auth_error_mapping() != 0
        || xqc_test_session_rejects_duplicate_setup_auth_values() != 0
        || xqc_test_draft18_setup_config_wire() != 0
        || xqc_test_draft18_setup_config_rejections() != 0)
    {
        return 1;
    }

    printf("moq_d18_setup_test: PASS\n");
    return 0;
}
