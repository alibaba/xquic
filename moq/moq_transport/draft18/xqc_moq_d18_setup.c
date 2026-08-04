#include "moq/moq_transport/draft18/xqc_moq_d18_setup.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_int.h"

#include <limits.h>
#include <string.h>

#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/common/xqc_malloc.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_defs.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_kv.h"

typedef struct {
    xqc_moq_d18_setup_options_t *options;
    xqc_moq_d18_setup_result_t result;
} xqc_moq_d18_setup_decode_ctx_t;

void
xqc_moq_d18_setup_options_init(xqc_moq_d18_setup_options_t *options)
{
    if (options != NULL) {
        memset(options, 0, sizeof(*options));
    }
}

void
xqc_moq_d18_setup_options_destroy(xqc_moq_d18_setup_options_t *options)
{
    if (options == NULL) {
        return;
    }
    if (options->owns_authorization_tokens) {
        xqc_free(options->authorization_tokens);
    }
    memset(options, 0, sizeof(*options));
}

static uint8_t
xqc_moq_d18_setup_option_is_known(uint64_t type)
{
    switch (type) {
    case XQC_MOQ_D18_SETUP_OPTION_PATH:
    case XQC_MOQ_D18_SETUP_OPTION_AUTHORIZATION_TOKEN:
    case XQC_MOQ_D18_SETUP_OPTION_MAX_AUTH_TOKEN_CACHE_SIZE:
    case XQC_MOQ_D18_SETUP_OPTION_AUTHORITY:
    case XQC_MOQ_D18_SETUP_OPTION_MOQT_IMPLEMENTATION:
        return 1;
    default:
        return 0;
    }
}

static xqc_moq_d18_setup_result_t
xqc_moq_d18_setup_append_token(xqc_moq_d18_setup_options_t *options,
    const xqc_moq_d18_kv_view_t *item)
{
    if (options->authorization_token_count
        == options->authorization_token_capacity)
    {
        size_t capacity = options->authorization_token_capacity == 0
            ? 4 : options->authorization_token_capacity * 2;
        if (capacity < options->authorization_token_capacity
            || capacity > SIZE_MAX / sizeof(*options->authorization_tokens))
        {
            return XQC_MOQ_D18_SETUP_NO_MEMORY;
        }
        xqc_moq_d18_bytes_view_t *tokens = xqc_realloc(
            options->authorization_tokens,
            capacity * sizeof(*options->authorization_tokens));
        if (tokens == NULL) {
            return XQC_MOQ_D18_SETUP_NO_MEMORY;
        }
        options->authorization_tokens = tokens;
        options->authorization_token_capacity = capacity;
        options->owns_authorization_tokens = 1;
    }

    xqc_moq_d18_bytes_view_t *token =
        &options->authorization_tokens[
            options->authorization_token_count++];
    token->data = item->bytes;
    token->len = item->bytes_len;
    token->present = 1;
    return XQC_MOQ_D18_SETUP_OK;
}

static xqc_moq_d18_kv_result_t
xqc_moq_d18_setup_decode_option(const xqc_moq_d18_kv_view_t *item,
    void *user_data)
{
    xqc_moq_d18_setup_decode_ctx_t *ctx = user_data;
    xqc_moq_d18_setup_options_t *options = ctx->options;

    switch (item->type) {
    case XQC_MOQ_D18_SETUP_OPTION_PATH:
        if (options->path.present) {
            ctx->result = XQC_MOQ_D18_SETUP_DUPLICATE;
            return XQC_MOQ_D18_KV_VISITOR_ERROR;
        }
        options->path = (xqc_moq_d18_bytes_view_t){
            item->bytes, item->bytes_len, 1,
        };
        break;

    case XQC_MOQ_D18_SETUP_OPTION_AUTHORIZATION_TOKEN:
        ctx->result = xqc_moq_d18_setup_append_token(options, item);
        if (ctx->result != XQC_MOQ_D18_SETUP_OK) {
            return XQC_MOQ_D18_KV_VISITOR_ERROR;
        }
        break;

    case XQC_MOQ_D18_SETUP_OPTION_MAX_AUTH_TOKEN_CACHE_SIZE:
        if (options->has_max_auth_token_cache_size) {
            ctx->result = XQC_MOQ_D18_SETUP_DUPLICATE;
            return XQC_MOQ_D18_KV_VISITOR_ERROR;
        }
        options->max_auth_token_cache_size = item->integer;
        options->has_max_auth_token_cache_size = 1;
        break;

    case XQC_MOQ_D18_SETUP_OPTION_AUTHORITY:
        if (options->authority.present) {
            ctx->result = XQC_MOQ_D18_SETUP_DUPLICATE;
            return XQC_MOQ_D18_KV_VISITOR_ERROR;
        }
        options->authority = (xqc_moq_d18_bytes_view_t){
            item->bytes, item->bytes_len, 1,
        };
        break;

    case XQC_MOQ_D18_SETUP_OPTION_MOQT_IMPLEMENTATION:
        if (options->implementation.present) {
            ctx->result = XQC_MOQ_D18_SETUP_DUPLICATE;
            return XQC_MOQ_D18_KV_VISITOR_ERROR;
        }
        options->implementation = (xqc_moq_d18_bytes_view_t){
            item->bytes, item->bytes_len, 1,
        };
        break;

    default:
        break;
    }

    return XQC_MOQ_D18_KV_OK;
}

static xqc_moq_d18_setup_result_t
xqc_moq_d18_setup_map_parse_error(xqc_moq_d18_kv_result_t result,
    const xqc_moq_d18_kv_error_t *error,
    const xqc_moq_d18_setup_decode_ctx_t *ctx)
{
    if (result == XQC_MOQ_D18_KV_VISITOR_ERROR) {
        return ctx->result;
    }
    if (result == XQC_MOQ_D18_KV_INVALID_ARGUMENT) {
        return XQC_MOQ_D18_SETUP_INVALID_ARGUMENT;
    }
    if (result == XQC_MOQ_D18_KV_TRUNCATED && error->has_type
        && xqc_moq_d18_setup_option_is_known(error->type))
    {
        return XQC_MOQ_D18_SETUP_FORMATTING;
    }
    return XQC_MOQ_D18_SETUP_PROTOCOL_VIOLATION;
}

xqc_moq_d18_setup_result_t
xqc_moq_d18_setup_options_decode(const uint8_t *block, size_t block_len,
    xqc_moq_d18_setup_options_t *options)
{
    if (options == NULL) {
        return XQC_MOQ_D18_SETUP_INVALID_ARGUMENT;
    }

    xqc_moq_d18_setup_options_destroy(options);
    xqc_moq_d18_setup_decode_ctx_t ctx = {
        .options = options,
        .result = XQC_MOQ_D18_SETUP_OK,
    };
    xqc_moq_d18_kv_error_t error;
    xqc_moq_d18_kv_result_t ret = xqc_moq_d18_kv_parse_ex(
        block, block_len, xqc_moq_d18_setup_decode_option, &ctx, &error);
    if (ret != XQC_MOQ_D18_KV_OK) {
        xqc_moq_d18_setup_result_t setup_ret =
            xqc_moq_d18_setup_map_parse_error(ret, &error, &ctx);
        xqc_moq_d18_setup_options_destroy(options);
        return setup_ret;
    }
    return XQC_MOQ_D18_SETUP_OK;
}

static xqc_moq_d18_setup_result_t
xqc_moq_d18_setup_add_length(size_t *length, uint64_t *previous_type,
    uint64_t type, uint8_t is_bytes, size_t bytes_len, uint64_t integer)
{
    if (type < *previous_type
        || (is_bytes && bytes_len > XQC_MOQ_D18_KV_MAX_BYTES))
    {
        return XQC_MOQ_D18_SETUP_INVALID_ARGUMENT;
    }

    size_t item_len = xqc_moq_d18_int_len(type - *previous_type);
    item_len += is_bytes
        ? xqc_moq_d18_int_len(bytes_len) + bytes_len
        : xqc_moq_d18_int_len(integer);
    if (item_len > UINT16_MAX - *length) {
        return XQC_MOQ_D18_SETUP_PROTOCOL_VIOLATION;
    }
    *length += item_len;
    *previous_type = type;
    return XQC_MOQ_D18_SETUP_OK;
}

static xqc_moq_d18_setup_result_t
xqc_moq_d18_setup_options_check_views(
    const xqc_moq_d18_setup_options_t *options)
{
    if ((options->path.present && options->path.len > 0
            && options->path.data == NULL)
        || (options->authority.present && options->authority.len > 0
            && options->authority.data == NULL)
        || (options->implementation.present
            && options->implementation.len > 0
            && options->implementation.data == NULL)
        || (options->authorization_token_count > 0
            && options->authorization_tokens == NULL))
    {
        return XQC_MOQ_D18_SETUP_INVALID_ARGUMENT;
    }
    for (size_t i = 0; i < options->authorization_token_count; i++) {
        const xqc_moq_d18_bytes_view_t *token =
            &options->authorization_tokens[i];
        if (token->len > 0 && token->data == NULL) {
            return XQC_MOQ_D18_SETUP_INVALID_ARGUMENT;
        }
    }
    return XQC_MOQ_D18_SETUP_OK;
}

xqc_moq_d18_setup_result_t
xqc_moq_d18_setup_options_encoded_length(
    const xqc_moq_d18_setup_options_t *options, size_t *encoded_len)
{
    if (options == NULL || encoded_len == NULL) {
        return XQC_MOQ_D18_SETUP_INVALID_ARGUMENT;
    }
    xqc_moq_d18_setup_result_t ret =
        xqc_moq_d18_setup_options_check_views(options);
    if (ret != XQC_MOQ_D18_SETUP_OK) {
        return ret;
    }

    size_t length = 0;
    uint64_t previous_type = 0;
#define XQC_MOQ_D18_ADD_BYTES(view, type_value) \
    do { \
        if ((view).present) { \
            ret = xqc_moq_d18_setup_add_length(&length, &previous_type, \
                (type_value), 1, (view).len, 0); \
            if (ret != XQC_MOQ_D18_SETUP_OK) { \
                return ret; \
            } \
        } \
    } while (0)

    XQC_MOQ_D18_ADD_BYTES(options->path, XQC_MOQ_D18_SETUP_OPTION_PATH);
    for (size_t i = 0; i < options->authorization_token_count; i++) {
        xqc_moq_d18_bytes_view_t token = options->authorization_tokens[i];
        token.present = 1;
        XQC_MOQ_D18_ADD_BYTES(token,
            XQC_MOQ_D18_SETUP_OPTION_AUTHORIZATION_TOKEN);
    }
    if (options->has_max_auth_token_cache_size) {
        ret = xqc_moq_d18_setup_add_length(&length, &previous_type,
            XQC_MOQ_D18_SETUP_OPTION_MAX_AUTH_TOKEN_CACHE_SIZE, 0, 0,
            options->max_auth_token_cache_size);
        if (ret != XQC_MOQ_D18_SETUP_OK) {
            return ret;
        }
    }
    XQC_MOQ_D18_ADD_BYTES(options->authority,
                          XQC_MOQ_D18_SETUP_OPTION_AUTHORITY);
    XQC_MOQ_D18_ADD_BYTES(options->implementation,
                          XQC_MOQ_D18_SETUP_OPTION_MOQT_IMPLEMENTATION);
#undef XQC_MOQ_D18_ADD_BYTES

    *encoded_len = length;
    return XQC_MOQ_D18_SETUP_OK;
}

static xqc_moq_d18_setup_result_t
xqc_moq_d18_setup_map_write_error(xqc_moq_d18_kv_result_t result)
{
    if (result == XQC_MOQ_D18_KV_NO_SPACE) {
        return XQC_MOQ_D18_SETUP_NO_SPACE;
    }
    if (result == XQC_MOQ_D18_KV_VALUE_TOO_LARGE) {
        return XQC_MOQ_D18_SETUP_PROTOCOL_VIOLATION;
    }
    return XQC_MOQ_D18_SETUP_INVALID_ARGUMENT;
}

xqc_moq_d18_setup_result_t
xqc_moq_d18_setup_options_encode(
    const xqc_moq_d18_setup_options_t *options, uint8_t *buf,
    size_t buf_cap, size_t *written)
{
    if (options == NULL || written == NULL || (buf_cap > 0 && buf == NULL)) {
        return XQC_MOQ_D18_SETUP_INVALID_ARGUMENT;
    }

    size_t encoded_len = 0;
    xqc_moq_d18_setup_result_t ret =
        xqc_moq_d18_setup_options_encoded_length(options, &encoded_len);
    if (ret != XQC_MOQ_D18_SETUP_OK) {
        return ret;
    }
    if (encoded_len > buf_cap) {
        return XQC_MOQ_D18_SETUP_NO_SPACE;
    }
    if (encoded_len == 0) {
        *written = 0;
        return XQC_MOQ_D18_SETUP_OK;
    }

    uint8_t *pos = buf;
    const uint8_t *end = buf + buf_cap;
    uint64_t previous_type = 0;
    xqc_moq_d18_kv_result_t kv_ret;
#define XQC_MOQ_D18_WRITE_BYTES(view, type_value) \
    do { \
        if ((view).present) { \
            kv_ret = xqc_moq_d18_kv_write_bytes(&pos, end, &previous_type, \
                (type_value), (view).data, (view).len); \
            if (kv_ret != XQC_MOQ_D18_KV_OK) { \
                return xqc_moq_d18_setup_map_write_error(kv_ret); \
            } \
        } \
    } while (0)

    XQC_MOQ_D18_WRITE_BYTES(options->path, XQC_MOQ_D18_SETUP_OPTION_PATH);
    for (size_t i = 0; i < options->authorization_token_count; i++) {
        xqc_moq_d18_bytes_view_t token = options->authorization_tokens[i];
        token.present = 1;
        XQC_MOQ_D18_WRITE_BYTES(token,
            XQC_MOQ_D18_SETUP_OPTION_AUTHORIZATION_TOKEN);
    }
    if (options->has_max_auth_token_cache_size) {
        kv_ret = xqc_moq_d18_kv_write_integer(&pos, end, &previous_type,
            XQC_MOQ_D18_SETUP_OPTION_MAX_AUTH_TOKEN_CACHE_SIZE,
            options->max_auth_token_cache_size);
        if (kv_ret != XQC_MOQ_D18_KV_OK) {
            return xqc_moq_d18_setup_map_write_error(kv_ret);
        }
    }
    XQC_MOQ_D18_WRITE_BYTES(options->authority,
                            XQC_MOQ_D18_SETUP_OPTION_AUTHORITY);
    XQC_MOQ_D18_WRITE_BYTES(options->implementation,
                            XQC_MOQ_D18_SETUP_OPTION_MOQT_IMPLEMENTATION);
#undef XQC_MOQ_D18_WRITE_BYTES

    *written = (size_t)(pos - buf);
    return XQC_MOQ_D18_SETUP_OK;
}

static uint8_t
xqc_moq_d18_ascii_is_alpha(uint8_t value)
{
    return (value >= 'A' && value <= 'Z')
        || (value >= 'a' && value <= 'z');
}

static uint8_t
xqc_moq_d18_ascii_is_digit(uint8_t value)
{
    return value >= '0' && value <= '9';
}

static uint8_t
xqc_moq_d18_ascii_is_hex(uint8_t value)
{
    return xqc_moq_d18_ascii_is_digit(value)
        || (value >= 'A' && value <= 'F')
        || (value >= 'a' && value <= 'f');
}

static uint8_t
xqc_moq_d18_uri_is_unreserved(uint8_t value)
{
    return xqc_moq_d18_ascii_is_alpha(value)
        || xqc_moq_d18_ascii_is_digit(value)
        || value == '-' || value == '.' || value == '_'
        || value == '~';
}

static uint8_t
xqc_moq_d18_uri_is_sub_delim(uint8_t value)
{
    switch (value) {
    case '!':
    case '$':
    case '&':
    case '\'':
    case '(':
    case ')':
    case '*':
    case '+':
    case ',':
    case ';':
    case '=':
        return 1;
    default:
        return 0;
    }
}

static uint8_t
xqc_moq_d18_uri_consume_pct(const uint8_t *value, size_t length,
    size_t *index)
{
    if (*index + 2 >= length
        || !xqc_moq_d18_ascii_is_hex(value[*index + 1])
        || !xqc_moq_d18_ascii_is_hex(value[*index + 2]))
    {
        return 0;
    }
    *index += 2;
    return 1;
}

static uint8_t
xqc_moq_d18_setup_path_is_valid(const xqc_moq_d18_bytes_view_t *path)
{
    if (path->len == 0) {
        return 1;
    }
    if (path->data == NULL
        || (path->data[0] != '/' && path->data[0] != '?'))
    {
        return 0;
    }

    uint8_t in_query = 0;
    for (size_t i = 0; i < path->len; i++) {
        uint8_t value = path->data[i];
        if (value == '%') {
            if (!xqc_moq_d18_uri_consume_pct(path->data, path->len, &i)) {
                return 0;
            }
            continue;
        }
        if (value == '?') {
            in_query = 1;
            continue;
        }
        if (xqc_moq_d18_uri_is_unreserved(value)
            || xqc_moq_d18_uri_is_sub_delim(value)
            || value == ':' || value == '@' || value == '/'
            || (in_query && value == '?'))
        {
            continue;
        }
        return 0;
    }
    return 1;
}

static uint8_t
xqc_moq_d18_uri_userinfo_is_valid(const uint8_t *value, size_t length)
{
    for (size_t i = 0; i < length; i++) {
        if (value[i] == '%') {
            if (!xqc_moq_d18_uri_consume_pct(value, length, &i)) {
                return 0;
            }
            continue;
        }
        if (!xqc_moq_d18_uri_is_unreserved(value[i])
            && !xqc_moq_d18_uri_is_sub_delim(value[i])
            && value[i] != ':')
        {
            return 0;
        }
    }
    return 1;
}

static uint8_t
xqc_moq_d18_uri_reg_name_is_valid(const uint8_t *value, size_t length)
{
    if (length == 0) {
        return 0;
    }
    for (size_t i = 0; i < length; i++) {
        if (value[i] == '%') {
            if (!xqc_moq_d18_uri_consume_pct(value, length, &i)) {
                return 0;
            }
            continue;
        }
        if (!xqc_moq_d18_uri_is_unreserved(value[i])
            && !xqc_moq_d18_uri_is_sub_delim(value[i]))
        {
            return 0;
        }
    }
    return 1;
}

static uint8_t
xqc_moq_d18_uri_ipv4_is_valid(const uint8_t *value, size_t length)
{
    size_t index = 0;
    for (size_t part = 0; part < 4; part++) {
        if (index >= length || !xqc_moq_d18_ascii_is_digit(value[index])) {
            return 0;
        }
        uint64_t number = 0;
        size_t digits = 0;
        while (index < length
               && xqc_moq_d18_ascii_is_digit(value[index]))
        {
            number = number * 10 + (uint64_t)(value[index] - '0');
            index++;
            digits++;
        }
        if (digits > 3 || number > 255) {
            return 0;
        }
        if (part == 3) {
            return index == length;
        }
        if (index >= length || value[index] != '.') {
            return 0;
        }
        index++;
    }
    return 0;
}

static uint8_t
xqc_moq_d18_uri_ipv6_is_valid(const uint8_t *value, size_t length)
{
    if (length == 0) {
        return 0;
    }

    size_t index = 0;
    size_t groups = 0;
    uint8_t compressed = 0;
    if (value[0] == ':') {
        if (length < 2 || value[1] != ':') {
            return 0;
        }
        compressed = 1;
        index = 2;
        if (index == length) {
            return 1;
        }
    }

    while (index < length) {
        size_t start = index;
        uint8_t has_dot = 0;
        while (index < length && value[index] != ':') {
            if (value[index] == '.') {
                has_dot = 1;
            }
            index++;
        }
        size_t token_len = index - start;
        if (token_len == 0) {
            return 0;
        }

        if (has_dot) {
            if (index != length
                || !xqc_moq_d18_uri_ipv4_is_valid(value + start, token_len))
            {
                return 0;
            }
            groups += 2;

        } else {
            if (token_len > 4) {
                return 0;
            }
            for (size_t i = start; i < index; i++) {
                if (!xqc_moq_d18_ascii_is_hex(value[i])) {
                    return 0;
                }
            }
            groups++;
        }
        if (groups > 8 || index == length) {
            break;
        }

        if (index + 1 < length && value[index + 1] == ':') {
            if (compressed) {
                return 0;
            }
            compressed = 1;
            index += 2;
            if (index == length) {
                break;
            }

        } else {
            index++;
            if (index == length) {
                return 0;
            }
        }
    }

    return compressed ? groups < 8 : groups == 8;
}

static uint8_t
xqc_moq_d18_uri_ipvfuture_is_valid(const uint8_t *value, size_t length)
{
    if (length < 4 || (value[0] != 'v' && value[0] != 'V')) {
        return 0;
    }
    size_t index = 1;
    size_t hex_start = index;
    while (index < length && xqc_moq_d18_ascii_is_hex(value[index])) {
        index++;
    }
    if (index == hex_start || index >= length || value[index] != '.') {
        return 0;
    }
    index++;
    if (index == length) {
        return 0;
    }
    for (; index < length; index++) {
        if (!xqc_moq_d18_uri_is_unreserved(value[index])
            && !xqc_moq_d18_uri_is_sub_delim(value[index])
            && value[index] != ':')
        {
            return 0;
        }
    }
    return 1;
}

static uint8_t
xqc_moq_d18_uri_port_is_valid(const uint8_t *value, size_t length)
{
    if (length == 0) {
        return 1;
    }
    uint64_t port = 0;
    for (size_t i = 0; i < length; i++) {
        if (!xqc_moq_d18_ascii_is_digit(value[i])) {
            return 0;
        }
        port = port * 10 + (uint64_t)(value[i] - '0');
        if (port > UINT16_MAX) {
            return 0;
        }
    }
    return 1;
}

static uint8_t
xqc_moq_d18_setup_authority_is_valid(
    const xqc_moq_d18_bytes_view_t *authority)
{
    if (authority->data == NULL || authority->len == 0) {
        return 0;
    }

    size_t host_start = 0;
    uint8_t has_at = 0;
    for (size_t i = 0; i < authority->len; i++) {
        if (authority->data[i] != '@') {
            continue;
        }
        if (has_at
            || !xqc_moq_d18_uri_userinfo_is_valid(authority->data, i))
        {
            return 0;
        }
        has_at = 1;
        host_start = i + 1;
    }
    if (host_start >= authority->len) {
        return 0;
    }

    const uint8_t *value = authority->data;
    if (value[host_start] == '[') {
        size_t close = host_start + 1;
        while (close < authority->len && value[close] != ']') {
            close++;
        }
        if (close >= authority->len || close == host_start + 1) {
            return 0;
        }
        const uint8_t *literal = value + host_start + 1;
        size_t literal_len = close - host_start - 1;
        if (!xqc_moq_d18_uri_ipv6_is_valid(literal, literal_len)
            && !xqc_moq_d18_uri_ipvfuture_is_valid(literal, literal_len))
        {
            return 0;
        }
        if (close + 1 == authority->len) {
            return 1;
        }
        return value[close + 1] == ':'
            && xqc_moq_d18_uri_port_is_valid(value + close + 2,
                                             authority->len - close - 2);
    }

    size_t colon = authority->len;
    for (size_t i = host_start; i < authority->len; i++) {
        if (value[i] != ':') {
            continue;
        }
        if (colon != authority->len) {
            return 0;
        }
        colon = i;
    }
    size_t host_len = colon - host_start;
    if (!xqc_moq_d18_uri_reg_name_is_valid(value + host_start, host_len)) {
        return 0;
    }
    return colon == authority->len
        || xqc_moq_d18_uri_port_is_valid(value + colon + 1,
                                         authority->len - colon - 1);
}

xqc_moq_d18_setup_result_t
xqc_moq_d18_setup_options_validate(
    const xqc_moq_d18_setup_options_t *options,
    xqc_moq_d18_setup_sender_t sender,
    xqc_moq_d18_setup_transport_t transport)
{
    if (options == NULL
        || (sender != XQC_MOQ_D18_SETUP_SENDER_CLIENT
            && sender != XQC_MOQ_D18_SETUP_SENDER_SERVER)
        || (transport != XQC_MOQ_D18_SETUP_TRANSPORT_NATIVE_QUIC
            && transport != XQC_MOQ_D18_SETUP_TRANSPORT_WEBTRANSPORT))
    {
        return XQC_MOQ_D18_SETUP_INVALID_ARGUMENT;
    }

    if (options->path.present) {
        if (sender != XQC_MOQ_D18_SETUP_SENDER_CLIENT
            || transport != XQC_MOQ_D18_SETUP_TRANSPORT_NATIVE_QUIC)
        {
            return XQC_MOQ_D18_SETUP_INVALID_PATH;
        }
        if (!xqc_moq_d18_setup_path_is_valid(&options->path)) {
            return XQC_MOQ_D18_SETUP_MALFORMED_PATH;
        }
    }

    if (options->authority.present) {
        if (sender != XQC_MOQ_D18_SETUP_SENDER_CLIENT
            || transport != XQC_MOQ_D18_SETUP_TRANSPORT_NATIVE_QUIC)
        {
            return XQC_MOQ_D18_SETUP_INVALID_AUTHORITY;
        }
        if (!xqc_moq_d18_setup_authority_is_valid(&options->authority)) {
            return XQC_MOQ_D18_SETUP_MALFORMED_AUTHORITY;
        }
    }

    return XQC_MOQ_D18_SETUP_OK;
}

uint64_t
xqc_moq_d18_setup_result_session_error(xqc_moq_d18_setup_result_t result)
{
    switch (result) {
    case XQC_MOQ_D18_SETUP_OK:
        return XQC_MOQ_D18_NO_ERROR;
    case XQC_MOQ_D18_SETUP_NO_MEMORY:
        return XQC_MOQ_D18_INTERNAL_ERROR;
    case XQC_MOQ_D18_SETUP_FORMATTING:
        return XQC_MOQ_D18_KEY_VALUE_FORMATTING_ERROR;
    case XQC_MOQ_D18_SETUP_INVALID_PATH:
        return XQC_MOQ_D18_INVALID_PATH;
    case XQC_MOQ_D18_SETUP_MALFORMED_PATH:
        return XQC_MOQ_D18_MALFORMED_PATH;
    case XQC_MOQ_D18_SETUP_INVALID_AUTHORITY:
        return XQC_MOQ_D18_INVALID_AUTHORITY;
    case XQC_MOQ_D18_SETUP_MALFORMED_AUTHORITY:
        return XQC_MOQ_D18_MALFORMED_AUTHORITY;
    default:
        return XQC_MOQ_D18_PROTOCOL_VIOLATION;
    }
}
