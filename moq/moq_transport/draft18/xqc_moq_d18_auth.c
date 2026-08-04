#include "moq/moq_transport/draft18/xqc_moq_d18_auth.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_int.h"

#include <string.h>

#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/common/xqc_malloc.h"

typedef struct {
    xqc_list_head_t list_member;
    uint64_t alias;
    uint64_t token_type;
    uint8_t *token_value;
    size_t token_value_len;
    uint8_t expired;
} xqc_moq_d18_auth_cache_entry_t;

static xqc_moq_d18_auth_result_t
xqc_moq_d18_auth_read_vi64(const uint8_t **pos, const uint8_t *end,
    uint64_t *value)
{
    int ret = xqc_moq_d18_int_read(*pos, end, value);
    if (ret < 0) {
        return XQC_MOQ_D18_AUTH_FORMATTING;
    }
    *pos += ret;
    return XQC_MOQ_D18_AUTH_OK;
}

xqc_moq_d18_auth_result_t
xqc_moq_d18_auth_token_decode(const uint8_t *buf, size_t buf_len,
    xqc_moq_d18_auth_token_t *token)
{
    if (token == NULL) {
        return XQC_MOQ_D18_AUTH_INVALID_ARGUMENT;
    }
    memset(token, 0, sizeof(*token));
    if (buf == NULL || buf_len == 0) {
        return XQC_MOQ_D18_AUTH_FORMATTING;
    }

    const uint8_t *pos = buf;
    const uint8_t *end = buf + buf_len;
    xqc_moq_d18_auth_result_t ret =
        xqc_moq_d18_auth_read_vi64(&pos, end, &token->alias_type);
    if (ret != XQC_MOQ_D18_AUTH_OK
        || token->alias_type > XQC_MOQ_D18_AUTH_USE_VALUE)
    {
        return XQC_MOQ_D18_AUTH_FORMATTING;
    }

    if (token->alias_type == XQC_MOQ_D18_AUTH_DELETE
        || token->alias_type == XQC_MOQ_D18_AUTH_REGISTER
        || token->alias_type == XQC_MOQ_D18_AUTH_USE_ALIAS)
    {
        ret = xqc_moq_d18_auth_read_vi64(&pos, end,
                                         &token->token_alias);
        if (ret != XQC_MOQ_D18_AUTH_OK) {
            return ret;
        }
        token->has_alias = 1;
    }

    if (token->alias_type == XQC_MOQ_D18_AUTH_REGISTER
        || token->alias_type == XQC_MOQ_D18_AUTH_USE_VALUE)
    {
        ret = xqc_moq_d18_auth_read_vi64(&pos, end, &token->token_type);
        if (ret != XQC_MOQ_D18_AUTH_OK) {
            return ret;
        }
        token->has_token_type = 1;
        token->token_value = pos;
        token->token_value_len = (size_t)(end - pos);
        return XQC_MOQ_D18_AUTH_OK;
    }

    return pos == end
        ? XQC_MOQ_D18_AUTH_OK : XQC_MOQ_D18_AUTH_FORMATTING;
}

static xqc_moq_d18_auth_result_t
xqc_moq_d18_auth_token_validate(const xqc_moq_d18_auth_token_t *token)
{
    if (token == NULL
        || token->alias_type > XQC_MOQ_D18_AUTH_USE_VALUE
        || (token->token_value_len > 0 && token->token_value == NULL))
    {
        return XQC_MOQ_D18_AUTH_INVALID_ARGUMENT;
    }

    switch (token->alias_type) {
    case XQC_MOQ_D18_AUTH_DELETE:
    case XQC_MOQ_D18_AUTH_USE_ALIAS:
        if (!token->has_alias || token->has_token_type
            || token->token_value_len != 0)
        {
            return XQC_MOQ_D18_AUTH_INVALID_ARGUMENT;
        }
        break;
    case XQC_MOQ_D18_AUTH_REGISTER:
        if (!token->has_alias || !token->has_token_type) {
            return XQC_MOQ_D18_AUTH_INVALID_ARGUMENT;
        }
        break;
    case XQC_MOQ_D18_AUTH_USE_VALUE:
        if (token->has_alias || !token->has_token_type) {
            return XQC_MOQ_D18_AUTH_INVALID_ARGUMENT;
        }
        break;
    default:
        return XQC_MOQ_D18_AUTH_INVALID_ARGUMENT;
    }
    return XQC_MOQ_D18_AUTH_OK;
}

xqc_moq_d18_auth_result_t
xqc_moq_d18_auth_token_encoded_length(
    const xqc_moq_d18_auth_token_t *token, size_t *encoded_len)
{
    if (encoded_len == NULL) {
        return XQC_MOQ_D18_AUTH_INVALID_ARGUMENT;
    }
    xqc_moq_d18_auth_result_t ret =
        xqc_moq_d18_auth_token_validate(token);
    if (ret != XQC_MOQ_D18_AUTH_OK) {
        return ret;
    }

    size_t length = xqc_moq_d18_int_len(token->alias_type);
    if (token->has_alias) {
        length += xqc_moq_d18_int_len(token->token_alias);
    }
    if (token->has_token_type) {
        length += xqc_moq_d18_int_len(token->token_type);
        if (token->token_value_len > SIZE_MAX - length) {
            return XQC_MOQ_D18_AUTH_INVALID_ARGUMENT;
        }
        length += token->token_value_len;
    }
    *encoded_len = length;
    return XQC_MOQ_D18_AUTH_OK;
}

xqc_moq_d18_auth_result_t
xqc_moq_d18_auth_token_encode(const xqc_moq_d18_auth_token_t *token,
    uint8_t *buf, size_t buf_cap, size_t *written)
{
    if (written == NULL || (buf_cap > 0 && buf == NULL)) {
        return XQC_MOQ_D18_AUTH_INVALID_ARGUMENT;
    }
    size_t encoded_len = 0;
    xqc_moq_d18_auth_result_t ret =
        xqc_moq_d18_auth_token_encoded_length(token, &encoded_len);
    if (ret != XQC_MOQ_D18_AUTH_OK) {
        return ret;
    }
    if (encoded_len > buf_cap) {
        return XQC_MOQ_D18_AUTH_NO_SPACE;
    }

    uint8_t *pos = xqc_moq_d18_int_write(buf, token->alias_type);
    if (token->has_alias) {
        pos = xqc_moq_d18_int_write(pos, token->token_alias);
    }
    if (token->has_token_type) {
        pos = xqc_moq_d18_int_write(pos, token->token_type);
        if (token->token_value_len > 0) {
            memcpy(pos, token->token_value, token->token_value_len);
            pos += token->token_value_len;
        }
    }
    *written = (size_t)(pos - buf);
    return XQC_MOQ_D18_AUTH_OK;
}

void
xqc_moq_d18_auth_cache_init(xqc_moq_d18_auth_cache_t *cache,
    uint64_t max_size)
{
    if (cache == NULL) {
        return;
    }
    xqc_init_list_head(&cache->entries);
    cache->max_size = max_size;
    cache->current_size = 0;
}

void
xqc_moq_d18_auth_cache_destroy(xqc_moq_d18_auth_cache_t *cache)
{
    if (cache == NULL) {
        return;
    }

    xqc_list_head_t *pos;
    xqc_list_head_t *next;
    xqc_list_for_each_safe(pos, next, &cache->entries) {
        xqc_moq_d18_auth_cache_entry_t *entry =
            xqc_list_entry(pos, xqc_moq_d18_auth_cache_entry_t,
                           list_member);
        xqc_list_del(pos);
        xqc_free(entry->token_value);
        xqc_free(entry);
    }
    xqc_init_list_head(&cache->entries);
    cache->current_size = 0;
}

static xqc_moq_d18_auth_cache_entry_t *
xqc_moq_d18_auth_cache_find(xqc_moq_d18_auth_cache_t *cache,
    uint64_t alias)
{
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &cache->entries) {
        xqc_moq_d18_auth_cache_entry_t *entry =
            xqc_list_entry(pos, xqc_moq_d18_auth_cache_entry_t,
                           list_member);
        if (entry->alias == alias) {
            return entry;
        }
    }
    return NULL;
}

static void
xqc_moq_d18_auth_resolve_entry(
    const xqc_moq_d18_auth_cache_entry_t *entry,
    xqc_moq_d18_auth_token_t *resolved)
{
    if (resolved == NULL) {
        return;
    }
    *resolved = (xqc_moq_d18_auth_token_t){
        .alias_type = XQC_MOQ_D18_AUTH_USE_VALUE,
        .token_type = entry->token_type,
        .token_value = entry->token_value,
        .token_value_len = entry->token_value_len,
        .has_token_type = 1,
    };
}

static void
xqc_moq_d18_auth_resolve_value(const xqc_moq_d18_auth_token_t *token,
    xqc_moq_d18_auth_token_t *resolved)
{
    if (resolved == NULL) {
        return;
    }
    *resolved = (xqc_moq_d18_auth_token_t){
        .alias_type = XQC_MOQ_D18_AUTH_USE_VALUE,
        .token_type = token->token_type,
        .token_value = token->token_value,
        .token_value_len = token->token_value_len,
        .has_token_type = 1,
    };
}

xqc_moq_d18_auth_result_t
xqc_moq_d18_auth_cache_apply(xqc_moq_d18_auth_cache_t *cache,
    const xqc_moq_d18_auth_token_t *token, uint8_t in_setup,
    uint8_t receiver_is_server, xqc_moq_d18_auth_token_t *resolved,
    uint8_t *registered)
{
    if (cache == NULL
        || xqc_moq_d18_auth_token_validate(token) != XQC_MOQ_D18_AUTH_OK)
    {
        return XQC_MOQ_D18_AUTH_INVALID_ARGUMENT;
    }
    if (resolved != NULL) {
        memset(resolved, 0, sizeof(*resolved));
    }
    if (registered != NULL) {
        *registered = 0;
    }

    if (in_setup && receiver_is_server
        && (token->alias_type == XQC_MOQ_D18_AUTH_DELETE
            || token->alias_type == XQC_MOQ_D18_AUTH_USE_ALIAS))
    {
        return XQC_MOQ_D18_AUTH_PROTOCOL_VIOLATION;
    }

    xqc_moq_d18_auth_cache_entry_t *entry;
    switch (token->alias_type) {
    case XQC_MOQ_D18_AUTH_DELETE:
        entry = xqc_moq_d18_auth_cache_find(cache, token->token_alias);
        if (entry == NULL) {
            return XQC_MOQ_D18_AUTH_UNKNOWN_ALIAS;
        }
        cache->current_size -= 16 + entry->token_value_len;
        xqc_list_del(&entry->list_member);
        xqc_free(entry->token_value);
        xqc_free(entry);
        return XQC_MOQ_D18_AUTH_OK;

    case XQC_MOQ_D18_AUTH_REGISTER: {
        if (xqc_moq_d18_auth_cache_find(cache, token->token_alias)
            != NULL)
        {
            return XQC_MOQ_D18_AUTH_DUPLICATE_ALIAS;
        }
        if (token->token_value_len > UINT64_MAX - 16) {
            return XQC_MOQ_D18_AUTH_CACHE_OVERFLOW;
        }
        uint64_t entry_size = 16 + token->token_value_len;
        if (entry_size > cache->max_size
            || cache->current_size > cache->max_size - entry_size)
        {
            if (in_setup) {
                xqc_moq_d18_auth_resolve_value(token, resolved);
                return XQC_MOQ_D18_AUTH_OK;
            }
            return XQC_MOQ_D18_AUTH_CACHE_OVERFLOW;
        }

        entry = xqc_calloc(1, sizeof(*entry));
        if (entry == NULL) {
            return XQC_MOQ_D18_AUTH_NO_MEMORY;
        }
        if (token->token_value_len > 0) {
            entry->token_value = xqc_malloc(token->token_value_len);
            if (entry->token_value == NULL) {
                xqc_free(entry);
                return XQC_MOQ_D18_AUTH_NO_MEMORY;
            }
            memcpy(entry->token_value, token->token_value,
                   token->token_value_len);
        }
        entry->alias = token->token_alias;
        entry->token_type = token->token_type;
        entry->token_value_len = token->token_value_len;
        xqc_init_list_head(&entry->list_member);
        xqc_list_add_tail(&entry->list_member, &cache->entries);
        cache->current_size += entry_size;
        if (registered != NULL) {
            *registered = 1;
        }
        xqc_moq_d18_auth_resolve_entry(entry, resolved);
        return XQC_MOQ_D18_AUTH_OK;
    }

    case XQC_MOQ_D18_AUTH_USE_ALIAS:
        entry = xqc_moq_d18_auth_cache_find(cache, token->token_alias);
        if (entry == NULL) {
            return XQC_MOQ_D18_AUTH_UNKNOWN_ALIAS;
        }
        if (entry->expired) {
            return XQC_MOQ_D18_AUTH_EXPIRED_TOKEN;
        }
        xqc_moq_d18_auth_resolve_entry(entry, resolved);
        return XQC_MOQ_D18_AUTH_OK;

    case XQC_MOQ_D18_AUTH_USE_VALUE:
        xqc_moq_d18_auth_resolve_value(token, resolved);
        return XQC_MOQ_D18_AUTH_OK;

    default:
        return XQC_MOQ_D18_AUTH_INVALID_ARGUMENT;
    }
}

xqc_moq_d18_auth_result_t
xqc_moq_d18_auth_cache_mark_expired(xqc_moq_d18_auth_cache_t *cache,
    uint64_t alias)
{
    if (cache == NULL) {
        return XQC_MOQ_D18_AUTH_INVALID_ARGUMENT;
    }
    xqc_moq_d18_auth_cache_entry_t *entry =
        xqc_moq_d18_auth_cache_find(cache, alias);
    if (entry == NULL) {
        return XQC_MOQ_D18_AUTH_UNKNOWN_ALIAS;
    }
    entry->expired = 1;
    return XQC_MOQ_D18_AUTH_OK;
}
