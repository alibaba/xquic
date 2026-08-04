#include "moq/moq_transport/draft18/xqc_moq_d18_properties.h"

#include <string.h>

#include "src/common/xqc_malloc.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_kv.h"

struct xqc_moq_d18_properties_s {
    xqc_moq_d18_property_scope_t scope;
    uint8_t *wire;
    size_t wire_len;
    uint8_t owns_wire;
    xqc_moq_d18_property_view_t *entries;
    size_t count;
};

typedef struct {
    size_t count;
} xqc_moq_d18_property_count_ctx_t;

typedef struct {
    xqc_moq_d18_properties_t *properties;
    size_t index;
    uint8_t allow_immutable;
    xqc_moq_d18_property_result_t result;
} xqc_moq_d18_property_fill_ctx_t;

static xqc_moq_d18_property_result_t xqc_moq_d18_properties_parse_internal(
    xqc_moq_d18_property_scope_t scope, const uint8_t *wire,
    size_t wire_len, uint8_t copy_wire, uint8_t allow_immutable,
    xqc_moq_d18_properties_t **properties);

static xqc_moq_d18_property_result_t
xqc_moq_d18_property_validate(const xqc_moq_d18_kv_view_t *item,
    xqc_moq_d18_property_scope_t scope, uint8_t *known)
{
    *known = 0;
    if (item->type >= 0x4000 && item->type <= 0x7fff) {
        return scope == XQC_MOQ_D18_PROPERTY_SCOPE_TRACK
            ? XQC_MOQ_D18_PROPERTY_UNSUPPORTED_EXTENSION
            : XQC_MOQ_D18_PROPERTY_PROTOCOL_VIOLATION;
    }

    switch (item->type) {
    case XQC_MOQ_D18_PROPERTY_OBJECT_DELIVERY_TIMEOUT:
    case XQC_MOQ_D18_PROPERTY_MAX_CACHE_DURATION:
        if (scope != XQC_MOQ_D18_PROPERTY_SCOPE_TRACK) {
            return XQC_MOQ_D18_PROPERTY_PROTOCOL_VIOLATION;
        }
        *known = 1;
        return XQC_MOQ_D18_PROPERTY_OK;

    case XQC_MOQ_D18_PROPERTY_SUBGROUP_DELIVERY_TIMEOUT:
        if (scope == XQC_MOQ_D18_PROPERTY_SCOPE_TRACK) {
            *known = 1;
        }
        /* 0x06 is also the provisional Object TIMESTAMP Property. */
        return XQC_MOQ_D18_PROPERTY_OK;

    case XQC_MOQ_D18_PROPERTY_IMMUTABLE_PROPERTIES:
        *known = 1;
        return XQC_MOQ_D18_PROPERTY_OK;

    case XQC_MOQ_D18_PROPERTY_DEFAULT_PUBLISHER_PRIORITY:
        if (scope != XQC_MOQ_D18_PROPERTY_SCOPE_TRACK
            || item->integer > UINT8_MAX)
        {
            return XQC_MOQ_D18_PROPERTY_PROTOCOL_VIOLATION;
        }
        *known = 1;
        return XQC_MOQ_D18_PROPERTY_OK;

    case XQC_MOQ_D18_PROPERTY_DEFAULT_PUBLISHER_GROUP_ORDER:
        if (scope != XQC_MOQ_D18_PROPERTY_SCOPE_TRACK
            || (item->integer != 1 && item->integer != 2))
        {
            return XQC_MOQ_D18_PROPERTY_PROTOCOL_VIOLATION;
        }
        *known = 1;
        return XQC_MOQ_D18_PROPERTY_OK;

    case XQC_MOQ_D18_PROPERTY_DYNAMIC_GROUPS:
        if (scope != XQC_MOQ_D18_PROPERTY_SCOPE_TRACK
            || item->integer > 1)
        {
            return XQC_MOQ_D18_PROPERTY_PROTOCOL_VIOLATION;
        }
        *known = 1;
        return XQC_MOQ_D18_PROPERTY_OK;

    case XQC_MOQ_D18_PROPERTY_PRIOR_GROUP_ID_GAP:
    case XQC_MOQ_D18_PROPERTY_PRIOR_OBJECT_ID_GAP:
        if (scope != XQC_MOQ_D18_PROPERTY_SCOPE_OBJECT) {
            return XQC_MOQ_D18_PROPERTY_PROTOCOL_VIOLATION;
        }
        *known = 1;
        return XQC_MOQ_D18_PROPERTY_OK;

    /* Provisional registrations from the draft-18 IANA table. */
    case 0x08: /* TIMESCALE, Track/Object */
        return XQC_MOQ_D18_PROPERTY_OK;
    case 0x0a: /* VIDEO_FRAME_MARKING, Object */
    case 0x0c: /* AUDIO_LEVEL, Object */
    case 0x0d: /* VIDEO_CONFIG, Object */
        return scope == XQC_MOQ_D18_PROPERTY_SCOPE_OBJECT
            ? XQC_MOQ_D18_PROPERTY_OK
            : XQC_MOQ_D18_PROPERTY_PROTOCOL_VIOLATION;

    default:
        return XQC_MOQ_D18_PROPERTY_OK;
    }
}

static xqc_moq_d18_kv_result_t
xqc_moq_d18_property_count(const xqc_moq_d18_kv_view_t *item,
    void *user_data)
{
    (void)item;
    xqc_moq_d18_property_count_ctx_t *ctx = user_data;
    if (ctx->count == SIZE_MAX) {
        return XQC_MOQ_D18_KV_VISITOR_ERROR;
    }
    ctx->count++;
    return XQC_MOQ_D18_KV_OK;
}

static xqc_moq_d18_kv_result_t
xqc_moq_d18_property_fill(const xqc_moq_d18_kv_view_t *item,
    void *user_data)
{
    xqc_moq_d18_property_fill_ctx_t *ctx = user_data;
    if (ctx->index >= ctx->properties->count) {
        return XQC_MOQ_D18_KV_VISITOR_ERROR;
    }

    xqc_moq_d18_property_view_t *property =
        &ctx->properties->entries[ctx->index++];
    xqc_moq_d18_property_result_t result =
        xqc_moq_d18_property_validate(
            item, ctx->properties->scope, &property->known);
    if (result != XQC_MOQ_D18_PROPERTY_OK) {
        ctx->result = result;
        return XQC_MOQ_D18_KV_VISITOR_ERROR;
    }
    property->type = item->type;
    property->is_bytes = item->is_bytes;
    property->integer = item->integer;
    property->bytes = item->bytes;
    property->bytes_len = item->bytes_len;
    property->encoded = item->encoded;
    property->encoded_len = item->encoded_len;

    if (item->type == XQC_MOQ_D18_PROPERTY_IMMUTABLE_PROPERTIES) {
        if (!ctx->allow_immutable) {
            ctx->result = XQC_MOQ_D18_PROPERTY_PROTOCOL_VIOLATION;
            return XQC_MOQ_D18_KV_VISITOR_ERROR;
        }
        xqc_moq_d18_properties_t *immutable = NULL;
        result = xqc_moq_d18_properties_parse_internal(
            ctx->properties->scope, item->bytes, item->bytes_len,
            0, 0, &immutable);
        if (result != XQC_MOQ_D18_PROPERTY_OK) {
            ctx->result = result;
            return XQC_MOQ_D18_KV_VISITOR_ERROR;
        }
        property->immutable = immutable;
    }
    return XQC_MOQ_D18_KV_OK;
}

static xqc_moq_d18_property_result_t
xqc_moq_d18_property_map_kv_result(xqc_moq_d18_kv_result_t result)
{
    if (result == XQC_MOQ_D18_KV_OK) {
        return XQC_MOQ_D18_PROPERTY_OK;
    }
    if (result == XQC_MOQ_D18_KV_INVALID_ARGUMENT) {
        return XQC_MOQ_D18_PROPERTY_INVALID_ARGUMENT;
    }
    return XQC_MOQ_D18_PROPERTY_FORMATTING;
}

static xqc_moq_d18_property_result_t
xqc_moq_d18_properties_parse_internal(xqc_moq_d18_property_scope_t scope,
    const uint8_t *wire, size_t wire_len, uint8_t copy_wire,
    uint8_t allow_immutable, xqc_moq_d18_properties_t **properties)
{
    if (properties == NULL
        || scope > XQC_MOQ_D18_PROPERTY_SCOPE_OBJECT
        || (wire_len > 0 && wire == NULL))
    {
        return XQC_MOQ_D18_PROPERTY_INVALID_ARGUMENT;
    }
    *properties = NULL;

    xqc_moq_d18_property_count_ctx_t count_ctx = {0};
    xqc_moq_d18_kv_result_t kv_result = xqc_moq_d18_kv_parse(
        wire, wire_len, xqc_moq_d18_property_count, &count_ctx);
    if (kv_result != XQC_MOQ_D18_KV_OK) {
        return xqc_moq_d18_property_map_kv_result(kv_result);
    }

    xqc_moq_d18_properties_t *result = xqc_calloc(1, sizeof(*result));
    if (result == NULL) {
        return XQC_MOQ_D18_PROPERTY_NO_MEMORY;
    }
    result->scope = scope;
    result->wire_len = wire_len;
    result->owns_wire = copy_wire;
    result->count = count_ctx.count;

    if (wire_len > 0) {
        if (copy_wire) {
            result->wire = xqc_malloc(wire_len);
            if (result->wire == NULL) {
                xqc_moq_d18_properties_destroy(result);
                return XQC_MOQ_D18_PROPERTY_NO_MEMORY;
            }
            memcpy(result->wire, wire, wire_len);

        } else {
            result->wire = (uint8_t *)wire;
        }
    }
    if (result->count > 0) {
        if (result->count > SIZE_MAX / sizeof(*result->entries)) {
            xqc_moq_d18_properties_destroy(result);
            return XQC_MOQ_D18_PROPERTY_NO_MEMORY;
        }
        result->entries = xqc_calloc(
            result->count, sizeof(*result->entries));
        if (result->entries == NULL) {
            xqc_moq_d18_properties_destroy(result);
            return XQC_MOQ_D18_PROPERTY_NO_MEMORY;
        }

        xqc_moq_d18_property_fill_ctx_t fill_ctx = {
            .properties = result,
            .allow_immutable = allow_immutable,
            .result = XQC_MOQ_D18_PROPERTY_OK,
        };
        kv_result = xqc_moq_d18_kv_parse(
            result->wire, result->wire_len,
            xqc_moq_d18_property_fill, &fill_ctx);
        if (kv_result != XQC_MOQ_D18_KV_OK
            || fill_ctx.index != result->count)
        {
            xqc_moq_d18_property_result_t property_result =
                fill_ctx.result != XQC_MOQ_D18_PROPERTY_OK
                ? fill_ctx.result
                : xqc_moq_d18_property_map_kv_result(kv_result);
            if (property_result == XQC_MOQ_D18_PROPERTY_OK) {
                property_result = XQC_MOQ_D18_PROPERTY_FORMATTING;
            }
            xqc_moq_d18_properties_destroy(result);
            return property_result;
        }
    }

    *properties = result;
    return XQC_MOQ_D18_PROPERTY_OK;
}

static size_t
xqc_moq_d18_properties_recursive_count(
    const xqc_moq_d18_properties_t *properties, uint64_t type)
{
    size_t count = 0;
    for (size_t i = 0; i < properties->count; i++) {
        const xqc_moq_d18_property_view_t *property =
            &properties->entries[i];
        if (property->type == type) {
            count++;
        }
        if (property->immutable != NULL) {
            count += xqc_moq_d18_properties_recursive_count(
                property->immutable, type);
        }
    }
    return count;
}

xqc_moq_d18_property_result_t
xqc_moq_d18_properties_parse(xqc_moq_d18_property_scope_t scope,
    const uint8_t *wire, size_t wire_len,
    xqc_moq_d18_properties_t **properties)
{
    xqc_moq_d18_property_result_t result =
        xqc_moq_d18_properties_parse_internal(
            scope, wire, wire_len, 1, 1, properties);
    if (result != XQC_MOQ_D18_PROPERTY_OK
        || scope != XQC_MOQ_D18_PROPERTY_SCOPE_OBJECT)
    {
        return result;
    }

    if (xqc_moq_d18_properties_recursive_count(
            *properties, XQC_MOQ_D18_PROPERTY_IMMUTABLE_PROPERTIES) > 1
        || xqc_moq_d18_properties_recursive_count(
            *properties, XQC_MOQ_D18_PROPERTY_PRIOR_GROUP_ID_GAP) > 1
        || xqc_moq_d18_properties_recursive_count(
            *properties, XQC_MOQ_D18_PROPERTY_PRIOR_OBJECT_ID_GAP) > 1)
    {
        xqc_moq_d18_properties_destroy(*properties);
        *properties = NULL;
        return XQC_MOQ_D18_PROPERTY_PROTOCOL_VIOLATION;
    }
    return XQC_MOQ_D18_PROPERTY_OK;
}

void
xqc_moq_d18_properties_destroy(xqc_moq_d18_properties_t *properties)
{
    if (properties == NULL) {
        return;
    }
    for (size_t i = 0; i < properties->count; i++) {
        xqc_moq_d18_properties_destroy(
            (xqc_moq_d18_properties_t *)properties->entries[i].immutable);
    }
    xqc_free(properties->entries);
    if (properties->owns_wire) {
        xqc_free(properties->wire);
    }
    xqc_free(properties);
}

xqc_moq_d18_property_result_t
xqc_moq_d18_properties_clone(const xqc_moq_d18_properties_t *properties,
    xqc_moq_d18_properties_t **clone)
{
    if (properties == NULL || clone == NULL) {
        return XQC_MOQ_D18_PROPERTY_INVALID_ARGUMENT;
    }
    return xqc_moq_d18_properties_parse(
        properties->scope, properties->wire, properties->wire_len, clone);
}

size_t
xqc_moq_d18_properties_count(const xqc_moq_d18_properties_t *properties)
{
    return properties == NULL ? 0 : properties->count;
}

const xqc_moq_d18_property_view_t *
xqc_moq_d18_properties_at(const xqc_moq_d18_properties_t *properties,
    size_t index)
{
    if (properties == NULL || index >= properties->count) {
        return NULL;
    }
    return &properties->entries[index];
}

static const xqc_moq_d18_property_view_t *
xqc_moq_d18_properties_find_internal(
    const xqc_moq_d18_properties_t *properties, uint64_t type,
    size_t *occurrence)
{
    for (size_t i = 0; i < properties->count; i++) {
        const xqc_moq_d18_property_view_t *property =
            &properties->entries[i];
        if (property->type == type) {
            if (*occurrence == 0) {
                return property;
            }
            (*occurrence)--;
        }
    }
    for (size_t i = 0; i < properties->count; i++) {
        const xqc_moq_d18_properties_t *immutable =
            properties->entries[i].immutable;
        if (immutable == NULL) {
            continue;
        }
        const xqc_moq_d18_property_view_t *found =
            xqc_moq_d18_properties_find_internal(
                immutable, type, occurrence);
        if (found != NULL) {
            return found;
        }
    }
    return NULL;
}

const xqc_moq_d18_property_view_t *
xqc_moq_d18_properties_find(const xqc_moq_d18_properties_t *properties,
    uint64_t type, size_t occurrence)
{
    if (properties == NULL) {
        return NULL;
    }
    return xqc_moq_d18_properties_find_internal(
        properties, type, &occurrence);
}

const uint8_t *
xqc_moq_d18_properties_wire(const xqc_moq_d18_properties_t *properties,
    size_t *wire_len)
{
    if (wire_len != NULL) {
        *wire_len = properties == NULL ? 0 : properties->wire_len;
    }
    return properties == NULL ? NULL : properties->wire;
}

xqc_moq_d18_property_result_t
xqc_moq_d18_properties_write(const xqc_moq_d18_properties_t *properties,
    uint8_t *buf, size_t buf_cap, size_t *written)
{
    if (written == NULL) {
        return XQC_MOQ_D18_PROPERTY_INVALID_ARGUMENT;
    }
    *written = 0;
    if (properties == NULL
        || (properties->wire_len > 0 && buf == NULL))
    {
        return XQC_MOQ_D18_PROPERTY_INVALID_ARGUMENT;
    }
    if (buf_cap < properties->wire_len) {
        return XQC_MOQ_D18_PROPERTY_NO_SPACE;
    }
    if (properties->wire_len > 0) {
        memcpy(buf, properties->wire, properties->wire_len);
    }
    *written = properties->wire_len;
    return XQC_MOQ_D18_PROPERTY_OK;
}
