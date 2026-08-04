#include <stddef.h>

#include "moq/moq_transport/draft18/xqc_moq_d18_registry.h"

typedef struct {
    uint64_t                    wire_type;
    xqc_moq_d18_message_kind_t  kind;
} xqc_moq_d18_registry_entry_t;

static const xqc_moq_d18_registry_entry_t xqc_moq_d18_initial_requests[] = {
    {XQC_MOQ_D18_MSG_SUBSCRIBE, XQC_MOQ_D18_MESSAGE_SUBSCRIBE},
    {XQC_MOQ_D18_MSG_PUBLISH, XQC_MOQ_D18_MESSAGE_PUBLISH},
    {XQC_MOQ_D18_MSG_FETCH, XQC_MOQ_D18_MESSAGE_FETCH},
    {XQC_MOQ_D18_MSG_TRACK_STATUS, XQC_MOQ_D18_MESSAGE_TRACK_STATUS},
    {
        XQC_MOQ_D18_MSG_PUBLISH_NAMESPACE,
        XQC_MOQ_D18_MESSAGE_PUBLISH_NAMESPACE,
    },
    {
        XQC_MOQ_D18_MSG_SUBSCRIBE_NAMESPACE,
        XQC_MOQ_D18_MESSAGE_SUBSCRIBE_NAMESPACE,
    },
    {
        XQC_MOQ_D18_MSG_SUBSCRIBE_TRACKS,
        XQC_MOQ_D18_MESSAGE_SUBSCRIBE_TRACKS,
    },
};

static const xqc_moq_d18_registry_entry_t xqc_moq_d18_request_messages[] = {
    {XQC_MOQ_D18_MSG_SUBSCRIBE_OK, XQC_MOQ_D18_MESSAGE_SUBSCRIBE_OK},
    {XQC_MOQ_D18_MSG_PUBLISH_OK, XQC_MOQ_D18_MESSAGE_PUBLISH_OK},
    {XQC_MOQ_D18_MSG_PUBLISH_DONE, XQC_MOQ_D18_MESSAGE_PUBLISH_DONE},
    {XQC_MOQ_D18_MSG_FETCH_OK, XQC_MOQ_D18_MESSAGE_FETCH_OK},
    {XQC_MOQ_D18_MSG_NAMESPACE, XQC_MOQ_D18_MESSAGE_NAMESPACE},
    {XQC_MOQ_D18_MSG_NAMESPACE_DONE, XQC_MOQ_D18_MESSAGE_NAMESPACE_DONE},
    {XQC_MOQ_D18_MSG_PUBLISH_BLOCKED, XQC_MOQ_D18_MESSAGE_PUBLISH_BLOCKED},
    {XQC_MOQ_D18_MSG_REQUEST_UPDATE, XQC_MOQ_D18_MESSAGE_REQUEST_UPDATE},
    {XQC_MOQ_D18_MSG_REQUEST_OK, XQC_MOQ_D18_MESSAGE_REQUEST_OK},
    {XQC_MOQ_D18_MSG_REQUEST_ERROR, XQC_MOQ_D18_MESSAGE_REQUEST_ERROR},
    {XQC_MOQ_D18_MSG_GOAWAY, XQC_MOQ_D18_MESSAGE_GOAWAY},
};

static int
xqc_moq_d18_find_entry(const xqc_moq_d18_registry_entry_t *entries,
    size_t count, uint64_t wire_type, xqc_moq_d18_message_kind_t *kind)
{
    for (size_t i = 0; i < count; ++i) {
        if (entries[i].wire_type == wire_type) {
            *kind = entries[i].kind;
            return 1;
        }
    }

    return 0;
}

int
xqc_moq_d18_is_subgroup_header_type(uint64_t wire_type)
{
    return wire_type <= 0x7f && (wire_type & 0x10) == 0x10;
}

static int
xqc_moq_d18_type_known(uint64_t wire_type)
{
    xqc_moq_d18_message_kind_t kind;

    if (wire_type == XQC_MOQ_D18_STREAM_TYPE_SETUP
        || wire_type == XQC_MOQ_D18_STREAM_TYPE_FETCH
        || wire_type == XQC_MOQ_D18_STREAM_TYPE_PADDING
        || xqc_moq_d18_is_subgroup_header_type(wire_type))
    {
        return 1;
    }

    if (xqc_moq_d18_find_entry(xqc_moq_d18_initial_requests,
            sizeof(xqc_moq_d18_initial_requests)
                / sizeof(xqc_moq_d18_initial_requests[0]),
            wire_type, &kind))
    {
        return 1;
    }

    return xqc_moq_d18_find_entry(xqc_moq_d18_request_messages,
        sizeof(xqc_moq_d18_request_messages)
            / sizeof(xqc_moq_d18_request_messages[0]),
        wire_type, &kind);
}

static int
xqc_moq_d18_lookup_uni(xqc_moq_d18_stream_class_t stream_class,
    xqc_moq_d18_message_position_t position, uint64_t wire_type,
    xqc_moq_d18_message_desc_t *desc)
{
    if (stream_class == XQC_MOQ_D18_STREAM_UNCLASSIFIED
        && position == XQC_MOQ_D18_POSITION_FIRST)
    {
        if (wire_type == XQC_MOQ_D18_STREAM_TYPE_SETUP) {
            desc->kind = XQC_MOQ_D18_MESSAGE_SETUP;
            desc->stream_class = XQC_MOQ_D18_STREAM_CONTROL;
            return XQC_MOQ_D18_REGISTRY_OK;
        }

        if (wire_type == XQC_MOQ_D18_STREAM_TYPE_FETCH) {
            desc->kind = XQC_MOQ_D18_MESSAGE_FETCH_HEADER;
            desc->stream_class = XQC_MOQ_D18_STREAM_FETCH;
            return XQC_MOQ_D18_REGISTRY_OK;
        }

        if (wire_type == XQC_MOQ_D18_STREAM_TYPE_PADDING) {
            desc->kind = XQC_MOQ_D18_MESSAGE_PADDING;
            desc->stream_class = XQC_MOQ_D18_STREAM_PADDING;
            return XQC_MOQ_D18_REGISTRY_OK;
        }

        if (xqc_moq_d18_is_subgroup_header_type(wire_type)) {
            desc->kind = XQC_MOQ_D18_MESSAGE_SUBGROUP_HEADER;
            desc->stream_class = XQC_MOQ_D18_STREAM_SUBGROUP;
            return XQC_MOQ_D18_REGISTRY_OK;
        }
    }

    if (stream_class == XQC_MOQ_D18_STREAM_CONTROL
        && position == XQC_MOQ_D18_POSITION_NEXT
        && wire_type == XQC_MOQ_D18_MSG_GOAWAY)
    {
        desc->kind = XQC_MOQ_D18_MESSAGE_GOAWAY;
        desc->stream_class = XQC_MOQ_D18_STREAM_CONTROL;
        return XQC_MOQ_D18_REGISTRY_OK;
    }

    return xqc_moq_d18_type_known(wire_type)
        ? XQC_MOQ_D18_REGISTRY_INVALID_PLACEMENT
        : XQC_MOQ_D18_REGISTRY_UNKNOWN_TYPE;
}

static int
xqc_moq_d18_lookup_bidi(xqc_moq_d18_stream_class_t stream_class,
    xqc_moq_d18_message_position_t position, uint64_t wire_type,
    xqc_moq_d18_message_desc_t *desc)
{
    xqc_moq_d18_message_kind_t kind;

    if (stream_class == XQC_MOQ_D18_STREAM_UNCLASSIFIED
        && position == XQC_MOQ_D18_POSITION_FIRST
        && xqc_moq_d18_find_entry(xqc_moq_d18_initial_requests,
            sizeof(xqc_moq_d18_initial_requests)
                / sizeof(xqc_moq_d18_initial_requests[0]),
            wire_type, &kind))
    {
        desc->kind = kind;
        desc->stream_class = XQC_MOQ_D18_STREAM_REQUEST;
        return XQC_MOQ_D18_REGISTRY_OK;
    }

    if (stream_class == XQC_MOQ_D18_STREAM_REQUEST
        && position == XQC_MOQ_D18_POSITION_NEXT
        && xqc_moq_d18_find_entry(xqc_moq_d18_request_messages,
            sizeof(xqc_moq_d18_request_messages)
                / sizeof(xqc_moq_d18_request_messages[0]),
            wire_type, &kind))
    {
        desc->kind = kind;
        desc->stream_class = XQC_MOQ_D18_STREAM_REQUEST;
        return XQC_MOQ_D18_REGISTRY_OK;
    }

    return xqc_moq_d18_type_known(wire_type)
        ? XQC_MOQ_D18_REGISTRY_INVALID_PLACEMENT
        : XQC_MOQ_D18_REGISTRY_UNKNOWN_TYPE;
}

int
xqc_moq_d18_registry_lookup(uint32_t version,
    xqc_moq_d18_stream_direction_t direction,
    xqc_moq_d18_stream_class_t stream_class,
    xqc_moq_d18_message_position_t position, uint64_t wire_type,
    xqc_moq_d18_message_desc_t *desc)
{
    xqc_moq_d18_message_desc_t result = {
        .wire_type = wire_type,
        .kind = XQC_MOQ_D18_MESSAGE_NONE,
        .stream_class = stream_class,
    };
    int ret;

    if (desc == NULL || direction == XQC_MOQ_D18_DIRECTION_UNKNOWN
        || position > XQC_MOQ_D18_POSITION_NEXT)
    {
        return XQC_MOQ_D18_REGISTRY_INVALID_ARGUMENT;
    }

    if (version != XQC_MOQ_D18_VERSION) {
        return XQC_MOQ_D18_REGISTRY_UNSUPPORTED_VERSION;
    }

    if (direction == XQC_MOQ_D18_DIRECTION_UNI) {
        ret = xqc_moq_d18_lookup_uni(stream_class, position, wire_type,
                                     &result);

    } else if (direction == XQC_MOQ_D18_DIRECTION_BIDI) {
        ret = xqc_moq_d18_lookup_bidi(stream_class, position, wire_type,
                                      &result);

    } else {
        return XQC_MOQ_D18_REGISTRY_INVALID_ARGUMENT;
    }

    if (ret == XQC_MOQ_D18_REGISTRY_OK) {
        *desc = result;
    }
    return ret;
}

int
xqc_moq_d18_stream_resolve(xqc_moq_d18_stream_context_t *context,
    uint64_t wire_type, xqc_moq_d18_message_desc_t *desc)
{
    xqc_moq_d18_message_desc_t result;
    int ret;

    if (context == NULL || desc == NULL) {
        return XQC_MOQ_D18_REGISTRY_INVALID_ARGUMENT;
    }

    ret = xqc_moq_d18_registry_lookup(
        XQC_MOQ_D18_VERSION, context->direction, context->stream_class,
        context->position, wire_type, &result);
    if (ret != XQC_MOQ_D18_REGISTRY_OK) {
        return ret;
    }

    context->stream_class = result.stream_class;
    *desc = result;
    return XQC_MOQ_D18_REGISTRY_OK;
}

void
xqc_moq_d18_stream_commit_message(
    xqc_moq_d18_stream_context_t *context)
{
    if (context != NULL) {
        context->position = XQC_MOQ_D18_POSITION_NEXT;
    }
}
