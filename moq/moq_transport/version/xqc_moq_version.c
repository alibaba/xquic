#include <string.h>

#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_transport/version/xqc_moq_version.h"

static const xqc_moq_alpn_policy_t xqc_moq_alpn_policies[] = {
    {
        XQC_ALPN_MOQ_LEGACY,
        sizeof(XQC_ALPN_MOQ_LEGACY) - 1,
        &xqc_moq_v5_profile_definition,
    },
    {
        XQC_ALPN_MOQ_DRAFT_05,
        sizeof(XQC_ALPN_MOQ_DRAFT_05) - 1,
        &xqc_moq_v5_profile_definition,
    },
    {
        XQC_ALPN_MOQ_DRAFT_14,
        sizeof(XQC_ALPN_MOQ_DRAFT_14) - 1,
        &xqc_moq_v14_profile_definition,
    },
    {
        XQC_ALPN_MOQ_DRAFT_18,
        sizeof(XQC_ALPN_MOQ_DRAFT_18) - 1,
        &xqc_moq_v18_profile_definition,
    },
};

size_t
xqc_moq_version_policy_count(void)
{
    return sizeof(xqc_moq_alpn_policies)
           / sizeof(xqc_moq_alpn_policies[0]);
}

const xqc_moq_alpn_policy_t *
xqc_moq_version_policy_at(size_t index)
{
    if (index >= xqc_moq_version_policy_count()) {
        return NULL;
    }

    return &xqc_moq_alpn_policies[index];
}

const xqc_moq_alpn_policy_t *
xqc_moq_version_policy_for_alpn(const char *alpn, size_t alpn_len)
{
    size_t i;

    if (alpn == NULL || alpn_len == 0) {
        return NULL;
    }

    for (i = 0; i < xqc_moq_version_policy_count(); ++i)
    {
        const xqc_moq_alpn_policy_t *policy = &xqc_moq_alpn_policies[i];
        if (policy->alpn_len == alpn_len
            && memcmp(policy->alpn, alpn, alpn_len) == 0)
        {
            return policy;
        }
    }

    return NULL;
}

const xqc_moq_version_profile_t *
xqc_moq_version_profile_for_version(uint64_t wire_version)
{
    switch (wire_version) {
    case XQC_MOQ_VERSION_5:
        return xqc_moq_v5_profile();
    case XQC_MOQ_VERSION_14:
        return xqc_moq_v14_profile();
    case XQC_MOQ_VERSION_18:
        return xqc_moq_v18_profile();
    default:
        return NULL;
    }
}

xqc_bool_t
xqc_moq_profile_has_capability(const xqc_moq_version_profile_t *profile,
    xqc_moq_capability_t capability)
{
    if (profile == NULL) {
        return XQC_FALSE;
    }

    return (profile->capabilities & (uint64_t) capability) != 0;
}

xqc_int_t
xqc_moq_profile_validate_setup(const xqc_moq_version_profile_t *profile,
    uint64_t wire_version)
{
    if (profile == NULL) {
        return -XQC_EPARAM;
    }

    return profile->wire_version == wire_version ? XQC_OK : -XQC_EVERSION;
}

xqc_int_t
xqc_moq_profile_require(const xqc_moq_version_profile_t *profile,
    xqc_moq_capability_t capability)
{
    if (profile == NULL) {
        return -XQC_EPARAM;
    }

    return xqc_moq_profile_has_capability(profile, capability)
           ? XQC_OK : -XQC_EALPN_NOT_SUPPORTED;
}

xqc_moq_stream_kind_t
xqc_moq_profile_classify_stream(const xqc_moq_version_profile_t *profile,
    xqc_moq_stream_kind_t current_kind, uint64_t wire_type)
{
    if (profile == NULL || profile->classify_stream == NULL) {
        return current_kind;
    }

    return profile->classify_stream(current_kind, wire_type);
}

xqc_moq_stream_kind_t
xqc_moq_profile_classify_outbound_stream(
    const xqc_moq_version_profile_t *profile,
    xqc_moq_stream_kind_t current_kind,
    xqc_moq_semantic_id_t semantic, uint64_t wire_type)
{
    if (profile == NULL || profile->classify_outbound_stream == NULL) {
        return current_kind;
    }

    return profile->classify_outbound_stream(
        current_kind, semantic, wire_type);
}

const xqc_moq_message_codec_entry_t *
xqc_moq_profile_find_codec(const xqc_moq_version_profile_t *profile,
    xqc_moq_stream_kind_t stream_kind, uint64_t wire_type)
{
    const xqc_moq_message_codec_entry_t *codecs;
    size_t codecs_count;
    size_t i;

    if (profile == NULL) {
        return NULL;
    }

    if ((stream_kind == XQC_MOQ_STREAM_V5_TRACK
         && !xqc_moq_profile_has_capability(
             profile, XQC_MOQ_CAP_TRACK_STREAM))
        || ((stream_kind == XQC_MOQ_STREAM_V14_SUBGROUP
             || stream_kind == XQC_MOQ_STREAM_D18_SUBGROUP)
            && !xqc_moq_profile_has_capability(
                profile, XQC_MOQ_CAP_SUBGROUP_STREAM)))
    {
        return NULL;
    }

    if (profile->normalize_wire_type != NULL) {
        wire_type = profile->normalize_wire_type(stream_kind, wire_type);
    }

    if (stream_kind == XQC_MOQ_STREAM_CONTROL) {
        codecs = profile->control_codecs;
        codecs_count = profile->control_codecs_count;

    } else if (stream_kind != XQC_MOQ_STREAM_UNKNOWN) {
        codecs = profile->data_codecs;
        codecs_count = profile->data_codecs_count;

    } else {
        return NULL;
    }

    for (i = 0; i < codecs_count; ++i) {
        if (codecs[i].stream_kind_mask != 0
            && (codecs[i].stream_kind_mask
                & XQC_MOQ_STREAM_KIND_MASK(stream_kind)) == 0)
        {
            continue;
        }
        if (codecs[i].wire_type == wire_type) {
            return &codecs[i];
        }
    }

    return NULL;
}

const xqc_moq_message_codec_entry_t *
xqc_moq_profile_find_semantic_codec(
    const xqc_moq_version_profile_t *profile,
    xqc_moq_semantic_id_t semantic)
{
    if (profile == NULL) {
        return NULL;
    }

    const xqc_moq_message_codec_entry_t *tables[] = {
        profile->control_codecs,
        profile->data_codecs,
        profile->continuation_codecs,
    };
    const size_t counts[] = {
        profile->control_codecs_count,
        profile->data_codecs_count,
        profile->continuation_codecs_count,
    };
    for (size_t table = 0;
         table < sizeof(tables) / sizeof(tables[0]); table++)
    {
        for (size_t i = 0; i < counts[table]; i++) {
            if (tables[table][i].semantic == semantic) {
                return &tables[table][i];
            }
        }
    }
    return NULL;
}

static const xqc_moq_message_codec_entry_t *
xqc_moq_profile_find_semantic_codec_for_kind(
    const xqc_moq_version_profile_t *profile,
    xqc_moq_semantic_id_t semantic,
    xqc_moq_stream_kind_t stream_kind)
{
    if (profile == NULL || stream_kind == XQC_MOQ_STREAM_UNKNOWN) {
        return NULL;
    }
    const xqc_moq_message_codec_entry_t *tables[] = {
        profile->control_codecs,
        profile->data_codecs,
        profile->continuation_codecs,
    };
    const size_t counts[] = {
        profile->control_codecs_count,
        profile->data_codecs_count,
        profile->continuation_codecs_count,
    };
    uint64_t kind_mask = XQC_MOQ_STREAM_KIND_MASK(stream_kind);
    for (size_t table = 0;
         table < sizeof(tables) / sizeof(tables[0]); table++)
    {
        for (size_t i = 0; i < counts[table]; i++) {
            const xqc_moq_message_codec_entry_t *codec =
                &tables[table][i];
            if (codec->semantic == semantic
                && (codec->stream_kind_mask == 0
                    || (codec->stream_kind_mask & kind_mask) != 0))
            {
                return codec;
            }
        }
    }
    return NULL;
}

static xqc_int_t
xqc_moq_profile_default_wire_type(
    const xqc_moq_version_profile_t *profile,
    xqc_moq_semantic_id_t semantic, uint64_t *wire_type)
{
    if (profile == NULL || wire_type == NULL) {
        return -XQC_EPARAM;
    }

    switch (semantic) {
    case XQC_MOQ_SEMANTIC_CLIENT_SETUP:
        *wire_type = profile->client_setup_type;
        break;
    case XQC_MOQ_SEMANTIC_SERVER_SETUP:
        *wire_type = profile->server_setup_type;
        break;
    case XQC_MOQ_SEMANTIC_SUBSCRIBE:
        *wire_type = XQC_MOQ_MSG_SUBSCRIBE;
        break;
    case XQC_MOQ_SEMANTIC_SUBSCRIBE_UPDATE:
        *wire_type = XQC_MOQ_MSG_SUBSCRIBE_UPDATE;
        break;
    case XQC_MOQ_SEMANTIC_UNSUBSCRIBE:
        *wire_type = XQC_MOQ_MSG_UNSUBSCRIBE;
        break;
    case XQC_MOQ_SEMANTIC_SUBSCRIBE_OK:
        *wire_type = XQC_MOQ_MSG_SUBSCRIBE_OK;
        break;
    case XQC_MOQ_SEMANTIC_SUBSCRIBE_ERROR:
        *wire_type = XQC_MOQ_MSG_SUBSCRIBE_ERROR;
        break;
    case XQC_MOQ_SEMANTIC_PUBLISH:
        *wire_type = XQC_MOQ_MSG_PUBLISH;
        break;
    case XQC_MOQ_SEMANTIC_PUBLISH_OK:
        *wire_type = XQC_MOQ_MSG_PUBLISH_OK;
        break;
    case XQC_MOQ_SEMANTIC_PUBLISH_ERROR:
        *wire_type = XQC_MOQ_MSG_PUBLISH_ERROR;
        break;
    case XQC_MOQ_SEMANTIC_PUBLISH_DONE:
        *wire_type = XQC_MOQ_MSG_PUBLISH_DONE;
        break;
    case XQC_MOQ_SEMANTIC_OBJECT_STREAM:
        *wire_type = XQC_MOQ_MSG_OBJECT_STREAM;
        break;
    case XQC_MOQ_SEMANTIC_SUBGROUP:
        *wire_type = XQC_MOQ_SUBGROUP_TYPE_WITH_ID;
        break;
    case XQC_MOQ_SEMANTIC_SUBGROUP_OBJECT:
    case XQC_MOQ_SEMANTIC_TRACK_STREAM_OBJECT:
        *wire_type = 0;
        break;
    case XQC_MOQ_SEMANTIC_TRACK_HEADER:
        *wire_type = XQC_MOQ_MSG_STREAM_HEADER_TRACK;
        break;
    case XQC_MOQ_SEMANTIC_GOAWAY:
        *wire_type = XQC_MOQ_MSG_GOAWAY;
        break;
    case XQC_MOQ_SEMANTIC_SUBSCRIBE_NAMESPACE:
        *wire_type = XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE;
        break;
    case XQC_MOQ_SEMANTIC_SUBSCRIBE_NAMESPACE_OK:
        *wire_type = XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE_OK;
        break;
    case XQC_MOQ_SEMANTIC_SUBSCRIBE_NAMESPACE_ERROR:
        *wire_type = XQC_MOQ_MSG_SUBSCRIBE_NAMESPACE_ERROR;
        break;
    case XQC_MOQ_SEMANTIC_UNSUBSCRIBE_NAMESPACE:
        *wire_type = XQC_MOQ_MSG_UNSUBSCRIBE_NAMESPACE;
        break;
    case XQC_MOQ_SEMANTIC_PUBLISH_NAMESPACE:
        *wire_type = XQC_MOQ_MSG_PUBLISH_NAMESPACE;
        break;
    case XQC_MOQ_SEMANTIC_PUBLISH_NAMESPACE_DONE:
        *wire_type = XQC_MOQ_MSG_PUBLISH_NAMESPACE_DONE;
        break;
    default:
        return -XQC_EALPN_NOT_SUPPORTED;
    }

    return XQC_OK;
}

xqc_int_t
xqc_moq_profile_resolve_outbound(
    const xqc_moq_version_profile_t *profile,
    xqc_moq_stream_kind_t current_kind,
    xqc_moq_semantic_id_t semantic,
    xqc_moq_message_resolution_t *resolution)
{
    uint64_t wire_type;
    xqc_int_t ret;

    if (profile == NULL || resolution == NULL) {
        return -XQC_EPARAM;
    }

    if (profile->resolve_outbound != NULL) {
        ret = profile->resolve_outbound(current_kind, semantic, &wire_type);
    } else {
        ret = xqc_moq_profile_default_wire_type(profile, semantic, &wire_type);
    }
    if (ret != XQC_OK) {
        return ret;
    }

    resolution->semantic = semantic;
    resolution->wire_type = wire_type;
    resolution->stream_kind = xqc_moq_profile_classify_outbound_stream(
        profile, current_kind, semantic, wire_type);
    resolution->codec = xqc_moq_profile_find_semantic_codec_for_kind(
        profile, semantic, resolution->stream_kind);
    if (resolution->codec == NULL) {
        resolution->codec = xqc_moq_profile_find_codec(
            profile, resolution->stream_kind, wire_type);
    }
    if (resolution->codec == NULL || resolution->codec->initialize == NULL) {
        return -XQC_EALPN_NOT_SUPPORTED;
    }

    return XQC_OK;
}

xqc_bool_t
xqc_moq_profile_next_data_codec(const xqc_moq_version_profile_t *profile,
    xqc_moq_stream_kind_t stream_kind, uint64_t current_wire_type,
    const xqc_moq_message_codec_entry_t **next_codec)
{
    if (profile == NULL || profile->next_data_semantic == NULL
        || next_codec == NULL)
    {
        return XQC_FALSE;
    }

    xqc_moq_semantic_id_t semantic;
    if (!profile->next_data_semantic(
            stream_kind, current_wire_type, &semantic))
    {
        return XQC_FALSE;
    }
    *next_codec = xqc_moq_profile_find_semantic_codec(profile, semantic);
    return *next_codec != NULL;
}

xqc_int_t
xqc_moq_profile_prepare_data_message(xqc_moq_stream_t *stream,
    const xqc_moq_message_codec_entry_t *codec,
    xqc_moq_msg_base_t *msg_base)
{
    if (stream == NULL || stream->session == NULL || codec == NULL
        || msg_base == NULL
        || stream->session->profile == NULL)
    {
        return -XQC_EPARAM;
    }

    xqc_int_t ret = xqc_moq_session_require_active(stream->session);
    if (ret != XQC_OK) {
        return ret;
    }

    if (stream->session->profile->prepare_data_message == NULL) {
        return XQC_OK;
    }

    return stream->session->profile->prepare_data_message(
        stream, codec, msg_base);
}

xqc_int_t
xqc_moq_profile_decode_datagram(xqc_moq_session_t *session,
    const uint8_t *data, size_t data_len)
{
    xqc_int_t ret;

    if (session == NULL || data == NULL || data_len == 0) {
        return -XQC_EPARAM;
    }

    ret = xqc_moq_session_require_active(session);
    if (ret != XQC_OK) {
        return ret;
    }

    ret = xqc_moq_profile_require(session->profile,
                                  XQC_MOQ_CAP_OBJECT_DATAGRAM);
    if (ret != XQC_OK) {
        return ret;
    }

    if (session->profile->decode_datagram == NULL) {
        return -XQC_EALPN_NOT_SUPPORTED;
    }

    return session->profile->decode_datagram(session, data, data_len);
}

xqc_int_t
xqc_moq_profile_adapt_subscribe(xqc_moq_session_t *session,
    xqc_moq_subscribe_msg_t *subscribe)
{
    if (session == NULL || subscribe == NULL || session->profile == NULL) {
        return -XQC_EPARAM;
    }

    xqc_int_t ret = xqc_moq_session_require_active(session);
    if (ret != XQC_OK) {
        return ret;
    }

    if (session->profile->adapt_subscribe == NULL) {
        return XQC_OK;
    }

    return session->profile->adapt_subscribe(subscribe);
}
