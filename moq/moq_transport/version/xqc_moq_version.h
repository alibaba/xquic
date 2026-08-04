#ifndef _XQC_MOQ_VERSION_H_INCLUDED_
#define _XQC_MOQ_VERSION_H_INCLUDED_

#include <stddef.h>
#include <stdint.h>

#include "moq/xqc_moq.h"

typedef enum {
    XQC_MOQ_STREAM_CONTROL,
    XQC_MOQ_STREAM_V5_OBJECT,
    XQC_MOQ_STREAM_V5_TRACK,
    XQC_MOQ_STREAM_V14_SUBGROUP,
    XQC_MOQ_STREAM_D18_REQUEST,
    XQC_MOQ_STREAM_D18_SUBGROUP,
    XQC_MOQ_STREAM_D18_FETCH,
    XQC_MOQ_STREAM_UNKNOWN,
} xqc_moq_stream_kind_t;

typedef enum {
    XQC_MOQ_DATA_STRATEGY_OBJECT_TRACK,
    XQC_MOQ_DATA_STRATEGY_SUBGROUP,
} xqc_moq_data_strategy_t;

typedef enum {
    XQC_MOQ_SEMANTIC_SETUP = 0x0ff,
    XQC_MOQ_SEMANTIC_CLIENT_SETUP = 0x100,
    XQC_MOQ_SEMANTIC_SERVER_SETUP,
    XQC_MOQ_SEMANTIC_SUBSCRIBE,
    XQC_MOQ_SEMANTIC_SUBSCRIBE_UPDATE,
    XQC_MOQ_SEMANTIC_UNSUBSCRIBE,
    XQC_MOQ_SEMANTIC_SUBSCRIBE_OK,
    XQC_MOQ_SEMANTIC_SUBSCRIBE_ERROR,
    XQC_MOQ_SEMANTIC_PUBLISH,
    XQC_MOQ_SEMANTIC_PUBLISH_OK,
    XQC_MOQ_SEMANTIC_PUBLISH_ERROR,
    XQC_MOQ_SEMANTIC_PUBLISH_DONE,
    XQC_MOQ_SEMANTIC_OBJECT_STREAM,
    XQC_MOQ_SEMANTIC_SUBGROUP,
    XQC_MOQ_SEMANTIC_SUBGROUP_OBJECT,
    XQC_MOQ_SEMANTIC_TRACK_HEADER,
    XQC_MOQ_SEMANTIC_TRACK_STREAM_OBJECT,
    XQC_MOQ_SEMANTIC_GOAWAY,
    XQC_MOQ_SEMANTIC_SUBSCRIBE_NAMESPACE,
    XQC_MOQ_SEMANTIC_SUBSCRIBE_NAMESPACE_OK,
    XQC_MOQ_SEMANTIC_SUBSCRIBE_NAMESPACE_ERROR,
    XQC_MOQ_SEMANTIC_UNSUBSCRIBE_NAMESPACE,
    XQC_MOQ_SEMANTIC_PUBLISH_NAMESPACE,
    XQC_MOQ_SEMANTIC_PUBLISH_NAMESPACE_DONE,
    XQC_MOQ_SEMANTIC_REQUEST_OK,
    XQC_MOQ_SEMANTIC_REQUEST_ERROR,
    XQC_MOQ_SEMANTIC_REQUEST_UPDATE,
    XQC_MOQ_SEMANTIC_SUBSCRIBE_TRACKS,
    XQC_MOQ_SEMANTIC_NAMESPACE,
    XQC_MOQ_SEMANTIC_NAMESPACE_DONE,
    XQC_MOQ_SEMANTIC_PUBLISH_BLOCKED,
    XQC_MOQ_SEMANTIC_GOAWAY_DRAFT18,
    XQC_MOQ_SEMANTIC_FETCH,
    XQC_MOQ_SEMANTIC_FETCH_OK,
    XQC_MOQ_SEMANTIC_TRACK_STATUS,
    XQC_MOQ_SEMANTIC_FETCH_HEADER,
    XQC_MOQ_SEMANTIC_FETCH_OBJECT,
} xqc_moq_semantic_id_t;

typedef enum {
    XQC_MOQ_CAP_TRACK_STREAM        = 1ULL << 0,
    XQC_MOQ_CAP_SUBGROUP_STREAM     = 1ULL << 2,
    XQC_MOQ_CAP_OBJECT_DATAGRAM     = 1ULL << 3,
    XQC_MOQ_CAP_PUBLISH             = 1ULL << 4,
    XQC_MOQ_CAP_SUBSCRIBE_NAMESPACE = 1ULL << 5,
    XQC_MOQ_CAP_HEADER_EXTENSION    = 1ULL << 6,
} xqc_moq_capability_t;

typedef struct xqc_moq_message_codec_entry_s {
    uint64_t wire_type;
    void *(*create)(void);
    void (*destroy)(void *);
    void (*initialize)(xqc_moq_msg_base_t *);
    xqc_moq_semantic_id_t semantic;
    /* Zero keeps legacy profile entries usable on every stream kind. */
    uint64_t stream_kind_mask;
} xqc_moq_message_codec_entry_t;

#define XQC_MOQ_STREAM_KIND_MASK(kind) (1ULL << (kind))

typedef struct {
    xqc_moq_semantic_id_t semantic;
    uint64_t wire_type;
    xqc_moq_stream_kind_t stream_kind;
    const xqc_moq_message_codec_entry_t *codec;
} xqc_moq_message_resolution_t;

typedef xqc_int_t (*xqc_moq_resolve_outbound_pt)(
    xqc_moq_stream_kind_t current_kind,
    xqc_moq_semantic_id_t semantic,
    uint64_t *wire_type);

typedef xqc_moq_stream_kind_t (*xqc_moq_classify_stream_pt)(
    xqc_moq_stream_kind_t current_kind, uint64_t wire_type);

typedef xqc_moq_stream_kind_t (*xqc_moq_classify_outbound_stream_pt)(
    xqc_moq_stream_kind_t current_kind,
    xqc_moq_semantic_id_t semantic, uint64_t wire_type);

typedef uint64_t (*xqc_moq_normalize_wire_type_pt)(
    xqc_moq_stream_kind_t stream_kind, uint64_t wire_type);

typedef xqc_bool_t (*xqc_moq_next_data_semantic_pt)(
    xqc_moq_stream_kind_t stream_kind, uint64_t current_wire_type,
    xqc_moq_semantic_id_t *next_semantic);

typedef xqc_int_t (*xqc_moq_prepare_data_message_pt)(
    xqc_moq_stream_t *stream,
    const xqc_moq_message_codec_entry_t *codec,
    xqc_moq_msg_base_t *msg_base);

typedef xqc_int_t (*xqc_moq_decode_datagram_pt)(
    xqc_moq_session_t *session, const uint8_t *data, size_t data_len);

typedef xqc_int_t (*xqc_moq_adapt_subscribe_pt)(
    xqc_moq_subscribe_msg_t *subscribe);

typedef struct xqc_moq_version_profile_s {
    const char *name;
    uint64_t wire_version;
    uint64_t capabilities;
    uint64_t client_setup_type;
    uint64_t server_setup_type;
    xqc_bool_t unified_setup;
    xqc_bool_t include_extdata_in_default_setup;
    /*
     * Whether the catalog track is advertised when the application made no
     * explicit choice. draft-05 peers expect it; a draft-14 peer that never
     * advertised a catalog track rejects the resulting SUBSCRIBE and closes
     * the session, so the default has to follow the negotiated profile.
     */
    xqc_bool_t catalog_default_enabled;
    xqc_moq_data_strategy_t data_strategy;
    const xqc_moq_message_codec_entry_t *control_codecs;
    size_t control_codecs_count;
    const xqc_moq_message_codec_entry_t *data_codecs;
    size_t data_codecs_count;
    const xqc_moq_message_codec_entry_t *continuation_codecs;
    size_t continuation_codecs_count;
    xqc_moq_classify_stream_pt classify_stream;
    xqc_moq_classify_outbound_stream_pt classify_outbound_stream;
    xqc_moq_normalize_wire_type_pt normalize_wire_type;
    xqc_moq_next_data_semantic_pt next_data_semantic;
    xqc_moq_prepare_data_message_pt prepare_data_message;
    xqc_moq_decode_datagram_pt decode_datagram;
    xqc_moq_adapt_subscribe_pt adapt_subscribe;
    xqc_moq_resolve_outbound_pt resolve_outbound;
} xqc_moq_version_profile_t;

typedef struct {
    const char *alpn;
    size_t alpn_len;
    const xqc_moq_version_profile_t *profile;
} xqc_moq_alpn_policy_t;

extern const xqc_moq_version_profile_t xqc_moq_v5_profile_definition;
extern const xqc_moq_version_profile_t xqc_moq_v14_profile_definition;
extern const xqc_moq_version_profile_t xqc_moq_v18_profile_definition;

const xqc_moq_alpn_policy_t *xqc_moq_version_policy_for_alpn(
    const char *alpn, size_t alpn_len);

size_t xqc_moq_version_policy_count(void);
const xqc_moq_alpn_policy_t *xqc_moq_version_policy_at(size_t index);

const xqc_moq_version_profile_t *xqc_moq_version_profile_for_version(
    uint64_t wire_version);

const xqc_moq_version_profile_t *xqc_moq_v5_profile(void);
const xqc_moq_version_profile_t *xqc_moq_v14_profile(void);
const xqc_moq_version_profile_t *xqc_moq_v18_profile(void);

xqc_bool_t xqc_moq_profile_has_capability(
    const xqc_moq_version_profile_t *profile,
    xqc_moq_capability_t capability);

xqc_int_t xqc_moq_profile_validate_setup(
    const xqc_moq_version_profile_t *profile, uint64_t wire_version);

xqc_int_t xqc_moq_profile_require(
    const xqc_moq_version_profile_t *profile,
    xqc_moq_capability_t capability);

xqc_moq_stream_kind_t xqc_moq_profile_classify_stream(
    const xqc_moq_version_profile_t *profile,
    xqc_moq_stream_kind_t current_kind, uint64_t wire_type);

xqc_moq_stream_kind_t xqc_moq_profile_classify_outbound_stream(
    const xqc_moq_version_profile_t *profile,
    xqc_moq_stream_kind_t current_kind,
    xqc_moq_semantic_id_t semantic, uint64_t wire_type);

const xqc_moq_message_codec_entry_t *xqc_moq_profile_find_codec(
    const xqc_moq_version_profile_t *profile,
    xqc_moq_stream_kind_t stream_kind, uint64_t wire_type);

const xqc_moq_message_codec_entry_t *xqc_moq_profile_find_semantic_codec(
    const xqc_moq_version_profile_t *profile,
    xqc_moq_semantic_id_t semantic);

xqc_int_t xqc_moq_profile_resolve_outbound(
    const xqc_moq_version_profile_t *profile,
    xqc_moq_stream_kind_t current_kind,
    xqc_moq_semantic_id_t semantic,
    xqc_moq_message_resolution_t *resolution);

xqc_bool_t xqc_moq_profile_next_data_codec(
    const xqc_moq_version_profile_t *profile,
    xqc_moq_stream_kind_t stream_kind, uint64_t current_wire_type,
    const xqc_moq_message_codec_entry_t **next_codec);

xqc_int_t xqc_moq_profile_prepare_data_message(
    xqc_moq_stream_t *stream,
    const xqc_moq_message_codec_entry_t *codec,
    xqc_moq_msg_base_t *msg_base);

xqc_int_t xqc_moq_profile_decode_datagram(
    xqc_moq_session_t *session, const uint8_t *data, size_t data_len);

xqc_int_t xqc_moq_profile_adapt_subscribe(
    xqc_moq_session_t *session, xqc_moq_subscribe_msg_t *subscribe);

#endif
