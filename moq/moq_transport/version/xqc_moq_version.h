#ifndef _XQC_MOQ_VERSION_H_INCLUDED_
#define _XQC_MOQ_VERSION_H_INCLUDED_

#include <stddef.h>
#include <stdint.h>

#include "moq/xqc_moq.h"

typedef enum {
    XQC_MOQ_STREAM_CONTROL,
    XQC_MOQ_STREAM_V5_OBJECT,
    XQC_MOQ_STREAM_V5_TRACK,
    XQC_MOQ_STREAM_V5_GROUP,
    XQC_MOQ_STREAM_V14_SUBGROUP,
    XQC_MOQ_STREAM_UNKNOWN,
} xqc_moq_stream_kind_t;

typedef enum {
    XQC_MOQ_CAP_TRACK_STREAM        = 1ULL << 0,
    XQC_MOQ_CAP_GROUP_STREAM        = 1ULL << 1,
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
} xqc_moq_message_codec_entry_t;

typedef xqc_moq_stream_kind_t (*xqc_moq_classify_stream_pt)(
    xqc_moq_stream_kind_t current_kind, uint64_t wire_type);

typedef uint64_t (*xqc_moq_normalize_wire_type_pt)(
    xqc_moq_stream_kind_t stream_kind, uint64_t wire_type);

typedef xqc_bool_t (*xqc_moq_next_data_message_pt)(
    xqc_moq_stream_kind_t stream_kind, uint64_t current_wire_type,
    uint64_t *next_wire_type);

typedef struct xqc_moq_version_profile_s {
    const char *name;
    uint64_t wire_version;
    uint64_t capabilities;
    uint64_t client_setup_type;
    uint64_t server_setup_type;
    const xqc_moq_message_codec_entry_t *control_codecs;
    size_t control_codecs_count;
    const xqc_moq_message_codec_entry_t *data_codecs;
    size_t data_codecs_count;
    xqc_moq_classify_stream_pt classify_stream;
    xqc_moq_normalize_wire_type_pt normalize_wire_type;
    xqc_moq_next_data_message_pt next_data_message;
} xqc_moq_version_profile_t;

typedef struct {
    const char *alpn;
    size_t alpn_len;
    const xqc_moq_version_profile_t *profile;
} xqc_moq_alpn_policy_t;

extern const xqc_moq_version_profile_t xqc_moq_v5_profile_definition;
extern const xqc_moq_version_profile_t xqc_moq_v14_profile_definition;

const xqc_moq_alpn_policy_t *xqc_moq_version_policy_for_alpn(
    const char *alpn, size_t alpn_len);

size_t xqc_moq_version_policy_count(void);
const xqc_moq_alpn_policy_t *xqc_moq_version_policy_at(size_t index);

const xqc_moq_version_profile_t *xqc_moq_version_profile_for_version(
    uint64_t wire_version);

const xqc_moq_version_profile_t *xqc_moq_v5_profile(void);
const xqc_moq_version_profile_t *xqc_moq_v14_profile(void);

xqc_bool_t xqc_moq_profile_has_capability(
    const xqc_moq_version_profile_t *profile,
    xqc_moq_capability_t capability);

xqc_moq_stream_kind_t xqc_moq_profile_classify_stream(
    const xqc_moq_version_profile_t *profile,
    xqc_moq_stream_kind_t current_kind, uint64_t wire_type);

const xqc_moq_message_codec_entry_t *xqc_moq_profile_find_codec(
    const xqc_moq_version_profile_t *profile,
    xqc_moq_stream_kind_t stream_kind, uint64_t wire_type);

xqc_bool_t xqc_moq_profile_next_data_message(
    const xqc_moq_version_profile_t *profile,
    xqc_moq_stream_kind_t stream_kind, uint64_t current_wire_type,
    uint64_t *next_wire_type);

#endif
