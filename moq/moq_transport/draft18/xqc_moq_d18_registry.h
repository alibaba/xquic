#ifndef _XQC_MOQ_D18_REGISTRY_H_INCLUDED_
#define _XQC_MOQ_D18_REGISTRY_H_INCLUDED_

#include <stdint.h>

#include "moq/moq_transport/draft18/xqc_moq_d18_defs.h"

typedef enum {
    XQC_MOQ_D18_MESSAGE_NONE,
    XQC_MOQ_D18_MESSAGE_SETUP,
    XQC_MOQ_D18_MESSAGE_GOAWAY,
    XQC_MOQ_D18_MESSAGE_SUBSCRIBE,
    XQC_MOQ_D18_MESSAGE_SUBSCRIBE_OK,
    XQC_MOQ_D18_MESSAGE_PUBLISH,
    XQC_MOQ_D18_MESSAGE_PUBLISH_OK,
    XQC_MOQ_D18_MESSAGE_PUBLISH_DONE,
    XQC_MOQ_D18_MESSAGE_FETCH,
    XQC_MOQ_D18_MESSAGE_FETCH_OK,
    XQC_MOQ_D18_MESSAGE_TRACK_STATUS,
    XQC_MOQ_D18_MESSAGE_PUBLISH_NAMESPACE,
    XQC_MOQ_D18_MESSAGE_SUBSCRIBE_NAMESPACE,
    XQC_MOQ_D18_MESSAGE_SUBSCRIBE_TRACKS,
    XQC_MOQ_D18_MESSAGE_NAMESPACE,
    XQC_MOQ_D18_MESSAGE_NAMESPACE_DONE,
    XQC_MOQ_D18_MESSAGE_PUBLISH_BLOCKED,
    XQC_MOQ_D18_MESSAGE_REQUEST_UPDATE,
    XQC_MOQ_D18_MESSAGE_REQUEST_OK,
    XQC_MOQ_D18_MESSAGE_REQUEST_ERROR,
    XQC_MOQ_D18_MESSAGE_FETCH_HEADER,
    XQC_MOQ_D18_MESSAGE_SUBGROUP_HEADER,
    XQC_MOQ_D18_MESSAGE_PADDING,
} xqc_moq_d18_message_kind_t;

typedef enum {
    XQC_MOQ_D18_DIRECTION_UNKNOWN,
    XQC_MOQ_D18_DIRECTION_BIDI,
    XQC_MOQ_D18_DIRECTION_UNI,
} xqc_moq_d18_stream_direction_t;

typedef enum {
    XQC_MOQ_D18_STREAM_UNCLASSIFIED,
    XQC_MOQ_D18_STREAM_CONTROL,
    XQC_MOQ_D18_STREAM_REQUEST,
    XQC_MOQ_D18_STREAM_SUBGROUP,
    XQC_MOQ_D18_STREAM_FETCH,
    XQC_MOQ_D18_STREAM_PADDING,
} xqc_moq_d18_stream_class_t;

typedef enum {
    XQC_MOQ_D18_POSITION_FIRST,
    XQC_MOQ_D18_POSITION_NEXT,
} xqc_moq_d18_message_position_t;

typedef enum {
    XQC_MOQ_D18_REGISTRY_OK = 0,
    XQC_MOQ_D18_REGISTRY_UNSUPPORTED_VERSION = -1,
    XQC_MOQ_D18_REGISTRY_UNKNOWN_TYPE = -2,
    XQC_MOQ_D18_REGISTRY_INVALID_PLACEMENT = -3,
    XQC_MOQ_D18_REGISTRY_INVALID_ARGUMENT = -4,
} xqc_moq_d18_registry_result_t;

typedef struct {
    uint64_t                        wire_type;
    xqc_moq_d18_message_kind_t      kind;
    xqc_moq_d18_stream_class_t      stream_class;
} xqc_moq_d18_message_desc_t;

typedef struct {
    xqc_moq_d18_stream_direction_t  direction;
    xqc_moq_d18_stream_class_t      stream_class;
    xqc_moq_d18_message_position_t  position;
} xqc_moq_d18_stream_context_t;

int xqc_moq_d18_registry_lookup(uint32_t version,
    xqc_moq_d18_stream_direction_t direction,
    xqc_moq_d18_stream_class_t stream_class,
    xqc_moq_d18_message_position_t position, uint64_t wire_type,
    xqc_moq_d18_message_desc_t *desc);

int xqc_moq_d18_is_subgroup_header_type(uint64_t wire_type);

int xqc_moq_d18_stream_resolve(xqc_moq_d18_stream_context_t *context,
    uint64_t wire_type, xqc_moq_d18_message_desc_t *desc);

void xqc_moq_d18_stream_commit_message(
    xqc_moq_d18_stream_context_t *context);

#endif /* _XQC_MOQ_D18_REGISTRY_H_INCLUDED_ */
