#ifndef _XQC_MOQ_CATALOG_H_INCLUDED_
#define _XQC_MOQ_CATALOG_H_INCLUDED_

#include "src/common/xqc_list.h"
#include "moq/xqc_moq.h"
#include "moq/moq_transport/xqc_moq_track.h"

#define STREAMING_FORMAT_VERSION "0.2"

typedef struct {
    xqc_moq_track_t                         track;
} xqc_moq_catalog_track_t;

typedef struct xqc_moq_catalog_common_track_fields_s {
    char                                    *track_namespace;
    char                                    *packaging;
    xqc_int_t                               renderGroup;
    xqc_moq_container_t                     container_format;
} xqc_moq_catalog_common_track_fields_t;

typedef struct xqc_moq_catalog_s {
    /* Root */
    xqc_int_t                               version;
    xqc_int_t                               sequence;
    xqc_int_t                               streaming_format;
    char                                    *streaming_format_version;
    xqc_moq_catalog_common_track_fields_t   common_track_fields;
    /* Encode */
    xqc_list_head_t                         *track_list_for_pub;
    /* Decode */
    xqc_list_head_t                         track_list_for_sub;
    xqc_log_t                               *log;
} xqc_moq_catalog_t;

extern const struct xqc_moq_track_ops_s xqc_moq_catalog_track_ops;

void xqc_moq_catalog_init(xqc_moq_catalog_t *catalog);

void xqc_moq_catalog_free_fields(xqc_moq_catalog_t *catalog);

xqc_int_t xqc_moq_catalog_encode(xqc_moq_catalog_t *catalog, uint8_t *buf, size_t buf_cap, xqc_int_t *encoded_len);

xqc_int_t xqc_moq_catalog_decode(xqc_moq_catalog_t *catalog, uint8_t *buf, size_t buf_len);

xqc_int_t xqc_moq_write_catalog(xqc_moq_session_t *session, uint64_t subscribe_id, xqc_moq_track_t *track);

xqc_int_t xqc_moq_subscribe_catalog(xqc_moq_session_t *session);

#endif /* _XQC_MOQ_CATALOG_H_INCLUDED_ */
