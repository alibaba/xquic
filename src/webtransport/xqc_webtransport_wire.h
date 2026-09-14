#ifndef XQC_WEBTRANSPORT_WIRE_H
#define XQC_WEBTRANSPORT_WIRE_H

#include <stdint.h>
#include <stddef.h>

#include "src/common/xqc_common.h"

typedef enum {
    XQC_WT_STREAM_TYPE_UNIDIRECTIONAL  = 0x54,
    XQC_WT_STREAM_TYPE_BIDIRECTIONAL   = 0x41,
    XQC_WT_STREAM_TYPE_CODE_UNKNOWN    = 1,
} xqc_wt_stream_type_code_t;

size_t xqc_wt_encode_session_id(uint64_t session_id, uint8_t *buf, size_t buf_len);

ssize_t xqc_wt_decode_session_id(const uint8_t *buf, size_t buf_len, uint64_t *session_id);

#endif /* XQC_WEBTRANSPORT_WIRE_H */
