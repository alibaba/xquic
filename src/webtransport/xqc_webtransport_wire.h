#ifndef XQC_WEBTRANSPORT_WIRE_H
#define XQC_WEBTRANSPORT_WIRE_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#include "src/common/xqc_common.h"

/* WebTransport stream type codes (RFC 9297 §4.3, §4.4) */
typedef enum {
    XQC_WT_STREAM_TYPE_UNIDIRECTIONAL  = 0x54,  /* WT uni stream */
    XQC_WT_STREAM_TYPE_BIDIRECTIONAL   = 0x41,  /* WEBTRANSPORT_STREAM (bidi) */
    XQC_WT_STREAM_TYPE_CODE_UNKNOWN    = 1,
} xqc_wt_stream_type_code_t;

/* Capsule types (RFC 9297 + WebTransport over HTTP/3) */
#define XQC_WT_CAPSULE_CLOSE_SESSION  0x2843
#define XQC_WT_CAPSULE_DRAIN_SESSION  0x2844

size_t xqc_wt_encode_session_id(uint64_t session_id, uint8_t *buf, size_t buf_len);

ssize_t xqc_wt_decode_session_id(const uint8_t *buf, size_t buf_len, uint64_t *session_id);

/**
 * Encode a CLOSE_WEBTRANSPORT_SESSION capsule.
 * Format: varint(capsule_type) + varint(payload_len) + 4-byte error_code + reason
 * @return bytes written, or 0 if buf_len is insufficient
 */
size_t xqc_wt_encode_close_session_capsule(uint32_t error_code,
    const char *reason, size_t reason_len,
    uint8_t *buf, size_t buf_len);

/**
 * Decode a CLOSE_WEBTRANSPORT_SESSION capsule payload (after capsule header).
 * @param payload     points to the capsule payload (after type+length)
 * @param payload_len length of payload
 * @param error_code  [out] parsed error code
 * @param reason      [out] pointer into payload buffer (not NUL-terminated)
 * @param reason_len  [out] length of reason string
 * @return bytes consumed from payload, or < 0 on error
 */
ssize_t xqc_wt_decode_close_session_capsule(const uint8_t *payload, size_t payload_len,
    uint32_t *error_code, const uint8_t **reason, size_t *reason_len);

/**
 * Encode a DRAIN_WEBTRANSPORT_SESSION capsule (empty payload).
 * @return bytes written, or 0 if buf_len is insufficient
 */
size_t xqc_wt_encode_drain_session_capsule(uint8_t *buf, size_t buf_len);

/**
 * Decode a capsule header (type + length) from a byte stream.
 * @param buf        input buffer
 * @param buf_len    input buffer length
 * @param type       [out] capsule type
 * @param payload_len [out] capsule payload length
 * @return bytes consumed for the header, or < 0 on error
 */
ssize_t xqc_wt_decode_capsule_header(const uint8_t *buf, size_t buf_len,
    uint64_t *type, uint64_t *payload_len);

#endif /* XQC_WEBTRANSPORT_WIRE_H */
