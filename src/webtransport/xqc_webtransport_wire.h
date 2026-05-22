#ifndef XQC_WEBTRANSPORT_WIRE_H
#define XQC_WEBTRANSPORT_WIRE_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#include "src/common/xqc_common.h"

/* WebTransport over HTTP/3 draft-15 stream type codes */
typedef enum {
    XQC_WT_STREAM_TYPE_UNIDIRECTIONAL  = 0x54,  /* WT uni stream */
    XQC_WT_STREAM_TYPE_BIDIRECTIONAL   = 0x41,  /* WEBTRANSPORT_STREAM (bidi) */
    XQC_WT_STREAM_TYPE_CODE_UNKNOWN    = 1,
} xqc_wt_stream_type_code_t;

/* Capsule types (HTTP Datagram/Capsule + WebTransport-H3 draft-15) */
#define XQC_WT_CAPSULE_CLOSE_SESSION  0x2843
#define XQC_WT_CAPSULE_DRAIN_SESSION  0x78ae
#define XQC_WT_CAPSULE_MAX_STREAMS_BIDI 0x190B4D3F
#define XQC_WT_CAPSULE_MAX_STREAMS_UNI  0x190B4D40
#define XQC_WT_CAPSULE_DATA_BLOCKED     0x190B4D41
#define XQC_WT_CAPSULE_MAX_STREAM_DATA  0x190B4D3E
#define XQC_WT_CAPSULE_STREAM_DATA_BLOCKED 0x190B4D42
#define XQC_WT_CAPSULE_STREAMS_BLOCKED_BIDI 0x190B4D43
#define XQC_WT_CAPSULE_STREAMS_BLOCKED_UNI  0x190B4D44
#define XQC_WT_CAPSULE_MAX_DATA         0x190B4D3D

#define XQC_WT_ERROR_BUFFERED_STREAM_REJECTED 0x3994bd84
#define XQC_WT_ERROR_SESSION_GONE      0x170d7b68
#define XQC_WT_ERROR_FLOW_CONTROL      0x045d4487
#define XQC_WT_ERROR_ALPN              0x0817b3dd
#define XQC_WT_ERROR_REQUIREMENTS_NOT_MET 0x212c0d48

#define XQC_WT_CLOSE_REASON_MAX_LEN 1024
#define XQC_WT_H3_ERROR_FIRST       0x52e4a40fa8dbULL
#define XQC_WT_H3_ERROR_LAST        0x52e5ac983162ULL

size_t xqc_wt_encode_session_id(uint64_t session_id, uint8_t *buf, size_t buf_len);

ssize_t xqc_wt_decode_session_id(const uint8_t *buf, size_t buf_len, uint64_t *session_id);

size_t xqc_wt_encode_h3_datagram_session_id(uint64_t session_id,
    uint8_t *buf, size_t buf_len);

ssize_t xqc_wt_decode_h3_datagram_session_id(const uint8_t *buf,
    size_t buf_len, uint64_t *session_id);

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

size_t xqc_wt_encode_flow_control_capsule(uint64_t capsule_type,
    uint64_t value, uint8_t *buf, size_t buf_len);

ssize_t xqc_wt_decode_flow_control_capsule_value(const uint8_t *payload,
    size_t payload_len, uint64_t *value);

uint64_t xqc_wt_app_error_to_h3(uint32_t app_error_code);

xqc_bool_t xqc_wt_h3_error_to_app(uint64_t h3_error_code,
    uint32_t *app_error_code);

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
