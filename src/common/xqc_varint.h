#ifndef XQC_VARINT_H
#define XQC_VARINT_H

#include "include/xqc_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * QUIC variable-length integer encoding (RFC 9000 Section 16).
 * Supports 1/2/4/8 byte encodings for values up to 2^62 - 1.
 */

/* Returns the number of bytes needed to encode val, or 0 on error. */
size_t xqc_varint_len(uint64_t val);

/* Encode val into buf. Returns bytes written, or 0 if buf too small. */
size_t xqc_varint_encode(uint8_t *buf, size_t buf_len, uint64_t val);

/* Decode a varint from buf. Returns bytes consumed, or 0 on error.
 * Decoded value is stored in *out. */
size_t xqc_varint_decode(const uint8_t *buf, size_t buf_len, uint64_t *out);

#ifdef __cplusplus
}
#endif

#endif /* XQC_VARINT_H */
