/**
 * xqc_webtransport_wire.c
 */

#include "xqc_webtransport_wire.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"

size_t
xqc_wt_encode_session_id(uint64_t session_id, uint8_t *buf, size_t buf_len)
{
    size_t need = xqc_put_varint_len(session_id);
    if (need == 0 || buf_len < need) {
        return 0;
    }
    (void)xqc_put_varint(buf, session_id);
    return need;
}

ssize_t
xqc_wt_decode_session_id(const uint8_t *buf, size_t buf_len, uint64_t *session_id)
{
    if (buf == NULL || session_id == NULL || buf_len == 0) {
        return -XQC_EPARAM;
    }

    const uint8_t *end = buf + buf_len;
    int            n   = xqc_vint_read(buf, end, session_id);
    if (n <= 0) {
        return -XQC_H3_DECODE_ERROR;
    }
    return n;
}

size_t
xqc_wt_encode_h3_datagram_session_id(uint64_t session_id,
    uint8_t *buf, size_t buf_len)
{
    if ((session_id & 0x03) != 0) {
        return 0;
    }
    return xqc_wt_encode_session_id(session_id >> 2, buf, buf_len);
}

ssize_t
xqc_wt_decode_h3_datagram_session_id(const uint8_t *buf,
    size_t buf_len, uint64_t *session_id)
{
    uint64_t quarter_stream_id = 0;
    ssize_t consumed = xqc_wt_decode_session_id(buf, buf_len, &quarter_stream_id);
    if (consumed <= 0) {
        return consumed;
    }
    if (quarter_stream_id > (UINT64_MAX >> 2)) {
        return -XQC_H3_DECODE_ERROR;
    }
    *session_id = quarter_stream_id << 2;
    return consumed;
}

/* ===== Capsule encoding/decoding (HTTP Datagram/Capsule + WebTransport-H3) ===== */

ssize_t
xqc_wt_decode_capsule_header(const uint8_t *buf, size_t buf_len,
    uint64_t *type, uint64_t *payload_len)
{
    if (buf == NULL || type == NULL || payload_len == NULL || buf_len == 0) {
        return -XQC_EPARAM;
    }

    const uint8_t *p   = buf;
    const uint8_t *end = buf + buf_len;
    int n;

    n = xqc_vint_read(p, end, type);
    if (n <= 0) {
        return -XQC_H3_DECODE_ERROR;
    }
    p += n;

    n = xqc_vint_read(p, end, payload_len);
    if (n <= 0) {
        return -XQC_H3_DECODE_ERROR;
    }
    p += n;

    return (ssize_t)(p - buf);
}

size_t
xqc_wt_encode_close_session_capsule(uint32_t error_code,
    const char *reason, size_t reason_len,
    uint8_t *buf, size_t buf_len)
{
    /* payload = 4-byte error_code (network byte order) + reason */
    size_t payload_len = 4 + reason_len;

    size_t type_vlen    = xqc_put_varint_len(XQC_WT_CAPSULE_CLOSE_SESSION);
    size_t payload_vlen = xqc_put_varint_len(payload_len);
    size_t total        = type_vlen + payload_vlen + payload_len;

    if (buf_len < total) {
        return 0;
    }

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_WT_CAPSULE_CLOSE_SESSION);
    p = xqc_put_varint(p, payload_len);

    /* error_code in network byte order (big-endian) */
    *p++ = (uint8_t)(error_code >> 24);
    *p++ = (uint8_t)(error_code >> 16);
    *p++ = (uint8_t)(error_code >> 8);
    *p++ = (uint8_t)(error_code);

    if (reason_len > 0 && reason != NULL) {
        memcpy(p, reason, reason_len);
        p += reason_len;
    }

    return (size_t)(p - buf);
}

ssize_t
xqc_wt_decode_close_session_capsule(const uint8_t *payload, size_t payload_len,
    uint32_t *error_code, const uint8_t **reason, size_t *reason_len)
{
    if (payload == NULL || error_code == NULL || payload_len < 4) {
        return -XQC_EPARAM;
    }

    *error_code = ((uint32_t)payload[0] << 24)
                | ((uint32_t)payload[1] << 16)
                | ((uint32_t)payload[2] << 8)
                | ((uint32_t)payload[3]);

    if (reason != NULL) {
        *reason = (payload_len > 4) ? (payload + 4) : NULL;
    }
    if (reason_len != NULL) {
        *reason_len = (payload_len > 4) ? (payload_len - 4) : 0;
    }

    return (ssize_t)payload_len;
}

size_t
xqc_wt_encode_drain_session_capsule(uint8_t *buf, size_t buf_len)
{
    /* DRAIN capsule has empty payload */
    size_t type_vlen    = xqc_put_varint_len(XQC_WT_CAPSULE_DRAIN_SESSION);
    size_t payload_vlen = xqc_put_varint_len(0);
    size_t total        = type_vlen + payload_vlen;

    if (buf_len < total) {
        return 0;
    }

    uint8_t *p = buf;
    p = xqc_put_varint(p, XQC_WT_CAPSULE_DRAIN_SESSION);
    p = xqc_put_varint(p, 0);

    return (size_t)(p - buf);
}

size_t
xqc_wt_encode_flow_control_capsule(uint64_t capsule_type,
    uint64_t value, uint8_t *buf, size_t buf_len)
{
    if (buf == NULL) {
        return 0;
    }

    size_t value_vlen   = xqc_put_varint_len(value);
    size_t type_vlen    = xqc_put_varint_len(capsule_type);
    size_t payload_vlen = xqc_put_varint_len(value_vlen);
    size_t total        = type_vlen + payload_vlen + value_vlen;
    if (value_vlen == 0 || type_vlen == 0 || payload_vlen == 0
        || buf_len < total)
    {
        return 0;
    }

    uint8_t *p = buf;
    p = xqc_put_varint(p, capsule_type);
    p = xqc_put_varint(p, value_vlen);
    p = xqc_put_varint(p, value);
    return (size_t)(p - buf);
}

ssize_t
xqc_wt_decode_flow_control_capsule_value(const uint8_t *payload,
    size_t payload_len, uint64_t *value)
{
    if (payload == NULL || value == NULL || payload_len == 0) {
        return -XQC_EPARAM;
    }

    const uint8_t *end = payload + payload_len;
    int n = xqc_vint_read(payload, end, value);
    if (n <= 0 || (size_t)n != payload_len) {
        return -XQC_H3_DECODE_ERROR;
    }
    return n;
}
