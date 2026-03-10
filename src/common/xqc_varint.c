#include "src/common/xqc_varint.h"
#include <string.h>

#define XQC_VARINT_MAX ((uint64_t)4611686018427387903ULL) /* 2^62 - 1 */

size_t
xqc_varint_len(uint64_t val)
{
    if (val <= 63) {
        return 1;
    }
    if (val <= 16383) {
        return 2;
    }
    if (val <= 1073741823) {
        return 4;
    }
    if (val <= XQC_VARINT_MAX) {
        return 8;
    }
    return 0;
}

size_t
xqc_varint_encode(uint8_t *buf, size_t buf_len, uint64_t val)
{
    size_t len = xqc_varint_len(val);
    if (len == 0 || buf_len < len) {
        return 0;
    }

    switch (len) {
    case 1:
        buf[0] = (uint8_t)val;
        break;
    case 2:
        buf[0] = (uint8_t)(0x40 | (val >> 8));
        buf[1] = (uint8_t)(val & 0xFF);
        break;
    case 4:
        buf[0] = (uint8_t)(0x80 | (val >> 24));
        buf[1] = (uint8_t)((val >> 16) & 0xFF);
        buf[2] = (uint8_t)((val >> 8) & 0xFF);
        buf[3] = (uint8_t)(val & 0xFF);
        break;
    case 8:
        buf[0] = (uint8_t)(0xC0 | (val >> 56));
        buf[1] = (uint8_t)((val >> 48) & 0xFF);
        buf[2] = (uint8_t)((val >> 40) & 0xFF);
        buf[3] = (uint8_t)((val >> 32) & 0xFF);
        buf[4] = (uint8_t)((val >> 24) & 0xFF);
        buf[5] = (uint8_t)((val >> 16) & 0xFF);
        buf[6] = (uint8_t)((val >> 8) & 0xFF);
        buf[7] = (uint8_t)(val & 0xFF);
        break;
    }
    return len;
}

size_t
xqc_varint_decode(const uint8_t *buf, size_t buf_len, uint64_t *out)
{
    if (buf_len == 0 || out == NULL) {
        return 0;
    }

    uint8_t prefix = buf[0] >> 6;
    size_t len = (size_t)1 << prefix;

    if (buf_len < len) {
        return 0;
    }

    uint64_t val = buf[0] & 0x3F;
    for (size_t i = 1; i < len; i++) {
        val = (val << 8) | buf[i];
    }

    *out = val;
    return len;
}
