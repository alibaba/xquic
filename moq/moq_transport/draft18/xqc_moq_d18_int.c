#include "moq/moq_transport/draft18/xqc_moq_d18_int.h"

size_t
xqc_moq_d18_int_len(uint64_t value)
{
    static const uint64_t limits[] = {
        0x7fULL,
        0x3fffULL,
        0x1fffffULL,
        0xfffffffULL,
        0x7ffffffffULL,
        0x3ffffffffffULL,
        0x1ffffffffffffULL,
        0xffffffffffffffULL,
    };
    for (size_t i = 0; i < sizeof(limits) / sizeof(limits[0]); i++) {
        if (value <= limits[i]) {
            return i + 1;
        }
    }
    return 9;
}

uint8_t *
xqc_moq_d18_int_write(uint8_t *buf, uint64_t value)
{
    size_t len = xqc_moq_d18_int_len(value);
    if (len == 1) {
        *buf = (uint8_t)value;
        return buf + 1;
    }
    for (size_t i = len; i > 1; i--) {
        buf[i - 1] = (uint8_t)value;
        value >>= 8;
    }
    if (len == 9) {
        buf[0] = 0xff;
    } else {
        buf[0] = (uint8_t)((0xffu << (9 - len)) | (uint8_t)value);
    }
    return buf + len;
}

int
xqc_moq_d18_int_read(const uint8_t *pos, const uint8_t *end,
    uint64_t *value)
{
    if (pos == NULL || end == NULL || value == NULL || pos >= end) {
        return -1;
    }
    uint8_t first = pos[0];
    size_t len = 1;
    uint8_t marker = 0x80;
    while ((first & marker) != 0) {
        len++;
        marker >>= 1;
        if (marker == 0) {
            break;
        }
    }
    if ((size_t)(end - pos) < len) {
        return -1;
    }
    uint64_t decoded = 0;
    if (len < 8) {
        decoded = first & (uint8_t)((1u << (8 - len)) - 1);
    }
    for (size_t i = 1; i < len; i++) {
        decoded = (decoded << 8) | pos[i];
    }
    *value = decoded;
    return (int)len;
}
