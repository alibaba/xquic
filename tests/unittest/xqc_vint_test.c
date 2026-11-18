/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_vint_test.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"
#include <string.h>
#include <CUnit/CUnit.h>
#include <stdio.h>

void
xqc_test_vint()
{

    uint64_t test[] = {63,16383,1073741823,4611686018427387903};
    int i = 0;
    for (; i < sizeof(test)/ sizeof(test[0]); i++) {
        unsigned char buff[8];
        memset(buff, 0, sizeof(buff));

        unsigned bits = xqc_vint_get_2bit(test[i]);
        unsigned len = xqc_vint_len(bits);
        xqc_vint_write(buff, test[i], bits, len);

        uint64_t val;
        int ret = xqc_vint_read(buff, buff+len, &val);

        CU_ASSERT(test[i] == val && ret == len);
    }
}

/* Independent wire values from draft-ietf-moq-transport-22 section 8.1. */
static const struct {
    uint64_t    value;
    size_t      len;
    uint8_t     wire[9];
} vi64_cases[] = {
    {0, 1, {0x00}},
    {37, 1, {0x25}},
    {127, 1, {0x7f}},
    {128, 2, {0x80, 0x80}},
    {15293, 2, {0xbb, 0xbd}},
    {16383, 2, {0xbf, 0xff}},
    {16384, 3, {0xc0, 0x40, 0x00}},
    {2097151, 3, {0xdf, 0xff, 0xff}},
    {2097152, 4, {0xe0, 0x20, 0x00, 0x00}},
    {226442877, 4, {0xed, 0x7f, 0x3e, 0x7d}},
    {268435455, 4, {0xef, 0xff, 0xff, 0xff}},
    {268435456, 5, {0xf0, 0x10, 0x00, 0x00, 0x00}},
    {34359738367ULL, 5, {0xf7, 0xff, 0xff, 0xff, 0xff}},
    {34359738368ULL, 6, {0xf8, 0x08, 0x00, 0x00, 0x00, 0x00}},
    {2893212287960ULL, 6, {0xfa, 0xa1, 0xa0, 0xe4, 0x03, 0xd8}},
    {4398046511103ULL, 6, {0xfb, 0xff, 0xff, 0xff, 0xff, 0xff}},
    {4398046511104ULL, 7, {0xfc, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {151288809941952ULL, 7, {0xfc, 0x89, 0x98, 0xab, 0xc6, 0x6b, 0xc0}},
    {562949953421311ULL, 7, {0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
    {562949953421312ULL, 8, {0xfe, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {70423237261249041ULL, 8,
        {0xfe, 0xfa, 0x31, 0x8f, 0xa8, 0xe3, 0xca, 0x11}},
    {72057594037927935ULL, 8,
        {0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
    {72057594037927936ULL, 9,
        {0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {UINT64_MAX, 9, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
};

void
xqc_test_vi64_vectors(void)
{
    for (size_t i = 0; i < sizeof(vi64_cases) / sizeof(vi64_cases[0]); i++) {
        uint8_t buf[XQC_VI64_MAX_LEN + 1];
        uint64_t value = ~vi64_cases[i].value;
        size_t len = vi64_cases[i].len;

        xqc_memset(buf, 0xa5, sizeof(buf));
        CU_ASSERT_EQUAL(xqc_vi64_len(vi64_cases[i].value), len);
        CU_ASSERT_EQUAL(xqc_vi64_write(buf, buf + len, vi64_cases[i].value),
                        len);
        CU_ASSERT_EQUAL(xqc_memcmp(buf, vi64_cases[i].wire, len), 0);
        CU_ASSERT_EQUAL(buf[len], 0xa5);
        CU_ASSERT_EQUAL(xqc_vi64_read(buf, buf + sizeof(buf), &value), len);
        CU_ASSERT_EQUAL(value, vi64_cases[i].value);
    }
}

void
xqc_test_vi64_bounds(void)
{
    for (size_t i = 0; i < sizeof(vi64_cases) / sizeof(vi64_cases[0]); i++) {
        const uint8_t *wire = vi64_cases[i].wire;
        uint64_t value = ~vi64_cases[i].value;
        uint8_t buf[XQC_VI64_MAX_LEN], unchanged[XQC_VI64_MAX_LEN];

        xqc_memset(buf, 0xa5, sizeof(buf));
        xqc_memcpy(unchanged, buf, sizeof(buf));
        for (size_t len = 0; len < vi64_cases[i].len; len++) {
            CU_ASSERT_EQUAL(xqc_vi64_read(wire, wire + len, &value), -1);
            CU_ASSERT_EQUAL(value, ~vi64_cases[i].value);
            CU_ASSERT_EQUAL(xqc_vi64_write(buf, buf + len,
                                           vi64_cases[i].value), -1);
            CU_ASSERT_EQUAL(xqc_memcmp(buf, unchanged, sizeof(buf)), 0);
        }

        /* Completing a previously short prefix must succeed without state. */
        CU_ASSERT_EQUAL(xqc_vi64_read(wire, wire + vi64_cases[i].len, &value),
                        vi64_cases[i].len);
        CU_ASSERT_EQUAL(value, vi64_cases[i].value);
        CU_ASSERT_EQUAL(xqc_vi64_read(wire + 1, wire, &value), -1);
        CU_ASSERT_EQUAL(value, vi64_cases[i].value);
        CU_ASSERT_EQUAL(xqc_vi64_write(buf + 1, buf, vi64_cases[i].value), -1);
        CU_ASSERT_EQUAL(xqc_memcmp(buf, unchanged, sizeof(buf)), 0);
    }
}

void
xqc_test_vi64_nonminimal(void)
{
    /* Section 8.1 permits every wider encoding that can hold the value. */
    const uint8_t prefixes[] = {0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff};
    const uint8_t values[] = {0, 37, 127};

    for (size_t i = 0; i < sizeof(prefixes); i++) {
        size_t len = i + 2;
        uint8_t wire[XQC_VI64_MAX_LEN] = {0};

        wire[0] = prefixes[i];
        for (size_t j = 0; j < sizeof(values); j++) {
            uint64_t value = UINT64_MAX;
            wire[len - 1] = values[j];

            for (size_t available = 0; available < len; available++) {
                CU_ASSERT_EQUAL(xqc_vi64_read(wire, wire + available, &value),
                                -1);
                CU_ASSERT_EQUAL(value, UINT64_MAX);
            }
            CU_ASSERT_EQUAL(xqc_vi64_read(wire, wire + len, &value), len);
            CU_ASSERT_EQUAL(value, values[j]);
        }
    }
}
