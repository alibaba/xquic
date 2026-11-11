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

/* each writer stores the value's low bytes most significant first */
void
xqc_test_vint_put_uint_be(void)
{
    static const uint8_t be[] = {0x01, 0x02, 0x03, 0x04,
                                 0x05, 0x06, 0x07, 0x08};
    uint8_t buf[8];

    CU_ASSERT(xqc_put_uint64be(buf, 0x0102030405060708ULL) == buf + 8);
    CU_ASSERT(memcmp(buf, be, 8) == 0);
    CU_ASSERT(xqc_put_uint48be(buf, 0x030405060708ULL) == buf + 6);
    CU_ASSERT(memcmp(buf, be + 2, 6) == 0);
    CU_ASSERT(xqc_put_uint32be(buf, 0x05060708) == buf + 4);
    CU_ASSERT(memcmp(buf, be + 4, 4) == 0);
    CU_ASSERT(xqc_put_uint24be(buf, 0x060708) == buf + 3);
    CU_ASSERT(memcmp(buf, be + 5, 3) == 0);
    CU_ASSERT(xqc_put_uint16be(buf, 0x0708) == buf + 2);
    CU_ASSERT(memcmp(buf, be + 6, 2) == 0);
}

/* RFC 9000 Appendix A.1 samples, written and read; a cut one is refused */
void
xqc_test_vint_rfc9000_samples(void)
{
    static const uint8_t eight[] = {0xc2, 0x19, 0x7c, 0x5e,
                                    0xff, 0x14, 0xe8, 0x8c};
    static const uint8_t four[] = {0x9d, 0x7f, 0x3e, 0x7d};
    uint8_t buf[8];
    uint64_t val;

    CU_ASSERT(xqc_put_varint(buf, 151288809941952652ULL) == buf + 8);
    CU_ASSERT(memcmp(buf, eight, sizeof(eight)) == 0);
    CU_ASSERT(xqc_vint_read(eight, eight + sizeof(eight), &val) == 8);
    CU_ASSERT(val == 151288809941952652ULL);

    CU_ASSERT(xqc_put_varint(buf, 494878333) == buf + 4);
    CU_ASSERT(memcmp(buf, four, sizeof(four)) == 0);
    CU_ASSERT(xqc_vint_read(four, four + sizeof(four), &val) == 4);
    CU_ASSERT(val == 494878333);

    /* one byte short of the eight the first byte announces */
    CU_ASSERT(xqc_vint_read(eight, eight + sizeof(eight) - 1, &val) < 0);
}
