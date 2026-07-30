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

    uint64_t vi64_test[] = {
        0, 127, 128, 16383, 16384, 2097151, 2097152,
        UINT64_C(72057594037927935), UINT64_MAX,
    };
    for (i = 0; i < sizeof(vi64_test) / sizeof(vi64_test[0]); i++) {
        unsigned char buff[XQC_VI64_MAX_LEN];
        memset(buff, 0, sizeof(buff));

        size_t len = xqc_vi64_len(vi64_test[i]);
        uint8_t *end = xqc_vi64_write(buff, vi64_test[i]);
        uint64_t val = 0;
        int ret = xqc_vi64_read(buff, end, &val);

        CU_ASSERT(len >= 1 && len <= XQC_VI64_MAX_LEN);
        CU_ASSERT((size_t)(end - buff) == len);
        CU_ASSERT(ret == (int)len);
        CU_ASSERT(val == vi64_test[i]);
    }

    unsigned char setup_type[XQC_VI64_MAX_LEN] = {0};
    uint8_t *setup_end = xqc_vi64_write(setup_type, 0x2f00);
    CU_ASSERT(setup_end - setup_type == 2);
    CU_ASSERT(setup_type[0] == 0xaf && setup_type[1] == 0x00);

    uint64_t val = 0;
    unsigned char non_minimal[] = {0x80, 0x25};
    CU_ASSERT(xqc_vi64_read(non_minimal, non_minimal + sizeof(non_minimal), &val) == 2);
    CU_ASSERT(val == 37);
    CU_ASSERT(xqc_vi64_read(non_minimal, non_minimal + 1, &val) < 0);
}
