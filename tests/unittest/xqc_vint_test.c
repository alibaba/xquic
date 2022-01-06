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