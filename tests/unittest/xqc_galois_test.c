/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include <xquic/xquic.h>
#include "src/transport/fec_schemes/xqc_galois_calculation.h"


void
xqc_test_galois_divide()
{
    xqc_int_t ret;
    unsigned char res;
    ret = xqc_galois_divide(0, 1, &res);
    CU_ASSERT(res == 0 && ret == 0);

    ret = xqc_galois_divide(1, 0, &res);
    CU_ASSERT(ret == -XQC_EPARAM);

    ret = xqc_galois_divide(5, 3, &res);
    CU_ASSERT(ret == 0 && res == 3);

    ret = xqc_galois_divide(3, 5, &res);
    CU_ASSERT(ret == 0 && res == 244);
}

void
xqc_test_galois_calculation()
{
    xqc_test_galois_divide();
}