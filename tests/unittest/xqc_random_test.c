/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "src/common/xqc_random.h"
#include "src/common/xqc_common.h"

void
xqc_test_get_random()
{
    u_char buf[1024];
    xqc_random_generator_t *rand_gen = NULL;
    xqc_log_t log;

    rand_gen = xqc_random_generator_create(&log);
    CU_ASSERT(rand_gen != NULL);

    int ret = xqc_get_random(rand_gen, buf, 1024);

    CU_ASSERT(ret == XQC_OK);
    xqc_random_generator_destroy(rand_gen);
}
