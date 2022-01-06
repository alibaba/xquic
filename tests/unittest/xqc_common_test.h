/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_COMMON_TEST_H
#define XQC_COMMON_TEST_H

#include "src/common/xqc_queue.h"
#include "src/common/xqc_hash.h"
#include "xquic/xquic.h"
#include "src/common/xqc_log.h"
#include "src/transport/xqc_engine.h"

void xqc_test_common();
const xqc_cid_t *test_cid_connect(xqc_engine_t *engine);
xqc_connection_t *test_engine_connect();
xqc_engine_t *test_create_engine();
xqc_engine_t *test_create_engine_server();


#endif
