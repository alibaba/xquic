/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_FEC_SCHEME_TEST_H_INCLUDED_
#define _XQC_FEC_SCHEME_TEST_H_INCLUDED_
#include "src/common/xqc_queue.h"
#include "src/common/xqc_hash.h"
#include "xquic/xquic.h"
#include "src/common/xqc_log.h"
#include "src/transport/xqc_engine.h"

void xqc_test_fec_scheme();

const xqc_cid_t *test_cid_connect_fec(xqc_engine_t *engine);
static xqc_connection_t *test_fec_connect(xqc_engine_t *engine);
xqc_connection_t *test_engine_connect_fec();

#endif /* _XQC_WAKEUP_PQ_TEST_H_INCLUDED_ */
