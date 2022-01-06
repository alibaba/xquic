/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_HQ_CTX_H
#define XQC_HQ_CTX_H

#include "xqc_hq.h"

xqc_int_t
xqc_hq_ctx_get_conn_callbacks(xqc_hq_conn_callbacks_t **hqc_cbs);

xqc_int_t
xqc_hq_ctx_get_request_callbacks(xqc_hq_request_callbacks_t **hqr_cbs);


#endif
