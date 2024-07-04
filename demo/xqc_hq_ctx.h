/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_HQ_CTX_H
#define XQC_HQ_CTX_H

#include "xqc_hq.h"

xqc_int_t xqc_hq_ctx_get_callbacks(xqc_engine_t *engine, char *alpn, size_t alpn_len, xqc_hq_callbacks_t **hq_cbs);


#endif
