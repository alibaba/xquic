/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_HQ_CONN_H
#define XQC_HQ_CONN_H

#include "xqc_hq.h"

typedef struct xqc_hq_conn_s {

    xqc_hq_conn_callbacks_t     hqc_cbs;
    xqc_hq_request_callbacks_t  hqr_cbs; 

    xqc_connection_t           *conn;

    xqc_log_t                  *log;

    void                       *user_data;

} xqc_hq_conn_s;

extern const xqc_conn_callbacks_t hq_conn_callbacks;

#endif