/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_REINJ_DEFAULT_H_INCLUDED_
#define _XQC_REINJ_DEFAULT_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>

typedef struct {
    xqc_log_t              *log;
    xqc_connection_t       *conn;
} xqc_default_reinj_ctl_t;

extern const xqc_reinj_ctl_callback_t xqc_default_reinj_ctl_cb;

#endif
