/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_REINJ_XLINK_H_INCLUDED_
#define _XQC_REINJ_XLINK_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>

typedef struct {
    xqc_log_t              *log;
} xqc_xlink_reinj_ctl_t;

extern const xqc_reinj_ctl_callback_t xqc_xlink_reinj_ctl_cb;

#endif /* _XQC_REINJ_XLINK_H_INCLUDED_ */
