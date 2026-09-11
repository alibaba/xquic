#ifndef XQC_WT_ECHO_SERVER_H
#define XQC_WT_ECHO_SERVER_H

#include <xquic/xquic.h>

xqc_int_t xqc_demo_wt_init(xqc_engine_t *engine, int draft_version,
    void (*schedule_send)(void *user_data), void *user_data);

#endif
