/* Copyright (c) 2026, Alibaba Group Holding Limited. */

#ifndef XQC_WT_APP_POLICY_H
#define XQC_WT_APP_POLICY_H

#include <xquic/xquic.h>

typedef xqc_int_t (*xqc_demo_wt_server_init_pt)(xqc_engine_t *engine,
    int case_id);

typedef struct {
    int                         require_webtransport;
    int                         allow_case_id;
    int                         allow_remote_certificate;
    int                         allow_client_probe;
    xqc_demo_wt_server_init_pt  server_init;
} xqc_demo_wt_app_policy_t;

extern const xqc_demo_wt_app_policy_t *xqc_demo_wt_app_policy;

/* Select once, before parsing the shared demo command line. */
int xqc_demo_wt_app_select(int server);
int xqc_demo_wt_app_is_interop(void);

#endif
