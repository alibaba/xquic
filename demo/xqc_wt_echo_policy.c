/* Copyright (c) 2026, Alibaba Group Holding Limited. */

#include "xqc_wt_app.h"
#include "case_test/webtransport/xqc_webtrans_test_cases.h"

const xqc_demo_wt_app_policy_t xqc_demo_wt_app_policy = {
    .require_webtransport = 0,
    .allow_case_id = 1,
    .allow_remote_certificate = 0,
    .server_init = xqc_wt_case_server_init,
};
