/* Copyright (c) 2026, Alibaba Group Holding Limited. */

#include <stdlib.h>
#include <string.h>
#include "xqc_wt_app_policy.h"
#include "case_test/webtransport/xqc_webtrans_test_cases.h"

const xqc_demo_wt_app_policy_t xqc_demo_wt_echo_policy = {
    .require_webtransport = 0,
    .allow_case_id = 1,
    .allow_remote_certificate = 0,
    .allow_client_probe = 1,
    .server_init = xqc_wt_case_server_init,
};

#ifdef XQC_ENABLE_WEBTRANSPORT_INTEROP
extern const xqc_demo_wt_app_policy_t xqc_wt_interop_policy;
#endif

const xqc_demo_wt_app_policy_t *xqc_demo_wt_app_policy =
    &xqc_demo_wt_echo_policy;

int
xqc_demo_wt_app_is_interop(void)
{
#ifdef XQC_ENABLE_WEBTRANSPORT_INTEROP
    return xqc_demo_wt_app_policy == &xqc_wt_interop_policy;
#else
    return 0;
#endif
}

int
xqc_demo_wt_app_select(int server)
{
    const char *role = getenv("ROLE");
    const char *testcase = getenv("TESTCASE");

    xqc_demo_wt_app_policy = &xqc_demo_wt_echo_policy;

    if (role == NULL && testcase == NULL) {
        return 0;
    }

#ifdef XQC_ENABLE_WEBTRANSPORT_INTEROP
    if (role == NULL || testcase == NULL
        || strcmp(role, server ? "server" : "client") != 0)
    {
        return -1;
    }
    if (strcmp(testcase, "handshake") != 0
        && strcmp(testcase, "transfer") != 0
        && strcmp(testcase, server
            ? "transfer-unidirectional-send"
            : "transfer-unidirectional-receive") != 0
        && strcmp(testcase, server
            ? "transfer-bidirectional-send"
            : "transfer-bidirectional-receive") != 0
        && strcmp(testcase, server
            ? "transfer-datagram-send"
            : "transfer-datagram-receive") != 0)
    {
        return -1;
    }
    xqc_demo_wt_app_policy = &xqc_wt_interop_policy;
    return 0;
#else
    return -1;
#endif
}
