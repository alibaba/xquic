/* Copyright (c) 2026, Alibaba Group Holding Limited. */

#ifndef XQC_WEBTRANS_TEST_CASES_H
#define XQC_WEBTRANS_TEST_CASES_H

#include <xquic/xqc_webtransport.h>

/* Zero continues the echo; one waits for the peer's rejection. */
xqc_int_t xqc_wt_case_prepare(xqc_wt_session_t *session, int case_id);
xqc_int_t xqc_wt_case_server_init(xqc_engine_t *engine, int case_id);

#endif
