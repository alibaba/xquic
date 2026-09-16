/* Copyright (c) 2026, Alibaba Group Holding Limited. */

#ifndef XQC_WEBTRANS_INTEROP_TEST_H
#define XQC_WEBTRANS_INTEROP_TEST_H

void xqc_test_wt_interop_policy(void);
void xqc_test_wt_app_select(void);
void xqc_test_wt_app_reject(void);
void xqc_test_wt_interop_paths(void);
void xqc_test_wt_interop_headers(void);
void xqc_test_wt_interop_file_confinement(void);
void xqc_test_wt_interop_roles(void);
void xqc_test_wt_interop_handshake_complete(void);
void xqc_test_wt_interop_peer_close_complete(void);
void xqc_test_wt_interop_peer_close_incomplete(void);
void xqc_test_wt_interop_datagram_backpressure(void);

#endif
