/* Copyright (c) 2026, Alibaba Group Holding Limited. */

#ifndef XQC_WEBTRANS_INTEROP_H
#define XQC_WEBTRANS_INTEROP_H

#include <xquic/xqc_webtransport.h>

xqc_int_t xqc_wt_interop_server_init(xqc_engine_t *engine,
    int draft_version, void (*schedule_send)(void *user_data),
    void *user_data);
xqc_int_t xqc_wt_interop_client_init(xqc_engine_t *engine,
    int draft_version, int case_id, size_t payload_len, int print_response,
    void (*schedule_send)(void *user_data),
    void (*finished)(void *user_data), void *user_data);
xqc_int_t xqc_wt_interop_client_open(xqc_h3_conn_t *h3_conn,
    const char *authority, const char *path, const char *origin);
int xqc_wt_interop_client_finish(void);
void xqc_wt_interop_datagram_tick(void);
xqc_int_t xqc_wt_interop_client_conn_closing(xqc_connection_t *conn,
    const xqc_cid_t *cid, xqc_int_t error, void *user_data);

#endif
