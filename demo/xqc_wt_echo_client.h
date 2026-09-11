#ifndef XQC_WT_ECHO_CLIENT_H
#define XQC_WT_ECHO_CLIENT_H

#include <xquic/xqc_webtransport.h>

xqc_int_t xqc_demo_wt_client_init(xqc_engine_t *engine, int draft_version,
    void (*schedule_send)(void *user_data),
    void (*finished)(void *user_data), void *user_data);
xqc_int_t xqc_demo_wt_client_open(xqc_h3_conn_t *h3_conn,
    const char *authority, const char *path, const char *origin);
int xqc_demo_wt_client_finish(void);
xqc_int_t xqc_demo_wt_client_conn_closing(xqc_connection_t *conn,
    const xqc_cid_t *cid, xqc_int_t error, void *user_data);

#endif
