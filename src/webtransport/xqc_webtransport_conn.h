/**
 * xqc_webtransport_conn.h
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */
#ifndef XQC_WEBTRANSPORT_CONN_H
#define XQC_WEBTRANSPORT_CONN_H

#include "src/http3/xqc_h3_defs.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/webtransport/xqc_webtransport_defs.h"
#include "src/common/xqc_id_hash.h"
#include <xquic/xqc_http3.h>
#include <xquic/xqc_webtransport.h>
#include "src/webtransport/xqc_webtransport_session.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct xqc_webtransport_conn_s{
    xqc_h3_conn_t* h3_conn;
    xqc_wt_session_t* wt_session; /* default / primary session */
    // uint64_t mConnTraceId;
    // struct event* ev_timeout;
    struct sockaddr_in6 peer_addr;
    socklen_t peer_addrlen;
    xqc_cid_t cid;

    xqc_bool_t bidistream_first_connect;

    size_t dgram_mss;

    xqc_id_hash_table_t *sessions; /* map sessionID -> xqc_wt_session_t* */

}xqc_wt_conn_t ;

xqc_wt_conn_t* xqc_wt_conn_create(xqc_h3_conn_t* h3_conn);

void xqc_wt_conn_set_dgram_mss(xqc_wt_conn_t* wt_conn, size_t dgram_mss);

/* session registration helpers */
xqc_int_t xqc_wt_conn_register_session(xqc_wt_conn_t *wt_conn, xqc_wt_session_t *session);

void xqc_wt_conn_unregister_session(xqc_wt_conn_t *wt_conn, uint64_t session_id);

xqc_wt_session_t *xqc_wt_conn_find_session(xqc_wt_conn_t *wt_conn, uint64_t session_id);




#ifdef __cplusplus
}
#endif

#endif
