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

typedef struct xqc_wt_ctx_s xqc_wt_ctx_t;

typedef struct xqc_wt_pending_dgram_s {
    uint64_t session_id;
    uint8_t *data;
    size_t   data_len;
    void    *user_data;
    uint64_t recv_time;
    struct xqc_wt_pending_dgram_s *next;
} xqc_wt_pending_dgram_t;

typedef struct xqc_webtransport_conn_s{
    xqc_h3_conn_t* h3_conn;
    xqc_wt_session_t* wt_session; /* default / primary session */
    struct sockaddr_in6 peer_addr;
    socklen_t peer_addrlen;
    xqc_cid_t cid;

    size_t dgram_mss;

    xqc_id_hash_table_t *sessions; /* map sessionID -> xqc_wt_session_t* */
    xqc_id_hash_table_t *closed_sessions; /* session IDs valid but terminated */
    xqc_id_hash_table_t *pending_streams; /* pre-session WT streams keyed by H3 stream id */
    size_t active_session_count;

    xqc_wt_pending_dgram_t *pending_dgram_head;
    xqc_wt_pending_dgram_t *pending_dgram_tail;
    size_t pending_dgram_count;
    size_t pending_dgram_bytes;
    uint64_t pending_dgram_buffered;
    uint64_t unknown_session_dgram_rejected;
    uint64_t pending_dgram_overflow_dropped;

    xqc_h3_request_t *pending_client_connect;

    xqc_wt_ctx_t *wt_ctx; /* back-pointer to WT context (shared, not owned) */

    void *py_handle;  /* back-pointer to py_client_t or py_server_t for CFFI routing */

}xqc_wt_conn_t ;

xqc_wt_conn_t* xqc_wt_conn_create(xqc_h3_conn_t* h3_conn);

xqc_int_t xqc_wt_conn_close(xqc_wt_conn_t* conn);

void xqc_wt_conn_set_dgram_mss(xqc_wt_conn_t* wt_conn, size_t dgram_mss);

/* session registration helpers */
xqc_int_t xqc_wt_conn_register_session(xqc_wt_conn_t *wt_conn, xqc_wt_session_t *session);

void xqc_wt_conn_unregister_session(xqc_wt_conn_t *wt_conn, uint64_t session_id);

xqc_wt_session_t *xqc_wt_conn_find_session(xqc_wt_conn_t *wt_conn, uint64_t session_id);

xqc_bool_t xqc_wt_conn_can_buffer_unknown_session(xqc_wt_conn_t *wt_conn,
    uint64_t session_id);

xqc_bool_t xqc_wt_conn_has_active_session_without_fc(xqc_wt_conn_t *wt_conn,
    xqc_wt_session_t *exclude);

void xqc_wt_conn_mark_session_closed(xqc_wt_conn_t *wt_conn, uint64_t session_id);

xqc_bool_t xqc_wt_conn_is_closed_session(xqc_wt_conn_t *wt_conn, uint64_t session_id);




#ifdef __cplusplus
}
#endif

#endif
