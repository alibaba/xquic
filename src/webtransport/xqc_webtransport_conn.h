/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#ifndef XQC_WEBTRANSPORT_CONN_H
#define XQC_WEBTRANSPORT_CONN_H

#include <xquic/xqc_webtransport.h>
#include "src/common/xqc_id_hash.h"
#include "src/common/xqc_list.h"
#include "src/webtransport/xqc_webtransport_ctx.h"
#include "src/webtransport/xqc_webtransport_session.h"

struct xqc_webtransport_conn_s {
    xqc_h3_conn_t        *h3_conn;
    xqc_wt_ctx_t         *ctx;
    xqc_wt_ctx_t          ctx_storage;
    xqc_h3_request_callbacks_t app_request_callbacks;
    xqc_list_head_t       h3_streams;
    xqc_wt_session_t     *wt_session;
    xqc_id_hash_table_t   sessions;
    xqc_list_head_t       session_list;
    xqc_list_head_t       pending_streams;
    xqc_list_head_t       pending_datagrams;
    xqc_list_head_t       sent_datagrams;
    size_t                session_count;
    size_t                pending_count;
    size_t                pending_bytes;
    size_t                sent_count;
    size_t                dgram_mss;
    uint64_t              latest_session_id;
    uint64_t              peer_max_sessions;
    xqc_bool_t            peer_datagram;
    xqc_bool_t            peer_connect;
    xqc_bool_t            settings_received;
    xqc_bool_t            closing;
    xqc_cid_t             cid;
};

xqc_wt_conn_t *xqc_wt_conn_create(xqc_h3_conn_t *h3_conn);
void xqc_wt_conn_destroy(xqc_wt_conn_t *conn);
xqc_int_t xqc_wt_conn_register_session(xqc_wt_conn_t *conn,
    xqc_wt_session_t *session);
void xqc_wt_conn_unregister_session(xqc_wt_conn_t *conn, uint64_t id);
xqc_wt_session_t *xqc_wt_conn_find_session(xqc_wt_conn_t *conn, uint64_t id);

#endif
