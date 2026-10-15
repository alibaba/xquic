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

/* draft-ietf-webtrans-http3-07 Section 8.2. */
#define XQC_WT_SETTING_MAX_SESSIONS UINT64_C(0xc671706a)

/* draft-ietf-webtrans-http3-16 Section 9.2. */
#define XQC_WT_SETTING_ENABLED_16 UINT64_C(0x2c7cf000)
#define XQC_WT_SETTING_INITIAL_MAX_STREAMS_UNI UINT64_C(0x2b64)
#define XQC_WT_SETTING_INITIAL_MAX_STREAMS_BIDI UINT64_C(0x2b65)
#define XQC_WT_SETTING_INITIAL_MAX_DATA UINT64_C(0x2b61)
#define XQC_WT_SETTING_DATAGRAM UINT64_C(0x33)
#define XQC_WT_SETTING_CONNECT UINT64_C(0x08)
#define XQC_WT_REQUIREMENTS_NOT_MET UINT64_C(0x212c0d48)
#define XQC_WT_FLOW_CONTROL_ERROR 0x045d4487

/* draft-ietf-webtrans-http3-16 Sections 5.5.1 and 5.5.2. */
#define XQC_WT_MAX_STREAMS (UINT64_C(1) << 60)

/* Implementation bucket count; collisions use chained session entries. */
#define XQC_WT_SESSION_HASH_BUCKETS 16
#define XQC_WT_STREAM_HASH_BUCKETS 256

struct xqc_webtransport_conn_s {
    xqc_h3_conn_t                   *h3_conn;
    xqc_wt_ctx_t                    *ctx;
    xqc_wt_ctx_t                     ctx_storage;
    xqc_h3_request_callbacks_t       app_request_callbacks;
    xqc_list_head_t                  h3_streams;
    xqc_id_hash_table_t              h3_stream_index;
    xqc_wt_session_t                *wt_session;
    xqc_id_hash_table_t              sessions;
    xqc_list_head_t                  session_list;
    xqc_list_head_t                  pending_streams;
    xqc_list_head_t                  pending_datagrams;
    xqc_list_head_t                  sent_datagrams;
    size_t                           session_count;
    size_t                           pending_count;
    size_t                           pending_bytes;
    size_t                           sent_count;
    uint64_t                         latest_session_id;
    uint64_t                         peer_max_sessions;
    uint64_t                         peer_initial_max_streams_uni;
    uint64_t                         peer_initial_max_streams_bidi;
    uint64_t                         peer_initial_max_data;
    xqc_webtransport_draft_version_t negotiated_version;
    xqc_bool_t                       peer_draft16;
    xqc_bool_t                       peer_datagram;
    xqc_bool_t                       peer_connect;
    xqc_bool_t                       settings_received;
    xqc_bool_t                       flow_control_enabled;
    xqc_bool_t                       client_creating;
    xqc_bool_t                       session_id_seen;
    xqc_bool_t                       goaway_notified;
    xqc_bool_t                       datagram_send_blocked;
    xqc_bool_t                       closing;
    xqc_cid_t                        cid;
};

xqc_wt_conn_t *xqc_wt_conn_create(xqc_h3_conn_t *h3_conn);
void xqc_wt_conn_destroy(xqc_wt_conn_t *conn);
xqc_int_t xqc_wt_conn_register_session(xqc_wt_conn_t *conn,
    xqc_wt_session_t *session);
size_t xqc_wt_conn_active_session_count(xqc_wt_conn_t *conn);
void xqc_wt_conn_unregister_session(xqc_wt_conn_t *conn, uint64_t id);
xqc_wt_session_t *xqc_wt_conn_find_session(xqc_wt_conn_t *conn, uint64_t id);
xqc_bool_t xqc_wt_conn_requirements_met(xqc_wt_conn_t *conn);
void xqc_wt_conn_notify_goaway(xqc_wt_conn_t *conn);

xqc_h3_settings_result_t xqc_wt_conn_peer_settings(xqc_h3_conn_t *h3c,
    const xqc_h3_setting_t *settings, size_t count, void *data);

xqc_wt_conn_t *xqc_wt_get_conn_from_h3(xqc_h3_conn_t *h3_conn);

#endif
