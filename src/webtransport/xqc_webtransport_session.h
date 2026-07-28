/**
 * xqc_webtransport_conn.h
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */
#ifndef XQC_WEBTRANSPORT_SESSION_H
#define XQC_WEBTRANSPORT_SESSION_H

#include <xquic/xqc_http3.h>
#include <xquic/xqc_webtransport.h>
#include "../src/common/utils/vint/xqc_discrete_int_parser.h"
#include "xquic/xquic_typedef.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct xqc_webtransport_session_s
{
    uint64_t session_id; // TODO remove in future version
    uint64_t stream_id_gen; // 生成stream id
    xqc_id_hash_table_t *stream_id_hash_table; // stream id hash table
    xqc_id_hash_table_t *pending_unistreams; // h3 stream id hash table

    // Conn for session
    xqc_wt_conn_t *wt_conn;

    xqc_h3_stream_t  *h3_stream;   /* CONNECT stream */
    xqc_h3_request_t *h3_request;  /* H3 request on the CONNECT stream */

    /* close info (CLOSE_WEBTRANSPORT_SESSION capsule) */
    uint32_t close_error_code;
    char    *close_reason;
    size_t   close_reason_len;
    xqc_bool_t close_capsule_sent;
    xqc_bool_t close_capsule_received;

    xqc_bool_t established;
    xqc_bool_t terminated;

    /* DRAIN_WEBTRANSPORT_SESSION received — peer requests no new streams */
    xqc_bool_t drain_received;

    /* draft-15 session flow control */
    xqc_bool_t flow_control_enabled;
    uint64_t local_max_streams_uni;   /* streams peer may open on this session */
    uint64_t local_max_streams_bidi;
    uint64_t local_max_data;          /* stream body bytes peer may send */
    uint64_t peer_max_streams_uni;    /* streams this endpoint may open */
    uint64_t peer_max_streams_bidi;
    uint64_t peer_max_data;
    uint64_t recv_streams_uni;
    uint64_t recv_streams_bidi;
    uint64_t recv_data;
    uint64_t sent_streams_uni;
    uint64_t sent_streams_bidi;
    uint64_t sent_data;
    uint64_t reserved_streams_uni;
    uint64_t reserved_streams_bidi;
    uint64_t reserved_data;
    uint64_t local_streams_uni_window;
    uint64_t local_streams_bidi_window;
    uint64_t local_data_window;

} xqc_wt_session_t;

/* Tagged wrapper for pending streams — disambiguates uni vs bidi without
 * relying on QUIC stream ID bit patterns. */
typedef enum {
    XQC_WT_PENDING_UNISTREAM  = 0,
    XQC_WT_PENDING_BIDISTREAM = 1,
} xqc_wt_pending_stream_type_t;

typedef struct {
    xqc_wt_pending_stream_type_t type;
    void                        *stream;  /* xqc_wt_unistream_t* or xqc_wt_bidistream_t* */
} xqc_wt_pending_stream_t;

typedef struct {
    uint64_t streams_uni;
    uint64_t streams_bidi;
    uint64_t data;
} xqc_wt_flow_reservation_t;

xqc_int_t xqc_wt_session_close(xqc_wt_session_t *session);

xqc_int_t xqc_wt_session_add_pendingstream(xqc_wt_session_t *session,
    xqc_h3_stream_t *h3_stream, void *wt_stream,
    xqc_wt_pending_stream_type_t stream_type);

xqc_wt_pending_stream_t* xqc_wt_session_pending_stream_find(
    xqc_wt_session_t *session, xqc_h3_stream_t *h3_stream);

xqc_int_t xqc_wt_session_on_incoming_stream(xqc_wt_session_t *session,
    xqc_bool_t is_bidi);

xqc_int_t xqc_wt_session_on_incoming_data(xqc_wt_session_t *session,
    uint64_t data_len);

xqc_int_t xqc_wt_session_update_peer_max_streams(xqc_wt_session_t *session,
    xqc_bool_t is_bidi, uint64_t value);

xqc_int_t xqc_wt_session_update_peer_max_data(xqc_wt_session_t *session,
    uint64_t value);

xqc_int_t xqc_wt_session_on_outgoing_stream(xqc_wt_session_t *session,
    xqc_bool_t is_bidi);

xqc_int_t xqc_wt_session_on_outgoing_data(xqc_wt_session_t *session,
    uint64_t data_len);

xqc_int_t xqc_wt_session_reserve_outgoing(xqc_wt_session_t *session,
    xqc_bool_t reserve_stream, xqc_bool_t is_bidi, uint64_t data_len,
    xqc_wt_flow_reservation_t *reservation);

void xqc_wt_session_rollback_outgoing(xqc_wt_session_t *session,
    const xqc_wt_flow_reservation_t *reservation);

xqc_int_t xqc_wt_session_commit_outgoing(xqc_wt_session_t *session,
    const xqc_wt_flow_reservation_t *reservation);

xqc_int_t xqc_wt_session_handle_blocked_capsule(xqc_wt_session_t *session,
    uint64_t capsule_type, uint64_t value);

xqc_int_t xqc_wt_session_flow_error(xqc_wt_session_t *session);

xqc_int_t xqc_wt_session_mark_established(xqc_wt_session_t *session);

xqc_int_t xqc_wt_session_mark_terminated(xqc_wt_session_t *session,
    xqc_bool_t abort_streams);

xqc_int_t xqc_wt_session_finish_connect_stream(xqc_wt_session_t *session);

xqc_int_t xqc_wt_session_receive_close_capsule(xqc_wt_session_t *session,
    uint32_t close_code, const uint8_t *reason, size_t reason_len);

#ifdef __cplusplus
}
#endif

#endif
