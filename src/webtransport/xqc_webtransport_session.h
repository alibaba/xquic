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

    /* DRAIN_WEBTRANSPORT_SESSION received — peer requests no new streams */
    xqc_bool_t drain_received;

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

xqc_int_t xqc_wt_session_close(xqc_wt_session_t *session);

xqc_int_t xqc_wt_session_add_pendingstream(xqc_wt_session_t *session,
    xqc_h3_stream_t *h3_stream, void *wt_stream,
    xqc_wt_pending_stream_type_t stream_type);

xqc_wt_pending_stream_t* xqc_wt_session_pending_stream_find(
    xqc_wt_session_t *session, xqc_h3_stream_t *h3_stream);



#ifdef __cplusplus
}
#endif

#endif
