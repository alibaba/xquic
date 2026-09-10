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
    uint64_t sessionID; // TODO remove in future version
    uint64_t stream_id_gen; // 生成stream id
    xqc_id_hash_table_t *stream_id_hash_table; // stream id hash table
    xqc_id_hash_table_t *pending_unistreams; // h3 stream id hash table

    // Conn for session
    xqc_wt_conn_t *wt_conn;

    xqc_h3_stream_t *h3_stream; // only for build connection
    
} xqc_wt_session_t;

xqc_int_t xqc_wt_session_close(xqc_wt_session_t *session);

xqc_int_t xqc_wt_session_add_pendingstream(xqc_wt_session_t *session,
    xqc_h3_stream_t *h3_stream, void *wt_stream);

void* xqc_wt_session_pending_stream_find(xqc_wt_session_t *session, xqc_h3_stream_t *h3_stream);



#ifdef __cplusplus
}
#endif

#endif
