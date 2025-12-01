/**
 * xqc_webtransport_session.c
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */
#include "xqc_webtransport_session.h"
#include "src/common/xqc_id_hash.h"
#include "src/transport/xqc_conn.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/webtransport/xqc_webtransport_conn.h"
#include "src/webtransport/xqc_webtransport_dgram.h"
#include "src/webtransport/xqc_webtransport_session.h"
#include "src/webtransport/xqc_webtransport_stream.h"

xqc_wt_session_t*
xqc_wt_session_init(uint64_t sessionID, xqc_wt_conn_t* conn,
    xqc_h3_stream_t* requestStr)
{
    xqc_wt_session_t* session;
    session = xqc_calloc(1, sizeof(xqc_wt_session_t));
    session->sessionID = sessionID;
    session->wt_conn = conn;
    session->h3_stream = requestStr;
    session->stream_id_gen = 0;
    session->stream_id_hash_table = xqc_calloc(1, sizeof(xqc_id_hash_table_t));
    session->pending_unistreams = xqc_calloc(1, sizeof(xqc_id_hash_table_t));
    xqc_id_hash_init(session->stream_id_hash_table, xqc_default_allocator, 16);
    xqc_id_hash_init(session->pending_unistreams, xqc_default_allocator, 16);

    /* register this session on the connection for future lookup (e.g. datagrams) */
    xqc_wt_conn_register_session(conn, session);

    return session;
}


xqc_int_t
xqc_wt_session_close(xqc_wt_session_t* session)
{
    xqc_int_t ret = XQC_OK;
    if (session->wt_conn) {
        xqc_wt_conn_unregister_session(session->wt_conn, session->sessionID);
    }
    if (session->h3_stream) ret = xqc_h3_stream_close(session->h3_stream);
    if (session->stream_id_hash_table)
        xqc_id_hash_release(session->stream_id_hash_table);
    if (session->pending_unistreams)
        xqc_id_hash_release(session->pending_unistreams);

    xqc_free(session->stream_id_hash_table);
    xqc_free(session->pending_unistreams);
    xqc_free(session);

    return ret;
}


xqc_int_t
xqc_wt_session_add_pendingstream(xqc_wt_session_t* session,
    xqc_h3_stream_t* h3_stream, void* wt_stream)
{
    xqc_stream_t* stream = h3_stream->stream;
    if (stream == NULL) {
        return XQC_ERROR;
    }

    uint64_t stream_id = stream->stream_id;
    xqc_id_hash_element_t e = { stream_id, wt_stream };
    return xqc_id_hash_add(session->pending_unistreams, e);
}

void*
xqc_wt_session_pending_stream_find(xqc_wt_session_t* session,
    xqc_h3_stream_t* h3_stream)
{
    xqc_stream_t* stream = h3_stream->stream;

    uint64_t stream_id = stream->stream_id;

    xqc_id_hash_element_t* ele =
        xqc_id_hash_find(session->pending_unistreams, stream_id);
    if (ele) {
        return ele->value;
    }
    return NULL;
}

xqc_connection_t*
xqc_wt_session_get_conn(xqc_wt_session_t* wt_session)
{
    if (wt_session == NULL || wt_session->wt_conn == NULL
        || wt_session->wt_conn->h3_conn == NULL)
    {
        return NULL;
    }

    return wt_session->wt_conn->h3_conn->conn;
}

xqc_h3_stream_t*
xqc_wt_session_get_h3_stream(xqc_wt_session_t* wt_session)
{
    return wt_session->h3_stream;
}
