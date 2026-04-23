/**
 * xqc_webtransport_session.c
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */
#include "xqc_webtransport_session.h"
#include "src/common/xqc_id_hash.h"
#include "src/common/xqc_malloc.h"
#include "src/transport/xqc_conn.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_request.h"
#include "src/webtransport/xqc_webtransport_conn.h"
#include "src/webtransport/xqc_webtransport_dgram.h"
#include "src/webtransport/xqc_webtransport_session.h"
#include "src/webtransport/xqc_webtransport_stream.h"
#include "src/webtransport/xqc_webtransport_wire.h"

xqc_wt_session_t*
xqc_wt_session_init(uint64_t session_id, xqc_wt_conn_t* conn,
    xqc_h3_stream_t* requestStr)
{
    xqc_wt_session_t* session;
    session = xqc_calloc(1, sizeof(xqc_wt_session_t));
    if (session == NULL) {
        return NULL;
    }
    session->session_id = session_id;
    session->wt_conn = conn;
    session->h3_stream = requestStr;
    session->stream_id_gen = 0;
    session->stream_id_hash_table = xqc_calloc(1, sizeof(xqc_id_hash_table_t));
    session->pending_unistreams = xqc_calloc(1, sizeof(xqc_id_hash_table_t));
    if (session->stream_id_hash_table == NULL || session->pending_unistreams == NULL) {
        xqc_free(session->stream_id_hash_table);
        xqc_free(session->pending_unistreams);
        xqc_free(session);
        return NULL;
    }
    xqc_id_hash_init(session->stream_id_hash_table, xqc_default_allocator, 16);
    xqc_id_hash_init(session->pending_unistreams, xqc_default_allocator, 16);

    /* register this session on the connection for future lookup (e.g. datagrams) */
    xqc_wt_conn_register_session(conn, session);

    return session;
}


xqc_int_t
xqc_wt_session_close(xqc_wt_session_t* session)
{
    if (session == NULL) {
        return XQC_OK;
    }
    xqc_int_t ret = XQC_OK;
    if (session->wt_conn) {
        xqc_wt_conn_unregister_session(session->wt_conn, session->session_id);
    }
    /* do NOT close h3_stream here — H3 layer manages stream lifecycle.
     * closing it here causes double-free when conn is destroyed. */
    session->h3_stream = NULL;

    /* Free WT-layer wrapper objects only. Do NOT call xqc_destroy_stream()
     * because the underlying QUIC streams are owned by xqc_conn_t and will
     * be (or already have been) destroyed by xqc_conn_destroy(). Calling
     * xqc_destroy_stream() here causes use-after-free / double-free SEGV. */
    if (session->pending_unistreams) {
        for (int i = 0; i < session->pending_unistreams->count; i++) {
            xqc_id_hash_node_t *node = session->pending_unistreams->list[i];
            while (node) {
                xqc_wt_pending_stream_t *ps =
                    (xqc_wt_pending_stream_t *)node->element.value;
                if (ps) {
                    if (ps->type == XQC_WT_PENDING_UNISTREAM) {
                        xqc_wt_unistream_t *uni =
                            (xqc_wt_unistream_t *)ps->stream;
                        if (uni) {
                            if (uni->type == XQC_WT_STREAM_TYPE_SEND
                                && uni->stream.send_stream) {
                                xqc_free(uni->stream.send_stream);
                            } else if (uni->type == XQC_WT_STREAM_TYPE_RECV
                                && uni->stream.recv_stream) {
                                xqc_free(uni->stream.recv_stream);
                            }
                            xqc_free(uni);
                        }
                    } else {
                        xqc_wt_bidistream_t *bidi =
                            (xqc_wt_bidistream_t *)ps->stream;
                        if (bidi) {
                            xqc_free(bidi->send_stream);
                            xqc_free(bidi->recv_stream);
                            xqc_free(bidi);
                        }
                    }
                    xqc_free(ps);
                }
                node = node->next;
            }
        }
        xqc_id_hash_release(session->pending_unistreams);
    }
    if (session->stream_id_hash_table)
        xqc_id_hash_release(session->stream_id_hash_table);

    xqc_free(session->stream_id_hash_table);
    xqc_free(session->pending_unistreams);
    if (session->close_reason) {
        xqc_free(session->close_reason);
    }
    xqc_free(session);

    return ret;
}


xqc_int_t
xqc_wt_session_add_pendingstream(xqc_wt_session_t* session,
    xqc_h3_stream_t* h3_stream, void* wt_stream,
    xqc_wt_pending_stream_type_t stream_type)
{
    xqc_stream_t* stream = h3_stream->stream;
    if (stream == NULL) {
        return XQC_ERROR;
    }

    xqc_wt_pending_stream_t *ps = xqc_malloc(sizeof(xqc_wt_pending_stream_t));
    if (ps == NULL) {
        return -XQC_EMALLOC;
    }
    ps->type = stream_type;
    ps->stream = wt_stream;

    uint64_t stream_id = stream->stream_id;
    xqc_id_hash_element_t e = { stream_id, ps };
    return xqc_id_hash_add(session->pending_unistreams, e);
}

xqc_wt_pending_stream_t*
xqc_wt_session_pending_stream_find(xqc_wt_session_t* session,
    xqc_h3_stream_t* h3_stream)
{
    if (session == NULL || h3_stream == NULL) {
        return NULL;
    }

    xqc_stream_t* stream = h3_stream->stream;
    if (stream == NULL) {
        return NULL;
    }

    uint64_t stream_id = stream->stream_id;
    return (xqc_wt_pending_stream_t *)xqc_id_hash_find(
        session->pending_unistreams, stream_id);
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

xqc_int_t
xqc_wt_session_close_with_error(xqc_wt_session_t *session,
    uint32_t error_code, const char *reason, size_t reason_len)
{
    if (session == NULL) {
        return -XQC_EPARAM;
    }

    if (session->close_capsule_sent) {
        return XQC_OK;
    }

    /* encode CLOSE_WEBTRANSPORT_SESSION capsule */
    uint8_t capsule_buf[512];
    size_t capsule_len = xqc_wt_encode_close_session_capsule(
        error_code, reason, reason_len, capsule_buf, sizeof(capsule_buf));
    if (capsule_len == 0) {
        return -XQC_ELIMIT;
    }

    /* send capsule as H3 DATA frame on the CONNECT stream, then FIN */
    if (session->h3_request == NULL) {
        return -XQC_EPARAM;
    }

    ssize_t sent = xqc_h3_request_send_body(session->h3_request,
        capsule_buf, capsule_len, 1);
    if (sent < 0) {
        return (xqc_int_t)sent;
    }

    session->close_capsule_sent = XQC_TRUE;
    session->close_error_code   = error_code;

    /* store reason for later retrieval */
    if (reason_len > 0 && reason != NULL) {
        session->close_reason = xqc_malloc(reason_len + 1);
        if (session->close_reason) {
            memcpy(session->close_reason, reason, reason_len);
            session->close_reason[reason_len] = '\0';
            session->close_reason_len = reason_len;
        }
    }

    return XQC_OK;
}

xqc_int_t
xqc_wt_session_drain(xqc_wt_session_t *session)
{
    if (session == NULL) {
        return -XQC_EPARAM;
    }

    /* encode DRAIN_WEBTRANSPORT_SESSION capsule */
    uint8_t capsule_buf[16];
    size_t capsule_len = xqc_wt_encode_drain_session_capsule(capsule_buf, sizeof(capsule_buf));
    if (capsule_len == 0) {
        return -XQC_ELIMIT;
    }

    /* send capsule as H3 DATA frame on the CONNECT stream (no FIN) */
    if (session->h3_request == NULL) {
        return -XQC_EPARAM;
    }

    ssize_t sent = xqc_h3_request_send_body(session->h3_request,
        capsule_buf, capsule_len, 0);
    if (sent < 0) {
        return (xqc_int_t)sent;
    }

    return XQC_OK;
}
