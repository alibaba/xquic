/**
 * xqc_webtransport_conn.c
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */
#include "xqc_webtransport_conn.h"
#include "src/common/xqc_malloc.h"
#include "src/webtransport/xqc_webtransport_session.h"
#include "src/webtransport/xqc_webtransport_stream.h"
#include "src/webtransport/xqc_webtransport_ctx.h"

static void
xqc_wt_conn_free_pending_streams(xqc_wt_conn_t *conn)
{
    if (conn == NULL || conn->pending_streams == NULL) {
        return;
    }

    for (int i = 0; i < conn->pending_streams->count; i++) {
        xqc_id_hash_node_t *node = conn->pending_streams->list[i];
        while (node) {
            xqc_wt_pending_stream_t *ps =
                (xqc_wt_pending_stream_t *)node->element.value;
            if (ps) {
                if (ps->type == XQC_WT_PENDING_BIDISTREAM) {
                    xqc_wt_bidistream_t *bidi =
                        (xqc_wt_bidistream_t *)ps->stream;
                    if (bidi) {
                        xqc_wt_stream_buffer_list_release(&bidi->pending_recv);
                        xqc_wt_bidistream_destroy(bidi);
                    }
                } else {
                    xqc_wt_unistream_t *uni =
                        (xqc_wt_unistream_t *)ps->stream;
                    if (uni) {
                        xqc_wt_stream_buffer_list_release(&uni->pending_recv);
                        if (uni->type == XQC_WT_STREAM_TYPE_SEND
                            && uni->stream.send_stream)
                        {
                            xqc_free(uni->stream.send_stream);
                        } else if (uni->type == XQC_WT_STREAM_TYPE_RECV
                                   && uni->stream.recv_stream)
                        {
                            xqc_free(uni->stream.recv_stream);
                        }
                        xqc_free(uni);
                    }
                }
                xqc_free(ps);
            }
            node = node->next;
        }
    }
    xqc_id_hash_release(conn->pending_streams);
    xqc_free(conn->pending_streams);
    conn->pending_streams = NULL;
}

static void
xqc_wt_conn_free_pending_dgrams(xqc_wt_conn_t *conn)
{
    xqc_wt_pending_dgram_t *node = conn ? conn->pending_dgram_head : NULL;
    while (node) {
        xqc_wt_pending_dgram_t *next = node->next;
        xqc_free(node->data);
        xqc_free(node);
        node = next;
    }
    if (conn) {
        conn->pending_dgram_head = NULL;
        conn->pending_dgram_tail = NULL;
        conn->pending_dgram_count = 0;
        conn->pending_dgram_bytes = 0;
    }
}

xqc_wt_conn_t* xqc_wt_conn_create(xqc_h3_conn_t* h3_conn)
{
    xqc_wt_conn_t* conn = xqc_calloc(1, sizeof(xqc_wt_conn_t));
    if (conn == NULL) {
        return NULL;
    }
    conn->h3_conn = h3_conn;
    conn->wt_session = NULL;
    conn->dgram_mss = XQC_WEBTRANSPORT_DEFAULT_DGRAM_MSS;

    /* initialize session map for potential multi-session support */
    conn->sessions = xqc_calloc(1, sizeof(xqc_id_hash_table_t));
    conn->closed_sessions = xqc_calloc(1, sizeof(xqc_id_hash_table_t));
    conn->pending_streams = xqc_calloc(1, sizeof(xqc_id_hash_table_t));
    conn->dgram_sessions = xqc_calloc(1, sizeof(xqc_id_hash_table_t));
    if (conn->sessions == NULL || conn->closed_sessions == NULL
        || conn->pending_streams == NULL || conn->dgram_sessions == NULL)
    {
        xqc_free(conn->sessions);
        xqc_free(conn->closed_sessions);
        xqc_free(conn->pending_streams);
        xqc_free(conn->dgram_sessions);
        xqc_free(conn);
        return NULL;
    }
    xqc_id_hash_init(conn->sessions, xqc_default_allocator, 16);
    xqc_id_hash_init(conn->closed_sessions, xqc_default_allocator, 16);
    xqc_id_hash_init(conn->pending_streams, xqc_default_allocator, 16);
    xqc_id_hash_init(conn->dgram_sessions, xqc_default_allocator, 16);

    return conn;
}

xqc_int_t xqc_wt_conn_close(xqc_wt_conn_t* conn)
{
    if (conn == NULL) {
        return -XQC_EPARAM;
    }

    /* destroy all sessions registered on this connection.
     * Clear wt_conn back-references first to prevent re-entrant unregister
     * calls from xqc_wt_session_close modifying the hash during iteration. */
    if (conn->sessions) {
        for (int i = 0; i < conn->sessions->count; i++) {
            xqc_id_hash_node_t *node = conn->sessions->list[i];
            while (node) {
                xqc_wt_session_t *s = (xqc_wt_session_t *)node->element.value;
                node = node->next;
                if (s) {
                    s->wt_conn = NULL;
                    xqc_wt_session_close(s);
                }
            }
        }
        xqc_id_hash_release(conn->sessions);
        xqc_free(conn->sessions);
        conn->sessions = NULL;
    } else if (conn->wt_session) {
        conn->wt_session->wt_conn = NULL;
    }
    if (conn->closed_sessions) {
        xqc_id_hash_release(conn->closed_sessions);
        xqc_free(conn->closed_sessions);
        conn->closed_sessions = NULL;
    }
    xqc_wt_conn_free_pending_streams(conn);
    xqc_wt_conn_free_pending_dgrams(conn);
    if (conn->dgram_sessions) {
        xqc_id_hash_release(conn->dgram_sessions);
        xqc_free(conn->dgram_sessions);
        conn->dgram_sessions = NULL;
    }
    xqc_free(conn);

    return 0;
}

void xqc_wt_conn_set_dgram_mss(xqc_wt_conn_t* conn, size_t mss)
{
    conn->dgram_mss = mss;
}

xqc_h3_conn_t *
xqc_wt_conn_get_h3_conn(xqc_wt_conn_t *wt_conn)
{
    return wt_conn ? wt_conn->h3_conn : NULL;
}

xqc_int_t
xqc_wt_conn_register_session(xqc_wt_conn_t *wt_conn, xqc_wt_session_t *session)
{
    if (wt_conn == NULL || session == NULL || wt_conn->sessions == NULL) {
        return XQC_ERROR;
    }

    xqc_id_hash_element_t e = {
        .hash  = session->session_id,
        .value = session,
    };

    xqc_int_t ret = xqc_id_hash_add(wt_conn->sessions, e);
    if (ret != XQC_OK) {
        return ret;
    }
    wt_conn->active_session_count++;

    /* keep the first registered session as default */
    if (wt_conn->wt_session == NULL) {
        wt_conn->wt_session = session;
    }

    return XQC_OK;
}

void
xqc_wt_conn_unregister_session(xqc_wt_conn_t *wt_conn, uint64_t session_id)
{
    if (wt_conn == NULL || wt_conn->sessions == NULL) {
        return;
    }
    if (xqc_id_hash_find(wt_conn->sessions, session_id) != NULL
        && wt_conn->active_session_count > 0)
    {
        wt_conn->active_session_count--;
    }
    xqc_wt_conn_mark_session_closed(wt_conn, session_id);
    xqc_id_hash_delete(wt_conn->sessions, session_id);
    if (wt_conn->wt_session && wt_conn->wt_session->session_id == session_id) {
        wt_conn->wt_session = NULL;
        for (int i = 0; i < wt_conn->sessions->count; i++) {
            xqc_id_hash_node_t *node = wt_conn->sessions->list[i];
            if (node && node->element.value) {
                wt_conn->wt_session = (xqc_wt_session_t *)node->element.value;
                break;
            }
        }
    }
}

xqc_wt_session_t *
xqc_wt_conn_find_session(xqc_wt_conn_t *wt_conn, uint64_t session_id)
{
    if (wt_conn == NULL || wt_conn->sessions == NULL) {
        return NULL;
    }
    return (xqc_wt_session_t *)xqc_id_hash_find(wt_conn->sessions, session_id);
}

xqc_bool_t
xqc_wt_conn_can_buffer_unknown_session(xqc_wt_conn_t *wt_conn,
    uint64_t session_id)
{
    if (wt_conn == NULL || (session_id & 0x03) != 0) {
        return XQC_FALSE;
    }

    uint64_t window = wt_conn->wt_ctx
        ? wt_conn->wt_ctx->unknown_session_dgram_window
        : XQC_WEBTRANSPORT_DEFAULT_UNKNOWN_SESSION_DGRAM_WINDOW;
    uint64_t next_window =
        ((uint64_t)wt_conn->active_session_count + window) << 2;
    return session_id <= next_window ? XQC_TRUE : XQC_FALSE;
}

xqc_bool_t
xqc_wt_conn_has_active_session_without_fc(xqc_wt_conn_t *wt_conn,
    xqc_wt_session_t *exclude)
{
    if (wt_conn == NULL || wt_conn->sessions == NULL) {
        return XQC_FALSE;
    }

    for (int i = 0; i < wt_conn->sessions->count; i++) {
        xqc_id_hash_node_t *node = wt_conn->sessions->list[i];
        while (node) {
            xqc_wt_session_t *session =
                (xqc_wt_session_t *)node->element.value;
            if (session && session != exclude && !session->terminated
                && !session->flow_control_enabled)
            {
                return XQC_TRUE;
            }
            node = node->next;
        }
    }

    return XQC_FALSE;
}

void
xqc_wt_conn_mark_session_closed(xqc_wt_conn_t *wt_conn, uint64_t session_id)
{
    if (wt_conn == NULL || wt_conn->closed_sessions == NULL) {
        return;
    }
    if (xqc_id_hash_find(wt_conn->closed_sessions, session_id) != NULL) {
        return;
    }

    xqc_id_hash_element_t e = {
        .hash = session_id,
        .value = wt_conn,
    };
    xqc_id_hash_add(wt_conn->closed_sessions, e);
}

xqc_bool_t
xqc_wt_conn_is_closed_session(xqc_wt_conn_t *wt_conn, uint64_t session_id)
{
    if (wt_conn == NULL || wt_conn->closed_sessions == NULL) {
        return XQC_FALSE;
    }
    return xqc_id_hash_find(wt_conn->closed_sessions, session_id) != NULL
           ? XQC_TRUE : XQC_FALSE;
}

xqc_int_t
xqc_wt_conn_register_dgram_session(xqc_wt_conn_t *wt_conn, uint64_t dgram_id,
    xqc_wt_session_t *session)
{
    if (wt_conn == NULL || session == NULL || wt_conn->dgram_sessions == NULL) {
        return -XQC_EPARAM;
    }

    xqc_id_hash_element_t e = {
        .hash = dgram_id,
        .value = session,
    };
    return xqc_id_hash_add(wt_conn->dgram_sessions, e);
}

xqc_wt_session_t *
xqc_wt_conn_find_dgram_session(xqc_wt_conn_t *wt_conn, uint64_t dgram_id)
{
    if (wt_conn == NULL || wt_conn->dgram_sessions == NULL) {
        return NULL;
    }
    return (xqc_wt_session_t *)xqc_id_hash_find(wt_conn->dgram_sessions,
        dgram_id);
}

void
xqc_wt_conn_unregister_dgram_session(xqc_wt_conn_t *wt_conn, uint64_t dgram_id)
{
    if (wt_conn == NULL || wt_conn->dgram_sessions == NULL) {
        return;
    }
    xqc_id_hash_delete(wt_conn->dgram_sessions, dgram_id);
}
