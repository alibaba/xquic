/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include "src/webtransport/xqc_webtransport_conn.h"
#include "src/webtransport/xqc_webtransport_stream.h"
#include "src/webtransport/xqc_webtransport_h3_stream.h"
#include "src/webtransport/xqc_webtransport_request_adapter.h"
#include "src/webtransport/xqc_webtransport_dgram.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_request.h"
#include "src/transport/xqc_conn.h"
#include "src/common/xqc_malloc.h"

typedef struct {
    uint64_t    peer_max_sessions;
    uint64_t    peer_initial_max_streams_uni;
    uint64_t    peer_initial_max_streams_bidi;
    uint64_t    peer_initial_max_data;
    xqc_bool_t  peer_draft16;
    xqc_bool_t  peer_datagram;
    xqc_bool_t  peer_connect;
} xqc_wt_peer_settings_t;

static xqc_int_t xqc_wt_peer_setting(uint64_t id, uint64_t value,
    xqc_wt_peer_settings_t *settings);
static xqc_int_t xqc_wt_peer_settings_complete(void *data);

xqc_wt_conn_t *
xqc_wt_conn_create(xqc_h3_conn_t *h3_conn)
{
    if (h3_conn == NULL || xqc_wt_get_conn_from_h3(h3_conn)) {
        return NULL;
    }
    xqc_wt_conn_t *conn = xqc_calloc(1, sizeof(*conn));
    if (!conn) {
        return NULL;
    }
    conn->h3_conn = h3_conn;
    xqc_init_list_head(&conn->h3_streams);
    xqc_init_list_head(&conn->session_list);
    xqc_init_list_head(&conn->pending_streams);
    xqc_init_list_head(&conn->pending_datagrams);
    xqc_init_list_head(&conn->sent_datagrams);
    if (xqc_id_hash_init(&conn->sessions, xqc_default_allocator,
                         XQC_WT_SESSION_HASH_BUCKETS)
        != XQC_OK)
    {
        xqc_free(conn);
        return NULL;
    }
    if (xqc_id_hash_init(&conn->h3_stream_index, xqc_default_allocator,
                         XQC_WT_STREAM_HASH_BUCKETS) != XQC_OK)
    {
        xqc_id_hash_release(&conn->sessions);
        xqc_free(conn);
        return NULL;
    }
    h3_conn->extension_data = conn;
    return conn;
}

xqc_wt_conn_t *
xqc_wt_get_conn_from_h3(xqc_h3_conn_t *h3_conn)
{
    return h3_conn ? h3_conn->extension_data : NULL;
}

xqc_bool_t
xqc_wt_conn_requirements_met(xqc_wt_conn_t *conn)
{
    if (!conn || !conn->settings_received || !conn->negotiated_version
        || !conn->peer_datagram || !conn->h3_conn->conn)
    {
        return XQC_FALSE;
    }
    xqc_connection_t *quic = conn->h3_conn->conn;
    if (!quic->local_settings.max_datagram_frame_size
        || !quic->remote_settings.max_datagram_frame_size
        || (quic->conn_type == XQC_CONN_TYPE_CLIENT && !conn->peer_connect))
    {
        return XQC_FALSE;
    }
    /*
     * draft-ietf-webtrans-http3-16 §3.1: no fallback on missing prerequisites.
     */
    return conn->negotiated_version == XQC_WEBTRANSPORT_DRAFT_VERSION_7
        || (quic->local_settings.reset_stream_at
            && quic->remote_settings.reset_stream_at);
}

void
xqc_wt_conn_notify_goaway(xqc_wt_conn_t *conn)
{
    if (!conn || conn->goaway_notified
        || !(conn->h3_conn->flags & XQC_H3_CONN_FLAG_GOAWAY_RECVD))
    {
        return;
    }
    conn->goaway_notified = XQC_TRUE;
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &conn->session_list) {
        xqc_wt_session_t *session = xqc_list_entry(pos,
                                                   xqc_wt_session_t, conn_list);
        if (session->open && !session->closed) {
            xqc_wt_session_notify_draining(session);
        }
    }
}

void
xqc_wt_conn_destroy(xqc_wt_conn_t *conn)
{
    if (!conn) {
        return;
    }
    conn->closing = XQC_TRUE;
    xqc_wt_conn_close_pending_streams(conn);
    while (!xqc_list_empty(&conn->session_list)) {
        xqc_wt_session_t *session = xqc_list_entry(conn->session_list.next,
                                                   xqc_wt_session_t, conn_list);
        xqc_wt_session_destroy(session);
    }
    xqc_wt_dgram_clear(conn);
    xqc_wt_h3_stream_clear(conn);
    xqc_id_hash_release(&conn->h3_stream_index);
    xqc_id_hash_release(&conn->sessions);
    if (conn->ctx) {
        conn->h3_conn->h3_conn_callbacks = conn->ctx->app_conn_callbacks;
        if (!conn->ctx->app_conn_callbacks.h3_conn_create_notify) {
            conn->h3_conn->flags &= ~XQC_H3_CONN_FLAG_UPPER_CONN_EXIST;
        }
    }
    conn->h3_conn->h3_request_callbacks = conn->app_request_callbacks;
    conn->h3_conn->extension_data = NULL;
    xqc_free(conn);
}

xqc_int_t
xqc_wt_conn_register_session(xqc_wt_conn_t *conn, xqc_wt_session_t *session)
{
    if (!conn || !session || conn->closing) {
        return -XQC_EPARAM;
    }
    xqc_id_hash_element_t e = {session->session_id, session};
    xqc_int_t ret = xqc_id_hash_add(&conn->sessions, e);
    if (ret != XQC_OK) {
        return ret;
    }
    xqc_list_add_tail(&session->conn_list, &conn->session_list);
    conn->session_count++;
    conn->session_id_seen = XQC_TRUE;
    conn->latest_session_id = xqc_max(conn->latest_session_id,
                                      session->session_id);
    if (!conn->wt_session) {
        conn->wt_session = session;
    }
    return XQC_OK;
}

size_t
xqc_wt_conn_active_session_count(xqc_wt_conn_t *conn)
{
    size_t count = 0;
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &conn->session_list) {
        xqc_wt_session_t *session = xqc_list_entry(pos,
                                                   xqc_wt_session_t, conn_list);
        count += !session->closed;
    }
    return count;
}

void
xqc_wt_conn_unregister_session(xqc_wt_conn_t *conn, uint64_t id)
{
    xqc_wt_session_t *session = xqc_wt_conn_find_session(conn, id);
    if (!session) {
        return;
    }
    xqc_id_hash_delete(&conn->sessions, id);
    xqc_list_del_init(&session->conn_list);
    conn->session_count--;
    if (conn->wt_session == session) {
        conn->wt_session = xqc_list_empty(&conn->session_list) ? NULL
            : xqc_list_entry(conn->session_list.next,
                             xqc_wt_session_t, conn_list);
    }
}

xqc_wt_session_t *
xqc_wt_conn_find_session(xqc_wt_conn_t *conn, uint64_t id)
{
    return conn ? xqc_id_hash_find(&conn->sessions, id) : NULL;
}

/* draft-ietf-webtrans-http3-16 Sections 3.1 and 7.1. */
static xqc_int_t
xqc_wt_peer_setting(uint64_t id, uint64_t value,
    xqc_wt_peer_settings_t *settings)
{
    /* Draft-16 Section 3.1: capability settings only allow 0 and 1. */
    if (id == XQC_WT_SETTING_MAX_SESSIONS) {
        settings->peer_max_sessions = value;
    } else if (id == XQC_WT_SETTING_ENABLED_16) {
        if (value > 1) {
            return -XQC_H3_SETTING_ERROR;
        }
        settings->peer_draft16 = value;
    } else if (id == XQC_WT_SETTING_INITIAL_MAX_STREAMS_UNI) {
        if (value > XQC_WT_MAX_STREAMS) {
            return -XQC_H3_SETTING_ERROR;
        }
        settings->peer_initial_max_streams_uni = value;
    } else if (id == XQC_WT_SETTING_INITIAL_MAX_STREAMS_BIDI) {
        if (value > XQC_WT_MAX_STREAMS) {
            return -XQC_H3_SETTING_ERROR;
        }
        settings->peer_initial_max_streams_bidi = value;
    } else if (id == XQC_WT_SETTING_INITIAL_MAX_DATA) {
        settings->peer_initial_max_data = value;
    } else if (id == XQC_WT_SETTING_DATAGRAM) {
        if (value > 1) {
            return -XQC_H3_SETTING_ERROR;
        }
        settings->peer_datagram = value;
    } else if (id == XQC_WT_SETTING_CONNECT) {
        if (value > 1) {
            return -XQC_H3_SETTING_ERROR;
        }
        settings->peer_connect = value;
    }
    return XQC_OK;
}

static xqc_int_t
xqc_wt_peer_settings_complete(void *data)
{
    xqc_wt_conn_t *conn = data;
    conn->settings_received = XQC_TRUE;
    if (conn->peer_draft16
        && conn->ctx->settings.draft_version
           == XQC_WEBTRANSPORT_DRAFT_VERSION_16)
    {
        conn->negotiated_version = XQC_WEBTRANSPORT_DRAFT_VERSION_16;
        conn->flow_control_enabled = conn->ctx->settings.max_sessions_count > 1
            && (conn->peer_initial_max_streams_uni
                || conn->peer_initial_max_streams_bidi
                || conn->peer_initial_max_data);
    } else if (conn->peer_max_sessions) {
        conn->negotiated_version = XQC_WEBTRANSPORT_DRAFT_VERSION_7;
    }
    if (conn->negotiated_version) {
        /* Draft-07 Section 4.2 and draft-16 Section 4.3 share this guard. */
        conn->h3_conn->flags |= XQC_H3_CONN_FLAG_WEBTRANSPORT;
        xqc_log(conn->h3_conn->log, XQC_LOG_DEBUG,
                "|WT version negotiated|draft:%d|",
                conn->negotiated_version == XQC_WEBTRANSPORT_DRAFT_VERSION_16
                    ? 16 : 7);
    }
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &conn->session_list) {
        xqc_wt_session_t *session = xqc_list_entry(pos,
                                                   xqc_wt_session_t, conn_list);
        xqc_wt_session_init_flow_control(session);
        if (!session->open && !session->closed) {
            xqc_int_t ret = session->client
                ? xqc_wt_client_send_request(session)
                : xqc_wt_request_read(
                    session->request,
                    XQC_REQ_NOTIFY_READ_HEADER | XQC_REQ_NOTIFY_READ_BODY,
                    session);
            if (ret != XQC_OK && !(session->client && session->closed)) {
                return ret;
            }
        }
    }
    return XQC_OK;
}

xqc_h3_settings_result_t
xqc_wt_conn_peer_settings(xqc_h3_conn_t *h3c,
    const xqc_h3_setting_t *settings, size_t count, void *data)
{
    xqc_wt_conn_t *conn = xqc_wt_get_conn_from_h3(h3c);
    if (!conn || !conn->ctx || (count && !settings)
        || conn->settings_received)
    {
        return XQC_H3_SETTINGS_INTERNAL_ERROR;
    }
    /* Validate the complete batch before publishing any WT capability. */
    xqc_wt_peer_settings_t candidate = {0};
    for (size_t i = 0; i < count; i++) {
        if (xqc_wt_peer_setting(settings[i].identifier, settings[i].value,
                                &candidate) != XQC_OK)
        {
            return XQC_H3_SETTINGS_REJECT;
        }
    }
    if (conn->ctx->app_conn_callbacks.h3_conn_peer_extern_settings_notify) {
        xqc_h3_settings_result_t result = conn->ctx->app_conn_callbacks
            .h3_conn_peer_extern_settings_notify(h3c, settings, count, data);
        if (result != XQC_H3_SETTINGS_ACCEPT) {
            return result;
        }
    }
    conn->peer_max_sessions = candidate.peer_max_sessions;
    conn->peer_draft16 = candidate.peer_draft16;
    conn->peer_datagram = candidate.peer_datagram;
    conn->peer_connect = candidate.peer_connect;
    conn->peer_initial_max_streams_uni = candidate.peer_initial_max_streams_uni;
    conn->peer_initial_max_streams_bidi =
        candidate.peer_initial_max_streams_bidi;
    conn->peer_initial_max_data = candidate.peer_initial_max_data;
    return xqc_wt_peer_settings_complete(conn) == XQC_OK
        ? XQC_H3_SETTINGS_ACCEPT : XQC_H3_SETTINGS_INTERNAL_ERROR;
}
