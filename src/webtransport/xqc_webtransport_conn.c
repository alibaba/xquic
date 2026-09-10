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
#include "src/common/xqc_malloc.h"

static xqc_int_t xqc_wt_peer_setting(uint64_t id, uint64_t value,
    void *data);
static xqc_int_t xqc_wt_peer_settings_complete(void *data);

xqc_wt_conn_t *
xqc_wt_conn_create(xqc_h3_conn_t *h3_conn)
{
    if (h3_conn == NULL || xqc_wt_create_conn(h3_conn)) {
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
    if (xqc_id_hash_init(&conn->sessions, xqc_default_allocator, 16)
        != XQC_OK)
    {
        xqc_free(conn);
        return NULL;
    }
    h3_conn->settings_user_data = conn;
    h3_conn->on_settings_entry = xqc_wt_peer_setting;
    h3_conn->on_settings_complete = xqc_wt_peer_settings_complete;
    return conn;
}

xqc_wt_conn_t *
xqc_wt_create_conn(xqc_h3_conn_t *h3_conn)
{
    return h3_conn && h3_conn->on_settings_entry == xqc_wt_peer_setting
        ? h3_conn->settings_user_data : NULL;
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
    xqc_id_hash_release(&conn->sessions);
    if (conn->ctx) {
        conn->h3_conn->h3_conn_callbacks = conn->ctx->app_conn_callbacks;
        if (!conn->ctx->app_conn_callbacks.h3_conn_create_notify) {
            conn->h3_conn->flags &= ~XQC_H3_CONN_FLAG_UPPER_CONN_EXIST;
        }
    }
    conn->h3_conn->h3_request_callbacks = conn->app_request_callbacks;
    conn->h3_conn->settings_user_data = NULL;
    conn->h3_conn->local_settings_extra = NULL;
    conn->h3_conn->local_settings_extra_count = 0;
    conn->h3_conn->on_settings_entry = NULL;
    conn->h3_conn->on_settings_complete = NULL;
    xqc_free(conn);
}

xqc_int_t
xqc_wt_conn_close(xqc_wt_conn_t *conn)
{
    if (!conn || !conn->h3_conn) {
        return -XQC_EPARAM;
    }
    return xqc_conn_close_with_error(conn->h3_conn->conn, 0);
}

void
xqc_wt_conn_set_dgram_mss(xqc_wt_conn_t *conn, size_t mss)
{
    if (conn) {
        conn->dgram_mss = mss;
    }
}

xqc_int_t
xqc_wt_conn_register_session(xqc_wt_conn_t *conn, xqc_wt_session_t *session)
{
    if (!conn || !session || conn->closing) {
        return -XQC_EPARAM;
    }
    xqc_id_hash_element_t e = {session->sessionID, session};
    xqc_int_t ret = xqc_id_hash_add(&conn->sessions, e);
    if (ret != XQC_OK) {
        return ret;
    }
    xqc_list_add_tail(&session->conn_list, &conn->session_list);
    conn->session_count++;
    conn->latest_session_id = xqc_max(conn->latest_session_id,
                                    session->sessionID);
    if (!conn->wt_session) {
        conn->wt_session = session;
    }
    return XQC_OK;
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

/* draft-ietf-webtrans-http3-07 Sections 3.1, 3.2 and 8.2. */
static xqc_int_t
xqc_wt_peer_setting(uint64_t id, uint64_t value, void *data)
{
    xqc_wt_conn_t *conn = data;
    if (id == UINT64_C(0xc671706a)) {
        conn->peer_max_sessions = value;
    } else if (id == 0x33) {
        if (value > 1) {
            return -XQC_H3_SETTING_ERROR;
        }
        conn->peer_datagram = value;
    } else if (id == 0x08) {
        if (value > 1) {
            return -XQC_H3_SETTING_ERROR;
        }
        conn->peer_connect = value;
    }
    return XQC_OK;
}

static xqc_int_t
xqc_wt_peer_settings_complete(void *data)
{
    xqc_wt_conn_t *conn = data;
    conn->settings_received = XQC_TRUE;
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &conn->session_list) {
        xqc_wt_session_t *session = xqc_list_entry(pos,
            xqc_wt_session_t, conn_list);
        if (!session->open && !session->closed) {
            xqc_int_t ret = xqc_wt_request_read(session->request,
                XQC_REQ_NOTIFY_READ_HEADER | XQC_REQ_NOTIFY_READ_BODY,
                session);
            if (ret != XQC_OK) {
                return ret;
            }
        }
    }
    return XQC_OK;
}
