/**
 * xqc_webtransport_conn.c
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */
#include "xqc_webtransport_conn.h"
#include "src/common/xqc_malloc.h"


xqc_wt_conn_t* xqc_wt_conn_create(xqc_h3_conn_t* h3_conn)
{
    xqc_wt_conn_t* conn = xqc_calloc(1, sizeof(xqc_wt_conn_t));
    conn->h3_conn = h3_conn;
    conn->wt_session = NULL;
    conn->bidistream_first_connect = XQC_FALSE;
    conn->dgram_mss = 100;

    /* initialize session map for potential multi-session support */
    conn->sessions = xqc_calloc(1, sizeof(xqc_id_hash_table_t));
    if (conn->sessions) {
        xqc_id_hash_init(conn->sessions, xqc_default_allocator, 16);
    }

    return conn;
}

xqc_int_t xqc_wt_conn_close(xqc_wt_conn_t* conn)
{
    if (conn->sessions) {
        xqc_id_hash_release(conn->sessions);
        xqc_free(conn->sessions);
        conn->sessions = NULL;
    }
    xqc_free(conn);

    return 0;
}

void xqc_wt_conn_set_dgram_mss(xqc_wt_conn_t* conn, size_t mss)
{
    conn->dgram_mss = mss;
}

xqc_int_t
xqc_wt_conn_register_session(xqc_wt_conn_t *wt_conn, xqc_wt_session_t *session)
{
    if (wt_conn == NULL || session == NULL || wt_conn->sessions == NULL) {
        return XQC_ERROR;
    }

    xqc_id_hash_element_t e = {
        .hash  = session->sessionID,
        .value = session,
    };

    xqc_int_t ret = xqc_id_hash_add(wt_conn->sessions, e);
    if (ret != XQC_OK) {
        return ret;
    }

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
    xqc_id_hash_delete(wt_conn->sessions, session_id);
    /* do not touch wt_conn->wt_session here; it is managed by caller */
}

xqc_wt_session_t *
xqc_wt_conn_find_session(xqc_wt_conn_t *wt_conn, uint64_t session_id)
{
    if (wt_conn == NULL || wt_conn->sessions == NULL) {
        return NULL;
    }
    return (xqc_wt_session_t *)xqc_id_hash_find(wt_conn->sessions, session_id);
}
