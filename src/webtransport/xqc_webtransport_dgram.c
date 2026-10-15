/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include "src/webtransport/xqc_webtransport_dgram.h"
#include "src/webtransport/xqc_webtransport_conn.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_packet_out.h"
#include "src/common/xqc_malloc.h"

#define XQC_WT_SENT_DGRAM_MAX 1024

/* RFC 9297 Section 2.1: client-initiated bidi Stream ID divided by four. */
#define XQC_WT_MAX_QUARTER_STREAM_ID (XQC_WT_VARINT_MAX / 4)

typedef struct {
    xqc_list_head_t  list;
    uint64_t         session_id;
    uint64_t         id;
} xqc_wt_sent_dgram_t;

typedef struct {
    xqc_list_head_t  list;
    uint64_t         session_id;
    uint64_t         id;
    size_t           len;
    unsigned char    data[];
} xqc_wt_dgram_t;

static xqc_wt_conn_t *xqc_wt_dgram_conn(xqc_connection_t *conn);
static void xqc_wt_dgram_deliver(xqc_wt_session_t *session, const void *data,
    size_t len, uint64_t time);
static void xqc_wt_dgram_read(xqc_connection_t *transport, void *user_data,
    const void *data, size_t len, uint64_t time);
static void xqc_wt_dgram_write(xqc_connection_t *transport, void *user_data);
static int xqc_wt_dgram_complete(xqc_connection_t *transport, uint64_t id,
    xqc_bool_t lost);
static int xqc_wt_dgram_lost(xqc_connection_t *conn, uint64_t id, void *data);
static void xqc_wt_dgram_acked(xqc_connection_t *conn, uint64_t id, void *data);
static void xqc_wt_dgram_mss(xqc_connection_t *transport,
    size_t mss, void *data);

static xqc_wt_conn_t *
xqc_wt_dgram_conn(xqc_connection_t *conn)
{
    xqc_h3_conn_t *h3c = conn->proto_data;
    return xqc_wt_get_conn_from_h3(h3c);
}

static void
xqc_wt_dgram_deliver(xqc_wt_session_t *session, const void *data,
    size_t len, uint64_t time)
{
    if (xqc_wt_session_is_writable(session)
        && session->wt_conn->ctx->dgram_cbs.dgram_read_notify)
    {
        session->wt_conn->ctx->dgram_cbs.dgram_read_notify(
            session, data,
            len, xqc_wt_session_get_callback_user_data(session), time);
    }
}

static void
xqc_wt_dgram_read(xqc_connection_t *transport, void *user_data,
    const void *data, size_t len, uint64_t time)
{
    xqc_wt_conn_t *conn = xqc_wt_dgram_conn(transport);
    uint64_t quarter_stream_id;
    ssize_t prefix = xqc_wt_get_varint(data, len, &quarter_stream_id);
    if (!conn || prefix < 0
        || quarter_stream_id > XQC_WT_MAX_QUARTER_STREAM_ID)
    {
        return;
    }
    /* RFC 9297 Section 2.1: HTTP datagrams carry the Quarter Stream ID. */
    uint64_t id = quarter_stream_id * 4;
    const unsigned char *payload = (const unsigned char *)data + prefix;
    len -= prefix;
    xqc_wt_session_t *session = xqc_wt_conn_find_session(conn, id);
    if (session && session->open && !session->closed) {
        xqc_wt_dgram_deliver(session, payload, len, time);
        return;
    }
    if ((session && session->closed) || id < conn->latest_session_id
        || (!session && conn->session_id_seen
            && id == conn->latest_session_id))
    {
        xqc_log(conn->h3_conn->log, XQC_LOG_DEBUG,
                "|WT datagram ignored|closed or stale session:%ui|", id);
        return;
    }
    xqc_wt_ctx_t *ctx = conn->ctx;
    if (quarter_stream_id - conn->latest_session_id / 4 > ctx->pending_window
        || conn->pending_count >= ctx->pending_count_max
        || len > ctx->pending_bytes_max - conn->pending_bytes)
    {
        xqc_log(conn->h3_conn->log, XQC_LOG_WARN,
                "|WT pending datagram limit|session:%ui|count:%uz|bytes:%uz|",
                id, conn->pending_count, conn->pending_bytes);
        return;
    }
    xqc_wt_dgram_t *pending = xqc_malloc(sizeof(*pending) + len);
    if (!pending) {
        xqc_log(conn->h3_conn->log, XQC_LOG_ERROR,
                "|WT pending datagram allocation failed|len:%uz|", len);
        return;
    }
    pending->session_id = id;
    pending->id = time;
    pending->len = len;
    memcpy(pending->data, payload, len);
    xqc_list_add_tail(&pending->list, &conn->pending_datagrams);
    conn->pending_count++;
    conn->pending_bytes += len;
}

void
xqc_wt_dgram_resume(xqc_wt_session_t *session)
{
    xqc_wt_conn_t *conn = session->wt_conn;
    uint64_t id = session->session_id;
    xqc_list_head_t *pos = conn->pending_datagrams.next;
    while (pos != &conn->pending_datagrams) {
        xqc_wt_dgram_t *item = xqc_list_entry(pos, xqc_wt_dgram_t, list);
        if (item->session_id == id) {
            xqc_list_del(pos);
            conn->pending_count--;
            conn->pending_bytes -= item->len;
            xqc_wt_dgram_deliver(session, item->data, item->len, item->id);
            xqc_free(item);
            /* The read callback may close the session and purge the queue. */
            session = xqc_wt_conn_find_session(conn, id);
            if (!xqc_wt_session_is_writable(session)) {
                return;
            }
            pos = conn->pending_datagrams.next;
        } else {
            pos = pos->next;
        }
    }
}

void
xqc_wt_dgram_purge(xqc_wt_session_t *session)
{
    xqc_wt_conn_t *conn = session->wt_conn;
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &conn->pending_datagrams) {
        xqc_wt_dgram_t *item = xqc_list_entry(pos, xqc_wt_dgram_t, list);
        if (item->session_id == session->session_id) {
            xqc_list_del(pos);
            conn->pending_count--;
            conn->pending_bytes -= item->len;
            xqc_free(item);
        }
    }
}

xqc_int_t
xqc_wt_session_datagram_send(xqc_wt_session_t *session,
    const void *data, size_t len, uint64_t *datagram_id)
{
    if (!session || (!data && len)) {
        return -XQC_EPARAM;
    }
    if (!xqc_wt_session_is_writable(session)) {
        return -XQC_ESTATE;
    }
    xqc_wt_conn_t *conn = session->wt_conn;
    unsigned char packet[XQC_MAX_PACKET_OUT_SIZE];
    size_t prefix_len = xqc_wt_put_varint(session->session_id / 4,
                                          packet, sizeof(packet));
    size_t mss = xqc_min(xqc_datagram_get_mss(conn->h3_conn->conn),
                         sizeof(packet));
    if (mss < prefix_len || len > mss - prefix_len) {
        return -XQC_EDGRAM_TOO_LARGE;
    }
    if (conn->sent_count >= XQC_WT_SENT_DGRAM_MAX) {
        conn->datagram_send_blocked = XQC_TRUE;
        return -XQC_EAGAIN;
    }
    xqc_wt_sent_dgram_t *item = xqc_malloc(sizeof(*item));
    if (!item) {
        return -XQC_EMALLOC;
    }
    item->session_id = session->session_id;
    if (len) {
        memcpy(packet + prefix_len, data, len);
    }
    xqc_int_t ret = xqc_datagram_send(
        conn->h3_conn->conn, packet,
        prefix_len + len, &item->id, XQC_DATA_QOS_HIGHEST);
    if (ret == XQC_OK) {
        if (datagram_id) {
            *datagram_id = item->id;
        }
        xqc_list_add_tail(&item->list, &conn->sent_datagrams);
        conn->sent_count++;
    } else {
        xqc_free(item);
    }
    return ret;
}


static void
xqc_wt_dgram_write(xqc_connection_t *transport, void *user_data)
{
    xqc_wt_conn_t *conn = xqc_wt_dgram_conn(transport);
    if (!conn || !conn->ctx->dgram_cbs.dgram_write_notify) {
        return;
    }
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &conn->session_list) {
        xqc_wt_session_t *session = xqc_list_entry(pos,
                                                   xqc_wt_session_t, conn_list);
        if (xqc_wt_session_is_writable(session)) {
            conn->ctx->dgram_cbs.dgram_write_notify(
                session, xqc_wt_session_get_callback_user_data(session));
        }
    }
}

static int
xqc_wt_dgram_complete(xqc_connection_t *transport, uint64_t id,
    xqc_bool_t lost)
{
    xqc_wt_conn_t *conn = xqc_wt_dgram_conn(transport);
    if (!conn) {
        return 0;
    }
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &conn->sent_datagrams) {
        xqc_wt_sent_dgram_t *item = xqc_list_entry(pos,
                                                   xqc_wt_sent_dgram_t, list);
        if (item->id != id) {
            continue;
        }
        xqc_wt_session_t *session =
            xqc_wt_conn_find_session(conn, item->session_id);
        int ret = 0;
        if (xqc_wt_session_is_writable(session)) {
            void *ctx = xqc_wt_session_get_callback_user_data(session);
            if (lost && conn->ctx->dgram_cbs.dgram_lost_notify) {
                ret = conn->ctx->dgram_cbs.dgram_lost_notify(session, id, ctx);
            } else if (!lost && conn->ctx->dgram_cbs.dgram_acked_notify) {
                conn->ctx->dgram_cbs.dgram_acked_notify(session, id, ctx);
            }
        }
        if (!lost || ret != XQC_DGRAM_RETX_ASKED_BY_APP) {
            xqc_list_del(pos);
            conn->sent_count--;
            xqc_free(item);
            if (conn->datagram_send_blocked) {
                conn->datagram_send_blocked = XQC_FALSE;
                xqc_wt_dgram_write(transport, NULL);
            }
        }
        return ret;
    }
    return 0;
}

static int
xqc_wt_dgram_lost(xqc_connection_t *conn, uint64_t id, void *data)
{
    return xqc_wt_dgram_complete(conn, id, XQC_TRUE);
}

static void
xqc_wt_dgram_acked(xqc_connection_t *conn, uint64_t id, void *data)
{
    xqc_wt_dgram_complete(conn, id, XQC_FALSE);
}

static void
xqc_wt_dgram_mss(xqc_connection_t *transport, size_t mss, void *data)
{
    xqc_wt_conn_t *conn = xqc_wt_dgram_conn(transport);
    if (!conn) {
        return;
    }
    mss = xqc_min(mss, XQC_MAX_PACKET_OUT_SIZE);
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &conn->session_list) {
        xqc_wt_session_t *session = xqc_list_entry(pos,
                                                   xqc_wt_session_t, conn_list);
        unsigned char buf[XQC_WT_VARINT_MAX_LEN];
        size_t prefix = xqc_wt_put_varint(session->session_id / 4,
                                          buf, sizeof(buf));
        if (xqc_wt_session_is_writable(session)
            && conn->ctx->dgram_cbs.dgram_mss_updated_notify)
        {
            conn->ctx->dgram_cbs.dgram_mss_updated_notify(
                session, mss > prefix ? mss - prefix : 0,
                xqc_wt_session_get_callback_user_data(session));
        }
    }
}

void
xqc_wt_dgram_callbacks(xqc_datagram_callbacks_t *callbacks)
{
    callbacks->datagram_read_notify = xqc_wt_dgram_read;
    callbacks->datagram_write_notify = xqc_wt_dgram_write;
    callbacks->datagram_acked_notify = xqc_wt_dgram_acked;
    callbacks->datagram_lost_notify = xqc_wt_dgram_lost;
    callbacks->datagram_mss_updated_notify = xqc_wt_dgram_mss;
}

void
xqc_wt_dgram_clear(xqc_wt_conn_t *conn)
{
    xqc_list_head_t *heads[] = {
        &conn->pending_datagrams, &conn->sent_datagrams
    };
    for (size_t i = 0; i < 2; i++) {
        while (!xqc_list_empty(heads[i])) {
            /* Both queue node types have the list as their first member. */
            xqc_list_head_t *item = heads[i]->next;
            xqc_list_del(item);
            xqc_free(item);
        }
    }
}
