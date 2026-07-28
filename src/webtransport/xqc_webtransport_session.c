/**
 * xqc_webtransport_session.c
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */
#include "xqc_webtransport_session.h"
#include "src/common/xqc_id_hash.h"
#include "src/common/xqc_malloc.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_packet_out.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_request.h"
#include "src/webtransport/xqc_webtransport_conn.h"
#include "src/webtransport/xqc_webtransport_dgram.h"
#include "src/webtransport/xqc_webtransport_session.h"
#include "src/webtransport/xqc_webtransport_stream.h"
#include "src/webtransport/xqc_webtransport_wire.h"

#define XQC_WT_DEFAULT_STREAMS_WINDOW 1024
#define XQC_WT_DEFAULT_DATA_WINDOW    (16 * 1024 * 1024ULL)

static xqc_bool_t
xqc_wt_local_settings_has_nonzero_flow(xqc_h3_conn_settings_t *settings)
{
    if (settings == NULL) {
        return XQC_FALSE;
    }

    return (settings->wt_initial_max_streams_uni != 0
            || settings->wt_initial_max_streams_bidi != 0
            || settings->wt_initial_max_data != 0)
           ? XQC_TRUE : XQC_FALSE;
}

static xqc_bool_t
xqc_wt_peer_settings_has_nonzero_flow(xqc_h3_conn_settings_t *settings)
{
    if (settings == NULL) {
        return XQC_FALSE;
    }

    return ((settings->wt_initial_max_streams_uni_present
             && settings->wt_initial_max_streams_uni != 0)
            || (settings->wt_initial_max_streams_bidi_present
                && settings->wt_initial_max_streams_bidi != 0)
            || (settings->wt_initial_max_data_present
                && settings->wt_initial_max_data != 0))
           ? XQC_TRUE : XQC_FALSE;
}

void
xqc_wt_stream_buffer_list_release(xqc_wt_buffer_list_t *list)
{
    if (list == NULL) {
        return;
    }
    xqc_wt_buffer_t *node = list->head;
    while (node) {
        xqc_wt_buffer_t *next = node->next;
        xqc_free(node->data);
        xqc_free(node);
        node = next;
    }
    list->head = NULL;
    list->tail = NULL;
}

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

    if (conn && conn->h3_conn) {
        xqc_h3_conn_settings_t *local = &conn->h3_conn->local_h3_conn_settings;
        xqc_h3_conn_settings_t *peer = &conn->h3_conn->peer_h3_conn_settings;
        session->local_max_streams_uni = local->wt_initial_max_streams_uni;
        session->local_max_streams_bidi = local->wt_initial_max_streams_bidi;
        session->local_max_data = local->wt_initial_max_data;
        session->peer_max_streams_uni = peer->wt_initial_max_streams_uni;
        session->peer_max_streams_bidi = peer->wt_initial_max_streams_bidi;
        session->peer_max_data = peer->wt_initial_max_data;
        session->local_streams_uni_window =
            session->local_max_streams_uni ? session->local_max_streams_uni
                                           : XQC_WT_DEFAULT_STREAMS_WINDOW;
        session->local_streams_bidi_window =
            session->local_max_streams_bidi ? session->local_max_streams_bidi
                                            : XQC_WT_DEFAULT_STREAMS_WINDOW;
        session->local_data_window =
            session->local_max_data ? session->local_max_data
                                    : XQC_WT_DEFAULT_DATA_WINDOW;
        xqc_bool_t local_has_wt_flow =
            xqc_wt_local_settings_has_nonzero_flow(local);
        xqc_bool_t peer_has_wt_flow =
            xqc_wt_peer_settings_has_nonzero_flow(peer);

        switch (local->webtransport_mode) {
        case XQC_WT_MODE_BROWSER_LEGACY:
            session->flow_control_enabled = XQC_FALSE;
            break;
        case XQC_WT_MODE_BROWSER_COMPAT:
            session->flow_control_enabled =
                local_has_wt_flow && peer_has_wt_flow;
            break;
        case XQC_WT_MODE_DRAFT15_STRICT:
        default:
            session->flow_control_enabled =
                local_has_wt_flow && peer_has_wt_flow;
            break;
        }
    }

    /* register this session on the connection for future lookup (e.g. datagrams) */
    if (xqc_wt_conn_register_session(conn, session) != XQC_OK) {
        xqc_id_hash_release(session->stream_id_hash_table);
        xqc_id_hash_release(session->pending_unistreams);
        xqc_free(session->stream_id_hash_table);
        xqc_free(session->pending_unistreams);
        xqc_free(session);
        return NULL;
    }

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
                            xqc_wt_stream_buffer_list_release(&uni->pending_recv);
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
                            xqc_wt_stream_buffer_list_release(&bidi->pending_recv);
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
    if (session == NULL || session->pending_unistreams == NULL
        || h3_stream == NULL || wt_stream == NULL)
    {
        return -XQC_EPARAM;
    }

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
    xqc_int_t ret = xqc_id_hash_add(session->pending_unistreams, e);
    if (ret != XQC_OK) {
        xqc_free(ps);
    }
    return ret;
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

xqc_int_t
xqc_wt_session_flow_error(xqc_wt_session_t *session)
{
    static const char reason[] = "flow control error";
    if (session == NULL) {
        return -XQC_EPARAM;
    }
    xqc_wt_session_close_with_error(session, XQC_WT_ERROR_FLOW_CONTROL,
        reason, sizeof(reason) - 1);
    return -XQC_EPROTO;
}

static xqc_int_t
xqc_wt_session_send_flow_capsule(xqc_wt_session_t *session,
    uint64_t capsule_type, uint64_t value)
{
    if (session == NULL || session->h3_request == NULL
        || session->terminated)
    {
        return -XQC_ESTATE;
    }

    uint8_t capsule_buf[32];
    size_t capsule_len = xqc_wt_encode_flow_control_capsule(capsule_type,
        value, capsule_buf, sizeof(capsule_buf));
    if (capsule_len == 0) {
        return -XQC_ELIMIT;
    }

    ssize_t sent = xqc_h3_request_send_body(session->h3_request,
        capsule_buf, capsule_len, 0);
    return sent < 0 ? (xqc_int_t)sent : XQC_OK;
}

static xqc_int_t
xqc_wt_session_send_max_streams(xqc_wt_session_t *session, xqc_bool_t is_bidi)
{
    return xqc_wt_session_send_flow_capsule(session,
        is_bidi ? XQC_WT_CAPSULE_MAX_STREAMS_BIDI
                : XQC_WT_CAPSULE_MAX_STREAMS_UNI,
        is_bidi ? session->local_max_streams_bidi
                : session->local_max_streams_uni);
}

static xqc_int_t
xqc_wt_session_send_max_data(xqc_wt_session_t *session)
{
    return xqc_wt_session_send_flow_capsule(session,
        XQC_WT_CAPSULE_MAX_DATA, session->local_max_data);
}

static xqc_int_t
xqc_wt_session_maybe_extend_local_streams(xqc_wt_session_t *session,
    xqc_bool_t is_bidi)
{
    uint64_t count = is_bidi ? session->recv_streams_bidi
                             : session->recv_streams_uni;
    uint64_t *limit = is_bidi ? &session->local_max_streams_bidi
                              : &session->local_max_streams_uni;
    uint64_t window = is_bidi ? session->local_streams_bidi_window
                              : session->local_streams_uni_window;
    if (window == 0) {
        window = XQC_WT_DEFAULT_STREAMS_WINDOW;
    }
    if (*limit == 0 || count < (*limit + 1) / 2) {
        return XQC_OK;
    }
    if (*limit > UINT64_MAX - window) {
        return xqc_wt_session_flow_error(session);
    }
    *limit += window;
    return xqc_wt_session_send_max_streams(session, is_bidi);
}

static xqc_int_t
xqc_wt_session_maybe_extend_local_data(xqc_wt_session_t *session)
{
    uint64_t window = session->local_data_window
        ? session->local_data_window : XQC_WT_DEFAULT_DATA_WINDOW;
    if (session->local_max_data == 0
        || session->recv_data < (session->local_max_data + 1) / 2)
    {
        return XQC_OK;
    }
    if (session->local_max_data > UINT64_MAX - window) {
        return xqc_wt_session_flow_error(session);
    }
    session->local_max_data += window;
    return xqc_wt_session_send_max_data(session);
}

xqc_int_t
xqc_wt_session_mark_established(xqc_wt_session_t *session)
{
    if (session == NULL) {
        return -XQC_EPARAM;
    }
    if (session->terminated) {
        return -XQC_ESTATE;
    }
    if (session->wt_conn && session->wt_conn->h3_conn) {
        xqc_h3_conn_settings_t *local =
            &session->wt_conn->h3_conn->local_h3_conn_settings;
        xqc_h3_conn_settings_t *peer =
            &session->wt_conn->h3_conn->peer_h3_conn_settings;
        session->local_max_streams_uni = local->wt_initial_max_streams_uni;
        session->local_max_streams_bidi = local->wt_initial_max_streams_bidi;
        session->local_max_data = local->wt_initial_max_data;
        if (peer->wt_initial_max_streams_uni_present) {
            session->peer_max_streams_uni = peer->wt_initial_max_streams_uni;
        }
        if (peer->wt_initial_max_streams_bidi_present) {
            session->peer_max_streams_bidi = peer->wt_initial_max_streams_bidi;
        }
        if (peer->wt_initial_max_data_present) {
            session->peer_max_data = peer->wt_initial_max_data;
        }
        xqc_bool_t local_has_wt_flow =
            xqc_wt_local_settings_has_nonzero_flow(local);
        xqc_bool_t peer_has_wt_flow =
            xqc_wt_peer_settings_has_nonzero_flow(peer);
        session->flow_control_enabled =
            local->webtransport_mode == XQC_WT_MODE_BROWSER_LEGACY
                ? XQC_FALSE : (local_has_wt_flow && peer_has_wt_flow);
    }
    session->established = XQC_TRUE;
    return XQC_OK;
}

static void
xqc_wt_session_abort_associated_streams(xqc_wt_session_t *session)
{
    if (session == NULL || session->pending_unistreams == NULL) {
        return;
    }

    for (int i = 0; i < session->pending_unistreams->count; i++) {
        xqc_id_hash_node_t *node = session->pending_unistreams->list[i];
        while (node) {
            xqc_wt_pending_stream_t *ps =
                (xqc_wt_pending_stream_t *)node->element.value;
            if (ps && ps->type == XQC_WT_PENDING_UNISTREAM && ps->stream) {
                xqc_wt_unistream_t *uni = (xqc_wt_unistream_t *)ps->stream;
                if (uni->type == XQC_WT_STREAM_TYPE_SEND) {
                    xqc_wt_send_stream_t *send_stream = uni->stream.send_stream;
                    if (send_stream && send_stream->stream) {
                        xqc_wt_send_stream_reset_at(send_stream,
                            XQC_WT_STREAM_TYPE_UNIDIRECTIONAL,
                            uni->session_id, XQC_WT_ERROR_SESSION_GONE);
                    }
                } else if (uni->type == XQC_WT_STREAM_TYPE_RECV) {
                    xqc_wt_recv_stream_t *recv_stream = uni->stream.recv_stream;
                    xqc_connection_t *conn = recv_stream && recv_stream->stream
                        ? recv_stream->stream->stream_conn : NULL;
                    if (conn && conn->conn_state < XQC_CONN_STATE_CLOSING) {
                        xqc_write_stop_sending_to_packet(conn,
                            recv_stream->stream, XQC_WT_ERROR_SESSION_GONE);
                    }
                }
            } else if (ps && ps->type == XQC_WT_PENDING_BIDISTREAM && ps->stream) {
                xqc_wt_bidistream_t *bidi = (xqc_wt_bidistream_t *)ps->stream;
                xqc_connection_t *send_conn = bidi->send_stream
                    && bidi->send_stream->stream
                    ? bidi->send_stream->stream->stream_conn : NULL;
                if (send_conn && send_conn->conn_state < XQC_CONN_STATE_CLOSING) {
                    xqc_wt_send_stream_reset_at(bidi->send_stream,
                        XQC_WT_STREAM_TYPE_BIDIRECTIONAL,
                        bidi->session_id, XQC_WT_ERROR_SESSION_GONE);
                }
                xqc_connection_t *recv_conn = bidi->recv_stream
                    && bidi->recv_stream->stream
                    ? bidi->recv_stream->stream->stream_conn : NULL;
                if (recv_conn && recv_conn->conn_state < XQC_CONN_STATE_CLOSING) {
                    xqc_write_stop_sending_to_packet(recv_conn,
                        bidi->recv_stream->stream, XQC_WT_ERROR_SESSION_GONE);
                }
            }
            node = node->next;
        }
    }
}

xqc_int_t
xqc_wt_session_mark_terminated(xqc_wt_session_t *session,
    xqc_bool_t abort_streams)
{
    if (session == NULL) {
        return -XQC_EPARAM;
    }
    if (session->terminated) {
        return XQC_OK;
    }

    session->terminated = XQC_TRUE;
    if (session->wt_conn) {
        xqc_wt_conn_mark_session_closed(session->wt_conn, session->session_id);
    }

    if (abort_streams) {
        xqc_wt_session_abort_associated_streams(session);
    }

    return XQC_OK;
}

xqc_int_t
xqc_wt_session_on_incoming_stream(xqc_wt_session_t *session, xqc_bool_t is_bidi)
{
    if (session == NULL) {
        return -XQC_EPARAM;
    }
    if (session->terminated) {
        return -XQC_ESTATE;
    }
    if (!session->flow_control_enabled) {
        return XQC_OK;
    }

    uint64_t *count = is_bidi ? &session->recv_streams_bidi
                              : &session->recv_streams_uni;
    uint64_t limit = is_bidi ? session->local_max_streams_bidi
                             : session->local_max_streams_uni;
    (*count)++;
    if (*count > limit) {
        return xqc_wt_session_flow_error(session);
    }
    return xqc_wt_session_maybe_extend_local_streams(session, is_bidi);
}

xqc_int_t
xqc_wt_session_on_incoming_data(xqc_wt_session_t *session, uint64_t data_len)
{
    if (session == NULL) {
        return -XQC_EPARAM;
    }
    if (session->terminated) {
        return -XQC_ESTATE;
    }
    if (!session->flow_control_enabled) {
        return XQC_OK;
    }
    if (data_len > UINT64_MAX - session->recv_data) {
        return xqc_wt_session_flow_error(session);
    }
    session->recv_data += data_len;
    if (session->recv_data > session->local_max_data) {
        return xqc_wt_session_flow_error(session);
    }
    return xqc_wt_session_maybe_extend_local_data(session);
}

xqc_int_t
xqc_wt_session_on_outgoing_stream(xqc_wt_session_t *session, xqc_bool_t is_bidi)
{
    xqc_wt_flow_reservation_t reservation = {0};
    xqc_int_t ret = xqc_wt_session_reserve_outgoing(session, XQC_TRUE, is_bidi, 0,
        &reservation);
    if (ret < 0) {
        return ret;
    }
    return xqc_wt_session_commit_outgoing(session, &reservation);
}

xqc_int_t
xqc_wt_session_on_outgoing_data(xqc_wt_session_t *session, uint64_t data_len)
{
    xqc_wt_flow_reservation_t reservation = {0};
    xqc_int_t ret = xqc_wt_session_reserve_outgoing(session, XQC_FALSE, XQC_TRUE,
        data_len, &reservation);
    if (ret < 0) {
        return ret;
    }
    return xqc_wt_session_commit_outgoing(session, &reservation);
}

xqc_int_t
xqc_wt_session_reserve_outgoing(xqc_wt_session_t *session,
    xqc_bool_t reserve_stream, xqc_bool_t is_bidi, uint64_t data_len,
    xqc_wt_flow_reservation_t *reservation)
{
    if (session == NULL || reservation == NULL) {
        return -XQC_EPARAM;
    }
    memset(reservation, 0, sizeof(*reservation));
    if (session->terminated || !session->established) {
        return -XQC_ESTATE;
    }
    if (!session->flow_control_enabled) {
        return XQC_OK;
    }

    if (reserve_stream) {
        uint64_t count = is_bidi ? session->sent_streams_bidi
                                 : session->sent_streams_uni;
        uint64_t reserved = is_bidi ? session->reserved_streams_bidi
                                    : session->reserved_streams_uni;
        uint64_t limit = is_bidi ? session->peer_max_streams_bidi
                                 : session->peer_max_streams_uni;
        if (count > UINT64_MAX - reserved || count + reserved >= limit) {
            xqc_wt_session_send_flow_capsule(session,
                is_bidi ? XQC_WT_CAPSULE_STREAMS_BLOCKED_BIDI
                        : XQC_WT_CAPSULE_STREAMS_BLOCKED_UNI,
                limit);
            return -XQC_ESTREAM_BLOCKED;
        }
    }

    if (session->sent_data > UINT64_MAX - session->reserved_data
        || data_len > UINT64_MAX - session->sent_data - session->reserved_data
        || session->sent_data + session->reserved_data + data_len > session->peer_max_data)
    {
        xqc_wt_session_send_flow_capsule(session,
            XQC_WT_CAPSULE_DATA_BLOCKED, session->peer_max_data);
        return -XQC_ECONN_BLOCKED;
    }

    if (reserve_stream) {
        if (is_bidi) {
            session->reserved_streams_bidi++;
            reservation->streams_bidi = 1;

        } else {
            session->reserved_streams_uni++;
            reservation->streams_uni = 1;
        }
    }

    session->reserved_data += data_len;
    reservation->data = data_len;
    return XQC_OK;
}

void
xqc_wt_session_rollback_outgoing(xqc_wt_session_t *session,
    const xqc_wt_flow_reservation_t *reservation)
{
    if (session == NULL || reservation == NULL || !session->flow_control_enabled) {
        return;
    }
    if (reservation->streams_bidi) {
        session->reserved_streams_bidi =
            session->reserved_streams_bidi >= reservation->streams_bidi
                ? session->reserved_streams_bidi - reservation->streams_bidi : 0;
    }
    if (reservation->streams_uni) {
        session->reserved_streams_uni =
            session->reserved_streams_uni >= reservation->streams_uni
                ? session->reserved_streams_uni - reservation->streams_uni : 0;
    }
    if (reservation->data) {
        session->reserved_data = session->reserved_data >= reservation->data
            ? session->reserved_data - reservation->data : 0;
    }
}

xqc_int_t
xqc_wt_session_commit_outgoing(xqc_wt_session_t *session,
    const xqc_wt_flow_reservation_t *reservation)
{
    if (session == NULL || reservation == NULL) {
        return -XQC_EPARAM;
    }
    if (!session->flow_control_enabled) {
        return XQC_OK;
    }
    if (reservation->streams_bidi > session->reserved_streams_bidi
        || reservation->streams_uni > session->reserved_streams_uni
        || reservation->data > session->reserved_data
        || reservation->streams_bidi > UINT64_MAX - session->sent_streams_bidi
        || reservation->streams_uni > UINT64_MAX - session->sent_streams_uni
        || reservation->data > UINT64_MAX - session->sent_data)
    {
        return -XQC_EPROTO;
    }
    session->reserved_streams_bidi -= reservation->streams_bidi;
    session->reserved_streams_uni -= reservation->streams_uni;
    session->reserved_data -= reservation->data;
    session->sent_streams_bidi += reservation->streams_bidi;
    session->sent_streams_uni += reservation->streams_uni;
    session->sent_data += reservation->data;
    return XQC_OK;
}

xqc_int_t
xqc_wt_session_handle_blocked_capsule(xqc_wt_session_t *session,
    uint64_t capsule_type, uint64_t value)
{
    if (session == NULL) {
        return -XQC_EPARAM;
    }
    if (!session->flow_control_enabled) {
        return XQC_OK;
    }

    if (capsule_type == XQC_WT_CAPSULE_DATA_BLOCKED) {
        uint64_t window = session->local_data_window
            ? session->local_data_window : XQC_WT_DEFAULT_DATA_WINDOW;
        if (value >= session->local_max_data) {
            if (value > UINT64_MAX - window) {
                return xqc_wt_session_flow_error(session);
            }
            session->local_max_data = value + window;
            return xqc_wt_session_send_max_data(session);
        }
        return XQC_OK;
    }

    if (capsule_type == XQC_WT_CAPSULE_STREAMS_BLOCKED_BIDI
        || capsule_type == XQC_WT_CAPSULE_STREAMS_BLOCKED_UNI)
    {
        xqc_bool_t is_bidi =
            capsule_type == XQC_WT_CAPSULE_STREAMS_BLOCKED_BIDI;
        uint64_t *limit = is_bidi ? &session->local_max_streams_bidi
                                  : &session->local_max_streams_uni;
        uint64_t window = is_bidi ? session->local_streams_bidi_window
                                  : session->local_streams_uni_window;
        if (window == 0) {
            window = XQC_WT_DEFAULT_STREAMS_WINDOW;
        }
        if (value >= *limit) {
            if (value > UINT64_MAX - window) {
                return xqc_wt_session_flow_error(session);
            }
            *limit = value + window;
            return xqc_wt_session_send_max_streams(session, is_bidi);
        }
    }

    return XQC_OK;
}

xqc_int_t
xqc_wt_session_update_peer_max_streams(xqc_wt_session_t *session,
    xqc_bool_t is_bidi, uint64_t value)
{
    if (session == NULL) {
        return -XQC_EPARAM;
    }
    if (!session->flow_control_enabled) {
        return XQC_OK;
    }
    if (value > (1ULL << 60)) {
        xqc_connection_t *conn = xqc_wt_session_get_conn(session);
        if (conn) {
            xqc_conn_close_with_error(conn, H3_DATAGRAM_ERROR);
        }
        return -XQC_EPROTO;
    }
    uint64_t *limit = is_bidi ? &session->peer_max_streams_bidi
                              : &session->peer_max_streams_uni;
    if (value < *limit) {
        return xqc_wt_session_flow_error(session);
    }
    *limit = value;
    return XQC_OK;
}

xqc_int_t
xqc_wt_session_update_peer_max_data(xqc_wt_session_t *session, uint64_t value)
{
    if (session == NULL) {
        return -XQC_EPARAM;
    }
    if (!session->flow_control_enabled) {
        return XQC_OK;
    }
    if (value < session->peer_max_data) {
        return xqc_wt_session_flow_error(session);
    }
    session->peer_max_data = value;
    return XQC_OK;
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

xqc_h3_conn_t*
xqc_wt_session_get_h3_conn(xqc_wt_session_t* wt_session)
{
    if (wt_session == NULL || wt_session->wt_conn == NULL) {
        return NULL;
    }

    return wt_session->wt_conn->h3_conn;
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
    uint8_t capsule_buf[XQC_WT_CLOSE_REASON_MAX_LEN + 16];
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
    xqc_wt_session_mark_terminated(session, XQC_TRUE);

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
xqc_wt_session_finish_connect_stream(xqc_wt_session_t *session)
{
    if (session == NULL || session->h3_request == NULL) {
        return -XQC_EPARAM;
    }

    ssize_t sent = xqc_h3_request_finish(session->h3_request);
    if (sent == -XQC_ESTREAM_RESET) {
        /* The peer may send STOP_SENDING together with its close capsule.
         * Its receive side is already closed, so failing to send our FIN is
         * an expected terminal state rather than a connection error. */
        return XQC_OK;
    }
    if (sent < 0) {
        return (xqc_int_t)sent;
    }

    return XQC_OK;
}

xqc_int_t
xqc_wt_session_receive_close_capsule(xqc_wt_session_t *session,
    uint32_t close_code, const uint8_t *reason, size_t reason_len)
{
    if (session == NULL) {
        return -XQC_EPARAM;
    }
    if (session->close_capsule_received) {
        return -H3_MESSAGE_ERROR;
    }

    char *copy = NULL;
    if (reason_len > 0 && reason != NULL) {
        copy = xqc_malloc(reason_len + 1);
        if (copy == NULL) {
            return -XQC_EMALLOC;
        }
        memcpy(copy, reason, reason_len);
        copy[reason_len] = '\0';
    }

    session->close_capsule_received = XQC_TRUE;
    session->close_error_code = close_code;

    if (copy != NULL) {
        if (session->close_reason) {
            xqc_free(session->close_reason);
        }
        session->close_reason = copy;
        session->close_reason_len = reason_len;
    }

    xqc_wt_session_mark_terminated(session, XQC_TRUE);
    return xqc_wt_session_finish_connect_stream(session);
}

xqc_int_t
xqc_wt_session_drain(xqc_wt_session_t *session)
{
    if (session == NULL) {
        return -XQC_EPARAM;
    }
    if (session->terminated || !session->established) {
        return -XQC_ESTATE;
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

uint32_t
xqc_wt_session_get_close_error_code(xqc_wt_session_t *session)
{
    return session ? session->close_error_code : 0;
}

const char *
xqc_wt_session_get_close_reason(xqc_wt_session_t *session, size_t *reason_len)
{
    if (reason_len) {
        *reason_len = session ? session->close_reason_len : 0;
    }
    return session ? session->close_reason : NULL;
}

xqc_bool_t
xqc_wt_session_is_established(xqc_wt_session_t *session)
{
    return session ? session->established : XQC_FALSE;
}

xqc_bool_t
xqc_wt_session_is_terminated(xqc_wt_session_t *session)
{
    return session ? session->terminated : XQC_FALSE;
}
