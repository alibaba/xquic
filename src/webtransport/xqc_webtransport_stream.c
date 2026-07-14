/**
 * xqc_webtransport_stream.c
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */
#include "xqc_webtransport_stream.h"
#include "src/common/utils/var_buf/xqc_var_buf.h"
#include "src/common/xqc_id_hash.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_packet_out.h"
#include "src/webtransport/xqc_webtransport_conn.h"
#include "src/webtransport/xqc_webtransport_defs.h"
#include "src/webtransport/xqc_webtransport_session.h"
#include "xquic/xqc_webtransport.h"
#include "src/webtransport/xqc_webtransport_wire.h"

/* removed: global uninitialized wt_log was UB. Use conn/session log instead. */

xqc_wt_stream_map_t *
xqc_wt_stream_map_init(void)
{
    int DEFAULT_BUCKET_SIZE = 10;

    xqc_id_hash_table_t *FuncMap = xqc_calloc(1, sizeof(xqc_id_hash_table_t));
    if (FuncMap == NULL) {
        return NULL;
    }
    xqc_id_hash_init(FuncMap, xqc_default_allocator, DEFAULT_BUCKET_SIZE);

    xqc_wt_stream_map_t *stream_map = xqc_malloc(sizeof(xqc_wt_stream_map_t));
    if (stream_map == NULL) {
        xqc_id_hash_release(FuncMap);
        xqc_free(FuncMap);
        return NULL;
    }

    stream_map->FuncMap = FuncMap;
    return stream_map;
}

wt_stream_close_func_pt
xqc_wt_stream_map_find_by_stream_id(xqc_wt_stream_map_t *stream_map,
    xqc_stream_id_t                                      stream_id)
{
    wt_stream_close_func_pt close_func =
        (wt_stream_close_func_pt)xqc_id_hash_find(stream_map->FuncMap,
            stream_id);
    return close_func;
}

void
xqc_wt_stream_map_addstream(xqc_wt_stream_map_t *stream_map,
    xqc_stream_id_t stream_id, wt_stream_close_func_pt close_func)
{
    xqc_id_hash_element_t element = {stream_id, close_func};
    xqc_id_hash_add(stream_map->FuncMap, element);
    // printf("xqc stream map add stream success!\n") ;
}

void
xqc_wt_stream_map_removestream(xqc_wt_stream_map_t *stream_map,
    xqc_stream_id_t                                 stream_id)
{
    xqc_id_hash_delete(stream_map->FuncMap, stream_id);
}

void
xqc_wt_stream_map_closeSession(xqc_wt_stream_map_t *stream_map)
{
    if (stream_map == NULL || stream_map->FuncMap == NULL) {
        return;
    }
    /* iterate all buckets in the hash table */
    for (int idx = 0; idx < stream_map->FuncMap->count; idx++) {
        xqc_id_hash_node_t *node = stream_map->FuncMap->list[idx];
        while (node != NULL) {
            wt_stream_close_func_pt close_func =
                (wt_stream_close_func_pt)node->element.value;
            if (close_func) {
                close_func();
            }
            node = node->next;
        }
    }
    xqc_id_hash_release(stream_map->FuncMap);
    xqc_free(stream_map->FuncMap);
    xqc_free(stream_map);
}

uint64_t
xqc_wt_send_stream_getid(xqc_wt_send_stream_t *wt_stream)
{
    if (wt_stream == NULL || wt_stream->stream == NULL) {
        return 0;
    }
    return wt_stream->stream->stream_id;
}

xqc_wt_send_stream_t *
xqc_wt_create_send_stream(xqc_wt_session_t *session,
    wt_stream_close_func_pt                 close_func)
{
    if (session == NULL) {
        /* session is NULL */
        return NULL;
    }


    xqc_connection_t *conn =
        xqc_h3_conn_get_xqc_conn(session->wt_conn->h3_conn);
    if (conn == NULL) {
        // xqc_log
        // xqc_send_stream_close
        return NULL;
    }
    // 注意下列语句在创建conn超过限制的时候内部会报错
    xqc_stream_t *stream =
        xqc_stream_create_with_direction(conn, XQC_STREAM_UNI, NULL);
    if (stream == NULL) {
        // xqc_log
        // xqc_send_stream_close
        return NULL;
    }
    xqc_wt_send_stream_t *wt_stream =
        (xqc_wt_send_stream_t *)xqc_malloc(sizeof(xqc_wt_send_stream_t));
    if (wt_stream == NULL) {
        xqc_stream_close(stream);
        return NULL;
    }
    memset(wt_stream, 0, sizeof(xqc_wt_send_stream_t));
    wt_stream->stream = stream;
    wt_stream->send_header_flag = XQC_FALSE;
    wt_stream->close_func = close_func;
    return wt_stream;
}

xqc_wt_recv_stream_t *
xqc_wt_create_recv_stream_passive(xqc_h3_stream_t *h3_stream,
    wt_stream_close_func_pt                        close_func)
{
    if (h3_stream == NULL) {
        /* h3_stream is NULL */
        return NULL;
    }
    xqc_wt_recv_stream_t *wt_stream =
        (xqc_wt_recv_stream_t *)xqc_malloc(sizeof(xqc_wt_recv_stream_t));
    if (wt_stream == NULL) {
        return NULL;
    }
    memset(wt_stream, 0, sizeof(xqc_wt_recv_stream_t));
    wt_stream->h3_stream = h3_stream;
    wt_stream->stream    = h3_stream->stream;
    wt_stream->close_func = close_func;
    return wt_stream;
}

xqc_wt_recv_stream_t *
xqc_wt_create_recv_stream_active(xqc_h3_stream_t *h3_stream,
    wt_stream_close_func_pt                       close_func)
{
    if (h3_stream == NULL) {
        return NULL;
    }
    xqc_wt_recv_stream_t *wt_stream =
        (xqc_wt_recv_stream_t *)xqc_malloc(sizeof(xqc_wt_recv_stream_t));
    if (wt_stream == NULL) {
        return NULL;
    }
    memset(wt_stream, 0, sizeof(xqc_wt_recv_stream_t));
    xqc_connection_t *conn = xqc_h3_conn_get_xqc_conn(h3_stream->h3c);
    if (conn == NULL) {
        xqc_free(wt_stream);
        return NULL;
    }
    wt_stream->stream =
        xqc_stream_create_with_direction(conn, XQC_STREAM_UNI, NULL);
    if (wt_stream->stream == NULL) {
        xqc_free(wt_stream);
        return NULL;
    }
    wt_stream->h3_stream = h3_stream;
    wt_stream->close_func = close_func;
    return wt_stream;
}

xqc_h3_stream_t *
xqc_wt_unistream_get_h3_stream(xqc_wt_unistream_t *wt_stream)
{
    return wt_stream->h3_stream;
}

uint64_t
xqc_wt_unistream_getid(xqc_wt_unistream_t *wt_stream)
{
    xqc_h3_stream_t *h3_stream = xqc_wt_unistream_get_h3_stream(wt_stream);
    if (h3_stream == NULL) {
        return 0;
    }
    return h3_stream->stream_id;
}

xqc_wt_unistream_t *
xqc_wt_create_unistream(xqc_wt_unistream_type_t unistream_type,
    xqc_wt_session_t *session, wt_stream_close_func_pt close_func,
    xqc_h3_stream_t *h3_stream)
{
    if (session == NULL) {
        // xqc_log
        return NULL;
    }
    if (h3_stream == NULL) {
        // xqc_log
        return NULL;
    }

    xqc_wt_unistream_t *wt_unistream =
        (xqc_wt_unistream_t *)xqc_malloc(sizeof(xqc_wt_unistream_t));
    if (wt_unistream == NULL) {
        return NULL;
    }
    memset(wt_unistream, 0, sizeof(xqc_wt_unistream_t));

    xqc_connection_t *conn =
        xqc_h3_conn_get_xqc_conn(session->wt_conn->h3_conn);
    wt_unistream->conn = conn;
    wt_unistream->close_func = close_func;
    wt_unistream->packet_parsed_flag = XQC_FALSE;

    wt_unistream->type = unistream_type;
    if (wt_unistream->type == XQC_WT_STREAM_TYPE_SEND) {
        xqc_wt_flow_reservation_t reservation = {0};
        if (xqc_wt_session_reserve_outgoing(session, XQC_TRUE, XQC_FALSE, 0,
                &reservation) < 0)
        {
            xqc_free(wt_unistream);
            return NULL;
        }
        wt_unistream->stream.send_stream =
            xqc_wt_create_send_stream(session, close_func);
        if (wt_unistream->stream.send_stream == NULL) {
            xqc_wt_session_rollback_outgoing(session, &reservation);
            xqc_free(wt_unistream);
            return NULL;
        }
        if (xqc_wt_session_commit_outgoing(session, &reservation) != XQC_OK) {
            xqc_destroy_stream(wt_unistream->stream.send_stream->stream);
            xqc_free(wt_unistream->stream.send_stream);
            xqc_free(wt_unistream);
            return NULL;
        }
        wt_unistream->fin.send_fin = XQC_FALSE;
    } else if (wt_unistream->type == XQC_WT_STREAM_TYPE_RECV) {
        wt_unistream->stream.recv_stream =
            xqc_wt_create_recv_stream_passive(h3_stream, close_func);
        wt_unistream->fin.recv_fin = XQC_FALSE;
    } else {
        xqc_free(wt_unistream);
        return NULL;
    }

    wt_unistream->session_id = session->session_id;
    wt_unistream->session = session;

    return wt_unistream;
}

xqc_int_t
xqc_wt_unistream_close(xqc_wt_unistream_t *wt_stream)
{
    if (wt_stream == NULL) {
        return -XQC_EPARAM;
    }

    /* Note: caller is responsible for removing this stream from session's
     * pending_unistreams hash table before calling close, since unistream
     * does not hold a back-reference to its session. */

    if (wt_stream->type == XQC_WT_STREAM_TYPE_SEND) {
        xqc_wt_send_stream_t *send_stream = wt_stream->stream.send_stream;
        if (send_stream && send_stream->stream) {
            xqc_destroy_stream(send_stream->stream);
        }
        if (wt_stream->close_func) wt_stream->close_func();
    } else if (wt_stream->type == XQC_WT_STREAM_TYPE_RECV) {
        xqc_wt_recv_stream_t *recv_stream = wt_stream->stream.recv_stream;
        if (recv_stream && recv_stream->stream) {
            xqc_destroy_stream(recv_stream->stream);
        }
        if (wt_stream->close_func) wt_stream->close_func();
    }
    xqc_free(wt_stream);
    return XQC_OK;
}

static xqc_int_t
xqc_wt_send_stream_prepare_header(xqc_wt_send_stream_t *send_stream,
    uint64_t stream_type, uint64_t session_id)
{
    if (send_stream == NULL) {
        return -XQC_EPARAM;
    }
    if (send_stream->send_header_flag || send_stream->send_header_len != 0) {
        return XQC_OK;
    }

    uint8_t *p = send_stream->send_header_buf;
    size_t left = sizeof(send_stream->send_header_buf);

    size_t n = xqc_put_varint_len(stream_type);
    if (n == 0 || n > left) {
        return XQC_ERROR;
    }
    xqc_put_varint(p, stream_type);
    p += n;
    left -= n;

    n = xqc_wt_encode_session_id(session_id, p, left);
    if (n == 0) {
        return XQC_ERROR;
    }
    p += n;

    send_stream->send_header_len =
        (size_t)(p - send_stream->send_header_buf);
    send_stream->send_header_sent = 0;
    return XQC_OK;
}

static ssize_t
xqc_wt_send_stream_send_with_header(xqc_wt_send_stream_t *send_stream,
    uint64_t stream_type, uint64_t session_id, void *data, uint32_t len,
    int fin, uint32_t *payload_sent, xqc_bool_t *sent_any,
    xqc_bool_t *full_write)
{
    if (send_stream == NULL || send_stream->stream == NULL) {
        return -XQC_EPARAM;
    }
    if (payload_sent) {
        *payload_sent = 0;
    }
    if (sent_any) {
        *sent_any = XQC_FALSE;
    }
    if (full_write) {
        *full_write = XQC_FALSE;
    }

    if (!send_stream->send_header_flag) {
        xqc_int_t prep_ret = xqc_wt_send_stream_prepare_header(send_stream,
            stream_type, session_id);
        if (prep_ret < 0) {
            return prep_ret;
        }
    }

    size_t header_remaining = 0;
    if (!send_stream->send_header_flag) {
        header_remaining =
            send_stream->send_header_len - send_stream->send_header_sent;
    }

    size_t total_len = header_remaining + len;
    uint8_t *send_data = data;
    xqc_bool_t allocated = XQC_FALSE;
    if (header_remaining > 0) {
        send_data = xqc_malloc(total_len ? total_len : 1);
        if (send_data == NULL) {
            return -XQC_EMALLOC;
        }
        allocated = XQC_TRUE;
        memcpy(send_data,
            send_stream->send_header_buf + send_stream->send_header_sent,
            header_remaining);
        if (len > 0 && data != NULL) {
            memcpy(send_data + header_remaining, data, len);
        }
    }

    ssize_t ret = xqc_stream_send(send_stream->stream, send_data, total_len,
        fin);
    if (allocated) {
        xqc_free(send_data);
    }
    if (ret < 0) {
        return ret;
    }

    size_t accepted_total = (size_t)ret;
    if (sent_any && accepted_total > 0) {
        *sent_any = XQC_TRUE;
    }

    size_t accepted_payload = accepted_total;
    if (header_remaining > 0) {
        size_t accepted_header = accepted_total < header_remaining
            ? accepted_total : header_remaining;
        send_stream->send_header_sent += accepted_header;
        if (send_stream->send_header_sent == send_stream->send_header_len) {
            send_stream->send_header_flag = XQC_TRUE;
            send_stream->send_header_len = 0;
            send_stream->send_header_sent = 0;
        }
        accepted_payload = accepted_total > header_remaining
            ? accepted_total - header_remaining : 0;
    }
    if (accepted_payload > len) {
        accepted_payload = len;
    }
    if (payload_sent) {
        *payload_sent = (uint32_t)accepted_payload;
    }
    if (full_write && accepted_total == total_len) {
        *full_write = XQC_TRUE;
    }
    return (ssize_t)accepted_payload;
}

static xqc_bool_t
xqc_wt_conn_can_send_abort(xqc_connection_t *conn)
{
    return conn != NULL && conn->conn_state < XQC_CONN_STATE_CLOSING;
}

xqc_int_t
xqc_wt_unistream_send(xqc_wt_unistream_t *wt_unistream, void *data,
    uint32_t len, int fin)
{
    if (wt_unistream == NULL || wt_unistream->stream.send_stream == NULL) {
        return XQC_ERROR;
    }
    xqc_wt_send_stream_t *send_stream = wt_unistream->stream.send_stream;
    uint32_t payload_len = len;
    xqc_wt_flow_reservation_t reservation = {0};
    xqc_int_t fc_ret = xqc_wt_session_reserve_outgoing(
        wt_unistream->session, XQC_FALSE, XQC_FALSE, payload_len, &reservation);
    if (fc_ret < 0) {
        return fc_ret;
    }

    uint32_t accepted_payload = 0;
    xqc_bool_t full_write = XQC_FALSE;
    ssize_t ret = xqc_wt_send_stream_send_with_header(send_stream,
        XQC_WT_STREAM_TYPE_UNIDIRECTIONAL, wt_unistream->session_id,
        data, len, fin, &accepted_payload, NULL, &full_write);
    if (ret < 0) {
        xqc_wt_session_rollback_outgoing(wt_unistream->session, &reservation);
        return ret;
    }

    if (accepted_payload < payload_len) {
        xqc_wt_flow_reservation_t rollback = {0};
        rollback.data = payload_len - accepted_payload;
        xqc_wt_session_rollback_outgoing(wt_unistream->session, &rollback);
    }
    reservation.data = accepted_payload;
    xqc_int_t commit_ret =
        xqc_wt_session_commit_outgoing(wt_unistream->session, &reservation);
    if (commit_ret < 0) {
        return commit_ret;
    }
    if (fin == 1 && full_write) wt_unistream->fin.send_fin = XQC_TRUE;
    return accepted_payload;
}

// xqc_wt_bidistream

xqc_wt_bidistream_t *
xqc_wt_create_bidistream(xqc_h3_stream_t *h3_stream, xqc_wt_session_t *session,
    wt_stream_close_func_pt send_close_func,
    wt_stream_close_func_pt recv_close_func, xqc_bool_t passive_created)
{
    if (session == NULL || h3_stream == NULL) {
        return NULL;
    }
    xqc_wt_bidistream_t *wt_bidistream =
        (xqc_wt_bidistream_t *)xqc_malloc(sizeof(xqc_wt_bidistream_t));
    if (wt_bidistream == NULL) {
        return NULL;
    }
    memset(wt_bidistream, 0, sizeof(xqc_wt_bidistream_t));

    wt_bidistream->recv_stream_close_func = recv_close_func;
    wt_bidistream->send_stream_close_func = send_close_func;
    wt_bidistream->h3_stream = h3_stream;
    wt_bidistream->send_stream =
        (xqc_wt_send_stream_t *)xqc_malloc(sizeof(xqc_wt_send_stream_t));
    if (wt_bidistream->send_stream == NULL) {
        xqc_free(wt_bidistream);
        return NULL;
    }
    memset(wt_bidistream->send_stream, 0, sizeof(xqc_wt_send_stream_t));
    wt_bidistream->send_stream->h3_stream = h3_stream;
    wt_bidistream->send_stream->stream = h3_stream->stream;
    wt_bidistream->send_stream->close_func = send_close_func;
    wt_bidistream->send_stream->send_header_flag = passive_created;

    wt_bidistream->recv_stream =
        xqc_wt_create_recv_stream_passive(h3_stream, recv_close_func);
    if (wt_bidistream->recv_stream == NULL) {
        xqc_free(wt_bidistream->send_stream);
        xqc_free(wt_bidistream);
        return NULL;
    }
    wt_bidistream->packet_parsed_flag = passive_created;
    wt_bidistream->send_fin = XQC_FALSE;
    wt_bidistream->recv_fin = XQC_FALSE;
    wt_bidistream->session_id = session->session_id;
    wt_bidistream->session = session;

    return wt_bidistream;
}

xqc_h3_stream_t *
xqc_wt_bidistream_get_h3_stream(xqc_wt_bidistream_t *wt_bidistream)
{
    return wt_bidistream->h3_stream;
}

static xqc_int_t
xqc_wt_bidistream_send_inner(xqc_wt_bidistream_t *wt_stream, void *data,
    uint32_t len, int fin, xqc_bool_t reserve_data, xqc_bool_t *sent_any,
    uint32_t *payload_sent)
{
    if (wt_stream == NULL) {
        return -XQC_EPARAM;
    }
    if (sent_any) {
        *sent_any = XQC_FALSE;
    }
    if (payload_sent) {
        *payload_sent = 0;
    }

    uint32_t payload_len = len;
    xqc_wt_flow_reservation_t reservation = {0};
    if (reserve_data) {
        xqc_int_t fc_ret = xqc_wt_session_reserve_outgoing(
            wt_stream->session, XQC_FALSE, XQC_TRUE, payload_len,
            &reservation);
        if (fc_ret < 0) {
            return fc_ret;
        }
    } else if (wt_stream->session
               && wt_stream->session->flow_control_enabled
               && payload_len > wt_stream->session->reserved_data)
    {
        return -XQC_EPROTO;
    }

    uint32_t accepted_payload = 0;
    xqc_bool_t full_write = XQC_FALSE;
    ssize_t ret = xqc_wt_send_stream_send_with_header(wt_stream->send_stream,
        XQC_WT_STREAM_TYPE_BIDIRECTIONAL, wt_stream->session_id, data, len,
        fin, &accepted_payload, sent_any, &full_write);
    if (ret < 0) {
        xqc_wt_session_rollback_outgoing(wt_stream->session, &reservation);
        return ret;
    }

    wt_stream->packet_parsed_flag = wt_stream->send_stream->send_header_flag;
    if (payload_sent) {
        *payload_sent = accepted_payload;
    }
    if (reserve_data && accepted_payload < payload_len) {
        xqc_wt_flow_reservation_t rollback = {0};
        rollback.data = payload_len - accepted_payload;
        xqc_wt_session_rollback_outgoing(wt_stream->session, &rollback);
    }
    if (reserve_data) {
        reservation.data = accepted_payload;
        xqc_int_t commit_ret =
            xqc_wt_session_commit_outgoing(wt_stream->session, &reservation);
        if (commit_ret < 0) {
            return commit_ret;
        }
    }
    if (fin == 1 && full_write) wt_stream->send_fin = XQC_TRUE;
    return accepted_payload;
}

xqc_int_t
xqc_wt_bidistream_send(xqc_wt_bidistream_t *wt_stream, void *data, uint32_t len,
    int fin)
{
    return xqc_wt_bidistream_send_inner(wt_stream, data, len, fin, XQC_TRUE,
        NULL, NULL);
}

xqc_int_t
xqc_wt_bidistream_send_reserved(xqc_wt_bidistream_t *wt_stream, void *data,
    uint32_t len, int fin, xqc_bool_t *sent_any, uint32_t *payload_sent)
{
    return xqc_wt_bidistream_send_inner(wt_stream, data, len, fin, XQC_FALSE,
        sent_any, payload_sent);
}

// for test
uint8_t
test_show_stream_type(xqc_wt_unistream_t *wt_stream)
{
    return wt_stream->type;
}

// for test
xqc_int_t
xqc_wt_unistream_set_h3_stream(xqc_wt_unistream_t *wt_stream,
    xqc_h3_stream_t                               *h3_stream)
{
    wt_stream->h3_stream = h3_stream;
    return XQC_OK;
}

// for test
void
xqc_wt_unistream_set_session_id(xqc_wt_unistream_t *wt_stream,
    uint64_t                                       session_id)
{
    wt_stream->session_id = session_id;
}

uint64_t
xqc_wt_unistream_get_session_id(xqc_wt_unistream_t *wt_stream)
{
    return wt_stream->session_id;
}

uint64_t
xqc_wt_bidistream_get_session_id(xqc_wt_bidistream_t *wt_stream)
{
    return wt_stream->session_id;
}

/* ===== Stream RESET_STREAM / STOP_SENDING (RFC 9000 §3.5, §3.3) ===== */

static uint64_t
xqc_wt_reset_final_size(xqc_wt_send_stream_t *send_stream)
{
    uint64_t final_size = send_stream->stream->stream_send_offset;
    uint64_t header_size = send_stream->send_header_flag
        ? send_stream->send_header_sent
        : send_stream->send_header_len;
    return final_size < header_size ? header_size : final_size;
}

xqc_int_t
xqc_wt_send_stream_reset_at(xqc_wt_send_stream_t *send_stream,
    uint64_t stream_type, uint64_t session_id, uint64_t h3_error_code)
{
    if (send_stream == NULL || send_stream->stream == NULL) {
        return -XQC_EPARAM;
    }

    xqc_connection_t *conn = send_stream->stream->stream_conn;
    if (!xqc_wt_conn_can_send_abort(conn)) {
        return -XQC_ESTATE;
    }

    xqc_int_t prep_ret = xqc_wt_send_stream_prepare_header(send_stream,
        stream_type, session_id);
    if (prep_ret < 0) {
        return prep_ret;
    }

    uint64_t final_size = xqc_wt_reset_final_size(send_stream);
    return xqc_write_reset_stream_at_to_packet(conn, send_stream->stream,
        h3_error_code, final_size, final_size);
}

xqc_int_t
xqc_wt_unistream_reset(xqc_wt_unistream_t *wt_stream, uint64_t error_code)
{
    if (wt_stream == NULL) {
        return -XQC_EPARAM;
    }
    if (wt_stream->type == XQC_WT_STREAM_TYPE_SEND) {
        xqc_wt_send_stream_t *send_stream = wt_stream->stream.send_stream;
        return xqc_wt_send_stream_reset_at(send_stream,
            XQC_WT_STREAM_TYPE_UNIDIRECTIONAL, wt_stream->session_id,
            xqc_wt_app_error_to_h3((uint32_t)error_code));
    }
    return -XQC_EPARAM;
}

xqc_int_t
xqc_wt_unistream_stop_sending(xqc_wt_unistream_t *wt_stream, uint64_t error_code)
{
    if (wt_stream == NULL) {
        return -XQC_EPARAM;
    }
    if (wt_stream->type == XQC_WT_STREAM_TYPE_RECV) {
        xqc_wt_recv_stream_t *recv_stream = wt_stream->stream.recv_stream;
        if (recv_stream && recv_stream->stream) {
            xqc_connection_t *conn = recv_stream->stream->stream_conn;
            if (!xqc_wt_conn_can_send_abort(conn)) {
                return -XQC_ESTATE;
            }
            return xqc_write_stop_sending_to_packet(conn, recv_stream->stream,
                xqc_wt_app_error_to_h3((uint32_t)error_code));
        }
    }
    return -XQC_EPARAM;
}

xqc_int_t
xqc_wt_bidistream_reset(xqc_wt_bidistream_t *wt_stream, uint64_t error_code)
{
    if (wt_stream == NULL) {
        return -XQC_EPARAM;
    }
    if (wt_stream->send_stream && wt_stream->send_stream->stream) {
        return xqc_wt_send_stream_reset_at(wt_stream->send_stream,
            XQC_WT_STREAM_TYPE_BIDIRECTIONAL, wt_stream->session_id,
            xqc_wt_app_error_to_h3((uint32_t)error_code));
    }
    return -XQC_EPARAM;
}

xqc_int_t
xqc_wt_bidistream_stop_sending(xqc_wt_bidistream_t *wt_stream, uint64_t error_code)
{
    if (wt_stream == NULL) {
        return -XQC_EPARAM;
    }
    if (wt_stream->recv_stream && wt_stream->recv_stream->stream) {
        xqc_connection_t *conn = wt_stream->recv_stream->stream->stream_conn;
        if (!xqc_wt_conn_can_send_abort(conn)) {
            return -XQC_ESTATE;
        }
        return xqc_write_stop_sending_to_packet(conn, wt_stream->recv_stream->stream,
            xqc_wt_app_error_to_h3((uint32_t)error_code));
    }
    return -XQC_EPARAM;
}

xqc_int_t
xqc_wt_bidistream_destroy(xqc_wt_bidistream_t *wt_stream)
{
    if (wt_stream == NULL) {
        return XQC_OK;
    }
    if (wt_stream->send_stream) {
        xqc_free(wt_stream->send_stream);
    }
    if (wt_stream->recv_stream) {
        xqc_free(wt_stream->recv_stream);
    }
    xqc_free(wt_stream);
    return XQC_OK;
}


/*
 * Free a unistream's WT wrapper memory without closing the underlying
 * QUIC stream.  Mirrors xqc_wt_bidistream_destroy().
 */
void
xqc_wt_unistream_destroy(xqc_wt_unistream_t *wt_stream)
{
    if (wt_stream == NULL) {
        return;
    }

    if (wt_stream->type == XQC_WT_STREAM_TYPE_SEND) {
        if (wt_stream->stream.send_stream) {
            xqc_free(wt_stream->stream.send_stream);
        }

    } else if (wt_stream->type == XQC_WT_STREAM_TYPE_RECV) {
        if (wt_stream->stream.recv_stream) {
            xqc_free(wt_stream->stream.recv_stream);
        }
    }

    xqc_wt_stream_buffer_list_release(&wt_stream->pending_recv);
    xqc_free(wt_stream);
}
