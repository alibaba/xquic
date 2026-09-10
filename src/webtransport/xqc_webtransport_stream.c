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
#include "src/webtransport/xqc_webtransport_conn.h"
#include "src/webtransport/xqc_webtransport_defs.h"
#include "src/webtransport/xqc_webtransport_session.h"
#include "xquic/xqc_webtransport.h"
#include "src/webtransport/xqc_webtransport_wire.h"

xqc_log_t wt_log;

xqc_wt_stream_map_t *
xqc_wt_stream_map_init()
{
    int DEFAULT_BUCKET_SIZE = 10;

    xqc_id_hash_table_t *FuncMap = xqc_calloc(1, sizeof(xqc_id_hash_table_t));
    xqc_id_hash_init(FuncMap, xqc_default_allocator, DEFAULT_BUCKET_SIZE);
    if (FuncMap == NULL) {
        printf("xqc_wt_stream_map_init failed\n");
        xqc_log(&wt_log, XQC_LOG_ERROR,
            "xqc_wt_stream_map FuncMap init failed\n");
        return NULL;
    }
    xqc_wt_stream_map_t *stream_map = xqc_malloc(sizeof(xqc_wt_stream_map_t));
    if (!stream_map) {
        printf("xqc_wt_stream_map_init failed\n");
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
    for (int idx = 0; idx < stream_map->FuncMap->count; idx++) {
        xqc_id_hash_node_t     *node = stream_map->FuncMap->list[idx];
        wt_stream_close_func_pt close_func =
            (wt_stream_close_func_pt)node->element.value;
        close_func();
    }
    xqc_id_hash_release(stream_map->FuncMap);
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
        xqc_log(&wt_log, XQC_LOG_ERROR,
            "xqc_wt_create_send_stream conn is NULL\n");
        return NULL;
    }


    xqc_connection_t *conn =
        xqc_h3_conn_get_xqc_conn(session->wt_conn->h3_conn);
    if (conn == NULL) {
        // xqc_log
        // xqc_send_stream_close
        return NULL;
    }
    xqc_stream_t *stream =
        xqc_stream_create_with_direction(conn, XQC_STREAM_UNI, NULL);
    if (stream == NULL) {
        // xqc_log
        // xqc_send_stream_close
        return NULL;
    }
    xqc_wt_send_stream_t *wt_stream =
        (xqc_wt_send_stream_t *)xqc_malloc(sizeof(xqc_wt_send_stream_t));
    wt_stream->stream = stream;
    wt_stream->send_header_flag = XQC_FALSE;
    wt_stream->close_func = NULL;
    wt_stream->close_func = close_func;
    return wt_stream;
}

xqc_wt_recv_stream_t *
xqc_wt_create_recv_stream_passive(xqc_h3_stream_t *h3_stream,
    wt_stream_close_func_pt                        close_func)
{
    if (h3_stream == NULL) {
        xqc_log(&wt_log, XQC_LOG_ERROR,
            "xqc_wt_create_recv_stream conn is NULL\n");
        return NULL;
    }
    xqc_wt_recv_stream_t *wt_stream =
        (xqc_wt_recv_stream_t *)xqc_malloc(sizeof(xqc_wt_recv_stream_t));

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
        xqc_log(&wt_log, XQC_LOG_ERROR,
            "xqc_wt_create_recv_stream conn is NULL\n");
        return NULL;
    }
    xqc_wt_recv_stream_t *wt_stream =
        (xqc_wt_recv_stream_t *)xqc_malloc(sizeof(xqc_wt_recv_stream_t));
    xqc_connection_t *conn = xqc_h3_conn_get_xqc_conn(h3_stream->h3c);
    wt_stream->stream =
        xqc_stream_create_with_direction(conn, XQC_STREAM_UNI, NULL);
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
    xqc_connection_t *conn =
        xqc_h3_conn_get_xqc_conn(session->wt_conn->h3_conn);
    wt_unistream->conn = conn;
    wt_unistream->close_func = close_func;
    wt_unistream->packet_parsed_flag = XQC_FALSE;

    wt_unistream->type = unistream_type;
    if (wt_unistream->type == XQC_WT_STREAM_TYPE_SEND) {
        wt_unistream->stream.send_stream =
            xqc_wt_create_send_stream(session, close_func);
        // assert(wt_unistream->stream.send_stream != NULL);
        wt_unistream->fin.send_fin = XQC_FALSE;
    } else if (wt_unistream->type == XQC_WT_STREAM_TYPE_RECV) {
        wt_unistream->stream.recv_stream =
            xqc_wt_create_recv_stream_passive(h3_stream, close_func);
        wt_unistream->fin.recv_fin = XQC_FALSE;
    } else {   // when getting invalid parameter , close the stream
        xqc_wt_unistream_close(wt_unistream);
        // xqc_log
        return NULL;
    }

    wt_unistream->sessionID = session->sessionID;

    return wt_unistream;
}

xqc_int_t
xqc_wt_unistream_close(xqc_wt_unistream_t *wt_stream)
{
    if (wt_stream->type == XQC_WT_STREAM_TYPE_SEND) {
        xqc_wt_send_stream_t *send_stream = wt_stream->stream.send_stream;
        if (send_stream->stream) xqc_destroy_stream(send_stream->stream);
        wt_stream->fin.send_fin = XQC_FALSE;
        if (wt_stream->close_func) wt_stream->close_func();
    } else if (wt_stream->type == XQC_WT_STREAM_TYPE_RECV) {
        xqc_wt_recv_stream_t *recv_stream = wt_stream->stream.recv_stream;
        if (recv_stream->stream) xqc_destroy_stream(recv_stream->stream);
        wt_stream->fin.recv_fin = XQC_FALSE;
        if (wt_stream->close_func) wt_stream->close_func();
    }
    xqc_free(wt_stream);
    wt_stream = NULL;
    return XQC_OK;
}

xqc_int_t
xqc_wt_unistream_send(xqc_wt_unistream_t *wt_unistream, void *data,
    uint32_t len, int fin)
{
    if (wt_unistream->stream.send_stream == NULL) {
        return XQC_ERROR;
    }
    xqc_wt_send_stream_t *send_stream = wt_unistream->stream.send_stream;

    uint8_t   *send_data   = NULL;
    xqc_bool_t origin_data = XQC_FALSE;
    if (send_stream->send_header_flag == XQC_FALSE) {
        uint8_t header_buf[16];
        uint8_t *p     = header_buf;
        size_t   left  = sizeof(header_buf);

        size_t n = xqc_put_varint_len(XQC_WT_STREAM_TYPE_UNIDIRECTIONAL);
        if (n == 0 || n > left) {
            return XQC_ERROR;
        }
        (void)xqc_put_varint(p, XQC_WT_STREAM_TYPE_UNIDIRECTIONAL);
        p    += n;
        left -= n;

        n = xqc_wt_encode_session_id(wt_unistream->sessionID, p, left);
        if (n == 0) {
            return XQC_ERROR;
        }
        p    += n;

        size_t header_len = (size_t)(p - header_buf);

        send_data = xqc_calloc(len + header_len, sizeof(uint8_t));
        if (send_data == NULL) {
            return XQC_ERROR;
        }
        memcpy(send_data, header_buf, header_len);
        memcpy(send_data + header_len, data, len);
        len += header_len;
        send_stream->send_header_flag = XQC_TRUE;
    } else {
        send_data   = data;
        origin_data = XQC_TRUE;
    }

    int     offset = 0;
    ssize_t ret = 0;
    while (offset < len) {
        ret = xqc_stream_send(send_stream->stream, send_data + offset,
            len - offset, fin);
        if (ret < 0) {
            if (origin_data == XQC_FALSE) xqc_free(send_data);
            if (ret == -XQC_EAGAIN) {
                return 0;
            } else {
                return ret;
            }
        }

        offset += ret;
    }
    if (fin == 1) wt_unistream->fin.send_fin = XQC_TRUE;
    if (origin_data == XQC_FALSE) xqc_free(send_data);
    return ret;
}

// xqc_wt_bidistream

xqc_wt_bidistream_t *
xqc_wt_create_bidistream(xqc_h3_stream_t *h3_stream, xqc_wt_session_t *session,
    wt_stream_close_func_pt send_close_func,
    wt_stream_close_func_pt recv_close_func, xqc_bool_t passive_created)
{
    xqc_wt_bidistream_t *wt_bidistream =
        (xqc_wt_bidistream_t *)xqc_malloc(sizeof(xqc_wt_bidistream_t));

    wt_bidistream->recv_stream_close_func = recv_close_func;
    wt_bidistream->send_stream_close_func = send_close_func;
    if (session == NULL) {
        // xqc_log
        return NULL;
    }
    if (h3_stream == NULL) {
        // xqc_log
        return NULL;
    }

    wt_bidistream->h3_stream = h3_stream;
    wt_bidistream->send_stream =
        xqc_wt_create_send_stream(session, send_close_func);

    if (passive_created) {
        wt_bidistream->recv_stream =
            xqc_wt_create_recv_stream_passive(h3_stream, recv_close_func);
        wt_bidistream->packet_parsed_flag = XQC_TRUE;
    } else {
        wt_bidistream->recv_stream =
            xqc_wt_create_recv_stream_active(h3_stream, recv_close_func);
        wt_bidistream->packet_parsed_flag = XQC_FALSE;
    }
    wt_bidistream->send_fin = XQC_FALSE;
    wt_bidistream->recv_fin = XQC_FALSE;
    wt_bidistream->packet_parsed_flag = XQC_FALSE;
    wt_bidistream->sessionID = session->sessionID;

    return wt_bidistream;
}

xqc_h3_stream_t *
xqc_wt_bidistream_get_h3_stream(xqc_wt_bidistream_t *wt_bidistream)
{
    return wt_bidistream->h3_stream;
}

xqc_int_t
xqc_wt_bidistream_send(xqc_wt_bidistream_t *wt_stream, void *data, uint32_t len,
    int fin)
{

    xqc_bool_t origin_data = XQC_FALSE;
    uint8_t   *send_data   = NULL;

    if (!wt_stream->packet_parsed_flag) {
        uint8_t header_buf[16];
        uint8_t *p    = header_buf;
        size_t   left = sizeof(header_buf);

        size_t n = xqc_put_varint_len(XQC_WT_STREAM_TYPE_BIDIRECTIONAL);
        if (n == 0 || n > left) {
            return XQC_ERROR;
        }
        (void)xqc_put_varint(p, XQC_WT_STREAM_TYPE_BIDIRECTIONAL);
        p    += n;
        left -= n;

        n = xqc_wt_encode_session_id(wt_stream->sessionID, p, left);
        if (n == 0) {
            return XQC_ERROR;
        }
        p += n;

        size_t header_len = (size_t)(p - header_buf);

        send_data = xqc_calloc(len + header_len, sizeof(uint8_t));
        if (send_data == NULL) {
            return XQC_ERROR;
        }
        memcpy(send_data, header_buf, header_len);
        memcpy(send_data + header_len, data, len);
        len += header_len;
        wt_stream->packet_parsed_flag = XQC_TRUE;
    } else {
        origin_data = XQC_TRUE;
        send_data   = data;
    }

    int     offset = 0;
    ssize_t ret = 0;
    while (offset < len) {
        ret = xqc_stream_send(wt_stream->h3_stream->stream, send_data + offset,
            len - offset, fin);
        if (ret < 0) {
            if (origin_data == XQC_FALSE) xqc_free(send_data);
            if (ret == -XQC_EAGAIN) {
                return 0;
            } else {
                return ret;
            }
        }

        offset += ret;
    }
    if (fin == 1) wt_stream->send_fin = XQC_TRUE;
    if (origin_data == XQC_FALSE) xqc_free(send_data);
    return ret;
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
xqc_wt_unistream_set_sessionID(xqc_wt_unistream_t *wt_stream,
    uint64_t                                       sessionID)
{
    wt_stream->sessionID = sessionID;
}

uint64_t
xqc_wt_unistream_get_sessionID(xqc_wt_unistream_t *wt_stream)
{
    return wt_stream->sessionID;
}

uint64_t
xqc_wt_bidistream_get_sessionID(xqc_wt_bidistream_t *wt_stream)
{
    return wt_stream->sessionID;
}
