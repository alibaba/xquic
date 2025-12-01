/**
 * xqc_webtransport_ctx.c
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */
#include "xqc_webtransport_ctx.h"
#include "src/common/xqc_id_hash.h"
#include "src/http3/xqc_h3_request.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "xqc_webtransport_conn.h"
#include "xqc_webtransport_request.h"
#include "xqc_webtransport_session.h"
#include "xqc_webtransport_stream.h"
#include "xqc_webtransport_wire.h"
#include "xquic/xquic.h"

enum
{
    XQC_HEADER_UNISTREAM  = 0x54,
    XQC_HEADER_BIDISTREAM = 0x41,
    XQC_HEADER_UNKNOWN    = 1
};

xqc_wt_ctx_t *
xqc_wt_get_ctx_by_h3conn(xqc_h3_conn_t *h3_conn)
{
    xqc_connection_t *conn   = xqc_h3_conn_get_xqc_conn(h3_conn);
    xqc_engine_t     *engine = conn->engine;
    xqc_wt_ctx_t     *ctx    = (engine->user_data);
    return (xqc_wt_ctx_t *)ctx;
}

xqc_wt_ctx_t *
xqc_wt_get_ctx_by_conn(xqc_connection_t *conn)
{
    xqc_engine_t *engine = conn->engine;
    xqc_wt_ctx_t *wt_ctx = (engine->user_data);

    return wt_ctx;
}

void
wt_default_dgram_read_handler(xqc_connection_t *conn, void *user_data, const void *data,
    size_t data_len, uint64_t unix_ts)
{
    xqc_wt_ctx_t *wt_ctx = xqc_wt_get_ctx_by_conn(conn);
    xqc_wt_conn_t *wt_conn =
        (xqc_wt_conn_t *)xqc_conn_get_user_data(conn);

    if (!wt_ctx || !wt_conn || !wt_ctx->dgram_cbs ||
        !wt_ctx->dgram_cbs->dgram_read_notify) {
        return;
    }

    const uint8_t *buf = (const uint8_t *)data;
    size_t         len = data_len;
    uint64_t       session_id = 0;
    ssize_t        consumed   = xqc_wt_decode_session_id(buf, len, &session_id);

    xqc_wt_session_t *wt_session = NULL;
    const void       *payload    = data;
    size_t            payload_len = data_len;

    if (consumed > 0 && (size_t)consumed <= len) {
        payload     = buf + consumed;
        payload_len = len - (size_t)consumed;
        wt_session  = xqc_wt_conn_find_session(wt_conn, session_id);
    }

    if (!wt_session) {
        wt_session = wt_conn->wt_session;
    }

    wt_ctx->dgram_cbs->dgram_read_notify(wt_session, payload, payload_len,
        user_data, unix_ts);
}

void
wt_default_dgram_write_handler(xqc_connection_t *conn, void *user_data)
{
    xqc_wt_ctx_t *wt_ctx  = xqc_wt_get_ctx_by_conn(conn);
    xqc_wt_conn_t *wt_conn = (xqc_wt_conn_t *)xqc_conn_get_user_data(conn);
    if (!wt_ctx || !wt_conn || !wt_ctx->dgram_cbs ||
        !wt_ctx->dgram_cbs->dgram_write_notify) {
        return;
    }
    xqc_wt_session_t *wt_session = wt_conn->wt_session;
    if (!wt_session) {
        return;
    }
    wt_ctx->dgram_cbs->dgram_write_notify(wt_session, user_data);
}

enum WTSettingsID
{
    /* h3 settings */
    WT_SETTINGS_ENABLE_WEBTRANSPORT = 0x2b603742,
    WT_SETTINGS_DATAGRAM            = 0x33,
    WT_SETTINGS_EXTENDEDCONNECT     = 0x8,
};

int
wt_default_h3_conn_create_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *h3c_user_data)
{
    xqc_wt_conn_t *wt_conn = xqc_wt_conn_create(h3_conn);
    xqc_wt_conn_set_dgram_mss(wt_conn, XQC_WEBTRANSPORT_DEFAULT_DGRAM_MSS);
    xqc_h3_conn_set_user_data(h3_conn, wt_conn);
    xqc_conn_set_transport_user_data(xqc_h3_conn_get_xqc_conn(h3_conn), wt_conn);

    xqc_h3_conn_get_peer_addr(h3_conn, (struct sockaddr *)&wt_conn->peer_addr,
        sizeof(wt_conn->peer_addr), &wt_conn->peer_addrlen);

    memcpy(&wt_conn->cid, cid, sizeof(*cid));

    return 0;
}

int
wt_default_h3_request_create_notify(xqc_h3_request_t *h3_request, void *h3s_user_data)
{
    static int request_cnt = 0;
    request_cnt++;
    printf("request_cnt = %d\n", request_cnt);
    xqc_h3_conn_t *h3_conn       = (h3_request && h3_request->h3_stream)
        ? h3_request->h3_stream->h3c
        : NULL;
    if (h3_conn == NULL) {
        return XQC_ERROR;
    }
    xqc_wt_request_t *wt_request = xqc_wt_request_create(h3_conn->log);
    if (wt_request == NULL) {
        return XQC_ERROR;
    }
    wt_request->h3_request       = h3_request;
    wt_request->is_header_recv   = XQC_FALSE;

    xqc_wt_conn_t *wt_conn = (xqc_wt_conn_t *)(xqc_h3_conn_get_user_data(h3_conn));
    wt_request->wt_conn    = wt_conn;

    xqc_stream_id_t h3_stream_id = h3_request->h3_stream
        ? h3_request->h3_stream->stream_id
        : 0;
    xqc_wt_session_t *wt_session =
        xqc_wt_session_init(h3_stream_id, wt_conn, h3_request->h3_stream);

    wt_request->user_data = (void *)wt_session;
    xqc_h3_request_set_user_data(h3_request, wt_request);

    return 0;
}

int
check_str_equal(const char *str1, const char *str2)
{
    if (str1 == NULL || str2 == NULL) {
        return 0;
    }
    return strcmp(str1, str2) == 0;
}

int
xqc_wt_process_request_headers(xqc_wt_request_t *wt_request, xqc_wt_ctx_t *wt_ctx,
    xqc_http_headers_t *headers)
{
    char *path = xqc_wt_request_table_find(wt_request, ":path");
    if (path == NULL) {
        return XQC_ERROR;
    }

    xqc_h3_stream_t  *h3_stream = wt_request->h3_request
        ? wt_request->h3_request->h3_stream
        : NULL;
    xqc_wt_session_t *session   = (xqc_wt_session_t *)(wt_request->user_data);
    // wt_request->user_data = (void*)session;
    if (wt_ctx->session_cbs && wt_ctx->session_cbs->webtransport_session_create_notify) {
        return wt_ctx->session_cbs->webtransport_session_create_notify(session, headers, 0, NULL);
        // TODO modify later
    }
    return XQC_OK;
}

int
wt_default_h3_request_read_notify(xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag,
    void *strm_user_data)
{
    printf("wt_svr_h3_request_read_notify\n");
    unsigned char     fin        = 0;
    xqc_wt_request_t *wt_request = (xqc_wt_request_t *)strm_user_data;

    xqc_wt_ctx_t    *wt_ctx    = NULL;
    xqc_h3_stream_t *h3_stream = h3_request ? h3_request->h3_stream : NULL;

    if (h3_stream == NULL) {
        return XQC_ERROR;
    }

    wt_ctx = xqc_wt_get_ctx_by_h3conn(h3_stream->h3c);

    // assert(wt_ctx != NULL);

    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        xqc_http_headers_t *headers = xqc_h3_request_recv_headers(h3_request, &fin);
        if (headers == NULL) {
            return XQC_ERROR;
        }
        for (int i = 0; i < headers->count; i++) {
            char *name  = (char *)headers->headers[i].name.iov_base;
            char *value = (char *)headers->headers[i].value.iov_base;
            printf("header name = %s, value = %s\n", name, value);
            if (check_str_equal(name, ":path")) {
                // to process "?"
                // like "127.0.0.1/publish?stream_id=1"
                if (xqc_wt_request_table_find(wt_request, ":path") == NULL)
                    xqc_wt_request_table_insert(wt_request, name, value);
            }
            xqc_wt_request_table_insert(wt_request, name, value);
            // log
        }

        char *request_name = xqc_wt_request_table_find(wt_request, ":method");
        if (request_name == NULL || !check_str_equal(request_name, "CONNECT")) {
            return XQC_ERROR;
        }

        request_name = xqc_wt_request_table_find(wt_request, ":protocol");
        if (request_name == NULL || !check_str_equal(request_name, "webtransport")) {
            return XQC_ERROR;
        }

        request_name = xqc_wt_request_table_find(wt_request, "sec-webtransport-http3-draft02");
        if (request_name && !check_str_equal(request_name, "1")) {
            return XQC_ERROR;
        }

        char              response_header_buf[10][32];
        xqc_http_header_t response_header_status_protocol[] = {
            {
                .name  = {.iov_base = (void *)":status", .iov_len = 7},
                .value = {.iov_base = (void *)"200", .iov_len = 3},
                .flags = 0,
            },
        };

        xqc_http_headers_t response_headers = {
            .headers = response_header_status_protocol,
            .count   = 1,
        };

        char *path = xqc_wt_request_table_find(wt_request, ":path");

        if (wt_request->header_sent == 0) {
            if (wt_ctx->session_cbs &&
                wt_ctx->session_cbs->webtransport_will_create_session_notify) {
                int ret = wt_ctx->session_cbs->webtransport_will_create_session_notify(headers,
                    &response_headers);
                if (ret != 1) {
                    // TODO send 403/404 headers
                    return XQC_ERROR;
                }
            }
            ssize_t ret = xqc_h3_request_send_headers(h3_request, &response_headers, 0);
            if (ret < 0) {
                printf("xqc_h3_request_send_headers error %zd\n", ret);
                return ret;
            } else {
                printf("xqc_h3_request_send_headers success size=%zd\n", ret);
                wt_request->header_sent = 1;
            }
            return xqc_wt_process_request_headers(wt_request, wt_ctx, headers);
        }
    } else if (flag & XQC_REQ_NOTIFY_READ_BODY) {
        char    buff[4096] = {0};
        size_t  buff_size  = 4096;
        ssize_t read       = 0;
        ssize_t read_sum   = 0;
        do {
            read = xqc_h3_request_recv_body(h3_request, (unsigned char *)buff, buff_size, &fin);
            if (read == -XQC_EAGAIN) {
                break;
            } else if (read < 0) {
                printf("xqc_h3_request_recv_body error %zd\n", read);
                return 0;
            }

            read_sum += read;
            wt_request->recv_body_len += read;
        } while (read > 0 && !fin);

        printf("xqc_h3_request_recv_body read:%zd, offset:%zu, fin:%d\n", read_sum,
            wt_request->recv_body_len, fin);
        return XQC_OK;
    }

    return XQC_OK;
}

int
wt_default_h3_request_close_notify(xqc_h3_request_t *h3_request, void *strm_user_data)
{
        xqc_wt_request_t *wt_request = (xqc_wt_request_t *)strm_user_data;

    xqc_h3_stream_t *h3_stream = h3_request ? h3_request->h3_stream : NULL;
    xqc_h3_conn_t   *h3_conn   = h3_stream->h3c;
    xqc_wt_ctx_t    *wt_ctx    = NULL;
    wt_ctx                     = xqc_wt_get_ctx_by_h3conn(h3_conn);

    xqc_wt_session_t *session = (xqc_wt_session_t *)wt_request->user_data;
    if (wt_ctx->session_cbs->webtransport_session_close_notify) {
        wt_ctx->session_cbs->webtransport_session_close_notify(session, NULL, 0, NULL);
    }

    xqc_wt_session_close(session);

    xqc_wt_request_destroy(wt_request);

    return 0;
}

int
wt_default_h3_conn_close_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *h3c_user_data)
{
    xqc_wt_ctx_t *wt_ctx = NULL;
    wt_ctx               = xqc_wt_get_ctx_by_h3conn(h3_conn);

    // TODO: close related webtransport resources if needed
    (void)wt_ctx;
    (void)cid;
    (void)h3c_user_data;
    return 0;
}

int
wt_default_h3_frame_paser_notify(int frame_type, xqc_h3_conn_t *h3_conn, xqc_h3_stream_t *h3_stream,
    const unsigned char *pos, size_t sz, int *ret, int *fin)
{
    // 这边的双向流只处理了建立连接时候的双向流 (request)
    printf("h3_custom_frame_parse = %d\n", frame_type);
    if (frame_type == 1) {
        return 0;
    }
    if (frame_type == 0x41) {
        return 0;
    }
    return 1;
}

int
wt_default_unknown_unistream_notify(int stream_type, xqc_h3_conn_t *h3_conn,
    xqc_h3_stream_t *h3_stream, int *ret)
{
    if (stream_type != XQC_HEADER_UNISTREAM) {
        return 0;
    }
    // add unistream
    xqc_wt_conn_t *wt_conn       = (xqc_wt_conn_t *)(xqc_h3_conn_get_user_data(h3_conn));
    xqc_wt_ctx_t  *wt_ctx        = NULL;
    wt_ctx                       = xqc_wt_get_ctx_by_h3conn(h3_conn);
    xqc_wt_session_t *wt_session = wt_conn->wt_session;
    // create recv unistream
    xqc_wt_unistream_t *wt_unistream =
        xqc_wt_create_unistream(XQC_WT_STREAM_TYPE_RECV, wt_session, NULL, h3_stream);

    xqc_wt_session_add_pendingstream(wt_session, h3_stream, wt_unistream);

    // xqc_wt_unistream_set_sessionID(wt_unistream, sessionID);

    if (wt_ctx->stream_cbs->wt_unistream_create_notify) {
        wt_ctx->stream_cbs->wt_unistream_create_notify(wt_unistream, wt_session,
            xqc_h3_conn_get_user_data(h3_conn));
    }
    *ret = 0;

    return 1;
}

int
wt_default_unknown_unistream_recvdata_notify(xqc_h3_conn_t *h3_conn, xqc_h3_stream_t *h3_stream,
    uint8_t *data, size_t size, int *ret)
{
    xqc_wt_conn_t    *wt_conn    = (xqc_wt_conn_t *)(xqc_h3_conn_get_user_data(h3_conn));
    xqc_wt_session_t *wt_session = wt_conn->wt_session;
    xqc_wt_ctx_t     *wt_ctx     = NULL;
    wt_ctx                       = xqc_wt_get_ctx_by_h3conn(h3_conn);
    // 通过h3 去找对应的stream

    void *ele = xqc_wt_session_pending_stream_find(wt_session, h3_stream);
    if (ele == NULL) {
        // TODO xqc_log
        return XQC_ERROR;
    }
    xqc_wt_unistream_t *wt_unistream = (xqc_wt_unistream_t *)(ele);

    int      nread      = 0;
    uint64_t session_id = wt_unistream->sessionID;
    if (wt_unistream->packet_parsed_flag == XQC_FALSE) {
        ssize_t consumed = xqc_wt_decode_session_id(data, size, &session_id);
        if (consumed < 0) {
            if (ret) {
                *ret = -XQC_H3_DECODE_ERROR;
                return 1;
            }
        } else {
            nread = (int)consumed;
        }

        wt_unistream->packet_parsed_flag = XQC_TRUE;
    }
    wt_unistream->sessionID = session_id;

    wt_session = xqc_wt_conn_find_session(wt_conn, session_id);
    if (wt_session == NULL) {
        wt_session = wt_conn->wt_session;
    }

    if (wt_session == NULL) {
        return 0;
    }

    if (size > (size_t)nread) {
        int processed = 0, result = 1;
        if (wt_ctx->stream_cbs && wt_ctx->stream_cbs->wt_unistream_read_notify) {
            void *strm_data = NULL;
            wt_ctx->stream_cbs->wt_unistream_read_notify(
                wt_unistream, wt_session, data + nread, size - nread, &processed);
        } else {
            result = 1;
        }

        processed = (int)(size - nread);
        if (result && processed > 0) {
            nread += processed;
        }
    }

    if (ret) {
        *ret = nread;
        return 1;
    }
    return 0;
}

int
wt_default_unknown_bidistream_notify(int stream_type, xqc_h3_conn_t *h3_conn,
    xqc_h3_stream_t *h3_stream, int *ret)
{
    int config_frame = 0;

    xqc_wt_conn_t *wt_conn       = (xqc_wt_conn_t *)(xqc_h3_conn_get_user_data(h3_conn));
    xqc_wt_ctx_t  *wt_ctx        = NULL;
    wt_ctx                       = xqc_wt_get_ctx_by_h3conn(h3_conn);
    xqc_wt_session_t *wt_session = wt_conn->wt_session;

    if (wt_conn->bidistream_first_connect == XQC_FALSE) {
        wt_conn->bidistream_first_connect = XQC_TRUE;
        config_frame                      = 1;
    }

    if (config_frame) {
        return config_frame;
    }

    xqc_wt_bidistream_t *wt_bidistream =
        xqc_wt_create_bidistream(h3_stream, wt_session, NULL, NULL, XQC_TRUE);

    xqc_wt_session_add_pendingstream(wt_session, h3_stream, wt_bidistream);

    if (wt_ctx->stream_cbs->wt_bidistream_create_notify) {
        wt_ctx->stream_cbs->wt_bidistream_create_notify(wt_bidistream, wt_session,
            xqc_h3_conn_get_user_data(h3_conn));
    }
    return config_frame;
}

int
wt_default_unknown_bidistream_recvdata_notify(xqc_h3_conn_t *h3_conn, xqc_h3_stream_t *h3_stream,
    uint8_t *data, size_t size, int *ret)
{
    xqc_wt_conn_t    *wt_conn    = (xqc_wt_conn_t *)(xqc_h3_conn_get_user_data(h3_conn));
    xqc_wt_session_t *default_session = wt_conn->wt_session;
    xqc_wt_ctx_t     *wt_ctx     = NULL;

    if (!default_session) {
        if (ret) {
            *ret = size;
        }
        return 1;
    }

    wt_ctx = xqc_wt_get_ctx_by_h3conn(h3_conn);

    void *ele = xqc_wt_session_pending_stream_find(default_session, h3_stream);
    if (ele == NULL) {
        return XQC_ERROR;
    }
    xqc_wt_bidistream_t *wt_bidistream = (xqc_wt_bidistream_t *)(ele);

    int      nread      = 0;
    uint64_t session_id = wt_bidistream->sessionID;

    if (wt_bidistream->packet_parsed_flag == XQC_FALSE) {
        ssize_t consumed = xqc_wt_decode_session_id(data, size, &session_id);
        if (consumed < 0) {
            if (ret) {
                *ret = -XQC_H3_DECODE_ERROR;
            }
            return 1;
        }
        nread = (int)consumed;
        wt_bidistream->packet_parsed_flag = XQC_TRUE;
        wt_bidistream->sessionID          = session_id;
    }

    xqc_wt_session_t *wt_session = xqc_wt_conn_find_session(wt_conn, session_id);
    if (wt_session == NULL) {
        wt_session = wt_conn->wt_session;
    }
    if (wt_session == NULL) {
        if (ret) {
            *ret = size;
        }
        return 1;
    }

    if (size > (size_t)nread) {

        int processed = 0, result = 1;
        if (wt_ctx->stream_cbs && wt_ctx->stream_cbs->wt_bidistream_read_notify) {
            void *strm_data = NULL;
            wt_ctx->stream_cbs->wt_bidistream_read_notify(wt_bidistream, wt_session,
                data + nread, size - nread, &processed);

        } else {
            result = 1;
        }

        processed = (int)(size - nread);
        if (result && processed > 0) {
            nread += processed;
        }
    }

    if (ret) {
        *ret = nread;
        return 1;
    }
    return 0;
}

void
wt_default_handshake_finished_notify(xqc_h3_conn_t *h3_conn, void *h3c_user_data)
{
    xqc_wt_conn_t    *wt_conn    = (xqc_wt_conn_t *)(xqc_h3_conn_get_user_data(h3_conn));
    xqc_wt_ctx_t     *wt_ctx     = xqc_wt_get_ctx_by_h3conn(h3_conn);
    xqc_wt_session_t *wt_session = wt_conn->wt_session;
    if (wt_ctx->session_cbs &&
        wt_ctx->session_cbs->webtransport_session_handshake_finished_notify) {
        wt_ctx->session_cbs->webtransport_session_handshake_finished_notify(wt_session);
    }
}

xqc_int_t
xqc_wt_ctx_init(xqc_engine_t *engine, xqc_webtransport_dgram_callbacks_t *wt_dgram_cbs,
    xqc_webtransport_session_callbacks_t *wt_session_cbs,
    xqc_webtransport_stream_callbacks_t  *wt_stream_cbs)
{
    // alpn ctx init part
    xqc_wt_ctx_t *wt_ctx = (xqc_wt_ctx_t *)xqc_calloc(1, sizeof(xqc_wt_ctx_t));
    wt_ctx->dgram_cbs    = wt_dgram_cbs;
    wt_ctx->session_cbs  = wt_session_cbs;
    wt_ctx->stream_cbs   = wt_stream_cbs;

    xqc_h3_callbacks_t h3_cbs = {
        .h3c_cbs =
            {
                .h3_conn_create_notify      = wt_default_h3_conn_create_notify,
                .h3_conn_close_notify       = wt_default_h3_conn_close_notify,
                .h3_conn_handshake_finished = wt_default_handshake_finished_notify,
            },
        .h3r_cbs =
            {
                .h3_request_create_notify            = wt_default_h3_request_create_notify,
                .h3_request_close_notify             = wt_default_h3_request_close_notify,
                .h3_request_read_notify              = wt_default_h3_request_read_notify,
                .h3_request_write_notify             = NULL,
                .h3_request_closing_notify           = NULL,
            }

    };
    int ret = xqc_h3_ctx_init(engine, &h3_cbs);
    /* init http3 context (with h3-ext & default datagram callbacks) */
    engine->user_data = (void *)wt_ctx;


    return ret;
}

const xqc_cid_t *
xqc_webtransport_connect(xqc_engine_t *engine, const xqc_conn_settings_t *conn_settings,
    const unsigned char *token, unsigned token_len, const char *server_host, int no_crypto_flag,
    const xqc_conn_ssl_config_t *conn_ssl_config, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *user_data)
{
    const char *alpn = XQC_DEFINED_ALPN_H3_EXT;
    return xqc_connect(engine, conn_settings, token, token_len, server_host, no_crypto_flag,
        conn_ssl_config, peer_addr, peer_addrlen, alpn, user_data);
}
