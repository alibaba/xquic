/**
 * xqc_webtransport_ctx.c
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */
#include "xqc_webtransport_ctx.h"
#include "src/http3/xqc_h3_ctx.h"
#include "src/common/xqc_id_hash.h"
#include "src/http3/frame/xqc_h3_frame_defs.h"
#include "src/http3/xqc_h3_request.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/http3/xqc_h3_ext_bytestream.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/common/xqc_common.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_stream.h"
#include "xqc_webtransport_conn.h"
#include "xqc_webtransport_request.h"
#include "xqc_webtransport_session.h"
#include "xqc_webtransport_stream.h"
#include "xqc_webtransport_wire.h"
#include "xquic/xquic.h"

xqc_wt_ctx_t *
xqc_wt_ctx_get_by_engine(xqc_engine_t *engine)
{
    xqc_h3_ctx_t *h3_ctx = xqc_engine_get_alpn_ctx(engine,
        XQC_ALPN_H3, strlen(XQC_ALPN_H3));
    if (h3_ctx && h3_ctx->ext_ctx) {
        return (xqc_wt_ctx_t *)h3_ctx->ext_ctx;
    }
    return NULL;
}

xqc_wt_ctx_t *
xqc_wt_get_ctx_by_h3conn(xqc_h3_conn_t *h3_conn)
{
    xqc_wt_conn_t *wt_conn = (xqc_wt_conn_t *)xqc_h3_conn_get_user_data(h3_conn);
    if (wt_conn && wt_conn->wt_ctx) {
        return wt_conn->wt_ctx;
    }
    /* fallback: retrieve from engine alpn ctx */
    if (h3_conn && h3_conn->conn && h3_conn->conn->engine) {
        return xqc_wt_ctx_get_by_engine(h3_conn->conn->engine);
    }
    return NULL;
}

xqc_wt_ctx_t *
xqc_wt_get_ctx_by_conn(xqc_connection_t *conn)
{
    xqc_wt_conn_t *wt_conn = (xqc_wt_conn_t *)xqc_conn_get_user_data(conn);
    if (wt_conn && wt_conn->wt_ctx) {
        return wt_conn->wt_ctx;
    }
    if (conn && conn->engine) {
        return xqc_wt_ctx_get_by_engine(conn->engine);
    }
    return NULL;
}

void
xqc_wt_dgram_read_handler(xqc_connection_t *conn, void *user_data, const void *data,
    size_t data_len, uint64_t unix_ts)
{
    xqc_wt_ctx_t *wt_ctx = xqc_wt_get_ctx_by_conn(conn);
    xqc_wt_conn_t *wt_conn =
        (xqc_wt_conn_t *)xqc_conn_get_user_data(conn);

    if (!wt_ctx || !wt_conn) {
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

    /* call application callback if registered */
    if (wt_ctx->dgram_cbs.dgram_read_notify) {
        wt_ctx->dgram_cbs.dgram_read_notify(wt_session, payload, payload_len,
            user_data, unix_ts);
    }
}

void
xqc_wt_dgram_write_handler(xqc_connection_t *conn, void *user_data)
{
    xqc_wt_ctx_t *wt_ctx  = xqc_wt_get_ctx_by_conn(conn);
    xqc_wt_conn_t *wt_conn = (xqc_wt_conn_t *)xqc_conn_get_user_data(conn);
    if (!wt_ctx || !wt_conn ||
        !wt_ctx->dgram_cbs.dgram_write_notify) {
        return;
    }
    xqc_wt_session_t *wt_session = wt_conn->wt_session;
    if (!wt_session) {
        return;
    }
    wt_ctx->dgram_cbs.dgram_write_notify(wt_session, user_data);
}

/* WT settings IDs (see src/http3/xqc_h3_defs.h):
 *   XQC_H3_SETTINGS_ENABLE_CONNECT_PROTOCOL      = 0x08       (RFC 9220)
 *   XQC_H3_SETTINGS_H3_DATAGRAM                  = 0x33       (RFC 9297)
 *   XQC_H3_SETTINGS_ENABLE_WEBTRANSPORT           = 0x2b603742 (draft-ietf-webtrans-http3)
 *   XQC_H3_SETTINGS_WEBTRANSPORT_MAX_SESSIONS     = 0xc671706a (RFC 9297 §3.1)
 */

int
xqc_wt_h3_conn_create_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *h3c_user_data)
{
    xqc_wt_conn_t *wt_conn = xqc_wt_conn_create(h3_conn);
    if (wt_conn == NULL) {
        return -XQC_EMALLOC;
    }
    xqc_connection_t *conn = xqc_h3_conn_get_xqc_conn(h3_conn);
    wt_conn->wt_ctx = xqc_wt_ctx_get_by_engine(conn->engine);
    wt_conn->py_handle = conn->engine->user_data;  /* py_client_t* or py_server_t* */
    xqc_wt_conn_set_dgram_mss(wt_conn, XQC_WEBTRANSPORT_DEFAULT_DGRAM_MSS);
    xqc_h3_conn_set_user_data(h3_conn, wt_conn);
    xqc_conn_set_transport_user_data(conn, wt_conn);

    xqc_h3_conn_get_peer_addr(h3_conn, (struct sockaddr *)&wt_conn->peer_addr,
        sizeof(wt_conn->peer_addr), &wt_conn->peer_addrlen);

    memcpy(&wt_conn->cid, cid, sizeof(*cid));

    return 0;
}

int
xqc_wt_h3_request_create_notify(xqc_h3_request_t *h3_request, void *h3s_user_data)
{
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
    if (wt_session == NULL) {
        return -XQC_EMALLOC;
    }
    wt_session->h3_request = h3_request;

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
    xqc_wt_session_t *session = (xqc_wt_session_t *)(wt_request->user_data);

    if (wt_ctx->session_cbs.webtransport_session_create_notify) {
        /* pass wt_conn as h3c_user_data so py_server_session_create can find the server handle */
        void *h3c_user_data = session ? (void *)session->wt_conn : NULL;
        return wt_ctx->session_cbs.webtransport_session_create_notify(session, headers, 0, h3c_user_data);
    }
    return XQC_OK;
}

int
xqc_wt_h3_request_read_notify(xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag,
    void *strm_user_data)
{
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
            if (check_str_equal(name, ":path")) {
                // to process "?"
                // like "127.0.0.1/publish?stream_id=1"
                if (xqc_wt_request_table_find(wt_request, ":path") == NULL)
                    xqc_wt_request_table_insert(wt_request, name, value);
            }
            xqc_wt_request_table_insert(wt_request, name, value);
            // log
        }

        /* debug: print headers */
        /* distinguish client vs server by connection type */
        xqc_conn_type_t conn_type = h3_stream->h3c->conn->conn_type;

        if (conn_type == XQC_CONN_TYPE_CLIENT) {
            /* client: check for 200 response (session established) */
            char *status = xqc_wt_request_table_find(wt_request, ":status");
            if (status != NULL && check_str_equal(status, "200")) {
                return xqc_wt_process_request_headers(wt_request, wt_ctx, headers);
            }
            return XQC_OK;
        }

        /* server side: check for Extended CONNECT request */
        char *request_name = xqc_wt_request_table_find(wt_request, ":method");
        if (request_name == NULL || !check_str_equal(request_name, "CONNECT")) {
            return XQC_ERROR;
        }

        request_name = xqc_wt_request_table_find(wt_request, ":protocol");
        if (request_name == NULL || !check_str_equal(request_name, "webtransport")) {
            return XQC_ERROR;
        }

        /* draft02 header is optional — RFC final version (Safari 17.4+) does not send it.
         * Only reject if explicitly present with an unsupported value. */
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
            if (                wt_ctx->session_cbs.webtransport_will_create_session_notify) {
                int ret = wt_ctx->session_cbs.webtransport_will_create_session_notify(headers,
                    &response_headers);
                if (ret != 1) {
                    // TODO send 403/404 headers
                    return XQC_ERROR;
                }
            }
            ssize_t ret = xqc_h3_request_send_headers(h3_request, &response_headers, 0);
            if (ret < 0) {
                return ret;
            }
            wt_request->header_sent = 1;
            return xqc_wt_process_request_headers(wt_request, wt_ctx, headers);
        }
    } else if (flag & XQC_REQ_NOTIFY_READ_BODY) {
        /* body data on the CONNECT stream may contain capsules (RFC 9297).
         * Capsules may span multiple DATA frames, so we maintain a reassembly
         * buffer (wt_request->capsule_buf) for incomplete capsules. */
        char    recv_buf[4096];
        ssize_t read     = 0;
        ssize_t read_sum = 0;
        do {
            read = xqc_h3_request_recv_body(h3_request,
                (unsigned char *)recv_buf, sizeof(recv_buf), &fin);
            if (read == -XQC_EAGAIN) {
                break;
            } else if (read < 0) {
                return 0;
            }

            read_sum += read;
            wt_request->recv_body_len += read;

            if (read <= 0) {
                continue;
            }

            /* merge with any leftover from previous call */
            const uint8_t *parse_buf;
            size_t         parse_len;
            uint8_t       *merged = NULL;

            #define XQC_WT_CAPSULE_BUF_MAX  65536  /* 64 KB */
            if (wt_request->capsule_buf_len > 0) {
                size_t total = wt_request->capsule_buf_len + (size_t)read;
                if (total > XQC_WT_CAPSULE_BUF_MAX) {
                    xqc_free(wt_request->capsule_buf);
                    wt_request->capsule_buf     = NULL;
                    wt_request->capsule_buf_len = 0;
                    return -XQC_ELIMIT;
                }
                merged = xqc_malloc(total);
                if (merged == NULL) {
                    return -XQC_EMALLOC;
                }
                memcpy(merged, wt_request->capsule_buf, wt_request->capsule_buf_len);
                memcpy(merged + wt_request->capsule_buf_len, recv_buf, (size_t)read);
                parse_buf = merged;
                parse_len = total;

                xqc_free(wt_request->capsule_buf);
                wt_request->capsule_buf     = NULL;
                wt_request->capsule_buf_len = 0;
            } else {
                parse_buf = (const uint8_t *)recv_buf;
                parse_len = (size_t)read;
            }

            /* parse capsules from the buffer */
            const uint8_t *p   = parse_buf;
            size_t         rem = parse_len;
            while (rem > 0) {
                uint64_t capsule_type = 0;
                uint64_t payload_len  = 0;
                ssize_t  hdr_len = xqc_wt_decode_capsule_header(p, rem,
                    &capsule_type, &payload_len);
                if (hdr_len <= 0 || (size_t)hdr_len + payload_len > rem) {
                    break; /* incomplete capsule header or payload */
                }

                const uint8_t *payload = p + hdr_len;

                if (capsule_type == XQC_WT_CAPSULE_CLOSE_SESSION) {
                    uint32_t       close_code = 0;
                    const uint8_t *reason     = NULL;
                    size_t         reason_len = 0;
                    xqc_wt_decode_close_session_capsule(payload, (size_t)payload_len,
                        &close_code, &reason, &reason_len);

                    xqc_wt_session_t *session = (xqc_wt_session_t *)wt_request->user_data;
                    if (session) {
                        session->close_error_code = close_code;
                        if (reason_len > 0 && reason != NULL) {
                            session->close_reason = xqc_malloc(reason_len + 1);
                            if (session->close_reason) {
                                memcpy(session->close_reason, reason, reason_len);
                                session->close_reason[reason_len] = '\0';
                                session->close_reason_len = reason_len;
                            }
                        }
                        /* notify application of session close */
                        if (wt_ctx
                            && wt_ctx->session_cbs.webtransport_session_close_notify)
                        {
                            wt_ctx->session_cbs.webtransport_session_close_notify(
                                session, NULL, NULL,
                                xqc_h3_conn_get_user_data(h3_stream->h3c));
                        }
                    }
                } else if (capsule_type == XQC_WT_CAPSULE_DRAIN_SESSION) {
                    xqc_wt_session_t *session = (xqc_wt_session_t *)wt_request->user_data;
                    if (session) {
                        session->drain_received = XQC_TRUE;
                    }
                }
                p   += (size_t)hdr_len + (size_t)payload_len;
                rem -= (size_t)hdr_len + (size_t)payload_len;
            }

            /* save any incomplete capsule data for the next callback */
            if (rem > 0) {
                wt_request->capsule_buf = xqc_malloc(rem);
                if (wt_request->capsule_buf) {
                    memcpy(wt_request->capsule_buf, p, rem);
                    wt_request->capsule_buf_len = rem;
                }
            }

            if (merged) {
                xqc_free(merged);
            }
        } while (read > 0 && !fin);

        return XQC_OK;
    }

    return XQC_OK;
}

int
xqc_wt_h3_request_close_notify(xqc_h3_request_t *h3_request, void *strm_user_data)
{
    xqc_wt_request_t *wt_request = (xqc_wt_request_t *)strm_user_data;
    if (wt_request == NULL) {
        return 0;
    }
    /* clear user_data to prevent double-free if called again during teardown */
    xqc_h3_request_set_user_data(h3_request, NULL);

    xqc_h3_stream_t *h3_stream = h3_request ? h3_request->h3_stream : NULL;
    if (h3_stream == NULL) {
        xqc_wt_request_destroy(wt_request);
        return 0;
    }

    xqc_h3_conn_t *h3_conn = h3_stream->h3c;
    xqc_wt_ctx_t  *wt_ctx  = xqc_wt_get_ctx_by_h3conn(h3_conn);

    xqc_wt_session_t *session = (xqc_wt_session_t *)wt_request->user_data;
    wt_request->user_data = NULL;  /* prevent double-close */
    if (session) {
        if (wt_ctx &&             wt_ctx->session_cbs.webtransport_session_close_notify) {
            wt_ctx->session_cbs.webtransport_session_close_notify(session, NULL, 0, NULL);
        }
        xqc_wt_session_close(session);
    }

    xqc_wt_request_destroy(wt_request);

    return 0;
}

int
xqc_wt_h3_conn_close_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *h3c_user_data)
{
    xqc_wt_conn_t *wt_conn = (xqc_wt_conn_t *)xqc_h3_conn_get_user_data(h3_conn);
    if (wt_conn) {
        xqc_h3_conn_set_user_data(h3_conn, NULL);  /* prevent double-free in subsequent stream close */
        xqc_wt_conn_close(wt_conn);
    }
    (void)cid;
    (void)h3c_user_data;
    return 0;
}

int
xqc_wt_h3_frame_paser_notify(int frame_type, xqc_h3_conn_t *h3_conn, xqc_h3_stream_t *h3_stream,
    const unsigned char *pos, size_t sz, int *ret, int *fin)
{
    if (frame_type == XQC_H3_FRM_HEADERS) {
        return 0;
    }
    if (frame_type == XQC_WT_STREAM_TYPE_BIDIRECTIONAL) {
        return 0;
    }
    return 1;
}

int
xqc_wt_unknown_unistream_notify(int stream_type, xqc_h3_conn_t *h3_conn,
    xqc_h3_stream_t *h3_stream, int *ret)
{
    if (stream_type != XQC_H3_STREAM_TYPE_WT_UNI) {
        return 0;
    }
    xqc_wt_conn_t *wt_conn = (xqc_wt_conn_t *)(xqc_h3_conn_get_user_data(h3_conn));
    if (wt_conn == NULL) {
        *ret = -XQC_EPARAM;
        return 0;
    }

    xqc_wt_ctx_t *wt_ctx = xqc_wt_get_ctx_by_h3conn(h3_conn);
    if (wt_ctx == NULL) {
        *ret = -XQC_EPARAM;
        return 0;
    }

    xqc_wt_session_t *wt_session = wt_conn->wt_session;
    if (wt_session == NULL) {
        /* session not yet established; drop stream */
        *ret = -XQC_ESTATE;
        return 0;
    }

    xqc_wt_unistream_t *wt_unistream =
        xqc_wt_create_unistream(XQC_WT_STREAM_TYPE_RECV, wt_session, NULL, h3_stream);
    if (wt_unistream == NULL) {
        *ret = -XQC_EMALLOC;
        return 0;
    }

    xqc_wt_session_add_pendingstream(wt_session, h3_stream, wt_unistream,
        XQC_WT_PENDING_UNISTREAM);

    if (wt_ctx->stream_cbs.wt_unistream_create_notify) {
        wt_ctx->stream_cbs.wt_unistream_create_notify(wt_unistream, wt_session,
            xqc_h3_conn_get_user_data(h3_conn));
    }
    *ret = 0;

    return 1;
}

int
xqc_wt_unknown_unistream_recvdata_notify(xqc_h3_conn_t *h3_conn, xqc_h3_stream_t *h3_stream,
    uint8_t *data, size_t size, int *ret)
{
    xqc_wt_conn_t    *wt_conn    = (xqc_wt_conn_t *)(xqc_h3_conn_get_user_data(h3_conn));
    if (wt_conn == NULL) {
        return 0;
    }
    xqc_wt_session_t *wt_session = wt_conn->wt_session;
    xqc_wt_ctx_t     *wt_ctx     = xqc_wt_get_ctx_by_h3conn(h3_conn);

    xqc_wt_pending_stream_t *ps = xqc_wt_session_pending_stream_find(wt_session, h3_stream);
    if (ps == NULL) {
        return XQC_ERROR;
    }
    xqc_wt_unistream_t *wt_unistream = (xqc_wt_unistream_t *)(ps->stream);

    int      nread      = 0;
    uint64_t session_id = wt_unistream->session_id;
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
    wt_unistream->session_id = session_id;

    wt_session = xqc_wt_conn_find_session(wt_conn, session_id);
    if (wt_session == NULL) {
        wt_session = wt_conn->wt_session;  /* fallback for single-session mode */
    }

    if (wt_session == NULL) {
        return 0;
    }
    if (size > (size_t)nread) {
        int processed = 0;
        if (wt_ctx && wt_ctx->stream_cbs.wt_unistream_read_notify) {
            wt_ctx->stream_cbs.wt_unistream_read_notify(
                wt_unistream, wt_session, data + nread, size - nread, &processed);
        }
        /* if callback did not report bytes consumed, assume all data was consumed */
        if (processed <= 0) {
            processed = (int)(size - nread);
        }
        nread += processed;
    }

    if (ret) {
        *ret = nread;
        return 1;
    }
    return 0;
}

/* public wrappers called from H3 layer for WT uni streams */
void
xqc_wt_h3_uni_stream_created(xqc_h3_conn_t *h3c,
    xqc_h3_stream_t *h3s, int *ret)
{
    xqc_wt_unknown_unistream_notify(XQC_WT_STREAM_TYPE_UNIDIRECTIONAL, h3c, h3s, ret);
}

void
xqc_wt_h3_uni_stream_recv(xqc_h3_conn_t *h3c,
    xqc_h3_stream_t *h3s, uint8_t *data, size_t size, int *ret)
{
    xqc_wt_unknown_unistream_recvdata_notify(h3c, h3s, data, size, ret);
}

int
xqc_wt_unknown_bidistream_notify(int stream_type, xqc_h3_conn_t *h3_conn,
    xqc_h3_stream_t *h3_stream, int *ret)
{
    xqc_wt_conn_t *wt_conn = (xqc_wt_conn_t *)(xqc_h3_conn_get_user_data(h3_conn));
    if (wt_conn == NULL) {
        return 0;
    }

    xqc_wt_ctx_t *wt_ctx = xqc_wt_get_ctx_by_h3conn(h3_conn);

    xqc_wt_session_t *wt_session = wt_conn->wt_session;
    if (wt_session == NULL) {
        return 0;
    }

    xqc_wt_bidistream_t *wt_bidistream =
        xqc_wt_create_bidistream(h3_stream, wt_session, NULL, NULL, XQC_TRUE);
    if (wt_bidistream == NULL) {
        return 0;
    }

    xqc_wt_session_add_pendingstream(wt_session, h3_stream, wt_bidistream,
        XQC_WT_PENDING_BIDISTREAM);

    if (wt_ctx && wt_ctx->stream_cbs.wt_bidistream_create_notify) {
        wt_ctx->stream_cbs.wt_bidistream_create_notify(wt_bidistream, wt_session,
            xqc_h3_conn_get_user_data(h3_conn));
    }
    return 0;
}

int
xqc_wt_unknown_bidistream_recvdata_notify(xqc_h3_conn_t *h3_conn, xqc_h3_stream_t *h3_stream,
    uint8_t *data, size_t size, uint8_t fin, int *ret)
{
    xqc_wt_conn_t    *wt_conn    = (xqc_wt_conn_t *)(xqc_h3_conn_get_user_data(h3_conn));
    if (wt_conn == NULL) {
        if (ret) { *ret = size; }
        return 1;
    }
    xqc_wt_session_t *default_session = wt_conn->wt_session;
    xqc_wt_ctx_t     *wt_ctx     = NULL;

    if (!default_session) {
        if (ret) {
            *ret = size;
        }
        return 1;
    }

    wt_ctx = xqc_wt_get_ctx_by_h3conn(h3_conn);

    xqc_wt_pending_stream_t *ps = xqc_wt_session_pending_stream_find(default_session, h3_stream);
    if (ps == NULL) {
        return XQC_ERROR;
    }
    xqc_wt_bidistream_t *wt_bidistream = (xqc_wt_bidistream_t *)(ps->stream);

    int      nread      = 0;
    uint64_t session_id = wt_bidistream->session_id;

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
        wt_bidistream->session_id          = session_id;
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

    /* Propagate FIN to bidistream so application callback can detect stream end */
    if (fin) {
        wt_bidistream->recv_fin = XQC_TRUE;
    }

    if (size > (size_t)nread || fin) {
        int processed = 0;
        if (wt_ctx && wt_ctx->stream_cbs.wt_bidistream_read_notify) {
            wt_ctx->stream_cbs.wt_bidistream_read_notify(wt_bidistream, wt_session,
                data + nread, size - nread, &processed);
        }
        /* if callback did not report bytes consumed, assume all data was consumed */
        if (processed <= 0) {
            processed = (int)(size - nread);
        }
        nread += processed;
    }

    if (ret) {
        *ret = nread;
        return 1;
    }
    return 0;
}

void
xqc_wt_handshake_finished_notify(xqc_h3_conn_t *h3_conn, void *h3c_user_data)
{
    xqc_wt_conn_t *wt_conn = (xqc_wt_conn_t *)(xqc_h3_conn_get_user_data(h3_conn));
    if (wt_conn == NULL) {
        return;
    }
    xqc_wt_ctx_t *wt_ctx = xqc_wt_get_ctx_by_h3conn(h3_conn);
    if (wt_ctx == NULL) {
        return;
    }
    xqc_wt_session_t *wt_session = wt_conn->wt_session;
    if (wt_ctx->session_cbs.webtransport_session_handshake_finished_notify) {
        if (wt_session == NULL) {
            /* Client-side: handshake completes before open_session().
             * Create a temporary session shell so the callback can reach py_handle. */
            xqc_wt_session_t tmp = {0};
            tmp.wt_conn = wt_conn;
            wt_ctx->session_cbs.webtransport_session_handshake_finished_notify(&tmp);
        } else {
            wt_ctx->session_cbs.webtransport_session_handshake_finished_notify(wt_session);
        }
    }
}

/* H3 ext datagram callback — forward to application or echo as fallback */
static void
wt_h3_dgram_read_notify(xqc_h3_conn_t *conn, const void *data, size_t data_len,
    void *user_data, uint64_t recv_time)
{
    xqc_wt_conn_t *wt_conn = (xqc_wt_conn_t *)xqc_h3_conn_get_user_data(conn);
    xqc_wt_ctx_t  *wt_ctx  = xqc_wt_get_ctx_by_h3conn(conn);

    /* if application registered a datagram callback, let it handle */
    if (wt_ctx && wt_ctx->dgram_cbs.dgram_read_notify) {
        xqc_wt_session_t *wt_session = wt_conn ? wt_conn->wt_session : NULL;
        wt_ctx->dgram_cbs.dgram_read_notify(wt_session, data, data_len, user_data, recv_time);
        return;
    }

    /* no datagram callback registered — drop silently */
}

/* bytestream callbacks for WebTransport bidi streams */
static xqc_int_t
wt_bs_create_notify(xqc_h3_ext_bytestream_t *h3_ext_bs, void *bs_user_data)
{
    xqc_h3_conn_t   *h3_conn   = xqc_h3_ext_bytestream_get_h3_conn(h3_ext_bs);
    xqc_h3_stream_t *h3_stream = xqc_h3_ext_bytestream_get_h3_stream(h3_ext_bs);
    if (h3_conn == NULL || h3_stream == NULL) {
        return 0;
    }

    /* Create the WT bidistream object and register it in the session's
     * pending_unistreams so that xqc_wt_unknown_bidistream_recvdata_notify
     * can find it when data arrives via the bypass path. */
    int wt_ret = 0;
    xqc_wt_unknown_bidistream_notify(XQC_WT_STREAM_TYPE_BIDIRECTIONAL,
        h3_conn, h3_stream, &wt_ret);

    return 0;
}

static xqc_int_t
wt_bs_close_notify(xqc_h3_ext_bytestream_t *h3_ext_bs, void *bs_user_data)
{
    return 0;
}

static int
wt_bs_read_notify(xqc_h3_ext_bytestream_t *h3_ext_bs,
    const void *data, size_t data_len, uint8_t fin, void *bs_user_data,
    uint64_t data_recv_time)
{
    xqc_h3_conn_t   *h3_conn   = xqc_h3_ext_bytestream_get_h3_conn(h3_ext_bs);
    xqc_h3_stream_t  *h3_stream = xqc_h3_ext_bytestream_get_h3_stream(h3_ext_bs);
    if (h3_conn == NULL || h3_stream == NULL) {
        return 0;
    }

    /* Skip empty non-FIN frames (no data, no signal) */
    if ((data == NULL || data_len == 0) && !fin) {
        return 0;
    }

    /* Delegate to the WT bidi recvdata handler, which parses the session_id
     * from the raw payload and dispatches to the application callback. */
    int ret = 0;
    xqc_wt_unknown_bidistream_recvdata_notify(h3_conn, h3_stream,
        (uint8_t *)data, data_len, fin, &ret);

    return 0;
}

static xqc_int_t
wt_bs_write_notify(xqc_h3_ext_bytestream_t *h3_ext_bs, void *bs_user_data)
{
    return 0;
}


xqc_int_t
xqc_wt_ctx_init(xqc_engine_t *engine, xqc_webtransport_dgram_callbacks_t *wt_dgram_cbs,
    xqc_webtransport_session_callbacks_t *wt_session_cbs,
    xqc_webtransport_stream_callbacks_t  *wt_stream_cbs,
    uint64_t max_sessions)
{
    xqc_wt_ctx_t *wt_ctx = (xqc_wt_ctx_t *)xqc_calloc(1, sizeof(xqc_wt_ctx_t));
    if (wt_ctx == NULL) {
        return -XQC_EMALLOC;
    }
    if (wt_dgram_cbs)   wt_ctx->dgram_cbs   = *wt_dgram_cbs;
    if (wt_session_cbs) wt_ctx->session_cbs = *wt_session_cbs;
    if (wt_stream_cbs)  wt_ctx->stream_cbs  = *wt_stream_cbs;
    wt_ctx->max_sessions = max_sessions;

    xqc_h3_callbacks_t h3_cbs = {
        .h3c_cbs =
            {
                .h3_conn_create_notify      = xqc_wt_h3_conn_create_notify,
                .h3_conn_close_notify       = xqc_wt_h3_conn_close_notify,
                .h3_conn_handshake_finished = xqc_wt_handshake_finished_notify,
            },
        .h3r_cbs =
            {
                .h3_request_create_notify            = xqc_wt_h3_request_create_notify,
                .h3_request_close_notify             = xqc_wt_h3_request_close_notify,
                .h3_request_read_notify              = xqc_wt_h3_request_read_notify,
                .h3_request_write_notify             = NULL,
                .h3_request_closing_notify           = NULL,
            },
        .h3_ext_bs_cbs =
            {
                .bs_create_notify = wt_bs_create_notify,
                .bs_close_notify  = wt_bs_close_notify,
                .bs_read_notify   = wt_bs_read_notify,
                .bs_write_notify  = wt_bs_write_notify,
            },
        .h3_ext_dgram_cbs =
            {
                .dgram_read_notify = wt_h3_dgram_read_notify,
            },
    };
    int ret = xqc_h3_ctx_init(engine, &h3_cbs);
    if (ret != XQC_OK) {
        xqc_free(wt_ctx);
        return ret;
    }

    /* store wt_ctx in each ALPN's h3_ctx and configure WT SETTINGS */
    const char *alpns[] = { XQC_ALPN_H3, XQC_ALPN_H3_29, XQC_ALPN_H3_EXT };
    for (int a = 0; a < 3; a++) {
        xqc_h3_ctx_t *h3_ctx = xqc_engine_get_alpn_ctx(engine,
            alpns[a], strlen(alpns[a]));
        if (h3_ctx) {
            h3_ctx->ext_ctx = wt_ctx;
            h3_ctx->h3c_def_local_settings.enable_webtransport = 1;
            h3_ctx->h3c_def_local_settings.webtransport_max_sessions =
                wt_ctx->max_sessions > 0 ? wt_ctx->max_sessions : 1;
            h3_ctx->h3c_def_local_settings.h3_datagram = 1;
            h3_ctx->h3c_def_local_settings.enable_connect_protocol = 1;
        }
    }

    return ret;
}


xqc_int_t
xqc_wt_client_open_session(xqc_engine_t *engine, const xqc_cid_t *cid,
    const char *path, const char *authority, void *user_data)
{
    if (engine == NULL || cid == NULL || path == NULL) {
        return -XQC_EPARAM;
    }

    /* create H3 request for Extended CONNECT */
    xqc_h3_request_t *h3_request = xqc_h3_request_create(engine, cid, NULL, user_data);
    if (h3_request == NULL) {
        return -XQC_ECREATE_STREAM;
    }

    /* send Extended CONNECT headers (RFC 9220) */
    const char *auth = authority ? authority : "localhost";
    xqc_http_header_t headers[] = {
        {.name  = {.iov_base = (void *)":method",    .iov_len = 7},
         .value = {.iov_base = (void *)"CONNECT",    .iov_len = 7}},
        {.name  = {.iov_base = (void *)":protocol",  .iov_len = 9},
         .value = {.iov_base = (void *)"webtransport", .iov_len = 12}},
        {.name  = {.iov_base = (void *)":scheme",    .iov_len = 7},
         .value = {.iov_base = (void *)"https",      .iov_len = 5}},
        {.name  = {.iov_base = (void *)":authority",  .iov_len = 10},
         .value = {.iov_base = (void *)auth,          .iov_len = strlen(auth)}},
        {.name  = {.iov_base = (void *)":path",      .iov_len = 5},
         .value = {.iov_base = (void *)path,          .iov_len = strlen(path)}},
    };

    xqc_http_headers_t hdrs = {.headers = headers, .count = 5};
    ssize_t ret = xqc_h3_request_send_headers(h3_request, &hdrs, 0);
    if (ret < 0) {
        return (xqc_int_t)ret;
    }

    return XQC_OK;
}


ssize_t
xqc_wt_session_send_bidi(xqc_wt_session_t *session,
    const void *data, size_t data_len, int fin)
{
    if (session == NULL || session->wt_conn == NULL) {
        return -XQC_EPARAM;
    }

    xqc_h3_conn_t *h3c = session->wt_conn->h3_conn;
    if (h3c == NULL) {
        return -XQC_EPARAM;
    }

    /* create a QUIC bidi stream for WT data */
    xqc_connection_t *conn = xqc_h3_conn_get_xqc_conn(h3c);
    xqc_stream_t *stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    if (stream == NULL) {
        return -XQC_ECREATE_STREAM;
    }

    /* FIRST: create H3 stream and mark as WT type BEFORE sending data.
     * This ensures the H3 layer knows about this stream before any
     * flow control or retransmit callbacks fire. */
    xqc_h3_stream_t *h3s = (xqc_h3_stream_t *)stream->user_data;
    if (h3s == NULL) {
        /* Use BYTESTEAM type so H3 layer routes to process_bytestream.
         * Set WT_BIDI flag so bytestream bypasses H3 frame parser. */
        h3s = xqc_h3_stream_create(h3c, stream,
                                    XQC_H3_STREAM_TYPE_BYTESTEAM, NULL);
        if (h3s) {
            stream->user_data = h3s;
        }
    } else if (h3s->type == XQC_H3_STREAM_TYPE_UNKNOWN) {
        h3s->type = XQC_H3_STREAM_TYPE_BYTESTEAM;
    }
    if (h3s) {
        h3s->flags |= XQC_HTTP3_STREAM_FLAG_WT_BIDI;
        if (h3s->h3_ext_bs == NULL) {
            h3s->h3_ext_bs = xqc_h3_ext_bytestream_create_passive(h3c, h3s, NULL);
        }
    }

    /* build WT bidi stream header: varint(type) + varint(session_id) */
    uint8_t wt_hdr[16];
    unsigned char *p = wt_hdr;
    p = xqc_put_varint(p, XQC_WT_STREAM_TYPE_BIDIRECTIONAL);
    p = xqc_put_varint(p, session->session_id);   /* session_id */
    size_t hdr_len = p - wt_hdr;

    /* combine header + payload */
    size_t total = hdr_len + data_len;
    uint8_t *buf = xqc_malloc(total);
    if (buf == NULL) {
        return -XQC_EMALLOC;
    }
    memcpy(buf, wt_hdr, hdr_len);
    if (data_len > 0) {
        memcpy(buf + hdr_len, data, data_len);
    }

    /* send on the QUIC bidi stream */
    ssize_t sent = xqc_stream_send(stream, buf, total, fin);
    xqc_free(buf);

    if (sent < 0) {
        return sent;
    }

    /* register wt_bidistream in pending_unistreams so that
     * inbound data on the same bidi stream can be routed to
     * xqc_wt_unknown_bidistream_recvdata_notify → bidistream_read_notify */
    xqc_wt_bidistream_t *wt_bidi =
        xqc_wt_create_bidistream(h3s, session, NULL, NULL, XQC_FALSE);
    if (wt_bidi) {
        wt_bidi->packet_parsed_flag = XQC_TRUE;
        wt_bidi->session_id = session->session_id;
        xqc_wt_session_add_pendingstream(session, h3s, wt_bidi,
            XQC_WT_PENDING_BIDISTREAM);
    }

    return (ssize_t)data_len;
}

const xqc_cid_t *
xqc_webtransport_connect(xqc_engine_t *engine, const xqc_conn_settings_t *conn_settings,
    const unsigned char *token, unsigned token_len, const char *server_host, int no_crypto_flag,
    const xqc_conn_ssl_config_t *conn_ssl_config, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *user_data)
{
    /* use standard h3 ALPN via xqc_h3_connect (RFC 9220) */
    return xqc_h3_connect(engine, conn_settings, token, token_len, server_host, no_crypto_flag,
        conn_ssl_config, peer_addr, peer_addrlen, user_data);
}
