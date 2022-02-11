/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/http3/xqc_h3_request.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_engine.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_ctx.h"
#include "src/common/xqc_time.h"


xqc_h3_request_t *
xqc_h3_request_create(xqc_engine_t *engine, const xqc_cid_t *cid, void *user_data)
{
    xqc_stream_t       *stream;
    xqc_h3_stream_t    *h3_stream;
    xqc_h3_request_t   *h3_request;
    xqc_h3_conn_t      *h3_conn;

    stream = xqc_stream_create(engine, cid, NULL);
    if (!stream) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|xqc_stream_create error|");
        return NULL;
    }

    h3_conn = (xqc_h3_conn_t*)stream->stream_conn->app_proto_user_data;

    h3_stream = xqc_h3_stream_create(h3_conn, stream, XQC_H3_STREAM_TYPE_REQUEST, user_data);
    if (!h3_stream) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|xqc_h3_stream_create error|");
        return NULL;
    }

    h3_request = xqc_h3_request_create_inner(h3_conn, h3_stream, user_data);
    if (!h3_request) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|xqc_h3_request_create_inner error|");
        return NULL;
    }

    xqc_log(engine->log, XQC_LOG_DEBUG, "|success|stream_id:%ui|conn:%p|conn_state:%s|flag:%s|",
            h3_stream->stream_id, h3_conn->conn, xqc_conn_state_2_str(h3_conn->conn->conn_state),
            xqc_conn_flag_2_str(h3_conn->conn->conn_flag));
    return h3_request;
}

void
xqc_h3_request_destroy(xqc_h3_request_t *h3_request)
{
    xqc_h3_stream_t *h3s = h3_request->h3_stream;

    /* print request statistic log */
    xqc_request_stats_t stats = xqc_h3_request_get_stats(h3_request);
    xqc_log(h3_request->h3_stream->log, XQC_LOG_REPORT, "|stream_id:%ui|err:%ui"
            "|rcvd_bdy_sz:%uz|snd_bdy_sz:%uz|rcvd_hdr_sz:%uz|snd_hdr_sz:%uz"
            "|blkd_tm:%ui|nblkd_tm:%ui|strm_fin_tm:%ui|h3r_s_tm:%ui|h3r_e_tm:%ui"
            "|h3r_hdr_s_tm:%ui|h3r_hdr_e_tm:%ui|", h3s->stream_id,
            stats.stream_err, stats.recv_body_size, stats.send_body_size,
            stats.recv_header_size, stats.send_header_size,
            stats.blocked_time, stats.unblocked_time, stats.stream_fin_time,
            stats.h3r_begin_time, stats.h3r_end_time,
            stats.h3r_header_begin_time, stats.h3r_header_end_time);

    if (h3_request->request_if->h3_request_close_notify) {
        h3_request->request_if->h3_request_close_notify(h3_request, h3_request->user_data);
    }

    for (size_t i = 0; i < XQC_H3_REQUEST_MAX_HEADERS_CNT; i++) {
        xqc_h3_headers_free(&h3_request->h3_header[i]);
    }

    xqc_list_buf_list_free(&h3_request->body_buf);
    xqc_free(h3_request);
}

xqc_int_t 
xqc_h3_request_close(xqc_h3_request_t *h3_request)
{
    xqc_connection_t *conn = h3_request->h3_stream->h3c->conn;
    xqc_h3_stream_t  *h3s  = h3_request->h3_stream;

    xqc_int_t ret = xqc_h3_stream_close(h3_request->h3_stream);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|fail|ret:%d|stream_id:%ui|conn:%p|conn_state:%s|"
                "flag:%s|", ret, h3s->stream_id, conn, xqc_conn_state_2_str(conn->conn_state),
                xqc_conn_flag_2_str(conn->conn_flag));
        return ret;
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|success|stream_id:%ui|conn:%p|conn_state:%s|flag:%s|",
            h3s->stream_id, conn, xqc_conn_state_2_str(conn->conn_state),
            xqc_conn_flag_2_str(conn->conn_flag));

    return XQC_OK;
}

void
xqc_h3_request_header_initial(xqc_h3_request_t *h3_request)
{
    xqc_h3_headers_initial(&h3_request->h3_header[XQC_H3_REQUEST_HEADER]);
    xqc_h3_headers_initial(&h3_request->h3_header[XQC_H3_REQUEST_TRAILER]);
}


xqc_int_t
xqc_h3_request_init_callbacks(xqc_h3_request_t *h3r)
{
    xqc_h3_callbacks_t *h3_cbs = NULL;
    xqc_int_t ret = xqc_h3_ctx_get_app_callbacks(&h3_cbs);
    if (XQC_OK != ret || h3_cbs == NULL) {
        xqc_log(h3r->h3_stream->log, XQC_LOG_ERROR, "|can't get app callbacks, not initialized ?");
        return ret;
    }

    h3r->request_if = &h3_cbs->h3r_cbs;

    return XQC_OK;
}


xqc_h3_request_t *
xqc_h3_request_create_inner(xqc_h3_conn_t *h3_conn, xqc_h3_stream_t *h3_stream, void *user_data)
{
    xqc_h3_request_t *h3_request;
    h3_request = xqc_calloc(1, sizeof(xqc_h3_request_t));
    if (!h3_request) {
        xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_calloc error|");
        return NULL;
    }

    h3_request->h3_stream = h3_stream;
    h3_request->user_data = user_data;
    h3_request->fin_flag = 0;
    xqc_h3_request_header_initial(h3_request);

    h3_stream->h3r = h3_request;

    xqc_init_list_head(&h3_request->body_buf);
    h3_request->body_buf_count = 0;

    xqc_h3_request_init_callbacks(h3_request);

    if (h3_request->request_if->h3_request_create_notify) {
        h3_request->request_if->h3_request_create_notify(h3_request, h3_request->user_data);
    }

    xqc_h3_request_begin(h3_request);

    return h3_request;
}

xqc_request_stats_t
xqc_h3_request_get_stats(xqc_h3_request_t *h3_request)
{
    xqc_request_stats_t stats;

    uint64_t conn_err       = h3_request->h3_stream->h3c->conn->conn_err;
    stats.recv_body_size    = h3_request->body_recvd;
    stats.send_body_size    = h3_request->body_sent;
    stats.recv_header_size  = h3_request->header_recvd;
    stats.send_header_size  = h3_request->header_sent;
    stats.stream_err        = conn_err != 0 ? conn_err : (int)xqc_h3_stream_get_err(h3_request->h3_stream);
    stats.blocked_time      = h3_request->blocked_time;
    stats.unblocked_time    = h3_request->unblocked_time;
    stats.stream_fin_time   = h3_request->stream_fin_time;
    stats.h3r_begin_time    = h3_request->h3r_begin_time;
    stats.h3r_end_time      = h3_request->h3r_end_time;
    stats.h3r_header_begin_time = h3_request->h3r_header_begin_time;
    stats.h3r_header_end_time   = h3_request->h3r_header_end_time;

    return stats;
}

void
xqc_h3_request_set_user_data(xqc_h3_request_t *h3_request, void *user_data)
{
    h3_request->user_data = user_data;
}


xqc_int_t
xqc_h3_request_make_name_lowercase(xqc_http_header_t *dst, xqc_http_header_t *src,
    xqc_var_buf_t *buf)
{
    xqc_int_t       ret;
    xqc_bool_t      use_original_buf    = XQC_TRUE; /* whether use memory from original header */

    for (size_t i = 0; i < src->name.iov_len; i++) {
        unsigned char c = ((char *)src->name.iov_base)[i];

        /* uppercase character found */
        if (c >= 'A' && c <= 'Z') {
            use_original_buf = XQC_FALSE;
            break;
        }
    }

    /* all lower case, do not need to copy */
    if (use_original_buf == XQC_TRUE) {
        dst->name.iov_base = src->name.iov_base;
        dst->name.iov_len = src->name.iov_len;
        return XQC_OK;
    }

    /* copy to new buffer */
    /* check capacity */
    if (buf->buf_len - buf->data_len < src->name.iov_len + 1) {
        return -XQC_ELIMIT;
    }
    
    /* make memory from var buf the memory of lowercase header */
    unsigned char *lc_dst = buf->data + buf->data_len;
    unsigned char *lc_src = lc_dst;
    
    /* convert reset characters to lowercase */
    xqc_str_tolower(lc_dst, src->name.iov_base, src->name.iov_len);
    lc_dst += src->name.iov_len;
    
    /* add terminator */
    *lc_dst = '\0';
    
    buf->data_len += (src->name.iov_len + 1);

    dst->name.iov_base = lc_src;
    dst->name.iov_len = src->name.iov_len;

    return XQC_OK;
}

xqc_int_t
xqc_h3_request_copy_header(xqc_http_header_t *dst, xqc_http_header_t *src, xqc_var_buf_t *buf)
{
    /* try to make field name to lower-case if upper-case characters is contained */
    xqc_int_t ret = xqc_h3_request_make_name_lowercase(dst, src, buf);
    if (ret != XQC_OK) {
        return ret;
    }

    dst->value = src->value;
    dst->flags = src->flags;

    return XQC_OK;
}


ssize_t
xqc_h3_request_send_headers(xqc_h3_request_t *h3_request, xqc_http_headers_t *headers, uint8_t fin)
{
    xqc_int_t ret;

    ssize_t sent = 0;
    int i = 0;
    int pt = 0;

    if (!headers) {
        xqc_log(h3_request->h3_stream->log, XQC_LOG_ERROR, "|headers MUST NOT be NULL|");
        return -XQC_H3_EPARAM;
    }

    /* used to convert upper case filed line key to lowercase */
    xqc_var_buf_t *lowercase_buf = xqc_var_buf_create(XQC_H3_HEADERS_LOWERCASE_BUF_SIZE);
    if (NULL == lowercase_buf) {
        xqc_log(h3_request->h3_stream->log, XQC_LOG_ERROR, "|malloc buf for lowercase error|");
        return -XQC_EMALLOC;
    }

    /*  malloc a new  move pesudo headers in the front of list */
    xqc_http_headers_t new_headers;
    xqc_http_headers_t *headers_in = &new_headers;
    headers_in->headers = xqc_malloc(headers->count * sizeof(xqc_http_header_t));
    if (headers_in->headers == NULL) {
        xqc_log(h3_request->h3_stream->log, XQC_LOG_ERROR, "|malloc error|");
        sent = -XQC_H3_EMALLOC;
        goto end;
    }

    headers_in->capacity = headers->count;
    headers_in->total_len = 0;

    /* make pesudo headers first */
    for (i = 0; i < headers->count; i++) {
        if (headers->headers[i].name.iov_len > 0
            && *((unsigned char *)headers->headers[i].name.iov_base) == ':')
        {
            ret = xqc_h3_request_copy_header(&headers_in->headers[pt],
                                             &headers->headers[i], lowercase_buf);
            if (ret != XQC_OK) {
                xqc_log(h3_request->h3_stream->log, XQC_LOG_ERROR,
                        "|copy header error|ret:%d|", ret);
                sent = ret;
                goto end;
            }

            headers_in->total_len +=
                (headers->headers[pt].name.iov_len + headers->headers[pt].value.iov_len);
            pt++;
        }
    }

    /* copy other headers */
    for (i = 0; i < headers->count; i++) {
        if (headers->headers[i].name.iov_len > 0
            && *((unsigned char *)headers->headers[i].name.iov_base) != ':')
        {
            ret = xqc_h3_request_copy_header(&headers_in->headers[pt],
                                             &headers->headers[i], lowercase_buf);
            if (ret != XQC_OK) {
                xqc_log(h3_request->h3_stream->log, XQC_LOG_ERROR,
                        "|copy header error|ret:%d|", ret);
                sent = ret;
                goto end;
            }

            headers_in->total_len +=
                (headers->headers[pt].name.iov_len + headers->headers[pt].value.iov_len);
            pt++;
        }
    }

    headers_in->count = pt;
    sent = xqc_h3_stream_send_headers(h3_request->h3_stream, headers_in, fin);

end:
    /* free headers_in->headers */
    xqc_free(headers_in->headers);
    xqc_var_buf_free(lowercase_buf);

    return sent;
}


ssize_t
xqc_h3_request_send_body(xqc_h3_request_t *h3_request, unsigned char *data, size_t data_size,
    uint8_t fin)
{
    /* data_size is allowed if it's fin only */
    if (data_size > 0 && data == NULL) {
        return -XQC_H3_EPARAM;
    }

    ssize_t sent = xqc_h3_stream_send_data(h3_request->h3_stream, data, data_size, fin);
    if (sent == -XQC_EAGAIN) {
        xqc_log(h3_request->h3_stream->h3c->log, XQC_LOG_DEBUG,
                "|xqc_h3_stream_send_data eagain|stream_id:%ui|data_size:%uz|fin:%ud|",
                h3_request->h3_stream->stream_id, data_size, (unsigned int)fin);
        return sent;

    } else if (sent < 0) {
        xqc_log(h3_request->h3_stream->h3c->log, XQC_LOG_ERROR,
                "|xqc_h3_stream_send_data error|stream_id:%ui|ret:%z|data_size:%z|fin:%d|",
                h3_request->h3_stream->stream_id, sent, data_size, fin);
        return sent;
    }

    h3_request->body_sent += sent;
    if (fin && sent == data_size) {
        h3_request->body_sent_final_size = h3_request->body_sent;
    }

    xqc_log(h3_request->h3_stream->h3c->log, XQC_LOG_DEBUG, "|stream_id:%ui|data_size:%uz|sent:%z|"
            "body_sent:%uz|body_sent_final_size:%uz|fin:%ud|conn:%p|",
            h3_request->h3_stream->stream_id, data_size, sent, h3_request->body_sent, 
            h3_request->body_sent_final_size, (unsigned int)fin, h3_request->h3_stream->h3c->conn);

    return sent;
}

ssize_t
xqc_h3_request_finish(xqc_h3_request_t *h3_request)
{
    return xqc_h3_stream_send_finish(h3_request->h3_stream);
}


xqc_http_headers_t *
xqc_h3_request_recv_headers(xqc_h3_request_t *h3_request, uint8_t *fin)
{
    /* header */
    if (h3_request->read_flag & XQC_REQ_NOTIFY_READ_HEADER) {
        xqc_log(h3_request->h3_stream->log, XQC_LOG_DEBUG,
                "|recv header|stream_id:%ui|fin:%ud|conn:%p|",
                h3_request->h3_stream->stream_id, (unsigned int)*fin,
                h3_request->h3_stream->h3c->conn);

        /* if there is body or trailer exists, recv fin together with body or trailer */
        *fin = (h3_request->read_flag == XQC_REQ_NOTIFY_READ_HEADER) ? h3_request->fin_flag : 0;
        if (*fin) {
            xqc_h3_request_end(h3_request);
        }

        /* unset read flag */
        h3_request->read_flag &= ~XQC_REQ_NOTIFY_READ_HEADER;
        return &h3_request->h3_header[XQC_H3_REQUEST_HEADER];
    }

    /* trailer section */
    if (h3_request->read_flag & XQC_REQ_NOTIFY_READ_TRAILER) {
        xqc_log(h3_request->h3_stream->log, XQC_LOG_DEBUG,
                "|recv tailer header|stream_id:%ui|fin:%ud|conn:%p|",
                h3_request->h3_stream->stream_id, (unsigned int)*fin,
                h3_request->h3_stream->h3c->conn);

        *fin = h3_request->fin_flag;
        if (*fin) {
            xqc_h3_request_end(h3_request);
        }

        /* unset read flag */
        h3_request->read_flag &= ~XQC_REQ_NOTIFY_READ_TRAILER;
        return &h3_request->h3_header[XQC_H3_REQUEST_TRAILER];
    }

    return NULL;
}

ssize_t
xqc_h3_request_recv_body(xqc_h3_request_t *h3_request, unsigned char *recv_buf,
    size_t recv_buf_size, uint8_t *fin)
{
    ssize_t n_recv = 0;
    xqc_list_head_t *pos, *next;
    xqc_list_buf_t *list_buf = NULL;

    *fin = XQC_FALSE;

    xqc_list_for_each_safe(pos, next, &h3_request->body_buf) {
        list_buf = xqc_list_entry(pos, xqc_list_buf_t, list_head);
        xqc_var_buf_t *buf = list_buf->buf;
        if (buf->data_len == 0) {
            h3_request->body_buf_count--;
            xqc_list_buf_free(list_buf);
            continue;
        }

        if (buf->data_len - buf->consumed_len <= recv_buf_size - n_recv) {
            memcpy(recv_buf + n_recv, buf->data + buf->consumed_len,
                   buf->data_len - buf->consumed_len);
            n_recv += buf->data_len - buf->consumed_len;
            h3_request->body_buf_count--;
            xqc_list_buf_free(list_buf);

        } else {
            memcpy(recv_buf + n_recv, buf->data + buf->consumed_len, recv_buf_size - n_recv);
            buf->consumed_len += recv_buf_size - n_recv;
            n_recv = recv_buf_size;
            break;
        }
    }

    /* all data in body buf was read, reset XQC_REQ_NOTIFY_READ_BODY */
    if (xqc_list_empty(&h3_request->body_buf)) {
        h3_request->read_flag &= ~XQC_REQ_NOTIFY_READ_BODY;
    }

    h3_request->body_recvd += n_recv;
    if (h3_request->body_buf_count == 0) {
        *fin = h3_request->fin_flag;
        if (*fin) {
            h3_request->body_recvd_final_size = h3_request->body_recvd;
            xqc_h3_request_end(h3_request);
        }
    }

    if (n_recv == 0 && !*fin) {
        return -XQC_EAGAIN;
    }

    xqc_log(h3_request->h3_stream->h3c->log, XQC_LOG_DEBUG,
            "|stream_id:%ui|recv_buf_size:%z|n_recv:%z|body_recvd:%uz|body_recvd_final_size:%uz|"
            "fin:%d|conn:%p|", h3_request->h3_stream->stream_id, recv_buf_size,
            n_recv, h3_request->body_recvd, h3_request->body_recvd_final_size, *fin,
            h3_request->h3_stream->h3c->conn);
    return n_recv;
}

xqc_int_t
xqc_h3_request_on_recv_header(xqc_h3_request_t *h3r)
{
    /* used to set read_flag */
    static const xqc_request_notify_flag_t hdr_type_2_flag[XQC_H3_REQUEST_MAX_HEADERS_CNT] = {
        XQC_REQ_NOTIFY_READ_HEADER,
        XQC_REQ_NOTIFY_READ_TRAILER
    };

    xqc_http_headers_t *headers;

    /* header section and trailer section are all processed */
    if (h3r->current_header >= XQC_H3_REQUEST_MAX_HEADERS_CNT) {
        xqc_log(h3r->h3_stream->log, XQC_LOG_WARN, "|headers count exceed 2|"
                "stream_id:%ui|", h3r->h3_stream->stream_id);
        return -XQC_H3_INVALID_HEADER;
    }

    headers = &h3r->h3_header[h3r->current_header];

    xqc_h3_request_header_end(h3r);

    /* header is too large */
    if (headers->total_len
        > h3r->h3_stream->h3c->local_h3_conn_settings.max_field_section_size)
    {
        xqc_log(h3r->h3_stream->log, XQC_LOG_ERROR, "|large nv|conn:%p|fields_size:%ui|exceed|"
                "SETTINGS_MAX_FIELD_SECTION_SIZE:%ui|", h3r->h3_stream->h3c->conn,
                headers->total_len, 
                h3r->h3_stream->h3c->local_h3_conn_settings.max_field_section_size);
        return -XQC_H3_INVALID_HEADER;
    }

    /* set read flag */
    h3r->read_flag |= hdr_type_2_flag[h3r->current_header];

    h3r->header_recvd += headers->total_len;

    /* prepare to process next header */
    h3r->current_header++;

    /* header notify callback */
    xqc_int_t ret = h3r->request_if->h3_request_read_notify(h3r, h3r->read_flag, h3r->user_data);
    if (ret < 0) {
        xqc_log(h3r->h3_stream->log, XQC_LOG_ERROR, "|h3_request_read_notify error|%d|"
                "stream_id:%ui|conn:%p|", ret, h3r->h3_stream->stream_id,
                h3r->h3_stream->h3c->conn);
        return ret;
    }

    return XQC_OK;
}

xqc_int_t
xqc_h3_request_on_recv_body(xqc_h3_request_t *h3r)
{
    /* there might be a fin only operation, which shall be notified to user */
    if (!xqc_list_empty(&h3r->body_buf) || (h3r->fin_flag == XQC_TRUE)) {

        if (!xqc_list_empty(&h3r->body_buf)) {
            h3r->read_flag |= XQC_REQ_NOTIFY_READ_BODY;
        }

        xqc_int_t ret = h3r->request_if->h3_request_read_notify(h3r, h3r->read_flag, h3r->user_data);
        if (ret < 0) {
            xqc_log(h3r->h3_stream->log, XQC_LOG_ERROR, "|h3_request_read_notify error|%d|"
                    "stream_id:%ui|conn:%p|", ret, h3r->h3_stream->stream_id,
                    h3r->h3_stream->h3c->conn);
            return ret;
        }
    }

    return XQC_OK;
}


xqc_int_t
xqc_h3_request_on_recv_empty_fin(xqc_h3_request_t *h3r)
{
    xqc_int_t ret;

    if (h3r->fin_flag) {
        xqc_log(h3r->h3_stream->log, XQC_LOG_WARN, "|duplicated fin|");
        return XQC_OK;
    }

    h3r->fin_flag = 1;
    xqc_h3_request_end(h3r);

    /*
     * if read flag is not XQC_REQ_NOTIFY_READ_NULL, it means that there is header or content not
     * received by application, shall not notify empty fin event, application will be noticed when
     * receiving header and content
     */
    if (h3r->read_flag != XQC_REQ_NOTIFY_READ_NULL) {
        return XQC_OK;
    }

    /* if all header and content were received by application, notify empty fin */
    ret = h3r->request_if->h3_request_read_notify(h3r, XQC_REQ_NOTIFY_READ_EMPTY_FIN,
                                                  h3r->user_data);
    if (ret < 0) {
        xqc_log(h3r->h3_stream->log, XQC_LOG_ERROR, "|h3_request_read_notify error|%d|"
                "stream_id:%ui|conn:%p|", ret, h3r->h3_stream->stream_id,
                h3r->h3_stream->h3c->conn);
        return ret;
    }

    xqc_log(h3r->h3_stream->h3c->log, XQC_LOG_DEBUG, "|stream_id:%ui|recv_fin|conn:%p|",
            h3r->h3_stream->stream_id, h3r->h3_stream->h3c->conn);

    return XQC_OK;
}


void *
xqc_h3_get_conn_user_data_by_request(xqc_h3_request_t *h3_request)
{
    return h3_request->h3_stream->h3c->user_data;
}

xqc_stream_id_t
xqc_h3_stream_id(xqc_h3_request_t *h3_request)
{
    return h3_request->h3_stream->stream_id;
}

xqc_http_headers_t *
xqc_h3_request_get_writing_headers(xqc_h3_request_t *h3r)
{
    if (h3r->current_header >= XQC_H3_REQUEST_MAX_HEADERS_CNT) {
        return NULL;
    }

    xqc_h3_request_header_begin(h3r);
    return &h3r->h3_header[h3r->current_header];
}

#define XQC_H3_REQUEST_RECORD_TIME(a)       \
    if ((a) == 0) {                         \
        (a) = xqc_monotonic_timestamp();    \
    }                                       \

void
xqc_h3_request_blocked(xqc_h3_request_t *h3r)
{
    XQC_H3_REQUEST_RECORD_TIME(h3r->blocked_time);
}

void
xqc_h3_request_unblocked(xqc_h3_request_t *h3r)
{
    XQC_H3_REQUEST_RECORD_TIME(h3r->unblocked_time);
}

void
xqc_h3_request_header_begin(xqc_h3_request_t *h3r)
{
    XQC_H3_REQUEST_RECORD_TIME(h3r->h3r_header_begin_time);
}

void
xqc_h3_request_header_end(xqc_h3_request_t *h3r)
{
    XQC_H3_REQUEST_RECORD_TIME(h3r->h3r_header_end_time);
}

void
xqc_h3_request_stream_fin(xqc_h3_request_t *h3r)
{
    XQC_H3_REQUEST_RECORD_TIME(h3r->stream_fin_time);
}

void
xqc_h3_request_begin(xqc_h3_request_t *h3r)
{
    XQC_H3_REQUEST_RECORD_TIME(h3r->h3r_begin_time);
}

void
xqc_h3_request_end(xqc_h3_request_t *h3r)
{
    XQC_H3_REQUEST_RECORD_TIME(h3r->h3r_end_time);
}
