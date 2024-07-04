/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/http3/xqc_h3_stream.h"
#include "src/http3/xqc_h3_request.h"
#include "src/http3/qpack/xqc_qpack.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_engine.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_ext_bytestream.h"

xqc_h3_stream_t *
xqc_h3_stream_create(xqc_h3_conn_t *h3c, xqc_stream_t *stream, xqc_h3_stream_type_t type,
    void *user_data)
{
    xqc_h3_stream_t *h3s = xqc_calloc(1, sizeof(xqc_h3_stream_t));
    if (!h3s) {
        xqc_log(h3c->log, XQC_LOG_ERROR, "|xqc_calloc error|");
        return NULL;
    }

    h3s->stream = stream;
    h3s->stream_id = stream->stream_id;
    h3s->stream_err = 0;
    h3s->h3c = h3c;
    h3s->user_data = user_data;
    h3s->h3r = NULL;
    h3s->type = type;
    h3s->qpack = xqc_h3_conn_get_qpack(h3c);
    h3s->flags = XQC_HTTP3_STREAM_FLAG_NONE;
    xqc_discrete_int_pctx_clear(&h3s->pctx.type);
    memset(&h3s->pctx.frame_pctx, 0, sizeof(xqc_h3_frame_pctx_t));
    h3s->blocked_stream = NULL;
    xqc_init_list_head(&h3s->send_buf);
    xqc_init_list_head(&h3s->blocked_buf);
    h3s->ctx = xqc_qpack_create_req_ctx(stream->stream_id);
    h3s->log = h3c->log;
    h3s->recv_rate_limit = stream->recv_rate_bytes_per_sec;

    stream->user_data = h3s;
    stream->stream_flag |= XQC_STREAM_FLAG_HAS_H3;
    if (h3s->type != XQC_H3_STREAM_TYPE_UNKNOWN) {
        xqc_log_event(h3s->log, HTTP_STREAM_TYPE_SET, h3s, XQC_LOG_LOCAL_EVENT);
    }

    return h3s;
}

/* close h3 stream actively */
xqc_int_t
xqc_h3_stream_close(xqc_h3_stream_t *h3s)
{
    h3s->flags |= XQC_HTTP3_STREAM_FLAG_ACTIVELY_CLOSED;

    xqc_log(h3s->log, XQC_LOG_DEBUG, "|h3s close");

    if (h3s->flags & XQC_HTTP3_STREAM_FLAG_CLOSED) {
        /*
         * transport stream notified its close event before, and h3 stream is
         * not referred any more, will destroy h3 stream and notify to
         * application immediately, even h3 stream is being blocked now
         */
        if (h3s->ref_cnt == 0) {
            xqc_h3_stream_destroy(h3s);
        }
        return XQC_OK;

    } else {
        /*
         * lifetime of stream and h3 stream synchronizes,
         * will destroy h3 stream during stream close notify
         */
        return xqc_stream_close(h3s->stream);
    }
}


void
xqc_h3_stream_destroy(xqc_h3_stream_t *h3s)
{
    /* if h3 stream is still blocked, remove it from h3 connection */
    if (h3s->blocked_stream) {
        xqc_h3_conn_remove_blocked_stream(h3s->h3c, h3s->blocked_stream);
        h3s->blocked_stream = NULL;
    }

    if (h3s->h3r && h3s->type == XQC_H3_STREAM_TYPE_REQUEST) {
        xqc_h3_request_destroy(h3s->h3r);
    }

    //TODO: destroy bytestream
    if (h3s->h3_ext_bs && h3s->type == XQC_H3_STREAM_TYPE_BYTESTEAM) {
        xqc_h3_ext_bytestream_destroy(h3s->h3_ext_bs);
    }

    xqc_h3_frm_reset_pctx(&h3s->pctx.frame_pctx);
    xqc_qpack_destroy_req_ctx(h3s->ctx);
    xqc_list_buf_list_free(&h3s->send_buf);
    xqc_list_buf_list_free(&h3s->blocked_buf);

    xqc_log(h3s->log, XQC_LOG_DEBUG, "|stream_id:%ui|h3_stream_type:%d|",
            h3s->stream_id, h3s->type);

    xqc_free(h3s);
}


xqc_int_t
xqc_h3_stream_send_buffer(xqc_h3_stream_t *h3s)
{
    if (NULL == h3s->stream) {
        xqc_log(h3s->log, XQC_LOG_ERROR,
                "|transport stream was NULL|stream_id:%ui|", h3s->stream_id);
        return -XQC_ESTATE;
    }

    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &h3s->send_buf) {
        xqc_list_buf_t *list_buf = xqc_list_entry(pos, xqc_list_buf_t, list_head);
        xqc_var_buf_t *buf = list_buf->buf;

        if (!(h3s->flags & XQC_HTTP3_STREAM_FLAG_FIN_SENT)) {

            if (buf->data != NULL) {
                /* buf with bytes remain and buf with fin only */
                if (buf->consumed_len < buf->data_len
                    || (buf->data_len == 0 && buf->fin_flag))
                {
                    /* send buffer with transport stream */
                    ssize_t sent = xqc_stream_send(h3s->stream, buf->data + buf->consumed_len,
                                                   buf->data_len - buf->consumed_len, buf->fin_flag);
                    if (sent < 0) {
                        /* don't print XQC_EAGAIN and XQC_ESTREAM_RESET */
                        if (sent != -XQC_EAGAIN && sent != -XQC_ESTREAM_RESET) {
                            xqc_log(h3s->log, XQC_LOG_ERROR, "|xqc_stream_send error|ret:%z|", sent);
                        }

                        return sent;
                    }

                    buf->consumed_len += sent;
                    if (buf->consumed_len != buf->data_len) {
                        return -XQC_EAGAIN;
                    }

                } else if (buf->data_len > 0) {
                    xqc_log(h3s->log, XQC_LOG_ERROR, "|send_buf is empty|buf->consumed_len:%uz"
                            "|buf->data_len:%uz", buf->consumed_len, buf->data_len);
                }

                /* a buffer with fin flag is sent, mark the FIN_SENT flag */
                if (buf->data_len == buf->consumed_len && buf->fin_flag) {
                    h3s->flags |= XQC_HTTP3_STREAM_FLAG_FIN_SENT;
                }

            } else {
                xqc_log(h3s->log, XQC_LOG_ERROR, "|send_buf is NULL|");
            }

        } else {
            xqc_log(h3s->log, XQC_LOG_ERROR,
                    "|send data after fin sent|stream_id:%ui", h3s->stream_id);
        }

        xqc_list_buf_free(list_buf);
    }

    return XQC_OK;
}


static inline uint64_t
xqc_h3_uncompressed_fields_size(xqc_http_headers_t *headers)
{
    /*
     * The size of a field list is calculated based on the uncompressed size of fields, including
     * the length of the name and value in bytes plus an overhead of 32 bytes for each field
     */
    return headers->total_len + headers->count * 32;
}


ssize_t
xqc_h3_stream_write_headers(xqc_h3_stream_t *h3s, xqc_http_headers_t *headers, uint8_t fin)
{
    ssize_t processed = 0;

    /* prepare buf for encoded field section size */
    size_t buf_size = xqc_max(XQC_VAR_BUF_INIT_SIZE, headers->total_len);   /* larger is better */
    xqc_var_buf_t *data = xqc_var_buf_create(buf_size);
    if (data == NULL) {
        xqc_log(h3s->log, XQC_LOG_ERROR, "|malloc error|stream_id:%ui|fin:%d|",
                h3s->stream_id, (unsigned int)fin);
        return -XQC_EMALLOC;
    }

    /* encode headers with qpack */
    xqc_int_t ret = xqc_qpack_enc_headers(h3s->qpack, h3s->stream_id, headers, data);
    if (ret != XQC_OK) {
        xqc_var_buf_free(data);
        return ret;
    }
    processed += data->data_len;
    xqc_log_event(h3s->log, QPACK_HEADERS_ENCODED, XQC_LOG_HEADER_FRAME, h3s->stream->stream_id, data->data_len);

    /* write HEADERS frame */
    ret = xqc_h3_frm_write_headers(&h3s->send_buf, data, fin);
    if (ret != XQC_OK) {
        xqc_log(h3s->log, XQC_LOG_ERROR, "|write HEADERS frame error|stream_id:%ui|fin:%d|",
                h3s->stream_id, (unsigned int)fin);
        xqc_var_buf_free(data);
        return ret;
    }
    xqc_log_event(h3s->log, HTTP_FRAME_CREATED, h3s, XQC_H3_FRM_HEADERS, headers);

    /* send HEADERS frame */
    ret = xqc_h3_stream_send_buffer(h3s);
    if (ret == -XQC_EAGAIN) {
        xqc_log(h3s->log, XQC_LOG_DEBUG, "|send HEADERS frame eagain|stream_id:%ui|fin:%ud|",
                h3s->stream_id, (unsigned int)fin);
        return processed;

    } else if (ret < 0) {
        xqc_log(h3s->log, XQC_LOG_ERROR, "|send HEADERS frame error|%d|stream_id:%ui|fin:%ud|",
                ret, h3s->stream_id, (unsigned int)fin);
        processed = ret;
    }

    return processed;
}


//TODO: remove obsoloted internal functions
ssize_t
xqc_h3_stream_write_data_to_buffer(xqc_h3_stream_t *h3s, unsigned char *data, uint64_t data_size,
    uint8_t fin)
{
    uint64_t write = 0;
    uint64_t size;
    uint8_t flag;
    xqc_int_t ret;

    do {
        /* truncate data if it is too large */
        if (data_size > write + XQC_H3_STREAM_MAX_FRM_PAYLOAD) {
            size = XQC_H3_STREAM_MAX_FRM_PAYLOAD;
            flag = 0;

        } else {
            size = data_size - write;
            flag = fin;
        }

        /* write DATA frame */
        ret = xqc_h3_frm_write_data(&h3s->send_buf, data + write, size, flag);
        if (ret != XQC_OK) {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|write DATA frame error|%d|stream_id:%ui|fin:%d|",
                    ret, h3s->stream_id, (unsigned int)fin);
            return ret;
        }
        write += size;
        xqc_log_event(h3s->log, HTTP_FRAME_CREATED, h3s, XQC_H3_FRM_DATA, size);

        /* send DATA frame */
        ret = xqc_h3_stream_send_buffer(h3s);
        if (ret == -XQC_EAGAIN) {
            return write;

        } else if (ret < 0) {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|send DATA frame error|%d|stream_id:%ui|fin:%d|",
                    ret, h3s->stream_id, (unsigned int)fin);
            return ret;
        }

    } while (data_size > write);

    return write;
}


xqc_int_t
xqc_h3_stream_write_setting_to_buffer(xqc_h3_stream_t *h3s, xqc_h3_conn_settings_t *settings,
    uint8_t fin)
{
    xqc_int_t ret = xqc_h3_frm_write_settings(&h3s->send_buf, settings, fin);
    if (ret != XQC_OK) {
        xqc_log(h3s->log, XQC_LOG_ERROR, "|write SETTINGS frame error|%d|stream_id:%ui|fin:%d|",
                ret, h3s->stream_id, (unsigned int)fin);
        return ret;
    }
    xqc_log_event(h3s->log, HTTP_FRAME_CREATED, h3s, XQC_H3_FRM_SETTINGS, settings);

    ret = xqc_h3_stream_send_buffer(h3s);
    if (ret < 0 && ret != -XQC_EAGAIN) {
        xqc_log(h3s->log, XQC_LOG_ERROR, "|send SETTINGS frame error|%d|stream_id:%ui|fin:%d|",
                ret, h3s->stream_id, (unsigned int)fin);
        return ret;
    }

    return XQC_OK;
}


xqc_int_t
xqc_h3_stream_write_goaway_to_buffer(xqc_h3_stream_t *h3s, uint64_t push_id, uint8_t fin)
{
    xqc_int_t ret = xqc_h3_frm_write_goaway(&h3s->send_buf, push_id, fin);
    if (ret != XQC_OK) {
        xqc_log(h3s->log, XQC_LOG_ERROR, "|write GOAWAY frame error|%d|stream_id:%ui|fin:%d|",
                ret, h3s->stream_id, (unsigned int)fin);
        return ret;
    }
    xqc_log_event(h3s->log, HTTP_FRAME_CREATED, h3s, XQC_H3_FRM_GOAWAY, push_id);

    ret = xqc_h3_stream_send_buffer(h3s);
    if (ret < 0 && ret != -XQC_EAGAIN) {
        xqc_log(h3s->log, XQC_LOG_ERROR, "|send GOAWAY frame error|%d|stream_id:%ui|fin:%d|",
                ret, h3s->stream_id, (unsigned int)fin);
        return ret;
    }

    return XQC_OK;
}

xqc_int_t
xqc_h3_stream_write_bidi_stream_type_to_buffer(xqc_h3_stream_t *h3s, uint64_t stype, uint8_t fin)
{
    xqc_int_t ret = xqc_h3_ext_frm_write_bidi_stream_type(&h3s->send_buf, stype, fin);
    if (ret != XQC_OK) {
        xqc_log(h3s->log, XQC_LOG_ERROR, "|write BIDI_STREAM_TYPE frame error|%d|stream_id:%ui|fin:%d|",
                ret, h3s->stream_id, (unsigned int)fin);
        return ret;
    }
    xqc_log_event(h3s->log, HTTP_FRAME_CREATED, h3s, XQC_H3_EXT_FRM_BIDI_STREAM_TYPE, stype);

    ret = xqc_h3_stream_send_buffer(h3s);
    if (ret < 0 && ret != -XQC_EAGAIN) {
        xqc_log(h3s->log, XQC_LOG_ERROR, "|send BIDI_STREAM_TYPE frame error|%d|stream_id:%ui|fin:%d|",
                ret, h3s->stream_id, (unsigned int)fin);
        return ret;
    }

    return XQC_OK;
}




ssize_t
xqc_h3_stream_send_headers(xqc_h3_stream_t *h3s, xqc_http_headers_t *headers, uint8_t fin)
{
    xqc_h3_conn_t  *h3c;
    uint64_t        fields_size;
    uint64_t        max_field_section_size;
    ssize_t         write;

    /* nothing to send */
    if (headers->count == 0) {
        return 0;
    }

    h3c = h3s->h3c;

    /* header size constrains */
    fields_size = xqc_h3_uncompressed_fields_size(headers);
    max_field_section_size = h3c->peer_h3_conn_settings.max_field_section_size;
    if (fields_size > max_field_section_size) {
        xqc_log(h3c->log, XQC_LOG_ERROR, "|large nv|conn:%p|fields_size:%ui|exceed|"
                "SETTINGS_MAX_FIELD_SECTION_SIZE:%ui|", h3c->conn, fields_size, 
                max_field_section_size);
        return -XQC_H3_INVALID_HEADER;
    }

    h3s->flags |= XQC_HTTP3_STREAM_NEED_WRITE_NOTIFY;

    /* QPACK & gen HEADERS frame */
    write = xqc_h3_stream_write_headers(h3s, headers, fin);
    if (write < 0) {
        xqc_log(h3c->log, XQC_LOG_ERROR, "|xqc_h3_stream_write_headers error|ret:%z||stream_id:%ui",
                write, h3s->stream_id);
        XQC_H3_CONN_ERR(h3c, H3_INTERNAL_ERROR, write);

    } else {
        h3s->h3r->compressed_header_sent += write;
    }
    /* header_sent is the sum of plaintext header name value length */
    h3s->h3r->header_sent += headers->total_len;

    xqc_log(h3c->log, XQC_LOG_DEBUG, "|write:%z|stream_id:%ui|fin:%ud|conn:%p|flag:%s|", write,
            h3s->stream_id, (unsigned int)fin, h3c->conn, xqc_conn_flag_2_str(h3c->conn, h3c->conn->conn_flag));

    h3s->flags &= ~XQC_HTTP3_STREAM_NEED_WRITE_NOTIFY;

    xqc_engine_main_logic_internal(h3c->conn->engine);

    return write;
}

ssize_t
xqc_h3_stream_send_data_frame(xqc_h3_stream_t *h3s, unsigned char *data, size_t data_size, uint8_t fin)
{
    size_t data_sent = 0;
    ssize_t sent;
    xqc_int_t ret;
    uint8_t fin_only = fin && !data_size;
    uint8_t fin_only_sent = 0;
    uint8_t fin_flag_for_quic_stream = 0;
    unsigned char *pos;

    /* Send buffered HEADERS frame if any */
    ret = xqc_h3_stream_send_buffer(h3s);
    if (ret < 0) {
        return ret;
    }
    
    xqc_log(h3s->log, XQC_LOG_DEBUG, "|xqc_h3_stream_send_buffer|success|");

    do {
        if (h3s->flags & XQC_HTTP3_STREAM_FLAG_FIN_SENT) {
            xqc_log(h3s->log, XQC_LOG_ERROR,
                    "|send data after fin sent|stream_id:%ui", h3s->stream_id);
            break;
        }

        if (h3s->data_frame.data_sent > h3s->data_frame.data_len) {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|data_sent exceed data_len|");
            XQC_H3_CONN_ERR(h3s->h3c, H3_INTERNAL_ERROR, -XQC_H3_STATE_ERROR);
            return -XQC_H3_STATE_ERROR;
        }

        /* Generate new frame header */
        if (h3s->data_frame.data_sent == h3s->data_frame.data_len) {
            h3s->data_frame.data_len = data_size - data_sent;
            h3s->data_frame.data_sent = 0;

            pos = h3s->data_frame.header_buf;
            pos = xqc_put_varint(pos, XQC_H3_FRM_DATA);
            pos = xqc_put_varint(pos, h3s->data_frame.data_len);

            h3s->data_frame.header_len = pos - h3s->data_frame.header_buf;
            h3s->data_frame.header_sent = 0;
            fin_flag_for_quic_stream = fin;

        } else {
            /* there is already a old data_frame */
            if ((data_size - data_sent) <= (h3s->data_frame.data_len - h3s->data_frame.data_sent)) {
                fin_flag_for_quic_stream = fin;

            } else {
                /* !!! this is important, otherwise an infinite-loop will happen. */
                fin_flag_for_quic_stream = 0;
            }
        }

        /* Send frame header */
        if (h3s->data_frame.header_sent != h3s->data_frame.header_len) {
            sent = xqc_stream_send(h3s->stream, h3s->data_frame.header_buf + h3s->data_frame.header_sent,
                                   h3s->data_frame.header_len - h3s->data_frame.header_sent, fin_only);
            if (sent == -XQC_EAGAIN) {
                break;

            } else if (sent < 0) {
                return sent;
            }

            h3s->data_frame.header_sent += sent;

            xqc_log(h3s->log, XQC_LOG_DEBUG, "|send_header|success|fin:%d|fin_only:%d|\n", fin, fin_only);

            if (fin_only) {
                if (h3s->data_frame.header_sent == h3s->data_frame.header_len) {
                    fin_only_sent = 1;
                    h3s->flags |= XQC_HTTP3_STREAM_FLAG_FIN_SENT;
                }
                break;
            }
        }

        /* Send frame data */
        sent = xqc_stream_send(h3s->stream, data + data_sent,
                xqc_min(data_size - data_sent, h3s->data_frame.data_len - h3s->data_frame.data_sent), fin_flag_for_quic_stream);
        if (sent == -XQC_EAGAIN) {
            break;

        } else if (sent < 0) {
            return sent;
        }

        data_sent += sent;
        h3s->data_frame.data_sent += sent;

        /* if all data and fin is sent, mark the FIN_SENT flag */
        if (fin_flag_for_quic_stream
            && h3s->data_frame.data_sent == h3s->data_frame.data_len)
        {
            h3s->flags |= XQC_HTTP3_STREAM_FLAG_FIN_SENT;
        }

    } while (data_sent < data_size);

    /* Nothing sent */
    if (data_sent == 0 && fin_only_sent == 0) {
        return -XQC_EAGAIN;
    }
    return data_sent;
}

ssize_t
xqc_h3_stream_send_data(xqc_h3_stream_t *h3s, unsigned char *data, size_t data_size, uint8_t fin)
{
    h3s->flags |= XQC_HTTP3_STREAM_NEED_WRITE_NOTIFY;

    ssize_t write = xqc_h3_stream_send_data_frame(h3s, data, data_size, fin);
    if (write == -XQC_EAGAIN) {
        return write;
    } else if (write < 0) {
        xqc_log(h3s->log, XQC_LOG_ERROR, "|send data frame error|%z|", write);
        return write;
    }

    if (write == data_size) {
        h3s->flags &= ~XQC_HTTP3_STREAM_NEED_WRITE_NOTIFY;
    }

    xqc_log(h3s->log, XQC_LOG_DEBUG, "|stream_id:%ui|data_size:%uz|write:%z|fin:%ud|conn:%p|",
            h3s->stream_id, data_size, write, (unsigned int)fin, h3s->h3c->conn);

    xqc_engine_main_logic_internal(h3s->h3c->conn->engine);

    return write;
}

xqc_int_t
xqc_h3_stream_send_finish(xqc_h3_stream_t *h3s)
{
    xqc_int_t ret;

    if (!xqc_list_empty(&h3s->send_buf)) {
        /* if send_buf is not empty, attach fin flag to the last buf */
        xqc_list_buf_t *last_buf = xqc_list_entry(h3s->send_buf.prev, xqc_list_buf_t, list_head);
        xqc_var_buf_t *buf = last_buf->buf;

        buf->fin_flag = 1;

    } else {
        /* if send_buf is not empty, create a buf with fin set */
        xqc_var_buf_t *buf = xqc_var_buf_create(0);
        if (NULL == buf) {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|create buffer error|");
            return -XQC_EMALLOC;
        }

        buf->fin_flag = 1;

        ret = xqc_list_buf_to_tail(&h3s->send_buf, buf);
        if (ret != XQC_OK) {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|add buffer to the end of send buf list error|");
            xqc_var_buf_free(buf);
            return ret;
        }
    }

    /* send buffer */
    ret = xqc_h3_stream_send_buffer(h3s);
    if (ret != XQC_OK) {
        if (ret != -XQC_EAGAIN) {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|h3 stream send buffer error|ret:%d|", ret);
        }
        return ret;
    }

    xqc_engine_main_logic_internal(h3s->h3c->conn->engine);
    return XQC_OK;
}


xqc_int_t
xqc_h3_stream_send_uni_stream_hdr(xqc_h3_stream_t *h3s)
{
    size_t len = xqc_vint_len_by_val(h3s->type);
    xqc_var_buf_t *buf = xqc_var_buf_create(len);
    if (buf == NULL) {
        xqc_log(h3s->log, XQC_LOG_ERROR, "|create buf for uni-stream type error|stream_id:%ui",
                h3s->stream_id);
        return -XQC_EMALLOC;
    }

    /* write uni stream type */
    unsigned char *pos = buf->data;
    pos = xqc_put_varint(pos, h3s->type);
    buf->data_len = pos - buf->data;

    xqc_int_t ret = xqc_list_buf_to_tail(&h3s->send_buf, buf);
    if (ret != XQC_OK) {
        xqc_log(h3s->log, XQC_LOG_ERROR, "|add uni-stream hdr to send buf error|%d|stream_id:%ui",
                ret, h3s->stream_id);
        xqc_var_buf_free(buf);
        return ret;
    }

    ret = xqc_h3_stream_send_buffer(h3s);
    if (ret < 0 && ret != -XQC_EAGAIN) {
        xqc_log(h3s->log, XQC_LOG_ERROR, "|send uni-stream hdr error|%d|stream_id:%ui",
                ret, h3s->stream_id);
        return ret;
    }

    return XQC_OK;
}


xqc_int_t
xqc_h3_stream_send_setting(xqc_h3_stream_t *h3s, xqc_h3_conn_settings_t *settings, uint8_t fin)
{
    xqc_int_t ret = xqc_h3_stream_write_setting_to_buffer(h3s, settings, fin);
    if (ret < 0) {
        return ret;
    }

    return XQC_OK;
}


xqc_int_t
xqc_h3_stream_send_goaway(xqc_h3_stream_t *h3s, uint64_t push_id, uint8_t fin)
{
    xqc_int_t ret = xqc_h3_stream_write_goaway_to_buffer(h3s, push_id, fin);
    if (ret < 0) {
        return ret;
    }

    xqc_engine_main_logic_internal(h3s->h3c->conn->engine);

    return XQC_OK;
}

xqc_int_t 
xqc_h3_stream_send_bidi_stream_type(xqc_h3_stream_t *h3s, 
    xqc_h3_bidi_stream_type_t stype, uint8_t fin)
{
    xqc_int_t ret = xqc_h3_stream_write_bidi_stream_type_to_buffer(h3s, stype, fin);
    if (ret < 0) {
        return ret;
    }

    xqc_engine_main_logic_internal(h3s->h3c->conn->engine);   
    return XQC_OK;
}


int
xqc_h3_stream_write_notify(xqc_stream_t *stream, void *user_data)
{
    int ret;
    /* server h3_stream might not be created yet */
    if (!user_data) {
        xqc_log(stream->stream_conn->log, XQC_LOG_DEBUG, "|user_data empty|");
        return XQC_OK;
    }

    xqc_h3_stream_t *h3s = (xqc_h3_stream_t*) user_data;
    xqc_log(h3s->log, XQC_LOG_DEBUG, "|stream_type:%d|stream_id:%ui|conn:%p|",
            h3s->type, h3s->stream_id, stream->stream_conn);

    /* send frame buffer */
    ret = xqc_h3_stream_send_buffer(h3s);
    if (ret == -XQC_EAGAIN || ret == -XQC_ESTREAM_RESET) {
        xqc_log(h3s->log, XQC_LOG_DEBUG, "|stream not available|stream_id:%ui|ret:%d|", 
                h3s->stream_id, ret);
        return XQC_OK;

    } else if (ret < 0) {
        xqc_log(h3s->log, XQC_LOG_ERROR, "|send buf error|%z|stream_id:%ui|", ret,
                h3s->stream_id);
        return ret;
    }

    xqc_log(h3s->log, XQC_LOG_DEBUG, "|xqc_h3_stream_send_buffer|success|");

    /* request write  */
    if (h3s->type == XQC_H3_STREAM_TYPE_REQUEST
        && (h3s->flags & XQC_HTTP3_STREAM_NEED_WRITE_NOTIFY))
    {
        if (h3s->h3r->request_if->h3_request_write_notify) {
            ret = h3s->h3r->request_if->h3_request_write_notify(h3s->h3r, h3s->h3r->user_data);
            if (ret < 0) {
                xqc_log(stream->stream_conn->log, XQC_LOG_ERROR,
                        "|h3_request_write_notify error|%d|", ret);
                return ret;
            }
            xqc_log(h3s->log, XQC_LOG_DEBUG, "|h3_request_write_notify|success|");
        }
    }

    //TODO: implement the notification of bytestream writable event
    if (h3s->type == XQC_H3_STREAM_TYPE_BYTESTEAM
        && (h3s->flags & XQC_HTTP3_STREAM_NEED_WRITE_NOTIFY))
    {
        xqc_log(h3s->log, XQC_LOG_DEBUG, "|h3_ext_bytestream_write_notify|start|");
        ret = xqc_h3_ext_bytestream_notify_write(h3s->h3_ext_bs);
        if (ret < 0) {
            xqc_log(stream->stream_conn->log, XQC_LOG_ERROR,
                    "|h3_ext_bytestream_write_notify error|%d|", ret);
            return ret;
        }
        xqc_log(h3s->log, XQC_LOG_DEBUG, "|h3_ext_bytestream_write_notify|success|");
    }

    return XQC_OK;
}


ssize_t
xqc_h3_stream_process_control(xqc_h3_stream_t *h3s, unsigned char *data, size_t data_len)
{
    xqc_h3_conn_t *h3c = h3s->h3c;
    xqc_h3_frame_pctx_t *pctx = &h3s->pctx.frame_pctx;
    xqc_h3_frame_pl_t *pl = &pctx->frame.frame_payload;

    ssize_t processed = 0;
    while (processed < data_len) {
        ssize_t read = xqc_h3_frm_parse(data + processed, data_len - processed, pctx);
        if (read < 0) {
            xqc_h3_frm_reset_pctx(pctx);
            return read;
        }

        processed += read;

        if (pctx->state != XQC_H3_FRM_STATE_END && data_len != processed) {
            xqc_log(h3c->log, XQC_LOG_ERROR, "|parse frame state error|state:%d"
                    "|data_len:%uz|processed:%uz|type:%xL|len:%uz|consumed:%uz",
                    pctx->state, data_len, processed, pctx->frame.type,
                    pctx->frame.len, pctx->frame.consumed_len);
            xqc_h3_frm_reset_pctx(pctx);
            return -XQC_H3_DECODE_ERROR;
        }

        if (pctx->frame.type != XQC_H3_FRM_SETTINGS
            && !(h3s->h3c->flags & XQC_H3_CONN_FLAG_SETTINGS_RECVED))
        {
            xqc_h3_frm_reset_pctx(pctx);
            return -H3_FRAME_UNEXPECTED;
        }

        if (pctx->state == XQC_H3_FRM_STATE_END) {
            switch (pctx->frame.type) {
            case XQC_H3_FRM_CANCEL_PUSH:
                /* TODO: not implemented */
                break;

            case XQC_H3_FRM_SETTINGS:
                if (h3s->h3c->flags & XQC_H3_CONN_FLAG_SETTINGS_RECVED) {
                    xqc_h3_frm_reset_pctx(pctx);
                    return -H3_FRAME_UNEXPECTED;
                }

                h3s->h3c->flags |= XQC_H3_CONN_FLAG_SETTINGS_RECVED;

                if (xqc_h3_frm_parse_setting(pl->settings.setting, (void *)h3c) < 0) {
                    xqc_h3_frm_reset_pctx(pctx);
                    return -H3_SETTINGS_ERROR;
                }
                break;

            case XQC_H3_FRM_GOAWAY:
                if (h3c->goaway_stream_id > pl->goaway.stream_id.vi) {
                    h3c->goaway_stream_id = pl->goaway.stream_id.vi;

                } else {
                    xqc_log(h3c->log, XQC_LOG_WARN, "|xqc_h3_stream_process_control goaway_frame"
                            " receive bigger push id|push_id:%ui|",
                            pl->goaway.stream_id.vi);
                }
                h3s->h3c->flags |= XQC_H3_CONN_FLAG_GOAWAY_RECVD;
                break;

            case XQC_H3_FRM_MAX_PUSH_ID:
                /* PUSH related is not implemented yet */
                h3c->max_stream_id_recvd = pl->max_push_id.push_id.vi;
                break;

            default:
                /* ignore unknown h3 frame */
                xqc_log(h3c->log, XQC_LOG_INFO, "|ignore unknown frame|"
                        "type:%xL|", pctx->frame.type);
                break;
            }

            xqc_log_event(h3s->log, HTTP_FRAME_PARSED, h3s);
            if (pctx->frame.type == XQC_H3_FRM_SETTINGS) {
                xqc_log_event(h3c->log, HTTP_PARAMETERS_SET, h3c, XQC_LOG_REMOTE_EVENT);
            }
            xqc_h3_frm_reset_pctx(pctx);
        }
    }

    return processed;
}

ssize_t
xqc_h3_stream_process_push(xqc_h3_stream_t *h3s, unsigned char *data, size_t data_len)
{
    xqc_h3_frame_pctx_t *pctx = &h3s->pctx.frame_pctx;
    size_t processed = 0;

    while (processed < data_len) {
        ssize_t read = xqc_h3_frm_parse(data + processed, data_len - processed, pctx);
        if (read < 0) {
            xqc_h3_frm_reset_pctx(pctx);
            return read;
        }

        processed += read;

        if (pctx->state != XQC_H3_FRM_STATE_END && data_len != processed) {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|parse frame state error|state:%d||data_len:%uz|"
                    "processed:%uz|", pctx->state, data_len, processed);
            xqc_h3_frm_reset_pctx(pctx);
            return -XQC_H3_DECODE_ERROR;
        }

        if (pctx->state == XQC_H3_FRM_STATE_END) {
            switch (pctx->frame.type) {
            case XQC_H3_FRM_HEADERS:
                /* PUSH related is not implemented yet */
                break;
            case XQC_H3_FRM_DATA:
                /* PUSH related is not implemented yet */
                break;
            default:
                xqc_log(h3s->log, XQC_LOG_INFO, "|ignore unknown frame|"
                        "frame type:%xL|", pctx->frame.type);
                break;
            }
            xqc_log_event(h3s->log, HTTP_FRAME_PARSED, h3s);
            xqc_h3_frm_reset_pctx(pctx);
        }
    }

    return processed;
}

ssize_t
xqc_h3_stream_process_request(xqc_h3_stream_t *h3s, unsigned char *data, size_t data_len,
    xqc_bool_t fin_flag)
{
    if (h3s->h3r == NULL) {
        h3s->h3r = xqc_h3_request_create_inner(h3s->h3c, h3s, h3s->user_data);
        if (!h3s->h3r) {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|xqc_h3_request_create_inner error|");
            return -XQC_H3_ECREATE_REQUEST;
        }
    }

    if (data == NULL) {
        return -XQC_H3_EPARAM;
    }

    xqc_h3_frame_pctx_t *pctx = &h3s->pctx.frame_pctx;
    ssize_t processed = 0;
    ssize_t len = 0;
    xqc_int_t ret;
    xqc_bool_t blocked = XQC_FALSE;
    xqc_http_headers_t *hdrs = NULL;
    xqc_var_buf_t *buf;

    if (data_len == 0) {
        if (fin_flag) {
            /* process fin only */
            ret = xqc_h3_request_on_recv_empty_fin(h3s->h3r);
            if (ret < 0) {
                return ret;
            }
        }

        return 0;
    }

    /* process request bytes */
    while (processed < data_len) {
        xqc_log(h3s->log, XQC_LOG_DEBUG, "|parse frame|state:%d|data_len:%uz|process:%z|",
                pctx->state, data_len, processed);

        /* parse frame, mainly the type, length field */
        ssize_t read = xqc_h3_frm_parse(data + processed, data_len - processed, pctx);
        if (read < 0) {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|parse frame error|ret:%z|state:%d|frame_type:%xL|",
                    read, pctx->state, pctx->frame.type);
            xqc_h3_frm_reset_pctx(pctx);
            return read;
        }

        xqc_log(h3s->log, XQC_LOG_DEBUG, "|parse frame success|frame_type:%xL|len:%ui|read:%z|",
                pctx->frame.type, pctx->frame.len, read);
        processed += read;

        xqc_bool_t fin = pctx->state == XQC_H3_FRM_STATE_END ? XQC_TRUE : XQC_FALSE;

        /* begin to parse the payload of a frame */
        if (pctx->state >= XQC_H3_FRM_STATE_PAYLOAD) {
            switch (pctx->frame.type) {
            case XQC_H3_FRM_HEADERS:
                /* get headers memory for writing */
                hdrs = xqc_h3_request_get_writing_headers(h3s->h3r);
                if (NULL == hdrs) {
                    xqc_log(h3s->log, XQC_LOG_ERROR, "|get writing header error|");
                    XQC_H3_CONN_ERR(h3s->h3c, H3_GENERAL_PROTOCOL_ERROR, -XQC_H3_INVALID_HEADER);
                    return -XQC_H3_INVALID_HEADER;
                }

                len = xqc_min(pctx->frame.len - pctx->frame.consumed_len, data_len - processed);
                read = xqc_qpack_dec_headers(h3s->qpack, h3s->ctx, data + processed, len,
                                             hdrs, fin, &blocked);
                if (read < 0) {
                    xqc_log(h3s->log, XQC_LOG_ERROR, "|xqc_h3_stream_process_request error"
                            "|error frame type:%xL|", pctx->frame.type);
                    xqc_h3_frm_reset_pctx(pctx);
                    return -XQC_QPACK_SAVE_HEADERS_ERROR;
                }
                processed += read;
                pctx->frame.consumed_len += read;

                /* decode blocked, shall wait for dynamic table entries from encoder stream */
                if (blocked) {
                    /* shall not block again */
                    if ((h3s->flags & XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED)
                        || h3s->blocked_stream)
                    {
                        xqc_log(h3s->log, XQC_LOG_ERROR, "|stream blocked twice, peer's qpack "
                                "encoder violates protocol|stream_id:%ui|ric:%ui|ic:%ui|",
                                h3s->stream_id, xqc_qpack_get_req_rqrd_insert_cnt(h3s->ctx),
                                xqc_qpack_get_dec_insert_count(h3s->qpack));
                        XQC_H3_CONN_ERR(h3s->h3c, H3_GENERAL_PROTOCOL_ERROR, -XQC_H3_DECODE_ERROR);
                        return -XQC_H3_DECODE_ERROR;
                    }

                    xqc_log(h3s->log, XQC_LOG_DEBUG, "|request stream blocked|stream_id:%ui|",
                            h3s->stream_id);
                    xqc_log_event(h3s->log, QPACK_STREAM_STATE_UPDATED, h3s);

                    /* add blocked stream to h3 connection */
                    h3s->flags |= XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED;
                    h3s->blocked_stream = xqc_h3_conn_add_blocked_stream(
                        h3s->h3c, h3s, xqc_qpack_get_req_rqrd_insert_cnt(h3s->ctx));
                    if (h3s->blocked_stream == NULL) {
                        return -XQC_H3_BLOCKED_STREAM_EXCEED;
                    }

                    xqc_h3_request_blocked(h3s->h3r);

                    return processed;

                } else {
                    /* blocked before, unblock now */
                    if (h3s->flags & XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED) {
                        h3s->flags &= ~XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED;

                        /* remove blocked stream */
                        if (h3s->blocked_stream) {
                            xqc_h3_conn_remove_blocked_stream(h3s->h3c, h3s->blocked_stream);
                            h3s->blocked_stream = NULL;
                            xqc_h3_request_unblocked(h3s->h3r);
                        }
                    }
                }

                if (pctx->frame.len == pctx->frame.consumed_len) {
                    xqc_log_event(h3s->log, HTTP_FRAME_PARSED, h3s);
                    fin = 1;
                    h3s->h3r->compressed_header_recvd += pctx->frame.len;
                    xqc_h3_frm_reset_pctx(pctx);
                    xqc_qpack_clear_req_ctx(h3s->ctx);
                    if (fin_flag && processed == data_len) {
                        h3s->h3r->fin_flag = fin_flag;
                    }

                    ret = xqc_h3_request_on_recv_header(h3s->h3r);
                    if (ret != XQC_OK) {
                        xqc_log(h3s->log, XQC_LOG_ERROR, "|recv header error|%d|", ret);
                        return ret;
                    }
                }
                break;

            case XQC_H3_FRM_DATA:
                len = xqc_min(pctx->frame.len - pctx->frame.consumed_len, data_len - processed);
                buf = xqc_var_buf_create(len);
                if (buf == NULL) {
                    return -XQC_EMALLOC;
                }

                ret = xqc_var_buf_save_data(buf, data + processed, len);
                if (ret != XQC_OK) {
                    xqc_var_buf_free(buf);
                    xqc_h3_frm_reset_pctx(pctx);
                    return ret;
                }

                /* add data to buffer list */
                ret = xqc_list_buf_to_tail(&h3s->h3r->body_buf, buf);
                if (ret < 0) {
                    xqc_h3_frm_reset_pctx(pctx);
                    return ret;
                }
                h3s->h3r->body_buf_count++;

                processed += len;
                pctx->frame.consumed_len += len;

                xqc_h3_request_body_begin(h3s->h3r);

                if (pctx->frame.len == pctx->frame.consumed_len) {
                    fin = 1;
                    if (fin_flag && processed == data_len) {
                        h3s->h3r->fin_flag = fin_flag;
                    }
                }
                break;

            case XQC_H3_FRM_PUSH_PROMISE:
                /* PUSH related is not implemented yet */
                break;

            default:
                xqc_log(h3s->log, XQC_LOG_INFO, "|ignore unknown frame|"
                        "frame type:%xL|", pctx->frame.type);
                break;
            }

            if (fin) {
                xqc_log_event(h3s->log, HTTP_FRAME_PARSED, h3s);
                xqc_h3_frm_reset_pctx(pctx);
            }
        }
    }

    return processed;
}

ssize_t
xqc_h3_stream_process_bytestream(xqc_h3_stream_t *h3s, 
    unsigned char *data, size_t data_len,
    xqc_bool_t fin_flag)
{

    if (data == NULL) {
        return -XQC_H3_EPARAM;
    }

    xqc_h3_frame_pctx_t *pctx = &h3s->pctx.frame_pctx;
    ssize_t processed = 0;
    ssize_t len = 0;
    xqc_int_t ret;
    xqc_h3_ext_bytestream_data_buf_t *buf;

    /* process bytestream bytes */
    while (processed < data_len) {
        xqc_log(h3s->log, XQC_LOG_DEBUG, "|parse frame|state:%d|data_len:%uz|process:%z|",
                pctx->state, data_len, processed);

        /* parse frame, mainly the type, length field */
        ssize_t read = xqc_h3_frm_parse(data + processed, data_len - processed, pctx);
        if (read < 0) {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|parse frame error|ret:%z|state:%d|frame_type:%xL|",
                    read, pctx->state, pctx->frame.type);
            xqc_h3_frm_reset_pctx(pctx);
            return read;
        }

        xqc_log(h3s->log, XQC_LOG_DEBUG, "|parse frame success|frame_type:%xL|len:%ui|read:%z|",
                pctx->frame.type, pctx->frame.len, read);
        processed += read;

        xqc_bool_t fin = pctx->state == XQC_H3_FRM_STATE_END ? XQC_TRUE : XQC_FALSE;

        /* begin to parse the payload of a frame */
        if (pctx->state >= XQC_H3_FRM_STATE_PAYLOAD) {
            switch (pctx->frame.type) {
            case XQC_H3_FRM_HEADERS:
                /* ignore header frames */
                len = xqc_min(pctx->frame.len - pctx->frame.consumed_len, data_len - processed);
                processed += len;
                pctx->frame.consumed_len += len;
                if (pctx->frame.len == pctx->frame.consumed_len) {
                    fin = 1;
                }
                break;
            
            case XQC_H3_FRM_DATA:
                buf = xqc_h3_ext_bytestream_get_last_data_buf(h3s->h3_ext_bs, pctx);
                if (buf == NULL) {
                    xqc_h3_frm_reset_pctx(pctx);
                    return -XQC_EMALLOC;
                }

                len = xqc_min(pctx->frame.len - pctx->frame.consumed_len, data_len - processed);
                ret = xqc_h3_ext_bytestream_save_data_to_buf(buf, data + processed, len);
                if (ret != XQC_OK) {
                    xqc_h3_frm_reset_pctx(pctx);
                    return ret;
                }


                processed += len;
                pctx->frame.consumed_len += len;

                xqc_h3_ext_bytestream_recv_begin(h3s->h3_ext_bs);

                if (pctx->frame.len == pctx->frame.consumed_len) {
                    fin = 1;
                    buf->end_time = xqc_monotonic_timestamp();
                }
                break;
            
            default:
                xqc_log(h3s->log, XQC_LOG_INFO, "|ignore unexpected frame|"
                        "frame type:%xL|", pctx->frame.type);
                break;
            }

            if (fin) {
                xqc_log_event(h3s->log, HTTP_FRAME_PARSED, h3s);
                xqc_h3_frm_reset_pctx(pctx);
            }
        }
    }

    return processed;
}


ssize_t
xqc_h3_stream_process_uni_stream_type(const uint8_t *data, size_t data_len, 
    xqc_discrete_int_pctx_t *vctx, xqc_bool_t *fin)
{
    /* parse stream type */
    ssize_t nread = xqc_discrete_vint_parse(data, data_len, vctx, fin);
    if (nread < 0) {
        return -XQC_H3_DECODE_ERROR;
    }

    return nread;
}


/* process uni stream payload */
ssize_t
xqc_h3_stream_process_uni_payload(xqc_h3_stream_t *h3s, unsigned char *data, size_t data_len)
{
    ssize_t processed = 0;
    xqc_log(h3s->log, XQC_LOG_DEBUG, "|xqc_h3_stream_process_uni_payload|type:%d|sz:%uz|",
            h3s->type, data_len);

    switch (h3s->type) {
    case XQC_H3_STREAM_TYPE_CONTROL:
        processed = xqc_h3_stream_process_control(h3s, data, data_len);
        break;

    case XQC_H3_STREAM_TYPE_PUSH:
        processed = xqc_h3_stream_process_push(h3s, data, data_len);
        break;

    case XQC_H3_STREAM_TYPE_QPACK_ENCODER:
        processed = xqc_qpack_process_encoder(h3s->qpack, data, data_len);
        break;

    case XQC_H3_STREAM_TYPE_QPACK_DECODER:
        processed = xqc_qpack_process_decoder(h3s->qpack, data, data_len);
        break;

    /* bytes from reserved stream type will be ignored */
    default:
        processed = data_len;
        break;
    }

    return processed;
}


ssize_t
xqc_h3_stream_process_uni(xqc_h3_stream_t *h3s, unsigned char *data, size_t data_len)
{
    ssize_t processed = 0;

    /* uni-stream header indicates stream type, parse stream type */
    if (!(h3s->flags & XQC_HTTP3_STREAM_FLAG_TYPE_IDENTIFIED)) {
        xqc_bool_t fin = XQC_FALSE;  /* finish flag of parse stream type */
        ssize_t read = xqc_h3_stream_process_uni_stream_type(data + processed, data_len - processed,
                                                             &h3s->pctx.type, &fin);
        if (read < 0) {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|parse uni-stream type error|ret:%ui|", read);
            return read;
        }
        processed += read;

        /* exception, parsing not finished while bytes remaining */
        if (!fin && processed != data_len) {
            xqc_log(h3s->log, XQC_LOG_ERROR,
                    "|parse uni-stream type state error|ret:%ui", processed);
            XQC_H3_CONN_ERR(h3s->h3c, H3_FRAME_ERROR, -XQC_H3_DECODE_ERROR);
            return -XQC_H3_DECODE_ERROR;
        }

        if (fin) {
            /* check legitimation of uni-stream */
            h3s->type = h3s->pctx.type.vi;
            h3s->flags |= XQC_HTTP3_STREAM_FLAG_TYPE_IDENTIFIED;
            xqc_discrete_int_pctx_clear(&h3s->pctx.type);
            xqc_log_event(h3s->log, HTTP_STREAM_TYPE_SET, h3s, XQC_LOG_REMOTE_EVENT);

            if (xqc_h3_conn_on_uni_stream_created(h3s->h3c, h3s->type) != XQC_OK) {
                return -XQC_H3_INVALID_STREAM;
            }
        }
    }

    if (data_len != processed) {
        /* deliver data to modules which is concerned */
        ssize_t read = xqc_h3_stream_process_uni_payload(h3s, data + processed,
                                                         data_len - processed);
        if (read < 0 || read + processed != data_len) {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|error processing uni-stream payload|type:%d|"
                    "sz:%uz|processed:%z|", h3s->type, data_len, read);
            return -XQC_H3_DECODE_ERROR;
        }
        processed += read;
    }

    return processed;
}


/* process bidi stream payload */
ssize_t
xqc_h3_stream_process_bidi_payload(xqc_h3_stream_t *h3s, unsigned char *data, size_t data_len,
    xqc_bool_t fin_flag)
{
    ssize_t processed = 0;
    switch (h3s->type) {
    case XQC_H3_STREAM_TYPE_REQUEST:
        processed = xqc_h3_stream_process_request(h3s, data, data_len, fin_flag);
        break;

    case XQC_H3_STREAM_TYPE_BYTESTEAM:
        //TODO: process bytestream 
        processed = xqc_h3_stream_process_bytestream(h3s, data, data_len, fin_flag);
        break; 

    /* bytes from reserved stream type will be ignored */
    default:
        processed = data_len;
        break;
    }

    return processed;
}

xqc_int_t
xqc_h3_stream_create_inner_request_stream(xqc_h3_stream_t *h3s)
{
    if (h3s->h3r && h3s->type == XQC_H3_STREAM_TYPE_UNKNOWN) {
        // if the request is already created for a stream with unknown type, 
        // we should return an error.
        xqc_log(h3s->log, XQC_LOG_ERROR, 
                "|xqc_h3_request already exist in an h3 stream with unknown type|"
                "stream_id:%ui|", h3s->stream_id);
        return -XQC_H3_ECREATE_REQUEST;
    }

    if (h3s->h3r == NULL) {
        h3s->h3r = xqc_h3_request_create_inner(h3s->h3c, h3s, NULL);
        if (!h3s->h3r) {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|xqc_h3_request_create_inner error|");
            return -XQC_H3_ECREATE_REQUEST;
        }

        h3s->type = XQC_H3_STREAM_TYPE_REQUEST;
    }

    return XQC_OK;  
}

xqc_int_t
xqc_h3_stream_create_inner_bytestream(xqc_h3_stream_t *h3s)
{
    if (h3s->h3_ext_bs && h3s->type == XQC_H3_STREAM_TYPE_UNKNOWN) {
        // if the bytestream is already created for a stream with unknown type, 
        // we should return an error.
        xqc_log(h3s->log, XQC_LOG_ERROR, 
                "|xqc_h3_ext_bytestream already exist in an h3 stream with unknown type|"
                "stream_id:%ui|", h3s->stream_id);
        return -XQC_H3_ECREATE_BYTESTREAM;
    }

    if (h3s->h3_ext_bs == NULL) {
        h3s->h3_ext_bs = xqc_h3_ext_bytestream_create_passive(h3s->h3c, h3s, NULL);
        if (!h3s->h3_ext_bs) {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|xqc_h3_ext_bytestream_create_passive error|");
            return -XQC_H3_ECREATE_BYTESTREAM;
        }

        h3s->type = XQC_H3_STREAM_TYPE_BYTESTEAM;
    }

    return XQC_OK;  
}


ssize_t
xqc_h3_stream_process_bidi_type_unknown(xqc_h3_stream_t *h3s, 
    unsigned char *data, size_t data_len,
    xqc_bool_t fin_flag)
{
    if (data == NULL) {
        return -XQC_H3_EPARAM;
    }

    xqc_h3_frame_pctx_t *pctx = &h3s->pctx.frame_pctx;
    ssize_t processed = 0;
    xqc_int_t ret = 0;
    xqc_h3_bidi_stream_type_t bidi_stream_type = 0;

    /* trying to parse the first frame */
    xqc_log(h3s->log, XQC_LOG_DEBUG, "|parse frame|state:%d|data_len:%uz|process:%z|",
            pctx->state, data_len, processed);

    /* parse frame, mainly the type, length field */
    ssize_t read = xqc_h3_frm_parse(data + processed, data_len - processed, pctx);
    if (read < 0) {
        xqc_log(h3s->log, XQC_LOG_ERROR, "|parse frame error|ret:%z|state:%d|frame_type:%xL|",
                read, pctx->state, pctx->frame.type);
        xqc_h3_frm_reset_pctx(pctx);
        return read;
    }

    processed += read;

    xqc_bool_t fin = pctx->state == XQC_H3_FRM_STATE_END ? XQC_TRUE : XQC_FALSE;

    if (pctx->state >= XQC_H3_FRM_STATE_LEN) {
        /* the type of the 1st frame is determined */
        xqc_log(h3s->log, XQC_LOG_DEBUG, "|parse frame type success|frame_type:%xL|read:%z|",
                pctx->frame.type, read);
        
        if (pctx->frame.type != XQC_H3_EXT_FRM_BIDI_STREAM_TYPE) {
            /* the first frame is not BIDI_STREAM_TYPE */
            ret = xqc_h3_stream_create_inner_request_stream(h3s);

        } else {
            /* the first frame is BIDI_STREAM_TYPE, and it is parsed */
            if (fin) {
                bidi_stream_type = pctx->frame.frame_payload.stream_type.stream_type.vi;
                xqc_log(h3s->log, XQC_LOG_DEBUG, 
                        "|read bidi_stream_type from BIDI_STREAM_TYPE frame|"
                        "bidi_stream_type:%d|",
                        bidi_stream_type);
                switch (bidi_stream_type) {
                case XQC_H3_BIDI_STREAM_TYPE_REQUEST: 
                    ret = xqc_h3_stream_create_inner_request_stream(h3s);
                    break;
                case XQC_H3_BIDI_STREAM_TYPE_BYTESTREAM:
                    //TODO: create byte stream
                    ret = xqc_h3_stream_create_inner_bytestream(h3s);
                    break;
                default:
                    xqc_log(h3s->log, XQC_LOG_ERROR, 
                            "|unexpected bidi stream type|"
                            "bidi_stream_type:%ui|",
                            bidi_stream_type);
                    ret = -XQC_H3_INVALID_BIDI_STREAM_TYPE;
                    break;
                }
            }
        }

        if (ret != XQC_OK) {
            xqc_h3_frm_reset_pctx(pctx);
            return ret;
        }   
    }

    if (processed == data_len && fin_flag 
        && h3s->type == XQC_H3_STREAM_TYPE_UNKNOWN) 
    {
        // if we have received a fin_flag while the type of stream is still undetermined
        // we treat the stream as a request stream
        ret = xqc_h3_stream_create_inner_request_stream(h3s);
        if (ret != XQC_OK) {
            xqc_h3_frm_reset_pctx(pctx);
            return ret;
        }
    }

    if (fin) {
        xqc_log_event(h3s->log, HTTP_FRAME_PARSED, h3s);
        xqc_h3_frm_reset_pctx(pctx);
    }

    return processed;
}

ssize_t
xqc_h3_stream_process_bidi(xqc_h3_stream_t *h3s, unsigned char *data, size_t data_len,
    xqc_bool_t fin_flag)
{
    ssize_t processed = 0, total_processed = 0;

    if (h3s->flags & XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED) {
        return 0;
    }

    xqc_log(h3s->log, XQC_LOG_DEBUG, 
                "|xqc_h3_stream_process_bidi|%uz|%d|", 
                data_len, fin_flag);

    /* 
     * TODO: if the stream type is unknown, 
     * we parse the first H3 frame to decide what type the stream is 
     */

    if (XQC_H3_STREAM_TYPE_UNKNOWN == h3s->type) {
        if (h3s->h3c->flags & XQC_H3_CONN_FLAG_EXT_ENABLED) {
            processed = xqc_h3_stream_process_bidi_type_unknown(h3s, data, data_len, fin_flag);

        } else {
            /* MUST set the stream type to h3 request */
            processed = xqc_h3_stream_create_inner_request_stream(h3s);
        }
    }

    if (processed < 0) {
        xqc_log(h3s->log, XQC_LOG_ERROR, 
                "|xqc_h3_stream_process_bidi_type_unknown error|%z|", 
                processed);
        return processed;
    }

    total_processed += processed;
  
    processed =  xqc_h3_stream_process_bidi_payload(h3s, data + processed, data_len - processed, fin_flag);
    if (processed < 0) {
        return processed;
    }

    total_processed += processed;

    return total_processed;
}


xqc_int_t
xqc_h3_stream_process_in(xqc_h3_stream_t *h3s, unsigned char *data, size_t data_len,
    xqc_bool_t fin_flag)
{
    ssize_t processed = 0;
    xqc_h3_conn_t *h3c = h3s->h3c;
    xqc_int_t errcode = XQC_OK;

    /* nothing to process */
    if (data_len == 0 && !fin_flag) {
        return XQC_OK;
    }

    xqc_log(h3c->log, XQC_LOG_DEBUG, "|stream_id:%ui|h3_stream_type:%d|data_size:%uz|fin:%ud",
            h3s->stream_id, h3s->type, data_len, (unsigned int)fin_flag);

    if (xqc_stream_is_uni(h3s->stream_id)) {
        /* process uni stream bytes */
        processed = xqc_h3_stream_process_uni(h3s, data, data_len);
        if (processed < 0 || processed != data_len) {
            xqc_log(h3c->log, XQC_LOG_ERROR, "|xqc_h3_stream_process_uni error|processed:%z"
                    "|size:%uz|stream_id:%ui|", processed, data_len, h3s->stream_id);

            XQC_H3_CONN_ERR(h3c, H3_FRAME_ERROR, -XQC_H3_EPROC_CONTROL);
            return -XQC_H3_EPROC_CONTROL;
        }

        xqc_log(h3c->log, XQC_LOG_DEBUG, "|xqc_h3_stream_process_uni|%z|", processed);

    } else {
        /* process bidi stream bytes */
        processed = xqc_h3_stream_process_bidi(h3s, data, data_len, fin_flag);
        if (processed < 0) {
            /* error occurred */
            xqc_log(h3c->log, XQC_LOG_ERROR, "|xqc_h3_stream_process_bidi|%z|", processed);

            errcode = -XQC_H3_EPROC_REQUEST;

            if (h3s->type == XQC_H3_STREAM_TYPE_BYTESTEAM) {
                errcode = -XQC_H3_EPROC_BYTESTREAM;
            }
            
            if (processed == -XQC_H3_INVALID_HEADER) {
                XQC_H3_CONN_ERR(h3c, H3_GENERAL_PROTOCOL_ERROR, errcode);

            } else {
                XQC_H3_CONN_ERR(h3c, H3_FRAME_ERROR, errcode);
            }

            // TODO: define an errorcode for bytstream?
            return errcode;

        } else if (processed != data_len) {
            /* if not all bytes are processed, the decoder shall be blocked */
            if (!(h3s->flags & XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED)) {
                xqc_log(h3c->log, XQC_LOG_ERROR, "|h3_stream is not blocked|processed:%ui|"
                        "data_len:%ui", processed, data_len);
                return XQC_ERROR;
            }

            /* if blocked, store data in blocked buffer */
            xqc_var_buf_t *buf = xqc_var_buf_create(XQC_DATA_BUF_SIZE_4K);
            if (buf == NULL) {
                return -XQC_H3_EMALLOC;
            }
            xqc_int_t ret = xqc_var_buf_save_data(buf, data + processed, data_len - processed);
            if (ret != XQC_OK) {
                xqc_var_buf_free(buf);
                return ret;
            }

            /* add remained data to blocked buf list */
            ret = xqc_list_buf_to_tail(&h3s->blocked_buf, buf);
            if (ret < 0) {
                xqc_var_buf_free(buf);
                return ret;
            }
        }
    }

    return XQC_OK;
}


xqc_var_buf_t *
xqc_h3_stream_get_buf(xqc_h3_stream_t *h3s, xqc_list_head_t *head, size_t expected_size)
{
    xqc_var_buf_t *buf = NULL;

    if (!xqc_list_empty(head)) {
        /* the last in list */
        xqc_list_buf_t *list_buf = xqc_list_entry(head->prev, xqc_list_buf_t, list_head);
        buf = list_buf->buf;

        /* reuse the last buf until it is fully used */
        if (buf->data_len == buf->buf_len) {
            buf = NULL;
        }
    }

    /* can't find a buf, or can't reuse a buf, create a new one  */
    if (buf == NULL) {
        /* no memory buffer or the last is full, create a new one */
        buf = xqc_var_buf_create(expected_size);
        if (buf == NULL) {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|create buf error|");
            return NULL;
        }

        xqc_int_t ret = xqc_list_buf_to_tail(head, buf);
        if (ret < 0) {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|add new buf to blocked buf error|ret:%d", ret);
            xqc_var_buf_free(buf);
            return NULL;
        }
    }

    return buf;
}


xqc_int_t
xqc_h3_stream_process_blocked_data(xqc_stream_t *stream, xqc_h3_stream_t *h3s, xqc_bool_t *fin)
{
    ssize_t         rcvd = 0;
    xqc_var_buf_t  *buf = NULL;

    do
    {
        buf = xqc_h3_stream_get_buf(h3s, &h3s->blocked_buf, XQC_DATA_BUF_SIZE_4K);
        if (buf == NULL) {
            return -XQC_EMALLOC;
        }

        /* recv from transport stream, and buffer data to blocked buf list */
        rcvd = xqc_stream_recv(stream, buf->data + buf->data_len, 
                               buf->buf_len - buf->data_len, fin);
        if (rcvd == -XQC_EAGAIN) {
            break;

        } else if (rcvd < 0) {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|xqc_stream_recv error|%z|", rcvd);
            return -XQC_H3_STREAM_RECV_ERROR;
        }

        xqc_log(h3s->log, XQC_LOG_DEBUG, "|xqc_stream_recv|read:%z|fin:%ud|", rcvd, (unsigned int)*fin);

        buf->data_len += rcvd;
        buf->fin_flag = *fin;

        if (*fin) {
            h3s->flags |= XQC_HTTP3_STREAM_FLAG_READ_EOF;

            if (h3s->type == XQC_H3_STREAM_TYPE_REQUEST) {
                /* only request stream will be blocked */
                xqc_h3_request_stream_fin(h3s->h3r);
            }
        }

    } while (buf->buf_len == buf->data_len && !*fin);

    return XQC_OK;
}


xqc_int_t
xqc_h3_stream_process_data(xqc_stream_t *stream, xqc_h3_stream_t *h3s, xqc_bool_t *fin)
{
    xqc_int_t       ret;
    ssize_t         read;
    xqc_h3_conn_t  *h3c = (xqc_h3_conn_t *)stream->stream_conn->proto_data;
    unsigned char   buff[XQC_DATA_BUF_SIZE_4K];
    size_t          buff_size = XQC_DATA_BUF_SIZE_4K;
    uint64_t        insert_cnt = xqc_qpack_get_dec_insert_count(h3s->qpack);

    do
    {
        /* recv data from transport stream */
        read = xqc_stream_recv(h3s->stream, buff, buff_size, fin);
        if (read == -XQC_EAGAIN) {
            return XQC_OK;

        } else if (read < 0) {
            xqc_log(h3c->log, XQC_LOG_ERROR, "|xqc_stream_recv error|%z|", read);
            return -XQC_H3_STREAM_RECV_ERROR;
        }
        xqc_log(h3c->log, XQC_LOG_DEBUG, "|xqc_stream_recv|read:%z|fin:%ud|", read, (unsigned int)*fin);

        if (*fin) {
            h3s->flags |= XQC_HTTP3_STREAM_FLAG_READ_EOF;

            if (h3s->type == XQC_H3_STREAM_TYPE_REQUEST) {
                /* only request stream will be blocked */
                xqc_h3_request_stream_fin(h3s->h3r);
                xqc_h3_stream_update_stats(h3s);
            }
        }

        /* process h3 stream data */
        ret = xqc_h3_stream_process_in(h3s, buff, read, *fin);
        if (ret != XQC_OK) {
            xqc_log(h3c->log, XQC_LOG_ERROR, "|xqc_h3_stream_process_in error|%d|", ret);
            XQC_H3_CONN_ERR(h3s->h3c, H3_INTERNAL_ERROR, ret);
            return ret;
        }

        /* after process in, the stream might be blocked, read all data and add to blocked list */
        if (h3s->flags & XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED) {
            return xqc_h3_stream_process_blocked_data(stream, h3s, fin);
        }

    } while (read == buff_size && !*fin);

    if (*fin) {
        if (h3s->type == XQC_H3_STREAM_TYPE_REQUEST) {
            h3s->h3r->fin_flag = *fin;

        } else if (h3s->type == XQC_H3_STREAM_TYPE_BYTESTEAM) {
            //TODO: mark the fin flag of the bytestream and record time
            xqc_h3_ext_bytestream_fin_rcvd(h3s->h3_ext_bs);
            xqc_h3_ext_bytestream_set_fin_rcvd_flag(h3s->h3_ext_bs);
        }    
    }

    if (xqc_qpack_get_dec_insert_count(h3s->qpack) > insert_cnt) {
        ret = xqc_h3_conn_process_blocked_stream(h3s->h3c);
        if (ret != XQC_OK) {
            xqc_log(h3c->log, XQC_LOG_ERROR, "|xqc_h3_conn_process_blocked_stream error|ret:%d|"
                    "stream_id:%ui", ret, h3s->stream_id);
            return ret;
        }
    }

    return XQC_OK;
}


xqc_int_t
xqc_h3_stream_process_blocked_stream(xqc_h3_stream_t *h3s)
{
    xqc_list_head_t *pos, *next;
    xqc_list_buf_t  *list_buf = NULL;

    xqc_log(h3s->log, XQC_LOG_DEBUG,
            "|decode blocked header success|stream_id:%ui|", h3s->stream_id);
    xqc_log_event(h3s->log, QPACK_STREAM_STATE_UPDATED, h3s);

    h3s->ref_cnt++;

    xqc_list_for_each_safe(pos, next, &h3s->blocked_buf) {
        list_buf = xqc_list_entry(pos, xqc_list_buf_t, list_head);

        xqc_var_buf_t *buf = list_buf->buf;
        ssize_t processed = xqc_h3_stream_process_request(h3s, buf->data + buf->consumed_len,
                                                          buf->data_len - buf->consumed_len, buf->fin_flag);
        if (processed < 0) {
            h3s->ref_cnt--;
            return processed;
        }
        buf->consumed_len += processed;

        if (buf->consumed_len == buf->data_len) {
            xqc_list_buf_free(list_buf);

        } else {
            h3s->ref_cnt--;
            return XQC_OK;
        }
    }

    /* notify DATA to application ASAP */
    if (h3s->type == XQC_H3_STREAM_TYPE_REQUEST
        && !xqc_list_empty(&h3s->h3r->body_buf))
    {
        /* notify DATA whenever there is data */
        xqc_int_t ret = xqc_h3_request_on_recv_body(h3s->h3r);
        if (ret != XQC_OK) {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|recv body error|%d|", ret);
            h3s->ref_cnt--;
            return ret;
        }
    }

    h3s->ref_cnt--;

    /*
     * Blocked h3 stream will be delayed to destroy when stream was closed while all bytes are read.
     * Hence, if the h3 stream is unblocked, h3 stream shall be destroyed after processing.
     * 
     * NOTICE: if there is a trailer section, h3 stream might be blocked again. If it will be
     * unblocked again, it will be destroyed after all bytes processed; If the connection is closed,
     * it will be destroyed when h3 connection destroy the blocked stream list.
     */
    if ((h3s->flags & XQC_HTTP3_STREAM_FLAG_CLOSED)
        && h3s->blocked_stream == NULL && h3s->ref_cnt == 0)
    {
        /* QUIC transport stream was closed while h3_stream was being blocked, destroy h3_stream */
        xqc_log(h3s->log, XQC_LOG_INFO, "|h3 stream unblocked and destroyed while transport stream"
                " was closed|stream_id:%ui", h3s->stream_id);
        xqc_h3_stream_destroy(h3s);
        return XQC_OK;
    }

    return XQC_OK;
}


xqc_int_t
xqc_h3_stream_create_notify(xqc_stream_t *stream, void *user_data)
{
    xqc_connection_t *conn = stream->stream_conn;
    xqc_h3_conn_t    *h3c = conn->proto_data;
    
    /* do not accept server initiated bidirectional streams at client */
    if (conn->conn_type == XQC_CONN_TYPE_CLIENT
        && stream->stream_type == XQC_SVR_BID)
    {
        /* xquic do not support server-inited bidi stream, return error and
           discard all subsequent stream data */
        xqc_log(h3c->log, XQC_LOG_ERROR, 
                "|ignore server initiated bidi-streams at client|");
        return -XQC_ECREATE_STREAM;
    }

    return XQC_OK;
}



int
xqc_h3_stream_read_notify(xqc_stream_t *stream, void *user_data)
{
    xqc_int_t ret;

    xqc_h3_stream_t *h3s;
    xqc_h3_conn_t   *h3c = (xqc_h3_conn_t *)stream->stream_conn->proto_data;

    /* server h3_stream might not be created yet */
    if (!user_data) {
        h3s = xqc_h3_stream_create(h3c, stream, XQC_H3_STREAM_TYPE_UNKNOWN, NULL);
        if (!h3s) {
            xqc_log(h3c->log, XQC_LOG_ERROR, "|xqc_h3_stream_create error|");
            return -XQC_H3_ECREATE_STREAM;
        }

        xqc_log(h3c->log, XQC_LOG_DEBUG, "|create h3stream|stream_id:%ui", stream->stream_id);

    } else {
        h3s = (xqc_h3_stream_t *)user_data;
    }

    /* in case that read notify */
    if (h3s->flags & XQC_HTTP3_STREAM_IN_READING) {
        xqc_log(h3c->log, XQC_LOG_ERROR, "|read again|stream_id:%ui|", stream->stream_id);
        return XQC_OK;
    }
    h3s->flags |= XQC_HTTP3_STREAM_IN_READING;

    /* check goaway */
    if (xqc_h3_conn_is_goaway_recved(h3c, stream->stream_id) == XQC_TRUE) {
        /*
         * peer sent goaway and keep on sending data, 
         * stop it with STOP_SENDING frame 
         */
        ret = xqc_write_stop_sending_to_packet(h3c->conn, stream, H3_REQUEST_CANCELLED);
        if (ret != XQC_OK) {
            xqc_log(h3c->log, XQC_LOG_ERROR, "|xqc_write_stop_sending_to_packet error|%d|", ret);
            h3s->flags &= ~XQC_HTTP3_STREAM_IN_READING;
            return ret;
        }

        h3s->flags &= ~XQC_HTTP3_STREAM_IN_READING;
        return XQC_OK;
    }

    xqc_bool_t fin = XQC_FALSE;
    /* if stream is blocked, recv and buffer data */
    if (h3s->flags & XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED) {
        ret = xqc_h3_stream_process_blocked_data(stream, h3s, &fin);

        h3s->flags &= ~XQC_HTTP3_STREAM_IN_READING;
        if (ret == -XQC_H3_STREAM_RECV_ERROR) {
            return XQC_OK;
        } else if (ret != XQC_OK) {
            xqc_log(h3c->log, XQC_LOG_ERROR, "|xqc_h3_stream_process_blocked_data error|%d|", ret);
            return ret;
        }

    } else {
        /* if stream is not blocked, recv data and process */
        ret = xqc_h3_stream_process_data(stream, h3s, &fin);

        h3s->flags &= ~XQC_HTTP3_STREAM_IN_READING;
        if (ret == -XQC_H3_STREAM_RECV_ERROR) {
            return XQC_OK;
        } else if (ret != XQC_OK) {
            xqc_log(h3c->log, XQC_LOG_ERROR, "|xqc_h3_stream_process_data error|%d|", ret);
            return ret;
        }

        /* REQUEST: notify DATA to application ASAP */
        if (h3s->type == XQC_H3_STREAM_TYPE_REQUEST
            && !xqc_list_empty(&h3s->h3r->body_buf))
        {
            /* notify DATA whenever there is data */
            ret = xqc_h3_request_on_recv_body(h3s->h3r);
            if (ret != XQC_OK) {
                xqc_log(h3s->log, XQC_LOG_ERROR, "|recv body error|%d|", ret);
                return ret;
            }
        }

        /* TODO: BYTESTRAM: notify DATA to application ASAP */
        if (h3s->type == XQC_H3_STREAM_TYPE_BYTESTEAM
            && xqc_h3_ext_bytestream_should_notify_read(h3s->h3_ext_bs))
        {
            ret = xqc_h3_ext_bytestream_notify_read(h3s->h3_ext_bs);
            if (ret < 0) {
                xqc_log(h3s->log, XQC_LOG_ERROR, "|recv bytestream error|%d|", ret);
                return ret;
            }
        }
    }

    xqc_log(h3c->log, XQC_LOG_DEBUG, "|success|stream_id:%ui|conn:%p|",
            h3s->stream_id, h3c->conn);

    return XQC_OK;
}

void
xqc_h3_stream_update_stats(xqc_h3_stream_t *h3s)
{
    if (h3s->stream == NULL) {
        return;
    }

    if (h3s->type == XQC_H3_STREAM_TYPE_REQUEST) {
        h3s->h3r->stream_fin_send_time = h3s->stream->stream_stats.local_fin_snd_time;
        h3s->h3r->stream_fst_fin_snd_time = h3s->stream->stream_stats.local_fst_fin_snd_time;
        h3s->h3r->stream_fin_ack_time = h3s->stream->stream_stats.first_fin_ack_time;
        h3s->h3r->send_cwnd_blk_cnt = h3s->stream->stream_stats.send_cwnd_blk_cnt;
        h3s->h3r->sched_cwnd_blk_cnt = h3s->stream->stream_stats.sched_cwnd_blk_cnt;
        h3s->h3r->send_pacing_blk_cnt = h3s->stream->stream_stats.send_pacing_blk_cnt;
        h3s->h3r->send_cwnd_blk_duration = h3s->stream->stream_stats.send_cwnd_blk_duration;
        h3s->h3r->sched_cwnd_blk_duration = h3s->stream->stream_stats.sched_cwnd_blk_duration;
        h3s->h3r->send_pacing_blk_duration = h3s->stream->stream_stats.send_pacing_blk_duration;
        h3s->h3r->retrans_pkt_cnt = h3s->stream->stream_stats.retrans_pkt_cnt;
        h3s->h3r->stream_fst_pkt_snd_time = h3s->stream->stream_stats.first_snd_time;
        h3s->h3r->stream_fst_pkt_rcv_time = h3s->stream->stream_stats.first_rcv_time;
    }

    h3s->send_offset = h3s->stream->stream_send_offset;
    h3s->recv_offset = h3s->stream->stream_data_in.merged_offset_end;

    if (h3s->h3c == NULL) {
        return;
    }

    xqc_connection_t *conn = xqc_h3_conn_get_xqc_conn(h3s->h3c);

    if (conn == NULL) {
        return;
    }
    
    if (h3s->stream->stream_flag & XQC_STREAM_FLAG_HAS_0RTT) {
        if (conn->conn_flag & XQC_CONN_FLAG_0RTT_OK) {
            h3s->early_data_state = 1;

        } else {
            h3s->early_data_state = 2;
        }
    }
}

int
xqc_h3_stream_close_notify(xqc_stream_t *stream, void *user_data)
{
    if (!(stream->stream_flag & XQC_STREAM_FLAG_HAS_H3)) {
        xqc_log(stream->stream_conn->log, XQC_LOG_DEBUG,
                "|has no h3 stream|stream_id:%ui", xqc_stream_id(stream));
        return XQC_OK;
    }

    xqc_h3_stream_t *h3s = (xqc_h3_stream_t*)user_data;
    h3s->flags |= XQC_HTTP3_STREAM_FLAG_CLOSED;
    xqc_h3_stream_get_err(h3s);
    xqc_h3_stream_get_path_info(h3s);

    if (h3s->h3r && h3s->type == XQC_H3_STREAM_TYPE_REQUEST) {
        h3s->h3r->stream_close_msg = h3s->stream->stream_close_msg;
        xqc_h3_stream_update_stats(h3s);
    }

    if (h3s->h3_ext_bs && h3s->type == XQC_H3_STREAM_TYPE_BYTESTEAM) {
        //TODO: record stats info
        xqc_h3_ext_bytestream_save_stats_from_stream(h3s->h3_ext_bs, h3s->stream);
    }

    xqc_memcpy(h3s->begin_trans_state, stream->begin_trans_state, XQC_STREAM_TRANSPORT_STATE_SZ);
    xqc_memcpy(h3s->end_trans_state, stream->end_trans_state, XQC_STREAM_TRANSPORT_STATE_SZ);

    h3s->stream = NULL;     /* stream closed, MUST NOT use it any more */

    /*
     * transport stream will automatically close itself after all stream data was received by h3
     * stream. under this situation, blocked h3_stream shall wait for encoder stream insertions.
     * otherwise, the h3_stream shall be destroyed.
     */
    if (!(h3s->flags & XQC_HTTP3_STREAM_FLAG_ACTIVELY_CLOSED)
        && (h3s->flags & XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED)
        && (h3s->flags & XQC_HTTP3_STREAM_FLAG_READ_EOF))
    {
        /* 
         * if stream closed passively, while h3 stream received all data 
         * and is waiting for encoder stream, will delay the destruction 
         */
        xqc_log(h3s->log, XQC_LOG_INFO, "|transport stream close while blocked and fin, "
                "will delay until unblocked|stream_id:%ui|h3s:%p|stream:%p", h3s->stream_id, h3s, stream);
        return XQC_OK;
    }

    xqc_log(h3s->log, XQC_LOG_DEBUG, "|destroy h3 stream success|h3_stream_type:%d|stream_id:%ui"
            "|blocked:%d", h3s->type, h3s->stream_id,
            (h3s->flags & XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED ? 1 : 0));

    /* destroy h3_stream */
    xqc_h3_stream_destroy(h3s);

    return XQC_OK;
}


void
xqc_h3_stream_closing_notify(xqc_stream_t *stream,
    xqc_int_t err_code, void *strm_user_data)
{
    xqc_h3_stream_t *h3s;

    h3s = (xqc_h3_stream_t *)strm_user_data;
    if (NULL == h3s) {
        return;
    }

    /* only http3 request shall be notified */
    if (h3s->type == XQC_H3_STREAM_TYPE_REQUEST
        && h3s->h3r)
    {
        xqc_h3_request_closing(h3s->h3r, err_code);
    }
}

/**
 * transport callback
 */
const xqc_stream_callbacks_t h3_stream_callbacks = {
    .stream_create_notify  = xqc_h3_stream_create_notify,
    .stream_write_notify   = xqc_h3_stream_write_notify,
    .stream_read_notify    = xqc_h3_stream_read_notify,
    .stream_close_notify   = xqc_h3_stream_close_notify,
    .stream_closing_notify = xqc_h3_stream_closing_notify,
};


xqc_var_buf_t *
xqc_h3_stream_get_send_buf(xqc_h3_stream_t *h3s)
{
    return xqc_h3_stream_get_buf(h3s, &h3s->send_buf, XQC_VAR_BUF_INIT_SIZE);
}

uint64_t
xqc_h3_stream_get_err(xqc_h3_stream_t *h3s)
{
    /* update stream_err if transport stream is still alive */
    if (h3s->stream) {
        h3s->stream_err = h3s->stream->stream_err;
    }

    return h3s->stream_err;
}

void
xqc_h3_stream_get_path_info(xqc_h3_stream_t *h3s)
{
    /* update path_info if transport stream is still alive */
    if (h3s->stream) {
        for (int i = 0; i < XQC_MAX_PATHS_COUNT; ++i) {
            h3s->paths_info[i].path_id             = h3s->stream->paths_info[i].path_id;
            h3s->paths_info[i].path_pkt_recv_count = h3s->stream->paths_info[i].path_pkt_recv_count;
            h3s->paths_info[i].path_pkt_send_count = h3s->stream->paths_info[i].path_pkt_send_count;
            h3s->paths_info[i].path_send_bytes     = h3s->stream->paths_info[i].path_send_bytes;
            h3s->paths_info[i].path_send_reinject_bytes = h3s->stream->paths_info[i].path_send_reinject_bytes;
            h3s->paths_info[i].path_recv_bytes = h3s->stream->paths_info[i].path_recv_bytes;
            h3s->paths_info[i].path_recv_reinject_bytes = h3s->stream->paths_info[i].path_recv_reinject_bytes;
            h3s->paths_info[i].path_recv_effective_bytes = h3s->stream->paths_info[i].path_recv_effective_bytes;
            h3s->paths_info[i].path_recv_effective_reinject_bytes = h3s->stream->paths_info[i].path_recv_effective_reinject_bytes;
        }
    }
}

void
xqc_h3_stream_set_priority(xqc_h3_stream_t *h3s, xqc_h3_priority_t *prio)
{
    if (!(h3s->flags & XQC_HTTP3_STREAM_FLAG_PRIORITY_SET)) {
        h3s->flags |= XQC_HTTP3_STREAM_FLAG_PRIORITY_SET;

        h3s->priority.urgency     = prio->urgency;
        h3s->priority.incremental = prio->incremental;
        h3s->priority.schedule    = prio->schedule;
        h3s->priority.reinject    = prio->reinject;

        if (h3s->stream == NULL) {
            xqc_log(h3s->log, XQC_LOG_ERROR, "|transport stream was NULL|stream_id:%ui|", h3s->stream_id);
            return;
        }

        xqc_stream_set_multipath_usage(h3s->stream, h3s->priority.schedule, h3s->priority.reinject);
    }
}
