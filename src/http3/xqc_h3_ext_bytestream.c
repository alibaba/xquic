#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_stream.h"
#include "src/common/xqc_log.h"
#include "src/http3/xqc_h3_ext_bytestream.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/common/xqc_common.h"
#include "src/http3/xqc_h3_ctx.h"

typedef enum {
    XQC_H3_EXT_BYTESTREAM_FLAG_FIN_RCVD           = 1,
    XQC_H3_EXT_BYTESTREAM_FLAG_FIN_SENT           = 1 << 1,
    XQC_H3_EXT_BYTESTREAM_FLAG_FIN_READ           = 1 << 2,
    XQC_H3_EXT_BYTESTREAM_FLAG_UPPER_LAYER_EXIST  = 1 << 3,
} xqc_h3_ext_bytestream_flag_t;

typedef struct xqc_h3_ext_bytestream_s {

    /* h3 stream handler */
    xqc_h3_stream_t                   *h3_stream;

    /* user data for request callback */
    void                              *user_data;

    /* bytestream callback */
    xqc_h3_ext_bytestream_callbacks_t *bs_callbacks;

    /* flag */
    xqc_h3_ext_bytestream_flag_t       flag;

    /* received body buf list and statistic information */
    xqc_list_head_t                    data_buf_list;
    uint64_t                           data_buf_cnt;

    /* var_buf */
    xqc_var_buf_t                     *msg_buf;

    /* statistic */
    size_t                             bytes_rcvd;
    size_t                             bytes_sent;
    const char                        *stream_close_msg;
    xqc_usec_t                         create_time;
    xqc_usec_t                         fin_rcvd_time;
    xqc_usec_t                         fin_read_time;
    xqc_usec_t                         fin_sent_time;
    xqc_usec_t                         fin_acked_time;
    xqc_usec_t                         first_byte_sent_time;
    xqc_usec_t                         first_byte_rcvd_time;

} xqc_h3_ext_bytestream_t;

xqc_h3_ext_bytestream_data_buf_t*
xqc_h3_ext_bytestream_create_data_buf(xqc_h3_frame_pctx_t *pctx)
{
    xqc_h3_ext_bytestream_data_buf_t *new_buf = xqc_calloc(1, sizeof(xqc_h3_ext_bytestream_data_buf_t));
    if (new_buf) {
        xqc_init_list_head(&new_buf->list);
        xqc_init_list_head(&new_buf->buf_list);
        new_buf->total_len = pctx->frame.len;
        new_buf->curr_len = 0;
    }
    return new_buf;
}

void
xqc_h3_ext_bytestream_free_data_buf(xqc_h3_ext_bytestream_data_buf_t *buf)
{
    if (buf) {
        xqc_list_buf_list_free(&buf->buf_list);
        xqc_list_del_init(&buf->list);
        xqc_free(buf);
    }
}

xqc_h3_ext_bytestream_data_buf_t*
xqc_h3_ext_bytestream_get_last_data_buf(xqc_h3_ext_bytestream_t *bs, xqc_h3_frame_pctx_t *pctx)
{
    if (bs->data_buf_cnt > 0) {
        xqc_list_head_t *tail_node;
        xqc_h3_ext_bytestream_data_buf_t *tail_buf;
        tail_node = bs->data_buf_list.prev;
        tail_buf = xqc_list_entry(tail_node, xqc_h3_ext_bytestream_data_buf_t, list);
        if (tail_buf->curr_len < tail_buf->total_len) {
            return tail_buf;
        }
    }

    /* create a new buf */
    xqc_h3_ext_bytestream_data_buf_t *new_buf = xqc_h3_ext_bytestream_create_data_buf(pctx);
    if (new_buf) {
        bs->data_buf_cnt++;
        xqc_list_add_tail(&new_buf->list, &bs->data_buf_list);
        new_buf->start_time = xqc_monotonic_timestamp();
    }
    return new_buf;
}

xqc_int_t 
xqc_h3_ext_bytestream_save_data_to_buf(xqc_h3_ext_bytestream_data_buf_t *buf,
    const uint8_t *data, size_t data_len)
{
    /* sanity check */
    if (buf->curr_len + data_len > buf->total_len) {
        return -XQC_H3_DECODE_ERROR;
    }

    xqc_int_t ret = XQC_OK;
    xqc_var_buf_t *v_buf = xqc_var_buf_create_with_limit(data_len, data_len);
    if (!v_buf) {
        return -XQC_EMALLOC;
    }

    ret = xqc_list_buf_to_tail(&buf->buf_list, v_buf);
    if (ret != XQC_OK) {
        xqc_var_buf_free(v_buf);
        return -XQC_EMALLOC;
    }

    xqc_var_buf_save_data(v_buf, data, data_len);
    buf->curr_len += data_len;
    buf->buf_cnt++;
    
    return XQC_OK;
}

xqc_var_buf_t* 
xqc_h3_ext_bytestream_data_buf_merge(xqc_h3_ext_bytestream_data_buf_t *buf)
{
    xqc_var_buf_t *v_buf = NULL;
    xqc_list_buf_t *segment;

    /* optimization: reduce memcpy for short messages */
    if (buf->buf_cnt == 1) {
        segment = xqc_list_entry(buf->buf_list.next, xqc_list_buf_t, list_head);
        v_buf = segment->buf;
        segment->buf = NULL;
        xqc_list_buf_free(segment);
        buf->buf_cnt--;
        return v_buf;
    }

    v_buf = xqc_var_buf_create_with_limit(buf->total_len, buf->total_len);
    if (!v_buf) {
        return NULL;
    }

    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &buf->buf_list) {
        segment = xqc_list_entry(pos, xqc_list_buf_t, list_head);
        xqc_var_buf_save_data(v_buf, segment->buf->data, segment->buf->data_len);
        xqc_list_buf_free(segment);
        buf->buf_cnt--;
    }
    return v_buf;
}

xqc_int_t 
xqc_h3_ext_bytestream_init_callbacks(xqc_h3_conn_t *h3c, xqc_h3_ext_bytestream_t *bs)
{
    bs->bs_callbacks = &h3c->h3_ext_bs_callbacks;
    return XQC_OK;
}

xqc_h3_ext_bytestream_t* 
xqc_h3_ext_bytestream_create_inner(xqc_h3_conn_t *h3_conn, 
    xqc_h3_stream_t *h3_stream, void *user_data)
{
    xqc_h3_ext_bytestream_t *bs;
    bs = xqc_calloc(1, sizeof(xqc_h3_ext_bytestream_t));
    if (!bs) {
        xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_calloc error|");
        return NULL;
    }

    if (xqc_h3_ext_bytestream_init_callbacks(h3_conn, bs) != XQC_OK) {
        xqc_free(bs);
        return NULL;
    }

    bs->h3_stream = h3_stream;
    bs->user_data = user_data;
    bs->flag = 0;
    bs->create_time = xqc_monotonic_timestamp();
    bs->msg_buf = NULL;

    xqc_init_list_head(&bs->data_buf_list);
    bs->data_buf_cnt = 0;

    return bs;
}


xqc_h3_ext_bytestream_t*
xqc_h3_ext_bytestream_create(xqc_engine_t *engine, 
	const xqc_cid_t *cid, void *user_data)
{
    xqc_stream_t              *stream;
    xqc_h3_stream_t           *h3_stream;
    xqc_h3_ext_bytestream_t   *h3_ext_bs;
    xqc_h3_conn_t             *h3_conn;
    int                        ret;

    stream = xqc_stream_create(engine, cid, NULL, NULL);
    if (!stream) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|xqc_stream_create error|");
        return NULL;
    }

    h3_conn = (xqc_h3_conn_t*)stream->stream_conn->proto_data;

    if (!(h3_conn->flags & XQC_H3_CONN_FLAG_EXT_ENABLED)) {
        // it is safe to destroy the stream here, as it is not notified to upper layer.
        xqc_destroy_stream(stream);
        xqc_log(engine->log, XQC_LOG_ERROR, "|try to create bytestream while it is disabled on the connection|");
        return NULL;
    }

    h3_stream = xqc_h3_stream_create(h3_conn, stream, XQC_H3_STREAM_TYPE_BYTESTEAM, user_data);
    if (!h3_stream) {
        // it is safe to destroy the stream here, as it is not notified to upper layer.
        xqc_destroy_stream(stream);
        xqc_log(engine->log, XQC_LOG_ERROR, "|xqc_h3_stream_create error|");
        return NULL;
    }

    h3_ext_bs = xqc_h3_ext_bytestream_create_inner(h3_conn, h3_stream, user_data);
    if (!h3_ext_bs) {
        // it is safe to destroy the stream here, as it is not notified to upper layer.
        xqc_destroy_stream(stream);
        // the h3_stream will be destroyed in the close_notify triggered by xqc_destroy_stream
        xqc_log(engine->log, XQC_LOG_ERROR, "|xqc_h3_ext_bytestream_create_inner error|");
        return NULL;
    }

    h3_stream->h3_ext_bs = h3_ext_bs;
    
    // the initiator of the bytestream should send bidi_stream_type frame
    if (xqc_h3_stream_send_bidi_stream_type(h3_stream, XQC_H3_BIDI_STREAM_TYPE_BYTESTREAM, 0) != XQC_OK) {
        // it is safe to destroy the stream here, as it is not notified to upper layer.
        xqc_destroy_stream(stream);
        // the h3_stream will be destroyed in the close_notify triggered by xqc_destroy_stream
        // the h3_ext_bytestream will be destroyed when h3_stream is destroyed
        xqc_log(engine->log, XQC_LOG_ERROR, "|send bidi_stream_type frame error|");
        return NULL;
    }

    if (h3_ext_bs->bs_callbacks->bs_create_notify
        && !(h3_ext_bs->flag & XQC_H3_EXT_BYTESTREAM_FLAG_UPPER_LAYER_EXIST))
    {
        ret = h3_ext_bs->bs_callbacks->bs_create_notify(h3_ext_bs, h3_ext_bs->user_data);
        if (ret < 0) {
            xqc_log(engine->log, XQC_LOG_INFO, "|app create callback error|");
        }
        
    }

    h3_ext_bs->flag |= XQC_H3_EXT_BYTESTREAM_FLAG_UPPER_LAYER_EXIST;

    xqc_log(engine->log, XQC_LOG_DEBUG, "|success|stream_id:%ui|conn:%p|conn_state:%s|flag:%s|",
            h3_stream->stream_id, h3_conn->conn, xqc_conn_state_2_str(h3_conn->conn->conn_state),
            xqc_conn_flag_2_str(h3_conn->conn, h3_conn->conn->conn_flag));

    return h3_ext_bs;
}

xqc_h3_ext_bytestream_t*
xqc_h3_ext_bytestream_create_passive(xqc_h3_conn_t *h3_conn, 
    xqc_h3_stream_t *h3_stream, void *user_data)
{
    xqc_h3_ext_bytestream_t *h3_ext_bs = xqc_h3_ext_bytestream_create_inner(h3_conn, h3_stream, user_data);
    int ret;
    if (!h3_ext_bs) {
        xqc_log(h3_conn->log, XQC_LOG_ERROR, "|xqc_h3_ext_bytestream_create_inner error|");
        return NULL;
    }

    h3_stream->h3_ext_bs = h3_ext_bs;

    if (h3_ext_bs->bs_callbacks->bs_create_notify
        && !(h3_ext_bs->flag & XQC_H3_EXT_BYTESTREAM_FLAG_UPPER_LAYER_EXIST))
    {
        
        ret = h3_ext_bs->bs_callbacks->bs_create_notify(h3_ext_bs, h3_ext_bs->user_data);
        if (ret < 0) {
            xqc_log(h3_conn->log, XQC_LOG_INFO, "|app create notify error|%d|", ret);
        }
    }

    h3_ext_bs->flag |= XQC_H3_EXT_BYTESTREAM_FLAG_UPPER_LAYER_EXIST;

    return h3_ext_bs;
}

void
xqc_h3_ext_bytestream_destroy(xqc_h3_ext_bytestream_t *bs)
{
    xqc_h3_stream_t *h3s = bs->h3_stream;

    /* print request statistic log */
    xqc_h3_ext_bytestream_stats_t stats = xqc_h3_ext_bytestream_get_stats(bs);

    xqc_log(h3s->log, XQC_LOG_REPORT, "|stream_id:%ui|close_msg:%s|err:%d"
            "|bytes_sent:%uz|bytes_rcvd:%uz|create_time:%ui|fb_sent_delay:%ui|fb_rcvd_delay:%ui"
            "|fin_sent_delay:%ui|fin_acked_delay:%ui|fin_rcvd_delay:%ui|",
            xqc_h3_ext_bytestream_id(bs), stats.stream_close_msg ? stats.stream_close_msg : "",
            stats.stream_err, stats.bytes_sent, stats.bytes_rcvd,
            stats.create_time, 
            xqc_calc_delay(stats.first_byte_sent_time, stats.create_time),
            xqc_calc_delay(stats.first_byte_rcvd_time, stats.create_time),
            xqc_calc_delay(stats.fin_sent_time, stats.create_time),
            xqc_calc_delay(stats.fin_acked_time, stats.create_time),
            xqc_calc_delay(stats.fin_rcvd_time, stats.create_time));

    if (bs->bs_callbacks->bs_close_notify
        && (bs->flag & XQC_H3_EXT_BYTESTREAM_FLAG_UPPER_LAYER_EXIST)) 
    {
        bs->bs_callbacks->bs_close_notify(bs, bs->user_data);
        bs->flag &= ~XQC_H3_EXT_BYTESTREAM_FLAG_UPPER_LAYER_EXIST;
    }

    xqc_list_head_t *pos, *next;
    xqc_h3_ext_bytestream_data_buf_t *buf;
    xqc_list_for_each_safe(pos, next, &bs->data_buf_list) {
        buf = xqc_list_entry(pos, xqc_h3_ext_bytestream_data_buf_t, list);
        xqc_h3_ext_bytestream_free_data_buf(buf);
    }

    if (bs->msg_buf) {
        xqc_var_buf_free(bs->msg_buf);
    }

    xqc_free(bs);
}

xqc_int_t 
xqc_h3_ext_bytestream_close(xqc_h3_ext_bytestream_t *h3_ext_bs)
{
    xqc_connection_t *conn = h3_ext_bs->h3_stream->h3c->conn;
    xqc_h3_stream_t  *h3s  = h3_ext_bs->h3_stream;

    xqc_int_t ret = xqc_h3_stream_close(h3s);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|fail|ret:%d|stream_id:%ui|conn:%p|conn_state:%s|"
                "flag:%s|", ret, h3s->stream_id, conn, xqc_conn_state_2_str(conn->conn_state),
                xqc_conn_flag_2_str(conn, conn->conn_flag));
        return ret;
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|success|stream_id:%ui|conn:%p|conn_state:%s|flag:%s|",
            h3s->stream_id, conn, xqc_conn_state_2_str(conn->conn_state),
            xqc_conn_flag_2_str(conn, conn->conn_flag));

    return XQC_OK;
}


ssize_t 
xqc_h3_ext_bytestream_finish(xqc_h3_ext_bytestream_t *h3_ext_bs)
{
    xqc_int_t ret = 0;
    if (h3_ext_bs->flag & XQC_H3_EXT_BYTESTREAM_FLAG_FIN_SENT) {
        xqc_log(h3_ext_bs->h3_stream->log, XQC_LOG_DEBUG, "|already sent fin|");
        return XQC_OK;
    }
    ret = xqc_h3_ext_bytestream_send(h3_ext_bs, NULL, 0, 1, XQC_DATA_QOS_HIGHEST);
    if (ret == 0) {
        xqc_log(h3_ext_bs->h3_stream->log, XQC_LOG_DEBUG, "|send pure fin|");
    }
    
    return ret;
}


void 
xqc_h3_ext_bytestream_set_user_data(xqc_h3_ext_bytestream_t *h3_ext_bs, 
	void *user_data)
{
    h3_ext_bs->user_data = user_data;
}



void *
xqc_h3_ext_bytestream_get_user_data(xqc_h3_ext_bytestream_t *h3_ext_bs)
{
    return h3_ext_bs->user_data;
}


void 
xqc_h3_ext_bytestream_save_stats_from_stream(xqc_h3_ext_bytestream_t *bs, 
    xqc_stream_t *stream)
{
    bs->fin_acked_time = stream->stream_stats.first_fin_ack_time;
    bs->stream_close_msg = stream->stream_close_msg;
}


xqc_h3_ext_bytestream_stats_t 
xqc_h3_ext_bytestream_get_stats(xqc_h3_ext_bytestream_t *h3_ext_bs)
{
    xqc_h3_ext_bytestream_stats_t stats;
    stats.create_time = h3_ext_bs->create_time;
    stats.bytes_rcvd = h3_ext_bs->bytes_rcvd;
    stats.bytes_sent = h3_ext_bs->bytes_sent;
    stats.fin_sent_time = h3_ext_bs->fin_sent_time;
    stats.fin_acked_time = h3_ext_bs->fin_acked_time;
    stats.fin_rcvd_time = h3_ext_bs->fin_rcvd_time;
    stats.fin_read_time = h3_ext_bs->fin_read_time;
    stats.first_byte_rcvd_time = h3_ext_bs->first_byte_rcvd_time;
    stats.first_byte_sent_time = h3_ext_bs->first_byte_sent_time;
    stats.stream_close_msg = h3_ext_bs->stream_close_msg;
    stats.stream_err = xqc_h3_stream_get_err(h3_ext_bs->h3_stream);
    return stats;
}


ssize_t 
xqc_h3_ext_bytestream_send(xqc_h3_ext_bytestream_t *h3_ext_bs, 
	unsigned char *data, size_t data_size, uint8_t fin, 
    xqc_data_qos_level_t qos_level)
{
    /* data_size is allowed if it's fin only */
    if (data_size > 0 && data == NULL) {
        return -XQC_H3_EPARAM;
    }

    if (h3_ext_bs->flag & XQC_H3_EXT_BYTESTREAM_FLAG_FIN_SENT) {
        xqc_log(h3_ext_bs->h3_stream->log, XQC_LOG_WARN, 
                "|send data after FIN sent|stream_id:%ui|", 
                xqc_h3_ext_bytestream_id(h3_ext_bs));
        return -XQC_H3_BYTESTREAM_FIN_SENT;
    }

    if (h3_ext_bs->msg_buf) {
        xqc_log(h3_ext_bs->h3_stream->log, XQC_LOG_DEBUG,
                "|msg_buf_has_blocked_data|stream_id:%ui|data_size:%uz|fin:%ud|",
                h3_ext_bs->h3_stream->stream_id, data_size, (unsigned int)fin);
        return -XQC_EAGAIN;
    }

    ssize_t sent = xqc_h3_stream_send_data(h3_ext_bs->h3_stream, data, data_size, fin);

    if (sent < 0 && sent != -XQC_EAGAIN) {
        xqc_log(h3_ext_bs->h3_stream->log, XQC_LOG_ERROR,
                "|xqc_h3_stream_send_data error|stream_id:%ui|ret:%z|data_size:%z|fin:%d|",
                h3_ext_bs->h3_stream->stream_id, sent, data_size, fin);
        return sent;
    }

    if (sent >= 0) {
        h3_ext_bs->bytes_sent += sent;
        if (fin && sent == data_size) {
            xqc_h3_ext_bytestream_fin_sent(h3_ext_bs);
            xqc_h3_ext_bytestream_set_fin_sent_flag(h3_ext_bs);
        }

        xqc_h3_ext_bytestream_send_begin(h3_ext_bs);
    }

    if ((sent == -XQC_EAGAIN) || (sent >= 0 && sent != data_size)) {
        xqc_log(h3_ext_bs->h3_stream->log, XQC_LOG_DEBUG,
                "|xqc_h3_stream_send_data blocked|stream_id:%ui|data_size:%uz|fin:%ud|",
                h3_ext_bs->h3_stream->stream_id, data_size, (unsigned int)fin);
        /* create a msg buffer for the current msg */
        if (h3_ext_bs->msg_buf) {
            xqc_log(h3_ext_bs->h3_stream->log, XQC_LOG_ERROR, 
                    "|msg_buf_already_exist|stream_id:%ui|data_size:%uz|fin:%ud|sent:%z|", 
                    h3_ext_bs->h3_stream->stream_id, data_size, (unsigned int)fin, sent);
            XQC_H3_CONN_ERR(h3_ext_bs->h3_stream->h3c, H3_INTERNAL_ERROR, -XQC_H3_BYTESTREAM_MSG_BUF_EXIST);
            return -XQC_H3_BYTESTREAM_MSG_BUF_EXIST;
        }

        sent = sent == -XQC_EAGAIN ? 0 : sent;
        h3_ext_bs->msg_buf = xqc_var_buf_create(data_size - sent);

        if (!h3_ext_bs->msg_buf) {
            xqc_log(h3_ext_bs->h3_stream->log, XQC_LOG_ERROR, 
                    "|malloc_msg_buffer_failed|stream_id:%ui|data_size:%uz|fin:%ud|buf_sz:%z|", 
                    h3_ext_bs->h3_stream->stream_id, data_size, (unsigned int)fin, data_size - sent);
            XQC_H3_CONN_ERR(h3_ext_bs->h3_stream->h3c, H3_INTERNAL_ERROR, -XQC_H3_EMALLOC);
            return -XQC_H3_EMALLOC;
        }

        xqc_var_buf_save_data(h3_ext_bs->msg_buf, data + sent, data_size - sent);
        h3_ext_bs->msg_buf->fin_flag = fin;

        return data_size;
    }

    xqc_log(h3_ext_bs->h3_stream->log, XQC_LOG_DEBUG, "|stream_id:%ui|data_size:%uz|sent:%z|"
            "total_bytes_sent:%uz|fin:%ud|conn:%p|",
            xqc_h3_ext_bytestream_id(h3_ext_bs), data_size, sent, h3_ext_bs->bytes_sent, 
            (unsigned int)fin, h3_ext_bs->h3_stream->h3c->conn);

    return sent;
}

xqc_stream_id_t 
xqc_h3_ext_bytestream_id(xqc_h3_ext_bytestream_t *h3_ext_bs)
{
    return h3_ext_bs->h3_stream->stream_id;
}


xqc_h3_conn_t*
xqc_h3_ext_bytestream_get_h3_conn(xqc_h3_ext_bytestream_t *h3_ext_bs)
{
    return h3_ext_bs->h3_stream->h3c;
}

xqc_int_t 
xqc_h3_ext_bytestream_append_data_buf(xqc_h3_ext_bytestream_t *bs, 
    xqc_var_buf_t *buf)
{
    xqc_int_t ret = XQC_OK;
    ret = xqc_list_buf_to_tail(&bs->data_buf_list, buf);
    if (ret == XQC_OK) {
        bs->data_buf_cnt++;
    }
    return ret;
}

#define XQC_H3_EXT_BYTESTREAM_RECORD_TIME(a) \
    if ((a) == 0) {                          \
        (a) = xqc_monotonic_timestamp();     \
    }                                        \

void 
xqc_h3_ext_bytestream_recv_begin(xqc_h3_ext_bytestream_t *bs)
{
    XQC_H3_EXT_BYTESTREAM_RECORD_TIME(bs->first_byte_rcvd_time);
}

void 
xqc_h3_ext_bytestream_send_begin(xqc_h3_ext_bytestream_t *bs)
{
    XQC_H3_EXT_BYTESTREAM_RECORD_TIME(bs->first_byte_sent_time);
}

void 
xqc_h3_ext_bytestream_fin_rcvd(xqc_h3_ext_bytestream_t *bs)
{
    XQC_H3_EXT_BYTESTREAM_RECORD_TIME(bs->fin_rcvd_time);
}

void 
xqc_h3_ext_bytestream_fin_read(xqc_h3_ext_bytestream_t *bs)
{
    XQC_H3_EXT_BYTESTREAM_RECORD_TIME(bs->fin_read_time);
}

void 
xqc_h3_ext_bytestream_fin_sent(xqc_h3_ext_bytestream_t *bs)
{
    XQC_H3_EXT_BYTESTREAM_RECORD_TIME(bs->fin_sent_time);
}


xqc_int_t 
xqc_h3_ext_bytestream_notify_write(xqc_h3_ext_bytestream_t *bs)
{
    xqc_int_t ret = XQC_OK;
    xqc_bool_t msg_buf_done = XQC_FALSE;

    /* send msg buf first */
    if (bs->msg_buf) {
        ssize_t sent = xqc_h3_stream_send_data(bs->h3_stream, 
                                               bs->msg_buf->data + bs->msg_buf->consumed_len, 
                                               bs->msg_buf->data_len - bs->msg_buf->consumed_len, 
                                               bs->msg_buf->fin_flag);
        if (XQC_UNLIKELY(sent == -XQC_EAGAIN)) {
            return XQC_OK;

        } else if (XQC_UNLIKELY(sent < 0)) {
            xqc_log(bs->h3_stream->h3c->log, XQC_LOG_ERROR, 
                    "|send_msg_buf_err|stream_id:%ui|msg_sz:%z|fin_flag:%d|ret:%z|",
                    xqc_h3_ext_bytestream_id(bs), 
                    bs->msg_buf->data_len - bs->msg_buf->consumed_len,
                    bs->msg_buf->fin_flag,
                    sent);
            return sent;
        }

        bs->msg_buf->consumed_len += sent;
        bs->bytes_sent += sent;

        if (bs->msg_buf->data_len == bs->msg_buf->consumed_len) {
            if (bs->msg_buf->fin_flag) {
                xqc_h3_ext_bytestream_fin_sent(bs);
                xqc_h3_ext_bytestream_set_fin_sent_flag(bs);
            }
            xqc_var_buf_free(bs->msg_buf);
            bs->msg_buf = NULL;
        }

        xqc_h3_ext_bytestream_send_begin(bs);
    }

    if (bs->bs_callbacks->bs_write_notify
        && (bs->flag & XQC_H3_EXT_BYTESTREAM_FLAG_UPPER_LAYER_EXIST)) 
    {
        ret =  bs->bs_callbacks->bs_write_notify(bs, bs->user_data);
    }
    return ret;
}

void 
xqc_h3_ext_bytestream_set_fin_sent_flag(xqc_h3_ext_bytestream_t *bs)
{
    bs->flag |= XQC_H3_EXT_BYTESTREAM_FLAG_FIN_SENT;
}

void 
xqc_h3_ext_bytestream_set_fin_rcvd_flag(xqc_h3_ext_bytestream_t *bs)
{
    bs->flag |= XQC_H3_EXT_BYTESTREAM_FLAG_FIN_RCVD;
}

xqc_bool_t 
xqc_h3_ext_bytestream_should_notify_read(xqc_h3_ext_bytestream_t *bs)
{
    if(!xqc_list_empty(&bs->data_buf_list)
       || ((bs->flag & XQC_H3_EXT_BYTESTREAM_FLAG_FIN_RCVD)  
           && !(bs->flag & XQC_H3_EXT_BYTESTREAM_FLAG_FIN_READ)))
    {
        return XQC_TRUE;
    }
    return XQC_FALSE;
}

xqc_int_t 
xqc_h3_ext_bytestream_notify_read(xqc_h3_ext_bytestream_t *bs)
{
    xqc_int_t ret = XQC_OK;
    xqc_list_head_t *node, *next;
    xqc_h3_ext_bytestream_data_buf_t *buf;
    xqc_var_buf_t *merged_buf;
    size_t data_sz;
    uint8_t fin = 0;

    xqc_list_for_each_safe(node, next, &bs->data_buf_list) {
        buf = xqc_list_entry(node, xqc_h3_ext_bytestream_data_buf_t, list);

        if (buf->end_time) {
            if (bs->data_buf_cnt == 1 
                && (bs->flag & XQC_H3_EXT_BYTESTREAM_FLAG_FIN_RCVD)) 
            {
                fin = 1;
                bs->flag |= XQC_H3_EXT_BYTESTREAM_FLAG_FIN_READ;
                xqc_h3_ext_bytestream_fin_read(bs);
            }
            ret = XQC_OK;
            data_sz = buf->total_len;
            
            merged_buf = xqc_h3_ext_bytestream_data_buf_merge(buf);
            if (merged_buf) {
                if (bs->bs_callbacks->bs_read_notify
                    && (bs->flag & XQC_H3_EXT_BYTESTREAM_FLAG_UPPER_LAYER_EXIST))
                {
                    ret = bs->bs_callbacks->bs_read_notify(bs, merged_buf->data, 
                                                           merged_buf->data_len, 
                                                           fin,
                                                           bs->user_data, 
                                                           buf->end_time - buf->start_time);
                }

                
                bs->bytes_rcvd += data_sz;
                xqc_log(bs->h3_stream->h3c->log, XQC_LOG_DEBUG, 
                        "|msg_read_notify|stream_id:%ui|msg_sz:%z|fin:%d|rcv_start:%ui|rcv_end:%ui|", 
                        xqc_h3_ext_bytestream_id(bs), data_sz, fin, buf->start_time, buf->end_time);

            } else {
                ret = -XQC_EMALLOC;
                xqc_log(bs->h3_stream->h3c->log, XQC_LOG_ERROR, "|merge_data_buf_error|");
            }

            xqc_h3_ext_bytestream_free_data_buf(buf);
            bs->data_buf_cnt--;
            if (ret < 0) {
                xqc_log(bs->h3_stream->h3c->log, XQC_LOG_ERROR, "|bs_read_notify_err|stream_id:%ui|ret:%d|data_sz:%z|fin:%d|",
                        xqc_h3_ext_bytestream_id(bs), ret, data_sz, fin);
                return ret;
            }
        } 
    }

    /* fin only */
    if (bs->data_buf_cnt == 0 
        && ((bs->flag & XQC_H3_EXT_BYTESTREAM_FLAG_FIN_RCVD)  
            && !(bs->flag & XQC_H3_EXT_BYTESTREAM_FLAG_FIN_READ)))
    {
        bs->flag |= XQC_H3_EXT_BYTESTREAM_FLAG_FIN_READ;
        xqc_h3_ext_bytestream_fin_read(bs);
        ret = XQC_OK;

        if (bs->bs_callbacks->bs_read_notify
            && (bs->flag & XQC_H3_EXT_BYTESTREAM_FLAG_UPPER_LAYER_EXIST))
        {
            ret = bs->bs_callbacks->bs_read_notify(bs, NULL, 
                                                   0, 
                                                   1,
                                                   bs->user_data, 
                                                   bs->fin_read_time - bs->fin_rcvd_time);
        }
        xqc_log(bs->h3_stream->h3c->log, XQC_LOG_DEBUG, 
                "|pure_fin_read_notify|stream_id:%ui|fin_rcv:%ui|fin_read:%ui|", 
                xqc_h3_ext_bytestream_id(bs), bs->fin_rcvd_time, bs->fin_read_time);
        if (ret < 0) {
            xqc_log(bs->h3_stream->h3c->log, XQC_LOG_ERROR, "|bs_read_notify_app_err|stream_id:%ui|ret:%d|data_sz:0|fin:1|",
                    xqc_h3_ext_bytestream_id(bs), ret);
        }
    }

    return ret;
}