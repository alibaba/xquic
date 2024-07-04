/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */
#include <inttypes.h>
#include "src/http3/xqc_h3_request.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_engine.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_ctx.h"
#include "src/common/xqc_time.h"


xqc_h3_request_t *
xqc_h3_request_create(xqc_engine_t *engine, 
    const xqc_cid_t *cid, xqc_stream_settings_t *settings, void *user_data)
{
    xqc_stream_t       *stream;
    xqc_h3_stream_t    *h3_stream;
    xqc_h3_request_t   *h3_request;
    xqc_h3_conn_t      *h3_conn;

    stream = xqc_stream_create(engine, cid, settings, NULL);
    if (!stream) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|xqc_stream_create error|");
        return NULL;
    }

    h3_conn = (xqc_h3_conn_t*)stream->stream_conn->proto_data;

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
            xqc_conn_flag_2_str(h3_conn->conn, h3_conn->conn->conn_flag));
    return h3_request;
}

void
xqc_h3_request_destroy(xqc_h3_request_t *h3_request)
{
    xqc_h3_stream_t *h3s = h3_request->h3_stream;

    /* print request statistic log */
    xqc_request_stats_t stats = xqc_h3_request_get_stats(h3_request);

    xqc_usec_t create_time = h3_request->h3r_begin_time;

    xqc_log(h3_request->h3_stream->log, XQC_LOG_REPORT, "|stream_id:%ui|close_msg:%s|err:%d"
            "|rcvd_bdy_sz:%uz|snd_bdy_sz:%uz|rcvd_hdr_sz:%uz|snd_hdr_sz:%uz"
            "|create:%ui|blkd:%ui|nblkd:%ui|hdr_b:%ui|hdr_e:%ui|bdy_b:%ui|fin:%ui|recv_end:%ui"
            "|hrd_send:%ui|bdy_send:%ui|fin_send:%ui|fin_ack:%ui|last_send:%ui|last_recv:%ui"
            "|mp_state:%d|path_info:%s|comp_hdr_s:%uz|comp_hdr_r:%uz|fst_fin_snd:%ui|"
            "sched_blk:%ud|sched_blk_time:%ui|"
            "cwnd_blk:%ud|cwnd_blk_time:%ui|"
            "pacing_blk:%ud|pacing_blk_time:%ui|begin_state:%s|end_state:%s|",
            h3s->stream_id, stats.stream_close_msg ? stats.stream_close_msg : "",
            stats.stream_err, stats.recv_body_size, stats.send_body_size,
            stats.recv_header_size, stats.send_header_size,
            create_time,
            xqc_calc_delay(stats.blocked_time, create_time),
            xqc_calc_delay(stats.unblocked_time, create_time),
            xqc_calc_delay(stats.h3r_header_begin_time, create_time),
            xqc_calc_delay(stats.h3r_header_end_time, create_time),
            xqc_calc_delay(stats.h3r_body_begin_time, create_time),
            xqc_calc_delay(stats.stream_fin_time, create_time),
            xqc_calc_delay(stats.h3r_end_time, create_time),
            xqc_calc_delay(stats.h3r_header_send_time, create_time),
            xqc_calc_delay(stats.h3r_body_send_time, create_time),
            xqc_calc_delay(stats.stream_fin_send_time, create_time),
            xqc_calc_delay(stats.stream_fin_ack_time, create_time),
            xqc_calc_delay(h3_request->h3_stream->h3c->conn->conn_last_send_time, create_time),
            xqc_calc_delay(h3_request->h3_stream->h3c->conn->conn_last_recv_time, create_time),
            stats.mp_state, stats.stream_info, stats.send_hdr_compressed,
            stats.recv_hdr_compressed,
            xqc_calc_delay(stats.stream_fst_fin_snd_time, create_time),
            h3_request->sched_cwnd_blk_cnt, 
            h3_request->sched_cwnd_blk_duration / 1000,
            h3_request->send_cwnd_blk_cnt, 
            h3_request->send_cwnd_blk_duration/ 1000,
            h3_request->send_pacing_blk_cnt, 
            h3_request->send_pacing_blk_duration / 1000,
            h3s->begin_trans_state,
            h3s->end_trans_state);

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
                xqc_conn_flag_2_str(conn, conn->conn_flag));
        return ret;
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|success|stream_id:%ui|conn:%p|conn_state:%s|flag:%s|",
            h3s->stream_id, conn, xqc_conn_state_2_str(conn->conn_state),
            xqc_conn_flag_2_str(conn, conn->conn_flag));

    return XQC_OK;
}

void
xqc_h3_request_header_initial(xqc_h3_request_t *h3_request)
{
    xqc_h3_headers_initial(&h3_request->h3_header[XQC_H3_REQUEST_HEADER]);
    xqc_h3_headers_initial(&h3_request->h3_header[XQC_H3_REQUEST_TRAILER]);
}


xqc_int_t
xqc_h3_request_init_callbacks(xqc_h3_conn_t *h3c, xqc_h3_request_t *h3r)
{
    h3r->request_if = &h3c->h3_request_callbacks;
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

    xqc_h3_request_init_callbacks(h3_conn, h3_request);

    if (h3_request->request_if->h3_request_create_notify) {
        h3_request->request_if->h3_request_create_notify(h3_request, h3_request->user_data);
    }

    xqc_h3_request_begin(h3_request);

    return h3_request;
}

void 
xqc_h3_request_encode_rtts(xqc_h3_request_t *h3r, char *buff, size_t buff_size)
{
    xqc_h3_stream_t *h3_stream = h3r->h3_stream;
    size_t cursor = 0;
    int ret, i;

    for (int i = 0; i < XQC_MAX_PATHS_COUNT; ++i) {
        if ((h3_stream->paths_info[i].path_send_bytes > 0)
            || (h3_stream->paths_info[i].path_recv_bytes > 0))
        {
            ret = snprintf(buff + cursor, buff_size - cursor, 
                           "%"PRIu64"-", h3_stream->paths_info[i].path_srtt / 1000);
            cursor += ret;

            if (cursor >= buff_size) {
                break;
            }
        }
    }

    cursor = xqc_min(cursor, buff_size);
    for (i = cursor - 1; i >= 0; i--) {
        if (buff[i] == '-') {
            buff[i] = '\0';
            break;
        }
    }
    buff[buff_size - 1] = '\0';
}

void
xqc_stream_info_print(xqc_h3_stream_t *h3_stream, xqc_request_stats_t *stats)
{
    xqc_h3_conn_t *h3c = h3_stream->h3c;
    char *buff = stats->stream_info;
    size_t buff_size = XQC_STREAM_INFO_LEN;
    size_t cursor = 0, ret = 0;
    int i;
    int flag = 0;
    char mp_settings[XQC_MP_SETTINGS_STR_LEN] = {0};

    if (h3c->conn->handshake_complete_time > 0) {
        flag = 1;
    }

    if (h3c->conn->conn_settings.enable_stream_rate_limit) {
        flag |= 1 << 1;
    }

    xqc_conn_encode_mp_settings(h3c->conn, mp_settings, XQC_MP_SETTINGS_STR_LEN);

    ret = snprintf(buff, buff_size, "(%d,%"PRIu64",%s,%"PRIu64",%"PRIu64",%"PRIu64",%u)#", 
                   flag, h3_stream->recv_rate_limit, mp_settings,
                   h3_stream->send_offset, h3_stream->recv_offset,
                   stats->cwnd_blocked_ms, stats->retrans_cnt);

    cursor += ret;

    if (cursor >= buff_size) {
        goto full;
    }

    for (int i = 0; i < XQC_MAX_PATHS_COUNT; ++i) {
        if ((h3_stream->paths_info[i].path_send_bytes > 0)
            || (h3_stream->paths_info[i].path_recv_bytes > 0))
        {
            ret = snprintf(buff + cursor, buff_size - cursor, 
                            "%"PRIu64"-%"PRIu64"-%"PRIu64"-%"PRIu64"-%"PRIu64"-%"PRIu64"-%d#",
                            h3_stream->paths_info[i].path_id,
                            h3_stream->paths_info[i].path_pkt_send_count,
                            h3_stream->paths_info[i].path_pkt_recv_count,
                            h3_stream->paths_info[i].path_send_bytes,
                            h3_stream->paths_info[i].path_recv_bytes,
                            h3_stream->paths_info[i].path_srtt,
                            h3_stream->paths_info[i].path_app_status);
            cursor += ret;

            if (cursor >= buff_size) {
                goto full;
            }
        }
    }

full:
    cursor = xqc_min(cursor, buff_size);
    for (i = cursor - 1; i >= 0; i--) {
        if (buff[i] == '-' || buff[i] == '#') {
            buff[i] = '\0';
            break;
        }
    }
    buff[buff_size - 1] = '\0';
}


xqc_int_t 
xqc_h3_request_update_settings(xqc_h3_request_t *h3_request, 
    xqc_stream_settings_t *settings)
{
    if (h3_request && settings 
        && h3_request->h3_stream && h3_request->h3_stream->stream)
    {
        if (xqc_stream_update_settings(h3_request->h3_stream->stream, 
                                       settings) == XQC_OK) 
        {
            h3_request->h3_stream->recv_rate_limit = settings->recv_rate_bytes_per_sec;
            return XQC_OK;
        }
    }
    
    return -XQC_EPARAM;
}

xqc_request_stats_t
xqc_h3_request_get_stats(xqc_h3_request_t *h3_request)
{
    xqc_request_stats_t stats;
    xqc_memzero(&stats, sizeof(stats));

    /* try to update stats */
    xqc_h3_stream_update_stats(h3_request->h3_stream);

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
    stats.h3r_body_begin_time   = h3_request->h3r_body_begin_time;
    stats.h3r_header_send_time  = h3_request->h3r_header_send_time;
    stats.h3r_body_send_time    = h3_request->h3r_body_send_time;
    stats.stream_fin_send_time  = h3_request->stream_fin_send_time;
    stats.stream_fst_fin_snd_time = h3_request->stream_fst_fin_snd_time;
    stats.stream_fin_ack_time   = h3_request->stream_fin_ack_time;
    stats.stream_close_msg      = h3_request->stream_close_msg;
    stats.send_hdr_compressed = h3_request->compressed_header_sent;
    stats.recv_hdr_compressed = h3_request->compressed_header_recvd;
    stats.rate_limit = h3_request->h3_stream->recv_rate_limit;
    stats.cwnd_blocked_ms = (h3_request->sched_cwnd_blk_duration + h3_request->send_cwnd_blk_duration) / 1000;
    stats.early_data_state = h3_request->h3_stream->early_data_state;
    stats.retrans_cnt = h3_request->retrans_pkt_cnt;
    stats.stream_fst_pkt_snd_time = h3_request->stream_fst_pkt_snd_time;
    stats.stream_fst_pkt_rcv_time = h3_request->stream_fst_pkt_rcv_time;

    xqc_h3_stream_get_path_info(h3_request->h3_stream);
    xqc_request_path_metrics_print(h3_request->h3_stream->h3c->conn,
                                   h3_request->h3_stream, &stats);
    xqc_stream_info_print(h3_request->h3_stream, &stats);

    return stats;
}

xqc_int_t
xqc_h3_request_stats_print(xqc_h3_request_t *h3_request, char *str, size_t size)
{
    xqc_request_stats_t stats = xqc_h3_request_get_stats(h3_request);
    xqc_usec_t create_time = h3_request->h3r_begin_time;
    char rtt_str[32] = {0};
    xqc_h3_request_encode_rtts(h3_request, rtt_str, 32);
    return snprintf(str, size, "%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64
                    ",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",cc:%"PRIu64
                    ",rtx:%u,rtt:%s",
                    h3_request->h3_stream->stream_id,
                    xqc_calc_delay(stats.h3r_header_begin_time, create_time) / 1000,
                    xqc_calc_delay(stats.h3r_header_end_time, create_time) / 1000,
                    xqc_calc_delay(stats.h3r_body_begin_time, create_time) / 1000,
                    xqc_calc_delay(stats.stream_fin_time, create_time) / 1000,
                    xqc_calc_delay(stats.h3r_end_time, create_time) / 1000,
                    xqc_calc_delay(stats.h3r_header_send_time, create_time) / 1000,
                    xqc_calc_delay(stats.h3r_body_send_time, create_time) / 1000,
                    xqc_calc_delay(stats.stream_fin_send_time, create_time) / 1000,
                    xqc_calc_delay(stats.stream_fin_ack_time, create_time) / 1000,
                    stats.cwnd_blocked_ms, stats.retrans_cnt, rtt_str);
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

    /*  malloc a new  move pseudo headers in the front of list */
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

    /* make pseudo headers first */
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
    xqc_h3_request_on_header_send(h3_request);

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

    xqc_h3_request_on_body_send(h3_request);

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

    xqc_int_t ret;
    xqc_http_headers_t *headers;

    if (h3r->current_header == 1) {
        /* notify data before trailer headers*/
        ret = xqc_h3_request_on_recv_body(h3r);
        if (ret != XQC_OK) {
            xqc_log(h3r->h3_stream->log, XQC_LOG_ERROR, "|recv body error|%d|", ret);
            return ret;
        }
    }

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
    if (h3r->request_if->h3_request_read_notify) {
        ret = h3r->request_if->h3_request_read_notify(h3r, h3r->read_flag, h3r->user_data);
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
xqc_h3_request_on_recv_body(xqc_h3_request_t *h3r)
{
    /* Note, the case of empty fin is already handled at another place. */
    if (!xqc_list_empty(&h3r->body_buf)) {

        h3r->read_flag |= XQC_REQ_NOTIFY_READ_BODY;
        if (h3r->request_if->h3_request_read_notify) {
            xqc_int_t ret = h3r->request_if->h3_request_read_notify(h3r, h3r->read_flag, h3r->user_data);
            if (ret < 0) {
                xqc_log(h3r->h3_stream->log, XQC_LOG_ERROR, "|h3_request_read_notify error|%d|"
                        "stream_id:%ui|conn:%p|", ret, h3r->h3_stream->stream_id,
                        h3r->h3_stream->h3c->conn);
                return ret;
            }
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

    if (h3r->request_if->h3_request_read_notify) {
        /* if all header and content were received by application, notify empty fin */
        ret = h3r->request_if->h3_request_read_notify(h3r, XQC_REQ_NOTIFY_READ_EMPTY_FIN,
                                                    h3r->user_data);
        if (ret < 0) {
            xqc_log(h3r->h3_stream->log, XQC_LOG_ERROR, "|h3_request_read_notify error|%d|"
                    "stream_id:%ui|conn:%p|", ret, h3r->h3_stream->stream_id,
                    h3r->h3_stream->h3c->conn);
            return ret;
        }
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
xqc_h3_request_body_begin(xqc_h3_request_t *h3r)
{
    XQC_H3_REQUEST_RECORD_TIME(h3r->h3r_body_begin_time);
}

void
xqc_h3_request_on_header_send(xqc_h3_request_t *h3r)
{
    XQC_H3_REQUEST_RECORD_TIME(h3r->h3r_header_send_time);
}

void
xqc_h3_request_on_body_send(xqc_h3_request_t *h3r)
{
    XQC_H3_REQUEST_RECORD_TIME(h3r->h3r_body_send_time);
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

void
xqc_h3_request_closing(xqc_h3_request_t *h3r, xqc_int_t err)
{
    if (h3r->request_if->h3_request_closing_notify) {
        h3r->request_if->h3_request_closing_notify(h3r, err, h3r->user_data);
    }
}


#define XQC_PRIORITY_URGENCY "u="
#define XQC_PRIORITY_URGENCY_LEN 2

#define XQC_PRIORITY_INCREMENTAL ", i"
#define XQC_PRIORITY_INCREMENTAL_LEN 3

#define XQC_PRIORITY_SCHEDULE ", s="
#define XQC_PRIORITY_SCHEDULE_LEN 4

#define XQC_PRIORITY_REINJECT ", r="
#define XQC_PRIORITY_REINJECT_LEN 4

void
xqc_h3_priority_init(xqc_h3_priority_t *prio)
{
    prio->urgency = XQC_DEFAULT_HTTP_PRIORITY_URGENCY;
    prio->incremental = XQC_FALSE;
    prio->schedule = 0;
    prio->reinject = 0;
}

size_t
xqc_write_http_priority(xqc_h3_priority_t *prio,
    uint8_t *dst, size_t dstcap)
{
    uint8_t *begin = dst;

    size_t need = XQC_PRIORITY_URGENCY_LEN + 1
                + XQC_PRIORITY_INCREMENTAL_LEN
                + XQC_PRIORITY_SCHEDULE_LEN + 1
                + XQC_PRIORITY_REINJECT_LEN + 1;
    if (need > dstcap) {
        return -XQC_H3_BUFFER_EXCEED;
    }

    xqc_memcpy(dst, XQC_PRIORITY_URGENCY, XQC_PRIORITY_URGENCY_LEN);
    dst += XQC_PRIORITY_URGENCY_LEN;
    *dst++ = '0' + prio->urgency;

    if (prio->incremental) {
        xqc_memcpy(dst, XQC_PRIORITY_INCREMENTAL, XQC_PRIORITY_INCREMENTAL_LEN);
        dst += XQC_PRIORITY_INCREMENTAL_LEN;
    }

    xqc_memcpy(dst, XQC_PRIORITY_SCHEDULE, XQC_PRIORITY_SCHEDULE_LEN);
    dst += XQC_PRIORITY_SCHEDULE_LEN;
    *dst++ = '0' + prio->schedule;

    xqc_memcpy(dst, XQC_PRIORITY_REINJECT, XQC_PRIORITY_REINJECT_LEN);
    dst += XQC_PRIORITY_REINJECT_LEN;
    *dst++ = '0' + prio->reinject;

    return dst - begin;
}


xqc_int_t
xqc_parse_http_priority(xqc_h3_priority_t *dst,
    const uint8_t *str, size_t str_len)
{
    xqc_h3_priority_t prio;
    xqc_h3_priority_init(&prio);

    uint8_t *p = (uint8_t *)str;
    uint8_t *e = p + str_len;

    uint8_t *v, *next_k;

    while (*p != '\0' && p < e) {
        if (*p == ' ') {
            p++;
            continue;
        }

        if (strncmp(p, "u=", xqc_lengthof("u=")) == 0) {
            p += xqc_lengthof("u=");
            prio.urgency = strtoul(p, NULL, 10);

        } else if (strncmp(p, "i", xqc_lengthof("i")) == 0) {
            v = strchr(p, '=');
            next_k =  strchr(p, ',');

            if ((v == NULL) || (next_k != NULL && v > next_k)) {
                p += xqc_lengthof("i");
                prio.incremental = XQC_TRUE;

            } else if (strncmp(p, "i=?", xqc_lengthof("i=?")) == 0) {
                p += xqc_lengthof("i=?");
                prio.incremental = strtoul(p, NULL, 10);

            } else {
                return -XQC_H3_INVALID_PRIORITY;
            }

        } else if (strncmp(p, "s=", xqc_lengthof("s=")) == 0) {
            p += xqc_lengthof("s=");
            prio.schedule = strtoul(p, NULL, 10);

        } else if (strncmp(p, "r=", xqc_lengthof("r=")) == 0) {
            p += xqc_lengthof("r=");
            prio.reinject = strtoul(p, NULL, 10);

        }

        p = strchr(p, ',');
        if (p == NULL) {
            goto end;
        }
        p++;
    }

end:
    *dst = prio;
    return XQC_OK;
}

xqc_int_t
xqc_h3_request_check_priority(xqc_h3_priority_t *prio)
{
    if (prio->urgency < XQC_HIGHEST_HTTP_PRIORITY_URGENCY
        || prio->urgency > XQC_LOWEST_HTTP_PRIORITY_URGENCY)
    {
        return -XQC_H3_INVALID_PRIORITY;
    }

    if ((prio->incremental != XQC_FALSE) && (prio->incremental != XQC_TRUE)) {
        return -XQC_H3_INVALID_PRIORITY;
    }

    return XQC_OK;
}

xqc_int_t
xqc_h3_request_set_priority(xqc_h3_request_t *h3r, xqc_h3_priority_t *prio)
{
    xqc_int_t ret = xqc_h3_request_check_priority(prio);
    if (ret != XQC_OK) {
        xqc_log(h3r->h3_stream->log, XQC_LOG_ERROR,
                "|xqc_h3_request_check_priority error|%d|stream_id:%ui|conn:%p|",
                ret, h3r->h3_stream->stream_id, h3r->h3_stream->h3c->conn);
        return ret;
    }

    xqc_h3_stream_set_priority(h3r->h3_stream, prio);
    xqc_log_event(h3r->h3_stream->log, HTTP_PRIORITY_UPDATED, prio, h3r->h3_stream);
    return XQC_OK;
}