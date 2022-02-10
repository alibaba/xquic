/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/http3/qpack/xqc_qpack.h"
#include "src/http3/xqc_h3_request.h"
#include "src/http3/xqc_h3_conn.h"



/* qpack handler */
typedef struct xqc_qpack_s {
    /* encoder for encoding headers to encoded field section */
    xqc_encoder_t          *enc;

    /* decoder for parsing encoded field section to headers */
    xqc_decoder_t          *dec;

    /* context for parsing decoder instructions */
    xqc_ins_dec_ctx_t      *dctx;

    /* context for parsing encoder instructions */
    xqc_ins_enc_ctx_t      *ectx;

    /* log handler */
    xqc_log_t              *log;

    /* instruction callback for encoder/decoder instruction buffer and write */
    xqc_qpack_ins_cb_t      ins_cb;

    /* user_data for xqc_qpack_ins_cb_t */
    void                   *user_data;

    /* max dynamic table capacity configured by local */
    uint64_t                max_cap;
} xqc_qpack_s;


xqc_qpack_t *
xqc_qpack_create(uint64_t max_cap, xqc_log_t *log, const xqc_qpack_ins_cb_t *ins_cb,
    void *user_data)
{
    if (NULL == ins_cb) {
        return NULL;
    }

    xqc_qpack_t *qpk = xqc_malloc(sizeof(xqc_qpack_t));
    if (qpk == NULL) {
        return NULL;
    }

    qpk->dec = xqc_decoder_create(log, max_cap);
    if (NULL == qpk->dec) {
        goto fail;
    }

    qpk->enc = xqc_encoder_create(log);
    if (NULL == qpk->enc) {
        goto fail;
    }

    qpk->ectx = xqc_ins_encoder_ctx_create();
    if (NULL == qpk->ectx) {
        goto fail;
    }

    qpk->dctx = xqc_ins_decoder_ctx_create();
    if (NULL == qpk->dctx) {
        goto fail;
    }

    qpk->ins_cb = *ins_cb;
    qpk->log = log;
    qpk->user_data = user_data;
    qpk->max_cap = max_cap;

    return qpk;

fail:
    xqc_qpack_destroy(qpk);
    return NULL;
}

void
xqc_qpack_destroy(xqc_qpack_t *qpk)
{
    if (qpk == NULL) {
        return;
    }

    if (qpk->dec) {
        xqc_decoder_destroy(qpk->dec);
    }

    if (qpk->enc) {
        xqc_encoder_destroy(qpk->enc);
    }

    if (qpk->ectx) {
        xqc_ins_encoder_ctx_free(qpk->ectx);
    }

    if (qpk->dctx) {
        xqc_ins_decoder_ctx_free(qpk->dctx);
    }

    xqc_free(qpk);
}

/* write and notify Set Dynamic Table Capacity instruction to peer */
static inline xqc_int_t
xqc_qpack_notify_set_dtable_cap(xqc_qpack_t *qpk, uint64_t cap)
{
    ssize_t         cb_ret;
    xqc_var_buf_t  *buf = qpk->ins_cb.get_buf_cb(XQC_INS_TYPE_ENCODER, qpk->user_data);
    if (NULL == buf) {
        xqc_log(qpk->log, XQC_LOG_ERROR, "|get encoder instruction error|");
        return -XQC_ENOBUF;
    }

    xqc_int_t ret = xqc_ins_write_set_dtable_cap(buf, cap);
    if (ret != XQC_OK) {
        xqc_log(qpk->log, XQC_LOG_ERROR, "|write sdtc error|ret:%d|", ret);
        goto fail;
    }
    xqc_log_event(qpk->log, QPACK_INSTRUCTION_CREATED, XQC_LOG_ENCODER_EVENT,
                  XQC_INS_TYPE_ENC_SET_DTABLE_CAP, cap);

    cb_ret = qpk->ins_cb.write_ins_cb(XQC_INS_TYPE_ENCODER, buf, qpk->user_data);
    if (cb_ret < 0) {
        xqc_log(qpk->log, XQC_LOG_ERROR, "|encoder instruction callback error|ret:%z|", cb_ret);
        ret = cb_ret;
        goto fail;
    }

fail:
    return ret;
}


/* write and notify Insert Count Increment */
static inline xqc_int_t
xqc_qpack_notify_insert_cnt_increment(xqc_qpack_t *qpk, uint64_t increment)
{
    ssize_t cb_ret;
    xqc_var_buf_t *buf = qpk->ins_cb.get_buf_cb(XQC_INS_TYPE_DECODER, qpk->user_data);
    if (NULL == buf) {
        xqc_log(qpk->log, XQC_LOG_ERROR, "|get encoder instruction error|");
        return -XQC_ENOBUF;
    }

    xqc_int_t ret = xqc_ins_write_icnt_increment(buf, increment);
    if (ret < 0) {
        xqc_log(qpk->log, XQC_LOG_ERROR, "|write ici error|ret:%d|", ret);
        goto fail;
    }
    xqc_log_event(qpk->log, QPACK_INSTRUCTION_CREATED, XQC_LOG_DECODER_EVENT,
                  XQC_INS_TYPE_DEC_INSERT_CNT_INC, increment);

    cb_ret = qpk->ins_cb.write_ins_cb(XQC_INS_TYPE_DECODER, buf, qpk->user_data);
    if (cb_ret < 0) {
        xqc_log(qpk->log, XQC_LOG_ERROR, "|decoder instruction callback error|ret:%z|", cb_ret);
        ret = cb_ret;
        goto fail;
    }

fail:
    return ret;
}

/* write and notify Section Acknowledgement */
static inline xqc_int_t
xqc_qpack_notify_section_ack(xqc_qpack_t *qpk, uint64_t stream_id)
{
    ssize_t cb_ret;
    xqc_var_buf_t *buf = qpk->ins_cb.get_buf_cb(XQC_INS_TYPE_DECODER, qpk->user_data);
    if (NULL == buf) {
        xqc_log(qpk->log, XQC_LOG_ERROR, "|get encoder instruction error|");
        return -XQC_ENOBUF;
    }

    xqc_int_t ret = xqc_ins_write_section_ack(buf, stream_id);
    if (ret < 0) {
        xqc_log(qpk->log, XQC_LOG_ERROR, "|write sack error|ret:%d|", ret);
        goto fail;
    }
    xqc_log_event(qpk->log, QPACK_INSTRUCTION_CREATED, XQC_LOG_DECODER_EVENT,
                  XQC_INS_TYPE_DEC_SECTION_ACK, stream_id);

    cb_ret = qpk->ins_cb.write_ins_cb(XQC_INS_TYPE_DECODER, buf, qpk->user_data);
    if (cb_ret < 0) {
        xqc_log(qpk->log, XQC_LOG_ERROR, "|decoder instruction callback error|ret:%z|", cb_ret);
        ret = cb_ret;
        goto fail;
    }

fail:
    return ret;
}

xqc_int_t
xqc_qpack_set_enc_max_dtable_cap(xqc_qpack_t *qpk, size_t max_cap)
{
    return xqc_encoder_set_max_dtable_cap(qpk->enc, max_cap);
}


xqc_int_t
xqc_qpack_set_dtable_cap(xqc_qpack_t *qpk, size_t cap)
{
    /* set encoder's dtable capacity, which is the minor of max_cap and cap */
    uint64_t min_cap = xqc_min(cap, qpk->max_cap);
    xqc_int_t ret = xqc_encoder_set_dtable_cap(qpk->enc, min_cap);
    if (ret != XQC_OK) {
        xqc_log(qpk->log, XQC_LOG_WARN, "|set encoder dynamic table cap error|ret:%d|", ret);
        return ret;
    }

    ret = xqc_qpack_notify_set_dtable_cap(qpk, min_cap);
    if (ret != XQC_OK) {
        xqc_log(qpk->log, XQC_LOG_ERROR, "|notify sdtc error|%d|", ret);
        return ret;
    }

    return XQC_OK;
}


xqc_int_t
xqc_qpack_set_max_blocked_stream(xqc_qpack_t *qpk, size_t max_blocked_stream)
{
    return xqc_encoder_set_max_blocked_stream(qpk->enc, max_blocked_stream);
}


uint64_t
xqc_qpack_get_dec_insert_count(xqc_qpack_t *qpk)
{
    return xqc_decoder_get_insert_cnt(qpk->dec);
}

static inline xqc_int_t
xqc_qpack_on_encoder_ins(xqc_qpack_t *qpk, xqc_ins_enc_ctx_t *ctx)
{
    xqc_int_t ret = XQC_OK;

    xqc_log(qpk->log, XQC_LOG_DEBUG, "|recv encoder ins|type:%d|", ctx->type);

    switch (ctx->type) {
    case XQC_INS_TYPE_ENC_SET_DTABLE_CAP:
        ret = xqc_decoder_set_dtable_cap(qpk->dec, ctx->capacity.value);
        break;

    case XQC_INS_TYPE_ENC_INSERT_NAME_REF:
        ret = xqc_decoder_insert_name_ref(qpk->dec, ctx->table, ctx->name_index.value, 
                                          ctx->value->value->data, ctx->value->value->data_len);
        break;

    case XQC_INS_TYPE_ENC_INSERT_LITERAL:
        ret = xqc_decoder_insert_literal(qpk->dec, ctx->name->value->data,
                                         ctx->name->value->data_len, ctx->value->value->data,
                                         ctx->value->value->data_len);
        break;

    case XQC_INS_TYPE_ENC_DUP:
        ret = xqc_decoder_duplicate(qpk->dec, ctx->name_index.value);
        break;

    default:
        xqc_log(qpk->log, XQC_LOG_ERROR, "|unknown encoder instruction|type:%ui|", ctx->type);
        return -XQC_QPACK_UNKNOWN_INSTRUCTION;
    }

    if (ret != XQC_OK) {
        xqc_log(qpk->log, XQC_LOG_ERROR, "|decoder act on encoder instruction error|ret:%d|", ret);
    }

    return ret;
}


ssize_t
xqc_qpack_process_encoder(xqc_qpack_t *qpk, unsigned char *data, size_t data_len)
{
    xqc_ins_enc_ctx_t *ctx = qpk->ectx;
    ssize_t read;
    xqc_int_t ret;
    ssize_t processed = 0;
    uint64_t ori_krc = xqc_qpack_get_dec_insert_count(qpk);  /* original Known Received Count */

    while (processed < data_len) {
        xqc_log(qpk->log, XQC_LOG_DEBUG, "|parse encoder instruction|type:%d|state:%d",
                ctx->type, ctx->state);

        /* parse instruction bytes */
        read = xqc_ins_parse_encoder(data + processed, data_len - processed, ctx);
        if (read < 0) {
            xqc_log(qpk->log, XQC_LOG_ERROR, "|parse encoder instruction error|ret:%d|type:%d"
                    "|state:%d|data_len:%d|processed:%d|", read, ctx->type,
                    ctx->state, data_len, processed);
            return read;
        }
        processed += read;

        /* all bytes shall be processed while not finish parsing a instruction */
        if (ctx->state != XQC_INS_ES_STATE_FINISH && data_len != processed) {
            xqc_log(qpk->log, XQC_LOG_ERROR, "|bytes remaining while not finished|");
            return -XQC_QPACK_INSTRUCTION_ERROR;
        }

        /* process instruction */
        if (ctx->state == XQC_INS_ES_STATE_FINISH) {
            xqc_log_event(qpk->log, QPACK_INSTRUCTION_PARSED, XQC_LOG_ENCODER_EVENT, ctx);
            ret = xqc_qpack_on_encoder_ins(qpk, ctx);
            if (ret != XQC_OK) {
                xqc_log(qpk->log, XQC_LOG_ERROR, "|process encoder instruction error|ret:%d|", ret);
                return ret;
            }
        }
    }

    /*
     * get insertion into decoder's dtable, reply Insert Count Increment to peer
     * notify here rather than xqc_qpack_on_encoder_ins to reduce ICI count
     */
    if (xqc_qpack_get_dec_insert_count(qpk) > ori_krc) {
        ret = xqc_qpack_notify_insert_cnt_increment(
            qpk, (xqc_qpack_get_dec_insert_count(qpk) - ori_krc));
        if (ret < 0) {
            xqc_log(qpk->log, XQC_LOG_ERROR, "|write increment error|ret:%d|", ret);
            return ret;
        }
    }

    return processed;
}


static inline xqc_int_t
xqc_qpack_on_decoder_ins(xqc_qpack_t *qpk, xqc_ins_dec_ctx_t *ctx)
{
    xqc_int_t ret = XQC_OK;

    xqc_log(qpk->log, XQC_LOG_DEBUG, "|recv decoder ins|type:%d|", ctx->type);

    switch (ctx->type) {
    case XQC_INS_TYPE_DEC_SECTION_ACK:
        ret = xqc_encoder_section_ack(qpk->enc, ctx->stream_id.value);
        if (ret != XQC_OK) {
            xqc_log(qpk->log, XQC_LOG_ERROR, "|on section ack error|ret:%i|stream_id:%ui|",
                    ret, ctx->stream_id.value);
            return -XQC_QPACK_ENCODER_ERROR;
        }
        break;

    case XQC_INS_TYPE_DEC_STREAM_CANCEL:
        ret = xqc_encoder_cancel_stream(qpk->enc, ctx->stream_id.value);
        if (ret != XQC_OK) {
            xqc_log(qpk->log, XQC_LOG_ERROR, "|on stream cancel error|ret:%i|stream_id:%ui|",
                    ret, ctx->stream_id.value);
            return -XQC_QPACK_ENCODER_ERROR;
        }
        break;

    case XQC_INS_TYPE_DEC_INSERT_CNT_INC:
        ret = xqc_encoder_increase_known_rcvd_count(qpk->enc, ctx->increment.value);
        if (ret != XQC_OK) {
            xqc_log(qpk->log, XQC_LOG_ERROR, "|on ici error|ret:%i|", ret);
            return -XQC_QPACK_ENCODER_ERROR;
        }
        break;

    default:
        xqc_log(qpk->log, XQC_LOG_ERROR, "|unknown decoder instruction|type:%ui|", ctx->type);
        return -XQC_QPACK_UNKNOWN_INSTRUCTION;
    }

    return XQC_OK;
}

ssize_t
xqc_qpack_process_decoder(xqc_qpack_t *qpk, unsigned char *data, size_t data_len)
{
    xqc_ins_dec_ctx_t *ctx = qpk->dctx;
    ssize_t processed = 0;
    while (processed < data_len) {
        /* parse decoder instruction bytes */
        ssize_t read = xqc_ins_parse_decoder(data + processed, data_len - processed, ctx);
        if (read < 0) {
            xqc_log(qpk->log, XQC_LOG_ERROR, "|parse decoder instruction error|ret:%i|", read);
            return read;
        }
        processed += read;

        /* all bytes shall be processed while not finish parsing a instruction */
        if (ctx->state != XQC_INS_DS_STATE_FINISH && data_len != processed) {
            xqc_log(qpk->log, XQC_LOG_ERROR, "|bytes remaining while not finished|");
            return -XQC_QPACK_INSTRUCTION_ERROR;
        }

        /* respond to instruction */
        if (ctx->state == XQC_INS_DS_STATE_FINISH) {
            xqc_log_event(qpk->log, QPACK_INSTRUCTION_PARSED, XQC_LOG_DECODER_EVENT, ctx);
            xqc_int_t ret = xqc_qpack_on_decoder_ins(qpk, ctx);
            if (ret != XQC_OK) {
                xqc_log(qpk->log, XQC_LOG_ERROR, "|process encoder instruction error|ret:%d|", ret);
                return ret;
            }
        }
    }

    return processed;
}

xqc_rep_ctx_t *
xqc_qpack_create_req_ctx(uint64_t stream_id)
{
    return xqc_rep_ctx_create(stream_id);
}

void
xqc_qpack_clear_req_ctx(void *ctx)
{
    xqc_rep_ctx_clear((xqc_rep_ctx_t *)ctx);
}

void
xqc_qpack_destroy_req_ctx(void *ctx)
{
    xqc_rep_ctx_free((xqc_rep_ctx_t *)ctx);
}

uint64_t
xqc_qpack_get_req_rqrd_insert_cnt(void *ctx)
{
    return xqc_rep_get_ric((xqc_rep_ctx_t *)ctx);
}


xqc_int_t
xqc_qpack_enc_headers(xqc_qpack_t *qpk, uint64_t stream_id,
    xqc_http_headers_t *headers, xqc_var_buf_t *data)
{
    xqc_var_buf_t *ins_buf = qpk->ins_cb.get_buf_cb(XQC_INS_TYPE_ENCODER, qpk->user_data);
    if (NULL == ins_buf) {
        xqc_log(qpk->log, XQC_LOG_ERROR, "|get encoder instruction error|");
        return -XQC_ENOBUF;
    }

    xqc_int_t ret = xqc_encoder_enc_headers(qpk->enc, data, ins_buf, stream_id, headers);
    if (ret != XQC_OK) {
        xqc_log(qpk->log, XQC_LOG_ERROR, "|encode headers error|%d|", ret);
        return ret;
    }

    ssize_t processed = qpk->ins_cb.write_ins_cb(XQC_INS_TYPE_ENCODER, ins_buf,
                                                      qpk->user_data);
    if (processed < 0) {
        xqc_log(qpk->log, XQC_LOG_ERROR, "|write instruction error|%d|", processed);
        return -XQC_H3_EQPACK_ENCODE;
    }

    return XQC_OK;
}


ssize_t
xqc_qpack_dec_headers(xqc_qpack_t *qpk, xqc_rep_ctx_t *req_ctx, unsigned char *data,
    size_t data_len, xqc_http_headers_t *headers, xqc_bool_t fin, xqc_bool_t *blocked)
{
    ssize_t read = 0;
    unsigned char *pos = data;
    unsigned char *end = data + data_len;

    /* prepare write headers */
    if (headers->capacity == 0) {
        xqc_h3_headers_create_buf(headers, XQC_H3_REQUEST_INITIAL_HEADERS_CAPACITY);
    }

    /* decode filed line from bytes one by one */
    while (pos < end) {
        /* header count exceed current headers capacity, expand capacity */
        if (headers->count >= headers->capacity) {
            size_t capacity = xqc_min(headers->capacity * 2, headers->capacity + 128);
            if (xqc_h3_headers_realloc_buf(headers, capacity) < 0) {
                xqc_log(qpk->log, XQC_LOG_ERROR, "|realloc headers buf error!|");
                return -XQC_QPACK_SAVE_HEADERS_ERROR;
            }
        }

        /* decode one header at most */
        xqc_http_header_t *hdr = &headers->headers[headers->count];
        read = xqc_decoder_dec_header(qpk->dec, req_ctx, pos, end - pos, hdr, blocked);
        if (read < 0) {
            xqc_log(qpk->log, XQC_LOG_ERROR, "|decode headers error!|ret:%d|", read);
            return -XQC_QPACK_DECODER_ERROR;
        }
        pos += read;

        /* one field line is available */
        if (req_ctx->state == XQC_REP_DECODE_STATE_FINISH) {
            headers->count++;
            headers->total_len += (hdr->name.iov_len + hdr->value.iov_len);
            xqc_rep_ctx_clear_rep(req_ctx);

        } else {
            if (*blocked == XQC_TRUE) {
                xqc_log(qpk->log, XQC_LOG_DEBUG, "|be blocked|");
                return pos - data;

            } else {
                /* if not blocked, and not all bytes are processed, consider it as an error */
                if (pos < end) {
                    xqc_log(qpk->log, XQC_LOG_ERROR, "|shall finish all bytes while not blocked|");
                    return -XQC_QPACK_DECODER_ERROR; 
                }
            }
        }
    }

    if (fin == XQC_TRUE && xqc_rep_get_ric(req_ctx) > 0) {
        xqc_int_t ret = xqc_qpack_notify_section_ack(qpk, req_ctx->stream_id);
        if (ret < 0) {
            xqc_log(qpk->log, XQC_LOG_ERROR, "|notify SECTION ACK error|ret:%d|", ret);
            return ret;
        }
    }

    return pos - data;
}

void
xqc_qpack_set_enc_insert_limit(xqc_qpack_t *qpk, double name_limit, double entry_limit)
{
    xqc_encoder_set_insert_limit(qpk->enc, name_limit, entry_limit);
}
