/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/http3/qpack/xqc_decoder.h"
#include "src/http3/xqc_h3_header.h"

typedef struct xqc_decoder_s {
    xqc_dtable_t           *dtable;

    /*
     * max dtable capacity is the configured size of dynamic table, this value is used to decode 
     * the Required Insert Count in encoded filed sections
     */
    size_t                  max_ents;

    /* log handler */
    xqc_log_t              *log;
} xqc_decoder_s;



xqc_decoder_t *
xqc_decoder_create(xqc_log_t *log, size_t max_dtable_cap)
{
    xqc_decoder_t *dec = xqc_malloc(sizeof(xqc_decoder_t));
    if (dec == NULL) {
        return NULL;
    }

    dec->dtable = xqc_dtable_create(XQC_QPACK_DEFAULT_HASH_TABLE_SIZE, log);
    if (dec->dtable == NULL) {
        xqc_free(dec);
        return NULL;
    }

    dec->max_ents = xqc_dtable_max_entry_cnt(max_dtable_cap);
    dec->log = log;

    return dec;
}


void
xqc_decoder_destroy(xqc_decoder_t *dec)
{
    if (dec) {
        if (dec->dtable) {
            xqc_dtable_free(dec->dtable);
        }

        xqc_free(dec);
    }
}


xqc_int_t
xqc_decoder_index(xqc_decoder_t *dec, xqc_flag_t t, uint64_t idx, xqc_var_buf_t *name_buf,
    xqc_var_buf_t *value_buf)
{
    xqc_log(dec->log, XQC_LOG_DEBUG, "|decode indexed|t:%d|idx:%ui|", t, idx);

    if (name_buf->data_len != 0 || value_buf->data_len != 0) {
        xqc_log(dec->log, XQC_LOG_ERROR, "|nv not clear|name_len:%uz|value_len:%uz|",
                name_buf->data_len, value_buf->data_len);
    }
    xqc_var_buf_clear(name_buf);
    xqc_var_buf_clear(value_buf);

    if (t == XQC_DTABLE_FLAG) {
        return xqc_dtable_get_nv(dec->dtable, idx, name_buf, value_buf);

    } else {
        return xqc_stable_get_nv(idx, name_buf, value_buf);
    }
}


xqc_int_t
xqc_decoder_name_index(xqc_decoder_t *dec, xqc_flag_t t, uint64_t idx, xqc_var_buf_t *name_buf)
{
    xqc_log(dec->log, XQC_LOG_DEBUG, "|decode name indexed|t:%d|idx:%ui|", t, idx);

    if (name_buf->data_len != 0) {
        xqc_log(dec->log, XQC_LOG_ERROR, "|nv not clear|name_len:%uz|", name_buf->data_len);
    }
    xqc_var_buf_clear(name_buf);

    if (t == XQC_DTABLE_FLAG) {
        return xqc_dtable_get_nv(dec->dtable, idx, name_buf, NULL);

    } else {
        return xqc_stable_get_nv(idx, name_buf, NULL);
    }
}

xqc_int_t
xqc_decoder_copy_header(xqc_http_header_t *hdr, xqc_var_buf_t *name, xqc_var_buf_t *value)
{
    hdr->name.iov_len = name->data_len;
    xqc_int_t ret = xqc_var_buf_save_prepare(name, 1);
    if (ret != XQC_OK) {
        return ret;
    }
    hdr->name.iov_base = xqc_var_buf_take_over(name);

    hdr->value.iov_len = value->data_len;
    ret = xqc_var_buf_save_prepare(value, 1);
    if (ret != XQC_OK) {
        return ret;
    }
    hdr->value.iov_base = xqc_var_buf_take_over(value);

    *((unsigned char *)hdr->name.iov_base + hdr->name.iov_len) = '\0';
    *((unsigned char *)hdr->value.iov_base + hdr->value.iov_len) = '\0';

    return XQC_OK;
}

xqc_int_t
xqc_decoder_save_hdr(xqc_decoder_t *dec, xqc_rep_ctx_t *ctx, xqc_http_header_t *hdr)
{
    xqc_int_t ret;
    xqc_var_buf_t *name = ctx->name->value;
    xqc_var_buf_t *value = ctx->value->value;

    /* convert index to string */
    switch (ctx->type) {
    case XQC_REP_TYPE_INDEXED:
    case XQC_REP_TYPE_POST_BASE_INDEXED:
        ret = xqc_decoder_index(dec, ctx->table, ctx->index.value, name, value);
        if (ret != XQC_OK) {
            xqc_log(dec->log, XQC_LOG_ERROR, "|decode indexed field line error|type:%d"
                    "|base:%ui|ret:%d|", ctx->type, ctx->base.value, ret);
            return -XQC_QPACK_DECODER_ERROR;
        }
        /* restore never flag */
        hdr->flags = 
            ctx->never ? XQC_HTTP_HEADER_FLAG_NEVER_INDEX : XQC_HTTP_HEADER_FLAG_NONE;
        break;

    case XQC_REP_TYPE_NAME_REFERENCE:
    case XQC_REP_TYPE_POST_BASE_NAME_REFERENCE:
        ret = xqc_decoder_name_index(dec, ctx->table, ctx->index.value, name);
        if (ret != XQC_OK) {
            xqc_log(dec->log, XQC_LOG_ERROR, "|decode name indexed field line error|type:%d|"
                    "base:%ui|ret:%d|", ctx->type, ctx->base.value, ret);
            return -XQC_QPACK_DECODER_ERROR;
        }
        /* restore never flag */
        hdr->flags = 
            ctx->never ? XQC_HTTP_HEADER_FLAG_NEVER_INDEX_VALUE : XQC_HTTP_HEADER_FLAG_NONE;
        break;

    case XQC_REP_TYPE_LITERAL:
        break;

    default:
        xqc_log(dec->log, XQC_LOG_ERROR, "|unknown field line|type:%d|", ctx->type);
        return -XQC_QPACK_DECODER_ERROR;
    }

    /* copy name and value */
    return xqc_decoder_copy_header(hdr, name, value);
}


ssize_t
xqc_decoder_dec_header(xqc_decoder_t *dec, xqc_rep_ctx_t *ctx, unsigned char *buf, size_t buf_len,
    xqc_http_header_t *hdr, xqc_bool_t *blocked)
{
    ssize_t processed = 0;
    ssize_t read = 0;

    /* decode efs prefix first */
    if (ctx->state < XQC_REP_DECODE_STATE_OPCODE) {
        read = xqc_rep_decode_prefix(ctx, dec->max_ents,
                                     xqc_dtable_get_insert_cnt(dec->dtable), buf, buf_len);
        if (read < 0) {
            xqc_log(dec->log, XQC_LOG_ERROR, "|decode prefix error|processed:%z|state:%d"
                    "|max_ents:%uz|icnt:%ui|", read, ctx->state, dec->max_ents,
                    xqc_dtable_get_insert_cnt(dec->dtable));
            return -XQC_QPACK_DECODER_ERROR;
        }
        processed += read;
        if (ctx->state == XQC_REP_DECODE_STATE_OPCODE) {
            xqc_log(dec->log, XQC_LOG_DEBUG, "|encoded field section prefix|ric:%ui|s:%d|db:%ui|",
                    ctx->ric.value, ctx->sign, ctx->base.value);
            xqc_log_event(dec->log, QPACK_HEADERS_DECODED, XQC_LOG_BLOCK_PREFIX,
                          ctx->ric.value, ctx->base.value);
        }
    }

    /* ric not satisfied, blocked */
    if (ctx->state > XQC_REP_DECODE_STATE_RICNT
        && ctx->ric.value > xqc_dtable_get_insert_cnt(dec->dtable))
    {
        *blocked = XQC_TRUE;
        return processed;
    }

    if (ctx->state >= XQC_REP_DECODE_STATE_OPCODE) {
        /* decode one field line */
        read = xqc_rep_decode_field_line(ctx, buf + processed, buf_len - processed);
        if (read < 0) {
            xqc_log(dec->log, XQC_LOG_ERROR, "|decode field line error|type:%d|state:%d|"
                    "processed:%z|", ctx->type, ctx->state, read);
            if (ctx->state == XQC_REP_DECODE_STATE_NAME && ctx->name->huff_flag > 0) {
                xqc_log(dec->log, XQC_LOG_ERROR, "|decode name error|pre_state:%d|end:%d|bit:%d|",
                        ctx->name->huff_ctx.pre_state, ctx->name->huff_ctx.end,
                        ctx->name->huff_ctx.bit);
            }
            if (ctx->state == XQC_REP_DECODE_STATE_VALUE && ctx->value->huff_flag > 0) {
                xqc_log(dec->log, XQC_LOG_ERROR, "|decode value error|pre_state:%d|end:%d|bit:%d|",
                        (unsigned int)ctx->value->huff_ctx.pre_state, (unsigned int)ctx->value->huff_ctx.end,
                        (unsigned int)ctx->value->huff_ctx.bit);
            }
            return -XQC_QPACK_DECODER_ERROR;
        }
        processed += read;

        /* finish decoding a field line, copy result to header, and reset ctx */
        if (ctx->state == XQC_REP_DECODE_STATE_FINISH) {
            xqc_log(dec->log, XQC_LOG_DEBUG, "|decode one field line|type:%d|", ctx->type);
            xqc_int_t ret = xqc_decoder_save_hdr(dec, ctx, hdr);
            if (ret != XQC_OK) {
                xqc_log(dec->log, XQC_LOG_ERROR, "|save header error|ret:%d|", ret);
                return ret;
            }
            xqc_log_event(dec->log, QPACK_HEADERS_DECODED, XQC_LOG_HEADER_BLOCK, ctx, hdr);
        }
    }

    return processed;
}


xqc_int_t
xqc_decoder_set_dtable_cap(xqc_decoder_t *dec, uint64_t cap)
{
    xqc_log(dec->log, XQC_LOG_DEBUG, "|on set dtable cap|cap:%ui|", cap);
    xqc_log_event(dec->log, QPACK_STATE_UPDATED, XQC_LOG_DECODER_EVENT, dec->dtable);
    return xqc_dtable_set_capacity(dec->dtable, cap);
}


xqc_int_t
xqc_decoder_duplicate(xqc_decoder_t *dec, uint64_t idx)
{
    uint64_t new_idx = 0;
    uint64_t base_idx = xqc_dtable_get_insert_cnt(dec->dtable);
    idx = xqc_brel2abs(base_idx, idx);

    xqc_int_t ret = xqc_dtable_duplicate(dec->dtable, idx, &new_idx);
    if (ret != XQC_OK) {
        xqc_log(dec->log, XQC_LOG_ERROR, "|duplicate entry error|ret:%d|idx:%ui|", ret, idx);
        return -XQC_QPACK_DECODER_ERROR;
    }

    xqc_log(dec->log, XQC_LOG_DEBUG, "|on duplicate|idx:%ui|new_idx:%ui|ret:%d|", 
            idx, new_idx, ret);
    xqc_log_event(dec->log, QPACK_STATE_UPDATED, XQC_LOG_DECODER_EVENT, dec->dtable);

    return XQC_OK;
}


xqc_int_t
xqc_decoder_insert_literal(xqc_decoder_t *dec, unsigned char *name, size_t nlen,
    unsigned char *value, size_t vlen)
{
    uint64_t idx = XQC_INVALID_INDEX;

    xqc_int_t ret = xqc_dtable_add(dec->dtable, name, nlen, value, vlen, &idx);
    if (ret != XQC_OK) {
        xqc_log(dec->log, XQC_LOG_ERROR, "|insert entry error|ret:%d|name:%*s|value:%*s|", ret,
                (size_t) xqc_min(nlen, 512), name, (size_t) xqc_min(vlen, 512), value);
        return -XQC_QPACK_DECODER_ERROR;
    }

    xqc_log(dec->log, XQC_LOG_DEBUG, "|on insert literal|idx:%ui|ret:%d|nlen:%uz|name:%*s|vlen:%uz|"
            "value:%*s|", idx, ret, nlen, (size_t) xqc_min(nlen, 512), name, vlen,
            (size_t) xqc_min(vlen, 512), value);
    xqc_log_event(dec->log, QPACK_STATE_UPDATED, XQC_LOG_DECODER_EVENT, dec->dtable);

    return XQC_OK;
}


xqc_int_t
xqc_decoder_insert_name_ref(xqc_decoder_t *dec, xqc_flag_t t, uint64_t nidx,
    unsigned char *value, size_t vlen)
{
    uint64_t idx;
    xqc_var_buf_t *nbuf = xqc_var_buf_create(XQC_HTTP3_QPACK_MAX_NAMELEN);
    if (nbuf == NULL) {
        return -XQC_EMALLOC;
    }
    if (t == XQC_DTABLE_FLAG) {
        nidx = xqc_brel2abs(xqc_dtable_get_insert_cnt(dec->dtable), nidx);
    }

    xqc_int_t ret = xqc_decoder_name_index(dec, t, nidx, nbuf);
    if (ret != XQC_OK) {
        xqc_log(dec->log, XQC_LOG_ERROR, "|name index error|ret:%d|nidx:%ui|", ret, nidx);
        xqc_var_buf_free(nbuf);
        return -XQC_QPACK_DECODER_ERROR;
    }

    ret = xqc_dtable_add(dec->dtable, nbuf->data, nbuf->data_len, value, vlen, &idx);
    if (ret != XQC_OK) {
        xqc_log(dec->log, XQC_LOG_ERROR, "|insert entry error|ret:%d|nidx:%ui|value:%*s|", ret,
                nidx, (size_t) xqc_min(vlen, 512), value);
        xqc_var_buf_free(nbuf);
        return -XQC_QPACK_DECODER_ERROR;
    }

    xqc_log(dec->log, XQC_LOG_DEBUG, "|on insert name ref|nidx:%ui|value:%*s|idx:%ui|",
            nidx, (size_t) xqc_min(vlen, 512), value, idx);
    xqc_log_event(dec->log, QPACK_STATE_UPDATED, XQC_LOG_DECODER_EVENT, dec->dtable);

    xqc_var_buf_free(nbuf);
    return XQC_OK;
}


uint64_t
xqc_decoder_get_insert_cnt(xqc_decoder_t *dec)
{
    return xqc_dtable_get_insert_cnt(dec->dtable);
}

void
xqc_log_QPACK_HEADERS_DECODED_callback(xqc_log_t *log, const char *func, ...)
{
    va_list args;
    va_start(args, func);
    xqc_int_t type = va_arg(args, xqc_int_t);
    if (type == XQC_LOG_BLOCK_PREFIX) {
        uint64_t ricnt = va_arg(args, uint64_t);
        uint64_t base = va_arg(args, uint64_t);
        xqc_log_implement(log, QPACK_HEADERS_DECODED, func,
                          "|prefix|ricnt:%ui|base:%ui|", ricnt, base);

    } else if (type == XQC_LOG_HEADER_BLOCK) {
        xqc_rep_ctx_t *ctx = va_arg(args, xqc_rep_ctx_t*);
        xqc_http_header_t *hdr = va_arg(args, xqc_http_header_t*);
        switch (ctx->type) {
        case XQC_REP_TYPE_INDEXED:
        case XQC_REP_TYPE_POST_BASE_INDEXED: {
            xqc_flag_t pb = ctx->type == XQC_REP_TYPE_POST_BASE_INDEXED;
            xqc_log_implement(log, QPACK_HEADERS_DECODED, func,
                              "|header|indexed field line|%s%s|index:%ui|",
                              ctx->table == XQC_DTABLE_FLAG ? "dtable" : "stable",
                              pb ? "" : "|post base", ctx->index.value);
            break;
        }

        case XQC_REP_TYPE_NAME_REFERENCE:
        case XQC_REP_TYPE_POST_BASE_NAME_REFERENCE: {
            xqc_flag_t pb = ctx->type == XQC_REP_TYPE_POST_BASE_NAME_REFERENCE;
            xqc_log_implement(log, QPACK_HEADERS_DECODED, func,
                              "|header|literal with name reference|%s%s|index:%ui|value:%*s|",
                              ctx->table == XQC_DTABLE_FLAG ? "|dtable" : "|stable",
                              pb ? "" : "|post base", ctx->index.value,
                              (size_t) hdr->value.iov_len, hdr->value.iov_base);
            break;
        }

        case XQC_REP_TYPE_LITERAL:
            if (hdr->value.iov_len > 0) {
                xqc_log_implement(log, QPACK_HEADERS_DECODED, func,
                                  "|header|literal|name:%*s|value:%*s|",
                                  (size_t) hdr->name.iov_len, hdr->name.iov_base,
                                  (size_t) hdr->value.iov_len, hdr->value.iov_base);

            } else {
                xqc_log_implement(log, QPACK_HEADERS_DECODED, func,
                                  "|header|literal|name:%*s|",
                                  (size_t) hdr->name.iov_len, hdr->name.iov_base);
            }
            break;
        }

    } else {
        uint64_t stream_id = va_arg(args, uint64_t);
        uint64_t length = va_arg(args, uint64_t);
        xqc_log_implement(log, QPACK_HEADERS_DECODED, func,
                          "|frame|stream_id:%ui|length:%ui|", stream_id, length);
    }
    va_end(args);
}
