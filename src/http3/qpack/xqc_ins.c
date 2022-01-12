/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/http3/qpack/xqc_ins.h"
#include "src/http3/qpack/dtable/xqc_dtable.h"
#include "xqc_prefixed_str.h"



xqc_ins_enc_ctx_t *
xqc_ins_encoder_ctx_create()
{
    xqc_ins_enc_ctx_t *ctx = xqc_malloc(sizeof(xqc_ins_enc_ctx_t));
    xqc_memset(ctx, 0, sizeof(xqc_ins_enc_ctx_t));
    ctx->name = xqc_prefixed_str_pctx_create(XQC_VAR_BUF_INIT_SIZE);
    ctx->value = xqc_prefixed_str_pctx_create(XQC_H3_MAX_FIELD_SECTION_SIZE);
    return ctx;
}


void
xqc_ins_encoder_ctx_free(xqc_ins_enc_ctx_t *ctx)
{
    if (ctx) {
        xqc_prefixed_str_free(ctx->name);
        xqc_prefixed_str_free(ctx->value);
        xqc_free(ctx);
    }
}


xqc_ins_dec_ctx_t *
xqc_ins_decoder_ctx_create()
{
    xqc_ins_dec_ctx_t *ctx = xqc_malloc(sizeof(xqc_ins_dec_ctx_t));
    xqc_memset(ctx, 0, sizeof(xqc_ins_dec_ctx_t));
    return ctx;
}


void
xqc_ins_decoder_ctx_free(xqc_ins_dec_ctx_t *ctx)
{
    xqc_free(ctx);
}


/* parse encoder instruction type */
xqc_ins_enc_type_t
xqc_ins_enc_type(const unsigned char *data)
{
    if (data[0] & 0x80) {
        return XQC_INS_TYPE_ENC_INSERT_NAME_REF;
    }

    if (data[0] & 0x40) {
        return XQC_INS_TYPE_ENC_INSERT_LITERAL;
    }

    if (data[0] & 0x20) {
        return XQC_INS_TYPE_ENC_SET_DTABLE_CAP;
    }

    return XQC_INS_TYPE_ENC_DUP;
}



ssize_t
xqc_ins_parse_set_dtable_capacity(unsigned char *buf, uint64_t buf_len, xqc_ins_enc_ctx_t *ctx)
{
    unsigned char *pos = buf, *end = buf + buf_len;
    ssize_t read;
    int fin = 0;

    switch (ctx->state) {
    case XQC_INS_ES_OPCODE:
        ctx->state = XQC_INS_ES_CAPACITY;
        xqc_prefixed_int_init(&ctx->capacity, 5);

    case XQC_INS_ES_CAPACITY:
        read = xqc_prefixed_int_read(&ctx->capacity, pos, end, &fin);
        if (read < 0) {
            return read;
        }
        pos += read;

        if (fin) {
            ctx->state = XQC_INS_ES_STATE_FINISH;
        }
        break;

    default:
        return -XQC_QPACK_DECODER_ERROR;
    }

    return pos - buf;
}


ssize_t
xqc_ins_parse_insert_name_reference(unsigned char *buf, uint64_t buf_len, xqc_ins_enc_ctx_t *ctx)
{
    unsigned char *pos = buf, *end = buf + buf_len;
    ssize_t read;
    int fin = 0;

    switch (ctx->state) {
    case XQC_INS_ES_OPCODE:
        ctx->table = (*pos) & 0x40;
        ctx->state = XQC_INS_ES_STATE_INDEX;
        xqc_prefixed_int_init(&ctx->name_index, 6);

    case XQC_INS_ES_STATE_INDEX:
        read = xqc_prefixed_int_read(&ctx->name_index, pos, end, &fin);
        if (read < 0) {
            return read;
        }
        pos += read;

        if (fin) {
            ctx->state = XQC_INS_ES_STATE_VALUE;
            xqc_prefixed_str_init(ctx->value, 7);

        } else {
            goto finish;
        }

        if (pos == end) {
            goto finish;
        }

    case XQC_INS_ES_STATE_VALUE:
        read = xqc_parse_prefixed_str(ctx->value, pos, end - pos, &fin);
        if (read < 0) {
            return read;
        }
        pos += read;

        if (fin) {
            ctx->state = XQC_INS_ES_STATE_FINISH;
        }
        break;

    default:
        return -XQC_QPACK_DECODER_ERROR;
    }

finish:
    return pos - buf;
}


ssize_t
xqc_ins_parse_insert_literal_name(unsigned char *buf, uint64_t buf_len, xqc_ins_enc_ctx_t *ctx)
{
    unsigned char *pos = buf, *end = buf + buf_len;
    ssize_t read;
    int fin = 0;

    switch (ctx->state) {
    case XQC_INS_ES_OPCODE:
        ctx->state = XQC_INS_ES_STATE_NAME;
        xqc_prefixed_str_init(ctx->name, 5);

    case XQC_INS_ES_STATE_NAME:
        read = xqc_parse_prefixed_str(ctx->name, pos, end - pos, &fin);
        if (read < 0) {
            return read;
        }
        pos += read;

        if (fin) {
            fin = XQC_FALSE;
            ctx->state = XQC_INS_ES_STATE_VALUE;
            xqc_prefixed_str_init(ctx->value, 7);
        }

        if (pos == end) {
            goto finish;
        }

    case XQC_INS_ES_STATE_VALUE:
        read = xqc_parse_prefixed_str(ctx->value, pos, end - pos, &fin);
        if (read < 0) {
            return read;
        }
        pos += read;

        if (fin) {
            ctx->state = XQC_INS_ES_STATE_FINISH;
        }
        break;

    default:
        return -XQC_QPACK_DECODER_ERROR;
    }

finish:
    return pos - buf;
}


ssize_t
xqc_ins_parse_duplicate(unsigned char *buf, uint64_t buf_len, xqc_ins_enc_ctx_t *ctx)
{
    unsigned char *pos = buf, *end = buf + buf_len;
    ssize_t read;
    int fin = 0;

    switch (ctx->state) {
    case XQC_INS_ES_OPCODE:
        ctx->state = XQC_INS_ES_STATE_INDEX;
        xqc_prefixed_int_init(&ctx->name_index, 5);

    case XQC_INS_ES_STATE_INDEX:
        read = xqc_prefixed_int_read(&ctx->name_index, pos, end, &fin);
        if (read < 0) {
            return read;
        }
        pos += read;

        if (fin) {
            ctx->state = XQC_INS_ES_STATE_FINISH;
        }
        break;

    default:
        return -XQC_QPACK_DECODER_ERROR;
    }

    return pos - buf;
}


ssize_t
xqc_ins_parse_encoder(unsigned char *buf, uint64_t buf_len, xqc_ins_enc_ctx_t *ctx)
{
    unsigned char *pos = buf, *end = buf + buf_len;
    ssize_t read;
    if (ctx->state == XQC_INS_ES_STATE_FINISH) {
        ctx->state = XQC_INS_ES_OPCODE;
    }

    if (ctx->state == XQC_INS_ES_OPCODE) {
        ctx->type = xqc_ins_enc_type(buf);
    }

    switch (ctx->type) {
    case XQC_INS_TYPE_ENC_SET_DTABLE_CAP:
        read = xqc_ins_parse_set_dtable_capacity(pos, end - pos, ctx);
        if (read < 0) {
            return -QPACK_ENCODER_STREAM_ERROR;
        }
        pos += read;
        break;

    case XQC_INS_TYPE_ENC_INSERT_NAME_REF:
        read = xqc_ins_parse_insert_name_reference(pos, end - pos, ctx);
        if (read < 0) {
            return -QPACK_ENCODER_STREAM_ERROR;
        }
        pos += read;
        break;

    case XQC_INS_TYPE_ENC_INSERT_LITERAL:
        read = xqc_ins_parse_insert_literal_name(pos, end - pos, ctx);
        if (read < 0) {
            return -QPACK_ENCODER_STREAM_ERROR;
        }
        pos += read;
        break;

    case XQC_INS_TYPE_ENC_DUP:
        read = xqc_ins_parse_duplicate(pos, end - pos, ctx);
        if (read < 0) {
            return -QPACK_ENCODER_STREAM_ERROR;
        }
        pos += read;
        break;

    default:
        return -QPACK_ENCODER_STREAM_ERROR;
    }

    if (pos < end && ctx->state != XQC_INS_ES_STATE_FINISH) {
        return -QPACK_ENCODER_STREAM_ERROR;
    }

    return pos - buf;
}



xqc_ins_dec_type_t
xqc_ins_decoder_type(const unsigned char *data)
{
    if (data[0] & 0x80) {
        return XQC_INS_TYPE_DEC_SECTION_ACK;
    }

    if (data[0] & 0x40) {
        return XQC_INS_TYPE_DEC_STREAM_CANCEL;
    }

    return XQC_INS_TYPE_DEC_INSERT_CNT_INC;
}


ssize_t
xqc_ins_parse_decoder(unsigned char *buf, uint64_t buf_len, xqc_ins_dec_ctx_t *ctx)
{
    unsigned char *pos = buf, *end = buf + buf_len;
    ssize_t read;
    int fin = 0;

    if (ctx->state == XQC_INS_DS_STATE_FINISH) {
        ctx->state = XQC_INS_DS_STATE_OPCODE;
    }

    while (ctx->state != XQC_INS_DS_STATE_FINISH && pos < end) {
        switch (ctx->state) {

        case XQC_INS_DS_STATE_OPCODE:
            ctx->type = xqc_ins_decoder_type(buf);
            switch (ctx->type) {
            case XQC_INS_TYPE_DEC_SECTION_ACK:
                xqc_prefixed_int_init(&ctx->stream_id, 7);
                ctx->state = XQC_INS_DS_STATE_STREAM_ID;
                break;
            case XQC_INS_TYPE_DEC_STREAM_CANCEL:
                xqc_prefixed_int_init(&ctx->stream_id, 6);
                ctx->state = XQC_INS_DS_STATE_STREAM_ID;
                break;
            case XQC_INS_TYPE_DEC_INSERT_CNT_INC:
                xqc_prefixed_int_init(&ctx->increment, 6);
                ctx->state = XQC_INS_DS_STATE_INCREMENT;
                break;
            default:
                return -XQC_QPACK_INSTRUCTION_ERROR;
            }
            break;

        case XQC_INS_DS_STATE_STREAM_ID:
            read = xqc_prefixed_int_read(&ctx->stream_id, pos, end, &fin);
            if (read < 0) {
                return read;
            }
            pos += read;

            if (fin) {
                ctx->state = XQC_INS_DS_STATE_FINISH;
            }
            break;

        case XQC_INS_DS_STATE_INCREMENT:
            read = xqc_prefixed_int_read(&ctx->increment, pos, end, &fin);
            if (read < 0) {
                return read;
            }
            pos += read;

            if (fin) {
                ctx->state = XQC_INS_DS_STATE_FINISH;
            }
            break;

        default:
            return -XQC_QPACK_DECODER_ERROR;
        }
    }

    return pos - buf;
}



xqc_int_t
xqc_ins_write_set_dtable_cap(xqc_var_buf_t *buf, uint64_t capacity)
{
    xqc_int_t ret = xqc_var_buf_save_prepare(buf, xqc_prefixed_int_put_len(capacity, 5));
    if (ret != XQC_OK) {
        return ret;
    }

    unsigned char *pos = buf->data + buf->data_len;
    *pos = 0x20;
    pos = xqc_prefixed_int_put(pos, capacity, 5);
    buf->data_len = pos - buf->data;

    return XQC_OK;
}


xqc_int_t
xqc_ins_write_insert_name_ref(xqc_var_buf_t *buf, xqc_flag_t table, uint64_t index,
    unsigned char *value, uint64_t vlen)
{
    xqc_int_t ret = xqc_var_buf_save_prepare(buf, xqc_prefixed_int_put_len(index, 6)
                                                  + xqc_prefixed_int_put_len(vlen, 7) + vlen);
    if (ret != XQC_OK) {
        return ret;
    }

    /* write prefix and t flag */
    unsigned char *pos = buf->data + buf->data_len;
    *pos = 0x80 | (table << 6);

    /* write index */
    pos = xqc_prefixed_int_put(pos, index, 6);
    buf->data_len = pos - buf->data;

    /* write value */
    *pos = 0x00;
    ret = xqc_write_prefixed_str(buf, value, vlen, 7);
    if (ret != XQC_OK) {
        return ret;
    }

    return XQC_OK;
}



xqc_int_t
xqc_ins_write_insert_literal_name(xqc_var_buf_t *buf, unsigned char *name, uint64_t nlen,
    unsigned char *value, uint64_t vlen)
{
    xqc_int_t ret = xqc_var_buf_save_prepare(buf, xqc_prefixed_int_put_len(nlen, 5) + nlen
                                                  + xqc_prefixed_int_put_len(vlen, 7) + vlen);
    if (ret != XQC_OK) {
        return ret;
    }

    /* write prefix, name, value */
    unsigned char *pos = buf->data + buf->data_len;
    *pos = 0x40;

    ret = xqc_write_prefixed_str(buf, name, nlen, 5);
    if (ret != XQC_OK) {
        return ret;
    }

    pos = buf->data + buf->data_len;
    *pos = 0x00;
    ret = xqc_write_prefixed_str(buf, value, vlen, 7);
    if (ret != XQC_OK) {
        return ret;
    }

    return XQC_OK;
}


xqc_int_t
xqc_ins_write_dup(xqc_var_buf_t *buf, uint64_t index)
{
    xqc_int_t ret = xqc_var_buf_save_prepare(buf, xqc_prefixed_int_put_len(index, 5));
    if (ret != XQC_OK) {
        return ret;
    }

    unsigned char *pos = buf->data + buf->data_len;
    *pos = 0x00;

    pos = xqc_prefixed_int_put(pos, index, 5);
    buf->data_len = pos - buf->data;

    return XQC_OK;
}


xqc_int_t
xqc_ins_write_section_ack(xqc_var_buf_t *buf, uint64_t stream_id)
{
    xqc_int_t ret = xqc_var_buf_save_prepare(buf, xqc_prefixed_int_put_len(stream_id, 7));
    if (ret != XQC_OK) {
        return ret;
    }

    unsigned char *pos = buf->data + buf->data_len;
    *pos = 0x80;

    pos = xqc_prefixed_int_put(pos, stream_id, 7);
    buf->data_len = pos - buf->data;

    return XQC_OK;
}


xqc_int_t
xqc_ins_write_stream_cancel(xqc_var_buf_t *buf, uint64_t stream_id)
{
    xqc_int_t ret = xqc_var_buf_save_prepare(buf, xqc_prefixed_int_put_len(stream_id, 6));
    if (ret != XQC_OK) {
        return ret;
    }

    unsigned char *pos = buf->data + buf->data_len;
    *pos = 0x40;

    pos = xqc_prefixed_int_put(pos, stream_id, 6);
    buf->data_len = pos - buf->data;

    return XQC_OK;
}


xqc_int_t
xqc_ins_write_icnt_increment(xqc_var_buf_t *buf, uint64_t increment)
{
    xqc_int_t ret = xqc_var_buf_save_prepare(buf, xqc_prefixed_int_put_len(increment, 6));
    if (ret != XQC_OK) {
        return ret;
    }

    unsigned char *pos = buf->data + buf->data_len;
    *pos = 0x00;

    pos = xqc_prefixed_int_put(pos, increment, 6);
    buf->data_len = pos - buf->data;

    return XQC_OK;
}
