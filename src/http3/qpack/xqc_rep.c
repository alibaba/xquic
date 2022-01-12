/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/common/utils/huffman/xqc_huffman.h"
#include "src/http3/qpack/xqc_rep.h"
#include "src/http3/qpack/xqc_prefixed_str.h"

xqc_rep_ctx_t *
xqc_rep_ctx_create(uint64_t stream_id)
{
    xqc_rep_ctx_t *ctx = xqc_malloc(sizeof(xqc_rep_ctx_t));
    if (NULL == ctx) {
        return NULL;
    }

    xqc_memset(ctx, 0, sizeof(xqc_rep_ctx_t));
    ctx->stream_id = stream_id;
    ctx->name = xqc_prefixed_str_pctx_create(XQC_VAR_BUF_INIT_SIZE);
    ctx->value = xqc_prefixed_str_pctx_create(XQC_VAR_BUF_INIT_SIZE);
    ctx->state = XQC_REP_DECODE_STATE_RICNT;
    return ctx;
}

/* called after all headers in a HEADERS frame are decoded */
void
xqc_rep_ctx_clear(xqc_rep_ctx_t *ctx)
{
    ctx->state = XQC_REP_DECODE_STATE_RICNT;
    xqc_prefixed_int_init(&ctx->ric, 0);
    xqc_prefixed_int_init(&ctx->base, 0);
    xqc_prefixed_int_init(&ctx->index, 0);
    xqc_prefixed_str_init(ctx->name, 0);
    xqc_prefixed_str_init(ctx->value, 0);
}

/* called after a header is decoded */
void
xqc_rep_ctx_clear_rep(xqc_rep_ctx_t *ctx)
{
    ctx->state = XQC_REP_DECODE_STATE_OPCODE;
    xqc_prefixed_int_init(&ctx->index, 0);
    xqc_prefixed_str_init(ctx->name, 0);
    xqc_prefixed_str_init(ctx->value, 0);
}

void
xqc_rep_ctx_free(xqc_rep_ctx_t *ctx)
{
    if (ctx) {
        xqc_prefixed_str_free(ctx->name);
        xqc_prefixed_str_free(ctx->value);
        xqc_free(ctx);
    }
}

uint64_t
xqc_rep_get_ric(xqc_rep_ctx_t *ctx)
{
    return ctx->ric.value;
}


xqc_rep_type_t
xqc_rep_type(const unsigned char *data)
{
    if (data[0] & 0x80) {
        return XQC_REP_TYPE_INDEXED;

    } else if (data[0] & 0x40) {
        return XQC_REP_TYPE_NAME_REFERENCE;

    } else if (data[0] & 0x20) {
        return XQC_REP_TYPE_LITERAL;

    } else if (data[0] & 0x10) {
        return XQC_REP_TYPE_POST_BASE_INDEXED;

    } else {
        return XQC_REP_TYPE_POST_BASE_NAME_REFERENCE;
    }
}


/* reconstruct required insert count */
static inline xqc_int_t
xqc_rep_reconstruct_ric(xqc_rep_ctx_t *ctx, uint64_t max_ents, uint64_t insert_cnt)
{
    if (ctx->ric.value != 0) {
        uint64_t full_range = 2 * max_ents;
        if (ctx->ric.value > full_range) {
            return -XQC_QPACK_DECODER_ERROR;
        }

        uint64_t max_value = insert_cnt + max_ents;
        uint64_t max_wrapped = max_value / full_range * full_range;
        ctx->ric.value = max_wrapped + ctx->ric.value - 1;
        if (ctx->ric.value > max_value) {
            if (ctx->ric.value < full_range) {
                return -XQC_QPACK_DECODER_ERROR;
            }
            ctx->ric.value -= full_range;
        }

        if (ctx->ric.value == 0) {
            return -XQC_QPACK_DECODER_ERROR;
        }
    }

    return XQC_OK;
}


ssize_t
xqc_rep_decode_prefix(xqc_rep_ctx_t *ctx, size_t max_ents, uint64_t icnt, unsigned char *buf,
    uint64_t buf_len)
{
    if (buf_len == 0) {
        return 0;
    }

    unsigned char *pos = buf, *end = buf + buf_len;
    ssize_t read;
    int fin = 0;
    switch (ctx->state) {
    case XQC_REP_DECODE_STATE_RICNT:
        read = xqc_prefixed_int_read(&ctx->ric, pos, end, &fin);
        if (read < 0) {
            return read;
        }
        pos += read;

        if (fin) {
            ctx->state = XQC_REP_DECODE_STATE_BASE_SIGN;
            xqc_int_t ret = xqc_rep_reconstruct_ric(ctx, max_ents, icnt);
            if (ret < 0) {
                return ret;
            }

        } else {
            break;
        }

    case XQC_REP_DECODE_STATE_BASE_SIGN:
        ctx->sign = (*pos) & 0x80;
        ctx->state = XQC_REP_DECODE_STATE_BASE;
        xqc_prefixed_int_init(&ctx->base, 7);

    case XQC_REP_DECODE_STATE_BASE:
        read = xqc_prefixed_int_read(&ctx->base, pos, end, &fin);
        if (read < 0) {
            return read;
        }
        pos += read;
        if (fin) {
            if (ctx->sign == 0) {
                ctx->base.value = ctx->ric.value + ctx->base.value;
            } else {
                ctx->base.value = ctx->ric.value - ctx->base.value - 1;
            }
            ctx->state = XQC_REP_DECODE_STATE_OPCODE;
        }
        break;

    default:
        return -XQC_QPACK_DECODER_ERROR;
    }

    if (pos < end && ctx->state != XQC_REP_DECODE_STATE_OPCODE) {
        return -XQC_QPACK_DECODER_ERROR;
    }

    return pos - buf;
}

ssize_t
xqc_rep_decode_base_index(xqc_rep_ctx_t *ctx, unsigned char *buf, uint64_t buf_len)
{
    if (buf_len == 0) {
        return 0;
    }

    unsigned char *pos = buf, *end = buf + buf_len;
    ssize_t read;
    int fin = 0;

    switch (ctx->state) {
    case XQC_REP_DECODE_STATE_OPCODE:
        ctx->table = (*pos) & 0x40 ? XQC_STABLE_FLAG : XQC_DTABLE_FLAG;
        ctx->state = XQC_REP_DECODE_STATE_INDEX;
        xqc_prefixed_int_init(&ctx->index, 6);
    case XQC_REP_DECODE_STATE_INDEX:
        read = xqc_prefixed_int_read(&ctx->index, pos, end, &fin);
        if (read < 0) {
            return read;
        }
        pos += read;
        if (fin) {
            ctx->state = XQC_REP_DECODE_STATE_FINISH;
        }
        break;
    default:
        return -XQC_QPACK_DECODER_ERROR;
    }
finish:
    return pos - buf;
}

ssize_t
xqc_rep_decode_post_base_index(xqc_rep_ctx_t *ctx, unsigned char *buf, uint64_t buf_len)
{
    if (buf_len == 0) {
        return 0;
    }

    unsigned char *pos = buf, *end = buf + buf_len;
    ssize_t read;
    int fin = 0;

    switch (ctx->state) {
    case XQC_REP_DECODE_STATE_OPCODE:
        ctx->state = XQC_REP_DECODE_STATE_INDEX;
        ctx->table = XQC_DTABLE_FLAG;
        xqc_prefixed_int_init(&ctx->index, 4);
    case XQC_REP_DECODE_STATE_INDEX:
        read = xqc_prefixed_int_read(&ctx->index, pos, end, &fin);
        if (read < 0) {
            return read;
        }
        pos += read;
        if (fin) {
            ctx->state = XQC_REP_DECODE_STATE_FINISH;
        }
        break;
    default:
        return -XQC_QPACK_DECODER_ERROR;
    }
finish:
    return pos - buf;
}

ssize_t
xqc_rep_decode_name_reference(xqc_rep_ctx_t *ctx, unsigned char *buf, uint64_t buf_len)
{
    if (buf_len == 0) {
        return 0;
    }

    unsigned char *pos = buf, *end = buf + buf_len;
    ssize_t read;
    int fin = 0;

    switch (ctx->state) {
    case XQC_REP_DECODE_STATE_OPCODE:
        ctx->never = (*pos) & 0x20;
        ctx->table = (*pos) & 0x10 ? XQC_STABLE_FLAG : XQC_DTABLE_FLAG;
        ctx->state = XQC_REP_DECODE_STATE_INDEX;
        xqc_prefixed_int_init(&ctx->index, 4);

    case XQC_REP_DECODE_STATE_INDEX:
        read = xqc_prefixed_int_read(&ctx->index, pos, end, &fin);
        if (read < 0) {
            return read;
        }
        pos += read;

        if (fin) {
            ctx->state = XQC_REP_DECODE_STATE_VALUE;
            xqc_prefixed_str_init(ctx->value, 7);

        } else {
            goto finish;
        }

        if (pos == end) {
            goto finish;
        }

    case XQC_REP_DECODE_STATE_VALUE:
        read = xqc_parse_prefixed_str(ctx->value, pos, end - pos, &fin);
        if (read < 0) {
            return read;
        }
        pos += read;

        if (fin) {
            ctx->state = XQC_REP_DECODE_STATE_FINISH;
        }
        break;

    default:
        return -XQC_QPACK_DECODER_ERROR;
    }

finish:
    return pos - buf;
}


ssize_t
xqc_rep_decode_post_base_name_reference(xqc_rep_ctx_t *ctx, unsigned char *buf, uint64_t buf_len)
{
    if (buf_len == 0) {
        return 0;
    }

    unsigned char *pos = buf, *end = buf + buf_len;
    ssize_t read;
    int fin = 0;

    switch (ctx->state) {
    case XQC_REP_DECODE_STATE_OPCODE:
        ctx->never = (*pos) & 0x08;
        ctx->table = XQC_DTABLE_FLAG;
        ctx->state = XQC_REP_DECODE_STATE_INDEX;
        xqc_prefixed_int_init(&ctx->index, 3);

    case XQC_REP_DECODE_STATE_INDEX:
        read = xqc_prefixed_int_read(&ctx->index, pos, end, &fin);
        if (read < 0) {
            return read;
        }
        pos += read;

        if (fin) {
            ctx->state = XQC_REP_DECODE_STATE_VALUE;
            xqc_prefixed_str_init(ctx->value, 7);

        } else {
            goto finish;
        }

        if (pos == end) {
            goto finish;
        }

    case XQC_REP_DECODE_STATE_VALUE:
        read = xqc_parse_prefixed_str(ctx->value, pos, end - pos, &fin);
        if (read < 0) {
            return read;
        }
        pos += read;

        if (fin) {
            ctx->state = XQC_REP_DECODE_STATE_FINISH;
        }
        break;

    default:
        return -XQC_QPACK_DECODER_ERROR;
    }

finish:
    return pos - buf;
}

/* decode literal field line with literal name */
ssize_t
xqc_rep_decode_literal(xqc_rep_ctx_t *ctx, unsigned char *buf, uint64_t buf_len)
{
    if (buf_len == 0) {
        return 0;
    }

    unsigned char *pos = buf, *end = buf + buf_len;
    ssize_t read;
    int fin = 0;

    switch (ctx->state) {
    case XQC_REP_DECODE_STATE_OPCODE:
        ctx->never = (*pos) & 0x10;
        xqc_prefixed_str_init(ctx->name, 3);
        ctx->state = XQC_REP_DECODE_STATE_NAME;

    case XQC_REP_DECODE_STATE_NAME:
        read = xqc_parse_prefixed_str(ctx->name, pos, end - pos, &fin);
        if (read < 0) {
            return read;
        }
        pos += read;

        if (fin) {
            ctx->state = XQC_REP_DECODE_STATE_VALUE;
            xqc_prefixed_str_init(ctx->value, 7);

        } else {
            goto finish;
        }

        if (pos == end) {
            goto finish;
        }

    case XQC_REP_DECODE_STATE_VALUE:
        read = xqc_parse_prefixed_str(ctx->value, pos, end - pos, &fin);
        if (read < 0) {
            return read;
        }
        pos += read;

        if (fin) {
            ctx->state = XQC_REP_DECODE_STATE_FINISH;
        }
        break;

    default:
        return -XQC_QPACK_DECODER_ERROR;
    }

finish:
    return pos - buf;
}

ssize_t
xqc_rep_decode_field_line(xqc_rep_ctx_t *ctx, unsigned char *buf, uint64_t buf_len)
{
    if (buf_len == 0) {
        return 0;
    }

    ssize_t read = 0;
    unsigned char *pos = buf, *end = buf + buf_len;
    if (ctx->state == XQC_REP_DECODE_STATE_OPCODE) {
        ctx->type = xqc_rep_type(pos);
    }

    switch (ctx->type) {
    case XQC_REP_TYPE_INDEXED:
        read = xqc_rep_decode_base_index(ctx, pos, end - pos);
        if (read < 0) {
            return read;
        }
        pos += read;

        if (ctx->state == XQC_REP_DECODE_STATE_FINISH) {
            if (ctx->table == XQC_DTABLE_FLAG) {
                ctx->index.value = xqc_brel2abs(ctx->base.value, ctx->index.value);
            }
        }
        break;

    case XQC_REP_TYPE_POST_BASE_INDEXED:
        ctx->table = 0;
        read = xqc_rep_decode_post_base_index(ctx, pos, end - pos);
        if (read < 0) {
            return read;
        }
        pos += read;

        if (ctx->state == XQC_REP_DECODE_STATE_FINISH) {
            if (ctx->table == XQC_DTABLE_FLAG) {
                ctx->index.value = xqc_pbrel2abs(ctx->base.value, ctx->index.value);
            }
        }
        break;

    case XQC_REP_TYPE_NAME_REFERENCE:
        read = xqc_rep_decode_name_reference(ctx, pos, end - pos);
        if (read < 0) {
            return read;
        }
        pos += read;

        if (ctx->state == XQC_REP_DECODE_STATE_FINISH) {
            if (ctx->table == XQC_DTABLE_FLAG) {
                ctx->index.value = xqc_brel2abs(ctx->base.value, ctx->index.value);
            }
        }
        break;

    case XQC_REP_TYPE_POST_BASE_NAME_REFERENCE:
        ctx->table = 0;
        read = xqc_rep_decode_post_base_name_reference(ctx, pos, end - pos);
        if (read < 0) {
            return read;
        }
        pos += read;

        if (ctx->state == XQC_REP_DECODE_STATE_FINISH) {
            if (ctx->table == XQC_DTABLE_FLAG) {
                ctx->index.value = xqc_pbrel2abs(ctx->base.value, ctx->index.value);
            }
        }
        break;

    case XQC_REP_TYPE_LITERAL:
        read = xqc_rep_decode_literal(ctx, pos, end - pos);
        if (read < 0) {
            return read;
        }
        pos += read;
        break;

    default:
        return -XQC_QPACK_DECODER_ERROR;
    }

    return pos - buf;
}


static inline uint64_t
xqc_rep_encode_ricnt(uint64_t max_ents, uint64_t ricnt)
{
    return (ricnt == 0) ? 0 : ((ricnt % (2 * max_ents)) + 1);
}


xqc_int_t
xqc_rep_write_prefix(xqc_var_buf_t *buf, uint64_t max_ents, uint64_t ricnt, uint64_t base)
{
    uint64_t dbase = 0;
    xqc_flag_t s = 0;   /* base flag */
    uint64_t enc_ricnt = xqc_rep_encode_ricnt(max_ents, ricnt);

    /* S flag and delta base */
    if (base >= ricnt) {
        s = 0;
        dbase = base - ricnt;

    } else {
        s = 1;
        dbase = ricnt - 1 - base;
    }

    /* calculate the size of encoded field section prefix */
    xqc_int_t ret = xqc_var_buf_save_prepare(buf, xqc_prefixed_int_put_len(enc_ricnt, 8)
                                                   + xqc_prefixed_int_put_len(dbase, 7));
    if (ret != XQC_OK) {
        return ret;
    }

    unsigned char *pos = buf->data + buf->data_len;

    /* write required insert count */
    pos = xqc_prefixed_int_put(pos, enc_ricnt, 8);
    buf->data_len = pos - buf->data;

    /* write base flag */
    *pos = s << 7;

    /* write delta base */
    pos = xqc_prefixed_int_put(pos, dbase, 7);
    buf->data_len = pos - buf->data;

    return XQC_OK;
}


xqc_int_t
xqc_rep_write_indexed(xqc_var_buf_t *buf, xqc_flag_t t, uint64_t idx)
{
    xqc_int_t ret = xqc_var_buf_save_prepare(buf, xqc_prefixed_int_put_len(idx, 6));
    if (ret != XQC_OK) {
        return ret;
    }

    unsigned char *pos = buf->data + buf->data_len;

    /* write prefix pattern and t flag */
    *pos = 0x80 | (t << 6);

    /* write index */
    pos = xqc_prefixed_int_put(pos, idx, 6);
    buf->data_len = pos - buf->data;

    return XQC_OK;
}


xqc_int_t
xqc_rep_write_indexed_pb(xqc_var_buf_t *buf, uint64_t idx)
{
    xqc_int_t ret = xqc_var_buf_save_prepare(buf, xqc_prefixed_int_put_len(idx, 4));
    if (ret != XQC_OK) {
        return ret;
    }

    unsigned char *pos = buf->data + buf->data_len;

    /* write prefix pattern */
    *pos = 0x10;

    /* write post-base index */
    pos = xqc_prefixed_int_put(pos, idx, 4);
    buf->data_len = pos - buf->data;

    return XQC_OK;
}


xqc_int_t
xqc_rep_write_literal_with_name_ref(xqc_var_buf_t *buf, xqc_flag_t n, xqc_flag_t t, uint64_t nidx,
    uint64_t vlen, uint8_t *value)
{
    xqc_int_t ret = xqc_var_buf_save_prepare(buf, xqc_prefixed_int_put_len(nidx, 4)
                                                  + xqc_prefixed_int_put_len(vlen, 7)
                                                  + vlen);
    if (ret != XQC_OK) {
        return ret;
    }

    unsigned char *pos = buf->data + buf->data_len;

    /* write prefix pattern, N bit, T bit */
    *pos = 0x40 | (n << 5) | (t << 4);

    /* write name index */
    pos = xqc_prefixed_int_put(pos, nidx, 4);
    buf->data_len = pos - buf->data;

    /* write value huffman flag, value len, and value */
    *pos = 0x00;
    ret = xqc_write_prefixed_str(buf, value, vlen, 7);
    if (ret != XQC_OK) {
        return ret;
    }

    return XQC_OK;
}


xqc_int_t
xqc_rep_write_literal_with_pb_name_ref(xqc_var_buf_t *buf, xqc_flag_t n, uint64_t nidx,
    uint64_t vlen, uint8_t *value)
{
    xqc_int_t ret = xqc_var_buf_save_prepare(buf, xqc_prefixed_int_put_len(nidx, 3)
                                                  + xqc_prefixed_int_put_len(vlen, 7)
                                                  + vlen);
    if (ret != XQC_OK) {
        return ret;
    }

    unsigned char *pos = buf->data + buf->data_len;

    /* write prefix pattern and n bit, prefix pattern is 0x0X */
    *pos = (n << 3);
    pos = xqc_prefixed_int_put(pos, nidx, 3);
    buf->data_len = pos - buf->data;

    /* write value huffman flag and value string */
    *pos = 0x00;
    ret = xqc_write_prefixed_str(buf, value, vlen, 7);
    if (ret != XQC_OK) {
        return ret;
    }

    return XQC_OK;
}


xqc_int_t
xqc_rep_write_literal_name_value(xqc_var_buf_t *buf, xqc_flag_t n, uint64_t nlen, uint8_t *name,
    uint64_t vlen, uint8_t *value)
{
    xqc_int_t ret = xqc_var_buf_save_prepare(buf, xqc_prefixed_int_put_len(nlen, 3) + nlen
                                                  + xqc_prefixed_int_put_len(vlen, 7) + vlen);
    if (ret != XQC_OK) {
        return ret;
    }

    unsigned char *pos = buf->data + buf->data_len;

    /* write prefix pattern, n flag, name huffman flag */
    *pos = 0x20 | (n << 4);

    /* write name len and name */
    ret = xqc_write_prefixed_str(buf, name, nlen, 3);
    if (ret != XQC_OK) {
        return ret;
    }

    /* write value huffman bit, value len, and value */
    pos = buf->data + buf->data_len;
    *pos = 0x00;
    ret = xqc_write_prefixed_str(buf, value, vlen, 7);
    if (ret != XQC_OK) {
        return ret;
    }

    return XQC_OK;
}

