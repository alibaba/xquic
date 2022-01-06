/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/http3/qpack/xqc_prefixed_str.h"


void
xqc_prefixed_str_init(xqc_prefixed_str_t *pctx, uint8_t n)
{
    xqc_prefixed_int_init(&pctx->len, n);
    pctx->used_len = 0;
    xqc_var_buf_clear(pctx->value);
    pctx->stg = XQC_PS_STAGE_H;
    xqc_huffman_dec_ctx_init(&pctx->huff_ctx);
}

void
xqc_prefixed_str_free(xqc_prefixed_str_t *pctx)
{
    if (pctx != NULL) {
        if (pctx->value != NULL) {
            xqc_var_buf_free(pctx->value);
            pctx->value = NULL;
        }
        xqc_free(pctx);
    }
}

xqc_prefixed_str_t *
xqc_prefixed_str_pctx_create(size_t capacity)
{
    xqc_prefixed_str_t *pctx = xqc_malloc(sizeof(xqc_prefixed_str_t));
    memset(pctx, 0, sizeof(xqc_prefixed_str_t));

    pctx->value = xqc_var_buf_create(capacity);
    if (pctx->value == NULL) {
        xqc_free(pctx);
        return NULL;
    }

    xqc_prefixed_str_init(pctx, 0);
    return pctx;
}

ssize_t
xqc_parse_prefixed_str(xqc_prefixed_str_t *pstr, uint8_t *buf, size_t len, int *fin_flag)
{
    xqc_int_t   ret;
    uint8_t    *pos = buf, *end = buf + len;
    ssize_t     read = 0;
    ssize_t     write = 0;
    ssize_t     l = 0;
    int         fin = 0;

    *fin_flag = XQC_FALSE;
    switch (pstr->stg) {
    case XQC_PS_STAGE_H:
        pstr->huff_flag = (*pos) & (1 << pstr->len.prefix);
        pstr->stg = XQC_PS_STAGE_LEN;

    case XQC_PS_STAGE_LEN:
        read = xqc_prefixed_int_read(&pstr->len, pos, end, &fin);
        if (read < 0) {
            return read;
        }
        pos += read;

        if (fin) {
            /* zero-length string, finish and return directly */
            if (pstr->len.value == 0) {
                pstr->stg = XQC_PS_STAGE_FINISH;
                break;
            }

            pstr->stg = XQC_PS_STAGE_VALUE;
            if (pstr->huff_flag > 0) {
                xqc_huffman_dec_ctx_init(&pstr->huff_ctx);
                pstr->used_len = 0;
                xqc_var_buf_clear(pstr->value);
            }

            if (pos == end) {
                break;
            }

        } else {
            /* need more bytes for decode prefixed int */
            break;
        }

    case XQC_PS_STAGE_VALUE:
        if (pstr->huff_flag == 0) {
            /* get all of remained input buffer of all of remained value length */
            l = xqc_min(end - pos, pstr->len.value - pstr->value->data_len);
            ret = xqc_var_buf_save_data(pstr->value, pos, l);
            if (ret != XQC_OK) {
                return ret;
            }
            pos += l;

            if (pstr->value->data_len == pstr->len.value) {
                pstr->stg = XQC_PS_STAGE_FINISH;
            }

        } else {
            while (pos < end) {
                /* l is the length to be read */
                l = xqc_min(end - pos, pstr->len.value - pstr->used_len);
                ret = xqc_var_buf_save_prepare(pstr->value, 2 * (pstr->len.value - pstr->used_len));
                if (ret != XQC_OK) {
                    return ret;
                }

                /* decode huffman string */
                read = xqc_huffman_dec(&pstr->huff_ctx, pstr->value->data + pstr->value->data_len,
                                       pstr->value->buf_len - pstr->value->data_len, pos, l, 
                                       pstr->used_len + l == pstr->len.value, &write);
                if (read < 0) {
                    return read;
                }

                pos += read;
                pstr->used_len += read;         /* processed bytes of huffman decoded buffer */
                pstr->value->data_len += write; /* output string length */

                /* all huffman encoded bytes are read */
                if (pstr->used_len == pstr->len.value) {
                    pstr->stg = XQC_PS_STAGE_FINISH;
                    break;
                }
            }
        }
        break;

    default:
        return -XQC_QPACK_STATE_ERROR;
    }

    /* write '\0' */
    if (pstr->stg == XQC_PS_STAGE_FINISH) {
        ret = xqc_var_buf_save_prepare(pstr->value, 1);
        if (ret != XQC_OK) {
            return ret;
        }

        pstr->value->data[pstr->value->data_len] = '\0';
        *fin_flag = XQC_TRUE;
    }

    return pos - buf;
}

xqc_int_t
xqc_write_prefixed_str(xqc_var_buf_t *buf, uint8_t *str, uint64_t len, uint8_t n)
{
    xqc_int_t   ret;
    uint8_t    *pos;
    size_t      ps_len = 0;

    /* write str */
    size_t huff_len = xqc_huffman_enc_len(str, len);
    if (huff_len < len) {
        ps_len = xqc_prefixed_int_put_len(huff_len, n) + huff_len;
        ret = xqc_var_buf_save_prepare(buf, ps_len);
        if (ret != XQC_OK) {
            return ret;
        }

        pos = buf->data + buf->data_len;

        /* write huffman flag */
        pos[0] |= 1 << n;

        /* write length */
        pos = xqc_prefixed_int_put(pos, huff_len, n);
        buf->data_len = pos - buf->data;

        /* write string */
        pos = xqc_huffman_enc(pos, str, len);
        buf->data_len = pos - buf->data;
        if (buf->data_len > buf->buf_len) {
            return XQC_ERROR;
        }

    } else {
        ps_len = xqc_prefixed_int_put_len(len, n) + len;
        ret = xqc_var_buf_save_prepare(buf, ps_len);
        if (ret != XQC_OK) {
            return ret;
        }

        pos = buf->data + buf->data_len;

        /* set huffman bit to 0 */
        pos[0] &= ~(1 << n);

        pos = xqc_prefixed_int_put(pos, len, n);
        buf->data_len = pos - buf->data;

        ret = xqc_var_buf_save_data(buf, str, len);
        if (ret != XQC_OK) {
            return ret;
        }
    }

    return XQC_OK;
}
