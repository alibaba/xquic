/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_discrete_int_parser.h"

void
xqc_discrete_int_pctx_clear(xqc_discrete_int_pctx_t *pctx)
{
    pctx->vi = 0;
    pctx->left = 0;
}

ssize_t
xqc_discrete_vint_parse(const uint8_t *p, size_t sz,
    xqc_discrete_int_pctx_t *pctx, xqc_bool_t *fin)
{
    *fin = XQC_FALSE;
    if (sz == 0) {
        return 0;
    }

    const uint8_t *pos = p;

    /* read the first byte */
    if (pctx->left == 0) {
        pctx->left = xqc_get_varint_len(p);
        pctx->vi = xqc_get_varint_fb(p);

        pctx->left--;
        sz--;
        pos++;
    }

    size_t cnt = xqc_min(pctx->left, sz);
    const uint8_t *end = pos + cnt;
    while (pos < end) {
        pctx->vi = (pctx->vi << 8) + *pos;
        pos++;
    }

    pctx->left -= cnt;
    if (pctx->left == 0) {
        *fin = XQC_TRUE;
    }

    return (pos - p);
}


ssize_t
xqc_fixed_len_int_parse(const uint8_t *p, size_t sz, uint8_t len,
    xqc_discrete_int_pctx_t *pctx, xqc_bool_t *fin)
{
    *fin = XQC_FALSE;
    if (sz == 0) {
        return 0;
    }

    const uint8_t *pos = p;

    /* set remain bytes state if it is the first byte now */
    if (pctx->left == 0) {
        pctx->left = len;
    }

    size_t cnt = xqc_min(pctx->left, sz);
    const uint8_t *end = pos + cnt;
    while (pos < end) {
        pctx->vi = (pctx->vi << 8) + *pos;
        pos++;
    }

    pctx->left -= cnt;
    if (pctx->left == 0) {
        *fin = XQC_TRUE;
    }

    return (pos - p);
}
