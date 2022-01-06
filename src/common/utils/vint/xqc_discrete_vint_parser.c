/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_discrete_vint_parser.h"

void
xqc_h3_vint_pctx_clear(xqc_discrete_vint_pctx_t *pctx)
{
    pctx->vi = 0;
    pctx->left = 0;
}

ssize_t
xqc_discrete_vint_parse(const uint8_t *p, size_t sz, xqc_discrete_vint_pctx_t *st, xqc_bool_t *fin)
{
    *fin = XQC_FALSE;
    if (sz == 0) {
        return 0;
    }

    const uint8_t *pos = p;

    /* read the first byte */
    if (st->left == 0) {
        st->left = xqc_get_varint_len(p);
        st->vi = xqc_get_varint_fb(p);

        st->left--;
        sz--;
        pos++;
    }

    size_t cnt = xqc_min(st->left, sz);
    const uint8_t *end = pos + cnt;
    while (pos < end) {
        st->vi = (st->vi << 8) + *pos;
        pos++;
    }

    st->left -= cnt;
    if (st->left == 0) {
        *fin = XQC_TRUE;
    }

    return (pos - p);
}
