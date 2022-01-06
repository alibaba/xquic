/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/tls/xqc_hkdf.h"
#include "src/common/xqc_str.h"

xqc_int_t
xqc_hkdf_expand_label(uint8_t *dest, size_t destlen,
    const uint8_t *secret, size_t secretlen,
    const uint8_t *label, size_t labellen,
    const xqc_digest_t *md) 
{
    unsigned char        info[256];
    static const uint8_t LABEL[] = "tls13 ";
    unsigned char       *p = info;

    *p++ = destlen / 256;
    *p++ = destlen % 256;
    *p++ = xqc_lengthof(LABEL) + labellen;
    p = xqc_cpymem(p, LABEL, xqc_lengthof(LABEL));
    p = xqc_cpymem(p, label, labellen);
    *p++ = 0;

    return xqc_hkdf_expand(dest, destlen, secret, secretlen, info, p - info, md);
}
