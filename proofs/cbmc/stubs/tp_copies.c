/*
 * Verbatim copies of small functions that the parsers call, so that the
 * harnesses do not need xqc_cid.c and xqc_fec.c, which include the OpenSSL
 * headers (not available for the 32-bit model) and define the CID-set
 * functions that stubs/packet_stubs.c replaces.  Keep in sync with:
 *   xqc_cid_is_equal(), xqc_cid_set()  src/transport/xqc_cid.c
 *   xqc_set_fec_scheme()               src/transport/xqc_fec.c
 */
#include <string.h>
#include <xquic/xquic.h>
#include "src/common/xqc_str.h"

xqc_int_t
xqc_cid_is_equal(const xqc_cid_t *dst, const xqc_cid_t *src)
{
    if (dst == NULL || src == NULL) {
        return XQC_ERROR;
    }

    if (dst->cid_len != src->cid_len) {
        return XQC_ERROR;
    }

    if (xqc_memcmp(dst->cid_buf, src->cid_buf, dst->cid_len)) {
        return XQC_ERROR;
    }

    return XQC_OK;
}

void
xqc_cid_set(xqc_cid_t *cid, const unsigned char *data, uint8_t len)
{
    cid->cid_len = len;
    if (len) {
        xqc_memcpy(cid->cid_buf, data, len);
    }
}

xqc_int_t
xqc_set_fec_scheme(uint64_t in, xqc_fec_schemes_e *out)
{
    switch (in) {
    case XQC_REED_SOLOMON_CODE:
        *out = XQC_REED_SOLOMON_CODE;
        return XQC_OK;
    case XQC_XOR_CODE:
        *out = XQC_XOR_CODE;
        return XQC_OK;
    case XQC_PACKET_MASK_CODE:
        *out = XQC_PACKET_MASK_CODE;
        return XQC_OK;
    default:
        break;
    }

    return -XQC_EFEC_SCHEME_ERROR;
}
