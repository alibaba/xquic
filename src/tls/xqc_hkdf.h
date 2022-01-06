/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_HKDF_H_
#define XQC_HKDF_H_

#include "src/tls/xqc_crypto.h"

xqc_int_t xqc_hkdf_extract(uint8_t *dest, size_t destlen, const uint8_t *secret, size_t secretlen,
    const uint8_t *salt, size_t saltlen, const xqc_digest_t *md);

xqc_int_t xqc_hkdf_expand(uint8_t *dest, size_t destlen, const uint8_t *secret, size_t secretlen,
    const uint8_t *info, size_t infolen, const xqc_digest_t *md);

xqc_int_t xqc_hkdf_expand_label(uint8_t *dest, size_t destlen, const uint8_t *secret,
    size_t secretlen, const uint8_t *label, size_t labellen, const xqc_digest_t *md);

#endif