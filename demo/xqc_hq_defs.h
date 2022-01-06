/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_HQ_DEFS_H
#define XQC_HQ_DEFS_H

#include <xquic/xquic.h>
#include "src/common/xqc_malloc.h"

#include <inttypes.h>

#define XQC_ALPN_HQ_INTEROP         "hq-interop"
#define XQC_ALPN_HQ_INTEROP_LEN     10
#define XQC_ALPN_HQ_29              "hq-29"
#define XQC_ALPN_HQ_29_LEN          5

static const char* const xqc_hq_alpn[] = {
    [XQC_IDRAFT_INIT_VER]        = "",                      /* placeholder */
    [XQC_VERSION_V1]             = XQC_ALPN_HQ_INTEROP,     /* QUIC v1 */
    [XQC_IDRAFT_VER_29]          = XQC_ALPN_HQ_29,          /* draft-29 */
    [XQC_IDRAFT_VER_NEGOTIATION] = "",
};

#define PRINT_LOG(format, ...) printf("%s|%d|"format"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)

#endif
