/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_h3_defs.h"

#include <xquic/xquic.h>

const char* const xqc_h3_alpn[] = {
    [XQC_IDRAFT_INIT_VER]        = "",              /* placeholder */
    [XQC_VERSION_V1]             = XQC_ALPN_H3,     /* QUIC v1 */
    [XQC_IDRAFT_VER_29]          = XQC_ALPN_H3_29,  /* draft-29 */
    [XQC_IDRAFT_VER_NEGOTIATION] = "",
};
