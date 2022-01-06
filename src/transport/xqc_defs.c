/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/transport/xqc_defs.h"
#include "src/common/xqc_str.h"
#include <string.h>

const uint32_t xqc_proto_version_value[XQC_VERSION_MAX] = {
    0xFFFFFFFF,
    0x00000001,
    0xFF00001D,
    0x00000000,
};


const unsigned char xqc_proto_version_field[XQC_VERSION_MAX][XQC_PROTO_VERSION_LEN] = {
    [XQC_IDRAFT_INIT_VER]        = { 0xFF, 0xFF, 0xFF, 0xFF, },  /* placeholder */
    [XQC_VERSION_V1]             = { 0x00, 0x00, 0x00, 0x01, },
    [XQC_IDRAFT_VER_29]          = { 0xFF, 0x00, 0x00, 0x1D, },
    [XQC_IDRAFT_VER_NEGOTIATION] = { 0x00, 0x00, 0x00, 0x00, },
};
