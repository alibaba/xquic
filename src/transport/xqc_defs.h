/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_DEFS_H
#define XQC_DEFS_H

#include <stdint.h>
#include <xquic/xquic.h>

#define XQC_MAX_PACKET_LEN              1500

/* default connection timeout(millisecond) */
#define XQC_CONN_DEFAULT_IDLE_TIMEOUT   120000
/* default connection initial timeout(millisecond) */
#define XQC_CONN_INITIAL_IDLE_TIMEOUT   10000


#define XQC_CONN_ADDR_VALIDATION_CID_ENTROPY 8

/* connection PTO packet count */
#define XQC_CONN_PTO_PKT_CNT_MAX        2

/* connection max UDP payload size */
#define XQC_CONN_MAX_UDP_PAYLOAD_SIZE   1500

/* connection active cid limit */
#define XQC_CONN_ACTIVE_CID_LIMIT       8

/* version definitions */
#define XQC_VERSION_V1_VALUE            0x00000001
#define XQC_IDRAFT_VER_29_VALUE         0xFF00001D

#define XQC_PROTO_VERSION_LEN           4

/* the value of max_streams transport parameter or MAX_STREAMS frame must <= 2^60 */
#define XQC_MAX_STREAMS                 ((uint64_t)1 << 60)

#define XQC_CONN_MAX_CRYPTO_DATA_TOTAL_LEN (10*1024*1024)

/* length of stateless reset token */
#define XQC_STATELESS_RESET_TOKENLEN    16

/* max token length supported by xquic */
#define XQC_MAX_TOKEN_LEN               256


extern const uint32_t       xqc_proto_version_value[];
extern const unsigned char  xqc_proto_version_field[][XQC_PROTO_VERSION_LEN];


#define xqc_check_proto_version_valid(ver) \
        ((ver) > XQC_IDRAFT_INIT_VER && (ver) < XQC_IDRAFT_VER_NEGOTIATION)


/* max alpn length */
#define XQC_MAX_ALPN_LEN                        255

/* limit of anti-amplification */
#define XQC_DEFAULT_ANTI_AMPLIFICATION_LIMIT    3

#endif