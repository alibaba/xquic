/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_PACKET_H_INCLUDED_
#define _XQC_PACKET_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include "src/common/xqc_list.h"
#include "src/tls/xqc_tls_defs.h"

#define XQC_ACK_SPACE                       16
#define XQC_FEC_SPACE                       12
#define XQC_HEADER_SPACE                    28
#define XQC_QUIC_MIN_MSS                    1200
/* 1500 - 40 (IPv6) - 8 (UDP) - 16 (ACK) - 16 (AEAD) */
#define XQC_QUIC_MAX_MSS                    1420
#define XQC_MSS                             (XQC_QUIC_MAX_MSS + XQC_ACK_SPACE)

/* max 0rtt packet count sent by client */
#define XQC_PACKET_0RTT_MAX_COUNT           30
/* max 0rtt packet count buffered by server before Initial packet received */
#define XQC_UNDECRYPT_0RTT_MAX_BEFORE_INIT  10
/* max buffered packet count */
#define XQC_UNDECRYPT_PACKET_MAX            100

typedef enum xqc_pkt_num_space {
    XQC_PNS_INIT      = 0,
    XQC_PNS_HSK       = 1,
    XQC_PNS_APP_DATA  = 2,
    XQC_PNS_N         = 3,
} xqc_pkt_num_space_t;

typedef enum xqc_pkt_type {
    XQC_PTYPE_INIT  = 0,
    XQC_PTYPE_0RTT  = 1,
    XQC_PTYPE_HSK   = 2,
    XQC_PTYPE_RETRY = 3,
    XQC_PTYPE_SHORT_HEADER,
    XQC_PTYPE_VERSION_NEGOTIATION,
    XQC_PTYPE_NUM,
} xqc_pkt_type_t;


struct xqc_packet_s {
    xqc_packet_number_t     pkt_num;
    xqc_pkt_num_space_t     pkt_pns;
    xqc_pkt_type_t          pkt_type;
    xqc_cid_t               pkt_dcid;
    xqc_cid_t               pkt_scid;

    /*
     * length is the sum of pkt_numlen and the length of QUIC packet payload.
     */
    uint64_t                length;
    size_t                  pkt_num_offset;

};


#define XQC_PACKET_IS_LONG_HEADER(buf)          ((buf[0] & 0x80) == 0x80)
#define XQC_PACKET_IS_SHORT_HEADER(buf)         ((buf[0] & 0xC0) == 0x40)

#define XQC_PACKET_LONG_HEADER_GET_TYPE(buf)    ((buf[0] & 0x30) >> 4)

#define XQC_PACKET_VERSION_LENGTH               4
#define XQC_PACKET_LONG_HEADER_PREFIX_LENGTH    (1 + XQC_PACKET_VERSION_LENGTH)
#define XQC_PACKET_INITIAL_MIN_LENGTH           XQC_QUIC_MIN_MSS

#define XQC_PACKET_SHORT_HEADER_PKTNO_LEN(buf)  ((buf[0] & 0x03) + 1)
#define XQC_PACKET_SHORT_HEADER_KEY_PHASE(buf)  ((buf[0] & 0x04) >> 2)

#define xqc_parse_uint16(p) ((p)[0] << 8 | (p)[1])
#define xqc_parse_uint32(p) ((p)[0] << 24 | (p)[1] << 16 | (p)[2] << 8 | (p)[3])

/* check if the packet has packet number */
static inline uint8_t
xqc_has_packet_number(xqc_packet_t *pkt)
{
    /* VERSION_NEGOTIATION/RETRY packet don't have packet number */
    if (XQC_UNLIKELY(XQC_PTYPE_VERSION_NEGOTIATION == pkt->pkt_type
                     || XQC_PTYPE_RETRY == pkt->pkt_type))
    {
        return XQC_FALSE;
    }

    return XQC_TRUE;
}

const char *xqc_pkt_type_2_str(xqc_pkt_type_t pkt_type);

xqc_encrypt_level_t xqc_packet_type_to_enc_level(xqc_pkt_type_t pkt_type);

xqc_pkt_num_space_t xqc_packet_type_to_pns(xqc_pkt_type_t pkt_type);

xqc_pkt_type_t xqc_state_to_pkt_type(xqc_connection_t *conn);

/**
 * process a single QUIC packet from packet_in
 */
xqc_int_t xqc_packet_process_single(xqc_connection_t *c, xqc_packet_in_t *packet_in);


#endif /* _XQC_PACKET_H_INCLUDED_ */
