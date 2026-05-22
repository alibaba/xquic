/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <xquic/xquic.h>
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_conn.h"
#include "src/common/xqc_algorithm.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/transport/xqc_defs.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_recv_record.h"
#include "src/transport/xqc_packet_parser.h"
#include "src/transport/xqc_cid.h"
#include "src/transport/xqc_utils.h"
#include "src/transport/xqc_engine.h"
#include "src/tls/xqc_tls.h"



static const char * const pkt_type_2_str[XQC_PTYPE_NUM] = {
    [XQC_PTYPE_INIT]                = "INIT",
    [XQC_PTYPE_0RTT]                = "0RTT",
    [XQC_PTYPE_HSK]                 = "HSK",
    [XQC_PTYPE_RETRY]               = "RETRY",
    [XQC_PTYPE_SHORT_HEADER]        = "SHORT_HEADER",
    [XQC_PTYPE_VERSION_NEGOTIATION] = "VERSION_NEGOTIATION",
};

const char *
xqc_pkt_type_2_str(xqc_pkt_type_t pkt_type)
{
    return pkt_type_2_str[pkt_type];
}

xqc_encrypt_level_t
xqc_packet_type_to_enc_level(xqc_pkt_type_t pkt_type)
{
    switch (pkt_type) {
    case XQC_PTYPE_INIT:
        return XQC_ENC_LEV_INIT;
    case XQC_PTYPE_0RTT:
        return XQC_ENC_LEV_0RTT;
    case XQC_PTYPE_HSK:
        return XQC_ENC_LEV_HSK;
    case XQC_PTYPE_SHORT_HEADER:
        return XQC_ENC_LEV_1RTT;
    default:
        return XQC_ENC_LEV_INIT;
    }
}

xqc_pkt_num_space_t
xqc_packet_type_to_pns(xqc_pkt_type_t pkt_type)
{
    switch (pkt_type) {
    case XQC_PTYPE_INIT:
        return XQC_PNS_INIT;
    case XQC_PTYPE_0RTT:
        return XQC_PNS_APP_DATA;
    case XQC_PTYPE_HSK:
        return XQC_PNS_HSK;
    case XQC_PTYPE_SHORT_HEADER:
        return XQC_PNS_APP_DATA;
    default:
        return XQC_PNS_N;
    }
}

xqc_pkt_type_t
xqc_state_to_pkt_type(xqc_connection_t *conn)
{
    switch (conn->conn_state) {
    case XQC_CONN_STATE_CLIENT_INIT:
    case XQC_CONN_STATE_CLIENT_INITIAL_SENT:
    case XQC_CONN_STATE_CLIENT_INITIAL_RECVD:
    case XQC_CONN_STATE_SERVER_INIT:
    case XQC_CONN_STATE_SERVER_INITIAL_RECVD:
    case XQC_CONN_STATE_SERVER_INITIAL_SENT:
        return XQC_PTYPE_INIT;
    case XQC_CONN_STATE_CLIENT_HANDSHAKE_RECVD:
    case XQC_CONN_STATE_CLIENT_HANDSHAKE_SENT:
    case XQC_CONN_STATE_SERVER_HANDSHAKE_SENT:
    case XQC_CONN_STATE_SERVER_HANDSHAKE_RECVD:
        return XQC_PTYPE_HSK;
    default:
        return XQC_PTYPE_SHORT_HEADER;
    }
}

uint8_t
xqc_packet_need_decrypt(xqc_packet_t *pkt)
{
    /* packets don't need decryption */
    return xqc_has_packet_number(pkt);
}

/* 
 * a client MUST discard Initial keys when it first sends a Handshake packet 
 * and a server MUST discard Initial keys when it first successfully processes a Handshake packet
 * we should ignore initial packet if xqc_conn_check_initial_packet_from_cur_state return XQC_FALSE
 */
static inline xqc_int_t
xqc_conn_check_initial_packet_from_cur_state(xqc_conn_state_t cur_state)
{
    switch(cur_state) {
        case XQC_CONN_STATE_CLIENT_INIT:
        case XQC_CONN_STATE_CLIENT_INITIAL_SENT:
        case XQC_CONN_STATE_CLIENT_INITIAL_RECVD:
        case XQC_CONN_STATE_SERVER_INIT:
        case XQC_CONN_STATE_SERVER_INITIAL_RECVD:
        case XQC_CONN_STATE_SERVER_INITIAL_SENT:
        case XQC_CONN_STATE_SERVER_HANDSHAKE_SENT:
        case XQC_CONN_STATE_SERVER_HANDSHAKE_RECVD:
            return XQC_TRUE;
        default:
            return XQC_FALSE;

    }
    return XQC_TRUE;
}


xqc_int_t
xqc_packet_parse_single(xqc_connection_t *c, xqc_packet_in_t *packet_in)
{
    unsigned char *pos = packet_in->pos;
    xqc_int_t ret = XQC_ERROR;

    if (XQC_BUFF_LEFT_SIZE(pos, packet_in->last) == 0) {
        xqc_log(c->log, XQC_LOG_ERROR,
                "|xqc_packet_parse_short_header error:%d|", ret);
        return -XQC_EILLPKT;
    }

    /* short header */
    if (XQC_PACKET_IS_SHORT_HEADER(pos)) {
        ret = xqc_packet_parse_short_header(c, packet_in);
        if (ret != XQC_OK) {
            xqc_log(c->log, XQC_LOG_ERROR,
                    "|xqc_packet_parse_short_header error:%d|", ret);
            return ret;
        }

        /* check handshake */
        if (!xqc_conn_check_handshake_completed(c)) {
            /* handshake not completed, buffer packets */
            xqc_log(c->log, XQC_LOG_WARN,
                    "|delay|buff 1RTT packet before handshake completed|");
            xqc_conn_buff_undecrypt_packet_in(packet_in, c, XQC_ENC_LEV_1RTT);
            return -XQC_EWAITING;
        }

    } else if (XQC_PACKET_IS_LONG_HEADER(pos)) {    /* long header */
        /* buffer packets if key is not ready */
        if (XQC_PACKET_LONG_HEADER_GET_TYPE(packet_in->pos) == XQC_PTYPE_0RTT) {
            c->conn_flag |= XQC_CONN_FLAG_HAS_0RTT;

            if (!xqc_tls_is_key_ready(c->tls, XQC_ENC_LEV_0RTT, XQC_KEY_TYPE_RX_READ)) {
                /* buffer packets */
                xqc_log(c->log, XQC_LOG_INFO, "|delay|buff 0RTT before 0rtt_key_ready|");
                xqc_conn_buff_undecrypt_packet_in(packet_in, c, XQC_ENC_LEV_0RTT);
                return -XQC_EWAITING;
            }

        } else if (XQC_PACKET_LONG_HEADER_GET_TYPE(packet_in->pos) == XQC_PTYPE_HSK
                   && !xqc_tls_is_key_ready(c->tls, XQC_ENC_LEV_HSK, XQC_KEY_TYPE_RX_READ))
        {
            /* buffer packets */
            xqc_log(c->log, XQC_LOG_INFO, "|delay|buff HSK before hs_rx_key_ready|");
            xqc_conn_buff_undecrypt_packet_in(packet_in, c, XQC_ENC_LEV_HSK);
            return -XQC_EWAITING;
        } else if (XQC_PTYPE_INIT == XQC_PACKET_LONG_HEADER_GET_TYPE(packet_in->pos)) {
            if (XQC_UNLIKELY(xqc_conn_check_initial_packet_from_cur_state(c->conn_state) == XQC_FALSE)) {
                xqc_log(c->log, XQC_LOG_INFO, "|initial packet should be discarded"
                        "|curr_stat:%d|", c->conn_state);
                return -XQC_EIGNORE_PKT;
            }
        }

        /* parse packet */
        ret = xqc_packet_parse_long_header(c, packet_in);
        if (XQC_OK != ret) {
            xqc_log(c->log, XQC_LOG_ERROR,
                    "|xqc_packet_parse_long_header error:%d|", ret);
            return ret;
        }

        if (XQC_PTYPE_INIT == XQC_PACKET_LONG_HEADER_GET_TYPE(pos)) {
            if (c->conn_type == XQC_CONN_TYPE_SERVER && !(c->conn_flag & XQC_CONN_FLAG_SERVER_ACCEPT)) {
                return xqc_conn_server_accept(c); 
            }
        }

    } else {
        xqc_log(c->log, XQC_LOG_INFO, "unknown packet type, first byte[%d], "
                "skip all buf, skip length: %d", pos[0], packet_in->last - packet_in->pos);
        return -XQC_EIGNORE_PKT;
    }

    return ret;
}

xqc_int_t
xqc_packet_decrypt_single(xqc_connection_t *c, xqc_packet_in_t *packet_in)
{
    xqc_int_t ret = XQC_OK;

    /* 
     * remember the last position of udp packet, as the last pointer
     * of packet_in will be changed during processing QUIC packets 
     */
    unsigned char *last = packet_in->last;

    /* decrypt packet */
    ret = xqc_packet_decrypt(c, packet_in);
    if (ret == XQC_OK) {
        /* process frames */
        xqc_log(c->log, XQC_LOG_DEBUG, "|pkt_type:%s|pkt_num:%ui|",
                xqc_pkt_type_2_str(packet_in->pi_pkt.pkt_type), packet_in->pi_pkt.pkt_num);
        ret = xqc_process_frames(c, packet_in);
        if (ret != XQC_OK) {
            xqc_log(c->log, XQC_LOG_ERROR, "|xqc_process_frames error|%d|", ret);
            return ret;
        }

    } else {
        if (ret == -XQC_TLS_DATA_REJECT) {
            xqc_log(c->log, XQC_LOG_DEBUG, "|decrypt early data reject, continue|");
            ret = -XQC_EIGNORE_PKT;

        } else {
            xqc_log_event(c->log, TRA_PACKET_DROPPED, "decrypt data error", ret, 
                xqc_pkt_type_2_str(packet_in->pi_pkt.pkt_type), packet_in->pi_pkt.pkt_num);
            c->packet_dropped_count ++;
            ret = -XQC_EDECRYPT;
            /* don't close connection, just drop the packet */
        }
        return ret;
    }

    /* restore the udp packet's end */
    packet_in->last = last;
    return ret;
}

xqc_int_t
xqc_packet_process_single(xqc_connection_t *c,
    xqc_packet_in_t *packet_in)
{
    return xqc_packet_process_single_anchored(c, packet_in, NULL, NULL);
}

/*
 * RFC 9000 Section 12.2: every coalesced packet that follows the first
 * one in a UDP datagram is required to carry the same Destination
 * Connection ID as the first packet; receivers MUST discard any
 * mismatching subsequent packet without processing its payload, while
 * continuing to process the rest of the datagram.
 *
 * The check has to happen after xqc_packet_parse_single (so that
 * pi_pkt.pkt_dcid and packet_in->last are populated for the current
 * packet) but BEFORE xqc_packet_decrypt_single, because the "decrypt"
 * step internally calls xqc_process_frames and applies STREAM/ACK/CRYPTO
 * frames to the connection state. Once that returns, dropping the packet
 * at the caller level cannot un-apply those frames - it would only skip
 * xqc_conn_on_pkt_processed bookkeeping, which is not what §12.2 requires.
 *
 * Only packets that carry a packet number participate in anchoring and
 * mismatch detection. VERSION_NEGOTIATION and RETRY are stand-alone by
 * spec and must not be coalesced, so they are skipped here to avoid
 * polluting the anchor.
 */
xqc_int_t
xqc_packet_process_single_anchored(xqc_connection_t *c,
    xqc_packet_in_t *packet_in,
    xqc_cid_t *first_dcid, xqc_bool_t *first_dcid_seen)
{
    xqc_int_t ret = XQC_ERROR;

    /* parse packet */
    ret = xqc_packet_parse_single(c, packet_in);
    if (XQC_OK != ret) {
        return ret;
    }

    /* those packets with no packet number, don't need to be decrypt or put into CC */
    if (!xqc_packet_need_decrypt(&packet_in->pi_pkt)) {
        return XQC_OK;
    }

    /*
     * Anchor on the DCID of the first parsed packet that needs decryption,
     * and reject every subsequent packet whose DCID does not match. Doing
     * this before xqc_packet_decrypt_single guarantees that the offending
     * packet's frames are never delivered to the connection state machine
     * and that no AEAD work is spent on a packet we are required to drop.
     */
    if (first_dcid != NULL && first_dcid_seen != NULL) {
        if (*first_dcid_seen == XQC_FALSE) {
            xqc_cid_set(first_dcid, packet_in->pi_pkt.pkt_dcid.cid_buf,
                        packet_in->pi_pkt.pkt_dcid.cid_len);
            *first_dcid_seen = XQC_TRUE;

        } else if (xqc_cid_is_equal(first_dcid,
                                    &packet_in->pi_pkt.pkt_dcid) != XQC_OK)
        {
            xqc_log(c->log, XQC_LOG_WARN,
                    "|coalesced pkt dcid mismatch|first_dcid:%s|pkt_dcid:%s|pkt_type:%s|",
                    xqc_dcid_str(c->engine, first_dcid),
                    xqc_scid_str(c->engine, &packet_in->pi_pkt.pkt_dcid),
                    xqc_pkt_type_2_str(packet_in->pi_pkt.pkt_type));

            xqc_log_event(c->log, TRA_PACKET_DROPPED,
                          "coalesced pkt dcid mismatch", XQC_OK,
                          xqc_pkt_type_2_str(packet_in->pi_pkt.pkt_type),
                          (uint64_t)0);
            c->packet_dropped_count++;
            return -XQC_ECOALESCED_DCID_MISMATCH;
        }
    }

    /* decrypt packet */
    ret = xqc_packet_decrypt_single(c, packet_in);
    if (ret != XQC_OK) {
        return ret;
    }

    return XQC_OK;
}




