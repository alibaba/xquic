/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_transport_params.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/common/xqc_str.h"
#include "src/transport/xqc_defs.h"
#include "src/transport/xqc_cid.h"
#include "src/transport/xqc_fec.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>


#define XQC_PREFERRED_ADDR_IPV4_LEN         4
#define XQC_PREFERRED_ADDR_IPV4_PORT_LEN    2
#define XQC_PREFERRED_ADDR_IPV6_LEN         16
#define XQC_PREFERRED_ADDR_IPV6_PORT_LEN    2

/* ack_delay_exponent above 20 is invalid */
#define XQC_MAX_ACK_DELAY_EXPONENT          20

static inline uint16_t
xqc_get_uint16(const uint8_t *p)
{
    uint16_t n;
    memcpy(&n, p, 2);
    return ntohs(n);
}


static ssize_t 
xqc_transport_params_calc_length(const xqc_transport_params_t *params,
    xqc_transport_params_type_t exttype) 
{
    size_t len = 0;
    size_t preferred_addrlen = 0, preferred_fec_paramslen = 0;

    if (params->original_dest_connection_id_present) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_ORIGINAL_DEST_CONNECTION_ID) +
               xqc_put_varint_len(params->original_dest_connection_id.cid_len) + 
               params->original_dest_connection_id.cid_len;
    }

    if (params->max_idle_timeout) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_MAX_IDLE_TIMEOUT) + 
               xqc_put_varint_len(xqc_put_varint_len(params->max_idle_timeout)) +
               xqc_put_varint_len(params->max_idle_timeout);
    }

    if (XQC_TP_TYPE_ENCRYPTED_EXTENSIONS == exttype 
        && params->stateless_reset_token_present) 
    {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_STATELESS_RESET_TOKEN) +
               xqc_put_varint_len(XQC_STATELESS_RESET_TOKENLEN) + 
               XQC_STATELESS_RESET_TOKENLEN;
    }

    if (params->max_udp_payload_size != XQC_DEFAULT_MAX_UDP_PAYLOAD_SIZE) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_MAX_UDP_PAYLOAD_SIZE) + 
               xqc_put_varint_len(xqc_put_varint_len(params->max_udp_payload_size)) +
               xqc_put_varint_len(params->max_udp_payload_size);
    }

    if (params->initial_max_data) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_INITIAL_MAX_DATA) + 
               xqc_put_varint_len(xqc_put_varint_len(params->initial_max_data)) +
               xqc_put_varint_len(params->initial_max_data);
    }

    if (params->initial_max_stream_data_bidi_local) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL) + 
               xqc_put_varint_len(xqc_put_varint_len(params->initial_max_stream_data_bidi_local)) +
               xqc_put_varint_len(params->initial_max_stream_data_bidi_local);
    }

    if (params->initial_max_stream_data_bidi_remote) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE) + 
               xqc_put_varint_len(xqc_put_varint_len(params->initial_max_stream_data_bidi_remote)) +
               xqc_put_varint_len(params->initial_max_stream_data_bidi_remote);
    }

    if (params->initial_max_stream_data_uni) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI) + 
               xqc_put_varint_len(xqc_put_varint_len(params->initial_max_stream_data_uni)) +
               xqc_put_varint_len(params->initial_max_stream_data_uni);
    }

    if (params->initial_max_streams_bidi) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI) + 
               xqc_put_varint_len(xqc_put_varint_len(params->initial_max_streams_bidi)) +
               xqc_put_varint_len(params->initial_max_streams_bidi);
    }

    if (params->initial_max_streams_uni) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI) + 
               xqc_put_varint_len(xqc_put_varint_len(params->initial_max_streams_uni)) +
               xqc_put_varint_len(params->initial_max_streams_uni);
    }

    if (params->ack_delay_exponent != XQC_DEFAULT_ACK_DELAY_EXPONENT) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_ACK_DELAY_EXPONENT) + 
               xqc_put_varint_len(xqc_put_varint_len(params->ack_delay_exponent)) +
               xqc_put_varint_len(params->ack_delay_exponent);
    }

    if (params->max_ack_delay != XQC_DEFAULT_MAX_ACK_DELAY) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_MAX_ACK_DELAY) + 
               xqc_put_varint_len(xqc_put_varint_len(params->max_ack_delay)) +
               xqc_put_varint_len(params->max_ack_delay);
    }

    if (params->disable_active_migration) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_DISABLE_ACTIVE_MIGRATION) +
               xqc_put_varint_len(0);   /* disable_active_migration is zero-length transport parameter */
    }

    /* PREFERRED_ADDRESS */
    if (exttype == XQC_TP_TYPE_ENCRYPTED_EXTENSIONS
        && params->preferred_address_present
        && params->preferred_address.cid.cid_len > 0)
    {
        preferred_addrlen = sizeof(params->preferred_address.ipv4) +
                            sizeof(params->preferred_address.ipv4_port) +
                            sizeof(params->preferred_address.ipv6) +
                            sizeof(params->preferred_address.ipv6_port) +
                            sizeof(params->preferred_address.cid.cid_len) +
                            params->preferred_address.cid.cid_len +
                            sizeof(params->preferred_address.stateless_reset_token);

        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_PREFERRED_ADDRESS) +
               xqc_put_varint_len(preferred_addrlen) + preferred_addrlen;
    }

    if (params->active_connection_id_limit != XQC_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_ACTIVE_CONNECTION_ID_LIMIT) +
               xqc_put_varint_len(xqc_put_varint_len(params->active_connection_id_limit)) +
               xqc_put_varint_len(params->active_connection_id_limit);
    }

    if (params->initial_source_connection_id_present) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_INITIAL_SOURCE_CONNECTION_ID) +
               xqc_put_varint_len(params->initial_source_connection_id.cid_len) +
               params->initial_source_connection_id.cid_len;
    }

    if (params->retry_source_connection_id_present) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_RETRY_SOURCE_CONNECTION_ID) +
               xqc_put_varint_len(params->retry_source_connection_id.cid_len) +
               params->retry_source_connection_id.cid_len;
    }

    if (params->no_crypto) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_NO_CRYPTO) +
               xqc_put_varint_len(xqc_put_varint_len(params->no_crypto)) +
               xqc_put_varint_len(params->no_crypto);
    }

    if (params->enable_multipath) {
        if (params->multipath_version == XQC_MULTIPATH_06) {
            /* enable_multipath (-draft06) is zero-length transport parameter */
            len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_ENABLE_MULTIPATH_06) +
                   xqc_put_varint_len(0);

        } else if (params->multipath_version == XQC_MULTIPATH_05) {
            /* enable_multipath (-draft05) is zero-length transport parameter */
            len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_ENABLE_MULTIPATH_05) +
                   xqc_put_varint_len(0);
        
        } else {
            len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_ENABLE_MULTIPATH_04) +
                   xqc_put_varint_len(xqc_put_varint_len(params->enable_multipath)) +
                   xqc_put_varint_len(params->enable_multipath);
        }
    }

    if (params->close_dgram_redundancy == XQC_RED_SET_CLOSE) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_CLOSE_DGRAM_REDUNDANCY) +
           xqc_put_varint_len(xqc_put_varint_len(params->close_dgram_redundancy)) +
           xqc_put_varint_len(params->close_dgram_redundancy);  
    }          

#ifdef XQC_ENABLE_FEC
    if (params->enable_encode_fec || params->enable_decode_fec) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_FEC_VERSION) + 
            xqc_put_varint_len(0);
    }

    /*
     * if enable_encode_fec, add fec related params' length:
     * max_symbol_size; max_src_symbol_len; max_encoder_schemes;
     */
    if (params->enable_encode_fec
        && params->fec_encoder_schemes_num > 0
        && params->fec_encoder_schemes_num <= XQC_FEC_MAX_SCHEME_NUM)
    {
        preferred_fec_paramslen += xqc_put_varint_len(params->fec_encoder_schemes_num);

        for (xqc_int_t i = 0; i < params->fec_encoder_schemes_num; i++) {
            preferred_fec_paramslen += xqc_put_varint_len(params->fec_encoder_schemes[i]);
        }
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_FEC_ENCODER_SCHEMES) +
                xqc_put_varint_len(preferred_fec_paramslen) + preferred_fec_paramslen;

        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_FEC_MAX_SYMBOL_SIZE) +
               xqc_put_varint_len(xqc_put_varint_len(params->fec_max_symbol_size)) +
               xqc_put_varint_len(params->fec_max_symbol_size);

        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_FEC_MAX_SYMBOL_NUM) +
               xqc_put_varint_len(xqc_put_varint_len(params->fec_max_symbols_num)) +
               xqc_put_varint_len(params->fec_max_symbols_num);
    }
    /*
     * if enable_decode_fec, add fec related params' length:
     * max_decoder_schemes;
     */
    if (params->enable_decode_fec
        && params->fec_decoder_schemes_num > 0
        && params->fec_decoder_schemes_num <= XQC_FEC_MAX_SCHEME_NUM)
    {
        preferred_fec_paramslen = 0;
        preferred_fec_paramslen += xqc_put_varint_len(params->fec_decoder_schemes_num);
        for (xqc_int_t i = 0; i < params->fec_decoder_schemes_num; i++) {
            preferred_fec_paramslen += xqc_put_varint_len(params->fec_decoder_schemes[i]);
        }
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_FEC_DECODER_SCHEMES) +
                xqc_put_varint_len(preferred_fec_paramslen) + preferred_fec_paramslen;
    }
#endif

    if (params->max_datagram_frame_size) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_MAX_DATAGRAM_FRAME_SIZE) +
               xqc_put_varint_len(xqc_put_varint_len(params->max_datagram_frame_size)) +
               xqc_put_varint_len(params->max_datagram_frame_size);
    }

    if (params->conn_option_num) {
        len += xqc_put_varint_len(XQC_TRANSPORT_PARAM_GOOGLE_CO) + 
               xqc_put_varint_len(params->conn_option_num * sizeof(uint32_t)) +
               params->conn_option_num * sizeof(uint32_t);
    }

    return len;
}


/**
 * put variant int value param into buf
 */
inline static uint8_t*
xqc_put_varint_param(uint8_t* p, xqc_transport_param_id_t id, uint64_t v)
{
    p = xqc_put_varint(p, id);
    p = xqc_put_varint(p, xqc_put_varint_len(v));
    p = xqc_put_varint(p, v);
    return p;
}

/**
 * put zero-length value param into buf
 */
inline static uint8_t*
xqc_put_zero_length_param(uint8_t* p, xqc_transport_param_id_t id)
{
    p = xqc_put_varint(p, id);  /* put id */
    p = xqc_put_varint(p, 0);   /* put length, which is 0 */
    return p;
}


xqc_int_t
xqc_encode_transport_params(const xqc_transport_params_t *params,
    xqc_transport_params_type_t exttype, uint8_t *out, size_t out_cap, size_t *out_len)
{
    uint8_t *p = out;
    size_t len = 0;
    size_t preferred_addrlen = 0, preferred_fec_paramslen = 0;
    int i;

    /* calculate encoding length */
    len += xqc_transport_params_calc_length(params, exttype);
    if (out_cap < len) {
        return -XQC_TLS_NOBUF;
    }

    /* start writing */
    /* write transport parameter buffer len */
    if (params->original_dest_connection_id_present) {
        p = xqc_put_varint(p, XQC_TRANSPORT_PARAM_ORIGINAL_DEST_CONNECTION_ID);
        p = xqc_put_varint(p, params->original_dest_connection_id.cid_len);
        p = xqc_cpymem(p, params->original_dest_connection_id.cid_buf,
                       params->original_dest_connection_id.cid_len);
    }

    if (params->max_idle_timeout) {
        p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_MAX_IDLE_TIMEOUT, 
                                 params->max_idle_timeout);
    }

    if (XQC_TP_TYPE_ENCRYPTED_EXTENSIONS == exttype 
        && params->stateless_reset_token_present) 
    {
        p = xqc_put_varint(p, XQC_TRANSPORT_PARAM_STATELESS_RESET_TOKEN);
        p = xqc_put_varint(p, XQC_STATELESS_RESET_TOKENLEN);
        p = xqc_cpymem(p, params->stateless_reset_token, XQC_STATELESS_RESET_TOKENLEN);
    }

    if (params->max_udp_payload_size != XQC_DEFAULT_MAX_UDP_PAYLOAD_SIZE) {
        p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_MAX_UDP_PAYLOAD_SIZE, 
                                 params->max_udp_payload_size);
    }

    if (params->initial_max_data) {
        p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_INITIAL_MAX_DATA, 
                                 params->initial_max_data);
    }

    if (params->initial_max_stream_data_bidi_local) {
        p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                                 params->initial_max_stream_data_bidi_local);
    }

    if (params->initial_max_stream_data_bidi_remote) {
        p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                                 params->initial_max_stream_data_bidi_remote);
    }

    if (params->initial_max_stream_data_uni) {
        p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI,
                                 params->initial_max_stream_data_uni);
    }

    if (params->initial_max_streams_bidi) {
        p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI,
                                 params->initial_max_streams_bidi);
    }

    if (params->initial_max_streams_uni) {
        p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI,
                                 params->initial_max_streams_uni);
    }

    if (params->ack_delay_exponent != XQC_DEFAULT_ACK_DELAY_EXPONENT) {
        p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_ACK_DELAY_EXPONENT,
                                 params->ack_delay_exponent);
    }

    if (params->max_ack_delay != XQC_DEFAULT_MAX_ACK_DELAY) {
        p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_MAX_ACK_DELAY,
                                 params->max_ack_delay);
    }

    if (params->disable_active_migration) {
        p = xqc_put_zero_length_param(p, XQC_TRANSPORT_PARAM_DISABLE_ACTIVE_MIGRATION);
    }

    if (exttype == XQC_TP_TYPE_ENCRYPTED_EXTENSIONS 
        && params->preferred_address_present
        && params->preferred_address.cid.cid_len > 0)   /* cid MUST NOT be zero-length */
    {
        preferred_addrlen = sizeof(params->preferred_address.ipv4) + 
                            sizeof(params->preferred_address.ipv4_port) + 
                            sizeof(params->preferred_address.ipv6) + 
                            sizeof(params->preferred_address.ipv6_port) +
                            sizeof(params->preferred_address.cid.cid_len) + 
                            params->preferred_address.cid.cid_len +
                            sizeof(params->preferred_address.stateless_reset_token);

        p = xqc_put_varint(p, XQC_TRANSPORT_PARAM_PREFERRED_ADDRESS);
        p = xqc_put_varint(p, preferred_addrlen);
        p = xqc_cpymem(p, params->preferred_address.ipv4, sizeof(params->preferred_address.ipv4));
        p = xqc_put_uint16be(p, params->preferred_address.ipv4_port);
        p = xqc_cpymem(p, params->preferred_address.ipv6, sizeof(params->preferred_address.ipv6));
        p = xqc_put_uint16be(p, params->preferred_address.ipv6_port);
        *p++ = params->preferred_address.cid.cid_len;
        p = xqc_cpymem(p, params->preferred_address.cid.cid_buf, params->preferred_address.cid.cid_len);
        p = xqc_cpymem(p, params->preferred_address.stateless_reset_token, XQC_STATELESS_RESET_TOKENLEN);
    }

    if (params->active_connection_id_limit != XQC_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT) {
        p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_ACTIVE_CONNECTION_ID_LIMIT,
                                 params->active_connection_id_limit);
    }

    if (params->initial_source_connection_id_present) {
        p = xqc_put_varint(p, XQC_TRANSPORT_PARAM_INITIAL_SOURCE_CONNECTION_ID);
        p = xqc_put_varint(p, params->initial_source_connection_id.cid_len);
        p = xqc_cpymem(p, params->initial_source_connection_id.cid_buf, params->initial_source_connection_id.cid_len);
    }

    if (params->retry_source_connection_id_present) {
        p = xqc_put_varint(p, XQC_TRANSPORT_PARAM_RETRY_SOURCE_CONNECTION_ID);
        p = xqc_put_varint(p, params->retry_source_connection_id.cid_len);
        p = xqc_cpymem(p, params->retry_source_connection_id.cid_buf, params->retry_source_connection_id.cid_len);
    }

    if (params->max_datagram_frame_size) {
        p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_MAX_DATAGRAM_FRAME_SIZE,
                                 params->max_datagram_frame_size);
    }

    if (params->no_crypto) {
        p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_NO_CRYPTO,
                                 params->no_crypto);
    }

    if (params->enable_multipath) {
        if (params->multipath_version == XQC_MULTIPATH_06) {
            p = xqc_put_zero_length_param(p, XQC_TRANSPORT_PARAM_ENABLE_MULTIPATH_06);

        } else if (params->multipath_version == XQC_MULTIPATH_05) {
            p = xqc_put_zero_length_param(p, XQC_TRANSPORT_PARAM_ENABLE_MULTIPATH_05);

        } else {
            p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_ENABLE_MULTIPATH_04, params->enable_multipath);
        }
    }

    if (params->close_dgram_redundancy == XQC_RED_SET_CLOSE) {
        p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_CLOSE_DGRAM_REDUNDANCY,
                                 params->close_dgram_redundancy);
    }


    if (params->conn_option_num) {
        p = xqc_put_varint(p, XQC_TRANSPORT_PARAM_GOOGLE_CO);
        p = xqc_put_varint(p, sizeof(uint32_t) * params->conn_option_num);
        for (i = 0; i < params->conn_option_num; i++) {
            p = xqc_put_uint32be(p, params->conn_options[i]);
        }
    }

#ifdef XQC_ENABLE_FEC
    if (params->enable_encode_fec || params->enable_decode_fec) {
        p = xqc_put_zero_length_param(p, XQC_TRANSPORT_PARAM_FEC_VERSION);
    }

    if (params->enable_encode_fec
        && params->fec_encoder_schemes_num > 0
        && params->fec_encoder_schemes_num <= XQC_FEC_MAX_SCHEME_NUM)
    {
        preferred_fec_paramslen = 0;
        p = xqc_put_varint(p, XQC_TRANSPORT_PARAM_FEC_ENCODER_SCHEMES);
        preferred_fec_paramslen = xqc_put_varint_len(params->fec_encoder_schemes_num);
        for (xqc_int_t i = 0; i < params->fec_encoder_schemes_num; i++) {
            preferred_fec_paramslen += xqc_put_varint_len(params->fec_encoder_schemes[i]);
        }
        p = xqc_put_varint(p, preferred_fec_paramslen);

        p = xqc_put_varint(p, params->fec_encoder_schemes_num);
        for (xqc_int_t i = 0; i < params->fec_encoder_schemes_num; i++) {
            p = xqc_put_varint(p, params->fec_encoder_schemes[i]);
        }
        p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_FEC_MAX_SYMBOL_SIZE,
                                 params->fec_max_symbol_size);

        p = xqc_put_varint_param(p, XQC_TRANSPORT_PARAM_FEC_MAX_SYMBOL_NUM,
                                 params->fec_max_symbols_num);
    }

    if (params->enable_decode_fec
        && params->fec_decoder_schemes_num > 0
        && params->fec_decoder_schemes_num <= XQC_FEC_MAX_SCHEME_NUM)
    {
        preferred_fec_paramslen = 0;
        if (params->fec_decoder_schemes_num > 0 && params->fec_encoder_schemes_num <= XQC_FEC_MAX_SCHEME_NUM) {
            p = xqc_put_varint(p, XQC_TRANSPORT_PARAM_FEC_DECODER_SCHEMES);
            preferred_fec_paramslen = xqc_put_varint_len(params->fec_decoder_schemes_num);
            for (xqc_int_t i = 0; i < params->fec_decoder_schemes_num; i++) {
                preferred_fec_paramslen += xqc_put_varint_len(params->fec_decoder_schemes[i]);
            }
            p = xqc_put_varint(p, preferred_fec_paramslen);

            p = xqc_put_varint(p, params->fec_decoder_schemes_num);
            for (xqc_int_t i = 0; i < params->fec_decoder_schemes_num; i++) {
                p = xqc_put_varint(p, params->fec_decoder_schemes[i]);
            }
        }
    }
#endif    

    if ((size_t)(p - out) != len) {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }

    *out_len = len;
    return XQC_OK;
}


/* dst should be destination value point */
#define XQC_DECODE_VINT_VALUE(dst, p, end)                  \
    do {                                                    \
        ssize_t nread = xqc_vint_read((p), (end), (dst));   \
        if (nread < 0) {                                    \
            return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;      \
        }                                                   \
        return XQC_OK;                                      \
    } while(0) 


static xqc_int_t
xqc_decode_original_dest_cid(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    if (exttype != XQC_TP_TYPE_ENCRYPTED_EXTENSIONS) {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }

    xqc_cid_set(&params->original_dest_connection_id, p, param_len);
    params->original_dest_connection_id_present = 1;
    return XQC_OK;
}

static xqc_int_t
xqc_decode_max_idle_timeout(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    XQC_DECODE_VINT_VALUE(&params->max_idle_timeout, p, end);
}

static xqc_int_t
xqc_decode_stateless_token(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    if (exttype != XQC_TP_TYPE_ENCRYPTED_EXTENSIONS) {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }

    if ((size_t)(end - p) < sizeof(params->stateless_reset_token)
        || param_len != sizeof(params->stateless_reset_token))
    {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }

    memcpy(params->stateless_reset_token, p, param_len);
    params->stateless_reset_token_present = 1;
    return XQC_OK;
}

static xqc_int_t
xqc_decode_max_udp_payload_size(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    XQC_DECODE_VINT_VALUE(&params->max_udp_payload_size, p, end);
}

static xqc_int_t
xqc_decode_initial_max_data(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    XQC_DECODE_VINT_VALUE(&params->initial_max_data, p, end);
}

static xqc_int_t
xqc_decode_initial_max_stream_data_bidi_local(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    XQC_DECODE_VINT_VALUE(&params->initial_max_stream_data_bidi_local, p, end);
}

static xqc_int_t
xqc_decode_initial_max_stream_data_bidi_remote(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    XQC_DECODE_VINT_VALUE(&params->initial_max_stream_data_bidi_remote, p, end);
}

static xqc_int_t
xqc_decode_initial_max_stream_data_uni(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    XQC_DECODE_VINT_VALUE(&params->initial_max_stream_data_uni, p, end);
}

static xqc_int_t
xqc_decode_initial_max_streams_bidi(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    XQC_DECODE_VINT_VALUE(&params->initial_max_streams_bidi, p, end);
}

static xqc_int_t
xqc_decode_initial_max_streams_uni(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    XQC_DECODE_VINT_VALUE(&params->initial_max_streams_uni, p, end);
}

static xqc_int_t
xqc_decode_ack_delay_exponent(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    ssize_t nread = xqc_vint_read(p, end, &params->ack_delay_exponent);
    /* [TRANSPORT] Values above 20 are invalid */
    if (nread < 0 || params->ack_delay_exponent > XQC_MAX_ACK_DELAY_EXPONENT) {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }
    return XQC_OK;
}

static xqc_int_t
xqc_decode_max_ack_delay(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    XQC_DECODE_VINT_VALUE(&params->max_ack_delay, p, end);
}

static xqc_int_t
xqc_decode_disable_active_migration(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    /* disable_active_migration param is a zero-length value, presentation means disable */
    params->disable_active_migration = 1;
    return XQC_OK;
}

static xqc_int_t
xqc_decode_preferred_address(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    if (exttype != XQC_TP_TYPE_ENCRYPTED_EXTENSIONS) {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }

    if ((end - p) < param_len) {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }

    /* IPv4 addr */
    if ((end - p) < XQC_PREFERRED_ADDR_IPV4_LEN + XQC_PREFERRED_ADDR_IPV4_PORT_LEN) {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }

    memcpy(&params->preferred_address.ipv4, p, sizeof(params->preferred_address.ipv4));
    p += sizeof(params->preferred_address.ipv4);

    /* IPv4 port */
    params->preferred_address.ipv4_port = xqc_get_uint16(p);
    p += sizeof(uint16_t);

    /* IPv6 addr */
    if ((end - p) < XQC_PREFERRED_ADDR_IPV6_LEN + XQC_PREFERRED_ADDR_IPV6_PORT_LEN) {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }

    memcpy(&params->preferred_address.ipv6, p, sizeof(params->preferred_address.ipv6));
    p += sizeof(params->preferred_address.ipv6);

    /* IPv6 port */
    params->preferred_address.ipv6_port = xqc_get_uint16(p);
    p += sizeof(uint16_t);

    /* cid len */
    if ((end - p) < 1) {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }

    params->preferred_address.cid.cid_len = *p++;
    if (params->preferred_address.cid.cid_len > XQC_MAX_CID_LEN
        || 0 == params->preferred_address.cid.cid_len
        || (end - p) < params->preferred_address.cid.cid_len)
    {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }

    /* cid */
    if (params->preferred_address.cid.cid_len) {
        memcpy(params->preferred_address.cid.cid_buf, p,
                params->preferred_address.cid.cid_len);
        p += params->preferred_address.cid.cid_len;
    }

    /* stateless reset token */
    if ((end - p) < XQC_STATELESS_RESET_TOKENLEN) {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }
    memcpy(params->preferred_address.stateless_reset_token, p,
            sizeof(params->preferred_address.stateless_reset_token));
    p += sizeof(params->preferred_address.stateless_reset_token);

    params->preferred_address_present = 1;
    return XQC_OK;
}

static xqc_int_t
xqc_decode_active_cid_limit(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    XQC_DECODE_VINT_VALUE(&params->active_connection_id_limit, p, end);
}

static xqc_int_t
xqc_decode_initial_scid(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    xqc_cid_set(&params->initial_source_connection_id, p, param_len);
    params->initial_source_connection_id_present = 1;
    return XQC_OK;
}

static xqc_int_t
xqc_decode_retry_scid(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    xqc_cid_set(&params->retry_source_connection_id, p, param_len);
    params->retry_source_connection_id_present = 1;
    return XQC_OK;
}

static xqc_int_t
xqc_decode_no_crypto(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    XQC_DECODE_VINT_VALUE(&params->no_crypto, p, end);
}

static xqc_int_t
xqc_decode_enable_multipath(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    if (param_type == XQC_TRANSPORT_PARAM_ENABLE_MULTIPATH_06) {
        /* enable_multipath param is a zero-length value, presentation means enable */
        params->enable_multipath = 1;
        params->multipath_version = XQC_MULTIPATH_06;
        return XQC_OK;
    } else if (param_type == XQC_TRANSPORT_PARAM_ENABLE_MULTIPATH_05) {
        /* enable_multipath param is a zero-length value, presentation means enable */
        params->enable_multipath = 1;
        params->multipath_version = XQC_MULTIPATH_05;
        return XQC_OK;
    } else if (param_type == XQC_TRANSPORT_PARAM_ENABLE_MULTIPATH_04) {
        if (params->multipath_version > XQC_MULTIPATH_04) {
            return XQC_OK;
        }
        params->multipath_version = XQC_MULTIPATH_04;
        XQC_DECODE_VINT_VALUE(&params->enable_multipath, p, end);
    }
    return XQC_OK;
}

static xqc_int_t
xqc_decode_close_dgram_redundancy(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    uint64_t ret = 0;
    ssize_t nread = xqc_vint_read(p, end, &ret);

    switch (ret) {
    case XQC_RED_SET_CLOSE:
        params->close_dgram_redundancy = XQC_RED_SET_CLOSE;
        break;

    default:
        params->close_dgram_redundancy = XQC_RED_NOT_USE;
        break;
    }
    return XQC_OK;
}

#ifdef XQC_ENABLE_FEC
static xqc_int_t
xqc_decode_fec_version(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    switch (param_type) {
    case XQC_TRANSPORT_PARAM_FEC_VERSION:
        params->fec_version = XQC_FEC_01;
        break;

    default:
        params->fec_version = XQC_ERR_FEC_VERSION;
        break;
    }

    return XQC_OK;
}

static xqc_int_t
xqc_decode_fec_max_symbol_size(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    XQC_DECODE_VINT_VALUE(&params->fec_max_symbol_size, p, end);
}

static xqc_int_t
xqc_decode_fec_max_symbols_num(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    XQC_DECODE_VINT_VALUE(&params->fec_max_symbols_num, p, end);
}

static xqc_int_t
xqc_decode_encoder_schemes(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    int         vlen;
    uint64_t    schemes_len, curr_scheme;
    xqc_int_t   i, tmp_len;
    
    tmp_len = 0;
    schemes_len = curr_scheme = 0;
    vlen = xqc_vint_read(p, end, &schemes_len);
    
    if (schemes_len < 0) {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }

    params->fec_encoder_schemes_num = schemes_len;
    p += vlen;

    for (i = 0; i < schemes_len && tmp_len < XQC_FEC_MAX_SCHEME_NUM; i++) {
        vlen = xqc_vint_read(p, end, &curr_scheme);
        if (xqc_set_fec_scheme(curr_scheme, &params->fec_encoder_schemes[tmp_len]) == XQC_OK) {
            tmp_len++;
        }
        p += vlen;
    }

    for (i; i < schemes_len; i++) {
        p += xqc_vint_read(p, end, &curr_scheme);
    }

    params->enable_encode_fec = 1;
    params->fec_encoder_schemes_num = tmp_len;
    return XQC_OK;
}

static xqc_int_t
xqc_decode_decoder_schemes(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    int      vlen;
    uint64_t schemes_len, curr_scheme;
    xqc_int_t i, tmp_len;

    tmp_len = 0;
    schemes_len = curr_scheme = 0;
    vlen = xqc_vint_read(p, end, &schemes_len);

    if (schemes_len < 0) {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }

    params->fec_decoder_schemes_num = schemes_len;
    p += vlen;

    for (i = 0; i < schemes_len && tmp_len < XQC_FEC_MAX_SCHEME_NUM; i++) {
        vlen = xqc_vint_read(p, end, &curr_scheme);
        if (xqc_set_fec_scheme(curr_scheme, &params->fec_decoder_schemes[tmp_len]) == XQC_OK) {
            tmp_len++;
        }
        p += vlen;
    }

    for (i; i < schemes_len; i++) {
        p += xqc_vint_read(p, end, &curr_scheme);
    }

    params->enable_decode_fec = 1;
    params->fec_decoder_schemes_num = tmp_len;

    return XQC_OK;
}
#endif
static xqc_int_t
xqc_decode_max_datagram_frame_size(xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len)
{
    XQC_DECODE_VINT_VALUE(&params->max_datagram_frame_size, p, end);
}


/* decode value from p, and store value in the input params */
typedef xqc_int_t (*xqc_trans_param_decode_func)(
    xqc_transport_params_t *params, xqc_transport_params_type_t exttype,
    const uint8_t *p, const uint8_t *end, uint64_t param_type, uint64_t param_len);

xqc_trans_param_decode_func xqc_trans_param_decode_func_list[] = {
    xqc_decode_original_dest_cid, 
    xqc_decode_max_idle_timeout, 
    xqc_decode_stateless_token,
    xqc_decode_max_udp_payload_size,
    xqc_decode_initial_max_data,
    xqc_decode_initial_max_stream_data_bidi_local,
    xqc_decode_initial_max_stream_data_bidi_remote,
    xqc_decode_initial_max_stream_data_uni,
    xqc_decode_initial_max_streams_bidi,
    xqc_decode_initial_max_streams_uni,
    xqc_decode_ack_delay_exponent,
    xqc_decode_max_ack_delay,
    xqc_decode_disable_active_migration,
    xqc_decode_preferred_address,
    xqc_decode_active_cid_limit,
    xqc_decode_initial_scid,
    xqc_decode_retry_scid,
    xqc_decode_enable_multipath,
    xqc_decode_max_datagram_frame_size,
    xqc_decode_close_dgram_redundancy,
#ifdef XQC_ENABLE_FEC
    xqc_decode_fec_version,
    xqc_decode_encoder_schemes,
    xqc_decode_decoder_schemes,
    xqc_decode_fec_max_symbol_size,
    xqc_decode_fec_max_symbols_num,
#endif
    xqc_decode_no_crypto,
};


/* convert param_type to param's index in xqc_trans_param_decode_func_list */
uint64_t 
xqc_trans_param_get_index(uint64_t param_type) 
{
    switch (param_type) {

    case XQC_TRANSPORT_PARAM_ORIGINAL_DEST_CONNECTION_ID:
    case XQC_TRANSPORT_PARAM_MAX_IDLE_TIMEOUT:
    case XQC_TRANSPORT_PARAM_STATELESS_RESET_TOKEN:
    case XQC_TRANSPORT_PARAM_MAX_UDP_PAYLOAD_SIZE:
    case XQC_TRANSPORT_PARAM_INITIAL_MAX_DATA:
    case XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
    case XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
    case XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI:
    case XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI:
    case XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI:
    case XQC_TRANSPORT_PARAM_ACK_DELAY_EXPONENT:
    case XQC_TRANSPORT_PARAM_MAX_ACK_DELAY:
    case XQC_TRANSPORT_PARAM_DISABLE_ACTIVE_MIGRATION:
    case XQC_TRANSPORT_PARAM_PREFERRED_ADDRESS:
    case XQC_TRANSPORT_PARAM_ACTIVE_CONNECTION_ID_LIMIT:
    case XQC_TRANSPORT_PARAM_INITIAL_SOURCE_CONNECTION_ID:
    case XQC_TRANSPORT_PARAM_RETRY_SOURCE_CONNECTION_ID:
        return param_type;
    
    case XQC_TRANSPORT_PARAM_ENABLE_MULTIPATH_04:
    case XQC_TRANSPORT_PARAM_ENABLE_MULTIPATH_05:
    case XQC_TRANSPORT_PARAM_ENABLE_MULTIPATH_06:
        return XQC_TRANSPORT_PARAM_ENABLE_MULTIPATH_PARSER;

    case XQC_TRANSPORT_PARAM_MAX_DATAGRAM_FRAME_SIZE:
        return XQC_TRANSPORT_PARAM_MAX_DATAGRAM_FRAME_SIZE_PARSER;
    
    case XQC_TRANSPORT_PARAM_CLOSE_DGRAM_REDUNDANCY:
        return param_type;

#ifdef XQC_ENABLE_FEC
    case XQC_TRANSPORT_PARAM_FEC_VERSION:
        return XQC_TRANSPORT_PARAM_FEC_VERSION_PARSER;

    case XQC_TRANSPORT_PARAM_FEC_ENCODER_SCHEMES:
        return XQC_TRANSPORT_PARAM_FEC_ENCODER_SCHEMES_PARSER;

    case XQC_TRANSPORT_PARAM_FEC_DECODER_SCHEMES:
        return XQC_TRANSPORT_PARAM_FEC_DECODER_SCHEMES_PARSER;

    case XQC_TRANSPORT_PARAM_FEC_MAX_SYMBOL_SIZE:
        return XQC_TRANSPORT_PARAM_FEC_MAX_SYMBOL_SIZE_PARSER;

    case XQC_TRANSPORT_PARAM_FEC_MAX_SYMBOL_NUM:
        return XQC_TRANSPORT_PARAM_FEC_MAX_SYMBOL_NUM_PARSER;

#endif

    // 验证一下编译开关关闭时候是否有问题
    case XQC_TRANSPORT_PARAM_NO_CRYPTO:
        return XQC_TRANSPORT_PARAM_PROTOCOL_MAX;

    default:
        break;
    }

    return XQC_TRANSPORT_PARAM_UNKNOWN; 
}


/**
 * decode one param
 */
static inline xqc_int_t
xqc_decode_one_transport_param(xqc_transport_params_t *params,
    xqc_transport_params_type_t exttype, const uint8_t **start, const uint8_t *end)
{
    const uint8_t *p = *start;
    uint64_t param_type = 0;
    uint64_t param_len = 0;

    /* read param type */
    ssize_t nread = xqc_vint_read(p, end, &param_type);
    if (nread < 0) {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }
    p += nread;

    /* read param len */
    nread = xqc_vint_read(p, end, &param_len);
    if (nread < 0 || p + nread + param_len > end ) {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }
    p += nread;

    /* 
     * read param value, note: some parameters are allowed to be zero-length,
     * for example, disable_active_migration. 
     */
    uint64_t param_index = xqc_trans_param_get_index(param_type);
    if (param_index != XQC_TRANSPORT_PARAM_UNKNOWN) {
        xqc_int_t ret = xqc_trans_param_decode_func_list[param_index](params, exttype, p, end,
                                                                      param_type, param_len);
        if (ret < 0) {
            return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
        }
    }

    p += param_len;

    *start = p;
    return XQC_OK;
}

xqc_int_t
xqc_decode_transport_params(xqc_transport_params_t *params,
    xqc_transport_params_type_t exttype, const uint8_t *in, size_t in_len)
{
    const uint8_t *p, *end;
    xqc_int_t ret = XQC_OK;

    p = in;
    end = in + in_len;

    /* Set default values */
    params->preferred_address_present = 0;
    params->original_dest_connection_id_present = 0;
    params->max_idle_timeout = 0;

    params->stateless_reset_token_present = 0;
    params->max_udp_payload_size = XQC_DEFAULT_MAX_UDP_PAYLOAD_SIZE;

    params->initial_max_data = 0;
    params->initial_max_streams_bidi = 0;
    params->initial_max_streams_uni = 0;
    params->initial_max_stream_data_bidi_local = 0;
    params->initial_max_stream_data_bidi_remote = 0;
    params->initial_max_stream_data_uni = 0;

    params->ack_delay_exponent = XQC_DEFAULT_ACK_DELAY_EXPONENT;
    params->max_ack_delay = XQC_DEFAULT_MAX_ACK_DELAY;
    params->disable_active_migration = 0;   /* default 0 in protocol */
    params->active_connection_id_limit = XQC_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT;

    params->initial_source_connection_id_present = 0;
    params->initial_source_connection_id.cid_len = 0;
    params->retry_source_connection_id_present = 0;
    params->retry_source_connection_id.cid_len = 0;

    params->no_crypto = 0;
    params->max_datagram_frame_size = 0;

    params->enable_multipath = 0;
    params->multipath_version = XQC_ERR_MULTIPATH_VERSION;

    /* init fec params value */
    params->enable_encode_fec = 0;
    params->enable_decode_fec = 0;
    params->fec_version = XQC_ERR_FEC_VERSION;
    params->fec_max_symbol_size = 0;
    params->fec_max_symbols_num = 0;
    params->fec_encoder_schemes_num = 0;
    params->fec_decoder_schemes_num = 0;

    params->close_dgram_redundancy = XQC_RED_NOT_USE;

    while (p < end) {
        ret = xqc_decode_one_transport_param(params, exttype, &p, end);
        if (ret < 0) {
            return ret;
        }
    }

    if (end != p) {
        return -XQC_TLS_MALFORMED_TRANSPORT_PARAM;
    }

    return XQC_OK;
}


xqc_int_t
xqc_read_transport_params(char *tp_data, size_t tp_data_len, xqc_transport_params_t *params)
{
    char *p = tp_data;
    char *e = p + tp_data_len;
    while (*p != '\0' && p < e) {
        if (*p == ' ') {
            p++;
        }

        if (strncmp(p, "initial_max_streams_bidi=",
                    xqc_lengthof("initial_max_streams_bidi=")) == 0)
        {
            p += xqc_lengthof("initial_max_streams_bidi=");
            params->initial_max_streams_bidi = strtoul(p, NULL, 10);

        } else if (strncmp(p, "initial_max_streams_uni=",
                           xqc_lengthof("initial_max_streams_uni=")) == 0)
        {
            p += xqc_lengthof("initial_max_streams_uni=");
            params->initial_max_streams_uni = strtoul(p, NULL, 10);

        } else if (strncmp(p, "initial_max_stream_data_bidi_local=",
                           xqc_lengthof("initial_max_stream_data_bidi_local=")) == 0)
        {
            p += xqc_lengthof("initial_max_stream_data_bidi_local=");
            params->initial_max_stream_data_bidi_local = strtoul(p, NULL, 10);

        } else if (strncmp(p, "initial_max_stream_data_bidi_remote=",
                           xqc_lengthof("initial_max_stream_data_bidi_remote=")) == 0)
        {
            p += xqc_lengthof("initial_max_stream_data_bidi_remote=");
            params->initial_max_stream_data_bidi_remote = strtoul(p, NULL, 10);

        } else if (strncmp(p, "initial_max_stream_data_uni=",
                           xqc_lengthof("initial_max_stream_data_uni=")) == 0)
        {
            p += xqc_lengthof("initial_max_stream_data_uni=");
            params->initial_max_stream_data_uni = strtoul(p, NULL, 10);

        } else if (strncmp(p, "initial_max_data=", xqc_lengthof("initial_max_data=")) == 0) {
            p += xqc_lengthof("initial_max_data=");
            params->initial_max_data = strtoul(p, NULL, 10);

        } else if (strncmp(p, "max_ack_delay=", xqc_lengthof("max_ack_delay=")) == 0) {
            p += xqc_lengthof("max_ack_delay=");
            params->max_ack_delay = strtoul(p, NULL, 10);

        } else if (strncmp(p, "max_datagram_frame_size=", xqc_lengthof("max_datagram_frame_size=")) == 0) {
            p += xqc_lengthof("max_datagram_frame_size=");
            params->max_datagram_frame_size = strtoul(p, NULL, 10);
        }

        p = strchr(p, '\n');
        if (p == NULL) {
            return 0;
        }
        p++;
    }

    return XQC_OK;
}


ssize_t
xqc_write_transport_params(char *tp_buf, size_t cap, const xqc_transport_params_t *params)
{
    char dgram_tp_str[256] = "";
    ssize_t tp_data_len = 0;

    if (params->max_datagram_frame_size) {
        tp_data_len = snprintf(dgram_tp_str, 256, 
                               "max_datagram_frame_size=%"PRIu64"\n", 
                               params->max_datagram_frame_size);
        if (tp_data_len < 0) {
            return -XQC_ESYS;
        }
    }
    

    tp_data_len = snprintf(tp_buf, cap, "initial_max_streams_bidi=%"PRIu64"\n"
                                   "initial_max_streams_uni=%"PRIu64"\n"
                                   "initial_max_stream_data_bidi_local=%"PRIu64"\n"
                                   "initial_max_stream_data_bidi_remote=%"PRIu64"\n"
                                   "initial_max_stream_data_uni=%"PRIu64"\n"
                                   "initial_max_data=%"PRIu64"\n"
                                   "max_ack_delay=%"PRIu64"\n"
                                   "%s",
                                   params->initial_max_streams_bidi,
                                   params->initial_max_streams_uni,
                                   params->initial_max_stream_data_bidi_local,
                                   params->initial_max_stream_data_bidi_remote,
                                   params->initial_max_stream_data_uni,
                                   params->initial_max_data,
                                   params->max_ack_delay,
                                   dgram_tp_str);
                                   
    if (tp_data_len < 0) {
        return -XQC_ESYS;
    }

    return tp_data_len;
}

void 
xqc_init_transport_params(xqc_transport_params_t *params)
{
    xqc_memzero(params, sizeof(xqc_transport_params_t));

    /* like xqc_conn_init_trans_settings. */
    params->max_ack_delay = XQC_DEFAULT_MAX_ACK_DELAY;
    params->ack_delay_exponent = XQC_DEFAULT_ACK_DELAY_EXPONENT;
    params->max_udp_payload_size = XQC_DEFAULT_MAX_UDP_PAYLOAD_SIZE;
    params->active_connection_id_limit = XQC_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT;
}
