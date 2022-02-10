/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_TRANSPORT_PARAMS_H_
#define XQC_TRANSPORT_PARAMS_H_

#include <xquic/xquic.h>
#include "src/transport/xqc_defs.h"

/* default value for max_ack_delay */
#define XQC_DEFAULT_MAX_ACK_DELAY               25

/* default value for ack_delay_exponent */
#define XQC_DEFAULT_ACK_DELAY_EXPONENT          3

/* default value for max_udp_payload_size */
#define XQC_DEFAULT_MAX_UDP_PAYLOAD_SIZE        65527

/* default value for active_connection_id_limit */
#define XQC_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT  2

/* max buffer length of encoded transport parameter */
#define XQC_MAX_TRANSPORT_PARAM_BUF_LEN         512


/**
 * @brief transport parameter type
 */
typedef enum {
    /* transport parameter for client */
    XQC_TP_TYPE_CLIENT_HELLO,

    /* transport parameter for server */
    XQC_TP_TYPE_ENCRYPTED_EXTENSIONS

} xqc_transport_params_type_t;


/**
 * @brief definition of transport parameter types
 */
typedef enum {
    XQC_TRANSPORT_PARAM_ORIGINAL_DEST_CONNECTION_ID         = 0x0000,
    XQC_TRANSPORT_PARAM_MAX_IDLE_TIMEOUT                    = 0x0001,
    XQC_TRANSPORT_PARAM_STATELESS_RESET_TOKEN               = 0x0002,
    XQC_TRANSPORT_PARAM_MAX_UDP_PAYLOAD_SIZE                = 0x0003,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_DATA                    = 0x0004,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL  = 0x0005,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 0x0006,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI         = 0x0007,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI            = 0x0008,
    XQC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI             = 0x0009,
    XQC_TRANSPORT_PARAM_ACK_DELAY_EXPONENT                  = 0x000a,
    XQC_TRANSPORT_PARAM_MAX_ACK_DELAY                       = 0x000b,
    XQC_TRANSPORT_PARAM_DISABLE_ACTIVE_MIGRATION            = 0x000c,
    XQC_TRANSPORT_PARAM_PREFERRED_ADDRESS                   = 0x000d,
    XQC_TRANSPORT_PARAM_ACTIVE_CONNECTION_ID_LIMIT          = 0x000e,
    XQC_TRANSPORT_PARAM_INITIAL_SOURCE_CONNECTION_ID        = 0x000f,
    XQC_TRANSPORT_PARAM_RETRY_SOURCE_CONNECTION_ID          = 0x0010,

    /* upper limit of params defined in [Transport] */
    XQC_TRANSPORT_PARAM_PROTOCOL_MAX,

    /* do no cryption on 0-RTT and 1-RTT packets */
    XQC_TRANSPORT_PARAM_NO_CRYPTO                           = 0x1000,

    /* upper limit of params defined by xquic */
    XQC_TRANSPORT_PARAM_UNKNOWN,
} xqc_transport_param_id_t;


typedef struct {
    uint8_t                 ipv4[4];
    uint16_t                ipv4_port;
    uint8_t                 ipv6[16];
    uint16_t                ipv6_port;
    xqc_cid_t               cid;
    uint8_t                 stateless_reset_token[XQC_STATELESS_RESET_TOKENLEN];
} xqc_preferred_addr_t;


/* transport parameters */
typedef struct {
    xqc_preferred_addr_t    preferred_address;
    uint8_t                 preferred_address_present;

    xqc_cid_t               original_dest_connection_id;
    uint8_t                 original_dest_connection_id_present;

    xqc_usec_t              max_idle_timeout;
    uint8_t                 stateless_reset_token[XQC_STATELESS_RESET_TOKENLEN];
    uint8_t                 stateless_reset_token_present;
    uint64_t                max_udp_payload_size;
    uint64_t                initial_max_data;
    uint64_t                initial_max_stream_data_bidi_local;
    uint64_t                initial_max_stream_data_bidi_remote;
    uint64_t                initial_max_stream_data_uni;
    uint64_t                initial_max_streams_bidi;
    uint64_t                initial_max_streams_uni;
    uint64_t                ack_delay_exponent;
    xqc_usec_t              max_ack_delay;
    xqc_flag_t              disable_active_migration;
    uint64_t                active_connection_id_limit;

    xqc_cid_t               initial_source_connection_id;
    uint8_t                 initial_source_connection_id_present;

    xqc_cid_t               retry_source_connection_id;
    uint8_t                 retry_source_connection_id_present;

    /**
     * no_crypto is a self-defined experimental transport parameter by xquic, xquic will do no
     * encryption on 0-RTT or 1-RTT packets if no_crypto is set to be 1.
     * no_crypto is designed to be effective only on current connection and do not apply to future
     * connections, it is prohibited to store this parameter.
     * NOTICE: no_crypto MIGHT be modified or removed as it is not an official parameter.
     */
    uint64_t                no_crypto;

} xqc_transport_params_t;



/**
 * encode transport parameters. 
 * @param params input transport parameter structure
 * @param exttype the occasion of transport parameter
 * @param out pointer of destination buffer
 * @param out_cap capacity of output data buffer
 * @param out_len encoded buffer len
 * @return XQC_OK for success, negative for failure
 */
xqc_int_t xqc_encode_transport_params(const xqc_transport_params_t *params,
    xqc_transport_params_type_t exttype, uint8_t *out, size_t out_cap, size_t *out_len);


/**
 * decode transport parameters. 
 * @param params output transport parameter structure
 * @param exttype the occasion of transport parameter
 * @param in encoded transport parameter buf
 * @param in_len encoded transport parameter buf len
 * @return XQC_OK for success, negative for failure
 */
xqc_int_t xqc_decode_transport_params(xqc_transport_params_t *params,
    xqc_transport_params_type_t exttype, const uint8_t *in, size_t in_len);


xqc_int_t xqc_read_transport_params(char *tp_data, size_t tp_data_len,
    xqc_transport_params_t *params);

ssize_t xqc_write_transport_params(char *tp_buf, size_t cap,
    const xqc_transport_params_t *params);


#endif /* XQC_TRANSPORT_PARAMS_H_ */