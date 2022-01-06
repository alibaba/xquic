/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_TLS_DEFS_H
#define XQC_TLS_DEFS_H

#include <xquic/xquic.h>
#include "src/common/xqc_common.h"
#include "src/common/xqc_log.h"
#include "src/common/xqc_common_inc.h"


#define XQC_TLS_AEAD_OVERHEAD_MAX_LEN   16


typedef struct xqc_tls_ctx_s    xqc_tls_ctx_t;
typedef struct xqc_tls_s        xqc_tls_t;


typedef enum {
    XQC_TLS_TYPE_SERVER = 0x00,
    XQC_TLS_TYPE_CLIENT,
} xqc_tls_type_t;


/**
 * @brief encryption levels, equivalent to the definition in ssl lib
 */
typedef enum xqc_encrypt_level_s {
    XQC_ENC_LEV_INIT,

    XQC_ENC_LEV_0RTT,

    XQC_ENC_LEV_HSK,

    XQC_ENC_LEV_1RTT,

    XQC_ENC_LEV_MAX,
} xqc_encrypt_level_t;


typedef enum {
    XQC_KEY_TYPE_RX_READ,
    XQC_KEY_TYPE_TX_WRITE,
} xqc_key_type_t;


/* definitions for early data accept */
typedef enum xqc_tls_early_data_accept_s {

    XQC_TLS_EARLY_DATA_UNKNOWN  = -2,

    XQC_TLS_EARLY_DATA_REJECT   = -1,

    XQC_TLS_NO_EARLY_DATA       = 0,

    XQC_TLS_EARLY_DATA_ACCEPT   = 1
} xqc_tls_early_data_accept_t;



/**
 * @brief tls config for create xqc_tls_t instance
 */
typedef struct xqc_tls_config_s {
    /* session ticket, only for client */
    unsigned char          *session_ticket;
    size_t                  session_ticket_len;

    /* bit-map flag defined in xqc_cert_verify_flag_e, only for client */
    uint8_t                 cert_verify_flag;

    /* hostname of server, only for client */
    char                   *hostname;

    /* alpn string, only for client */
    char                   *alpn;

    /**
     * no_crypto flag, only for client.
     * 1 for processing 0-RTT/1-RTT packets without encryption or decryption
     */
    int                     no_crypto_flag;

    /* local transport parameter, REQUIRED for both client and server */
    uint8_t                *trans_params;
    size_t                  trans_params_len;

} xqc_tls_config_t;


/**
 * @brief crypto data callback. the data is generated when doing tls handshake, and upper layer
 * shall wrap it as CRYPTO frame.
 */
typedef xqc_int_t (*xqc_tls_crypto_data_pt)(xqc_encrypt_level_t level, const uint8_t *data,
    size_t len, void *user_data);

/**
 * @brief quic transport parameter callback
 */
typedef void (*xqc_tls_trans_param_pt)(const uint8_t *tp, size_t len, void *user_data);

/**
 * @brief application level protocol negotiation callback.
 */
typedef xqc_int_t (*xqc_tls_alpn_select_pt)(const char *alpn, size_t alpn_len, void *user_data);

/**
 * @brief certificate verify callback
 */
typedef xqc_int_t (*xqc_tls_cert_pt)(const unsigned char *certs[], const size_t cert_len[],
    size_t certs_len, void *user_data);

/**
 * @brief new session ticket callback, SHALL be stored by application
 */
typedef void (*xqc_tls_session_pt)(const char *data, size_t data_len, void *user_data);

/**
 * @brief keylog callback, might be used for debug
 */
typedef xqc_keylog_pt xqc_tls_keylog_pt;

/**
 * @brief tls fatal error callback. which will be triggered when ssl reported an tls error.
 * the parameter tls_err is from tls. which ranges in [0, 255], upper layer shall convert it to QUIC
 * CONNECTION_CLOSE error codes (CRYPTO_ERROR, 0x0100-0x01ff).
 */
typedef void (*xqc_tls_error_pt)(xqc_int_t tls_err, void *user_data);

/**
 * @brief tls handshake complete callback
 */
typedef void (*xqc_tls_handshake_completed_pt)(void *user_data);

/**
 * @brief definition of callback functions to upper layer
 */
typedef struct xqc_tls_callbacks_s {

    /* generated crypto data callback function */
    xqc_tls_crypto_data_pt          crypto_data_cb;

    /* transport parameter callback function */
    xqc_tls_trans_param_pt          tp_cb;

    /* alpn selection callback function */
    xqc_tls_alpn_select_pt          alpn_select_cb;

    /* certificate verify callback function */
    xqc_tls_cert_pt                 cert_verify_cb;

    /* session ticket callback function */
    xqc_tls_session_pt              session_cb;

    /* for writing tx and rx secrets */
    xqc_tls_keylog_pt               keylog_cb;

    /* for notify tls errors, upper layer shall translate it 
       to CRYPTO_ERROR and close connection */
    xqc_tls_error_pt                error_cb;

    /* for notify tls handshake completed, which is equivalent to QUIC handshake completed */
    xqc_tls_handshake_completed_pt  hsk_completed_cb;
} xqc_tls_callbacks_t;


#endif
