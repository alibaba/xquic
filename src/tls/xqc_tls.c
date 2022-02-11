/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_tls.h"
#include "xqc_tls_ctx.h"
#include "xqc_ssl_if.h"
#include "xqc_ssl_cbs.h"
#include "xqc_crypto.h"
#include "src/common/xqc_common.h"
#include <openssl/rand.h>


typedef enum xqc_tls_flag_e {
    /* initial state */
    XQC_TLS_FLAG_NONE                   = 0,

    /* received peer's transport parameter. this is used for transport parameter callback */
    XQC_TLS_FLAG_TRANSPORT_PARAM_RCVD   = 1 << 0,

    /*
     * handshake completed flag. this is set when ssl library report handshake completion,
     * and is used for process crypto data
     */
    XQC_TLS_FLAG_HSK_COMPLETED          = 1 << 1,

} xqc_tls_flag_t;


typedef struct xqc_tls_s {
    /* tls context */
    xqc_tls_ctx_t              *ctx;

    /* SSL handler */
    SSL                        *ssl;

    /* tls type. instance of client and server got different behaviour */
    xqc_tls_type_t              type;

    /* cert verify config */
    uint8_t                     cert_verify_flag;

    /* no crypto */
    xqc_bool_t                  no_crypto;

    /* crypto context */
    xqc_crypto_t               *crypto[XQC_ENC_LEV_MAX];

    /* log handler */
    xqc_log_t                  *log;

    /* callback functions and user_data */
    xqc_tls_callbacks_t        *cbs;
    void                       *user_data;

    /* whether client used resumption. aka, whether client inputs session ticket */
    xqc_bool_t                  resumption;

    /* tls state flag */
    xqc_tls_flag_t              flag;

    /* quic version. used to decide protection salt */
    xqc_proto_version_t         version;

    xqc_bool_t                  key_update_confirmed;

} xqc_tls_t;


/* quic method callback functions for ssl library */
SSL_QUIC_METHOD xqc_ssl_quic_method;


xqc_bool_t
xqc_tls_check_session_ticket_timeout(SSL_SESSION *session)
{
    uint32_t now = (uint32_t)time(NULL);
    uint32_t session_time = SSL_get_time(session);
    if (session_time > now) {
        return XQC_FALSE;
    }

    uint32_t agesec = now - session_time;
    uint64_t session_timeout = SSL_SESSION_get_timeout(session);
    if (session_timeout < agesec) {
        return XQC_FALSE;
    }

    /* session is still available */
    return XQC_TRUE;
}


xqc_int_t
xqc_tls_cli_set_session_data(xqc_tls_t *tls, char *session_data, size_t session_data_len)
{
    xqc_int_t ret = XQC_OK;
    int ssl_ret;
    SSL *ssl = tls->ssl;

    BIO *bio = BIO_new_mem_buf(session_data, session_data_len);
    if (bio == NULL) {
        xqc_log(tls->log, XQC_LOG_DEBUG, "|new mem buf error|%s",
                ERR_error_string(ERR_get_error(), NULL));
        return -XQC_TLS_INTERNAL;
    }

    SSL_SESSION *session = PEM_read_bio_SSL_SESSION(bio, NULL, 0, NULL);
    if (session == NULL) {
        ret = -XQC_TLS_INTERNAL;
        xqc_log(tls->log, XQC_LOG_DEBUG, "|read session ticket info error|%s",
                ERR_error_string(ERR_get_error(), NULL));
        goto end;
    }

    if (!xqc_tls_check_session_ticket_timeout(session)) {
        ret = -XQC_TLS_INVALID_ARGUMENT;
        xqc_log(tls->log, XQC_LOG_DEBUG, "|check session timeout failed|%s",
                ERR_error_string(ERR_get_error(), NULL));
        goto end;
    }

    ssl_ret = SSL_set_session(ssl, session);
    if (ssl_ret != XQC_SSL_SUCCESS) {
        ret = -XQC_TLS_INTERNAL;
        xqc_log(tls->log, XQC_LOG_ERROR, "|set session error|%s",
                ERR_error_string(ERR_get_error(), NULL));
        goto end;
    }

end:
    if (bio) {
        BIO_free(bio);
    }

    if (session) {
        SSL_SESSION_free(session);
    }

    return ret;
}

/* only for client */
xqc_int_t
xqc_tls_set_alpn(SSL *ssl, const char *alpn)
{
    if (NULL == alpn) {
        return -XQC_TLS_INVALID_ARGUMENT;
    }

    size_t alpn_len = strlen(alpn);
    if (alpn_len >= 128) {
        return -XQC_TLS_INVALID_ARGUMENT;
    }

    /* 
     * ALPN protocol is a series of non-empty, 8-bit length-prefixed strings, 
     * the length is one byte more than input alpn string.
     */
    size_t protos_len = alpn_len + 1;
    uint8_t *p_alpn = xqc_malloc(protos_len + 1);
    if (p_alpn == NULL) {
        return -XQC_TLS_NOBUF;
    }

    /*
     * copy the alpn string len into first byte, copy the alpn string into
     * the rest bytes, set the last byte with '\0'
     */
    p_alpn[0] = alpn_len;
    strncpy(&p_alpn[1], alpn, protos_len);
    p_alpn[protos_len] = '\0';
    SSL_set_alpn_protos(ssl, p_alpn, protos_len);

    xqc_free(p_alpn);
    return XQC_OK;
}


xqc_int_t
xqc_tls_init_client_ssl(xqc_tls_t *tls, xqc_tls_config_t *cfg)
{
    xqc_int_t   ret = XQC_OK;
    char       *hostname = NULL;
    SSL        *ssl = tls->ssl;

    /* configure ssl as client */
    SSL_set_connect_state(ssl);

    /* If remote host is NULL, send "localhost" as SNI. */
    if (NULL == cfg->hostname || 0 == strlen(cfg->hostname)) {
        hostname = "localhost";

    } else {
        hostname = cfg->hostname;
    }

    SSL_set_tlsext_host_name(ssl, hostname);

    /*
     * set alpn in ClientHello. for client, xquic set alpn for every ssl instance. while server set 
     * the alpn select callback function while initializing tls context. 
     */
    ret = xqc_tls_set_alpn(ssl, cfg->alpn);
    if (ret != XQC_OK) {
        xqc_log(tls->log, XQC_LOG_ERROR, "|xqc_create_client_ssl|set alpn error|");
        goto end;
    }

    /* set session data and enable early data */
    if (cfg->session_ticket && cfg->session_ticket_len > 0) {
        if (xqc_tls_cli_set_session_data(tls, cfg->session_ticket,
                                         cfg->session_ticket_len) == XQC_OK)
        {
            tls->resumption = XQC_TRUE;
            xqc_ssl_enable_max_early_data(ssl);
        }
    }

    /* set verify if flag set */
    if (cfg->cert_verify_flag & XQC_TLS_CERT_FLAG_NEED_VERIFY) { 
        if (X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), hostname,
                                        strlen(hostname)) != XQC_SSL_SUCCESS)
        {
            /* hostname set failed need log */
            xqc_log(tls->log,  XQC_LOG_DEBUG, "|certificate verify set hostname failed|");
            ret = -XQC_TLS_INTERNAL;
            goto end;
        }

        SSL_set_verify(ssl, SSL_VERIFY_PEER, xqc_ssl_cert_verify_cb);
    }

end:
    return ret;
}

xqc_int_t
xqc_tls_init_server_ssl(xqc_tls_t *tls, xqc_tls_config_t *cfg)
{
    xqc_int_t ret = XQC_OK;
    SSL *ssl = tls->ssl;

    /* configure ssl as server */
    SSL_set_accept_state(ssl);

    /* enable early data and set context */
    xqc_ssl_enable_max_early_data(ssl);
    SSL_set_quic_early_data_context(ssl, (const uint8_t *)XQC_EARLY_DATA_CONTEXT, 
                                    XQC_EARLY_DATA_CONTEXT_LEN);

    return ret;
}

xqc_int_t
xqc_tls_create_ssl(xqc_tls_t *tls, xqc_tls_config_t *cfg)
{
    xqc_int_t ret = XQC_OK;
    int ssl_ret;

    /* create ssl instance */
    SSL *ssl = SSL_new(xqc_tls_ctx_get_ssl_ctx(tls->ctx));
    if (ssl == NULL) {
        xqc_log(tls->log, XQC_LOG_ERROR, "|SSL_new return null|%s|",
                ERR_error_string(ERR_get_error(), NULL));
        ret = -XQC_TLS_INTERNAL;
        goto end;
    }
    tls->ssl = ssl;

    /* 
     * make tls the app data of ssl instance, which will be used in callback
     * functions defined in xqc_ssl_cbs.h
     */
    ssl_ret = SSL_set_app_data(ssl, tls);
    if (ssl_ret != XQC_SSL_SUCCESS) {
        xqc_log(tls->log, XQC_LOG_ERROR, "|ssl set app data error|%s|",
                ERR_error_string(ERR_get_error(), NULL));
        ret = -XQC_TLS_INTERNAL;
        goto end;
    }

    ssl_ret = SSL_set_quic_method(ssl, &xqc_ssl_quic_method);
    if (ssl_ret != XQC_SSL_SUCCESS) {
        xqc_log(tls->log, XQC_LOG_ERROR, "|ssl set quic method error|",
                ERR_error_string(ERR_get_error(), NULL));
        ret = -XQC_TLS_INTERNAL;
        goto end;
    }

    /* set local transport parameter */
    ssl_ret = SSL_set_quic_transport_params(tls->ssl, cfg->trans_params, cfg->trans_params_len);
    if (ssl_ret != XQC_SSL_SUCCESS) {
        xqc_log(tls->log, XQC_LOG_ERROR, "|set transport params error|%s|",
                ERR_error_string(ERR_get_error(), NULL));
        ret = -XQC_TLS_INTERNAL;
        goto end;
    }


    /* the difference of initialization between client and server */
    if (tls->type == XQC_TLS_TYPE_SERVER) {
        ret = xqc_tls_init_server_ssl(tls, cfg);

    } else {
        ret = xqc_tls_init_client_ssl(tls, cfg);
    }

end:
    return ret;
}


xqc_tls_t *
xqc_tls_create(xqc_tls_ctx_t *ctx, xqc_tls_config_t *cfg, xqc_log_t *log, void *user_data)
{
    xqc_int_t ret;

    xqc_tls_t *tls = xqc_calloc(1, sizeof(xqc_tls_t));
    if (NULL == tls) {
        return NULL;
    }

    /* set upper layer callback functions */
    xqc_tls_ctx_get_tls_callbacks(ctx, &tls->cbs);

    tls->type = xqc_tls_ctx_get_type(ctx);
    tls->ctx = ctx;
    tls->log = log;
    tls->user_data = user_data;
    tls->cert_verify_flag = cfg->cert_verify_flag;
    tls->no_crypto = cfg->no_crypto_flag;
    tls->key_update_confirmed = XQC_TRUE;

    /* init ssl with input config */
    ret = xqc_tls_create_ssl(tls, cfg);
    if (XQC_OK != ret) {
        goto fail;
    }

    return tls;

fail:
    xqc_tls_destroy(tls);
    return NULL;
}


/* try to get transport parameter bytes from ssl and notify to Transport layer */
void
xqc_tls_process_trans_param(xqc_tls_t *tls)
{
    const uint8_t *peer_tp;
    size_t tp_len = 0;

    if (tls->flag & XQC_TLS_FLAG_TRANSPORT_PARAM_RCVD) {
        /* transport parameter already known, need no more process */
        return;
    }

    /* get buffer */
    SSL_get_peer_quic_transport_params(tls->ssl, &peer_tp, &tp_len);
    if (tp_len <= 0) {
        return;
    }

    /* callback to Transport layer */
    if (tls->cbs->tp_cb) {
        tls->cbs->tp_cb(peer_tp, tp_len, tls->user_data);
    }

    tls->flag |= XQC_TLS_FLAG_TRANSPORT_PARAM_RCVD;
}

xqc_int_t
xqc_tls_do_handshake(xqc_tls_t *tls)
{
    xqc_ssl_handshake_res_t res = xqc_ssl_do_handshake(tls->ssl);
    if (res == XQC_SSL_HSK_RES_FAIL) {
        xqc_log(tls->log, XQC_LOG_ERROR, "|TLS handshake error:%s|",
                ERR_error_string(ERR_get_error(), NULL));
        return -XQC_TLS_INTERNAL;
    }

    if (res == XQC_SSL_HSK_RES_WAIT) {
        return XQC_OK;
    }

    /* SSL_do_handshake returns 1 when handshake has completed or False Started */
    tls->flag |= XQC_TLS_FLAG_HSK_COMPLETED;
    if (tls->cbs->hsk_completed_cb) {
        tls->cbs->hsk_completed_cb(tls->user_data);
    }

    return XQC_OK;
}

xqc_int_t
xqc_tls_derive_and_install_initial_keys(xqc_tls_t *tls, const xqc_cid_t *odcid)
{
    xqc_int_t ret;
    xqc_crypto_t *init_crypto = tls->crypto[XQC_ENC_LEV_INIT];

    /* initial secret for packet protection client/server */
    uint8_t cli_initial_secret[INITIAL_SECRET_MAX_LEN] = {0};
    uint8_t svr_initial_secret[INITIAL_SECRET_MAX_LEN] = {0};

    /* derive initial key */
    ret = xqc_crypto_derive_initial_secret(cli_initial_secret, INITIAL_SECRET_MAX_LEN,
                                           svr_initial_secret, INITIAL_SECRET_MAX_LEN,
                                           odcid, xqc_crypto_initial_salt[tls->version],
                                           strlen(xqc_crypto_initial_salt[tls->version]));
    if (XQC_OK != ret) {
        xqc_log(tls->log, XQC_LOG_ERROR, "|derive initial secret error|ret:%d", ret);
        return ret;
    }

    /* install initial rx/tx keys */
    if (tls->type == XQC_TLS_TYPE_CLIENT) {
        /* client use client initial secret to derive tx key */
        ret = xqc_crypto_derive_keys(init_crypto, cli_initial_secret, INITIAL_SECRET_MAX_LEN,
                                     XQC_KEY_TYPE_TX_WRITE);
        if (ret != XQC_OK) {
            xqc_log(tls->log, XQC_LOG_ERROR, "|client install initial write key error");
            return ret;
        }

        /* client use server initial secret to derive rx key */
        ret = xqc_crypto_derive_keys(init_crypto, svr_initial_secret, INITIAL_SECRET_MAX_LEN,
                                     XQC_KEY_TYPE_RX_READ);
        if (ret != XQC_OK) {
            xqc_log(tls->log, XQC_LOG_ERROR, "|client install initial read key error");
            return ret;
        }

    } else {
        /* server use server initial secret to derive tx key */
        ret = xqc_crypto_derive_keys(init_crypto, svr_initial_secret, INITIAL_SECRET_MAX_LEN,
                                     XQC_KEY_TYPE_TX_WRITE);
        if (ret != XQC_OK) {
            xqc_log(tls->log, XQC_LOG_ERROR, "|server install initial write key error");
            return ret;
        }

        /* server use client initial secret to derive rx key */
        ret = xqc_crypto_derive_keys(init_crypto, cli_initial_secret, INITIAL_SECRET_MAX_LEN,
                                     XQC_KEY_TYPE_RX_READ);
        if (ret != XQC_OK) {
            xqc_log(tls->log, XQC_LOG_ERROR, "|client install initial read key error");
            return ret;
        }
    }

    return XQC_OK;
}


xqc_int_t
xqc_tls_init_client(xqc_tls_t *tls, const xqc_cid_t *odcid)
{
    xqc_int_t ret = xqc_tls_derive_and_install_initial_keys(tls, odcid);
    if (ret != XQC_OK) {
        xqc_log(tls->log, XQC_LOG_ERROR, "|derive initial keys error|ret:%d", ret);
        return ret;
    }

    /* do handshake to generate ClientHello */
    return xqc_tls_do_handshake(tls);
}

xqc_int_t
xqc_tls_init_server(xqc_tls_t *tls, const xqc_cid_t *odcid)
{
    return xqc_tls_derive_and_install_initial_keys(tls, odcid);
}

xqc_int_t
xqc_tls_init(xqc_tls_t *tls, xqc_proto_version_t version, const xqc_cid_t *odcid)
{
    tls->version = version;

    /* set the quic_transport_parameters extension codepoint */
    SSL_set_quic_use_legacy_codepoint(tls->ssl, tls->version != XQC_VERSION_V1);

    /* create init level crypto */
    tls->crypto[XQC_ENC_LEV_INIT] = xqc_crypto_create(XQC_TLS13_AES_128_GCM_SHA256, tls->log);
    if (NULL == tls->crypto[XQC_ENC_LEV_INIT]) {
        xqc_log(tls->log, XQC_LOG_ERROR, "|create init level crypto error|");
        return -XQC_TLS_NOMEM;
    }

    /* derive and install initial keys */
    if (tls->type == XQC_TLS_TYPE_SERVER) {
        return xqc_tls_init_server(tls, odcid);

    } else {
        return xqc_tls_init_client(tls, odcid);
    }

    return XQC_OK;
}

xqc_int_t
xqc_tls_reset_initial(xqc_tls_t *tls, xqc_proto_version_t version, const xqc_cid_t *odcid)
{
    tls->version = version;

    if (tls->crypto[XQC_ENC_LEV_INIT] == NULL) {
        xqc_log(tls->log, XQC_LOG_ERROR, "|tls instance is not inited");
        return -XQC_TLS_INVALID_STATE;
    }

    return xqc_tls_derive_and_install_initial_keys(tls, odcid);
}


void
xqc_tls_destroy(xqc_tls_t *tls)
{
    if (tls) {
        if (tls->ssl) {
            SSL_free(tls->ssl);
        }

        for (xqc_encrypt_level_t lv = 0; lv < XQC_ENC_LEV_MAX; lv++) {
            xqc_crypto_destroy(tls->crypto[lv]);
        }

        xqc_free(tls);
    }
}


xqc_int_t
xqc_tls_process_crypto_data(xqc_tls_t *tls, xqc_encrypt_level_t level,
    const uint8_t *crypto_data, size_t data_len)
{
    SSL *ssl = tls->ssl;
    int ret;
    int err;

    if (SSL_provide_quic_data(ssl, (enum ssl_encryption_level_t)level, crypto_data, data_len)
        != XQC_SSL_SUCCESS)
    {
        xqc_log(tls->log, XQC_LOG_ERROR, "|SSL_provide_quic_data failed|level:%d|%s|",
                level, ERR_error_string(ERR_get_error(), NULL));
        return -XQC_TLS_INTERNAL;
    }

    if (!(tls->flag & XQC_TLS_FLAG_HSK_COMPLETED)) {
        /* handshake not completed, continue handshake */
        if (xqc_tls_do_handshake(tls) != XQC_OK) {
            xqc_log(tls->log, XQC_LOG_ERROR, "|xqc_do_handshake failed |");
            return -XQC_TLS_DO_HANDSHAKE_ERROR;
        }

    } else {
        /* handshake finished, process NewSessionTicket */
        ret = SSL_process_quic_post_handshake(ssl);

        if (ret != XQC_SSL_SUCCESS) {
            err = SSL_get_error(ssl, ret);
            switch (err) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                return XQC_OK;
            case SSL_ERROR_SSL:
            case SSL_ERROR_ZERO_RETURN:
            default:
                xqc_log(tls->log, XQC_LOG_ERROR, "|SSL_process_quic_post_handshake failed|%s",
                        ERR_error_string(ERR_get_error(), NULL));
                return -XQC_TLS_POST_HANDSHAKE_ERROR;
            }
        }
    }

    return XQC_OK;
}


xqc_int_t
xqc_tls_encrypt_header(xqc_tls_t *tls, xqc_encrypt_level_t level,
    xqc_pkt_type_t pkt_type, uint8_t *header, uint8_t *pktno, uint8_t *end)
{
    xqc_crypto_t *crypto = tls->crypto[level];
    if (crypto == NULL) {
        xqc_log(tls->log, XQC_LOG_ERROR, "|crypto not initialized|level:%d|", level);
        return -XQC_TLS_INVALID_STATE;
    }

    return xqc_crypto_encrypt_header(crypto, pkt_type, header, pktno, end);
}


xqc_int_t
xqc_tls_encrypt_payload(xqc_tls_t *tls, xqc_encrypt_level_t level,
    uint64_t pktno, uint8_t *header, size_t header_len, uint8_t *payload, size_t payload_len,
    uint8_t *dst, size_t dst_cap, size_t *dst_len)
{
    xqc_crypto_t *crypto = tls->crypto[level];
    if (crypto == NULL) {
        xqc_log(tls->log, XQC_LOG_ERROR, "|crypto not initialized|level:%d|", level);
        return -XQC_TLS_INVALID_STATE;
    }

    xqc_uint_t key_phase = 0;
    if (level == XQC_ENC_LEV_1RTT) {
        key_phase = XQC_PACKET_SHORT_HEADER_KEY_PHASE(header);
        if (key_phase >= XQC_KEY_PHASE_CNT) {
            xqc_log(tls->log, XQC_LOG_ERROR, "|illegal key phase|key_phase:%ui|", key_phase);
            return -XQC_TLS_INVALID_STATE;
        }
    }

    return xqc_crypto_encrypt_payload(crypto, pktno, key_phase, header, header_len,
                                      payload, payload_len, dst, dst_cap, dst_len);
}

xqc_int_t
xqc_tls_decrypt_header(xqc_tls_t *tls, xqc_encrypt_level_t level, 
    xqc_pkt_type_t pkt_type, uint8_t *header, uint8_t *pktno, uint8_t *end)
{
    xqc_crypto_t *crypto = tls->crypto[level];
    if (crypto == NULL) {
        xqc_log(tls->log, XQC_LOG_ERROR, "|crypto not initialized|level:%d|", level);
        return -XQC_TLS_INVALID_STATE;
    }

    return xqc_crypto_decrypt_header(crypto, pkt_type, header, pktno, end);
}


xqc_int_t
xqc_tls_decrypt_payload(xqc_tls_t *tls, xqc_encrypt_level_t level,
    uint64_t pktno, uint8_t *header, size_t header_len, uint8_t *payload, size_t payload_len,
    uint8_t *dst, size_t dst_cap, size_t *dst_len)
{
    xqc_crypto_t *crypto = tls->crypto[level];
    if (crypto == NULL) {
        xqc_log(tls->log, XQC_LOG_ERROR, "|crypto not initialized|level:%d|", level);
        return -XQC_TLS_INVALID_STATE;
    }

    xqc_uint_t key_phase = 0;
    if (level == XQC_ENC_LEV_1RTT) {
        key_phase = XQC_PACKET_SHORT_HEADER_KEY_PHASE(header);
        if (key_phase >= XQC_KEY_PHASE_CNT) {
            xqc_log(tls->log, XQC_LOG_ERROR, "|illegal key phase|key_phase:%ui|", key_phase);
            return -XQC_TLS_INVALID_STATE;
        }
    }

    return xqc_crypto_decrypt_payload(crypto, pktno, key_phase, header, header_len,
                                      payload, payload_len, dst, dst_cap, dst_len);
}


xqc_bool_t
xqc_tls_is_key_ready(xqc_tls_t *tls, xqc_encrypt_level_t level, xqc_key_type_t key_type)
{
    if (NULL == tls->crypto[level]) {
        return XQC_FALSE;
    }

    return xqc_crypto_is_key_ready(tls->crypto[level], key_type);
}

uint32_t
xqc_tls_get_cipher_id(SSL *ssl, xqc_encrypt_level_t level, xqc_bool_t no_crypto)
{
    if (no_crypto == XQC_TRUE
        && (level == XQC_ENC_LEV_0RTT || level == XQC_ENC_LEV_1RTT))
    {
        return NID_undef;
    }

    return SSL_CIPHER_get_id(SSL_get_current_cipher(ssl));
}

xqc_tls_early_data_accept_t
xqc_tls_is_early_data_accepted(xqc_tls_t *tls)
{
    /* client set no session ticket */
    if (tls->type == XQC_TLS_TYPE_CLIENT && !tls->resumption) {
        return XQC_TLS_NO_EARLY_DATA;
    }

    return xqc_ssl_is_early_data_accepted(tls->ssl)
        ? XQC_TLS_EARLY_DATA_ACCEPT : XQC_TLS_EARLY_DATA_REJECT;
}

xqc_bool_t
xqc_tls_is_ready_to_send_early_data(xqc_tls_t *tls)
{
    if (tls->resumption == XQC_FALSE) {
        /* server will always be false */
        return XQC_FALSE;
    }

    /* ready to send when 0rtt tx key is ready */
    return xqc_tls_is_key_ready(tls, XQC_ENC_LEV_0RTT, XQC_KEY_TYPE_TX_WRITE);
}

ssize_t
xqc_tls_aead_tag_len(xqc_tls_t *tls, xqc_encrypt_level_t level)
{
    xqc_crypto_t *crypto = tls->crypto[level];
    if (crypto == NULL) {
        xqc_log(tls->log, XQC_LOG_ERROR, "|crypto not initialized|level:%d|", level);
        return -XQC_TLS_INVALID_STATE;
    }

    return xqc_crypto_aead_tag_len(crypto);
}

void
xqc_tls_set_no_crypto(xqc_tls_t *tls)
{
    tls->no_crypto = XQC_TRUE;
}

void
xqc_tls_set_1rtt_key_phase(xqc_tls_t *tls, xqc_uint_t key_phase)
{
    tls->crypto[XQC_ENC_LEV_1RTT]->key_phase = key_phase;
}

xqc_bool_t
xqc_tls_is_key_update_confirmed(xqc_tls_t *tls)
{
    return tls->key_update_confirmed;
}

xqc_int_t
xqc_tls_update_1rtt_keys(xqc_tls_t *tls, xqc_key_type_t type)
{
    xqc_crypto_t *crypto = tls->crypto[XQC_ENC_LEV_1RTT];
    if (crypto == NULL) {
        xqc_log(tls->log, XQC_LOG_ERROR, "|invalid state|1rtt crypto is null|");
        return -XQC_TLS_UPDATE_KEY_ERROR;
    }

    xqc_int_t ret = xqc_crypto_derive_updated_keys(crypto, type);
    if (ret != XQC_OK) {
        xqc_log(tls->log, XQC_LOG_ERROR, "|derive write keys error|");
        return -XQC_TLS_UPDATE_KEY_ERROR;
    }

    if (type == XQC_KEY_TYPE_RX_READ) {
        tls->key_update_confirmed = XQC_FALSE;

    } else if (type == XQC_KEY_TYPE_TX_WRITE) {
        tls->key_update_confirmed = XQC_TRUE;
    }

    return XQC_OK;
}

void
xqc_tls_discard_old_1rtt_keys(xqc_tls_t *tls)
{
    xqc_crypto_discard_old_keys(tls->crypto[XQC_ENC_LEV_1RTT]);
}


/**
 * ============================================================================
 *                        callback functions to upper layer
 * ============================================================================
 */

void
xqc_ssl_keylog_cb(const SSL *ssl, const char *line)
{
    xqc_tls_t *tls = (xqc_tls_t *)SSL_get_app_data(ssl);
    if (tls->cbs->keylog_cb) {
        tls->cbs->keylog_cb(line, tls->user_data);
    }
}


int
xqc_ssl_alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
    const unsigned char *in, unsigned int inlen, void *arg)
{
    xqc_tls_t *tls = (xqc_tls_t *)SSL_get_app_data(ssl);

    /* get configured alpn_list */
    xqc_engine_ssl_config_t *cfg = NULL;
    xqc_tls_ctx_get_cfg(tls->ctx, &cfg);

    /* get alpn list */
    uint8_t *alpn_list = NULL;
    size_t alpn_list_len = 0;
    xqc_tls_ctx_get_alpn_list(tls->ctx, &alpn_list, &alpn_list_len);

    /* select alp */
    if (SSL_select_next_proto((unsigned char **)out, outlen, alpn_list, alpn_list_len, in, inlen)
        != OPENSSL_NPN_NEGOTIATED)
    {
        xqc_log(tls->log, XQC_LOG_ERROR, "|select proto error|");
        return SSL_TLSEXT_ERR_NOACK;
    }

    /* notify alpn selection to upper layer */
    const unsigned char *alpn = (uint8_t *)(*out);
    size_t alpn_len = *outlen;
    xqc_int_t ret = tls->cbs->alpn_select_cb(alpn, alpn_len, tls->user_data);
    if (XQC_OK != ret) {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    xqc_log(tls->log, XQC_LOG_DEBUG, "|select alpn|%*s|", alpn_len, alpn);
    return SSL_TLSEXT_ERR_OK;
}


int
xqc_ssl_session_ticket_key_cb(SSL *ssl, uint8_t *key_name, uint8_t *iv,
    EVP_CIPHER_CTX *cipher_ctx, HMAC_CTX *hmac_ctx, int encrypt)
{
    size_t size = 0;
    const EVP_CIPHER *cipher = NULL;
    const EVP_MD *digest = EVP_sha256();
    xqc_tls_t *tls = (xqc_tls_t *)SSL_get_app_data(ssl);

    /* get session ticket key */
    xqc_ssl_session_ticket_key_t *key = NULL;
    xqc_tls_ctx_get_session_ticket_key(tls->ctx, &key);
    if (NULL == key) {
        xqc_log(tls->log, XQC_LOG_ERROR, "|get session ticket key failed|");
        return -1;
    }

    if (encrypt == 1) {
        /* encrypt session ticket, returns 1 on success and -1 on error */
        if (key->size == 48) {
            cipher = EVP_aes_128_cbc();
            size = 16;

        } else {
            cipher = EVP_aes_256_cbc();
            size = 32;
        }

        if (RAND_bytes(iv, EVP_CIPHER_iv_length(cipher)) != 1) {
            xqc_log(tls->log, XQC_LOG_ERROR, "|RAND_bytes() failed|");
            return -1;
        }

        if (EVP_EncryptInit_ex(cipher_ctx, cipher, NULL, key->aes_key, iv) != 1) {
            xqc_log(tls->log, XQC_LOG_ERROR, "|EVP_EncryptInit_ex() failed|");
            return -1;
        }

        if (HMAC_Init_ex(hmac_ctx, key->hmac_key, size, digest, NULL) != 1) {
            xqc_log(tls->log, XQC_LOG_ERROR, "|HMAC_Init_ex() failed|");
            return -1;
        }

        memcpy(key_name, key->name, 16);

    } else {
        /*
         * decrypt session ticket, returns -1 to abort the handshake,
         * 0 if decrypting the ticket failed, and 1 or 2 on success
         */
        if (memcmp(key_name, key->name, 16) != 0) {
            xqc_log(tls->log, XQC_LOG_ERROR, "|ssl session ticket decrypt, key name not match|");
            return -1;
        }

        if (key->size == 48) {
            cipher = EVP_aes_128_cbc();
            size = 16;

        } else {
            cipher = EVP_aes_256_cbc();
            size = 32;
        }

        if (HMAC_Init_ex(hmac_ctx, key->hmac_key, size, digest, NULL) != 1) {
            xqc_log(tls->log, XQC_LOG_ERROR, "|HMAC_Init_ex() failed|");
            return 0;
        }

        if (EVP_DecryptInit_ex(cipher_ctx, cipher, NULL, key->aes_key, iv) != 1) {
            xqc_log(tls->log, XQC_LOG_ERROR, "|EVP_DecryptInit_ex() failed|");
            return 0;
        }
    }

    return 1;
}


int
xqc_ssl_new_session_cb(SSL *ssl, SSL_SESSION *session)
{
    xqc_tls_t *tls = (xqc_tls_t *)SSL_get_app_data(ssl);

    /* check if early data is enabled */
    if (!xqc_ssl_session_is_early_data_enabled(session)) {
        xqc_log(tls->log, XQC_LOG_ERROR, "|early data is not enabled|");
        goto end;
    }

    if (tls->cbs->session_cb != NULL) {
        char *data = NULL;

        BIO *bio = BIO_new(BIO_s_mem());
        if (bio == NULL) {
            xqc_log(tls->log, XQC_LOG_ERROR, "|save new session error|");
            goto end;
        }

        PEM_write_bio_SSL_SESSION(bio, session);
        size_t data_len = BIO_get_mem_data(bio,  &data);
        if (data_len == 0 || data == NULL) {
            xqc_log(tls->log, XQC_LOG_ERROR, "|save new session error|");

        } else {
            /* callback to upper layer */
            tls->cbs->session_cb(data, data_len, tls->user_data);
        }

        BIO_free(bio);
    }

end:
    /* return one for taking ownership and zero otherwise */
    return 0;
}


int
xqc_ssl_cert_verify_cb(int ok, X509_STORE_CTX *store_ctx)
{
    int verify_res = XQC_SSL_SUCCESS;
    size_t certs_array_len = 0;
    unsigned char *certs_array[XQC_MAX_VERIFY_DEPTH] = {0};
    size_t certs_len[XQC_MAX_VERIFY_DEPTH] = {0};

    if (ok == XQC_SSL_SUCCESS) {
        return XQC_SSL_SUCCESS;
    }

    SSL *ssl = X509_STORE_CTX_get_ex_data(store_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    if (ssl == NULL) {
        return XQC_SSL_FAIL;
    }

    xqc_tls_t *tls = (xqc_tls_t *)SSL_get_app_data(ssl);
    if (tls == NULL) {
        return XQC_SSL_FAIL;
    }

    int err_code = X509_STORE_CTX_get_error(store_ctx);
    if (err_code != X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
        && err_code != X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
        && !((tls->cert_verify_flag & XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED) != 0
             && XQC_TLS_SELF_SIGNED_CERT(err_code)))
    {
        xqc_log(tls->log, XQC_LOG_ERROR, "|certificate verify failed with err_code:%d|", err_code);
        if (tls->cbs->error_cb) {
            tls->cbs->error_cb(err_code, tls->user_data);
        }
        return XQC_SSL_FAIL;
    }

    /* get certs array */
    xqc_int_t ret = xqc_ssl_get_certs_array(ssl, store_ctx, certs_array, XQC_MAX_VERIFY_DEPTH,
                                            &certs_array_len, certs_len);
    if (ret != XQC_OK) {
        xqc_log(tls->log, XQC_LOG_ERROR, "|get cert array error|%d|", ret);
        if (tls->cbs->error_cb) {
            tls->cbs->error_cb(err_code, tls->user_data);
        }
        verify_res = XQC_SSL_FAIL;
        goto end;
    }

    /* callback to upper layer */
    if (tls->cbs->cert_verify_cb != NULL) {
        if (tls->cbs->cert_verify_cb((const unsigned char **)certs_array, certs_len, 
                                     certs_array_len, tls->user_data) != XQC_OK)
        {
            verify_res = XQC_SSL_FAIL;

        } else {
            verify_res = XQC_SSL_SUCCESS;
        }
    }

end:
    xqc_ssl_free_certs_array(certs_array, certs_array_len);
    return verify_res;
}


/**
 * ============================================================================
 *                        quic method callback functions
 * ============================================================================
 */

int 
xqc_tls_set_read_secret(SSL *ssl, enum ssl_encryption_level_t level,
    const SSL_CIPHER *cipher, const uint8_t *secret, size_t secret_len)
{
    xqc_int_t ret;
    xqc_tls_t *tls = SSL_get_app_data(ssl);

    /* try to process transport parameter if ssl parsed the quic_transport_params extension */
    xqc_tls_process_trans_param(tls);

    /* create crypto instance if not created */
    if (NULL == tls->crypto[level]) {
        tls->crypto[level] = xqc_crypto_create(
            xqc_tls_get_cipher_id(ssl, (xqc_encrypt_level_t)level, tls->no_crypto), tls->log);
        if (NULL == tls->crypto[level]) {
            xqc_log(tls->log, XQC_LOG_ERROR, "|create crypto error");
            return XQC_SSL_FAIL;
        }
    }

    /* save application traffic secret */
    if (level == ssl_encryption_application) {
        ret = xqc_crypto_save_application_traffic_secret_0(tls->crypto[level], secret,
                                                           secret_len, XQC_KEY_TYPE_RX_READ);
        if (ret != XQC_OK) {
            xqc_log(tls->log, XQC_LOG_ERROR,
                    "|save application traffic secret error|level:%d|ret:%d", level, ret);
            return XQC_SSL_FAIL;
        }
    }

    /* derive and install read key */
    xqc_crypto_t *crypto = tls->crypto[level];
    ret = xqc_crypto_derive_keys(crypto, secret, secret_len, XQC_KEY_TYPE_RX_READ);
    if (ret != XQC_OK) {
        xqc_log(tls->log, XQC_LOG_ERROR, "|install write key error|level:%d|ret:%d", level, ret);
        return XQC_SSL_FAIL;
    }

    return XQC_SSL_SUCCESS;
}


int 
xqc_tls_set_write_secret(SSL *ssl, enum ssl_encryption_level_t level,
    const SSL_CIPHER *cipher, const uint8_t *secret, size_t secret_len)
{
    xqc_int_t ret;
    xqc_tls_t *tls = SSL_get_app_data(ssl);

    /* try to process transport parameter if ssl parsed the quic_transport_params extension */
    xqc_tls_process_trans_param(tls);

    /* create crypto instance if not created */
    if (NULL == tls->crypto[level]) {
        tls->crypto[level] = xqc_crypto_create(
            xqc_tls_get_cipher_id(ssl, (xqc_encrypt_level_t)level, tls->no_crypto), tls->log);
        if (NULL == tls->crypto[level]) {
            xqc_log(tls->log, XQC_LOG_ERROR, "|create crypto error");
            return XQC_SSL_FAIL;
        }
    }

    /* save application traffic secret */
    if (level == ssl_encryption_application) {
        ret = xqc_crypto_save_application_traffic_secret_0(tls->crypto[level], secret,
                                                           secret_len, XQC_KEY_TYPE_TX_WRITE);
        if (ret != XQC_OK) {
            xqc_log(tls->log, XQC_LOG_ERROR,
                    "|save application traffic secret error|level:%d|ret:%d", level, ret);
            return XQC_SSL_FAIL;
        }
    }

    /* derive and install write key */
    xqc_crypto_t *crypto = tls->crypto[level];
    ret = xqc_crypto_derive_keys(crypto, secret, secret_len, XQC_KEY_TYPE_TX_WRITE);
    if (ret != XQC_OK) {
        xqc_log(tls->log, XQC_LOG_ERROR, "|install write key error|level:%d|ret:%d", level, ret);
        return XQC_SSL_FAIL;
    }

    return XQC_SSL_SUCCESS;
}

int 
xqc_tls_add_handshake_data(SSL *ssl, enum ssl_encryption_level_t level,
    const uint8_t *data, size_t len)
{
    xqc_tls_t *tls = SSL_get_app_data(ssl);

    /* notify tls handshake data to upper layer */
    if (tls->cbs->crypto_data_cb) {
        if (tls->cbs->crypto_data_cb((xqc_encrypt_level_t)level, data, len,
                                     tls->user_data) != XQC_OK)
        {
            xqc_log(tls->log, XQC_LOG_ERROR, "|crypto_data_cb error|");
            return XQC_SSL_FAIL;
        }
    }

    return XQC_SSL_SUCCESS;
}

int 
xqc_tls_flush_flight(SSL *ssl)
{
    return XQC_SSL_SUCCESS;
}

int 
xqc_tls_send_alert(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert)
{
    xqc_tls_t *tls = SSL_get_app_data(ssl);

    xqc_log(tls->log, XQC_LOG_ERROR, "|ssl alert|level:%d|alert:%d|error:%s",
            level, alert, ERR_error_string(ERR_get_error(), NULL));

    /* callback to upper layer. */
    if (tls->cbs->error_cb) {
        tls->cbs->error_cb(alert, tls->user_data);
    }

    return XQC_SSL_SUCCESS;
}

SSL_QUIC_METHOD xqc_ssl_quic_method = {
    .set_read_secret    = xqc_tls_set_read_secret,
    .set_write_secret   = xqc_tls_set_write_secret,
    .add_handshake_data = xqc_tls_add_handshake_data,
    .flush_flight       = xqc_tls_flush_flight,
    .send_alert         = xqc_tls_send_alert,
};
