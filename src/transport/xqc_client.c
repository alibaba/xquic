/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <xquic/xquic.h>
#include "src/http3/xqc_h3_stream.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_client.h"
#include "src/transport/xqc_cid.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_utils.h"
#include "src/transport/xqc_defs.h"
#include "src/tls/xqc_tls.h"

xqc_connection_t *
xqc_client_connect(xqc_engine_t *engine, const xqc_conn_settings_t *conn_settings,
    const unsigned char *token, unsigned token_len, const char *server_host, int no_crypto_flag,
    const xqc_conn_ssl_config_t *conn_ssl_config, const char *alpn, 
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user_data)
{
    xqc_cid_t dcid;
    xqc_cid_t scid;

    if (NULL == conn_ssl_config) {
        xqc_log(engine->log, XQC_LOG_ERROR,
                "|xqc_conn_ssl_config is NULL|");
        return NULL;
    }

    if (token_len > XQC_MAX_TOKEN_LEN) {
        xqc_log(engine->log, XQC_LOG_ERROR,
                "|%ud exceed XQC_MAX_TOKEN_LEN|", token_len);
        return NULL;
    }

    if (xqc_generate_cid(engine, NULL, &scid, 0) != XQC_OK
        || xqc_generate_cid(engine, NULL, &dcid, 0) != XQC_OK)
    {
        xqc_log(engine->log, XQC_LOG_ERROR,
                "|generate dcid or scid error|");
        return NULL;
    }

    xqc_connection_t *xc = xqc_client_create_connection(engine, dcid, scid, conn_settings,
                                                        server_host, no_crypto_flag,
                                                        conn_ssl_config, alpn, user_data);
    if (xc == NULL) {
        xqc_log(engine->log, XQC_LOG_ERROR,
                "|create connection error|");
        return NULL;
    }

    if (token && token_len > 0) {
        xc->conn_token_len = token_len;
        memcpy(xc->conn_token, token, token_len);
    }

    if (peer_addr && peer_addrlen > 0) {
        xc->peer_addrlen = peer_addrlen;
        memcpy(xc->peer_addr, peer_addr, peer_addrlen);
    }

    xqc_log(engine->log, XQC_LOG_DEBUG, "|xqc_connect|");
    xqc_log_event(xc->log, CON_CONNECTION_STARTED, xc, XQC_LOG_REMOTE_EVENT);

    /* conn_create callback */
    if (xc->app_proto_cbs.conn_cbs.conn_create_notify) {
        if (xc->app_proto_cbs.conn_cbs.conn_create_notify(xc, &xc->scid_set.user_scid, user_data)) {
            xqc_conn_destroy(xc);
            return NULL;
        }

        xc->conn_flag |= XQC_CONN_FLAG_UPPER_CONN_EXIST;
    }

    /* xqc_conn_destroy must be called before the connection is inserted into conns_active_pq */
    if (!(xc->conn_flag & XQC_CONN_FLAG_TICKING)) {
        if (xqc_conns_pq_push(engine->conns_active_pq, xc, 0)) {
            return NULL;
        }
        xc->conn_flag |= XQC_CONN_FLAG_TICKING;
    }

    xqc_engine_main_logic_internal(engine, xc);

    /* when the connection is destroyed in the main logic, we should return error to upper level */
    if (xqc_engine_conns_hash_find(engine, &scid, 's') == NULL) {
        return NULL;
    }

    return xc;
}

const xqc_cid_t *
xqc_connect(xqc_engine_t *engine, const xqc_conn_settings_t *conn_settings, 
    const unsigned char *token, unsigned token_len, const char *server_host, int no_crypto_flag,
    const xqc_conn_ssl_config_t *conn_ssl_config, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, const char *alpn, void *user_data)
{
    xqc_connection_t *conn;

    if (NULL == alpn || strlen(alpn) > XQC_MAX_ALPN_LEN) {
        return NULL;
    }

    conn = xqc_client_connect(engine, conn_settings, token, token_len, server_host, no_crypto_flag, 
                              conn_ssl_config, alpn, peer_addr, peer_addrlen, user_data);
    if (conn) {
        return &conn->scid_set.user_scid;
    }

    return NULL;
}


xqc_int_t
xqc_client_create_tls(xqc_connection_t *conn, const xqc_conn_ssl_config_t *conn_ssl_config,
    const char *hostname, int no_crypto_flag, const char *alpn)
{
    xqc_int_t           ret;
    xqc_tls_config_t    cfg = {0};
    uint8_t             tp_buf[XQC_MAX_TRANSPORT_PARAM_BUF_LEN] = {0};
    uint8_t            *session_ticket_buf;
    uint8_t            *alpn_buf;
    size_t              alpn_cap;
    unsigned char      *hostname_buf;
    size_t              host_cap;

    /* init tls config */
    cfg.cert_verify_flag = conn_ssl_config->cert_verify_flag;
    cfg.no_crypto_flag = no_crypto_flag;

    /* copy session ticket */
    cfg.session_ticket = xqc_malloc(conn_ssl_config->session_ticket_len + 1);
    if (NULL == cfg.session_ticket) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|malloc for session ticket fail|");
        ret = -XQC_EMALLOC;
        goto end;
    }
    xqc_memcpy(cfg.session_ticket, conn_ssl_config->session_ticket_data,
               conn_ssl_config->session_ticket_len);
    cfg.session_ticket_len = conn_ssl_config->session_ticket_len;

    /* copy alpn */
    alpn_cap = strlen(alpn) + 1;
    cfg.alpn = xqc_malloc(alpn_cap);
    if (NULL == cfg.alpn) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|malloc for alpn fail|");
        ret = -XQC_EMALLOC;
        goto end;
    }
    strncpy(cfg.alpn, alpn, alpn_cap);

    /* copy hostname */
    host_cap = strlen(hostname) + 1;
    cfg.hostname = xqc_malloc(host_cap);
    if (NULL == cfg.alpn) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|malloc for alpn fail|");
        ret = -XQC_EMALLOC;
        goto end;
    }
    strncpy(cfg.hostname, hostname, host_cap);

    /* encode local transport parameters, and set to tls config */
    cfg.trans_params = tp_buf;
    ret = xqc_conn_encode_local_tp(conn, cfg.trans_params,
                                   XQC_MAX_TRANSPORT_PARAM_BUF_LEN, &cfg.trans_params_len);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|encode transport parameter error|ret:%d", ret);
        goto end;
    }

    /* create tls instance */
    conn->tls = xqc_tls_create(conn->engine->tls_ctx, &cfg, conn->log, conn);
    if (NULL == conn->tls) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|create tls instance error");
        ret = -XQC_EMALLOC;
        goto end;
    }

    /* start handshake */
    ret = xqc_tls_init(conn->tls, conn->version, &conn->original_dcid);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|init tls error");
        goto end;
    }

end:
    if (cfg.session_ticket) {
        xqc_free(cfg.session_ticket);
    }

    if (cfg.alpn) {
        xqc_free(cfg.alpn);
    }

    if (cfg.hostname) {
        xqc_free(cfg.hostname);
    }

    return ret;
}


xqc_connection_t *
xqc_client_create_connection(xqc_engine_t *engine, xqc_cid_t dcid, xqc_cid_t scid,
    const xqc_conn_settings_t *settings, const char *server_host, int no_crypto_flag,
    const xqc_conn_ssl_config_t *conn_ssl_config, const char *alpn, void *user_data)
{
    xqc_int_t               ret;
    xqc_transport_params_t  tp;
    xqc_trans_settings_t   *local_settings;

    xqc_connection_t *xc = xqc_conn_create(engine, &dcid, &scid, settings, user_data,
                                           XQC_CONN_TYPE_CLIENT);
    if (xc == NULL) {
        return NULL;
    }

    /* save odcid */
    xqc_cid_copy(&(xc->original_dcid), &(xc->dcid_set.current_dcid));

    /* create initial crypto stream, which MUST be created before tls for storing ClientHello */
    xc->crypto_stream[XQC_ENC_LEV_INIT] = xqc_create_crypto_stream(xc, XQC_ENC_LEV_INIT, user_data);
    if (!xc->crypto_stream[XQC_ENC_LEV_INIT]) {
        goto fail;
    }

    /* set no crypto option */
    local_settings = &xc->local_settings;
    if (no_crypto_flag == 1) {
        local_settings->no_crypto = XQC_TRUE;  /* no_crypto 1 means do not crypto*/

    } else {
        local_settings->no_crypto = XQC_FALSE;
    }

    /* create and init tls, startup ClientHello */
    if (xqc_client_create_tls(xc, conn_ssl_config, server_host, no_crypto_flag, alpn) != XQC_OK) {
        goto fail;
    }

    /* recover server's transport parameter */
    if (conn_ssl_config->transport_parameter_data
        && conn_ssl_config->transport_parameter_data_len > 0)
    {
        xqc_memzero(&tp, sizeof(xqc_transport_params_t));
        ret = xqc_read_transport_params(conn_ssl_config->transport_parameter_data,
                                                  conn_ssl_config->transport_parameter_data_len, &tp);
        if (ret == XQC_OK) {
            xqc_conn_set_early_remote_transport_params(xc, &tp);
        }
    }

    if (xqc_conn_client_on_alpn(xc, alpn, strlen(alpn)) != XQC_OK) {
        goto fail;
    }

    return xc;

fail:
    xqc_conn_destroy(xc);
    return NULL;
}

