/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_hq_conn.h"
#include "xqc_hq_defs.h"
#include "xqc_hq_ctx.h"

#include "src/common/xqc_common_inc.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_conn.h"


typedef struct xqc_hq_conn_s {
    xqc_hq_conn_callbacks_t    *hqc_cbs;

    xqc_connection_t           *conn;

    xqc_log_t                  *log;

    void                       *user_data;

} xqc_hq_conn_s;


xqc_hq_conn_t *
xqc_hq_conn_create(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data)
{
    xqc_hq_conn_t *hqc = xqc_calloc(1, sizeof(xqc_hq_conn_t));
    if (NULL == hqc) {
        return NULL;
    }

    if (xqc_hq_ctx_get_conn_callbacks(&hqc->hqc_cbs) != XQC_OK) {
        PRINT_LOG("|create hq conn failed");
        xqc_free(hqc);
        return NULL;
    }

    hqc->user_data = user_data;
    hqc->log = conn->log;
    hqc->conn = conn;

    return hqc;
}


void
xqc_hq_conn_destroy(xqc_hq_conn_t *hqc)
{
    if (hqc) {
        xqc_free(hqc);
    }
}


xqc_hq_conn_t *
xqc_hq_conn_create_passive(xqc_connection_t *conn, const xqc_cid_t *cid)
{
    xqc_hq_conn_t *hqc = xqc_hq_conn_create(conn, cid, NULL);
    if (NULL == hqc) {
        PRINT_LOG("|create hq conn failed");
        return NULL;
    }

    xqc_conn_set_alp_user_data(conn, hqc);
    return hqc;
}


xqc_hq_conn_t *
xqc_hq_connect(xqc_engine_t *engine, const xqc_conn_settings_t *conn_settings, 
    const unsigned char *token, unsigned token_len, const char *server_host, int no_crypto_flag,
    const xqc_conn_ssl_config_t *conn_ssl_config, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *user_data)
{
    /* HQ is also known as HTTP/0.9, here it is used as interop protocol */
    const xqc_cid_t *cid = xqc_connect(engine, conn_settings, token, token_len, server_host,
        no_crypto_flag, conn_ssl_config, peer_addr, peer_addrlen, 
        xqc_hq_alpn[conn_settings->proto_version], user_data);
    if (cid == NULL) {
        return NULL;
    }

    xqc_hq_conn_t *hqc = xqc_hq_conn_create(xqc_engine_conns_hash_find(engine, cid, 's'),
                                            cid, user_data);
    if (NULL == hqc) {
        xqc_conn_close(engine, cid);
        return NULL;
    }

    return hqc;
}


xqc_int_t
xqc_hq_conn_close(xqc_engine_t *engine, xqc_hq_conn_t *hqc, const xqc_cid_t *cid)
{
    return xqc_conn_close(engine, cid);
}


void
xqc_hq_conn_set_user_data(xqc_hq_conn_t *hqc, void *user_data)
{
    hqc->user_data = user_data;
}


xqc_int_t
xqc_hq_conn_get_peer_addr(xqc_hq_conn_t *hqc, struct sockaddr *addr, socklen_t addr_cap,
    socklen_t *peer_addr_len)
{
    return xqc_conn_get_peer_addr(hqc->conn, addr, addr_cap, peer_addr_len);
}

xqc_int_t
xqc_hq_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *conn_user_data)
{
    /* here conn_user_data is the app-layer user_data */
    xqc_hq_conn_t *hqc = xqc_hq_conn_create(conn, cid, conn_user_data);
    if (NULL == hqc) {
        PRINT_LOG("|create hq conn failed");
        return -XQC_EMALLOC;
    }

    /* set hqc as conn's application-layer-protocol user_data */
    xqc_conn_set_alp_user_data(conn, hqc);

    if (hqc->hqc_cbs->conn_create_notify) {
        /* NOTICE: if hqc is created passively, hqc->user_data is NULL */
        return hqc->hqc_cbs->conn_create_notify(hqc, cid, hqc->user_data);
    }

    return XQC_OK;
}

xqc_int_t
xqc_hq_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *conn_user_data)
{
    xqc_int_t ret = XQC_OK;

    xqc_hq_conn_t *hqc = (xqc_hq_conn_t *)conn_user_data;
    if (hqc->hqc_cbs->conn_close_notify) {
        ret = hqc->hqc_cbs->conn_close_notify(hqc, cid, hqc->user_data);
        if (ret != XQC_OK) {
            return ret;
        }
    }

    xqc_hq_conn_destroy(hqc);

    return XQC_OK;
}


void
xqc_hq_conn_handshake_finished(xqc_connection_t *conn, void *conn_user_data)
{
    return;
}


/* connection callback over quic Transport layere */
const xqc_conn_callbacks_t hq_conn_callbacks = {
    .conn_create_notify         = xqc_hq_conn_create_notify,
    .conn_close_notify          = xqc_hq_conn_close_notify,
    .conn_handshake_finished    = xqc_hq_conn_handshake_finished,
};
