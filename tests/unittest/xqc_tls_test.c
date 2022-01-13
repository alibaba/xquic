/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xqc_common_test.h"
#include "src/transport/xqc_conn.h"
#include "src/tls/xqc_tls_ctx.h"
#include "src/tls/xqc_tls.h"

#define XQC_TEST_MAX_CRYPTO_DATA_BUF 16 * 1024

#define XQC_TEST_SESSION_TICKET_KEY "\xa8\x6d\x19\x70\x06\x08\x9b\x2d" \
"\xa7\x17\x50\xf7\x97\x78\xf7\xe8\x3c\x5a\xc4\x9d\x61\x34\xe3\xa1\xfa" \
"\x62\x7b\x66\xf0\x2f\x5b\xdc\x63\x12\x8d\x10\x9a\x57\x5c\xdd\x1b\xc3" \
"\x8f\x13\x93\x3c\x85\xe6\x0a"

void
xqc_test_create_client_tls_ctx()
{
    xqc_engine_t *engine = test_create_engine();

    xqc_engine_ssl_config_t engine_ssl_config;
    memset(&engine_ssl_config, 0, sizeof(engine_ssl_config));

    /* not set ciphers and groups */
    xqc_tls_ctx_t *ctx = xqc_tls_ctx_create(XQC_TLS_TYPE_CLIENT, &engine_ssl_config,
                                            &xqc_conn_tls_cbs, engine->log);
    CU_ASSERT(ctx != NULL);

    SSL_CTX *ssl_ctx = xqc_tls_ctx_get_ssl_ctx(ctx);
    CU_ASSERT(ssl_ctx != NULL);

    xqc_tls_type_t tls_type = xqc_tls_ctx_get_type(ctx);
    CU_ASSERT(tls_type == XQC_TLS_TYPE_CLIENT);

    xqc_engine_ssl_config_t *cfg = NULL;
    xqc_tls_ctx_get_cfg(ctx, &cfg);
    CU_ASSERT(0 == strcmp(cfg->ciphers, XQC_TLS_CIPHERS));
    CU_ASSERT(0 == strcmp(cfg->groups, XQC_TLS_GROUPS));

    xqc_tls_ctx_destroy(ctx);

    /* set ciphers and groups */
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;

    ctx = xqc_tls_ctx_create(XQC_TLS_TYPE_CLIENT, &engine_ssl_config, &xqc_conn_tls_cbs, engine->log);
    CU_ASSERT(ctx != NULL);

    ssl_ctx = xqc_tls_ctx_get_ssl_ctx(ctx);
    CU_ASSERT(ssl_ctx != NULL);

    tls_type = xqc_tls_ctx_get_type(ctx);
    CU_ASSERT(tls_type == XQC_TLS_TYPE_CLIENT);

    cfg = NULL;
    xqc_tls_ctx_get_cfg(ctx, &cfg);
    CU_ASSERT(0 == strcmp(cfg->ciphers, XQC_TLS_CIPHERS));
    CU_ASSERT(0 == strcmp(cfg->groups, XQC_TLS_GROUPS));

    xqc_tls_ctx_destroy(ctx);
    xqc_engine_destroy(engine);
}

void
xqc_test_create_server_tls_ctx()
{
    xqc_engine_t *engine = test_create_engine_server();

    xqc_engine_ssl_config_t engine_ssl_config;
    memset(&engine_ssl_config, 0, sizeof(engine_ssl_config));

    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;

    /* no private key file */
    xqc_tls_ctx_t *ctx = xqc_tls_ctx_create(XQC_TLS_TYPE_SERVER, &engine_ssl_config,
                                            &xqc_conn_tls_cbs, engine->log);
    CU_ASSERT(ctx == NULL);

    /* no cert file */
    engine_ssl_config.private_key_file = "./server.key";
    ctx = xqc_tls_ctx_create(XQC_TLS_TYPE_SERVER, &engine_ssl_config, &xqc_conn_tls_cbs, engine->log);
    CU_ASSERT(ctx == NULL);

    /* no session ticket key data */
    engine_ssl_config.cert_file = "./server.crt";
    engine_ssl_config.session_ticket_key_data = NULL;
    engine_ssl_config.session_ticket_key_len = 0;
    ctx = xqc_tls_ctx_create(XQC_TLS_TYPE_SERVER, &engine_ssl_config, &xqc_conn_tls_cbs, engine->log);
    CU_ASSERT(ctx != NULL);

    SSL_CTX *ssl_ctx = xqc_tls_ctx_get_ssl_ctx(ctx);
    CU_ASSERT(ssl_ctx != NULL);

    xqc_tls_type_t tls_type = xqc_tls_ctx_get_type(ctx);
    CU_ASSERT(tls_type == XQC_TLS_TYPE_SERVER);

    xqc_engine_ssl_config_t *cfg = NULL;
    xqc_tls_ctx_get_cfg(ctx, &cfg);
    CU_ASSERT(0 == strcmp(cfg->ciphers, XQC_TLS_CIPHERS));
    CU_ASSERT(0 == strcmp(cfg->groups, XQC_TLS_GROUPS));
    CU_ASSERT(0 == strcmp(cfg->private_key_file, "./server.key"));
    CU_ASSERT(0 == strcmp(cfg->cert_file, "./server.crt"));

    xqc_ssl_session_ticket_key_t *key = NULL;
    xqc_tls_ctx_get_session_ticket_key(ctx, &key);
    CU_ASSERT(key->size == 0);

    xqc_tls_ctx_destroy(ctx);

    /* init session ticket key error */
    engine_ssl_config.session_ticket_key_data = "test_stk";
    engine_ssl_config.session_ticket_key_len = 8;

    ctx = xqc_tls_ctx_create(XQC_TLS_TYPE_SERVER, &engine_ssl_config, &xqc_conn_tls_cbs, engine->log);
    CU_ASSERT(ctx == NULL);

    xqc_engine_destroy(engine);
}

#define TEST_ALPN_1 "transport"
#define TEST_ALPN_2 "h3"

void
xqc_test_tls_ctx_register_alpn()
{
    xqc_engine_t *engine = test_create_engine();
    xqc_engine_ssl_config_t engine_ssl_config;
    memset(&engine_ssl_config, 0, sizeof(engine_ssl_config));
    xqc_tls_ctx_t *ctx = xqc_tls_ctx_create(XQC_TLS_TYPE_CLIENT, &engine_ssl_config,
                                            &xqc_conn_tls_cbs, engine->log);
    CU_ASSERT(ctx != NULL);

    xqc_int_t ret;
    uint8_t *alpn_list = NULL;
    size_t alpn_list_len = 0;

    /* register alpn in tls context */
    ret = xqc_tls_ctx_register_alpn(ctx, TEST_ALPN_1, sizeof(TEST_ALPN_1) - 1);
    CU_ASSERT(ret == XQC_OK);

    ret = xqc_tls_ctx_register_alpn(ctx, TEST_ALPN_2, sizeof(TEST_ALPN_2) - 1);
    CU_ASSERT(ret == XQC_OK);

    xqc_tls_ctx_get_alpn_list(ctx, &alpn_list, &alpn_list_len);
    CU_ASSERT(alpn_list_len == sizeof(TEST_ALPN_1) + sizeof(TEST_ALPN_2));

    /* unregister alpn in tls context */
    ret = xqc_tls_ctx_unregister_alpn(ctx, TEST_ALPN_1, sizeof(TEST_ALPN_1) - 1);
    CU_ASSERT(ret == XQC_OK);

    xqc_tls_ctx_get_alpn_list(ctx, &alpn_list, &alpn_list_len);
    CU_ASSERT(alpn_list_len == sizeof(TEST_ALPN_2));

    ret = xqc_tls_ctx_unregister_alpn(ctx, TEST_ALPN_2, sizeof(TEST_ALPN_2) - 1);
    CU_ASSERT(ret == XQC_OK);

    xqc_tls_ctx_get_alpn_list(ctx, &alpn_list, &alpn_list_len);
    CU_ASSERT(alpn_list_len == 0);

    xqc_tls_ctx_destroy(ctx);
    xqc_engine_destroy(engine);
}

void
xqc_test_tls_reset_initial()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    /* reset initial keys */
    xqc_int_t ret = xqc_tls_reset_initial(conn->tls, conn->version, &conn->original_dcid);
    CU_ASSERT(ret == XQC_OK);

    ret = xqc_tls_is_key_ready(conn->tls, XQC_ENC_LEV_INIT, XQC_KEY_TYPE_RX_READ);
    CU_ASSERT(ret == XQC_TRUE);
    ret = xqc_tls_is_key_ready(conn->tls, XQC_ENC_LEV_INIT, XQC_KEY_TYPE_TX_WRITE);
    CU_ASSERT(ret == XQC_TRUE);

    xqc_engine_destroy(conn->engine);
}

typedef struct xqc_tls_test_buff_s {
    xqc_list_head_t    initial_crypto_data_list;
    xqc_list_head_t    hsk_crypto_data_list;
    xqc_list_head_t    application_crypto_data_list;

    xqc_bool_t         handshake_completed;

    unsigned char     *new_session_ticket;
    size_t             new_session_ticket_len;

    /* for test corner case: multiple crypto data */
    int                crypto_data_cnt;
    size_t             crypto_data_total_len;

    uint64_t           error_code;

} xqc_tls_test_buff_t;

static inline xqc_tls_test_buff_t*
xqc_create_tls_test_buffer()
{
    xqc_tls_test_buff_t *ttbuf = xqc_malloc(sizeof(xqc_tls_test_buff_t));
    xqc_init_list_head(&ttbuf->initial_crypto_data_list);
    xqc_init_list_head(&ttbuf->hsk_crypto_data_list);
    xqc_init_list_head(&ttbuf->application_crypto_data_list);

    ttbuf->handshake_completed = XQC_FALSE;

    ttbuf->new_session_ticket = NULL;
    ttbuf->new_session_ticket_len = 0;

    ttbuf->crypto_data_cnt = 0;
    ttbuf->crypto_data_total_len = 0;

    ttbuf->error_code = 0;

    return ttbuf;
}

static inline void
xqc_free_crypto_data_list(xqc_list_head_t *buffer_list)
{
    xqc_list_head_t *head = buffer_list;
    xqc_list_head_t *pos, *next;
    xqc_hs_buffer_t *hs_buf = NULL;

    xqc_list_for_each_safe(pos, next, head) {
        hs_buf = xqc_list_entry(pos, xqc_hs_buffer_t, list_head);
        xqc_list_del(pos);
        xqc_free(hs_buf);
    }
}

static inline void
xqc_destroy_tls_test_buffer(xqc_tls_test_buff_t *ttbuf)
{
    xqc_free_crypto_data_list(&ttbuf->initial_crypto_data_list);
    xqc_free_crypto_data_list(&ttbuf->hsk_crypto_data_list);
    xqc_free_crypto_data_list(&ttbuf->application_crypto_data_list);

    if (ttbuf->new_session_ticket != NULL) {
        xqc_free(ttbuf->new_session_ticket);
    }
    ttbuf->new_session_ticket_len = 0;

    xqc_free(ttbuf);
    ttbuf = NULL;
}

static inline size_t
xqc_crypto_data_list_get_buf(xqc_list_head_t *head, uint8_t *data)
{
    xqc_hs_buffer_t *hs_buf = NULL;
    xqc_list_head_t *pos, *next;
    size_t len = 0;

    xqc_list_for_each_safe(pos, next, head) {
        hs_buf = xqc_list_entry(pos, xqc_hs_buffer_t, list_head);

        if (len + hs_buf->data_len > XQC_TEST_MAX_CRYPTO_DATA_BUF) {
            return -XQC_TLS_NOBUF;
        }

        memcpy(data + len, hs_buf->data, hs_buf->data_len);
        len += hs_buf->data_len;
    }

    return len;
}

static inline xqc_hs_buffer_t *
xqc_create_hs_buffer(int buf_size)
{
    xqc_hs_buffer_t *buf = xqc_malloc(sizeof(xqc_hs_buffer_t) + buf_size);
    if (buf == NULL) {
        return NULL;
    }

    xqc_init_list_head(&buf->list_head);
    buf->data_len = buf_size;
    return buf;
}

xqc_int_t
xqc_tt_crypto_data_cb(xqc_encrypt_level_t level, const uint8_t *data, size_t len, void *user_data)
{
    xqc_tls_test_buff_t *ttbuf = (xqc_tls_test_buff_t *)user_data;
    xqc_list_head_t *crypto_data_list = NULL;

    switch (level) {
    case XQC_ENC_LEV_INIT:
        crypto_data_list = &ttbuf->initial_crypto_data_list;
        break;

    case XQC_ENC_LEV_HSK:
        crypto_data_list = &ttbuf->hsk_crypto_data_list;
        break;

    case XQC_ENC_LEV_1RTT:
        crypto_data_list = &ttbuf->application_crypto_data_list;
        break;

    default:
        return -XQC_EFATAL;
    }

    xqc_hs_buffer_t *hs_buf = xqc_create_hs_buffer(len);
    if (XQC_UNLIKELY(!hs_buf)) {
        return -XQC_EMALLOC;
    }

    memcpy(hs_buf->data, data, len);
    xqc_list_add_tail(&hs_buf->list_head, crypto_data_list);

    ttbuf->crypto_data_cnt++;
    ttbuf->crypto_data_total_len += len;

    return XQC_OK;
}

void
xqc_tt_transport_params_cb(const uint8_t *tp, size_t len, void *user_data)
{
}

xqc_int_t
xqc_tt_alpn_select_cb(const char *alpn, size_t alpn_len, void *user_data)
{
    return XQC_OK;
}

xqc_int_t
xqc_tt_cert_verify_cb(const unsigned char *certs[], const size_t cert_len[],
                      size_t certs_len, void *user_data)
{
    return XQC_OK;
}

void
xqc_tt_session_cb(const char *data, size_t data_len, void *user_data)
{
    xqc_tls_test_buff_t *ttbuf = (xqc_tls_test_buff_t *)user_data;
    if (ttbuf->new_session_ticket == NULL && ttbuf->new_session_ticket_len == 0) {
        ttbuf->new_session_ticket = xqc_malloc(data_len);
        memcpy(ttbuf->new_session_ticket, data, data_len);
        ttbuf->new_session_ticket_len = data_len;
    }
}

void
xqc_tt_keylog_cb(const char *line, void *user_data)
{
}

void
xqc_tt_tls_error_cb(xqc_int_t tls_err, void *user_data)
{
    xqc_tls_test_buff_t *ttbuf = (xqc_tls_test_buff_t *)user_data;

    ttbuf->error_code = tls_err;
}

void
xqc_tt_handshake_completed_cb(void *user_data)
{
    xqc_tls_test_buff_t *ttbuf = (xqc_tls_test_buff_t *)user_data;
    ttbuf->handshake_completed = XQC_TRUE;
}

xqc_tls_callbacks_t tls_test_cbs = {
    .crypto_data_cb = xqc_tt_crypto_data_cb,
    .tp_cb = xqc_tt_transport_params_cb,
    .alpn_select_cb = xqc_tt_alpn_select_cb,
    .cert_verify_cb = xqc_tt_cert_verify_cb,
    .session_cb = xqc_tt_session_cb,
    .keylog_cb = xqc_tt_keylog_cb,
    .error_cb = xqc_tt_tls_error_cb,
    .hsk_completed_cb = xqc_tt_handshake_completed_cb,
};

#define def_engine_ssl_config                            \
    xqc_engine_ssl_config_t engine_ssl_config;           \
    engine_ssl_config.private_key_file = "./server.key"; \
    engine_ssl_config.cert_file = "./server.crt";        \
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;         \
    engine_ssl_config.groups = XQC_TLS_GROUPS;           \
    engine_ssl_config.session_ticket_key_len = 48;       \
    engine_ssl_config.session_ticket_key_data = XQC_TEST_SESSION_TICKET_KEY;

void
xqc_test_tls_generic()
{
    def_engine_ssl_config
    xqc_int_t ret;
    int cnt;

    uint8_t *data_buf = malloc(XQC_TEST_MAX_CRYPTO_DATA_BUF);
    size_t   data_len = 0;

    /* 1-RTT */

    /* create server engine and tls_ctx */
    xqc_engine_t *engine_svr = test_create_engine_server();
    xqc_tls_ctx_t *ctx_svr = xqc_tls_ctx_create(XQC_TLS_TYPE_SERVER, &engine_ssl_config,
                                                &tls_test_cbs, engine_svr->log);
    CU_ASSERT(ctx_svr != NULL);

    ret = xqc_tls_ctx_register_alpn(ctx_svr, "transport", 9);
    CU_ASSERT(ret == XQC_OK);

    /* create client engine and tls_ctx */
    xqc_engine_t *engine_cli = test_create_engine();
    xqc_tls_ctx_t *ctx_cli = xqc_tls_ctx_create(XQC_TLS_TYPE_CLIENT, &engine_ssl_config,
                                                &tls_test_cbs, engine_cli->log);
    CU_ASSERT(ctx_cli != NULL);

    ret = xqc_tls_ctx_register_alpn(ctx_cli, "transport", 9);
    CU_ASSERT(ret == XQC_OK);

    /* get tls config */
    xqc_connection_t *test_conn = test_engine_connect();
    xqc_tls_config_t tls_config = {0};
    tls_config.session_ticket = NULL;
    tls_config.session_ticket_len = 0;
    tls_config.cert_verify_flag = 0;
    tls_config.hostname = "127.0.0.1";
    tls_config.alpn = "transport";
    tls_config.no_crypto_flag = 0;

    /* encode local transport params */
    char tp_buf[XQC_MAX_TRANSPORT_PARAM_BUF_LEN] = {0};
    tls_config.trans_params = tp_buf;
    xqc_conn_encode_local_tp(test_conn, tls_config.trans_params,
                             XQC_MAX_TRANSPORT_PARAM_BUF_LEN, &tls_config.trans_params_len);

    /* create client tls */
    xqc_tls_test_buff_t *ttbuf_cli = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_cli = xqc_tls_create(ctx_cli, &tls_config, engine_cli->log, ttbuf_cli);

    /* client start handshake, generate ClientHello */
    xqc_cid_t odcid;
    xqc_generate_cid(engine_cli, NULL, &odcid, 0);

    ret = xqc_tls_init(tls_cli, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(!xqc_list_empty(&ttbuf_cli->initial_crypto_data_list)); /* ClientHello */

    /* create server tls */
    xqc_tls_test_buff_t *ttbuf_svr = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_svr = xqc_tls_create(ctx_svr, &tls_config, engine_svr->log, ttbuf_svr);

    /* server handshake, process ClientHello, genrate ServerHello & Handshake data */
    ret = xqc_tls_init(tls_svr, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);

    data_len = xqc_crypto_data_list_get_buf(&ttbuf_cli->initial_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_svr, XQC_ENC_LEV_INIT, data_buf, data_len);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(!xqc_list_empty(&ttbuf_svr->initial_crypto_data_list)); /* ServerHello */
    CU_ASSERT(!xqc_list_empty(&ttbuf_svr->hsk_crypto_data_list));     /* EE, CERT, CV, FIN */

    /* client process handshake data from server */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_svr->initial_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_cli, XQC_ENC_LEV_INIT, data_buf, data_len);
    CU_ASSERT(ret == XQC_OK);

    data_len = xqc_crypto_data_list_get_buf(&ttbuf_svr->hsk_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_cli, XQC_ENC_LEV_HSK, data_buf, data_len);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(ttbuf_cli->handshake_completed == XQC_TRUE);
    CU_ASSERT(!xqc_list_empty(&ttbuf_cli->hsk_crypto_data_list)); /* FIN */

    /* server process handshake data from client, send new session ticket */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_cli->hsk_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_svr, XQC_ENC_LEV_HSK, data_buf, data_len);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(ttbuf_svr->handshake_completed == XQC_TRUE);
    CU_ASSERT(!xqc_list_empty(&ttbuf_svr->application_crypto_data_list)); /* New Session Ticket */

    /* client save session ticket data */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_svr->application_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_cli, XQC_ENC_LEV_1RTT, data_buf, data_len);
    CU_ASSERT(ttbuf_cli->new_session_ticket != NULL);
    CU_ASSERT(ttbuf_cli->new_session_ticket_len > 0);


    /* 0-RTT */

    tls_config.session_ticket = ttbuf_cli->new_session_ticket;
    tls_config.session_ticket_len = ttbuf_cli->new_session_ticket_len;

    /* create client tls */
    xqc_tls_test_buff_t *ttbuf_0rtt_cli = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_0rtt_cli = xqc_tls_create(ctx_cli, &tls_config, engine_cli->log, ttbuf_0rtt_cli);

    /* client start handshake, generate ClientHello */
    ret = xqc_tls_init(tls_0rtt_cli, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(!xqc_list_empty(&ttbuf_0rtt_cli->initial_crypto_data_list)); /* ClientHello */

    /* create server tls */
    xqc_tls_test_buff_t *ttbuf_0rtt_svr = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_0rtt_svr = xqc_tls_create(ctx_svr, &tls_config, engine_svr->log, ttbuf_0rtt_svr);

    /* server handshake, process ClientHello, genrate ServerHello & Handshake data */
    ret = xqc_tls_init(tls_0rtt_svr, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);

    data_len = xqc_crypto_data_list_get_buf(&ttbuf_0rtt_cli->initial_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_0rtt_svr, XQC_ENC_LEV_INIT, data_buf, data_len);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(!xqc_list_empty(&ttbuf_0rtt_svr->initial_crypto_data_list)); /* ServerHello */
    CU_ASSERT(!xqc_list_empty(&ttbuf_0rtt_svr->hsk_crypto_data_list));     /* EE, CERT, CV, FIN */

    /* client process handshake data from server */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_0rtt_svr->initial_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_0rtt_cli, XQC_ENC_LEV_INIT, data_buf, data_len);
    CU_ASSERT(ret == XQC_OK);

    data_len = xqc_crypto_data_list_get_buf(&ttbuf_0rtt_svr->hsk_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_0rtt_cli, XQC_ENC_LEV_HSK, data_buf, data_len);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(ttbuf_0rtt_cli->handshake_completed == XQC_TRUE);
    CU_ASSERT(!xqc_list_empty(&ttbuf_0rtt_cli->hsk_crypto_data_list)); /* FIN */

    /* server process handshake data from client */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_0rtt_cli->hsk_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_0rtt_svr, XQC_ENC_LEV_HSK, data_buf, data_len);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(ttbuf_0rtt_svr->handshake_completed == XQC_TRUE);



    xqc_destroy_tls_test_buffer(ttbuf_cli);
    xqc_destroy_tls_test_buffer(ttbuf_svr);
    xqc_destroy_tls_test_buffer(ttbuf_0rtt_cli);
    xqc_destroy_tls_test_buffer(ttbuf_0rtt_svr);

    xqc_tls_destroy(tls_cli);
    xqc_tls_destroy(tls_svr);
    xqc_tls_destroy(tls_0rtt_cli);
    xqc_tls_destroy(tls_0rtt_svr);

    xqc_tls_ctx_destroy(ctx_cli);
    xqc_tls_ctx_destroy(ctx_svr);

    xqc_engine_destroy(engine_cli);
    xqc_engine_destroy(engine_svr);
    xqc_engine_destroy(test_conn->engine);

    free(data_buf);
}

void
xqc_test_tls_multiple_crypto_data()
{
    def_engine_ssl_config
    xqc_int_t ret;
    int cnt;

    uint8_t *data_buf = malloc(XQC_TEST_MAX_CRYPTO_DATA_BUF);
    size_t  data_len = 0;

    /* create server engine and tls_ctx */
    xqc_engine_t *engine_svr = test_create_engine_server();
    xqc_tls_ctx_t *ctx_svr = xqc_tls_ctx_create(XQC_TLS_TYPE_SERVER, &engine_ssl_config,
                                                &tls_test_cbs, engine_svr->log);
    CU_ASSERT(ctx_svr != NULL);

    ret = xqc_tls_ctx_register_alpn(ctx_svr, "transport", 9);
    CU_ASSERT(ret == XQC_OK);

    /* create client engine and tls_ctx */
    xqc_engine_t *engine_cli = test_create_engine();
    xqc_tls_ctx_t *ctx_cli = xqc_tls_ctx_create(XQC_TLS_TYPE_CLIENT, &engine_ssl_config,
                                                &tls_test_cbs, engine_cli->log);
    CU_ASSERT(ctx_cli != NULL);

    ret = xqc_tls_ctx_register_alpn(ctx_cli, "transport", 9);
    CU_ASSERT(ret == XQC_OK);

    /* get tls config */
    xqc_connection_t *test_conn = test_engine_connect();
    xqc_tls_config_t tls_config = {0};
    tls_config.session_ticket = NULL;
    tls_config.session_ticket_len = 0;
    tls_config.cert_verify_flag = 0;
    tls_config.hostname = "127.0.0.1";
    tls_config.alpn = "transport";
    tls_config.no_crypto_flag = 0;

    /* encode local transport params */
    char tp_buf[XQC_MAX_TRANSPORT_PARAM_BUF_LEN] = {0};
    tls_config.trans_params = tp_buf;
    xqc_conn_encode_local_tp(test_conn, tls_config.trans_params,
                             XQC_MAX_TRANSPORT_PARAM_BUF_LEN, &tls_config.trans_params_len);

    /* create client tls */
    xqc_tls_test_buff_t *ttbuf_cli = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_cli = xqc_tls_create(ctx_cli, &tls_config, engine_cli->log, ttbuf_cli);

    /* client start handshake, generate ClientHello */
    xqc_cid_t odcid;
    xqc_generate_cid(engine_cli, NULL, &odcid, 0);

    ret = xqc_tls_init(tls_cli, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(!xqc_list_empty(&ttbuf_cli->initial_crypto_data_list)); /* ClientHello */

    /* create server tls */
    xqc_tls_test_buff_t *ttbuf_svr = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_svr = xqc_tls_create(ctx_svr, &tls_config, engine_svr->log, ttbuf_svr);

    /* server handshake, process ClientHello, genrate ServerHello & Handshake data */
    ret = xqc_tls_init(tls_svr, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);

    data_len = xqc_crypto_data_list_get_buf(&ttbuf_cli->initial_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_svr, XQC_ENC_LEV_INIT, data_buf, data_len);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(!xqc_list_empty(&ttbuf_svr->initial_crypto_data_list)); /* ServerHello */
    CU_ASSERT(!xqc_list_empty(&ttbuf_svr->hsk_crypto_data_list));     /* EE, CERT, CV, FIN */

    int svr_cnt = ttbuf_svr->crypto_data_cnt;
    size_t svr_total_len = ttbuf_svr->crypto_data_total_len;

    /* 
     * mock client sent 2 ClientHello, then server xqc_tls_process_crypto_data will return error,
     * and server crypto_data_list will not increase.
     */

    data_len = xqc_crypto_data_list_get_buf(&ttbuf_cli->initial_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_svr, XQC_ENC_LEV_INIT, data_buf, data_len);
    CU_ASSERT(ret != XQC_OK);
    CU_ASSERT(ttbuf_svr->crypto_data_cnt == svr_cnt);
    CU_ASSERT(ttbuf_svr->crypto_data_total_len == svr_total_len);

    xqc_destroy_tls_test_buffer(ttbuf_cli);
    xqc_destroy_tls_test_buffer(ttbuf_svr);
    xqc_tls_destroy(tls_cli);
    xqc_tls_destroy(tls_svr);
    xqc_tls_ctx_destroy(ctx_cli);
    xqc_tls_ctx_destroy(ctx_svr);
    xqc_engine_destroy(engine_cli);
    xqc_engine_destroy(engine_svr);

    free(data_buf);
}

void
xqc_test_tls_process_truncated_crypto_handshake()
{
    def_engine_ssl_config
    xqc_int_t ret;
    int cnt;

    uint8_t *data_buf = malloc(XQC_TEST_MAX_CRYPTO_DATA_BUF);
    size_t   data_len = 0;

    /* 1-RTT */

    /* create server engine and tls_ctx */
    xqc_engine_t *engine_svr = test_create_engine_server();
    xqc_tls_ctx_t *ctx_svr = xqc_tls_ctx_create(XQC_TLS_TYPE_SERVER, &engine_ssl_config,
                                                &tls_test_cbs, engine_svr->log);
    CU_ASSERT(ctx_svr != NULL);

    ret = xqc_tls_ctx_register_alpn(ctx_svr, "transport", 9);
    CU_ASSERT(ret == XQC_OK);

    /* create client engine and tls_ctx */
    xqc_engine_t *engine_cli = test_create_engine();
    xqc_tls_ctx_t *ctx_cli = xqc_tls_ctx_create(XQC_TLS_TYPE_CLIENT, &engine_ssl_config,
                                                &tls_test_cbs, engine_cli->log);
    CU_ASSERT(ctx_cli != NULL);

    ret = xqc_tls_ctx_register_alpn(ctx_cli, "transport", 9);
    CU_ASSERT(ret == XQC_OK);

    /* get tls config */
    xqc_connection_t *test_conn = test_engine_connect();
    xqc_tls_config_t tls_config = {0};
    tls_config.session_ticket = NULL;
    tls_config.session_ticket_len = 0;
    tls_config.cert_verify_flag = 0;
    tls_config.hostname = "127.0.0.1";
    tls_config.alpn = "transport";
    tls_config.no_crypto_flag = 0;

    /* encode local transport params */
    char tp_buf[XQC_MAX_TRANSPORT_PARAM_BUF_LEN] = {0};
    tls_config.trans_params = tp_buf;
    xqc_conn_encode_local_tp(test_conn, tls_config.trans_params,
                             XQC_MAX_TRANSPORT_PARAM_BUF_LEN, &tls_config.trans_params_len);

    /* create client tls */
    xqc_tls_test_buff_t *ttbuf_cli = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_cli = xqc_tls_create(ctx_cli, &tls_config, engine_cli->log, ttbuf_cli);

    /* client start handshake, generate ClientHello */
    xqc_cid_t odcid;
    xqc_generate_cid(engine_cli, NULL, &odcid, 0);

    ret = xqc_tls_init(tls_cli, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(!xqc_list_empty(&ttbuf_cli->initial_crypto_data_list)); /* ClientHello */

    /* create server tls */
    xqc_tls_test_buff_t *ttbuf_svr = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_svr = xqc_tls_create(ctx_svr, &tls_config, engine_svr->log, ttbuf_svr);

    /* server handshake */
    ret = xqc_tls_init(tls_svr, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);

    /* process ClientHello, genrate ServerHello & Handshake data */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_cli->initial_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    for (size_t i = 0; i < data_len; i++) {
        ret = xqc_tls_process_crypto_data(tls_svr, XQC_ENC_LEV_INIT, data_buf + i, 1);
        CU_ASSERT(ret == XQC_OK);
    }
    CU_ASSERT(!xqc_list_empty(&ttbuf_svr->initial_crypto_data_list)); /* ServerHello */
    CU_ASSERT(!xqc_list_empty(&ttbuf_svr->hsk_crypto_data_list));     /* EE, CERT, CV, FIN */

    /* client process handshake data from server */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_svr->initial_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    for (size_t i = 0; i < data_len; i++) {
        ret = xqc_tls_process_crypto_data(tls_cli, XQC_ENC_LEV_INIT, data_buf + i, 1);
        CU_ASSERT(ret == XQC_OK);
    }

    data_len = xqc_crypto_data_list_get_buf(&ttbuf_svr->hsk_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    for (size_t i = 0; i < data_len; i++) {
        ret = xqc_tls_process_crypto_data(tls_cli, XQC_ENC_LEV_HSK, data_buf + i, 1);
        CU_ASSERT(ret == XQC_OK);
    }
    CU_ASSERT(ttbuf_cli->handshake_completed == XQC_TRUE);
    CU_ASSERT(!xqc_list_empty(&ttbuf_cli->hsk_crypto_data_list)); /* FIN */

    /* server process handshake data from client, send new session ticket */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_cli->hsk_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    for (size_t i = 0; i < data_len; i++) {
        ret = xqc_tls_process_crypto_data(tls_svr, XQC_ENC_LEV_HSK, data_buf + i, 1);
        CU_ASSERT(ret == XQC_OK);
    }
    CU_ASSERT(ttbuf_svr->handshake_completed == XQC_TRUE);
    CU_ASSERT(!xqc_list_empty(&ttbuf_svr->application_crypto_data_list)); /* New Session Ticket */

    /* client process new session ticket data */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_svr->application_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_cli, XQC_ENC_LEV_1RTT, data_buf, data_len);
    for (size_t i = 0; i < data_len; i++) {
        ret = xqc_tls_process_crypto_data(tls_cli, XQC_ENC_LEV_1RTT, data_buf + i, 1);
        CU_ASSERT(ret == XQC_OK);
    }
    CU_ASSERT(ttbuf_cli->new_session_ticket != NULL);
    CU_ASSERT(ttbuf_cli->new_session_ticket_len > 0);


    /* 0-RTT and Resumption */
    tls_config.session_ticket = ttbuf_cli->new_session_ticket;
    tls_config.session_ticket_len = ttbuf_cli->new_session_ticket_len;

    /* create client tls */
    xqc_tls_test_buff_t *ttbuf_0rtt_cli = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_0rtt_cli = xqc_tls_create(ctx_cli, &tls_config, engine_cli->log, ttbuf_0rtt_cli);

    /* client start handshake, generate ClientHello */
    ret = xqc_tls_init(tls_0rtt_cli, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(!xqc_list_empty(&ttbuf_0rtt_cli->initial_crypto_data_list)); /* ClientHello */

    /* create server buffer */
    xqc_tls_test_buff_t *ttbuf_0rtt_svr = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_0rtt_svr = xqc_tls_create(ctx_svr, &tls_config, engine_svr->log, ttbuf_0rtt_svr);

    /* create server tls */
    ret = xqc_tls_init(tls_0rtt_svr, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);

    /* server process ClientHello, genrate ServerHello & Handshake data ClientHello */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_0rtt_cli->initial_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    for (size_t i = 0; i < data_len; i++) {
        ret = xqc_tls_process_crypto_data(tls_0rtt_svr, XQC_ENC_LEV_INIT, data_buf + i, 1);
        CU_ASSERT(ret == XQC_OK);
    }
    CU_ASSERT(!xqc_list_empty(&ttbuf_0rtt_svr->initial_crypto_data_list)); /* ServerHello */
    CU_ASSERT(!xqc_list_empty(&ttbuf_0rtt_svr->hsk_crypto_data_list));     /* EE, CERT, CV, FIN */

    /* client process handshake data from server */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_0rtt_svr->initial_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    for (size_t i = 0; i < data_len; i++) {
        ret = xqc_tls_process_crypto_data(tls_0rtt_cli, XQC_ENC_LEV_INIT, data_buf + i, 1);
        CU_ASSERT(ret == XQC_OK);
    }

    data_len = xqc_crypto_data_list_get_buf(&ttbuf_0rtt_svr->hsk_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    for (size_t i = 0; i < data_len; i++) {
        ret = xqc_tls_process_crypto_data(tls_0rtt_cli, XQC_ENC_LEV_HSK, data_buf + i, 1);
        CU_ASSERT(ret == XQC_OK);
    }
    CU_ASSERT(ttbuf_0rtt_cli->handshake_completed == XQC_TRUE);
    CU_ASSERT(!xqc_list_empty(&ttbuf_0rtt_cli->hsk_crypto_data_list)); /* FIN */

    /* server process handshake data from client */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_0rtt_cli->hsk_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    for (size_t i = 0; i < data_len; i++) {
        ret = xqc_tls_process_crypto_data(tls_0rtt_svr, XQC_ENC_LEV_HSK, data_buf + i, 1);
        CU_ASSERT(ret == XQC_OK);
    }
    CU_ASSERT(ttbuf_0rtt_svr->handshake_completed == XQC_TRUE);


    xqc_destroy_tls_test_buffer(ttbuf_cli);
    xqc_destroy_tls_test_buffer(ttbuf_svr);
    xqc_tls_destroy(tls_cli);
    xqc_tls_destroy(tls_svr);

    xqc_destroy_tls_test_buffer(ttbuf_0rtt_cli);
    xqc_destroy_tls_test_buffer(ttbuf_0rtt_svr);
    xqc_tls_destroy(tls_0rtt_cli);
    xqc_tls_destroy(tls_0rtt_svr);

    xqc_tls_ctx_destroy(ctx_cli);
    xqc_tls_ctx_destroy(ctx_svr);
    xqc_engine_destroy(engine_cli);
    xqc_engine_destroy(engine_svr);

    free(data_buf);
}


void
xqc_test_tls_failure()
{
    def_engine_ssl_config
    xqc_int_t ret;
    int cnt;

    uint8_t *data_buf = malloc(XQC_TEST_MAX_CRYPTO_DATA_BUF);
    size_t   data_len = 0;

    /* 1-RTT */

    /* create server engine and tls_ctx */
    xqc_engine_t *engine_svr = test_create_engine_server();
    xqc_tls_ctx_t *ctx_svr = xqc_tls_ctx_create(XQC_TLS_TYPE_SERVER, &engine_ssl_config,
                                                &tls_test_cbs, engine_svr->log);
    CU_ASSERT(ctx_svr != NULL);

    ret = xqc_tls_ctx_register_alpn(ctx_svr, "transport", 9);
    CU_ASSERT(ret == XQC_OK);

    /* create client engine and tls_ctx */
    xqc_engine_t *engine_cli = test_create_engine();
    xqc_tls_ctx_t *ctx_cli = xqc_tls_ctx_create(XQC_TLS_TYPE_CLIENT, &engine_ssl_config,
                                                &tls_test_cbs, engine_cli->log);
    CU_ASSERT(ctx_cli != NULL);

    ret = xqc_tls_ctx_register_alpn(ctx_cli, "transport", 9);
    CU_ASSERT(ret == XQC_OK);

    /* get tls config */
    xqc_connection_t *test_conn = test_engine_connect();
    xqc_tls_config_t tls_config = {0};
    tls_config.session_ticket = NULL;
    tls_config.session_ticket_len = 0;
    tls_config.cert_verify_flag = 0;
    tls_config.hostname = "127.0.0.1";
    tls_config.alpn = "transport";
    tls_config.no_crypto_flag = 0;

    /* encode local transport params */
    char tp_buf[XQC_MAX_TRANSPORT_PARAM_BUF_LEN] = {0};
    tls_config.trans_params = tp_buf;
    xqc_conn_encode_local_tp(test_conn, tls_config.trans_params,
                             XQC_MAX_TRANSPORT_PARAM_BUF_LEN, &tls_config.trans_params_len);

    /* create client tls */
    xqc_tls_test_buff_t *ttbuf_cli = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_cli = xqc_tls_create(ctx_cli, &tls_config, engine_cli->log, ttbuf_cli);

    /* client start handshake, generate ClientHello */
    xqc_cid_t odcid;
    xqc_generate_cid(engine_cli, NULL, &odcid, 0);

    ret = xqc_tls_init(tls_cli, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(!xqc_list_empty(&ttbuf_cli->initial_crypto_data_list)); /* ClientHello */

    /* create server tls */
    xqc_tls_test_buff_t *ttbuf_svr = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_svr = xqc_tls_create(ctx_svr, &tls_config, engine_svr->log, ttbuf_svr);

    /* server handshake, process ClientHello, genrate ServerHello & Handshake data */
    ret = xqc_tls_init(tls_svr, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);

    data_len = xqc_crypto_data_list_get_buf(&ttbuf_cli->initial_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_svr, XQC_ENC_LEV_INIT, data_buf, data_len);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(!xqc_list_empty(&ttbuf_svr->initial_crypto_data_list)); /* ServerHello */
    CU_ASSERT(!xqc_list_empty(&ttbuf_svr->hsk_crypto_data_list));     /* EE, CERT, CV, FIN */

    /* client process handshake data from server */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_svr->initial_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_cli, XQC_ENC_LEV_INIT, data_buf, data_len);
    CU_ASSERT(ret == XQC_OK);

    data_len = xqc_crypto_data_list_get_buf(&ttbuf_svr->hsk_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_cli, XQC_ENC_LEV_HSK, data_buf, data_len);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(ttbuf_cli->handshake_completed == XQC_TRUE);
    CU_ASSERT(!xqc_list_empty(&ttbuf_cli->hsk_crypto_data_list)); /* FIN */

    /* corrupt crypto data */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_cli->hsk_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    for (size_t i = 20; i < data_len; i++) {
        if (i % 3 == 0) {
            data_buf[i] = ~data_buf[i];
        }
    }

    /* process error crypto data */
    ret = xqc_tls_process_crypto_data(tls_svr, XQC_ENC_LEV_HSK, data_buf, data_len);
    CU_ASSERT(ret != XQC_OK);
    CU_ASSERT(ttbuf_svr->error_code != 0);

    xqc_destroy_tls_test_buffer(ttbuf_cli);
    xqc_destroy_tls_test_buffer(ttbuf_svr);
    xqc_tls_destroy(tls_cli);
    xqc_tls_destroy(tls_svr);

    xqc_tls_ctx_destroy(ctx_cli);
    xqc_tls_ctx_destroy(ctx_svr);
    xqc_engine_destroy(engine_cli);
    xqc_engine_destroy(engine_svr);

    free(data_buf);
}

void
xqc_test_tls()
{
    xqc_test_create_client_tls_ctx();
    xqc_test_create_server_tls_ctx();
    xqc_test_tls_ctx_register_alpn();

    xqc_test_tls_reset_initial();
    xqc_test_tls_generic();

    xqc_test_tls_multiple_crypto_data();
    xqc_test_tls_process_truncated_crypto_handshake();

    xqc_test_tls_failure();
}