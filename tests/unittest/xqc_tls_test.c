/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xqc_common_test.h"
#include "src/transport/xqc_conn.h"
#include "src/tls/xqc_tls_ctx.h"
#include "src/tls/xqc_tls.h"
#include "src/tls/xqc_ssl_cbs.h"

#define XQC_TEST_MAX_CRYPTO_DATA_BUF 16 * 1024

#define XQC_TEST_SESSION_TICKET_KEY "\xa8\x6d\x19\x70\x06\x08\x9b\x2d" \
"\xa7\x17\x50\xf7\x97\x78\xf7\xe8\x3c\x5a\xc4\x9d\x61\x34\xe3\xa1\xfa" \
"\x62\x7b\x66\xf0\x2f\x5b\xdc\x63\x12\x8d\x10\x9a\x57\x5c\xdd\x1b\xc3" \
"\x8f\x13\x93\x3c\x85"

typedef struct xqc_tls_test_buff_s {
    union {
        struct {
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
            uint64_t           transport_error_code;
        };
        xqc_connection_t conn;
    };
    int                  cert_cb_called;
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
    ttbuf->transport_error_code = 0;
    ttbuf->cert_cb_called = 0;

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

xqc_int_t
xqc_tt_cert_cb(const char *sni, void **chain, void **crt, void **key,
               void *user_data)
{
    xqc_tls_test_buff_t *ttbuf = (xqc_tls_test_buff_t *)user_data;

    if (sni == NULL) {
        return -XQC_TLS_INVALID_ARGUMENT;
    }

    ttbuf->cert_cb_called++;
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
xqc_tt_transport_error_cb(xqc_int_t transport_err, void *user_data)
{
    xqc_tls_test_buff_t *ttbuf = (xqc_tls_test_buff_t *)user_data;

    ttbuf->transport_error_code = transport_err;
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
    .transport_error_cb = xqc_tt_transport_error_cb,
    .hsk_completed_cb = xqc_tt_handshake_completed_cb,
};

#define def_engine_ssl_config_svr                            \
    xqc_engine_ssl_config_t engine_ssl_config_svr = {0};     \
    engine_ssl_config_svr.private_key_file = "./server.key"; \
    engine_ssl_config_svr.cert_file = "./server.crt";        \
    engine_ssl_config_svr.ciphers = XQC_TLS_CIPHERS;         \
    engine_ssl_config_svr.groups = XQC_TLS_GROUPS;           \
    engine_ssl_config_svr.session_ticket_key_len = 48;       \
    engine_ssl_config_svr.session_ticket_key_data = XQC_TEST_SESSION_TICKET_KEY;   

#define def_engine_ssl_config_cli                            \
    xqc_engine_ssl_config_t engine_ssl_config_cli = {0};     \
    engine_ssl_config_cli.ciphers = XQC_TLS_CIPHERS;         \
    engine_ssl_config_cli.groups = XQC_TLS_GROUPS;  
    
static xqc_log_t *test_log;
static xqc_tls_ctx_t *ctx_cli, *ctx_svr;

#define TEST_ALPN_1 "transport"
#define TEST_ALPN_2 "h3"

static xqc_int_t
xqc_test_tls_default_cert_handshake(xqc_bool_t with_sni,
                                    int *cert_cb_called)
{
    xqc_int_t              ret = -XQC_EFATAL;
    size_t                 data_len;
    uint8_t               *data_buf = NULL;
    xqc_log_t             *log = NULL;
    xqc_tls_ctx_t         *local_ctx_cli = NULL;
    xqc_tls_ctx_t         *local_ctx_svr = NULL;
    xqc_tls_t             *tls_cli = NULL;
    xqc_tls_t             *tls_svr = NULL;
    xqc_tls_test_buff_t   *ttbuf_cli = NULL;
    xqc_tls_test_buff_t   *ttbuf_svr = NULL;
    xqc_log_callbacks_t    log_cb = xqc_null_log_cb;
    xqc_tls_callbacks_t    cert_test_cbs = tls_test_cbs;
    xqc_tls_config_t       tls_config = {0};
    xqc_cid_t              odcid = {1};
    def_engine_ssl_config_cli;
    def_engine_ssl_config_svr;

    *cert_cb_called = 0;
    cert_test_cbs.cert_cb = xqc_tt_cert_cb;

    log = xqc_log_init(0, 0, 0, 0, 0, NULL, &log_cb, NULL);
    if (log == NULL) {
        goto end;
    }

    local_ctx_cli = xqc_tls_ctx_create(XQC_TLS_TYPE_CLIENT,
        &engine_ssl_config_cli, &cert_test_cbs, log);
    local_ctx_svr = xqc_tls_ctx_create(XQC_TLS_TYPE_SERVER,
        &engine_ssl_config_svr, &cert_test_cbs, log);
    if (local_ctx_cli == NULL || local_ctx_svr == NULL) {
        goto end;
    }

    ret = xqc_tls_ctx_register_alpn(local_ctx_svr, TEST_ALPN_1,
                                    sizeof(TEST_ALPN_1) - 1);
    if (ret != XQC_OK) {
        goto end;
    }

    tls_config.hostname = "test.xquic.com";
    tls_config.alpn = TEST_ALPN_1;
    tls_config.trans_params = "10086";
    tls_config.trans_params_len = 5;

    ttbuf_cli = xqc_create_tls_test_buffer();
    ttbuf_svr = xqc_create_tls_test_buffer();
    if (ttbuf_cli == NULL || ttbuf_svr == NULL) {
        ret = -XQC_EMALLOC;
        goto end;
    }

    tls_cli = xqc_tls_create(local_ctx_cli, &tls_config, log, ttbuf_cli);
    tls_svr = xqc_tls_create(local_ctx_svr, &tls_config, log, ttbuf_svr);
    if (tls_cli == NULL || tls_svr == NULL) {
        ret = -XQC_TLS_INTERNAL;
        goto end;
    }

    if (!with_sni
        && SSL_set_tlsext_host_name(xqc_tls_get_ssl(tls_cli), NULL)
           != XQC_SSL_SUCCESS)
    {
        ret = -XQC_TLS_INTERNAL;
        goto end;
    }

    ret = xqc_tls_init(tls_cli, XQC_VERSION_V1, &odcid);
    if (ret != XQC_OK
        || xqc_list_empty(&ttbuf_cli->initial_crypto_data_list))
    {
        ret = -XQC_TLS_INTERNAL;
        goto end;
    }

    ret = xqc_tls_init(tls_svr, XQC_VERSION_V1, &odcid);
    if (ret != XQC_OK) {
        goto end;
    }

    data_buf = xqc_malloc(XQC_TEST_MAX_CRYPTO_DATA_BUF);
    if (data_buf == NULL) {
        ret = -XQC_EMALLOC;
        goto end;
    }

    data_len = xqc_crypto_data_list_get_buf(
        &ttbuf_cli->initial_crypto_data_list, data_buf);
    if (data_len == 0 || data_len > XQC_TEST_MAX_CRYPTO_DATA_BUF) {
        ret = -XQC_TLS_INTERNAL;
        goto end;
    }

    ret = xqc_tls_process_crypto_data(tls_svr, XQC_ENC_LEV_INIT,
                                      data_buf, data_len);
    *cert_cb_called = ttbuf_svr->cert_cb_called;
    if (ret == XQC_OK
        && (xqc_list_empty(&ttbuf_svr->initial_crypto_data_list)
            || xqc_list_empty(&ttbuf_svr->hsk_crypto_data_list)))
    {
        ret = -XQC_TLS_INTERNAL;
    }

end:
    if (data_buf != NULL) {
        xqc_free(data_buf);
    }
    if (tls_cli != NULL) {
        xqc_tls_destroy(tls_cli);
    }
    if (tls_svr != NULL) {
        xqc_tls_destroy(tls_svr);
    }
    if (ttbuf_cli != NULL) {
        xqc_destroy_tls_test_buffer(ttbuf_cli);
    }
    if (ttbuf_svr != NULL) {
        xqc_destroy_tls_test_buffer(ttbuf_svr);
    }
    if (local_ctx_cli != NULL) {
        xqc_tls_ctx_destroy(local_ctx_cli);
    }
    if (local_ctx_svr != NULL) {
        xqc_tls_ctx_destroy(local_ctx_svr);
    }
    if (log != NULL) {
        xqc_free(log);
    }

    return ret;
}

void
xqc_test_tls_default_cert_with_sni(void)
{
    int cert_cb_called;

    CU_ASSERT_EQUAL(xqc_test_tls_default_cert_handshake(
        XQC_TRUE, &cert_cb_called), XQC_OK);
    CU_ASSERT_EQUAL(cert_cb_called, 1);
}

void
xqc_test_tls_default_cert_without_sni(void)
{
    int cert_cb_called;

    CU_ASSERT_EQUAL(xqc_test_tls_default_cert_handshake(
        XQC_FALSE, &cert_cb_called), XQC_OK);
    CU_ASSERT_EQUAL(cert_cb_called, 0);
}

void
xqc_test_create_client_tls_ctx()
{
    xqc_engine_ssl_config_t engine_ssl_config;
    memset(&engine_ssl_config, 0, sizeof(engine_ssl_config));

    /* not set ciphers and groups */
    xqc_tls_ctx_t *ctx;
    SSL_CTX *ssl_ctx;
    xqc_tls_type_t tls_type;
    xqc_engine_ssl_config_t *cfg = NULL;

    ctx = xqc_tls_ctx_create(XQC_TLS_TYPE_CLIENT, &engine_ssl_config,
            &tls_test_cbs, test_log);
    CU_ASSERT(ctx != NULL);

    ssl_ctx = xqc_tls_ctx_get_ssl_ctx(ctx);
    CU_ASSERT(ssl_ctx != NULL);

    tls_type = xqc_tls_ctx_get_type(ctx);
    CU_ASSERT(tls_type == XQC_TLS_TYPE_CLIENT);

    xqc_tls_ctx_get_cfg(ctx, &cfg);
    CU_ASSERT(0 == strcmp(cfg->ciphers, XQC_TLS_CIPHERS));
    CU_ASSERT(0 == strcmp(cfg->groups, XQC_TLS_GROUPS));

    xqc_tls_ctx_destroy(ctx);

    /* set ciphers and groups */
    def_engine_ssl_config_cli;
    ctx = xqc_tls_ctx_create(XQC_TLS_TYPE_CLIENT, &engine_ssl_config_cli, &tls_test_cbs, test_log);
    CU_ASSERT(ctx != NULL);

    ssl_ctx = xqc_tls_ctx_get_ssl_ctx(ctx);
    CU_ASSERT(ssl_ctx != NULL);

    tls_type = xqc_tls_ctx_get_type(ctx);
    CU_ASSERT(tls_type == XQC_TLS_TYPE_CLIENT);

    cfg = NULL;
    xqc_tls_ctx_get_cfg(ctx, &cfg);
    CU_ASSERT(0 == strcmp(cfg->ciphers, XQC_TLS_CIPHERS));
    CU_ASSERT(0 == strcmp(cfg->groups, XQC_TLS_GROUPS));

    ctx_cli = ctx;
}

void
xqc_test_create_server_tls_ctx()
{
    xqc_engine_ssl_config_t engine_ssl_config;
    memset(&engine_ssl_config, 0, sizeof(engine_ssl_config));

    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;
    /* no private key file */
    xqc_tls_ctx_t *ctx;
    SSL_CTX *ssl_ctx;
    xqc_tls_type_t tls_type;
    xqc_engine_ssl_config_t *cfg = NULL;
    xqc_ssl_session_ticket_key_t *key = NULL;

    ctx = xqc_tls_ctx_create(XQC_TLS_TYPE_SERVER, &engine_ssl_config,
            &tls_test_cbs, test_log);
    CU_ASSERT(ctx == NULL);

    /* no cert file */
    engine_ssl_config.private_key_file = "./server.key";
    ctx = xqc_tls_ctx_create(XQC_TLS_TYPE_SERVER, &engine_ssl_config, &tls_test_cbs, test_log);
    CU_ASSERT(ctx == NULL);

    /* no session ticket key data */
    engine_ssl_config.cert_file = "./server.crt";
    engine_ssl_config.session_ticket_key_data = NULL;
    engine_ssl_config.session_ticket_key_len = 0;
    ctx = xqc_tls_ctx_create(XQC_TLS_TYPE_SERVER, &engine_ssl_config, &tls_test_cbs, test_log);
    CU_ASSERT(ctx != NULL);

    ssl_ctx = xqc_tls_ctx_get_ssl_ctx(ctx);
    CU_ASSERT(ssl_ctx != NULL);

    tls_type = xqc_tls_ctx_get_type(ctx);
    CU_ASSERT(tls_type == XQC_TLS_TYPE_SERVER);

    
    xqc_tls_ctx_get_cfg(ctx, &cfg);
    CU_ASSERT(0 == strcmp(cfg->ciphers, XQC_TLS_CIPHERS));
    CU_ASSERT(0 == strcmp(cfg->groups, XQC_TLS_GROUPS));
    CU_ASSERT(0 == strcmp(cfg->private_key_file, "./server.key"));
    CU_ASSERT(0 == strcmp(cfg->cert_file, "./server.crt"));

    
    xqc_tls_ctx_get_session_ticket_key(ctx, &key);
    CU_ASSERT(key->size == 0);

    xqc_tls_ctx_destroy(ctx);

    /* init session ticket key error */
    engine_ssl_config.session_ticket_key_data = "test_stk";
    engine_ssl_config.session_ticket_key_len = 8;

    ctx = xqc_tls_ctx_create(XQC_TLS_TYPE_SERVER, &engine_ssl_config, &tls_test_cbs, test_log);
    CU_ASSERT(ctx == NULL);

    /* final one */
    def_engine_ssl_config_svr;
    ctx = xqc_tls_ctx_create(XQC_TLS_TYPE_SERVER, &engine_ssl_config_svr,
            &tls_test_cbs, test_log);
    CU_ASSERT(ctx != NULL);
    
    ctx_svr = ctx;
}

void
xqc_test_tls_ctx_register_alpn()
{
    xqc_int_t ret;
    uint8_t *alpn_list = NULL;
    size_t alpn_list_len = 0;

    /* register alpn in tls context */
    ret = xqc_tls_ctx_register_alpn(ctx_cli, TEST_ALPN_1, sizeof(TEST_ALPN_1) - 1);
    CU_ASSERT(ret == XQC_OK);

    ret = xqc_tls_ctx_register_alpn(ctx_cli, TEST_ALPN_2, sizeof(TEST_ALPN_2) - 1);
    CU_ASSERT(ret == XQC_OK);

    xqc_tls_ctx_get_alpn_list(ctx_cli, &alpn_list, &alpn_list_len);
    CU_ASSERT(alpn_list_len == sizeof(TEST_ALPN_1) + sizeof(TEST_ALPN_2));

    /* unregister alpn in tls context */
    ret = xqc_tls_ctx_unregister_alpn(ctx_cli, TEST_ALPN_2, sizeof(TEST_ALPN_2) - 1);
    CU_ASSERT(ret == XQC_OK);

    xqc_tls_ctx_get_alpn_list(ctx_cli, &alpn_list, &alpn_list_len);
    CU_ASSERT(alpn_list_len == sizeof(TEST_ALPN_1));

    /* register alpn in tls context */
    ret = xqc_tls_ctx_register_alpn(ctx_svr, TEST_ALPN_1, sizeof(TEST_ALPN_1) - 1);
    CU_ASSERT(ret == XQC_OK);

    ret = xqc_tls_ctx_register_alpn(ctx_svr, TEST_ALPN_2, sizeof(TEST_ALPN_2) - 1);
    CU_ASSERT(ret == XQC_OK);

    xqc_tls_ctx_get_alpn_list(ctx_svr, &alpn_list, &alpn_list_len);
    CU_ASSERT(alpn_list_len == sizeof(TEST_ALPN_1) + sizeof(TEST_ALPN_2));

    /* unregister alpn in tls context */
    ret = xqc_tls_ctx_unregister_alpn(ctx_svr, TEST_ALPN_2, sizeof(TEST_ALPN_2) - 1);
    CU_ASSERT(ret == XQC_OK);

    xqc_tls_ctx_get_alpn_list(ctx_svr, &alpn_list, &alpn_list_len);
    CU_ASSERT(alpn_list_len == sizeof(TEST_ALPN_1));
}

void
xqc_test_tls_reset_initial()
{
    /* get tls config */
    xqc_tls_config_t tls_config = {0};
    tls_config.session_ticket = NULL;
    tls_config.session_ticket_len = 0;
    tls_config.cert_verify_flag = 0;
    tls_config.hostname = "test.xquic.com";
    tls_config.alpn = "transport";
    tls_config.no_crypto_flag = 0;
    tls_config.trans_params = "10086";
    tls_config.trans_params_len = 5;

    /* create client tls */
    xqc_tls_test_buff_t *ttbuf_cli = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_cli = xqc_tls_create(ctx_cli, &tls_config, test_log, ttbuf_cli);

    /* client start handshake, generate ClientHello */
    xqc_cid_t odcid = {1};

    xqc_int_t ret = xqc_tls_init(tls_cli, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);

    /* reset initial keys */
    ret = xqc_tls_reset_initial(tls_cli, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);

    ret = xqc_tls_is_key_ready(tls_cli, XQC_ENC_LEV_INIT, XQC_KEY_TYPE_RX_READ);
    CU_ASSERT(ret == XQC_TRUE);
    ret = xqc_tls_is_key_ready(tls_cli, XQC_ENC_LEV_INIT, XQC_KEY_TYPE_TX_WRITE);
    CU_ASSERT(ret == XQC_TRUE);

    xqc_destroy_tls_test_buffer(ttbuf_cli);
    xqc_tls_destroy(tls_cli);
}        

void
xqc_test_tls_generic()
{
    xqc_int_t ret;
    int cnt;
    size_t early_data_offset;

    uint8_t *data_buf = malloc(XQC_TEST_MAX_CRYPTO_DATA_BUF);
    size_t   data_len = 0;

    /* get tls config */
    xqc_tls_config_t tls_config = {0};
    tls_config.session_ticket = NULL;
    tls_config.session_ticket_len = 0;
    tls_config.cert_verify_flag = 0;
    tls_config.hostname = "test.xquic.com";
    tls_config.alpn = "transport";
    tls_config.no_crypto_flag = 0;
    tls_config.trans_params = "10086";
    tls_config.trans_params_len = 5;
    tls_config.reset_stream_at = 1;
    tls_config.max_udp_payload_size = XQC_DEFAULT_MAX_UDP_PAYLOAD_SIZE;

    /* create client tls */
    xqc_tls_test_buff_t *ttbuf_cli = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_cli = xqc_tls_create(ctx_cli, &tls_config, test_log, ttbuf_cli);

    /* client start handshake, generate ClientHello */
    xqc_cid_t odcid = {1};

    ret = xqc_tls_init(tls_cli, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(!xqc_list_empty(&ttbuf_cli->initial_crypto_data_list)); /* ClientHello */

    /* create server tls */
    xqc_tls_test_buff_t *ttbuf_svr = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_svr = xqc_tls_create(ctx_svr, &tls_config, test_log, ttbuf_svr);

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
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(ttbuf_cli->new_session_ticket != NULL);
    CU_ASSERT(ttbuf_cli->new_session_ticket_len > 0);
    CU_ASSERT(ttbuf_cli->transport_error_code == 0);

    /* RFC 9001 Section 4.6.1 requires this sentinel for QUIC 0-RTT. */
    for (early_data_offset = 0; early_data_offset + 8 <= data_len;
         early_data_offset++)
    {
        if (data_buf[early_data_offset] == 0
            && data_buf[early_data_offset + 1] == TLSEXT_TYPE_early_data
            && data_buf[early_data_offset + 2] == 0
            && data_buf[early_data_offset + 3] == 4
            && memcmp(data_buf + early_data_offset + 4,
                      "\xff\xff\xff\xff", 4) == 0)
        {
            break;
        }
    }
    CU_ASSERT(early_data_offset + 8 <= data_len);
    data_buf[early_data_offset + 7] = 0;
    ret = xqc_tls_process_crypto_data(tls_cli, XQC_ENC_LEV_1RTT,
                                      data_buf, data_len);
    CU_ASSERT(ret != XQC_OK);
    CU_ASSERT(ttbuf_cli->transport_error_code == TRA_PROTOCOL_VIOLATION);
    CU_ASSERT(ttbuf_cli->error_code == 0);

    /* 0-RTT */
    tls_config.session_ticket = ttbuf_cli->new_session_ticket;
    tls_config.session_ticket_len = ttbuf_cli->new_session_ticket_len;

    /* create client tls */
    xqc_tls_test_buff_t *ttbuf_0rtt_cli = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_0rtt_cli = xqc_tls_create(ctx_cli, &tls_config, test_log, ttbuf_0rtt_cli);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ttbuf_0rtt_cli);
    CU_ASSERT_PTR_NOT_NULL_FATAL(tls_0rtt_cli);

    /* client start handshake, generate ClientHello */
    ret = xqc_tls_init(tls_0rtt_cli, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(!xqc_list_empty(&ttbuf_0rtt_cli->initial_crypto_data_list)); /* ClientHello */

    /* create server tls */
    xqc_tls_test_buff_t *ttbuf_0rtt_svr = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_0rtt_svr = xqc_tls_create(ctx_svr, &tls_config, test_log, ttbuf_0rtt_svr);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ttbuf_0rtt_svr);
    CU_ASSERT_PTR_NOT_NULL_FATAL(tls_0rtt_svr);

    /* server handshake, process ClientHello, genrate ServerHello & Handshake data */
    ret = xqc_tls_init(tls_0rtt_svr, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);

    data_len = xqc_crypto_data_list_get_buf(&ttbuf_0rtt_cli->initial_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_0rtt_svr, XQC_ENC_LEV_INIT, data_buf, data_len);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(xqc_tls_is_early_data_accepted(tls_0rtt_svr)
              == XQC_TLS_EARLY_DATA_ACCEPT);
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

    /* A server capability downgrade rejects 0-RTT from the old ticket. */
    tls_config.reset_stream_at = 0;
    xqc_tls_test_buff_t *ttbuf_reject_cli = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_reject_cli = xqc_tls_create(ctx_cli, &tls_config,
                                               test_log,
                                               ttbuf_reject_cli);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ttbuf_reject_cli);
    CU_ASSERT_PTR_NOT_NULL_FATAL(tls_reject_cli);
    ret = xqc_tls_init(tls_reject_cli, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);

    xqc_tls_test_buff_t *ttbuf_reject_svr = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_reject_svr = xqc_tls_create(ctx_svr, &tls_config,
                                               test_log,
                                               ttbuf_reject_svr);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ttbuf_reject_svr);
    CU_ASSERT_PTR_NOT_NULL_FATAL(tls_reject_svr);
    ret = xqc_tls_init(tls_reject_svr, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);
    data_len = xqc_crypto_data_list_get_buf(
        &ttbuf_reject_cli->initial_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_reject_svr,
                                      XQC_ENC_LEV_INIT,
                                      data_buf, data_len);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(xqc_tls_is_early_data_accepted(tls_reject_svr)
              == XQC_TLS_EARLY_DATA_REJECT);

    xqc_destroy_tls_test_buffer(ttbuf_cli);
    xqc_destroy_tls_test_buffer(ttbuf_svr);
    xqc_destroy_tls_test_buffer(ttbuf_0rtt_cli);
    xqc_destroy_tls_test_buffer(ttbuf_0rtt_svr);
    xqc_destroy_tls_test_buffer(ttbuf_reject_cli);
    xqc_destroy_tls_test_buffer(ttbuf_reject_svr);

    xqc_tls_destroy(tls_cli);
    xqc_tls_destroy(tls_svr);
    xqc_tls_destroy(tls_0rtt_cli);
    xqc_tls_destroy(tls_0rtt_svr);
    xqc_tls_destroy(tls_reject_cli);
    xqc_tls_destroy(tls_reject_svr);

    free(data_buf);
}

void
xqc_test_tls_multiple_crypto_data()
{
    xqc_int_t ret;
    int cnt;

    uint8_t *data_buf = malloc(XQC_TEST_MAX_CRYPTO_DATA_BUF);
    size_t  data_len = 0;

    /* get tls config */
    xqc_tls_config_t tls_config = {0};
    tls_config.session_ticket = NULL;
    tls_config.session_ticket_len = 0;
    tls_config.cert_verify_flag = 0;
    tls_config.hostname = "test.xquic.com";
    tls_config.alpn = "transport";
    tls_config.no_crypto_flag = 0;
    tls_config.trans_params = "test";
    tls_config.trans_params_len = 4;

    /* create client tls */
    xqc_tls_test_buff_t *ttbuf_cli = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_cli = xqc_tls_create(ctx_cli, &tls_config, test_log, ttbuf_cli);

    /* client start handshake, generate ClientHello */
    xqc_cid_t odcid = {1};

    ret = xqc_tls_init(tls_cli, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(!xqc_list_empty(&ttbuf_cli->initial_crypto_data_list)); /* ClientHello */

    /* create server tls */
    xqc_tls_test_buff_t *ttbuf_svr = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_svr = xqc_tls_create(ctx_svr, &tls_config, test_log, ttbuf_svr);

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

    free(data_buf);
}

void
xqc_test_tls_process_truncated_crypto_handshake()
{
    xqc_int_t ret;
    int cnt;

    uint8_t *data_buf = malloc(XQC_TEST_MAX_CRYPTO_DATA_BUF);
    size_t   data_len = 0;

    /* get tls config */
    xqc_tls_config_t tls_config = {0};
    tls_config.session_ticket = NULL;
    tls_config.session_ticket_len = 0;
    tls_config.cert_verify_flag = 0;
    tls_config.hostname = "test.xquic.com";
    tls_config.alpn = "transport";
    tls_config.no_crypto_flag = 0;
    tls_config.trans_params = "test";
    tls_config.trans_params_len = 4;

    /* create client tls */
    xqc_tls_test_buff_t *ttbuf_cli = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_cli = xqc_tls_create(ctx_cli, &tls_config, test_log, ttbuf_cli);

    /* client start handshake, generate ClientHello */
    xqc_cid_t odcid = {1};

    ret = xqc_tls_init(tls_cli, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(!xqc_list_empty(&ttbuf_cli->initial_crypto_data_list)); /* ClientHello */

    /* create server tls */
    xqc_tls_test_buff_t *ttbuf_svr = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_svr = xqc_tls_create(ctx_svr, &tls_config, test_log, ttbuf_svr);

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
    xqc_tls_t *tls_0rtt_cli = xqc_tls_create(ctx_cli, &tls_config, test_log, ttbuf_0rtt_cli);

    /* client start handshake, generate ClientHello */
    ret = xqc_tls_init(tls_0rtt_cli, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(!xqc_list_empty(&ttbuf_0rtt_cli->initial_crypto_data_list)); /* ClientHello */

    /* create server buffer */
    xqc_tls_test_buff_t *ttbuf_0rtt_svr = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_0rtt_svr = xqc_tls_create(ctx_svr, &tls_config, test_log, ttbuf_0rtt_svr);

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
    xqc_destroy_tls_test_buffer(ttbuf_0rtt_cli);
    xqc_destroy_tls_test_buffer(ttbuf_0rtt_svr);

    xqc_tls_destroy(tls_cli);
    xqc_tls_destroy(tls_svr);
    xqc_tls_destroy(tls_0rtt_cli);
    xqc_tls_destroy(tls_0rtt_svr);

    free(data_buf);
}


void
xqc_test_tls_failure()
{
    xqc_int_t ret;
    int cnt;

    uint8_t *data_buf = malloc(XQC_TEST_MAX_CRYPTO_DATA_BUF);
    size_t   data_len = 0;

    /* 1-RTT */
    /* get tls config */
    xqc_tls_config_t tls_config = {0};
    tls_config.session_ticket = NULL;
    tls_config.session_ticket_len = 0;
    tls_config.cert_verify_flag = 0;
    tls_config.hostname = "test.xquic.com";
    tls_config.alpn = "transport";
    tls_config.no_crypto_flag = 0;
    tls_config.trans_params = "test";
    tls_config.trans_params_len = 4;

    /* create client tls */
    xqc_tls_test_buff_t *ttbuf_cli = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_cli = xqc_tls_create(ctx_cli, &tls_config, test_log, ttbuf_cli);

    /* client start handshake, generate ClientHello */
    xqc_cid_t odcid = {1};

    ret = xqc_tls_init(tls_cli, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(!xqc_list_empty(&ttbuf_cli->initial_crypto_data_list)); /* ClientHello */

    /* create server tls */
    xqc_tls_test_buff_t *ttbuf_svr = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_svr = xqc_tls_create(ctx_svr, &tls_config, test_log, ttbuf_svr);

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

    free(data_buf);
}

void xqc_test_destroy_tls_ctx()
{
    xqc_tls_ctx_destroy(ctx_cli);
    xqc_tls_ctx_destroy(ctx_svr);
}

#ifndef OPENSSL_IS_BORINGSSL
static int
xqc_test_invalid_reset_ticket_cb(SSL *ssl, void *arg)
{
    uint8_t data[9] = {2, 0};
    int binding = *(int *)arg;
    size_t len = binding >= 4 ? sizeof(data) : binding - 1;
    if (binding == 5) {
        data[0] = 0;
        data[7] = 0x04;
        data[8] = 0xaf;

    } else if (binding == 6) {
        data[0] = 0;
        data[1] = 0x40;
    }

    /* Missing, legacy, truncated, or invalid authenticated TP binding. */
    return SSL_SESSION_set1_ticket_appdata(SSL_get_session(ssl), data, len);
}
#endif


static xqc_tls_test_buff_t *
xqc_test_ticket_handshake(xqc_tls_ctx_t *server_ctx, int reset,
    xqc_tls_test_buff_t *saved, int reused, int early, int ticket_binding,
    uint64_t max_udp_payload_size, uint64_t updated_max)
{
    xqc_tls_config_t cfg = {0};
    xqc_cid_t odcid = {1};
    uint8_t data[XQC_TEST_MAX_CRYPTO_DATA_BUF];
    size_t len;
    xqc_tls_test_buff_t *client = xqc_create_tls_test_buffer();
    xqc_tls_test_buff_t *server = xqc_create_tls_test_buffer();

    cfg.hostname = "test.xquic.com";
    cfg.alpn = "transport";
    cfg.trans_params = (uint8_t *)(reset ? "new parameters" : "old parameters");
    cfg.trans_params_len = strlen((char *)cfg.trans_params);
    cfg.reset_stream_at = reset;
    cfg.max_udp_payload_size = max_udp_payload_size;
    if (saved != NULL) {
        cfg.session_ticket = saved->new_session_ticket;
        cfg.session_ticket_len = saved->new_session_ticket_len;
    }

    xqc_tls_t *cli = xqc_tls_create(ctx_cli, &cfg, test_log, client);
    xqc_tls_t *svr = xqc_tls_create(server_ctx, &cfg, test_log, server);
    CU_ASSERT_PTR_NOT_NULL(cli);
    CU_ASSERT_PTR_NOT_NULL(svr);
    if (cli == NULL || svr == NULL) {
        goto end;
    }
    if (updated_max != 0) {
        CU_ASSERT_EQUAL(xqc_tls_update_tp(svr, cfg.trans_params,
                                          cfg.trans_params_len), XQC_OK);
        CU_ASSERT_EQUAL(xqc_tls_update_early_data_tp(svr, updated_max),
                        XQC_OK);
    }
    if (ticket_binding) {
#ifdef OPENSSL_IS_BORINGSSL
        CU_ASSERT(SSL_set_quic_early_data_context(xqc_tls_get_ssl(svr),
                    (const uint8_t *)XQC_EARLY_DATA_CONTEXT,
                    XQC_EARLY_DATA_CONTEXT_LEN) == 1);
#else
        CU_ASSERT(SSL_CTX_set_session_ticket_cb(
            xqc_tls_ctx_get_ssl_ctx(server_ctx),
            xqc_test_invalid_reset_ticket_cb, xqc_ssl_tp_ticket_decrypt_cb,
            &ticket_binding) == 1);
#endif
    }
    CU_ASSERT_EQUAL(xqc_tls_init(cli, XQC_VERSION_V1, &odcid), XQC_OK);
    CU_ASSERT_EQUAL(xqc_tls_init(svr, XQC_VERSION_V1, &odcid), XQC_OK);

    len = xqc_crypto_data_list_get_buf(&client->initial_crypto_data_list, data);
    CU_ASSERT(len > 0);
    CU_ASSERT_EQUAL(xqc_tls_process_crypto_data(svr, XQC_ENC_LEV_INIT,
                                               data, len), XQC_OK);
    len = xqc_crypto_data_list_get_buf(&server->initial_crypto_data_list, data);
    CU_ASSERT(len > 0);
    CU_ASSERT_EQUAL(xqc_tls_process_crypto_data(cli, XQC_ENC_LEV_INIT,
                                               data, len), XQC_OK);
    len = xqc_crypto_data_list_get_buf(&server->hsk_crypto_data_list, data);
    CU_ASSERT(len > 0);
    CU_ASSERT_EQUAL(xqc_tls_process_crypto_data(cli, XQC_ENC_LEV_HSK,
                                               data, len), XQC_OK);
    len = xqc_crypto_data_list_get_buf(&client->hsk_crypto_data_list, data);
    CU_ASSERT(len > 0);
    CU_ASSERT_EQUAL(xqc_tls_process_crypto_data(svr, XQC_ENC_LEV_HSK,
                                               data, len), XQC_OK);
    CU_ASSERT(client->handshake_completed && server->handshake_completed);
    CU_ASSERT_EQUAL(SSL_session_reused(xqc_tls_get_ssl(cli)), reused);
    CU_ASSERT_EQUAL(SSL_session_reused(xqc_tls_get_ssl(svr)), reused);
    if (saved != NULL) {
        CU_ASSERT_EQUAL(xqc_tls_is_early_data_accepted(cli), early);
        CU_ASSERT_EQUAL(xqc_tls_is_early_data_accepted(svr), early);
    }

    len = xqc_crypto_data_list_get_buf(&server->application_crypto_data_list,
                                      data);
    CU_ASSERT(len > 0);
    CU_ASSERT_EQUAL(xqc_tls_process_crypto_data(cli, XQC_ENC_LEV_1RTT,
                                               data, len), XQC_OK);
    CU_ASSERT_PTR_NOT_NULL(client->new_session_ticket);
    CU_ASSERT(client->new_session_ticket_len > 0);

end:
#ifndef OPENSSL_IS_BORINGSSL
    CU_ASSERT(SSL_CTX_set_session_ticket_cb(xqc_tls_ctx_get_ssl_ctx(server_ctx),
        xqc_ssl_tp_ticket_generate_cb, xqc_ssl_tp_ticket_decrypt_cb,
        NULL) == 1);
#endif
    xqc_tls_destroy(cli);
    xqc_tls_destroy(svr);
    xqc_destroy_tls_test_buffer(server);
    return client;
}


static xqc_tls_test_buff_t *
xqc_test_reset_ticket_handshake(xqc_tls_ctx_t *server_ctx, int reset,
    xqc_tls_test_buff_t *saved, int reused, int early, int ticket_binding)
{
    return xqc_test_ticket_handshake(server_ctx, reset, saved, reused, early,
        ticket_binding, XQC_DEFAULT_MAX_UDP_PAYLOAD_SIZE, 0);
}


static void
xqc_test_reset_ticket_policy(void)
{
    char key[80];
    const size_t key_sizes[] = {0, 48, 80};
    memset(key, 0x37, sizeof(key));

    for (size_t k = 0; k < sizeof(key_sizes) / sizeof(key_sizes[0]); k++) {
        def_engine_ssl_config_svr;
        engine_ssl_config_svr.session_ticket_key_len = key_sizes[k];
        engine_ssl_config_svr.session_ticket_key_data = key_sizes[k] ? key : NULL;
        xqc_tls_ctx_t *ctx = xqc_tls_ctx_create(XQC_TLS_TYPE_SERVER,
            &engine_ssl_config_svr, &tls_test_cbs, test_log);
        CU_ASSERT_PTR_NOT_NULL_FATAL(ctx);
        CU_ASSERT_EQUAL(xqc_tls_ctx_register_alpn(ctx, "transport", 9), XQC_OK);

        /* Reject either reset mismatch and retain PSK reuse. */
        for (int saved = 0; saved <= 1; saved++) {
            for (int current = 0; current <= 1; current++) {
                int early = saved != current ? XQC_TLS_EARLY_DATA_REJECT
                                             : XQC_TLS_EARLY_DATA_ACCEPT;
                xqc_tls_test_buff_t *first = xqc_test_reset_ticket_handshake(
                    ctx, saved, NULL, 0, 0, 0);
                xqc_tls_test_buff_t *second = xqc_test_reset_ticket_handshake(
                    ctx, current, first, 1, early, 0);
                xqc_tls_test_buff_t *third = xqc_test_reset_ticket_handshake(
                    ctx, current, second, 1, XQC_TLS_EARLY_DATA_ACCEPT, 0);
                xqc_destroy_tls_test_buffer(first);
                xqc_destroy_tls_test_buffer(second);
                xqc_destroy_tls_test_buffer(third);
            }
        }

        int invalid_bindings = 1;
#ifndef OPENSSL_IS_BORINGSSL
        invalid_bindings = 6;
#endif
        for (int binding = 1; binding <= invalid_bindings; binding++) {
            /* Invalid bindings reject early data but permit renewed tickets. */
            xqc_tls_test_buff_t *legacy = xqc_test_reset_ticket_handshake(
                ctx, 0, NULL, 0, 0, binding);
            for (int current = 0; current <= 1; current++) {
                xqc_tls_test_buff_t *resumed = xqc_test_reset_ticket_handshake(
                    ctx, current, legacy, 1, XQC_TLS_EARLY_DATA_REJECT, 0);
                xqc_tls_test_buff_t *fresh = xqc_test_reset_ticket_handshake(
                    ctx, current, resumed, 1, XQC_TLS_EARLY_DATA_ACCEPT, 0);
                xqc_destroy_tls_test_buffer(fresh);
                xqc_destroy_tls_test_buffer(resumed);
            }
            xqc_destroy_tls_test_buffer(legacy);
        }
        xqc_tls_ctx_destroy(ctx);
    }
}


static void
xqc_test_max_udp_payload_ticket_policy(void)
{
    def_engine_ssl_config_svr;
    xqc_tls_ctx_t *ctx = xqc_tls_ctx_create(XQC_TLS_TYPE_SERVER,
        &engine_ssl_config_svr, &tls_test_cbs, test_log);
    CU_ASSERT_PTR_NOT_NULL_FATAL(ctx);
    CU_ASSERT_EQUAL(xqc_tls_ctx_register_alpn(ctx, "transport", 9), XQC_OK);

    const uint64_t limits[][2] = {
        {1400, 1400},
        {1400, XQC_PACKET_OUT_SIZE},
        {XQC_PACKET_OUT_SIZE, 1400},
    };
    for (size_t i = 0; i < sizeof(limits) / sizeof(limits[0]); i++) {
        int early = XQC_TLS_EARLY_DATA_ACCEPT;
        if (limits[i][1] < limits[i][0]) {
            early = XQC_TLS_EARLY_DATA_REJECT;
#ifdef OPENSSL_IS_BORINGSSL
        } else if (limits[i][1] > limits[i][0]) {
            /* Native contexts support equality, not an ordering relation. */
            early = XQC_TLS_EARLY_DATA_REJECT;
#endif
        }

        xqc_tls_test_buff_t *first = xqc_test_ticket_handshake(ctx, 0, NULL,
            0, 0, 0, limits[i][0], 0);
        xqc_tls_test_buff_t *second = xqc_test_ticket_handshake(ctx, 0, first,
            1, early, 0, limits[i][1], 0);
        xqc_tls_test_buff_t *third = xqc_test_ticket_handshake(ctx, 0, second,
            1, XQC_TLS_EARLY_DATA_ACCEPT, 0, limits[i][1], 0);
        xqc_destroy_tls_test_buffer(first);
        xqc_destroy_tls_test_buffer(second);
        xqc_destroy_tls_test_buffer(third);
    }

    /* A late local-TP update must refresh the value used for 0-RTT. */
    int early = XQC_TLS_EARLY_DATA_ACCEPT;
#ifdef OPENSSL_IS_BORINGSSL
    early = XQC_TLS_EARLY_DATA_REJECT;
#endif
    xqc_tls_test_buff_t *first = xqc_test_ticket_handshake(ctx, 0, NULL, 0,
        0, 0, XQC_PACKET_OUT_SIZE, 0);
    xqc_tls_test_buff_t *second = xqc_test_ticket_handshake(ctx, 0, first, 1,
        early, 0, XQC_PACKET_OUT_SIZE, 1400);
    xqc_tls_test_buff_t *third = xqc_test_ticket_handshake(ctx, 0, second, 1,
        XQC_TLS_EARLY_DATA_ACCEPT, 0, 1400, 0);
    xqc_destroy_tls_test_buffer(first);
    xqc_destroy_tls_test_buffer(second);
    xqc_destroy_tls_test_buffer(third);
    xqc_tls_ctx_destroy(ctx);
}


/*
 * Key update with real 1-RTT keys: a client connection whose TLS completed a
 * handshake receives packets that the server protects with its retired or
 * current keys through the connection receive path, around the old-key
 * discard deadline of RFC 9001 Sections 6.1 and 6.5.
 */
typedef struct {
    xqc_log_t             *log;
    xqc_tls_ctx_t         *ctx_cli;
    xqc_tls_ctx_t         *ctx_svr;
    xqc_tls_test_buff_t   *ttbuf_cli;
    xqc_tls_test_buff_t   *ttbuf_svr;
    xqc_tls_t             *tls_cli;
    xqc_tls_t             *tls_svr;
    xqc_tls_t             *conn_tls;
    xqc_connection_t      *conn;
} xqc_test_key_update_ctx_t;

static xqc_int_t xqc_test_key_update_setup(xqc_test_key_update_ctx_t *t);
static void xqc_test_key_update_teardown(xqc_test_key_update_ctx_t *t);
static xqc_bool_t xqc_test_key_update_deliver(xqc_test_key_update_ctx_t *t,
    xqc_uint_t key_phase, uint64_t pktno);
static void xqc_test_key_update_client_initiate(
    xqc_test_key_update_ctx_t *t);
static void xqc_test_key_update_server_update(xqc_test_key_update_ctx_t *t,
    xqc_uint_t key_phase);

static xqc_int_t
xqc_test_key_update_setup(xqc_test_key_update_ctx_t *t)
{
    xqc_log_callbacks_t log_cb = xqc_null_log_cb;
    xqc_tls_config_t cfg = {0};
    xqc_cid_t odcid = {1};
    uint8_t *data = NULL;
    size_t len;
    xqc_int_t ret = -XQC_EFATAL;
    def_engine_ssl_config_cli;
    def_engine_ssl_config_svr;

    memset(t, 0, sizeof(*t));
    t->log = xqc_log_init(0, 0, 0, 0, 0, NULL, &log_cb, NULL);
    t->ctx_cli = xqc_tls_ctx_create(XQC_TLS_TYPE_CLIENT,
        &engine_ssl_config_cli, &tls_test_cbs, t->log);
    t->ctx_svr = xqc_tls_ctx_create(XQC_TLS_TYPE_SERVER,
        &engine_ssl_config_svr, &tls_test_cbs, t->log);
    t->ttbuf_cli = xqc_create_tls_test_buffer();
    t->ttbuf_svr = xqc_create_tls_test_buffer();
    data = xqc_malloc(XQC_TEST_MAX_CRYPTO_DATA_BUF);
    if (t->log == NULL || t->ctx_cli == NULL || t->ctx_svr == NULL
        || t->ttbuf_cli == NULL || t->ttbuf_svr == NULL || data == NULL
        || xqc_tls_ctx_register_alpn(t->ctx_svr, TEST_ALPN_1,
                                     sizeof(TEST_ALPN_1) - 1) != XQC_OK)
    {
        goto end;
    }

    cfg.hostname = "test.xquic.com";
    cfg.alpn = TEST_ALPN_1;
    cfg.trans_params = (uint8_t *) "10086";
    cfg.trans_params_len = 5;
    t->tls_cli = xqc_tls_create(t->ctx_cli, &cfg, t->log, t->ttbuf_cli);
    t->tls_svr = xqc_tls_create(t->ctx_svr, &cfg, t->log, t->ttbuf_svr);
    if (t->tls_cli == NULL || t->tls_svr == NULL
        || xqc_tls_init(t->tls_cli, XQC_VERSION_V1, &odcid) != XQC_OK
        || xqc_tls_init(t->tls_svr, XQC_VERSION_V1, &odcid) != XQC_OK)
    {
        goto end;
    }

    len = xqc_crypto_data_list_get_buf(&t->ttbuf_cli->initial_crypto_data_list,
                                       data);
    if (xqc_tls_process_crypto_data(t->tls_svr, XQC_ENC_LEV_INIT, data, len)
        != XQC_OK)
    {
        goto end;
    }

    len = xqc_crypto_data_list_get_buf(&t->ttbuf_svr->initial_crypto_data_list,
                                       data);
    if (xqc_tls_process_crypto_data(t->tls_cli, XQC_ENC_LEV_INIT, data, len)
        != XQC_OK)
    {
        goto end;
    }

    len = xqc_crypto_data_list_get_buf(&t->ttbuf_svr->hsk_crypto_data_list,
                                       data);
    if (xqc_tls_process_crypto_data(t->tls_cli, XQC_ENC_LEV_HSK, data, len)
        != XQC_OK)
    {
        goto end;
    }

    len = xqc_crypto_data_list_get_buf(&t->ttbuf_cli->hsk_crypto_data_list,
                                       data);
    if (xqc_tls_process_crypto_data(t->tls_svr, XQC_ENC_LEV_HSK, data, len)
        != XQC_OK
        || !t->ttbuf_cli->handshake_completed
        || !t->ttbuf_svr->handshake_completed)
    {
        goto end;
    }

    /*
     * A client connection unprotects 1-RTT packets with the handshaked client
     * TLS. Its own transport handshake is not run, so mark it completed for
     * the receive path to accept 1-RTT packets.
     */
    t->conn = test_engine_connect();
    if (t->conn == NULL) {
        goto end;
    }
    t->conn_tls = t->conn->tls;
    t->conn->tls = t->tls_cli;
    t->conn->conn_flag |= XQC_CONN_FLAG_HANDSHAKE_COMPLETED;
    ret = XQC_OK;

end:
    xqc_free(data);
    if (ret != XQC_OK) {
        xqc_test_key_update_teardown(t);
    }
    return ret;
}

static void
xqc_test_key_update_teardown(xqc_test_key_update_ctx_t *t)
{
    if (t->conn != NULL) {
        t->conn->tls = t->conn_tls;
        xqc_engine_destroy(t->conn->engine);
    }
    if (t->tls_cli != NULL) {
        xqc_tls_destroy(t->tls_cli);
    }
    if (t->tls_svr != NULL) {
        xqc_tls_destroy(t->tls_svr);
    }
    if (t->ttbuf_cli != NULL) {
        xqc_destroy_tls_test_buffer(t->ttbuf_cli);
    }
    if (t->ttbuf_svr != NULL) {
        xqc_destroy_tls_test_buffer(t->ttbuf_svr);
    }
    if (t->ctx_cli != NULL) {
        xqc_tls_ctx_destroy(t->ctx_cli);
    }
    if (t->ctx_svr != NULL) {
        xqc_tls_ctx_destroy(t->ctx_svr);
    }
    if (t->log != NULL) {
        xqc_free(t->log);
    }
    memset(t, 0, sizeof(*t));
}

/*
 * The server protects a short header packet holding a PING frame with its
 * 1-RTT keys of key_phase, and the client connection receives it. Return
 * whether the connection unprotected it.
 */
static xqc_bool_t
xqc_test_key_update_deliver(xqc_test_key_update_ctx_t *t,
    xqc_uint_t key_phase, uint64_t pktno)
{
    xqc_connection_t *conn = t->conn;
    const xqc_cid_t *dcid = &conn->scid_set.user_scid;
    uint64_t dropped = conn->packet_dropped_count;
    uint8_t plain[32] = {0x01};
    uint8_t pkt[1 + XQC_MAX_CID_LEN + 4 + sizeof(plain) + 64];
    uint8_t *pn;
    size_t hdr_len;
    size_t enc_len = 0;

    /* fixed bit, key phase and a 4-byte packet number */
    pkt[0] = 0x43 | (key_phase ? 0x04 : 0);
    memcpy(pkt + 1, dcid->cid_buf, dcid->cid_len);
    pn = pkt + 1 + dcid->cid_len;
    pn[0] = (uint8_t) (pktno >> 24);
    pn[1] = (uint8_t) (pktno >> 16);
    pn[2] = (uint8_t) (pktno >> 8);
    pn[3] = (uint8_t) pktno;
    hdr_len = pn + 4 - pkt;

    if (xqc_tls_encrypt_payload(t->tls_svr, XQC_ENC_LEV_1RTT, pktno, 0,
                                pkt, hdr_len, plain, sizeof(plain),
                                pkt + hdr_len, sizeof(pkt) - hdr_len,
                                &enc_len) != XQC_OK
        || xqc_tls_encrypt_header(t->tls_svr, XQC_ENC_LEV_1RTT,
                                  XQC_PTYPE_SHORT_HEADER, pkt, pn,
                                  pkt + hdr_len + enc_len) != XQC_OK)
    {
        return XQC_FALSE;
    }

    if (xqc_conn_process_packet(conn, pkt, hdr_len + enc_len,
                                xqc_monotonic_timestamp()) != XQC_OK)
    {
        return XQC_FALSE;
    }

    return conn->packet_dropped_count == dropped;
}

/* the client initiates a key update, as xqc_packet_initiate_key_update does */
static void
xqc_test_key_update_client_initiate(xqc_test_key_update_ctx_t *t)
{
    CU_ASSERT_EQUAL(xqc_tls_update_1rtt_keys(t->tls_cli,
                                             XQC_KEY_TYPE_RX_READ), XQC_OK);
    CU_ASSERT_EQUAL(xqc_tls_update_1rtt_keys(t->tls_cli,
                                             XQC_KEY_TYPE_TX_WRITE), XQC_OK);
    CU_ASSERT_EQUAL(xqc_conn_confirm_key_update(t->conn, XQC_TRUE), XQC_OK);
}

/* the server derives the keys of the next key phase, numbered key_phase */
static void
xqc_test_key_update_server_update(xqc_test_key_update_ctx_t *t,
    xqc_uint_t key_phase)
{
    CU_ASSERT_EQUAL(xqc_tls_update_1rtt_keys(t->tls_svr,
                                             XQC_KEY_TYPE_RX_READ), XQC_OK);
    CU_ASSERT_EQUAL(xqc_tls_update_1rtt_keys(t->tls_svr,
                                             XQC_KEY_TYPE_TX_WRITE), XQC_OK);
    xqc_tls_set_1rtt_key_phase(t->tls_svr, key_phase);
}

/*
 * The client initiates a key update. The old-key discard deadline starts only
 * once a packet protected with the server's new keys has been unprotected.
 * Until that deadline, packets protected with the retired keys still decrypt;
 * after it, they are dropped, while the current keys keep working.
 */
void
xqc_test_tls_key_update_discards_retired_keys(void)
{
    xqc_test_key_update_ctx_t t;
    xqc_timer_manager_t *timers;
    xqc_usec_t before;
    xqc_usec_t deadline;

    CU_ASSERT_FATAL(xqc_test_key_update_setup(&t) == XQC_OK);
    timers = &t.conn->conn_timer_manager;
    CU_ASSERT(xqc_test_key_update_deliver(&t, 0, 1));

    xqc_test_key_update_client_initiate(&t);
    xqc_test_key_update_server_update(&t, 1);
    CU_ASSERT(xqc_test_key_update_deliver(&t, 0, 2));
    CU_ASSERT(!xqc_timer_is_set(timers, XQC_TIMER_KEY_UPDATE));

    before = xqc_monotonic_timestamp();
    CU_ASSERT(xqc_test_key_update_deliver(&t, 1, 6));
    CU_ASSERT_FATAL(xqc_timer_is_set(timers, XQC_TIMER_KEY_UPDATE));
    deadline = timers->timer[XQC_TIMER_KEY_UPDATE].expire_time;
    CU_ASSERT(deadline >= before + 3 * xqc_conn_get_max_pto(t.conn));

    xqc_timer_expire(timers, deadline - 1);
    CU_ASSERT(xqc_test_key_update_deliver(&t, 0, 3));

    xqc_timer_expire(timers, deadline);
    CU_ASSERT(!xqc_timer_is_set(timers, XQC_TIMER_KEY_UPDATE));
    CU_ASSERT(!xqc_test_key_update_deliver(&t, 0, 4));
    CU_ASSERT(xqc_test_key_update_deliver(&t, 1, 7));

    xqc_test_key_update_teardown(&t);
}

/*
 * The server starts a key update, and the client initiates the next one
 * before the discard deadline of the first has passed. That deadline must not
 * discard the keys the client has just retired: none of the server's packets
 * protected with the new keys has been unprotected yet (RFC 9001 Section 6.1).
 */
void
xqc_test_tls_key_update_keeps_retired_keys(void)
{
    xqc_test_key_update_ctx_t t;
    xqc_timer_manager_t *timers;
    xqc_usec_t before;
    xqc_usec_t deadline;

    CU_ASSERT_FATAL(xqc_test_key_update_setup(&t) == XQC_OK);
    timers = &t.conn->conn_timer_manager;
    CU_ASSERT(xqc_test_key_update_deliver(&t, 0, 1));

    xqc_test_key_update_server_update(&t, 1);
    CU_ASSERT(xqc_test_key_update_deliver(&t, 1, 2));
    CU_ASSERT_FATAL(xqc_timer_is_set(timers, XQC_TIMER_KEY_UPDATE));
    deadline = timers->timer[XQC_TIMER_KEY_UPDATE].expire_time;

    xqc_test_key_update_client_initiate(&t);
    xqc_test_key_update_server_update(&t, 0);
    CU_ASSERT(!xqc_timer_is_set(timers, XQC_TIMER_KEY_UPDATE));

    xqc_timer_expire(timers, deadline);
    CU_ASSERT(xqc_test_key_update_deliver(&t, 1, 3));

    before = xqc_monotonic_timestamp();
    CU_ASSERT(xqc_test_key_update_deliver(&t, 0, 6));
    CU_ASSERT_FATAL(xqc_timer_is_set(timers, XQC_TIMER_KEY_UPDATE));
    CU_ASSERT(timers->timer[XQC_TIMER_KEY_UPDATE].expire_time
              >= before + 3 * xqc_conn_get_max_pto(t.conn));
    CU_ASSERT(xqc_test_key_update_deliver(&t, 1, 4));

    xqc_test_key_update_teardown(&t);
}

/*
 * The server starts two key updates in a row. The discard deadline of the
 * first has passed when the packet starting the second arrives, but the
 * timers have not run yet, as when the packet is processed before the timers
 * of the next engine tick. The keys retired by the second update are still
 * kept for three times the PTO, and discarded after that.
 */
void
xqc_test_tls_key_update_responder_keeps_retired_keys(void)
{
    xqc_test_key_update_ctx_t t;
    xqc_timer_manager_t *timers;
    xqc_usec_t before;
    xqc_usec_t deadline;

    CU_ASSERT_FATAL(xqc_test_key_update_setup(&t) == XQC_OK);
    timers = &t.conn->conn_timer_manager;
    CU_ASSERT(xqc_test_key_update_deliver(&t, 0, 1));

    xqc_test_key_update_server_update(&t, 1);
    CU_ASSERT(xqc_test_key_update_deliver(&t, 1, 2));
    CU_ASSERT(xqc_test_key_update_deliver(&t, 1, 3));
    CU_ASSERT_FATAL(xqc_timer_is_set(timers, XQC_TIMER_KEY_UPDATE));
    xqc_timer_set(timers, XQC_TIMER_KEY_UPDATE, 0, 1);

    xqc_test_key_update_server_update(&t, 0);
    before = xqc_monotonic_timestamp();
    CU_ASSERT(xqc_test_key_update_deliver(&t, 0, 6));
    CU_ASSERT_EQUAL(t.conn->key_update_ctx.key_update_cnt, 2);
    deadline = timers->timer[XQC_TIMER_KEY_UPDATE].expire_time;
    CU_ASSERT(deadline >= before + 3 * xqc_conn_get_max_pto(t.conn));

    xqc_timer_expire(timers, before);
    CU_ASSERT(xqc_test_key_update_deliver(&t, 1, 4));

    xqc_timer_expire(timers, deadline);
    CU_ASSERT(!xqc_test_key_update_deliver(&t, 1, 5));
    CU_ASSERT(xqc_test_key_update_deliver(&t, 0, 7));

    xqc_test_key_update_teardown(&t);
}


void
xqc_test_tls(void)
{
    xqc_log_callbacks_t log_cb =  xqc_null_log_cb;
    test_log =  xqc_log_init(0, 0, 0, 0, 0, NULL, &log_cb, NULL);
    
    xqc_test_create_client_tls_ctx();
    xqc_test_create_server_tls_ctx();
    xqc_test_tls_ctx_register_alpn();
    xqc_test_tls_reset_initial();
    
    xqc_test_tls_multiple_crypto_data();
    xqc_test_tls_generic();
    xqc_test_reset_ticket_policy();
    xqc_test_max_udp_payload_ticket_policy();
    xqc_test_tls_process_truncated_crypto_handshake();
    xqc_test_tls_failure();
    
    xqc_test_destroy_tls_ctx();
    xqc_free(test_log);
}
