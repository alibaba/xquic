/*
 * A stateless reset token MUST be difficult to guess (RFC 9000 Section
 * 10.3.2), and only the server may know the key that protects its address
 * validation tokens (Section 8.1.4). An engine whose config sets no key
 * makes up a random one; a key that the config sets is used as is, so that
 * servers sharing it recognize each other's stateless resets and tokens.
 */

#include <CUnit/CUnit.h>
#include <string.h>
#include <arpa/inet.h>
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_packet_parser.h"
#include "xqc_common_test.h"
#include "xqc_engine_keys_test.h"

/* the token key that an engine used when its config set none */
#define XQC_TEST_PUBLIC_TOKEN_KEY   "xquic token key"

/* defined in xqc_engine.c: the secret of a token key */
void xqc_engine_initial_token_secret(unsigned char *src, uint16_t src_len,
    unsigned char *dst);


static void
xqc_test_keys_reset_token(xqc_engine_t *engine, unsigned char *token)
{
    xqc_cid_t cid;

    memset(&cid, 0, sizeof(cid));
    cid.cid_len = 8;
    memcpy(cid.cid_buf, "\x2d\xc6\x66\x7e\x58\x20\xe7\x61", cid.cid_len);
    xqc_gen_reset_token(&cid, token, XQC_STATELESS_RESET_TOKENLEN,
                        engine->config->reset_token_key,
                        engine->config->reset_token_keylen);
}

/*
 * A connection whose engine takes the server role for the token keys,
 * with a peer at 192.0.2.1: the token functions only read the engine's
 * token secrets and the peer address, so no certificate is needed.
 */
static xqc_connection_t *
xqc_test_keys_server_conn(const xqc_config_t *config)
{
    xqc_connection_t   *conn = test_engine_connect();
    struct sockaddr_in  sa;

    CU_ASSERT_FATAL(conn != NULL);
    conn->engine->eng_type = XQC_ENGINE_SERVER;
    if (config != NULL) {
        CU_ASSERT(xqc_engine_set_config(conn->engine, config) == XQC_OK);
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(4433);
    CU_ASSERT(inet_pton(AF_INET, "192.0.2.1", &sa.sin_addr) == 1);
    memcpy(conn->peer_addr, &sa, sizeof(sa));
    conn->peer_addrlen = sizeof(sa);
    return conn;
}

/* whether the token that issuer makes for the peer passes the checks of conn */
static xqc_int_t
xqc_test_keys_token_check(xqc_connection_t *issuer, xqc_connection_t *conn)
{
    unsigned char   token[XQC_MAX_TOKEN_LEN];
    unsigned        token_len = sizeof(token);

    CU_ASSERT_FATAL(xqc_conn_gen_token(issuer, token, &token_len) == XQC_OK);
    return xqc_conn_check_token(conn, token, token_len);
}

/* make every token version of engine use the public key of the past */
static void
xqc_test_keys_use_public_token_key(xqc_engine_t *engine)
{
    static const char key[] = XQC_TEST_PUBLIC_TOKEN_KEY;

    for (int i = 0; i < XQC_TOKEN_MAX_KEY_VERSION; i++) {
        xqc_engine_initial_token_secret((unsigned char *) key,
                                        sizeof(key) - 1,
                                        engine->token_secret_list[i]);
    }
}


/*
 * Engines whose config sets no stateless reset key make up different random
 * ones, so their tokens are not those of the empty key that anyone can
 * compute; a config set later without a key keeps the key in use.
 */
void
xqc_test_engine_keys_random_reset_key(void)
{
    unsigned char   token1[XQC_STATELESS_RESET_TOKENLEN];
    unsigned char   token2[XQC_STATELESS_RESET_TOKENLEN];
    unsigned char   empty_key_token[XQC_STATELESS_RESET_TOKENLEN];
    char            key[XQC_RESET_TOKEN_MAX_KEY_LEN];
    xqc_config_t    config;
    xqc_cid_t       cid;
    xqc_engine_t   *engine1 = test_create_engine();
    xqc_engine_t   *engine2 = test_create_engine();

    CU_ASSERT_FATAL(engine1 != NULL && engine2 != NULL);
    CU_ASSERT(engine1->config->reset_token_keylen == 32);
    CU_ASSERT(engine2->config->reset_token_keylen == 32);

    xqc_test_keys_reset_token(engine1, token1);
    xqc_test_keys_reset_token(engine2, token2);
    memset(&cid, 0, sizeof(cid));
    cid.cid_len = 8;
    memcpy(cid.cid_buf, "\x2d\xc6\x66\x7e\x58\x20\xe7\x61", cid.cid_len);
    xqc_gen_reset_token(&cid, empty_key_token, sizeof(empty_key_token),
                        "", 0);
    CU_ASSERT(memcmp(token1, token2, sizeof(token1)) != 0);
    CU_ASSERT(memcmp(token1, empty_key_token, sizeof(token1)) != 0);
    CU_ASSERT(memcmp(token2, empty_key_token, sizeof(token2)) != 0);

    /* abnormal: a config without a key does not bring the empty key back */
    memcpy(key, engine1->config->reset_token_key, 32);
    CU_ASSERT(xqc_engine_get_default_config(&config, XQC_ENGINE_CLIENT)
              == XQC_OK);
    CU_ASSERT(config.reset_token_keylen == 0);
    CU_ASSERT(xqc_engine_set_config(engine1, &config) == XQC_OK);
    CU_ASSERT(engine1->config->reset_token_keylen == 32);
    CU_ASSERT(memcmp(engine1->config->reset_token_key, key, 32) == 0);

    xqc_engine_destroy(engine1);
    xqc_engine_destroy(engine2);
}


/*
 * A stateless reset key that the config sets is used as is: engines sharing
 * it, such as the servers of a deployment or a restarted one, compute the
 * same tokens. A later config without a key keeps it.
 */
void
xqc_test_engine_keys_configured_reset_key(void)
{
    static const char shared_key[] = "a stateless reset key of a deployment";
    unsigned char   token1[XQC_STATELESS_RESET_TOKENLEN];
    unsigned char   token2[XQC_STATELESS_RESET_TOKENLEN];
    xqc_config_t    config;
    xqc_engine_t   *engine1 = test_create_engine();
    xqc_engine_t   *engine2 = test_create_engine();

    CU_ASSERT_FATAL(engine1 != NULL && engine2 != NULL);
    CU_ASSERT(xqc_engine_get_default_config(&config, XQC_ENGINE_SERVER)
              == XQC_OK);
    memcpy(config.reset_token_key, shared_key, sizeof(shared_key) - 1);
    config.reset_token_keylen = sizeof(shared_key) - 1;
    CU_ASSERT(xqc_engine_set_config(engine1, &config) == XQC_OK);
    CU_ASSERT(xqc_engine_set_config(engine2, &config) == XQC_OK);

    CU_ASSERT(engine1->config->reset_token_keylen == sizeof(shared_key) - 1);
    CU_ASSERT(memcmp(engine1->config->reset_token_key, shared_key,
                     sizeof(shared_key) - 1) == 0);
    xqc_test_keys_reset_token(engine1, token1);
    xqc_test_keys_reset_token(engine2, token2);
    CU_ASSERT(memcmp(token1, token2, sizeof(token1)) == 0);

    config.reset_token_keylen = 0;
    CU_ASSERT(xqc_engine_set_config(engine2, &config) == XQC_OK);
    xqc_test_keys_reset_token(engine2, token2);
    CU_ASSERT(memcmp(token1, token2, sizeof(token1)) == 0);

    xqc_engine_destroy(engine1);
    xqc_engine_destroy(engine2);
}


/*
 * Without token keys in the config, each engine accepts its own address
 * validation tokens, but not another engine's: their keys are random.
 */
void
xqc_test_engine_keys_random_token_key(void)
{
    xqc_config_t        config;
    xqc_connection_t   *conn1, *conn2;

    CU_ASSERT(xqc_engine_get_default_config(&config, XQC_ENGINE_SERVER)
              == XQC_OK);
    for (int i = 0; i < XQC_TOKEN_MAX_KEY_VERSION; i++) {
        CU_ASSERT(config.tk_len_list[i] == 0);
    }

    conn1 = xqc_test_keys_server_conn(&config);
    conn2 = xqc_test_keys_server_conn(&config);
    CU_ASSERT(xqc_test_keys_token_check(conn1, conn1) == XQC_OK);
    CU_ASSERT(xqc_test_keys_token_check(conn2, conn2) == XQC_OK);
    CU_ASSERT(xqc_test_keys_token_check(conn1, conn2) == XQC_ERROR);
    CU_ASSERT(xqc_test_keys_token_check(conn2, conn1) == XQC_ERROR);

    xqc_engine_destroy(conn1->engine);
    xqc_engine_destroy(conn2->engine);
}


/*
 * A token made with the key that engines used to share by default, for any
 * of the four versions that a token can name, is refused, also by a server
 * that sets the key of version 0 only. Servers that set the same key accept
 * each other's tokens.
 */
void
xqc_test_engine_keys_public_token_key_refused(void)
{
    static const char shared_key[] = "a token key of a deployment";
    xqc_config_t        config;
    xqc_connection_t   *forger, *conn1, *conn2;

    CU_ASSERT(xqc_engine_get_default_config(&config, XQC_ENGINE_SERVER)
              == XQC_OK);
    forger = xqc_test_keys_server_conn(NULL);
    xqc_test_keys_use_public_token_key(forger->engine);

    conn1 = xqc_test_keys_server_conn(&config);
    for (int i = 0; i < XQC_TOKEN_MAX_KEY_VERSION; i++) {
        forger->engine->cur_ts_index = i;
        CU_ASSERT(xqc_test_keys_token_check(forger, conn1) == XQC_ERROR);
    }
    xqc_engine_destroy(conn1->engine);

    /* the key of version 0 only, the version of the new tokens */
    memcpy(config.token_key_list[0], shared_key, sizeof(shared_key) - 1);
    config.tk_len_list[0] = sizeof(shared_key) - 1;
    conn1 = xqc_test_keys_server_conn(&config);
    conn2 = xqc_test_keys_server_conn(&config);
    CU_ASSERT(xqc_test_keys_token_check(conn1, conn2) == XQC_OK);
    CU_ASSERT(xqc_test_keys_token_check(conn2, conn1) == XQC_OK);
    for (int i = 1; i < XQC_TOKEN_MAX_KEY_VERSION; i++) {
        forger->engine->cur_ts_index = i;
        CU_ASSERT(xqc_test_keys_token_check(forger, conn1) == XQC_ERROR);
    }

    xqc_engine_destroy(conn1->engine);
    xqc_engine_destroy(conn2->engine);
    xqc_engine_destroy(forger->engine);
}
