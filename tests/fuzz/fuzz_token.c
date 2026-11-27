/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 *
 * Fuzz target: the address validation tokens of a server (RFC 9000
 * Section 8.1), as a client returns them in an Initial packet after a
 * Retry or a NEW_TOKEN frame.
 *
 * The first byte sets the client address family (bit 0) and how the rest
 * of the input becomes a token: as is (bit 1 clear), which mostly tests
 * the length checks and the decryption, or encrypted with the server's
 * current token key (bit 1 set), so that the plaintext fields are checked.
 * A token that the server makes for the address must validate.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_defs.h"
#include "src/transport/xqc_engine.h"
#include "xqc_fuzz_common.h"

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static xqc_engine_t *xqc_fuzz_engine;
static xqc_connection_t *xqc_fuzz_conn;


static ssize_t
xqc_fuzz_write_socket(const unsigned char *buf, size_t size,
                      const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                      void *user_data)
{
    return (ssize_t)size;
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    xqc_engine_ssl_config_t ssl_config;
    xqc_engine_callback_t callbacks;
    xqc_transport_callbacks_t tcbs;
    xqc_app_proto_callbacks_t app_cbs;
    xqc_conn_settings_t settings;
    xqc_conn_ssl_config_t conn_ssl_config;
    xqc_config_t config;
    const xqc_cid_t *cid;

    xqc_fuzz_ssl_config(&ssl_config);
    xqc_fuzz_engine_callbacks(&callbacks);
    memset(&tcbs, 0, sizeof(tcbs));
    tcbs.write_socket = xqc_fuzz_write_socket;

    xqc_fuzz_engine_config(&config, XQC_ENGINE_CLIENT);

    xqc_fuzz_engine = xqc_engine_create(XQC_ENGINE_CLIENT, &config, &ssl_config,
                                        &callbacks, &tcbs, NULL);
    if (xqc_fuzz_engine == NULL) {
        abort();
    }

    memset(&app_cbs, 0, sizeof(app_cbs));
    xqc_engine_register_alpn(xqc_fuzz_engine, "transport", 9, &app_cbs, NULL);

    memset(&settings, 0, sizeof(settings));
    settings.proto_version = XQC_VERSION_V1;
    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));
    cid = xqc_connect(xqc_fuzz_engine, &settings, NULL, 0, "", 0,
                      &conn_ssl_config, NULL, 0, "transport", NULL);
    if (cid == NULL) {
        abort();
    }

    /* the token functions only use the engine keys and the peer address */
    xqc_fuzz_conn = xqc_engine_conns_hash_find(xqc_fuzz_engine, cid, 's');
    if (xqc_fuzz_conn == NULL) {
        abort();
    }

    return 0;
}

static void
xqc_fuzz_set_peer(xqc_connection_t *conn, xqc_bool_t ipv6)
{
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)conn->peer_addr;
    struct sockaddr_in *sa4 = (struct sockaddr_in *)conn->peer_addr;

    memset(conn->peer_addr, 0, sizeof(conn->peer_addr));
    if (ipv6) {
        sa6->sin6_family = AF_INET6;
        memset(&sa6->sin6_addr, 0x20, sizeof(sa6->sin6_addr));
        sa6->sin6_port = htons(50000);
        conn->peer_addrlen = sizeof(*sa6);

    } else {
        sa4->sin_family = AF_INET;
        sa4->sin_addr.s_addr = htonl(0x0a000002);
        sa4->sin_port = htons(50000);
        conn->peer_addrlen = sizeof(*sa4);
    }
}

/* IV, flags, AES-128-GCM of the plaintext, tag: the server's token format */
static size_t
xqc_fuzz_encrypt_token(xqc_connection_t *conn, const uint8_t *plain,
                       size_t plain_len, uint8_t *token)
{
    EVP_CIPHER_CTX *ctx;
    uint8_t flag;
    size_t len = 0;
    int n;

    if (plain_len == 0
        || plain_len > XQC_MAX_TOKEN_LEN - XQC_TOKEN_IV_LEN - XQC_TOKEN_TAG_LEN)
    {
        return 0;
    }

    flag = plain[0];
    memset(token, 0xa5, XQC_TOKEN_IV_LEN);
    token[XQC_TOKEN_IV_LEN] = flag;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return 0;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL,
                           conn->engine
                               ->token_secret_list[flag
                                                   & XQC_TOKEN_VERSION_MASK],
                           token)
            != 1
        || EVP_EncryptUpdate(ctx, token + XQC_TOKEN_IV_LEN + 1, &n, plain + 1,
                             (int)plain_len - 1)
               != 1)
    {
        goto end;
    }
    len = XQC_TOKEN_IV_LEN + 1 + n;

    if (EVP_EncryptFinal_ex(ctx, token + len, &n) != 1) {
        len = 0;
        goto end;
    }
    len += n;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, XQC_TOKEN_TAG_LEN,
                            token + len)
        != 1)
    {
        len = 0;
        goto end;
    }
    len += XQC_TOKEN_TAG_LEN;

end:
    EVP_CIPHER_CTX_free(ctx);
    return len;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    xqc_fuzz_input_t in = {data, size};
    const uint8_t *body;
    uint8_t mode, token[XQC_MAX_TOKEN_LEN];
    uint8_t *buf;
    unsigned token_len;
    size_t len;

    xqc_fuzz_now = XQC_FUZZ_START_TIME;
    mode = xqc_fuzz_u8(&in);
    len = xqc_fuzz_take(&in, in.size, &body);

    xqc_fuzz_set_peer(xqc_fuzz_conn, mode & 0x01);
    xqc_fuzz_conn->conn_flag &= ~XQC_CONN_FLAG_UPDATE_NEW_TOKEN;

    if (mode & 0x02) {
        len = xqc_fuzz_encrypt_token(xqc_fuzz_conn, body, len, token);
        body = token;
    }

    /* a heap copy of the exact size, so that ASan catches overreads */
    buf = malloc(len ? len : 1);
    if (buf == NULL) {
        return 0;
    }
    memcpy(buf, body, len);
    (void)xqc_conn_check_token(xqc_fuzz_conn, buf, (unsigned)len);
    free(buf);

    /* a token of the server for this address validates */
    token_len = sizeof(token);
    if (xqc_conn_gen_token(xqc_fuzz_conn, token, &token_len) == XQC_OK
        && xqc_conn_check_token(xqc_fuzz_conn, token, token_len) != XQC_OK)
    {
        abort();
    }

    return 0;
}
