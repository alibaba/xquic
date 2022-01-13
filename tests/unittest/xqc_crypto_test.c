/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xqc_common_test.h"
#include "src/transport/xqc_conn.h"
#include "src/tls/xqc_tls_defs.h"
#include "src/tls/xqc_tls.h"
#include "src/tls/xqc_crypto.h"

#define XQC_TEST_CLIENT_SECRET "\x75\xf5\xba\x26\xff\x42\x51\x13\x20\x76\x4e\xd7" \
"\x36\x5c\x20\x8d\x5d\x9c\x8a\xd1\x01\xe5\x0f\xc1\xc3\xc5\xaa\xfb\xd6\x3b\x56\x4a"

#define XQC_TEST_SERVER_SECRET "\x65\x0b\x75\x13\xab\x55\x6c\xab\xa6\xf4\xda\x9e" \
"\x3e\x0b\x59\xeb\x2d\xf9\x61\xc5\xd9\xba\x78\xbc\x6f\xac\x50\x96\x57\x80\xfd\xa1"

#define XQC_TEST_UNKOWND_CIPHER_ID 0x11111111u


void
xqc_test_derive_initial_secret()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    xqc_int_t ret;
    xqc_cid_t *odcid = &conn->original_dcid;

    uint8_t client_initial_secret[INITIAL_SECRET_MAX_LEN] = {0};
    uint8_t server_initial_secret[INITIAL_SECRET_MAX_LEN] = {0};

    ret = xqc_crypto_derive_initial_secret(client_initial_secret, INITIAL_SECRET_MAX_LEN,
                                           server_initial_secret, INITIAL_SECRET_MAX_LEN,
                                           odcid, xqc_crypto_initial_salt[XQC_VERSION_V1],
                                           strlen(xqc_crypto_initial_salt[XQC_VERSION_V1]));
    CU_ASSERT(ret == XQC_OK);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_crypto_derive_keys(uint32_t cipher_id)
{
    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT(engine != NULL);

    xqc_int_t ret;
    xqc_crypto_t *crypto = NULL;

    if (cipher_id == XQC_TEST_UNKOWND_CIPHER_ID) {
        crypto = xqc_crypto_create(cipher_id, engine->log);
        CU_ASSERT(crypto == NULL);
        xqc_engine_destroy(engine);
        return;
    }

    crypto = xqc_crypto_create(cipher_id, engine->log);
    CU_ASSERT(crypto != NULL);

    ret = xqc_crypto_derive_keys(crypto, XQC_TEST_CLIENT_SECRET,
                                 sizeof(XQC_TEST_CLIENT_SECRET) - 1, XQC_KEY_TYPE_RX_READ);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(xqc_crypto_is_key_ready(crypto, XQC_KEY_TYPE_RX_READ) == XQC_TRUE);

    ret = xqc_crypto_derive_keys(crypto, XQC_TEST_CLIENT_SECRET,
                                 sizeof(XQC_TEST_CLIENT_SECRET) - 1, XQC_KEY_TYPE_TX_WRITE);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(xqc_crypto_is_key_ready(crypto, XQC_KEY_TYPE_TX_WRITE) == XQC_TRUE);

    xqc_crypto_destroy(crypto);
    xqc_engine_destroy(engine);
}

void
xqc_test_derive_packet_protection_keys()
{
    xqc_test_crypto_derive_keys(XQC_TLS13_AES_128_GCM_SHA256);
    xqc_test_crypto_derive_keys(XQC_TLS13_AES_256_GCM_SHA384);
    xqc_test_crypto_derive_keys(XQC_TLS13_CHACHA20_POLY1305_SHA256);
    xqc_test_crypto_derive_keys(NID_undef);
    xqc_test_crypto_derive_keys(XQC_TEST_UNKOWND_CIPHER_ID);
}


void
xqc_test_crypto()
{
    xqc_test_derive_initial_secret();
    xqc_test_derive_packet_protection_keys();
}

