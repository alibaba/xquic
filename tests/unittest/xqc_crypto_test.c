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


/*
 * Tests for issue #574 - RFC 9001 §5.4.2 HP sample boundary check.
 * Verifies that encrypt_header and decrypt_header reject packets too short
 * for a complete 16-byte HP sample (pktno + 4 + 16 > end).
 */
static void
xqc_test_hp_sample_boundary_one(xqc_bool_t is_encrypt, size_t total_len,
                                xqc_int_t expected_ret)
{
    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT_FATAL(engine != NULL);

    xqc_crypto_t *crypto = xqc_crypto_create(XQC_TLS13_AES_128_GCM_SHA256, engine->log);
    CU_ASSERT_FATAL(crypto != NULL);

    /* derive keys so hp key is non-NULL */
    xqc_int_t ret;
    ret = xqc_crypto_derive_keys(crypto, XQC_TEST_CLIENT_SECRET,
                                 sizeof(XQC_TEST_CLIENT_SECRET) - 1, XQC_KEY_TYPE_RX_READ);
    CU_ASSERT_FATAL(ret == XQC_OK);
    ret = xqc_crypto_derive_keys(crypto, XQC_TEST_CLIENT_SECRET,
                                 sizeof(XQC_TEST_CLIENT_SECRET) - 1, XQC_KEY_TYPE_TX_WRITE);
    CU_ASSERT_FATAL(ret == XQC_OK);

    /*
     * Build a fake short-header packet buffer.
     * Layout: [header_byte] [... padding ...] [pktno @ offset 1] [... to end]
     * header[0] & 0x03 = 0 -> pktno_len = 1, so pktno + 1 <= end is satisfied
     * as long as total_len >= 2. The HP sample check requires pktno + 4 + 16 <= end.
     * With pktno at offset 1, that means total_len >= 1 + 4 + 16 = 21.
     */
    uint8_t buf[64];
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x40; /* short header, pktno_len bits = 0 -> pktno_len = 1 */

    uint8_t *header = buf;
    uint8_t *pktno  = buf + 1;
    uint8_t *end    = buf + total_len;

    if (is_encrypt) {
        ret = xqc_crypto_encrypt_header(crypto, XQC_PTYPE_SHORT_HEADER,
                                        header, pktno, end);
    } else {
        ret = xqc_crypto_decrypt_header(crypto, XQC_PTYPE_SHORT_HEADER,
                                        header, pktno, end);
    }

    if (expected_ret < 0) {
        CU_ASSERT(ret == expected_ret);
    } else {
        CU_ASSERT(ret >= 0);
    }

    xqc_crypto_destroy(crypto);
    xqc_engine_destroy(engine);
}

void
xqc_test_hp_sample_boundary()
{
    /*
     * pktno at offset 1, sample starts at pktno+4 = offset 5.
     * Need sample + 16 <= end, i.e. total_len >= 5 + 16 = 21.
     */

    /* Case 1: decrypt, pktno present but sample offset itself is short. */
    xqc_test_hp_sample_boundary_one(XQC_FALSE, 2, -XQC_EILLPKT);

    /* Case 2: decrypt, sample starts exactly at end. */
    xqc_test_hp_sample_boundary_one(XQC_FALSE, 5, -XQC_EILLPKT);

    /* Case 3: decrypt, too short (20 bytes) -> -XQC_EILLPKT */
    xqc_test_hp_sample_boundary_one(XQC_FALSE, 20, -XQC_EILLPKT);

    /* Case 4: decrypt, exact boundary (21 bytes) -> should pass check */
    xqc_test_hp_sample_boundary_one(XQC_FALSE, 21, XQC_OK);

    /* Case 5: encrypt, pktno present but sample offset itself is short. */
    xqc_test_hp_sample_boundary_one(XQC_TRUE, 2, -XQC_EILLPKT);

    /* Case 6: encrypt, sample starts exactly at end. */
    xqc_test_hp_sample_boundary_one(XQC_TRUE, 5, -XQC_EILLPKT);

    /* Case 7: encrypt, too short (20 bytes) -> -XQC_EILLPKT */
    xqc_test_hp_sample_boundary_one(XQC_TRUE, 20, -XQC_EILLPKT);

    /* Case 8: encrypt, exact boundary (21 bytes) -> should pass check */
    xqc_test_hp_sample_boundary_one(XQC_TRUE, 21, XQC_OK);
}


void
xqc_test_crypto()
{
    xqc_test_derive_initial_secret();
    xqc_test_derive_packet_protection_keys();
}
