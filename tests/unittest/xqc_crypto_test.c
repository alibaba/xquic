/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <string.h>
#include <CUnit/CUnit.h>
#include "xqc_common_test.h"
#include "src/transport/xqc_conn.h"
#include "src/tls/xqc_tls_defs.h"
#include "src/tls/xqc_tls.h"
#include "src/tls/xqc_crypto.h"
#include "src/tls/xqc_hkdf.h"

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
                                           XQC_INITIAL_SALT_LEN);
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


/*
 * ==========================================================================
 * RFC 9001 Appendix A test vectors.
 *
 * Input:
 *   DCID  = 0x8394c8f03e515708
 *   Salt  = QUIC v1 initial salt (0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a)
 *
 * Reference: RFC 9001, Appendix A.1 "Keys"
 * ==========================================================================
 */

/* Destination Connection ID from RFC 9001 Appendix A */
static const uint8_t rfc9001_dcid[] = {
    0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08
};

/* initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id) */
static const uint8_t rfc9001_initial_secret[32] = {
    0x7d, 0xb5, 0xdf, 0x06, 0xe7, 0xa6, 0x9e, 0x43,
    0x24, 0x96, 0xad, 0xed, 0xb0, 0x08, 0x51, 0x92,
    0x35, 0x95, 0x22, 0x15, 0x96, 0xae, 0x2a, 0xe9,
    0xfb, 0x81, 0x15, 0xc1, 0xe9, 0xed, 0x0a, 0x44
};

/* client_initial_secret */
static const uint8_t rfc9001_client_initial_secret[32] = {
    0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75,
    0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4,
    0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a,
    0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea
};

/* server_initial_secret */
static const uint8_t rfc9001_server_initial_secret[32] = {
    0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd,
    0x21, 0x6c, 0x15, 0x5a, 0xd8, 0x44, 0xcc, 0x81,
    0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46, 0xfa, 0x7d,
    0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b
};

/* client AEAD key (AES-128-GCM, 16 bytes) */
static const uint8_t rfc9001_client_key[16] = {
    0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46,
    0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d
};

/* client AEAD IV (12 bytes) */
static const uint8_t rfc9001_client_iv[12] = {
    0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b,
    0x46, 0xfb, 0x25, 0x5c
};

/* client header protection key (AES-128-CTR, 16 bytes) */
static const uint8_t rfc9001_client_hp[16] = {
    0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
    0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2
};

/* server AEAD key (AES-128-GCM, 16 bytes) */
static const uint8_t rfc9001_server_key[16] = {
    0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c,
    0x88, 0xf0, 0xf3, 0x79, 0xb6, 0x06, 0x7e, 0x37
};

/* server AEAD IV (12 bytes) */
static const uint8_t rfc9001_server_iv[12] = {
    0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90, 0x58, 0x53,
    0xb0, 0xbb, 0xa0, 0x3e
};

/* server header protection key (AES-128-CTR, 16 bytes) */
static const uint8_t rfc9001_server_hp[16] = {
    0xc2, 0x06, 0xb8, 0xd9, 0xb9, 0xf0, 0xf3, 0x76,
    0x44, 0x43, 0x0b, 0x49, 0x0e, 0xea, 0xa3, 0x14
};


/*
 * Test A: verify HKDF-Extract produces the correct initial_secret.
 *
 * RFC 9001 S5.2:
 *   initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
 */
void
xqc_test_rfc9001_initial_secret()
{
    uint8_t initial_secret[INITIAL_SECRET_MAX_LEN] = {0};
    xqc_digest_t md;
    xqc_digest_init_to_sha256(&md);

    const uint8_t *salt = (const uint8_t *)xqc_crypto_initial_salt[XQC_VERSION_V1];
    size_t saltlen = 20;  /* QUIC v1 initial salt is exactly 20 bytes */

    xqc_int_t ret = xqc_hkdf_extract(initial_secret, INITIAL_SECRET_MAX_LEN,
                                      rfc9001_dcid, sizeof(rfc9001_dcid),
                                      salt, saltlen, &md);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(memcmp(initial_secret, rfc9001_initial_secret,
                     sizeof(rfc9001_initial_secret)) == 0);
}


/*
 * Test B: verify client_initial_secret and server_initial_secret
 * produced by xqc_crypto_derive_initial_secret().
 *
 * RFC 9001 Appendix A.1:
 *   client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
 *   server_initial_secret = HKDF-Expand-Label(initial_secret, "server in", "", 32)
 */
void
xqc_test_rfc9001_derive_initial_secrets()
{
    uint8_t cli_secret[INITIAL_SECRET_MAX_LEN] = {0};
    uint8_t svr_secret[INITIAL_SECRET_MAX_LEN] = {0};

    xqc_cid_t dcid;
    memset(&dcid, 0, sizeof(dcid));
    memcpy(dcid.cid_buf, rfc9001_dcid, sizeof(rfc9001_dcid));
    dcid.cid_len = sizeof(rfc9001_dcid);

    const uint8_t *salt = (const uint8_t *)xqc_crypto_initial_salt[XQC_VERSION_V1];
    size_t saltlen = 20;

    xqc_int_t ret = xqc_crypto_derive_initial_secret(
        cli_secret, INITIAL_SECRET_MAX_LEN,
        svr_secret, INITIAL_SECRET_MAX_LEN,
        &dcid, salt, saltlen);
    CU_ASSERT(ret == XQC_OK);

    CU_ASSERT(memcmp(cli_secret, rfc9001_client_initial_secret,
                     sizeof(rfc9001_client_initial_secret)) == 0);
    CU_ASSERT(memcmp(svr_secret, rfc9001_server_initial_secret,
                     sizeof(rfc9001_server_initial_secret)) == 0);
}


/*
 * Test C: verify client-side packet protection key, IV, and HP key.
 *
 * RFC 9001 Appendix A.1:
 *   key  = HKDF-Expand-Label(client_initial_secret, "quic key", "", 16)
 *   iv   = HKDF-Expand-Label(client_initial_secret, "quic iv",  "", 12)
 *   hp   = HKDF-Expand-Label(client_initial_secret, "quic hp",  "", 16)
 */
void
xqc_test_rfc9001_client_initial_keys()
{
    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT_FATAL(engine != NULL);

    xqc_crypto_t *crypto = xqc_crypto_create(XQC_TLS13_AES_128_GCM_SHA256,
                                              engine->log);
    CU_ASSERT_FATAL(crypto != NULL);

    xqc_int_t ret = xqc_crypto_derive_keys(crypto,
                                            rfc9001_client_initial_secret,
                                            INITIAL_SECRET_MAX_LEN,
                                            XQC_KEY_TYPE_RX_READ);
    CU_ASSERT(ret == XQC_OK);

    /* key_phase is 0 after xqc_crypto_create */
    xqc_crypto_km_t *ckm = &crypto->keys.rx_ckm[0];

    CU_ASSERT(ckm->key.len == sizeof(rfc9001_client_key));
    CU_ASSERT(memcmp(ckm->key.base, rfc9001_client_key,
                     sizeof(rfc9001_client_key)) == 0);

    CU_ASSERT(ckm->iv.len == sizeof(rfc9001_client_iv));
    CU_ASSERT(memcmp(ckm->iv.base, rfc9001_client_iv,
                     sizeof(rfc9001_client_iv)) == 0);

    CU_ASSERT(crypto->keys.rx_hp.len == sizeof(rfc9001_client_hp));
    CU_ASSERT(memcmp(crypto->keys.rx_hp.base, rfc9001_client_hp,
                     sizeof(rfc9001_client_hp)) == 0);

    xqc_crypto_destroy(crypto);
    xqc_engine_destroy(engine);
}


/*
 * Test D: verify server-side packet protection key, IV, and HP key.
 *
 * RFC 9001 Appendix A.1:
 *   key  = HKDF-Expand-Label(server_initial_secret, "quic key", "", 16)
 *   iv   = HKDF-Expand-Label(server_initial_secret, "quic iv",  "", 12)
 *   hp   = HKDF-Expand-Label(server_initial_secret, "quic hp",  "", 16)
 */
void
xqc_test_rfc9001_server_initial_keys()
{
    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT_FATAL(engine != NULL);

    xqc_crypto_t *crypto = xqc_crypto_create(XQC_TLS13_AES_128_GCM_SHA256,
                                              engine->log);
    CU_ASSERT_FATAL(crypto != NULL);

    xqc_int_t ret = xqc_crypto_derive_keys(crypto,
                                            rfc9001_server_initial_secret,
                                            INITIAL_SECRET_MAX_LEN,
                                            XQC_KEY_TYPE_RX_READ);
    CU_ASSERT(ret == XQC_OK);

    xqc_crypto_km_t *ckm = &crypto->keys.rx_ckm[0];

    CU_ASSERT(ckm->key.len == sizeof(rfc9001_server_key));
    CU_ASSERT(memcmp(ckm->key.base, rfc9001_server_key,
                     sizeof(rfc9001_server_key)) == 0);

    CU_ASSERT(ckm->iv.len == sizeof(rfc9001_server_iv));
    CU_ASSERT(memcmp(ckm->iv.base, rfc9001_server_iv,
                     sizeof(rfc9001_server_iv)) == 0);

    CU_ASSERT(crypto->keys.rx_hp.len == sizeof(rfc9001_server_hp));
    CU_ASSERT(memcmp(crypto->keys.rx_hp.base, rfc9001_server_hp,
                     sizeof(rfc9001_server_hp)) == 0);

    xqc_crypto_destroy(crypto);
    xqc_engine_destroy(engine);
}


void
xqc_test_initial_salt_length()
{
    /* XQC_INITIAL_SALT_LEN must be 20 (all QUIC versions) */
    CU_ASSERT_EQUAL(XQC_INITIAL_SALT_LEN, 20);

    /* sizeof each row must match the constant */
    CU_ASSERT_EQUAL(sizeof(xqc_crypto_initial_salt[XQC_VERSION_V1]),
                    XQC_INITIAL_SALT_LEN);
    CU_ASSERT_EQUAL(sizeof(xqc_crypto_initial_salt[XQC_IDRAFT_VER_29]),
                    XQC_INITIAL_SALT_LEN);
}

void
xqc_test_initial_salt_v1_value()
{
    /* RFC 9001 Section 5.2: 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a */
    static const uint8_t rfc9001_v1_salt[20] = {
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
        0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
        0xcc, 0xbb, 0x7f, 0x0a
    };

    CU_ASSERT_EQUAL(memcmp(xqc_crypto_initial_salt[XQC_VERSION_V1],
                           rfc9001_v1_salt, 20), 0);
}

void
xqc_test_initial_salt_null_byte_regression()
{
    /* salt with embedded 0x00: sizeof must still return 20 */
    static const uint8_t salt_with_null[XQC_INITIAL_SALT_LEN] = {
        0xAA, 0xBB, 0xCC, 0xDD,
        0x00,  /* embedded null */
        0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xAA,
        0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    };

    /* sizeof on a fixed-size uint8_t array is immune to 0x00 */
    CU_ASSERT_EQUAL(sizeof(salt_with_null), XQC_INITIAL_SALT_LEN);

    /* strlen would return 4 here -- that is the bug we are guarding */
    CU_ASSERT(strlen((const char *)salt_with_null) < XQC_INITIAL_SALT_LEN);

    /* the real salt table must also be immune */
    CU_ASSERT_EQUAL(sizeof(xqc_crypto_initial_salt[XQC_IDRAFT_INIT_VER]),
                    XQC_INITIAL_SALT_LEN);
}

void
xqc_test_crypto()
{
    xqc_test_derive_initial_secret();
    xqc_test_derive_packet_protection_keys();
}
