/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <string.h>
#include <CUnit/CUnit.h>

#include "xqc_common_test.h"
#include "xqc_quic_v2_test.h"

#include "src/transport/xqc_defs.h"
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_transport_params.h"
#include "src/tls/xqc_tls_defs.h"
#include "src/tls/xqc_tls.h"
#include "src/tls/xqc_tls_common.h"
#include "src/tls/xqc_crypto.h"
#include "src/tls/xqc_hkdf.h"


/* RFC 9369 Appendix A: the client-chosen Destination Connection ID */
static const uint8_t v2_dcid[] = {
    0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08
};

/* Appendix A.1 */
static const uint8_t v2_client_initial_secret[] = {
    0x14, 0xec, 0x9d, 0x6e, 0xb9, 0xfd, 0x7a, 0xf8,
    0x3b, 0xf5, 0xa6, 0x68, 0xbc, 0x17, 0xa7, 0xe2,
    0x83, 0x76, 0x6a, 0xad, 0xe7, 0xec, 0xd0, 0x89,
    0x1f, 0x70, 0xf9, 0xff, 0x7f, 0x4b, 0xf4, 0x7b
};
static const uint8_t v2_client_key[] = {
    0x8b, 0x1a, 0x0b, 0xc1, 0x21, 0x28, 0x42, 0x90,
    0xa2, 0x9e, 0x09, 0x71, 0xb5, 0xcd, 0x04, 0x5d
};
static const uint8_t v2_client_iv[] = {
    0x91, 0xf7, 0x3e, 0x23, 0x51, 0xd8, 0xfa, 0x91,
    0x66, 0x0e, 0x90, 0x9f
};
static const uint8_t v2_client_hp[] = {
    0x45, 0xb9, 0x5e, 0x15, 0x23, 0x5d, 0x6f, 0x45,
    0xa6, 0xb1, 0x9c, 0xbc, 0xb0, 0x29, 0x4b, 0xa9
};
static const uint8_t v2_server_initial_secret[] = {
    0x02, 0x63, 0xdb, 0x17, 0x82, 0x73, 0x1b, 0xf4,
    0x58, 0x8e, 0x7e, 0x4d, 0x93, 0xb7, 0x46, 0x39,
    0x07, 0xcb, 0x8c, 0xd8, 0x20, 0x0b, 0x5d, 0xa5,
    0x5a, 0x8b, 0xd4, 0x88, 0xea, 0xfc, 0x37, 0xc1
};
static const uint8_t v2_server_key[] = {
    0x82, 0xdb, 0x63, 0x78, 0x61, 0xd5, 0x5e, 0x1d,
    0x01, 0x1f, 0x19, 0xea, 0x71, 0xd5, 0xd2, 0xa7
};
static const uint8_t v2_server_iv[] = {
    0xdd, 0x13, 0xc2, 0x76, 0x49, 0x9c, 0x02, 0x49,
    0xd3, 0x31, 0x06, 0x52
};
static const uint8_t v2_server_hp[] = {
    0xed, 0xf6, 0xd0, 0x5c, 0x83, 0x12, 0x12, 0x01,
    0xb4, 0x36, 0xe1, 0x68, 0x77, 0x59, 0x3c, 0x3a
};

/* Appendix A.2: the header protection of the client Initial */
static const uint8_t v2_client_hp_sample[] = {
    0xff, 0xe6, 0x7b, 0x6a, 0xbc, 0xdb, 0x42, 0x98,
    0xb4, 0x85, 0xdd, 0x04, 0xde, 0x80, 0x60, 0x71
};
static const uint8_t v2_client_hp_mask[] = {
    0x94, 0xa0, 0xc9, 0x5e, 0x80
};

/* Appendix A.3: the server Initial */
static const uint8_t v2_server_payload[] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x40,
    0x5a, 0x02, 0x00, 0x00, 0x56, 0x03, 0x03, 0xee,
    0xfc, 0xe7, 0xf7, 0xb3, 0x7b, 0xa1, 0xd1, 0x63,
    0x2e, 0x96, 0x67, 0x78, 0x25, 0xdd, 0xf7, 0x39,
    0x88, 0xcf, 0xc7, 0x98, 0x25, 0xdf, 0x56, 0x6d,
    0xc5, 0x43, 0x0b, 0x9a, 0x04, 0x5a, 0x12, 0x00,
    0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x33, 0x00,
    0x24, 0x00, 0x1d, 0x00, 0x20, 0x9d, 0x3c, 0x94,
    0x0d, 0x89, 0x69, 0x0b, 0x84, 0xd0, 0x8a, 0x60,
    0x99, 0x3c, 0x14, 0x4e, 0xca, 0x68, 0x4d, 0x10,
    0x81, 0x28, 0x7c, 0x83, 0x4d, 0x53, 0x11, 0xbc,
    0xf3, 0x2b, 0xb9, 0xda, 0x1a, 0x00, 0x2b, 0x00,
    0x02, 0x03, 0x04
};
static const uint8_t v2_server_header[] = {
    0xd1, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x08, 0xf0,
    0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x00,
    0x40, 0x75, 0x00, 0x01
};
static const uint8_t v2_server_packet[] = {
    0xdc, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x08, 0xf0,
    0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x00,
    0x40, 0x75, 0xd9, 0x2f, 0xaa, 0xf1, 0x6f, 0x05,
    0xd8, 0xa4, 0x39, 0x8c, 0x47, 0x08, 0x96, 0x98,
    0xba, 0xee, 0xa2, 0x6b, 0x91, 0xeb, 0x76, 0x1d,
    0x9b, 0x89, 0x23, 0x7b, 0xbf, 0x87, 0x26, 0x30,
    0x17, 0x91, 0x53, 0x58, 0x23, 0x00, 0x35, 0xf7,
    0xfd, 0x39, 0x45, 0xd8, 0x89, 0x65, 0xcf, 0x17,
    0xf9, 0xaf, 0x6e, 0x16, 0x88, 0x6c, 0x61, 0xbf,
    0xc7, 0x03, 0x10, 0x6f, 0xba, 0xf3, 0xcb, 0x4c,
    0xfa, 0x52, 0x38, 0x2d, 0xd1, 0x6a, 0x39, 0x3e,
    0x42, 0x75, 0x75, 0x07, 0x69, 0x80, 0x75, 0xb2,
    0xc9, 0x84, 0xc7, 0x07, 0xf0, 0xa0, 0x81, 0x2d,
    0x8c, 0xd5, 0xa6, 0x88, 0x1e, 0xaf, 0x21, 0xce,
    0xda, 0x98, 0xf4, 0xbd, 0x23, 0xf6, 0xfe, 0x1a,
    0x3e, 0x2c, 0x43, 0xed, 0xd9, 0xce, 0x7c, 0xa8,
    0x4b, 0xed, 0x85, 0x21, 0xe2, 0xe1, 0x40
};

/* Appendix A.4: a Retry in response to the client Initial */
static const uint8_t v2_retry[] = {
    0xcf, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x08, 0xf0,
    0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74,
    0x6f, 0x6b, 0x65, 0x6e, 0xc8, 0x64, 0x6c, 0xe8,
    0xbf, 0xe3, 0x39, 0x52, 0xd9, 0x55, 0x54, 0x36,
    0x65, 0xdc, 0xc7, 0xb6
};

/* Appendix A.5: ChaCha20-Poly1305 short header packet */
static const uint8_t v2_chacha_secret[] = {
    0x9a, 0xc3, 0x12, 0xa7, 0xf8, 0x77, 0x46, 0x8e,
    0xbe, 0x69, 0x42, 0x27, 0x48, 0xad, 0x00, 0xa1,
    0x54, 0x43, 0xf1, 0x82, 0x03, 0xa0, 0x7d, 0x60,
    0x60, 0xf6, 0x88, 0xf3, 0x0f, 0x21, 0x63, 0x2b
};
static const uint8_t v2_chacha_key[] = {
    0x3b, 0xfc, 0xdd, 0xd7, 0x2b, 0xcf, 0x02, 0x54,
    0x1d, 0x7f, 0xa0, 0xdd, 0x1f, 0x5f, 0x9e, 0xee,
    0xa8, 0x17, 0xe0, 0x9a, 0x69, 0x63, 0xa0, 0xe6,
    0xc7, 0xdf, 0x0f, 0x9a, 0x1b, 0xab, 0x90, 0xf2
};
static const uint8_t v2_chacha_iv[] = {
    0xa6, 0xb5, 0xbc, 0x6a, 0xb7, 0xda, 0xfc, 0xe3,
    0x0f, 0xff, 0xf5, 0xdd
};
static const uint8_t v2_chacha_hp[] = {
    0xd6, 0x59, 0x76, 0x0d, 0x2b, 0xa4, 0x34, 0xa2,
    0x26, 0xfd, 0x37, 0xb3, 0x5c, 0x69, 0xe2, 0xda,
    0x82, 0x11, 0xd1, 0x0c, 0x4f, 0x12, 0x53, 0x87,
    0x87, 0xd6, 0x56, 0x45, 0xd5, 0xd1, 0xb8, 0xe2
};
static const uint8_t v2_chacha_ku[] = {
    0xc6, 0x93, 0x74, 0xc4, 0x9e, 0x3d, 0x2a, 0x94,
    0x66, 0xfa, 0x68, 0x9e, 0x49, 0xd4, 0x76, 0xdb,
    0x5d, 0x0d, 0xfb, 0xc8, 0x7d, 0x32, 0xce, 0xea,
    0xa6, 0x34, 0x3f, 0xd0, 0xae, 0x4c, 0x7d, 0x88
};
static const uint8_t v2_chacha_packet[] = {
    0x55, 0x58, 0xb1, 0xc6, 0x0a, 0xe7, 0xb6, 0xb9,
    0x32, 0xbc, 0x27, 0xd7, 0x86, 0xf4, 0xbc, 0x2b,
    0xb2, 0x0f, 0x21, 0x62, 0xba
};


void
xqc_test_quic_v2_version(void)
{
    CU_ASSERT(xqc_check_proto_version_valid(XQC_VERSION_V2));
    CU_ASSERT(xqc_check_proto_version_valid(XQC_VERSION_V1));
    CU_ASSERT(xqc_check_proto_version_valid(XQC_IDRAFT_VER_29));
    CU_ASSERT(!xqc_check_proto_version_valid(XQC_IDRAFT_INIT_VER));
    CU_ASSERT(!xqc_check_proto_version_valid(XQC_IDRAFT_VER_NEGOTIATION));
    CU_ASSERT(!xqc_check_proto_version_valid(XQC_VERSION_MAX));

    /* RFC 9369 Section 3.1 */
    CU_ASSERT_EQUAL(xqc_proto_version_value[XQC_VERSION_V2], 0x6b3343cf);
    CU_ASSERT_EQUAL(XQC_VERSION_V2_VALUE, 0x6b3343cf);
    CU_ASSERT_EQUAL(XQC_PACKET_VERSION_V2, XQC_VERSION_V2_VALUE);
    CU_ASSERT(memcmp(xqc_proto_version_field[XQC_VERSION_V2],
                     "\x6b\x33\x43\xcf", XQC_PROTO_VERSION_LEN) == 0);
}


/* RFC 9369 Section 3.2 */
void
xqc_test_quic_v2_packet_types(void)
{
    static const xqc_uint_t v2_bits[] = {
        [XQC_PTYPE_INIT] = 0x1, [XQC_PTYPE_0RTT] = 0x2,
        [XQC_PTYPE_HSK] = 0x3, [XQC_PTYPE_RETRY] = 0x0,
    };
    xqc_pkt_type_t t;

    for (t = XQC_PTYPE_INIT; t <= XQC_PTYPE_RETRY; t++) {
        /* QUIC v1 and draft-29 keep their codes */
        CU_ASSERT_EQUAL(xqc_packet_long_header_type_bits(XQC_VERSION_V1_VALUE,
                                                         t), t);
        CU_ASSERT_EQUAL(xqc_packet_long_header_type(XQC_IDRAFT_VER_29_VALUE,
                                                    t), t);

        CU_ASSERT_EQUAL(xqc_packet_long_header_type_bits(XQC_VERSION_V2_VALUE,
                                                         t), v2_bits[t]);
        CU_ASSERT_EQUAL(xqc_packet_long_header_type(XQC_VERSION_V2_VALUE,
                                                    v2_bits[t]), t);
    }

    /* the packets of Appendix A */
    CU_ASSERT_EQUAL(xqc_packet_get_long_header_type(v2_server_header,
                    sizeof(v2_server_header)), XQC_PTYPE_INIT);
    CU_ASSERT_EQUAL(xqc_packet_get_long_header_type(v2_retry,
                    sizeof(v2_retry)), XQC_PTYPE_RETRY);

    /* the same first byte in QUIC v1 is a 0-RTT packet */
    uint8_t v1_header[sizeof(v2_server_header)];
    memcpy(v1_header, v2_server_header, sizeof(v1_header));
    memcpy(v1_header + 1, "\x00\x00\x00\x01", XQC_PROTO_VERSION_LEN);
    CU_ASSERT_EQUAL(xqc_packet_get_long_header_type(v1_header,
                    sizeof(v1_header)), XQC_PTYPE_0RTT);

    /* too short for a version: read as QUIC v1, 0b00 an Initial */
    CU_ASSERT_EQUAL(xqc_packet_get_long_header_type(v2_retry, 4),
                    XQC_PTYPE_INIT);
}


static xqc_crypto_t *
xqc_test_quic_v2_crypto(xqc_engine_t *engine, uint32_t cipher_id,
    const uint8_t *secret, size_t secret_len, xqc_key_type_t type)
{
    xqc_crypto_t *crypto = xqc_crypto_create(cipher_id, engine->log);
    if (crypto == NULL) {
        return NULL;
    }

    crypto->quic_v2 = XQC_TRUE;
    if (xqc_crypto_derive_keys(crypto, secret, secret_len, type) != XQC_OK) {
        xqc_crypto_destroy(crypto);
        return NULL;
    }

    return crypto;
}


/* RFC 9369 Section 3.3 and Appendix A.1: Initial secrets and keys */
void
xqc_test_quic_v2_initial_keys(void)
{
    uint8_t cli_secret[INITIAL_SECRET_MAX_LEN] = {0};
    uint8_t svr_secret[INITIAL_SECRET_MAX_LEN] = {0};
    xqc_cid_t dcid;

    memset(&dcid, 0, sizeof(dcid));
    memcpy(dcid.cid_buf, v2_dcid, sizeof(v2_dcid));
    dcid.cid_len = sizeof(v2_dcid);

    CU_ASSERT_EQUAL(xqc_crypto_derive_initial_secret(
        cli_secret, sizeof(cli_secret), svr_secret, sizeof(svr_secret),
        &dcid, xqc_crypto_initial_salt[XQC_VERSION_V2], XQC_INITIAL_SALT_LEN),
        XQC_OK);
    CU_ASSERT(memcmp(cli_secret, v2_client_initial_secret,
                     sizeof(cli_secret)) == 0);
    CU_ASSERT(memcmp(svr_secret, v2_server_initial_secret,
                     sizeof(svr_secret)) == 0);

    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT_FATAL(engine != NULL);

    xqc_crypto_t *crypto = xqc_test_quic_v2_crypto(engine,
        XQC_TLS13_AES_128_GCM_SHA256, v2_client_initial_secret,
        sizeof(v2_client_initial_secret), XQC_KEY_TYPE_TX_WRITE);
    CU_ASSERT_FATAL(crypto != NULL);
    xqc_crypto_km_t *ckm = &crypto->keys.tx_ckm[0];
    CU_ASSERT(ckm->key.len == sizeof(v2_client_key)
              && memcmp(ckm->key.base, v2_client_key, ckm->key.len) == 0);
    CU_ASSERT(ckm->iv.len == sizeof(v2_client_iv)
              && memcmp(ckm->iv.base, v2_client_iv, ckm->iv.len) == 0);
    CU_ASSERT(crypto->keys.tx_hp.len == sizeof(v2_client_hp)
              && memcmp(crypto->keys.tx_hp.base, v2_client_hp,
                        sizeof(v2_client_hp)) == 0);

    /* Appendix A.2: the header protection mask of the client Initial */
    uint8_t zeros[5] = {0};
    uint8_t mask[5] = {0};
    size_t mask_len = 0;
    CU_ASSERT_EQUAL(crypto->hp_cipher.hp_mask(&crypto->hp_cipher,
                    crypto->keys.tx_hp_ctx, mask, sizeof(mask), &mask_len,
                    zeros, sizeof(zeros),
                    crypto->keys.tx_hp.base, crypto->keys.tx_hp.len,
                    v2_client_hp_sample, sizeof(v2_client_hp_sample)),
                    XQC_OK);
    CU_ASSERT(mask_len >= sizeof(mask)
              && memcmp(mask, v2_client_hp_mask, sizeof(mask)) == 0);
    xqc_crypto_destroy(crypto);

    crypto = xqc_test_quic_v2_crypto(engine, XQC_TLS13_AES_128_GCM_SHA256,
        v2_server_initial_secret, sizeof(v2_server_initial_secret),
        XQC_KEY_TYPE_RX_READ);
    CU_ASSERT_FATAL(crypto != NULL);
    ckm = &crypto->keys.rx_ckm[0];
    CU_ASSERT(ckm->key.len == sizeof(v2_server_key)
              && memcmp(ckm->key.base, v2_server_key, ckm->key.len) == 0);
    CU_ASSERT(ckm->iv.len == sizeof(v2_server_iv)
              && memcmp(ckm->iv.base, v2_server_iv, ckm->iv.len) == 0);
    CU_ASSERT(crypto->keys.rx_hp.len == sizeof(v2_server_hp)
              && memcmp(crypto->keys.rx_hp.base, v2_server_hp,
                        sizeof(v2_server_hp)) == 0);
    xqc_crypto_destroy(crypto);

    /* the QUIC v1 labels derive other keys from the same secret */
    crypto = xqc_crypto_create(XQC_TLS13_AES_128_GCM_SHA256, engine->log);
    CU_ASSERT_FATAL(crypto != NULL);
    CU_ASSERT_EQUAL(xqc_crypto_derive_keys(crypto, v2_server_initial_secret,
                    sizeof(v2_server_initial_secret), XQC_KEY_TYPE_RX_READ),
                    XQC_OK);
    CU_ASSERT(memcmp(crypto->keys.rx_ckm[0].key.base, v2_server_key,
                     sizeof(v2_server_key)) != 0);
    xqc_crypto_destroy(crypto);

    xqc_engine_destroy(engine);
}


/* RFC 9369 Appendix A.3: protect the server Initial */
void
xqc_test_quic_v2_server_initial(void)
{
    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT_FATAL(engine != NULL);
    xqc_crypto_t *crypto = xqc_test_quic_v2_crypto(engine,
        XQC_TLS13_AES_128_GCM_SHA256, v2_server_initial_secret,
        sizeof(v2_server_initial_secret), XQC_KEY_TYPE_TX_WRITE);
    CU_ASSERT_FATAL(crypto != NULL);

    uint8_t pkt[sizeof(v2_server_packet) + 16];
    size_t hlen = sizeof(v2_server_header);
    size_t clen = 0;
    memcpy(pkt, v2_server_header, hlen);
    CU_ASSERT_EQUAL(xqc_crypto_encrypt_payload(crypto, 1, 0, 0, pkt, hlen,
                    (uint8_t *)v2_server_payload, sizeof(v2_server_payload),
                    pkt + hlen, sizeof(pkt) - hlen, &clen), XQC_OK);
    CU_ASSERT_FATAL(hlen + clen == sizeof(v2_server_packet));
    CU_ASSERT_EQUAL(xqc_crypto_encrypt_header(crypto, XQC_PTYPE_INIT, pkt,
                    pkt + hlen - 2, pkt + hlen + clen), XQC_OK);
    CU_ASSERT(memcmp(pkt, v2_server_packet, sizeof(v2_server_packet)) == 0);

    xqc_crypto_destroy(crypto);
    xqc_engine_destroy(engine);
}


/* RFC 9369 Section 3.3.3 and Appendix A.4: the Retry Integrity Tag */
void
xqc_test_quic_v2_retry_tag(void)
{
    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT_FATAL(engine != NULL);

    /* the Retry pseudo-packet: ODCID Length, ODCID, Retry without tag */
    uint8_t pseudo[1 + sizeof(v2_dcid) + sizeof(v2_retry)];
    size_t retry_len = sizeof(v2_retry) - XQC_RETRY_INTEGRITY_TAG_LEN;
    pseudo[0] = sizeof(v2_dcid);
    memcpy(pseudo + 1, v2_dcid, sizeof(v2_dcid));
    memcpy(pseudo + 1 + sizeof(v2_dcid), v2_retry, retry_len);

    uint8_t tag[XQC_RETRY_INTEGRITY_TAG_LEN] = {0};
    size_t tag_len = 0;
    CU_ASSERT_EQUAL(xqc_tls_cal_retry_integrity_tag(engine->log, pseudo,
                    1 + sizeof(v2_dcid) + retry_len, tag, sizeof(tag),
                    &tag_len, XQC_VERSION_V2), XQC_OK);
    CU_ASSERT_EQUAL(tag_len, XQC_RETRY_INTEGRITY_TAG_LEN);
    CU_ASSERT(memcmp(tag, v2_retry + retry_len, sizeof(tag)) == 0);

    /* the QUIC v1 key and nonce give another tag */
    CU_ASSERT_EQUAL(xqc_tls_cal_retry_integrity_tag(engine->log, pseudo,
                    1 + sizeof(v2_dcid) + retry_len, tag, sizeof(tag),
                    &tag_len, XQC_VERSION_V1), XQC_OK);
    CU_ASSERT(memcmp(tag, v2_retry + retry_len, sizeof(tag)) != 0);

    xqc_engine_destroy(engine);
}


/* RFC 9369 Appendix A.5: ChaCha20-Poly1305 keys, key update, packet */
void
xqc_test_quic_v2_chacha20(void)
{
    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT_FATAL(engine != NULL);
    xqc_crypto_t *crypto = xqc_crypto_create(
        XQC_TLS13_CHACHA20_POLY1305_SHA256, engine->log);
    CU_ASSERT_FATAL(crypto != NULL);
    crypto->quic_v2 = XQC_TRUE;
    CU_ASSERT_EQUAL(xqc_crypto_save_application_traffic_secret_0(crypto,
                    v2_chacha_secret, sizeof(v2_chacha_secret),
                    XQC_KEY_TYPE_TX_WRITE), XQC_OK);
    CU_ASSERT_EQUAL(xqc_crypto_derive_keys(crypto, v2_chacha_secret,
                    sizeof(v2_chacha_secret), XQC_KEY_TYPE_TX_WRITE), XQC_OK);

    xqc_crypto_km_t *ckm = &crypto->keys.tx_ckm[0];
    CU_ASSERT(ckm->key.len == sizeof(v2_chacha_key)
              && memcmp(ckm->key.base, v2_chacha_key, ckm->key.len) == 0);
    CU_ASSERT(ckm->iv.len == sizeof(v2_chacha_iv)
              && memcmp(ckm->iv.base, v2_chacha_iv, ckm->iv.len) == 0);
    CU_ASSERT(crypto->keys.tx_hp.len == sizeof(v2_chacha_hp)
              && memcmp(crypto->keys.tx_hp.base, v2_chacha_hp,
                        sizeof(v2_chacha_hp)) == 0);

    /* a PING with packet number 654360564, encoded on 3 bytes */
    uint8_t pkt[sizeof(v2_chacha_packet) + 16];
    uint8_t ping = 0x01;
    size_t clen = 0;
    memcpy(pkt, "\x42\x00\xbf\xf4", 4);
    CU_ASSERT_EQUAL(xqc_crypto_encrypt_payload(crypto, 654360564, 0, 0,
                    pkt, 4, &ping, 1, pkt + 4, sizeof(pkt) - 4, &clen),
                    XQC_OK);
    CU_ASSERT_FATAL(4 + clen == sizeof(v2_chacha_packet));
    CU_ASSERT_EQUAL(xqc_crypto_encrypt_header(crypto, XQC_PTYPE_SHORT_HEADER,
                    pkt, pkt + 1, pkt + 4 + clen), XQC_OK);
    CU_ASSERT(memcmp(pkt, v2_chacha_packet, sizeof(v2_chacha_packet)) == 0);

    /* the next secret, "quicv2 ku" */
    CU_ASSERT_EQUAL(xqc_crypto_derive_updated_keys(crypto,
                    XQC_KEY_TYPE_TX_WRITE), XQC_OK);
    CU_ASSERT(crypto->keys.tx_ckm[1].secret.len == sizeof(v2_chacha_ku)
              && memcmp(crypto->keys.tx_ckm[1].secret.base, v2_chacha_ku,
                        sizeof(v2_chacha_ku)) == 0);

    xqc_crypto_destroy(crypto);
    xqc_engine_destroy(engine);
}


/* RFC 9368 Section 3: a Version Information, in and out */
void
xqc_test_quic_v2_version_info_codec(void)
{
    xqc_transport_params_t params, dec;
    uint8_t buf[XQC_MAX_TRANSPORT_PARAM_BUF_LEN];
    size_t len = 0;

    xqc_init_transport_params(&params);
    params.version_info_present = 1;
    params.chosen_version = XQC_VERSION_V2_VALUE;
    params.available_versions[0] = XQC_VERSION_V2_VALUE;
    params.available_versions[1] = XQC_VERSION_V1_VALUE;
    params.available_versions_count = 2;
    CU_ASSERT_EQUAL(xqc_encode_transport_params(&params,
                    XQC_TP_TYPE_CLIENT_HELLO, buf, sizeof(buf), &len), XQC_OK);

    memset(&dec, 0, sizeof(dec));
    CU_ASSERT_EQUAL(xqc_decode_transport_params(&dec,
                    XQC_TP_TYPE_CLIENT_HELLO, buf, len), XQC_OK);
    CU_ASSERT(dec.version_info_present == 1);
    CU_ASSERT(dec.chosen_version == XQC_VERSION_V2_VALUE);
    CU_ASSERT(dec.available_versions_count == 2
              && dec.available_versions[0] == XQC_VERSION_V2_VALUE
              && dec.available_versions[1] == XQC_VERSION_V1_VALUE);

    /* absent, it is reported absent */
    params.version_info_present = 0;
    CU_ASSERT_EQUAL(xqc_encode_transport_params(&params,
                    XQC_TP_TYPE_CLIENT_HELLO, buf, sizeof(buf), &len), XQC_OK);
    CU_ASSERT_EQUAL(xqc_decode_transport_params(&dec,
                    XQC_TP_TYPE_CLIENT_HELLO, buf, len), XQC_OK);
    CU_ASSERT(dec.version_info_present == 0);
}


/* RFC 9368 Section 4: the Version Information parsing failures */
void
xqc_test_quic_v2_version_info_malformed(void)
{
    /* the Chosen Version, version 1, out of Available Versions */
    static const uint8_t not_offered[] = {
        0x11, 0x08, 0x00, 0x00, 0x00, 0x01, 0x6b, 0x33, 0x43, 0xcf,
    };
    static const uint8_t no_available[] = {
        0x11, 0x04, 0x00, 0x00, 0x00, 0x01,
    };
    static const uint8_t short_len[] = {
        0x11, 0x03, 0x00, 0x00, 0x01,
    };
    static const uint8_t unaligned[] = {
        0x11, 0x06, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    };
    static const uint8_t zero_chosen[] = {
        0x11, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    };
    static const uint8_t zero_available[] = {
        0x11, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    };
    static const uint8_t twice[] = {
        0x11, 0x04, 0x00, 0x00, 0x00, 0x01,
        0x11, 0x04, 0x00, 0x00, 0x00, 0x01,
    };
    xqc_transport_params_t params;

    /* a server may leave its Chosen Version out, a client may not */
    memset(&params, 0, sizeof(params));
    CU_ASSERT_EQUAL(xqc_decode_transport_params(&params,
                    XQC_TP_TYPE_ENCRYPTED_EXTENSIONS, not_offered,
                    sizeof(not_offered)), XQC_OK);
    CU_ASSERT(params.version_info_present == 1
              && params.chosen_version == XQC_VERSION_V1_VALUE
              && params.available_versions_count == 1);
    CU_ASSERT_EQUAL(xqc_decode_transport_params(&params,
                    XQC_TP_TYPE_CLIENT_HELLO, not_offered,
                    sizeof(not_offered)), -XQC_TLS_MALFORMED_TRANSPORT_PARAM);

    /* the Available Versions of a server may be empty */
    CU_ASSERT_EQUAL(xqc_decode_transport_params(&params,
                    XQC_TP_TYPE_ENCRYPTED_EXTENSIONS, no_available,
                    sizeof(no_available)), XQC_OK);
    CU_ASSERT(params.version_info_present == 1
              && params.available_versions_count == 0);
    CU_ASSERT_EQUAL(xqc_decode_transport_params(&params,
                    XQC_TP_TYPE_CLIENT_HELLO, no_available,
                    sizeof(no_available)), -XQC_TLS_MALFORMED_TRANSPORT_PARAM);

    CU_ASSERT_EQUAL(xqc_decode_transport_params(&params,
                    XQC_TP_TYPE_ENCRYPTED_EXTENSIONS, short_len,
                    sizeof(short_len)), -XQC_TLS_MALFORMED_TRANSPORT_PARAM);
    CU_ASSERT_EQUAL(xqc_decode_transport_params(&params,
                    XQC_TP_TYPE_ENCRYPTED_EXTENSIONS, unaligned,
                    sizeof(unaligned)), -XQC_TLS_MALFORMED_TRANSPORT_PARAM);
    CU_ASSERT_EQUAL(xqc_decode_transport_params(&params,
                    XQC_TP_TYPE_ENCRYPTED_EXTENSIONS, zero_chosen,
                    sizeof(zero_chosen)), -XQC_TLS_MALFORMED_TRANSPORT_PARAM);
    CU_ASSERT_EQUAL(xqc_decode_transport_params(&params,
                    XQC_TP_TYPE_ENCRYPTED_EXTENSIONS, zero_available,
                    sizeof(zero_available)),
                    -XQC_TLS_MALFORMED_TRANSPORT_PARAM);

    /* RFC 9000 Section 7.4: a parameter sent twice */
    CU_ASSERT_EQUAL(xqc_decode_transport_params(&params,
                    XQC_TP_TYPE_ENCRYPTED_EXTENSIONS, twice, sizeof(twice)),
                    -XQC_TLS_MALFORMED_TRANSPORT_PARAM);
}


/*
 * RFC 9369 Section 4: an endpoint that supports version 2 sends its Version
 * Information; RFC 9368 Section 4: the peer's Chosen Version is the version
 * in use.
 */
void
xqc_test_quic_v2_version_info_conn(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_config_t *config = conn->engine->config;
    xqc_transport_params_t params;

    /* a version 1 client without version 2 sends none */
    CU_ASSERT_FATAL(conn->version == XQC_VERSION_V1);
    config->support_version_list[0] = XQC_VERSION_V1_VALUE;
    config->support_version_count = 1;
    memset(&params, 0, sizeof(params));
    xqc_conn_get_local_version_info(conn, &params);
    CU_ASSERT(params.version_info_present == 0);

    /* with version 2, the client offers the version in use alone */
    config->support_version_list[1] = XQC_VERSION_V2_VALUE;
    config->support_version_count = 2;
    xqc_conn_get_local_version_info(conn, &params);
    CU_ASSERT(params.version_info_present == 1
              && params.chosen_version == XQC_VERSION_V1_VALUE
              && params.available_versions_count == 1
              && params.available_versions[0] == XQC_VERSION_V1_VALUE);

    conn->version = XQC_VERSION_V2;
    xqc_conn_get_local_version_info(conn, &params);
    CU_ASSERT(params.version_info_present == 1
              && params.chosen_version == XQC_VERSION_V2_VALUE
              && params.available_versions_count == 1
              && params.available_versions[0] == XQC_VERSION_V2_VALUE);

    /* a server lists the versions it implements, once each */
    config->support_version_list[0] = XQC_VERSION_V2_VALUE;
    config->support_version_list[1] = 0x0a1a2a3a;
    config->support_version_list[2] = XQC_VERSION_V1_VALUE;
    config->support_version_list[3] = XQC_VERSION_V2_VALUE;
    config->support_version_count = 4;
    conn->conn_type = XQC_CONN_TYPE_SERVER;
    xqc_conn_get_local_version_info(conn, &params);
    conn->conn_type = XQC_CONN_TYPE_CLIENT;
    CU_ASSERT(params.version_info_present == 1
              && params.chosen_version == XQC_VERSION_V2_VALUE
              && params.available_versions_count == 2
              && params.available_versions[0] == XQC_VERSION_V2_VALUE
              && params.available_versions[1] == XQC_VERSION_V1_VALUE);

    /* the peer's Chosen Version, absent or equal to the version in use */
    CU_ASSERT_EQUAL(xqc_conn_check_version_info(conn, &params), XQC_OK);
    params.version_info_present = 0;
    CU_ASSERT_EQUAL(xqc_conn_check_version_info(conn, &params), XQC_OK);
    params.version_info_present = 1;
    params.chosen_version = XQC_VERSION_V1_VALUE;
    CU_ASSERT_EQUAL(xqc_conn_check_version_info(conn, &params),
                    -XQC_EVERSION);
    conn->version = XQC_VERSION_V1;
    CU_ASSERT_EQUAL(xqc_conn_check_version_info(conn, &params), XQC_OK);

    xqc_engine_destroy(conn->engine);
}


/* RFC 9369 Section 5: a token is accepted in the version that issued it */
void
xqc_test_quic_v2_token_version(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    unsigned char v1_token[XQC_MAX_TOKEN_LEN], v2_token[XQC_MAX_TOKEN_LEN];
    unsigned v1_len = sizeof(v1_token), v2_len = sizeof(v2_token);

    conn->version = XQC_VERSION_V1;
    CU_ASSERT_EQUAL(xqc_conn_gen_token(conn, v1_token, &v1_len), XQC_OK);
    conn->version = XQC_VERSION_V2;
    CU_ASSERT_EQUAL(xqc_conn_gen_token(conn, v2_token, &v2_len), XQC_OK);

    CU_ASSERT_EQUAL(xqc_conn_check_token(conn, v2_token, v2_len), XQC_OK);
    CU_ASSERT_EQUAL(xqc_conn_check_token(conn, v1_token, v1_len), XQC_ERROR);

    conn->version = XQC_VERSION_V1;
    CU_ASSERT_EQUAL(xqc_conn_check_token(conn, v1_token, v1_len), XQC_OK);
    CU_ASSERT_EQUAL(xqc_conn_check_token(conn, v2_token, v2_len), XQC_ERROR);

    xqc_engine_destroy(conn->engine);
}
