/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_CRYPTO_H_
#define XQC_CRYPTO_H_

#include <xquic/xquic_typedef.h>
#include <openssl/ssl.h>
#include "src/tls/xqc_tls_defs.h"
#include "src/tls/xqc_tls_common.h"
#include "src/transport/xqc_packet.h"

typedef struct xqc_pkt_protect_aead_s      xqc_pkt_protect_aead_t;
typedef struct xqc_hdr_protect_cipher_s    xqc_hdr_protect_cipher_t;

#undef  XQC_CRYPTO_PRIVATE
#define XQC_CRYPTO_PRIVATE

#ifdef OPENSSL_IS_BORINGSSL
#include "src/tls/boringssl/xqc_aead_impl.h"
#else
#include "src/tls/babassl/xqc_aead_impl.h"
#endif

#undef  XQC_CRYPTO_PRIVATE


/* aes_d_gcm  d is the length of key */
#define xqc_aead_init_aes_gcm(aead, d, ...)         XQC_AEAD_INIT_AES_GCM_IMPL(aead, d, __VA_ARGS__)

/* chacha20_poly1305 */
#define xqc_aead_init_chacha20_poly1305(obj, ...)   XQC_AEAD_INIT_CHACHA20_POLY1305_IMPL(obj, __VA_ARGS__)

/* aes_d_ctr */
#define xqc_cipher_init_aes_ctr(cipher, d, ...)     XQC_CIPHER_INIT_AES_CTR_IMPL(cipher, d, __VA_ARGS__)

/* chacha20 */
#define xqc_cipher_init_chacha20(cipher, ...)       XQC_CIPHER_INIT_CHACHA20_IMPL(cipher, __VA_ARGS__)

/* length of aead overhead */
#define xqc_aead_overhead(obj, cln)                 (XQC_AEAD_OVERHEAD_IMPL((obj), cln))

void xqc_aead_init_null(xqc_pkt_protect_aead_t *pp_aead, size_t taglen);
void xqc_cipher_init_null(xqc_hdr_protect_cipher_t *hp_cipher);


/* aead encrypt function */
typedef xqc_int_t (*xqc_aead_encrypt_pt)(const xqc_pkt_protect_aead_t *pp_aead,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *nonce, size_t noncelen,
    const uint8_t *ad, size_t adlen);

/* aead decrypt function */
typedef xqc_int_t (*xqc_aead_decrypt_pt)(const xqc_pkt_protect_aead_t *pp_aead,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *ciphertext, size_t ciphertextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *nonce, size_t noncelen,
    const uint8_t *ad, size_t adlen);

/* hp mask function */
typedef xqc_int_t (*xqc_hp_mask_pt)(const xqc_hdr_protect_cipher_t *hp_cipher,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *sample, size_t samplelen);


struct xqc_pkt_protect_aead_s {
    /*
     * implementation handler for aead
     * boringssl: const EVP_AEAD
     * babassl:   const EVP_CIPHER
     */
    XQC_AEAD_SUITES_IMPL    aead;

    size_t                  keylen;
    size_t                  noncelen;
    size_t                  taglen;

    xqc_aead_encrypt_pt     encrypt;
    xqc_aead_decrypt_pt     decrypt;
};


struct xqc_hdr_protect_cipher_s {
    /*
     * implementation handler for cipher
     * boringssl & babassl: const EVP_CIPHER *
     */
    XQC_CIPHER_SUITES_IMPL  cipher;

    size_t                  keylen;
    size_t                  noncelen;

    xqc_hp_mask_pt          hp_mask;
};

typedef struct xqc_digest_s {
    const EVP_MD *digest ;
} xqc_digest_t;

#define xqc_digest_init_to_sha256(obj)  ((obj)->digest = EVP_sha256())
#define xqc_digest_init_to_sha384(obj)  ((obj)->digest = EVP_sha384())

#define XQC_KEY_PHASE_CNT 2

typedef struct xqc_vec_s {
    uint8_t            *base;     /* pointer of data. */
    size_t              len;      /* byte count of base */
} xqc_vec_t;

typedef struct xqc_crypto_km_s {
    xqc_vec_t           key;
    xqc_vec_t           iv;

    /* application traffic secrets, only use on 1-rtt, for key update */
    xqc_vec_t           secret;
} xqc_crypto_km_t;

typedef struct xqc_crypto_keys_s {
    /* packet payload protect key */
    xqc_crypto_km_t     rx_ckm[XQC_KEY_PHASE_CNT];
    xqc_crypto_km_t     tx_ckm[XQC_KEY_PHASE_CNT];

    /* packet header protect key */
    xqc_vec_t           rx_hp;
    xqc_vec_t           tx_hp;
} xqc_crypto_keys_t;


typedef struct xqc_crypto_s {

    /* aead suites for packet payload protection */
    xqc_pkt_protect_aead_t      pp_aead;

    /* cipher suites for packet header protection */
    xqc_hdr_protect_cipher_t    hp_cipher;

    /* digest suites for hkdf operation */
    xqc_digest_t                md;

    /* every encryption level has its own key,iv and hpkey */
    xqc_crypto_keys_t           keys;

    /* log handler */
    xqc_log_t                  *log;

    /* key phase, 1-RTT : 1 or 0, others is always 0 */
    xqc_uint_t                  key_phase;

} xqc_crypto_t;


/**
 * @brief create crypto instance, initialize aead suites, cipher suites and digest suites
 */
xqc_crypto_t *xqc_crypto_create(uint32_t cipher_id, xqc_log_t *log);

/**
 * @brief destroy crypto instance
 */
void xqc_crypto_destroy(xqc_crypto_t *crypto);

/**
 * @brief install keys from secret
 */
xqc_int_t xqc_crypto_derive_keys(xqc_crypto_t *crypto, const uint8_t *secret, size_t secretlen,
    xqc_key_type_t type);

/**
 * @brief save application traffic secret for key update
 */
xqc_int_t xqc_crypto_save_application_traffic_secret_0(xqc_crypto_t *crypto,
    const uint8_t *secret, size_t secretlen, xqc_key_type_t type);

/**
 * @brief query is protection key is ready
 */
xqc_bool_t xqc_crypto_is_key_ready(xqc_crypto_t *crypto, xqc_key_type_t type);

/**
 * @brief encrypt packet payload
 *
 * @param crypto 
 * @param dst destination buffer
 * @param dst_cap capacity of dst
 * @param dst_len written length
 * @return XQC_OK for success, others for failure
 */
xqc_int_t xqc_crypto_encrypt_payload(xqc_crypto_t *crypto, uint64_t pktno, xqc_uint_t key_phase,
    uint8_t *header, size_t header_len, uint8_t *payload, size_t payload_len,
    uint8_t *dst, size_t dst_cap, size_t *dst_len);

/**
 * @brief decrypt packet payload
 * 
 * @param crypto 
 * @param header decrypted packet header
 * @param header_len decrypted packet header length
 * @param dst destination buffer for decrypted payload
 * @param dst_cap capacity of destination buffer
 * @param dst_len length of decrypted payload
 * @return xqc_int_t 
 */
xqc_int_t xqc_crypto_decrypt_payload(xqc_crypto_t *crypto, uint64_t pktno, xqc_uint_t key_phase,
    uint8_t *header, size_t header_len, uint8_t *payload, size_t payload_len,
    uint8_t *dst, size_t dst_cap, size_t *dst_len);

/**
 * @brief apply header protection
 * 
 * @param crypto 
 * @param header header to be protected with subsequent encrypted payload buffer, after header 
 * protection, the first byte and packet number will be modified and protected with mask.
 * @param pktno position of packet number
 * @param end end position of buffer
 * @return XQC_OK for success, others for failure 
 */
xqc_int_t xqc_crypto_encrypt_header(xqc_crypto_t *crypto, xqc_pkt_type_t pkt_type, uint8_t *header,
    uint8_t *pktno, uint8_t *end);

/**
 * @brief remove header protection
 * 
 * @param crypto 
 * @param header header buffer to be remove header protection, after remove, the first byte and 
 * packet number will be modified and restored
 * @param pktno position of packet number
 * @param end end position of buffer
 * @return XQC_OK for success, others for failure 
 */
xqc_int_t xqc_crypto_decrypt_header(xqc_crypto_t *crypto, xqc_pkt_type_t pkt_type, uint8_t *header,
    uint8_t *pktno, uint8_t *end);

/**
 * @brief derive initial level secret
 */
xqc_int_t xqc_crypto_derive_initial_secret(
    uint8_t *cli_initial_secret, size_t cli_initial_secret_len,
    uint8_t *svr_initial_secret, size_t svr_initial_secret_len,
    const xqc_cid_t *cid, const uint8_t *salt, size_t saltlen);


ssize_t xqc_crypto_aead_tag_len(xqc_crypto_t *crypto);


/**
 * @brief derive updated secrets and read/write keys on 1-RTT
 */
xqc_int_t xqc_crypto_derive_updated_keys(xqc_crypto_t *crypto, xqc_key_type_t type);

/**
 * @brief discard the old read and write keys on 1-RTT
 */
void xqc_crypto_discard_old_keys(xqc_crypto_t *crypto);


#endif