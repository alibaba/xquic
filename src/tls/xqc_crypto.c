/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/tls/xqc_crypto.h"
#include "src/tls/xqc_hkdf.h"
#include "src/common/xqc_str.h"
#include "src/common/xqc_malloc.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"


#define XQC_NONCE_LEN        16
#define XQC_HP_SAMPLELEN     16
#define XQC_HP_MASKLEN       5

#define XQC_FAKE_HP_MASK        "\x00\x00\x00\x00\x00"
#define XQC_FAKE_AEAD_OVERHEAD  XQC_TLS_AEAD_OVERHEAD_MAX_LEN

static inline void
xqc_vec_init(xqc_vec_t *vec)
{
    vec->base = NULL;
    vec->len = 0;
}

static inline void
xqc_vec_free(xqc_vec_t *vec)
{
    if (vec->base) {
        xqc_free(vec->base);
    }

    vec->base = NULL;
    vec->len = 0;
}

static inline xqc_int_t
xqc_vec_assign(xqc_vec_t * vec, const uint8_t * data, size_t data_len)
{
    vec->base = xqc_malloc(data_len);
    if (vec->base == NULL) {
        return -XQC_EMALLOC;
    }
    memcpy(vec->base, data, data_len);
    vec->len = data_len;
    return XQC_OK;
}

static inline void
xqc_ckm_init(xqc_crypto_km_t *ckm)
{
    xqc_vec_init(&ckm->secret);
    xqc_vec_init(&ckm->key);
    xqc_vec_init(&ckm->iv);
}

static inline void
xqc_ckm_free(xqc_crypto_km_t *ckm)
{
    xqc_vec_free(&ckm->secret);
    xqc_vec_free(&ckm->key);
    xqc_vec_free(&ckm->iv);
}

/* set aead suites, cipher suites and digest suites */
xqc_crypto_t *
xqc_crypto_create(uint32_t cipher_id, xqc_log_t *log)
{
    xqc_crypto_t *crypto = xqc_malloc(sizeof(xqc_crypto_t));
    if (crypto == NULL) {
        return NULL;
    }

    crypto->log = log;
    crypto->key_phase = 0;

    xqc_vec_init(&crypto->keys.tx_hp);
    xqc_vec_init(&crypto->keys.rx_hp);

    for (int i = 0; i < XQC_KEY_PHASE_CNT; i++) {
        xqc_ckm_init(&crypto->keys.tx_ckm[i]);
        xqc_ckm_init(&crypto->keys.rx_ckm[i]);
    }

    switch (cipher_id) {
    /* TLS_AES_128_GCM_SHA256 */
    case XQC_TLS13_AES_128_GCM_SHA256:
        xqc_aead_init_aes_gcm(&crypto->pp_aead, 128);
        xqc_cipher_init_aes_ctr(&crypto->hp_cipher, 128);
        xqc_digest_init_to_sha256(&crypto->md);
        break;

    /* TLS_AES_256_GCM_SHA384 */
    case XQC_TLS13_AES_256_GCM_SHA384:
        xqc_aead_init_aes_gcm(&crypto->pp_aead, 256);
        xqc_cipher_init_aes_ctr(&crypto->hp_cipher, 256);
        xqc_digest_init_to_sha384(&crypto->md);
        break;

    /* TLS_CHACHA20_POLY1305_SHA256 */
    case XQC_TLS13_CHACHA20_POLY1305_SHA256:
        xqc_aead_init_chacha20_poly1305(&crypto->pp_aead);
        xqc_cipher_init_chacha20(&crypto->hp_cipher);
        xqc_digest_init_to_sha256(&crypto->md);
        break;

    case NID_undef:
        xqc_aead_init_null(&crypto->pp_aead, XQC_FAKE_AEAD_OVERHEAD);
        xqc_cipher_init_null(&crypto->hp_cipher);
        xqc_digest_init_to_sha256(&crypto->md);
        break;

    default: /* TLS_AES_128_CCM_SHA256、TLS_AES_128_CCM_8_SHA256 not support */
        xqc_log(log, XQC_LOG_ERROR, "|not supoort cipher_id|%u|", cipher_id);
        xqc_free(crypto);
        return NULL;
    }

    return crypto;
}

void
xqc_crypto_destroy(xqc_crypto_t *crypto)
{
    if (crypto) {
        xqc_vec_free(&crypto->keys.tx_hp);
        xqc_vec_free(&crypto->keys.rx_hp);

        for (int i = 0; i < XQC_KEY_PHASE_CNT; i++) {
            xqc_ckm_free(&crypto->keys.tx_ckm[i]);
            xqc_ckm_free(&crypto->keys.rx_ckm[i]);
        }

        xqc_free(crypto);
    }
}

void
xqc_crypto_create_nonce(uint8_t *dest, const uint8_t *iv, size_t ivlen, uint64_t pktno)
{
    size_t i;

    memcpy(dest, iv, ivlen);
    pktno = bswap64(pktno);

    /* nonce is formed by combining the packet protection IV with the packet number */
    for (i = 0; i < 8; ++i) {
        dest[ivlen - 8 + i] ^= ((uint8_t *)&pktno)[i];
    }
}


xqc_int_t
xqc_crypto_encrypt_header(xqc_crypto_t *crypto, xqc_pkt_type_t pkt_type, uint8_t *header,
    uint8_t *pktno, uint8_t *end)
{
    xqc_int_t       ret;

    uint8_t         mask[XQC_HP_MASKLEN];
    size_t          nwrite;

    /* packet number position and sample position */
    size_t   pktno_len  = XQC_PACKET_SHORT_HEADER_PKTNO_LEN(header);
    uint8_t *sample     = pktno + 4;

    /* hp cipher and key */
    xqc_hdr_protect_cipher_t *hp_cipher = &crypto->hp_cipher;
    xqc_vec_t *hp  = &crypto->keys.tx_hp;
    if (hp_cipher == NULL || hp->base == NULL || hp->len == 0) {
        xqc_log(crypto->log, XQC_LOG_ERROR, "|hp encrypt key NULL|");
        return -XQC_EENCRYPT;
    }

    /* get length of packet number */
    if (pktno + pktno_len > end) {
        xqc_log(crypto->log, XQC_LOG_ERROR, "|illegal pkt, pkt num exceed buffer");
        return -XQC_EILLPKT;
    }

    /* generate header protection mask */
    ret = hp_cipher->hp_mask(hp_cipher,
                             mask, XQC_HP_MASKLEN, &nwrite,                  /* mask */
                             XQC_FAKE_HP_MASK, sizeof(XQC_FAKE_HP_MASK) - 1, /* plaintext */
                             hp->base, hp->len,                              /* key */
                             sample, XQC_HP_SAMPLELEN);                      /* sample */
    if (ret != XQC_OK || nwrite < XQC_HP_MASKLEN) {
        xqc_log(crypto->log, XQC_LOG_ERROR,
                "|calculate header protection mask error|ret:%d|nwrite:%z|", ret, nwrite);
        return -XQC_EENCRYPT;
    }

    /* protect the first byte of header */
    if (pkt_type == XQC_PTYPE_SHORT_HEADER) {
        *header = (uint8_t)(*header ^ (mask[0] & 0x1f));

    } else {
        *header = (uint8_t)(*header ^ (mask[0] & 0x0f));
    }

    /* protect packet number */
    for (size_t i = 0; i < pktno_len; ++i) {
        *(pktno + i) ^= mask[i + 1];
    }

    return XQC_OK;
}


xqc_int_t
xqc_crypto_decrypt_header(xqc_crypto_t *crypto, xqc_pkt_type_t pkt_type, uint8_t *header,
    uint8_t *pktno, uint8_t *end)
{
    xqc_int_t ret;
    size_t nwrite;

    /* header protection cipher and rx hp key */
    xqc_hdr_protect_cipher_t *hp_cipher = &crypto->hp_cipher;
    xqc_vec_t *hp = &crypto->keys.rx_hp;
    if (hp->base == NULL || hp->len == 0) {
        xqc_log(crypto->log, XQC_LOG_ERROR, "|hp rx key NULL|");
        return -XQC_TLS_DECRYPT_DATA_ERROR;
    }

    /* generate hp mask */
    uint8_t mask[XQC_HP_MASKLEN];
    uint8_t *sample = pktno + 4;
    ret = hp_cipher->hp_mask(hp_cipher,
                             mask, XQC_HP_MASKLEN, &nwrite,                     /* mask */
                             XQC_FAKE_HP_MASK, sizeof(XQC_FAKE_HP_MASK) - 1,    /* ciphertext */
                             hp->base, hp->len,                                 /* key */
                             sample, XQC_HP_SAMPLELEN);                         /* sample */
    if (ret != XQC_OK || nwrite < XQC_HP_MASKLEN) {
        xqc_log(crypto->log, XQC_LOG_ERROR, "|calculate header protection mask error|ret:%d|"
                "nwrite:%z|", ret, nwrite);
        return -XQC_TLS_DECRYPT_DATA_ERROR;
    }

    /* remove protection for first byte */
    if (pkt_type == XQC_PTYPE_SHORT_HEADER) {
        header[0] = (uint8_t)(header[0] ^ (mask[0] & 0x1f));

    } else {
        header[0] = (uint8_t)(header[0] ^ (mask[0] & 0x0f));
    }

    /* get length of packet number */
    size_t pktno_len = XQC_PACKET_SHORT_HEADER_PKTNO_LEN(header);
    if (pktno + pktno_len > end) {
        xqc_log(crypto->log, XQC_LOG_ERROR, "|illegal pkt, pkt num exceed buffer");
        return -XQC_EILLPKT;
    }

    /* remove protection for packet number */
    for (size_t i = 0; i < pktno_len; ++i) {
        pktno[i] = pktno[i] ^ mask[i + 1];
    }

    return XQC_OK;
}


xqc_int_t
xqc_crypto_encrypt_payload(xqc_crypto_t *crypto, uint64_t pktno, xqc_uint_t key_phase,
    uint8_t *header, size_t header_len, uint8_t *payload, size_t payload_len,
    uint8_t *dst, size_t dst_cap, size_t *dst_len)
{
    xqc_int_t ret;
    uint8_t nonce[XQC_NONCE_LEN];

    /* aead function and tx key */
    xqc_pkt_protect_aead_t *pp_aead = &crypto->pp_aead;
    xqc_crypto_km_t        *ckm     = &crypto->keys.tx_ckm[key_phase];
    if (ckm->key.base == NULL || ckm->key.len == 0
        || ckm->iv.base == NULL || ckm->iv.len == 0)
    {
        xqc_log(crypto->log, XQC_LOG_ERROR, "|pp encrypt key NULL|key_phase:%ui|", key_phase);
        return -XQC_TLS_ENCRYPT_DATA_ERROR;
    }

    /* generate nonce for aead encryption with original packet number */
    xqc_crypto_create_nonce(nonce, ckm->iv.base, ckm->iv.len, pktno);

    /* do aead encryption */
    ret = pp_aead->encrypt(pp_aead, dst, dst_cap, dst_len,         /* dest */
                           payload, payload_len,          /* plaintext */
                           ckm->key.base, ckm->key.len,   /* tx key */
                           nonce, ckm->iv.len,            /* nonce and iv */
                           header, header_len);           /* ad */
    if (ret != XQC_OK
        || *dst_len != (payload_len + xqc_aead_overhead(pp_aead, payload_len)))
    {
        xqc_log(crypto->log, XQC_LOG_ERROR,
                "|encrypt packet error|ret:%d|nwrite:%z|", ret, *dst_len);
        return -XQC_TLS_ENCRYPT_DATA_ERROR;
    }

    return XQC_OK;
}


xqc_int_t
xqc_crypto_decrypt_payload(xqc_crypto_t *crypto, uint64_t pktno, xqc_uint_t key_phase,
    uint8_t *header, size_t header_len, uint8_t *payload, size_t payload_len,
    uint8_t *dst, size_t dst_cap, size_t *dst_len)
{
    xqc_int_t ret;
    uint8_t nonce[XQC_NONCE_LEN];

    /* keys for decryption */
    xqc_pkt_protect_aead_t *pp_aead = &crypto->pp_aead;
    xqc_crypto_km_t        *ckm     = &crypto->keys.rx_ckm[key_phase];
    if (ckm->key.base == NULL || ckm->key.len == 0
        || ckm->iv.base == NULL || ckm->iv.len == 0)
    {
        xqc_log(crypto->log, XQC_LOG_ERROR, "|decrypt key NULL|key_phase:%ui|", key_phase);
        return -XQC_TLS_DECRYPT_DATA_ERROR;
    }

    /* create nonce */
    xqc_crypto_create_nonce(nonce, ckm->iv.base, ckm->iv.len, pktno);

    /* do aead decryption */
    ret = pp_aead->decrypt(pp_aead,
                           dst, dst_cap, dst_len,       /* dest */
                           payload, payload_len,        /* ciphertext */
                           ckm->key.base, ckm->key.len, /* rx key */
                           nonce, ckm->iv.len,          /* nonce and iv */
                           header, header_len);         /* ad */
    if (ret != XQC_OK
        || *dst_len != (payload_len - xqc_aead_overhead(pp_aead, payload_len)))
    {
        /* decrypt error might be common */
        xqc_log(crypto->log, XQC_LOG_INFO,
                "|decrypt payload error|ret:%d|write:%z|", ret, *dst_len);
        return -XQC_TLS_DECRYPT_DATA_ERROR;
    }

    return XQC_OK;
}


/* derive packet protection keys and store them in xqc_crypto_t */

xqc_int_t
xqc_crypto_derive_packet_protection_key(xqc_crypto_t *crypto, uint8_t *dest, size_t destcap,
    size_t *destlen, const uint8_t *secret, size_t secretlen)
{
    static uint8_t LABEL[] = "quic key";

    size_t keylen = crypto->pp_aead.keylen;
    if (keylen > destcap) {
        return -XQC_TLS_DERIVE_KEY_ERROR;
    }

    xqc_int_t ret = xqc_hkdf_expand_label(dest, keylen, secret, secretlen,
                                          LABEL, xqc_lengthof(LABEL), &crypto->md);
    if (ret != XQC_OK) {
        return -XQC_TLS_DERIVE_KEY_ERROR;
    }

    *destlen = keylen;
    return XQC_OK;
}

xqc_int_t
xqc_crypto_derive_packet_protection_iv(xqc_crypto_t *crypto, uint8_t *dest, size_t destcap,
    size_t *destlen, const uint8_t *secret, size_t secretlen)
{
    static uint8_t LABEL[] = "quic iv";

    /* 
     * he Length provided with "quic iv" is the minimum length of the AEAD nonce
     * or 8 bytes if that is larger 
     */
    size_t ivlen = xqc_max(8, crypto->pp_aead.noncelen);
    if (ivlen > destcap) {
        return -XQC_TLS_DERIVE_KEY_ERROR;
    }

    xqc_int_t ret = xqc_hkdf_expand_label(dest, ivlen, secret, secretlen,
                                          LABEL, xqc_lengthof(LABEL), &crypto->md);
    if (ret != XQC_OK) {
        return -XQC_TLS_DERIVE_KEY_ERROR;
    }

    *destlen = ivlen;
    return XQC_OK;
}

xqc_int_t
xqc_crypto_derive_header_protection_key(xqc_crypto_t *crypto, uint8_t *dest, size_t destcap,
    size_t *destlen, const uint8_t *secret, size_t secretlen)
{
    static uint8_t LABEL[] = "quic hp";

    size_t keylen = crypto->hp_cipher.keylen;
    if (keylen > destcap) {
        return -XQC_TLS_DERIVE_KEY_ERROR;
    }

    xqc_int_t ret = xqc_hkdf_expand_label(dest, keylen, secret, secretlen,
                                          LABEL, xqc_lengthof(LABEL), &crypto->md);
    if (ret != XQC_OK) {
        return -XQC_TLS_DERIVE_KEY_ERROR;
    }

    *destlen = keylen;
    return XQC_OK;
}

#define XQC_MAX_KNP_LEN 64

xqc_int_t
xqc_crypto_derive_keys(xqc_crypto_t *crypto, const uint8_t *secret, size_t secretlen,
    xqc_key_type_t type)
{
    /* derive packet protection keys (includes key & iv & hp) */
    uint8_t key[XQC_MAX_KNP_LEN] = {0}, iv[XQC_MAX_KNP_LEN] = {0}, hp[XQC_MAX_KNP_LEN] = {0}; 
    size_t  keycap = XQC_MAX_KNP_LEN,   ivcap = XQC_MAX_KNP_LEN,   hpcap = XQC_MAX_KNP_LEN;
    size_t  keylen = 0,                 ivlen = 0,                 hplen = 0;

    xqc_int_t ret;

    ret = xqc_crypto_derive_packet_protection_key(crypto, key, keycap, &keylen, secret, secretlen);
    if (ret != XQC_OK || keylen <= 0) {
        xqc_log(crypto->log, XQC_LOG_ERROR,
                "|xqc_crypto_derive_packet_protection_key failed|ret:%d|", ret);
        return ret;
    }


    ret = xqc_crypto_derive_packet_protection_iv(crypto, iv, ivcap, &ivlen, secret, secretlen);
    if (ret != XQC_OK || ivlen <= 0) {
        xqc_log(crypto->log, XQC_LOG_ERROR,
                "|xqc_crypto_derive_packet_protection_iv failed|ret:%d|", ret);
        return ret;
    }

    ret = xqc_crypto_derive_header_protection_key(crypto, hp, hpcap, &hplen, secret, secretlen);
    if (ret != XQC_OK || hplen <= 0) {
        xqc_log(crypto->log, XQC_LOG_ERROR,
                "|xqc_crypto_derive_header_protection_key failed|ret:%d|", ret);
        return ret;
    }

    /* store keys */
    xqc_crypto_km_t *p_ckm = NULL;
    xqc_vec_t *p_hp = NULL;

    switch (type) {
    case XQC_KEY_TYPE_RX_READ:
        p_ckm = &crypto->keys.rx_ckm[crypto->key_phase];
        p_hp = &crypto->keys.rx_hp;
        break;

    case XQC_KEY_TYPE_TX_WRITE:
        p_ckm = &crypto->keys.tx_ckm[crypto->key_phase];
        p_hp = &crypto->keys.tx_hp;
        break;

    default:
        xqc_log(crypto->log, XQC_LOG_ERROR, "|illegal crypto secret type|type:%d|", type);
        return -XQC_TLS_INVALID_ARGUMENT;
    }

    /* if already have keys, delete them and use new one */
    if (p_ckm->key.base != NULL && p_ckm->key.len > 0) {
        xqc_vec_free(&p_ckm->key);
    }

    if (p_ckm->iv.base != NULL && p_ckm->iv.len > 0) {
        xqc_vec_free(&p_ckm->iv);
    }

    if (p_hp->base != NULL && p_hp->len > 0) {
        xqc_vec_free(p_hp);
    }


    if (xqc_vec_assign(&p_ckm->key, key, keylen) != XQC_OK) {
        return -XQC_TLS_DERIVE_KEY_ERROR;
    }

    if (xqc_vec_assign(&p_ckm->iv, iv, ivlen) != XQC_OK) {
        return -XQC_TLS_DERIVE_KEY_ERROR;
    }

    if (xqc_vec_assign(p_hp, hp, hplen) != XQC_OK) {
        return -XQC_TLS_DERIVE_KEY_ERROR;
    }

    return XQC_OK;
}

xqc_int_t
xqc_crypto_save_application_traffic_secret_0(xqc_crypto_t *crypto,
    const uint8_t *secret, size_t secretlen, xqc_key_type_t type)
{
    xqc_crypto_km_t *ckm;
    switch (type) {
    case XQC_KEY_TYPE_RX_READ:
        ckm = &crypto->keys.rx_ckm[crypto->key_phase];
        break;

    case XQC_KEY_TYPE_TX_WRITE:
        ckm = &crypto->keys.tx_ckm[crypto->key_phase];
        break;
    
    default:
        xqc_log(crypto->log, XQC_LOG_ERROR, "|illegal crypto secret type|type:%d|", type);
        return -XQC_TLS_INVALID_ARGUMENT;
    }

    xqc_vec_assign(&ckm->secret, secret, secretlen);
    return XQC_OK;
}

xqc_bool_t
xqc_crypto_is_key_ready(xqc_crypto_t *crypto, xqc_key_type_t type)
{
    xqc_crypto_km_t *km;
    xqc_vec_t *hp;

    if (type == XQC_KEY_TYPE_RX_READ) {
        km = &crypto->keys.rx_ckm[crypto->key_phase];
        hp = &crypto->keys.rx_hp;

    } else {
        km = &crypto->keys.tx_ckm[crypto->key_phase];
        hp = &crypto->keys.tx_hp;
    }

    if (!km->key.base || km->key.len == 0
        || !km->iv.base || km->iv.len == 0)
    {
        return XQC_FALSE;
    }

    if (!hp->base || hp->len == 0) {
        return XQC_FALSE;
    }

    return XQC_TRUE;
}


/* derive initial secret (for initial encryption level) */

xqc_int_t
xqc_crypto_derive_initial_secret(uint8_t *cli_initial_secret, size_t cli_initial_secret_len,
    uint8_t *svr_initial_secret, size_t svr_initial_secret_len, const xqc_cid_t *cid,
    const uint8_t *salt, size_t saltlen)
{
    static uint8_t LABEL_SVR_IN[] = "server in";
    static uint8_t LABEL_CLI_IN[] = "client in";
    uint8_t initial_secret[INITIAL_SECRET_MAX_LEN] = {0};   /* the common initial secret */

    xqc_digest_t md;
    xqc_digest_init_to_sha256(&md);

    /* initial secret */
    xqc_int_t ret = xqc_hkdf_extract(initial_secret, INITIAL_SECRET_MAX_LEN, cid->cid_buf,
                                     cid->cid_len, salt, saltlen, &md);
    if (ret != XQC_OK) {
        return ret;
    }

    /* derive client initial secret for packet protection */
    ret = xqc_hkdf_expand_label(cli_initial_secret, cli_initial_secret_len,
                                initial_secret, INITIAL_SECRET_MAX_LEN,
                                LABEL_CLI_IN, xqc_lengthof(LABEL_CLI_IN), &md);
    if (ret != XQC_OK) {
        return ret;
    }

    /* derive server initial secret for packet protection */
    ret = xqc_hkdf_expand_label(svr_initial_secret, svr_initial_secret_len,
                                initial_secret, INITIAL_SECRET_MAX_LEN,
                                LABEL_SVR_IN, xqc_lengthof(LABEL_SVR_IN), &md);
    if (ret != XQC_OK) {
        return ret;
    }

    return XQC_OK;
}


ssize_t
xqc_crypto_aead_tag_len(xqc_crypto_t *crypto)
{
    return crypto->pp_aead.taglen;
}

xqc_int_t
xqc_crypto_derive_updated_keys(xqc_crypto_t *crypto, xqc_key_type_t type)
{
    xqc_int_t ret;

    xqc_uint_t current_key_phase = crypto->key_phase;
    xqc_uint_t updated_key_phase = current_key_phase ^ 1;

    xqc_crypto_km_t *current_ckm, *updated_ckm;
    switch (type) {
    case XQC_KEY_TYPE_RX_READ:
        current_ckm = &crypto->keys.rx_ckm[current_key_phase];
        updated_ckm = &crypto->keys.rx_ckm[updated_key_phase];
        break;

    case XQC_KEY_TYPE_TX_WRITE:
        current_ckm = &crypto->keys.tx_ckm[current_key_phase];
        updated_ckm = &crypto->keys.tx_ckm[updated_key_phase];
        break;

    default:
        xqc_log(crypto->log, XQC_LOG_ERROR, "|illegal crypto secret type|type:%d|", type);
        return -XQC_TLS_INVALID_ARGUMENT;
    }


    /* update application traffic secret */
    static uint8_t LABEL[] = "quic ku";
    uint8_t dest_buf[INITIAL_SECRET_MAX_LEN];

    ret = xqc_hkdf_expand_label(dest_buf, INITIAL_SECRET_MAX_LEN,
                                current_ckm->secret.base, current_ckm->secret.len,
                                LABEL, xqc_lengthof(LABEL), &crypto->md);
    if (ret != XQC_OK) {
        return -XQC_TLS_UPDATE_KEY_ERROR;
    }
    xqc_vec_assign(&updated_ckm->secret, dest_buf, current_ckm->secret.len);


    /* derive packet protection key with new secret */
    uint8_t key[XQC_MAX_KNP_LEN] = {0}, iv[XQC_MAX_KNP_LEN] = {0}; 
    size_t  keycap = XQC_MAX_KNP_LEN,   ivcap = XQC_MAX_KNP_LEN;
    size_t  keylen = 0,                 ivlen = 0;

    ret = xqc_crypto_derive_packet_protection_key(crypto, key, keycap, &keylen,
                                                  updated_ckm->secret.base,
                                                  updated_ckm->secret.len);
    if (ret != XQC_OK || keylen <= 0) {
        xqc_log(crypto->log, XQC_LOG_ERROR,
                "|xqc_crypto_derive_packet_protection_key failed|ret:%d|", ret);
        return -XQC_TLS_UPDATE_KEY_ERROR;
    }

    ret = xqc_crypto_derive_packet_protection_iv(crypto, iv, ivcap, &ivlen,
                                                 updated_ckm->secret.base,
                                                 updated_ckm->secret.len);
    if (ret != XQC_OK || ivlen <= 0) {
        xqc_log(crypto->log, XQC_LOG_ERROR,
                "|xqc_crypto_derive_packet_protection_iv failed|ret:%d|", ret);
        return -XQC_TLS_UPDATE_KEY_ERROR;
    }

    if (xqc_vec_assign(&updated_ckm->key, key, keylen) != XQC_OK) {
        return -XQC_TLS_UPDATE_KEY_ERROR;
    }

    if (xqc_vec_assign(&updated_ckm->iv, iv, ivlen) != XQC_OK) {
        return -XQC_TLS_UPDATE_KEY_ERROR;
    }

    return XQC_OK;
}

void
xqc_crypto_discard_old_keys(xqc_crypto_t *crypto)
{
    xqc_uint_t discard_key_phase = crypto->key_phase ^ 1;

    xqc_ckm_free(&crypto->keys.rx_ckm[discard_key_phase]);
    xqc_ckm_free(&crypto->keys.tx_ckm[discard_key_phase]);
}
