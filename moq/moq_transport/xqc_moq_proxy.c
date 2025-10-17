
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "moq/moq_transport/xqc_moq_proxy.h"
#include "moq/moq_transport/xqc_moq_session.h"

#define XQC_MOQ_PROXY_IV_BUFF_SIZE 16
#define XQC_MOQ_PROXY_IV_LEN 6
#define XQC_MOQ_PROXY_ENCRYPT_LEN 8
#define XQC_MOQ_PROXY_CID_LEN (XQC_MOQ_PROXY_IV_LEN + XQC_MOQ_PROXY_ENCRYPT_LEN)

xqc_int_t
xqc_moq_encode_cid_ipv4(uint32_t ip,/* Network order */ uint16_t port, /* Network order */
   const uint8_t *secret_key, uint8_t cid_len, uint8_t *encrypted_cid)
{
    EVP_CIPHER_CTX *ctx;
    xqc_int_t len;
    uint8_t iv[XQC_MOQ_PROXY_IV_BUFF_SIZE] = {0};
    uint8_t encrypt[XQC_MOQ_PROXY_ENCRYPT_LEN];

    /* Currently only 14-byte cid is supported */
    if (cid_len != XQC_MOQ_PROXY_CID_LEN) {
        return -MOQ_PROTOCOL_VIOLATION;
    }
    if (RAND_bytes(encrypted_cid, cid_len) != 1) {
        return -MOQ_INTERNAL_ERROR;
    }

    /* The first 4 bits are used as version */
    encrypted_cid[0] &= 0x0F;

    /* The first 6 bytes are used as iv */
    memcpy(iv, encrypted_cid, XQC_MOQ_PROXY_IV_LEN);

    /* byte[4~5]: Check bytes */
    /* byte[6~7]: Encrypted check bytes */
    /* byte[8~11]: Encrypted ip */
    /* byte[12~13]: Encrypted port */
    encrypt[0] = encrypted_cid[4];
    encrypt[1] = encrypted_cid[5];
    encrypt[2] = (uint8_t)((ip >> 24) & 0xFF);
    encrypt[3] = (uint8_t)((ip >> 16) & 0xFF);
    encrypt[4] = (uint8_t)((ip >> 8) & 0xFF);
    encrypt[5] = (uint8_t)(ip & 0xFF);
    encrypt[6] = (uint8_t)((port >> 8) & 0xFF);
    encrypt[7] = (uint8_t)(port & 0xFF);

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return -MOQ_INTERNAL_ERROR;
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, secret_key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -MOQ_INTERNAL_ERROR;
    }

    if (1 != EVP_EncryptUpdate(ctx, encrypted_cid + XQC_MOQ_PROXY_IV_LEN, &len, encrypt, XQC_MOQ_PROXY_ENCRYPT_LEN)) {
        EVP_CIPHER_CTX_free(ctx);
        return -MOQ_INTERNAL_ERROR;
    }

    if (len != XQC_MOQ_PROXY_ENCRYPT_LEN) {
        return -MOQ_INTERNAL_ERROR;
    }

    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

xqc_int_t
xqc_moq_decode_cid_ipv4(const uint8_t *encrypted_cid, uint8_t cid_len, const uint8_t *secret_key, 
    uint32_t *ip, /* Network order */ uint16_t *port /* Network order */)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    uint8_t iv[XQC_MOQ_PROXY_IV_BUFF_SIZE] = {0};
    uint8_t decrypted[XQC_MOQ_PROXY_ENCRYPT_LEN] = {0};
    uint8_t version;
    *ip = 0;
    *port = 0;

    /* Currently only 14-byte cid is supported */
    if (cid_len != XQC_MOQ_PROXY_CID_LEN) {
        return -MOQ_PROTOCOL_VIOLATION;
    }

    /* The first 4 bits are used as version */
    version = encrypted_cid[0] & 0xF0;
    if (version != 0) {
        return -MOQ_PROTOCOL_VIOLATION;
    }

    /* The first 6 bytes are used as iv */
    memcpy(iv, encrypted_cid, XQC_MOQ_PROXY_IV_LEN);

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return -MOQ_INTERNAL_ERROR;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, secret_key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -MOQ_INTERNAL_ERROR;
    }

    /* The last 6 bytes are used as encrypted check bytes and encrypted token */
    if (1 != EVP_DecryptUpdate(ctx, decrypted, &len, encrypted_cid + XQC_MOQ_PROXY_IV_LEN, XQC_MOQ_PROXY_ENCRYPT_LEN)) {
        EVP_CIPHER_CTX_free(ctx);
        return -MOQ_INTERNAL_ERROR;
    }

    if (len != XQC_MOQ_PROXY_ENCRYPT_LEN) {
        return -MOQ_INTERNAL_ERROR;
    }

    if (decrypted[0] != encrypted_cid[4] || decrypted[1] != encrypted_cid[5]) {
        return -MOQ_UNAUTHORIZED;
    }
    
    *ip |= ((uint32_t)decrypted[2] << 24);
    *ip |= ((uint32_t)decrypted[3] << 16);
    *ip |= ((uint32_t)decrypted[4] << 8);
    *ip |= ((uint32_t)decrypted[5]);
    *port |= ((uint16_t)decrypted[6] << 8);
    *port |= ((uint16_t)decrypted[7]);

    EVP_CIPHER_CTX_free(ctx);

    return 0;
}