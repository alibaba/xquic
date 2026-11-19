#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <xquic/xquic.h>
#include "src/transport/xqc_engine.h"


#define XQC_EN_SINGLE_PASS_ENCRYPTION_LEN 16

#define XQC_FIRST_OCTET 1

/* octets of a half of the longest four-pass plaintext, 19 octets */
#define XQC_LB_HALF_MAX_LEN ((XQC_MAX_CID_LEN - XQC_FIRST_OCTET + 1) / 2)

/* Each encrypted CID creates and releases a cipher ctx, which may occupies cpu resources a lot. It should be optimaized in the future.*/
xqc_int_t
xqc_cid_encryption_aes_128_ecb(unsigned char *plaintext, size_t plaintext_len, uint8_t *ciphertext, size_t ciphertext_len, uint8_t *key, size_t key_len, xqc_engine_t *engine)
{
    xqc_int_t update_len = 0, final_len = 0;
    xqc_log_t *log = engine->log;

    if (plaintext_len != XQC_EN_SINGLE_PASS_ENCRYPTION_LEN) {
        xqc_log(log, XQC_LOG_ERROR, "|lb-cid encryption error|lb-cid aes_128_ecb encryption parameter plaintext'length illegal(expect = 16)|");
        return -XQC_EPARAM;
    }

    if (plaintext_len != ciphertext_len) {
        xqc_log(log, XQC_LOG_ERROR, "|lb-cid encryption error|lb-cid aes_128_ecb encryption parameter plaintext and ciphertext illegal(expect equals in length)|");
        return -XQC_EPARAM;
    }

     if (key_len != XQC_LB_CID_KEY_LEN) {
        xqc_log(log, XQC_LOG_ERROR, "|lb-cid encryption error|lb-cid aes_128_ecb encryption parameter key'length illegal(expect = 16)|");
        return -XQC_EPARAM;
    }

    EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) {
        xqc_log(log, XQC_LOG_ERROR, "|lb-cid encryption error|lb-cid aes_128_ecb encryption ctx generate error|");
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -XQC_EENCRYPT_AES_128_ECB;
    }

    if (!EVP_EncryptInit_ex(cipher_ctx, EVP_aes_128_ecb(), NULL, key, NULL)) {
        xqc_log(log, XQC_LOG_ERROR, "|lb-cid encryption error|lb-cid aes_128_ecb encryption init error|");
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -XQC_EENCRYPT_AES_128_ECB;
    }

    EVP_CIPHER_CTX_set_padding(cipher_ctx, 0); 

    if (!EVP_EncryptUpdate(cipher_ctx, ciphertext, &update_len, plaintext, plaintext_len)) {
        xqc_log(log, XQC_LOG_ERROR, "|lb-cid encryption error|lb-cid aes_128_ecb encryption update error|");
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -XQC_EENCRYPT_AES_128_ECB;
    }

    if (!EVP_EncryptFinal_ex(cipher_ctx, ciphertext + update_len, &final_len)) {
        xqc_log(log, XQC_LOG_ERROR, "|lb-cid encryption error|lb-cid four-aes_128_ecb encryption final error|");
        EVP_CIPHER_CTX_free(cipher_ctx);
        return -XQC_EENCRYPT_AES_128_ECB;
    }

    EVP_CIPHER_CTX_free(cipher_ctx);

    return XQC_OK;
}

/*
 * One pass of the four-pass algorithm of draft-ietf-quic-load-balancers-13
 * Section 4.3.2. Passes 1 and 3 encrypt expand_left(left, pass) and XOR the
 * truncate_right() of the result into the right half; passes 2 and 4 encrypt
 * expand_right(right, pass) and XOR the truncate_left() of the result into
 * the left half.
 *
 * Each half is len * 4 bits of the len plaintext octets, kept in half_len
 * octets: the left half in the most significant bits, the right half in the
 * least significant ones. For an odd len, the low nibble of the last octet of
 * the left half and the high nibble of the first octet of the right half are
 * zero, so expanding or truncating a half copies octets and masks that nibble.
 */
static xqc_int_t
xqc_lb_cid_four_pass_round(uint8_t *left, uint8_t *right, size_t half_len,
    xqc_bool_t odd, uint8_t pass, uint8_t *key, size_t key_len,
    xqc_engine_t *engine)
{
    uint8_t     block[XQC_EN_SINGLE_PASS_ENCRYPTION_LEN];
    uint8_t     cipher[XQC_EN_SINGLE_PASS_ENCRYPTION_LEN];
    size_t      right_pos = sizeof(block) - half_len;
    size_t      i;
    xqc_int_t   ret;

    xqc_memzero(block, sizeof(block));

    if (pass % 2 == 1) {
        memcpy(block, left, half_len);
        block[sizeof(block) - 1] = pass;

    } else {
        block[0] = pass;
        memcpy(block + right_pos, right, half_len);
    }

    ret = xqc_cid_encryption_aes_128_ecb(block, sizeof(block), cipher,
                                         sizeof(cipher), key, key_len, engine);
    if (ret != XQC_OK) {
        return ret;
    }

    if (pass % 2 == 1) {
        if (odd) {
            cipher[right_pos] &= 0x0f;
        }

        for (i = 0; i < half_len; i++) {
            right[i] ^= cipher[right_pos + i];
        }

    } else {
        if (odd) {
            cipher[half_len - 1] &= 0xf0;
        }

        for (i = 0; i < half_len; i++) {
            left[i] ^= cipher[i];
        }
    }

    return XQC_OK;
}

/*
 * draft-ietf-quic-load-balancers-13 Section 4.3.2: split the plaintext into
 * left_0 and right_0 of in_len * 4 bits each, splitting the middle octet of
 * an odd length, run the four passes and join left_2 || right_2.
 */
static xqc_int_t
xqc_cid_encryption_four_pass(const uint8_t *in, size_t in_len, uint8_t *out,
    size_t out_len, uint8_t *key, size_t key_len, xqc_engine_t *engine)
{
    uint8_t     left[XQC_LB_HALF_MAX_LEN], right[XQC_LB_HALF_MAX_LEN];
    size_t      half_len = (in_len + 1) / 2;
    xqc_bool_t  odd = in_len % 2 == 1;
    uint8_t     pass;
    xqc_log_t  *log = engine->log;
    xqc_int_t   ret;

    if (in_len > XQC_MAX_CID_LEN - XQC_FIRST_OCTET) {
        xqc_log(log, XQC_LOG_ERROR, "|lb-cid encryption error|lb-cid "
                "four-pass encryption parameter in_len illegal"
                "(expect > 0 && <= 19)|");
        return -XQC_EPARAM;
    }

    if (out_len < in_len) {
        xqc_log(log, XQC_LOG_ERROR, "|lb-cid encryption error|lb-cid four-pass encryption parameter out_len illegal(expect no less than in_len)|");
        return -XQC_EPARAM;
    }

    if (key_len != XQC_LB_CID_KEY_LEN) {
        xqc_log(log, XQC_LOG_ERROR, "|lb-cid encryption error|lb-cid four-pass encryption parameter key'length illegal(expect = 16)|");
        return -XQC_EPARAM;
    }

    memcpy(left, in, half_len);
    memcpy(right, in + in_len - half_len, half_len);
    if (odd) {
        left[half_len - 1] &= 0xf0;
        right[0] &= 0x0f;
    }

    for (pass = 1; pass <= 4; pass++) {
        ret = xqc_lb_cid_four_pass_round(left, right, half_len, odd, pass,
                                         key, key_len, engine);
        if (ret != XQC_OK) {
            xqc_log(log, XQC_LOG_ERROR, "|lb-cid generate|lb-cid four-pass "
                    "encryption error|pass:%d|%d|", (int) pass, ret);
            return ret;
        }
    }

    /* for an odd length, left_2 and right_2 share the middle octet */
    if (odd) {
        left[half_len - 1] |= right[0];
    }

    memcpy(out + in_len - half_len, right, half_len);
    memcpy(out, left, half_len);

    return XQC_OK;
}

/**
 * @brief load balance cid encryption.
 * According to Draft : https://datatracker.ietf.org/doc/html/draft-ietf-quic-load-balancers-13#section-4.3
 */
xqc_int_t
xqc_lb_cid_encryption(uint8_t *cid_buf, size_t enc_len, uint8_t *out_buf, size_t out_buf_len, uint8_t *lb_cid_key, size_t lb_cid_key_len, xqc_engine_t *engine)
{
    size_t cid_buf_len = enc_len + XQC_FIRST_OCTET;

    xqc_log_t *log = engine->log;

    if (cid_buf_len > XQC_MAX_CID_LEN) {
        xqc_log(log, XQC_LOG_ERROR, "|lb-cid encryption error|parameter enc_len illegal(expect <= 19)|");
        return -XQC_EPARAM;
    }

    if (lb_cid_key_len != XQC_LB_CID_KEY_LEN) {
        xqc_log(log, XQC_LOG_ERROR, "|lb-cid encryption error|parameter lb_cid_key illegal(expect = 16)|");
        return -XQC_EPARAM;
    }
    
    if (out_buf_len < cid_buf_len) {
        xqc_log(log, XQC_LOG_ERROR, "|lb-cid encryption error|parameter out_buf_len illegal(expect no less than cid_buf_len)|");
        return -XQC_EPARAM;
    }

    if (enc_len == XQC_EN_SINGLE_PASS_ENCRYPTION_LEN) {
        xqc_int_t res = xqc_cid_encryption_aes_128_ecb(cid_buf + XQC_FIRST_OCTET, enc_len, out_buf + XQC_FIRST_OCTET, enc_len, lb_cid_key, lb_cid_key_len, engine);
        if (res < XQC_OK) {
            xqc_log(log, XQC_LOG_ERROR, "|lb-cid aes_128_ecb encryption error|%d|", res);
            return -XQC_EENCRYPT_LB_CID;
        }
    } else {
        xqc_int_t res = xqc_cid_encryption_four_pass(cid_buf + XQC_FIRST_OCTET, enc_len, out_buf + XQC_FIRST_OCTET, enc_len, lb_cid_key, lb_cid_key_len, engine);
        if (res < XQC_OK) {
            xqc_log(log, XQC_LOG_ERROR, "|lb-cid four-pass encryption error|%d|", res);
            return -XQC_EENCRYPT_LB_CID;
        }
    }

    unsigned char tmp_cid_buf[XQC_MAX_CID_LEN * 2 + 1];
    xqc_hex_dump(tmp_cid_buf, cid_buf, enc_len);
    tmp_cid_buf[enc_len * 2] = '\0';
    unsigned char tmp_out_buf[XQC_MAX_CID_LEN * 2 + 1];
    xqc_hex_dump(tmp_out_buf, out_buf, enc_len);
    tmp_out_buf[enc_len * 2] = '\0';
    xqc_log(log, XQC_LOG_INFO, "|lb cid encrypted|ori:%s|new:%s|", 
                    tmp_cid_buf, tmp_out_buf);
    return XQC_OK;
}