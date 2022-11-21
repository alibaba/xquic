#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <xquic/xquic.h>
#include "src/transport/xqc_engine.h"


#define XQC_MAX_TRUNCATE_LEN 128
#define XQC_EN_SINGLE_PASS_ENCRYPTION_LEN 16

#define XQC_HALF_CID_CIPHER_LEN 16
#define XQC_TMP_CIPHER_LEN 16
#define XQC_FIRST_OCTET 1

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

xqc_int_t 
xqc_expand_left(uint8_t* left, size_t left_len, uint8_t *right, size_t right_len, uint8_t *out, size_t out_len, xqc_engine_t *engine)
{
    if (left_len + right_len > out_len) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|lb-cid generate|lb-cid xqc_expand_left parameter `left_len` or `right_len` overflow(expect left_len + right_len <= out_len)|");
        return -XQC_EPARAM;
    }

    memset(out, 0, out_len);
    memcpy(out, right, right_len);
    memcpy(out + out_len - left_len, left, left_len);

    return XQC_OK;
}

xqc_int_t 
xqc_expand_right(uint8_t* left, size_t left_len, uint8_t *right, size_t right_len, uint8_t *out, size_t out_len, xqc_engine_t *engine)
{
    return xqc_expand_left(right, right_len, left, left_len, out, out_len, engine);
}

uint8_t
xqc_n_bit_1(xqc_int_t n)
{
    uint8_t out = 0;
    for (xqc_int_t i = 0; i < n; i++) {
        out <<= 1;
        out |= 1;
    }
    return out;
}

void
xqc_array_right_shift(uint8_t *in_out, xqc_int_t in_out_len, xqc_int_t bits, size_t save_lowest)
{
    if (bits > 8) {
        int byte = bits / 8;
        bits = bits % 8;
        memcpy(in_out, in_out + byte, in_out_len - byte);
        memset(in_out, 0, byte);
    }
    if (bits == 0) {
        return;
    }

    for (xqc_int_t i = 0; i < in_out_len; i++) {
        /* keep the lowest `bits(int)` bits unchanged when i=0 */
        if (i || !save_lowest) {
            in_out[i] >>= bits;
        }
        if (i + 1 < in_out_len) {
            uint8_t tmp = xqc_n_bit_1(bits);
            tmp = in_out[i + 1] & tmp;
            tmp <<= (8 - bits);
            in_out[i] |= tmp;
        }
    }
}

xqc_int_t
xqc_truncate_left(uint8_t *buf, size_t buf_len, size_t cut_len, uint8_t *out, size_t out_len, xqc_engine_t *engine)
{
    xqc_int_t cut_byte, left_bit;

    memset(out, 0, out_len);
    cut_byte = cut_len / 8;
    left_bit = cut_len % 8;

    if (cut_byte >= out_len || cut_byte >= buf_len) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|lb-cid generate|lb-cid xqc_truncate_left parameter `cut_len` overflow(cut_len / 8 is expected < min(out_len, buf_len))|");
        return -XQC_EPARAM;
    }

    memcpy(out + out_len - cut_byte, buf + buf_len - cut_byte, cut_byte);
    out[buf_len - cut_byte - 1] = buf[buf_len - cut_byte - 1] & (xqc_n_bit_1(left_bit) << (8 - left_bit));
    xqc_array_right_shift(out, out_len, XQC_MAX_TRUNCATE_LEN - cut_len, 0);

    return XQC_OK;
}

xqc_int_t
xqc_truncate_right(uint8_t *buf, size_t buf_len, size_t cut_len, uint8_t *out, size_t out_len, xqc_engine_t *engine)
{
    xqc_int_t cut_byte, left_bit;
    uint8_t ret;

    memset(out, 0, out_len);
    cut_byte = cut_len / 8;
    left_bit = cut_len % 8;

    if (cut_byte >= out_len || cut_byte >= buf_len) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|lb-cid generate|lb-cid xqc_truncate_right parameter `cut_len` overflow(cut_len / 8 is expected < min(out_len, buf_len))|");
        return -XQC_EPARAM;
    }

    memcpy(out, buf, cut_byte);
    out[cut_byte] = buf[cut_byte] & xqc_n_bit_1(left_bit);

    return XQC_OK ;
}

xqc_int_t
xqc_min_among_2(xqc_int_t a, xqc_int_t b)
{
    return (a < b) ? a : b;
}
xqc_int_t
xqc_array_xor(uint8_t *in1, size_t in1_len, uint8_t *in2, size_t in2_len, uint8_t *out, size_t out_len)
{
    xqc_int_t i;
    for (i = 0; i < in1_len && i < in2_len && i < out_len; i++) {
        out[i] = in1[i] ^ in2[i];
    }

    int min = xqc_min_among_2(in1_len - i, out_len - i);
    memcpy(out + i, in1 + i, min);

    min = xqc_min_among_2(in2_len - i, out_len - i);
    memcpy(out + i, in2 + i, min);

    return XQC_OK;
}

xqc_int_t
xqc_cid_encryption_four_pass(uint8_t *in, size_t in_len, uint8_t *out, size_t out_len, uint8_t *key, size_t key_len, xqc_engine_t *engine)
{
    uint8_t left_0[XQC_HALF_CID_CIPHER_LEN], right_0[XQC_HALF_CID_CIPHER_LEN], left_1[XQC_HALF_CID_CIPHER_LEN], right_1[XQC_HALF_CID_CIPHER_LEN], left_2[XQC_HALF_CID_CIPHER_LEN], right_2[XQC_HALF_CID_CIPHER_LEN];
    uint8_t tmp_out[XQC_TMP_CIPHER_LEN], tmp_exp[XQC_TMP_CIPHER_LEN], tmp_tru[XQC_TMP_CIPHER_LEN];
    uint8_t const_buf[1];
    xqc_int_t bits_per_byte = 8;
    xqc_int_t octet_per_128bits = 16;
    xqc_int_t const_buf_len = 1;
    xqc_int_t left_len_bit, right_len_bit, left_len_byte, right_len_byte;
    xqc_int_t shift_offset;
    xqc_log_t *log = engine->log;
    xqc_int_t ret;
    if (in_len > XQC_MAX_CID_LEN - XQC_FIRST_OCTET) {
        xqc_log(log, XQC_LOG_ERROR, "|lb-cid encryption error|lb-cid four-pass encryption parameter in_lengtn illegal(expect > 0 && <= 19)|");
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

    left_len_bit = right_len_bit = in_len * 4;
    left_len_byte = right_len_byte = (in_len + 1) / 2;
    shift_offset = right_len_byte * 8 - right_len_bit;

    memset(left_0, 0, sizeof(left_0));
    memset(left_1, 0, sizeof(left_1));
    memset(left_2, 0, sizeof(left_2));
    memset(right_0, 0, sizeof(right_0));
    memset(right_1, 0, sizeof(right_1));
    memset(right_2, 0, sizeof(right_2));
    memset(const_buf, 0, const_buf_len);

    memcpy(left_0, in + right_len_byte - 1, left_len_byte);
    xqc_array_right_shift(left_0, XQC_HALF_CID_CIPHER_LEN, right_len_bit - (right_len_byte - 1) * 8, 0);
    memcpy(tmp_tru, in, right_len_byte);
    xqc_truncate_right(tmp_tru, XQC_TMP_CIPHER_LEN, right_len_bit, right_0, XQC_HALF_CID_CIPHER_LEN, engine);

    const_buf[0] = 0x01;
    ret = xqc_expand_left(left_0, left_len_byte, const_buf, const_buf_len, tmp_exp, XQC_TMP_CIPHER_LEN, engine);
    if (ret != XQC_OK) {
        xqc_log(log, XQC_LOG_ERROR, "|lb-cid generate|lb-cid four-pass encryption first-pass aes encryption error|%d|", ret);
        return ret;
    }
    ret = xqc_cid_encryption_aes_128_ecb(tmp_exp, octet_per_128bits, tmp_out, octet_per_128bits, key, key_len, engine);
    if (ret != XQC_OK) {
        xqc_log(log, XQC_LOG_ERROR, "|lb-cid generate|lb-cid four-pass encryption first-pass aes encryption error|%d|", ret);
        return ret;
    }
    ret = xqc_truncate_right(tmp_out, XQC_TMP_CIPHER_LEN, right_len_bit, tmp_tru, XQC_TMP_CIPHER_LEN, engine);
    if (ret != XQC_OK) {
        xqc_log(log, XQC_LOG_ERROR, "|lb-cid generate|lb-cid four-pass encryption first-pass truncate error|%d|", ret);
        return ret;
    }
    xqc_array_xor(right_0, XQC_HALF_CID_CIPHER_LEN, tmp_tru, XQC_TMP_CIPHER_LEN, right_1, XQC_HALF_CID_CIPHER_LEN);

    const_buf[0] = 0x02;
    ret = xqc_expand_right(right_1, right_len_byte, const_buf, const_buf_len, tmp_exp, XQC_TMP_CIPHER_LEN, engine);
    if (ret != XQC_OK) {
        xqc_log(log, XQC_LOG_ERROR, "|lb-cid generate|lb-cid four-pass second-pass aes encryption error|%d|", ret);
        return ret;
    }
    ret = xqc_cid_encryption_aes_128_ecb(tmp_exp, octet_per_128bits, tmp_out, octet_per_128bits, key, key_len, engine);
    if (ret != XQC_OK) {
        xqc_log(log, XQC_LOG_ERROR, "|lb-cid generate|lb-cid four-pass second-pass aes encryption error|%d|", ret);
        return ret;
    }
    ret = xqc_truncate_left(tmp_out, XQC_TMP_CIPHER_LEN, left_len_bit, tmp_tru, XQC_TMP_CIPHER_LEN, engine);
    if (ret != XQC_OK) {
        xqc_log(log, XQC_LOG_ERROR, "|lb-cid generate|lb-cid four-pass encryption second-pass truncate error|%d|", ret);
        return ret;
    }
    xqc_array_xor(left_0, XQC_HALF_CID_CIPHER_LEN, tmp_tru, XQC_TMP_CIPHER_LEN, left_1, XQC_HALF_CID_CIPHER_LEN);

    const_buf[0] = 0x03;
    ret = xqc_expand_left(left_1, left_len_byte, const_buf, const_buf_len, tmp_exp, XQC_TMP_CIPHER_LEN, engine);
    if (ret != XQC_OK) {
        xqc_log(log, XQC_LOG_ERROR, "|lb-cid generate|lb-cid four-pass third-pass aes encryption error|%d|", ret);
        return ret;
    }
    ret = xqc_cid_encryption_aes_128_ecb(tmp_exp, octet_per_128bits, tmp_out, octet_per_128bits, key, key_len, engine);
    if (ret != XQC_OK) {
        xqc_log(log, XQC_LOG_ERROR, "|lb-cid generate|lb-cid four-pass third-pass aes encryption error|%d|", ret);
        return ret;
    }
    ret = xqc_truncate_right(tmp_out, XQC_TMP_CIPHER_LEN, right_len_bit, tmp_tru, XQC_TMP_CIPHER_LEN, engine);
    if (ret != XQC_OK) {
        xqc_log(log, XQC_LOG_ERROR, "|lb-cid generate|lb-cid four-pass encryption third-pass truncate error|%d|", ret);
        return ret;
    }
    xqc_array_xor(right_1, XQC_HALF_CID_CIPHER_LEN, tmp_tru, XQC_TMP_CIPHER_LEN, right_2, XQC_HALF_CID_CIPHER_LEN);

    const_buf[0] = 0x04;
    ret = xqc_expand_right(right_2, right_len_byte, const_buf, const_buf_len, tmp_exp, XQC_TMP_CIPHER_LEN, engine);
    if (ret != XQC_OK) {
        xqc_log(log, XQC_LOG_ERROR, "|lb-cid generate|lb-cid four-pass fourth-pass aes encryption error|%d|", ret);
        return ret;
    }
    ret = xqc_cid_encryption_aes_128_ecb(tmp_exp, octet_per_128bits, tmp_out, octet_per_128bits, key, key_len, engine);
    if (ret != XQC_OK) {
        xqc_log(log, XQC_LOG_ERROR, "|lb-cid generate|lb-cid four-pass fourth-pass aes encryption error|%d|", ret);
        return ret;
    }
    ret = xqc_truncate_left(tmp_out, XQC_TMP_CIPHER_LEN, left_len_bit, tmp_tru, XQC_TMP_CIPHER_LEN, engine);
    if (ret != XQC_OK) {
        xqc_log(log, XQC_LOG_ERROR, "|lb-cid generate|lb-cid four-pass encryption fourth-pass truncate error|%d|", ret);
        return ret;
    }
    xqc_array_xor(left_1, XQC_HALF_CID_CIPHER_LEN, tmp_tru, XQC_TMP_CIPHER_LEN, left_2, XQC_HALF_CID_CIPHER_LEN);

    memcpy(out + right_len_byte, left_2, left_len_byte);
    memcpy(out, right_2, right_len_byte);
    xqc_array_right_shift(out + right_len_byte - 1, left_len_byte + 1, shift_offset, 1);
    
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