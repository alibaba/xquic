/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_SSL_CBS_H
#define XQC_SSL_CBS_H

#include <openssl/ssl.h>

/**
 * @brief this file describes all the callback functions registered in ssl lib
 */


/**
 * @brief log key material
 * @see SSL_CTX_set_keylog_callback
 */
void xqc_ssl_keylog_cb(const SSL *ssl, const char *line);


/**
 * @brief select an ALPN protocol from the client's list of offered protocols
 * @see SSL_CTX_set_alpn_select_cb
 */
int xqc_ssl_alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
    const unsigned char *in, unsigned int inlen, void *arg);


/**
 * @brief be called when encrypting a new ticket and when decrypting a ticket from the client
 * 
 * @param encrypt 1:encrypt a new ticket; 0:decrypt a ticket
 * @see SSL_CTX_set_tlsext_ticket_key_cb
 */
int xqc_ssl_session_ticket_key_cb(SSL *ssl, unsigned char *key_name, unsigned char *iv,
    EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx, int encrypt);


/**
 * @brief be called when a new session is established and ready to be cached
 * @see SSL_CTX_sess_set_new_cb
 */
int xqc_ssl_new_session_cb(SSL *ssl, SSL_SESSION *session);


int xqc_ssl_cert_verify_cb(int ok, X509_STORE_CTX *store_ctx);

#endif