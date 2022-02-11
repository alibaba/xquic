/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_TLS_H
#define XQC_TLS_H

#include <xquic/xquic_typedef.h>
#include "xqc_tls_defs.h"
#include <openssl/err.h>
#include "src/transport/xqc_packet.h"

/**
 * @brief init tls context. MUST be called before any creation of xqc_tls_t
 */
xqc_tls_ctx_t *xqc_tls_ctx_create(xqc_tls_type_t type, const xqc_engine_ssl_config_t *cfg,
    const xqc_tls_callbacks_t *cbs, xqc_log_t *log);

/**
 * @brief destroy tls context, once destroyed, no instance of xqc_tls_t will be created
 */
void xqc_tls_ctx_destroy(xqc_tls_ctx_t *ctx);

/**
 * @brief alpn registration, which is used for alpn selection
 */
xqc_int_t xqc_tls_ctx_register_alpn(xqc_tls_ctx_t *ctx, const char *alpn, size_t alpn_len);

/**
 * @brief alpn unregistration
 */
xqc_int_t xqc_tls_ctx_unregister_alpn(xqc_tls_ctx_t *ctx, const char *alpn, size_t alpn_len);



/**
 * @brief create and initiate a tls instance
 * 
 * @param cfg config for initiating tls instance
 * @param user_data callback user_data for callback functions in xqc_tls_callbacks_t
 * @return XQC_OK for success, others for failure
 */
xqc_tls_t *xqc_tls_create(xqc_tls_ctx_t *ctx, xqc_tls_config_t *cfg, xqc_log_t *log,
    void *user_data);

/**
 * @brief initiate tls, need only call once after create a tls instance. for client, this will
 * trigger generating ClientHello.
 * 
 * @param version version of quic, with different versions comes the different
 * quic_transport_parameters extension codepoint in ClientHello and ServerHello.
 * @param odcid original dcid, used to generate initial secret
 * @return XQC_OK for success, others for failure
 */
xqc_int_t xqc_tls_init(xqc_tls_t *tls, xqc_proto_version_t version, const xqc_cid_t *odcid);

/**
 * @brief reset initial keys, this might be called after Retry or Version Negotiation
 * 
 * @param version new version, which is related to Initial Salt
 * @param odcid new destination connection id
 * @return XQC_OK for success, others for failure
 */
xqc_int_t xqc_tls_reset_initial(xqc_tls_t *tls, xqc_proto_version_t version,
    const xqc_cid_t *odcid);

/**
 * @brief destroy a tls instance
 */
void xqc_tls_destroy(xqc_tls_t *tls);

/**
 * @brief handle tls handshake data from peer's QUIC CRYPTO frame. during processing, events in 
 * xqc_tls_callbacks_t might be triggered.
 * 
 * @param level level of CRYPTO data, which shall be translated form QUIC packet type
 * @return XQC_OK for success, others for failure
 */
xqc_int_t xqc_tls_process_crypto_data(xqc_tls_t *tls, xqc_encrypt_level_t level,
    const uint8_t *crypto_data, size_t data_len);

/**
 * @brief apply header protection, will generate header protection mask, and modify the first byte
 * on header and bytes of pktno. MUST be called after calling xqc_tls_encrypt_payload.
 * 
 * @param header header to be protected with subsequent encrypted payload buffer, after header 
 * protection, the first byte and packet number will be modified and protected with mask.
 * @param pktno position of packet number
 * @param end end position of buffer, which is used to validate pktno and packet number length
 * @return XQC_OK for success, others for failure 
 */
xqc_int_t xqc_tls_encrypt_header(xqc_tls_t *tls, xqc_encrypt_level_t level,
    xqc_pkt_type_t pkt_type, uint8_t *header, uint8_t *pktno, uint8_t *end);

/**
 * @brief remove header protection, will generate header protection mask, and modify the first byte
 * on header and bytes of pktno. MUST be called before calling xqc_tls_decrypt_payload.
 * 
 * @param header header buffer to be remove header protection, after remove, the first byte and 
 * packet number will be modified and restored
 * @param pktno position of packet number
 * @param end end position of buffer, which is used to validate pktno and packet number length
 * @return XQC_OK for success, others for failure 
 */
xqc_int_t xqc_tls_decrypt_header(xqc_tls_t *tls, xqc_encrypt_level_t level,
    xqc_pkt_type_t pkt_type, uint8_t *header, uint8_t *pktno, uint8_t *end);

/**
 * @brief encrypt packet payload
 * 
 * @param pktno packet number, MUST be the original uncoded packet number
 * @param header position of packet header, will be used as ad, MUST be plaintext
 * @param header_len length of packet header
 * @param payload packet payload plaintext to be encrypted
 * @param payload_len length of packet payload plaintext
 * @param dst destination buffer
 * @param dst_cap capacity of dst
 * @param dst_len written length
 * @return XQC_OK for success, others for failure
 */
xqc_int_t xqc_tls_encrypt_payload(xqc_tls_t *tls, xqc_encrypt_level_t level,
    uint64_t pktno, uint8_t *header, size_t header_len, uint8_t *payload, size_t payload_len,
    uint8_t *dst, size_t dst_cap, size_t *dst_len);

/**
 * @brief decrypt packet payload
 * 
 * @param pktno packet number, MUST be the original uncoded packet number
 * @param header position of packet header, will be used as ad, MUST be plaintext
 * @param header_len length of packet header
 * @param payload packet payload plaintext to be encrypted
 * @param payload_len length of packet payload plaintext
 * @param dst destination buffer
 * @param dst_cap capacity of dst
 * @param dst_len written length
 * @return XQC_OK for success, others for failure
 */
xqc_int_t xqc_tls_decrypt_payload(xqc_tls_t *tls, xqc_encrypt_level_t level,
    uint64_t pktno, uint8_t *header, size_t header_len, uint8_t *payload, size_t payload_len,
    uint8_t *dst, size_t dst_cap, size_t *dst_len);

/**
 * @brief check if key is ready at specified encryption level
 */
xqc_bool_t xqc_tls_is_key_ready(xqc_tls_t *tls, xqc_encrypt_level_t level, xqc_key_type_t key_type);

/**
 * @brief check whether it is adequate to send early data
 */
xqc_bool_t xqc_tls_is_ready_to_send_early_data(xqc_tls_t *tls);

/**
 * @brief check if early data is accepted
 */
xqc_tls_early_data_accept_t xqc_tls_is_early_data_accepted(xqc_tls_t *tls);

/**
 * @brief get crypto aead tag length
 */
ssize_t xqc_tls_aead_tag_len(xqc_tls_t *tls, xqc_encrypt_level_t level);

/**
 * @brief set no crypto on 0-RTT and 1-RTT
 */
void xqc_tls_set_no_crypto(xqc_tls_t *tls);

/**
 * @brief update key phase on 1-RTT
 */
void xqc_tls_set_1rtt_key_phase(xqc_tls_t *tls, xqc_uint_t key_phase);

/**
 * @brief check if key update is waiting confirmed
 */
xqc_bool_t xqc_tls_is_key_update_confirmed(xqc_tls_t *tls);

/**
 * @brief derive updated read or write keys on 1-RTT
 */
xqc_int_t xqc_tls_update_1rtt_keys(xqc_tls_t *tls, xqc_key_type_t type);

/**
 * @brief discard the old read and write keys on 1-RTT
 */
void xqc_tls_discard_old_1rtt_keys(xqc_tls_t *tls);

#endif
