/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_KEY_UPDATE_TEST_H
#define XQC_KEY_UPDATE_TEST_H

/* RFC 9001 Section 6.1: MUST NOT initiate a key update prior to having
 * confirmed the handshake. See xqc_packet_encrypt_buf() in xqc_packet_parser.c.
 */
void xqc_test_key_update_blocked_before_handshake_confirmed(void);
void xqc_test_key_update_allowed_after_handshake_confirmed(void);

#endif
