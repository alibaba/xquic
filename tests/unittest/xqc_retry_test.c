/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xqc_retry_test.h"

#include "xqc_common_test.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_packet_parser.h"
#include "src/tls/xqc_tls.h"


#define XQC_TEST_RETRY_PACKET \
    "\xf0\x00\x00\x00\x01\x08\xbb\x22\xa6\x03\x33\x43\x66\x83\x04\xc6" \
    "\x74\x02\x85\x17\xb3\xe9\x32\xc8\xed\xf7\x75\x77\x4a\x8d\x1a\xed" \
    "\xe1\xda\xe0\xee\xc6\x63\xa2\x6f\x97\x21\x70\xb8\x9f\x8f\x85\xe8" \
    "\xf1\x3f\x74\x2e\xe6\xb1\x36\xb5\xe4\xcd\xf7\x98\xa2\x1d\x40\xa4" \
    "\x86\x5c\x94\x02\x2f\x36\x0a\x5d\xc9\x96\xfe\x68\xae\x32\x9d\x9e" \
    "\xa0\x9b\x65\x68\xa4\xe8\xb8\x83\x03\xcc\x81\xba\xe7\x27\xb5\x64" \
    "\x12\x5e\x87\x2c\x78\x47\x2e\x7e\xb6\x08\x0c\x9a\x56\xcd\xed\x1e" \
    "\x0c\xd3\xc7\x46\x28\x12\x51\xe8\x38\x9b\x21\x23\x59\xa3\x33\x5d" \
    "\x98\x88\x81\xbb\x34"

#define XQC_TEST_RETRY_ODCID "\x4e\xb3\xa4\x60\xf9\x77\xa4\x75"


void
xqc_test_retry()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    xqc_packet_in_t packet;
    xqc_packet_in_t *packet_in = &packet;
    memset(packet_in, 0, sizeof(*packet_in));
    xqc_packet_in_init(packet_in, XQC_TEST_RETRY_PACKET,
                       (sizeof(XQC_TEST_RETRY_PACKET) - 1),
                       NULL, XQC_MAX_PACKET_LEN,
                       xqc_monotonic_timestamp());

    /* used to format retry pseudo packet and calculate retry integrity tag */
    xqc_cid_set(&conn->original_dcid, XQC_TEST_RETRY_ODCID, sizeof(XQC_TEST_RETRY_ODCID) - 1);

    xqc_int_t ret;
    ret = xqc_packet_parse_long_header(conn, packet_in);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(conn->conn_flag & XQC_CONN_FLAG_RETRY_RECVD);

    xqc_engine_destroy(conn->engine);
}


/*
 * Issue #596 regression: xqc_tls_cal_retry_integrity_tag must use the binary
 * key/nonce lengths defined by RFC 9001 Section 5.8 (K = 128 bits = 16 bytes,
 * N = 96 bits = 12 bytes), not strlen() which stops at the first NUL byte.
 *
 * Ground truth: RFC 9001 Appendix A.4 (Retry).
 *   ODCID: 8394c8f03e515708 (8 bytes)
 *   Full Retry packet (with integrity tag):
 *     ff000000010008f067a5502a4262b574 6f6b656e
 *     04a265ba2eff4d829058fb3f0f2496ba
 *   Expected integrity tag (last 16 bytes):
 *     04a265ba2eff4d829058fb3f0f2496ba
 *
 * Pre-fix (using strlen): V1 key/nonce happen to contain no NUL byte, so the
 * V1 path keeps working by accident. This test pins V1 down to RFC ground
 * truth; the binary-length test catches strlen regressions.
 */
void
xqc_test_retry_integrity_tag_rfc9001()
{
    /* RFC 9001 A.4 ODCID: 8394c8f03e515708 */
    uint8_t odcid[] = {
        0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08
    };

    /* RFC 9001 A.4 Retry packet without the trailing 16-byte integrity tag.
     * Full RFC vector (36 bytes total):
     *   ff 00000001 00 08 f067a5502a4262b5 746f6b656e [16-byte tag]
     * Layout: type(1) + version(4) + DCID_len(1)=0 + SCID_len(1)=8 +
     *         SCID(8) + token "token"(5) = 20 bytes pre-tag. */
    uint8_t retry_no_tag[] = {
        0xff,                                             /* long header */
        0x00, 0x00, 0x00, 0x01,                           /* version = V1 */
        0x00,                                             /* DCID len = 0 */
        0x08,                                             /* SCID len = 8 */
        0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5,   /* SCID */
        0x74, 0x6f, 0x6b, 0x65, 0x6e                      /* token "token" */
    };

    /* RFC 9001 A.4 expected integrity tag */
    uint8_t expected_tag[16] = {
        0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82,
        0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba
    };

    /* Build retry pseudo-packet = odcid_len + odcid + retry_no_tag */
    uint8_t pseudo[1 + sizeof(odcid) + sizeof(retry_no_tag)];
    pseudo[0] = (uint8_t)sizeof(odcid);
    memcpy(pseudo + 1, odcid, sizeof(odcid));
    memcpy(pseudo + 1 + sizeof(odcid), retry_no_tag, sizeof(retry_no_tag));

    /* Get a log handle from a throwaway engine */
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    uint8_t  tag[16];
    size_t   tag_len = 0;
    xqc_int_t ret = xqc_tls_cal_retry_integrity_tag(conn->log,
                                                    pseudo, sizeof(pseudo),
                                                    tag, sizeof(tag), &tag_len,
                                                    XQC_VERSION_V1);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(tag_len == sizeof(expected_tag));
    CU_ASSERT(memcmp(tag, expected_tag, sizeof(expected_tag)) == 0);

    xqc_engine_destroy(conn->engine);
}


/*
 * Regression guard for binary Retry integrity key/nonce lengths.
 *
 * The in-range placeholder entry uses all-zero binary key/nonce material. A
 * strlen-based implementation passes a zero-length nonce to AEAD, while the
 * fixed-length implementation computes this GMAC with a 16-byte zero key and
 * 12-byte zero nonce.
 */
void
xqc_test_retry_integrity_tag_binary_lengths()
{
    uint8_t pseudo[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    uint8_t expected_tag[16] = {
        0x8a, 0x44, 0xec, 0x70, 0xda, 0x3a, 0x66, 0xff,
        0x6d, 0x07, 0xc5, 0x7b, 0x3f, 0x60, 0x72, 0x45
    };

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    uint8_t tag[16];
    size_t tag_len = 0;
    xqc_int_t ret = xqc_tls_cal_retry_integrity_tag(conn->log,
                                                    pseudo, sizeof(pseudo),
                                                    tag, sizeof(tag), &tag_len,
                                                    XQC_IDRAFT_INIT_VER);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(tag_len == sizeof(expected_tag));
    CU_ASSERT(memcmp(tag, expected_tag, sizeof(expected_tag)) == 0);

    ret = xqc_tls_cal_retry_integrity_tag(conn->log,
                                          pseudo, sizeof(pseudo),
                                          tag, sizeof(tag), &tag_len,
                                          XQC_VERSION_MAX);
    CU_ASSERT(ret == -XQC_TLS_INVALID_ARGUMENT);

    xqc_engine_destroy(conn->engine);
}
