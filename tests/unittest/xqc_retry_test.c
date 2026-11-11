/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include <arpa/inet.h>
#include "xqc_retry_test.h"

#include "xqc_common_test.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_defs.h"
#include "src/transport/xqc_packet_parser.h"


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

    uint8_t initial_dcid_len = conn->conn_initial_path->path_dcid.cid_len;

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
    CU_ASSERT(initial_dcid_len != packet_in->pi_pkt.pkt_scid.cid_len);
    CU_ASSERT(xqc_cid_is_equal(&conn->dcid_set.current_dcid,
                               &packet_in->pi_pkt.pkt_scid) == XQC_OK);
    CU_ASSERT(xqc_cid_is_equal(&conn->conn_initial_path->path_dcid,
                               &packet_in->pi_pkt.pkt_scid) == XQC_OK);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_retry_same_length_dcid()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    xqc_cid_t retry_scid;
    xqc_cid_copy(&retry_scid, &conn->conn_initial_path->path_dcid);
    retry_scid.cid_buf[0] ^= 0xff;
    CU_ASSERT(conn->conn_initial_path->path_dcid.cid_len
              == retry_scid.cid_len);
    CU_ASSERT(xqc_cid_is_equal(&conn->conn_initial_path->path_dcid,
                               &retry_scid) != XQC_OK);

    xqc_int_t ret = xqc_conn_on_recv_retry(conn, &retry_scid);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(xqc_cid_is_equal(&conn->dcid_set.current_dcid,
                               &retry_scid) == XQC_OK);
    CU_ASSERT(xqc_cid_is_equal(&conn->conn_initial_path->path_dcid,
                               &retry_scid) == XQC_OK);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_retry_invalid_token_close()
{
    static const unsigned char retry_scid_buf[] = "retrycid";

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    xqc_packet_in_t packet_in;
    memset(&packet_in, 0, sizeof(packet_in));

    conn->conn_type = XQC_CONN_TYPE_SERVER;
    conn->conn_flag |= XQC_CONN_FLAG_RETRY_SENT;
    conn->conn_flag &= ~XQC_CONN_FLAG_TOKEN_OK;
    conn->conn_token_len = 0;
    conn->conn_err = 0;
    conn->version = XQC_VERSION_V1;
    xqc_cid_set(&conn->retry_scid, retry_scid_buf, sizeof(retry_scid_buf) - 1);
    xqc_cid_copy(&packet_in.pi_pkt.pkt_dcid, &conn->retry_scid);

    xqc_int_t ret = xqc_conn_server_accept(conn, &packet_in);
    CU_ASSERT(ret == -XQC_EPROTO);
    CU_ASSERT(conn->conn_err == TRA_INVALID_TOKEN);
    CU_ASSERT(conn->conn_flag & XQC_CONN_FLAG_ERROR);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_retry_invalid_token_ignore_original_dcid()
{
    static const unsigned char retry_scid_buf[] = "retrycid";
    static const unsigned char original_dcid_buf[] = "origdcid";

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    xqc_packet_in_t packet_in;
    memset(&packet_in, 0, sizeof(packet_in));

    conn->conn_type = XQC_CONN_TYPE_SERVER;
    conn->conn_flag |= XQC_CONN_FLAG_RETRY_SENT;
    conn->conn_flag &= ~XQC_CONN_FLAG_TOKEN_OK;
    conn->conn_token_len = 0;
    conn->conn_err = 0;
    conn->version = XQC_VERSION_V1;
    xqc_cid_set(&conn->retry_scid, retry_scid_buf, sizeof(retry_scid_buf) - 1);
    xqc_cid_set(&packet_in.pi_pkt.pkt_dcid, original_dcid_buf, sizeof(original_dcid_buf) - 1);

    xqc_int_t ret = xqc_conn_server_accept(conn, &packet_in);
    CU_ASSERT(ret == -XQC_EIGNORE_PKT);
    CU_ASSERT(conn->conn_err == 0);
    CU_ASSERT(!(conn->conn_flag & XQC_CONN_FLAG_ERROR));

    xqc_engine_destroy(conn->engine);
}


/* defined in xqc_conn.c; lets the tests choose the expiry time */
xqc_int_t xqc_conn_generate_and_encrypt_token(xqc_connection_t *conn,
    unsigned char *token, unsigned *token_len, uint32_t expire);


typedef struct xqc_test_token_s {
    unsigned char   buf[XQC_MAX_TOKEN_LEN];
    unsigned        len;
} xqc_test_token_t;


static void
xqc_test_token_set_peer(xqc_connection_t *conn, int family, const char *ip)
{
    struct sockaddr_in   sa4;
    struct sockaddr_in6  sa6;

    if (family == AF_INET) {
        memset(&sa4, 0, sizeof(sa4));
        sa4.sin_family = AF_INET;
        sa4.sin_port = htons(4433);
        CU_ASSERT(inet_pton(AF_INET, ip, &sa4.sin_addr) == 1);
        memcpy(conn->peer_addr, &sa4, sizeof(sa4));
        conn->peer_addrlen = sizeof(sa4);

    } else {
        memset(&sa6, 0, sizeof(sa6));
        sa6.sin6_family = AF_INET6;
        sa6.sin6_port = htons(4433);
        CU_ASSERT(inet_pton(AF_INET6, ip, &sa6.sin6_addr) == 1);
        memcpy(conn->peer_addr, &sa6, sizeof(sa6));
        conn->peer_addrlen = sizeof(sa6);
    }
}


/* a token for the current peer address that expires at expire (s) */
static void
xqc_test_token_make(xqc_connection_t *conn, uint32_t expire,
    xqc_test_token_t *token)
{
    token->len = sizeof(token->buf);
    CU_ASSERT(xqc_conn_generate_and_encrypt_token(conn, token->buf,
                                                  &token->len,
                                                  htonl(expire)) == XQC_OK);
}


static xqc_int_t
xqc_test_token_check(xqc_connection_t *conn, const xqc_test_token_t *token)
{
    conn->conn_flag &= ~XQC_CONN_FLAG_UPDATE_NEW_TOKEN;
    return xqc_conn_check_token(conn, token->buf, token->len);
}


/*
 * The expiry time follows the address, at token offset 5 (IPv4) or
 * 17 (IPv6), so the checks must read it unaligned.
 */
void
xqc_test_token_lifetime()
{
    xqc_test_token_t token;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    uint32_t now = xqc_monotonic_timestamp() / 1000000;
    xqc_test_token_set_peer(conn, AF_INET, "192.0.2.1");

    /* a fresh token passes without asking for a new one */
    xqc_test_token_make(conn, now + XQC_TOKEN_EXPIRE_DELTA, &token);
    CU_ASSERT(xqc_test_token_check(conn, &token) == XQC_OK);
    CU_ASSERT(!(conn->conn_flag & XQC_CONN_FLAG_UPDATE_NEW_TOKEN));

    /* a token about to expire passes, and a new one will be sent */
    xqc_test_token_make(conn, now + 5, &token);
    CU_ASSERT(xqc_test_token_check(conn, &token) == XQC_OK);
    CU_ASSERT(conn->conn_flag & XQC_CONN_FLAG_UPDATE_NEW_TOKEN);

    /* an expired token is refused */
    if (now > 0) {
        xqc_test_token_make(conn, now - 1, &token);
        CU_ASSERT(xqc_test_token_check(conn, &token) == XQC_ERROR);
    }

    /* the same for an IPv6 peer */
    xqc_test_token_set_peer(conn, AF_INET6, "2001:db8::1");
    xqc_test_token_make(conn, now + XQC_TOKEN_EXPIRE_DELTA, &token);
    CU_ASSERT(xqc_test_token_check(conn, &token) == XQC_OK);
    CU_ASSERT(!(conn->conn_flag & XQC_CONN_FLAG_UPDATE_NEW_TOKEN));

    xqc_test_token_make(conn, now + 5, &token);
    CU_ASSERT(xqc_test_token_check(conn, &token) == XQC_OK);
    CU_ASSERT(conn->conn_flag & XQC_CONN_FLAG_UPDATE_NEW_TOKEN);

    xqc_engine_destroy(conn->engine);
}


/* a token is refused from an address other than the one it was made for */
void
xqc_test_token_address_mismatch()
{
    xqc_test_token_t token;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    /* the IPv4 mismatch is logged with the token's address */
    conn->log->log_level = XQC_LOG_INFO;
    uint32_t now = xqc_monotonic_timestamp() / 1000000;

    xqc_test_token_set_peer(conn, AF_INET, "192.0.2.1");
    xqc_test_token_make(conn, now + XQC_TOKEN_EXPIRE_DELTA, &token);
    xqc_test_token_set_peer(conn, AF_INET, "192.0.2.2");
    CU_ASSERT(xqc_test_token_check(conn, &token) == XQC_ERROR);

    xqc_test_token_set_peer(conn, AF_INET6, "2001:db8::1");
    xqc_test_token_make(conn, now + XQC_TOKEN_EXPIRE_DELTA, &token);
    xqc_test_token_set_peer(conn, AF_INET6, "2001:db8::2");
    CU_ASSERT(xqc_test_token_check(conn, &token) == XQC_ERROR);

    xqc_engine_destroy(conn->engine);
}
