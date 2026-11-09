/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xqc_retry_test.h"

#include "xqc_common_test.h"
#include "src/transport/xqc_utils.h"
#include "src/transport/xqc_conn.h"
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


/* the Retry packets a server connection sends before it accepts a client */
typedef struct xqc_test_retry_sent_s {
    size_t          count;
    xqc_cid_t       dcid;   /* of the last one */
    xqc_cid_t       scid;   /* of the last one */
} xqc_test_retry_sent_t;


static ssize_t
xqc_test_retry_write(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user_data)
{
    xqc_test_retry_sent_t *sent = user_data;

    CU_ASSERT(XQC_PACKET_IS_LONG_HEADER(buf)
              && XQC_PACKET_LONG_HEADER_GET_TYPE(buf) == XQC_PTYPE_RETRY);
    CU_ASSERT(xqc_packet_parse_cid(&sent->dcid, &sent->scid,
                                   XQC_DEFAULT_CID_LEN, buf, size) == XQC_OK);
    sent->count++;
    return (ssize_t)size;
}


static int
xqc_test_retry_required(xqc_engine_t *engine, xqc_connection_t *conn,
    const xqc_cid_t *cid, void *user_data)
{
    return XQC_TRUE;
}


static void
xqc_test_retry_capture(xqc_connection_t *conn, xqc_test_retry_sent_t *sent)
{
    memset(sent, 0, sizeof(*sent));
    conn->user_data = sent;
    conn->transport_cbs.conn_send_packet_before_accept = xqc_test_retry_write;
}


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
    xqc_test_retry_sent_t sent;

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
    xqc_test_retry_capture(conn, &sent);
    xqc_cid_set(&conn->retry_scid, retry_scid_buf, sizeof(retry_scid_buf) - 1);
    xqc_cid_copy(&packet_in.pi_pkt.pkt_dcid, &conn->retry_scid);

    xqc_int_t ret = xqc_conn_server_accept(conn, &packet_in);
    CU_ASSERT(ret == -XQC_EPROTO);
    CU_ASSERT(conn->conn_err == TRA_INVALID_TOKEN);
    CU_ASSERT(conn->conn_flag & XQC_CONN_FLAG_ERROR);
    /* RFC 9000 Section 17.2.5.2: this client discards any other Retry */
    CU_ASSERT(sent.count == 0);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_retry_invalid_token_ignore_original_dcid()
{
    xqc_test_retry_sent_t sent;
    xqc_cid_t retry_scid;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    xqc_packet_in_t packet_in;
    memset(&packet_in, 0, sizeof(packet_in));

    conn->conn_type = XQC_CONN_TYPE_SERVER;
    conn->conn_flag &= ~XQC_CONN_FLAG_TOKEN_OK;
    conn->conn_token_len = 0;
    conn->conn_err = 0;
    conn->version = XQC_VERSION_V1;
    xqc_test_retry_capture(conn, &sent);
    conn->transport_cbs.conn_retry_packet_condition_check =
        xqc_test_retry_required;
    xqc_cid_copy(&packet_in.pi_pkt.pkt_dcid, &conn->original_dcid);

    xqc_int_t ret = xqc_conn_server_accept(conn, &packet_in);
    CU_ASSERT(ret == -XQC_EIGNORE_PKT);
    CU_ASSERT_FATAL(sent.count == 1);
    xqc_cid_copy(&retry_scid, &sent.scid);

    /*
     * RFC 9000 Section 17.2.5.1: the Retry packet is lost and the client
     * sends its Initial packet again, which gets another Retry packet with
     * the same Source Connection ID.
     */
    ret = xqc_conn_server_accept(conn, &packet_in);
    CU_ASSERT(ret == -XQC_EIGNORE_PKT);
    CU_ASSERT(conn->conn_err == 0);
    CU_ASSERT(!(conn->conn_flag & XQC_CONN_FLAG_ERROR));
    CU_ASSERT(sent.count == 2);
    CU_ASSERT(xqc_cid_is_equal(&sent.scid, &retry_scid) == XQC_OK);
    CU_ASSERT(xqc_cid_is_equal(&sent.dcid,
                               &conn->dcid_set.current_dcid) == XQC_OK);
    CU_ASSERT(xqc_cid_is_equal(&conn->retry_scid, &retry_scid) == XQC_OK);

    /* the Retry Source Connection ID maps to the connection once */
    CU_ASSERT(xqc_remove_conns_hash(conn->engine->conns_hash, conn,
                                    retry_scid.cid_buf,
                                    retry_scid.cid_len) == XQC_OK);
    CU_ASSERT(xqc_find_conns_hash(conn->engine->conns_hash, conn,
                                  retry_scid.cid_buf,
                                  retry_scid.cid_len) == NULL);

    xqc_engine_destroy(conn->engine);
}
