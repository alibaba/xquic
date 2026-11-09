/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xqc_retry_test.h"

#include "xqc_common_test.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_packet_parser.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_stream.h"


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


/* move a queued or probe packet to its unacked list as sending it does */
static void
xqc_retry_test_packet_sent(xqc_connection_t *conn, xqc_packet_out_t *po,
    xqc_packet_number_t pkt_num)
{
    xqc_send_queue_remove_send(&po->po_list);
    po->po_pkt.pkt_num = pkt_num;
    po->po_path_id = conn->conn_initial_path->path_id;
    po->po_sent_time = xqc_monotonic_timestamp();
    xqc_send_ctl_increase_inflight(conn, po);
    xqc_conn_increase_unacked_stream_ref(conn, po);
    xqc_send_queue_insert_unacked(po,
        &conn->conn_send_queue->sndq_unacked_packets[po->po_pkt.pkt_pns],
        conn->conn_send_queue);
}

/* count the packets of a type queued for sending, return the last one */
static unsigned
xqc_retry_test_queued(xqc_connection_t *conn, xqc_pkt_type_t type,
    xqc_frame_type_bit_t frame, xqc_packet_out_t **last)
{
    xqc_send_queue_t *send_queue = conn->conn_send_queue;
    xqc_list_head_t *lists[] = {
        &send_queue->sndq_send_packets_high_pri,
        &send_queue->sndq_send_packets,
    };
    xqc_list_head_t *pos;
    unsigned n = 0;

    for (size_t i = 0; i < sizeof(lists) / sizeof(lists[0]); i++) {
        xqc_list_for_each(pos, lists[i]) {
            xqc_packet_out_t *po = xqc_list_entry(pos, xqc_packet_out_t,
                                                  po_list);
            if (po->po_pkt.pkt_type == type
                && (po->po_frame_types & frame))
            {
                n++;
                *last = po;
            }
        }
    }
    return n;
}

/*
 * RFC 9000 Section 17.2.5.2: a client that receives a Retry sends its
 * Initial again and SHOULD resend its 0-RTT data. The resent 0-RTT packet
 * is the only one left carrying the request: once it is acknowledged, the
 * stream's data is acknowledged. When PTO copies of the ClientHello and
 * of the 0-RTT packet were made before the Retry, each is resent once.
 */
void
xqc_test_retry_resend_sent_0rtt(void)
{
    static const unsigned char req[] = "GET /index.html\r\n";

    for (int probed = 0; probed < 2; probed++) {
        xqc_connection_t *conn = test_engine_connect();
        CU_ASSERT_FATAL(conn != NULL);
        xqc_path_ctx_t *path = conn->conn_initial_path;
        xqc_send_queue_t *send_queue = conn->conn_send_queue;

        xqc_stream_t *stream = xqc_stream_create_with_direction(conn,
            XQC_STREAM_BIDI, NULL);
        CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
        size_t written = 0;
        CU_ASSERT(xqc_write_stream_frame_to_packet(conn, stream,
            XQC_PTYPE_0RTT, 1, req, sizeof(req) - 1, &written) == XQC_OK);
        CU_ASSERT(written == sizeof(req) - 1);

        xqc_packet_out_t *zrtt = NULL;
        CU_ASSERT(xqc_retry_test_queued(conn, XQC_PTYPE_0RTT,
                                        XQC_FRAME_BIT_STREAM, &zrtt) == 1);
        CU_ASSERT_PTR_NOT_NULL_FATAL(zrtt);
        xqc_retry_test_packet_sent(conn, zrtt, 0);
        CU_ASSERT(stream->stream_unacked_pkt == 1);
        CU_ASSERT(stream->stream_state_send
                  == XQC_SEND_STREAM_ST_DATA_SENT);

        xqc_list_head_t *init_list =
            &send_queue->sndq_unacked_packets[XQC_PNS_INIT];
        CU_ASSERT_FATAL(!xqc_list_empty(init_list));
        xqc_packet_out_t *ch = xqc_list_entry(init_list->next,
                                              xqc_packet_out_t, po_list);
        CU_ASSERT(ch->po_frame_types & XQC_FRAME_BIT_CRYPTO);
        if (probed) {
            xqc_send_queue_copy_to_probe(ch, send_queue, path);
            xqc_send_queue_copy_to_probe(zrtt, send_queue, path);
        }

        xqc_cid_t retry_scid;
        xqc_cid_copy(&retry_scid, &path->path_dcid);
        retry_scid.cid_buf[0] ^= 0xff;
        CU_ASSERT(xqc_conn_on_recv_retry(conn, &retry_scid) == XQC_OK);

        xqc_packet_out_t *init = NULL;
        CU_ASSERT(xqc_retry_test_queued(conn, XQC_PTYPE_INIT,
                                        XQC_FRAME_BIT_CRYPTO, &init) == 1);
        zrtt = NULL;
        CU_ASSERT(xqc_retry_test_queued(conn, XQC_PTYPE_0RTT,
                                        XQC_FRAME_BIT_STREAM, &zrtt) == 1);
        CU_ASSERT_PTR_NOT_NULL_FATAL(zrtt);
        CU_ASSERT(zrtt->po_origin == NULL);

        /* the resent packet holds the stream's only unacked reference */
        xqc_retry_test_packet_sent(conn, zrtt, 1);
        CU_ASSERT(stream->stream_unacked_pkt == 1);
        xqc_send_ctl_on_packet_acked(path->path_send_ctl, zrtt,
                                     xqc_monotonic_timestamp(), 0);
        CU_ASSERT(stream->stream_unacked_pkt == 0);
        CU_ASSERT(stream->stream_state_send
                  == XQC_SEND_STREAM_ST_DATA_RECVD);
        CU_ASSERT(conn->conn_err == 0);

        xqc_engine_destroy(conn->engine);
    }
}

/*
 * A 0-RTT packet still queued when the Retry arrives holds no reference:
 * its resent packet takes one when it is sent, and a PTO copy of the
 * resent packet acknowledged first completes the stream once.
 */
void
xqc_test_retry_resend_unsent_0rtt(void)
{
    static const unsigned char req[] = "GET /\r\n";

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_path_ctx_t *path = conn->conn_initial_path;

    xqc_stream_t *stream = xqc_stream_create_with_direction(conn,
        XQC_STREAM_BIDI, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
    size_t written = 0;
    CU_ASSERT(xqc_write_stream_frame_to_packet(conn, stream, XQC_PTYPE_0RTT,
        1, req, sizeof(req) - 1, &written) == XQC_OK);
    CU_ASSERT(stream->stream_unacked_pkt == 0);

    xqc_cid_t retry_scid;
    xqc_cid_copy(&retry_scid, &path->path_dcid);
    retry_scid.cid_buf[0] ^= 0xff;
    CU_ASSERT(xqc_conn_on_recv_retry(conn, &retry_scid) == XQC_OK);

    xqc_packet_out_t *zrtt = NULL;
    CU_ASSERT(xqc_retry_test_queued(conn, XQC_PTYPE_0RTT,
                                    XQC_FRAME_BIT_STREAM, &zrtt) == 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(zrtt);
    CU_ASSERT(!(zrtt->po_flag & XQC_POF_STREAM_UNACK));
    xqc_retry_test_packet_sent(conn, zrtt, 0);
    CU_ASSERT(stream->stream_unacked_pkt == 1);
    CU_ASSERT(stream->stream_state_send == XQC_SEND_STREAM_ST_DATA_SENT);

    xqc_send_queue_copy_to_probe(zrtt, conn->conn_send_queue, path);
    xqc_list_head_t *probes = &conn->conn_send_queue->sndq_pto_probe_packets;
    CU_ASSERT_FATAL(!xqc_list_empty(probes));
    xqc_packet_out_t *copy = xqc_list_entry(probes->next, xqc_packet_out_t,
                                            po_list);
    CU_ASSERT(copy->po_origin == zrtt);
    xqc_retry_test_packet_sent(conn, copy, 1);
    CU_ASSERT(stream->stream_unacked_pkt == 1);

    xqc_send_ctl_on_packet_acked(path->path_send_ctl, copy,
                                 xqc_monotonic_timestamp(), 0);
    CU_ASSERT(stream->stream_unacked_pkt == 0);
    CU_ASSERT(stream->stream_state_send == XQC_SEND_STREAM_ST_DATA_RECVD);
    xqc_send_ctl_on_packet_acked(path->path_send_ctl, zrtt,
                                 xqc_monotonic_timestamp(), 0);
    CU_ASSERT(stream->stream_unacked_pkt == 0);
    CU_ASSERT(conn->conn_err == 0);

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
