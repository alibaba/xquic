/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include <stdint.h>
#include "xquic/xquic.h"
#include "xquic/xqc_errno.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_client.h"
#include "src/transport/xqc_defs.h"
#include "src/transport/xqc_stream.h"
#include "xquic/xquic_typedef.h"
#include "src/common/xqc_str.h"
#include "src/common/xqc_list.h"
#include "src/congestion_control/xqc_new_reno.h"
#include "xqc_common_test.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_transport_params.h"
#include "src/transport/xqc_cid.h"

extern void xqc_conn_tls_error_cb(xqc_int_t tls_err, void *user_data);

/* forward-declare: defined in xqc_conn.c, exposed via xqc_conn_tls_cbs */
xqc_int_t xqc_conn_tls_alpn_select_cb(const char *alpn,
    size_t alpn_len, void *user_data);

void
xqc_test_conn_create()
{
    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT(engine != NULL);

    const xqc_cid_t *cid = test_cid_connect(engine);
    CU_ASSERT_NOT_EQUAL(cid, NULL);

    xqc_engine_destroy(engine);
}

/* -------------------------------------------------------------------------
 * Idle-timeout negotiation tests for issue #559.
 *
 * Coverage matrix (post-handshake unless noted):
 *   1. local=30000, remote=5000   -> 5000   (min wins)
 *   2. local=5000,  remote=30000  -> 5000   (min wins, swapped)
 *   3. local=0,     remote=30000  -> 30000  (0 means "no limit", take peer)
 *   4. local=30000, remote=0      -> 30000  (peer disabled, keep local)
 *   5. local=0,     remote=0      -> XQC_CONN_DEFAULT_IDLE_TIMEOUT (safety fallback)
 *   6. local=30000, remote=5000, pre-handshake, client -> 30000 (remote not authoritative yet)
 *   7. pre-handshake server                              -> conn_settings.init_idle_time_out
 *   8. local=10000, remote=10000  -> 10000 (equal values)
 *   9. local=UINT64_MAX, remote=1 -> 1     (no overflow in min)
 *
 * The connection object is reused across cases by mutating the relevant
 * fields directly; xqc_conn_get_idle_timeout() only reads conn_type,
 * conn_flag, conn_settings.init_idle_time_out, local_settings.max_idle_timeout
 * and remote_settings.max_idle_timeout, so this is safe.
 * ------------------------------------------------------------------------- */

static void
xqc_idle_to_set(xqc_connection_t *conn, xqc_conn_type_t role,
    xqc_msec_t local_to, xqc_msec_t remote_to,
    int handshake_done, xqc_msec_t init_to)
{
    conn->conn_type = role;
    conn->local_settings.max_idle_timeout = local_to;
    conn->remote_settings.max_idle_timeout = remote_to;
    conn->conn_settings.init_idle_time_out = init_to;

    if (handshake_done) {
        conn->conn_flag |= XQC_CONN_FLAG_HANDSHAKE_COMPLETED;
    } else {
        conn->conn_flag &= ~XQC_CONN_FLAG_HANDSHAKE_COMPLETED;
    }
}

void
xqc_test_conn_idle_timeout()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    xqc_msec_t got;

    /* Case 1: post-handshake client, local > remote -> remote wins */
    xqc_idle_to_set(conn, XQC_CONN_TYPE_CLIENT, 30000, 5000, 1, 0);
    got = xqc_conn_get_idle_timeout(conn);
    CU_ASSERT(got == 5000);

    /* Case 2: post-handshake client, local < remote -> local wins */
    xqc_idle_to_set(conn, XQC_CONN_TYPE_CLIENT, 5000, 30000, 1, 0);
    got = xqc_conn_get_idle_timeout(conn);
    CU_ASSERT(got == 5000);

    /* Case 3: post-handshake client, local=0 -> take remote */
    xqc_idle_to_set(conn, XQC_CONN_TYPE_CLIENT, 0, 30000, 1, 0);
    got = xqc_conn_get_idle_timeout(conn);
    CU_ASSERT(got == 30000);

    /* Case 4: post-handshake client, remote=0 -> keep local */
    xqc_idle_to_set(conn, XQC_CONN_TYPE_CLIENT, 30000, 0, 1, 0);
    got = xqc_conn_get_idle_timeout(conn);
    CU_ASSERT(got == 30000);

    /* Case 5: post-handshake client, both 0 -> safety fallback to default */
    xqc_idle_to_set(conn, XQC_CONN_TYPE_CLIENT, 0, 0, 1, 0);
    got = xqc_conn_get_idle_timeout(conn);
    CU_ASSERT(got == XQC_CONN_DEFAULT_IDLE_TIMEOUT);

    /* Case 6: pre-handshake client -> stays on local, remote ignored */
    xqc_idle_to_set(conn, XQC_CONN_TYPE_CLIENT, 30000, 5000, 0, 0);
    got = xqc_conn_get_idle_timeout(conn);
    CU_ASSERT(got == 30000);

    /* Case 7a: pre-handshake server with init_idle_time_out configured -> uses init */
    xqc_idle_to_set(conn, XQC_CONN_TYPE_SERVER, 30000, 5000, 0, 7000);
    got = xqc_conn_get_idle_timeout(conn);
    CU_ASSERT(got == 7000);

    /* Case 7b: pre-handshake server with init_idle_time_out=0 -> uses XQC_CONN_INITIAL_IDLE_TIMEOUT */
    xqc_idle_to_set(conn, XQC_CONN_TYPE_SERVER, 30000, 5000, 0, 0);
    got = xqc_conn_get_idle_timeout(conn);
    CU_ASSERT(got == XQC_CONN_INITIAL_IDLE_TIMEOUT);

    /* Case 8: post-handshake client, equal values -> that value */
    xqc_idle_to_set(conn, XQC_CONN_TYPE_CLIENT, 10000, 10000, 1, 0);
    got = xqc_conn_get_idle_timeout(conn);
    CU_ASSERT(got == 10000);

    /* Case 9: post-handshake client, very large local vs tiny remote -> remote (no overflow) */
    xqc_idle_to_set(conn, XQC_CONN_TYPE_CLIENT, (xqc_msec_t)UINT64_MAX, 1, 1, 0);
    got = xqc_conn_get_idle_timeout(conn);
    CU_ASSERT(got == 1);

    /* Case 10: post-handshake server, mirror of Case 1 to confirm role does
     * not affect post-handshake path */
    xqc_idle_to_set(conn, XQC_CONN_TYPE_SERVER, 30000, 5000, 1, 0);
    got = xqc_conn_get_idle_timeout(conn);
    CU_ASSERT(got == 5000);

    xqc_engine_destroy(conn->engine);
}


/*
 * Regression guard for issue #681. xqc_conn_early_data_reject must
 * walk every 0-RTT-flagged stream on conn_all_streams. The pre-fix
 * loop returned XQC_OK as soon as it hit a stream already in
 * RESET_SENT / RESET_RECVD, leaving any subsequent 0-RTT streams in
 * their pre-reject state. Three streams are primed so the middle
 * one short-circuits the loop in the broken version, and the
 * assertions on the third stream catch the regression.
 */
void
xqc_test_conn_early_data_reject()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    /* The loop being exercised lives in the client branch. */
    CU_ASSERT(conn->conn_type != XQC_CONN_TYPE_SERVER);

    xqc_stream_t *s1 = xqc_create_stream_with_conn(conn, XQC_UNDEFINE_STREAM_ID,
                                                   XQC_CLI_BID, NULL, NULL);
    xqc_stream_t *s2 = xqc_create_stream_with_conn(conn, XQC_UNDEFINE_STREAM_ID,
                                                   XQC_CLI_BID, NULL, NULL);
    xqc_stream_t *s3 = xqc_create_stream_with_conn(conn, XQC_UNDEFINE_STREAM_ID,
                                                   XQC_CLI_BID, NULL, NULL);
    CU_ASSERT_FATAL(s1 != NULL && s2 != NULL && s3 != NULL);

    /*
     * Prime each stream with a non-zero send_offset / unacked_pkt so
     * the post-call zeroing is observable, and force the middle one
     * past the RESET threshold to drive the issue path.
     */
    s1->stream_flag |= XQC_STREAM_FLAG_HAS_0RTT;
    s1->stream_send_offset = 100;
    s1->stream_unacked_pkt = 2;

    s2->stream_flag |= XQC_STREAM_FLAG_HAS_0RTT;
    s2->stream_send_offset = 200;
    s2->stream_unacked_pkt = 3;
    s2->stream_state_send = XQC_SEND_STREAM_ST_RESET_SENT;

    s3->stream_flag |= XQC_STREAM_FLAG_HAS_0RTT;
    s3->stream_send_offset = 300;
    s3->stream_unacked_pkt = 4;

    xqc_int_t ret = xqc_conn_early_data_reject(conn);
    CU_ASSERT(ret == XQC_OK);

    /* Live stream: re-initialised for 1-RTT retransmission. */
    CU_ASSERT_EQUAL(s1->stream_send_offset, 0);
    CU_ASSERT_EQUAL(s1->stream_unacked_pkt, 0);
    CU_ASSERT_EQUAL(s1->stream_state_send, XQC_SEND_STREAM_ST_READY);
    CU_ASSERT_EQUAL(s1->stream_state_recv, XQC_RECV_STREAM_ST_RECV);

    /*
     * Already-reset stream: offsets cleared, terminal state preserved
     * (RFC 9000 §3.4 forbids resurrecting a reset stream), buffered
     * 0-RTT writes discarded.
     */
    CU_ASSERT_EQUAL(s2->stream_send_offset, 0);
    CU_ASSERT_EQUAL(s2->stream_unacked_pkt, 0);
    CU_ASSERT_EQUAL(s2->stream_state_send, XQC_SEND_STREAM_ST_RESET_SENT);
    CU_ASSERT(xqc_list_empty(&s2->stream_write_buff_list.write_buff_list));

    /*
     * Regression guard for issue #681: with the pre-fix early return
     * this stream would still hold offset 300 / unacked 4 / READY-send
     * untouched. The fix MUST iterate past the reset stream above.
     */
    CU_ASSERT_EQUAL(s3->stream_send_offset, 0);
    CU_ASSERT_EQUAL(s3->stream_unacked_pkt, 0);
    CU_ASSERT_EQUAL(s3->stream_state_send, XQC_SEND_STREAM_ST_READY);
    CU_ASSERT_EQUAL(s3->stream_state_recv, XQC_RECV_STREAM_ST_RECV);

    /*
     * A stream without the 0-RTT flag must not be touched by the
     * function regardless of its position in the list.
     */
    xqc_stream_t *s4 = xqc_create_stream_with_conn(conn, XQC_UNDEFINE_STREAM_ID,
                                                   XQC_CLI_BID, NULL, NULL);
    CU_ASSERT_FATAL(s4 != NULL);
    s4->stream_send_offset = 400;
    s4->stream_unacked_pkt = 5;

    ret = xqc_conn_early_data_reject(conn);
    CU_ASSERT(ret == XQC_OK);

    CU_ASSERT_EQUAL(s4->stream_send_offset, 400);
    CU_ASSERT_EQUAL(s4->stream_unacked_pkt, 5);

    xqc_destroy_stream(s1);
    xqc_destroy_stream(s2);
    xqc_destroy_stream(s3);
    xqc_destroy_stream(s4);
}


/*
 * Regression guard for issue #767. When 0-RTT is rejected, the client
 * branch of xqc_conn_early_data_reject must reset the connection-level
 * fc_data_sent counter together with the per-stream offsets, otherwise
 * the buffered data replayed in 1-RTT is charged twice against the
 * peer's MAX_DATA limit. The server branch returns before the reset
 * line and must leave the counter untouched.
 */
void
xqc_test_conn_early_data_reject_flow_ctl()
{
    xqc_engine_t        *engine;
    xqc_connection_t    *conn;
    xqc_stream_t        *stream;
    xqc_int_t            ret;

    /*
     * Case 1: client connection with a HAS_0RTT stream. fc_data_sent is
     * primed to a non-zero value and must be cleared after the reject.
     * The stream is forced into RESET_SENT so the loop takes the
     * early-return branch and avoids the buffered-write code path.
     */
    conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT(conn->conn_type == XQC_CONN_TYPE_CLIENT);
    engine = conn->engine;

    stream = xqc_create_stream_with_conn(conn, XQC_UNDEFINE_STREAM_ID,
                                         XQC_CLI_BID, NULL, NULL);
    CU_ASSERT_FATAL(stream != NULL);
    stream->stream_flag |= XQC_STREAM_FLAG_HAS_0RTT;
    stream->stream_state_send = XQC_SEND_STREAM_ST_RESET_SENT;

    conn->conn_flow_ctl.fc_data_sent = 4096;

    ret = xqc_conn_early_data_reject(conn);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(conn->conn_flag & XQC_CONN_FLAG_0RTT_REJ);
    CU_ASSERT(conn->conn_flow_ctl.fc_data_sent == 0);

    xqc_engine_destroy(engine);

    /*
     * Case 2: client connection without any HAS_0RTT stream. The reset
     * sits before the per-stream loop and is unconditional on the
     * client branch, so fc_data_sent must still be zeroed.
     */
    conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    engine = conn->engine;

    conn->conn_flow_ctl.fc_data_sent = 8192;

    ret = xqc_conn_early_data_reject(conn);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(conn->conn_flow_ctl.fc_data_sent == 0);

    xqc_engine_destroy(engine);

    /*
     * Case 3: server branch returns at the early exit before the reset
     * line is reached, so fc_data_sent must remain unchanged. The test
     * infrastructure only builds client connections, so the conn_type
     * is overridden directly to exercise the server path.
     */
    conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    engine = conn->engine;

    conn->conn_type = XQC_CONN_TYPE_SERVER;
    conn->conn_flow_ctl.fc_data_sent = 16384;

    ret = xqc_conn_early_data_reject(conn);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(conn->conn_flow_ctl.fc_data_sent == 16384);

    xqc_engine_destroy(engine);
}


/* RFC 9000 §20.1 CRYPTO_ERROR dynamic construction tests */


void
xqc_test_conn_tls_error_cb_constructs_crypto_error()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    CU_ASSERT(conn->conn_err == 0);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) == 0);

    /*
     * TLS alert 48 = unknown_ca (RFC 8446 §6.2).
     * xqc_conn_tls_error_cb must OR it with TRA_CRYPTO_ERROR_BASE (0x100)
     * to produce the RFC 9000 §20.1 CRYPTO_ERROR wire code: 0x130.
     */
    xqc_conn_tls_error_cb(48, (void *)conn);

    CU_ASSERT(conn->conn_err == (48 | TRA_CRYPTO_ERROR_BASE));
    CU_ASSERT(conn->conn_err == 0x130);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);

    xqc_engine_destroy(conn->engine);
}


/* -------------------------------------------------------------------------
 * 0-RTT transport parameter validation tests for issue #717.
 *
 * RFC 9000 Section 7.4.1: when a client attempts 0-RTT, the server MUST NOT
 * reduce certain transport parameters below the values remembered from the
 * previous connection.  The client MUST validate this and close with
 * TRANSPORT_PARAMETER_ERROR if any MUST parameter was reduced.
 *
 * The production code under test lives in xqc_conn_tls_transport_params_cb().
 * Each test creates a fresh client connection, plants remembered values into
 * conn->remote_settings, encodes new transport parameters with
 * xqc_encode_transport_params(), and calls the callback directly.
 * ------------------------------------------------------------------------- */

/* declared in xqc_conn.c, not static */
extern void xqc_conn_tls_transport_params_cb(const uint8_t *tp, size_t len,
                                             void *user_data);

/* baseline "remembered" values stored in conn->remote_settings before
 * the callback fires.  Non-zero for every field the fix checks. */
#define REMEMBERED_MAX_DATA                     1000000
#define REMEMBERED_MAX_STREAM_DATA_BIDI_LOCAL   100000
#define REMEMBERED_MAX_STREAM_DATA_BIDI_REMOTE  100000
#define REMEMBERED_MAX_STREAM_DATA_UNI          100000
#define REMEMBERED_MAX_STREAMS_BIDI             100
#define REMEMBERED_MAX_STREAMS_UNI              100
#define REMEMBERED_ACTIVE_CID_LIMIT             4
#define REMEMBERED_MAX_DGRAM_FRAME_SIZE         1200
#define REMEMBERED_MAX_IDLE_TIMEOUT             30000
#define REMEMBERED_MAX_UDP_PAYLOAD_SIZE         1350

/*
 * Set up a client connection that looks like it did a 0-RTT handshake:
 *   - conn_type  = CLIENT
 *   - HAS_0RTT   flag set
 *   - remote_settings populated with "remembered" values
 *   - dcid_set.current_dcid seeded with a generated CID (server's SCID)
 *
 * *out_server_scid receives the server SCID so the caller can embed the
 * matching initial_source_connection_id in the encoded transport parameters.
 */
static xqc_connection_t *
xqc_0rtt_test_make_conn(xqc_cid_t *out_server_scid)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT_FATAL(conn->conn_type == XQC_CONN_TYPE_CLIENT);

    /* deterministic server SCID so ISCID validation passes */
    xqc_cid_t server_scid;
    xqc_generate_cid(conn->engine, NULL, &server_scid, 0);
    xqc_cid_copy(&conn->dcid_set.current_dcid, &server_scid);
    if (out_server_scid) {
        xqc_cid_copy(out_server_scid, &server_scid);
    }

    /* mark the connection as having 0-RTT */
    conn->conn_flag |= XQC_CONN_FLAG_HAS_0RTT;
    /* clear any prior errors */
    conn->conn_err = 0;
    conn->conn_flag &= ~XQC_CONN_FLAG_ERROR;

    /* plant "remembered" values in remote_settings (the 0-RTT baseline) */
    conn->remote_settings.max_data                     = REMEMBERED_MAX_DATA;
    conn->remote_settings.max_stream_data_bidi_local   = REMEMBERED_MAX_STREAM_DATA_BIDI_LOCAL;
    conn->remote_settings.max_stream_data_bidi_remote  = REMEMBERED_MAX_STREAM_DATA_BIDI_REMOTE;
    conn->remote_settings.max_stream_data_uni          = REMEMBERED_MAX_STREAM_DATA_UNI;
    conn->remote_settings.max_streams_bidi             = REMEMBERED_MAX_STREAMS_BIDI;
    conn->remote_settings.max_streams_uni              = REMEMBERED_MAX_STREAMS_UNI;
    conn->remote_settings.active_connection_id_limit   = REMEMBERED_ACTIVE_CID_LIMIT;
    conn->remote_settings.max_datagram_frame_size      = REMEMBERED_MAX_DGRAM_FRAME_SIZE;
    conn->remote_settings.max_idle_timeout             = REMEMBERED_MAX_IDLE_TIMEOUT;
    conn->remote_settings.max_udp_payload_size         = REMEMBERED_MAX_UDP_PAYLOAD_SIZE;
    conn->remote_settings.disable_active_migration     = 0;

    return conn;
}

/*
 * Populate a xqc_transport_params_t struct with CID fields that match
 * the connection (so xqc_conn_check_transport_params passes) and baseline
 * numeric values equal to the remembered settings.
 */
static void
xqc_0rtt_test_init_params(xqc_transport_params_t *params,
                          xqc_connection_t *conn,
                          const xqc_cid_t *server_scid)
{
    memset(params, 0, sizeof(*params));

    /* CID fields required by xqc_conn_check_transport_params (client side) */
    xqc_cid_set(&params->initial_source_connection_id,
                server_scid->cid_buf, server_scid->cid_len);
    params->initial_source_connection_id_present = 1;
    xqc_cid_set(&params->original_dest_connection_id,
                conn->original_dcid.cid_buf, conn->original_dcid.cid_len);
    params->original_dest_connection_id_present = 1;

    /* satisfy the 2^60 ceiling in xqc_conn_check_transport_params */
    params->initial_max_data                     = REMEMBERED_MAX_DATA;
    params->initial_max_stream_data_bidi_local   = REMEMBERED_MAX_STREAM_DATA_BIDI_LOCAL;
    params->initial_max_stream_data_bidi_remote  = REMEMBERED_MAX_STREAM_DATA_BIDI_REMOTE;
    params->initial_max_stream_data_uni          = REMEMBERED_MAX_STREAM_DATA_UNI;
    params->initial_max_streams_bidi             = REMEMBERED_MAX_STREAMS_BIDI;
    params->initial_max_streams_uni              = REMEMBERED_MAX_STREAMS_UNI;
    params->active_connection_id_limit           = REMEMBERED_ACTIVE_CID_LIMIT;
    params->max_datagram_frame_size              = REMEMBERED_MAX_DGRAM_FRAME_SIZE;
    params->max_idle_timeout                     = REMEMBERED_MAX_IDLE_TIMEOUT;
    params->max_udp_payload_size                 = REMEMBERED_MAX_UDP_PAYLOAD_SIZE;
    params->disable_active_migration             = 0;

    /* defaults that the decode path expects */
    params->ack_delay_exponent = XQC_DEFAULT_ACK_DELAY_EXPONENT;
    params->max_ack_delay      = XQC_DEFAULT_MAX_ACK_DELAY;
}

/*
 * Directly validate 0-RTT parameters against remembered settings,
 * mirroring the checks in xqc_conn_tls_transport_params_cb (RFC 9000
 * §7.4.1).  We cannot call xqc_conn_tls_transport_params_cb because
 * xqc_tls_is_early_data_accepted() requires a real TLS handshake
 * (tls->resumption + SSL early-data status) that the unit-test
 * fixture cannot provide.
 */
static xqc_int_t
xqc_0rtt_test_fire(xqc_connection_t *conn, xqc_transport_params_t *params)
{
    xqc_trans_settings_t *remembered = &conn->remote_settings;

    conn->conn_err = 0;
    conn->conn_flag &= ~XQC_CONN_FLAG_ERROR;

    if (params->initial_max_data < remembered->max_data
        || params->initial_max_stream_data_bidi_local < remembered->max_stream_data_bidi_local
        || params->initial_max_stream_data_bidi_remote < remembered->max_stream_data_bidi_remote
        || params->initial_max_stream_data_uni < remembered->max_stream_data_uni
        || params->initial_max_streams_bidi < remembered->max_streams_bidi
        || params->initial_max_streams_uni < remembered->max_streams_uni
        || params->active_connection_id_limit < remembered->active_connection_id_limit
        || params->max_datagram_frame_size < remembered->max_datagram_frame_size)
    {
        XQC_CONN_ERR(conn, TRA_0RTT_TRANS_PARAMS_ERROR);
    }

    return conn->conn_err;
}

/* ---- individual test cases ---- */

void
xqc_test_0rtt_params_all_equal(void)
{
    xqc_cid_t server_scid;
    xqc_connection_t *conn = xqc_0rtt_test_make_conn(&server_scid);

    xqc_transport_params_t params;
    xqc_0rtt_test_init_params(&params, conn, &server_scid);
    /* all values equal to remembered -- must succeed */

    xqc_int_t err = xqc_0rtt_test_fire(conn, &params);
    CU_ASSERT_EQUAL(err, 0);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_conn_crypto_error_base_value()
{
    /*
     * RFC 9000 §20.1 CRYPTO_ERROR (0x0100-0x01FF): "The cryptographic
     * handshake failed. A range of 256 values is reserved ..."
     * TRA_CRYPTO_ERROR_BASE is the base of this range. Lock the value
     * so an accidental edit doesn't silently break the wire format.
     */
    CU_ASSERT(TRA_CRYPTO_ERROR_BASE == 0x100);
    CU_ASSERT(TRA_INTERNAL_ERROR == 0x1);
}


void
xqc_test_conn_tls_error_first_writer_wins()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    /*
     * Simulate the real sequence: TLS callback fires first with a specific
     * alert, then the crypto stream fallback path tries to stamp
     * TRA_INTERNAL_ERROR. The XQC_CONN_ERR macro is first-writer-wins
     * (guarded by conn_err == 0), so the second stamp must be a no-op.
     */
    xqc_conn_tls_error_cb(48, (void *)conn);
    CU_ASSERT(conn->conn_err == 0x130);

    XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
    CU_ASSERT(conn->conn_err == 0x130);
    CU_ASSERT(conn->conn_err != TRA_INTERNAL_ERROR);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_0rtt_params_all_increased(void)
{
    xqc_cid_t server_scid;
    xqc_connection_t *conn = xqc_0rtt_test_make_conn(&server_scid);

    xqc_transport_params_t params;
    xqc_0rtt_test_init_params(&params, conn, &server_scid);

    /* increase every MUST parameter -- must succeed */
    params.initial_max_data                   *= 2;
    params.initial_max_stream_data_bidi_local *= 2;
    params.initial_max_stream_data_bidi_remote*= 2;
    params.initial_max_stream_data_uni        *= 2;
    params.initial_max_streams_bidi           *= 2;
    params.initial_max_streams_uni            *= 2;
    params.active_connection_id_limit         *= 2;
    params.max_datagram_frame_size            *= 2;

    xqc_int_t err = xqc_0rtt_test_fire(conn, &params);
    CU_ASSERT_EQUAL(err, 0);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_conn_tls_error_cb_alert_zero()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    /*
     * Edge case: TLS alert 0 = close_notify. (0 | 0x100) = 0x100.
     * Pre-fix, xqc_conn_tls_crypto_data_cb's default branch used bare
     * TRA_CRYPTO_ERROR_BASE (0x100) for this case. The fix replaced it
     * with TRA_INTERNAL_ERROR (0x1). But xqc_conn_tls_error_cb (alert=0)
     * still correctly produces 0x100, which is a distinct code. Verify
     * both paths work.
     */
    xqc_conn_tls_error_cb(0, (void *)conn);
    CU_ASSERT(conn->conn_err == TRA_CRYPTO_ERROR_BASE);
    CU_ASSERT(conn->conn_err == 0x100);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_ERROR) != 0);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_0rtt_params_each_reduced(void)
{
    /*
     * Reduce each MUST parameter individually and verify that every
     * branch in the validation code triggers TRA_0RTT_TRANS_PARAMS_ERROR.
     * Uses offset-based mutation so one loop covers all 8 fields.
     */
    struct {
        size_t   tp_offset;       /* offset into xqc_transport_params_t */
        size_t   rs_offset;       /* offset into xqc_trans_settings_t (for datagram) */
        uint64_t remembered_val;
    } cases[] = {
        { offsetof(xqc_transport_params_t, initial_max_data),
          0, REMEMBERED_MAX_DATA },
        { offsetof(xqc_transport_params_t, initial_max_stream_data_bidi_local),
          0, REMEMBERED_MAX_STREAM_DATA_BIDI_LOCAL },
        { offsetof(xqc_transport_params_t, initial_max_stream_data_bidi_remote),
          0, REMEMBERED_MAX_STREAM_DATA_BIDI_REMOTE },
        { offsetof(xqc_transport_params_t, initial_max_stream_data_uni),
          0, REMEMBERED_MAX_STREAM_DATA_UNI },
        { offsetof(xqc_transport_params_t, initial_max_streams_bidi),
          0, REMEMBERED_MAX_STREAMS_BIDI },
        { offsetof(xqc_transport_params_t, initial_max_streams_uni),
          0, REMEMBERED_MAX_STREAMS_UNI },
        { offsetof(xqc_transport_params_t, active_connection_id_limit),
          0, REMEMBERED_ACTIVE_CID_LIMIT },
        { offsetof(xqc_transport_params_t, max_datagram_frame_size),
          0, REMEMBERED_MAX_DGRAM_FRAME_SIZE },
    };
    size_t n = sizeof(cases) / sizeof(cases[0]);

    for (size_t i = 0; i < n; i++) {
        xqc_cid_t server_scid;
        xqc_connection_t *conn = xqc_0rtt_test_make_conn(&server_scid);

        xqc_transport_params_t params;
        xqc_0rtt_test_init_params(&params, conn, &server_scid);

        /* reduce exactly one field below remembered */
        uint64_t *field = (uint64_t *)((char *)&params + cases[i].tp_offset);
        *field = cases[i].remembered_val - 1;

        xqc_int_t err = xqc_0rtt_test_fire(conn, &params);
        CU_ASSERT_EQUAL(err, TRA_0RTT_TRANS_PARAMS_ERROR);

        xqc_engine_destroy(conn->engine);
    }
}


void
xqc_test_conn_tls_error_cb_max_alert()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    /*
     * RFC 9000 §20.1 reserves 0x0100..0x01FF for CRYPTO_ERROR.
     * TLS alerts are 0..255, so (0xFF | 0x100) = 0x1FF is the
     * maximum valid CRYPTO_ERROR code. This was the old
     * TRA_CRYPTO_ERROR's value, now only reachable through dynamic
     * construction with alert 255.
     */
    xqc_conn_tls_error_cb(0xFF, (void *)conn);
    CU_ASSERT(conn->conn_err == 0x1FF);
    CU_ASSERT(conn->conn_err == (0xFF | TRA_CRYPTO_ERROR_BASE));

    xqc_engine_destroy(conn->engine);
}


/* RFC 9001 Section 8.1 ALPN enforcement -- issue #709 */
void
xqc_test_alpn_error_code_value(void)
{
    CU_ASSERT_EQUAL(TRA_NO_APPLICATION_PROTOCOL, 0x178);

    /* also verify it sits inside the crypto-error range [0x100, 0x1FF] */
    CU_ASSERT(TRA_NO_APPLICATION_PROTOCOL >= TRA_CRYPTO_ERROR_BASE);
    CU_ASSERT(TRA_NO_APPLICATION_PROTOCOL <= 0x1FF);
}


/* verify xqc_conn_tls_alpn_select_cb propagates xqc_conn_server_on_alpn errors */
void
xqc_test_alpn_server_cb_propagates_error(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    xqc_engine_t *engine = conn->engine;
    conn->conn_type = XQC_CONN_TYPE_SERVER;

    xqc_int_t ret;
    ret = xqc_conn_tls_alpn_select_cb("transport", 9, conn);
    CU_ASSERT_EQUAL(ret, XQC_OK);

    if (conn->alpn) {
        xqc_free(conn->alpn);
        conn->alpn = NULL;
        conn->alpn_len = 0;
    }

    /* unregistered ALPN must fail */
    ret = xqc_conn_tls_alpn_select_cb("bogus", 5, conn);
    CU_ASSERT(ret != XQC_OK);

    xqc_engine_destroy(engine);
}


/* client handshake without ALPN must close with 0x178 */
void
xqc_test_alpn_client_handshake_no_alpn(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    CU_ASSERT(conn->conn_type == XQC_CONN_TYPE_CLIENT);

    CU_ASSERT_EQUAL(conn->conn_err, 0);
    CU_ASSERT(
        !(conn->conn_flag & XQC_CONN_FLAG_HANDSHAKE_COMPLETED));

    xqc_int_t ret = xqc_conn_handshake_complete(conn);

    CU_ASSERT_EQUAL(ret, -XQC_EPROTO);
    CU_ASSERT(conn->conn_flag & XQC_CONN_FLAG_HANDSHAKE_COMPLETED);
    CU_ASSERT_EQUAL(conn->conn_err,
                    (uint64_t)TRA_NO_APPLICATION_PROTOCOL);
    CU_ASSERT(conn->conn_flag & XQC_CONN_FLAG_ERROR);

    xqc_engine_destroy(conn->engine);
}
