/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_tp_test.h"
#include "src/tls/xqc_tls_common.h"
#include "xqc_common_test.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_transport_params.h"

#include <CUnit/CUnit.h>

/* transport parameter from server */
#define XQC_TEST_DECODE_TP_BUF "\x44\xd4\x08\x8c\x46\xe0\xc9\x1b\x81\x88\x22\x05"                 \
                               "\x04\x80\x08\x00\x00\x06\x04\x80\x08\x00\x00\x07\x04\x80\x08\x00" \
                               "\x00\x04\x04\x80\x0c\x00\x00\x08\x02\x40\x64\x09\x02\x40\x64\x01" \
                               "\x04\x80\x00\x75\x30\x03\x02\x45\xac\x0b\x01\x1a\x0c\x00\x02\x10" \
                               "\xeb\x46\xd4\xff\xd2\x14\x26\xe4\xea\x6f\x84\xd8\xcd\x6b\xf5\xa1" \
                               "\x00\x08\x0b\xf7\xbe\xf4\x06\x7a\xa1\xb7\x0e\x01\x04\x0f\x04\xec" \
                               "\x86\xa2\xa7\x20\x01\x00"

char test_encode_tp_buf[XQC_MAX_TRANSPORT_PARAM_BUF_LEN];

void
xqc_test_encode_transport_params()
{
    xqc_int_t ret = XQC_OK;
    size_t nwrite = 0;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    xqc_transport_params_t params;
    memset(&params, 0, sizeof(xqc_transport_params_t));

    ret = xqc_conn_get_local_transport_params(conn, &params);
    CU_ASSERT(ret == XQC_OK);

    ret = xqc_encode_transport_params(&params, XQC_TP_TYPE_CLIENT_HELLO, test_encode_tp_buf,
                                      XQC_MAX_TRANSPORT_PARAM_BUF_LEN, &nwrite);
    CU_ASSERT(ret == XQC_OK && nwrite > 0);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_decode_transport_params()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    xqc_transport_params_t params;
    memset(&params, 0, sizeof(xqc_transport_params_t));

    xqc_int_t ret = xqc_decode_transport_params(&params,
                                                XQC_TP_TYPE_ENCRYPTED_EXTENSIONS,
                                                XQC_TEST_DECODE_TP_BUF,
                                                sizeof(XQC_TEST_DECODE_TP_BUF) - 1);
    CU_ASSERT(ret == XQC_OK);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_encrypted_extensions()
{
    xqc_engine_t *engine = test_create_engine_server();
    CU_ASSERT(engine != NULL);

    xqc_transport_params_t params;
    memset(&params, 0, sizeof(xqc_transport_params_t));

    uint8_t test_stateless_reset_token[XQC_STATELESS_RESET_TOKENLEN] = {0};
    xqc_cid_t test_odcid, test_iscid, test_rscid, test_pacid;
    xqc_generate_cid(engine, NULL, &test_odcid, 0);
    xqc_generate_cid(engine, NULL, &test_iscid, 0);
    xqc_generate_cid(engine, NULL, &test_rscid, 0);
    xqc_generate_cid(engine, NULL, &test_pacid, 0);

    params.initial_max_stream_data_bidi_local = 16 * 1024 * 1024;
    params.initial_max_stream_data_bidi_remote = 16 * 1024 * 1024;
    params.initial_max_stream_data_uni = 16 * 1024 * 1024;
    params.initial_max_data = 16 * 1024 * 1024 * 2;
    params.initial_max_streams_bidi = 1024;
    params.initial_max_streams_uni = 1024;
    params.max_idle_timeout = XQC_CONN_DEFAULT_IDLE_TIMEOUT - 1;
    params.max_udp_payload_size = XQC_CONN_MAX_UDP_PAYLOAD_SIZE - 1;

    params.stateless_reset_token_present = 1;
    memcpy(params.stateless_reset_token, test_stateless_reset_token, sizeof(params.stateless_reset_token));

    params.ack_delay_exponent = XQC_DEFAULT_ACK_DELAY_EXPONENT + 1;
    params.disable_active_migration = 1;
    params.max_ack_delay = XQC_DEFAULT_MAX_ACK_DELAY + 1;
    params.active_connection_id_limit = XQC_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT + 1;
    params.no_crypto = 1;
    params.enable_multipath = 1;

    xqc_cid_set(&params.preferred_address.cid, test_pacid.cid_buf, test_pacid.cid_len);
    memcpy(params.preferred_address.stateless_reset_token, test_stateless_reset_token, sizeof(params.stateless_reset_token));
    params.preferred_address_present = 1;

    xqc_cid_set(&params.original_dest_connection_id, test_odcid.cid_buf, test_odcid.cid_len);
    params.original_dest_connection_id_present = 1;

    xqc_cid_set(&params.initial_source_connection_id, test_iscid.cid_buf, test_iscid.cid_len);
    params.initial_source_connection_id_present = 1;

    xqc_cid_set(&params.retry_source_connection_id, test_rscid.cid_buf, test_rscid.cid_len);
    params.retry_source_connection_id_present = 1;

    xqc_int_t ret = XQC_OK;
    size_t nwrite = 0;

    ret = xqc_encode_transport_params(&params, XQC_TP_TYPE_ENCRYPTED_EXTENSIONS, test_encode_tp_buf,
                                      XQC_MAX_TRANSPORT_PARAM_BUF_LEN, &nwrite);
    CU_ASSERT(ret == XQC_OK && nwrite > 0);

    xqc_transport_params_t dec_params;
    memset(&dec_params, 0, sizeof(xqc_transport_params_t));

    ret = xqc_decode_transport_params(&dec_params, XQC_TP_TYPE_ENCRYPTED_EXTENSIONS,
                                     test_encode_tp_buf, nwrite);
    CU_ASSERT(ret == XQC_OK);

    xqc_engine_destroy(engine);
}

void
xqc_test_transport_params()
{
    xqc_test_encode_transport_params();
    xqc_test_decode_transport_params();

    xqc_test_encrypted_extensions();
}

/*
 * ============================================================================
 * Tests for xqc_conn_check_transport_params (RFC 9000 Section 7.3)
 *
 * Coverage matrix (server / client x ISCID / ODCID / RSCID x present / value):
 *   1  server: client did not send ISCID                  -> reject
 *   2  server: client sent ISCID with wrong value          -> reject
 *   3  server: client sent ISCID with correct value        -> accept
 *   4  server: client illegally sent server-only ODCID     -> reject
 *   5  client: server did not send ISCID                   -> reject
 *   6  client: server sent ISCID with wrong value          -> reject
 *   7  client: server did not send ODCID                   -> reject
 *   8  client: server sent ODCID with wrong value          -> reject
 *   9  client: ISCID + ODCID correct, no Retry             -> accept
 *  10  client: Retry happened, server omitted RSCID        -> reject
 *  11  client: Retry happened, RSCID value mismatched      -> reject
 *  12  client: Retry happened, all three CIDs correct      -> accept
 *  13  client: no Retry, but server illegally sent RSCID   -> reject
 * ============================================================================
 */

/* Build a minimally-valid baseline transport-parameter struct that already
 * satisfies the unrelated `parameters MUST NOT be larger than 2^60` check,
 * leaving each test case free to mutate only the CID-related fields. */
static void
xqc_tp_test_init_baseline(xqc_transport_params_t *params)
{
    memset(params, 0, sizeof(*params));
    params->initial_max_streams_bidi = 1024;
    params->initial_max_streams_uni = 1024;
    params->initial_max_stream_data_bidi_local = 16 * 1024;
    params->initial_max_stream_data_bidi_remote = 16 * 1024;
    params->initial_max_stream_data_uni = 16 * 1024;
}

/* ----------------------------------------------------------------------
 * Test fixture helpers
 *
 * `xqc_conn_check_transport_params` only reads the following connection
 * fields: conn_type, conn_flag, original_dcid, dcid_set.current_dcid,
 * retry_scid, log, engine. It is therefore safe to reuse a client-side
 * connection produced by test_engine_connect() and merely flip conn_type
 * to XQC_CONN_TYPE_SERVER for server-side cases — this avoids dragging in
 * the heavy xqc_conn_server_create() handshake-state machinery.
 * ---------------------------------------------------------------------- */

static xqc_connection_t *
xqc_tp_test_make_conn(xqc_conn_type_t role, xqc_cid_t *out_peer_scid)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    /* normalise the connection role for the test */
    conn->conn_type = role;
    conn->conn_flag &= ~XQC_CONN_FLAG_RETRY_RECVD;
    conn->retry_scid.cid_len = 0;

    /* deterministic peer SCID so tests can construct the matching ISCID */
    xqc_cid_t peer_scid;
    xqc_generate_cid(conn->engine, NULL, &peer_scid, 0);

    if (role == XQC_CONN_TYPE_SERVER) {
        /* on a real server, conn->dcid_set.current_dcid holds the client's
         * SCID (xqc_packet_parse_cid reverses pkt SCID→endpoint dcid,
         * then xqc_conn_create stores it as current_dcid). Populate it
         * here so that an ISCID echoed back by the (simulated) client can
         * be compared against it. */
        xqc_cid_copy(&conn->dcid_set.current_dcid, &peer_scid);
    } else {
        /* on a real client, conn->dcid_set.current_dcid stores the SCID of
         * the server's first Initial after xqc_conn_confirm_cid runs. */
        xqc_cid_copy(&conn->dcid_set.current_dcid, &peer_scid);
    }

    if (out_peer_scid) {
        xqc_cid_copy(out_peer_scid, &peer_scid);
    }
    return conn;
}

/* ---------- server-side cases (1..4) ---------- */

static void
xqc_tp_test_check_server_iscid_absent(void)
{
    xqc_cid_t peer_scid;
    xqc_connection_t *conn = xqc_tp_test_make_conn(XQC_CONN_TYPE_SERVER, &peer_scid);

    xqc_transport_params_t params;
    xqc_tp_test_init_baseline(&params);
    /* leave initial_source_connection_id_present = 0 */
    CU_ASSERT(xqc_conn_check_transport_params(conn, &params) == -XQC_TLS_TRANSPORT_PARAM);

    xqc_engine_destroy(conn->engine);
}

static void
xqc_tp_test_check_server_iscid_mismatch(void)
{
    xqc_cid_t peer_scid, wrong_iscid;
    xqc_connection_t *conn = xqc_tp_test_make_conn(XQC_CONN_TYPE_SERVER, &peer_scid);
    xqc_generate_cid(conn->engine, NULL, &wrong_iscid, 0);

    xqc_transport_params_t params;
    xqc_tp_test_init_baseline(&params);
    xqc_cid_set(&params.initial_source_connection_id, wrong_iscid.cid_buf, wrong_iscid.cid_len);
    params.initial_source_connection_id_present = 1;

    CU_ASSERT(xqc_conn_check_transport_params(conn, &params) == -XQC_TLS_TRANSPORT_PARAM);

    xqc_engine_destroy(conn->engine);
}

static void
xqc_tp_test_check_server_iscid_match(void)
{
    xqc_cid_t peer_scid;
    xqc_connection_t *conn = xqc_tp_test_make_conn(XQC_CONN_TYPE_SERVER, &peer_scid);

    xqc_transport_params_t params;
    xqc_tp_test_init_baseline(&params);
    xqc_cid_set(&params.initial_source_connection_id, peer_scid.cid_buf, peer_scid.cid_len);
    params.initial_source_connection_id_present = 1;

    CU_ASSERT(xqc_conn_check_transport_params(conn, &params) == XQC_OK);

    xqc_engine_destroy(conn->engine);
}

static void
xqc_tp_test_check_server_rejects_server_only_param(void)
{
    xqc_cid_t peer_scid, leaked_odcid;
    xqc_connection_t *conn = xqc_tp_test_make_conn(XQC_CONN_TYPE_SERVER, &peer_scid);
    xqc_generate_cid(conn->engine, NULL, &leaked_odcid, 0);

    xqc_transport_params_t params;
    xqc_tp_test_init_baseline(&params);
    xqc_cid_set(&params.initial_source_connection_id, peer_scid.cid_buf, peer_scid.cid_len);
    params.initial_source_connection_id_present = 1;
    /* client illegally sends a server-only parameter */
    xqc_cid_set(&params.original_dest_connection_id, leaked_odcid.cid_buf, leaked_odcid.cid_len);
    params.original_dest_connection_id_present = 1;

    CU_ASSERT(xqc_conn_check_transport_params(conn, &params) == -XQC_TLS_TRANSPORT_PARAM);

    xqc_engine_destroy(conn->engine);
}

/* shorthand for the client-side helper */
static xqc_connection_t *
xqc_tp_test_make_client_conn(xqc_cid_t *out_server_scid)
{
    return xqc_tp_test_make_conn(XQC_CONN_TYPE_CLIENT, out_server_scid);
}

/* ---------- client-side cases (5..13) ---------- */

static void
xqc_tp_test_check_client_iscid_absent(void)
{
    xqc_cid_t server_scid;
    xqc_connection_t *conn = xqc_tp_test_make_client_conn(&server_scid);

    xqc_transport_params_t params;
    xqc_tp_test_init_baseline(&params);
    /* leave initial_source_connection_id_present = 0 */
    CU_ASSERT(xqc_conn_check_transport_params(conn, &params) == -XQC_TLS_TRANSPORT_PARAM);

    xqc_engine_destroy(conn->engine);
}

static void
xqc_tp_test_check_client_iscid_mismatch(void)
{
    xqc_cid_t server_scid, wrong_iscid;
    xqc_connection_t *conn = xqc_tp_test_make_client_conn(&server_scid);
    xqc_generate_cid(conn->engine, NULL, &wrong_iscid, 0);

    xqc_transport_params_t params;
    xqc_tp_test_init_baseline(&params);
    xqc_cid_set(&params.initial_source_connection_id, wrong_iscid.cid_buf, wrong_iscid.cid_len);
    params.initial_source_connection_id_present = 1;
    /* even if ODCID is correct, ISCID mismatch must reject */
    xqc_cid_set(&params.original_dest_connection_id,
                conn->original_dcid.cid_buf, conn->original_dcid.cid_len);
    params.original_dest_connection_id_present = 1;

    CU_ASSERT(xqc_conn_check_transport_params(conn, &params) == -XQC_TLS_TRANSPORT_PARAM);

    xqc_engine_destroy(conn->engine);
}

static void
xqc_tp_test_check_client_odcid_absent(void)
{
    xqc_cid_t server_scid;
    xqc_connection_t *conn = xqc_tp_test_make_client_conn(&server_scid);

    xqc_transport_params_t params;
    xqc_tp_test_init_baseline(&params);
    xqc_cid_set(&params.initial_source_connection_id, server_scid.cid_buf, server_scid.cid_len);
    params.initial_source_connection_id_present = 1;
    /* leave original_dest_connection_id_present = 0 */

    CU_ASSERT(xqc_conn_check_transport_params(conn, &params) == -XQC_TLS_TRANSPORT_PARAM);

    xqc_engine_destroy(conn->engine);
}

static void
xqc_tp_test_check_client_odcid_mismatch(void)
{
    xqc_cid_t server_scid, wrong_odcid;
    xqc_connection_t *conn = xqc_tp_test_make_client_conn(&server_scid);
    xqc_generate_cid(conn->engine, NULL, &wrong_odcid, 0);

    xqc_transport_params_t params;
    xqc_tp_test_init_baseline(&params);
    xqc_cid_set(&params.initial_source_connection_id, server_scid.cid_buf, server_scid.cid_len);
    params.initial_source_connection_id_present = 1;
    xqc_cid_set(&params.original_dest_connection_id, wrong_odcid.cid_buf, wrong_odcid.cid_len);
    params.original_dest_connection_id_present = 1;

    CU_ASSERT(xqc_conn_check_transport_params(conn, &params) == -XQC_TLS_TRANSPORT_PARAM);

    xqc_engine_destroy(conn->engine);
}

static void
xqc_tp_test_check_client_all_match_no_retry(void)
{
    xqc_cid_t server_scid;
    xqc_connection_t *conn = xqc_tp_test_make_client_conn(&server_scid);

    xqc_transport_params_t params;
    xqc_tp_test_init_baseline(&params);
    xqc_cid_set(&params.initial_source_connection_id, server_scid.cid_buf, server_scid.cid_len);
    params.initial_source_connection_id_present = 1;
    xqc_cid_set(&params.original_dest_connection_id,
                conn->original_dcid.cid_buf, conn->original_dcid.cid_len);
    params.original_dest_connection_id_present = 1;

    CU_ASSERT(xqc_conn_check_transport_params(conn, &params) == XQC_OK);

    xqc_engine_destroy(conn->engine);
}

static void
xqc_tp_test_check_client_retry_rscid_absent(void)
{
    xqc_cid_t server_scid, retry_scid;
    xqc_connection_t *conn = xqc_tp_test_make_client_conn(&server_scid);
    xqc_generate_cid(conn->engine, NULL, &retry_scid, 0);

    /* simulate having received a Retry: set the flag and retry_scid */
    conn->conn_flag |= XQC_CONN_FLAG_RETRY_RECVD;
    xqc_cid_copy(&conn->retry_scid, &retry_scid);

    xqc_transport_params_t params;
    xqc_tp_test_init_baseline(&params);
    xqc_cid_set(&params.initial_source_connection_id, server_scid.cid_buf, server_scid.cid_len);
    params.initial_source_connection_id_present = 1;
    xqc_cid_set(&params.original_dest_connection_id,
                conn->original_dcid.cid_buf, conn->original_dcid.cid_len);
    params.original_dest_connection_id_present = 1;
    /* server omitted retry_source_connection_id */

    CU_ASSERT(xqc_conn_check_transport_params(conn, &params) == -XQC_TLS_TRANSPORT_PARAM);

    xqc_engine_destroy(conn->engine);
}

static void
xqc_tp_test_check_client_retry_rscid_mismatch(void)
{
    xqc_cid_t server_scid, retry_scid, wrong_rscid;
    xqc_connection_t *conn = xqc_tp_test_make_client_conn(&server_scid);
    xqc_generate_cid(conn->engine, NULL, &retry_scid, 0);
    xqc_generate_cid(conn->engine, NULL, &wrong_rscid, 0);

    conn->conn_flag |= XQC_CONN_FLAG_RETRY_RECVD;
    xqc_cid_copy(&conn->retry_scid, &retry_scid);

    xqc_transport_params_t params;
    xqc_tp_test_init_baseline(&params);
    xqc_cid_set(&params.initial_source_connection_id, server_scid.cid_buf, server_scid.cid_len);
    params.initial_source_connection_id_present = 1;
    xqc_cid_set(&params.original_dest_connection_id,
                conn->original_dcid.cid_buf, conn->original_dcid.cid_len);
    params.original_dest_connection_id_present = 1;
    xqc_cid_set(&params.retry_source_connection_id, wrong_rscid.cid_buf, wrong_rscid.cid_len);
    params.retry_source_connection_id_present = 1;

    CU_ASSERT(xqc_conn_check_transport_params(conn, &params) == -XQC_TLS_TRANSPORT_PARAM);

    xqc_engine_destroy(conn->engine);
}

static void
xqc_tp_test_check_client_retry_all_match(void)
{
    xqc_cid_t server_scid, retry_scid;
    xqc_connection_t *conn = xqc_tp_test_make_client_conn(&server_scid);
    xqc_generate_cid(conn->engine, NULL, &retry_scid, 0);

    conn->conn_flag |= XQC_CONN_FLAG_RETRY_RECVD;
    xqc_cid_copy(&conn->retry_scid, &retry_scid);

    xqc_transport_params_t params;
    xqc_tp_test_init_baseline(&params);
    xqc_cid_set(&params.initial_source_connection_id, server_scid.cid_buf, server_scid.cid_len);
    params.initial_source_connection_id_present = 1;
    xqc_cid_set(&params.original_dest_connection_id,
                conn->original_dcid.cid_buf, conn->original_dcid.cid_len);
    params.original_dest_connection_id_present = 1;
    xqc_cid_set(&params.retry_source_connection_id, retry_scid.cid_buf, retry_scid.cid_len);
    params.retry_source_connection_id_present = 1;

    CU_ASSERT(xqc_conn_check_transport_params(conn, &params) == XQC_OK);

    xqc_engine_destroy(conn->engine);
}

static void
xqc_tp_test_check_client_no_retry_but_rscid_present(void)
{
    xqc_cid_t server_scid, ghost_rscid;
    xqc_connection_t *conn = xqc_tp_test_make_client_conn(&server_scid);
    xqc_generate_cid(conn->engine, NULL, &ghost_rscid, 0);

    /* deliberately do NOT set XQC_CONN_FLAG_RETRY_RECVD */

    xqc_transport_params_t params;
    xqc_tp_test_init_baseline(&params);
    xqc_cid_set(&params.initial_source_connection_id, server_scid.cid_buf, server_scid.cid_len);
    params.initial_source_connection_id_present = 1;
    xqc_cid_set(&params.original_dest_connection_id,
                conn->original_dcid.cid_buf, conn->original_dcid.cid_len);
    params.original_dest_connection_id_present = 1;
    /* server illegally attaches retry_source_connection_id without sending Retry */
    xqc_cid_set(&params.retry_source_connection_id, ghost_rscid.cid_buf, ghost_rscid.cid_len);
    params.retry_source_connection_id_present = 1;

    CU_ASSERT(xqc_conn_check_transport_params(conn, &params) == -XQC_TLS_TRANSPORT_PARAM);

    xqc_engine_destroy(conn->engine);
}

/*
 * Test: reject TP CID fields exceeding XQC_MAX_CID_LEN (20 bytes).
 * Constructs raw TP buffers with oversized CID to trigger the length check.
 */
void
xqc_test_tp_cid_overflow(void)
{
    xqc_transport_params_t params;
    xqc_int_t ret;

    /*
     * TP wire format: varint(param_type) + varint(param_len) + data[param_len]
     * initial_source_connection_id = 0x0f, length = 21 (exceeds XQC_MAX_CID_LEN=20)
     */
    uint8_t tp_iscid_overflow[] = {
        0x0f,                                       /* param_type = initial_source_connection_id */
        0x15,                                       /* param_len = 21 (> 20) */
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,  /* 21 bytes of fake CID data */
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15
    };

    memset(&params, 0, sizeof(params));
    ret = xqc_decode_transport_params(&params, XQC_TP_TYPE_ENCRYPTED_EXTENSIONS,
                                      tp_iscid_overflow, sizeof(tp_iscid_overflow));
    CU_ASSERT(ret != XQC_OK);

    /*
     * original_destination_connection_id = 0x00, length = 21
     */
    uint8_t tp_odcid_overflow[] = {
        0x00,                                       /* param_type = original_dest_connection_id */
        0x15,                                       /* param_len = 21 */
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15
    };

    memset(&params, 0, sizeof(params));
    ret = xqc_decode_transport_params(&params, XQC_TP_TYPE_ENCRYPTED_EXTENSIONS,
                                      tp_odcid_overflow, sizeof(tp_odcid_overflow));
    CU_ASSERT(ret != XQC_OK);

    /*
     * retry_source_connection_id = 0x10, length = 21
     * 0x10 as varint: two-byte encoding 0x40 0x10
     */
    uint8_t tp_rscid_overflow[] = {
        0x40, 0x10,                                 /* param_type = retry_source_connection_id (2-byte varint) */
        0x15,                                       /* param_len = 21 */
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15
    };

    memset(&params, 0, sizeof(params));
    ret = xqc_decode_transport_params(&params, XQC_TP_TYPE_ENCRYPTED_EXTENSIONS,
                                      tp_rscid_overflow, sizeof(tp_rscid_overflow));
    CU_ASSERT(ret != XQC_OK);

    /* Boundary: exactly 20 bytes should succeed (initial_source_connection_id) */
    uint8_t tp_iscid_boundary[] = {
        0x0f,                                       /* param_type = initial_source_connection_id */
        0x14,                                       /* param_len = 20 (== XQC_MAX_CID_LEN) */
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14
    };

    memset(&params, 0, sizeof(params));
    ret = xqc_decode_transport_params(&params, XQC_TP_TYPE_ENCRYPTED_EXTENSIONS,
                                      tp_iscid_boundary, sizeof(tp_iscid_boundary));
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(params.initial_source_connection_id.cid_len == 20);
}

/*
 * RFC 9000 §18.2: active_connection_id_limit MUST be at least 2.
 * Verify that decoding a value of 0 or 1 returns an error.
 */
void
xqc_test_active_cid_limit_minimum(void)
{
    xqc_transport_params_t params;
    xqc_int_t ret;

    /*
     * Construct a minimal ENCRYPTED_EXTENSIONS transport parameter buffer
     * containing only active_connection_id_limit = 1 (varint encoded).
     *   param_type  = 0x0e (XQC_TRANSPORT_PARAM_ACTIVE_CONNECTION_ID_LIMIT)
     *   param_len   = 0x01
     *   param_value = 0x01 (varint for 1)
     */
    uint8_t tp_acl_one[] = {
        0x0e,   /* param_type = active_connection_id_limit */
        0x01,   /* param_len = 1 */
        0x01    /* value = 1 */
    };

    memset(&params, 0, sizeof(params));
    ret = xqc_decode_transport_params(&params, XQC_TP_TYPE_ENCRYPTED_EXTENSIONS,
                                      tp_acl_one, sizeof(tp_acl_one));
    CU_ASSERT(ret != XQC_OK);

    /* Also verify value = 0 is rejected */
    uint8_t tp_acl_zero[] = {
        0x0e,   /* param_type = active_connection_id_limit */
        0x01,   /* param_len = 1 */
        0x00    /* value = 0 */
    };

    memset(&params, 0, sizeof(params));
    ret = xqc_decode_transport_params(&params, XQC_TP_TYPE_ENCRYPTED_EXTENSIONS,
                                      tp_acl_zero, sizeof(tp_acl_zero));
    CU_ASSERT(ret != XQC_OK);

    /* Boundary: value = 2 should succeed */
    uint8_t tp_acl_two[] = {
        0x0e,   /* param_type = active_connection_id_limit */
        0x01,   /* param_len = 1 */
        0x02    /* value = 2 */
    };

    memset(&params, 0, sizeof(params));
    ret = xqc_decode_transport_params(&params, XQC_TP_TYPE_ENCRYPTED_EXTENSIONS,
                                      tp_acl_two, sizeof(tp_acl_two));
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(params.active_connection_id_limit == 2);
}

void
xqc_test_check_transport_params_cids(void)
{
    /* server-side */
    xqc_tp_test_check_server_iscid_absent();
    xqc_tp_test_check_server_iscid_mismatch();
    xqc_tp_test_check_server_iscid_match();
    xqc_tp_test_check_server_rejects_server_only_param();

    /* client-side */
    xqc_tp_test_check_client_iscid_absent();
    xqc_tp_test_check_client_iscid_mismatch();
    xqc_tp_test_check_client_odcid_absent();
    xqc_tp_test_check_client_odcid_mismatch();
    xqc_tp_test_check_client_all_match_no_retry();
    xqc_tp_test_check_client_retry_rscid_absent();
    xqc_tp_test_check_client_retry_rscid_mismatch();
    xqc_tp_test_check_client_retry_all_match();
    xqc_tp_test_check_client_no_retry_but_rscid_present();
}