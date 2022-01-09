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