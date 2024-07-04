/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>

#include "xqc_fec_scheme_test.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_fec_scheme.h"
#include "src/transport/fec_schemes/xqc_xor.h"
#include "xqc_common_test.h"

char XQC_TEST_SID_FRAME[] = {0x80, 0x00, 0xfe, 0xc5, 0x00, 0x00, 0x00, 0x00};
char XQC_TEST_RPR_FRAME[] = {0x80, 0x00, 0xfe, 0xc6, 0x00, 0x00, 0x00, 0x00};
char XQC_TEST_STREAM[] = {0x01, 0x00, 0x00, 0x00, 0x00};


const xqc_cid_t *
test_cid_connect_fec(xqc_engine_t *engine)
{
    xqc_conn_settings_t conn_settings;
    memset(&conn_settings, 0, sizeof(xqc_conn_settings_t));
    conn_settings.proto_version = XQC_VERSION_V1;
    conn_settings.enable_encode_fec = 1;
    conn_settings.enable_decode_fec = 1;
    
    xqc_conn_ssl_config_t conn_ssl_config;
    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));
    const xqc_cid_t *cid = xqc_connect(engine, &conn_settings, NULL, 0, "", 0, &conn_ssl_config,
                                       NULL, 0, "transport", NULL);
    return cid;
}
static xqc_connection_t *
test_fec_connect(xqc_engine_t *engine)
{
    const xqc_cid_t *cid = test_cid_connect_fec(engine);
    if (cid == NULL) {
        return NULL;
    }
    return xqc_engine_conns_hash_find(engine, cid, 's');
}

xqc_connection_t *
test_engine_connect_fec()
{
    xqc_engine_t *engine = test_create_engine();
    if (engine == NULL) {
        return NULL;
    }
    xqc_connection_t *conn = test_fec_connect(engine);
    return conn;
}

void
xqc_test_fec_frame_err()
{   
    xqc_connection_t *conn = test_engine_connect_fec();
    CU_ASSERT(conn != NULL);
    xqc_packet_in_t packet_in;
    packet_in.pos = XQC_TEST_SID_FRAME;
    packet_in.last = packet_in.pos + sizeof(XQC_TEST_SID_FRAME);
    int ret = xqc_process_frames(conn, &packet_in);
    CU_ASSERT(ret == -XQC_EFEC_NOT_SUPPORT_FEC);

    packet_in.pos = XQC_TEST_RPR_FRAME;
    packet_in.last = packet_in.pos + sizeof(XQC_TEST_RPR_FRAME);
    ret = xqc_process_frames(conn, &packet_in);
    CU_ASSERT(ret == -XQC_EFEC_NOT_SUPPORT_FEC);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_invalid_encoder_params()
{   
    xqc_int_t ret;
    xqc_connection_t *conn = test_engine_connect_fec();
    CU_ASSERT(conn != NULL);

    conn->conn_settings.fec_params.fec_max_symbol_num_per_block = 4;
    conn->conn_settings.fec_params.fec_code_rate = 2;
    ret = xqc_fec_encoder(conn, XQC_TEST_STREAM);
    CU_ASSERT(ret == -XQC_EFEC_SCHEME_ERROR);

    conn->conn_settings.fec_params.fec_code_rate = 1;
    ret = xqc_fec_encoder(conn, XQC_TEST_STREAM);
    CU_ASSERT(ret == XQC_OK);

    conn->conn_settings.fec_params.fec_code_rate = 0.75;
    conn->conn_settings.fec_encode_callback.xqc_fec_encode = NULL;
    ret = xqc_fec_encoder(conn, XQC_TEST_STREAM);
    CU_ASSERT(ret == -XQC_EFEC_SCHEME_ERROR);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_invalid_decoder_params()
{
    xqc_int_t ret;
    xqc_connection_t *conn = test_engine_connect_fec();
    CU_ASSERT(conn != NULL);

    // when fec_recv_symbols_num is smaller than expected, should return error;
    conn->fec_ctl->fec_recv_symbols_num[0] = 0;
    conn->remote_settings.fec_max_symbols_num = 3;
    ret = xqc_fec_decoder(conn, 0);
    CU_ASSERT(ret == -XQC_EFEC_SYMBOL_ERROR);

    // when decoder function is NULL, should return error;
    conn->conn_settings.fec_decode_callback.xqc_fec_decode = NULL;
    conn->fec_ctl->fec_recv_symbols_num[0] = 3;
    conn->fec_ctl->fec_recv_symbols_flag[0] = 0xe;
    conn->remote_settings.fec_max_symbols_num = 3;
    ret = xqc_fec_decoder(conn, 0);
    CU_ASSERT(ret == -XQC_EFEC_SCHEME_ERROR);

    // when fec_processed_blk_num overflow, it should process it properly;
    conn->fec_ctl->fec_recv_symbols_flag[0] = 0xf;
    conn->fec_ctl->fec_processed_blk_num = XQC_MAX_UINT32_VALUE;
    ret = xqc_fec_decoder(conn, 0);
    CU_ASSERT(ret == XQC_OK && conn->fec_ctl->fec_processed_blk_num == 1);

    // when recovered_failed_cnt overflow, it should process it properly;
    conn->conn_settings.fec_decode_callback.xqc_fec_decode = xqc_xor_decode;
    conn->fec_ctl->fec_recv_symbols_num[0] = 3;
    conn->fec_ctl->fec_recv_symbols_flag[0] = 0xe;
    conn->remote_settings.fec_max_symbols_num = 3;
    conn->fec_ctl->fec_recover_failed_cnt = XQC_MAX_UINT32_VALUE;
    for (xqc_int_t i = 1; i < 3; i++) {
        conn->fec_ctl->fec_recv_symbols_buff[0][i].is_valid = 1;
    }
    ret = xqc_fec_decoder(conn, 0);
    CU_ASSERT(ret == -XQC_EFEC_SCHEME_ERROR && conn->fec_ctl->fec_recover_failed_cnt == 1);

    xqc_engine_destroy(conn->engine);
}

void xqc_test_fec_scheme()
{
    xqc_test_fec_frame_err();
    xqc_test_invalid_encoder_params();
    xqc_test_invalid_decoder_params();
}
