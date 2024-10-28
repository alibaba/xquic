/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xqc_fec_test.h"
#include "xqc_fec_scheme_test.h"
#include "include/xquic/xquic.h"
#include "src/transport/xqc_fec.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_packet_out.h"
#include "xqc_common_test.h"

xqc_fec_schemes_e fec_schemes[XQC_FEC_MAX_SCHEME_NUM] = {0, XQC_XOR_CODE, XQC_REED_SOLOMON_CODE, XQC_PACKET_MASK_CODE};

void
xqc_test_fec_scheme_setter()
{
    xqc_int_t ret, encoder_scheme_len;
    xqc_fec_schemes_e encoder_schemes[XQC_FEC_MAX_SCHEME_NUM];

    ret = xqc_set_fec_schemes(fec_schemes, 4, encoder_schemes, &encoder_scheme_len);
    CU_ASSERT(ret == XQC_OK && encoder_scheme_len == 3);
}

void
xqc_test_fec_negotiation()
{
    xqc_int_t ret;
    xqc_connection_t *conn = test_engine_connect_fec();
    xqc_connection_t *conn_server = test_engine_connect_fec_server();
    xqc_transport_params_t params;    
    xqc_trans_settings_t *ls = &conn->local_settings;

    params.fec_version = XQC_ERR_FEC_VERSION;
    ret = xqc_negotiate_fec_schemes(conn, params);
    CU_ASSERT(ret == -XQC_EFEC_NOT_SUPPORT_FEC);

    params.fec_version = XQC_FEC_02;
    params.enable_encode_fec = 1;
    params.enable_decode_fec = 1;
    ls->enable_encode_fec = 1;
    ls->enable_decode_fec = 1;

    params.fec_encoder_schemes_num = 2;
    params.fec_decoder_schemes_num = 2;
    ret = xqc_negotiate_fec_schemes(conn, params);
    CU_ASSERT(ret == -XQC_EFEC_NOT_SUPPORT_FEC);

    xqc_engine_destroy(conn->engine);

    params.fec_encoder_schemes[0] = 20;
    params.fec_decoder_schemes[0] = 20;
    params.fec_encoder_schemes_num = 1;
    params.fec_decoder_schemes_num = 1;

    ls->fec_encoder_schemes[0] = 8;
    ls->fec_decoder_schemes[0] = 8;
    ls->fec_encoder_schemes_num = 1;
    ls->fec_decoder_schemes_num = 1;
    ret = xqc_negotiate_fec_schemes(conn_server, params);
    CU_ASSERT(ret == -XQC_EFEC_NOT_SUPPORT_FEC);

    xqc_engine_destroy(conn_server->engine);
}


void
xqc_test_write_repair_packet()
{
    xqc_int_t ret;
    xqc_list_head_t *prev = NULL;
    xqc_connection_t *conn = test_engine_connect_fec();

    ret = xqc_write_repair_packets(conn, 0, prev, 0, 0);
    CU_ASSERT(ret == XQC_OK);

    conn->conn_settings.fec_params.fec_max_symbol_num_per_block = 4;
    conn->conn_settings.fec_params.fec_code_rate = 1;
    conn->fec_ctl->fec_send_symbol_num[0] = 3;
    ret = xqc_write_repair_packets(conn, 0, prev, 1, 0);
    CU_ASSERT(ret == XQC_OK);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_gen_fec_frames()
{
    xqc_int_t ret, padding_len, limit;
    xqc_connection_t *conn = test_engine_connect_fec();
    xqc_packet_out_t* packet_out = xqc_packet_out_create(XQC_QUIC_MAX_MSS);
    packet_out->po_used_size = 1000;
    padding_len = 500;
    limit = 1200;
    ret = xqc_gen_padding_frame_with_len(conn, packet_out, padding_len, limit);
    CU_ASSERT(ret == -XQC_EFEC_SYMBOL_ERROR);

    // invalid po_used_size
    packet_out->po_used_size = XQC_QUIC_MAX_MSS + 1;
    ret = xqc_gen_sid_frame(conn, packet_out);
    CU_ASSERT(ret == -XQC_EPARAM);

    // invalid fec_send_block_num
    conn->fec_ctl->fec_send_block_num[0] = XQC_FEC_MAX_BLOCK_NUM + 1;
    packet_out->po_reserved_size = 12;
    packet_out->po_used_size = 0;
    ret = xqc_gen_sid_frame(conn, packet_out);
    CU_ASSERT(ret == -XQC_EFEC_SYMBOL_ERROR);

    ret = xqc_gen_repair_frame(conn, NULL, 0, 0, 0);
    CU_ASSERT(ret == -XQC_EPARAM);

    conn->conn_settings.fec_params.fec_ele_bit_size = 0;
    ret = xqc_gen_repair_frame(conn, packet_out, 0, 0, 0);
    CU_ASSERT(ret == -XQC_EPARAM);

    xqc_packet_out_destroy(packet_out);
    xqc_engine_destroy(conn->engine);
}

void
xqc_test_chk_fec_param()
{
    xqc_int_t ret;
    xqc_connection_t *conn = test_engine_connect_fec();

    ret = xqc_check_fec_params(conn, XQC_FEC_MAX_SYMBOL_NUM_PBLOCK, XQC_REPAIR_LEN + 1, XQC_SYMBOL_CACHE_LEN, XQC_MAX_SYMBOL_SIZE);
    CU_ASSERT(ret == -XQC_EFEC_SCHEME_ERROR);

    ret = xqc_check_fec_params(conn, XQC_FEC_MAX_SYMBOL_NUM_PBLOCK + 1, XQC_REPAIR_LEN, XQC_SYMBOL_CACHE_LEN, XQC_MAX_SYMBOL_SIZE);
    CU_ASSERT(ret == -XQC_EFEC_SYMBOL_ERROR);

    ret = xqc_check_fec_params(conn, XQC_FEC_MAX_SYMBOL_NUM_PBLOCK, XQC_REPAIR_LEN, XQC_SYMBOL_CACHE_LEN + 1, XQC_MAX_SYMBOL_SIZE);
    CU_ASSERT(ret == -XQC_EFEC_SYMBOL_ERROR);

    ret = xqc_check_fec_params(conn, XQC_FEC_MAX_SYMBOL_NUM_PBLOCK, XQC_REPAIR_LEN, XQC_SYMBOL_CACHE_LEN + 1, XQC_MAX_SYMBOL_SIZE + 1);
    CU_ASSERT(ret == -XQC_EFEC_SYMBOL_ERROR);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_encoder_chk_param()
{
    xqc_int_t ret, rpr_syb_num;
    xqc_connection_t *conn = test_engine_connect_fec();

    ret = xqc_fec_encoder_check_params(conn, 2, XQC_XOR_CODE, XQC_MAX_SYMBOL_SIZE);
    CU_ASSERT(ret == -XQC_EPARAM);
    
    ret = xqc_fec_encoder_check_params(conn, 1, XQC_XOR_CODE, XQC_MAX_SYMBOL_SIZE + 1);
    CU_ASSERT(ret == -XQC_EPARAM);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_fec()
{
    xqc_test_fec_scheme_setter();
    xqc_test_fec_negotiation();
    xqc_test_write_repair_packet();
    xqc_test_gen_fec_frames();
    xqc_test_chk_fec_param();
    xqc_test_encoder_chk_param();
}