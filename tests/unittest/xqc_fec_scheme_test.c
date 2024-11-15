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
#include "src/transport/xqc_fec.h"
#include "src/transport/fec_schemes/xqc_xor.h"
#include "xqc_common_test.h"
#include "src/transport/fec_schemes/xqc_packet_mask.h"
#include "include/xquic/xqc_errno.h"

char XQC_TEST_SID_FRAME[] = {0x80, 0x00, 0xfe, 0xc5, 0x00, 0x00, 0x00, 0x00};
char XQC_TEST_RPR_FRAME[] = {0x80, 0x00, 0xfe, 0xc6, 0x00, 0x00, 0x00, 0x00};
char XQC_TEST_STREAM[] = {0x01, 0x00, 0x00, 0x00, 0x00};
char XQC_TEST_REPAIR_KEY[] = {0x00};


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

xqc_connection_t *
test_engine_connect_fec_server()
{
    xqc_engine_t *engine = test_create_engine_server();
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
    CU_ASSERT(ret == -XQC_EIGNORE_PKT);

    packet_in.pos = XQC_TEST_RPR_FRAME;
    packet_in.last = packet_in.pos + sizeof(XQC_TEST_RPR_FRAME);
    ret = xqc_process_frames(conn, &packet_in);
    CU_ASSERT(ret == -XQC_EIGNORE_PKT);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_invalid_encoder_params()
{
    xqc_int_t ret;
    xqc_connection_t *conn = test_engine_connect_fec();
    CU_ASSERT(conn != NULL);

    conn->conn_settings.fec_params.fec_max_symbol_num_per_block = 4;
    conn->fec_ctl->fec_send_required_repair_num[0] = 8;
    ret = xqc_check_fec_params(conn, conn->conn_settings.fec_params.fec_max_symbol_num_per_block,
                               conn->fec_ctl->fec_send_required_repair_num[0], XQC_SYMBOL_CACHE_LEN, 5);
    CU_ASSERT(ret == -XQC_EFEC_SCHEME_ERROR);

    conn->fec_ctl->fec_send_required_repair_num[0] = 1;
    conn->conn_settings.fec_encode_callback.xqc_fec_encode = NULL;
    ret = xqc_fec_encoder(conn, XQC_TEST_STREAM, 5, 0);
    CU_ASSERT(ret == -XQC_EFEC_SCHEME_ERROR);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_invalid_decoder_params()
{
    xqc_int_t         ret, symbol_size;
    xqc_list_head_t  *symbol_list;
    xqc_connection_t *conn = test_engine_connect_fec();
    xqc_fec_rpr_syb_t *rpr_symbol;

    CU_ASSERT(conn != NULL);

    // when fec_recv_symbols_num is smaller than expected, should return error;
    // conn->remote_settings.fec_max_symbols_num = 3;
    // ret = xqc_fec_bc_decoder(conn, 0, 1);
    // CU_ASSERT(ret == -XQC_EFEC_SYMBOL_ERROR);

    // when fec_processed_blk_num overflow, it should process it properly;
    conn->remote_settings.fec_max_symbols_num = 0;
    conn->fec_ctl->fec_processed_blk_num = XQC_MAX_UINT32_VALUE;
    ret = xqc_fec_bc_decoder(conn, 0, 0);
    CU_ASSERT(ret == XQC_OK && conn->fec_ctl->fec_processed_blk_num == 0);


    // when decoder function is NULL, should return error;
    conn->conn_settings.fec_decode_callback.xqc_fec_decode = NULL;
    conn->remote_settings.fec_max_symbols_num = 3;
    symbol_size = 5;
    symbol_list = &conn->fec_ctl->fec_recv_src_syb_list;
    // 给recv symbol list加入一些节点
    for (xqc_int_t i = 0; i < 2; i++) {
        ret = xqc_insert_src_symbol_by_seq(conn, symbol_list, 0, i, &conn->fec_ctl->fec_src_syb_num, XQC_TEST_STREAM, symbol_size);
    }
    symbol_list = &conn->fec_ctl->fec_recv_rpr_syb_list;
    xqc_fec_rpr_syb_t tmp_rpr_symbol = {
        .block_id = 0,
        .payload = XQC_TEST_STREAM,
        .payload_size = symbol_size,
        .repair_key = XQC_TEST_REPAIR_KEY,
        .repair_key_size = 1
    };
    for (xqc_int_t i = 0; i < 1; i++) {
        tmp_rpr_symbol.symbol_idx = i;
        rpr_symbol = NULL;
        xqc_insert_rpr_symbol_by_seq(conn, symbol_list, &tmp_rpr_symbol, &conn->fec_ctl->fec_rpr_syb_num, &rpr_symbol);
    }
    ret = xqc_fec_bc_decoder(conn, 0, 1);
    CU_ASSERT(ret == -XQC_EFEC_SCHEME_ERROR);


    // when recovered_failed_cnt overflow, it should process it properly;
    conn->conn_settings.fec_decode_callback.xqc_fec_decode = xqc_xor_decode;
    conn->fec_ctl->fec_recover_failed_cnt = XQC_MAX_UINT32_VALUE;
    ret = xqc_fec_bc_decoder(conn, 0, 0);
    CU_ASSERT(ret == XQC_OK);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_fec_xor_decode()
{
    size_t              size;
    xqc_int_t           ret;
    unsigned char       *output[1], *pm;
    xqc_connection_t    *conn = test_engine_connect_fec();

    output[0] = xqc_malloc(XQC_MAX_SYMBOL_SIZE);
    size = 0;

    // empty list
    ret = xqc_xor_decode(conn, output, &size, 0);
    CU_ASSERT(ret == -XQC_EFEC_SYMBOL_ERROR);

    // repair symbol size error
    xqc_fec_rpr_syb_t tmp_rpr_symbol = {
        .block_id = 1,
        .symbol_idx = 0,
        .payload = XQC_TEST_STREAM,
        .payload_size = XQC_MAX_SYMBOL_SIZE + 1,
    };
    xqc_init_list_head(&tmp_rpr_symbol.fec_list);
    xqc_list_add(&tmp_rpr_symbol.fec_list, &conn->fec_ctl->fec_recv_rpr_syb_list);
    ret = xqc_xor_decode(conn, output, &size, 0);
    CU_ASSERT(ret == -XQC_EFEC_SCHEME_ERROR);

    // rpr block idx err
    tmp_rpr_symbol.payload_size = 5;
    ret = xqc_xor_decode(conn, output, &size, 0);
    CU_ASSERT(ret == -XQC_EFEC_SCHEME_ERROR);

    // src syb size err
    xqc_fec_src_syb_t tmp_src_symbol = {
        .block_id = 0,
        .symbol_idx = 0,
        .payload_size = XQC_MAX_SYMBOL_SIZE + 1
    };
    tmp_rpr_symbol.block_id = 0;
    xqc_init_list_head(&tmp_src_symbol.fec_list);
    xqc_list_add(&tmp_src_symbol.fec_list, &conn->fec_ctl->fec_recv_src_syb_list);
    ret = xqc_xor_decode(conn, output, &size, 0);
    CU_ASSERT(ret == -XQC_EFEC_SCHEME_ERROR);

    xqc_list_del(&tmp_src_symbol.fec_list);
    xqc_list_del(&tmp_rpr_symbol.fec_list);
    xqc_free(output[0]);
    xqc_engine_destroy(conn->engine);
}

void
xqc_test_fec_pm_decode()
{
    xqc_int_t           ret;
    unsigned char       *output, *pm;
    xqc_connection_t    *conn = test_engine_connect_fec();

    output = xqc_malloc(XQC_MAX_SYMBOL_SIZE);
    pm = xqc_malloc(XQC_MAX_RPR_KEY_SIZE);
    // output is NULL
    ret = xqc_packet_mask_decode_one(conn, NULL, 0, 0);
    CU_ASSERT(ret == -XQC_EPARAM);
    // no repair symbol
    ret = xqc_packet_mask_decode_one(conn, output, 0, 0);
    CU_ASSERT(ret == -XQC_EPARAM);

    // repair symbol size error
    xqc_fec_rpr_syb_t tmp_rpr_symbol = {
        .block_id = 0,
        .symbol_idx = 0,
        .payload = output,
        .payload_size = XQC_MAX_SYMBOL_SIZE + 1,
        .recv_mask = pm
    };
    xqc_init_list_head(&tmp_rpr_symbol.fec_list);
    xqc_list_add(&tmp_rpr_symbol.fec_list, &conn->fec_ctl->fec_recv_rpr_syb_list);
    ret = xqc_packet_mask_decode_one(conn, output, 0, 0);
    CU_ASSERT(ret == -XQC_EFEC_SCHEME_ERROR);

    // src symbol idx err
    tmp_rpr_symbol.payload_size = XQC_MAX_SYMBOL_SIZE;
    xqc_fec_src_syb_t tmp_src_symbol = {
        .block_id = 0,
        .symbol_idx = 80,
        .payload_size = XQC_MAX_SYMBOL_SIZE + 1
    };
    xqc_init_list_head(&tmp_src_symbol.fec_list);
    xqc_list_add(&tmp_src_symbol.fec_list, &conn->fec_ctl->fec_recv_src_syb_list);
    ret = xqc_packet_mask_decode_one(conn, output, 0, 0);
    CU_ASSERT(ret == -XQC_EFEC_SCHEME_ERROR);

    // src symbol size err
    tmp_src_symbol.symbol_idx = 0;
    ret = xqc_packet_mask_decode_one(conn, output, 0, 0);
    CU_ASSERT(ret == -XQC_EFEC_SCHEME_ERROR);

    xqc_list_del(&tmp_src_symbol.fec_list);
    xqc_list_del(&tmp_rpr_symbol.fec_list);
    xqc_free(output);
    xqc_free(pm);
    xqc_engine_destroy(conn->engine);
}

void xqc_test_fec_scheme()
{
    xqc_test_fec_frame_err();
    xqc_test_invalid_encoder_params();
    xqc_test_invalid_decoder_params();
    xqc_test_fec_xor_decode();
    xqc_test_fec_pm_decode();
}
