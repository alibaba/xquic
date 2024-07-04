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

xqc_fec_schemes_e fec_schemes[XQC_FEC_MAX_SCHEME_NUM] = {0, XQC_XOR_CODE, XQC_REED_SOLOMON_CODE, XQC_PACKET_MASK};

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
    xqc_transport_params_t params;    
    xqc_trans_settings_t *ls = &conn->local_settings;

    params.fec_version = XQC_ERR_FEC_VERSION;

    ret = xqc_negotiate_fec_schemes(conn, params);
    CU_ASSERT(ret == -XQC_EFEC_NOT_SUPPORT_FEC);
    xqc_engine_destroy(conn->engine);
}

void
xqc_test_flush_num()
{
    xqc_connection_t *conn = test_engine_connect_fec();
    conn->fec_ctl->fec_flush_blk_cnt = XQC_MAX_UINT32_VALUE;
    conn->fec_ctl->fec_ignore_blk_cnt = XQC_MAX_UINT32_VALUE;
    conn->conn_settings.fec_params.fec_max_window_size = 3;
    conn->fec_ctl->fec_recv_symbols_num[0] = 3;
    conn->fec_ctl->fec_recv_block_idx[0] = 0;
    xqc_fec_record_flush_blk(conn, 6);
    CU_ASSERT(conn->fec_ctl->fec_flush_blk_cnt == 1 && conn->fec_ctl->fec_ignore_blk_cnt == 1);
    xqc_engine_destroy(conn->engine);
}

void
xqc_test_process_fec_packet()
{
    xqc_int_t ret;
    xqc_connection_t *conn = test_engine_connect_fec();
    xqc_packet_out_t po;
    po.po_frame_types = 0;
    ret = xqc_process_fec_protected_packet(conn, &po);
    CU_ASSERT(ret == -XQC_EFEC_NOT_SUPPORT_FEC);
    xqc_engine_destroy(conn->engine);
}

void
xqc_test_write_repair_packet()
{
    xqc_int_t ret;
    xqc_list_head_t *prev = NULL;
    xqc_connection_t *conn = test_engine_connect_fec();

    conn->fec_ctl->fec_send_repair_symbols_num = 0;
    ret = xqc_write_repair_packets(conn, 0, prev);
    CU_ASSERT(ret == XQC_OK);

    conn->conn_settings.fec_params.fec_max_symbol_num_per_block = 4;
    conn->conn_settings.fec_params.fec_code_rate = 1;
    conn->fec_ctl->fec_send_src_symbols_num = 3;
    conn->fec_ctl->fec_send_repair_symbols_num = 1;
    ret = xqc_write_repair_packets(conn, 0, prev);
    CU_ASSERT(ret == -XQC_EFEC_SYMBOL_ERROR);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_gen_fec_frames()
{
    xqc_int_t ret, padding_len, limit;
    xqc_connection_t *conn = test_engine_connect_fec();
    xqc_packet_out_t packet_out;
    packet_out.po_used_size = 1000;
    padding_len = 500;
    limit = 1200;
    ret = xqc_gen_padding_frame_with_len(conn, &packet_out, padding_len, limit);
    CU_ASSERT(ret == -XQC_EFEC_SYMBOL_ERROR);

    packet_out.po_used_size = XQC_QUIC_MAX_MSS + 1;
    ret = xqc_gen_sid_frame(conn, &packet_out);
    CU_ASSERT(ret == -XQC_ENOBUF);

    conn->fec_ctl->fec_send_src_symbols_num = XQC_FEC_MAX_SYMBOL_PAYLOAD_ID;
    packet_out.po_used_size = 0;
    ret = xqc_gen_sid_frame(conn, &packet_out);
    CU_ASSERT(ret == -XQC_EFEC_SYMBOL_ERROR);

    ret = xqc_gen_repair_frame(conn, NULL, 0, 0, 0);
    CU_ASSERT(ret == -XQC_EPARAM);

    conn->conn_settings.fec_params.fec_ele_bit_size = 0;
    ret = xqc_gen_repair_frame(conn, &packet_out, 0, 0, 0);
    CU_ASSERT(ret == -XQC_EFEC_SYMBOL_ERROR);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_fec()
{
    xqc_test_fec_scheme_setter();
    xqc_test_fec_negotiation();
    xqc_test_process_fec_packet();
    xqc_test_flush_num();
    xqc_test_write_repair_packet();
    xqc_test_gen_fec_frames();
}