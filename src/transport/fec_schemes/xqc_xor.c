
/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
*/


#include "src/transport/fec_schemes/xqc_xor.h"
#include "src/transport/xqc_conn.h"

void
xqc_xor_init(xqc_connection_t *conn)
{
    if (conn->fec_ctl == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|fail to malloc space for fec_ctl");
        return;
    }
    conn->fec_ctl->fec_send_required_repair_num[XQC_DEFAULT_SIZE_REQ] = 1;
    return;
}

void
xqc_xor_init_one(xqc_connection_t *conn, uint8_t bm_idx)
{
    return;
}

#ifdef XQC_ON_x86
void
xqc_xor_string_simd_x86(unsigned char *input, unsigned char *outputs,
    xqc_int_t item_size)
{
    size_t i = 0;
    size_t aligned_len = item_size & ~(size_t)15;

    for (i = 0; i < aligned_len; i += 16) {
        __m128i output_unit = _mm_loadu_si128((__m128i *)(outputs + i));
        __m128i input_unit = _mm_loadu_si128((__m128i *)(input + i));
        __m128i result = _mm_xor_si128(output_unit, input_unit);
        _mm_storeu_si128((__m128i *)(outputs + i), result);
    }

    for (; i < item_size; ++i) {
        outputs[i] ^= input[i];
    }
}
#endif

#ifdef XQC_ON_ARM
void
xqc_xor_string_simd_arm(unsigned char *input, unsigned char *outputs,
    xqc_int_t item_size)
{
    size_t i = 0;
    size_t aligned_len = item_size & ~(size_t)15;

    for (i = 0; i < aligned_len; i += 16) {
        uint8x16_t out_data = vld1q_u8(outputs + i);
        uint8x16_t in_data = vld1q_u8(input + i);
        uint8x16_t result = veorq_u8(out_data, in_data);
        vst1q_u8(outputs + i, result);
    }

    for (; i < item_size; ++i) {
        outputs[i] ^= input[i];
    }
}
#endif

void
xqc_xor_string(unsigned char *input, unsigned char *outputs,
    xqc_int_t item_size)
{
    size_t i = 0;
    unsigned char *output_p;

    output_p = outputs;
    for (i = 0; i < item_size; i++) {
        *(output_p + i) ^= *(input + i);
    }
}


xqc_int_t
xqc_xor_code_one_symbol(unsigned char *input, unsigned char *outputs,
    xqc_int_t item_size)
{
    if (outputs == NULL) {
        return -XQC_EMALLOC;
    }

#if defined(XQC_ON_x86)
    xqc_xor_string_simd_x86(input, outputs, item_size);
#else
    xqc_xor_string(input, outputs, item_size);
#endif

    return XQC_OK;
}

xqc_int_t
xqc_xor_decode(xqc_connection_t *conn, unsigned char **outputs, size_t *output_size, xqc_int_t block_idx)
{
    xqc_int_t i, j, ret, recv_repair_symbols_num, output_len, block_mod;
    xqc_usec_t now, diff_time;
    xqc_stream_t *stream;
    xqc_list_head_t *pos, *next, *fec_recv_src_syb_list, *fec_recv_rpr_syb_list;
    xqc_fec_rpr_syb_t *symbol = NULL;

    *output_size = 0;
    ret = -XQC_EFEC_SYMBOL_ERROR;
    fec_recv_src_syb_list = &conn->fec_ctl->fec_recv_src_syb_list;
    fec_recv_rpr_syb_list = &conn->fec_ctl->fec_recv_rpr_syb_list;
    block_mod = conn->conn_settings.fec_params.fec_blk_log_mod;

    xqc_list_for_each_safe(pos, next, fec_recv_rpr_syb_list) {
        xqc_fec_rpr_syb_t *rpr_syb = xqc_list_entry(pos, xqc_fec_rpr_syb_t, fec_list);
        if (rpr_syb->block_id < block_idx) {
            continue;
        }
        if (rpr_syb->block_id == block_idx) {
            if (rpr_syb->payload_size > XQC_MAX_SYMBOL_SIZE) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xor decoder can't process rpr symbol with size bigger than XQC_MAX_SYMBOL_SIZE.");
                return -XQC_EFEC_SCHEME_ERROR;
            }
            ret = xqc_xor_code_one_symbol(rpr_syb->payload, outputs[0], rpr_syb->payload_size);
            if (ret != XQC_OK) {
                return ret;
            }
            *output_size = rpr_syb->payload_size;
            symbol = rpr_syb;
            break;
        }
        if (rpr_syb->block_id > block_idx) {
            return -XQC_EFEC_SCHEME_ERROR;
        }
    }
    xqc_list_for_each_safe(pos, next, fec_recv_src_syb_list) {
        xqc_fec_src_syb_t *src_syb = xqc_list_entry(pos, xqc_fec_src_syb_t, fec_list);
        if (src_syb->block_id < block_idx) {
            continue;
        }
        if (src_syb->block_id == block_idx) {
            if (src_syb->payload_size > XQC_MAX_SYMBOL_SIZE) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xor decoder can't process src symbol with size bigger than XQC_MAX_SYMBOL_SIZE.");
                return -XQC_EFEC_SCHEME_ERROR;
            }
            ret = xqc_xor_code_one_symbol(src_syb->payload, outputs[0], src_syb->payload_size);
            if (ret != XQC_OK) {
                return ret;
            }
        }
        if (src_syb->block_id > block_idx) {
            break;
        }
    }

    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_xor_decode|xor decode symbols failed");
        return ret;
    }

    // log the time it cost between recovered and rpr symbol received, control log rate
    if (conn->conn_settings.fec_params.fec_log_on && symbol && symbol->block_id % block_mod == 0) {
        now = xqc_monotonic_timestamp();
        diff_time = xqc_calc_delay(now, symbol->recv_time);
        xqc_log(conn->log, XQC_LOG_REPORT, "|fec_stats|XOR|current block: %d|recovered %ui ms after rpr received", symbol->block_id, diff_time / 1000);
    }

    return XQC_OK;
}

xqc_int_t
xqc_xor_encode(xqc_connection_t *conn, unsigned char *stream, size_t st_size, unsigned char **outputs,
    uint8_t fec_bm_mode)
{
    size_t              tmp_size;
    xqc_int_t           ret;

    if (st_size > XQC_MAX_SYMBOL_SIZE) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_xor_encode|invalid input size:%d|", st_size);
        return -XQC_EFEC_SYMBOL_ERROR;
    }

    ret = xqc_xor_code_one_symbol(stream, outputs[0], st_size);
    // set validation and payload size of fec_send_repair_symbols_buff object
    tmp_size = xqc_max(st_size, conn->fec_ctl->fec_send_repair_symbols_buff[fec_bm_mode][0].payload_size);
    if (tmp_size > XQC_MAX_SYMBOL_SIZE) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|repair symbol payload exceeds the buffer size");
        ret = -XQC_EFEC_SCHEME_ERROR;
    }
    // have to set fec_send_repair_symbols_buff, otherwise the payload won't be set to 0 after encode process
    xqc_set_object_value(&conn->fec_ctl->fec_send_repair_symbols_buff[fec_bm_mode][0], 1, outputs[0],
                         tmp_size);

    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|xqc_xor_encode|code one symbol failed");
        return -XQC_EFEC_SCHEME_ERROR;
    }
    
    return XQC_OK;
}

const xqc_fec_code_callback_t xqc_xor_code_cb = {
    .xqc_fec_init           = xqc_xor_init,
    .xqc_fec_init_one       = xqc_xor_init_one,
    .xqc_fec_decode         = xqc_xor_decode,
    .xqc_fec_encode         = xqc_xor_encode,
    // .destroy = xqc_rs_destroy,
};