
/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */


#ifndef _XQC_FEC_H_INCLUDED_
#define _XQC_FEC_H_INCLUDED_


#include <xquic/xquic_typedef.h>
#include <xquic/xqc_errno.h>
#include <xquic/xquic.h>
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_fec_scheme.h"
#include "src/transport/xqc_transport_params.h"


#define XQC_FEC_ELE_BIT_SIZE_DEFAULT    8
#define XQC_FEC_MAX_SYMBOL_NUM_TOTAL    256
#define XQC_FEC_MAX_SYMBOL_PAYLOAD_ID   0xffffffff - XQC_FEC_MAX_SYMBOL_NUM_TOTAL
#define XQC_FEC_MAX_SYMBOL_NUM_PBLOCK   4          /* 2^XQC_FEC_ELE_BIT_SIZE_DEFAULT */
#define XQC_FEC_CODE_RATE_DEFAULT       0.75
#define XQC_REPAIR_LEN                  1          /* (1-XQC_FEC_CODE_RATE_DEFAULT) * XQC_FEC_MAX_SYMBOL_NUM_PBLOCK */
#define XQC_SYMBOL_CACHE_LEN            10

typedef struct xqc_fec_object_s {
    size_t                       payload_size;
    xqc_int_t                    is_valid;
    unsigned char               *payload;
} xqc_fec_object_t;

typedef struct xqc_fec_ctl_s {
    xqc_connection_t            *conn;

    xqc_int_t                    fec_flow_id;
    uint32_t                     fec_recover_pkt_cnt;
    uint32_t                     fec_processed_blk_num;
    uint32_t                     fec_flush_blk_cnt;
    uint32_t                     fec_recover_failed_cnt;
    uint32_t                     fec_ignore_blk_cnt;
    uint32_t                     fec_recv_repair_num;

    xqc_int_t                    fec_send_src_symbols_num;       /* src symbols id for current fec process*/
    xqc_int_t                    fec_send_repair_symbols_num;
    xqc_fec_object_t             fec_send_repair_key[XQC_REPAIR_LEN];
    xqc_fec_object_t             fec_send_repair_symbols_buff[XQC_REPAIR_LEN];

    xqc_int_t                    fec_recv_block_idx[XQC_SYMBOL_CACHE_LEN];
    xqc_int_t                    fec_recv_symbols_num[XQC_SYMBOL_CACHE_LEN];
    xqc_int_t                    fec_recv_repair_symbols_num[XQC_SYMBOL_CACHE_LEN];
    xqc_fec_object_t             fec_recv_repair_key[XQC_SYMBOL_CACHE_LEN][XQC_REPAIR_LEN];
    xqc_fec_object_t             fec_recv_symbols_buff[XQC_SYMBOL_CACHE_LEN][XQC_FEC_MAX_SYMBOL_NUM_PBLOCK];
    uint64_t                     fec_recv_symbols_flag[XQC_SYMBOL_CACHE_LEN];

    unsigned char                LC_GM[XQC_MAX_MT_ROW][XQC_MAX_MT_ROW];
} xqc_fec_ctl_t;

xqc_int_t xqc_set_fec_scheme(uint64_t in, xqc_fec_schemes_e *out);
/* 
 * @desc
 * copy fec schemes from schemes to fec_schemes_buff, filtered by xqc_fec_schemes_e
 */
xqc_int_t xqc_set_fec_schemes(const xqc_fec_schemes_e *schemes, xqc_int_t schemes_len,
    xqc_fec_schemes_e *fec_schemes_buff, xqc_int_t *fec_schemes_buff_len);


/*
 * @desc
 * server set the final fec scheme
 */
xqc_int_t xqc_set_final_scheme(xqc_connection_t *conn, xqc_fec_schemes_e *local_fec_schemes_buff, xqc_int_t *local_fec_schemes_buff_len,
    xqc_fec_schemes_e *remote_fec_schemes_buff, xqc_int_t remote_fec_schemes_buff_len, xqc_int_t *final_scheme, xqc_fec_code_callback_t *callback);
/*
 * @desc
 * check if the fec scheme is supported by current host
 */
xqc_int_t xqc_is_fec_scheme_valid(xqc_fec_schemes_e scheme, xqc_fec_schemes_e *supported_schemes_buff,
    xqc_int_t supported_schemes_buff_len);

xqc_int_t xqc_is_packet_fec_protected(xqc_connection_t *conn, xqc_packet_out_t *packet_out);



xqc_fec_ctl_t *xqc_fec_ctl_create(xqc_connection_t *conn);

void xqc_fec_ctl_destroy(xqc_fec_ctl_t *fec_ctl);

xqc_int_t xqc_gen_src_payload_id(xqc_fec_ctl_t *fec_ctl, uint64_t *payload_id);

xqc_int_t xqc_fec_ctl_save_symbol(unsigned char **symbol_buff, const unsigned char *data,
    xqc_int_t data_len);

xqc_int_t xqc_fec_ctl_init_send_params(xqc_fec_ctl_t *fec_ctl);

xqc_int_t xqc_fec_ctl_init_recv_params(xqc_fec_ctl_t *fec_ctl, xqc_int_t block_idx);

xqc_int_t xqc_set_valid_scheme_cb(xqc_fec_code_callback_t *callback, xqc_int_t scheme);

xqc_int_t xqc_negotiate_fec_schemes(xqc_connection_t *conn, xqc_transport_params_t params);

xqc_int_t xqc_process_fec_protected_packet(xqc_connection_t *conn, xqc_packet_out_t *packet_out);

void xqc_set_object_value(xqc_fec_object_t *object, xqc_int_t is_valid,
    unsigned char *payload, size_t size);

xqc_int_t xqc_is_fec_cb_exist(xqc_fec_schemes_e scheme);

void xqc_init_object_value(xqc_fec_object_t *object);

xqc_int_t xqc_process_valid_symbol(xqc_connection_t *conn, xqc_int_t block_id, xqc_int_t symbol_idx,
    unsigned char *symbol, xqc_int_t symbol_size);

void xqc_fec_record_flush_blk(xqc_connection_t *conn, xqc_int_t block_id);
#endif  /* _XQC_FEC_H_INCLUDED_ */