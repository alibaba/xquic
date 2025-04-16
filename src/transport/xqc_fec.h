
/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */


#ifndef _XQC_FEC_H_INCLUDED_
#define _XQC_FEC_H_INCLUDED_


#include <xquic/xquic_typedef.h>
#include <xquic/xqc_errno.h>
#include <xquic/xquic.h>
#include "src/transport/xqc_packet_out.h"
// #include "src/transport/xqc_fec_scheme.h"
#include "src/transport/xqc_transport_params.h"
#include "src/common/xqc_str.h"
#include "src/transport/xqc_stream.h"


#define XQC_FEC_BLOCK_NUM               10
#define XQC_FEC_ELE_BIT_SIZE_DEFAULT    8
#define XQC_FEC_MAX_SYMBOL_NUM_TOTAL    256
#define XQC_FEC_MAX_SYMBOL_PAYLOAD_ID   0xffffffff - XQC_FEC_MAX_SYMBOL_NUM_TOTAL
#define XQC_FEC_MAX_BLOCK_NUM           0x00ffffff
#define XQC_FEC_MAX_SYMBOL_NUM          0x000000ff
#define XQC_FEC_MAX_SYMBOL_NUM_PBLOCK   48          /* 2^XQC_FEC_ELE_BIT_SIZE_DEFAULT */
#define XQC_FEC_CODE_RATE_DEFAULT       0.95
#define XQC_REPAIR_LEN                  10         /* (1-XQC_FEC_CODE_RATE_DEFAULT) * XQC_FEC_MAX_SYMBOL_NUM_PBLOCK */
#define XQC_BLOCK_MODE_LEN              5
#define XQC_SYMBOL_CACHE_LEN            96
#define XQC_MAX_RPR_KEY_SIZE            10
#define XQC_MAX_SYMBOL_SIZE             XQC_MAX_PACKET_OUT_SIZE + XQC_ACK_SPACE - XQC_FEC_SPACE
#define XQC_MAX_PM_SIZE                 288

static const uint8_t fec_blk_size_v2[XQC_BLOCK_MODE_LEN] = {0, 0, 4, 10, 20};
typedef struct xqc_fec_object_s {
    size_t                       payload_size;
    xqc_int_t                    is_valid;
    unsigned char               *payload;
} xqc_fec_object_t;

// FEC 2.0 params

typedef struct xqc_fec_src_syb_s {
    size_t                       payload_size;
    unsigned char               *payload;
    xqc_list_head_t              fec_list;
    xqc_int_t                    block_id;
    xqc_int_t                    symbol_idx;
    xqc_stream_id_t              stream_id;
} xqc_fec_src_syb_t;

typedef struct xqc_fec_rpr_syb_s {
    size_t                       payload_size;
    unsigned char               *payload;
    size_t                       repair_key_size;
    unsigned char               *repair_key;
    unsigned char               *recv_mask;
    xqc_list_head_t              fec_list;
    xqc_int_t                    block_id;
    xqc_int_t                    symbol_idx;
    xqc_usec_t                   recv_time;
} xqc_fec_rpr_syb_t;

typedef struct xqc_fec_payload_s {
    unsigned char               *payload;
    xqc_list_head_t              pld_list;
} xqc_fec_payload_t;

typedef enum {
    XQC_LOCAL_NOT_SUPPORT_ENC     = 1 << 0,
    XQC_LOCAL_NOT_SUPPORT_DEC     = 1 << 1,
    XQC_REMOTE_NOT_SUPPORT_ENC    = 1 << 2,
    XQC_REMOTE_NOT_SUPPORT_DEC    = 1 << 3,
    XQC_NO_COMMON_FEC_ENC         = 1 << 4,
    XQC_NO_COMMON_FEC_DEC         = 1 << 5,
    XQC_OLD_FEC_VERSION           = 1 << 6,
    XQC_CLIENT_RECEIVE_INV_ENC    = 1 << 7,
    XQC_CLIENT_RECEIVE_INV_DEC    = 1 << 8,
    XQC_REMOTE_PARAM_ERR          = 1 << 9
} xqc_fec_neg_fail_reason_e;



typedef struct xqc_fec_ctl_s {
    xqc_connection_t            *conn;

    xqc_int_t                    fec_flow_id;
    uint32_t                     fec_recover_pkt_cnt;
    uint32_t                     fec_processed_blk_num;
    uint32_t                     fec_flush_blk_cnt;
    uint32_t                     fec_recover_failed_cnt;
    uint32_t                     fec_recv_repair_num_total;
    uint32_t                     fec_send_repair_num_total;
    uint32_t                     fec_send_ahead;
    xqc_int_t                    fec_max_fin_blk_id;
    xqc_stream_id_t              latest_stream_id[XQC_FEC_BLOCK_NUM];

    xqc_fec_mp_mode_e            fec_mp_mode;
    uint64_t                     fec_rep_path_id;

    uint32_t                     fec_send_block_num[XQC_BLOCK_MODE_LEN];
    uint8_t                      fec_send_block_mode_size[XQC_BLOCK_MODE_LEN];
    uint32_t                     fec_send_required_repair_num[XQC_BLOCK_MODE_LEN];
    uint32_t                     fec_send_symbol_num[XQC_BLOCK_MODE_LEN];           /* src symbols number for current fec process */
    xqc_fec_object_t             fec_send_repair_key[XQC_BLOCK_MODE_LEN][XQC_REPAIR_LEN];
    xqc_fec_object_t             fec_send_repair_symbols_buff[XQC_BLOCK_MODE_LEN][XQC_REPAIR_LEN];
    uint8_t                      fec_send_decode_matrix[XQC_BLOCK_MODE_LEN][XQC_REPAIR_LEN][XQC_MAX_RPR_KEY_SIZE];
    unsigned char                decode_matrix[2 * XQC_RSM_COL][XQC_RSM_COL];

    // FEC 2.0 params
    xqc_list_head_t              fec_free_src_list;
    xqc_list_head_t              fec_free_rpr_list;
    xqc_list_head_t              fec_recv_src_syb_list;         /* source symbols (including recovered source symbols) list */
    xqc_list_head_t              fec_recv_rpr_syb_list;         /* repair symbols list */
    
    xqc_int_t                    fec_src_syb_num;
    xqc_int_t                    fec_rpr_syb_num;
    xqc_fec_object_t             fec_gen_repair_symbols_buff[XQC_REPAIR_LEN];

    xqc_int_t                    fec_enable_stream_num;         /* number of stream that enables fec */
    xqc_msec_t                   conn_avg_recv_delay;         /* fec averaged one way receive delay time */
    xqc_msec_t                   fec_avg_opt_time;         /* fec averaged one way receive delay time */
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
    xqc_fec_schemes_e *remote_fec_schemes_buff, xqc_int_t remote_fec_schemes_buff_len);


xqc_int_t xqc_is_packet_fec_protected(xqc_connection_t *conn, xqc_packet_out_t *packet_out);



xqc_fec_ctl_t *xqc_fec_ctl_create(xqc_connection_t *conn);

void xqc_fec_ctl_destroy(xqc_fec_ctl_t *fec_ctl);

xqc_int_t xqc_gen_src_payload_id(xqc_fec_ctl_t *fec_ctl, uint64_t *payload_id, uint8_t bm_idx);

xqc_int_t xqc_fec_ctl_save_symbol(unsigned char **symbol_buff, const unsigned char *data,
    xqc_int_t data_len);

xqc_int_t xqc_fec_ctl_init_send_params(xqc_connection_t *conn, uint8_t bm_idx);

xqc_int_t xqc_fec_ctl_init_recv_params(xqc_fec_ctl_t *fec_ctl, uint64_t block_id);

unsigned char *xqc_get_fec_scheme_str(xqc_fec_schemes_e scheme);

unsigned char *xqc_get_fec_mp_mode_str(xqc_fec_ctl_t *fec_ctl);

xqc_int_t xqc_negotiate_fec_schemes(xqc_connection_t *conn, xqc_transport_params_t params);

xqc_int_t xqc_process_fec_protected_packet(xqc_connection_t *conn, xqc_packet_out_t *packet_out);

void xqc_set_object_value(xqc_fec_object_t *object, xqc_int_t is_valid,
    unsigned char *payload, size_t size);

void xqc_init_object_value(xqc_fec_object_t *object);

xqc_int_t xqc_process_src_symbol(xqc_connection_t *conn, uint64_t block_id, uint64_t symbol_idx,
    unsigned char *symbol, xqc_int_t symbol_size);

xqc_int_t xqc_process_rpr_symbol(xqc_connection_t *conn, xqc_fec_rpr_syb_t *tmp_rpr_symbol);


xqc_int_t xqc_get_symbols_buff(unsigned char **output, xqc_fec_ctl_t *fec_ctl, uint64_t block_idx, size_t *size);

xqc_fec_rpr_syb_t *xqc_get_rpr_symbol(xqc_list_head_t *head, uint64_t block_id, uint64_t symbol_id);


xqc_int_t xqc_cnt_src_symbols_num(xqc_fec_ctl_t *fec_ctl, uint64_t block_id);

xqc_int_t xqc_cnt_rpr_symbols_num(xqc_fec_ctl_t *fec_ctl, uint64_t block_id);

xqc_int_t xqc_get_symbol_flag(xqc_connection_t *conn, uint64_t block_id);

xqc_fec_src_syb_t *xqc_build_src_symbol(xqc_connection_t *conn, uint64_t block_id, uint64_t symbol_idx,
    unsigned char *symbol, xqc_int_t symbol_size);

xqc_int_t xqc_insert_src_symbol_by_seq(xqc_connection_t *conn, xqc_list_head_t *symbol_list, 
    uint64_t block_id, uint64_t symbol_idx, xqc_int_t *blk_output,
    unsigned char *symbol, xqc_int_t symbol_size);

xqc_int_t xqc_insert_rpr_symbol_by_seq(xqc_connection_t *conn, xqc_list_head_t *symbol_list, 
    xqc_fec_rpr_syb_t *tmp_rpr_symbol, xqc_int_t *blk_output, xqc_fec_rpr_syb_t **rpr_symbol);

void xqc_remove_rpr_symbol_from_list(xqc_fec_ctl_t *fec_ctl, xqc_fec_rpr_syb_t *rpr_symbol);

xqc_int_t xqc_check_fec_params(xqc_connection_t *conn, xqc_int_t src_symbol_num, xqc_int_t total_symbol_num,
    xqc_int_t max_window_size, xqc_int_t symbol_size);

xqc_fec_rpr_syb_t *xqc_build_rpr_symbol(xqc_connection_t *conn, xqc_fec_rpr_syb_t *tmp_rpr_symbol);

void xqc_set_fec_blk_size(xqc_connection_t *conn, xqc_transport_params_t params);

uint8_t xqc_get_fec_blk_size(xqc_connection_t *conn, uint8_t blk_md);

void xqc_on_fec_negotiate_success(xqc_connection_t *conn, xqc_transport_params_t params);

xqc_int_t xqc_send_repair_packets_ahead(xqc_connection_t *conn, xqc_list_head_t *prev, uint8_t fec_bm_mode);


xqc_int_t xqc_send_repair_packets(xqc_connection_t *conn, xqc_fec_schemes_e scheme, xqc_list_head_t *prev,
    uint8_t fec_bm_mode);

xqc_int_t xqc_process_fec_protected_packet_moq(xqc_stream_t *stream);

void xqc_fec_on_stream_size_changed(xqc_stream_t *quic_stream);
#endif  /* _XQC_FEC_H_INCLUDED_ */