/**
 * xqc_webtransport_defs.h
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */
#ifndef XQC_WEBTRANSPORT_DEFS_H
#define XQC_WEBTRANSPORT_DEFS_H

// #include "src/common/utils/var_buf/xqc_var_buf.h"
#include <xquic/xqc_http3.h>
#include <xquic/xqc_webtransport.h>


typedef struct wt_dgram_block_s
{   // fork from user_dgram_blk_t
    unsigned char *data;
    size_t         data_len;
    size_t         to_send_size;
    size_t         data_sent;
    size_t         data_recv;
    size_t         data_lost;
    size_t         dgram_lost;
} wt_dgram_blk_t;

enum WebtransportVersion
{
    Draft02,
    Draft07
};

wt_dgram_blk_t *xqc_wt_dgram_blk_create(const void *data, size_t data_len);

void xqc_wt_dgram_blk_destroy(wt_dgram_blk_t *dgram_blk);


#endif
