/**
 * xqc_webtransport_defs.c
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */
#include "xqc_webtransport_defs.h"
#include "src/common/xqc_list.h"
#include "src/common/xqc_malloc.h"

wt_dgram_blk_t *
xqc_wt_dgram_blk_create(const void *data, size_t data_len)
{
    wt_dgram_blk_t *dgram_blk = xqc_calloc(1, sizeof(wt_dgram_blk_t));
    dgram_blk->data = xqc_malloc(data_len * sizeof(unsigned char));
    memcpy(dgram_blk->data, data, data_len);
    dgram_blk->data_len = data_len;
    dgram_blk->to_send_size = data_len;
    dgram_blk->data_sent = 0;
    dgram_blk->data_recv = 0;
    dgram_blk->data_lost = 0;
    dgram_blk->dgram_lost = 0;
    return dgram_blk;
}

void
xqc_wt_dgram_blk_destroy(wt_dgram_blk_t *dgram_blk)
{
    xqc_free(dgram_blk->data);
    xqc_free(dgram_blk);
}