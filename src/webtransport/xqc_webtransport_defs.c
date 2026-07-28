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
    if (dgram_blk == NULL) {
        return NULL;
    }
    dgram_blk->data = xqc_malloc(data_len * sizeof(unsigned char));
    if (dgram_blk->data == NULL) {
        xqc_free(dgram_blk);
        return NULL;
    }
    memcpy(dgram_blk->data, data, data_len);
    dgram_blk->data_len = data_len;
    dgram_blk->to_send_size = data_len;
    return dgram_blk;
}

void
xqc_wt_dgram_blk_destroy(wt_dgram_blk_t *dgram_blk)
{
    if (dgram_blk == NULL) {
        return;
    }
    xqc_free(dgram_blk->data);
    xqc_free(dgram_blk);
}