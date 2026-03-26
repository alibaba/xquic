/**
 * xqc_webtransport_dgram.h
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */
#ifndef XQC_WEBTRANSPORT_DGRAM_H
#define XQC_WEBTRANSPORT_DGRAM_H


#include <xquic/xqc_http3.h>
#include <xquic/xqc_webtransport.h>


#ifdef __cplusplus
extern "C" {
#endif

xqc_int_t xqc_wt_datagram_send_blk(xqc_wt_conn_t *user_conn, wt_dgram_blk_t *dgram_blk);

xqc_int_t xqc_webtransport_datagram_send(xqc_webtransport_conn_t *user_conn, void *data,
    uint32_t data_len);


#ifdef __cplusplus
}
#endif

#endif
