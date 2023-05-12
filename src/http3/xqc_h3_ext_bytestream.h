/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_H3_EXT_BYTESTREAM_H_INCLUDED_
#define _XQC_H3_EXT_BYTESTREAM_H_INCLUDED_

#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_stream.h"

typedef struct xqc_h3_ext_bytestream_data_buf_s {
    xqc_list_head_t  list;
    xqc_list_head_t  buf_list;
    uint32_t         buf_cnt;
    uint64_t         total_len;
    uint64_t         curr_len;
    xqc_usec_t       start_time;
    xqc_usec_t       end_time;
} xqc_h3_ext_bytestream_data_buf_t;

typedef struct xqc_h3_ext_bytestream_s xqc_h3_ext_bytestream_t;

void xqc_h3_ext_bytestream_destroy(xqc_h3_ext_bytestream_t *bs);

xqc_int_t xqc_h3_ext_bytestream_notify_write(xqc_h3_ext_bytestream_t *bs);

xqc_h3_ext_bytestream_t *xqc_h3_ext_bytestream_create_passive(
    xqc_h3_conn_t *h3_conn, xqc_h3_stream_t *h3_stream, void *user_data);

xqc_int_t xqc_h3_ext_bytestream_append_data_buf(xqc_h3_ext_bytestream_t *bs, 
    xqc_var_buf_t *buf);

xqc_h3_ext_bytestream_data_buf_t* xqc_h3_ext_bytestream_get_last_data_buf(xqc_h3_ext_bytestream_t *bs, xqc_h3_frame_pctx_t *pctx);
xqc_int_t xqc_h3_ext_bytestream_save_data_to_buf(xqc_h3_ext_bytestream_data_buf_t *buf,
    const uint8_t *data, size_t data_len);

void xqc_h3_ext_bytestream_set_fin_sent_flag(xqc_h3_ext_bytestream_t *bs);
void xqc_h3_ext_bytestream_set_fin_rcvd_flag(xqc_h3_ext_bytestream_t *bs);

xqc_bool_t xqc_h3_ext_bytestream_should_notify_read(xqc_h3_ext_bytestream_t *bs);

xqc_int_t xqc_h3_ext_bytestream_notify_read(xqc_h3_ext_bytestream_t *bs);

void xqc_h3_ext_bytestream_save_stats_from_stream(xqc_h3_ext_bytestream_t *bs, 
    xqc_stream_t *stream);

/* to record performance statistics */
void xqc_h3_ext_bytestream_recv_begin(xqc_h3_ext_bytestream_t *bs);
void xqc_h3_ext_bytestream_send_begin(xqc_h3_ext_bytestream_t *bs);
void xqc_h3_ext_bytestream_fin_rcvd(xqc_h3_ext_bytestream_t *bs);
void xqc_h3_ext_bytestream_fin_read(xqc_h3_ext_bytestream_t *bs);
void xqc_h3_ext_bytestream_fin_sent(xqc_h3_ext_bytestream_t *bs);



#endif