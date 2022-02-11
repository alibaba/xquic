/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_H3_REQUEST_H_INCLUDED_
#define _XQC_H3_REQUEST_H_INCLUDED_

#include "src/http3/xqc_h3_stream.h"
#include "src/http3/xqc_h3_header.h"

#define XQC_H3_REQUEST_INITIAL_HEADERS_CAPACITY 32

typedef struct xqc_h3_request_s {
    /* h3 stream handler */
    xqc_h3_stream_t                *h3_stream;

    /* user data for request callback */
    void                           *user_data;

    /* request callback */
    xqc_h3_request_callbacks_t     *request_if;

    /* receive fin flag */
    xqc_bool_t                      fin_flag;

    /* read flag of http3 request */
    xqc_request_notify_flag_t       read_flag;

    /* compressed header size recved */
    size_t                          header_recvd;
    /* received header buf */
    xqc_http_headers_t              h3_header[XQC_H3_REQUEST_MAX_HEADERS_CNT];
    /* total received headers frame count */
    xqc_h3_header_type_t            current_header;

    /* received body buf list and statistic information */
    xqc_list_head_t                 body_buf;
    uint64_t                        body_buf_count;
    size_t                          body_recvd;
    size_t                          body_recvd_final_size;

    /* compressed header size sent */
    size_t                          header_sent;

    /* send body statistic information */
    size_t                          body_sent;
    size_t                          body_sent_final_size;

    /* statistic */
    xqc_msec_t                      blocked_time;           /* time of h3 stream being blocked */
    xqc_msec_t                      unblocked_time;         /* time of h3 stream being unblocked */
    xqc_msec_t                      stream_fin_time;        /* time of receiving transport fin */
    xqc_msec_t                      h3r_begin_time;         /* time of creating request */
    xqc_msec_t                      h3r_end_time;           /* time of request fin */
    xqc_msec_t                      h3r_header_begin_time;  /* time of receiving HEADERS frame */
    xqc_msec_t                      h3r_header_end_time;    /* time of finishing processing HEADERS frame */

} xqc_h3_request_t;


xqc_h3_request_t *xqc_h3_request_create(xqc_engine_t *engine, const xqc_cid_t *cid,
    void *user_data);

xqc_h3_request_t *xqc_h3_request_create_inner(xqc_h3_conn_t *h3_conn, xqc_h3_stream_t *h3_stream,
    void *user_data);

void xqc_h3_request_destroy(xqc_h3_request_t *h3_request);

/**
 * @brief notify events
 */
xqc_int_t xqc_h3_request_on_recv_header(xqc_h3_request_t *h3r);
xqc_int_t xqc_h3_request_on_recv_body(xqc_h3_request_t *h3r);
xqc_int_t xqc_h3_request_on_recv_empty_fin(xqc_h3_request_t *h3r);

/* get headers for writing */
xqc_http_headers_t *xqc_h3_request_get_writing_headers(xqc_h3_request_t *h3r);

void xqc_h3_request_blocked(xqc_h3_request_t *h3r);
void xqc_h3_request_unblocked(xqc_h3_request_t *h3r);
void xqc_h3_request_header_begin(xqc_h3_request_t *h3r);
void xqc_h3_request_header_end(xqc_h3_request_t *h3r);
void xqc_h3_request_stream_fin(xqc_h3_request_t *h3r);
void xqc_h3_request_begin(xqc_h3_request_t *h3r);
void xqc_h3_request_end(xqc_h3_request_t *h3r);

#endif /* _XQC_H3_REQUEST_H_INCLUDED_ */
