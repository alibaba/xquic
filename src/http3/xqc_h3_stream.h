/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_H3_STREAM_H_
#define _XQC_H3_STREAM_H_

#include "src/common/utils/var_buf/xqc_var_buf.h"
#include "src/http3/xqc_h3_defs.h"
#include "src/http3/qpack/xqc_qpack.h"
#include "src/http3/frame/xqc_h3_frame.h"
#include "src/transport/xqc_stream.h"

typedef struct xqc_h3_conn_s    xqc_h3_conn_t;
typedef struct xqc_h3_stream_s  xqc_h3_stream_t;

typedef enum {
    /* uni stream types */
    XQC_H3_STREAM_TYPE_CONTROL          = 0x00,
    XQC_H3_STREAM_TYPE_PUSH             = 0x01,
    XQC_H3_STREAM_TYPE_QPACK_ENCODER    = 0x02,
    XQC_H3_STREAM_TYPE_QPACK_DECODER    = 0x03,

    /* bidi stream type */
    XQC_H3_STREAM_TYPE_REQUEST          = 0x10,
    XQC_H3_STREAM_TYPE_BYTESTEAM        = 0x20,

    /* reserved stream type or others */
    XQC_H3_STREAM_TYPE_UNKNOWN          = 0xFFFFFFFFFFFFFFFFull,
} xqc_h3_stream_type_t;

typedef enum {
   XQC_H3_BIDI_STREAM_TYPE_REQUEST    = 0,
   XQC_H3_BIDI_STREAM_TYPE_BYTESTREAM = 1,
} xqc_h3_bidi_stream_type_t;

typedef enum {
    XQC_HTTP3_STREAM_FLAG_NONE                  = 0x0000,
    XQC_HTTP3_STREAM_FLAG_TYPE_IDENTIFIED       = 0x0001,
    /* XQC_HTTP3_STREAM_FLAG_FC_BLOCKED indicates that stream is
       blocked by QUIC flow control. */
    XQC_HTTP3_STREAM_FLAG_FC_BLOCKED            = 0x0002,
    /* XQC_HTTP3_STREAM_FLAG_READ_DATA_BLOCKED indicates that application
       is temporarily unable to provide data. */
    XQC_HTTP3_STREAM_FLAG_READ_DATA_BLOCKED     = 0x0004,
    /* XQC_HTTP3_STREAM_FLAG_WRITE_END_STREAM indicates that application
       finished to feed outgoing data. */
    XQC_HTTP3_STREAM_FLAG_WRITE_END_STREAM      = 0x0008,
    /* XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED indicates that stream is
       blocked due to QPACK decoding. */
    XQC_HTTP3_STREAM_FLAG_QPACK_DECODE_BLOCKED  = 0x0010,
    /* XQC_HTTP3_STREAM_FLAG_READ_EOF indicates that remote endpoint sent
       fin. */
    XQC_HTTP3_STREAM_FLAG_READ_EOF              = 0x0020,
    /* XQC_HTTP3_STREAM_FLAG_CLOSED indicates that QUIC stream was closed.
       h3 stream object will still alive because it might be blocked
       by QPACK decoder. */
    XQC_HTTP3_STREAM_FLAG_CLOSED                = 0x0040,
    /* XQC_HTTP3_STREAM_FLAG_PUSH_PROMISE_BLOCKED indicates that stream is
       blocked because the corresponding PUSH_PROMISE has not been
       received yet. */
    XQC_HTTP3_STREAM_FLAG_PUSH_PROMISE_BLOCKED  = 0x0080,
    /* XQC_HTTP3_STREAM_FLAG_PRIORITY_SET indicates that stream
       has been prioritized. */
    XQC_HTTP3_STREAM_FLAG_PRIORITY_SET          = 0x0100,
    /* XQC_HTTP3_STREAM_FLAG_RESET indicates that stream is reset. */
    XQC_HTTP3_STREAM_FLAG_RESET                 = 0x0200,
    XQC_HTTP3_STREAM_NEED_WRITE_NOTIFY          = 0x0400,
    XQC_HTTP3_STREAM_IN_READING                 = 0x0800,
    /* XQC_HTTP3_STREAM_FLAG_ACTIVELY_CLOSED indicates that application actively
       closed request, this will close h3 stream immediately when h3 stream is 
       blocked and waiting for encoder stream insertions while Transport stream
       notify its close */
    XQC_HTTP3_STREAM_FLAG_ACTIVELY_CLOSED       = 0x1000,
    /* FIN was sent and no data will be sent any more */
    XQC_HTTP3_STREAM_FLAG_FIN_SENT              = 0x2000,
} xqc_h3_stream_flag;

typedef struct xqc_h3_stream_pctx_s {
    /* parsing context for uni-stream type */
    xqc_discrete_int_pctx_t         type;

    /* parsing context for control-stream */
    xqc_h3_frame_pctx_t             frame_pctx;
} xqc_h3_stream_pctx_t;



typedef struct xqc_h3_stream_s {
    /* transport stream context, the lifetime might be out of sync with h3_stream. */
    xqc_stream_t                   *stream;
    uint64_t                        stream_id;
    uint64_t                        stream_err;
    void                           *user_data;

    /* http3 connection */
    xqc_h3_conn_t                  *h3c;

    /*
     * bidi stream user interface, used to send/recv request contents. h3r is
     * available only in request streams, create or dereference in control or
     * reserved streams is forbidden.
     */
    union {
      xqc_h3_request_t               *h3r;
      xqc_h3_ext_bytestream_t        *h3_ext_bs;
    };
    

    /* stream type */
    xqc_h3_stream_type_t            type;

    /* qpack handler */
    xqc_qpack_t                    *qpack;

    /* stream flags, used to remember states */
    uint64_t                        flags;

    /* stream parsing state context */
    xqc_h3_stream_pctx_t            pctx;

    /* stream send buffer */
    xqc_list_head_t                 send_buf;

    /* stream priority (RFC9218) */
    xqc_h3_priority_t               priority;

    struct {
        size_t                      header_len;
        size_t                      header_sent;
        size_t                      data_len;
        size_t                      data_sent;
        unsigned char               header_buf[16];
    } data_frame;

    /* blocked data buffer, used to store request
       stream data when stream is blocked */
    xqc_list_head_t                 blocked_buf;
    xqc_h3_blocked_stream_t        *blocked_stream;

    /* context of representation */
    xqc_rep_ctx_t                  *ctx;

    xqc_log_t                      *log;

    xqc_path_metrics_t              paths_info[XQC_MAX_PATHS_COUNT];

   /* referred count of h3 stream */
    uint32_t                        ref_cnt;

    uint64_t                        recv_rate_limit;
    uint64_t                        send_offset;
    uint64_t                        recv_offset;

    uint8_t                         early_data_state;

    char                            begin_trans_state[XQC_STREAM_TRANSPORT_STATE_SZ];
    char                            end_trans_state[XQC_STREAM_TRANSPORT_STATE_SZ];

} xqc_h3_stream_t;


/* transport layer callback hook */
extern const xqc_stream_callbacks_t h3_stream_callbacks;

void xqc_h3_stream_update_stats(xqc_h3_stream_t *h3s);

xqc_h3_stream_t *xqc_h3_stream_create(xqc_h3_conn_t *h3c, xqc_stream_t *stream,
   xqc_h3_stream_type_t type, void *user_data);

xqc_int_t xqc_h3_stream_close(xqc_h3_stream_t *h3s);

void xqc_h3_stream_destroy(xqc_h3_stream_t *h3s);

xqc_int_t xqc_h3_stream_send_buffer(xqc_h3_stream_t *h3s);

xqc_int_t xqc_h3_stream_send_uni_stream_hdr(xqc_h3_stream_t *h3s);

ssize_t xqc_h3_stream_send_headers(xqc_h3_stream_t *h3s, xqc_http_headers_t *headers, uint8_t fin);

ssize_t xqc_h3_stream_send_data(xqc_h3_stream_t *h3s, unsigned char *data, size_t data_size,
   uint8_t fin);

xqc_int_t xqc_h3_stream_send_finish(xqc_h3_stream_t *h3s);

xqc_int_t xqc_h3_stream_send_setting(xqc_h3_stream_t *h3s, xqc_h3_conn_settings_t *settings,
   uint8_t fin);

xqc_int_t xqc_h3_stream_send_goaway(xqc_h3_stream_t *h3s, uint64_t push_id, uint8_t fin);

xqc_int_t xqc_h3_stream_process_blocked_stream(xqc_h3_stream_t *h3s);

xqc_var_buf_t *xqc_h3_stream_get_send_buf(xqc_h3_stream_t *h3s);

uint64_t xqc_h3_stream_get_err(xqc_h3_stream_t *h3s);

void xqc_h3_stream_get_path_info(xqc_h3_stream_t *h3s);

void xqc_h3_stream_set_priority(xqc_h3_stream_t *h3s, xqc_h3_priority_t *prio);

xqc_int_t xqc_h3_stream_send_bidi_stream_type(xqc_h3_stream_t *h3s, 
   xqc_h3_bidi_stream_type_t stype, uint8_t fin);

#endif
