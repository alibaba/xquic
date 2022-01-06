/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_H3_CONN_H_INCLUDED_
#define _XQC_H3_CONN_H_INCLUDED_

#include "src/http3/xqc_var_buf.h"
#include "src/http3/xqc_h3_defs.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/transport/xqc_conn.h"
#include <xquic/xqc_http3.h>

#define XQC_H3_SETTINGS_UNSET XQC_MAX_UINT64_VALUE


/* Send CONNECTION_CLOSE with err if ret is an h3 retcode */
#define XQC_H3_CONN_ERR(h3_conn, err, ret) do {                     \
    if (h3_conn->conn->conn_err == 0 && ret <= -XQC_H3_EMALLOC) {   \
        h3_conn->conn->conn_err = err;                              \
        h3_conn->conn->conn_flag |= XQC_CONN_FLAG_ERROR;            \
        xqc_log(h3_conn->conn->log, XQC_LOG_ERROR, "|conn:%p|err:0x%xi|ret:%i|%s|", \
                h3_conn->conn, h3_conn->conn->conn_err, (int64_t)ret,   \
                xqc_conn_addr_str(h3_conn->conn));                  \
    }                                                               \
} while(0)                                                          \


extern xqc_h3_conn_settings_t default_h3_conn_settings;



typedef enum {
    /* settings recved, the first frame recved on
       control stream MUST be settings */
    XQC_H3_CONN_FLAG_SETTINGS_RECVED            = 1 << 0,

    /* peer's control stream opened and created */
    XQC_H3_CONN_FLAG_CONTROL_OPENED             = 1 << 1,

    /* peer's push stream opened and created */
    XQC_H3_CONN_FLAG_PUSH_OPENED                = 1 << 2,

    /* peer's qpack encoder stream opened and created */
    XQC_H3_CONN_FLAG_QPACK_ENCODER_OPENED       = 1 << 3,

    /* peer's qpack decoder stream opened and created */
    XQC_H3_CONN_FLAG_QPACK_DECODER_OPENED       = 1 << 4,

    /* endpoint has sent goaway frame */
    XQC_H3_CONN_FLAG_GOAWAY_SEND                = 1 << 5,

    /* endpoint has recved goaway frame */
    XQC_H3_CONN_FLAG_GOAWAY_RECVD               = 1 << 6,

    /* used to remember that h3_conn had informed
       the upper layer of h3 connection creation */
    XQC_H3_CONN_FLAG_UPPER_CONN_EXIST           = 1 << 7,

} xqc_http3_conn_flag;

typedef struct xqc_h3_conn_s {
    /* transport contexts */
    xqc_connection_t           *conn;
    xqc_log_t                  *log;
    void                       *user_data;

    /* h3 connection state flags */
    uint64_t                    flags;

    /* h3 connection callback functions for user */
    xqc_h3_conn_callbacks_t     h3_conn_callbacks;

    uint64_t                    max_stream_id_recvd;
    uint64_t                    goaway_stream_id;

    /* qpack context */
    xqc_qpack_t                *qpack;

    /* uni-streams */
    xqc_h3_stream_t            *qdec_stream;
    xqc_h3_stream_t            *qenc_stream;
    xqc_h3_stream_t            *control_stream_out;

    /* blocked streams */
    xqc_list_head_t             block_stream_head;
    uint64_t                    block_stream_count;

    /* h3 settings */
    xqc_h3_conn_settings_t      local_h3_conn_settings; /* set by user for sending to the peer */
    xqc_h3_conn_settings_t      peer_h3_conn_settings;  /* receive from peer */
} xqc_h3_conn_t;


extern const xqc_conn_callbacks_t  h3_conn_callbacks;


/**
 * @brief create and destroy an http3 connection
 */
xqc_h3_conn_t *xqc_h3_conn_create(xqc_connection_t *conn, void *user_data);
void xqc_h3_conn_destroy(xqc_h3_conn_t *h3c);

/**
 * validate the uni stream creation event
 */
xqc_int_t xqc_h3_conn_on_uni_stream_created(xqc_h3_conn_t *h3c, uint64_t stype);

/**
 * whether goaway is recved
 */
xqc_bool_t xqc_h3_conn_is_goaway_recved(xqc_h3_conn_t *h3c, uint64_t stream_id);

xqc_int_t xqc_h3_conn_on_settings_entry_received(uint64_t identifier, uint64_t value,
    void *user_data);

/**
 * get qpack instance
 * this is used to encode or decode http headers in xqc_h3_stream_t
 */
xqc_qpack_t *xqc_h3_conn_get_qpack(xqc_h3_conn_t *h3c);

/* add a blocked request stream */
xqc_h3_blocked_stream_t *xqc_h3_conn_add_blocked_stream(xqc_h3_conn_t *h3c, xqc_h3_stream_t *h3s,
    uint64_t ric);

/* remove a blocked request stream when unblocked or abandoned */
void xqc_h3_conn_remove_blocked_stream(xqc_h3_conn_t *h3c, xqc_h3_blocked_stream_t *blocked_stream);

xqc_int_t xqc_h3_conn_process_blocked_stream(xqc_h3_conn_t *h3c);

xqc_var_buf_t *xqc_h3_conn_get_ins_buf(xqc_qpack_ins_type_t type, void *user_data);

ssize_t xqc_h3_conn_send_ins(xqc_qpack_ins_type_t type, xqc_var_buf_t *buf, void *user_data);


#endif /* _XQC_H3_CONN_H_INCLUDED_ */
