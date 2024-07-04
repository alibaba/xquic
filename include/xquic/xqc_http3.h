/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_H3_H
#define XQC_H3_H

#include "xquic.h"


#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief read flag of xqc_h3_request_read_notify_pt
 */
typedef enum {
    /* nothing readable */
    XQC_REQ_NOTIFY_READ_NULL            = 0,

    /* read header section flag, this will be set when the first HEADERS is processed */
    XQC_REQ_NOTIFY_READ_HEADER          = 1 << 0,

    /* read body flag, this will be set when a DATA frame is processed */
    XQC_REQ_NOTIFY_READ_BODY            = 1 << 1,

    /* read trailer section flag, this will be set when trailer HEADERS frame is processed */
    XQC_REQ_NOTIFY_READ_TRAILER         = 1 << 2,

    /* read empty fin flag, notify callback will be triggered when a single fin frame is received
       while HEADERS and DATA were notified. This flag will NEVER be set with other flags */
    XQC_REQ_NOTIFY_READ_EMPTY_FIN       = 1 << 3,
} xqc_request_notify_flag_t;


/**
 * @brief definition for http3 connection state callback function. including create and close
 */
typedef int (*xqc_h3_conn_notify_pt)(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, 
    void *h3c_user_data);

typedef void (*xqc_h3_handshake_finished_pt)(xqc_h3_conn_t *h3_conn, void *h3c_user_data);

typedef void (*xqc_h3_conn_ping_ack_notify_pt)(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid,
    void *ping_user_data, void *h3c_user_data);

/**
 * @brief http3 request callbacks
 */
typedef int (*xqc_h3_request_notify_pt)(xqc_h3_request_t *h3_request, void *h3s_user_data);

/**
 * @brief read data callback function
 */
typedef int (*xqc_h3_request_read_notify_pt)(xqc_h3_request_t *h3_request, 
    xqc_request_notify_flag_t flag, void *h3s_user_data);

typedef void (*xqc_h3_request_closing_notify_pt)(xqc_h3_request_t *h3_request, 
    xqc_int_t err, void *h3s_user_data);

/**
 * @brief encode flags of http headers
 */
typedef enum xqc_http3_nv_flag_s {
    /**
     * no flag is set. encode header with default strategy.
     */
    XQC_HTTP_HEADER_FLAG_NONE               = 0x00,

    /**
     * header's name and value shall be encoded as literal, and shall never be indexed.
     */
    XQC_HTTP_HEADER_FLAG_NEVER_INDEX        = 0x01,

    /**
     * header's value is variant and shall never be put into dynamic table and be indexed. this
     * will reduce useless data in dynamic table and might increase the hit rate.
     * 
     * some headers might be frequent but with different values, it is a waste to put these value
     * into dynamic table. application layer can use this flag to tell QPACK not to put value into
     * dynamic table.
     */
    XQC_HTTP_HEADER_FLAG_NEVER_INDEX_VALUE  = 0x02

} xqc_http3_nv_flag_t;


typedef struct xqc_http_header_s {
    /* name of http header */
    struct iovec        name;

    /* value of http header */
    struct iovec        value;

    /* flags of xqc_http3_nv_flag_t with OR operator */
    uint8_t             flags;
} xqc_http_header_t;


typedef struct xqc_http_headers_s {
    /* array of http headers */
    xqc_http_header_t      *headers;

    /* count of headers */
    size_t                  count;

    /* capacity of headers */
    size_t                  capacity;

    /* total byte count of headers */
    size_t                  total_len;
} xqc_http_headers_t;


#define XQC_STREAM_INFO_LEN 128

/**
 * @brief request statistics structure
 */
typedef struct xqc_request_stats_s {
    size_t      send_body_size;
    size_t      recv_body_size;
    size_t      send_header_size;       /* plaintext header size */
    size_t      recv_header_size;       /* plaintext header size */
    size_t      send_hdr_compressed;    /* compressed header size */
    size_t      recv_hdr_compressed;    /* compressed header size */
    int         stream_err;             /* QUIC layer error code, 0 for no error */
    xqc_usec_t  blocked_time;           /* time of h3 stream being blocked */
    xqc_usec_t  unblocked_time;         /* time of h3 stream being unblocked */
    xqc_usec_t  stream_fin_time;        /* time of receiving transport fin */
    xqc_usec_t  h3r_begin_time;         /* time of creating request */
    xqc_usec_t  h3r_end_time;           /* time of request fin */
    xqc_usec_t  h3r_header_begin_time;  /* time of receiving HEADERS frame */
    xqc_usec_t  h3r_header_end_time;    /* time of finishing processing HEADERS frame */
    xqc_usec_t  h3r_body_begin_time;    /* time of receiving DATA frame */
    xqc_usec_t  h3r_header_send_time;
    xqc_usec_t  h3r_body_send_time;
    xqc_usec_t  stream_fin_send_time;
    xqc_usec_t  stream_fin_ack_time;
    const char *stream_close_msg;

    /**
     * @brief 请求级别MP状态
     * 0: 该请求所在连接当前仅有一条可用路径
     * 1: 该请求所在连接当前有多条可用路径，该请求同时在 Available 和 Standby 路径传输
     * 2: 该请求所在连接当前有多条可用路径，但该请求仅在  Standby  路径传输
     * 3: 该请求所在连接当前有多条可用路径，但该请求仅在 Available 路径传输
     */
    int         mp_state;
    float       mp_default_path_send_weight;
    float       mp_default_path_recv_weight;
    float       mp_standby_path_send_weight;
    float       mp_standby_path_recv_weight;

    uint64_t    rate_limit;

    /**
     * @brief 0RTT state
     * 0: no 0RTT
     * 1: 0RTT accept
     * 2: 0RTT reject
     */
    uint8_t     early_data_state;

    char        stream_info[XQC_STREAM_INFO_LEN];

    xqc_usec_t  stream_fst_fin_snd_time;
    
    /**
     * @brief how long the request was blocked by congestion control (ms)
     */
    xqc_msec_t  cwnd_blocked_ms;  
    /**
     * @brief the number of packet has been retransmitted
     */
    uint32_t    retrans_cnt;

    xqc_usec_t  stream_fst_pkt_snd_time;
    xqc_usec_t  stream_fst_pkt_rcv_time;
    
} xqc_request_stats_t;

/**
 * @brief bytestream statistics
 * 
 */
typedef struct xqc_h3_ext_bytestream_stats_s {
    size_t      bytes_sent;
    size_t      bytes_rcvd;
    int         stream_err;
    const char *stream_close_msg;
    xqc_usec_t  create_time;
    xqc_usec_t  fin_rcvd_time;
    xqc_usec_t  fin_read_time;
    xqc_usec_t  fin_sent_time;
    xqc_usec_t  fin_acked_time;
    xqc_usec_t  first_byte_sent_time;
    xqc_usec_t  first_byte_rcvd_time;
} xqc_h3_ext_bytestream_stats_t;

/* connection settings for http3 */
typedef struct xqc_h3_conn_settings_s {
    /* MAX_FIELD_SECTION_SIZE of http3 */
    uint64_t max_field_section_size;

    /* MAX_PUSH_STREAMS */
    uint64_t max_pushes;

    /* ENC_MAX_DYNAMIC_TABLE_CAPACITY */
    uint64_t qpack_enc_max_table_capacity;

    /* DEC_MAX_DYNAMIC_TABLE_CAPACITY */
    uint64_t qpack_dec_max_table_capacity;

    /* MAX_BLOCKED_STREAMS */
    uint64_t qpack_blocked_streams;

#ifdef XQC_COMPAT_DUPLICATE
    /* compat with the original qpack encoder's duplicate strategy */
    xqc_bool_t  qpack_compat_duplicate;
#endif

} xqc_h3_conn_settings_t;

/**
 * @brief callback for h3 bytestream read
 * @param h3_ext_bs bytestream
 * @param data data to be read. NOTE, this could be a NULL pointer, please ONLY read it if data_len > 0.
 * @param data_len length of data to be read
 * @param fin the bytestream is finished
 * @param bs_user_data bytestream user data
 * @param data_recv_time time spent for receiving data
 */
typedef int (*xqc_h3_ext_bytestream_read_notify_pt)(xqc_h3_ext_bytestream_t *h3_ext_bs, 
    const void *data, size_t data_len, uint8_t fin, void *bs_user_data, uint64_t data_recv_time);

/**
 * @brief callbacks for extended h3 bytestream
 */
typedef int (*xqc_h3_ext_bytestream_notify_pt)(xqc_h3_ext_bytestream_t *h3_ext_bs, 
    void *bs_user_data);


/**
 * @brief the callback API to notify the application that there is a datagram to be read
 *
 * @param conn the connection handle
 * @param user_data the user_data set by xqc_h3_ext_datagram_set_user_data
 * @param data the data delivered by this callback
 * @param data_len the length of the delivered data
 * @param data_recv_time time spent for receiving data
 */
typedef void (*xqc_h3_ext_datagram_read_notify_pt)(xqc_h3_conn_t *conn,
    const void *data, size_t data_len, void *user_data, uint64_t data_recv_time);

/**
 * @brief the callback API to notify the application that datagrams can be sent
 *
 * @param conn the connection handle
 * @param user_data the user_data set by xqc_h3_ext_datagram_set_user_data
 */
typedef void (*xqc_h3_ext_datagram_write_notify_pt)(xqc_h3_conn_t *conn,
    void *user_data);

/**
 * @brief the callback API to notify the application that a datagram is declared lost.
 * However, the datagram could also be acknowledged later, as the underlying
 * loss detection is not fully accurate. Applications should handle this type of
 * spurious loss. The return value is used to ask the QUIC stack to retransmit the lost 
 * datagram packet.
 *
 * @param conn the connection handle
 * @param user_data the user_data set by xqc_h3_ext_datagram_set_user_data
 * @param dgram_id the id of the lost datagram
 * @return 0, do not retransmit;
 *         XQC_DGRAM_RETX_ASKED_BY_APP, retransmit;
 *         others, ignored by the QUIC stack.
 */
typedef int (*xqc_h3_ext_datagram_lost_notify_pt)(xqc_h3_conn_t *conn, 
    uint64_t dgram_id, void *user_data);

/**
 * @brief the callback API to notify the application that a datagram is acked
 * 
 * @param conn the connection handle
 * @param user_data the user_data set by xqc_h3_ext_datagram_set_user_data
 * @param dgram_id the id of the acked datagram
 */
typedef void (*xqc_h3_ext_datagram_acked_notify_pt)(xqc_h3_conn_t *conn,
    uint64_t dgram_id, void *user_data);


/**
 * @brief the callback to notify application the MSS of QUIC datagrams. Note, 
 *        the MSS of QUIC datagrams will never shrink. If the MSS is zero, it 
 *        means this connection does not support sending QUIC datagrams.
 * 
 * @param conn the connection handle
 * @param user_data the dgram_data set by xqc_h3_ext_datagram_set_user_data
 * @param mss the MSS of QUIC datagrams
 */
typedef void (*xqc_h3_ext_datagram_mss_updated_notify_pt)(xqc_h3_conn_t *conn,
    size_t mss, void *user_data);


typedef struct xqc_h3_ext_dgram_callbacks_s {

    /* the return value is ignored by XQUIC stack */
    xqc_h3_ext_datagram_read_notify_pt          dgram_read_notify;

    /* the return value is ignored by XQUIC stack */
    xqc_h3_ext_datagram_write_notify_pt         dgram_write_notify;

    /* the return value is ignored by XQUIC stack */
    xqc_h3_ext_datagram_acked_notify_pt         dgram_acked_notify;

    /* the return value is ignored by XQUIC stack */
    xqc_h3_ext_datagram_lost_notify_pt          dgram_lost_notify;
    xqc_h3_ext_datagram_mss_updated_notify_pt   dgram_mss_updated_notify;

} xqc_h3_ext_dgram_callbacks_t;

/**
 * @brief http3 connection callbacks for application layer
 */
typedef struct xqc_h3_conn_callbacks_s {
    /* http3 connection creation callback, REQUIRED for server, OPTIONAL for client */
    xqc_h3_conn_notify_pt               h3_conn_create_notify;

    /* http3 connection close callback */
    xqc_h3_conn_notify_pt               h3_conn_close_notify;

    /* handshake finished callback. which will be triggered when HANDSHAKE_DONE is received */
    xqc_h3_handshake_finished_pt        h3_conn_handshake_finished;

    /* ping callback. which will be triggered when ping is acked */
    xqc_h3_conn_ping_ack_notify_pt      h3_conn_ping_acked;            /* optional */

} xqc_h3_conn_callbacks_t;


/** 
 * @brief http3 request callbacks for application layer
 */
typedef struct xqc_h3_request_callbacks_s {
    /* request creation notify. it will be triggered after a request was created, and is required
       for server, optional for client */
    xqc_h3_request_notify_pt            h3_request_create_notify;

    /* request close notify. which will be triggered after a request was closed */
    xqc_h3_request_notify_pt            h3_request_close_notify;

    /* request read notify callback. which will be triggered after received http headers or body */
    xqc_h3_request_read_notify_pt       h3_request_read_notify;

    /* request write notify callback. when triggered, users can continue to send headers or body */
    xqc_h3_request_notify_pt            h3_request_write_notify;

    /* request closing notify callback, will be triggered when request is closing */
    xqc_h3_request_closing_notify_pt    h3_request_closing_notify;

} xqc_h3_request_callbacks_t;

typedef struct xqc_h3_ext_bytestream_callbacks_s {

    /* the return value is ignored by XQUIC stack */
    xqc_h3_ext_bytestream_notify_pt       bs_create_notify;

    /* the return value is ignored by XQUIC stack */
    xqc_h3_ext_bytestream_notify_pt       bs_close_notify;

    /* negative return values will cause the connection to be closed */
    xqc_h3_ext_bytestream_read_notify_pt  bs_read_notify;

    /* negative return values will cause the connection to be closed */
    xqc_h3_ext_bytestream_notify_pt       bs_write_notify;

} xqc_h3_ext_bytestream_callbacks_t;


typedef struct xqc_h3_callbacks_s {

    /* http3 connection callbacks */
    xqc_h3_conn_callbacks_t           h3c_cbs;

    /* http3 request callbacks */
    xqc_h3_request_callbacks_t        h3r_cbs;

    /* datagram callbacks */
    xqc_h3_ext_dgram_callbacks_t      h3_ext_dgram_cbs;

    /* bytestream callbacks */
    xqc_h3_ext_bytestream_callbacks_t h3_ext_bs_cbs;

} xqc_h3_callbacks_t;


/**
 * @brief init h3 context into xqc_engine_t, this MUST BE called before create any http3 connection
 * 
 * @param engine the engine handler created by xqc_engine_create
 * @return xqc_int_t XQC_OK for success, others for failure
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_h3_ctx_init(xqc_engine_t *engine, xqc_h3_callbacks_t *h3_cbs);


XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_h3_ctx_destroy(xqc_engine_t *engine);


/**
 * @brief set max h3 max dynamic table capacity. It MUST only be called after 
 *        xqc_h3_ctx_init.
 * 
 * @param engine the engine handler created by xqc_engine_create
 * @param value capacity of dynamic table, 0 for disable dynamic table 
 */
XQC_EXPORT_PUBLIC_API
void xqc_h3_engine_set_max_dtable_capacity(xqc_engine_t *engine, size_t capacity);

/**
 * @brief @deprecated use xqc_h3_engine_set_max_dtable_capacity instead. 
 *        It MUST only be called after xqc_h3_ctx_init.
 * 
 * @param engine the engine handler created by xqc_engine_create
 * @param value 0:disable dynamic table
 */
XQC_EXPORT_PUBLIC_API
void xqc_h3_engine_set_dec_max_dtable_capacity(xqc_engine_t *engine, size_t value);

/**
 * @brief @deprecated use xqc_h3_engine_set_max_dtable_capacity instead.
 *        It MUST only be called after xqc_h3_ctx_init.
 * 
 * @param engine the engine handler created by xqc_engine_create
 * @param value 0:disable dynamic table
 */
XQC_EXPORT_PUBLIC_API
void xqc_h3_engine_set_enc_max_dtable_capacity(xqc_engine_t *engine, size_t value);

/**
 * @brief set max h3 field section size.
 *        It MUST only be called after xqc_h3_ctx_init.
 * 
 * @param engine the engine handler created by xqc_engine_create
 * @param size size of field section size
 */
XQC_EXPORT_PUBLIC_API
void xqc_h3_engine_set_max_field_section_size(xqc_engine_t *engine, size_t size);

/**
 * @brief set the limit for qpack blocked streams. 
 *        It MUST only be called after xqc_h3_ctx_init.
 * 
 * @param engine 
 * @param value 
 * @return XQC_EXPORT_PUBLIC_API 
 */
XQC_EXPORT_PUBLIC_API
void xqc_h3_engine_set_qpack_blocked_streams(xqc_engine_t *engine, size_t value);

#ifdef XQC_COMPAT_DUPLICATE
/**
 * @brief It MUST only be called after xqc_h3_ctx_init.
 * 
 * @param engine the engine handler created by xqc_engine_create
 * @param cmpt value
 * @return XQC_EXPORT_PUBLIC_API 
 */
XQC_EXPORT_PUBLIC_API
void xqc_h3_engine_set_qpack_compat_duplicate(xqc_engine_t *engine,
    xqc_bool_t cmpt);
#endif


/**
 * User can set h3 settings when h3_conn_create_notify callbacks
 */
XQC_EXPORT_PUBLIC_API
void xqc_h3_engine_set_local_settings(xqc_engine_t *engine, 
    const xqc_h3_conn_settings_t *h3_conn_settings);

/**
 * @brief create and http3 connection
 * 
 * @param engine return from xqc_engine_create
 * @param conn_settings connection settings
 * @param token token receive from server, xqc_save_token_pt callback
 * @param token_len length of token
 * @param server_host server domain
 * @param no_crypto_flag 1:without crypto
 * @param conn_ssl_config For handshake
 * @param peer_addr address of peer
 * @param peer_addrlen length of peer_addr
 * @param user_data returned in connection callback functions
 * @return cid of the connection; user should copy cid to your own memory, in case of cid destroyed
 * in xquic library
 */
XQC_EXPORT_PUBLIC_API
const xqc_cid_t *xqc_h3_connect(xqc_engine_t *engine, const xqc_conn_settings_t *conn_settings,
    const unsigned char *token, unsigned token_len, const char *server_host, int no_crypto_flag,
    const xqc_conn_ssl_config_t *conn_ssl_config, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *user_data);


/**
 * @brief manually close a http3 connection
 * 
 * @param engine engine handler created by xqc_engine_create
 * @param cid connection id of http3 connection
 * @return XQC_OK for success, others for failure 
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_h3_conn_close(xqc_engine_t *engine, const xqc_cid_t *cid);


/**
 * @brief get QUIC connection handler
 * 
 * @param h3c http3 connection handler
 * @return quic_connection on which h3_conn rely
 */
XQC_EXPORT_PUBLIC_API
xqc_connection_t *xqc_h3_conn_get_xqc_conn(xqc_h3_conn_t *h3c);


/**
 * @brief get http3 protocol error number
 * 
 * @param h3c handler of http3 connection
 * @return error number of http3 connection, HTTP_NO_ERROR(0x100) For no-error
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_h3_conn_get_errno(xqc_h3_conn_t *h3c);


/**
 * @brief get ssl handler of http3 connection
 * 
 * @param h3c handler of http3 connection
 * @return ssl handler of http3 connection
 */
XQC_EXPORT_PUBLIC_API
void *xqc_h3_conn_get_ssl(xqc_h3_conn_t *h3c);


/**
 * @brief set user_data for http3 connection, user_data could be the application layer context of 
 * http3 connection
 * 
 * @param h3c handler of http3 connection
 * @param user_data should set user_data when h3_conn_create_notify callbacks, which will be
 * returned as parameter of http3 connection callback functions
 */
XQC_EXPORT_PUBLIC_API
void xqc_h3_conn_set_user_data(xqc_h3_conn_t *h3c, void *user_data);

/**
 * @brief get user_data for http3 connection, user_data could be the application layer context of 
 * http3 connection
 * 
 * @param h3c handler of http3 connection
 * @return user_data 
 */
XQC_EXPORT_PUBLIC_API
void *xqc_h3_conn_get_user_data(xqc_h3_conn_t *h3_conn);



/**
 * @brief get peer address information, server should call this when h3_conn_create_notify triggers
 * 
 * @param h3c handler of http3 connection
 * @param addr [out] output address of peer
 * @param addr_cap capacity of addr
 * @param peer_addr_len [out] output length of addr
 * @return XQC_OK for success, others for failure
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_h3_conn_get_peer_addr(xqc_h3_conn_t *h3c, struct sockaddr *addr, socklen_t addr_cap,
    socklen_t *peer_addr_len);


/**
 * @brief get local address information, server should call this when h3_conn_create_notify triggers
 * 
 * @param h3c handler of http3 connection
 * @param addr [out] output address of peer
 * @param addr_cap capacity of addr
 * @param peer_addr_len [out] output length of addr
 * @return XQC_OK for success, others for failure
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_h3_conn_get_local_addr(xqc_h3_conn_t *h3c, struct sockaddr *addr,  socklen_t addr_cap,
    socklen_t *local_addr_len);


/**
 * @brief Send PING to peer, if ack received, h3_conn_ping_acked will callback with user_data
 * 
 * @param engine handler of engine
 * @param cid connection id of http3 connection, which is generated by xqc_h3_connect
 * @param ping_user_data 
 * @return XQC_OK for success, < 0 for error
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_h3_conn_send_ping(xqc_engine_t *engine, const xqc_cid_t *cid, void *ping_user_data);


/**
 * @brief check if h3 connection is ready to send 0rtt data
 * @param h3c h3 connection handler
 * @return XQC_TRUE for can send 0rtt, XQC_FALSE for can not
 */
XQC_EXPORT_PUBLIC_API
xqc_bool_t xqc_h3_conn_is_ready_to_send_early_data(xqc_h3_conn_t *h3c);


/**
 * @brief set the dynamic table capacity of an existing h3 connection
 * @param h3c h3 connection handler
 * @param capacity capacity of dynamic table, 0 for disable dynamic table 
 * @return XQC_OK for success, others for failure
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_h3_conn_set_qpack_dtable_cap(xqc_h3_conn_t *h3c, size_t capacity);



/**
 * @brief create a http3 request
 * @param engine handler created by xqc_engine_create
 * @param cid connection id of http3 connection
 * @param user_data For request
 * @param settings stream settings
 * @return handler of http3 request
 */
XQC_EXPORT_PUBLIC_API
xqc_h3_request_t *xqc_h3_request_create(xqc_engine_t *engine, const xqc_cid_t *cid, 
    xqc_stream_settings_t *settings, void *user_data);

/**
 * @brief get statistics of a http3 request user can get it before request destroyed
 * 
 * @param h3_request handler of http3 request
 * @return statistics information of request
 */
XQC_EXPORT_PUBLIC_API
xqc_request_stats_t xqc_h3_request_get_stats(xqc_h3_request_t *h3_request);

/**
 * @brief write important information into str
 * @return the number of characters printed
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_h3_request_stats_print(xqc_h3_request_t *h3_request, char *str, size_t size);

/**
 * @brief set user_data of a http3 request, which will be used as parameter of request
 * callback functions. server should set user_data when h3_request_create_notify triggers
 * 
 * @param h3_request handler of http3 request
 * @param user_data user data of request callback functions
 */
XQC_EXPORT_PUBLIC_API
void xqc_h3_request_set_user_data(xqc_h3_request_t *h3_request, void *user_data);

/**
 * @brief close request, send QUIC RESET_STREAM frame to peer. h3_request_close_notify will 
 * triggered when request is finally destroyed
 * 
 * @param h3_request handler of http3 request
 * @return XQC_OK for success, others for error
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_h3_request_close(xqc_h3_request_t *h3_request);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_h3_request_update_settings(xqc_h3_request_t *h3_request, 
    xqc_stream_settings_t *settings);

/**
 * @brief send http headers to peer
 * 
 * @param h3_request handler of http3 request
 * @param headers http headers
 * @param fin request finish flag, 1 for finish. if set here, it means request has no body
 * @return > 0 for Bytes sent，-XQC_EAGAIN try next time, < 0 for error, 0 for request finished
 */
XQC_EXPORT_PUBLIC_API
ssize_t xqc_h3_request_send_headers(xqc_h3_request_t *h3_request, xqc_http_headers_t *headers,
    uint8_t fin);

/**
 * @brief send http body to peer
 * 
 * @param h3_request handler of http3 request
 * @param data content of body
 * @param data_size length of body
 * @param fin request finish flag, 1 for finish.
 * @return > 0 for Bytes sent，-XQC_EAGAIN try next time, < 0 for error, 0 for request finished
 */
XQC_EXPORT_PUBLIC_API
ssize_t xqc_h3_request_send_body(xqc_h3_request_t *h3_request, unsigned char *data, 
    size_t data_size, uint8_t fin);

/**
 * @brief finish request. if fin is not sent yet, and application has nothing to send anymore, call
 * this function to send a QUIC STREAM frame with only fin
 *
 * @return > 0 for Bytes sent，-XQC_EAGAIN try next time, < 0 for error, 0 for request finished
 */
XQC_EXPORT_PUBLIC_API
ssize_t xqc_h3_request_finish(xqc_h3_request_t *h3_request);

/**
 * @brief receive headers of a request
 * 
 * @param h3_request handler of http3 request
 * @param fin request finish flag, 1 for finish. if not 0, it means request has no body
 * @return request headers. user should copy headers to your own memory，NULL for error
 */
XQC_EXPORT_PUBLIC_API
xqc_http_headers_t *xqc_h3_request_recv_headers(xqc_h3_request_t *h3_request, uint8_t *fin);

/**
 * @brief receive body of a request
 * 
 * @param h3_request handler of http3 request
 * @param fin request finish flag, 1 for finish
 * @return Bytes read，-XQC_EAGAIN try next time, <0 for error
 */
XQC_EXPORT_PUBLIC_API
ssize_t xqc_h3_request_recv_body(xqc_h3_request_t *h3_request, unsigned char *recv_buf, 
    size_t recv_buf_size, uint8_t *fin);


/**
 * @brief get connection's user_data by request
 * 
 * @param h3_request handler of http3 request
 * @return user_data set by user
 */
XQC_EXPORT_PUBLIC_API
void *xqc_h3_get_conn_user_data_by_request(xqc_h3_request_t *h3_request);

/**
 * @brief Get QUIC stream ID by request
 * 
 * @param h3_request handler of http3 request
 * @return QUIC stream id
 */
XQC_EXPORT_PUBLIC_API
xqc_stream_id_t xqc_h3_stream_id(xqc_h3_request_t *h3_request);


/**
 * @brief RFC 9218 HTTP Priority
 */
XQC_EXPORT_PUBLIC_API
size_t xqc_write_http_priority(xqc_h3_priority_t *prio,
    uint8_t *dst, size_t dstcap);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_parse_http_priority(xqc_h3_priority_t *dst,
    const uint8_t *str, size_t str_len);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_h3_request_set_priority(xqc_h3_request_t *h3r,
    xqc_h3_priority_t *prio);

/****************************/
/* New APIs for extended H3 */
/****************************/

/**
 * @brief create a bytestream based on extended H3
 * @param engine handler created by xqc_engine_create
 * @param cid connection id of http3 connection
 * @param user_data For bytestream
 * @return handler of bytestream
 */
XQC_EXPORT_PUBLIC_API
xqc_h3_ext_bytestream_t *xqc_h3_ext_bytestream_create(xqc_engine_t *engine, 
    const xqc_cid_t *cid, void *user_data);

/**
 * @brief close bytestream, send QUIC RESET_STREAM frame to peer. h3_ext_bytestream_close_notify will 
 * triggered when bytestream is finally destroyed
 * 
 * @param xqc_h3_ext_bytestream_t handler of bytestream
 * @return XQC_OK for success, others for error
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_h3_ext_bytestream_close(xqc_h3_ext_bytestream_t *h3_ext_bs);

/**
 * @brief finish bytestream. if fin is not sent yet, and application has nothing to send anymore, call
 * this function to send a QUIC STREAM frame with only fin
 *
 * @return > 0 for Bytes sent，-XQC_EAGAIN try next time, < 0 for error, 0 for bytestream finished
 */
XQC_EXPORT_PUBLIC_API
ssize_t xqc_h3_ext_bytestream_finish(xqc_h3_ext_bytestream_t *h3_ext_bs);

/**
 * @brief set user_data of a bytestream, which will be used as the parameter of the bytestream
 * callback functions. server should set user_data when h3_ext_bytestream_create_notify triggers
 * 
 * @param xqc_h3_ext_bytestream_t handler of the bytestream
 * @param user_data user data of the bytestream callback functions
 */
XQC_EXPORT_PUBLIC_API
void xqc_h3_ext_bytestream_set_user_data(xqc_h3_ext_bytestream_t *h3_ext_bs, 
    void *user_data);


/**
 * @brief get the user data associcated with the bytestream object
 * 
 * @param xqc_h3_ext_bytestream_t handler of the bytestream
 * @param user_data user data of the bytestream callback functions
 * @return the pointer of user data
 */
XQC_EXPORT_PUBLIC_API
void *xqc_h3_ext_bytestream_get_user_data(xqc_h3_ext_bytestream_t *h3_ext_bs);

/**
 * @brief get statistics of a bytestream
 * 
 * @param xqc_h3_ext_bytestream_t handler of the bytestream
 * @return statistics information of the bytestream
 */
XQC_EXPORT_PUBLIC_API
xqc_h3_ext_bytestream_stats_t xqc_h3_ext_bytestream_get_stats(
    xqc_h3_ext_bytestream_t *h3_ext_bs);

/**
 * @brief send data
 * 
 * @param xqc_h3_ext_bytestream_t handler of the bytestream
 * @param data content
 * @param data_size data length
 * @param fin request finish flag, 1 for finish.
 * @param qos level (must be the values defined in xqc_data_qos_level_t)
 * @return > 0 for bytes sent，-XQC_EAGAIN try next time, < 0 for error, 0 for bytestream finished
 */
XQC_EXPORT_PUBLIC_API
ssize_t xqc_h3_ext_bytestream_send(xqc_h3_ext_bytestream_t *h3_ext_bs, 
    unsigned char *data, size_t data_size, uint8_t fin, 
    xqc_data_qos_level_t qos_level);

/**
 * @brief Get QUIC stream ID by a bytestream
 * 
 * @param xqc_h3_ext_bytestream_t handler of a bytestream
 * @return QUIC stream id
 */
XQC_EXPORT_PUBLIC_API
xqc_stream_id_t xqc_h3_ext_bytestream_id(xqc_h3_ext_bytestream_t *h3_ext_bs);

/**
 * @brief get the h3 connection associated with a bytestream
 * 
 * @param xqc_h3_ext_bytestream_t handler of a bytestream
 * @return an h3 connection
 */
XQC_EXPORT_PUBLIC_API
xqc_h3_conn_t *xqc_h3_ext_bytestream_get_h3_conn(
    xqc_h3_ext_bytestream_t *h3_ext_bs);

/**
 * @brief the API to get the max length of the data that can be sent 
 *        via a single call of xqc_datagram_send
 * 
 * @param conn the connection handle 
 * @return 0 = the peer does not support datagram, >0 = the max length
 */
XQC_EXPORT_PUBLIC_API
size_t xqc_h3_ext_datagram_get_mss(xqc_h3_conn_t *conn);

/**
 * Server should set datagram user_data when datagram callbacks
 * @dgram_data: the user_data of all datagram callbacks
 */
XQC_EXPORT_PUBLIC_API
void xqc_h3_ext_datagram_set_user_data(xqc_h3_conn_t *conn, void *user_data);

/**
 * @return the user_data of all datagram callbacks
 */
XQC_EXPORT_PUBLIC_API
void *xqc_h3_ext_datagram_get_user_data(xqc_h3_conn_t *conn);


/**
 * @brief the API to send a datagram over the h3 connection
 * 
 * @param conn the connection handle 
 * @param data the data to be sent
 * @param data_len the length of the data
 * @param *dgram_id the pointer to return the id the datagram
 * @param qos level (must be the values defined in xqc_data_qos_level_t)
 * @return <0 = error (-XQC_EAGAIN, -XQC_CLOSING, -XQC_DGRAM_NOT_SUPPORTED, -XQC_DGRAM_TOO_LARGE, ...), 
 *         0 success
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_h3_ext_datagram_send(xqc_h3_conn_t *conn, void *data, 
    size_t data_len, uint64_t *dgram_id, 
    xqc_data_qos_level_t qos_level);

/**
 * @brief the API to send a datagram over the h3 connection
 * 
 * @param conn the connection handle 
 * @param iov multiple data buffers need to be sent 
 * @param *dgram_id the pointer to return the list of dgram_id 
 * @param iov_size the size of iov list 
 * @param *sent_cnt the number of successfully sent datagrams
 * @param *sent_bytes the total bytes of successfully sent datagrams
 * @param qos level (must be the values defined in xqc_data_qos_level_t)
 * @return <0 = error (-XQC_EAGAIN, -XQC_CLOSING, -XQC_DGRAM_NOT_SUPPORTED, -XQC_DGRAM_TOO_LARGE, ...), 
 *         0 success
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_h3_ext_datagram_send_multiple(xqc_h3_conn_t *conn, 
    struct iovec *iov, uint64_t *dgram_id_list, size_t iov_size, 
    size_t *sent_cnt, size_t *sent_bytes,
    xqc_data_qos_level_t qos_level);


#ifdef __cplusplus
}
#endif


#endif
