/**
 * xqc_webtransport.h
 * @copyright Copyright (c) 2024, Alibaba Group Holding Limited
 */
#ifndef XQC_WEBTRANSPORT_H
#define XQC_WEBTRANSPORT_H

#include "xquic.h"
#include "xqc_http3.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Draft Version of WebTransport
 */
typedef enum {
    XQC_WEBTRANSPORT_DRAFT_VERSION_2,
    XQC_WEBTRANSPORT_DRAFT_VERSION_7,
} xqc_webtransport_draft_version_t;

#define XQC_WEBTRANSPORT_DEFAULT_DGRAM_MSS 512

/**
 * @brief Stream Type of WebTransport
 */
typedef enum {
    XQC_WEBTRANSPORT_UNISTREAM,           // unidirectional stream
    XQC_WEBTRANSPORT_BISTREAM,            // bidirectional stream
    XQC_WEBTRANSPORT_STREAM_TYPE_UNKNOWN  // stream that is not parsed or supported
} xqc_webtransport_stream_type_t;

/**
 * @brief WebTransport Stream Type
 */

typedef enum xqc_wt_unistream_type_s {
    XQC_WT_STREAM_TYPE_SEND = 0,
    XQC_WT_STREAM_TYPE_RECV = 1,
    XQC_WT_STREAM_TYPE_UNKOWN = 2
} xqc_wt_unistream_type_t;

/**
 * @brief WebTransport Connection Settings (not completed)
 *
 */
typedef struct xqc_webtransport_conn_settings_s {
    /* max webtransport session count for single h3 connect */
    uint64_t max_sessions_count;
} xqc_webtransport_conn_settings_t;

/**
 * @brief webtransport connection object
 */
typedef struct xqc_webtransport_conn_s xqc_webtransport_conn_t;  // 兼容之前的定义
typedef xqc_webtransport_conn_t xqc_wt_conn_t;

/**
 * @brief webtransport request object
 */
typedef struct xqc_wt_request_s xqc_wt_request_t;

/**
 * @brief webtransport session object
 */
typedef struct xqc_webtransport_session_s xqc_webtransport_session_t;  // 兼容之前的定义
typedef xqc_webtransport_session_t xqc_wt_session_t;

/**
 * @brief webtransport unistream object
 */
typedef struct xqc_wt_unistream_s xqc_wt_unistream_t;

/**
 * @brief webtransport bidistream object
 */
typedef struct xqc_wt_bidistream_s xqc_wt_bidistream_t;

/**
 * @brief the callback API to notify the application that there is a datagram to be read
 *
 * @param conn the connection handle
 * @param user_data the user_data set by xqc_webtransport_datagram_set_user_data
 * @param data the data delivered by this callback
 * @param data_len the length of the delivered data
 * @param data_recv_time time spent for receiving data
 */
typedef void (*xqc_webtransport_datagram_read_notify_pt)(xqc_webtransport_session_t *session,
                                                         const void *data, size_t data_len, void *user_data, uint64_t data_recv_time);

/**
 * @brief the callback API to notify the application that datagrams can be sent
 *
 * @param conn the connection handle
 * @param user_data the user_data set by xqc_webtransport_datagram_set_user_data
 */
typedef void (*xqc_webtransport_datagram_write_notify_pt)(xqc_webtransport_session_t *session,
                                                          void *user_data);

typedef struct wt_dgram_block_s wt_dgram_blk_t;

/**
 * @brief the callback API to notify the application that a datagram is declared lost.
 * However, the datagram could also be acknowledged later, as the underlying
 * loss detection is not fully accurate. Applications should handle this type of
 * spurious loss. The return value is used to ask the QUIC stack to retransmit the lost
 * datagram packet.
 *
 * @param conn the connection handle
 * @param user_data the user_data set by xqc_webtransport_datagram_set_user_data
 * @param dgram_id the id of the lost datagram
 * @return 0, do not retransmit;
 *         XQC_DGRAM_RETX_ASKED_BY_APP, retransmit;
 *         others, ignored by the QUIC stack.
 */
typedef int (*xqc_webtransport_datagram_lost_notify_pt)(xqc_webtransport_session_t *session,
                                                        uint64_t dgram_id, void *user_data);

/**
 * @brief the callback API to notify the application that a datagram is acked
 *
 * @param conn the connection handle
 * @param user_data the user_data set by xqc_webtransport_datagram_set_user_data
 * @param dgram_id the id of the acked datagram
 */
typedef void (*xqc_webtransport_datagram_acked_notify_pt)(xqc_webtransport_session_t *session,
                                                          uint64_t dgram_id, void *user_data);

/**
 * @brief the callback to notify application the MSS of QUIC datagrams. Note,
 *        the MSS of QUIC datagrams will never shrink. If the MSS is zero, it
 *        means this connection does not support sending QUIC datagrams.
 *
 * @param conn the connection handle
 * @param user_data the dgram_data set by xqc_webtransport_datagram_set_user_data
 * @param mss the MSS of QUIC datagrams
 */
typedef void (*xqc_webtransport_datagram_mss_updated_notify_pt)(xqc_webtransport_session_t *session,
                                                                size_t mss, void *user_data);

/**
 * @brief webtransport datagram callbacks for application layer
 * @param dgram_read_notify the callback to notify the application that there is a datagram to be read
 * @param dgram_write_notify the callback to notify the application that datagrams have been sent
 * @param dgram_acked_notify the callback to notify the application that a datagram is acked
 * @param dgram_lost_notify the callback to notify the application that a datagram is declared lost
 * @param dgram_mss_updated_notify the callback to notify the application that the MSS of QUIC datagrams
 *
 */
typedef struct xqc_webtransport_dgram_callbacks_s {
    /* the return value is ignored by XQUIC stack */
    xqc_webtransport_datagram_read_notify_pt dgram_read_notify;

    /* the return value is ignored by XQUIC stack */
    xqc_webtransport_datagram_write_notify_pt dgram_write_notify;

    /* the return value is ignored by XQUIC stack */
    xqc_webtransport_datagram_acked_notify_pt dgram_acked_notify;

    /* the return value is ignored by XQUIC stack */
    xqc_webtransport_datagram_lost_notify_pt dgram_lost_notify;

    /* the return value is ignored by XQUIC stack */
    xqc_webtransport_datagram_mss_updated_notify_pt dgram_mss_updated_notify;

} xqc_webtransport_dgram_callbacks_t;

/**
 * @brief definition for webtransport session state callback function. including create and close
 * @param session wt_session
 * @param headers http headers. You can get detailed information from headers
 * @param cid connection id , which is used to passed by h3 layer
 * @param h3c_user_data user data from h3 connection,passed by h3 layer
 */
typedef int (*xqc_webtransport_session_notify_pt)(xqc_webtransport_session_t *session, xqc_http_headers_t *headers, const xqc_cid_t *cid,
                                                  void *h3c_user_data);

/**
 * @brief webtransport will create session callback, if return 0, will not create the session,
 * @param headers http headers. You can get detailed information from headers
 * @param response http headers, which will be sent back to client , you can change
 * @return if return 1, will create the session, and send back the response
 */
typedef int (*xqc_webtransport_on_create_session_notify_pt)(xqc_http_headers_t *headers, xqc_http_headers_t *response);

/**
 * @brief webtransport stream close function callback
 * trigger when stream is closed
 */
typedef void (*wt_stream_close_func_pt)();

/**
 * @brief webtransport session handshake finished notify
 * @param session webtransport_session
 */
typedef void (*xqc_webtransport_session_handshake_finish_notify_pt)(xqc_webtransport_session_t *session);

/**
 * @brief webtransport session callbacks for application layer
 */
typedef struct xqc_webtransport_session_callbacks_s {
    /* webtransport will create session callback, if return 0, will not create the session, if return 1, will create the session, and send back the response */
    xqc_webtransport_on_create_session_notify_pt webtransport_will_create_session_notify;
    /* webtransport connection creation callback, REQUIRED for server, OPTIONAL for client */
    xqc_webtransport_session_notify_pt webtransport_session_create_notify;
    /* webtransport connection close callback */
    xqc_webtransport_session_notify_pt webtransport_session_close_notify;
    /*webtransport connection finished notify */
    xqc_webtransport_session_handshake_finish_notify_pt webtransport_session_handshake_finished_notify;

} xqc_webtransport_session_callbacks_t;

/**
 * @brief general callback function definition for stream create, close, read and write.
 *
 * @param stream webtransport stream handler
 * @param strm_user_data stream level user_data, which was the parameter of xqc_webtransport_stream_create set by
 * client, or the parameter of xqc_webtransport_stream_set_user_data set by server
 * @return 0 for success, -1 for failure
 */
typedef xqc_int_t (*xqc_webtransport_unistream_notify_pt)(xqc_wt_unistream_t *stream, xqc_wt_session_t *session,
                                                          void *strm_user_data);

typedef xqc_int_t (*xqc_webtransport_bidistream_notify_pt)(xqc_wt_bidistream_t *stream, xqc_wt_session_t *session,
                                                           void *strm_user_data);

typedef xqc_int_t (*xqc_webtransport_unistream_read_notify_pt)(xqc_wt_unistream_t *stream,
                                                               xqc_wt_session_t *session, void *data, size_t data_len, void *strm_user_data);

typedef xqc_int_t (*xqc_webtransport_bidistream_read_notify_pt)(xqc_wt_bidistream_t *stream,
                                                                xqc_wt_session_t *session, void *data, size_t data_len, void *strm_user_data);

/* webtransport stream callback functions */
typedef struct xqc_webtransport_stream_callbacks_s {
    /**
     * @brief stream read callback function. REQUIRED for both client and server
     *
     * this will be triggered when QUIC stream data is ready for read. application layer could read
     * data when xqc_webtransport_stream_recv interface.
     */
    xqc_webtransport_unistream_read_notify_pt wt_unistream_read_notify;

    /**
     * @brief stream write callback function. REQUIRED for both client and server
     *
     * when sending data with xqc_stream_send, xquic might be blocked or send part of the data. if
     * this callback function is triggered, applications can continue to send the rest data.
     */
    xqc_webtransport_unistream_notify_pt wt_unistream_write_notify;

    /**
     * @brief stream create callback function. REQUIRED for server, OPTIONAL for client.
     *
     * this will be triggered when QUIC stream is created. applications can create its own stream
     * context in this callback function.
     */
    xqc_webtransport_unistream_notify_pt wt_unistream_create_notify;

    /**
     * @brief stream close callback function. REQUIRED for both server and client.
     *
     * this will be triggered when QUIC stream is finally closed. xquic will close stream after
     * sending or receiving RESET_STREAM frame after 3 times of PTO, or when connection is closed.
     * Applications can free the context which was created in stream_create_notify here.
     */
    xqc_webtransport_unistream_notify_pt wt_unistream_close_notify;

    /**
     * @brief stream reset callback function. OPTIONAL for both server and client
     *
     * this function will be triggered when a RESET_STREAM frame is received.
     */
    xqc_webtransport_unistream_notify_pt wt_unistream_closing_notify;

    /**
     * @brief stream read callback function. REQUIRED for both client and server
     *
     * this will be triggered when QUIC stream data is ready for read. application layer could read
     * data when xqc_webtransport_stream_recv interface.
     */
    xqc_webtransport_bidistream_read_notify_pt wt_bidistream_read_notify;

    /**
     * @brief stream write callback function. REQUIRED for both client and server
     *
     * when sending data with xqc_stream_send, xquic might be blocked or send part of the data. if
     * this callback function is triggered, applications can continue to send the rest data.
     */
    xqc_webtransport_bidistream_notify_pt wt_bidistream_write_notify;

    /**
     * @brief stream create callback function. REQUIRED for server, OPTIONAL for client.
     *
     * this will be triggered when QUIC stream is created. applications can create its own stream
     * context in this callback function.
     */
    xqc_webtransport_bidistream_notify_pt wt_bidistream_create_notify;

    /**
     * @brief stream close callback function. REQUIRED for both server and client.
     *
     * this will be triggered when QUIC stream is finally closed. xquic will close stream after
     * sending or receiving RESET_STREAM frame after 3 times of PTO, or when connection is closed.
     * Applications can free the context which was created in stream_create_notify here.
     */
    xqc_webtransport_bidistream_notify_pt wt_bidistream_close_notify;

} xqc_webtransport_stream_callbacks_t;

/**
 * @brief webtransport callbacks for application layer
 * @param dgram_cbs datagram callbacks
 * @param session_cbs session callbacks
 * @param stream_cbs stream callbacks (unidirectional and bidirectional)
 */
typedef struct xqc_webtransport_callbacks_s {
    xqc_webtransport_dgram_callbacks_t dgram_cbs;
    xqc_webtransport_session_callbacks_t session_cbs;
    xqc_webtransport_stream_callbacks_t stream_cbs;
} xqc_webtransport_callbacks_t;

/**
 * @brief
 *
 * @param engine
 * @param dgram_cbs
 * @param session_cbs
 * @param stream_cbs
 * @return XQC_EXPORT_PUBLIC_API
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_wt_ctx_init(xqc_engine_t *engine,
                          xqc_webtransport_dgram_callbacks_t *dgram_cbs,
                          xqc_webtransport_session_callbacks_t *session_cbs,
                          xqc_webtransport_stream_callbacks_t *stream_cbs);

/**
 * @brief create and webtransport connection from client (not implemented)
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
const xqc_cid_t *xqc_webtransport_connect(xqc_engine_t *engine, const xqc_conn_settings_t *conn_settings,
                                          const unsigned char *token, unsigned token_len, const char *server_host, int no_crypto_flag,
                                          const xqc_conn_ssl_config_t *conn_ssl_config, const struct sockaddr *peer_addr,
                                          socklen_t peer_addrlen, void *user_data);

/**
 * @brief create webtransport connection from server (not implemented)
 *
 * @param h3_conn
 * @return XQC_EXPORT_PUBLIC_API*
 */
xqc_wt_conn_t *xqc_wt_create_conn(xqc_h3_conn_t *h3_conn);

/**
 * @brief webtransport unistream init
 *
 * @param unistream_type type=0 send, type = 1 recv, other is not allowd
 * @param session webtransport session
 * @param close_func stream close function
 * @param h3_stream http3 stream
 * @return if successful , return xqc_wt_unistream_t* , otherwise return NULL
 */

XQC_EXPORT_PUBLIC_API
xqc_wt_unistream_t *xqc_wt_create_unistream(xqc_wt_unistream_type_t unistream_type, xqc_wt_session_t *session, wt_stream_close_func_pt close_func, xqc_h3_stream_t *h3_stream);

/**
 * @brief destroy webtransport unistream
 * @param webtransport_unistream
 * @todo: maybe change return value to xqc_int_t
 *
 */
XQC_EXPORT_PUBLIC_API
void xqc_wt_unistream_destroy(xqc_wt_unistream_t *wt_stream);

/**
 * @brief
 *
 * @param wt_conn webtransport connection
 * @param data void* data to be sent , focus on different type (uint8_t* or char*)
 * @param size data len
 * @return if successful , return XQC_OK , otherwise return XQC_ERROR
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_webtransport_datagram_send(xqc_webtransport_conn_t *wt_conn, void *data, uint32_t size);

/**
 * @brief
 *
 * @param sessionID any number for now , as we don't have pooling option
 * @param wt_conn webtransport connection
 * @param h3_stream http3 stream
 * @return if successful , return xqc_wt_session_t* , otherwise return NULL
 */
XQC_EXPORT_PUBLIC_API
xqc_wt_session_t *xqc_wt_session_init(uint64_t sessionID, xqc_wt_conn_t *wt_conn, xqc_h3_stream_t *h3_stream);

/**
 * @brief send data by webtransport unistream
 *
 * @param wt_stream pointer to webtransport unistream
 * @param data data to be sent, focus on different type (uint8_t* or char*)
 * @param len data len
 * @param fin 1:fin, 0:not fin.
 *            If fin is 1, we are not allowed to send data by this unistream anymore
 *            If fin is 0, client may not receive the data immediately (depends on client design)
 *
 * @return XQC_OK for success, XQC_ERROR for failure
 */

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_wt_unistream_send(xqc_wt_unistream_t *wt_stream, void *data, uint32_t len, int fin);

/**
 * @brief webtransport unistream close
 *
 * @param webtransport_unistream pointer to webtransport unistream
 * @return XQC_OK for success, XQC_ERROR for failure
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_wt_unistream_close(xqc_wt_unistream_t *wt_stream);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_wt_conn_close(xqc_wt_conn_t *conn);
/**
 * @brief request table insert , for header parsing
 *
 * @param wt_request webtransport request
 * @param key
 * @param value
 */
void xqc_wt_request_table_insert(xqc_wt_request_t *wt_request, const char *key, const char *value);

/**
 * @brief send data by webtransport bidistream
 *
 * @param wt_stream webtransport bidistream
 * @param data data to be sent
 * @param len data len
 * @param fin 1:fin, 0:not fin. other value is not allowed
 * @return XQC_EXPORT_PUBLIC_API
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_wt_bidistream_send(xqc_wt_bidistream_t *wt_bidistream, void *data, uint32_t len, int fin);

/**
 * @brief Get the webtransport conn by webtransport session
 *
 * @param wt_session webtransport session
 * @return xqc_connection_t*
 */
XQC_EXPORT_PUBLIC_API
xqc_connection_t *xqc_wt_session_get_conn(xqc_wt_session_t *wt_session);

/**
 * @brief set the dgram mss of the connection , if not set then dgram_mss = 100 ;
 * @details if datagram to be sent is larger than mss, it will be split into multiple datagrams
 * @param conn
 * @param mss
 *
 */
XQC_EXPORT_PUBLIC_API
void xqc_wt_conn_set_dgram_mss(xqc_wt_conn_t *conn, size_t mss);

XQC_EXPORT_PUBLIC_API
xqc_h3_stream_t *xqc_wt_session_get_h3_stream(xqc_wt_session_t *session);

/* for test
XQC_EXPORT_PUBLIC_API
uint64_t xqc_wt_unistream_get_sessionID(xqc_wt_unistream_t *wt_stream);

XQC_EXPORT_PUBLIC_API
uint64_t xqc_wt_bidistream_get_sessionID(xqc_wt_bidistream_t *wt_stream);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_wt_unistream_set_h3_stream(xqc_wt_unistream_t *stream, xqc_h3_stream_t *h3_stream);
*/

#ifdef __cplusplus
}
#endif

#endif
