/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQUIC_H_INCLUDED_
#define _XQUIC_H_INCLUDED_

/**
 * Public API for using libxquic
 */
#include "xqc_configure.h"
#include "xquic_typedef.h"

#if defined(XQC_SYS_WINDOWS) && !defined(XQC_ON_MINGW)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief engine type definition
 */
typedef enum {
    XQC_ENGINE_SERVER,
    XQC_ENGINE_CLIENT
} xqc_engine_type_t;


/**
 * @brief supported versions for IETF drafts
 */
typedef enum xqc_proto_version_s {
    /* placeholder */
    XQC_IDRAFT_INIT_VER,

    /* former version of QUIC RFC 9000 */
    XQC_VERSION_V1,

    /* IETF Draft-29 */
    XQC_IDRAFT_VER_29,

     /* Special version for version negotiation. */
    XQC_IDRAFT_VER_NEGOTIATION,

    XQC_VERSION_MAX
} xqc_proto_version_t;

#define XQC_SUPPORT_VERSION_MAX         64


#define XQC_TLS_CIPHERS "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
#define XQC_TLS_GROUPS "P-256:X25519:P-384:P-521"


#define XQC_RESET_TOKEN_MAX_KEY_LEN     256


/**
 * the max message count of iovec in sendmmsg
 */
#define XQC_MAX_SEND_MSG_ONCE           32

#define XQC_INITIAL_PATH_ID             0

#define XQC_DGRAM_RETX_ASKED_BY_APP     1

#define XQC_CO_MAX_NUM                  16
#define XQC_CO_STR_MAX_LEN              (5 * XQC_CO_MAX_NUM)

#define XQC_FEC_MAX_SCHEME_NUM          5


/**
 * @brief get timestamp callback function. this might be useful on different platforms
 * @return timestamp in microsecond
 */
typedef xqc_usec_t (*xqc_timestamp_pt)(void);

/**
 * @brief event timer callback function. MUST be set for both client and server
 * xquic don't have implementation of timer, but will tell the interval of timer by this function.
 * applications shall implement the timer, and invoke xqc_engine_main_logic after timer expires.
 *
 * @param wake_after interval of timer, with micro-second.
 * @param engine_user_data user_data of engine
 */
typedef void (*xqc_set_event_timer_pt)(xqc_usec_t wake_after, void *engine_user_data);

/**
 * @brief cid generate callback.
 *
 * @param ori_cid the original dcid sent by client.
 * @param cid_buf  buffer for cid generated
 * @param cid_buflen len for cid_buf
 * @param engine_user_data  user data of engine from `xqc_engine_create`
 * @return negative for failed, non-negative (including 0) for the length of bytes written. if the
 * count of written bytes is less than cid_buflen, xquic will fill rest of cid_buf with random bytes
 */
typedef ssize_t (*xqc_cid_generate_pt)(const xqc_cid_t *ori_cid, uint8_t *cid_buf,
    size_t cid_buflen, void *engine_user_data);

/**
 * @brief engine secret log callback. will only be effective when build with XQC_PRINT_SECRET
 *
 * this callback will be invoked everytime when TLS layer generates a secret, and will be triggered
 * multiple times during handshake. keylog could be used in wireshark to parse QUIC packets
 */
typedef void (*xqc_eng_keylog_pt)(const xqc_cid_t *scid, const char *line, void *engine_user_data);

/**
 * @brief tls secret log callback. will only be effective when build with XQC_PRINT_SECRET
 *
 * this callback will be invoked everytime when TLS layer generates a secret, and will be triggered
 * multiple times during handshake. keylog could be used in wireshark to parse QUIC packets
 */
typedef void (*xqc_keylog_pt)(const char *line, void *engine_user_data);

/**
 * @brief log callback functions
 */
typedef struct xqc_log_callbacks_s {
    /**
     * trace log callback function
     *
     * trace log including XQC_LOG_FATAL, XQC_LOG_ERROR, XQC_LOG_WARN, XQC_LOG_STATS, XQC_LOG_INFO,
     * XQC_LOG_DEBUG, xquic will output logs with the level higher or equal to the level configured
     * in xqc_log_init. Besides, when qlog enable and EVENT_IMPORTANCE_SELECTED importance is set, some
     * event log will output log by xqc_log_write_err callback.
     */
    void (*xqc_log_write_err)(xqc_log_level_t lvl, const void *buf, size_t size, void *engine_user_data);

    /**
     * statistic log callback function
     *
     * this function will be triggered when write XQC_LOG_REPORT or XQC_LOG_STATS level logs.
     * mainly when connection close, stream close.
     */
    void (*xqc_log_write_stat)(xqc_log_level_t lvl, const void *buf, size_t size, void *engine_user_data);

    /**
     * qlog event callback function
     *
     * qlog event importance including EVENT_IMPORTANCE_SELECTED, EVENT_IMPORTANCE_CORE, EVENT_IMPORTANCE_BASE,
     * EVENT_IMPORTANCE_EXTRA and EVENT_IMPORTANCE_REMOVED.
     * EVENT_IMPORTANCE_CORE, EVENT_IMPORTANCE_BASE and EVENT_IMPORTANCE_EXTRA follow the defination of qlog draft.
     * EVENT_IMPORTANCE_SELECTED works by xqc_log_write_err
     * EVENT_IMPORTANCE_REMOVED exits, because the last qlog draft remove some qlog event, but the current qvis tool
     * still need them.
     */
    void (*xqc_qlog_event_write)(qlog_event_importance_t imp, const void *buf, size_t size, void *engine_user_data);

} xqc_log_callbacks_t;


/**
 * @brief connection accept callback.
 *
 * this function is invoked when incoming a new QUIC connection. return 0 means accept this new
 * connection. return negative values if application layer will not accept the new connection
 * due to busy or some reason else
 *
 * @param user_data the user_data parameter of xqc_engine_packet_process
 * @return negative for refuse connection. 0 for accept
 */
typedef int (*xqc_server_accept_pt)(xqc_engine_t *engine, xqc_connection_t *conn,
    const xqc_cid_t *cid, void *user_data);

/**
 * @brief connection refused callback. corresponding to xqc_server_accept_pt callback function.
 * this function will be invoked when a QUIC connection is refused by xquic due to security
 * considerations, applications SHALL link the connection's lifetime between itself and xquic, and
 * free the context if it was created during xqc_server_accept_pt.
 *
 * @param user_data the user_data parameter of connection
 */
typedef void (*xqc_server_refuse_pt)(xqc_engine_t *engine, xqc_connection_t *conn,
    const xqc_cid_t *cid, void *user_data);

/**
 * @brief engine can't find connection related to input udp packet, and return a STATELESS_RESET
 * packet, implementations shall send this buffer back to peer. this callback function is almost the
 * same with xqc_socket_write_pt, but with different user_data definition.
 *
 * @param user_data user_data related to connection, originated from the user_data parameter of
 * xqc_engine_packet_process
 */
typedef ssize_t (*xqc_stateless_reset_pt)(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    const struct sockaddr *local_addr, socklen_t local_addrlen,
    void *user_data);

/**
 * @brief connection closing notify callback function. will be triggered when a
 * connection is not available and will not send/receive data any more. this 
 * callback is helpful to avoid attempts to send data on a closing connection.
 * NOTICE: this callback function will be triggered at the beginning of
 * connection close, while the conn_close_notify will be triggered at the end of
 * connection close.
 * 
 * @param conn pointer of connection
 * @param cid connection id
 * @param err_code the reason of connection close
 * @param conn_user_data the user_data which will be used in callback functions
 * between xquic transport connection and application
 */
typedef xqc_int_t (*xqc_conn_closing_notify_pt)(xqc_connection_t *conn,
    const xqc_cid_t *cid, xqc_int_t err_code, void *conn_user_data);


/**
 * @brief general callback function definition for connection create and close
 * 
 * @param conn_user_data the user_data which will be used in callback functions
 * between xquic transport connection and application
 * @param conn_proto_data the user_data which will be used in callback functions
 * between xquic transport connection and application-layer-protocol
 */
typedef int (*xqc_conn_notify_pt)(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *conn_user_data, void *conn_proto_data);

/**
 * @brief QUIC connection token callback. REQUIRED for client.
 * token is used by the server to validate client's address during the handshake period of next
 * connection to the same server. client applications shall save token to local storage, if
 * need to connect the same server, read the token and take it as the parameter of xqc_connect.
 *
 * NOTICE: as client initiate multiple connections to multiple QUIC servers or server clusters,
 * it shall save the tokens separately, e.g. save the token with the domain as the key
 */
typedef void (*xqc_save_token_pt)(const unsigned char *token, uint32_t token_len,
    void *conn_user_data);

/**
 * @brief general type of session ticket and transport parameter callback function
 */
typedef void (*xqc_save_string_pt)(const char *data, size_t data_len, void *conn_user_data);

/**
 * @brief session ticket callback function
 *
 * session ticket is essential for 0-RTT connections. with the same storage requirements and
 * strategy as token. when initiating a new connection, session ticket is part of
 * xqc_conn_ssl_config_t parameter
 */
typedef xqc_save_string_pt xqc_save_session_pt;

/**
 * @brief transport parameters callback
 *
 * transport parameters are use when initiating 0-RTT connections to avoid violating the server's
 * restriction, it shall be remembered with the same storage requirements and strategy as token.
 * When initiating a new connection, transport parameters is part of xqc_conn_ssl_config_t parameter
 */
typedef xqc_save_string_pt xqc_save_trans_param_pt;


/**
 * @brief handshake finished callback function
 *
 * this will be trigger when the QUIC connection handshake is completed, that is, when the TLS
 * stack has both sent a Finished message and verified the peer's Finished message
 */
typedef void (*xqc_handshake_finished_pt)(xqc_connection_t *conn, void *conn_user_data,
    void *conn_proto_data);

/**
 * @brief PING acked callback function.
 *
 * if application send a PING frame with xqc_conn_send_ping function, this callback function will be
 * triggered when this PING frame is acked by peer. noticing that PING frame do not need repair, it
 * might not be triggered if PING frame is lost or ACK frame is lost.
 * xquic might send PING frames  will not trigger this callback
 */
typedef void (*xqc_conn_ping_ack_notify_pt)(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *ping_user_data, void *conn_user_data, void *conn_proto_data);

/**
 * @brief cid update callback function.
 *
 * this function will be trigger after receive peer's RETIRE_CONNECTION_ID frame and the SCID of
 * endpoint is changed. cid change might be essential if load balance or some other mechanism
 * related with cid is introduced, applications shall update the CID after the callback is triggered
 *
 * @param conn connection handler
 * @param retire_cid cid that was retired by peer
 * @param new_cid cid that would be used
 * @param conn_user_data connection level user_data
 */
typedef void (*xqc_conn_update_cid_notify_pt)(xqc_connection_t *conn, const xqc_cid_t *retire_cid,
    const xqc_cid_t *new_cid, void *conn_user_data);

/**
 * @brief client certificate verify callback
 *
 * @param certs[] X509 certificates in DER format
 * @param cert_len[] lengths of X509 certificates in DER format
 * @return 0 for success, -1 for verify failed and xquic will close the connection
 */
typedef int (*xqc_cert_verify_pt)(const unsigned char *certs[], const size_t cert_len[],
    size_t certs_len, void *conn_user_data);


/**
 * @brief server peer addr changed notify
 *
 * this function will be trigger after receive peer's changed addr.
 *
 * @param conn connection handler
 * @param conn_user_data connection level user_data
 */
typedef void (*xqc_conn_peer_addr_changed_nofity_pt)(xqc_connection_t *conn, void *conn_user_data);


/**
 * @brief server peer addr changed notify
 *
 * this function will be trigger after receive peer's changed addr.
 *
 * @param conn connection handler
 * @param path_id id of path
 * @param conn_user_data connection level user_data
 */
typedef void (*xqc_path_peer_addr_changed_nofity_pt)(xqc_connection_t *conn, uint64_t path_id, void *conn_user_data);


/**
 * @brief return value of xqc_socket_write_pt and xqc_send_mmsg_pt callback function
 */
#define XQC_SOCKET_ERROR                -1
#define XQC_SOCKET_EAGAIN               -2

/**
 * @brief writing data callback function
 *
 * @param buf  packet buffer
 * @param size  packet size
 * @param peer_addr  peer address
 * @param peer_addrlen  peer address length
 * @param conn_user_data user_data of connection
 * @return bytes of data which is successfully sent:
 * XQC_SOCKET_ERROR for error, xquic will destroy the connection
 * XQC_SOCKET_EAGAIN for EAGAIN, application could continue sending data with xqc_conn_continue_send
 * function when socket write event is ready
 */
typedef ssize_t (*xqc_socket_write_pt)(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data);

/**
 * @brief sendmmsg callback function. the implementation of this shall send data with sendmmsg
 *
 * @param msg_iov message vector
 * @param vlen vector of messages
 * @param peer_addr address of peer
 * @param peer_addrlen  length of peer_addr param
 * @param conn_user_data user_data of connection
 * @return count of messages that are successfully sent:
 * XQC_SOCKET_ERROR for error, xquic will destroy the connection
 * XQC_SOCKET_EAGAIN for EAGAIN, application could continue sending data with xqc_conn_continue_send
 * function when socket write event is ready
 * Warning: server's user_data is what passed in xqc_engine_packet_process when send a stateless
 * reset packet, as xquic can't find a connection
 */
typedef ssize_t (*xqc_send_mmsg_pt)(const struct iovec *msg_iov, unsigned int vlen,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data);


/**
 * @brief set data callback mode for a transport connection. this mode differs
 * from write_socket, which has a different user_data, once this callback
 * function is set, write_socket will be not functional until it is unset.
 *
 * @param buf packet buffer
 * @param size packet size
 * @param peer_addr peer address
 * @param peer_addrlen peer address length
 * @param cb_user_data user_data of xqc_conn_pkt_filter_callback_pt
 */
typedef ssize_t (*xqc_conn_pkt_filter_callback_pt)(const unsigned char *buf,
    size_t size, const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    void *cb_user_data);


/**
 * @brief multi-path ready callback function
 *
 * this callback function will be triggered when a new connection id is received and endpoint
 * get unused cids. it's a precondition of multi-path
 *
 * @param scid source connection id of endpoint
 * @param conn_user_data user_data of connection
 */
typedef void (*xqc_conn_ready_to_create_path_notify_pt)(const xqc_cid_t *scid,
    void *conn_user_data);

/**
 * @brief get chain certs and key by sin
 */
typedef xqc_int_t (*xqc_conn_cert_cb_pt)(const char *sni,
    void **chain, void **crt, void **key, void *user_data);

/**
 * @brief multi-path create callback function
 *
 * @param conn connection handler
 * @param scid source connection id of endpoint
 * @param path_id id of path
 * @param conn_user_data user_data of connection
 */
typedef int (*xqc_path_created_notify_pt)(xqc_connection_t *conn,
    const xqc_cid_t *scid, uint64_t path_id, void *conn_user_data);

/**
 * @brief multi-path remove path callback function.
 *
 * this callback function will be triggered when path is closing
 * and then the application-layer can release related resource.
 *
 * @param scid source connection id of endpoint
 * @param path_id id of path
 * @param conn_user_data user_data of connection
 */
typedef void (*xqc_path_removed_notify_pt)(const xqc_cid_t *scid, uint64_t path_id,
    void *conn_user_data);

typedef enum {
    XQC_PATH_DEGRADE,
    XQC_PATH_RECOVERY,
} xqc_path_status_change_type_t;


/**
 * @brief multi-path write socket callback function
 *
 * @param path_id path identifier
 * @param conn_user_data user_data of connection
 * @param buf packet buffer
 * @param size packet size
 * @param peer_addr peer address
 * @param peer_addrlen peer address length
 * @param conn_user_data user_data of connection
 * @return bytes of data which is successfully sent to socket:
 * XQC_SOCKET_ERROR for error, xquic will destroy the connection
 * XQC_SOCKET_EAGAIN for EAGAIN, we should call xqc_conn_continue_send when socket is ready to write
 * Warning: server's user_data is what passed in xqc_engine_packet_process when send a reset packet
 */
typedef ssize_t (*xqc_socket_write_ex_pt)(uint64_t path_id,
    const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    void *conn_user_data);

/**
 * @brief multi-path write socket callback function with sendmmsg
 *
 * @param path_id path identifier
 * @param msg_iov vector of messages
 * @param vlen count of messages
 * @param peer_addr peer address
 * @param peer_addrlen peer address length
 * @param conn_user_data user_data of connection, which was the parameter of xqc_connect set by
 * client, or the parameter of xqc_conn_set_transport_user_data set by server
 * @return bytes of data which is successfully sent to socket:
 * XQC_SOCKET_ERROR for error, xquic will destroy the connection
 * XQC_SOCKET_EAGAIN for EAGAIN, we should call xqc_conn_continue_send when socket is ready to write
 * Warning: server's user_data is what passed in xqc_engine_packet_process when send a reset packet
 */
typedef ssize_t (*xqc_send_mmsg_ex_pt)(uint64_t path_id,
    const struct iovec *msg_iov, unsigned int vlen,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    void *conn_user_data);


/**
 * @brief general callback function definition for stream create, close, read and write.
 *
 * @param stream QUIC stream handler
 * @param strm_user_data stream level user_data, which was the parameter of xqc_stream_create set by
 * client, or the parameter of xqc_stream_set_user_data set by server
 * @return 0 for success, -1 for failure
 */
typedef xqc_int_t (*xqc_stream_notify_pt)(xqc_stream_t *stream,
    void *strm_user_data);

/**
 * @brief stream closing callback function, this will be triggered when some
 * error on a stream happens.
 *
 * @param stream QUIC stream handler
 * @param err_code error code
 * @param strm_user_data stream level user_data, which was the parameter of xqc_stream_create set by
 * client, or the parameter of xqc_stream_set_user_data set by server
 * @return 0 for success, -1 for failure
 */
typedef void (*xqc_stream_closing_notify_pt)(xqc_stream_t *stream,
    xqc_int_t err_code, void *strm_user_data);

/**
 * @brief the callback API to notify application that there is a datagram to be read
 *
 * @param conn the connection handle
 * @param user_data the dgram_data set by xqc_datagram_set_user_data
 * @param data the data delivered by this callback
 * @param data_len the length of the delivered data
 * @param dgram_recv_ts the unix timestamp when the datagram is received from socket
 */
typedef void (*xqc_datagram_read_notify_pt)(xqc_connection_t *conn,
    void *user_data, const void *data, size_t data_len, uint64_t unix_ts);

/**
 * @brief the callback API to notify application that datagrams can be sent
 *
 * @param conn the connection handle
 * @param user_data the dgram_data set by xqc_datagram_set_user_data
 */
typedef void (*xqc_datagram_write_notify_pt)(xqc_connection_t *conn,
    void *user_data);

/**
 * @brief the callback API to notify application that a datagram is declared lost.
 * However, the datagram could also be acknowledged later, as the underlying
 * loss detection is not fully accurate. Applications should handle this type of
 * spurious loss. The return value indicates how this lost datagram is 
 * handled by the QUIC stack. NOTE, if the QUIC stack replicates the datagram 
 * (e.g. reinjection or retransmission), this callback can be triggered 
 * multiple times for a dgram_id. 
 * 
 * @param conn the connection handle
 * @param user_data the dgram_data set by xqc_datagram_set_user_data
 * @param dgram_id the id of the lost datagram
 * @return 0: the stack will not retransmit the packet; 
 *         XQC_DGRAM_RETX_ASKED_BY_APP (1): the stack will retransmit the packet;
 *         others are ignored by the QUIC stack.
 */
typedef xqc_int_t (*xqc_datagram_lost_notify_pt)(xqc_connection_t *conn,
    uint64_t dgram_id, void *user_data);

/**
 * @brief the callback API to notify application that a datagram is acked. Note,
 *        for every unique dgram_id, this callback will be only called once.
 * 
 * @param conn the connection handle
 * @param user_data the dgram_data set by xqc_datagram_set_user_data
 * @param dgram_id the id of the acked datagram
 */
typedef void (*xqc_datagram_acked_notify_pt)(xqc_connection_t *conn,
    uint64_t dgram_id, void *user_data);


/**
 * @brief the callback to notify application the MSS of QUIC datagrams. Note, 
 *        the MSS of QUIC datagrams will never shrink. If the MSS is zero, it 
 *        means this connection does not support sending QUIC datagrams.
 * 
 * @param conn the connection handle
 * @param user_data the dgram_data set by xqc_datagram_set_user_data
 * @param mss the MSS of QUIC datagrams
 */
typedef void (*xqc_datagram_mss_updated_notify_pt)(xqc_connection_t *conn,
    size_t mss, void *user_data);


/**
 * @brief callback functions which are more related to attributes of QUIC [Transport] but not ALPN.
 * In another word, these callback functions are events of QUIC Transport layer, and need to
 * interact with application-layer, which have less thing to do with ALPN layer.
 *
 * These callback functions shall directly call back to application layer, with user_data from
 * struct xqc_connection_t. unless Application-Layer-Protocol take over them.
 *
 * Generally, xquic defines callbacks as below:
 * 1. Callbacks between Transport and Application:
 * QUIC events that are common between different Application Protocols,
 * and is much more convenient to interact with Application and Application Protocol.
 *
 * 2. Callbacks between Application Protocol and Application:
 * Application-Protocol events will interact with Application Layer. these callback functions are
 * defined by Application Protocol Layers.
 *
 * 3. Callbacks between Transport and Application Protocol:
 * QUIC events that might be more essential to Application-Layer-Protocols, especially stream data
 *
 * +------------------------------------------------------------------------------+
 * |                             Application                                      |
 * |                                 +-- Application Protocol defined callbacks --+
 * |                                 |             Application Protocol           |
 * +-------- transport callbacks ----+--------- app protocol callbacks -----------+
 * |                              Transport                                       |
 * +------------------------------------------------------------------------------+
 */
typedef struct xqc_transport_callbacks_s {
    /**
     * accept new connection callback. REQUIRED only for server
     * NOTICE: this is the headmost callback trigger by xquic, the user_data of server_accept is
     * what was passed into xqc_engine_packet_process
     */
    xqc_server_accept_pt            server_accept;

    /**
     * connection refused by xquic. REQUIRED only for server
     */
    xqc_server_refuse_pt            server_refuse;

    /* stateless reset callback */
    xqc_stateless_reset_pt          stateless_reset;

    /**
     * write socket callback, ALTERNATIVE with write_mmsg
     */
    xqc_socket_write_pt             write_socket;

    /**
     * write socket with send_mmsg callback, ALTERNATIVE with write_socket
     */
    xqc_send_mmsg_pt                write_mmsg;

    /**
     * write socket callback, ALTERNATIVE with write_mmsg
     */
    xqc_socket_write_ex_pt          write_socket_ex;

    /**
     * write socket with send_mmsg callback, ALTERNATIVE with write_socket
     */
    xqc_send_mmsg_ex_pt             write_mmsg_ex;

    /**
     * QUIC connection cid update callback, REQUIRED for both server and client
     */
    xqc_conn_update_cid_notify_pt   conn_update_cid_notify;

    /**
     * QUIC token callback. REQUIRED for client
     */
    xqc_save_token_pt               save_token;

    /**
     * tls session ticket callback. REQUIRED for client
     */
    xqc_save_session_pt             save_session_cb;

    /**
     * QUIC transport parameter callback. REQUIRED for client
     */
    xqc_save_trans_param_pt         save_tp_cb;

    /**
     * tls certificate verify callback. REQUIRED for client
     */
    xqc_cert_verify_pt              cert_verify_cb;

    /**
     * multi-path available callback. REQUIRED for client if multi-path is needed
     */
    xqc_conn_ready_to_create_path_notify_pt ready_to_create_path_notify;

    /**
     * path create callback function. REQUIRED for server if multi-path is needed
     */
    xqc_path_created_notify_pt      path_created_notify;

    /**
     * path remove callback function. REQUIRED both for client and server if multi-path is needed
     */
    xqc_path_removed_notify_pt      path_removed_notify;

    /**
     * connection closing callback function. OPTIONAL for both client and server
     */
    xqc_conn_closing_notify_pt      conn_closing;

    /**
     * QUIC connection peer addr changed callback, REQUIRED for server.
     */
    xqc_conn_peer_addr_changed_nofity_pt    conn_peer_addr_changed_notify;

    /**
     * QUIC path peer addr changed callback, REQUIRED for server.
     */
    xqc_path_peer_addr_changed_nofity_pt    path_peer_addr_changed_notify;

    /**
     * @brief cert callback
     */
    xqc_conn_cert_cb_pt                     conn_cert_cb;

} xqc_transport_callbacks_t;


/**
 * @brief QUIC connection callback functions for Application-layer-Protocol.
 */
typedef struct xqc_conn_callbacks_s {

    /**
     * connection create notify callback. REQUIRED for server, OPTIONAL for client.
     *
     * this function will be invoked after connection is created, user can create application layer
     * context in this callback function
     *
     * return 0 for success, -1 for failure, e.g. malloc error, on which xquic will close connection
     */
    xqc_conn_notify_pt                  conn_create_notify;

    /**
     * connection close notify. REQUIRED for both client and server
     *
     * this function will be invoked after QUIC connection is closed. user can free application
     * level context created in conn_create_notify callback function
     */
    xqc_conn_notify_pt                  conn_close_notify;

    /**
     * handshake complete callback. OPTIONAL for client and server
     */
    xqc_handshake_finished_pt           conn_handshake_finished;

    /**
     * active PING acked callback. OPTIONAL for both client and server
     */
    xqc_conn_ping_ack_notify_pt         conn_ping_acked;

} xqc_conn_callbacks_t;


/* QUIC layer stream callback functions */
typedef struct xqc_stream_callbacks_s {
    /**
     * stream read callback function. REQUIRED for both client and server
     *
     * this will be triggered when QUIC stream data is ready for read. application layer could read
     * data when xqc_stream_recv interface.
     */
    xqc_stream_notify_pt            stream_read_notify;

    /**
     * stream write callback function. REQUIRED for both client and server
     *
     * when sending data with xqc_stream_send, xquic might be blocked or send part of the data. if
     * this callback function is triggered, applications can continue to send the rest data.
     */
    xqc_stream_notify_pt            stream_write_notify;

    /**
     * stream create callback function. REQUIRED for server, OPTIONAL for client.
     *
     * this will be triggered when QUIC stream is created. applications can create its own stream
     * context in this callback function.
     */
    xqc_stream_notify_pt            stream_create_notify;

    /**
     * stream close callback function. REQUIRED for both server and client.
     *
     * this will be triggered when QUIC stream is finally closed. xquic will close stream after
     * sending or receiving RESET_STREAM frame after 3 times of PTO, or when connection is closed.
     * Applications can free the context which was created in stream_create_notify here.
     */
    xqc_stream_notify_pt            stream_close_notify;

    /**
     * @brief stream reset callback function. OPTIONAL for both server and client
     * 
     * this function will be triggered when a RESET_STREAM frame is received.
     */
    xqc_stream_closing_notify_pt    stream_closing_notify;

} xqc_stream_callbacks_t;

/* QUIC layer datagram callback functions */
typedef struct xqc_datagram_callbacks_s {
    /**
     * datagram read callback function. REQUIRED for both client and server if they want to use datagram
     *
     * this will be triggered when a QUIC datagram is received. application layer could read
     * data from the arguments of this callback.
     */
    xqc_datagram_read_notify_pt         datagram_read_notify;

    /**
     * datagram write callback function. REQUIRED for both client and server if they want to use datagram
     *
     * when sending data with xqc_datagram_send or xqc_datagram_send_multiple, xquic might be blocked or send part of the data. if
     * this callback function is triggered, applications can continue to send the rest data.
     */
    xqc_datagram_write_notify_pt        datagram_write_notify;

    /**
     * datagram acked callback function. OPTIONAL for server and client.
     *
     * this will be triggered when a QUIC packet containing a DATAGRAM frame is acked. 
     */
    xqc_datagram_acked_notify_pt        datagram_acked_notify;

    /**
     * datagram lost callback function. OPTIONAL for server and client.
     *
     * this will be triggered when a QUIC packet containing a DATAGRAM frame is lost. 
     */
    xqc_datagram_lost_notify_pt         datagram_lost_notify;

    xqc_datagram_mss_updated_notify_pt  datagram_mss_updated_notify;

} xqc_datagram_callbacks_t;


/**
 * @brief connection and stream callbacks for QUIC level, Application-Layer-Protocol shall implement
 * these callback functions and register ALP with xqc_engine_register_alpn
 */
typedef struct xqc_app_proto_callbacks_s {

    /* QUIC connection callback functions for Application-Layer-Protocol */
    xqc_conn_callbacks_t        conn_cbs;

    /* QUIC stream callback functions */
    xqc_stream_callbacks_t      stream_cbs;

    /* QUIC datagram callback functions */
    xqc_datagram_callbacks_t    dgram_cbs;

} xqc_app_proto_callbacks_t;

typedef enum {
    XQC_DATA_QOS_HIGHEST = 1,
    XQC_DATA_QOS_HIGH	 = 2,
    XQC_DATA_QOS_MEDIUM  = 3,
    XQC_DATA_QOS_NORMAL  = 4,
    XQC_DATA_QOS_LOW     = 5,
    XQC_DATA_QOS_LOWEST  = 6,
    XQC_DATA_QOS_PROBING = 7,
} xqc_data_qos_level_t;

typedef struct xqc_cc_params_s {
    uint32_t    customize_on;
    uint32_t    init_cwnd;
    uint32_t    min_cwnd;
    uint32_t    expect_bw;
    uint32_t    max_expect_bw;
    uint8_t     bbr_enable_lt_bw;
    uint32_t    cc_optimization_flags;
    /* 0 < delta <= delta_max, default 0.05, ->0 = more throughput-oriented */
    double      copa_delta_base; 
    /* 0 < delta_max <= 1.0, default 0.5 */
    double      copa_delta_max;
    /* 
     * 1.0 <= delta_ai_unit, default 1.0, greater values mean more aggressive
     * when Copa competes with loss-based CCAs.
     */
    double      copa_delta_ai_unit;
} xqc_cc_params_t;

typedef struct xqc_scheduler_params_u {
    uint64_t    rtt_us_thr_high;
    uint64_t    rtt_us_thr_low;
    uint64_t    bw_Bps_thr;
    double      loss_percent_thr_high;
    double      loss_percent_thr_low;
    uint32_t    pto_cnt_thr;
} xqc_scheduler_params_t;

typedef enum {
    XQC_REED_SOLOMON_CODE  = 8,
    XQC_XOR_CODE = 11, /* 测试用，没有在IANA登记过*/
    XQC_PACKET_MASK = 12,
} xqc_fec_schemes_e;

typedef struct xqc_fec_params_s {
    float                   fec_code_rate;                                  /* code rate represents the source symbol percents in total symbols */
    xqc_int_t               fec_ele_bit_size;                               /* element bit size of current fec finite filed */
    uint64_t                fec_protected_frames;                           /* frame type that should be protected by fec */
    uint64_t                fec_max_window_size;                            /* maximum number of block that current host can store */
    uint64_t                fec_max_symbol_size;                            /* (E) maximum symbol size of each symbol */
    uint64_t                fec_max_symbol_num_per_block;                   /* (B) maximum symbol number of each block */
    
    xqc_int_t               fec_encoder_schemes_num;
    xqc_int_t               fec_decoder_schemes_num;
    xqc_fec_schemes_e       fec_encoder_schemes[XQC_FEC_MAX_SCHEME_NUM];    /* fec schemes supported by current host as encoder */
    xqc_fec_schemes_e       fec_decoder_schemes[XQC_FEC_MAX_SCHEME_NUM];    /* fec schemes supported by current host as decoder */

    xqc_int_t               fec_encoder_scheme;                             /* final fec scheme as encoder after negotiation */
    xqc_int_t               fec_decoder_scheme;                             /* final fec scheme as decoder after negotiation */
} xqc_fec_params_t;

typedef struct xqc_congestion_control_callback_s {
    /* Callback on initialization, for memory allocation */
    size_t (*xqc_cong_ctl_size)(void);

    /* Callback on connection initialization, support for passing in congestion algorithm parameters */
    void (*xqc_cong_ctl_init)(void *cong_ctl, xqc_send_ctl_t *ctl_ctx, xqc_cc_params_t cc_params);

    /* Callback when packet loss is detected, reduce congestion window according to algorithm */
    void (*xqc_cong_ctl_on_lost)(void *cong_ctl, xqc_usec_t lost_sent_time);

    /* Callback when packet acked, increase congestion window according to algorithm */
    void (*xqc_cong_ctl_on_ack)(void *cong_ctl, xqc_packet_out_t *po, xqc_usec_t now);

    /* Callback when sending a packet, to determine if the packet can be sent */
    uint64_t (*xqc_cong_ctl_get_cwnd)(void *cong_ctl);

    /* Callback when all packets are detected as lost within 1-RTT, reset the congestion window */
    void (*xqc_cong_ctl_reset_cwnd)(void *cong_ctl);

    /* If the connection is in slow start state */
    int (*xqc_cong_ctl_in_slow_start)(void *cong_ctl);

    /* If the connection is in recovery state. */
    int (*xqc_cong_ctl_in_recovery)(void *cong_ctl);

    /* This function is used by BBR and Cubic*/
    void (*xqc_cong_ctl_restart_from_idle)(void *cong_ctl, uint64_t arg);

    /* For BBR */
    void (*xqc_cong_ctl_on_ack_multiple_pkts)(void *cong_ctl, xqc_sample_t *sampler);

    /* initialize bbr */
    void (*xqc_cong_ctl_init_bbr)(void *cong_ctl, xqc_sample_t *sampler, xqc_cc_params_t cc_params);

    /* get pacing rate */
    uint32_t (*xqc_cong_ctl_get_pacing_rate)(void *cong_ctl);

    /* get estimation of bandwidth */
    uint32_t (*xqc_cong_ctl_get_bandwidth_estimate)(void *cong_ctl);

    xqc_bbr_info_interface_t *xqc_cong_ctl_info_cb;
} xqc_cong_ctrl_callback_t;

#ifdef XQC_ENABLE_RENO
XQC_EXPORT_PUBLIC_API XQC_EXTERN const xqc_cong_ctrl_callback_t xqc_reno_cb;
#endif
#ifdef XQC_ENABLE_BBR2
XQC_EXPORT_PUBLIC_API XQC_EXTERN const xqc_cong_ctrl_callback_t xqc_bbr2_cb;
#endif
XQC_EXPORT_PUBLIC_API XQC_EXTERN const xqc_cong_ctrl_callback_t xqc_bbr_cb;
XQC_EXPORT_PUBLIC_API XQC_EXTERN const xqc_cong_ctrl_callback_t xqc_cubic_cb;
#ifdef XQC_ENABLE_UNLIMITED
XQC_EXPORT_PUBLIC_API XQC_EXTERN const xqc_cong_ctrl_callback_t xqc_unlimited_cc_cb;
#endif
#ifdef XQC_ENABLE_COPA
XQC_EXPORT_PUBLIC_API XQC_EXTERN const xqc_cong_ctrl_callback_t xqc_copa_cb;
#endif

typedef enum xqc_scheduler_path_event_e {
    XQC_SCHED_EVENT_PATH_NOT_FULL = 0,
} xqc_scheduler_path_event_t;

typedef enum xqc_scheduler_conn_event_e {
    XQC_SCHED_EVENT_CONN_ROUND_START = 0,
    XQC_SCHED_EVENT_CONN_ROUND_FIN   = 1,
} xqc_scheduler_conn_event_t;

typedef struct xqc_scheduler_callback_s {

    size_t (*xqc_scheduler_size)(void);

    void (*xqc_scheduler_init)(void *scheduler, xqc_log_t *log, xqc_scheduler_params_t *params);

    xqc_path_ctx_t * (*xqc_scheduler_get_path)(void *scheduler,
        xqc_connection_t *conn, xqc_packet_out_t *packet_out,
        int check_cwnd, int reinject, xqc_bool_t *cc_blocked);

    void (*xqc_scheduler_handle_path_event)(void *scheduler, 
        xqc_path_ctx_t *path, xqc_scheduler_path_event_t event, void *event_arg);

    void (*xqc_scheduler_handle_conn_event)(void *scheduler, 
        xqc_connection_t *conn, xqc_scheduler_conn_event_t event, void *event_arg);

} xqc_scheduler_callback_t;

XQC_EXPORT_PUBLIC_API XQC_EXTERN const xqc_scheduler_callback_t xqc_minrtt_scheduler_cb;
XQC_EXPORT_PUBLIC_API XQC_EXTERN const xqc_scheduler_callback_t xqc_backup_scheduler_cb;
XQC_EXPORT_PUBLIC_API XQC_EXTERN const xqc_scheduler_callback_t xqc_rap_scheduler_cb;
#ifdef XQC_ENABLE_MP_INTEROP
XQC_EXPORT_PUBLIC_API XQC_EXTERN const xqc_scheduler_callback_t xqc_interop_scheduler_cb;
#endif

typedef enum {
    XQC_REINJ_UNACK_AFTER_SCHED   = 1 << 0,
    XQC_REINJ_UNACK_BEFORE_SCHED  = 1 << 1,
    XQC_REINJ_UNACK_AFTER_SEND    = 1 << 2,
} xqc_reinjection_mode_t;

typedef struct xqc_reinj_ctl_callback_s {

    size_t (*xqc_reinj_ctl_size)(void);

    void (*xqc_reinj_ctl_init)(void *reinj_ctl, xqc_connection_t *conn);

    void (*xqc_reinj_ctl_update)(void *reinj_ctl, void *qoe_info);

    void (*xqc_reinj_ctl_reset)(void *reinj_ctl, void *qoe_info);

    xqc_bool_t (*xqc_reinj_ctl_can_reinject)(void *reinj_ctl, xqc_packet_out_t *po, xqc_reinjection_mode_t mode);

} xqc_reinj_ctl_callback_t;

XQC_EXPORT_PUBLIC_API XQC_EXTERN const xqc_reinj_ctl_callback_t xqc_default_reinj_ctl_cb;
XQC_EXPORT_PUBLIC_API XQC_EXTERN const xqc_reinj_ctl_callback_t xqc_deadline_reinj_ctl_cb;
XQC_EXPORT_PUBLIC_API XQC_EXTERN const xqc_reinj_ctl_callback_t xqc_dgram_reinj_ctl_cb;

typedef struct xqc_fec_code_callback_s {
    void (*xqc_fec_init)(xqc_connection_t *conn);
    xqc_int_t (*xqc_fec_encode)(xqc_connection_t *conn, unsigned char *unit_data, unsigned char **outputs);
    xqc_int_t (*xqc_fec_decode)(xqc_connection_t *conn, unsigned char **recovered_symbols_buff, xqc_int_t block_idx,
                                xqc_int_t *loss_symbols_idx, xqc_int_t loss_symbols_len);
} xqc_fec_code_callback_t;

XQC_EXPORT_PUBLIC_API extern const xqc_fec_code_callback_t xqc_xor_code_cb;
XQC_EXPORT_PUBLIC_API extern const xqc_fec_code_callback_t xqc_reed_solomon_code_cb;

/**
 * @struct xqc_config_t
 * QUIC config parameters
 */
typedef struct xqc_config_s {
    /* log level */
    xqc_log_level_t cfg_log_level;

    /* enable log based on event or not, non-zero for enable, 0 for not */
    xqc_flag_t      cfg_log_event;

    /* qlog evnet importance */
    qlog_event_importance_t cfg_qlog_importance;

    /* print timestamp in log or not, non-zero for print, 0 for not */
    xqc_flag_t      cfg_log_timestamp;

    /* print level name in log or not, non-zero for print, 0 for not */
    xqc_flag_t      cfg_log_level_name;

    /* connection memory pool size, which will be used for congestion control */
    size_t          conn_pool_size;

    /* bucket size of stream hash table in xqc_connection_t */
    size_t          streams_hash_bucket_size;

    /* bucket size of connection hash table in engine */
    size_t          conns_hash_bucket_size;

    /* capacity of connection priority queue in engine */
    size_t          conns_active_pq_capacity;

    /* capacity of wakeup connection priority queue in engine */
    size_t          conns_wakeup_pq_capacity;

    /* supported quic version list, actually draft-29 and quic-v1 is supported */
    uint32_t        support_version_list[XQC_SUPPORT_VERSION_MAX];

    /* supported quic version count */
    uint32_t        support_version_count;

    /* default connection id length */
    uint8_t         cid_len;

    /**
     * only for server, whether server will negotiate cid with client. non-zero for negotiate and 0
     * for not. when enable, server will not reuse client's original DCID, and generate its own cid.
     *
     * NOTICE: if length of client's original DCID is not equal to cid_len, server will always
     * generate its own cid, despite of the enable of cid negotiation.
     */
    uint8_t         cid_negotiate;

    /* used to generate stateless reset token */
    char            reset_token_key[XQC_RESET_TOKEN_MAX_KEY_LEN];
    size_t          reset_token_keylen;

    /**
     * sendmmsg switch. non-zero for enable, 0 for disable.
     * if enabled, xquic will try to use write_mmsg callback function instead of write_socket.
     *
     * NOTICE: if sendmmsg is enabled, xquic will check write_mmsg callback function when creating
     * engine. if write_mmsg is NULL and sendmmsg_on is non-zero, xqc_engine_create will fail
     */
    int             sendmmsg_on;

    /**
     * @brief enable h3 ext (default: 0)
     * 
     */
    uint8_t         enable_h3_ext;

    /**
     * @brief disable or enable logging (default: 0, enable)
     * 
     */
    xqc_bool_t      log_disable;
} xqc_config_t;


/**
 * @brief engine callback functions.
 */
typedef struct xqc_engine_callback_s {
    /* timer callback for event loop */
    xqc_set_event_timer_pt          set_event_timer;

    /* write log file callback, REQUIRED */
    xqc_log_callbacks_t             log_callbacks;

    /* custom cid generator, OPTIONAL for server */
    xqc_cid_generate_pt             cid_generate_cb;

    /* tls secret callback, OPTIONAL */
    xqc_eng_keylog_pt               keylog_cb;

    /* get realtime timestamp callback function. if not set, xquic will get timestamp with inner
       function xqc_now, which relies on gettimeofday */
    xqc_timestamp_pt                realtime_ts;

    /* get monotonic increasing timestamp callback function. if not set, xquic will get timestamp
       with inner function xqc_now, which relies on gettimeofday */
    xqc_timestamp_pt                monotonic_ts;

} xqc_engine_callback_t;


typedef struct xqc_engine_ssl_config_s {
    char       *private_key_file;           /* For server */
    char       *cert_file;                  /* For server */
    char       *ciphers;
    char       *groups;

    uint32_t    session_timeout;            /* Session lifetime in second */
    char       *session_ticket_key_data;    /* For server */
    size_t      session_ticket_key_len;     /* For server */

} xqc_engine_ssl_config_t;



typedef enum {
    XQC_TLS_CERT_FLAG_NEED_VERIFY        = 1 << 0,
    XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED  = 1 << 1,
} xqc_cert_verify_flag_e;

typedef enum {
    XQC_RED_NOT_USE             = 0,
    XQC_RED_SET_CLOSE           = 1,
} xqc_dgram_red_setting_e;

/**
 * @brief connection tls config for client
 */
typedef struct xqc_conn_ssl_config_s {
    /**
     * session ticket data buffer.
     *
     * session ticket is read from client's local storage, which is from save_session_cb callback
     * and was stored after previous successful connection to a server
     */
    char       *session_ticket_data;

    /**
     * length of session_ticket_data
     */
    size_t      session_ticket_len;

    /**
     * server's transport parameter, derived as well as session_ticket_data
     */
    char       *transport_parameter_data;

    /**
     * length of transport_parameter_data
     */
    size_t      transport_parameter_data_len;

    /**
     * certificate verify flag. which is a bit-map flag defined in xqc_cert_verify_flag_e
     */
    uint8_t     cert_verify_flag;
} xqc_conn_ssl_config_t;

typedef struct xqc_linger_s {
    uint32_t                    linger_on;          /* close connection after all data sent and acked, default: 0 */
    xqc_usec_t                  linger_timeout;     /* 3*PTO if linger_timeout is 0 */
} xqc_linger_t;

typedef enum {
    XQC_ERR_MULTIPATH_VERSION   = 0x00,
    XQC_MULTIPATH_04            = 0x04,
    XQC_MULTIPATH_05            = 0x05,
    XQC_MULTIPATH_06            = 0x06,
} xqc_multipath_version_t;

typedef enum {
    XQC_ERR_FEC_VERSION         = 0x00,
    XQC_FEC_01                  = 0x01,
} xqc_fec_version_t;

typedef struct xqc_conn_settings_s {
    int                         pacing_on;          /* default: 0 */
    int                         ping_on;            /* client sends PING to keepalive, default:0 */
    xqc_cong_ctrl_callback_t    cong_ctrl_callback; /* default: xqc_cubic_cb */
    xqc_cc_params_t             cc_params;
    uint32_t                    so_sndbuf;          /* socket option SO_SNDBUF, 0 for unlimited */
    uint64_t                    sndq_packets_used_max;  /* 
                                                         * default: XQC_SNDQ_PACKETS_USED_MAX. 
                                                         * It should be set to buffer 2xBDP packets at least for performance consideration. 
                                                         * The default value is 16000 pkts. 
                                                         */
    xqc_linger_t                linger;
    xqc_proto_version_t         proto_version;      /* QUIC protocol version */
    xqc_msec_t                  init_idle_time_out; /* initial idle timeout interval, effective before handshake completion */
    xqc_msec_t                  idle_time_out;      /* idle timeout interval, effective after handshake completion */
    int32_t                     spurious_loss_detect_on;
    uint32_t                    anti_amplification_limit;   /* limit of anti-amplification, default 5 */
    uint64_t                    keyupdate_pkt_threshold;    /* packet limit of a single 1-rtt key, 0 for unlimited */
    size_t                      max_pkt_out_size;

    /*
    * datgram option
    * 0: no support for datagram mode (default)
    * >0: the max size of datagrams that the local end is willing to receive
    * 65535: the local end is willing to receive a datagram with any length as 
    *        long as it fits in a QUIC packet
    */
    uint16_t                    max_datagram_frame_size;
    
    /* 
     * multipath option:
     * https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-05#section-3
     * 0: don't support multipath
     * 1: supports multipath (unified solution) - multiple PN spaces
     */
    uint64_t                    enable_multipath;
    xqc_multipath_version_t     multipath_version;
    uint64_t                    least_available_cid_count;

    /*
     * reinjection option:
     * 0: default, no reinjection
     * bit0 = 1: 
     *    reinject unacked packets after scheduling packets to paths.
     * bit1 = 1: 
     *    reinject unacked packets before scheduling packets to paths.
     * bit2 = 1
     *    reinject unacked packets after sending packets.
     */
    int                         mp_enable_reinjection;
    /*
     * deadline = max(low_bound, min(hard_deadline, srtt * srtt_factor))
     * default values:
     *   low_bound = 0
     *   hard_deadline = INF
     *   srtt_factor = 2.0
     */
    double                      reinj_flexible_deadline_srtt_factor;
    uint64_t                    reinj_hard_deadline;
    uint64_t                    reinj_deadline_lower_bound;

    /*
     * By default, XQUIC returns ACK_MPs on the path where the data 
     * is received unless the path is not avaliable anymore. 
     * 
     * Setting mp_ack_on_any_path to 1 can enable XQUIC to return ACK_MPs on any
     * paths according to the scheduler.
     */
    uint8_t                     mp_ack_on_any_path;

    /*
     * When sending a ping packet for connection keep-alive, we replicate the 
     * the packet on all acitve paths to keep all paths alive (disable:0, enable:1).
     * The default value is 0.
     */
    uint8_t                     mp_ping_on;
    
    /* scheduler callback, default: xqc_minrtt_scheduler_cb */
    xqc_scheduler_callback_t    scheduler_callback;
    xqc_scheduler_params_t      scheduler_params;

    /* reinj_ctl callback, default: xqc_default_reinj_ctl_cb */
    xqc_reinj_ctl_callback_t    reinj_ctl_callback;

    /* ms */
    xqc_msec_t                  standby_path_probe_timeout;

    /* params for performance tuning */
    /* max ack delay: ms */
    uint32_t                    max_ack_delay;
    /* generate an ACK if received ack-eliciting pkts >= ack_frequency */
    uint32_t                    ack_frequency; 
    uint8_t                     adaptive_ack_frequency;
    uint64_t                    loss_detection_pkt_thresh;
    double                      pto_backoff_factor;

    /* datagram redundancy: 0 disable, 1 enable, 2 only enable multipath redundancy */
    uint8_t                     datagram_redundancy;
    uint8_t                     datagram_force_retrans_on;
    uint64_t                    datagram_redundant_probe;

    /* enable PMTUD */
    uint8_t                     enable_pmtud;
    /* probing interval (us), default: 500000 */
    uint64_t                    pmtud_probing_interval; 

    /* enable marking reinjected packets with reserved bits */
    uint8_t                     marking_reinjection;

    /* 
     * The limitation on conn recv rate (only applied to stream data) in bytes per second.
     * NOTE: the minimal rate limitation is (63000/RTT) Bps. For instance, if RTT is 60ms,
     * the minimal valid rate limitation is about 1MBps. Any recv_rate_bytes_per_sec less
     * than the minimal valid rate limitation will not be guaranteed.
     * default: 0 (no limitation).
     */
    uint64_t                    recv_rate_bytes_per_sec;

    /*
     * The switch to enable stream-level recv rate throttling. Default: off (0)
     */
    uint8_t                     enable_stream_rate_limit;

    /*
     * initial recv window. Default: 0 (use the internal default value)
     */
    uint32_t                    init_recv_window;

    /*
     * initial flow control value
     */
    xqc_bool_t                  is_interop_mode;

#ifdef XQC_PROTECT_POOL_MEM
    uint8_t                     protect_pool_mem;
#endif

    char                        conn_option_str[XQC_CO_STR_MAX_LEN];

    /**
     * @brief intial_rtt (us). Default: 0 (use the internal default value -- 250000)
     * 
     */
    xqc_usec_t                  initial_rtt;
    /**
     * @brief initial pto duration (us). Default: 0 (use the internal default value -- 3xinitial_rtt)
     * 
     */
    xqc_usec_t                  initial_pto_duration;
    
    /* 
     * fec option:
     * 0: don't support fec
     * 1: supports fec 
     */
    uint64_t                    enable_encode_fec;
    uint64_t                    enable_decode_fec;
    xqc_fec_params_t            fec_params;
    xqc_fec_code_callback_t     fec_encode_callback;
    xqc_fec_code_callback_t     fec_decode_callback;

    xqc_dgram_red_setting_e     close_dgram_redundancy;

} xqc_conn_settings_t;


typedef enum {
    XQC_0RTT_NONE,      /* without 0-RTT */
    XQC_0RTT_ACCEPT,    /* 0-RTT was accepted */
    XQC_0RTT_REJECT,    /* 0-RTT was rejected */
} xqc_0rtt_flag_t;


#define XQC_MAX_PATHS_COUNT 8
#define XQC_CONN_INFO_LEN 400

typedef struct xqc_path_metrics_s {
    uint64_t            path_id;

    uint64_t            path_pkt_recv_count;
    uint64_t            path_pkt_send_count;

    uint64_t            path_send_bytes;
    uint64_t            path_send_reinject_bytes;

    uint64_t            path_recv_bytes;
    uint64_t            path_recv_reinject_bytes;
    uint64_t            path_recv_effective_bytes;
    uint64_t            path_recv_effective_reinject_bytes;

    uint64_t            path_srtt;
    uint8_t             path_app_status;
} xqc_path_metrics_t;


typedef struct xqc_conn_stats_s {
    uint32_t            send_count;
    uint32_t            lost_count;
    uint32_t            tlp_count;
    uint32_t            spurious_loss_count;
    uint32_t            lost_dgram_count;       /* how many datagram frames (pkts) are lost */
    xqc_usec_t          srtt;                   /* smoothed SRTT at present: initial value = 250000 */
    xqc_usec_t          min_rtt;                /* minimum RTT until now: initial value = 0xFFFFFFFF */
    uint64_t            inflight_bytes;         /* initial value = 0 */
    xqc_0rtt_flag_t     early_data_flag;
    uint32_t            recv_count;
    int                 spurious_loss_detect_on;
    int                 conn_err;
    char                ack_info[50];

    /**
     * @brief enable_multipath: 表示MP参数协商结果
     * 0: 不支持MP
     * 1: 支持MP, 采用 Single PNS
     * 2: 支持MP, 采用 Multiple PNS
     */
    int                 enable_multipath;

    /**
     * @brief 连接级别MP状态
     * 0: 未尝试建立过双路 (create_path_count <= 1)
     * 1: 成功建立起双路，对端验证成功 (create_path_count > 1 && validated_path_count > 1)
     * 2: 尝试建立过双路，但没有探测成功 (create_path_count > 1 && validated_path_count <= 1)
     */
    int                 mp_state;

    int                 total_rebind_count;
    int                 total_rebind_valid;

    xqc_path_metrics_t  paths_info[XQC_MAX_PATHS_COUNT];
    char                conn_info[XQC_CONN_INFO_LEN];

    char                alpn[XQC_MAX_ALPN_BUF_LEN];
} xqc_conn_stats_t;

typedef struct xqc_conn_qos_stats_s {
    xqc_usec_t          srtt;            /* smoothed SRTT at present: initial value = 250000 */
    xqc_usec_t          min_rtt;         /* minimum RTT until now: initial value = 0xFFFFFFFF */
    uint64_t            inflight_bytes;  /* initial value = 0 */
} xqc_conn_qos_stats_t;

/*************************************************************
 *  engine layer APIs
 *************************************************************/

/**
 * @brief Create new xquic engine.
 *
 * @param engine_type  XQC_ENGINE_SERVER or XQC_ENGINE_CLIENT
 * @param engine_config config for basic framework, quic, network, etc.
 * @param ssl_config basic ssl config
 * @param engine_callback environment callback functions, including timer, socket, log, etc.
 * @param transport_cbs transport callback functions
 * @param conn_callback default connection callback functions
 */
XQC_EXPORT_PUBLIC_API
xqc_engine_t *xqc_engine_create(xqc_engine_type_t engine_type,
    const xqc_config_t *engine_config,
    const xqc_engine_ssl_config_t *ssl_config,
    const xqc_engine_callback_t *engine_callback,
    const xqc_transport_callbacks_t *transport_cbs,
    void *user_data);


/**
 * @brief destroy engine. this is called after all connections are destroyed
 * NOTICE: MUST NOT be called in any xquic callback functions, for this function will destroy engine
 * immediately, result in segmentation fault.
 */
XQC_EXPORT_PUBLIC_API
void xqc_engine_destroy(xqc_engine_t *engine);


/**
 * @brief register alpn and connection and stream callbacks. user can implement his own application
 * protocol by registering alpn, and taking quic connection and streams as application connection
 * and request
 *
 * @param engine engine handler
 * @param alpn Application-Layer-Protocol, for example, h3, hq-interop, or self-defined
 * @param alpn_len length of Application-Layer-Protocol string
 * @param ap_cbs connection and stream event callback functions for application-layer-protocol
 * @param alp_ctx the context of the upper layer protocol (e.g. the callback functions and default settings of the upper layer protocol)
 * @return XQC_EXPORT_PUBLIC_API
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_engine_register_alpn(xqc_engine_t *engine, const char *alpn, size_t alpn_len,
    xqc_app_proto_callbacks_t *ap_cbs, void *alp_ctx);


/**
 * @brief unregister an alpn and its quic connection callbacks
 *
 * @param engine engine handler
 * @param alpn Application-Layer-Protocol, for example, h3, hq-interop, or self-defined
 * @param alpn_len length of alpn
 * @return XQC_EXPORT_PUBLIC_API
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_engine_unregister_alpn(xqc_engine_t *engine, const char *alpn, size_t alpn_len);

/**
 * @brief get the context an application layer protocol
 * 
 * @param engine engine handler
 * @param alpn Application-Layer-Protocol, for example, h3, hq-interop, or self-defined
 * @param alpn_len length of alpn
 * @return the context
 */
XQC_EXPORT_PUBLIC_API
void* xqc_engine_get_alpn_ctx(xqc_engine_t *engine, const char *alpn, size_t alpn_len);

/**
 * @brief get the private context
 * 
 * @param engine 
 * @return XQC_EXPORT_PUBLIC_API* 
 */
XQC_EXPORT_PUBLIC_API
void* xqc_engine_get_priv_ctx(xqc_engine_t *engine);

/**
 * @brief save the private context
 * 
 * @param engine 
 * @param priv_ctx 
 * @return XQC_EXPORT_PUBLIC_API 
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_engine_set_priv_ctx(xqc_engine_t *engine, void *priv_ctx);

/**
 * Pass received UDP packet payload into xquic engine.
 * @param recv_time   UDP packet received time in microsecond
 * @param user_data   connection user_data, server is NULL
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_engine_packet_process(xqc_engine_t *engine,
    const unsigned char *packet_in_buf, size_t packet_in_size,
    const struct sockaddr *local_addr, socklen_t local_addrlen,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    xqc_usec_t recv_time, void *user_data);


/**
 * @brief Process all connections, application implements MUST call this function in timer callback
 */
XQC_EXPORT_PUBLIC_API
void xqc_engine_main_logic(xqc_engine_t *engine);


/**
 * @brief get default config of xquic
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_engine_get_default_config(xqc_config_t *config, xqc_engine_type_t engine_type);


/**
 * Modify engine config before engine created. Default config will be used otherwise.
 * Item value 0 means use default value.
 * @return 0 for success, <0 for error. default value is used if config item is illegal
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_engine_set_config(xqc_engine_t *engine, const xqc_config_t *engine_config);


/**
 * @brief Set server's connection settings. it can be called anytime. settings will take effect on
 * new created connections
 */
XQC_EXPORT_PUBLIC_API
void xqc_server_set_conn_settings(xqc_engine_t *engine, const xqc_conn_settings_t *settings);


/**
 * @brief Set the log level of xquic
 *
 * @param log_level engine will print logs which level >= log_level
 */
XQC_EXPORT_PUBLIC_API
void xqc_engine_set_log_level(xqc_engine_t *engine, xqc_log_level_t log_level);


/**
 * @brief enable/disable the log module of xquic
 *
 * @param enable XQC_TRUE for disable, XQC_FALSE for enable
 */
XQC_EXPORT_PUBLIC_API
void xqc_log_disable(xqc_engine_t *engine, xqc_bool_t disable);


/**
 * user should call after a number of packet processed in xqc_engine_packet_process
 * call after recv a batch packets, may destroy connection when error
 */
XQC_EXPORT_PUBLIC_API
void xqc_engine_finish_recv(xqc_engine_t *engine);

XQC_EXPORT_PUBLIC_API
xqc_connection_t *xqc_engine_get_conn_by_scid(xqc_engine_t *engine,
    const xqc_cid_t *cid);

/*************************************************************
 *  QUIC layer APIs
 *************************************************************/
/**
 * Client connect without http3
 * @param engine return from xqc_engine_create
 * @param conn_settings settings of connection
 * @param token token receive from server, xqc_save_token_pt callback
 * @param token_len
 * @param server_host server domain
 * @param no_crypto_flag 1: without encryption on 0-RTT and 1-RTT packets. this flag will add
 * no_crypto transport parameter when initiating a connection, which is not an official parameter
 * and might be modified or removed
 * @param conn_ssl_config For handshake
 * @param user_data For connection
 * @param peer_addr address of peer
 * @param peer_addrlen length of peer_addr
 * @param alpn Application-Layer-Protocol, MUST NOT be NULL
 * @return user should copy cid to your own memory, in case of cid destroyed in xquic library
 */
XQC_EXPORT_PUBLIC_API
const xqc_cid_t *xqc_connect(xqc_engine_t *engine,
    const xqc_conn_settings_t *conn_settings,
    const unsigned char *token, unsigned token_len,
    const char *server_host, int no_crypto_flag,
    const xqc_conn_ssl_config_t *conn_ssl_config,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    const char *alpn, void *user_data);

/**
 * Send CONNECTION_CLOSE to peer, conn_close_notify will callback when connection destroyed
 * @return 0 for success, <0 for error
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_conn_close(xqc_engine_t *engine, const xqc_cid_t *cid);

/**
 * @brief close connection with error code
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_conn_close_with_error(xqc_connection_t *conn, uint64_t err_code);

/**
 * Get errno when conn_close_notify, 0 For no-error
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_conn_get_errno(xqc_connection_t *conn);


/**
 * Get ssl handler of specified connection
 */
XQC_EXPORT_PUBLIC_API
void *xqc_conn_get_ssl(xqc_connection_t *conn);


/**
 * @brief get latest rtt sample of the initial path
 * 
 */
XQC_EXPORT_PUBLIC_API
xqc_usec_t xqc_conn_get_lastest_rtt(xqc_engine_t *engine, const xqc_cid_t *cid);


/**
 * Server should set user_data when conn_create_notify callbacks
 */
XQC_EXPORT_PUBLIC_API
void xqc_conn_set_transport_user_data(xqc_connection_t *conn, void *user_data);

/**
 * @brief set application-layer-protocol user_data to xqc_connection_t. which will be used in
 * xqc_conn_callbacks_t
 */
XQC_EXPORT_PUBLIC_API
void xqc_conn_set_alp_user_data(xqc_connection_t *conn, void *proto_data);


/**
 * Server should get peer addr when conn_create_notify callbacks
 * @param peer_addr_len is a return value
 * @return XQC_OK for success, others for failure
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_conn_get_peer_addr(xqc_connection_t *conn, struct sockaddr *addr, socklen_t addr_cap,
    socklen_t *peer_addr_len);

/**
 * Server should get local addr when conn_create_notify callbacks
 * @param local_addr_len is a return value
 * @return XQC_OK for success, others for failure
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_conn_get_local_addr(xqc_connection_t *conn, struct sockaddr *addr, socklen_t addr_cap,
    socklen_t *local_addr_len);

/**
 * Send PING to peer, if ack received, conn_ping_acked will callback with user_data
 * @return 0 for success, <0 for error
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_conn_send_ping(xqc_engine_t *engine, const xqc_cid_t *cid, void *ping_user_data);

/**
 * @return 1 for can send 0rtt, 0 for cannot send 0rtt
 */
XQC_EXPORT_PUBLIC_API
xqc_bool_t xqc_conn_is_ready_to_send_early_data(xqc_connection_t *conn);

/**
 * @brief set the packet filter callback function, and replace write_socket.
 * NOTICE: this function is not conflict with send_mmsg.
 */
XQC_EXPORT_PUBLIC_API
void xqc_conn_set_pkt_filter_callback(xqc_connection_t *conn,
    xqc_conn_pkt_filter_callback_pt pf_cb, void *pf_cb_user_data);

/**
 * @brief unset the packet filter callback function, and restore write_socket
 */
XQC_EXPORT_PUBLIC_API
void xqc_conn_unset_pkt_filter_callback(xqc_connection_t *conn);


/**
 * @brief get public local transport settings.
 */
XQC_EXPORT_PUBLIC_API
xqc_conn_public_local_trans_settings_t 
xqc_conn_get_public_local_trans_settings(xqc_connection_t *conn);

/**
 * @brief set public local transport settings
 */
XQC_EXPORT_PUBLIC_API
void xqc_conn_set_public_local_trans_settings(xqc_connection_t *conn, 
    xqc_conn_public_local_trans_settings_t *settings);

/**
 * @brief get public remote transport settings.
 */
XQC_EXPORT_PUBLIC_API
xqc_conn_public_remote_trans_settings_t 
xqc_conn_get_public_remote_trans_settings(xqc_connection_t *conn);

/**
 * @brief set public remote transport settings
 */
XQC_EXPORT_PUBLIC_API
void xqc_conn_set_public_remote_trans_settings(xqc_connection_t *conn, 
    xqc_conn_public_remote_trans_settings_t *settings);


/**
 * Create new stream in quic connection.
 * @param user_data  user_data for this stream
 */
XQC_EXPORT_PUBLIC_API
xqc_stream_t *xqc_stream_create(xqc_engine_t *engine, 
    const xqc_cid_t *cid, xqc_stream_settings_t *settings, void *user_data);

XQC_EXPORT_PUBLIC_API
xqc_stream_t *xqc_stream_create_with_direction(xqc_connection_t *conn,
    xqc_stream_direction_t dir, void *user_data);

XQC_EXPORT_PUBLIC_API
xqc_stream_direction_t xqc_stream_get_direction(xqc_stream_t *strm);

/**
 * Server should set user_data when stream_create_notify callbacks
 */
XQC_EXPORT_PUBLIC_API
void xqc_stream_set_user_data(xqc_stream_t *stream, void *user_data);


XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_stream_update_settings(xqc_stream_t *stream, 
    xqc_stream_settings_t *settings);

/**
 * Get connection's user_data by stream
 */
XQC_EXPORT_PUBLIC_API
void *xqc_get_conn_user_data_by_stream(xqc_stream_t *stream);

/**
 * Get connection's app_proto_user_data by stream
 */
XQC_EXPORT_PUBLIC_API
void *xqc_get_conn_alp_user_data_by_stream(xqc_stream_t *stream);


/**
 * Get stream ID
 */
XQC_EXPORT_PUBLIC_API
xqc_stream_id_t xqc_stream_id(xqc_stream_t *stream);

/**
 * Send RESET_STREAM to peer, stream_close_notify will callback when stream destroyed
 * @retval XQC_OK for success, others for failure
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_stream_close(xqc_stream_t *stream);

/**
 * Recv data in stream.
 * @return bytes read, -XQC_EAGAIN try next time, <0 for error
 */
XQC_EXPORT_PUBLIC_API
ssize_t xqc_stream_recv(xqc_stream_t *stream, unsigned char *recv_buf, size_t recv_buf_size,
    uint8_t *fin);

/**
 * Send data in stream.
 * @param fin  0 or 1,  1 - final data block send in this stream.
 * @return bytes sent, -XQC_EAGAIN try next time, <0 for error
 */
XQC_EXPORT_PUBLIC_API
ssize_t xqc_stream_send(xqc_stream_t *stream, unsigned char *send_data, size_t send_data_size,
    uint8_t fin);

/**
 * @brief the API to get the max length of the data that can be sent 
 *        via a single call of xqc_datagram_send; NOTE, if the DCID length could
 *        be changed during the lifetime of the connection, applications is 
 *        suggested to call xqc_datagram_get_mss every time before 
 *        send datagram data or when getting -XQC_EDGRAM_TOO_LARGE error 
 *        from sending datagram data. In MPQUIC cases, the DCID of all paths 
 *        MUST be the same. Otherwise, there might be unexpected errors.
 * 
 * @param conn the connection handle 
 * @return 0 = the peer does not support datagram, >0 = the max length
 */
XQC_EXPORT_PUBLIC_API
size_t xqc_datagram_get_mss(xqc_connection_t *conn);

/**
 * Server should set datagram user_data when datagram callbacks
 * @dgram_data: the user_data of all datagram callbacks
 */
XQC_EXPORT_PUBLIC_API
void xqc_datagram_set_user_data(xqc_connection_t *conn, void *dgram_data);

/**
 * @dgram_data: the user_data of all datagram callbacks
 */
XQC_EXPORT_PUBLIC_API
void *xqc_datagram_get_user_data(xqc_connection_t *conn);

/**
 * @brief the API to send a datagram over the QUIC connection
 * 
 * @param conn the connection handle 
 * @param data the data to be sent
 * @param data_len the length of the data
 * @param *dgram_id the pointer to return the id the datagram
 * @param qos level (must be the values defined in xqc_data_qos_level_t)
 * @return <0 = error (-XQC_EAGAIN, -XQC_CLOSING, -XQC_EDGRAM_NOT_SUPPORTED, -XQC_EDGRAM_TOO_LARGE, ...), 
 *         0 success
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_datagram_send(xqc_connection_t *conn, void *data, 
    size_t data_len, uint64_t *dgram_id, xqc_data_qos_level_t qos_level);

/**
 * @brief the API to send a datagram over the QUIC connection
 * 
 * @param conn the connection handle 
 * @param iov multiple data buffers need to be sent 
 * @param *dgram_id the pointer to return the list of dgram_id 
 * @param iov_size the size of iov list 
 * @param *sent_cnt the number of successfully sent datagrams
 * @param *sent_bytes the total bytes of successfully sent datagrams
 * @param qos level (must be the values defined in xqc_data_qos_level_t)
 * @return <0 = error (-XQC_EAGAIN, -XQC_CLOSING, -XQC_EDGRAM_NOT_SUPPORTED, -XQC_EDGRAM_TOO_LARGE, ...), 
 *         0 success
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_datagram_send_multiple(xqc_connection_t *conn, 
    struct iovec *iov, uint64_t *dgram_id_list, size_t iov_size, 
    size_t *sent_cnt, size_t *sent_bytes, xqc_data_qos_level_t qos_level);


/**
 * Get dcid and scid before process packet
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_packet_parse_cid(xqc_cid_t *dcid, xqc_cid_t *scid, uint8_t cid_len,
                               const unsigned char *buf, size_t size);

/**
 * @brief compare two cids
 * @return XQC_OK if equal, others if not equal
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_cid_is_equal(const xqc_cid_t *dst, const xqc_cid_t *src);

/**
 * Get scid in hex, end with '\0'
 * @param scid is returned from xqc_connect or xqc_h3_connect
 * @return user should copy return buffer to your own memory if you will access in the future
 */
XQC_EXPORT_PUBLIC_API
unsigned char *xqc_scid_str(xqc_engine_t *engine, const xqc_cid_t *scid);

XQC_EXPORT_PUBLIC_API
unsigned char *xqc_dcid_str(xqc_engine_t *engine, const xqc_cid_t *dcid);

XQC_EXPORT_PUBLIC_API
unsigned char *xqc_dcid_str_by_scid(xqc_engine_t *engine, const xqc_cid_t *scid);

XQC_EXPORT_PUBLIC_API
uint8_t xqc_engine_config_get_cid_len(xqc_engine_t *engine);

/**
 * User should call xqc_conn_continue_send when write event ready
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_conn_continue_send(xqc_engine_t *engine, const xqc_cid_t *cid);

/**
 * User should call xqc_conn_continue_send when write event ready
 */
XQC_EXPORT_PUBLIC_API
void xqc_conn_continue_send_by_conn(xqc_connection_t *conn);

/**
 * User can get xqc_conn_stats_t by cid
 */
XQC_EXPORT_PUBLIC_API
xqc_conn_stats_t xqc_conn_get_stats(xqc_engine_t *engine, const xqc_cid_t *cid);


/**
 * User can get xqc_conn_qos_stats_t by cid
 */
XQC_EXPORT_PUBLIC_API
xqc_conn_qos_stats_t xqc_conn_get_qos_stats(xqc_engine_t *engine, const xqc_cid_t *cid);

/**
 * create new path for client
 * @param cid scid for connection
 * @param new_path_id if new path is created successfully, return new_path_id in this param
 * @param path_status the initial status of the new path (1 = STANDBY, other values = AVAILABLE)
 * @return XQC_OK (0) when success, <0 for error
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_conn_create_path(xqc_engine_t *engine,
    const xqc_cid_t *cid, uint64_t *new_path_id,
    int path_status);


/**
 * Close a path
 * @param cid scid for connection
 * @param close_path_id path identifier for the closing path
 * @return XQC_OK (0) when success, <0 for error
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_conn_close_path(xqc_engine_t *engine, const xqc_cid_t *cid, uint64_t closed_path_id);


/**
 * Mark a path as "standby", i.e., suggest that no traffic should be sent
 * on that path if another path is available.
 * @param cid scid for connection
 * @param path_id path identifier for the path
 * @return XQC_OK (0) when success, <0 for error
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_conn_mark_path_standby(xqc_engine_t *engine, const xqc_cid_t *cid, uint64_t path_id);


/**
 * Mark a path as "available", i.e., allow the peer to use its own logic
 * to split traffic among available paths.
 * @param cid scid for connection
 * @param path_id path identifier for the path
 * @return XQC_OK (0) when success, <0 for error
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_conn_mark_path_available(xqc_engine_t *engine, const xqc_cid_t *cid, uint64_t path_id);

/**
 * Mark a path as "frozen", i.e., both peers should not send any traffic on this path.
 * @param cid scid for connection
 * @param path_id path identifier for the path
 * @return XQC_OK (0) when success, <0 for error
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_conn_mark_path_frozen(xqc_engine_t *engine, const xqc_cid_t *cid, uint64_t path_id);


/**
 * Calculate how many available paths on the current connection, i.e., paths which finished validation and is marked "available" status.
 * @param engine xquic engine ctx
 * @param cid scid for connection
 * @return number of available paths when success, <0 for error
 */
XQC_EXPORT_PUBLIC_API xqc_int_t xqc_conn_available_paths(xqc_engine_t *engine, const xqc_cid_t *cid);


XQC_EXPORT_PUBLIC_API
xqc_conn_type_t xqc_conn_get_type(xqc_connection_t *conn);

/**
 * Server should get peer addr when path_create_notify callbacks
 * @param peer_addr_len is a return value
 * @return XQC_OK for success, others for failure
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_path_get_peer_addr(xqc_connection_t *conn, uint64_t path_id,
    struct sockaddr *addr, socklen_t addr_cap, socklen_t *peer_addr_len);

/**
 * Server should get local addr when path_create_notify callbacks
 * @param local_addr_len is a return value
 * @return XQC_OK for success, others for failure
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_path_get_local_addr(xqc_connection_t *conn, uint64_t path_id,
    struct sockaddr *addr, socklen_t addr_cap, socklen_t *local_addr_len);

    

/**
 * @brief load balance cid encryption.
 * According to Draft : https://datatracker.ietf.org/doc/html/draft-ietf-quic-load-balancers-13#section-4.3.2
 * @param enc_len plaintext length.
 * @param cid_buf the plaintext to be encrypted.
 * @param out_buf the ciphertext of the plaintext encrypted.
 * @param out_buf_len the length of the ciphertext to be encrypted.
 * @param lb_cid_key  encryption secret.
 * @param lb_cid_key_len secret length.
 * @param engine engine from `xqc_engine_create`
 * @return negative for failed, 0 for the success.
 *
 * The length of cid_buf must not exceed the maximum length of the cid (20 byte), the length of out_buf should be no less than cid_buf_length.
 * The length of lb_cid_key should be exactly 16 bytes.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_lb_cid_encryption(uint8_t *cid_buf, size_t enc_len, uint8_t *out_buf, size_t out_buf_len, uint8_t *lb_cid_key, size_t lb_cid_key_len, xqc_engine_t *engine);

/**
 * @brief client calls this API to check if it should delete 0rtt ticket according to
 * the errorcode of xqc_conn in conn_close_notify
 * @return XQC_TRUE = yes;
 */
XQC_EXPORT_PUBLIC_API
xqc_bool_t xqc_conn_should_clear_0rtt_ticket(xqc_int_t conn_err);

/**
 * @brief Users call this function to get a template of conn settings, which serves
 *        as the starting point for users who want to refine conn settings according 
 *        to their needs
 * @param settings_type there are different types of templates in XQUIC
 * @return conn settings
 */
XQC_EXPORT_PUBLIC_API
xqc_conn_settings_t xqc_conn_get_conn_settings_template(xqc_conn_settings_type_t settings_type);

#ifdef __cplusplus
}
#endif

#endif /* _XQUIC_H_INCLUDED_ */

