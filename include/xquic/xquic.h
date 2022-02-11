/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQUIC_H_INCLUDED_
#define _XQUIC_H_INCLUDED_

/**
 * Public API for using libxquic
 */
#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#endif
#include "xquic_typedef.h"

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
     * in xqc_congit_t.
     */
    void (*xqc_log_write_err)(xqc_log_level_t lvl, const void *buf, size_t size, void *engine_user_data);

    /**
     * statistic log callback function
     *
     * this function will be triggered when write XQC_LOG_REPORT or XQC_LOG_STATS level logs.
     * mainly when connection close, stream close.
     */
    void (*xqc_log_write_stat)(xqc_log_level_t lvl, const void *buf, size_t size, void *engine_user_data);

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
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user_data);

/**
 * @brief general callback function definition for connection create and close
 */
typedef int (*xqc_conn_notify_pt)(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *conn_user_data);

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
typedef void (*xqc_handshake_finished_pt)(xqc_connection_t *conn, void *conn_user_data);

/**
 * @brief PING acked callback function.
 *
 * if application send a PING frame with xqc_conn_send_ping function, this callback function will be
 * triggered when this PING frame is acked by peer. noticing that PING frame do not need repair, it
 * might not be triggered if PING frame is lost or ACK frame is lost.
 * xquic might send PING frames  will not trigger this callback
 */
typedef void (*xqc_conn_ping_ack_notify_pt)(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *ping_user_data, void *conn_user_data);

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
 * @brief multi-path create callback function
 *
 * @param scid source connection id of endpoint
 * @param path_id id of path
 * @param conn_user_data user_data of connection
 */
typedef void (*xqc_path_created_notify_pt)(const xqc_cid_t *scid, uint64_t path_id,
    void *conn_user_data);

/**
 * @brief multi-path remove path callback function. will be triggered when path is destroyed
 *
 * @param scid source connection id of endpoint
 * @param path_id id of path
 * @param conn_user_data user_data of connection
 */
typedef void (*xqc_path_removed_notify_pt)(const xqc_cid_t *scid, uint64_t path_id,
    void *conn_user_data);

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
typedef ssize_t (*xqc_mp_socket_write_pt)(uint64_t path_id, const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data);

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
typedef ssize_t (*xqc_mp_send_mmsg_pt)(uint64_t path_id, const struct iovec *msg_iov,
    unsigned int vlen, const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    void *conn_user_data);


/**
 * @brief general callback function definition for stream create, close, read and write.
 *
 * @param stream QUIC stream handler
 * @param strm_user_data stream level user_data, which was the parameter of xqc_stream_create set by
 * client, or the parameter of xqc_stream_set_user_data set by server
 * @return 0 for success, -1 for failure
 */
typedef int (*xqc_stream_notify_pt)(xqc_stream_t *stream, void *strm_user_data);


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
     * multi-path available callback. REQUIRED both for client and server if multi-path is needed
     */
    xqc_conn_ready_to_create_path_notify_pt ready_to_create_path_notify;

    /**
     * path create callback function. REQUIRED both for client and server if multi-path is needed
     */
    xqc_path_created_notify_pt      path_created_notify;

    /**
     * path remove callback function. REQUIRED both for client and server if multi-path is needed
     */
    xqc_path_removed_notify_pt      path_removed_notify;

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
    xqc_conn_notify_pt              conn_create_notify;

    /**
     * connection close notify. REQUIRED for both client and server
     *
     * this function will be invoked after QUIC connection is closed. user can free application
     * level context created in conn_create_notify callback function
     */
    xqc_conn_notify_pt              conn_close_notify;

    /**
     * handshake complete callback. OPTIONAL for client and server
     */
    xqc_handshake_finished_pt       conn_handshake_finished;

    /**
     * active PING acked callback. OPTIONAL for both client and server
     */
    xqc_conn_ping_ack_notify_pt     conn_ping_acked;

} xqc_conn_callbacks_t;


/* QUIC layer stream callback functions */
typedef struct xqc_stream_callbacks_s {
    /**
     * stream read callback function. REQUIRED for both client and server
     *
     * this will be triggered when QUIC stream data is ready for read. application layer could read
     * data when xqc_stream_recv interface.
     */
    xqc_stream_notify_pt        stream_read_notify;

    /**
     * stream write callback function. REQUIRED for both client and server
     *
     * when sending data with xqc_stream_send, xquic might be blocked or send part of the data. if
     * this callback function is triggered, applications can continue to send the rest data.
     */
    xqc_stream_notify_pt        stream_write_notify;

    /**
     * stream create callback function. REQUIRED for server, OPTIONAL for client.
     *
     * this will be triggered when QUIC stream is created. applications can create its own stream
     * context in this callback function.
     */
    xqc_stream_notify_pt        stream_create_notify;

    /**
     * stream close callback function. REQUIRED for both server and client.
     *
     * this will be triggered when QUIC stream is finally closed. xquic will close stream after
     * sending or receiving RESET_STREAM frame after 3 times of PTO, or when connection is closed.
     * Applications can free the context which was created in stream_create_notify here.
     */
    xqc_stream_notify_pt        stream_close_notify;

} xqc_stream_callbacks_t;


/**
 * @brief connection and stream callbacks for QUIC level, Application-Layer-Protocol shall implement
 * these callback functions and register ALP with xqc_engine_register_alpn
 */
typedef struct xqc_app_proto_callbacks_s {

    /* QUIC connection callback functions for Application-Layer-Protocol */
    xqc_conn_callbacks_t        conn_cbs;

    /* QUIC stream callback functions */
    xqc_stream_callbacks_t      stream_cbs;

} xqc_app_proto_callbacks_t;


typedef struct xqc_cc_params_s {
    uint32_t    customize_on;
    uint32_t    init_cwnd;
    uint32_t    expect_bw;
    uint32_t    max_expect_bw;
    uint32_t    cc_optimization_flags;
} xqc_cc_params_t;

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
    void (*xqc_cong_ctl_bbr)(void *cong_ctl, xqc_sample_t *sampler);

    /* initialize bbr */
    void (*xqc_cong_ctl_init_bbr)(void *cong_ctl, xqc_sample_t *sampler, xqc_cc_params_t cc_params);

    /* get pacing rate */
    uint32_t (*xqc_cong_ctl_get_pacing_rate)(void *cong_ctl);

    /* get estimation of bandwidth */
    uint32_t (*xqc_cong_ctl_get_bandwidth_estimate)(void *cong_ctl);

    xqc_bbr_info_interface_t *xqc_cong_ctl_info_cb;
} xqc_cong_ctrl_callback_t;

#ifndef XQC_DISABLE_RENO
XQC_EXPORT_PUBLIC_API extern const xqc_cong_ctrl_callback_t xqc_reno_cb;
#endif
#ifdef XQC_ENABLE_BBR2
XQC_EXPORT_PUBLIC_API extern const xqc_cong_ctrl_callback_t xqc_bbr2_cb;
#endif
XQC_EXPORT_PUBLIC_API extern const xqc_cong_ctrl_callback_t xqc_bbr_cb;
XQC_EXPORT_PUBLIC_API extern const xqc_cong_ctrl_callback_t xqc_cubic_cb;


/**
 * @struct xqc_config_t
 * QUIC config parameters
 */
typedef struct xqc_config_s {
    /* log level */
    xqc_log_level_t cfg_log_level;

    /* enable log based on event or not, non-zero for enable, 0 for not */
    xqc_flag_t      cfg_log_event;

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
    xqc_keylog_pt                   keylog_cb;

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

typedef struct xqc_conn_settings_s {
    int                         pacing_on;          /* default: 0 */
    int                         ping_on;            /* client sends PING to keepalive, default:0 */
    xqc_cong_ctrl_callback_t    cong_ctrl_callback; /* default: xqc_cubic_cb */
    xqc_cc_params_t             cc_params;
    uint32_t                    so_sndbuf;          /* socket option SO_SNDBUF, 0 for unlimited */
    xqc_linger_t                linger;
    xqc_proto_version_t         proto_version;      /* QUIC protocol version */
    xqc_msec_t                  init_idle_time_out; /* initial idle timeout interval, effective before handshake completion */
    xqc_msec_t                  idle_time_out;      /* idle timeout interval, effective after handshake completion */
    int32_t                     spurious_loss_detect_on;
    uint32_t                    anti_amplification_limit;   /* limit of anti-amplification, default 3 */
    uint64_t                    keyupdate_pkt_threshold;    /* packet limit of a single 1-rtt key, 0 for unlimited */
} xqc_conn_settings_t;


typedef enum {
    XQC_0RTT_NONE,      /* without 0-RTT */
    XQC_0RTT_ACCEPT,    /* 0-RTT was accepted */
    XQC_0RTT_REJECT,    /* 0-RTT was rejected */
} xqc_0rtt_flag_t;

typedef struct xqc_conn_stats_s {
    uint32_t            send_count;
    uint32_t            lost_count;
    uint32_t            tlp_count;
    uint32_t            spurious_loss_count;
    xqc_usec_t          srtt;
    xqc_0rtt_flag_t     early_data_flag;
    uint32_t            recv_count;
    int                 spurious_loss_detect_on;
    int                 conn_err;
    char                ack_info[50];
} xqc_conn_stats_t;


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
 * @return XQC_EXPORT_PUBLIC_API
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_engine_register_alpn(xqc_engine_t *engine, const char *alpn, size_t alpn_len,
    xqc_app_proto_callbacks_t *ap_cbs);


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
void xqc_server_set_conn_settings(const xqc_conn_settings_t *settings);


/**
 * @brief Set the log level of xquic
 *
 * @param log_level engine will print logs which level >= log_level
 */
XQC_EXPORT_PUBLIC_API
void xqc_engine_set_log_level(xqc_engine_t *engine, xqc_log_level_t log_level);


/**
 * user should call after a number of packet processed in xqc_engine_packet_process
 * call after recv a batch packets, may destroy connection when error
 */
XQC_EXPORT_PUBLIC_API
void xqc_engine_finish_recv(xqc_engine_t *engine);


/**
 * call after recv a batch packets, do not destroy connection
 */
XQC_EXPORT_PUBLIC_API
void xqc_engine_recv_batch(xqc_engine_t *engine, xqc_connection_t *conn);


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
 * Get errno when conn_close_notify, 0 For no-error
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_conn_get_errno(xqc_connection_t *conn);


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
void xqc_conn_set_alp_user_data(xqc_connection_t *conn, void *app_proto_user_data);


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
 * Create new stream in quic connection.
 * @param user_data  user_data for this stream
 */
XQC_EXPORT_PUBLIC_API
xqc_stream_t *xqc_stream_create(xqc_engine_t *engine, const xqc_cid_t *cid, void *user_data);

/**
 * Server should set user_data when stream_create_notify callbacks
 */
XQC_EXPORT_PUBLIC_API
void xqc_stream_set_user_data(xqc_stream_t *stream, void *user_data);

/**
 * Get connection's user_data by stream
 */
XQC_EXPORT_PUBLIC_API
void *xqc_get_conn_user_data_by_stream(xqc_stream_t *stream);

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
unsigned char *xqc_scid_str(const xqc_cid_t *scid);

XQC_EXPORT_PUBLIC_API
unsigned char *xqc_dcid_str(const xqc_cid_t *dcid);

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
 * User can get xqc_conn_stats_t by cid
 */
XQC_EXPORT_PUBLIC_API
xqc_conn_stats_t xqc_conn_get_stats(xqc_engine_t *engine, const xqc_cid_t *cid);


#ifdef __cplusplus
}
#endif

#endif /* _XQUIC_H_INCLUDED_ */

