//
// Created by Neho on 2022/8/23.
//

#ifndef XQUICANDROIDDEMO_XQC_COMMON_H
#define XQUICANDROIDDEMO_XQC_COMMON_H


#include "xquic.h"
#include "xqc_http3.h"
#include "event.h"

#define XQC_MAX_LOG_LEN 2048
#define XQC_PACKET_TMP_BUF_LEN 1500
#define MAX_BUF_SIZE (100*1024*1024)
#define MAX_HEADER 100

typedef enum cc_type {
    CC_TYPE_BBR,
    CC_TYPE_CUBIC,
    CC_TYPE_RENO
} CCTYPE;

typedef void(*callback_body_content_to_java) (void* java_level_obj, const char * body_content, size_t body_len);

typedef struct client_user_data_params_s {
    /* URL */
    const char* url;

    /* log level */
    int log_level;

    /* Echo check on (0) */
    int g_echo_check;

    /* total number of request to send (1) */
    int g_req_max;

    /* get or post (0) */
    int g_is_get;

    /* body size to send (1024*1024) */
    int g_send_body_size;

    /* forceCertVerification */
    int force_cert_verificaion;

    /* force 1 RTT */
    int g_force_1rtt;

    /* No encryprion */
    int no_encryption;

    /* url相关 */
    char g_scheme[8];
    char g_host[64];
    char g_url_path[256];

    /* header count */
    int g_header_num;

    /* server address and port */
    char server_addr[64];
    int server_port;

    /* Transport layer. No HTTP3. */
    int transport;

    /* conn timeout */
    int g_conn_timeout;

    /* IPv6*/
    int g_ipv6;

    /* cc */
    CCTYPE cc;

    /* Pacing ON */
    int pacing_on;

    /*Number of Parallel requests per single connection. Default 1.*/
    int req_paral;

    /* 回调相关 */
    callback_body_content_to_java callback_body_content;
    void *java_level_obj;


}client_user_data_params_t;


typedef struct client_ctx_s {
    xqc_engine_t   *engine;

    /* event base的两种事件 */
    struct ev_timer ev_engine;

    /* event base, the root */
    struct ev_loop *eb;

    /* log相关handler */
    struct __sFILE *log_fd;
    struct __sFILE *keylog_fd;

    /* (mess) user param */
    client_user_data_params_t *user_params;

} client_ctx_t;


typedef struct user_conn_s {
    int                 fd;
    xqc_cid_t           cid;

    struct sockaddr    *local_addr;
    socklen_t           local_addrlen;
    xqc_flag_t          get_local_addr;
    struct sockaddr    *peer_addr;
    socklen_t           peer_addrlen;

    unsigned char      *token;
    unsigned            token_len;

    struct ev_io       ev_socket;
    struct ev_timer    ev_timeout;

    int                 h3;

    client_ctx_t *ctx;

}user_conn_t;

typedef struct user_stream_s {
    xqc_stream_t       *stream;
    xqc_h3_request_t   *h3_request;
    user_conn_t        *user_conn;
    uint64_t            send_offset;
    int                 header_sent;
    int                 header_recvd;
    char               *send_body;
    size_t              send_body_len;
    size_t              send_body_max;
    char               *recv_body;
    size_t              recv_body_len;
    int                 recv_fin;
    xqc_msec_t          start_time;
    xqc_msec_t          first_frame_time;   /* first frame download time */
    xqc_msec_t          last_read_time;
    int                 abnormal_count;
    int                 body_read_notify_cnt;
} user_stream_t;

#endif //XQUICANDROIDDEMO_XQC_COMMON_H