#ifndef XQC_MINI_CLIENT_H
#define XQC_MINI_CLIENT_H

#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <memory.h>
#include <stdlib.h>
#include <string.h>
#include <event2/event.h>
#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>
#include <xquic/xquic_typedef.h>

#include "../tests/platform.h"
#include "common.h"
#include "mini_client_cb.h"

#define DEFAULT_IP   "127.0.0.1"
#define DEFAULT_PORT 8443
#define DEFAULT_HOST "test.xquic.com"

#define SESSION_TICKET_BUF_MAX_SIZE 8192
#define TRANSPORT_PARAMS_MAX_SIZE 8192
#define TOKEN_MAX_SIZE 8192
#define MAX_PATH_CNT 2
#define XQC_PACKET_BUF_LEN 1500

#define SESSION_TICKET_FILE         "session_ticket"
#define TRANSPORT_PARAMS_FILE       "transport_params"
#define TOKEN_FILE                  "token"

#define LOG_PATH "clog.log"
#define KEY_PATH "ckeys.log"
#define OUT_DIR  "."

/**
 * net config definition
 * net config is those arguments about socket information
 * all configuration on net should be put under this section
 */

typedef struct xqc_mini_cli_net_config_s {
    /* server addr info */
    struct sockaddr_in  addr;
    int                 addr_len;
    char                server_addr[64];
    short               server_port;
} xqc_mini_cli_net_config_t;

/**
 * quic config definition
 * quic config is those arguments required by quic features, including connection settings, ssl configs, etc.
 * all configuration on quic should be put under this section
 */

typedef struct xqc_mini_cli_quic_config_s {
    /* cipher config */
    char        ciphers[CIPHER_SUIT_LEN];
    char        groups[TLS_GROUPS_LEN];

    /* connection ssl config */
    char        session_ticket[SESSION_TICKET_BUF_MAX_SIZE];
    int         session_ticket_len;
    char        transport_parameter[TRANSPORT_PARAMS_MAX_SIZE];
    int         transport_parameter_len;

    char        token[TOKEN_MAX_SIZE];
    int         token_len;
    
    int         no_encryption;

    /* multipath */
    int         multipath;     // mp option, 0: disable, 1: enable
    char        mp_sched[32];  // mp scheduler, minrtt/backup

    /* congestion control */
    CC_TYPE     cc;             // cc algrithm, bbr/cubic
} xqc_mini_cli_quic_config_t;

/**
 * the environment config definition
 * environment config is those arguments about IO inputs and outputs
 * all configuration on environment should be put under this section
 */

typedef struct xqc_mini_cli_env_config_s {
    /* log config */
    char log_path[PATH_LEN];

    /* tls certificates */
    char private_key_file[PATH_LEN];
    char cert_file[PATH_LEN];

    /* key export */
    char key_out_path[PATH_LEN];

    /* output file */
    char out_file_dir[PATH_LEN];
} xqc_mini_cli_env_config_t;


/**
 * the request config definition
 * request config is those arguments about request information
 * all configuration on request should be put under this section
 */
typedef struct xqc_mini_cli_req_config_s {
    char            path[RESOURCE_LEN];         /* request path */
    char            scheme[8];                  /* request scheme, http/https */
    REQUEST_METHOD  method;
    char            host[256];                  /* request host */
    // char            auth[AUTHORITY_LEN];
    char            url[URL_LEN];               /* original url */
} xqc_mini_cli_req_config_t;


typedef struct xqc_mini_cli_args_s {
    /* network args */
    xqc_mini_cli_net_config_t   net_cfg;

    /* xquic args */
    xqc_mini_cli_quic_config_t  quic_cfg;

    /* environment args */
    xqc_mini_cli_env_config_t   env_cfg;

    /* request args */
    xqc_mini_cli_req_config_t   req_cfg;
} xqc_mini_cli_args_t;


typedef struct xqc_mini_cli_ctx_s {
    struct event_base   *eb;

    /* used to remember fd type to send stateless reset */
    int                 current_fd;

    /* ipv4 server */
    int                 fd;
    struct sockaddr_in  local_addr;
    socklen_t           local_addrlen;
    struct event        *ev_socket;

    xqc_engine_t        *engine;    // xquic engine for current context
    struct event        *ev_engine;

    xqc_mini_cli_args_t *args;      // server arguments for current context

    int                 log_fd;
    int                 keylog_fd;
} xqc_mini_cli_ctx_t;


typedef struct xqc_mini_cli_user_conn_s {
    
    xqc_cid_t               cid;

    xqc_mini_cli_ctx_t      *ctx;
    // xqc_mini_cli_user_path_t paths[MAX_PATH_CNT];

    // struct event            *ev_idle_restart;
    // struct event            *ev_close_path;
    struct event            *ev_timeout;
    struct event            *ev_request;

} xqc_mini_cli_user_conn_t;

typedef struct xqc_mini_cli_user_stream_s {
    xqc_mini_cli_user_conn_t   *user_conn;

    /* save file */
    // char                        file_name[RESOURCE_LEN];
    // FILE                        *recv_body_fp;

    /* stat for IO */
    size_t                      send_body_len;
    size_t                      recv_body_len;
    int                         recv_fin;
    xqc_msec_t                  start_time;


    /* h3 request content */
    xqc_h3_request_t           *h3_request;

    xqc_http_headers_t          h3_hdrs;
    uint8_t                     hdr_sent;

    char                       *send_body_buff;
    int                         send_body_size;
    size_t                      send_offset;

} xqc_mini_cli_user_stream_t;


int xqc_mini_cli_request_send(xqc_h3_request_t *h3_request, xqc_mini_cli_user_stream_t *user_stream);

#endif