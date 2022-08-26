
/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_MULTIPATH_H
#define XQC_MULTIPATH_H

#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>
#include "src/common/xqc_common.h"
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_recv_record.h"
#include "src/transport/xqc_frame_parser.h"


/* enable multipath */
typedef enum {
    XQC_CONN_NOT_SUPPORT_MULTIPATH      = 0,    /* 00 */
    XQC_CONN_MULTIPATH_SINGLE_PNS       = 1,    /* 01 */
    XQC_CONN_MULTIPATH_MULTIPLE_PNS     = 2,    /* 10 */
} xqc_multipath_mode_t;

/* path state */
typedef enum {
    XQC_PATH_STATE_INIT       = 0,    /* initial state */
    XQC_PATH_STATE_VALIDATING = 1,    /* PATH_CHALLENGE sent/received on new path */
    XQC_PATH_STATE_ACTIVE     = 2,    /* PATH_RESPONSE received */
    XQC_PATH_STATE_CLOSING    = 3,    /* PATH_ABANDONED sent/received */
    XQC_PATH_STATE_CLOSED     = 4,
} xqc_path_state_t;

/* path close mode: passive & proactive */
typedef enum {
    XQC_PATH_CLOSE_PASSIVE    = 0,
    XQC_PATH_CLOSE_PROACTIVE  = 1,
} xqc_path_close_mode_t;

typedef enum {
    XQC_SEND_TYPE_NORMAL,
    XQC_SEND_TYPE_NORMAL_HIGH_PRI,
    XQC_SEND_TYPE_RETRANS,
    XQC_SEND_TYPE_PTO_PROBE,
    XQC_SEND_TYPE_N,
} xqc_send_type_t;

/* path context */
struct xqc_path_ctx_s {

    /* Path_identifier */
    uint64_t            path_id;    /* path identifier */
    xqc_cid_t           path_scid;
    xqc_cid_t           path_dcid;

    /* Path_address: 4-tuple */
    unsigned char       peer_addr[sizeof(struct sockaddr_in6)],
                        local_addr[sizeof(struct sockaddr_in6)];
    socklen_t           peer_addrlen,
                        local_addrlen;

    char                addr_str[2*(XQC_MAX_CID_LEN + INET6_ADDRSTRLEN) + 10];
    socklen_t           addr_str_len;

    /* server receives a packet from different address (NAT rebinding) */
    uint32_t            rebinding_count;
    /* server validate NAT rebinding (PATH_CHALLENGE & PATH_RESPONSE) */
    uint32_t            rebinding_valid;

    unsigned char       rebinding_addr[sizeof(struct sockaddr_in6)];
    socklen_t           rebinding_addrlen;
    int                 rebinding_check_response;

    /* Path_state */
    xqc_path_state_t    path_state;
    unsigned char       path_challenge_data[XQC_PATH_CHALLENGE_DATA_LEN];

    /* Path cc & ack tracking */
    xqc_send_ctl_t     *path_send_ctl;
    xqc_pn_ctl_t       *path_pn_ctl;

    /* path send buffer, used to store packets scheduled to this path */
    xqc_list_head_t     path_schedule_buf[XQC_SEND_TYPE_N];
    uint32_t            path_schedule_bytes;

    /* related structs */
    xqc_connection_t   *parent_conn;
    xqc_list_head_t     path_list;

    /* Path_metrics */
    xqc_path_metrics_t  path_metrics;
    xqc_usec_t          path_create_time;
    xqc_usec_t          path_destroy_time;
};

typedef struct {
    uint64_t            path_id;
    uint8_t             path_state;

    uint64_t            path_pkt_recv_count;
    uint64_t            path_pkt_send_count;
    
    uint64_t            path_create_time;
    uint64_t            path_destroy_time;
    
    uint64_t            update_rtt_count;
    uint64_t            mean_latest_rtt;
    uint32_t            cv_latest_rtt;

} xqc_path_info_t;

xqc_bool_t xqc_is_same_addr(const struct sockaddr *sa1, const struct sockaddr *sa2);
xqc_bool_t xqc_is_same_addr_as_any_path(xqc_connection_t *conn, const struct sockaddr *peer_addr);

xqc_int_t xqc_generate_path_challenge_data(xqc_connection_t *conn, xqc_path_ctx_t *path);

/* check mp support */
xqc_multipath_mode_t xqc_conn_enable_multipath(xqc_connection_t *conn);

/* init path_list & initial path for connection */
xqc_int_t xqc_conn_init_paths_list(xqc_connection_t *conn);

/* destroy all the paths of the connection */
void xqc_conn_destroy_paths_list(xqc_connection_t *conn);

void xqc_path_schedule_buf_destroy(xqc_path_ctx_t *path);

/* create path inner */
xqc_path_ctx_t *xqc_conn_create_path_inner(xqc_connection_t *conn, xqc_cid_t *scid, xqc_cid_t *dcid);

/* server update client addr when recv path_challenge frame */
xqc_int_t xqc_conn_server_init_path_addr(xqc_connection_t *conn, uint64_t path_id,
    const struct sockaddr *local_addr, socklen_t local_addrlen,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen);

xqc_int_t xqc_conn_client_init_path_addr(xqc_connection_t *conn);

/* path state: "ACTIVE" -> "CLOSING" */
xqc_int_t xqc_path_closing(xqc_connection_t *conn, xqc_path_ctx_t *path, xqc_path_close_mode_t close_mode);

/* find path */
xqc_path_ctx_t *xqc_conn_find_path_by_path_id(xqc_connection_t *conn, uint64_t path_id);
xqc_path_ctx_t *xqc_conn_find_path_by_scid(xqc_connection_t *conn, xqc_cid_t *scid);
xqc_path_ctx_t *xqc_conn_find_path_by_dcid(xqc_connection_t *conn, xqc_cid_t *dcid);

void xqc_move_packet_to_scheduled_path(xqc_path_ctx_t *path, xqc_packet_out_t *packet_out, xqc_send_type_t send_type);
void xqc_on_remove_packet_from_path_buf(xqc_path_ctx_t *path, xqc_packet_out_t *packet_out);
void xqc_put_packets_back_to_send_queue(xqc_connection_t *conn, xqc_path_ctx_t *path, xqc_list_head_t *head, xqc_send_type_t send_type);

/* path statistics */
void xqc_conn_path_metrics_print(xqc_connection_t *conn, xqc_conn_stats_t *stats);
void xqc_request_path_metrics_print(xqc_connection_t *conn, xqc_h3_stream_t *h3_stream, xqc_request_stats_t *stats);

void xqc_stream_path_metrics_print(xqc_connection_t *conn, xqc_stream_t *stream, char *buff, size_t buff_size);
void xqc_stream_path_metrics_on_send(xqc_connection_t *conn, xqc_packet_out_t *po);
void xqc_stream_path_metrics_on_recv(xqc_connection_t *conn, xqc_stream_t *stream, xqc_packet_in_t *pi);

void xqc_path_metrics_print(xqc_connection_t *conn, char *buff, unsigned buff_size);
void xqc_h3s_path_metrics_print(xqc_h3_stream_t *h3_stream, char *buff, unsigned buff_size);

xqc_msec_t xqc_path_get_idle_timeout(xqc_path_ctx_t *path);

void xqc_path_validate(xqc_path_ctx_t *path);

xqc_bool_t xqc_path_is_initial_path(xqc_path_ctx_t *path);

void xqc_path_record_info(xqc_path_ctx_t *path, xqc_path_info_t *path_info);

size_t xqc_path_info_print(xqc_path_info_t *path_info, char **buff, size_t *buff_size);

#endif /* XQC_MULTIPATH_H */


