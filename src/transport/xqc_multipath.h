
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
    XQC_CONN_MULTIPATH_MULTIPLE_PNS     = 1,    /* 01 */
} xqc_multipath_mode_t;

/* path state */
typedef enum {
    XQC_PATH_STATE_INIT       = 0,    /* initial state */
    XQC_PATH_STATE_VALIDATING = 1,    /* PATH_CHALLENGE sent/received on new path */
    XQC_PATH_STATE_ACTIVE     = 2,    /* PATH_RESPONSE received */
    XQC_PATH_STATE_CLOSING    = 3,    /* PATH_ABANDONED sent or received */
    XQC_PATH_STATE_CLOSED     = 4,    /* PATH_ABANDONED acked or draining timeout */
} xqc_path_state_t;

/* application layer path status */
typedef enum {
    /* max */
    XQC_APP_PATH_STATUS_NONE,
    /* suggest that no traffic should be sent on that path if another path is available */
    XQC_APP_PATH_STATUS_STANDBY   = 1,
    /* allow the peer to use its own logic to split traffic among available paths */
    XQC_APP_PATH_STATUS_AVAILABLE = 2,
    /* freeze a path */
    XQC_APP_PATH_STATUS_FROZEN    = 3,
    /* max */
    XQC_APP_PATH_STATUS_MAX,
} xqc_app_path_status_t;


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

typedef enum {
    XQC_PATH_FLAG_SEND_STATUS_SHIFT,
    XQC_PATH_FLAG_RECV_STATUS_SHIFT,
    XQC_PATH_FLAG_SOCKET_ERROR_SHIFT,
    XQC_PATH_FLAG_SHOULD_ACK_INIT_SHIFT,
    XQC_PATH_FLAG_SHOULD_ACK_HSK_SHIFT,
    XQC_PATH_FLAG_SHOULD_ACK_01RTT_SHIFT,
} xqc_path_flag_shift_t;

typedef enum {
    XQC_PATH_FLAG_SEND_STATUS       = 1 << XQC_PATH_FLAG_SEND_STATUS_SHIFT,
    XQC_PATH_FLAG_RECV_STATUS       = 1 << XQC_PATH_FLAG_RECV_STATUS_SHIFT,
    XQC_PATH_FLAG_SOCKET_ERROR      = 1 << XQC_PATH_FLAG_SOCKET_ERROR_SHIFT,
    XQC_PATH_FLAG_SHOULD_ACK_INIT   = 1 << XQC_PATH_FLAG_SHOULD_ACK_INIT_SHIFT,
    XQC_PATH_FLAG_SHOULD_ACK_HSK    = 1 << XQC_PATH_FLAG_SHOULD_ACK_HSK_SHIFT,
    XQC_PATH_FLAG_SHOULD_ACK_01RTT  = 1 << XQC_PATH_FLAG_SHOULD_ACK_01RTT_SHIFT,
} xqc_path_flag_t;

typedef enum {
    XQC_PATH_SPECIFIED_BY_ACK       = 1 << 0,  /* ack */
    XQC_PATH_SPECIFIED_BY_PCPR      = 1 << 1,  /* path challenge & response */
    XQC_PATH_SPECIFIED_BY_PTO       = 1 << 2,  /* PTO probe */
    XQC_PATH_SPECIFIED_BY_REINJ     = 1 << 3,  /* reinjection on a specific path */
    XQC_PATH_SPECIFIED_BY_PTMUD     = 1 << 4,  /* PMTUD Probe */
    XQC_PATH_SPECIFIED_BY_KAP       = 1 << 5,  /* Keepalive Probe */
    XQC_PATH_SPECIFIED_BY_PQP       = 1 << 6,  /* Path Quality Probe */
} xqc_path_specified_flag_t;

typedef enum {
    XQC_PATH_CLASS_AVAILABLE_HIGH,
    XQC_PATH_CLASS_STANDBY_HIGH,
    XQC_PATH_CLASS_AVAILABLE_MID,
    XQC_PATH_CLASS_STANDBY_MID,
    XQC_PATH_CLASS_AVAILABLE_LOW,
    XQC_PATH_CLASS_STANDBY_LOW,
    XQC_PATH_CLASS_PERF_CLASS_SIZE,
} xqc_path_perf_class_t;

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

    xqc_path_flag_t     path_flag;

    /* application layer path status, sync via PATH_STATUS frame */
    xqc_app_path_status_t   app_path_status;
    xqc_app_path_status_t   next_app_path_state;
    uint64_t                app_path_status_send_seq_num;
    uint64_t                app_path_status_recv_seq_num;

    xqc_usec_t              last_app_path_status_changed_time;

    /* Path cc & ack tracking */
    xqc_send_ctl_t     *path_send_ctl;
    xqc_pn_ctl_t       *path_pn_ctl;

    /* path send buffer, used to store packets scheduled to this path */
    xqc_list_head_t     path_schedule_buf[XQC_SEND_TYPE_N];
    uint32_t            path_schedule_bytes;
    xqc_list_head_t     path_reinj_tmp_buf;

    /* related structs */
    xqc_connection_t   *parent_conn;
    xqc_list_head_t     path_list;

    /* Path_metrics */
    xqc_path_metrics_t  path_metrics;
    xqc_usec_t          path_create_time;
    xqc_usec_t          path_destroy_time;

    /* path backup mode */
    uint32_t            standby_probe_count;
    uint32_t            app_path_status_changed_count;

    /* PTMUD */
    size_t              curr_pkt_out_size;
    size_t              path_max_pkt_out_size;
};

/* 埋点路径信息 */
/* 区别于xquic.h的xqc_path_metrics_t，填在conn_stat的conn_info字段里 */
typedef struct {
    uint64_t            path_id;
    uint8_t             path_state;
    uint8_t             app_path_status;

    uint64_t            path_bytes_send;
    uint64_t            path_bytes_recv;
    
    uint64_t            path_create_time;
    uint64_t            path_destroy_time;
    
    uint64_t            srtt;
    uint32_t            loss_cnt;
    uint32_t            tlp_cnt;
    uint32_t            pkt_send_cnt;
    uint32_t            pkt_recv_cnt;
    uint32_t            dgram_send_cnt;
    uint32_t            dgram_recv_cnt;
    uint32_t            red_dgram_send_cnt;
    uint32_t            red_dgram_recv_cnt;

    uint32_t            standby_probe_count;
    uint32_t            app_path_status_changed_count;    
} xqc_path_info_t;

xqc_bool_t xqc_is_same_addr(const struct sockaddr *sa1, const struct sockaddr *sa2);
xqc_bool_t xqc_is_same_addr_as_any_path(xqc_connection_t *conn, const struct sockaddr *peer_addr);

xqc_int_t xqc_generate_path_challenge_data(xqc_connection_t *conn, xqc_path_ctx_t *path);

/* check mp support */
xqc_multipath_mode_t xqc_conn_enable_multipath(xqc_connection_t *conn);

/* check multipath version negotiation */
xqc_multipath_version_t xqc_conn_multipath_version_negotiation(xqc_connection_t *conn);

/* init path_list & initial path for connection */
xqc_int_t xqc_conn_init_paths_list(xqc_connection_t *conn);

/* destroy all the paths of the connection */
void xqc_conn_destroy_paths_list(xqc_connection_t *conn);

void xqc_path_schedule_buf_destroy(xqc_path_ctx_t *path);
void xqc_path_schedule_buf_pre_destroy(xqc_send_queue_t *send_queue, xqc_path_ctx_t *path);

/* create path inner */
xqc_path_ctx_t *xqc_conn_create_path_inner(xqc_connection_t *conn, 
    xqc_cid_t *scid, xqc_cid_t *dcid, xqc_app_path_status_t path_status);

/* server update client addr when recv path_challenge frame */
xqc_int_t xqc_conn_server_init_path_addr(xqc_connection_t *conn, uint64_t path_id,
    const struct sockaddr *local_addr, socklen_t local_addrlen,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen);

xqc_int_t xqc_conn_client_init_path_addr(xqc_connection_t *conn);

void xqc_set_path_state(xqc_path_ctx_t *path, xqc_path_state_t state);

/* path state: "ACTIVE" -> "CLOSING" */
xqc_int_t xqc_path_immediate_close(xqc_path_ctx_t *path);

/* path state: "ACTIVE/CLOSING/DRAINING" -> "CLOSED" */
xqc_int_t xqc_path_closed(xqc_path_ctx_t *path);

/* find path */
xqc_path_ctx_t *xqc_conn_find_path_by_path_id(xqc_connection_t *conn, uint64_t path_id);
xqc_path_ctx_t *xqc_conn_find_path_by_scid(xqc_connection_t *conn, xqc_cid_t *scid);
xqc_path_ctx_t *xqc_conn_find_path_by_dcid(xqc_connection_t *conn, xqc_cid_t *dcid);
xqc_path_ctx_t *xqc_conn_find_path_by_dcid_seq(xqc_connection_t *conn, uint64_t dcid_seq);

void xqc_path_send_buffer_append(xqc_path_ctx_t *path, xqc_packet_out_t *packet_out, xqc_list_head_t *head);
void xqc_path_send_buffer_remove(xqc_path_ctx_t *path, xqc_packet_out_t *packet_out);
void xqc_path_send_buffer_clear(xqc_connection_t *conn, xqc_path_ctx_t *path, xqc_list_head_t *head, xqc_send_type_t send_type);

xqc_int_t xqc_set_application_path_status(xqc_path_ctx_t *path, xqc_app_path_status_t status, xqc_bool_t is_tx);

/* path statistics */
void xqc_conn_path_metrics_print(xqc_connection_t *conn, xqc_conn_stats_t *stats);
void xqc_request_path_metrics_print(xqc_connection_t *conn, xqc_h3_stream_t *h3_stream, xqc_request_stats_t *stats);

void xqc_stream_path_metrics_print(xqc_connection_t *conn, xqc_stream_t *stream, char *buff, size_t buff_size);
void xqc_stream_path_metrics_on_send(xqc_connection_t *conn, xqc_packet_out_t *po);
void xqc_stream_path_metrics_on_recv(xqc_connection_t *conn, xqc_stream_t *stream, xqc_packet_in_t *pi);

xqc_msec_t xqc_path_get_idle_timeout(xqc_path_ctx_t *path);

void xqc_path_validate(xqc_path_ctx_t *path);

xqc_int_t xqc_conn_is_current_mp_version_supported(xqc_multipath_version_t mp_version);

xqc_bool_t xqc_path_is_initial_path(xqc_path_ctx_t *path);

void xqc_path_record_info(xqc_path_ctx_t *path, xqc_path_info_t *path_info);

xqc_bool_t xqc_path_is_full(xqc_path_ctx_t *path);

xqc_int_t xqc_path_standby_probe(xqc_path_ctx_t *path);

xqc_path_perf_class_t xqc_path_get_perf_class(xqc_path_ctx_t *path);

double xqc_path_recent_loss_rate(xqc_path_ctx_t *path);

#endif /* XQC_MULTIPATH_H */


