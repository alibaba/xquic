/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_CONN_H_INCLUDED_
#define _XQC_CONN_H_INCLUDED_

#include <openssl/ssl.h>
#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>
#include "src/transport/xqc_cid.h"
#include "src/common/xqc_log.h"
#include "src/common/xqc_log_event_callback.h"
#include "src/common/xqc_common.h"
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_recv_record.h"
#include "src/transport/xqc_defs.h"
#include "src/transport/xqc_transport_params.h"
#include "src/transport/xqc_timer.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_fec.h"
#include "src/transport/xqc_fec_scheme.h"
#include "src/tls/xqc_tls.h"
#include "src/common/xqc_list.h"

#define XQC_MAX_DATAGRAM_REDUNDANCY 2
#define XQC_MIN_DATAGRAM_REDUNDANT_PROBE_INTERVAL 30000 /* 30ms min probing interval */
#define XQC_FC_INIT_RTT 60000
#define XQC_MIN_RECV_WINDOW (63000) /* ~ 1MBps when RTT = 60ms */
#define XQC_MIN_STANDBY_RPOBE_TIMEOUT 500 /* 500ms */

#define XQC_TOKEN_EXPIRE_DELTA (7 * 24 * 60 * 60)           /* expire in N seconds */
#define XQC_TOKEN_UPDATE_DELTA (XQC_TOKEN_EXPIRE_DELTA / 2) /* early update */

/* maximum accumulated number of xqc_engine_packet_process */
#define XQC_MAX_PACKET_PROCESS_BATCH 100

#define XQC_MAX_RECV_WINDOW (16 * 1024 * 1024)

#define XQC_MP_SETTINGS_STR_LEN (30)

static const uint32_t MAX_RSP_CONN_CLOSE_CNT = 3;

/* for debugging, will be deleted later */
#ifdef DEBUG_PRINT
#define XQC_DEBUG_PRINT printf("%s:%d (%s)\n", __FILE__, __LINE__, __FUNCTION__);
#else
#define XQC_DEBUG_PRINT
#endif

#define XQC_CONN_CLOSE_MSG(conn, msg) do {          \
    if ((conn)->conn_close_msg == NULL) {           \
        (conn)->conn_close_msg = (msg);             \
    }                                               \
} while(0)                                          \

/* send CONNECTION_CLOSE with err */
#define XQC_CONN_ERR(conn, err) do {                \
    if ((conn)->conn_err == 0) {                    \
        (conn)->conn_err = (err);                   \
        XQC_CONN_CLOSE_MSG(conn, "local error");    \
        (conn)->conn_flag |= XQC_CONN_FLAG_ERROR;   \
        xqc_conn_closing(conn);                     \
        xqc_log((conn)->log, XQC_LOG_ERROR, "|conn:%p|err:0x%xi|%s|", (conn), (uint64_t)(err), xqc_conn_addr_str(conn)); \
    }                                               \
} while(0)                                          \

extern xqc_conn_settings_t internal_default_conn_settings;
extern const xqc_tls_callbacks_t xqc_conn_tls_cbs;

/* !!WARNING: to add state, please update conn_state_2_str */
typedef enum {
    /* server */
    XQC_CONN_STATE_SERVER_INIT = 0,
    XQC_CONN_STATE_SERVER_INITIAL_RECVD,
    XQC_CONN_STATE_SERVER_INITIAL_SENT,
    XQC_CONN_STATE_SERVER_HANDSHAKE_SENT,
    XQC_CONN_STATE_SERVER_HANDSHAKE_RECVD,
    /* client */
    XQC_CONN_STATE_CLIENT_INIT = 5,
    XQC_CONN_STATE_CLIENT_INITIAL_SENT,
    XQC_CONN_STATE_CLIENT_INITIAL_RECVD,
    XQC_CONN_STATE_CLIENT_HANDSHAKE_RECVD,
    XQC_CONN_STATE_CLIENT_HANDSHAKE_SENT,
    /* client & server */
    XQC_CONN_STATE_ESTABED = 10,
    XQC_CONN_STATE_CLOSING,
    XQC_CONN_STATE_DRAINING,
    XQC_CONN_STATE_CLOSED,
    XQC_CONN_STATE_N,
} xqc_conn_state_t;

#define XQC_CONN_IMMEDIATE_CLOSE_FLAGS (XQC_CONN_FLAG_ERROR)

/* !!WARNING: to add flag, please update conn_flag_2_str */
typedef enum {
    XQC_CONN_FLAG_WAIT_WAKEUP_SHIFT,
    XQC_CONN_FLAG_HANDSHAKE_COMPLETED_SHIFT,
    XQC_CONN_FLAG_CAN_SEND_1RTT_SHIFT,
    XQC_CONN_FLAG_TICKING_SHIFT,
    XQC_CONN_FLAG_ACK_HAS_GAP_SHIFT,
    XQC_CONN_FLAG_TIME_OUT_SHIFT,
    XQC_CONN_FLAG_ERROR_SHIFT,
    XQC_CONN_FLAG_DATA_BLOCKED_SHIFT,
    XQC_CONN_FLAG_DCID_OK_SHIFT,
    XQC_CONN_FLAG_TOKEN_OK_SHIFT,
    XQC_CONN_FLAG_HAS_0RTT_SHIFT,
    XQC_CONN_FLAG_0RTT_OK_SHIFT,
    XQC_CONN_FLAG_0RTT_REJ_SHIFT,
    XQC_CONN_FLAG_UPPER_CONN_EXIST_SHIFT,
    XQC_CONN_FLAG_INIT_RECVD_SHIFT,
    XQC_CONN_FLAG_NEED_RUN_SHIFT,
    XQC_CONN_FLAG_PING_SHIFT,
    XQC_CONN_FLAG_HSK_ACKED_SHIFT,
    XQC_CONN_FLAG_RESERVE_SHIFT,
    XQC_CONN_FLAG_HANDSHAKE_DONE_RECVD_SHIFT,
    XQC_CONN_FLAG_UPDATE_NEW_TOKEN_SHIFT,
    XQC_CONN_FLAG_VERSION_NEGOTIATION_SHIFT,
    XQC_CONN_FLAG_HANDSHAKE_CONFIRMED_SHIFT,
    XQC_CONN_FLAG_HANDSHAKE_DONE_ACKED_SHIFT,
    XQC_CONN_FLAG_ADDR_VALIDATED_SHIFT,
    XQC_CONN_FLAG_NEW_CID_ACKED_SHIFT,
    XQC_CONN_FLAG_LINGER_CLOSING_SHIFT,
    XQC_CONN_FLAG_RETRY_RECVD_SHIFT,
    XQC_CONN_FLAG_TLS_CH_SHIFT,
    XQC_CONN_FLAG_TLS_HSK_COMPLETED_SHIFT,
    XQC_CONN_FLAG_RECV_NEW_PATH_SHIFT,
    XQC_CONN_FLAG_VALIDATE_REBINDING_SHIFT,
    XQC_CONN_FLAG_CONN_CLOSING_NOTIFY_SHIFT,
    XQC_CONN_FLAG_CONN_CLOSING_NOTIFIED_SHIFT,
    XQC_CONN_FLAG_DGRAM_WAIT_FOR_1RTT_SHIFT,
    XQC_CONN_FLAG_LOCAL_TP_UPDATED_SHIFT,
    XQC_CONN_FLAG_PMTUD_PROBING_SHIFT,
    XQC_CONN_FLAG_NO_DGRAM_NOTIFIED_SHIFT,
    XQC_CONN_FLAG_DGRAM_MSS_NOTIFY_SHIFT,
    XQC_CONN_FLAG_MP_WAIT_SCID_SHIFT,
    XQC_CONN_FLAG_MP_WAIT_DCID_SHIFT,
    XQC_CONN_FLAG_MP_READY_NOTIFY_SHIFT,
    XQC_CONN_FLAG_HANDSHAKE_DONE_SENT_SHIFT,
    XQC_CONN_FLAG_SHIFT_NUM,
} xqc_conn_flag_shift_t;

typedef enum {
    XQC_CONN_FLAG_WAIT_WAKEUP           = 1ULL << XQC_CONN_FLAG_WAIT_WAKEUP_SHIFT,
    XQC_CONN_FLAG_HANDSHAKE_COMPLETED   = 1ULL << XQC_CONN_FLAG_HANDSHAKE_COMPLETED_SHIFT,
    XQC_CONN_FLAG_CAN_SEND_1RTT         = 1ULL << XQC_CONN_FLAG_CAN_SEND_1RTT_SHIFT,
    XQC_CONN_FLAG_TICKING               = 1ULL << XQC_CONN_FLAG_TICKING_SHIFT,
    XQC_CONN_FLAG_ACK_HAS_GAP           = 1ULL << XQC_CONN_FLAG_ACK_HAS_GAP_SHIFT,
    XQC_CONN_FLAG_TIME_OUT              = 1ULL << XQC_CONN_FLAG_TIME_OUT_SHIFT,
    XQC_CONN_FLAG_ERROR                 = 1ULL << XQC_CONN_FLAG_ERROR_SHIFT,
    XQC_CONN_FLAG_DATA_BLOCKED          = 1ULL << XQC_CONN_FLAG_DATA_BLOCKED_SHIFT,
    XQC_CONN_FLAG_DCID_OK               = 1ULL << XQC_CONN_FLAG_DCID_OK_SHIFT,
    XQC_CONN_FLAG_TOKEN_OK              = 1ULL << XQC_CONN_FLAG_TOKEN_OK_SHIFT,
    XQC_CONN_FLAG_HAS_0RTT              = 1ULL << XQC_CONN_FLAG_HAS_0RTT_SHIFT,
    XQC_CONN_FLAG_0RTT_OK               = 1ULL << XQC_CONN_FLAG_0RTT_OK_SHIFT,
    XQC_CONN_FLAG_0RTT_REJ              = 1ULL << XQC_CONN_FLAG_0RTT_REJ_SHIFT,
    XQC_CONN_FLAG_UPPER_CONN_EXIST      = 1ULL << XQC_CONN_FLAG_UPPER_CONN_EXIST_SHIFT,
    XQC_CONN_FLAG_INIT_RECVD            = 1ULL << XQC_CONN_FLAG_INIT_RECVD_SHIFT,
    XQC_CONN_FLAG_NEED_RUN              = 1ULL << XQC_CONN_FLAG_NEED_RUN_SHIFT,
    XQC_CONN_FLAG_PING                  = 1ULL << XQC_CONN_FLAG_PING_SHIFT,
    XQC_CONN_FLAG_HSK_ACKED             = 1ULL << XQC_CONN_FLAG_HSK_ACKED_SHIFT,
    XQC_CONN_FLAG_RESERVE               = 1ULL << XQC_CONN_FLAG_RESERVE_SHIFT,
    XQC_CONN_FLAG_HANDSHAKE_DONE_RECVD  = 1ULL << XQC_CONN_FLAG_HANDSHAKE_DONE_RECVD_SHIFT,
    XQC_CONN_FLAG_UPDATE_NEW_TOKEN      = 1ULL << XQC_CONN_FLAG_UPDATE_NEW_TOKEN_SHIFT,
    XQC_CONN_FLAG_VERSION_NEGOTIATION   = 1ULL << XQC_CONN_FLAG_VERSION_NEGOTIATION_SHIFT,
    XQC_CONN_FLAG_HANDSHAKE_CONFIRMED   = 1ULL << XQC_CONN_FLAG_HANDSHAKE_CONFIRMED_SHIFT,
    XQC_CONN_FLAG_HANDSHAKE_DONE_ACKED  = 1ULL << XQC_CONN_FLAG_HANDSHAKE_DONE_ACKED_SHIFT,
    XQC_CONN_FLAG_ADDR_VALIDATED        = 1ULL << XQC_CONN_FLAG_ADDR_VALIDATED_SHIFT,
    XQC_CONN_FLAG_NEW_CID_ACKED         = 1ULL << XQC_CONN_FLAG_NEW_CID_ACKED_SHIFT,
    XQC_CONN_FLAG_LINGER_CLOSING        = 1ULL << XQC_CONN_FLAG_LINGER_CLOSING_SHIFT,
    XQC_CONN_FLAG_RETRY_RECVD           = 1ULL << XQC_CONN_FLAG_RETRY_RECVD_SHIFT,
    XQC_CONN_FLAG_TLS_CH_RECVD          = 1ULL << XQC_CONN_FLAG_TLS_CH_SHIFT,
    XQC_CONN_FLAG_TLS_HSK_COMPLETED     = 1ULL << XQC_CONN_FLAG_TLS_HSK_COMPLETED_SHIFT,
    XQC_CONN_FLAG_RECV_NEW_PATH         = 1ULL << XQC_CONN_FLAG_RECV_NEW_PATH_SHIFT,
    XQC_CONN_FLAG_VALIDATE_REBINDING    = 1ULL << XQC_CONN_FLAG_VALIDATE_REBINDING_SHIFT,
    XQC_CONN_FLAG_CLOSING_NOTIFY        = 1ULL << XQC_CONN_FLAG_CONN_CLOSING_NOTIFY_SHIFT,
    XQC_CONN_FLAG_CLOSING_NOTIFIED      = 1ULL << XQC_CONN_FLAG_CONN_CLOSING_NOTIFIED_SHIFT,
    XQC_CONN_FLAG_DGRAM_WAIT_FOR_1RTT   = 1ULL << XQC_CONN_FLAG_DGRAM_WAIT_FOR_1RTT_SHIFT,
    XQC_CONN_FLAG_LOCAL_TP_UPDATED      = 1ULL << XQC_CONN_FLAG_LOCAL_TP_UPDATED_SHIFT,
    XQC_CONN_FLAG_PMTUD_PROBING         = 1ULL << XQC_CONN_FLAG_PMTUD_PROBING_SHIFT,
    XQC_CONN_FLAG_NO_DGRAM_NOTIFIED     = 1ULL << XQC_CONN_FLAG_NO_DGRAM_NOTIFIED_SHIFT,
    XQC_CONN_FLAG_DGRAM_MSS_NOTIFY      = 1ULL << XQC_CONN_FLAG_DGRAM_MSS_NOTIFY_SHIFT,
    XQC_CONN_FLAG_MP_WAIT_SCID          = 1ULL << XQC_CONN_FLAG_MP_WAIT_SCID_SHIFT,
    XQC_CONN_FLAG_MP_WAIT_DCID          = 1ULL << XQC_CONN_FLAG_MP_WAIT_DCID_SHIFT,
    XQC_CONN_FLAG_MP_READY_NOTIFY       = 1ULL << XQC_CONN_FLAG_MP_READY_NOTIFY_SHIFT,
    XQC_CONN_FLAG_HANDSHAKE_DONE_SENT   = 1ULL << XQC_CONN_FLAG_HANDSHAKE_DONE_SENT_SHIFT,

} xqc_conn_flag_t;


typedef struct {
    xqc_preferred_addr_t    preferred_address;
    xqc_usec_t              max_idle_timeout;
    uint8_t                 stateless_reset_token[XQC_STATELESS_RESET_TOKENLEN];
    uint8_t                 stateless_reset_token_present;
    uint64_t                max_udp_payload_size;
    uint64_t                max_data;
    uint64_t                max_stream_data_bidi_local;
    uint64_t                max_stream_data_bidi_remote;
    uint64_t                max_stream_data_uni;
    uint64_t                max_streams_bidi;
    uint64_t                max_streams_uni;
    uint64_t                ack_delay_exponent;
    xqc_usec_t              max_ack_delay;
    xqc_flag_t              disable_active_migration;
    uint64_t                active_connection_id_limit;
    uint64_t                no_crypto;
    uint64_t                enable_multipath;
    xqc_multipath_version_t multipath_version;
    uint16_t                max_datagram_frame_size;
    uint32_t                conn_options[XQC_CO_MAX_NUM];
    uint8_t                 conn_option_num;
    uint64_t                enable_encode_fec;
    uint64_t                enable_decode_fec;
    uint64_t                fec_max_symbol_size;
    uint64_t                fec_max_symbols_num;
    xqc_fec_schemes_e       fec_encoder_schemes[XQC_FEC_MAX_SCHEME_NUM];
    xqc_fec_schemes_e       fec_decoder_schemes[XQC_FEC_MAX_SCHEME_NUM];
    xqc_int_t               fec_encoder_schemes_num;
    xqc_int_t               fec_decoder_schemes_num;
    xqc_dgram_red_setting_e close_dgram_redundancy;
} xqc_trans_settings_t;
 

typedef struct {
    /* flow control limit */
    uint64_t                fc_max_data_can_send;
    uint64_t                fc_data_sent;
    uint64_t                fc_max_data_can_recv;
    uint64_t                fc_data_recved;
    uint64_t                fc_data_read;

    uint64_t                fc_max_streams_bidi_can_send;
    uint64_t                fc_max_streams_bidi_can_recv;
    uint64_t                fc_max_streams_uni_can_send;
    uint64_t                fc_max_streams_uni_can_recv;

    uint64_t                fc_recv_windows_size;
    xqc_usec_t              fc_last_window_update_time;
} xqc_conn_flow_ctl_t;


typedef struct {
    xqc_list_head_t list_head;
    size_t          data_len;
    char            data[];
} xqc_hs_buffer_t;

typedef struct {
    xqc_uint_t              cur_out_key_phase; /* key phase used in current sent packets */
    xqc_uint_t              next_in_key_phase; /* key phase expected in next received packets */
    xqc_uint_t              key_update_cnt;    /* number of key updates per connection */

    /* for current out key phase */
    xqc_packet_number_t     first_sent_pktno;  /* lowest packet number sent with each key phase */
    xqc_packet_number_t     first_recv_pktno;  /* lowest packet number recv with each key phase */
    uint64_t                enc_pkt_cnt;       /* number of packet encrypt with each key phase */
    xqc_usec_t              initiate_time_guard;  /* time limit for initiating next key update */

} xqc_key_update_ctx_t;

typedef struct xqc_ping_record_s {
    xqc_list_head_t list;
    uint8_t         notified;
    uint32_t        ref_cnt;
} xqc_ping_record_t;

struct xqc_connection_s {

    xqc_conn_settings_t             conn_settings;
    xqc_engine_t                   *engine;

    xqc_proto_version_t             version;
    /* set when client receives a non-VN package from server or receives a VN package and processes it */
    uint32_t                        discard_vn_flag;

    /* original destination connection id, RFC 9000, Section 7.3. */
    xqc_cid_t                       original_dcid;
    /* initial source connection id, RFC 9000, Section 7.3 */
    xqc_cid_t                       initial_scid;

    xqc_dcid_set_t                  dcid_set;
    xqc_scid_set_t                  scid_set;

    unsigned char                   peer_addr[sizeof(struct sockaddr_in6)];
    socklen_t                       peer_addrlen;

    unsigned char                   local_addr[sizeof(struct sockaddr_in6)];
    socklen_t                       local_addrlen;

    char                            addr_str[2 * (XQC_MAX_CID_LEN + INET6_ADDRSTRLEN) + 10];
    size_t                          addr_str_len;

    unsigned char                   conn_token[XQC_MAX_TOKEN_LEN];
    unsigned char                  *enc_pkt;
    size_t                          enc_pkt_cap;
    size_t                          enc_pkt_len;
    uint32_t                        conn_token_len;
    uint32_t                        zero_rtt_count;
    uint32_t                        retry_count;
    uint32_t                        conn_close_count;
    uint32_t                        packet_need_process_count; /* xqc_engine_packet_process number */

    xqc_conn_state_t                conn_state;
    xqc_memory_pool_t              *conn_pool;

    /* tls instance for tls handshake and data encryption/decryption */
    xqc_tls_t                      *tls;

    xqc_id_hash_table_t            *streams_hash;
    xqc_id_hash_table_t            *passive_streams_hash;
    xqc_list_head_t                 conn_write_streams,
                                    conn_read_streams, /* xqc_stream_t */
                                    conn_closing_streams,
                                    conn_all_streams;
    xqc_stream_t                   *crypto_stream[XQC_ENC_LEV_MAX];
    uint64_t                        cur_stream_id_bidi_local;
    uint64_t                        cur_stream_id_uni_local;
    int64_t                         max_stream_id_bidi_remote;
    int64_t                         max_stream_id_uni_remote;

    xqc_trans_settings_t            local_settings;
    xqc_trans_settings_t            remote_settings;

    /* a bitmap to record if ACKs should be generated for path[pns] */
    uint64_t                        ack_flag;
    xqc_conn_flag_t                 conn_flag;
    xqc_conn_type_t                 conn_type;

    /* callback function and user_data to application layer */
    xqc_transport_callbacks_t       transport_cbs;
    void                           *user_data;      /* user_data for application layer */

    /* callback function and user_data to application-layer-protocol layer */
    char                           *alpn;
    size_t                          alpn_len;
    xqc_app_proto_callbacks_t       app_proto_cbs;
    void                           *proto_data;

    void                           *dgram_data;

    xqc_list_head_t                 undecrypt_packet_in[XQC_ENC_LEV_MAX];  /* buffer for reordered packets */
    uint32_t                        undecrypt_count[XQC_ENC_LEV_MAX];

    xqc_log_t                      *log;

    xqc_send_queue_t               *conn_send_queue;

    xqc_timer_manager_t             conn_timer_manager;

    xqc_usec_t                      last_ticked_time;
    xqc_usec_t                      next_tick_time;
    xqc_usec_t                      conn_create_time;
    xqc_usec_t                      handshake_complete_time; /* record the time when the handshake ends */
    xqc_usec_t                      first_data_send_time;    /* record the time when the bidirectional stream first sent data */
    xqc_usec_t                      conn_close_recv_time;
    xqc_usec_t                      conn_close_send_time;
    xqc_usec_t                      conn_last_send_time;
    xqc_usec_t                      conn_last_recv_time;
    xqc_usec_t                      conn_hsk_recv_time;

    xqc_conn_flow_ctl_t             conn_flow_ctl;

    uint32_t                        wakeup_pq_index;

    uint64_t                        conn_err;
    const char                     *conn_close_msg;

    /* for multi-path */
    xqc_multipath_mode_t            enable_multipath;
    xqc_path_ctx_t                 *conn_initial_path;
    xqc_list_head_t                 conn_paths_list;
    uint64_t                        validating_path_id;
    uint32_t                        create_path_count;
    uint32_t                        validated_path_count;
    uint32_t                        active_path_count;

    /* for qlog */
    uint32_t                        MTU_updated_count;    
    uint32_t                        packet_dropped_count;
    
    
    const
    xqc_scheduler_callback_t       *scheduler_callback;
    void                           *scheduler;

    const
    xqc_reinj_ctl_callback_t       *reinj_callback;
    void                           *reinj_ctl;

    /* xqc_hs_buffer_t data buffer for crypto data from tls */
    xqc_list_head_t                 initial_crypto_data_list;
    xqc_list_head_t                 hsk_crypto_data_list;
    xqc_list_head_t                 application_crypto_data_list;

    /* for limit the length of crypto_data */
    size_t                          crypto_data_total_len;

    /* for key update */
    xqc_key_update_ctx_t            key_update_ctx;

    /* for data callback mode, instead of write_socket/write_mmsg */
    xqc_conn_pkt_filter_callback_pt pkt_filter_cb;
    void                           *pkt_filter_cb_user_data;

    /* for datagram */
    uint64_t                        next_dgram_id;
    xqc_list_head_t                 dgram_0rtt_buffer_list;
    uint16_t                        dgram_mss;

    struct {
        uint32_t                    total_dgram;
        uint32_t                    hp_dgram;
        uint32_t                    hp_red_dgram;
        uint32_t                    hp_red_dgram_mp;
        uint32_t                    timer_red_dgram;
    } dgram_stats;

    struct {
        uint64_t                    send_bytes;
        uint64_t                    reinjected_bytes;
        uint64_t                    recv_bytes;
    } stream_stats;         

    xqc_gp_timer_id_t               dgram_probe_timer;
    xqc_var_buf_t                  *last_dgram;

    /* min pkt_out_size across all paths */
    size_t                          pkt_out_size;
    size_t                          max_pkt_out_size;
    size_t                          probing_pkt_out_size;
    uint32_t                        probing_cnt;

    /* pending ping notification */
    xqc_list_head_t                 ping_notification_list;

    /* cc blocking stats */
    uint32_t                        sched_cc_blocked;
    uint32_t                        send_cc_blocked;

    /* internal loss detection stats */
    uint32_t                        detected_loss_cnt;

    /* max consecutive PTO cnt among all paths */
    uint16_t                        max_pto_cnt;
    uint32_t                        finished_streams;
    uint32_t                        cli_bidi_streams;
    uint32_t                        svr_bidi_streams;

    /* for fec */
    xqc_fec_ctl_t                  *fec_ctl;
    

    /* receved pkts stats */
    struct {
        xqc_pkt_type_t              pkt_types[3];
        xqc_frame_type_bit_t        pkt_frames[3];
        uint32_t                    pkt_size[3];
        uint32_t                    pkt_udp_size[3];
        int                         pkt_err[3];
        xqc_usec_t                  pkt_timestamp[3];
        xqc_packet_number_t         pkt_pn[3];
        uint8_t                     curr_index;
        uint32_t                    conn_rcvd_pkts;
        uint32_t                    conn_udp_pkts;
    } rcv_pkt_stats;

    struct {
        xqc_pkt_type_t              pkt_types[3];
        xqc_frame_type_bit_t        pkt_frames[3];
        uint32_t                    pkt_size[3];
        xqc_usec_t                  pkt_timestamp[3];
        xqc_packet_number_t         pkt_pn[3];
        uint8_t                     curr_index;
        uint32_t                    conn_sent_pkts;
    } snd_pkt_stats;
};

extern const xqc_h3_conn_settings_t default_local_h3_conn_settings;

const char *xqc_conn_flag_2_str(xqc_connection_t *conn, xqc_conn_flag_t conn_flag);
const char *xqc_conn_state_2_str(xqc_conn_state_t state);
void xqc_conn_init_flow_ctl(xqc_connection_t *conn);

xqc_connection_t *xqc_conn_create(xqc_engine_t *engine, xqc_cid_t *dcid, xqc_cid_t *scid,
    const xqc_conn_settings_t *settings, void *user_data, xqc_conn_type_t type);

xqc_connection_t *xqc_conn_server_create(xqc_engine_t *engine, const struct sockaddr *local_addr,
    socklen_t local_addrlen, const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    xqc_cid_t *dcid, xqc_cid_t *scid, xqc_conn_settings_t *settings, void *user_data);

void xqc_conn_destroy(xqc_connection_t *xc);

xqc_int_t xqc_conn_client_on_alpn(xqc_connection_t *conn, const unsigned char *alpn, size_t alpn_len);
xqc_int_t xqc_conn_server_on_alpn(xqc_connection_t *conn, const unsigned char *alpn, size_t alpn_len);

ssize_t xqc_path_send_one_packet(xqc_connection_t *conn, xqc_path_ctx_t *path, xqc_packet_out_t *packet_out);
void xqc_conn_send_packets(xqc_connection_t *conn);
void xqc_conn_send_packets_batch(xqc_connection_t *conn);

void xqc_conn_check_path_utilization(xqc_connection_t *conn);
uint64_t xqc_conn_get_unscheduled_bytes(xqc_connection_t *conn);

xqc_int_t xqc_conn_enc_packet(xqc_connection_t *conn,
    xqc_path_ctx_t *path, xqc_packet_out_t *packet_out,
    char *enc_pkt, size_t enc_pkt_cap, size_t *enc_pkt_len, xqc_usec_t current_time);

void xqc_conn_transmit_pto_probe_packets(xqc_connection_t *conn);
void xqc_conn_transmit_pto_probe_packets_batch(xqc_connection_t *conn);
void xqc_conn_retransmit_lost_packets(xqc_connection_t *conn);
void xqc_conn_retransmit_lost_packets_batch(xqc_connection_t *conn);
xqc_int_t xqc_path_send_ping_to_probe(xqc_path_ctx_t *path, xqc_pkt_num_space_t pns, xqc_path_specified_flag_t flag);
void xqc_path_send_one_or_two_ack_elicit_pkts(xqc_path_ctx_t *path, xqc_pkt_num_space_t pns);
void xqc_conn_send_one_ack_eliciting_pkt(xqc_connection_t *conn, xqc_pkt_num_space_t pns);

xqc_int_t xqc_conn_check_handshake_completed(xqc_connection_t *conn);
xqc_int_t xqc_conn_is_handshake_confirmed(xqc_connection_t *conn);
xqc_int_t xqc_conn_immediate_close(xqc_connection_t *conn);
xqc_int_t xqc_conn_send_retry(xqc_connection_t *conn, unsigned char *token, unsigned token_len);
xqc_int_t xqc_conn_version_check(xqc_connection_t *c, uint32_t version);
xqc_int_t xqc_conn_send_version_negotiation(xqc_connection_t *c);
xqc_int_t xqc_conn_check_token(xqc_connection_t *conn, const unsigned char *token, unsigned token_len);
void xqc_conn_gen_token(xqc_connection_t *conn, unsigned char *token, unsigned *token_len);
xqc_int_t xqc_conn_early_data_reject(xqc_connection_t *conn);
xqc_int_t xqc_conn_early_data_accept(xqc_connection_t *conn);
xqc_bool_t xqc_conn_is_ready_to_send_early_data(xqc_connection_t *conn);
xqc_int_t xqc_conn_handshake_complete(xqc_connection_t *conn);

xqc_int_t xqc_conn_buff_undecrypt_packet_in(xqc_packet_in_t *packet_in, xqc_connection_t *conn,
    xqc_encrypt_level_t encrypt_level);
xqc_int_t xqc_conn_process_undecrypt_packet_in(xqc_connection_t *conn, xqc_encrypt_level_t encrypt_level);
void xqc_conn_buff_1rtt_packet(xqc_connection_t *conn, xqc_packet_out_t *po);
void xqc_conn_buff_1rtt_packets(xqc_connection_t *conn);
void xqc_conn_write_buffed_1rtt_packets(xqc_connection_t *conn);
xqc_usec_t xqc_conn_next_wakeup_time(xqc_connection_t *conn);

char *xqc_local_addr_str(xqc_engine_t *engine, const struct sockaddr *local_addr, socklen_t local_addrlen);
char *xqc_peer_addr_str(xqc_engine_t *engine, const struct sockaddr *peer_addr, socklen_t peer_addrlen);
char *xqc_conn_addr_str(xqc_connection_t *conn);
char *xqc_path_addr_str(xqc_path_ctx_t *path);

static inline void
xqc_conn_process_undecrypt_packets(xqc_connection_t *conn)
{
    /* process reordered 1RTT packets after handshake completed */
    if (conn->undecrypt_count[XQC_ENC_LEV_1RTT] > 0
        && conn->conn_flag & XQC_CONN_FLAG_HANDSHAKE_COMPLETED)
    {
        xqc_conn_process_undecrypt_packet_in(conn, XQC_ENC_LEV_1RTT);
    }

    /* process reordered 0RTT packets after 0RTT read key is installed */
    if (conn->undecrypt_count[XQC_ENC_LEV_0RTT] > 0
        && xqc_tls_is_key_ready(conn->tls, XQC_ENC_LEV_0RTT, XQC_KEY_TYPE_RX_READ))
    {
        xqc_conn_process_undecrypt_packet_in(conn, XQC_ENC_LEV_0RTT);
    }

    /* process reordered HSK packets after HSK read key is installed */
    if (conn->undecrypt_count[XQC_ENC_LEV_HSK] > 0
        && xqc_tls_is_key_ready(conn->tls, XQC_ENC_LEV_HSK, XQC_KEY_TYPE_RX_READ))
    {
        xqc_conn_process_undecrypt_packet_in(conn, XQC_ENC_LEV_HSK);
    }
}

static inline xqc_int_t
xqc_conn_has_undecrypt_packets(xqc_connection_t *conn)
{
    return conn->undecrypt_count[XQC_ENC_LEV_1RTT]
        || conn->undecrypt_count[XQC_ENC_LEV_0RTT]
        || conn->undecrypt_count[XQC_ENC_LEV_HSK];
}

/* process an UDP datagram */
xqc_int_t xqc_conn_process_packet(xqc_connection_t *c, const unsigned char *packet_in_buf,
    size_t packet_in_size, xqc_usec_t recv_time);

void xqc_conn_process_packet_recved_path(xqc_connection_t *conn, xqc_cid_t *scid, 
    size_t packet_in_size, xqc_usec_t recv_time);

xqc_int_t xqc_conn_check_handshake_complete(xqc_connection_t *conn);


xqc_int_t xqc_conn_check_unused_cids(xqc_connection_t *conn);
xqc_int_t xqc_conn_try_add_new_conn_id(xqc_connection_t *conn, uint64_t retire_prior_to);
xqc_int_t xqc_conn_check_dcid(xqc_connection_t *conn, xqc_cid_t *dcid);
void xqc_conn_destroy_cids(xqc_connection_t *conn);
xqc_int_t xqc_conn_update_user_scid(xqc_connection_t *conn, xqc_scid_set_t *scid_set);
xqc_int_t xqc_conn_set_cid_retired_ts(xqc_connection_t *conn, xqc_cid_inner_t *inner_cid);

xqc_bool_t xqc_conn_peer_complete_address_validation(xqc_connection_t *c);
xqc_bool_t xqc_conn_has_hsk_keys(xqc_connection_t *c);
void *xqc_conn_get_user_data(xqc_connection_t *c);

/* transport parameters functions */
xqc_int_t xqc_conn_get_local_transport_params(xqc_connection_t *conn,
    xqc_transport_params_t *params);
xqc_int_t xqc_conn_set_early_remote_transport_params(xqc_connection_t *conn,
    const xqc_transport_params_t *params);

xqc_int_t xqc_conn_encode_local_tp(xqc_connection_t *conn, uint8_t *dst, size_t dst_cap,
    size_t *dst_len);

xqc_int_t xqc_conn_on_recv_retry(xqc_connection_t *conn, xqc_cid_t *retry_scid);

/* get idle timeout in milliseconds */
xqc_msec_t xqc_conn_get_idle_timeout(xqc_connection_t *conn);

xqc_int_t xqc_conn_confirm_key_update(xqc_connection_t *conn);

/* from send_ctl */
void xqc_conn_decrease_unacked_stream_ref(xqc_connection_t *conn, xqc_packet_out_t *packet_out);
void xqc_conn_increase_unacked_stream_ref(xqc_connection_t *conn, xqc_packet_out_t *packet_out);
void xqc_conn_update_stream_stats_on_sent(xqc_connection_t *conn, xqc_packet_out_t *packet_out, xqc_usec_t now);

/* 选择所有path的PTO中最大的那个，作为conn的PTO，用于连接级别的定时器触发:
 * - XQC_TIMER_LINGER_CLOSE
 * - XQC_TIMER_CONN_DRAINING
 * - XQC_TIMER_KEY_UPDATE
 * - XQC_TIMER_STREAM_CLOSE
 */
xqc_usec_t xqc_conn_get_max_pto(xqc_connection_t *conn);

void xqc_conn_ptmud_probing(xqc_connection_t *conn);

/* 用于流控 */
xqc_usec_t xqc_conn_get_min_srtt(xqc_connection_t *conn, xqc_bool_t available_only);
xqc_usec_t xqc_conn_get_max_srtt(xqc_connection_t *conn);

void xqc_conn_check_app_limit(xqc_connection_t *conn);

void xqc_conn_timer_expire(xqc_connection_t *conn, xqc_usec_t now);

void xqc_conn_closing(xqc_connection_t *conn);

void xqc_conn_closing_notify(xqc_connection_t *conn);

xqc_int_t xqc_conn_send_path_challenge(xqc_connection_t *conn, xqc_path_ctx_t *path);

int xqc_conn_buff_0rtt_datagram(xqc_connection_t *conn, void *data, size_t data_len, uint64_t dgram_id, xqc_data_qos_level_t qos_level);

void xqc_conn_destroy_0rtt_datagram_buffer_list(xqc_connection_t *conn);
void xqc_conn_resend_0rtt_datagram(xqc_connection_t *conn);

xqc_gp_timer_id_t xqc_conn_register_gp_timer(xqc_connection_t *conn, char *timer_name, xqc_gp_timer_timeout_pt cb, void *user_data);

void xqc_conn_unregister_gp_timer(xqc_connection_t *conn, xqc_gp_timer_id_t gp_timer_id);

xqc_int_t xqc_conn_gp_timer_set(xqc_connection_t *conn, xqc_gp_timer_id_t gp_timer_id, xqc_usec_t expire_time);

xqc_int_t xqc_conn_gp_timer_unset(xqc_connection_t *conn, xqc_gp_timer_id_t gp_timer_id);

xqc_int_t xqc_conn_gp_timer_get_info(xqc_connection_t *conn, xqc_gp_timer_id_t gp_timer_id, xqc_bool_t *is_set, xqc_usec_t *expire_time);


void xqc_conn_schedule_packets_to_paths(xqc_connection_t *conn);

void xqc_conn_encode_transport_state(xqc_connection_t *conn, char *buf, size_t buf_sz);

static inline xqc_uint_t 
xqc_conn_get_mss(xqc_connection_t *conn) {
    return conn->pkt_out_size + XQC_ACK_SPACE;
}

xqc_int_t xqc_conn_handle_stateless_reset(xqc_connection_t *conn,
    const uint8_t *sr_token);

xqc_int_t xqc_conn_handle_deprecated_stateless_reset(xqc_connection_t *conn,
    const xqc_cid_t *scid);

void xqc_conn_try_to_update_mss(xqc_connection_t *conn);

void xqc_conn_get_stats_internal(xqc_connection_t *conn, xqc_conn_stats_t *stats);

xqc_ping_record_t* xqc_conn_create_ping_record(xqc_connection_t *conn);

void xqc_conn_destroy_ping_record(xqc_ping_record_t *pr);

void xqc_conn_destroy_ping_notification_list(xqc_connection_t *conn);

xqc_int_t xqc_conn_send_ping_internal(xqc_connection_t *conn, void *ping_user_data, xqc_bool_t notify);

void xqc_conn_encode_mp_settings(xqc_connection_t *conn, char *buf, size_t buf_sz);

xqc_int_t xqc_conn_retire_dcid_prior_to(xqc_connection_t *conn, uint64_t retire_prior_to);
void xqc_path_send_packets(xqc_connection_t *conn, xqc_path_ctx_t *path,
    xqc_list_head_t *head, int congest, xqc_send_type_t send_type);

#ifdef XQC_ENABLE_FEC
void xqc_insert_fec_packets(xqc_connection_t *conn, xqc_list_head_t *head);
void xqc_insert_fec_packets_all(xqc_connection_t *conn);
#endif
#endif /* _XQC_CONN_H_INCLUDED_ */
