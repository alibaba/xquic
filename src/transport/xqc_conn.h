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
#include "src/tls/xqc_tls.h"


#define XQC_TOKEN_EXPIRE_DELTA (7 * 24 * 60 * 60)           /* expire in N seconds */
#define XQC_TOKEN_UPDATE_DELTA (XQC_TOKEN_EXPIRE_DELTA / 2) /* early update */

#define XQC_MAX_AVAILABLE_CID_COUNT  16

/* maximum accumulated number of xqc_engine_packet_process */
#define XQC_MAX_PACKET_PROCESS_BATCH 100

#define XQC_MAX_RECV_WINDOW (16 * 1024 * 1024)

static const uint32_t MAX_RSP_CONN_CLOSE_CNT = 3;

/* for debugging, will be deleted later */
#ifdef DEBUG_PRINT
#define XQC_DEBUG_PRINT printf("%s:%d (%s)\n", __FILE__, __LINE__, __FUNCTION__);
#else
#define XQC_DEBUG_PRINT
#endif

/* send CONNECTION_CLOSE with err */
#define XQC_CONN_ERR(conn, err) do {            \
    if ((conn)->conn_err == 0) {                \
        (conn)->conn_err = (err);               \
        (conn)->conn_flag |= XQC_CONN_FLAG_ERROR; \
        xqc_log((conn)->log, XQC_LOG_ERROR, "|conn:%p|err:0x%xi|%s|", (conn), (uint64_t)(err), xqc_conn_addr_str(conn)); \
    }                                       \
} while(0)                                  \

extern xqc_conn_settings_t default_conn_settings;
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

typedef enum {
    XQC_CONN_TYPE_SERVER,
    XQC_CONN_TYPE_CLIENT,
} xqc_conn_type_t;

#define XQC_CONN_FLAG_SHOULD_ACK (XQC_CONN_FLAG_SHOULD_ACK_INIT     \
                                  | XQC_CONN_FLAG_SHOULD_ACK_HSK    \
                                  | XQC_CONN_FLAG_SHOULD_ACK_01RTT) \

#define XQC_CONN_IMMEDIATE_CLOSE_FLAGS (XQC_CONN_FLAG_ERROR)

/* !!WARNING: to add flag, please update conn_flag_2_str */
typedef enum {
    XQC_CONN_FLAG_WAIT_WAKEUP_SHIFT,
    XQC_CONN_FLAG_HANDSHAKE_COMPLETED_SHIFT,
    XQC_CONN_FLAG_CAN_SEND_1RTT_SHIFT,
    XQC_CONN_FLAG_TICKING_SHIFT,
    XQC_CONN_FLAG_SHOULD_ACK_INIT_SHIFT,
    XQC_CONN_FLAG_SHOULD_ACK_HSK_SHIFT      = (XQC_CONN_FLAG_SHOULD_ACK_INIT_SHIFT + XQC_PNS_HSK),
    XQC_CONN_FLAG_SHOULD_ACK_01RTT_SHIFT    = (XQC_CONN_FLAG_SHOULD_ACK_INIT_SHIFT + XQC_PNS_APP_DATA),
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
    XQC_CONN_FLAG_SVR_INIT_RECVD_SHIFT,
    XQC_CONN_FLAG_NEED_RUN_SHIFT,
    XQC_CONN_FLAG_PING_SHIFT,
    XQC_CONN_FLAG_HSK_ACKED_SHIFT,
    XQC_CONN_FLAG_CANNOT_DESTROY_SHIFT,
    XQC_CONN_FLAG_HANDSHAKE_DONE_RECVD_SHIFT,
    XQC_CONN_FLAG_UPDATE_NEW_TOKEN_SHIFT,
    XQC_CONN_FLAG_VERSION_NEGOTIATION_SHIFT,
    XQC_CONN_FLAG_HANDSHAKE_CONFIRMED_SHIFT,
    XQC_CONN_FLAG_HANDSHAKE_DONE_ACKED_SHIFT,
    XQC_CONN_FLAG_ADDR_VALIDATED_SHIFT,
    XQC_CONN_FLAG_NEW_CID_RECEIVED_SHIFT,
    XQC_CONN_FLAG_LINGER_CLOSING_SHIFT,
    XQC_CONN_FLAG_RECV_RETRY_SHIFT,
    XQC_CONN_FLAG_TLS_HSK_COMPLETED_SHIFT,
    XQC_CONN_FLAG_SHIFT_NUM,
} xqc_conn_flag_shift_t;

typedef enum {
    XQC_CONN_FLAG_WAIT_WAKEUP           = 1UL << XQC_CONN_FLAG_WAIT_WAKEUP_SHIFT,
    XQC_CONN_FLAG_HANDSHAKE_COMPLETED   = 1UL << XQC_CONN_FLAG_HANDSHAKE_COMPLETED_SHIFT,
    XQC_CONN_FLAG_CAN_SEND_1RTT         = 1UL << XQC_CONN_FLAG_CAN_SEND_1RTT_SHIFT,
    XQC_CONN_FLAG_TICKING               = 1UL << XQC_CONN_FLAG_TICKING_SHIFT,
    XQC_CONN_FLAG_SHOULD_ACK_INIT       = 1UL << XQC_CONN_FLAG_SHOULD_ACK_INIT_SHIFT,
    XQC_CONN_FLAG_SHOULD_ACK_HSK        = 1UL << XQC_CONN_FLAG_SHOULD_ACK_HSK_SHIFT,
    XQC_CONN_FLAG_SHOULD_ACK_01RTT      = 1UL << XQC_CONN_FLAG_SHOULD_ACK_01RTT_SHIFT,
    XQC_CONN_FLAG_ACK_HAS_GAP           = 1UL << XQC_CONN_FLAG_ACK_HAS_GAP_SHIFT,
    XQC_CONN_FLAG_TIME_OUT              = 1UL << XQC_CONN_FLAG_TIME_OUT_SHIFT,
    XQC_CONN_FLAG_ERROR                 = 1UL << XQC_CONN_FLAG_ERROR_SHIFT,
    XQC_CONN_FLAG_DATA_BLOCKED          = 1UL << XQC_CONN_FLAG_DATA_BLOCKED_SHIFT,
    XQC_CONN_FLAG_DCID_OK               = 1UL << XQC_CONN_FLAG_DCID_OK_SHIFT,
    XQC_CONN_FLAG_TOKEN_OK              = 1UL << XQC_CONN_FLAG_TOKEN_OK_SHIFT,
    XQC_CONN_FLAG_HAS_0RTT              = 1UL << XQC_CONN_FLAG_HAS_0RTT_SHIFT,
    XQC_CONN_FLAG_0RTT_OK               = 1UL << XQC_CONN_FLAG_0RTT_OK_SHIFT,
    XQC_CONN_FLAG_0RTT_REJ              = 1UL << XQC_CONN_FLAG_0RTT_REJ_SHIFT,
    XQC_CONN_FLAG_UPPER_CONN_EXIST      = 1UL << XQC_CONN_FLAG_UPPER_CONN_EXIST_SHIFT,
    XQC_CONN_FLAG_SVR_INIT_RECVD        = 1UL << XQC_CONN_FLAG_SVR_INIT_RECVD_SHIFT,
    XQC_CONN_FLAG_NEED_RUN              = 1UL << XQC_CONN_FLAG_NEED_RUN_SHIFT,
    XQC_CONN_FLAG_PING                  = 1UL << XQC_CONN_FLAG_PING_SHIFT,
    XQC_CONN_FLAG_HSK_ACKED             = 1UL << XQC_CONN_FLAG_HSK_ACKED_SHIFT,
    XQC_CONN_FLAG_CANNOT_DESTROY        = 1UL << XQC_CONN_FLAG_CANNOT_DESTROY_SHIFT,
    XQC_CONN_FLAG_HANDSHAKE_DONE_RECVD  = 1UL << XQC_CONN_FLAG_HANDSHAKE_DONE_RECVD_SHIFT,
    XQC_CONN_FLAG_UPDATE_NEW_TOKEN      = 1UL << XQC_CONN_FLAG_UPDATE_NEW_TOKEN_SHIFT,
    XQC_CONN_FLAG_VERSION_NEGOTIATION   = 1UL << XQC_CONN_FLAG_VERSION_NEGOTIATION_SHIFT,
    XQC_CONN_FLAG_HANDSHAKE_CONFIRMED   = 1UL << XQC_CONN_FLAG_HANDSHAKE_CONFIRMED_SHIFT,
    XQC_CONN_FLAG_HANDSHAKE_DONE_ACKED  = 1UL << XQC_CONN_FLAG_HANDSHAKE_DONE_ACKED_SHIFT,
    XQC_CONN_FLAG_ADDR_VALIDATED        = 1UL << XQC_CONN_FLAG_ADDR_VALIDATED_SHIFT,
    XQC_CONN_FLAG_NEW_CID_RECEIVED      = 1UL << XQC_CONN_FLAG_NEW_CID_RECEIVED_SHIFT,
    XQC_CONN_FLAG_LINGER_CLOSING        = 1UL << XQC_CONN_FLAG_LINGER_CLOSING_SHIFT,
    XQC_CONN_FLAG_RECV_RETRY            = 1UL << XQC_CONN_FLAG_RECV_RETRY_SHIFT,
    XQC_CONN_FLAG_TLS_HSK_COMPLETED     = 1UL << XQC_CONN_FLAG_TLS_HSK_COMPLETED_SHIFT,
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

} xqc_key_update_ctx_t;

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
    unsigned char                   enc_pkt[XQC_PACKET_OUT_SIZE_EXT];
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
    xqc_conn_flag_t                 conn_flag;
    xqc_conn_type_t                 conn_type;

    /* callback function and user_data to application layer */
    xqc_transport_callbacks_t       transport_cbs;
    void                           *user_data;      /* user_data for application layer */

    /* callback function and user_data to application-layer-protocol layer */
    xqc_app_proto_callbacks_t       app_proto_cbs;
    void                           *app_proto_user_data;

    xqc_list_head_t                 undecrypt_packet_in[XQC_ENC_LEV_MAX];  /* buffer for reordered packets */
    uint32_t                        undecrypt_count[XQC_ENC_LEV_MAX];

    xqc_recv_record_t               recv_record[XQC_PNS_N]; /* record received pkt number range in a list */
    uint32_t                        ack_eliciting_pkt[XQC_PNS_N]; /* Ack-eliciting Packets received since last ack sent */

    xqc_log_t                      *log;

    xqc_send_ctl_t                 *conn_send_ctl;

    xqc_usec_t                      last_ticked_time;
    xqc_usec_t                      next_tick_time;
    xqc_usec_t                      conn_create_time;
    xqc_usec_t                      handshake_complete_time; /* record the time when the handshake ends */
    xqc_usec_t                      first_data_send_time;    /* record the time when the bidirectional stream first sent data */

    xqc_conn_flow_ctl_t             conn_flow_ctl;

    uint32_t                        wakeup_pq_index;

    uint64_t                        conn_err;

    /* for multi-path */
    xqc_path_ctx_t                 *conn_initial_path;
    xqc_list_head_t                 conn_paths_list;

    /* xqc_hs_buffer_t data buffer for crypto data from tls */
    xqc_list_head_t                 initial_crypto_data_list;
    xqc_list_head_t                 hsk_crypto_data_list;
    xqc_list_head_t                 application_crypto_data_list;

    /* only for initial level crypto data */
    xqc_list_head_t                 retry_crypto_data_buffer;

    /* for limit the length of crypto_data */
    size_t                          crypto_data_total_len;

    /* for key update */
    xqc_key_update_ctx_t            key_update_ctx;
};

const char *xqc_conn_flag_2_str(xqc_conn_flag_t conn_flag);
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

ssize_t xqc_conn_send_one_packet(xqc_connection_t *conn, xqc_packet_out_t *packet_out);
void xqc_conn_send_packets(xqc_connection_t *conn);
void xqc_conn_send_packets_batch(xqc_connection_t *conn);

xqc_int_t xqc_conn_enc_packet(xqc_connection_t *conn, xqc_packet_out_t *packet_out, 
    char *enc_pkt, size_t enc_pkt_cap, size_t *enc_pkt_len, xqc_usec_t current_time);

void xqc_conn_transmit_pto_probe_packets(xqc_connection_t *conn);
void xqc_conn_transmit_pto_probe_packets_batch(xqc_connection_t *conn);
void xqc_conn_retransmit_lost_packets(xqc_connection_t *conn);
void xqc_conn_retransmit_lost_packets_batch(xqc_connection_t *conn);
void xqc_conn_send_one_or_two_ack_elicit_pkts(xqc_connection_t *c, xqc_pkt_num_space_t pns);
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
void xqc_conn_buff_1rtt_packets(xqc_connection_t *conn);
void xqc_conn_write_buffed_1rtt_packets(xqc_connection_t *conn);
xqc_usec_t xqc_conn_next_wakeup_time(xqc_connection_t *conn);

char *xqc_conn_local_addr_str(const struct sockaddr *local_addr, socklen_t local_addrlen);
char *xqc_conn_peer_addr_str(const struct sockaddr *peer_addr, socklen_t peer_addrlen);
char *xqc_conn_addr_str(xqc_connection_t *conn);

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

static inline xqc_int_t
xqc_conn_should_ack(xqc_connection_t *conn)
{
    if (conn->conn_flag & XQC_CONN_FLAG_SHOULD_ACK) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|should_generate_ack yes|flag:%s|",
                xqc_conn_flag_2_str(conn->conn_flag));
        return 1;
    }
    return 0;
}

/* process an UDP datagram */
xqc_int_t xqc_conn_process_packet(xqc_connection_t *c, const unsigned char *packet_in_buf,
    size_t packet_in_size, xqc_usec_t recv_time);

xqc_int_t xqc_conn_check_handshake_complete(xqc_connection_t *conn);


xqc_int_t xqc_conn_check_unused_cids(xqc_connection_t *conn);
xqc_int_t xqc_conn_try_add_new_conn_id(xqc_connection_t *conn, uint64_t retire_prior_to);
xqc_int_t xqc_conn_try_retire_conn_id(xqc_connection_t *conn, uint64_t seq_num);
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

xqc_int_t xqc_conn_on_recv_retry(xqc_connection_t *conn);

/* get idle timeout in milliseconds */
xqc_msec_t xqc_conn_get_idle_timeout(xqc_connection_t *conn);

xqc_int_t xqc_conn_confirm_key_update(xqc_connection_t *conn);

#endif /* _XQC_CONN_H_INCLUDED_ */
