/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <xquic/xquic.h>
#include <errno.h>
#include "src/http3/xqc_h3_stream.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/common/xqc_algorithm.h"
#include "src/common/xqc_common.h"
#include "src/common/xqc_malloc.h"
#include "src/common/xqc_str_hash.h"
#include "src/common/xqc_hash.h"
#include "src/common/xqc_priority_q.h"
#include "src/common/xqc_memory_pool.h"
#include "src/common/xqc_id_hash.h"
#include "src/transport/xqc_defs.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_cid.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_packet_parser.h"
#include "src/transport/xqc_utils.h"
#include "src/transport/xqc_wakeup_pq.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_reinjection.h"
#include "src/tls/xqc_tls.h"


xqc_conn_settings_t default_conn_settings = {
    .pacing_on                  = 0,
    .ping_on                    = 0,
    .so_sndbuf                  = 0,
    .sndq_packets_used_max      = 0,
    .linger                     = {.linger_on = 0, .linger_timeout = 0},
    .proto_version              = XQC_VERSION_V1,
    .init_idle_time_out         = XQC_CONN_INITIAL_IDLE_TIMEOUT,
    .idle_time_out              = XQC_CONN_DEFAULT_IDLE_TIMEOUT,
    .enable_multipath           = 0,
    .spurious_loss_detect_on    = 0,
    .anti_amplification_limit   = XQC_DEFAULT_ANTI_AMPLIFICATION_LIMIT,
    .keyupdate_pkt_threshold    = 0,
    .max_pkt_out_size           = XQC_PACKET_OUT_SIZE,
    .mp_enable_reinjection      = 0,

    .reinj_flexible_deadline_srtt_factor = 2.0,
    .reinj_hard_deadline                 = XQC_MAX_UINT64_VALUE,
    .reinj_deadline_lower_bound          = 0,

    .path_unreachable_pto_count = 6,
    .standby_path_probe_timeout = 0,
};

void
xqc_server_set_conn_settings(const xqc_conn_settings_t *settings)
{
    default_conn_settings.cong_ctrl_callback = settings->cong_ctrl_callback;
    default_conn_settings.cc_params = settings->cc_params;
    default_conn_settings.scheduler_params = settings->scheduler_params;
    default_conn_settings.pacing_on = settings->pacing_on;
    default_conn_settings.ping_on   = settings->ping_on;
    default_conn_settings.so_sndbuf = settings->so_sndbuf;
    default_conn_settings.sndq_packets_used_max = settings->sndq_packets_used_max;
    default_conn_settings.linger    = settings->linger;
    default_conn_settings.spurious_loss_detect_on = settings->spurious_loss_detect_on;

    if (settings->init_idle_time_out > 0) {
        default_conn_settings.init_idle_time_out = settings->init_idle_time_out;
    }

    if (settings->idle_time_out > 0) {
        default_conn_settings.idle_time_out = settings->idle_time_out;
    }

    if (settings->anti_amplification_limit > XQC_DEFAULT_ANTI_AMPLIFICATION_LIMIT) {
        default_conn_settings.anti_amplification_limit = settings->anti_amplification_limit;
    }

    if (xqc_check_proto_version_valid(settings->proto_version)) {
        default_conn_settings.proto_version = settings->proto_version;
    }

    default_conn_settings.keyupdate_pkt_threshold = settings->keyupdate_pkt_threshold;

    if (settings->max_pkt_out_size > default_conn_settings.max_pkt_out_size) {
        default_conn_settings.max_pkt_out_size = settings->max_pkt_out_size;
    }

    default_conn_settings.enable_multipath = settings->enable_multipath;

    default_conn_settings.scheduler_callback = settings->scheduler_callback;
    default_conn_settings.reinj_ctl_callback = settings->reinj_ctl_callback;
    default_conn_settings.mp_enable_reinjection = settings->mp_enable_reinjection;

    if (settings->reinj_flexible_deadline_srtt_factor > 0) {
        default_conn_settings.reinj_flexible_deadline_srtt_factor = settings->reinj_flexible_deadline_srtt_factor;
    }

    if (settings->reinj_hard_deadline > 0) {
        default_conn_settings.reinj_hard_deadline = settings->reinj_hard_deadline;
    }

    if (settings->reinj_deadline_lower_bound > 0) {
        default_conn_settings.reinj_deadline_lower_bound = settings->reinj_deadline_lower_bound;
    }

    if (settings->path_unreachable_pto_count > 0) {
        default_conn_settings.path_unreachable_pto_count = settings->path_unreachable_pto_count;
    }

    if (settings->standby_path_probe_timeout > 0) {
        default_conn_settings.standby_path_probe_timeout = settings->standby_path_probe_timeout;
    }
}

static const char * const xqc_conn_flag_to_str[XQC_CONN_FLAG_SHIFT_NUM] = {
    [XQC_CONN_FLAG_WAIT_WAKEUP_SHIFT]           = "WAIT_WAKEUP",
    [XQC_CONN_FLAG_HANDSHAKE_COMPLETED_SHIFT]   = "HSK_DONE",
    [XQC_CONN_FLAG_CAN_SEND_1RTT_SHIFT]         = "CAN_SEND_1RTT",
    [XQC_CONN_FLAG_TICKING_SHIFT]               = "TICKING",
    [XQC_CONN_FLAG_SHOULD_ACK_INIT_SHIFT]       = "ACK_INIT",
    [XQC_CONN_FLAG_SHOULD_ACK_HSK_SHIFT]        = "ACK_HSK",
    [XQC_CONN_FLAG_SHOULD_ACK_01RTT_SHIFT]      = "ACK_01RTT",
    [XQC_CONN_FLAG_ACK_HAS_GAP_SHIFT]           = "HAS_GAP",
    [XQC_CONN_FLAG_TIME_OUT_SHIFT]              = "TIME_OUT",
    [XQC_CONN_FLAG_ERROR_SHIFT]                 = "ERROR",
    [XQC_CONN_FLAG_DATA_BLOCKED_SHIFT]          = "DATA_BLOCKED",
    [XQC_CONN_FLAG_DCID_OK_SHIFT]               = "DCID_OK",
    [XQC_CONN_FLAG_TOKEN_OK_SHIFT]              = "TOKEN_OK",
    [XQC_CONN_FLAG_HAS_0RTT_SHIFT]              = "HAS_0RTT",
    [XQC_CONN_FLAG_0RTT_OK_SHIFT]               = "0RTT_OK",
    [XQC_CONN_FLAG_0RTT_REJ_SHIFT]              = "0RTT_REJECT",
    [XQC_CONN_FLAG_UPPER_CONN_EXIST_SHIFT]      = "UPPER_CONN_EXIST",
    [XQC_CONN_FLAG_INIT_RECVD_SHIFT]            = "INIT_RECVD",
    [XQC_CONN_FLAG_NEED_RUN_SHIFT]              = "NEED_RUN",
    [XQC_CONN_FLAG_PING_SHIFT]                  = "PING",
    [XQC_CONN_FLAG_HSK_ACKED_SHIFT]             = "HSK_ACKED",
    [XQC_CONN_FLAG_RESERVE_SHIFT]               = "RESERVE",
    [XQC_CONN_FLAG_HANDSHAKE_DONE_RECVD_SHIFT]  = "HSK_DONE_RECVD",
    [XQC_CONN_FLAG_UPDATE_NEW_TOKEN_SHIFT]      = "UPDATE_NEW_TOKEN",
    [XQC_CONN_FLAG_VERSION_NEGOTIATION_SHIFT]   = "VERSION_NEGOTIATION",
    [XQC_CONN_FLAG_HANDSHAKE_CONFIRMED_SHIFT]   = "HSK_CONFIRMED",
    [XQC_CONN_FLAG_HANDSHAKE_DONE_ACKED_SHIFT]  = "HSK_DONE_ACKED",
    [XQC_CONN_FLAG_ADDR_VALIDATED_SHIFT]        = "ADDR_VALIDATED",
    [XQC_CONN_FLAG_NEW_CID_RECEIVED_SHIFT]      = "NEW_CID_RECEIVED",
    [XQC_CONN_FLAG_LINGER_CLOSING_SHIFT]        = "LINGER_CLOSING",
    [XQC_CONN_FLAG_RETRY_RECVD_SHIFT]           = "RETRY_RECVD",
    [XQC_CONN_FLAG_TLS_HSK_COMPLETED_SHIFT]     = "TLS_HSK_CMPTD",
    [XQC_CONN_FLAG_RECV_NEW_PATH_SHIFT]         = "RECV_NEW_PATH",
    [XQC_CONN_FLAG_VALIDATE_REBINDING_SHIFT]    = "VALIDATE_REBINDING",
    [XQC_CONN_FLAG_CONN_CLOSING_NOTIFY_SHIFT]   = "CLOSING_NOTIFY",
    [XQC_CONN_FLAG_CONN_CLOSING_NOTIFIED_SHIFT] = "CLOSING_NOTIFIED"
};

unsigned char g_conn_flag_buf[1024];

const char *
xqc_conn_flag_2_str(xqc_conn_flag_t conn_flag)
{
    g_conn_flag_buf[0] = '\0';
    size_t pos = 0;
    int wsize;
    for (int i = 0; i < XQC_CONN_FLAG_SHIFT_NUM; i++) {
        if (conn_flag & 1ULL << i) {
            wsize = snprintf(g_conn_flag_buf + pos, sizeof(g_conn_flag_buf) - pos, "%s ", 
                             xqc_conn_flag_to_str[i]);
            if (wsize < 0 || wsize >= sizeof(g_conn_flag_buf) - pos) {
                break;
            }
            pos += wsize;
        }
    }

    return g_conn_flag_buf;
}

static const char * const xqc_conn_state_to_str[XQC_CONN_STATE_N] = {
    [XQC_CONN_STATE_SERVER_INIT]            = "S_INIT",
    [XQC_CONN_STATE_SERVER_INITIAL_RECVD]   = "S_INITIAL_RECVD",
    [XQC_CONN_STATE_SERVER_INITIAL_SENT]    = "S_INITIAL_SENT",
    [XQC_CONN_STATE_SERVER_HANDSHAKE_SENT]  = "S_HANDSHAKE_SENT",
    [XQC_CONN_STATE_SERVER_HANDSHAKE_RECVD] = "S_HANDSHAKE_RECVD",
    [XQC_CONN_STATE_CLIENT_INIT]            = "C_INIT",
    [XQC_CONN_STATE_CLIENT_INITIAL_RECVD]   = "C_INITIAL_RECVD",
    [XQC_CONN_STATE_CLIENT_INITIAL_SENT]    = "C_INITIAL_SENT",
    [XQC_CONN_STATE_CLIENT_HANDSHAKE_SENT]  = "C_HANDSHAKE_SENT",
    [XQC_CONN_STATE_CLIENT_HANDSHAKE_RECVD] = "C_HANDSHAKE_RECVD",
    [XQC_CONN_STATE_ESTABED]                = "ESTABED",
    [XQC_CONN_STATE_CLOSING]                = "CLOSING",
    [XQC_CONN_STATE_DRAINING]               = "DRAINING",
    [XQC_CONN_STATE_CLOSED]                 = "CLOSED",
};

const char *
xqc_conn_state_2_str(xqc_conn_state_t state)
{
    return xqc_conn_state_to_str[state];
}

/* local parameter */

/**
 * set settings to default, integer parameters default to be 0,
 * while some are defined in [Transport] as non-zero values.
 * if a parameter is absent, default value below will be used.
 */
static inline void
xqc_conn_set_default_settings(xqc_trans_settings_t *settings)
{
    memset(settings, 0, sizeof(xqc_trans_settings_t));

    /* transport parameter related attributes */
    settings->max_ack_delay              = XQC_DEFAULT_MAX_ACK_DELAY;
    settings->ack_delay_exponent         = XQC_DEFAULT_ACK_DELAY_EXPONENT;
    settings->max_udp_payload_size       = XQC_DEFAULT_MAX_UDP_PAYLOAD_SIZE;
    settings->active_connection_id_limit = XQC_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT;
}

static inline void
xqc_conn_init_trans_settings(xqc_connection_t *conn)
{
    /* set local and remote settings to default */
    xqc_trans_settings_t *ls = &conn->local_settings;
    xqc_trans_settings_t *rs = &conn->remote_settings;
    xqc_conn_set_default_settings(ls);
    xqc_conn_set_default_settings(rs);

    /* set local default setting values */
    ls->max_streams_bidi = 128;
    ls->max_stream_data_bidi_remote = 16 * 1024 * 1024;
    ls->max_stream_data_bidi_local = 16 * 1024 * 1024;

    ls->max_streams_uni = 128;
    ls->max_stream_data_uni = 16 * 1024 * 1024;

    /* max_data is the sum of stream_data on all uni and bidi streams */
    ls->max_data = ls->max_streams_bidi * ls->max_stream_data_bidi_local
        + ls->max_streams_uni * ls->max_stream_data_uni;

    ls->max_idle_timeout = default_conn_settings.idle_time_out;

    ls->max_udp_payload_size = XQC_CONN_MAX_UDP_PAYLOAD_SIZE;

    ls->active_connection_id_limit = XQC_CONN_ACTIVE_CID_LIMIT;

    ls->enable_multipath = conn->conn_settings.enable_multipath;

    ls->disable_active_migration = ls->enable_multipath ? 0 : 1;
}


void 
xqc_conn_init_flow_ctl(xqc_connection_t *conn)
{
    xqc_conn_flow_ctl_t *flow_ctl = &conn->conn_flow_ctl;
    xqc_trans_settings_t * settings = & conn->local_settings;

    /* TODO: send params are inited to be zero, until zerortt inited or handshake done */
    flow_ctl->fc_max_data_can_send = 1024 * 1024; /* replace with the value specified by peer after handshake */
    flow_ctl->fc_max_streams_bidi_can_send = 16; /* replace with the value specified by peer after handshake */
    flow_ctl->fc_max_streams_uni_can_send = 16; /* replace with the value specified by peer after handshake */

    flow_ctl->fc_max_data_can_recv = settings->max_data;
    flow_ctl->fc_max_streams_bidi_can_recv = settings->max_streams_bidi;
    flow_ctl->fc_max_streams_uni_can_recv = settings->max_streams_uni;
    flow_ctl->fc_data_sent = 0;
    flow_ctl->fc_data_recved = 0;
    flow_ctl->fc_recv_windows_size = settings->max_data;
    flow_ctl->fc_last_window_update_time = 0;
}

static inline void
xqc_conn_init_key_update_ctx(xqc_connection_t *conn)
{
    xqc_key_update_ctx_t *ctx = &conn->key_update_ctx;

    ctx->cur_out_key_phase = 0;
    ctx->next_in_key_phase = 0;

    ctx->first_sent_pktno  = 0;
    ctx->first_recv_pktno  = 0;
    ctx->enc_pkt_cnt       = 0;

    ctx->initiate_time_guard   = 0;
}

static inline void
xqc_conn_init_timer_manager(xqc_connection_t *conn)
{
    xqc_timer_manager_t *timer_manager = &conn->conn_timer_manager;
    xqc_usec_t now = xqc_monotonic_timestamp();

    xqc_timer_init(timer_manager, conn->log, conn);

    xqc_timer_set(timer_manager, XQC_TIMER_CONN_IDLE, now, xqc_conn_get_idle_timeout(conn) * 1000);

    if (conn->conn_settings.ping_on
        && conn->conn_type == XQC_CONN_TYPE_CLIENT)
    {
        xqc_timer_set(timer_manager, XQC_TIMER_PING, now, XQC_PING_TIMEOUT * 1000);
    }
}

xqc_connection_t *
xqc_conn_create(xqc_engine_t *engine, xqc_cid_t *dcid, xqc_cid_t *scid,
    const xqc_conn_settings_t *settings, void *user_data, xqc_conn_type_t type)
{
    xqc_connection_t *xc = NULL;
    xqc_memory_pool_t *pool = xqc_create_pool(engine->config->conn_pool_size);
    if (pool == NULL) {
        return NULL;
    }

    xc = xqc_pcalloc(pool, sizeof(xqc_connection_t));
    if (xc == NULL) {
        goto fail;
    }

    xc->conn_settings = *settings;

    if (xc->conn_settings.max_pkt_out_size < default_conn_settings.max_pkt_out_size) {
        xc->conn_settings.max_pkt_out_size = default_conn_settings.max_pkt_out_size;
    }

    xc->version = (type == XQC_CONN_TYPE_CLIENT) ? settings->proto_version : XQC_IDRAFT_INIT_VER;

    if (type == XQC_CONN_TYPE_CLIENT
        && !xqc_check_proto_version_valid(settings->proto_version)) 
    {
        xc->conn_settings.proto_version = XQC_VERSION_V1;
        xc->version = XQC_VERSION_V1;
    }

    /* make sure a 0-value config will not result in immediate timeout */
    if (xc->conn_settings.init_idle_time_out == 0) {
        xc->conn_settings.init_idle_time_out = XQC_CONN_INITIAL_IDLE_TIMEOUT;
    }

    if (xc->conn_settings.anti_amplification_limit < XQC_DEFAULT_ANTI_AMPLIFICATION_LIMIT) {
        xc->conn_settings.anti_amplification_limit = XQC_DEFAULT_ANTI_AMPLIFICATION_LIMIT;
    }

    if (xc->conn_settings.path_unreachable_pto_count == 0) {
        xc->conn_settings.path_unreachable_pto_count = default_conn_settings.path_unreachable_pto_count;
    }

    if (xc->conn_settings.reinj_flexible_deadline_srtt_factor == 0) {
        xc->conn_settings.reinj_flexible_deadline_srtt_factor = default_conn_settings.reinj_flexible_deadline_srtt_factor;
    }

    if (xc->conn_settings.reinj_hard_deadline == 0) {
        xc->conn_settings.reinj_hard_deadline = default_conn_settings.reinj_hard_deadline;
    }

    xqc_conn_init_trans_settings(xc);
    xqc_conn_init_flow_ctl(xc);
    xqc_conn_init_key_update_ctx(xc);

    xc->conn_pool = pool;

    xqc_init_dcid_set(&xc->dcid_set);
    xqc_init_scid_set(&xc->scid_set);

    xqc_cid_copy(&(xc->dcid_set.current_dcid), dcid);
    xqc_hex_dump(xc->dcid_set.current_dcid_str, dcid->cid_buf, dcid->cid_len);
    xc->dcid_set.current_dcid_str[dcid->cid_len * 2] = '\0';
    if (xqc_cid_set_insert_cid(&xc->dcid_set.cid_set, dcid, XQC_CID_USED,
                               xc->local_settings.active_connection_id_limit))
    {
        goto fail;
    }

    xqc_cid_copy(&(xc->scid_set.user_scid), scid);
    xqc_hex_dump(xc->scid_set.original_scid_str, scid->cid_buf, scid->cid_len);
    xc->scid_set.original_scid_str[scid->cid_len * 2] = '\0';
    xc->scid_set.largest_scid_seq_num = scid->cid_seq_num;
    if (xqc_cid_set_insert_cid(&xc->scid_set.cid_set, scid, XQC_CID_USED,
                               xc->remote_settings.active_connection_id_limit))
    {
        goto fail;
    }

    xqc_cid_copy(&(xc->initial_scid), scid);

    xc->engine = engine;
    xc->log = xqc_log_init(engine->log->log_level, engine->log->log_event, engine->log->log_timestamp,
                           engine->log->log_level_name, engine->log->log_callbacks, engine->log->user_data);
    xc->log->scid = xc->scid_set.original_scid_str;
    xc->transport_cbs = engine->transport_cbs;
    xc->user_data = user_data;
    xc->discard_vn_flag = 0;
    xc->conn_type = type;
    xc->conn_flag = 0;
    xc->conn_state = (type == XQC_CONN_TYPE_SERVER) ? XQC_CONN_STATE_SERVER_INIT : XQC_CONN_STATE_CLIENT_INIT;
    xc->zero_rtt_count = 0;
    xc->conn_create_time = xqc_monotonic_timestamp();
    xc->handshake_complete_time = 0;
    xc->first_data_send_time = 0;
    xc->max_stream_id_bidi_remote = -1;
    xc->max_stream_id_uni_remote = -1;
    xc->history_path = xqc_calloc(1, sizeof(xqc_conn_path_history_t));

    for (xqc_encrypt_level_t encrypt_level = XQC_ENC_LEV_INIT; encrypt_level < XQC_ENC_LEV_MAX; encrypt_level++) {
        xc->undecrypt_count[encrypt_level] = 0;
    }

    xc->enc_pkt = xqc_malloc(xc->conn_settings.max_pkt_out_size + XQC_PACKET_OUT_EXT_SPACE);
    if (NULL == xc->enc_pkt) {
        xqc_log(xc->log, XQC_LOG_ERROR, "|malloc enc pkt buf fail");
        goto fail;
    }
    xc->enc_pkt_cap = xc->conn_settings.max_pkt_out_size + XQC_PACKET_OUT_EXT_SPACE;

    xc->conn_send_queue = xqc_send_queue_create(xc);
    if (xc->conn_send_queue == NULL) {
        goto fail;
    }

    xqc_conn_init_timer_manager(xc);

    xqc_init_list_head(&xc->conn_write_streams);
    xqc_init_list_head(&xc->conn_read_streams);
    xqc_init_list_head(&xc->conn_closing_streams);
    xqc_init_list_head(&xc->conn_all_streams);

    xqc_init_list_head(&xc->initial_crypto_data_list);
    xqc_init_list_head(&xc->hsk_crypto_data_list);
    xqc_init_list_head(&xc->application_crypto_data_list);
    for (xqc_encrypt_level_t encrypt_level = XQC_ENC_LEV_INIT; encrypt_level < XQC_ENC_LEV_MAX; encrypt_level++) {
        xqc_init_list_head(&xc->undecrypt_packet_in[encrypt_level]);
    }
    xc->crypto_data_total_len = 0;

    /* create streams_hash */
    xc->streams_hash = xqc_pcalloc(xc->conn_pool, sizeof(xqc_id_hash_table_t));
    if (xc->streams_hash == NULL) {
        goto fail;
    }

    if (xqc_id_hash_init(xc->streams_hash,
                         xqc_default_allocator,
                         engine->config->streams_hash_bucket_size) == XQC_ERROR) {
        goto fail;
    }

    xc->passive_streams_hash = xqc_pcalloc(xc->conn_pool, sizeof(xqc_id_hash_table_t));
    if (xc->passive_streams_hash == NULL) {
        goto fail;
    }

    if (xqc_id_hash_init(xc->passive_streams_hash, xqc_default_allocator,
                         engine->config->streams_hash_bucket_size) == XQC_ERROR) {
        goto fail;
    }

    /* insert into engine's conns_hash */
    if (xqc_insert_conns_hash(engine->conns_hash, xc, &xc->scid_set.user_scid)) {
        goto fail;
    }

    if (xqc_conn_init_paths_list(xc) != XQC_OK) {
        goto fail;
    }

    if (xc->conn_settings.enable_multipath != 0) {
        /* set scheduler callback (default: minRTT) */
        if (xc->conn_settings.scheduler_callback.xqc_scheduler_init) {
            xc->scheduler_callback = &xc->conn_settings.scheduler_callback;

        } else {
            xc->scheduler_callback = &xqc_minrtt_scheduler_cb;
        }

        xc->scheduler = xqc_pcalloc(xc->conn_pool, xc->scheduler_callback->xqc_scheduler_size());
        xc->scheduler_callback->xqc_scheduler_init(xc->scheduler, xc->log, &xc->conn_settings.scheduler_params);
    }

    /* set reinject control callback if reinjection enabled */
    if (xc->conn_settings.reinj_ctl_callback.xqc_reinj_ctl_init) {
        xc->reinj_callback = &xc->conn_settings.reinj_ctl_callback;
        xc->reinj_ctl = xqc_pcalloc(xc->conn_pool, xc->reinj_callback->xqc_reinj_ctl_size());
        xc->reinj_callback->xqc_reinj_ctl_init(xc->reinj_ctl, &xc->conn_settings, xc->log);
    }

    xc->pkt_filter_cb = NULL;

    xqc_log(xc->log, XQC_LOG_DEBUG, "|success|scid:%s|dcid:%s|conn:%p|",
            xqc_scid_str(&xc->scid_set.user_scid), xqc_dcid_str(&xc->dcid_set.current_dcid), xc);
    xqc_log_event(xc->log, TRA_PARAMETERS_SET, xc, XQC_LOG_LOCAL_EVENT);

    return xc;

fail:
    if (xc != NULL) {
        xqc_conn_destroy(xc);
    }
    return NULL;
}

xqc_int_t
xqc_conn_encode_local_tp(xqc_connection_t *conn, uint8_t *dst, size_t dst_cap, size_t *dst_len)
{
    xqc_transport_params_t params;
    memset(&params, 0, sizeof(xqc_transport_params_t));

    xqc_transport_params_type_t tp_type = 
        (conn->conn_type == XQC_CONN_TYPE_CLIENT ? XQC_TP_TYPE_CLIENT_HELLO :
            XQC_TP_TYPE_ENCRYPTED_EXTENSIONS);

    /* get local transport params */
    xqc_int_t ret = xqc_conn_get_local_transport_params(conn, &params);
    if (ret != XQC_OK) {
        return ret;
    }

    /* serialize transport params */
    ret = xqc_encode_transport_params(&params, tp_type, dst, dst_cap, dst_len);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|encode tls trans param error|ret:%d", ret);
        return ret;
    }

    return XQC_OK;
}


xqc_int_t
xqc_conn_create_server_tls(xqc_connection_t *conn)
{
    xqc_int_t ret;

    /* init cfg */
    xqc_tls_config_t cfg = {0};
    char tp_buf[XQC_MAX_TRANSPORT_PARAM_BUF_LEN] = {0};
    cfg.trans_params = tp_buf;

    /* encode local transport parameters, and set to tls config */
    ret = xqc_conn_encode_local_tp(conn, cfg.trans_params,
                                   XQC_MAX_TRANSPORT_PARAM_BUF_LEN, &cfg.trans_params_len);
    if (ret != XQC_OK) {
        return ret;
    }

    /* create tls instance */
    conn->tls = xqc_tls_create(conn->engine->tls_ctx, &cfg, conn->log, conn);
    if (NULL == conn->tls) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|create tls instance error");
        return -XQC_EMALLOC;
    }

    return XQC_OK;
}


xqc_connection_t *
xqc_conn_server_create(xqc_engine_t *engine, const struct sockaddr *local_addr,
    socklen_t local_addrlen, const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    xqc_cid_t *dcid, xqc_cid_t *scid, xqc_conn_settings_t *settings, void *user_data)
{
    xqc_int_t           ret;
    xqc_connection_t   *conn;
    xqc_cid_t           new_scid;

    xqc_cid_copy(&new_scid, scid);

    /*
     * Server enable cid negotiate, or client initial dcid length not equal to server config length. 
     * If use the peer's dcid as scid directly, must make sure
     * its length equals to the config cid_len, otherwise might fail
     * decoding dcid from subsequent short header packets
     */
    if (engine->config->cid_negotiate
        || new_scid.cid_len != engine->config->cid_len) 
    {
        /* server generates it's own cid */
        if (xqc_generate_cid(engine, scid, &new_scid, 0) != XQC_OK) {
            xqc_log(engine->log, XQC_LOG_ERROR, "|fail to generate_cid|");
            return NULL;
        }
    }

    conn = xqc_conn_create(engine, dcid, &new_scid, settings, user_data, XQC_CONN_TYPE_SERVER);
    if (conn == NULL) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|fail to create connection|");
        return NULL;
    }

    xqc_cid_copy(&conn->original_dcid, scid);

    if (xqc_cid_in_cid_set(&conn->scid_set.cid_set, &conn->original_dcid) == NULL) {
        /*
         * if server choose it's own cid, then if server Initial is lost,
         * and if client Initial retransmit, server might use odcid to
         * find the created conn
         */
        if (xqc_insert_conns_hash(engine->conns_hash, conn, &conn->original_dcid)) {
            goto fail;
        }

        xqc_log(conn->log, XQC_LOG_INFO, "|hash odcid conn|odcid:%s|conn:%p|",
                xqc_dcid_str(&conn->original_dcid), conn);
    }

    xqc_memcpy(conn->local_addr, local_addr, local_addrlen);
    xqc_memcpy(conn->peer_addr, peer_addr, peer_addrlen);
    conn->local_addrlen = local_addrlen;
    conn->peer_addrlen = peer_addrlen;

    ret = xqc_conn_create_server_tls(conn);
    if (ret != XQC_OK) {
        goto fail;
    }

    ret = xqc_conn_server_init_path_addr(conn, XQC_INITIAL_PATH_ID,
                                         local_addr, local_addrlen,
                                         peer_addr, peer_addrlen);
    if (ret != XQC_OK) {
        goto fail;
    }

    xqc_log(engine->log, XQC_LOG_DEBUG, "|server accept new conn|");

    if (conn->transport_cbs.server_accept) {
        if (conn->transport_cbs.server_accept(engine, conn, &conn->scid_set.user_scid, user_data) < 0) {
            xqc_log(engine->log, XQC_LOG_ERROR, "|server_accept callback return error|");
            XQC_CONN_ERR(conn, TRA_CONNECTION_REFUSED_ERROR);
            goto fail;
        }
        conn->conn_flag |= XQC_CONN_FLAG_UPPER_CONN_EXIST;
    }

    xqc_log_event(conn->log, CON_CONNECTION_STARTED, conn, XQC_LOG_REMOTE_EVENT);
    return conn;

fail:
    xqc_conn_destroy(conn);
    return NULL;
}


xqc_int_t
xqc_conn_client_on_alpn(xqc_connection_t *conn, const unsigned char *alpn, size_t alpn_len)
{
    xqc_int_t ret;

    /* set quic callbacks to quic connection */
    ret = xqc_engine_get_alpn_callbacks(conn->engine, alpn, alpn_len, &conn->app_proto_cbs);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|can't get application layer callback|ret:%d", ret);
        return ret;
    }

    return XQC_OK;
}


xqc_int_t
xqc_conn_server_on_alpn(xqc_connection_t *conn, const unsigned char *alpn, size_t alpn_len)
{
    xqc_int_t ret;

    /* set quic callbacks to quic connection */
    ret = xqc_engine_get_alpn_callbacks(conn->engine, alpn, alpn_len, &conn->app_proto_cbs);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|can't get application layer callback|ret:%d", ret);
        return ret;
    }

    /* do callback */
    if (conn->app_proto_cbs.conn_cbs.conn_create_notify) {
        if (conn->app_proto_cbs.conn_cbs.conn_create_notify(conn, &conn->scid_set.user_scid,
            conn->user_data, conn->proto_data))
        {
            XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
            return -TRA_INTERNAL_ERROR;
        }
        conn->conn_flag |= XQC_CONN_FLAG_UPPER_CONN_EXIST;
    }

    return XQC_OK;
}


void
xqc_conn_destroy(xqc_connection_t *xc)
{
    static const char  *empty           = "";
    const char         *out_alpn        = NULL;
    size_t              out_alpn_len    = 0;

    if (!xc) {
        return;
    }

    if (xc->conn_flag & XQC_CONN_FLAG_TICKING) {
        xqc_log(xc->log, XQC_LOG_ERROR, "|in XQC_CONN_FLAG_TICKING|%p|", xc);
        xc->conn_state = XQC_CONN_STATE_CLOSED;
        return;
    }

    char path_info_buff[100 * XQC_MAX_PATHS_COUNT] = {'\0'};
    xqc_path_metrics_print(xc, path_info_buff, 50 * XQC_MAX_PATHS_COUNT);

    if (xc->tls) {
        xqc_tls_get_selected_alpn(xc->tls, &out_alpn, &out_alpn_len);
    }

    if (out_alpn == NULL) {
        out_alpn = empty;
        out_alpn_len = 0;
    }

    xqc_log(xc->log, XQC_LOG_REPORT, "|%p|"
            "has_0rtt:%d|0rtt_accept:%d|token_ok:%d|handshake_time:%ui|"
            "first_send_delay:%ui|conn_persist:%ui|keyupdate_cnt:%d|err:0x%xi|close_msg:%s|%s|"
            "hsk_recv:%ui|close_recv:%ui|close_send:%ui|last_recv:%ui|last_send:%ui|"
            "mp_enable:%ud|create:%ud|validated:%ud|active:%ud|path_info:%s|alpn:%*s",
            xc,
            xc->conn_flag & XQC_CONN_FLAG_HAS_0RTT ? 1:0,
            xc->conn_flag & XQC_CONN_FLAG_0RTT_OK ? 1:0,
            xc->conn_type == XQC_CONN_TYPE_SERVER ? (xc->conn_flag & XQC_CONN_FLAG_TOKEN_OK ? 1:0) : (-1),
            (xc->handshake_complete_time > xc->conn_create_time) ? (xc->handshake_complete_time - xc->conn_create_time) : 0,
            (xc->first_data_send_time > xc->conn_create_time) ? (xc->first_data_send_time - xc->conn_create_time) : 0,
            xqc_monotonic_timestamp() - xc->conn_create_time, xc->key_update_ctx.key_update_cnt,
            xc->conn_err, xc->conn_close_msg ? : "", xqc_conn_addr_str(xc),
            xqc_calc_delay(xc->conn_hsk_recv_time, xc->conn_create_time),
            xqc_calc_delay(xc->conn_close_recv_time, xc->conn_create_time),
            xqc_calc_delay(xc->conn_close_send_time, xc->conn_create_time),
            xqc_calc_delay(xc->conn_last_recv_time, xc->conn_create_time),
            xqc_calc_delay(xc->conn_last_send_time, xc->conn_create_time),
            xc->enable_multipath, xc->create_path_count, xc->validated_path_count, xc->active_path_count,
            path_info_buff, out_alpn_len, out_alpn);
    xqc_log_event(xc->log, CON_CONNECTION_CLOSED, xc);

    if (xc->conn_flag & XQC_CONN_FLAG_WAIT_WAKEUP) {
        xqc_wakeup_pq_remove(xc->engine->conns_wait_wakeup_pq, xc);
        xc->conn_flag &= ~XQC_CONN_FLAG_WAIT_WAKEUP;
    }

    xqc_list_head_t *pos, *next;
    xqc_stream_t    *stream;
    xqc_packet_in_t *packet_in;

    /* destroy streams, must before conn_close_notify */
    xqc_list_for_each_safe(pos, next, &xc->conn_all_streams) {
        stream = xqc_list_entry(pos, xqc_stream_t, all_stream_list);
        XQC_STREAM_CLOSE_MSG(stream, "conn closed");
        xqc_destroy_stream(stream);
    }

    /* notify destruction */
    if (xc->conn_flag & XQC_CONN_FLAG_UPPER_CONN_EXIST) {
        /* ALPN negotiated, notify close through application layer protocol callback function */
        if (xc->app_proto_cbs.conn_cbs.conn_close_notify) {
            xc->app_proto_cbs.conn_cbs.conn_close_notify(xc, &xc->scid_set.user_scid,
                                                         xc->user_data,
                                                         xc->proto_data);

        } else if (xc->transport_cbs.server_refuse) {
            /* ALPN context is not initialized, ClientHello has not been received */
            xc->transport_cbs.server_refuse(xc->engine, xc, &xc->scid_set.user_scid, xc->user_data);
            xqc_log(xc->log, XQC_LOG_REPORT,
                    "|conn close notified by refuse|%s", xqc_conn_addr_str(xc));

        } else {
            xqc_log(xc->log, XQC_LOG_REPORT,
                    "|conn close event not notified|%s", xqc_conn_addr_str(xc));
        }

        xc->conn_flag &= ~XQC_CONN_FLAG_UPPER_CONN_EXIST;
    }

    xqc_send_queue_destroy(xc->conn_send_queue);

    /* free streams hash */
    if (xc->streams_hash) {
        xqc_id_hash_release(xc->streams_hash);
        xc->streams_hash = NULL;
    }

    if (xc->passive_streams_hash) {
        xqc_id_hash_release(xc->passive_streams_hash);
        xc->passive_streams_hash = NULL;
    }

    xqc_conn_destroy_paths_list(xc);

    /* remove path history */
    xqc_free((void *)xc->history_path);

    for (xqc_encrypt_level_t encrypt_level = XQC_ENC_LEV_INIT; encrypt_level < XQC_ENC_LEV_MAX; encrypt_level++) {
        xqc_list_for_each_safe(pos, next, &xc->undecrypt_packet_in[encrypt_level]) {
            packet_in = xqc_list_entry(pos, xqc_packet_in_t, pi_list);
            xqc_list_del_init(pos);
            xqc_packet_in_destroy(packet_in, xc);
        }
    }

    for (xqc_encrypt_level_t encrypt_level = XQC_ENC_LEV_INIT;
         encrypt_level < XQC_ENC_LEV_MAX; encrypt_level++)
    {
        if (xc->crypto_stream[encrypt_level]) {
            xqc_destroy_crypto_stream(xc, xc->crypto_stream[encrypt_level]);
        }
    }

    /* remove from engine's conns_hash and destroy cid_set*/
    xqc_conn_destroy_cids(xc);

    if (xc->tls) {
        xqc_tls_destroy(xc->tls);
    }

    if (xc->enc_pkt) {
        xqc_free(xc->enc_pkt);
    }

    xqc_log_release(xc->log);

    /* free pool, must be the last thing to do */
    if (xc->conn_pool) {
        xqc_destroy_pool(xc->conn_pool);
    }
}

void
xqc_conn_set_transport_user_data(xqc_connection_t *conn, void *user_data)
{
    conn->user_data = user_data;
}

void
xqc_conn_set_alp_user_data(xqc_connection_t *conn, void *user_data)
{
    conn->proto_data = user_data;
}

xqc_int_t
xqc_conn_get_peer_addr(xqc_connection_t *conn, struct sockaddr *addr, socklen_t addr_cap,
    socklen_t *peer_addr_len)
{
    if (conn->peer_addrlen > addr_cap) {
        return -XQC_ENOBUF;
    }

    *peer_addr_len = conn->peer_addrlen;
    xqc_memcpy(addr, conn->peer_addr, conn->peer_addrlen);
    return XQC_OK;
}

xqc_int_t
xqc_conn_get_local_addr(xqc_connection_t *conn, struct sockaddr *addr, socklen_t addr_cap,
    socklen_t *local_addr_len)
{
    if (conn->local_addrlen > addr_cap) {
        return -XQC_ENOBUF;
    }

    *local_addr_len = conn->local_addrlen;
    xqc_memcpy(addr, conn->local_addr, conn->local_addrlen);
    return XQC_OK;
}

/* used by upper level, shall never be invoked in xquic */
xqc_int_t
xqc_conn_send_ping(xqc_engine_t *engine, const xqc_cid_t *cid, void *ping_user_data)
{
    xqc_connection_t *conn;
    xqc_int_t ret;
    conn = xqc_engine_conns_hash_find(engine, cid, 's');
    if (!conn) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|can not find connection|cid:%s",
                xqc_scid_str(cid));
        return -XQC_ECONN_NFOUND;
    }

    if (conn->conn_state >= XQC_CONN_STATE_CLOSING) {
        return XQC_OK;
    }

    ret = xqc_write_ping_to_packet(conn, ping_user_data, XQC_TRUE);
    if (ret < 0) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|write ping error|");
        return ret;
    }

    if (!(conn->conn_flag & XQC_CONN_FLAG_TICKING)) {
        if (0 == xqc_conns_pq_push(conn->engine->conns_active_pq, conn, conn->last_ticked_time)) {
            conn->conn_flag |= XQC_CONN_FLAG_TICKING;
        }
    }

    xqc_engine_main_logic_internal(engine);
    return XQC_OK;
}

/* check whether conn should close when write_socket return XQC_SOCKET_ERROR */
xqc_bool_t
xqc_conn_should_close(xqc_connection_t *conn, xqc_path_ctx_t *path)
{
    if (!conn->enable_multipath) {
        return XQC_TRUE;
    }

    if (conn->active_path_count < 2 && path->path_state == XQC_PATH_STATE_ACTIVE) {
        return XQC_TRUE;
    }

    xqc_int_t ret;
    if (path->path_state < XQC_PATH_STATE_CLOSING) {
        ret = xqc_path_immediate_close(path);
        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_path_immediate_close error|ret:%d|", ret);
        }
    }

    return XQC_FALSE;
}


ssize_t
xqc_send_burst(xqc_connection_t *conn, xqc_path_ctx_t *path, struct iovec *iov, int cnt)
{
    ssize_t sent = 0;

    if (conn->transport_cbs.write_mmsg_ex) {
        sent = conn->transport_cbs.write_mmsg_ex(path->path_id, iov, cnt,
                                                (struct sockaddr *)path->peer_addr,
                                                path->peer_addrlen,
                                                xqc_conn_get_user_data(conn));

        if (sent < 0) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|error send mmsg|");
            if (sent == XQC_SOCKET_ERROR) {
                if (xqc_conn_should_close(conn, path)) {
                    xqc_log(conn->log, XQC_LOG_ERROR, "|socket exception, close connection|");
                    conn->conn_state = XQC_CONN_STATE_CLOSED;
                }
            }
        }

    } else {
        sent = conn->transport_cbs.write_mmsg(iov, cnt,
                                              (struct sockaddr *)conn->peer_addr,
                                              conn->peer_addrlen,
                                              xqc_conn_get_user_data(conn));
        if (sent < 0) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|error send mmsg|");
            if (sent == XQC_SOCKET_ERROR) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|socket exception, close connection|");
                conn->conn_state = XQC_CONN_STATE_CLOSED;
            }
        }
    }

    return sent;
}

xqc_int_t
xqc_check_duplicate_acked_pkt(xqc_connection_t *conn,
    xqc_packet_out_t *packet_out, xqc_send_type_t send_type)
{
    if (send_type == XQC_SEND_TYPE_RETRANS) {
        if (xqc_send_ctl_indirectly_ack_po(conn, packet_out)) {
            return XQC_TRUE;
        }
        /* If not a TLP packet, mark it LOST */
        packet_out->po_flag |= XQC_POF_LOST;
        xqc_log(conn->log, XQC_LOG_DEBUG,
                "|retransmit_lost_packets|conn:%p|pkt_num:%ui|size:%ud|pkt_type:%s|frame:%s|",
                conn, packet_out->po_pkt.pkt_num, packet_out->po_used_size,
                xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type),
                xqc_frame_type_2_str(packet_out->po_frame_types));

    } else if (send_type == XQC_SEND_TYPE_PTO_PROBE) {
        if (xqc_send_ctl_indirectly_ack_po(conn, packet_out)) {
            return XQC_TRUE;
        }
        xqc_log(conn->log, XQC_LOG_DEBUG,
                "|transmit_pto_probe_packets|conn:%p|pkt_num:%ui|size:%ud|pkt_type:%s|frame:%s|",
                conn, packet_out->po_pkt.pkt_num, packet_out->po_used_size,
                xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type),
                xqc_frame_type_2_str(packet_out->po_frame_types));

    } else if (packet_out->po_flag & XQC_POF_REINJECTED_REPLICA) {
        if (xqc_send_ctl_indirectly_ack_po(conn, packet_out)) {
            return XQC_TRUE;
        }
        xqc_log(conn->log, XQC_LOG_DEBUG,
                "|transmit_reinject_replica_packets|conn:%p|pkt_num:%ui|size:%ud|pkt_type:%s|frame:%s|",
                conn, packet_out->po_pkt.pkt_num, packet_out->po_used_size,
                xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type),
                xqc_frame_type_2_str(packet_out->po_frame_types));
    }

    return XQC_FALSE;
}


void
xqc_conn_schedule_packets(xqc_connection_t *conn,  xqc_list_head_t *head, 
    xqc_bool_t  packets_are_limited_by_cc, xqc_send_type_t send_type)
{
    ssize_t ret;

    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;
    xqc_packet_out_t *packet_out;

    xqc_list_for_each_safe(pos, next, head) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);

        /* 1. connection level not support schedule multipath */
        if (conn->enable_multipath == XQC_CONN_NOT_SUPPORT_MULTIPATH) {
            path = conn->conn_initial_path;

        /* 2. 已设置特定路径发送的包，例如：PATH_CHALLENGE PATH_RESPONSE MP_ACK(原路径ACK) */
        } else if (packet_out->po_is_path_specified) {
            path = xqc_conn_find_path_by_path_id(conn, packet_out->po_path_id);
            if ((path == NULL) || (path->path_state == XQC_PATH_STATE_CLOSED)) {
                xqc_send_queue_remove_send(&packet_out->po_list);
                xqc_send_queue_insert_free(packet_out, &conn->conn_send_queue->sndq_free_packets, conn->conn_send_queue);
                continue;
            }

            xqc_log(conn->log, XQC_LOG_DEBUG, "|specify|path:%ui|state:%d|frame_type:%s|stream_id:%ui|stream_offset:%ui|",
                    path->path_id, path->path_state, xqc_frame_type_2_str(packet_out->po_frame_types),
                    packet_out->po_stream_id, packet_out->po_stream_offset);

        /* 3. schedule packet multipath */
        } else {
            path = conn->scheduler_callback->
                   xqc_scheduler_get_path(conn->scheduler, 
                                          conn, packet_out, 
                                          packets_are_limited_by_cc, 0);
            if (path == NULL) {
                break;
            }
        }

        xqc_path_send_buffer_append(path, packet_out, &path->path_schedule_buf[send_type]);
    }
}

void
xqc_on_packets_send_burst(xqc_connection_t *conn, xqc_path_ctx_t *path, ssize_t sent, xqc_usec_t now, xqc_send_type_t send_type)
{
    xqc_list_head_t  *pos, *next;
    xqc_packet_out_t *packet_out;
    int remove_count = 0; /* remove from send */

    xqc_send_ctl_t *send_ctl = path->path_send_ctl;
    xqc_pn_ctl_t *pn_ctl = xqc_get_pn_ctl(conn, path);
    xqc_send_queue_t *send_queue = conn->conn_send_queue;

    xqc_list_for_each_safe(pos, next, &path->path_schedule_buf[send_type]) {
        if (remove_count >= sent) {
            break;
        }

        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (xqc_has_packet_number(&packet_out->po_pkt)) {
            /* count packets with pkt_num in the send control */
            if (XQC_CAN_IN_FLIGHT(packet_out->po_frame_types 
                && xqc_pacing_is_on(&send_ctl->ctl_pacing)))
            {
                xqc_pacing_on_packet_sent(&send_ctl->ctl_pacing, packet_out->po_used_size);
            }

            xqc_send_ctl_on_packet_sent(send_ctl, pn_ctl, packet_out, now, sent);
            xqc_path_send_buffer_remove(path, packet_out);
            if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
                xqc_send_queue_insert_unacked(packet_out,
                                              &send_queue->sndq_unacked_packets[packet_out->po_pkt.pkt_pns],
                                              send_queue);

            } else {
                xqc_send_queue_insert_free(packet_out, &send_queue->sndq_free_packets, send_queue);
            }
            xqc_log(conn->log, XQC_LOG_INFO,
                    "|<==|conn:%p|path:%ui|pkt_num:%ui|size:%ud|sent:%z|pkt_type:%s|frame:%s|inflight:%ud|now:%ui|",
                    conn, path->path_id, packet_out->po_pkt.pkt_num, packet_out->po_used_size, sent,
                    xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type),
                    xqc_frame_type_2_str(packet_out->po_frame_types),
                    send_ctl->ctl_bytes_in_flight, now);

        } else {
            /* packets with no packet number can't be acknowledged, hence they need no control */
            xqc_path_send_buffer_remove(path, packet_out);
            xqc_send_queue_insert_free(packet_out, &send_queue->sndq_free_packets, send_queue);
            xqc_log(conn->log, XQC_LOG_INFO, "|<==|conn:%p|size:%ud|sent:%z|pkt_type:%s|",
                    conn, packet_out->po_used_size, sent, xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type));
        }

        remove_count++;
    }
}


void
xqc_convert_pkt_0rtt_2_1rtt(xqc_connection_t *conn, xqc_packet_out_t *packet_out)
{
    /* long header to short header, directly write old buffer */
    unsigned int ori_po_used_size = packet_out->po_used_size;
    unsigned char *ori_payload = packet_out->po_payload;
    unsigned int ori_payload_len = ori_po_used_size - (packet_out->po_payload - packet_out->po_buf);

    /* convert pkt info */
    packet_out->po_pkt.pkt_pns = XQC_PNS_APP_DATA;
    packet_out->po_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;

    /* copy header */
    packet_out->po_used_size = 0;
    int ret = xqc_gen_short_packet_header(packet_out, conn->dcid_set.current_dcid.cid_buf,
                                          conn->dcid_set.current_dcid.cid_len, XQC_PKTNO_BITS, 0,
                                          conn->key_update_ctx.cur_out_key_phase);
    packet_out->po_used_size = ret;

    /* copy frame directly */
    memmove(packet_out->po_buf + ret, ori_payload, ori_payload_len);
    packet_out->po_payload = packet_out->po_buf + ret;
    packet_out->po_used_size += ori_payload_len;

    xqc_log(conn->log, XQC_LOG_DEBUG, "|0RTT to 1RTT|conn:%p|type:%d|pkt_num:%ui|pns:%d|frame:%s|", 
            conn, packet_out->po_pkt.pkt_type, packet_out->po_pkt.pkt_num, packet_out->po_pkt.pkt_pns, 
            xqc_frame_type_2_str(packet_out->po_frame_types));
}


ssize_t
xqc_path_send_burst_packets(xqc_connection_t *conn, xqc_path_ctx_t *path,
    int congest, xqc_send_type_t send_type)
{
    ssize_t           ret;
    struct iovec      iov_array[XQC_MAX_SEND_MSG_ONCE];
    char              enc_pkt_array[XQC_MAX_SEND_MSG_ONCE][XQC_CONN_MAX_UDP_PAYLOAD_SIZE];
    int               burst_cnt = 0;
    xqc_packet_out_t *packet_out;
    xqc_list_head_t  *pos, *next;
    xqc_send_ctl_t   *send_ctl = path->path_send_ctl;
    uint32_t          total_bytes_to_send = 0;

    /* process packets */
    xqc_usec_t now = xqc_monotonic_timestamp();
    xqc_list_for_each_safe(pos, next, &path->path_schedule_buf[send_type]) {
        /* process one packet */
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        iov_array[burst_cnt].iov_base = enc_pkt_array[burst_cnt];
        iov_array[burst_cnt].iov_len = XQC_CONN_MAX_UDP_PAYLOAD_SIZE;

        if (xqc_has_packet_number(&packet_out->po_pkt)) {
            if (xqc_check_duplicate_acked_pkt(conn, packet_out, send_type)) {
                continue;
            }

            /* check the anti-amplification limit, will allow a bit larger than 3x received */
            if (xqc_send_ctl_check_anti_amplification(send_ctl, total_bytes_to_send)) {
                xqc_log(conn->log, XQC_LOG_INFO,
                        "|blocked by anti amplification limit|total_sent:%ui|3*total_recv:%ui|",
                        send_ctl->ctl_bytes_send + total_bytes_to_send, 3 * send_ctl->ctl_bytes_recv);
                break;
            }

            /* check cc limit */
            if (congest
                && !xqc_send_packet_check_cc(send_ctl, packet_out, total_bytes_to_send))
            {
                break;
            }

            /* retransmit 0-RTT packets in 1-RTT if 1-RTT keys are ready. */
            if (XQC_UNLIKELY(packet_out->po_pkt.pkt_type == XQC_PTYPE_0RTT
                && conn->conn_flag & XQC_CONN_FLAG_CAN_SEND_1RTT))
            {
                xqc_convert_pkt_0rtt_2_1rtt(conn, packet_out);
            }

            /* enc packet */
            ret = xqc_conn_enc_packet(conn, path, packet_out, iov_array[burst_cnt].iov_base,
                                      XQC_CONN_MAX_UDP_PAYLOAD_SIZE, &iov_array[burst_cnt].iov_len, now);
            if (XQC_OK != ret) {
                return ret;
            }

            total_bytes_to_send += packet_out->po_used_size;

        } else {
            xqc_memcpy(iov_array[burst_cnt].iov_base, packet_out->po_buf, packet_out->po_used_size);
            iov_array[burst_cnt].iov_len = packet_out->po_used_size;
        }

        /* reach send limit, break and send packets */
        burst_cnt++;
        if (burst_cnt >= XQC_MAX_SEND_MSG_ONCE) {
            burst_cnt = XQC_MAX_SEND_MSG_ONCE;
            break;
        }
    }

    /* nothing to send, return */
    if (burst_cnt == 0) {
        return burst_cnt;
    }

    /* burst send packets */
    ret = xqc_send_burst(conn, path, iov_array, burst_cnt);
    if (ret < 0) {
        return ret;

    } else if (ret != burst_cnt) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|error send msg|sent:%ui||cnt:%d|", ret, burst_cnt);
    }

    xqc_on_packets_send_burst(conn, path, ret, now, send_type);
    return ret;
}


void
xqc_path_send_packets_batch(xqc_connection_t *conn, xqc_path_ctx_t *path,
    xqc_list_head_t *head, int congest, xqc_send_type_t send_type)
{
    ssize_t send_burst_count = 0;

    while (!(xqc_list_empty(&path->path_schedule_buf[send_type]))) {
        send_burst_count = xqc_path_send_burst_packets(conn, path, congest, send_type);
        if (send_burst_count != XQC_MAX_SEND_MSG_ONCE) {
            break;
        }
    }

    if (send_burst_count < 0) {
        xqc_path_send_buffer_clear(conn, path, head, send_type);
    }

}

void
xqc_conn_send_packets_batch(xqc_connection_t *conn)
{
    int congest;
    xqc_path_ctx_t  *path;
    xqc_list_head_t *head;
    xqc_list_head_t *pos, *next;

    congest = 0;
    head = &conn->conn_send_queue->sndq_send_packets_high_pri;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        xqc_path_send_packets_batch(conn, path, head, congest, XQC_SEND_TYPE_NORMAL_HIGH_PRI);
    }

    head = &conn->conn_send_queue->sndq_send_packets;
    congest = 1;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        xqc_path_send_packets_batch(conn, path, head, congest, XQC_SEND_TYPE_NORMAL);
    }

    return;
}


void
xqc_path_send_packets(xqc_connection_t *conn, xqc_path_ctx_t *path,
    xqc_list_head_t *head, int congest, xqc_send_type_t send_type)
{
    ssize_t ret = 0;
    xqc_list_head_t  *pos, *next;
    xqc_packet_out_t *packet_out;

    xqc_send_ctl_t *send_ctl = path->path_send_ctl;
    xqc_send_queue_t *send_queue = conn->conn_send_queue;

    xqc_list_for_each_safe(pos, next, &path->path_schedule_buf[send_type]) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);

        if (xqc_check_duplicate_acked_pkt(conn, packet_out, send_type)) {
            xqc_log(conn->log, XQC_LOG_DEBUG, "|path:%ui|canceled_bytes:%ud|reinj:%d|", path->path_id, packet_out->po_used_size, XQC_MP_PKT_REINJECTED(packet_out));
            continue;
        }

        /* check the anti-amplification limit, will allow a bit larger than 3x received */
        if (xqc_send_ctl_check_anti_amplification(send_ctl, 0)) {
            xqc_log(conn->log, XQC_LOG_INFO,
                    "|blocked by anti amplification limit|total_sent:%ui|3*total_recv:%ui|",
                    send_ctl->ctl_bytes_send, 3 * send_ctl->ctl_bytes_recv);
            break;
        }

        /* check cc limit */
        if (congest
            && !xqc_send_packet_check_cc(send_ctl, packet_out, 0))
        {
            break;
        }

        ret = xqc_path_send_one_packet(conn, path, packet_out);
        if (ret < 0) {
            break;
        }

        if (XQC_CAN_IN_FLIGHT(packet_out->po_frame_types)
            && xqc_pacing_is_on(&send_ctl->ctl_pacing))
        {
            xqc_pacing_on_packet_sent(&send_ctl->ctl_pacing, packet_out->po_used_size);
        }

        /* move send list to unacked list */
        xqc_path_send_buffer_remove(path, packet_out);
        if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
            xqc_send_queue_insert_unacked(packet_out,
                                          &send_queue->sndq_unacked_packets[packet_out->po_pkt.pkt_pns],
                                          send_queue);

        } else {
            xqc_send_queue_insert_free(packet_out, &send_queue->sndq_free_packets, send_queue);
        }
    }

    if (ret < 0) {
        xqc_path_send_buffer_clear(conn, path, head, send_type);
    }

}

void
xqc_conn_send_packets(xqc_connection_t *conn)
{
    XQC_DEBUG_PRINT

    int congest;
    xqc_path_ctx_t  *path;
    xqc_list_head_t *head;
    xqc_list_head_t *pos, *next;

     /* high priority packets are not limited by CC */
    congest = 0;
    head = &conn->conn_send_queue->sndq_send_packets_high_pri;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        xqc_path_send_packets(conn, path, head, congest, XQC_SEND_TYPE_NORMAL_HIGH_PRI);
    }

    congest = 1;
    head = &conn->conn_send_queue->sndq_send_packets;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        xqc_path_send_packets(conn, path, head, congest, XQC_SEND_TYPE_NORMAL);
    }

}

xqc_int_t
xqc_need_padding(xqc_connection_t *conn, xqc_packet_out_t *packet_out)
{
    xqc_int_t ret = XQC_FALSE;
    if (packet_out->po_pkt.pkt_pns == XQC_PNS_INIT) {
        if (conn->engine->eng_type == XQC_ENGINE_CLIENT) {
            /*
             * client MUST expand the payload of all UDP datagrams carrying
             * Initial packets to at least the smallest allowed maximum datagram
             * size of 1200 bytes
             */
            ret = XQC_TRUE;

        } else {
            /*
             * server MUST expand the payload of all UDP datagrams carrying ack-
             * eliciting Initial packets to at least the smallest allowed maximum
             * datagram size of 1200 bytes
             */
            if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)) {
                ret = XQC_TRUE;
            }
        }

    } else if ((packet_out->po_frame_types & XQC_FRAME_BIT_PATH_CHALLENGE)
               || (packet_out->po_frame_types & XQC_FRAME_BIT_PATH_RESPONSE))
    {
        return XQC_TRUE;
    }

    return ret;
}

xqc_int_t
xqc_conn_enc_packet(xqc_connection_t *conn,
    xqc_path_ctx_t *path, xqc_packet_out_t *packet_out,
    char *enc_pkt, size_t enc_pkt_cap, size_t *enc_pkt_len, xqc_usec_t current_time)
{
    /* update dcid by send path */
    xqc_short_packet_update_dcid(packet_out, path->path_dcid);


    /* pad packet if needed */
    if (xqc_need_padding(conn, packet_out)) {
        xqc_gen_padding_frame(packet_out);
    }

    /* generate packet number and update packet length, might do packet number encoding here */
    xqc_pn_ctl_t *pn_ctl = xqc_get_pn_ctl(conn, path);
    packet_out->po_pkt.pkt_num = pn_ctl->ctl_packet_number[packet_out->po_pkt.pkt_pns]++;
    xqc_write_packet_number(packet_out->po_ppktno, packet_out->po_pkt.pkt_num, XQC_PKTNO_BITS);
    xqc_long_packet_update_length(packet_out);
    xqc_short_packet_update_key_phase(packet_out, conn->key_update_ctx.cur_out_key_phase);
    xqc_short_packet_update_custom_spin_bit(packet_out);

    /* encrypt */
    xqc_int_t ret = xqc_packet_encrypt_buf(conn, packet_out, enc_pkt, enc_pkt_cap, enc_pkt_len);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|encrypt packet error|");
        conn->conn_state = XQC_CONN_STATE_CLOSED;
        return -XQC_EENCRYPT;
    }

    packet_out->po_sent_time = current_time;
    return XQC_OK;
}


/* send data with callback, and process callback errors */
ssize_t
xqc_send(xqc_connection_t *conn, xqc_path_ctx_t *path, unsigned char *data, unsigned int len)
{
    ssize_t sent;

    if (conn->pkt_filter_cb) {
        sent = conn->pkt_filter_cb(data, len, (struct sockaddr *)conn->peer_addr,
                             conn->peer_addrlen, conn->pkt_filter_cb_user_data);
        if (sent < 0) {
            xqc_log(conn->log, XQC_LOG_ERROR,  "|pkt_filter_cb error|conn:%p|"
                    "size:%ud|sent:%z|", conn, len, sent);
            return -XQC_EPACKET_FILETER_CALLBACK;
        }
        sent = len;

    } else if (conn->transport_cbs.write_socket_ex) {
        sent = conn->transport_cbs.write_socket_ex(path->path_id, data, len,
                                                   (struct sockaddr *)path->peer_addr,
                                                   path->peer_addrlen,
                                                   xqc_conn_get_user_data(conn));
        if (sent != len) {
            xqc_log(conn->log, XQC_LOG_ERROR,
                    "|write_socket error|conn:%p|size:%ud|sent:%z|", conn, len, sent);

            /* if callback return XQC_SOCKET_ERROR, close the connection */
            if (sent == XQC_SOCKET_ERROR) {
                if (xqc_conn_should_close(conn, path)) {
                    xqc_log(conn->log, XQC_LOG_ERROR, "|conn:%p|socket exception, close connection|", conn);
                    conn->conn_state = XQC_CONN_STATE_CLOSED;
                }
            }
            return -XQC_ESOCKET;
        }

    } else {
        sent = conn->transport_cbs.write_socket(data, len,
                                                (struct sockaddr *)conn->peer_addr,
                                                conn->peer_addrlen,
                                                xqc_conn_get_user_data(conn));
        if (sent != len) {
            xqc_log(conn->log, XQC_LOG_ERROR, 
                    "|write_socket error|conn:%p|size:%ud|sent:%z|", conn, len, sent);

            /* if callback return XQC_SOCKET_ERROR, close the connection */
            if (sent == XQC_SOCKET_ERROR) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|conn:%p|socket exception, close connection|", conn);
                conn->conn_state = XQC_CONN_STATE_CLOSED;
            }
            return -XQC_ESOCKET;
        }
    }

    xqc_log_event(conn->log, TRA_DATAGRAMS_SENT, sent);

    return sent;
}

/* send packets which have no packet number */
ssize_t
xqc_process_packet_without_pn(xqc_connection_t *conn, xqc_path_ctx_t *path, xqc_packet_out_t *packet_out)
{
    /* directly send to peer */
    ssize_t sent = xqc_send(conn, path, packet_out->po_buf, packet_out->po_used_size);
    xqc_log(conn->log, XQC_LOG_INFO, "|<==|conn:%p|size:%ud|sent:%z|pkt_type:%s|",
            conn, packet_out->po_used_size, sent, xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type));

    if (sent > 0) {
        xqc_log_event(conn->log, TRA_PACKET_SENT, packet_out);
    }
    return sent;
}


/* send data in packet number space */
ssize_t
xqc_send_packet_with_pn(xqc_connection_t *conn, xqc_path_ctx_t *path, xqc_packet_out_t *packet_out)
{
    /* record the send time of packet */
    xqc_usec_t now = xqc_monotonic_timestamp();
    packet_out->po_sent_time = now;

    /* send data */
    ssize_t sent = xqc_send(conn, path, conn->enc_pkt, conn->enc_pkt_len);
    if (sent != conn->enc_pkt_len) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|write_socket error|conn:%p|path:%ui|pkt_num:%ui|size:%ud|sent:%z|pkt_type:%s|frame:%s|now:%ui|",
                conn, path->path_id, packet_out->po_pkt.pkt_num, packet_out->po_used_size, sent,
                xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type),
                xqc_frame_type_2_str(packet_out->po_frame_types), now);
        return sent;

    } else {
        xqc_log(conn->log, XQC_LOG_INFO,
                "|<==|conn:%p|path:%ui|pkt_num:%ui|size:%ud|sent:%z|pkt_type:%s|frame:%s|inflight:%ud|now:%ui|stream_id:%ui|stream_offset:%ui|",
                conn, path->path_id, packet_out->po_pkt.pkt_num, packet_out->po_used_size, sent,
                xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type),
                xqc_frame_type_2_str(packet_out->po_frame_types), path->path_send_ctl->ctl_bytes_in_flight, now, packet_out->po_stream_id, packet_out->po_stream_offset);
        xqc_log_event(conn->log, TRA_PACKET_SENT, packet_out);
    }

    /* deliver packet to send control */
    xqc_pn_ctl_t *pn_ctl = xqc_get_pn_ctl(conn, path);
    pn_ctl->ctl_packet_number[packet_out->po_pkt.pkt_pns]++;
    xqc_send_ctl_on_packet_sent(path->path_send_ctl, pn_ctl, packet_out, now, sent);
    return sent;
}

ssize_t
xqc_enc_packet_with_pn(xqc_connection_t *conn, xqc_path_ctx_t *path, xqc_packet_out_t *packet_out)
{
    /* update dcid by send path */
    xqc_short_packet_update_dcid(packet_out, path->path_dcid);

    /* pad packet if needed */
    if (xqc_need_padding(conn, packet_out)) {
        xqc_gen_padding_frame(packet_out);
    }

    /*
     * 0RTT packets might be lost or retransmitted during handshake, once client get 1RTT keys,
     * it should retransmit the data with 1RTT packets instead.
     */
    if (XQC_UNLIKELY(packet_out->po_pkt.pkt_type == XQC_PTYPE_0RTT
        && conn->conn_flag & XQC_CONN_FLAG_CAN_SEND_1RTT))
    {
        xqc_convert_pkt_0rtt_2_1rtt(conn, packet_out);
    }

    /* generate packet number */
    xqc_pn_ctl_t *pn_ctl = xqc_get_pn_ctl(conn, path);
    packet_out->po_pkt.pkt_num = pn_ctl->ctl_packet_number[packet_out->po_pkt.pkt_pns];
    xqc_write_packet_number(packet_out->po_ppktno, packet_out->po_pkt.pkt_num, XQC_PKTNO_BITS);
    xqc_long_packet_update_length(packet_out);
    xqc_short_packet_update_key_phase(packet_out, conn->key_update_ctx.cur_out_key_phase);
    xqc_short_packet_update_custom_spin_bit(packet_out);

    /* encrypt packet body */
    if (xqc_packet_encrypt(conn, packet_out) < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|encrypt packet error|");
        conn->conn_state = XQC_CONN_STATE_CLOSED;
        return -XQC_EENCRYPT;
    }

    return XQC_OK;
}

/* process and send packet which has a packet number */
ssize_t
xqc_process_packet_with_pn(xqc_connection_t *conn, xqc_path_ctx_t *path, xqc_packet_out_t *packet_out)
{
    ssize_t ret = xqc_enc_packet_with_pn(conn, path, packet_out);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_enc_packet_with_pn error|");
        return ret;
    }

    /* send packet in packet number space */
    return xqc_send_packet_with_pn(conn, path, packet_out);
}


ssize_t
xqc_path_send_one_packet(xqc_connection_t *conn, xqc_path_ctx_t *path, xqc_packet_out_t *packet_out)
{
    if (xqc_has_packet_number(&packet_out->po_pkt)) {
        return xqc_process_packet_with_pn(conn, path, packet_out);

    } else {
        return xqc_process_packet_without_pn(conn, path, packet_out);
    }
}

void 
xqc_conn_check_path_utilization(xqc_connection_t *conn)
{
    if (!conn->enable_multipath) {
        return;
    }
    
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        
        if (path->path_state != XQC_PATH_STATE_ACTIVE) {
            continue;
        }

        if ((path->tra_path_status != XQC_TRA_PATH_STATUS_IN_USE) && (conn->in_use_active_path_count > 0)) {
            continue;
        }

        if (!xqc_path_is_full(path) 
            && conn->scheduler_callback->xqc_scheduler_handle_path_event)
        {
            conn->scheduler_callback->xqc_scheduler_handle_path_event(conn->scheduler, path, XQC_SCHED_EVENT_PATH_NOT_FULL, NULL);
        }

    }
}

static void 
xqc_conn_schedule_start(xqc_connection_t *conn)
{
    if (!conn->enable_multipath) {
        return;
    }

    if (conn->scheduler_callback->xqc_scheduler_handle_conn_event) {
        conn->scheduler_callback->xqc_scheduler_handle_conn_event(conn->scheduler, conn, XQC_SCHED_EVENT_CONN_ROUND_START, NULL);
    }
}

static void 
xqc_conn_schedule_end(xqc_connection_t *conn)
{
    if (!conn->enable_multipath) {
        return;
    }

    if (conn->scheduler_callback->xqc_scheduler_handle_conn_event) {
        conn->scheduler_callback->xqc_scheduler_handle_conn_event(conn->scheduler, conn, XQC_SCHED_EVENT_CONN_ROUND_FIN, NULL);
    }
}

void
xqc_conn_schedule_packets_to_paths(xqc_connection_t *conn)
{
    xqc_conn_schedule_start(conn);

    /* do neither CC nor Pacing */
    xqc_list_head_t *head = &conn->conn_send_queue->sndq_pto_probe_packets;

    xqc_conn_schedule_packets(conn, head, XQC_FALSE, XQC_SEND_TYPE_PTO_PROBE);

    head = &conn->conn_send_queue->sndq_lost_packets;
    
    xqc_conn_schedule_packets(conn, head, XQC_TRUE, XQC_SEND_TYPE_RETRANS);

    head = &conn->conn_send_queue->sndq_send_packets_high_pri;
    xqc_conn_schedule_packets(conn, head, XQC_FALSE, 
                              XQC_SEND_TYPE_NORMAL_HIGH_PRI);

    /* try to reinject unacked packets if paths still have cwnd */
    if ((conn->conn_settings.mp_enable_reinjection & XQC_REINJ_UNACK_BY_DEADLINE)
        && conn->reinj_callback
        && conn->reinj_callback->xqc_reinj_ctl_unack_queue
        && conn->reinj_callback->xqc_reinj_ctl_unack_queue(conn->reinj_ctl, 
                                                           NULL, conn))
    {
        xqc_conn_reinject_unack_packets_by_deadline(conn);
    }

    head = &conn->conn_send_queue->sndq_send_packets;
    xqc_conn_schedule_packets(conn, head, XQC_TRUE, XQC_SEND_TYPE_NORMAL);

    /* all packets are scheduled, we need to check if there are paths not fully utilized */
    xqc_conn_check_path_utilization(conn);
    xqc_conn_schedule_end(conn);

    if ((conn->conn_settings.mp_enable_reinjection & XQC_REINJ_UNACK_BY_CAPACITY)
        && xqc_list_empty(&conn->conn_send_queue->sndq_send_packets)
        && conn->reinj_callback
        && conn->reinj_callback->xqc_reinj_ctl_unack_queue
        && conn->reinj_callback->xqc_reinj_ctl_unack_queue(conn->reinj_ctl, NULL, conn))
    {
        xqc_conn_reinject_unack_packets_by_capacity(conn);
    }

}


void 
xqc_conn_transmit_pto_probe_packets(xqc_connection_t *conn)
{
    /* do neither CC nor Pacing */
    xqc_list_head_t *head = &conn->conn_send_queue->sndq_pto_probe_packets;
    int congest = 0;
    xqc_path_ctx_t  *path;
    xqc_list_head_t *pos, *next;
    
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        xqc_path_send_packets(conn, path, head, congest, XQC_SEND_TYPE_PTO_PROBE);
    }
}


void
xqc_conn_retransmit_lost_packets(xqc_connection_t *conn)
{
    xqc_list_head_t *head = &conn->conn_send_queue->sndq_lost_packets;
    int congest = 1;

    xqc_path_ctx_t  *path;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        xqc_path_send_packets(conn, path, head, congest, XQC_SEND_TYPE_RETRANS);
    }
}


void
xqc_conn_transmit_pto_probe_packets_batch(xqc_connection_t *conn)
{
    xqc_list_head_t *head = &conn->conn_send_queue->sndq_pto_probe_packets;
    int congest = 0; /* probe packets MUST NOT be blocked by the congestion controller */

    xqc_path_ctx_t *path;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        xqc_path_send_packets_batch(conn, path, head, congest, XQC_SEND_TYPE_PTO_PROBE);
    }
}

void
xqc_conn_retransmit_lost_packets_batch(xqc_connection_t *conn)
{
    xqc_list_head_t *head = &conn->conn_send_queue->sndq_lost_packets;
    int congest = 1; /* do congestion control */

    xqc_path_ctx_t *path;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        xqc_path_send_packets_batch(conn, path, head, congest, XQC_SEND_TYPE_RETRANS);
    }

}

static inline xqc_packet_out_t *
xqc_conn_gen_ping(xqc_connection_t *conn, xqc_pkt_num_space_t pns)
{
    /* convert pns to ptype */
    xqc_pkt_type_t ptype = XQC_PTYPE_NUM;
    switch (pns) {
    case XQC_PNS_INIT:
        ptype = XQC_PTYPE_INIT;
        break;

    case XQC_PNS_HSK:
        ptype = XQC_PTYPE_HSK;
        break;

    case XQC_PNS_APP_DATA:
        ptype = XQC_PTYPE_SHORT_HEADER;
        break;

    default:
        break;
    }

    /* get pkt, which is inserted into sent list */
    xqc_packet_out_t *packet_out = xqc_write_new_packet(conn, ptype);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return NULL;
    }

    /* write PING to pkt */
    xqc_int_t ret = xqc_gen_ping_frame(packet_out);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_ping_frame error|");
        xqc_maybe_recycle_packet_out(packet_out, conn);
        return NULL;
    }

    packet_out->po_user_data = NULL;
    packet_out->po_used_size += ret;

    return packet_out;
}

xqc_int_t
xqc_path_send_ping_to_probe(xqc_path_ctx_t *path, xqc_pkt_num_space_t pns)
{
    xqc_connection_t *conn = path->parent_conn;

    xqc_packet_out_t *packet_out = xqc_conn_gen_ping(conn, pns);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_EWRITE_PKT;
    }

    packet_out->po_is_path_specified = XQC_TRUE;
    packet_out->po_path_id = path->path_id;

    /* put PING into probe list, which is not limited by amplification or congestion-control */
    xqc_send_queue_remove_send(&packet_out->po_list);
    xqc_send_queue_insert_probe(&packet_out->po_list, &conn->conn_send_queue->sndq_pto_probe_packets);

    return XQC_OK;
}


void
xqc_path_send_one_or_two_ack_elicit_pkts(xqc_path_ctx_t *path, xqc_pkt_num_space_t pns)
{
    xqc_connection_t *c = path->parent_conn;
    xqc_log(c->log, XQC_LOG_DEBUG, "|send two ack-eliciting pkts|path:%ui|pns:%d|", path->path_id, pns);

    xqc_packet_out_t *packet_out;
    xqc_list_head_t *pos, *next;
    xqc_int_t ret;
    xqc_int_t probe_num = XQC_CONN_PTO_PKT_CNT_MAX;
    xqc_bool_t find_hsd = XQC_FALSE;

    if ((c->conn_type == XQC_CONN_TYPE_SERVER) && !(c->conn_flag & XQC_CONN_FLAG_HANDSHAKE_DONE_ACKED)) {
        find_hsd = XQC_TRUE;
    }

    /* if only one packet is in pns unacked list, this loop will try to send this packet again */
    while (probe_num > 0) {
        xqc_list_for_each_safe(pos, next, &c->conn_send_queue->sndq_unacked_packets[pns]) {
            packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);

            if (xqc_send_ctl_indirectly_ack_po(c, packet_out)) {
                continue;
            }

            if (packet_out->po_is_path_specified && packet_out->po_path_id != path->path_id) {
                continue;
            }

            if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)
                && XQC_NEED_REPAIR(packet_out->po_frame_types))
            {
                if (find_hsd && !(packet_out->po_frame_types & XQC_FRAME_BIT_HANDSHAKE_DONE)) {
                    continue;
                }

                packet_out->po_flag |= XQC_POF_TLP;

                xqc_log(c->log, XQC_LOG_DEBUG, "|conn:%p|path:%ui|pkt_num:%ui|size:%ud|pkt_type:%s|frame:%s|conn_state:%s|",
                        c, packet_out->po_path_id, packet_out->po_pkt.pkt_num, packet_out->po_used_size,
                        xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type),
                        xqc_frame_type_2_str(packet_out->po_frame_types),
                        xqc_conn_state_2_str(c->conn_state));

                xqc_send_ctl_decrease_inflight(c, packet_out);
                xqc_send_queue_copy_to_probe(packet_out, c->conn_send_queue, path);

                if (--probe_num == 0) {
                    break;
                }

                if (find_hsd) {
                    find_hsd = XQC_FALSE;
                    break;
                }
            }
        }

        /* no data found in PTO pns, break and send PING */
        if (XQC_CONN_PTO_PKT_CNT_MAX == probe_num) {
            if (find_hsd) {
                find_hsd = XQC_FALSE;
            } else {
                break;
            }
        }
    }

    while (probe_num > 0) {
        xqc_log(c->log, XQC_LOG_DEBUG, "|PING on PTO, cnt: %d|", probe_num);
        xqc_path_send_ping_to_probe(path, pns);
        probe_num--;
    }
}


/* used by client to break amplification limit at server, or to prove address ownership */
void
xqc_conn_send_one_ack_eliciting_pkt(xqc_connection_t *conn, xqc_pkt_num_space_t pns)
{
    /* PING will be put into send list */
    xqc_conn_gen_ping(conn, pns);
}


xqc_int_t
xqc_conn_check_handshake_completed(xqc_connection_t *conn)
{
    return ((conn->conn_flag & XQC_CONN_FLAG_HANDSHAKE_COMPLETED) != 0);
}

xqc_int_t
xqc_conn_is_handshake_confirmed(xqc_connection_t *conn)
{
    return ((conn->conn_flag & XQC_CONN_FLAG_HANDSHAKE_CONFIRMED) != 0);
}

xqc_int_t
xqc_conn_close(xqc_engine_t *engine, const xqc_cid_t *cid)
{
    xqc_int_t ret;
    xqc_connection_t *conn;

    conn = xqc_engine_conns_hash_find(engine, cid, 's');
    if (!conn) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|can not find connection|cid:%s",
                xqc_scid_str(cid));
        return -XQC_ECONN_NFOUND;
    }

    xqc_log(conn->log, XQC_LOG_INFO, "|conn:%p|state:%s|flag:%s|", conn,
            xqc_conn_state_2_str(conn->conn_state), xqc_conn_flag_2_str(conn->conn_flag));

    XQC_CONN_CLOSE_MSG(conn, "local close");

    if (conn->conn_state >= XQC_CONN_STATE_DRAINING) {
        return XQC_OK;
    }

    /* close connection after all data sent and acked or XQC_TIMER_LINGER_CLOSE timeout */
    xqc_usec_t now = xqc_monotonic_timestamp();
    xqc_usec_t pto = xqc_conn_get_max_pto(conn);
    if (conn->conn_settings.linger.linger_on && !xqc_send_queue_out_queue_empty(conn->conn_send_queue)) {
        conn->conn_flag |= XQC_CONN_FLAG_LINGER_CLOSING;
        xqc_timer_set(&conn->conn_timer_manager, XQC_TIMER_LINGER_CLOSE, now,
                      (conn->conn_settings.linger.linger_timeout ? : 3 * pto));
        goto end;
    }

    ret = xqc_conn_immediate_close(conn);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_immediate_close error|ret:%d|", ret);
        return ret;
    }

end:
    if (!(conn->conn_flag & XQC_CONN_FLAG_TICKING)) {
        if (0 == xqc_conns_pq_push(conn->engine->conns_active_pq, conn, conn->last_ticked_time)) {
            conn->conn_flag |= XQC_CONN_FLAG_TICKING;
        }
    }

    xqc_engine_wakeup_once(conn->engine);

    return XQC_OK;
}

xqc_int_t
xqc_conn_close_with_error(xqc_connection_t *conn, uint64_t err_code)
{
    XQC_CONN_ERR(conn, err_code);
    return XQC_OK;
}

xqc_int_t
xqc_conn_get_errno(xqc_connection_t *conn)
{
    return conn->conn_err;
}

xqc_int_t
xqc_conn_immediate_close(xqc_connection_t *conn)
{
    if (conn->conn_state >= XQC_CONN_STATE_DRAINING) {
        return XQC_OK;
    }

    if (!(conn->conn_flag & XQC_CONN_FLAG_INIT_RECVD)
       && conn->conn_type == XQC_CONN_TYPE_SERVER)
    {
        conn->conn_state = XQC_CONN_STATE_CLOSED;
        xqc_conn_log(conn, XQC_LOG_ERROR, "|server cannot send CONNECTION_CLOSE before initial pkt received|");
        return XQC_OK;
    }

    int ret;
    xqc_send_ctl_t *send_ctl;
    xqc_usec_t now;

    if (conn->conn_state < XQC_CONN_STATE_CLOSING) {

        xqc_log(conn->log, XQC_LOG_INFO, "|state to closing|state:%s|flags:%s",
                xqc_conn_state_2_str(conn->conn_state), xqc_conn_flag_2_str(conn->conn_flag));

        conn->conn_state = XQC_CONN_STATE_CLOSING;

        xqc_send_queue_drop_packets(conn);

        now = xqc_monotonic_timestamp();
        xqc_usec_t pto = xqc_conn_get_max_pto(conn);
        if (!xqc_timer_is_set(&conn->conn_timer_manager, XQC_TIMER_CONN_DRAINING)) {
            xqc_timer_set(&conn->conn_timer_manager, XQC_TIMER_CONN_DRAINING, now, 3 * pto);
        }


        xqc_path_ctx_t *path = NULL;
        xqc_list_head_t *pos, *next;
        xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
            path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
            for (int i = 0; i <= XQC_TIMER_LOSS_DETECTION; i++) {
                xqc_timer_unset(&path->path_send_ctl->path_timer_manager, i);
            }
        }
    }

    /*
     * [Transport] 10.3.  Immediate Close, During the closing period, an endpoint that sends a CONNECTION_CLOSE
     * frame SHOULD respond to any incoming packet that can be decrypted with another packet containing a CONNECTION_CLOSE
     * frame.  Such an endpoint SHOULD limit the number of packets it generates containing a CONNECTION_CLOSE frame.
     */
    if (conn->conn_close_count < MAX_RSP_CONN_CLOSE_CNT) {
        ret = xqc_write_conn_close_to_packet(conn, conn->conn_err);
        if (ret) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_conn_close_to_packet error|ret:%d|", ret);
        }
        ++conn->conn_close_count;
        xqc_log(conn->log, XQC_LOG_DEBUG, "|gen_conn_close|state:%s|", xqc_conn_state_2_str(conn->conn_state));
    }

    return XQC_OK;
}


xqc_int_t
xqc_conn_send_retry(xqc_connection_t *conn, unsigned char *token, unsigned token_len)
{
    xqc_engine_t *engine = conn->engine;
    unsigned char buf[XQC_PACKET_OUT_SIZE];
    xqc_int_t size = (xqc_int_t)xqc_gen_retry_packet(buf,
                                                     conn->dcid_set.current_dcid.cid_buf,
                                                     conn->dcid_set.current_dcid.cid_len,
                                                     conn->scid_set.user_scid.cid_buf,
                                                     conn->scid_set.user_scid.cid_len,
                                                     conn->original_dcid.cid_buf,
                                                     conn->original_dcid.cid_len,
                                                     token, token_len,
                                                     XQC_VERSION_V1);
    if (size < 0) {
        return size;
    }

    size = (xqc_int_t)conn->transport_cbs.write_socket(
        buf, (size_t)size, (struct sockaddr*)conn->peer_addr, conn->peer_addrlen,
        xqc_conn_get_user_data(conn));
    if (size < 0) {
        return size;
    }

    xqc_log(engine->log, XQC_LOG_INFO, "|<==|xqc_conn_send_retry ok|size:%d|", size);
    return XQC_OK;
}


xqc_int_t
xqc_conn_version_check(xqc_connection_t *c, uint32_t version)
{
    xqc_engine_t *engine = c->engine;
    int i = 0;

    if (c->conn_type == XQC_CONN_TYPE_SERVER && c->version == XQC_IDRAFT_INIT_VER) {

        uint32_t *list = engine->config->support_version_list;
        uint32_t count = engine->config->support_version_count;

        if (xqc_uint32_list_find(list, count, version) == -1) {
            return -XQC_EPROTO;
        }

        for (i = XQC_IDRAFT_INIT_VER + 1; i < XQC_IDRAFT_VER_NEGOTIATION; i++) {
            if (xqc_proto_version_value[i] == version) {
                c->version = i;

                xqc_int_t ret = xqc_tls_init(c->tls, c->version, &c->original_dcid);
                if (ret != XQC_OK) {
                    xqc_log(c->log, XQC_LOG_ERROR, "|init tls error|");
                    return ret;
                }

                return XQC_OK;
            }
        }

        return -XQC_EPROTO;
    }

    return XQC_OK;
}


xqc_int_t
xqc_conn_send_version_negotiation(xqc_connection_t *c)
{
    xqc_packet_out_t *packet_out = xqc_packet_out_get_and_insert_send(c->conn_send_queue, XQC_PTYPE_VERSION_NEGOTIATION);
    if (packet_out == NULL) {
        xqc_log(c->log, XQC_LOG_ERROR, "|get XQC_PTYPE_VERSION_NEGOTIATION error|");
        return -XQC_EWRITE_PKT;
    }

    unsigned char *p = packet_out->po_buf;
    /* first byte of packet */
    *p++ = (1 << 7);

    /* version */
    *(uint32_t *)p = 0;
    p += sizeof(uint32_t);

    /* dcid len */
    *p = c->dcid_set.current_dcid.cid_len;
    ++p;

    /* dcid */
    memcpy(p, c->dcid_set.current_dcid.cid_buf, c->dcid_set.current_dcid.cid_len);
    p += c->dcid_set.current_dcid.cid_len;

    /* original destination ID len */
    *p = c->original_dcid.cid_len;
    ++p;

    /* original destination ID */
    memcpy(p, c->original_dcid.cid_buf, c->original_dcid.cid_len);
    p += c->original_dcid.cid_len;

    /* set supported version list */
    uint32_t *version_list = c->engine->config->support_version_list;
    uint32_t version_count = c->engine->config->support_version_count;
    unsigned char *end = packet_out->po_buf + packet_out->po_buf_size;
    for (size_t i = 0; i < version_count; ++i) {
        if (p + sizeof(uint32_t) <= end) {
            *(uint32_t*)p = htonl(version_list[i]);
            p += sizeof(uint32_t);

        } else {
            break;
        }
    }

    /* set used size of packet */
    packet_out->po_used_size = p - packet_out->po_buf;

    /* push to conns queue */
    if (!(c->conn_flag & XQC_CONN_FLAG_TICKING)) {
        if (0 == xqc_conns_pq_push(c->engine->conns_active_pq, c, c->last_ticked_time)) {
            c->conn_flag |= XQC_CONN_FLAG_TICKING;
        }
    }

    c->conn_flag &= ~XQC_CONN_FLAG_VERSION_NEGOTIATION;
    return XQC_OK;
}


int
xqc_conn_continue_send(xqc_engine_t *engine, const xqc_cid_t *cid)
{
    xqc_connection_t *conn = xqc_engine_conns_hash_find(engine, cid, 's');
    if (!conn) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|can not find connection|cid:%s",
                xqc_scid_str(cid));
        return -XQC_ECONN_NFOUND;
    }
    xqc_log(conn->log, XQC_LOG_DEBUG, "|conn:%p|", conn);

    xqc_engine_main_logic_internal(conn->engine);
    return XQC_OK;
}

void
xqc_conn_info_print(xqc_connection_t *conn, xqc_conn_stats_t *conn_stats)
{
    char *buff = conn_stats->conn_info;
    size_t buff_size = XQC_CONN_INFO_LEN;
    int ret = 0;
    int record_cnt = 0;
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path = NULL;
    xqc_path_info_t path_info;

    /* path layer 自定义 */
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        xqc_path_record_info(path, &path_info);
        ret = xqc_path_info_print(&path_info, &buff, &buff_size);
        if (ret <= 0) {
            xqc_log(conn->log, XQC_LOG_WARN, "|write cur_path_info error|");
            return;
        }

        record_cnt++;
        if (record_cnt >= XQC_MAX_PATHS_COUNT) {
            return;
        }
    }

    /* history */
    int his_cnt = conn->history_path->path_cnt - 1;
    int index = 0;
    while (his_cnt >= 0 && record_cnt < XQC_MAX_PATHS_COUNT) {
        index = his_cnt % XQC_MAX_PATHS_COUNT;
        ret = xqc_path_info_print(&conn->history_path->path_info[index], &buff, &buff_size);
        if (ret <= 0) {
            xqc_log(conn->log, XQC_LOG_WARN, "|write his_path_info error|");
            return;
        }

        his_cnt--;
        record_cnt++;
    }
}

xqc_conn_stats_t
xqc_conn_get_stats(xqc_engine_t *engine, const xqc_cid_t *cid)
{
    xqc_connection_t *conn;
    xqc_conn_stats_t conn_stats;
    xqc_memzero(&conn_stats, sizeof(conn_stats));
    for (int i = 0; i < XQC_MAX_PATHS_COUNT; ++i) {
        conn_stats.paths_info[i].path_id = XQC_MAX_UINT64_VALUE;
    }

    conn = xqc_engine_conns_hash_find(engine, cid, 's');
    if (!conn) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|can not find connection|cid:%s",
                xqc_scid_str(cid));
        return conn_stats;
    }

    /* 1. 与路径无关的连接级别埋点 */
    conn_stats.conn_err = (int)conn->conn_err;
    conn_stats.early_data_flag = XQC_0RTT_NONE;
    conn_stats.enable_multipath = conn->enable_multipath;
    conn_stats.spurious_loss_detect_on = conn->conn_settings.spurious_loss_detect_on;
    if (conn->conn_flag & XQC_CONN_FLAG_HAS_0RTT) {
        if (conn->conn_flag & XQC_CONN_FLAG_0RTT_OK) {
            conn_stats.early_data_flag = XQC_0RTT_ACCEPT;

        } else if (conn->conn_flag & XQC_CONN_FLAG_0RTT_REJ) {
            conn_stats.early_data_flag = XQC_0RTT_REJECT;
        }
    }

    /* 2. srtt 和 ack_info 使用主路信息 (TODO: 有问题，后续需要修改) */
    if (conn->conn_initial_path
        && conn->conn_initial_path->path_send_ctl
        && conn->conn_initial_path->path_pn_ctl)
    {
        conn_stats.srtt = conn->conn_initial_path->path_send_ctl->ctl_srtt;
        xqc_recv_record_print(conn, &conn->conn_initial_path->path_pn_ctl->ctl_recv_record[XQC_PNS_APP_DATA],
                              conn_stats.ack_info, sizeof(conn_stats.ack_info));
    }


    /* 3. 遍历路径，获取各个路径count加和 */
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path = NULL;
    xqc_send_ctl_t *send_ctl;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (path == NULL) {
            xqc_log(conn->log, XQC_LOG_WARN, "|path NULL|");
            continue;
        }

        send_ctl = path->path_send_ctl;
        if (send_ctl == NULL) {
            xqc_log(conn->log, XQC_LOG_WARN, "|path_send_ctl NULL|path%ui|", path->path_id);
            continue;
        }

        conn_stats.lost_count           += send_ctl->ctl_lost_count;
        conn_stats.send_count           += send_ctl->ctl_send_count;
        conn_stats.tlp_count            += send_ctl->ctl_tlp_count;
        conn_stats.spurious_loss_count  += send_ctl->ctl_spurious_loss_count;
        conn_stats.recv_count           += send_ctl->ctl_recv_count;
    }

    /* 路径信息 */
    xqc_conn_path_metrics_print(conn, &conn_stats);

    /* 自定义信息 */
    xqc_conn_info_print(conn, &conn_stats);

    return conn_stats;
}

xqc_int_t
xqc_conn_check_token(xqc_connection_t *conn, const unsigned char *token, unsigned token_len)
{
    if (token_len > XQC_MAX_TOKEN_LEN) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|%ud exceed XQC_MAX_TOKEN_LEN|", token_len);
        return XQC_ERROR;

    } else if (token_len == 0) {
        xqc_log(conn->log, XQC_LOG_INFO, "|token empty|");
        return XQC_ERROR;
    }

    struct sockaddr *sa = (struct sockaddr *)conn->peer_addr;
    const unsigned char *pos = token;
    if (*pos++ & 0x80) {
        struct in6_addr *in6 = (struct in6_addr *)pos;
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)sa;
        if (token_len != 21) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|token_len error|token_len:%ui|", token_len);
            return XQC_ERROR;
        }
        if (memcmp(&sa6->sin6_addr, in6, sizeof(struct in6_addr)) != 0) {
            xqc_log(conn->log, XQC_LOG_WARN, "|ipv6 not match|");
            return XQC_ERROR;
        }
        pos += sizeof(struct in6_addr);

    } else {
        struct in_addr *in4 = (struct in_addr *)pos;
        struct sockaddr_in *sa4 = (struct sockaddr_in *)sa;
        if (token_len != 9) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|token_len error|token_len:%ui|", token_len);
            return XQC_ERROR;
        }
        xqc_log(conn->log, XQC_LOG_DEBUG, "|peer_addr:%s|", inet_ntoa(sa4->sin_addr));

        if (memcmp(&sa4->sin_addr, pos, sizeof(struct in_addr)) != 0) {
            xqc_log(conn->log, XQC_LOG_INFO, "|ipv4 not match|token_addr:%s|", inet_ntoa(*in4));
            return XQC_ERROR;
        }
        pos += sizeof(struct in_addr);
    }

    /* check token lifetime */
    uint32_t *expire = (uint32_t *)pos;
    *expire = ntohl(*expire);
    uint64_t now = xqc_monotonic_timestamp() / 1000000;
    if (*expire < now) {
        xqc_log(conn->log, XQC_LOG_INFO, "|token_expire|expire:%ud|now:%ui|", *expire, now);
        return XQC_ERROR;

    } else if (*expire - now <= XQC_TOKEN_UPDATE_DELTA) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|new token|expire:%ud|now:%ui|delta:%ud|",
                *expire, now, XQC_TOKEN_UPDATE_DELTA);
        conn->conn_flag |= XQC_CONN_FLAG_UPDATE_NEW_TOKEN;
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|pass|");
    return XQC_OK;
}

/*
 * +-+-+-+-+-+-+-+-+
 * |v|0|0|0|0|0|0|0|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                     IP(32/128)                                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                   Expire Time(32)                             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * v: 0 For IPv4, 1 For IPv6
 */
void
xqc_conn_gen_token(xqc_connection_t *conn, unsigned char *token, unsigned *token_len)
{
    struct sockaddr *sa = (struct sockaddr *)conn->peer_addr;
    if (sa->sa_family == AF_INET) {
        *token++ = 0x00;
        struct sockaddr_in *sa4 = (struct sockaddr_in *)sa;
        memcpy(token, &sa4->sin_addr, sizeof(struct in_addr));
        token += sizeof(struct in_addr);

        *token_len = 9;

    } else {
        *token++ = 0x80;
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)sa;
        memcpy(token, &sa6->sin6_addr, sizeof(struct in6_addr));
        token += sizeof(struct in6_addr);

        *token_len = 21;
    }

    uint32_t expire = xqc_monotonic_timestamp() / 1000000 + XQC_TOKEN_EXPIRE_DELTA;
    xqc_log(conn->log, XQC_LOG_DEBUG, "|expire:%ud|", expire);
    expire = htonl(expire);
    memcpy(token, &expire, sizeof(expire));
}

xqc_int_t
xqc_conn_early_data_reject(xqc_connection_t *conn)
{
    xqc_list_head_t *pos, *next;
    xqc_stream_t *stream;

    xqc_log(conn->log, XQC_LOG_DEBUG, "|reject|");

    conn->conn_flag |= XQC_CONN_FLAG_0RTT_REJ;
    if (conn->conn_type == XQC_CONN_TYPE_SERVER) {
        xqc_packet_in_t *packet_in;
        xqc_list_for_each_safe(pos, next, &conn->undecrypt_packet_in[XQC_ENC_LEV_0RTT]) {
            packet_in = xqc_list_entry(pos, xqc_packet_in_t, pi_list);
            xqc_list_del_init(pos);
            xqc_packet_in_destroy(packet_in, conn);
        }
        return XQC_OK;
    }

    xqc_send_queue_drop_0rtt_packets(conn);

    xqc_list_for_each_safe(pos, next, &conn->conn_all_streams) {
        stream = xqc_list_entry(pos, xqc_stream_t, all_stream_list);
        if (stream->stream_flag & XQC_STREAM_FLAG_HAS_0RTT) {
            stream->stream_send_offset = 0;
            stream->stream_unacked_pkt = 0;
            if (stream->stream_state_send >= XQC_SEND_STREAM_ST_RESET_SENT
                || stream->stream_state_recv >= XQC_RECV_STREAM_ST_RESET_RECVD)
            {
                xqc_destroy_write_buff_list(&stream->stream_write_buff_list.write_buff_list);
                return XQC_OK;
            }
            xqc_stream_send_state_update(stream, XQC_SEND_STREAM_ST_READY);
            xqc_stream_recv_state_update(stream, XQC_RECV_STREAM_ST_RECV);
            xqc_stream_write_buffed_data_to_packets(stream);
        }
    }
    return XQC_OK;
}

xqc_int_t
xqc_conn_early_data_accept(xqc_connection_t *conn)
{
    xqc_list_head_t *pos, *next;
    xqc_stream_t *stream;

    xqc_log(conn->log, XQC_LOG_DEBUG, "|accept|");

    conn->conn_flag |= XQC_CONN_FLAG_0RTT_OK;
    if (conn->conn_type == XQC_CONN_TYPE_SERVER) {
        return XQC_OK;
    }

    xqc_list_for_each_safe(pos, next, &conn->conn_all_streams) {
        stream = xqc_list_entry(pos, xqc_stream_t, all_stream_list);
        xqc_destroy_write_buff_list(&stream->stream_write_buff_list.write_buff_list);
    }
    return XQC_OK;
}

xqc_bool_t
xqc_conn_is_ready_to_send_early_data(xqc_connection_t *conn)
{
    return xqc_tls_is_ready_to_send_early_data(conn->tls);
}

xqc_int_t
xqc_conn_handshake_confirmed(xqc_connection_t *conn)
{
    if (!(conn->conn_flag & XQC_CONN_FLAG_HANDSHAKE_CONFIRMED)) {
        xqc_log(conn->log, XQC_LOG_INFO, "|handshake confirmed|conn:%p|", conn);
        conn->conn_flag |= XQC_CONN_FLAG_HANDSHAKE_CONFIRMED;
        xqc_send_queue_drop_handshake_packets(conn);
    }

    return XQC_OK;
}

xqc_int_t
xqc_conn_handshake_complete(xqc_connection_t *conn)
{
    xqc_int_t ret;

    xqc_list_head_t *pos, *next;
    xqc_stream_t *stream;
    /* update flow control */
    conn->conn_flow_ctl.fc_max_data_can_send = conn->remote_settings.max_data;
    conn->conn_flow_ctl.fc_max_streams_bidi_can_send = conn->remote_settings.max_streams_bidi;
    conn->conn_flow_ctl.fc_max_streams_uni_can_send = conn->remote_settings.max_streams_uni;

    xqc_list_for_each_safe(pos, next, &conn->conn_all_streams) {
        stream = xqc_list_entry(pos, xqc_stream_t, all_stream_list);
        xqc_stream_set_flow_ctl(stream);
    }

    /* determine multipath mode */
    conn->enable_multipath = xqc_conn_enable_multipath(conn);

    /* conn's handshake is complete when TLS stack has reported handshake complete */
    conn->conn_flag |= XQC_CONN_FLAG_HANDSHAKE_COMPLETED;

    if (conn->conn_type == XQC_CONN_TYPE_SERVER) {
        /* the TLS handshake is considered confirmed at the server when the handshake completes */
        xqc_conn_handshake_confirmed(conn);

        /* send handshake_done immediately */
        ret = xqc_write_handshake_done_frame_to_packet(conn);
        if (ret < 0) {
            xqc_log(conn->log, XQC_LOG_WARN, "|write_handshake_done err|");
            return ret;
        }

        /* if client sent no token or sent an invalid token, server sends a NEW_TOKEN frame */
        if (!(conn->conn_flag & XQC_CONN_FLAG_TOKEN_OK)
            || conn->conn_flag & XQC_CONN_FLAG_UPDATE_NEW_TOKEN)
        {
            xqc_write_new_token_to_packet(conn);
        }

    } else {
        /*
         * client MUST discard Initial keys when it first sends a Handshake packet,
         * equivalent to handshake complete and can send 1RTT
         */
        xqc_send_queue_drop_initial_packets(conn);
    }

    /* 0RTT rejected, send in 1RTT again */
    if ((conn->conn_flag & XQC_CONN_FLAG_HANDSHAKE_COMPLETED) 
        && ((conn->conn_type == XQC_CONN_TYPE_CLIENT && conn->conn_flag & XQC_CONN_FLAG_HAS_0RTT)
            || conn->conn_type == XQC_CONN_TYPE_SERVER) 
        && !(conn->conn_flag & XQC_CONN_FLAG_0RTT_OK) 
        && !(conn->conn_flag & XQC_CONN_FLAG_0RTT_REJ)) 
    {
        int accept = xqc_tls_is_early_data_accepted(conn->tls);
        if (accept == XQC_TLS_EARLY_DATA_REJECT) {
            xqc_conn_early_data_reject(conn);

        } else if (accept == XQC_TLS_EARLY_DATA_ACCEPT) {
            xqc_conn_early_data_accept(conn);
        }
    }

    return XQC_OK;
}


xqc_int_t
xqc_conn_buff_undecrypt_packet_in(xqc_packet_in_t *packet_in,
    xqc_connection_t *conn, xqc_encrypt_level_t encrypt_level)
{
    if (conn->undecrypt_count[encrypt_level] >= XQC_UNDECRYPT_PACKET_MAX
        || packet_in->buf_size > XQC_MAX_PACKET_IN_LEN)
    {
        xqc_log(conn->log, XQC_LOG_WARN,
                "|delay|XQC_ELIMIT|undecrypt_count:%ud|encrypt_level:%d|buf_size:%uz|",
                conn->undecrypt_count[encrypt_level], encrypt_level, packet_in->buf_size);
        return -XQC_ELIMIT;
    }

    /* limit the buffered 0-RTT packet count before a valid client Initial packet is received */
    if (conn->conn_type == XQC_CONN_TYPE_SERVER
        && !(conn->conn_flag & XQC_CONN_FLAG_DCID_OK)
        && encrypt_level == XQC_ENC_LEV_0RTT
        && conn->undecrypt_count[encrypt_level] > XQC_UNDECRYPT_0RTT_MAX_BEFORE_INIT)
    {
        xqc_log(conn->log, XQC_LOG_WARN, "|0RTT reach buffer limit before DCID confirmed|");
        return -XQC_ELIMIT;
    }

    xqc_packet_in_t *new_packet = xqc_calloc(1, sizeof(xqc_packet_in_t));
    if (new_packet == NULL) {
        return -XQC_EMALLOC;
    }

    new_packet->buf = xqc_malloc(XQC_MAX_PACKET_IN_LEN);
    if (new_packet->buf == NULL) {
        xqc_free(new_packet);
        return -XQC_EMALLOC;
    }

    new_packet->pi_pkt = packet_in->pi_pkt;
    new_packet->buf_size = packet_in->buf_size;
    xqc_memcpy((unsigned char *)new_packet->buf, packet_in->buf, packet_in->buf_size);
    new_packet->pos = (unsigned char *)new_packet->buf + (packet_in->pos - packet_in->buf);
    new_packet->last = (unsigned char *)new_packet->buf + (packet_in->last - packet_in->buf);
    new_packet->pkt_recv_time = packet_in->pkt_recv_time;

    xqc_list_add_tail(&new_packet->pi_list, &conn->undecrypt_packet_in[encrypt_level]);
    conn->undecrypt_count[encrypt_level]++;

    xqc_log_event(conn->log, TRA_PACKET_BUFFERED, new_packet);
    xqc_log(conn->log, XQC_LOG_DEBUG, "|====>|delay|undecrypt_count:%ud|encrypt_level:%d|",
            conn->undecrypt_count[encrypt_level], encrypt_level);
    return XQC_OK;
}


xqc_int_t
xqc_conn_process_undecrypt_packet_in(xqc_connection_t *conn, xqc_encrypt_level_t encrypt_level)
{
    if (conn->undecrypt_count[encrypt_level] == 0) {
        return XQC_OK;
    }

    xqc_packet_in_t *packet_in;
    xqc_list_head_t *pos, *next;
    xqc_int_t ret;
    xqc_list_for_each_safe(pos, next, &conn->undecrypt_packet_in[encrypt_level]) {
        packet_in = xqc_list_entry(pos, xqc_packet_in_t, pi_list);
        xqc_log(conn->log, XQC_LOG_DEBUG, "|delay|undecrypt_count:%ud|encrypt_level:%d|",
                conn->undecrypt_count[encrypt_level], encrypt_level);

        ret = xqc_conn_process_packet(conn, packet_in->buf, packet_in->buf_size, packet_in->pkt_recv_time);
        if (ret) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_packet_process error|ret:%d|", ret);
            return ret;
        }

        xqc_list_del_init(pos);
        xqc_packet_in_destroy(packet_in, conn);
        conn->undecrypt_count[encrypt_level]--;
    }

    return XQC_OK;
}


void
xqc_conn_buff_1rtt_packets(xqc_connection_t *conn)
{
    xqc_packet_out_t *packet_out;
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &conn->conn_send_queue->sndq_send_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (packet_out->po_pkt.pkt_type == XQC_PTYPE_SHORT_HEADER) {
            xqc_send_queue_remove_send(&packet_out->po_list);
            xqc_send_queue_insert_buff(&packet_out->po_list, &conn->conn_send_queue->sndq_buff_1rtt_packets);
            if (!(conn->conn_flag & XQC_CONN_FLAG_DCID_OK)) {
                packet_out->po_flag |= XQC_POF_DCID_NOT_DONE;
            }
        }
    }
}


void
xqc_conn_write_buffed_1rtt_packets(xqc_connection_t *conn)
{
    if (conn->conn_flag & XQC_CONN_FLAG_CAN_SEND_1RTT) {
        xqc_send_queue_t *send_queue = conn->conn_send_queue;
        xqc_list_head_t *pos, *next;
        xqc_packet_out_t *packet_out;
        unsigned total = 0;
        xqc_list_for_each_safe(pos, next, &send_queue->sndq_buff_1rtt_packets) {
            packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
            xqc_send_queue_remove_buff(pos, send_queue);
            xqc_send_queue_insert_send(packet_out, &send_queue->sndq_send_packets, send_queue);
            if (packet_out->po_flag & XQC_POF_DCID_NOT_DONE) {
                xqc_short_packet_update_dcid(packet_out, conn->dcid_set.current_dcid);
            }
            ++total;
        }
        xqc_log(conn->log, XQC_LOG_DEBUG, "|total:%ui|", total);
    }
}


xqc_usec_t
xqc_conn_next_wakeup_time(xqc_connection_t *conn)
{
    xqc_usec_t min_time = XQC_MAX_UINT64_VALUE;
    xqc_usec_t wakeup_time;
    xqc_timer_t *timer;

    for (xqc_timer_type_t type = 0; type < XQC_TIMER_N; ++type) {
        timer = &conn->conn_timer_manager.timer[type];
        if (timer->timer_is_set) {
            min_time = xqc_min(min_time, timer->expire_time);
        }
    }

    xqc_path_ctx_t *path;
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (path->path_state != XQC_PATH_STATE_ACTIVE) {
            continue;
        }

        for (xqc_timer_type_t type = 0; type < XQC_TIMER_N; ++type) {
            timer = &path->path_send_ctl->path_timer_manager.timer[type];
            if (timer->timer_is_set) {
                min_time = xqc_min(min_time, timer->expire_time);
            }
        }
    }

    wakeup_time = min_time == XQC_MAX_UINT64_VALUE ? 0 : min_time;

    xqc_log(conn->log, XQC_LOG_DEBUG, "|wakeup_time:%ui|", wakeup_time);
    return wakeup_time;
}

static char g_local_addr_str[INET6_ADDRSTRLEN];
static char g_peer_addr_str[INET6_ADDRSTRLEN];

char *
xqc_local_addr_str(const struct sockaddr *local_addr, socklen_t local_addrlen)
{
    if (local_addrlen == 0 || local_addr == NULL) {
        g_local_addr_str[0] = '\0';
        return g_local_addr_str;
    }

    struct sockaddr_in *sa_local = (struct sockaddr_in *)local_addr;
    if (sa_local->sin_family == AF_INET) {
        if (inet_ntop(sa_local->sin_family, &sa_local->sin_addr, g_local_addr_str, local_addrlen) == NULL) {
            g_local_addr_str[0] = '\0';
        }

    } else {
        if (inet_ntop(sa_local->sin_family, &((struct sockaddr_in6*)sa_local)->sin6_addr,
                      g_local_addr_str, local_addrlen) == NULL)
        {
            g_local_addr_str[0] = '\0';
        }
    }

    return g_local_addr_str;
}


char *
xqc_peer_addr_str(const struct sockaddr *peer_addr, socklen_t peer_addrlen)
{
    if (peer_addrlen == 0 || peer_addr == NULL) {
        g_peer_addr_str[0] = '\0';
        return g_peer_addr_str;
    }

    struct sockaddr_in *sa_peer = (struct sockaddr_in *)peer_addr;
    if (sa_peer->sin_family == AF_INET) {
        if (inet_ntop(sa_peer->sin_family, &sa_peer->sin_addr, g_peer_addr_str, peer_addrlen) == NULL) {
            g_peer_addr_str[0] = '\0';
        }

    } else {
        if (inet_ntop(sa_peer->sin_family, &((struct sockaddr_in6*)sa_peer)->sin6_addr,
                      g_peer_addr_str, peer_addrlen) == NULL)
        {
            g_peer_addr_str[0] = '\0';
        }
    }

    return g_peer_addr_str;
}


char *
xqc_conn_addr_str(xqc_connection_t *conn)
{
    if (conn->local_addrlen == 0 || conn->peer_addrlen == 0
        || conn->scid_set.user_scid.cid_len == 0 || conn->dcid_set.current_dcid.cid_len == 0)
    {
        return "addr or cid not avail";
    }

    if (conn->addr_str_len == 0) {
        struct sockaddr_in *sa_local = (struct sockaddr_in *)conn->local_addr;
        struct sockaddr_in *sa_peer = (struct sockaddr_in *)conn->peer_addr;

        conn->addr_str_len = snprintf(conn->addr_str, sizeof(conn->addr_str), "l-%s-%d-%s p-%s-%d-%s",
                                      xqc_local_addr_str((struct sockaddr*)sa_local, conn->local_addrlen),
                                      ntohs(sa_local->sin_port), xqc_scid_str(&conn->scid_set.user_scid),
                                      xqc_peer_addr_str((struct sockaddr*)sa_peer, conn->peer_addrlen),
                                      ntohs(sa_peer->sin_port), xqc_dcid_str(&conn->dcid_set.current_dcid));
    }

    return conn->addr_str;
}

char *
xqc_path_addr_str(xqc_path_ctx_t *path)
{
    if (path->local_addrlen == 0 || path->peer_addrlen == 0
        || path->path_scid.cid_len == 0 || path->path_dcid.cid_len == 0)
    {
        return "addr or cid not avail";
    }

    if (path->addr_str_len == 0) {
        struct sockaddr_in *sa_local = (struct sockaddr_in *)path->local_addr;
        struct sockaddr_in *sa_peer = (struct sockaddr_in *)path->peer_addr;

        path->addr_str_len = snprintf(path->addr_str, sizeof(path->addr_str), "l-%s-%d-%s p-%s-%d-%s",
                                      xqc_local_addr_str((struct sockaddr*)sa_local, path->local_addrlen),
                                      ntohs(sa_local->sin_port), xqc_scid_str(&path->path_scid),
                                      xqc_peer_addr_str((struct sockaddr*)sa_peer, path->peer_addrlen),
                                      ntohs(sa_peer->sin_port), xqc_dcid_str(&path->path_dcid));
    }

    return path->addr_str;
}


void
xqc_conn_record_single(xqc_connection_t *c, xqc_packet_in_t *packet_in)
{
    if (!xqc_has_packet_number(&packet_in->pi_pkt)) {
        return;
    }

    xqc_path_ctx_t *path = xqc_conn_find_path_by_path_id(c, packet_in->pi_path_id);
    if (path == NULL) {
        return;
    }
    xqc_pn_ctl_t *pn_ctl = xqc_get_pn_ctl(c, path);
    xqc_send_ctl_t *send_ctl = path->path_send_ctl;

    xqc_pkt_range_status range_status;
    int out_of_order = 0;
    xqc_pkt_num_space_t pns = packet_in->pi_pkt.pkt_pns;
    xqc_packet_number_t pkt_num = packet_in->pi_pkt.pkt_num;

    range_status = xqc_recv_record_add(&pn_ctl->ctl_recv_record[pns], pkt_num);
    if (range_status == XQC_PKTRANGE_OK) {
        if (XQC_IS_ACK_ELICITING(packet_in->pi_frame_types)) {
            ++send_ctl->ctl_ack_eliciting_pkt[pns];

            if (pkt_num > send_ctl->ctl_largest_received[pns] || send_ctl->ctl_largest_received[pns] == XQC_MAX_UINT64_VALUE) {
                send_ctl->ctl_largest_received[pns] = pkt_num;
                send_ctl->ctl_largest_recv_time[pns] = packet_in->pkt_recv_time;
            }

            if (pkt_num < send_ctl->ctl_unack_received[pns]) {
                send_ctl->ctl_unack_received[pns] = pkt_num;
                xqc_log(c->log, XQC_LOG_DEBUG, "|path:%ui|ctl_unack_received:%ui|", path->path_id, send_ctl->ctl_unack_received[pns]);
            }
        }

        if (pkt_num != xqc_recv_record_largest(&pn_ctl->ctl_recv_record[pns])) {
            out_of_order = 1;
        }

        xqc_maybe_should_ack(c, path, pn_ctl, pns, out_of_order, packet_in->pkt_recv_time);
    }

    // xqc_recv_record_log(c, &pn_ctl->ctl_recv_record[pns]);
    xqc_log(c->log, XQC_LOG_DEBUG, "|path:%ui|xqc_recv_record_add|status:%d|pkt_num:%ui|largest:%ui|pns:%d|",
            path->path_id, range_status, pkt_num, xqc_recv_record_largest(&pn_ctl->ctl_recv_record[pns]), pns);
}


xqc_int_t
xqc_conn_confirm_cid(xqc_connection_t *c, xqc_packet_t *pkt)
{
    /* 
     *  after a successful process of Initial packet, SCID from Initial
     *  is not equal to what remembered when connection was created, as
     *  server is not willing to use the client's DCID as SCID;
     */

    xqc_int_t ret;

    if (!(c->conn_flag & XQC_CONN_FLAG_DCID_OK)) {

        if (xqc_cid_in_cid_set(&c->dcid_set.cid_set, &pkt->pkt_scid) == NULL) {
            ret = xqc_cid_set_insert_cid(&c->dcid_set.cid_set, &pkt->pkt_scid, XQC_CID_USED,
                                         c->local_settings.active_connection_id_limit);
            if (ret != XQC_OK) {
                xqc_log(c->log, XQC_LOG_ERROR,
                        "|xqc_cid_set_insert_cid error|limit:%ui|unused:%ui|used:%ui|",
                        c->local_settings.active_connection_id_limit,
                        c->dcid_set.cid_set.unused_cnt, c->dcid_set.cid_set.used_cnt);
                return ret;
            }
        }

        if (XQC_OK != xqc_cid_is_equal(&c->dcid_set.current_dcid, &pkt->pkt_scid)) {
            xqc_log(c->log, XQC_LOG_INFO, "|dcid change|ori:%s|new:%s|", 
                    xqc_dcid_str(&c->dcid_set.current_dcid), xqc_scid_str(&pkt->pkt_scid));
            xqc_cid_copy(&c->dcid_set.current_dcid, &pkt->pkt_scid);
            xqc_cid_copy(&c->conn_initial_path->path_dcid, &pkt->pkt_scid);
        }

        if (xqc_insert_conns_hash(c->engine->conns_hash_dcid, c, &c->dcid_set.current_dcid)) {
            xqc_log(c->log, XQC_LOG_ERROR, "|insert conn hash error");
            return -XQC_EMALLOC;
        }

        c->conn_flag |= XQC_CONN_FLAG_DCID_OK;
    }

    return XQC_OK;
}


/**
 * client will validate server's addr by:
 * 1) successful processing of Initial packet.
 * 2) successful processing of VN/Retry packet with the DCID client chose
 * 3) server uses the CID which client provided in Initial packet with at least 8 bytes
 *
 * server will validate client's addr by:
 * 1) successful processing of Handshake packet.
 * 2) client's Initial/Handshake packet uses server's CID with at least 8 bytes
 * 3) client's Initial token is what server provided in NEW_TOKEN/Retry frame
 */
void
xqc_conn_addr_validated(xqc_connection_t *c)
{
    c->conn_flag |= XQC_CONN_FLAG_ADDR_VALIDATED;
    xqc_log(c->log, XQC_LOG_INFO, "|Address Validated|conn:%p|role:%d|", c, c->conn_type);
}


void
xqc_conn_server_validate_address(xqc_connection_t *c, xqc_packet_in_t *pi)
{
    switch (pi->pi_pkt.pkt_type) {
    case XQC_PTYPE_INIT:
        if (XQC_CONN_FLAG_TOKEN_OK & c->conn_flag) {
            /* NEW_TOKEN or Retry token is valid */
            xqc_conn_addr_validated(c);

        } else {
            /**
             * when server close its own CID, and server reached its anti-amplification limit,
             * client MAY send an Initial packet with PING/PADDING on PTO with server's CID
             */
            if (c->scid_set.user_scid.cid_len >= XQC_CONN_ADDR_VALIDATION_CID_ENTROPY
                && xqc_cid_in_cid_set(&c->scid_set.cid_set, &c->original_dcid) == NULL
                && xqc_cid_in_cid_set(&c->scid_set.cid_set, &pi->pi_pkt.pkt_dcid) != NULL)
            {
                xqc_conn_addr_validated(c);
            }
        }
        break;

    case XQC_PTYPE_HSK:
        /* successful processing of Handshake packet */
        xqc_conn_addr_validated(c);
        break;

    default:
        break;
    }

    /*
     * loss detection timer might be unset when anti-amplification limit is reached, but receiving 
     * a handshake or receiving a packet with cid which was choosed by server, will remove the 
     * anti-amplification state, and loss detection timer shall be re-armed.
     */
    if (c->conn_flag & XQC_CONN_FLAG_ADDR_VALIDATED) {
        xqc_send_ctl_rearm_ld_timer(c->conn_initial_path->path_send_ctl);
    }
}


void
xqc_conn_client_validate_address(xqc_connection_t *c, xqc_packet_in_t *pi)
{
    switch (pi->pi_pkt.pkt_type) {
    case XQC_PTYPE_INIT:
    case XQC_PTYPE_RETRY:
    case XQC_PTYPE_VERSION_NEGOTIATION:
        xqc_conn_addr_validated(c);
        break;

    default:
        break;
    }
}


void
xqc_conn_validate_address(xqc_connection_t *c, xqc_packet_in_t *pi)
{
    if (c->conn_type == XQC_CONN_TYPE_SERVER) {
        xqc_conn_server_validate_address(c, pi);

    } else {
        xqc_conn_client_validate_address(c, pi);
    }
}


xqc_int_t
xqc_conn_on_initial_processed(xqc_connection_t *c, xqc_packet_in_t *pi, xqc_usec_t now)
{
    /* successful decryption of initial packet means that pkt's DCID/SCID is confirmed */
    return xqc_conn_confirm_cid(c, &pi->pi_pkt);
}


xqc_int_t
xqc_conn_on_hsk_processed(xqc_connection_t *c, xqc_packet_in_t *pi, xqc_usec_t now)
{
    if (c->conn_hsk_recv_time == 0) {
        c->conn_hsk_recv_time = now;
    }
    if (c->conn_type == XQC_CONN_TYPE_SERVER) {
        /* server MUST discard Initial keys when it first successfully processes a Handshake packet */
        xqc_send_queue_drop_initial_packets(c);
    }

    return XQC_OK;
}


xqc_int_t
xqc_conn_on_1rtt_processed(xqc_connection_t *c, xqc_packet_in_t *pi, xqc_usec_t now)
{
    if (c->conn_type == XQC_CONN_TYPE_CLIENT) {
        /*
         * once client receives HANDSHAKE_DONE frame, handshake
         * is confirmed, and MUST discard its handshake keys
         */
        if (pi->pi_frame_types & XQC_FRAME_BIT_HANDSHAKE_DONE) {
            xqc_conn_handshake_confirmed(c);
        }
    }

    return XQC_OK;
}


xqc_int_t
xqc_conn_on_pkt_processed(xqc_connection_t *c, xqc_packet_in_t *pi, xqc_usec_t now)
{
    xqc_int_t ret = XQC_OK;
    switch (pi->pi_pkt.pkt_type) {
    case XQC_PTYPE_INIT:
        ret = xqc_conn_on_initial_processed(c, pi, now);
        break;

    case XQC_PTYPE_HSK:
        ret = xqc_conn_on_hsk_processed(c, pi, now);
        break;

    case XQC_PTYPE_SHORT_HEADER:
        ret = xqc_conn_on_1rtt_processed(c, pi, now);
        break;

    default:
        break;
    }

    /* validate peer's address */
    if (!(c->conn_flag & XQC_CONN_FLAG_ADDR_VALIDATED)) {
        xqc_conn_validate_address(c, pi);
    }

    /* record packet */
    xqc_conn_record_single(c, pi);
    if (pi->pi_frame_types & (~(XQC_FRAME_BIT_STREAM|XQC_FRAME_BIT_PADDING))) {
        c->conn_flag |= XQC_CONN_FLAG_NEED_RUN;
    }

    c->conn_last_recv_time = now;

    xqc_log(c->log, XQC_LOG_INFO, "|====>|conn:%p|path:%ui|size:%uz|pkt_type:%s|pkt_num:%ui|frame:%s|recv_time:%ui|",
            c, pi->pi_path_id, pi->buf_size, xqc_pkt_type_2_str(pi->pi_pkt.pkt_type), pi->pi_pkt.pkt_num,
            xqc_frame_type_2_str(pi->pi_frame_types), pi->pkt_recv_time);
    return ret;
}


uint8_t
xqc_conn_tolerant_error(xqc_int_t ret)
{
    if (-XQC_EVERSION == ret || -XQC_EILLPKT == ret || -XQC_EWAITING == ret || -XQC_EIGNORE_PKT == ret) {
        return XQC_TRUE;
    }

    return XQC_FALSE;
}

xqc_int_t
xqc_conn_process_packet(xqc_connection_t *c,
    const unsigned char *packet_in_buf, size_t packet_in_size, xqc_usec_t recv_time)
{
    xqc_int_t ret = XQC_ERROR;
    const unsigned char *last_pos = NULL;
    const unsigned char *pos = packet_in_buf;                   /* start of QUIC pkt */
    const unsigned char *end = packet_in_buf + packet_in_size;  /* end of udp datagram */
    xqc_packet_in_t packet;
    unsigned char decrypt_payload[XQC_MAX_PACKET_IN_LEN];

    /* process all QUIC packets in UDP datagram */
    while (pos < end) {
        last_pos = pos;

        /* init packet in */
        xqc_packet_in_t *packet_in = &packet;
        memset(packet_in, 0, sizeof(*packet_in));
        xqc_packet_in_init(packet_in, pos, end - pos, decrypt_payload, XQC_MAX_PACKET_IN_LEN, recv_time);

        /* packet_in->pos will update inside */
        ret = xqc_packet_process_single(c, packet_in);
        if (ret == XQC_OK) {
            if (XQC_OK != (ret = xqc_conn_on_pkt_processed(c, packet_in, recv_time))) {
                xqc_log(c->log, XQC_LOG_ERROR, "|on_pkt_process error|ret:%d|", ret);
            }

        } else if (xqc_conn_tolerant_error(ret)) {
            xqc_log(c->log, XQC_LOG_INFO, "|ignore err|%d|", ret);
            packet_in->pos = packet_in->last;
            return XQC_OK;
        }

        /* error occurred or read state is error */
        if (ret != XQC_OK || last_pos == packet_in->pos) {
            /* if last_pos equals packet_in->pos, might trigger infinite loop, return to avoid it */
            xqc_log(c->log, XQC_LOG_ERROR, "|process packets err|ret:%d|pos:%p|buf:%p|buf_size:%uz|",
                    ret, packet_in->pos, packet_in->buf, packet_in->buf_size);
            return ret != XQC_OK ? ret : -XQC_ESYS;
        }

        /* consume all the bytes and start parse next QUIC packet */
        pos = packet_in->last;
        xqc_log_event(c->log, TRA_PACKET_RECEIVED, packet_in);
    }

    return XQC_OK;
}


void
xqc_conn_process_packet_recved_path(xqc_connection_t *conn, xqc_cid_t *scid,
    size_t packet_in_size, xqc_usec_t recv_time)
{
    xqc_path_ctx_t *path = xqc_conn_find_path_by_scid(conn, scid);
    if (path == NULL) {
        xqc_log(conn->log, XQC_LOG_INFO, "|ignore unknown path|scid:%s|", xqc_scid_str(scid));
        return;
    }

    xqc_send_ctl_on_dgram_received(path->path_send_ctl, packet_in_size);

    xqc_timer_set(&path->path_send_ctl->path_timer_manager, XQC_TIMER_PATH_IDLE,
                  recv_time, xqc_path_get_idle_timeout(path) * 1000);

    return;
}


xqc_int_t
xqc_conn_check_tx_key(xqc_connection_t *conn)
{
    /* if tx key is ready, conn can send 1RTT packets */
    if (xqc_tls_is_key_ready(conn->tls, XQC_ENC_LEV_1RTT, XQC_KEY_TYPE_TX_WRITE)) {
        xqc_log(conn->log, XQC_LOG_INFO, "|keys are ready, can send 1rtt now|");
        conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT;
    }

    return XQC_OK;
}

xqc_int_t
xqc_conn_check_handshake_complete(xqc_connection_t *conn)
{
    if (!(conn->conn_flag & XQC_CONN_FLAG_HANDSHAKE_COMPLETED)
        && conn->conn_state == XQC_CONN_STATE_ESTABED)
    {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|HANDSHAKE_COMPLETED|conn:%p|", conn);
        xqc_conn_handshake_complete(conn);

        if (conn->app_proto_cbs.conn_cbs.conn_handshake_finished) {
            conn->app_proto_cbs.conn_cbs.conn_handshake_finished(conn, conn->user_data, conn->proto_data);
        }
    }

    /* check tx keys after handshake complete */
    xqc_conn_check_tx_key(conn);
    return XQC_OK;
}


/* should have at lease one unused dcid & one unused scid */
xqc_int_t
xqc_conn_check_unused_cids(xqc_connection_t *conn)
{
    if (conn->dcid_set.cid_set.unused_cnt == 0 || conn->scid_set.cid_set.unused_cnt == 0) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|don't have available unused cid|%ui|%ui|", 
                conn->dcid_set.cid_set.unused_cnt, conn->scid_set.cid_set.unused_cnt);
        return -XQC_EMP_NO_AVAIL_PATH_ID;
    }
    return XQC_OK;
}


void
xqc_conn_destroy_cids(xqc_connection_t *conn)
{
    xqc_cid_inner_t *cid = NULL;
    xqc_list_head_t *pos, *next;

    if (conn->engine->conns_hash) {
        if (xqc_find_conns_hash(conn->engine->conns_hash, conn, &conn->original_dcid)) {
            xqc_remove_conns_hash(conn->engine->conns_hash, conn, &conn->original_dcid);
        }

        xqc_list_for_each_safe(pos, next, &conn->scid_set.cid_set.list_head) {
            cid = xqc_list_entry(pos, xqc_cid_inner_t, list);
            if (xqc_find_conns_hash(conn->engine->conns_hash, conn, &cid->cid)) {
                xqc_remove_conns_hash(conn->engine->conns_hash, conn, &cid->cid);
            }
        }
    }

    if (conn->engine->conns_hash_dcid && (conn->conn_flag & XQC_CONN_FLAG_DCID_OK)) {
        xqc_list_for_each_safe(pos, next, &conn->dcid_set.cid_set.list_head) {
            cid = xqc_list_entry(pos, xqc_cid_inner_t, list);
            if (xqc_find_conns_hash(conn->engine->conns_hash_dcid, conn, &cid->cid)) {
                xqc_remove_conns_hash(conn->engine->conns_hash_dcid, conn, &cid->cid);
            }
        }
    }

    xqc_destroy_cid_set(&conn->scid_set.cid_set);
    xqc_destroy_cid_set(&conn->dcid_set.cid_set);
}


xqc_int_t
xqc_conn_try_add_new_conn_id(xqc_connection_t *conn, uint64_t retire_prior_to)
{
    if ((xqc_conn_is_handshake_confirmed(conn))
        && (conn->scid_set.cid_set.unused_cnt == 0)
        && (conn->scid_set.cid_set.used_cnt < conn->remote_settings.active_connection_id_limit))
    {
        xqc_int_t ret = xqc_write_new_conn_id_frame_to_packet(conn, retire_prior_to);
        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_conn_id_frame_to_packet error|");
            return ret;
        }
    }

    return XQC_OK;
}


xqc_int_t
xqc_conn_confirm_key_update(xqc_connection_t *conn)
{
    xqc_key_update_ctx_t *ctx = &conn->key_update_ctx;
    xqc_pn_ctl_t *pn_ctl = xqc_get_pn_ctl(conn, conn->conn_initial_path);

    ctx->key_update_cnt++;
    ctx->first_sent_pktno = pn_ctl->ctl_packet_number[XQC_PNS_APP_DATA] + 1;
    ctx->first_recv_pktno = XQC_MAX_UINT64_VALUE;
    ctx->cur_out_key_phase ^= 1;
    ctx->next_in_key_phase ^= 1;
    ctx->enc_pkt_cnt = 0;

    xqc_tls_set_1rtt_key_phase(conn->tls, ctx->cur_out_key_phase);
    xqc_log(conn->log, XQC_LOG_DEBUG, "|key phase changed to %ui|", ctx->cur_out_key_phase);

    /*
     * An endpoint SHOULD retain old read keys for no more than three times the PTO after having
     * received a packet protected using the new keys. After this period, old read keys and their
     * corresponding secrets SHOULD be discarded.
     */
    xqc_usec_t now = xqc_monotonic_timestamp();
    xqc_usec_t pto = xqc_conn_get_max_pto(conn);
    if (!xqc_timer_is_set(&conn->conn_timer_manager, XQC_TIMER_KEY_UPDATE)) {
        xqc_timer_set(&conn->conn_timer_manager, XQC_TIMER_KEY_UPDATE, now, 3 * pto);
    }

    /*
     * Endpoints need to allow for the possibility that a peer might not be able to decrypt
     * packets that initiate a key update during the period when the peer retains old keys.
     * Endpoints SHOULD wait three times the PTO before initiating a key update after receiving
     * an acknowledgment that confirms that the previous key update was received.
     * Failing to allow sufficient time could lead to packets being discarded.
     */
    ctx->initiate_time_guard = now + 3 * pto;

    return XQC_OK;
}


/* check whether if the dcid is valid for the connection */
xqc_int_t
xqc_conn_check_dcid(xqc_connection_t *conn, xqc_cid_t *dcid)
{
    xqc_int_t ret;

    xqc_cid_inner_t *scid = xqc_cid_in_cid_set(&conn->scid_set.cid_set, dcid);
    if (scid == NULL) {
        return -XQC_ECONN_CID_NOT_FOUND;
    }

    if (scid->state == XQC_CID_UNUSED) {
        ret = xqc_cid_switch_to_next_state(&conn->scid_set.cid_set, scid, XQC_CID_USED);
        if (ret < 0) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_cid_switch_to_next_state error|scid:%s|",
                    xqc_scid_str(&scid->cid));
            return ret;
        }
    }

    return XQC_OK;
}

xqc_int_t
xqc_conn_set_cid_retired_ts(xqc_connection_t *conn, xqc_cid_inner_t *inner_cid)
{
    xqc_int_t ret = XQC_OK;

    ret = xqc_cid_switch_to_next_state(&conn->scid_set.cid_set, inner_cid, XQC_CID_RETIRED);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|set cid retired error|");
        return ret;
    }

    xqc_usec_t now = xqc_monotonic_timestamp();
    xqc_usec_t pto = xqc_conn_get_max_pto(conn);

    /* set retired timestamp */
    inner_cid->retired_ts = now + 3 * pto;

    /* set timer to remove the retired cids */
    if (!xqc_timer_is_set(&conn->conn_timer_manager, XQC_TIMER_RETIRE_CID)) {
        xqc_timer_set(&conn->conn_timer_manager, XQC_TIMER_RETIRE_CID, now, 3 * pto);
    }

    return ret;
}

/* switch another used scid to replace user_scid */
xqc_int_t
xqc_conn_update_user_scid(xqc_connection_t *conn, xqc_scid_set_t *scid_set)
{
    xqc_cid_inner_t *scid;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &scid_set->cid_set.list_head) {
        scid = xqc_list_entry(pos, xqc_cid_inner_t, list);

        if (scid->state == XQC_CID_USED
            && xqc_cid_is_equal(&scid_set->user_scid, &scid->cid) != XQC_OK)
        {
            if (conn->transport_cbs.conn_update_cid_notify) {
                conn->transport_cbs.conn_update_cid_notify(conn, &scid_set->user_scid, &scid->cid,
                                                           xqc_conn_get_user_data(conn));
            }

            xqc_cid_copy(&scid_set->user_scid, &scid->cid);
            return XQC_OK;
        }
    }

    return -XQC_ECONN_NO_AVAIL_CID;
}


xqc_bool_t
xqc_conn_peer_complete_address_validation(xqc_connection_t *c)
{
    /* server assume clients validate server's address implicitly */
    if (c->conn_type == XQC_CONN_TYPE_SERVER) {
        return XQC_TRUE;

    } else {
        return (c->conn_flag & XQC_CONN_FLAG_HANDSHAKE_CONFIRMED)
            || xqc_send_ctl_ack_received_in_pns(c->conn_initial_path->path_send_ctl, XQC_PNS_HSK);
    }
}


void *
xqc_conn_get_user_data(xqc_connection_t *c)
{
    if (NULL == c) {
        return NULL;
    }

    return c->user_data;
}


xqc_bool_t
xqc_conn_has_hsk_keys(xqc_connection_t *c)
{
    return xqc_tls_is_key_ready(c->tls, XQC_ENC_LEV_HSK, XQC_KEY_TYPE_TX_WRITE)
        && xqc_tls_is_key_ready(c->tls, XQC_ENC_LEV_HSK, XQC_KEY_TYPE_RX_READ);
}


static xqc_bool_t
xqc_need_reassemble_packet(xqc_packet_out_t *packet_out)
{
    if (packet_out->po_pkt.pkt_type == XQC_PTYPE_INIT
        && packet_out->po_frame_types & XQC_FRAME_BIT_CRYPTO)
    {
        return XQC_TRUE;

    } else if (packet_out->po_pkt.pkt_type == XQC_PTYPE_0RTT) {
        return XQC_TRUE;
    }

    return XQC_FALSE;
}

static xqc_int_t
xqc_conn_reassemble_packet(xqc_connection_t *conn, xqc_packet_out_t *ori_po)
{
    xqc_packet_out_t *new_po = xqc_write_new_packet(conn, ori_po->po_pkt.pkt_type);
    if (new_po == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_EWRITE_PKT;
    }

    /* copy frame without padding */
    unsigned int ori_payload_len = 0;
    if (xqc_need_padding(conn, ori_po) && ori_po->po_padding != NULL) {
        ori_payload_len = ori_po->po_padding - ori_po->po_payload;

    } else {
        ori_payload_len = ori_po->po_used_size - (ori_po->po_payload - ori_po->po_buf);
    }

    new_po->po_payload = new_po->po_buf + new_po->po_used_size;
    memcpy(new_po->po_payload, ori_po->po_payload, ori_payload_len);
    new_po->po_used_size += ori_payload_len;

    /* copy packet_out info */
    new_po->po_frame_types = ori_po->po_frame_types;
    for (int i = 0; i < XQC_MAX_STREAM_FRAME_IN_PO; i++) {
        new_po->po_stream_frames[i] = ori_po->po_stream_frames[i];
    }

    /* set RESEND flag */
    new_po->po_flag |= XQC_POF_RESEND;

    if (new_po->po_frame_types & XQC_FRAME_BIT_CRYPTO) {
        xqc_send_queue_move_to_high_pri(&new_po->po_list, conn->conn_send_queue);
    }

    xqc_log(conn->log, XQC_LOG_DEBUG,
            "|pkt_num:%ui|ptype:%d|frames:%s|",
            new_po->po_pkt.pkt_num, new_po->po_pkt.pkt_type,
            xqc_frame_type_2_str(new_po->po_frame_types));

    return XQC_OK;
}

static xqc_int_t
xqc_conn_resend_packets(xqc_connection_t *conn)
{
    /*
     * Generate new header and reassemble packet for Initial and 0-RTT packets
     * that need to be resent, and drop all old packets with the original header.
     *
     * TODO: Refactoring packet generation: generate packet header before sent.
     * Then we don't have to reassemble the packets.
     */

    xqc_int_t ret;
    xqc_send_queue_t *send_queue = conn->conn_send_queue;

    xqc_list_head_t *pos, *next;
    xqc_packet_out_t *packet_out;

    xqc_list_for_each_safe(pos, next, &send_queue->sndq_send_packets) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);

        if (packet_out->po_flag & XQC_POF_RESEND) {
            continue;
        }

        /* reassemble new packet with updated header and insert to send queue */
        if (xqc_need_reassemble_packet(packet_out)) {
            ret = xqc_conn_reassemble_packet(conn, packet_out);
            if (ret != XQC_OK) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_reassemble_packet error|ret:%d|", ret);
                return ret;
            }
        }

        /* drop old packet */
        xqc_send_queue_remove_send(pos);
        xqc_send_queue_insert_free(packet_out, &send_queue->sndq_free_packets, send_queue);
    }

    return XQC_OK;
}

xqc_int_t
xqc_conn_on_recv_retry(xqc_connection_t *conn, xqc_cid_t *retry_scid)
{
    xqc_int_t ret;

    conn->conn_flag |= XQC_CONN_FLAG_RETRY_RECVD;

    /* change the DCID it uses for sending packets in response to Retry packet. */
    xqc_cid_copy(&conn->dcid_set.current_dcid, retry_scid);

    /* reset initial keys */
    ret = xqc_tls_reset_initial(conn->tls, conn->version, retry_scid);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_tls_reset_initial error|retry_scid:%s|ret:%d|",
                xqc_scid_str(retry_scid), ret);
        return ret;
    }

    /*
     * clients that receive a Retry packet reset congestion control and loss
     * recovery state, including resetting any pending timers.
     */
    xqc_send_ctl_reset(conn->conn_initial_path->path_send_ctl);

    /*
     * client responds to a Retry packet with an Initial packet that includes
     * the provided Retry token to continue connection establishment.
     * client SHOULD attempt to resend data in 0-RTT packets after it sends a
     * new Initial packet.
     */
    ret = xqc_conn_resend_packets(conn);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_resend_packets error|ret:%d|", ret);
        return ret;
    }

    return XQC_OK;
}


xqc_int_t
xqc_conn_set_remote_transport_params(xqc_connection_t *conn,
    const xqc_transport_params_t *params, xqc_transport_params_type_t exttype)
{
    /* check transport parameters type */
    switch (exttype) {

    case XQC_TP_TYPE_CLIENT_HELLO:
        if (conn->conn_type != XQC_CONN_TYPE_SERVER) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|wrong transport_param_type|CH|");
            return -XQC_EPARAM;
        }
        break;

    case XQC_TP_TYPE_ENCRYPTED_EXTENSIONS:
        if (conn->conn_type != XQC_CONN_TYPE_CLIENT) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|wrong transport_param_type|EE|");
            return -XQC_EPARAM;
        }
        break;

    default:
        xqc_log(conn->log, XQC_LOG_ERROR, "|unknown transport_param_type|");
        return -XQC_EPARAM;
    }


    /* copy settings from transport parameters */
    xqc_trans_settings_t *settings = &conn->remote_settings;

    settings->max_stream_data_bidi_local = params->initial_max_stream_data_bidi_local;
    settings->max_stream_data_bidi_remote = params->initial_max_stream_data_bidi_remote;
    settings->max_stream_data_uni = params->initial_max_stream_data_uni;
    settings->max_data = params->initial_max_data;
    settings->max_streams_bidi = params->initial_max_streams_bidi;
    settings->max_streams_uni = params->initial_max_streams_uni;
    settings->max_idle_timeout = params->max_idle_timeout;
    settings->max_udp_payload_size = params->max_udp_payload_size;
    settings->stateless_reset_token_present = params->stateless_reset_token_present;

    if (params->stateless_reset_token_present) {
        xqc_memcpy(settings->stateless_reset_token, params->stateless_reset_token,
                   sizeof(settings->stateless_reset_token));

    } else {
        xqc_memset(settings->stateless_reset_token, 0, sizeof(settings->stateless_reset_token));
    }

    settings->ack_delay_exponent = params->ack_delay_exponent;
    settings->disable_active_migration = params->disable_active_migration;
    settings->max_ack_delay = params->max_ack_delay;
    settings->preferred_address = params->preferred_address;
    settings->active_connection_id_limit = params->active_connection_id_limit;

    settings->enable_multipath = params->enable_multipath;
    return XQC_OK;
}

xqc_int_t
xqc_conn_get_local_transport_params(xqc_connection_t *conn, xqc_transport_params_t *params)
{
    /* copy transport parameters from conn local settings */
    xqc_trans_settings_t *settings = &conn->local_settings;

    params->initial_max_stream_data_bidi_local = settings->max_stream_data_bidi_local;
    params->initial_max_stream_data_bidi_remote = settings->max_stream_data_bidi_remote;
    params->initial_max_stream_data_uni = settings->max_stream_data_uni;
    params->initial_max_data = settings->max_data;
    params->initial_max_streams_bidi = settings->max_streams_bidi;
    params->initial_max_streams_uni = settings->max_streams_uni;
    params->max_idle_timeout = settings->max_idle_timeout;
    params->max_udp_payload_size = settings->max_udp_payload_size;
    params->stateless_reset_token_present = settings->stateless_reset_token_present;

    if (settings->stateless_reset_token_present) {
        memcpy(params->stateless_reset_token, settings->stateless_reset_token,
               sizeof(params->stateless_reset_token));

    } else {
        memset(params->stateless_reset_token, 0, sizeof(params->stateless_reset_token));
    }

    params->ack_delay_exponent = settings->ack_delay_exponent;
    params->disable_active_migration = settings->disable_active_migration;
    params->max_ack_delay = settings->max_ack_delay;
    params->preferred_address = settings->preferred_address;
    params->active_connection_id_limit = settings->active_connection_id_limit;
    params->no_crypto = settings->no_crypto;
    params->enable_multipath = settings->enable_multipath;

    /* set other transport parameters */
    if (conn->conn_type == XQC_CONN_TYPE_SERVER
        && conn->original_dcid.cid_len > 0)
    {
        xqc_cid_set(&params->original_dest_connection_id,
                     conn->original_dcid.cid_buf, conn->original_dcid.cid_len);
        params->original_dest_connection_id_present = 1;

    } else {
        params->original_dest_connection_id_present = 0;
    }

    xqc_cid_set(&params->initial_source_connection_id,
                 conn->initial_scid.cid_buf, conn->initial_scid.cid_len);
    params->initial_source_connection_id_present = 1;

    params->retry_source_connection_id.cid_len = 0;
    params->retry_source_connection_id_present = 0;

    return XQC_OK;
}

static inline xqc_int_t
xqc_conn_check_transport_params(xqc_connection_t *conn, const xqc_transport_params_t *params)
{
    /* parameters MUST NOT be larger than 2^60 */
    if (params->initial_max_streams_bidi > XQC_MAX_STREAMS
        || params->initial_max_streams_uni > XQC_MAX_STREAMS
        || params->initial_max_stream_data_bidi_local > XQC_MAX_STREAMS
        || params->initial_max_stream_data_bidi_remote > XQC_MAX_STREAMS
        || params->initial_max_stream_data_uni > XQC_MAX_STREAMS)
    {
        return -XQC_TLS_TRANSPORT_PARAM;
    }

    if (conn->conn_type == XQC_CONN_TYPE_SERVER) {
        /* server MUST NOT received server-only parameters from client */
        if (params->original_dest_connection_id_present
            || params->preferred_address_present
            || params->retry_source_connection_id_present
            || params->stateless_reset_token_present)
        {
            return -XQC_TLS_TRANSPORT_PARAM;
        }
    }

    if (conn->conn_type == XQC_CONN_TYPE_CLIENT) {
        /* check retry_source_connection_id parameter if recv retry packet */
        if (conn->conn_flag & XQC_CONN_FLAG_RETRY_RECVD) {
            if (!params->retry_source_connection_id_present) {
                return -XQC_TLS_TRANSPORT_PARAM;
            }

        } else if (params->retry_source_connection_id_present) {
            return -XQC_TLS_TRANSPORT_PARAM;
        }
    }

    return XQC_OK;
}

void
xqc_conn_tls_transport_params_cb(const uint8_t *tp, size_t len, void *user_data)
{
    xqc_int_t ret;
    xqc_transport_params_t params;

    xqc_connection_t *conn = (xqc_connection_t *)user_data;
    xqc_transport_params_type_t tp_type = (conn->conn_type == XQC_CONN_TYPE_CLIENT 
        ? XQC_TP_TYPE_ENCRYPTED_EXTENSIONS : XQC_TP_TYPE_CLIENT_HELLO);

    memset(&params, 0, sizeof(xqc_transport_params_t));

    /* decode peer's transport parameter */
    ret = xqc_decode_transport_params(&params, tp_type, tp, len);
    if (ret != XQC_OK) {
        XQC_CONN_ERR(conn, TRA_TRANSPORT_PARAMETER_ERROR);
        return;
    }

    /* validate peer's transport parameter */
    ret = xqc_conn_check_transport_params(conn, &params);
    if (ret != XQC_OK) {
        XQC_CONN_ERR(conn, TRA_TRANSPORT_PARAMETER_ERROR);
        return;
    }

    /* set remote transport param */
    ret = xqc_conn_set_remote_transport_params(conn, &params, tp_type);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_conn_set_remote_transport_params failed|ret:%d|", ret);
        XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
        return;
    }

    /* save no crypto flag */
    if (params.no_crypto == 1) {
        conn->remote_settings.no_crypto = 1;
        conn->local_settings.no_crypto = 1;
        xqc_tls_set_no_crypto(conn->tls);
    }

    /* notify application layer to save transport parameter */
    if (conn->transport_cbs.save_tp_cb) {
        char tp_buf[8192] = {0};
        ssize_t written = xqc_write_transport_params(tp_buf, sizeof(tp_buf), &params);
        if (written < 0) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|write transport params error|");
            return;
        }

        conn->transport_cbs.save_tp_cb(tp_buf, written, conn->user_data);
    }
}


static inline xqc_hs_buffer_t *
xqc_create_hs_buffer(int buf_size)
{
    xqc_hs_buffer_t *buf = xqc_malloc(sizeof(xqc_hs_buffer_t) + buf_size);
    if (buf == NULL) {
        return NULL;
    }

    xqc_init_list_head(&buf->list_head);
    buf->data_len = buf_size;
    return buf;
}

xqc_int_t
xqc_conn_tls_crypto_data_cb(xqc_encrypt_level_t level, const uint8_t *data,
    size_t len, void *user_data)
{
    xqc_connection_t *conn = (xqc_connection_t *)user_data;
    xqc_list_head_t *crypto_data_list = NULL;
    xqc_list_head_t *retry_buff = NULL;

    switch (level) {
    case XQC_ENC_LEV_INIT:
        /* ClientHello, ServerHello, HelloRetryRequest are from initial encryption level */
        crypto_data_list = &conn->initial_crypto_data_list;
        break;

    case XQC_ENC_LEV_HSK:
        /* Encrypted Extension, Certificate, Certificate Verify, Finished */
        crypto_data_list = &conn->hsk_crypto_data_list;
        break;

    case XQC_ENC_LEV_1RTT:
        /* New Session Ticket is from application level */
        crypto_data_list = &conn->application_crypto_data_list;
        break;

    default:
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|impossible crypto data from encryption level|level:%d|", level);
        XQC_CONN_ERR(conn, TRA_CRYPTO_ERROR_BASE);
        return -XQC_EFATAL;
    }

    xqc_hs_buffer_t *hs_buf = xqc_create_hs_buffer(len);
    if (XQC_UNLIKELY(!hs_buf)) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_create_hs_buffer failed|");
        return -XQC_EMALLOC;
    }

    /* 
     * should limit the length of crypto data when the TLS layer generates unlimited data
     * or when the client sends duplicate ClientHello, etc.
     */
    conn->crypto_data_total_len += len;
    if (conn->crypto_data_total_len > XQC_CONN_MAX_CRYPTO_DATA_TOTAL_LEN) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|crypto_data_total_len exceed limit|total_len:%ui|", conn->crypto_data_total_len);

        xqc_free(hs_buf);
        XQC_CONN_ERR(conn, TRA_CRYPTO_BUFFER_EXCEEDED);
        return -XQC_EFATAL;
    }

    memcpy(hs_buf->data, data, len);
    xqc_list_add_tail(&hs_buf->list_head, crypto_data_list);

    return XQC_OK;
}


static void 
xqc_settings_copy_from_transport_params(xqc_trans_settings_t *dest,
    const xqc_transport_params_t *src)
{
    dest->max_stream_data_bidi_local = src->initial_max_stream_data_bidi_local;
    dest->max_stream_data_bidi_remote = src->initial_max_stream_data_bidi_remote;
    dest->max_stream_data_uni = src->initial_max_stream_data_uni;
    dest->max_data = src->initial_max_data;
    dest->max_streams_bidi = src->initial_max_streams_bidi;
    dest->max_streams_uni = src->initial_max_streams_uni;
    dest->max_idle_timeout = src->max_idle_timeout;
    dest->max_udp_payload_size = src->max_udp_payload_size;
    dest->stateless_reset_token_present = src->stateless_reset_token_present;

    if (src->stateless_reset_token_present) {
        xqc_memcpy(dest->stateless_reset_token, src->stateless_reset_token,
                   sizeof(dest->stateless_reset_token));

    } else {
        xqc_memset(dest->stateless_reset_token, 0, sizeof(dest->stateless_reset_token));
    }

    dest->ack_delay_exponent = src->ack_delay_exponent;
    dest->disable_active_migration = src->disable_active_migration;
    dest->max_ack_delay = src->max_ack_delay;
    dest->preferred_address = src->preferred_address;
    dest->active_connection_id_limit = src->active_connection_id_limit;

    dest->enable_multipath = src->enable_multipath;
}

void
xqc_conn_update_flow_ctl_settings(xqc_connection_t *conn)
{
    xqc_conn_flow_ctl_t *flow_ctl = &conn->conn_flow_ctl;
    xqc_trans_settings_t *remote_settings = &conn->remote_settings;

    flow_ctl->fc_max_data_can_send = remote_settings->max_data;
    flow_ctl->fc_max_streams_bidi_can_send = remote_settings->max_streams_bidi;
    flow_ctl->fc_max_streams_uni_can_send = remote_settings->max_streams_uni;
}


xqc_int_t
xqc_conn_set_early_remote_transport_params(xqc_connection_t *conn,
    const xqc_transport_params_t *params)
{
    if (conn->conn_type == XQC_CONN_TYPE_SERVER) {
        return -XQC_TLS_INVALID_STATE;
    }

    xqc_settings_copy_from_transport_params(&conn->remote_settings, params);
    xqc_conn_update_flow_ctl_settings(conn);
    return XQC_OK;
}

xqc_int_t
xqc_conn_tls_alpn_select_cb(const char *alpn, size_t alpn_len, void *user_data)
{
    xqc_connection_t *conn = (xqc_connection_t *)user_data;
    xqc_conn_server_on_alpn(conn, alpn, alpn_len);
    return XQC_OK;
}

xqc_int_t
xqc_conn_tls_cert_verify_cb(const unsigned char *certs[], const size_t cert_len[],
    size_t certs_len, void *user_data)
{
    xqc_connection_t *conn = (xqc_connection_t *)user_data;
    return conn->transport_cbs.cert_verify_cb(certs, cert_len, certs_len, conn->user_data);
}


void
xqc_conn_tls_session_cb(const char *data, size_t data_len, void *user_data)
{
    xqc_connection_t *conn = (xqc_connection_t *)user_data;
    conn->transport_cbs.save_session_cb(data, data_len, conn->user_data);
}

void
xqc_conn_tls_keylog_cb(const char *line, void *user_data)
{
#ifdef XQC_PRINT_SECRET
    xqc_connection_t *conn = (xqc_connection_t *)user_data;
    xqc_engine_t *eng = conn->engine;

    /* invoke engine's callback */
    if (eng->eng_callback.keylog_cb) {
        eng->eng_callback.keylog_cb(line, eng->user_data);
    }
#endif
}


void
xqc_conn_tls_error_cb(xqc_int_t tls_err, void *user_data)
{
    xqc_connection_t *conn = (xqc_connection_t *)user_data;
    xqc_log(conn->log, XQC_LOG_ERROR, "|tls error|0x%xi|", tls_err);
    XQC_CONN_ERR(conn, (tls_err | TRA_CRYPTO_ERROR_BASE));
}


void
xqc_free_crypto_buffer_list(xqc_list_head_t *buffer_list)
{
    xqc_list_head_t *head = buffer_list;
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, head) {
        xqc_list_del(pos);
        xqc_free(pos);
    }
}


xqc_int_t
xqc_conn_tls_cert_cb(const char *sni, void **chain, void **crt,
    void **key, void *user_data)
{
    xqc_connection_t *conn = (xqc_connection_t *)user_data;

    if (conn->transport_cbs.conn_cert_cb) {
        return conn->transport_cbs.conn_cert_cb(
            sni, chain, crt, key, conn->user_data);
    }

    /* if no callback is set, XQC_OK is also returned and the default cert will
       be used */
    return XQC_OK;
}

void
xqc_conn_tls_handshake_completed_cb(void *user_data)
{
    xqc_connection_t *conn = (xqc_connection_t *)user_data;

    conn->conn_flag |= XQC_CONN_FLAG_TLS_HSK_COMPLETED;
    conn->handshake_complete_time = xqc_monotonic_timestamp();
}

const xqc_tls_callbacks_t xqc_conn_tls_cbs = {
    .crypto_data_cb     = xqc_conn_tls_crypto_data_cb,
    .tp_cb              = xqc_conn_tls_transport_params_cb,
    .alpn_select_cb     = xqc_conn_tls_alpn_select_cb,
    .cert_verify_cb     = xqc_conn_tls_cert_verify_cb,
    .session_cb         = xqc_conn_tls_session_cb,
    .keylog_cb          = xqc_conn_tls_keylog_cb,
    .error_cb           = xqc_conn_tls_error_cb,
    .hsk_completed_cb   = xqc_conn_tls_handshake_completed_cb,
    .cert_cb            = xqc_conn_tls_cert_cb,
};

xqc_msec_t
xqc_conn_get_idle_timeout(xqc_connection_t *conn)
{
    if (conn->conn_type == XQC_CONN_TYPE_SERVER
        && !(conn->conn_flag & XQC_CONN_FLAG_HANDSHAKE_COMPLETED))
    {
        /* only server will limit idle timeout to init_idle_time_out before handshake completed */
        return conn->conn_settings.init_idle_time_out == 0
            ? XQC_CONN_INITIAL_IDLE_TIMEOUT : conn->conn_settings.init_idle_time_out;

    } else {
        return conn->local_settings.max_idle_timeout == 0
            ? XQC_CONN_DEFAULT_IDLE_TIMEOUT : conn->local_settings.max_idle_timeout;
    }
}


void
xqc_conn_decrease_unacked_stream_ref(xqc_connection_t *conn, xqc_packet_out_t *packet_out)
{
    int first_time_ack = 1;
    if (packet_out->po_flag & XQC_POF_STREAM_UNACK) {
        first_time_ack = first_time_ack && (!packet_out->po_acked);
        if (packet_out->po_origin) {
            first_time_ack = first_time_ack && (!packet_out->po_origin->po_acked);
        }
        if (first_time_ack) {
            xqc_stream_t *stream;
            for (int i = 0; i < XQC_MAX_STREAM_FRAME_IN_PO; i++) {
                if (packet_out->po_stream_frames[i].ps_is_used == 0) {
                    break;
                }
                stream = xqc_find_stream_by_id(packet_out->po_stream_frames[i].ps_stream_id, conn->streams_hash);
                if (stream != NULL) {
                    if (stream->stream_unacked_pkt == 0) {
                        xqc_log(conn->log, XQC_LOG_ERROR, "|stream_unacked_pkt too small|");

                    } else {
                        stream->stream_unacked_pkt--;
                    }

                    if (packet_out->po_stream_frames[i].ps_has_fin && stream->stream_stats.first_fin_ack_time == 0) {
                        stream->stream_stats.first_fin_ack_time = xqc_monotonic_timestamp();
                    }

                    /* Update stream state */
                    if (stream->stream_unacked_pkt == 0 && stream->stream_state_send == XQC_SEND_STREAM_ST_DATA_SENT) {
                        xqc_stream_send_state_update(stream, XQC_SEND_STREAM_ST_DATA_RECVD);
                        xqc_log(conn->log, XQC_LOG_DEBUG, "|stream enter DATA RECVD|");
                        xqc_stream_maybe_need_close(stream);
                    }
                }
            }
        }
        packet_out->po_flag &= ~XQC_POF_STREAM_UNACK;
    }
}

void
xqc_conn_increase_unacked_stream_ref(xqc_connection_t *conn, xqc_packet_out_t *packet_out)
{
    if ((packet_out->po_frame_types & XQC_FRAME_BIT_STREAM)
        && !(packet_out->po_flag & XQC_POF_STREAM_UNACK))
    {
        if ((!packet_out->po_origin)) {
            xqc_stream_t *stream;
            for (int i = 0; i < XQC_MAX_STREAM_FRAME_IN_PO; i++) {
                if (packet_out->po_stream_frames[i].ps_is_used == 0) {
                    break;
                }
                stream = xqc_find_stream_by_id(packet_out->po_stream_frames[i].ps_stream_id, conn->streams_hash);
                if (stream != NULL) {
                    stream->stream_unacked_pkt++;
                    /* Update stream state */
                    if (stream->stream_state_send == XQC_SEND_STREAM_ST_READY) {
                        xqc_stream_send_state_update(stream, XQC_SEND_STREAM_ST_SEND);
                    }
                    if (packet_out->po_stream_frames[i].ps_has_fin
                        && stream->stream_state_send == XQC_SEND_STREAM_ST_SEND)
                    {
                        xqc_stream_send_state_update(stream, XQC_SEND_STREAM_ST_DATA_SENT);
                    }
                }
            }
        }
        packet_out->po_flag |= XQC_POF_STREAM_UNACK;
    }
}


void
xqc_conn_update_stream_stats_on_sent(xqc_connection_t *conn, xqc_packet_out_t *packet_out, xqc_usec_t now)
{
    xqc_stream_id_t stream_id;
    xqc_stream_t *stream;
    if (packet_out->po_frame_types & XQC_FRAME_BIT_STREAM) {
        for (int i = 0; i < XQC_MAX_STREAM_FRAME_IN_PO; i++) {
            if (packet_out->po_stream_frames[i].ps_is_used == 0) {
                break;
            }
            stream_id = packet_out->po_stream_frames[i].ps_stream_id;
            stream = xqc_find_stream_by_id(stream_id, conn->streams_hash);
            if (stream) {
                if (stream->stream_stats.first_snd_time == 0) {
                    stream->stream_stats.first_snd_time = now;
                }
                if (packet_out->po_stream_frames[i].ps_has_fin) {
                    stream->stream_stats.local_fin_snd_time = now;
                }
                if (packet_out->po_stream_frames[i].ps_is_reset) {
                    stream->stream_stats.local_reset_time = now;
                }
            }

        }
    }
}


xqc_usec_t
xqc_conn_get_max_pto(xqc_connection_t *conn)
{
    xqc_path_ctx_t *path = NULL;
    xqc_usec_t max_pto = 0;

    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (path->path_state != XQC_PATH_STATE_ACTIVE) {
            continue;
        }

        max_pto = xqc_max(xqc_send_ctl_calc_pto(path->path_send_ctl), max_pto);
    }

    return max_pto;
}

xqc_usec_t
xqc_conn_get_min_srtt(xqc_connection_t *conn)
{
    xqc_path_ctx_t *path = NULL;
    xqc_usec_t min_srtt = XQC_MAX_UINT64_VALUE;

    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (path->path_state != XQC_PATH_STATE_ACTIVE) {
            continue;
        }

        min_srtt = xqc_min(path->path_send_ctl->ctl_srtt, min_srtt);
    }

    return min_srtt;
}

void
xqc_conn_timer_expire(xqc_connection_t *conn, xqc_usec_t now)
{
    xqc_timer_expire(&conn->conn_timer_manager, now);

    xqc_path_ctx_t *path = NULL;
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (path->path_state < XQC_PATH_STATE_CLOSED) {
            xqc_timer_expire(&path->path_send_ctl->path_timer_manager, now);
        }
    }
}

void xqc_conn_check_app_limit(xqc_connection_t *conn)
{
    xqc_path_ctx_t *path = NULL;
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (path->path_state != XQC_PATH_STATE_ACTIVE) {
            continue;
        }

        if (xqc_sample_check_app_limited(&path->path_send_ctl->sampler,
                                         path->path_send_ctl, conn->conn_send_queue))
        {
            xqc_pacing_on_app_limit(&path->path_send_ctl->ctl_pacing);
        }
    }
}

void
xqc_conn_closing(xqc_connection_t *conn)
{
    /* set closing notify flag, and do notify with CANNOT_DESTROY protection
       later during xqc_engine_process_conn */
    conn->conn_flag |= XQC_CONN_FLAG_CLOSING_NOTIFY;
}

void
xqc_conn_closing_notify(xqc_connection_t *conn)
{
    if (conn->transport_cbs.conn_closing
        && (conn->conn_flag & XQC_CONN_FLAG_CLOSING_NOTIFY))
    {
        conn->conn_flag &= ~XQC_CONN_FLAG_CLOSING_NOTIFY;

        if (!(conn->conn_flag & XQC_CONN_FLAG_CLOSING_NOTIFIED)) {
            conn->conn_flag |= XQC_CONN_FLAG_CLOSING_NOTIFIED;
            conn->transport_cbs.conn_closing(conn, &conn->scid_set.user_scid, conn->conn_err, conn->user_data);
        }
    }
}

void
xqc_conn_record_histroy_path(xqc_connection_t *conn, xqc_path_ctx_t *path)
{
    xqc_conn_path_history_t *history = conn->history_path;

    size_t index = history->path_cnt % XQC_MAX_PATHS_COUNT;
    xqc_path_record_info(path, &history->path_info[index]);
    history->path_cnt++;
}

xqc_int_t
xqc_conn_send_path_challenge(xqc_connection_t *conn, xqc_path_ctx_t *path)
{
    xqc_int_t ret = XQC_OK;

    /* generate random data for path challenge, store it to validate path_response */
    ret = xqc_generate_path_challenge_data(conn, path);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_generate_path_challenge_data error|%d|", ret);
        return ret;
    }

    /* write path challenge frame & send immediately */

    xqc_packet_out_t *packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_EWRITE_PKT;
    }

    ret = xqc_gen_path_challenge_frame(packet_out, path->path_challenge_data);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_gen_path_challenge_frame error|%d|", ret);
        goto end;
    }
    packet_out->po_used_size += ret;

    packet_out->po_is_path_specified = XQC_TRUE;
    packet_out->po_path_id = path->path_id;

    ret = xqc_enc_packet_with_pn(conn, path, packet_out);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_enc_packet_with_pn error|%d|", ret);
        goto end;
    }

    /* record the send time of packet */
    xqc_usec_t now = xqc_monotonic_timestamp();
    packet_out->po_sent_time = now;

    /* send data */
    ssize_t sent = conn->transport_cbs.write_socket_ex(path->path_id, conn->enc_pkt, conn->enc_pkt_len,
                                                       (struct sockaddr *)path->rebinding_addr,
                                                       path->rebinding_addrlen,
                                                       xqc_conn_get_user_data(conn));

    if (sent != conn->enc_pkt_len) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|write_socket error|conn:%p|pkt_num:%ui|size:%ud|sent:%z|pkt_type:%s|frame:%s|now:%ui|",
                conn, packet_out->po_pkt.pkt_num, packet_out->po_used_size, sent,
                xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type),
                xqc_frame_type_2_str(packet_out->po_frame_types), now);
        ret = -XQC_ESOCKET;
        goto end;

    } else {
        xqc_log(conn->log, XQC_LOG_INFO,
                "|<==|conn:%p|pkt_num:%ui|size:%ud|sent:%z|pkt_type:%s|frame:%s|inflight:%ud|now:%ui|",
                conn, packet_out->po_pkt.pkt_num, packet_out->po_used_size, sent,
                xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type),
                xqc_frame_type_2_str(packet_out->po_frame_types), path->path_send_ctl->ctl_bytes_in_flight, now);
        xqc_log_event(conn->log, TRA_DATAGRAMS_SENT, ret);
        xqc_log_event(conn->log, TRA_PACKET_SENT, packet_out);
    }

    xqc_pn_ctl_t *pn_ctl = xqc_get_pn_ctl(conn, path);
    pn_ctl->ctl_packet_number[packet_out->po_pkt.pkt_pns]++;

end:
    xqc_send_queue_remove_send(&packet_out->po_list);
    xqc_send_queue_insert_free(packet_out, &conn->conn_send_queue->sndq_free_packets, conn->conn_send_queue);
    return ret;
}

uint64_t 
xqc_conn_get_unscheduled_bytes(xqc_connection_t *conn)
{
    uint64_t scheduled_bytes = 0;
    uint64_t unsent_bytes_in_sndq;
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (path->path_schedule_bytes >= 0) {
            scheduled_bytes += path->path_schedule_bytes;

        } else {
            xqc_log(conn->log, XQC_LOG_ERROR, "|negative_path_scheduled_bytes!|");
        }
    }
    unsent_bytes_in_sndq = xqc_send_queue_get_unsent_packets_num(conn->conn_send_queue);
    unsent_bytes_in_sndq = unsent_bytes_in_sndq * xqc_conn_get_mss(conn);
    if (unsent_bytes_in_sndq >= scheduled_bytes) {
        return unsent_bytes_in_sndq - scheduled_bytes;

    } else {
        xqc_log(conn->log, XQC_LOG_ERROR, "|scheduled_bytes_more_than_unsent_bytes|"
                "sched_bytes:%ui|unsent_bytes:%ui|",
                scheduled_bytes, unsent_bytes_in_sndq);
        return 0;
    }
}


xqc_conn_type_t
xqc_conn_get_type(xqc_connection_t *conn)
{
    return conn->conn_type;
}

void
xqc_conn_set_pkt_filter_callback(xqc_connection_t *conn,
    xqc_conn_pkt_filter_callback_pt pkt_filter_cb,
    void *pkt_filter_cb_user_data)
{
    conn->pkt_filter_cb = pkt_filter_cb;
    conn->pkt_filter_cb_user_data = pkt_filter_cb_user_data;
}

void
xqc_conn_unset_pkt_filter_callback(xqc_connection_t *conn)
{
    if (conn) {
        conn->pkt_filter_cb = NULL;
        conn->pkt_filter_cb_user_data = NULL;
        xqc_log(conn->log, XQC_LOG_INFO, "|conn unset pkt filter callback, will"
                "use write_socket again");
    }
}
