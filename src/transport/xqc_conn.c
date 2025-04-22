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
#include "src/transport/xqc_recv_timestamps_info.h"
#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_cid.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_packet_parser.h"
#include "src/transport/xqc_utils.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_reinjection.h"
#include "src/transport/xqc_datagram.h"
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_fec.h"
#include "src/transport/xqc_fec_scheme.h"
#include "src/tls/xqc_tls.h"
#include <inttypes.h>


xqc_conn_settings_t internal_default_conn_settings = {
    .pacing_on                  = 0,
    .ping_on                    = 0,
    .so_sndbuf                  = 0,
    .sndq_packets_used_max      = 0,
    .linger                     = {.linger_on = 0, .linger_timeout = 0},
    .proto_version              = XQC_VERSION_V1,
    .init_idle_time_out         = XQC_CONN_INITIAL_IDLE_TIMEOUT,
    .idle_time_out              = XQC_CONN_DEFAULT_IDLE_TIMEOUT,
    .enable_multipath           = 0,
    .multipath_version          = XQC_MULTIPATH_10,
    .spurious_loss_detect_on    = 0,
    .anti_amplification_limit   = XQC_DEFAULT_ANTI_AMPLIFICATION_LIMIT,
    .keyupdate_pkt_threshold    = 0,
    .max_pkt_out_size           = XQC_PACKET_OUT_SIZE,
    .probing_pkt_out_size       = XQC_MAX_PACKET_OUT_SIZE,
    .max_datagram_frame_size    = 0,
    .mp_enable_reinjection      = 0,
    .mp_ack_on_any_path         = 0,
    .mp_ping_on                 = 0,
    .max_ack_delay              = XQC_DEFAULT_MAX_ACK_DELAY,
    .ack_frequency              = 2,
    .loss_detection_pkt_thresh  = XQC_kPacketThreshold,
    .pto_backoff_factor         = 2.0,
    .datagram_redundancy        = 0,
    .datagram_force_retrans_on  = 0,
    .datagram_redundant_probe   = 0,

    .reinj_flexible_deadline_srtt_factor = 1.1,
    .reinj_hard_deadline                 = 500000, /* 500ms */
    .reinj_deadline_lower_bound          = 20000, /* 20ms */

    .standby_path_probe_timeout = 0,
    .fec_conn_queue_rpr_timeout = 0,
    .enable_pmtud               = 0,
    .pmtud_probing_interval     = 500000,
    .marking_reinjection        = 0,

    .recv_rate_bytes_per_sec    = 0,
    .enable_stream_rate_limit   = 0,
    .close_dgram_redundancy= XQC_RED_NOT_USE,

    .scheduler_params           = {
                                    .bw_Bps_thr = 375000, 
                                    .loss_percent_thr_high = 30,
                                    .loss_percent_thr_low = 10,
                                    .pto_cnt_thr = 2,
                                    .rtt_us_thr_high = 2000000,
                                    .rtt_us_thr_low = 500000
                                  },
    .is_interop_mode            = 0,
#ifdef XQC_PROTECT_POOL_MEM
    .protect_pool_mem           = 0,
#endif
    .fec_level                  = XQC_FEC_CONN_LEVEL,    /** 0: connection level; 1: stream level */
    .enable_encode_fec          = 0,
    .enable_decode_fec          = 0,
    .fec_params                 = {
                                    .fec_code_rate                  = 0,
                                    .fec_ele_bit_size               = XQC_FEC_ELE_BIT_SIZE_DEFAULT,
                                    .fec_protected_frames           = XQC_FRAME_BIT_DATAGRAM | XQC_FRAME_BIT_STREAM,
                                    .fec_max_window_size            = XQC_SYMBOL_CACHE_LEN,
                                    .fec_mp_mode                    = XQC_FEC_MP_DEFAULT,
                                    .fec_max_symbol_num_per_block   = 10,
                                    .fec_encoder_schemes_num        = 0,
                                    .fec_decoder_schemes_num        = 0,
                                    .fec_encoder_scheme             = 0,
                                    .fec_decoder_scheme             = 0,
                                    .fec_blk_log_mod                = 1000,
                                    .fec_packet_mask_mode           = 0,
                                    .fec_log_on                     = 0,
                                  },
    .disable_send_mmsg          = 0,
    .init_max_path_id           = XQC_DEFAULT_INIT_MAX_PATH_ID,
    .control_pto_value          = 0,
    .max_udp_payload_size       = XQC_CONN_MAX_UDP_PAYLOAD_SIZE,

    .extended_ack_features     = 0,
    .max_receive_timestamps_per_ack    = 0,
    .receive_timestamps_exponent       = 0,
    .disable_pn_skipping               = 0
};


static void
xqc_conn_dgram_probe_timeout(xqc_gp_timer_id_t gp_timer_id,
    xqc_usec_t now, void *user_data)
{
    xqc_connection_t *conn = user_data;
    xqc_int_t ret = XQC_OK;
    size_t probe_size;
    if (conn->last_dgram && conn->last_dgram->data_len != 0) {
        probe_size = conn->last_dgram->data_len;
        ret = xqc_datagram_send(conn, conn->last_dgram->data, probe_size, NULL, XQC_DATA_QOS_PROBING);
        xqc_log(conn->log, XQC_LOG_DEBUG, "|timer_based_dgram_probe|ret:%d|dgram_sz:%z|", ret, probe_size);
    }
}

void
xqc_conn_set_default_sched_params(xqc_conn_settings_t *src_settings, xqc_conn_settings_t *settings)
{
    if (settings->scheduler_params.bw_Bps_thr == 0) {
        settings->scheduler_params.bw_Bps_thr = src_settings->scheduler_params.bw_Bps_thr;
    }

    if (settings->scheduler_params.loss_percent_thr_high == 0) {
        settings->scheduler_params.loss_percent_thr_high = src_settings->scheduler_params.loss_percent_thr_high;
    }

    if (settings->scheduler_params.loss_percent_thr_low == 0) {
        settings->scheduler_params.loss_percent_thr_low = src_settings->scheduler_params.loss_percent_thr_low;
    }

    if (settings->scheduler_params.pto_cnt_thr == 0) {
        settings->scheduler_params.pto_cnt_thr = src_settings->scheduler_params.pto_cnt_thr;
    }

    if (settings->scheduler_params.rtt_us_thr_high == 0) {
        settings->scheduler_params.rtt_us_thr_high = src_settings->scheduler_params.rtt_us_thr_high;
    }

    if (settings->scheduler_params.rtt_us_thr_low == 0) {
        settings->scheduler_params.rtt_us_thr_low = src_settings->scheduler_params.rtt_us_thr_low;
    }
}


void
xqc_server_set_conn_settings(xqc_engine_t *engine, const xqc_conn_settings_t *settings)
{
    engine->default_conn_settings.cong_ctrl_callback = settings->cong_ctrl_callback;
    engine->default_conn_settings.cc_params = settings->cc_params;
    engine->default_conn_settings.pacing_on = settings->pacing_on;
    engine->default_conn_settings.ping_on   = settings->ping_on;
    engine->default_conn_settings.so_sndbuf = settings->so_sndbuf;
    engine->default_conn_settings.sndq_packets_used_max = settings->sndq_packets_used_max;
    engine->default_conn_settings.linger    = settings->linger;
    engine->default_conn_settings.spurious_loss_detect_on = settings->spurious_loss_detect_on;
    engine->default_conn_settings.datagram_force_retrans_on = settings->datagram_force_retrans_on;
    engine->default_conn_settings.enable_pmtud = settings->enable_pmtud;
    engine->default_conn_settings.marking_reinjection = settings->marking_reinjection;
    engine->default_conn_settings.mp_ack_on_any_path = settings->mp_ack_on_any_path;
    engine->default_conn_settings.mp_ping_on = settings->mp_ping_on;
    engine->default_conn_settings.recv_rate_bytes_per_sec = settings->recv_rate_bytes_per_sec;
    engine->default_conn_settings.enable_stream_rate_limit = settings->enable_stream_rate_limit;
    engine->default_conn_settings.init_recv_window = settings->init_recv_window;
    engine->default_conn_settings.initial_rtt = settings->initial_rtt;
    engine->default_conn_settings.initial_pto_duration = settings->initial_pto_duration;
    engine->default_conn_settings.disable_send_mmsg = settings->disable_send_mmsg;
#ifdef XQC_PROTECT_POOL_MEM
    engine->default_conn_settings.protect_pool_mem = settings->protect_pool_mem;
#endif
    engine->default_conn_settings.adaptive_ack_frequency = settings->adaptive_ack_frequency;

    engine->default_conn_settings.scheduler_params = settings->scheduler_params;
    xqc_conn_set_default_sched_params(&internal_default_conn_settings, &engine->default_conn_settings);

    if (settings->max_udp_payload_size != 0) {
        engine->default_conn_settings.max_udp_payload_size = settings->max_udp_payload_size;
    }

    if (engine->default_conn_settings.init_recv_window) {
        engine->default_conn_settings.init_recv_window = xqc_max(engine->default_conn_settings.init_recv_window, XQC_QUIC_MAX_MSS);
    }

    if (settings->pmtud_probing_interval) {
        engine->default_conn_settings.pmtud_probing_interval = settings->pmtud_probing_interval;
    }

    if (settings->max_ack_delay) {
        engine->default_conn_settings.max_ack_delay = xqc_min(settings->max_ack_delay, XQC_DEFAULT_MAX_ACK_DELAY);
    }

    if (settings->datagram_redundant_probe) {
        engine->default_conn_settings.datagram_redundant_probe = xqc_max(settings->datagram_redundant_probe, 
                                                                 XQC_MIN_DATAGRAM_REDUNDANT_PROBE_INTERVAL);
    }

    if (settings->datagram_redundancy <= XQC_MAX_DATAGRAM_REDUNDANCY) {
        engine->default_conn_settings.datagram_redundancy = settings->datagram_redundancy;
    }

    if (settings->init_idle_time_out > 0) {
        engine->default_conn_settings.init_idle_time_out = settings->init_idle_time_out;
    }

    if (settings->fec_conn_queue_rpr_timeout > 0) {
        engine->default_conn_settings.fec_conn_queue_rpr_timeout = settings->fec_conn_queue_rpr_timeout;
    }

    if (settings->idle_time_out > 0) {
        engine->default_conn_settings.idle_time_out = settings->idle_time_out;
    }

    if (settings->anti_amplification_limit > 0) {
        engine->default_conn_settings.anti_amplification_limit = settings->anti_amplification_limit;
    }

    if (xqc_check_proto_version_valid(settings->proto_version)) {
        engine->default_conn_settings.proto_version = settings->proto_version;
    }

    engine->default_conn_settings.keyupdate_pkt_threshold = settings->keyupdate_pkt_threshold;
    engine->default_conn_settings.max_datagram_frame_size = settings->max_datagram_frame_size;

    if (settings->max_pkt_out_size != 0) {
        engine->default_conn_settings.max_pkt_out_size = settings->max_pkt_out_size;
    }

    if (engine->default_conn_settings.max_pkt_out_size > XQC_MAX_PACKET_OUT_SIZE) {
        engine->default_conn_settings.max_pkt_out_size = XQC_MAX_PACKET_OUT_SIZE;
    }

    engine->default_conn_settings.enable_multipath = settings->enable_multipath;
    engine->default_conn_settings.is_interop_mode = settings->is_interop_mode;

    if (xqc_conn_is_current_mp_version_supported(settings->multipath_version) == XQC_OK) {
        engine->default_conn_settings.multipath_version = settings->multipath_version;

    } else {
        engine->default_conn_settings.multipath_version = XQC_MULTIPATH_10;
    }

    if (settings->init_max_path_id == 0) {
        engine->default_conn_settings.init_max_path_id = XQC_DEFAULT_INIT_MAX_PATH_ID;
        
    } else {
        engine->default_conn_settings.init_max_path_id = settings->init_max_path_id;
    }

    engine->default_conn_settings.close_dgram_redundancy = settings->close_dgram_redundancy;

#ifdef XQC_ENABLE_FEC
    engine->default_conn_settings.enable_encode_fec = settings->enable_encode_fec;
    if (engine->default_conn_settings.enable_encode_fec) {
        xqc_set_fec_schemes(settings->fec_params.fec_encoder_schemes, settings->fec_params.fec_encoder_schemes_num,
                            engine->default_conn_settings.fec_params.fec_encoder_schemes, &engine->default_conn_settings.fec_params.fec_encoder_schemes_num);
        /* if no fec scheme was negotiated succesfully, set enable_encode_fec to 0 */
        engine->default_conn_settings.enable_encode_fec = engine->default_conn_settings.fec_params.fec_encoder_schemes_num == 0 ? 0 : settings->enable_encode_fec;
        if (settings->fec_params.fec_code_rate) {
            engine->default_conn_settings.fec_params.fec_code_rate = settings->fec_params.fec_code_rate;
        }
        if (settings->fec_params.fec_max_symbol_num_per_block) {
            engine->default_conn_settings.fec_params.fec_max_symbol_num_per_block = settings->fec_params.fec_max_symbol_num_per_block;
        }
        if (settings->fec_params.fec_mp_mode) {
            engine->default_conn_settings.fec_params.fec_mp_mode = settings->fec_params.fec_mp_mode;
        }
        if (settings->fec_level) {
            engine->default_conn_settings.fec_level = settings->fec_level;
        }
    }

    engine->default_conn_settings.enable_decode_fec = settings->enable_decode_fec;
    if (engine->default_conn_settings.enable_decode_fec) {
        xqc_set_fec_schemes(settings->fec_params.fec_decoder_schemes, settings->fec_params.fec_decoder_schemes_num,
                            engine->default_conn_settings.fec_params.fec_decoder_schemes, &engine->default_conn_settings.fec_params.fec_decoder_schemes_num);
        /* if no fec scheme was negotiated succesfully, set enable_decode_fec to 0 */
        engine->default_conn_settings.enable_decode_fec = engine->default_conn_settings.fec_params.fec_decoder_schemes_num == 0 ? 0 : settings->enable_decode_fec;
        if (settings->fec_params.fec_max_window_size) {
            engine->default_conn_settings.fec_params.fec_max_window_size = xqc_min(settings->fec_params.fec_max_window_size, XQC_SYMBOL_CACHE_LEN);
        }
        if (settings->fec_params.fec_blk_log_mod) {
            engine->default_conn_settings.fec_params.fec_blk_log_mod = settings->fec_params.fec_blk_log_mod;
        }
        if (settings->fec_params.fec_log_on) {
            engine->default_conn_settings.fec_params.fec_log_on = settings->fec_params.fec_log_on;
        }
        if (settings->fec_params.fec_packet_mask_mode) {
            engine->default_conn_settings.fec_params.fec_packet_mask_mode = settings->fec_params.fec_packet_mask_mode;
        }
    }

#endif

    engine->default_conn_settings.scheduler_callback = settings->scheduler_callback;
    engine->default_conn_settings.reinj_ctl_callback = settings->reinj_ctl_callback;
    engine->default_conn_settings.mp_enable_reinjection = settings->mp_enable_reinjection;

    if ((settings->extended_ack_features & XQC_ACK_EXT_FEATURE_BIT_RECV_TS) 
        && !settings->enable_multipath)
    {
        /* 
         * Bit 1 indicates whether Receive Timestamps are enabled.
         * Currently, we only use receive_timestamps features, so set extended_ack_features = XQC_ACK_EXT_FEATURE_BIT_RECV_TS.
         * 
         * Besides, multipath-quic and ack_ext are incompatible right now, disable ack_ext when enable multipath.
         * TODO: coordinate them in the future.
         */
        engine->default_conn_settings.extended_ack_features = XQC_ACK_EXT_FEATURE_BIT_RECV_TS;
        engine->default_conn_settings.max_receive_timestamps_per_ack = settings->max_receive_timestamps_per_ack;
        engine->default_conn_settings.receive_timestamps_exponent = settings->receive_timestamps_exponent;
    }

    if (settings->ack_frequency > 0) {
        engine->default_conn_settings.ack_frequency = settings->ack_frequency;
    }

    if (settings->pto_backoff_factor > 0) {
        engine->default_conn_settings.pto_backoff_factor = settings->pto_backoff_factor;
    }

    if (settings->loss_detection_pkt_thresh > 0) {
        engine->default_conn_settings.loss_detection_pkt_thresh = settings->loss_detection_pkt_thresh;
    }

    if (settings->reinj_flexible_deadline_srtt_factor > 0) {
        engine->default_conn_settings.reinj_flexible_deadline_srtt_factor = settings->reinj_flexible_deadline_srtt_factor;
    }

    if (settings->reinj_hard_deadline > 0) {
        engine->default_conn_settings.reinj_hard_deadline = settings->reinj_hard_deadline;
    }

    if (settings->reinj_deadline_lower_bound > 0) {
        engine->default_conn_settings.reinj_deadline_lower_bound = settings->reinj_deadline_lower_bound;
    }

    if (settings->standby_path_probe_timeout > 0) {
        /* no less than 500ms */
        engine->default_conn_settings.standby_path_probe_timeout = xqc_max(settings->standby_path_probe_timeout, XQC_MIN_STANDBY_RPOBE_TIMEOUT);
    }

    if (settings->keyupdate_pkt_threshold != UINT64_MAX) {
        engine->default_conn_settings.keyupdate_pkt_threshold = settings->keyupdate_pkt_threshold;
    }

    if (settings->probing_pkt_out_size > 0) {
        engine->default_conn_settings.probing_pkt_out_size = settings->probing_pkt_out_size;
    }
}

static const char * const xqc_conn_flag_to_str[XQC_CONN_FLAG_SHIFT_NUM] = {
    [XQC_CONN_FLAG_WAIT_WAKEUP_SHIFT]           = "WAIT_WAKEUP",
    [XQC_CONN_FLAG_HANDSHAKE_COMPLETED_SHIFT]   = "HSK_DONE",
    [XQC_CONN_FLAG_CAN_SEND_1RTT_SHIFT]         = "CAN_SEND_1RTT",
    [XQC_CONN_FLAG_TICKING_SHIFT]               = "TICKING",
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
    [XQC_CONN_FLAG_LINGER_CLOSING_SHIFT]        = "LINGER_CLOSING",
    [XQC_CONN_FLAG_RETRY_RECVD_SHIFT]           = "RETRY_RECVD",
    [XQC_CONN_FLAG_TLS_HSK_COMPLETED_SHIFT]     = "TLS_HSK_CMPTD",
    [XQC_CONN_FLAG_RECV_NEW_PATH_SHIFT]         = "RECV_NEW_PATH",
    [XQC_CONN_FLAG_VALIDATE_REBINDING_SHIFT]    = "VALIDATE_REBINDING",
    [XQC_CONN_FLAG_CONN_CLOSING_NOTIFY_SHIFT]   = "CLOSING_NOTIFY",
    [XQC_CONN_FLAG_CONN_CLOSING_NOTIFIED_SHIFT] = "CLOSING_NOTIFIED",
    [XQC_CONN_FLAG_DGRAM_WAIT_FOR_1RTT_SHIFT]   = "DGRAM_WAIT_FOR_1RTT",
    [XQC_CONN_FLAG_LOCAL_TP_UPDATED_SHIFT]      = "LOCAL_TP_UPDATED",
    [XQC_CONN_FLAG_PMTUD_PROBING_SHIFT]         = "PMTUD_PROBING",
    [XQC_CONN_FLAG_NO_DGRAM_NOTIFIED_SHIFT]     = "NO_DGRAM_NOTIFIED",
    [XQC_CONN_FLAG_DGRAM_MSS_NOTIFY_SHIFT]      = "DGRAM_MSS_NOTIFY",
    [XQC_CONN_FLAG_MP_WAIT_MP_READY_SHIFT]      = "MP_WAIT_MP_READY",
    [XQC_CONN_FLAG_MP_READY_NOTIFY_SHIFT]       = "MP_READY_NOTIFY",
};


const char *
xqc_conn_flag_2_str(xqc_connection_t *conn, xqc_conn_flag_t conn_flag)
{
    xqc_engine_t *engine = conn->engine;
    engine->conn_flag_str_buf[0] = '\0';
    size_t pos = 0;
    int wsize;
    for (int i = 0; i < XQC_CONN_FLAG_SHIFT_NUM; i++) {
        if (conn_flag & 1ULL << i) {
            wsize = snprintf(engine->conn_flag_str_buf + pos, sizeof(engine->conn_flag_str_buf) - pos, "%s ", 
                             xqc_conn_flag_to_str[i]);
            if (wsize < 0 || wsize >= sizeof(engine->conn_flag_str_buf) - pos) {
                break;
            }
            pos += wsize;
        }
    }

    return engine->conn_flag_str_buf;
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
    uint32_t i, co_bytes;
    char *co_str = conn->conn_settings.conn_option_str;

    xqc_conn_set_default_settings(ls);
    xqc_conn_set_default_settings(rs);

    /* set local default setting values */
    if (conn->conn_settings.is_interop_mode) {
        ls->max_streams_bidi = 128;
        ls->max_streams_uni = 128;

    } else {
        ls->max_streams_bidi = 1024;
        ls->max_streams_uni = 1024;
    }
    ls->max_stream_data_bidi_remote = XQC_MAX_RECV_WINDOW;
    ls->max_stream_data_uni = XQC_MAX_RECV_WINDOW;
    
    if (conn->conn_settings.enable_stream_rate_limit) {
        ls->max_stream_data_bidi_local = conn->conn_settings.init_recv_window;

    } else {
        ls->max_stream_data_bidi_local = XQC_MAX_RECV_WINDOW;
    }

    if (conn->conn_settings.is_interop_mode) {
        ls->max_data = 1024 * 1024;
        
    } else {
        if (conn->conn_settings.recv_rate_bytes_per_sec) {
            ls->max_data = conn->conn_settings.recv_rate_bytes_per_sec * XQC_FC_INIT_RTT / 1000000;
            ls->max_data = xqc_max(XQC_MIN_RECV_WINDOW, ls->max_data);
            ls->max_data = xqc_min(XQC_MAX_RECV_WINDOW, ls->max_data);

        } else {
            /* max_data is the sum of stream_data on all uni and bidi streams */
            ls->max_data = ls->max_streams_bidi * ls->max_stream_data_bidi_local
                + ls->max_streams_uni * ls->max_stream_data_uni;
        }
    }

    ls->max_idle_timeout = conn->conn_settings.idle_time_out;

    ls->max_udp_payload_size = conn->conn_settings.max_udp_payload_size;

    ls->active_connection_id_limit = XQC_CONN_ACTIVE_CID_LIMIT;

    ls->enable_multipath = conn->conn_settings.enable_multipath;
    
    ls->multipath_version = conn->conn_settings.multipath_version;
    ls->init_max_path_id = conn->conn_settings.init_max_path_id;
    ls->enable_pmtud = conn->conn_settings.enable_pmtud;

    ls->max_datagram_frame_size = conn->conn_settings.max_datagram_frame_size;
    ls->disable_active_migration = ls->enable_multipath ? 0 : 1;

    ls->max_ack_delay = conn->conn_settings.max_ack_delay;

    /* init local conn options */
    for (i = 0, co_bytes = 0; i < XQC_CO_STR_MAX_LEN; i++) {
        if (co_bytes == 4) {
            if ((co_str[i] != ',' && co_str[i] != '\0')) {
                // invalid CO. Stop decoding.
                break;

            } else {
                ls->conn_options[ls->conn_option_num++] = XQC_CO_TAG(co_str[i - 4], co_str[i - 3], co_str[i - 2], co_str[i - 1]);
            }

            co_bytes = 0;

        } else {
            if (xqc_char_is_letter_or_number(co_str[i])) {
                co_bytes++;

            } else {
                // invalid CO. Stop decoding.
                break;
            }
        }
    }

    ls->close_dgram_redundancy = conn->conn_settings.close_dgram_redundancy;

#ifdef XQC_ENABLE_FEC
    /* init FEC transport params */
    if (conn->conn_settings.enable_encode_fec) {
        ls->enable_encode_fec = conn->conn_settings.enable_encode_fec;
        ls->fec_max_symbols_num = conn->conn_settings.fec_params.fec_max_symbol_num_per_block;
        ls->fec_encoder_schemes_num = conn->conn_settings.fec_params.fec_encoder_schemes_num;
        for (xqc_int_t i = 0; i < conn->conn_settings.fec_params.fec_encoder_schemes_num; i++) {
            ls->fec_encoder_schemes[i] = conn->conn_settings.fec_params.fec_encoder_schemes[i];
        }
    }
    if (conn->conn_settings.enable_decode_fec) {
        ls->enable_decode_fec = conn->conn_settings.enable_decode_fec;
        ls->fec_decoder_schemes_num = conn->conn_settings.fec_params.fec_decoder_schemes_num;
        for (xqc_int_t i = 0; i < conn->conn_settings.fec_params.fec_decoder_schemes_num; i++) {
            ls->fec_decoder_schemes[i] = conn->conn_settings.fec_params.fec_decoder_schemes[i];
        }
    }
#endif

}


void 
xqc_conn_init_flow_ctl(xqc_connection_t *conn)
{
    xqc_conn_flow_ctl_t *flow_ctl = &conn->conn_flow_ctl;
    xqc_trans_settings_t * settings = & conn->local_settings;

    /* TODO: send params are inited to be zero, until zerortt inited or handshake done */
    flow_ctl->fc_max_data_can_send = settings->max_data; /* replace with the value specified by peer after handshake */
    flow_ctl->fc_max_data_can_recv = settings->max_data;
    flow_ctl->fc_max_streams_bidi_can_send = settings->max_streams_bidi; /* replace with the value specified by peer after handshake */
    flow_ctl->fc_max_streams_bidi_can_recv = settings->max_streams_bidi;
    flow_ctl->fc_max_streams_uni_can_send = settings->max_streams_uni; /* replace with the value specified by peer after handshake */
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

static void
xqc_conn_set_ack_ext_local_settings(xqc_trans_settings_t *local_settings, const xqc_conn_settings_t *settings)
{
    if (settings->extended_ack_features & XQC_ACK_EXT_FEATURE_BIT_RECV_TS) {
        local_settings->extended_ack_features = 2;
        local_settings->max_receive_timestamps_per_ack = settings->max_receive_timestamps_per_ack;
        local_settings->receive_timestamps_exponent = settings->receive_timestamps_exponent;
    }
}

xqc_connection_t *
xqc_conn_create(xqc_engine_t *engine, xqc_cid_t *dcid, xqc_cid_t *scid,
    const xqc_conn_settings_t *settings, void *user_data, xqc_conn_type_t type)
{
    xqc_connection_t *xc = NULL;
#ifdef XQC_PROTECT_POOL_MEM
    xqc_memory_pool_t *pool = xqc_create_pool(engine->config->conn_pool_size, settings->protect_pool_mem);
#else
    xqc_memory_pool_t *pool = xqc_create_pool(engine->config->conn_pool_size);
#endif
    if (pool == NULL) {
        return NULL;
    }

#ifdef XQC_PROTECT_POOL_MEM
    xqc_log(engine->log, XQC_LOG_DEBUG, "|mempool|protect:%d|page_sz:%z|",
            pool->protect_block, pool->page_size);
#endif

    xc = xqc_pcalloc(pool, sizeof(xqc_connection_t));
    if (xc == NULL) {
        goto fail;
    }

    xc->conn_settings = *settings;

    xqc_memcpy(xc->conn_settings.conn_option_str, settings->conn_option_str, XQC_CO_STR_MAX_LEN);
    xqc_conn_set_default_sched_params(&engine->default_conn_settings, &xc->conn_settings);

    if (xc->conn_settings.max_udp_payload_size == 0) {
        xc->conn_settings.max_udp_payload_size = engine->default_conn_settings.max_udp_payload_size;
    }

    if (xc->conn_settings.initial_rtt == 0) {
        xc->conn_settings.initial_rtt = XQC_kInitialRtt_us;
    }

    if (xc->conn_settings.max_ack_delay == 0) {
        xc->conn_settings.max_ack_delay = XQC_DEFAULT_MAX_ACK_DELAY;
    }
    xc->conn_settings.max_ack_delay = xqc_min(xc->conn_settings.max_ack_delay, XQC_DEFAULT_MAX_ACK_DELAY);

    if (xc->conn_settings.datagram_redundant_probe) {
        xc->conn_settings.datagram_redundant_probe = xqc_max(xc->conn_settings.datagram_redundant_probe,                    
                                                             XQC_MIN_DATAGRAM_REDUNDANT_PROBE_INTERVAL);
    }

    if (xc->conn_settings.mp_enable_reinjection & XQC_REINJ_UNACK_BEFORE_SCHED) {
        xc->conn_settings.mp_enable_reinjection |= XQC_REINJ_UNACK_AFTER_SEND;
    }


    if (xc->conn_settings.datagram_redundancy > XQC_MAX_DATAGRAM_REDUNDANCY) {
        xc->conn_settings.datagram_redundancy = XQC_MAX_DATAGRAM_REDUNDANCY;
    }

    if (xc->conn_settings.datagram_redundancy) {
        if (xc->conn_settings.datagram_redundancy == 1) {
            /* reinject packets on any path */
            xc->conn_settings.scheduler_callback = xqc_rap_scheduler_cb;

        } else {
            /* do not reinject packets on the same path */
            xc->conn_settings.scheduler_callback = xqc_minrtt_scheduler_cb;
        }

        xc->conn_settings.reinj_ctl_callback = xqc_dgram_reinj_ctl_cb;
        xc->conn_settings.mp_enable_reinjection |= XQC_REINJ_UNACK_AFTER_SEND;
    }

    if (xc->conn_settings.init_recv_window) {
        xc->conn_settings.init_recv_window = xqc_max(xc->conn_settings.init_recv_window, XQC_QUIC_MAX_MSS);

    } else {
        xc->conn_settings.init_recv_window = XQC_MIN_RECV_WINDOW;
    }

    if (xc->conn_settings.standby_path_probe_timeout) {
        xc->conn_settings.standby_path_probe_timeout = xqc_max(xc->conn_settings.standby_path_probe_timeout, XQC_MIN_STANDBY_RPOBE_TIMEOUT);
    }

    if (xc->conn_settings.max_pkt_out_size == 0) {
        xc->conn_settings.max_pkt_out_size = engine->default_conn_settings.max_pkt_out_size;
    }

    if (xc->conn_settings.max_pkt_out_size > XQC_MAX_PACKET_OUT_SIZE) {
        xc->conn_settings.max_pkt_out_size = XQC_MAX_PACKET_OUT_SIZE;
    }

    if (xc->conn_settings.pmtud_probing_interval == 0) {
        xc->conn_settings.pmtud_probing_interval = engine->default_conn_settings.pmtud_probing_interval;
    }

    if (xc->conn_settings.ack_frequency == 0) {
        xc->conn_settings.ack_frequency = engine->default_conn_settings.ack_frequency;
    }

    if (xc->conn_settings.pto_backoff_factor == 0) {
        xc->conn_settings.pto_backoff_factor = engine->default_conn_settings.pto_backoff_factor;
    }
    
    if (xc->conn_settings.loss_detection_pkt_thresh == 0) {
        xc->conn_settings.loss_detection_pkt_thresh = engine->default_conn_settings.loss_detection_pkt_thresh;
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

    if (xc->conn_settings.idle_time_out == 0) {
        xc->conn_settings.idle_time_out = XQC_CONN_DEFAULT_IDLE_TIMEOUT;
    }

    if (xc->conn_settings.anti_amplification_limit == 0) {
        xc->conn_settings.anti_amplification_limit = XQC_DEFAULT_ANTI_AMPLIFICATION_LIMIT;
    }

    if (xc->conn_settings.reinj_flexible_deadline_srtt_factor == 0) {
        xc->conn_settings.reinj_flexible_deadline_srtt_factor = engine->default_conn_settings.reinj_flexible_deadline_srtt_factor;
    }

    if (xc->conn_settings.reinj_hard_deadline == 0) {
        xc->conn_settings.reinj_hard_deadline = engine->default_conn_settings.reinj_hard_deadline;
    }

    if (xqc_conn_is_current_mp_version_supported(xc->conn_settings.multipath_version) != XQC_OK) {
        xc->conn_settings.multipath_version = XQC_MULTIPATH_10;
    }

    if (xc->conn_settings.init_max_path_id == 0) {
        xc->conn_settings.init_max_path_id = XQC_DEFAULT_INIT_MAX_PATH_ID;
    }

    if (xc->conn_settings.probing_pkt_out_size == 0) {
        xc->conn_settings.probing_pkt_out_size = engine->default_conn_settings.probing_pkt_out_size;
    }

    xc->conn_settings.extended_ack_features = 0;
    xc->conn_settings.max_receive_timestamps_per_ack = 0;
    xc->conn_settings.receive_timestamps_exponent = 0;

#ifdef XQC_ENABLE_FEC
    xc->fec_neg_fail_reason = 0;

    if (xc->conn_settings.enable_encode_fec) {
        if (xc->conn_settings.fec_params.fec_code_rate == 0) {
            xc->conn_settings.fec_params.fec_code_rate = engine->default_conn_settings.fec_params.fec_code_rate;
        }
        if (xc->conn_settings.fec_params.fec_ele_bit_size == 0) {
            xc->conn_settings.fec_params.fec_ele_bit_size = engine->default_conn_settings.fec_params.fec_ele_bit_size;
        }
        if (xc->conn_settings.fec_params.fec_protected_frames == 0) {
            xc->conn_settings.fec_params.fec_protected_frames = engine->default_conn_settings.fec_params.fec_protected_frames;
        }
        if (xc->conn_settings.fec_params.fec_max_symbol_num_per_block == 0) {
            xc->conn_settings.fec_params.fec_max_symbol_num_per_block = engine->default_conn_settings.fec_params.fec_max_symbol_num_per_block;
        }
        if (xc->conn_settings.fec_params.fec_mp_mode == 0) {
            xc->conn_settings.fec_params.fec_mp_mode = engine->default_conn_settings.fec_params.fec_mp_mode;
        }
        if (xc->conn_settings.fec_level == 0) {
            xc->conn_settings.fec_level = engine->default_conn_settings.fec_level;
        }
    }
    if (xc->conn_settings.enable_decode_fec) {
        if (xc->conn_settings.fec_params.fec_max_window_size) {
            xc->conn_settings.fec_params.fec_max_window_size = xqc_min(xc->conn_settings.fec_params.fec_max_window_size, XQC_SYMBOL_CACHE_LEN);

        } else {
            xc->conn_settings.fec_params.fec_max_window_size = engine->default_conn_settings.fec_params.fec_max_window_size;
        }
        if (xc->conn_settings.fec_params.fec_blk_log_mod == 0) {
            xc->conn_settings.fec_params.fec_blk_log_mod = engine->default_conn_settings.fec_params.fec_blk_log_mod;
        }
        if (xc->conn_settings.fec_params.fec_log_on == 0) {
            xc->conn_settings.fec_params.fec_log_on = engine->default_conn_settings.fec_params.fec_log_on;
        }

        if (xc->conn_settings.fec_params.fec_packet_mask_mode == 0) {
            xc->conn_settings.fec_params.fec_packet_mask_mode = engine->default_conn_settings.fec_params.fec_packet_mask_mode;
        }
    }
    if (xc->conn_settings.fec_conn_queue_rpr_timeout == 0) {
        xc->conn_settings.fec_conn_queue_rpr_timeout = engine->default_conn_settings.fec_conn_queue_rpr_timeout;
    }

    if (xc->conn_settings.enable_encode_fec
        || xc->conn_settings.enable_decode_fec)
    {
        xc->fec_ctl = xqc_fec_ctl_create(xc);
        if (xc->fec_ctl == NULL) {
            xc->conn_settings.enable_encode_fec = 0;
            xc->conn_settings.enable_decode_fec = 0;
        }
    }

#endif
    xqc_conn_init_trans_settings(xc);
    xqc_conn_set_ack_ext_local_settings(&xc->local_settings, settings);

    xqc_conn_init_flow_ctl(xc);
    xqc_conn_init_key_update_ctx(xc);

    xc->conn_pool = pool;

    xqc_init_cid_set(&xc->dcid_set);
    xqc_init_cid_set(&xc->scid_set);

    if (xqc_cid_set_add_path(&xc->dcid_set, XQC_INITIAL_PATH_ID) != XQC_OK) {
        goto fail;
    }

    if (xqc_cid_set_add_path(&xc->scid_set, XQC_INITIAL_PATH_ID) != XQC_OK) {
        goto fail;
    }

    xqc_cid_set_update_state(&xc->dcid_set, XQC_INITIAL_PATH_ID, XQC_CID_SET_USED);
    xqc_cid_set_update_state(&xc->scid_set, XQC_INITIAL_PATH_ID, XQC_CID_SET_USED);

    if (xqc_cid_set_insert_cid(&xc->dcid_set, dcid, XQC_CID_USED,
                               xc->local_settings.active_connection_id_limit, 
                               XQC_INITIAL_PATH_ID))
    {
        goto fail;
    }
    xqc_cid_copy(&(xc->dcid_set.current_dcid), dcid);
    xqc_hex_dump(xc->dcid_set.current_dcid_str, dcid->cid_buf, dcid->cid_len);
    xc->dcid_set.current_dcid_str[dcid->cid_len * 2] = '\0';

    if (xqc_cid_set_insert_cid(&xc->scid_set, scid, XQC_CID_USED,
                               xc->remote_settings.active_connection_id_limit, 
                               XQC_INITIAL_PATH_ID))
    {
        goto fail;
    }
    xqc_cid_copy(&(xc->scid_set.user_scid), scid);
    xqc_hex_dump(xc->scid_set.original_scid_str, scid->cid_buf, scid->cid_len);
    xc->scid_set.original_scid_str[scid->cid_len * 2] = '\0';
    xqc_cid_set_set_largest_seq_or_rpt(&xc->scid_set, XQC_INITIAL_PATH_ID, scid->cid_seq_num);
    xqc_cid_copy(&(xc->initial_scid), scid);

    xc->engine = engine;
    xc->log = xqc_log_init(engine->log->log_level, engine->log->log_event, engine->log->qlog_importance, engine->log->log_timestamp,
                           engine->log->log_level_name, engine, engine->log->log_callbacks, engine->log->user_data);
    xc->log->scid = xc->scid_set.original_scid_str;
    xc->transport_cbs = engine->transport_cbs;
    xc->user_data = user_data;
    xc->discard_vn_flag = 0;
    xc->conn_type = type;
    xc->conn_flag = 0;
    xc->conn_state = (type == XQC_CONN_TYPE_SERVER) ? XQC_CONN_STATE_SERVER_INIT : XQC_CONN_STATE_CLIENT_INIT;
    xqc_log_event(xc->log, CON_CONNECTION_STATE_UPDATED, xc);
    xc->zero_rtt_count = 0;
    xc->conn_create_time = xqc_monotonic_timestamp();
    xc->handshake_complete_time = 0;
    xc->first_data_send_time = 0;
    xc->max_stream_id_bidi_remote = -1;
    xc->max_stream_id_uni_remote = -1;
    xc->last_dgram = NULL;
    xc->pkt_out_size = xqc_min(xc->conn_settings.max_pkt_out_size, xc->conn_settings.max_udp_payload_size - XQC_PACKET_OUT_EXT_SPACE);
    xc->max_pkt_out_size = xc->conn_settings.probing_pkt_out_size;
    xc->probing_pkt_out_size = xc->conn_settings.probing_pkt_out_size;
    xc->probing_cnt = 0;

    for (xqc_encrypt_level_t encrypt_level = XQC_ENC_LEV_INIT; encrypt_level < XQC_ENC_LEV_MAX; encrypt_level++) {
        xc->undecrypt_count[encrypt_level] = 0;
    }

    xc->enc_pkt = xqc_malloc(XQC_PACKET_OUT_BUF_CAP);
    if (NULL == xc->enc_pkt) {
        xqc_log(xc->log, XQC_LOG_ERROR, "|malloc enc pkt buf fail");
        goto fail;
    }
    xc->enc_pkt_cap = XQC_PACKET_OUT_BUF_CAP;

    xc->conn_send_queue = xqc_send_queue_create(xc);
    if (xc->conn_send_queue == NULL) {
        goto fail;
    }

    xqc_conn_init_timer_manager(xc);

    if (xc->conn_settings.datagram_redundant_probe) {
        xc->last_dgram = xqc_var_buf_create_with_limit(XQC_MAX_PACKET_OUT_SIZE, XQC_MAX_PACKET_OUT_SIZE);
        if (xc->last_dgram == NULL) {
            goto fail;
        }

        xc->dgram_probe_timer = xqc_conn_register_gp_timer(xc, "dgram_probe", xqc_conn_dgram_probe_timeout, xc);
        if (xc->dgram_probe_timer < 0) {
            xqc_log(xc->log, XQC_LOG_ERROR, "|register dgram probe timer error|");
            goto fail;
        }
    }

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
    if (xqc_insert_conns_hash(engine->conns_hash, xc,
                              xc->scid_set.user_scid.cid_buf,
                              xc->scid_set.user_scid.cid_len))
    {
        goto fail;
    }

    /* set scheduler callback (default: minRTT) */
    if (xc->conn_settings.scheduler_callback.xqc_scheduler_init) {
        xc->scheduler_callback = &xc->conn_settings.scheduler_callback;

    } else {
        xc->scheduler_callback = &xqc_minrtt_scheduler_cb;
    }

    xc->scheduler = xqc_pcalloc(xc->conn_pool, xc->scheduler_callback->xqc_scheduler_size());
    if (xc->scheduler == NULL) {
        goto fail;
    }
    xc->scheduler_callback->xqc_scheduler_init(xc->scheduler, xc->log, &xc->conn_settings.scheduler_params);

    /* set reinject control callback if reinjection enabled */
    if (xc->conn_settings.reinj_ctl_callback.xqc_reinj_ctl_init) {
        xc->reinj_callback = &xc->conn_settings.reinj_ctl_callback;
        xc->reinj_ctl = xqc_pcalloc(xc->conn_pool, xc->reinj_callback->xqc_reinj_ctl_size());
        if (xc->reinj_ctl == NULL) {
            goto fail;
        }
        xc->reinj_callback->xqc_reinj_ctl_init(xc->reinj_ctl, xc);
    }


    /* 
     * Init paths after the scheduler and the reinjection controller are initialized. 
     */
    if (xqc_conn_init_paths_list(xc) != XQC_OK) {
        goto fail;
    }

    xc->pkt_filter_cb = NULL;

    /* for datagram */
    xc->next_dgram_id = 0;
    xqc_init_list_head(&xc->dgram_0rtt_buffer_list);
    xqc_init_list_head(&xc->ping_notification_list);

    xqc_log(xc->log, XQC_LOG_DEBUG, "|success|scid:%s|dcid:%s|conn:%p|",
            xqc_scid_str(engine, &xc->scid_set.user_scid), xqc_dcid_str(engine, &xc->dcid_set.current_dcid), xc);
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

    /* generate sr token for server's initial cid */
    xqc_gen_reset_token(&new_scid, new_scid.sr_token,
                        XQC_STATELESS_RESET_TOKENLEN,
                        engine->config->reset_token_key,
                        engine->config->reset_token_keylen);

    conn = xqc_conn_create(engine, dcid, &new_scid, settings, user_data, XQC_CONN_TYPE_SERVER);
    if (conn == NULL) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|fail to create connection|");
        return NULL;
    }

    xqc_cid_copy(&conn->original_dcid, scid);

    if (xqc_cid_in_cid_set(&conn->scid_set, &conn->original_dcid, XQC_INITIAL_PATH_ID) == NULL) {
        /*
         * if server choose it's own cid, then if server Initial is lost,
         * and if client Initial retransmit, server might use odcid to
         * find the created conn
         */
        if (xqc_insert_conns_hash(engine->conns_hash, conn,
                                  conn->original_dcid.cid_buf,
                                  conn->original_dcid.cid_len))
        {
            goto fail;
        }

        xqc_log(conn->log, XQC_LOG_INFO, "|hash odcid conn|odcid:%s|conn:%p|",
                xqc_dcid_str(engine, &conn->original_dcid), conn);
    }

    ret = xqc_memcpy_with_cap(conn->local_addr, sizeof(conn->local_addr), 
                              local_addr, local_addrlen);
    if (ret == XQC_OK) {
        conn->local_addrlen = local_addrlen;

    } else {
        xqc_log(conn->log, XQC_LOG_ERROR, 
                "|local addr too large|addr_len:%d|", 
                (int)local_addrlen);
        goto fail;
    }

    ret = xqc_memcpy_with_cap(conn->peer_addr, sizeof(conn->peer_addr), 
                              peer_addr, peer_addrlen);
    if (ret == XQC_OK) {
        conn->peer_addrlen = peer_addrlen;

    } else {
        xqc_log(conn->log, XQC_LOG_ERROR, 
                "|peer addr too large|addr_len:%d|", 
                (int)peer_addrlen);
        goto fail;
    }

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

    xqc_log_event(conn->log, CON_CONNECTION_STARTED, conn, XQC_LOG_REMOTE_EVENT);

    if (conn->transport_cbs.server_accept) {
        if (conn->transport_cbs.server_accept(engine, conn, &conn->scid_set.user_scid, user_data) < 0) {
            xqc_log(engine->log, XQC_LOG_ERROR, "|server_accept callback return error|");
            XQC_CONN_ERR(conn, TRA_CONNECTION_REFUSED_ERROR);
            goto fail;
        }
        conn->conn_flag |= XQC_CONN_FLAG_UPPER_CONN_EXIST;
    }

    return conn;

fail:
    xqc_conn_destroy(conn);
    return NULL;
}


xqc_int_t
xqc_conn_client_on_alpn(xqc_connection_t *conn, const unsigned char *alpn, size_t alpn_len)
{
    xqc_int_t ret;

    /* save alpn */
    conn->alpn = xqc_calloc(1, alpn_len + 1);
    if (conn->alpn == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|malloc alpn buffer error|");
        return -XQC_EMALLOC;
    }

    xqc_memcpy(conn->alpn, alpn, alpn_len);
    conn->alpn_len = alpn_len;

    /* set quic callbacks to quic connection */
    ret = xqc_engine_get_alpn_callbacks(conn->engine, alpn, alpn_len, &conn->app_proto_cbs);
    if (ret != XQC_OK) {
        xqc_free(conn->alpn);
        conn->alpn = NULL;
        conn->alpn_len = 0;
        xqc_log(conn->log, XQC_LOG_ERROR, "|can't get application layer callback|ret:%d", ret);
        return ret;
    }

    return XQC_OK;
}


xqc_int_t
xqc_conn_server_on_alpn(xqc_connection_t *conn, const unsigned char *alpn, size_t alpn_len)
{
    xqc_int_t ret;

    /* save alpn */
    conn->alpn = xqc_calloc(1, alpn_len + 1);
    if (conn->alpn == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|malloc alpn buffer error|");
        return -XQC_EMALLOC;
    }

    xqc_memcpy(conn->alpn, alpn, alpn_len);
    conn->alpn_len = alpn_len;

    /* set quic callbacks to quic connection */
    ret = xqc_engine_get_alpn_callbacks(conn->engine, alpn, alpn_len, &conn->app_proto_cbs);
    if (ret != XQC_OK) {
        xqc_free(conn->alpn);
        conn->alpn = NULL;
        conn->alpn_len = 0;
        xqc_log(conn->log, XQC_LOG_ERROR, "|can't get application layer callback|ret:%d", ret);
        return ret;
    }

    uint8_t tp_buf[XQC_MAX_TRANSPORT_PARAM_BUF_LEN] = {0};
    size_t tp_len = 0;

    /* do callback */
    if (conn->app_proto_cbs.conn_cbs.conn_create_notify) {
        if (conn->app_proto_cbs.conn_cbs.conn_create_notify(conn, &conn->scid_set.user_scid,
            conn->user_data, conn->proto_data))
        {
            goto err;
        }
        conn->conn_flag |= XQC_CONN_FLAG_UPPER_CONN_EXIST;
    }

    xqc_datagram_record_mss(conn);

    if (conn->conn_flag & XQC_CONN_FLAG_LOCAL_TP_UPDATED) {
        ret = xqc_conn_encode_local_tp(conn, tp_buf, 
                                       XQC_MAX_TRANSPORT_PARAM_BUF_LEN, &tp_len);
        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|server encode tp error|ret:%d|", ret);
            goto err;
        }

        ret = xqc_tls_update_tp(conn->tls, tp_buf, tp_len);

        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|server tls update tp error|ret:%d|", ret);
            goto err;
        }

        conn->conn_flag &= ~XQC_CONN_FLAG_LOCAL_TP_UPDATED;
        xqc_log(conn->log, XQC_LOG_INFO, 
                "|update tp|max_datagram_frame_size:%ud|", 
                conn->local_settings.max_datagram_frame_size);
    }

    return XQC_OK;

err:
    XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
    return -TRA_INTERNAL_ERROR;
}

#ifdef XQC_ENABLE_FEC
void
xqc_fec_conn_info_print(xqc_connection_t *conn, char *output, size_t output_size)
{
    int32_t i, ret;
    size_t curr_size;

    i = ret = 0;
    curr_size = 0;
    xqc_memset(output, 0, output_size);

    if (conn->fec_ctl == NULL) {
        goto full;
    }

    /* fec info, must be ended with ',' */
    ret = snprintf(output, output_size,
                   "%u,%u,%u,%u,%u,%u,%u,%u,%u,%s,%s,%d,%"PRIu64",%"PRIu64","
                   ,
                   conn->conn_settings.fec_params.fec_encoder_scheme ? 1 : 0,
                   conn->conn_settings.fec_params.fec_decoder_scheme ? 1 : 0,
                   conn->fec_ctl->fec_processed_blk_num > 0 ? 1 : 0,
                   conn->fec_ctl->fec_recover_pkt_cnt,
                   conn->fec_ctl->fec_recover_failed_cnt,
                   conn->fec_ctl->fec_flush_blk_cnt,
                   conn->fec_ctl->fec_recv_repair_num_total,
                   conn->fec_neg_fail_reason,
                   conn->fec_ctl->fec_send_ahead,
                   xqc_get_fec_scheme_str(conn->conn_settings.fec_params.fec_encoder_scheme),
                   xqc_get_fec_scheme_str(conn->conn_settings.fec_params.fec_decoder_scheme),
                   conn->fec_ctl->fec_enable_stream_num,
                   conn->fec_ctl->conn_avg_recv_delay / 1000,
                   conn->fec_ctl->fec_avg_opt_time / 1000
                   );

    curr_size += ret;

    if (curr_size >= output_size) {
        goto full;
    }

full:
    curr_size = xqc_min(curr_size, output_size);
    for (i = curr_size - 1; i >= 0; i--) {
        if (output[i] == ',') {
            output[i] = '\0';
            break;
        }
    }
    output[output_size - 1] = '\0';
}

#endif
void
xqc_common_conn_info_print(xqc_connection_t *conn, char *output, size_t output_size)
{
    int32_t i, ret;
    size_t curr_size;;

    i = ret = 0;
    curr_size = 0;
    xqc_memset(output, 0, output_size);

    /* common info, must be ended with ',' */
    ret = snprintf(output, output_size,
                   "%d,%"PRIu64",%"PRIu64",%"PRIu64",%d,"
                   ,
                   conn->conn_video_frames,
                   conn->conn_avg_close_delay / 1000,
                   conn->conn_avg_recv_delay / 1000,
                   conn->conn_latest_close_delay / 1000,
                   conn->burst_loss_cnt
                   );

    curr_size += ret;

    if (curr_size >= output_size) {
        goto full;
    }

full:
    curr_size = xqc_min(curr_size, output_size);
    for (i = curr_size - 1; i >= 0; i--) {
        if (output[i] == ',') {
            output[i] = '\0';
            break;
        }
    }
    output[output_size - 1] = '\0';
}

void
xqc_extern_conn_info_print(xqc_connection_t *conn, xqc_conn_stats_t *conn_stats)
{
    int32_t i, ret;
    char *buff = conn_stats->extern_conn_info;
    size_t curr_size, buff_size;

#ifdef XQC_ENABLE_FEC
    char fec_buf[XQC_MAX_FEC_BUF_LEN];
    xqc_fec_conn_info_print(conn, fec_buf, XQC_MAX_FEC_BUF_LEN);
#endif

    char common_buf[XQC_MAX_COMMON_BUF_LEN];
    xqc_common_conn_info_print(conn, common_buf, XQC_MAX_COMMON_BUF_LEN);

    i = ret = 0;
    curr_size = 0;
    buff_size = XQC_EXTERN_CONN_INFO_LEN;

    /* conn info */
    ret = snprintf(buff, buff_size,
                   "{"
#ifdef XQC_ENABLE_FEC
                   "\"fec\": \"%s\","
#endif
                   "\"common\": \"%s\","
                   "}"
#ifdef XQC_ENABLE_FEC
                   ,
                   fec_buf
#endif
                   ,
                   common_buf
                   );

    curr_size += ret;

    if (curr_size >= buff_size) {
        goto full;
    }

full:
    curr_size = xqc_min(curr_size, buff_size);
    buff[curr_size] = '\0';
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
        xqc_log_event(xc->log, CON_CONNECTION_STATE_UPDATED, xc);
        return;
    }

    uint8_t         fec_flag;
    xqc_conn_stats_t conn_stats;
    xqc_fec_schemes_e ensch, desch;
    unsigned char *ensch_str, *desch_str, *fec_mpm_str;

    fec_flag = 0;
    ensch = xc->conn_settings.fec_params.fec_encoder_scheme;
    desch = xc->conn_settings.fec_params.fec_decoder_scheme;
    ensch_str = desch_str = fec_mpm_str = "NO_FEC";

    xqc_memzero(&conn_stats, sizeof(xqc_conn_stats_t));
    xqc_conn_get_stats_internal(xc, &conn_stats);
#ifdef XQC_ENABLE_FEC
    fec_flag = 1;
    ensch_str = xqc_get_fec_scheme_str(ensch);
    desch_str = xqc_get_fec_scheme_str(desch);
    fec_mpm_str = xqc_get_fec_mp_mode_str(xc->fec_ctl);
#endif

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
            "mp_enable:%ud|create:%ud|validated:%ud|active:%ud|path_info:%s|alpn:%*s|rebind_count:%d|"
            "rebind_valid:%d|rtx_pkt:%ud|tlp_pkt:%ud|"
            "snd_pkt:%ud|spurious_loss:%ud|detected_loss:%ud|"
            "max_pto:%ud|finished_streams:%ud|cli_bidi_s:%ud|svr_bidi_s:%ud|"
            "fec_exist:%ud|"
            "fec_ensch:%s|fec_desch:%s|fec_neg_fail:%ud|"
            "fec_mp_mode:%s|send_fec_pkts:%ud|recovered_fec_num:%ud|"
            "max_po_size:%uz|max_probing_size:%uz|ppo_size:%uz|"
            "ext_conn_info:%s|max_acked_po_size:%uz|enable_pmtud:%ui|avg_closed_time:%ui|"
            ,
            xc,
            xc->conn_flag & XQC_CONN_FLAG_HAS_0RTT ? 1:0,
            xc->conn_flag & XQC_CONN_FLAG_0RTT_OK ? 1:0,
            xc->conn_type == XQC_CONN_TYPE_SERVER ? (xc->conn_flag & XQC_CONN_FLAG_TOKEN_OK ? 1:0) : (-1),
            (xc->handshake_complete_time > xc->conn_create_time) ? (xc->handshake_complete_time - xc->conn_create_time) : 0,
            (xc->first_data_send_time > xc->conn_create_time) ? (xc->first_data_send_time - xc->conn_create_time) : 0,
            xqc_monotonic_timestamp() - xc->conn_create_time, xc->key_update_ctx.key_update_cnt,
            xc->conn_err, xc->conn_close_msg ? xc->conn_close_msg : "", xqc_conn_addr_str(xc),
            xqc_calc_delay(xc->conn_hsk_recv_time, xc->conn_create_time),
            xqc_calc_delay(xc->conn_close_recv_time, xc->conn_create_time),
            xqc_calc_delay(xc->conn_close_send_time, xc->conn_create_time),
            xqc_calc_delay(xc->conn_last_recv_time, xc->conn_create_time),
            xqc_calc_delay(xc->conn_last_send_time, xc->conn_create_time),
            xc->enable_multipath, xc->create_path_count, xc->validated_path_count, xc->active_path_count,
            conn_stats.conn_info, out_alpn_len, out_alpn, conn_stats.total_rebind_count,
            conn_stats.total_rebind_valid,
            conn_stats.lost_count, conn_stats.tlp_count,
            conn_stats.send_count, conn_stats.spurious_loss_count, xc->detected_loss_cnt,
            xc->max_pto_cnt, xc->finished_streams, xc->cli_bidi_streams, xc->svr_bidi_streams,
            fec_flag,
            ensch_str, desch_str, xc->fec_neg_fail_reason,
            fec_mpm_str, conn_stats.send_fec_cnt, xc->fec_ctl ? xc->fec_ctl->fec_recover_pkt_cnt : 0,
            xc->pkt_out_size, xc->max_pkt_out_size, xc->probing_pkt_out_size,
            conn_stats.extern_conn_info, xc->max_acked_po_size, 
            xc->local_settings.enable_pmtud & xc->remote_settings.enable_pmtud, xc->conn_avg_close_delay
            );
    xqc_log_event(xc->log, CON_CONNECTION_CLOSED, xc);

    xqc_engine_remove_wakeup_queue(xc->engine, xc);

    xqc_list_head_t *pos, *next;
    xqc_stream_t    *stream;
    xqc_packet_in_t *packet_in;

    /* destroy streams, must before conn_close_notify */
    xqc_list_for_each_safe(pos, next, &xc->conn_all_streams) {
        stream = xqc_list_entry(pos, xqc_stream_t, all_stream_list);
        XQC_STREAM_CLOSE_MSG(stream, "conn closed");
        xqc_destroy_stream(stream);
    }

    xqc_conn_destroy_0rtt_datagram_buffer_list(xc);

    if (xc->conn_settings.datagram_redundant_probe
        && xc->dgram_probe_timer >= 0) {
        xqc_conn_unregister_gp_timer(xc, xc->dgram_probe_timer);
    }

    if (xc->last_dgram) {
        xqc_var_buf_free(xc->last_dgram);
        xc->last_dgram = NULL;
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

    /* destroy gp_timer list */
    xqc_timer_destroy_gp_timer_list(&xc->conn_timer_manager);

    xqc_send_queue_destroy(xc->conn_send_queue);
#ifdef XQC_ENABLE_FEC
    if (xc->fec_ctl) {
        xqc_fec_ctl_destroy(xc->fec_ctl);
    }
#endif
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

    xqc_conn_destroy_ping_notification_list(xc);

    /* remove from engine's conns_hash and destroy cid_set*/
    xqc_conn_destroy_cids(xc);

    if (xc->tls) {
        xqc_tls_destroy(xc->tls);
    }

    if (xc->enc_pkt) {
        xqc_free(xc->enc_pkt);
    }

    xqc_log_release(xc->log);

    if (xc->alpn) {
        xqc_free(xc->alpn);
    }

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

void 
xqc_conn_encode_transport_state(xqc_connection_t *conn, char *buf, size_t buf_sz)
{
    xqc_path_ctx_t *path;
    xqc_list_head_t *pos, *next;
    xqc_send_ctl_t *send_ctl;
    int ret, i;
    size_t cursor;
    uint64_t cwnd, inflight, sched_queue, pacing_rate, est_bw;
    xqc_usec_t srtt_ms;

    cursor = 0;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        send_ctl = path->path_send_ctl;
        if (path->path_state == XQC_PATH_STATE_ACTIVE) {
            //KB
            cwnd = send_ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(send_ctl->ctl_cong) >> 10;
            //KBps
            est_bw = xqc_send_ctl_get_est_bw(send_ctl) >> 10;
            srtt_ms = send_ctl->ctl_srtt / 1000;
            //KB
            inflight = send_ctl->ctl_bytes_in_flight >> 10;
            //KB
            sched_queue = path->path_schedule_bytes >> 10;
            //KBps
            pacing_rate = xqc_send_ctl_get_pacing_rate(send_ctl) >> 10;
            ret = snprintf(buf + cursor, buf_sz - cursor, 
                           "(%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64"),",
                           path->path_id, cwnd, inflight, sched_queue, est_bw, pacing_rate, srtt_ms);

            cursor += ret;

            if (cursor >= buf_sz) {
                break;
            }
        }
    }

    cursor = xqc_min(cursor, buf_sz);
    for (i = cursor - 1; i >= 0; i--) {
        if (buf[i] == ',') {
            buf[i] = '\0';
            break;
        }
    }
    buf[buf_sz - 1] = '\0';
}

xqc_int_t 
xqc_conn_send_ping_internal(xqc_connection_t *conn, void *ping_user_data, xqc_bool_t notify)
{
    xqc_int_t ret;
    xqc_path_ctx_t *path;
    xqc_list_head_t *pos, *next;
    xqc_bool_t has_ping;
    xqc_ping_record_t *pr;
    
    ret = XQC_OK;

    if (conn->conn_state >= XQC_CONN_STATE_CLOSING) {
        return ret;
    }

    pr = xqc_conn_create_ping_record(conn);

    if (pr == NULL) {
        return -XQC_EMALLOC;
    }

    has_ping = XQC_FALSE;

    if (conn->enable_multipath && conn->conn_settings.mp_ping_on) {
        xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
            path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
            if (path->path_state == XQC_PATH_STATE_ACTIVE) {
                ret = xqc_write_ping_to_packet(conn, path, ping_user_data, notify, pr);
                if (ret < 0) {
                    xqc_log(conn->log, XQC_LOG_ERROR, "|write ping error|path:%ui|", path->path_id);

                } else {
                    has_ping = XQC_TRUE;
                }
            }
        }

    } else {
        ret = xqc_write_ping_to_packet(conn, NULL, ping_user_data, notify, pr);
        if (ret < 0) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|write ping error|");
            
        } else {
            has_ping = XQC_TRUE;
        }
    }

    if (!has_ping) {
        xqc_conn_destroy_ping_record(pr);
        return ret;
    }

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
                xqc_scid_str(engine, cid));
        return -XQC_ECONN_NFOUND;
    }

    ret = xqc_conn_send_ping_internal(conn, ping_user_data, XQC_TRUE);
    if (ret) {
        return ret;
    }

    xqc_engine_remove_wakeup_queue(engine, conn);
    xqc_engine_add_active_queue(engine, conn);

    xqc_engine_conn_logic(engine, conn);
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

void 
xqc_conn_try_to_update_mss(xqc_connection_t *conn)
{
    xqc_path_ctx_t *path;
    xqc_list_head_t *pos, *next;
    size_t min_pkt_out_size = 0;
    size_t max_pkt_out_size = 0;
    
    /* try to update conn MTU */
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        if (path->path_state >= XQC_PATH_STATE_CLOSING) {
            continue;
        }

        if (min_pkt_out_size == 0 || path->curr_pkt_out_size < min_pkt_out_size) {
            min_pkt_out_size = path->curr_pkt_out_size;
            max_pkt_out_size = path->path_max_pkt_out_size;
        }
    }

    if (min_pkt_out_size > conn->pkt_out_size) {
        conn->pkt_out_size = min_pkt_out_size;
        /* try to update PMTUD probing info */
        conn->max_pkt_out_size = max_pkt_out_size;
        conn->probing_pkt_out_size = max_pkt_out_size;
        conn->probing_cnt = 0;
        /* launch new probing immediately */
        conn->conn_flag |= XQC_CONN_FLAG_PMTUD_PROBING;
        xqc_timer_unset(&conn->conn_timer_manager, XQC_TIMER_PMTUD_PROBING);
        /* update datagram mss */
        xqc_datagram_record_mss(conn);
    }
}


ssize_t
xqc_send_burst(xqc_connection_t *conn, xqc_path_ctx_t *path, struct iovec *iov, int cnt)
{
    ssize_t sent_size = 0;
    int sent_cnt = 0;
    
    if (conn->pkt_filter_cb) {

        for (sent_cnt = 0; sent_cnt < cnt; sent_cnt++) {
            sent_size = conn->pkt_filter_cb(iov[sent_cnt].iov_base,
                                       iov[sent_cnt].iov_len, 
                                       (struct sockaddr *)conn->peer_addr,
                                       conn->peer_addrlen, 
                                       conn->pkt_filter_cb_user_data);
            if (sent_size < 0) {
                xqc_log(conn->log, XQC_LOG_ERROR,  
                        "|pkt_filter_cb error|conn:%p|"
                        "size:%ud|sent:%z|sent_cnt:%d|", 
                        conn, iov[sent_cnt].iov_len, sent_size, 
                        sent_cnt);
                
                sent_size = sent_size == XQC_SOCKET_EAGAIN ? -XQC_EAGAIN : -XQC_ESOCKET;
                break;
            }
        }

        if (sent_size == -XQC_EAGAIN && sent_cnt == 0) {
            sent_cnt = -XQC_EAGAIN;
            
        } else if (sent_size == -XQC_ESOCKET) {
            sent_cnt = -XQC_EPACKET_FILETER_CALLBACK;
        }

    } else if (conn->transport_cbs.write_mmsg_ex) {
        sent_cnt = conn->transport_cbs.write_mmsg_ex(path->path_id, iov, cnt,
                                                (struct sockaddr *)path->peer_addr,
                                                path->peer_addrlen,
                                                xqc_conn_get_user_data(conn));

        if (sent_cnt < 0) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|error send mmsg|");
            if (sent_cnt == XQC_SOCKET_ERROR) {
                path->path_flag |= XQC_PATH_FLAG_SOCKET_ERROR;
                if (xqc_conn_should_close(conn, path)) {
                    xqc_log(conn->log, XQC_LOG_ERROR, "|socket exception, close connection|");
                    conn->conn_state = XQC_CONN_STATE_CLOSED;
                    xqc_log_event(conn->log, CON_CONNECTION_STATE_UPDATED, conn);
                }
            }

            sent_cnt = sent_cnt == XQC_SOCKET_EAGAIN ? -XQC_EAGAIN : -XQC_ESOCKET;
        }

    } else {
        sent_cnt = conn->transport_cbs.write_mmsg(iov, cnt,
                                              (struct sockaddr *)conn->peer_addr,
                                              conn->peer_addrlen,
                                              xqc_conn_get_user_data(conn));
        if (sent_cnt < 0) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|error send mmsg|");
            if (sent_cnt == XQC_SOCKET_ERROR) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|socket exception, close connection|");
                conn->conn_state = XQC_CONN_STATE_CLOSED;
                xqc_log_event(conn->log, CON_CONNECTION_STATE_UPDATED, conn);
            }

            sent_cnt = sent_cnt == XQC_SOCKET_EAGAIN ? -XQC_EAGAIN : -XQC_ESOCKET;
        }
    }

    return sent_cnt;
}

xqc_int_t
xqc_check_acked_or_dropped_pkt(xqc_connection_t *conn,
    xqc_packet_out_t *packet_out, xqc_send_type_t send_type)
{
    if (xqc_send_ctl_indirectly_ack_or_drop_po(conn, packet_out)) {
        return XQC_TRUE;
    }

    if (send_type == XQC_SEND_TYPE_RETRANS) {
        /* If not a TLP packet, mark it LOST */
        packet_out->po_flag |= XQC_POF_LOST;
    }

    xqc_log(conn->log, XQC_LOG_DEBUG,
            "|conn:%p|pkt_num:%ui|size:%ud|pkt_type:%s|frame:%s|",
            conn, packet_out->po_pkt.pkt_num, packet_out->po_used_size,
            xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type),
            xqc_frame_type_2_str(conn->engine, packet_out->po_frame_types));

    return XQC_FALSE;
}


void
xqc_conn_schedule_packets(xqc_connection_t *conn,  xqc_list_head_t *head, 
    xqc_bool_t  packets_are_limited_by_cc, xqc_send_type_t send_type)
{
    ssize_t ret;
    uint32_t send_repair_num, src_syb_num;
    uint64_t stream_id;
    xqc_bool_t cc_blocked, reset_rpr_timer;
    xqc_usec_t now, cq_fin_timeout;
    xqc_path_ctx_t *path;
    xqc_list_head_t *pos, *next;
    xqc_packet_out_t *packet_out;
    xqc_stream_t *stream;

    now = xqc_monotonic_timestamp();
    reset_rpr_timer = 0;

    xqc_list_for_each_safe(pos, next, head) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        /* 1. 已设置特定路径发送的包，例如：PATH_CHALLENGE PATH_RESPONSE MP_ACK(原路径ACK) */
        if (xqc_packet_out_on_specific_path(conn, packet_out, &path)) {
            if (path == NULL) {
                continue;
            }
            xqc_log(conn->log, XQC_LOG_DEBUG, "|specify|path:%ui|state:%d|frame_type:%s|stream_id:%ui|stream_offset:%ui|",
                    path->path_id, path->path_state, xqc_frame_type_2_str(conn->engine, packet_out->po_frame_types),
                    packet_out->po_stream_id, packet_out->po_stream_offset);

        /* 2. schedule packet multipath */
        } else {
            path = conn->scheduler_callback->
                   xqc_scheduler_get_path(conn->scheduler, 
                                          conn, packet_out, 
                                          packets_are_limited_by_cc, 
                                          0, &cc_blocked);
            if (path == NULL) {
                if (cc_blocked) {
                    conn->sched_cc_blocked++;
                    if (packet_out->po_sched_cwnd_blk_ts == 0) {
                        packet_out->po_sched_cwnd_blk_ts = now;
                    }
                }
                if (xqc_timer_is_set(&conn->conn_timer_manager, XQC_TIMER_QUEUE_FIN)) {
                    reset_rpr_timer = 1;
                }
                break;
            }
        }

#ifdef XQC_ENABLE_FEC
        /* FEC encode packets */
        if (conn->conn_settings.enable_encode_fec
            && conn->conn_settings.fec_params.fec_encoder_scheme
            && !(packet_out->po_frame_types & XQC_FRAME_BIT_SID
                 || packet_out->po_frame_types & XQC_FRAME_BIT_REPAIR_SYMBOL))
        {
            if (xqc_is_packet_fec_protected(conn, packet_out) == XQC_OK) {
                xqc_process_fec_protected_packet(conn, packet_out);
                /* if insert repair packet after current po, update next pointer; */
                next = pos->next;
                reset_rpr_timer = 1;
            }
        }
#endif

        xqc_path_send_buffer_append(path, packet_out, &path->path_schedule_buf[send_type]);
    }
    if (conn->conn_settings.fec_params.fec_encoder_scheme == XQC_PACKET_MASK_CODE
        && send_type == XQC_SEND_TYPE_NORMAL
        && reset_rpr_timer)
    {
        cq_fin_timeout = xqc_conn_get_queue_fin_timeout(conn);
        if (cq_fin_timeout) {
            xqc_timer_set(&conn->conn_timer_manager, XQC_TIMER_QUEUE_FIN, now, cq_fin_timeout * 1000);
        }
    }
}

static inline void
xqc_conn_log_sent_packet(xqc_connection_t *c, xqc_packet_out_t *po, 
    xqc_usec_t timestamp)
{
    int index = c->snd_pkt_stats.curr_index;
    c->snd_pkt_stats.pkt_frames[index] = po->po_frame_types;
    c->snd_pkt_stats.pkt_size[index] = po->po_used_size;
    c->snd_pkt_stats.pkt_timestamp[index] = xqc_calc_delay(timestamp, 
                                                           c->conn_create_time);
    c->snd_pkt_stats.pkt_timestamp[index] /= 1000;
    c->snd_pkt_stats.pkt_types[index] = po->po_pkt.pkt_type;
    c->snd_pkt_stats.pkt_pn[index] = po->po_pkt.pkt_num;
    c->snd_pkt_stats.conn_sent_pkts++;
    c->snd_pkt_stats.curr_index = (index + 1) % 3;
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

        xqc_conn_log_sent_packet(conn, packet_out, now);

        if (xqc_has_packet_number(&packet_out->po_pkt)) {
            /* count packets with pkt_num in the send control */
            if (XQC_CAN_IN_FLIGHT(packet_out->po_frame_types 
                && xqc_pacing_is_on(&send_ctl->ctl_pacing)))
            {
                xqc_pacing_on_packet_sent(&send_ctl->ctl_pacing, packet_out->po_used_size);
            }

            xqc_send_ctl_on_packet_sent(send_ctl, pn_ctl, packet_out, now);
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
                    xqc_frame_type_2_str(conn->engine, packet_out->po_frame_types),
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
    unsigned int ori_hdr_len = packet_out->po_payload - packet_out->po_buf;
    unsigned int ori_payload_len = ori_po_used_size - ori_hdr_len;

    /* convert pkt info */
    packet_out->po_pkt.pkt_pns = XQC_PNS_APP_DATA;
    packet_out->po_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;

    /* copy header */
    packet_out->po_used_size = 0;
    int ret = xqc_gen_short_packet_header(packet_out, conn->dcid_set.current_dcid.cid_buf,
                                          conn->dcid_set.current_dcid.cid_len, XQC_PKTNO_BITS, 0,
                                          conn->key_update_ctx.cur_out_key_phase);
    packet_out->po_used_size = ret;

    if (ori_hdr_len < ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|fatal|long_header_is_shorter_than_short_header|");
        XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
        return;
    }

    unsigned int hdr_offset_diff = (ori_hdr_len - ret);

    /* copy frame directly */
    memmove(packet_out->po_buf + ret, ori_payload, ori_payload_len);
    packet_out->po_payload = packet_out->po_buf + ret;
    packet_out->po_used_size += ori_payload_len;

    if (packet_out->po_ack_offset > 0) {
        if (packet_out->po_ack_offset < hdr_offset_diff) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|fatal|wrong_ack_frame_offset|");
            XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
            return;
        }
        packet_out->po_ack_offset -= hdr_offset_diff;
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|0RTT to 1RTT|conn:%p|type:%d|pkt_num:%ui|pns:%d|frame:%s|", 
            conn, packet_out->po_pkt.pkt_type, packet_out->po_pkt.pkt_num, packet_out->po_pkt.pkt_pns, 
            xqc_frame_type_2_str(conn->engine, packet_out->po_frame_types));
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
            if (xqc_check_acked_or_dropped_pkt(conn, packet_out, send_type)) {
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
                && !xqc_send_packet_check_cc(send_ctl, packet_out, total_bytes_to_send, now))
            {
                send_ctl->ctl_conn->send_cc_blocked++;
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

    /* @FIXME: in the case of EAGAIN, we should not reschedule packets. */
    if (send_burst_count < 0 && send_burst_count != -XQC_EAGAIN) {
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

    xqc_usec_t now = xqc_monotonic_timestamp();

    xqc_list_for_each_safe(pos, next, &path->path_schedule_buf[send_type]) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);

        if (xqc_check_acked_or_dropped_pkt(conn, packet_out, send_type)) {
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
            && !xqc_send_packet_check_cc(send_ctl, packet_out, 0, now))
        {
            send_ctl->ctl_conn->send_cc_blocked++;
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

        if (packet_out->po_frame_types & XQC_FRAME_BIT_DATAGRAM) {
            xqc_log(conn->log, XQC_LOG_DEBUG, "|dgram_id:%ui|", packet_out->po_dgram_id);
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

    /* @FIXME: in the case of EAGAIN, we should not reschedule packets. */
    if (ret < 0 && ret != -XQC_EAGAIN) {
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
               || (packet_out->po_frame_types & XQC_FRAME_BIT_PATH_RESPONSE)
               || (packet_out->po_flag & XQC_POF_PMTUD_PROBING))
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
        xqc_gen_padding_frame(conn, packet_out);
    }

    
    /* generate packet number and update packet length, might do packet number encoding here */
    xqc_pn_ctl_t *pn_ctl = xqc_get_pn_ctl(conn, path);
    xqc_send_ctl_set_next_pn_for_packet(conn, pn_ctl, packet_out, current_time);

    xqc_write_packet_number(packet_out->po_ppktno, packet_out->po_pkt.pkt_num, XQC_PKTNO_BITS);
    xqc_long_packet_update_length(packet_out);
    xqc_short_packet_update_key_phase(packet_out, conn->key_update_ctx.cur_out_key_phase);
    if (conn->conn_settings.marking_reinjection) {
        xqc_packet_update_reserved_bits(packet_out);
    }

    /* encrypt */
    xqc_int_t ret = xqc_packet_encrypt_buf(conn, packet_out, enc_pkt, enc_pkt_cap, enc_pkt_len);
    if (ret < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|encrypt packet error|");
        conn->conn_state = XQC_CONN_STATE_CLOSED;
        xqc_log_event(conn->log, CON_CONNECTION_STATE_UPDATED, conn);
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
            
            return sent == XQC_SOCKET_EAGAIN ? -XQC_EAGAIN : -XQC_EPACKET_FILETER_CALLBACK;
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
            xqc_log(conn->log, XQC_LOG_ERROR,
                    "|write_socket error|path:%ui|path_addr:%s|peer_addrlen:%d|", 
                    path->path_id, xqc_path_addr_str(path), (int)path->peer_addrlen);

            /* if callback return XQC_SOCKET_ERROR, close the connection */
            if (sent == XQC_SOCKET_ERROR) {
                path->path_flag |= XQC_PATH_FLAG_SOCKET_ERROR;
                if (xqc_conn_should_close(conn, path)) {
                    xqc_log(conn->log, XQC_LOG_ERROR, "|conn:%p|socket exception, close connection|", conn);
                    conn->conn_state = XQC_CONN_STATE_CLOSED;
                    xqc_log_event(conn->log, CON_CONNECTION_STATE_UPDATED, conn);
                }
            }

            return sent == XQC_SOCKET_EAGAIN ? -XQC_EAGAIN : -XQC_ESOCKET;
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
                xqc_log_event(conn->log, CON_CONNECTION_STATE_UPDATED, conn);
            }

            return sent == XQC_SOCKET_EAGAIN ? -XQC_EAGAIN : -XQC_ESOCKET;
        }
    }

    xqc_log_event(conn->log, TRA_DATAGRAMS_SENT, sent, path->path_id);

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
    xqc_log_event(conn->log, TRA_PACKET_SENT, conn, packet_out, path, 0, sent, 0);
    if (sent > 0) {
        xqc_conn_log_sent_packet(conn, packet_out, xqc_monotonic_timestamp());
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
                xqc_frame_type_2_str(conn->engine, packet_out->po_frame_types), now);
        return sent;

    } else {
        xqc_log(conn->log, XQC_LOG_INFO,
                "|<==|conn:%p|path:%ui|pkt_num:%ui|size:%ud|sent:%z|pkt_type:%s|frame:%s|inflight:%ud|now:%ui|stream_id:%ui|stream_offset:%ui|",
                conn, path->path_id, packet_out->po_pkt.pkt_num, packet_out->po_used_size, sent,
                xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type),
                xqc_frame_type_2_str(conn->engine, packet_out->po_frame_types), path->path_send_ctl->ctl_bytes_in_flight, now, packet_out->po_stream_id, packet_out->po_stream_offset);
        xqc_log_event(conn->log, TRA_PACKET_SENT, conn, packet_out, path, now, sent, 1);
    }

    /* deliver packet to send control */
    xqc_pn_ctl_t *pn_ctl = xqc_get_pn_ctl(conn, path);

    xqc_conn_log_sent_packet(conn, packet_out, now);
    xqc_send_ctl_on_packet_sent(path->path_send_ctl, pn_ctl, packet_out, now);
    return sent;
}

ssize_t
xqc_enc_packet_with_pn(xqc_connection_t *conn, xqc_path_ctx_t *path, xqc_packet_out_t *packet_out)
{
    /* update dcid by send path */
    xqc_short_packet_update_dcid(packet_out, path->path_dcid);

    /* pad packet if needed */
    if (xqc_need_padding(conn, packet_out)) {
        xqc_gen_padding_frame(conn, packet_out);
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
    xqc_usec_t current_time = xqc_monotonic_timestamp();
    
    xqc_send_ctl_set_next_pn_for_packet(conn, pn_ctl, packet_out, current_time);
    xqc_write_packet_number(packet_out->po_ppktno, packet_out->po_pkt.pkt_num, XQC_PKTNO_BITS);
    xqc_long_packet_update_length(packet_out);
    xqc_short_packet_update_key_phase(packet_out, conn->key_update_ctx.cur_out_key_phase);
    if (conn->conn_settings.marking_reinjection) {
        xqc_packet_update_reserved_bits(packet_out);
    }

    /* encrypt packet body */
    if (xqc_packet_encrypt(conn, packet_out) < 0) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|encrypt packet error|");
        conn->conn_state = XQC_CONN_STATE_CLOSED;
        xqc_log_event(conn->log, CON_CONNECTION_STATE_UPDATED, conn);
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
        xqc_log(conn->log, XQC_LOG_ERROR, 
                "|path:%ui|pkt_type:%d|pn:%ui|frames:%ui|size:%ud|", 
                path->path_id, packet_out->po_pkt.pkt_type, 
                packet_out->po_pkt.pkt_num, (uint64_t)packet_out->po_frame_types,
                packet_out->po_used_size);
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
    if (conn->conn_settings.mp_enable_reinjection & XQC_REINJ_UNACK_BEFORE_SCHED) {
        xqc_conn_reinject_unack_packets(conn, XQC_REINJ_UNACK_BEFORE_SCHED);
    }

    head = &conn->conn_send_queue->sndq_send_packets;
    xqc_conn_schedule_packets(conn, head, XQC_TRUE, XQC_SEND_TYPE_NORMAL);

    /* all packets are scheduled, we need to check if there are paths not fully utilized */
    xqc_conn_check_path_utilization(conn);
    xqc_conn_schedule_end(conn);

    if (conn->conn_settings.mp_enable_reinjection & XQC_REINJ_UNACK_AFTER_SCHED) {
        xqc_conn_reinject_unack_packets(conn, XQC_REINJ_UNACK_AFTER_SCHED);
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
xqc_path_send_ping_to_probe(xqc_path_ctx_t *path, xqc_pkt_num_space_t pns, 
    xqc_path_specified_flag_t flag)
{
    xqc_connection_t *conn = path->parent_conn;

    xqc_packet_out_t *packet_out = xqc_conn_gen_ping(conn, pns);
    if (packet_out == NULL) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_packet error|");
        return -XQC_EWRITE_PKT;
    }

    packet_out->po_path_flag |= flag;
    packet_out->po_path_id = path->path_id;

    /* put PING into probe list, which is not limited by amplification or congestion-control */
    xqc_send_queue_remove_send(&packet_out->po_list);
    xqc_send_queue_insert_probe(&packet_out->po_list, &conn->conn_send_queue->sndq_pto_probe_packets);

    return XQC_OK;
}

int
xqc_conn_send_probe_pkt(xqc_connection_t *c, xqc_path_ctx_t *path,
    xqc_packet_out_t *packet_out)
{
    xqc_reinjection_mode_t  mode;
    int reinject = 0;

    mode = c->conn_settings.mp_enable_reinjection & XQC_REINJ_UNACK_BEFORE_SCHED;

    xqc_log(c->log, XQC_LOG_DEBUG, "|conn:%p|path:%ui|pkt_num:%ui"
            "|size:%ud|pkt_type:%s|frame:%s|conn_state:%s|", c,
            packet_out->po_path_id, packet_out->po_pkt.pkt_num,
            packet_out->po_used_size,
            xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type),
            xqc_frame_type_2_str(c->engine, packet_out->po_frame_types),
            xqc_conn_state_2_str(c->conn_state));

    /* reinjection */
    if (c->enable_multipath
        && c->reinj_callback
        && c->reinj_callback->xqc_reinj_ctl_can_reinject
        && c->reinj_callback->xqc_reinj_ctl_can_reinject(
                c->reinj_ctl, packet_out, mode))
    {
        if (xqc_conn_try_reinject_packet(c, packet_out) == XQC_OK) {
            xqc_log(c->log, XQC_LOG_DEBUG, "|MP|REINJ|reinject pto packets|"
                    "pkt_num:%ui|size:%ud|pkt_type:%s|frame:%s|",
                    packet_out->po_pkt.pkt_num, packet_out->po_used_size,
                    xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type),
                    xqc_frame_type_2_str(c->engine, packet_out->po_frame_types));
            reinject = 1;
        }
    }

    if (packet_out->po_flag & XQC_POF_IN_FLIGHT) {
        c->detected_loss_cnt++;
    }

    xqc_send_ctl_decrease_inflight(c, packet_out);
    xqc_send_queue_copy_to_probe(packet_out, c->conn_send_queue, path);

    packet_out->po_flag |= XQC_POF_TLP;

    if (packet_out->po_frame_types & XQC_FRAME_BIT_DATAGRAM) {
        path->path_send_ctl->ctl_lost_dgram_cnt++;
    }

    return reinject;
}

void
xqc_path_send_one_or_two_ack_elicit_pkts(xqc_path_ctx_t *path,
    xqc_pkt_num_space_t pns)
{
    xqc_int_t               ret;
    xqc_connection_t       *c;
    xqc_packet_out_t       *packet_out;
    xqc_packet_out_t       *packet_out_last_sent;   /* for dup pto pkt */
    xqc_packet_out_t       *packet_out_later_send;  /* for sending HSK_DONE first */
    xqc_list_head_t        *pos, *next;
    xqc_list_head_t        *sndq;
    xqc_int_t               probe_num;
    xqc_bool_t              send_hsd;
    int                     has_reinjection = 0;

    c       = path->parent_conn;
    sndq    = &c->conn_send_queue->sndq_unacked_packets[pns];

    /* on PTO xquic will try to send 2 ack-eliciting pkts at most. and server
       shall send HANDSHAKE_DONE on PTO as it has not been acknowledged. */
    probe_num        = XQC_CONN_PTO_PKT_CNT_MAX;
    send_hsd         = XQC_FALSE;

    packet_out_last_sent  = NULL;
    packet_out_later_send = NULL;

    xqc_log(c->log, XQC_LOG_DEBUG, "|send two ack-eliciting pkts"
            "|path:%ui|pns:%d|", path->path_id, pns);

    /* if server's HANDSHAKE_DONE frame was sent and has not been acked, try to
       send it */
    if ((c->conn_type == XQC_CONN_TYPE_SERVER)
        && !(c->conn_flag & XQC_CONN_FLAG_HANDSHAKE_DONE_ACKED)
        &&  c->conn_flag & XQC_CONN_FLAG_HANDSHAKE_DONE_SENT)
    {
        send_hsd = XQC_TRUE;
    }

    xqc_list_for_each_safe(pos, next, sndq) {
        packet_out = xqc_list_entry(pos, xqc_packet_out_t, po_list);

        if (xqc_send_ctl_indirectly_ack_or_drop_po(c, packet_out)) {
            continue;
        }

        if (!xqc_packet_out_can_pto_probe(packet_out, path->path_id)) {
            continue;
        }

        if (XQC_IS_ACK_ELICITING(packet_out->po_frame_types)
            && (XQC_NEED_REPAIR(packet_out->po_frame_types) 
                || (packet_out->po_flag & XQC_POF_NOTIFY)
                || (packet_out->po_frame_types & XQC_FRAME_BIT_DATAGRAM
                    && c->conn_settings.datagram_force_retrans_on)))
        {
            /* if HSK_DONE is not confirmed, will skip all the pkts do not
               contain HSK_DONE frame, until a pkt with HSK_DONE is found, make
               HSK_DONE is always with the highest priority */
            if (send_hsd
                && !(packet_out->po_frame_types & XQC_FRAME_BIT_HANDSHAKE_DONE))
            {
                if (packet_out_later_send == NULL) {
                    /* remember the first ack-eliciting pkt if pkt with HSK_DONE
                       frame is not the first one */
                    packet_out_later_send = packet_out;
                }

                continue;
            }

            has_reinjection = has_reinjection || xqc_conn_send_probe_pkt(c, path, packet_out);
            packet_out_last_sent = packet_out;

            if (--probe_num == 0) {
                break;
            }

            /* if a pkt with HSK_DONE is after any other ack-eliciting pkts is
               sent, try to send the first ack-eliciting pkt */
            if (send_hsd &&
                (packet_out->po_frame_types & XQC_FRAME_BIT_HANDSHAKE_DONE))
            {
                send_hsd = XQC_FALSE;

                /* try to send the first ack-eliciting pkt do not contain
                   HSK_DONE frame */
                if (packet_out_later_send) {
                    has_reinjection = has_reinjection || xqc_conn_send_probe_pkt(c, path, packet_out_later_send);
                    packet_out_last_sent = packet_out_later_send;
                    packet_out_later_send = NULL;

                    if (--probe_num == 0) {
                        break;
                    }
                }
            }
        }
    }

    if (probe_num > 0) {
        if (packet_out_last_sent) {
            /* at least one pkt was sent, and there is still budget for send
               more ack-eliciting pkts, try to send the pkt again */
            while (probe_num > 0) {
                xqc_log(c->log, XQC_LOG_DEBUG, "|dup pkt on PTO, pkt_num:%ui|",
                        packet_out_last_sent->po_pkt.pkt_num);
                has_reinjection = has_reinjection || xqc_conn_send_probe_pkt(c, path, packet_out_last_sent);
                probe_num--;
            }

        } else {
            /* if no packet was sent, try to send PING frame */
            while (probe_num > 0) {
                xqc_log(c->log, XQC_LOG_DEBUG, "|PING on PTO, cnt: %d|", probe_num);
                xqc_path_send_ping_to_probe(path, pns, XQC_PATH_SPECIFIED_BY_PTO);
                probe_num--;
            }
        }
    }

    if (has_reinjection) {
        xqc_path_ctx_t *path;
        xqc_list_for_each_safe(pos, next, &c->conn_paths_list) {
            path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
            xqc_list_splice_tail_init(&path->path_reinj_tmp_buf,
                                      &path->path_schedule_buf[XQC_SEND_TYPE_NORMAL]);
        }
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
                xqc_scid_str(engine, cid));
        return -XQC_ECONN_NFOUND;
    }

    xqc_log(conn->log, XQC_LOG_INFO, "|conn:%p|state:%s|flag:%s|", conn,
            xqc_conn_state_2_str(conn->conn_state), xqc_conn_flag_2_str(conn, conn->conn_flag));

    XQC_CONN_CLOSE_MSG(conn, "local close");

    if (conn->conn_state >= XQC_CONN_STATE_DRAINING) {
        return XQC_OK;
    }

    /* close connection after all data sent and acked or XQC_TIMER_LINGER_CLOSE timeout */
    xqc_usec_t now = xqc_monotonic_timestamp();
    xqc_usec_t pto = xqc_conn_get_max_pto(conn);

    if (conn->conn_settings.linger.linger_on && !xqc_send_queue_out_queue_empty(conn->conn_send_queue)) {
        conn->conn_flag |= XQC_CONN_FLAG_LINGER_CLOSING;
        xqc_usec_t linger_timeout = conn->conn_settings.linger.linger_timeout;
        xqc_timer_set(&conn->conn_timer_manager, XQC_TIMER_LINGER_CLOSE, now,
                      (linger_timeout ? linger_timeout : 3 * pto));
        goto end;
    }

    ret = xqc_conn_immediate_close(conn);
    if (ret) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_immediate_close error|ret:%d|", ret);
        return ret;
    }

end:
    xqc_engine_remove_wakeup_queue(engine, conn);
    xqc_engine_add_active_queue(engine, conn);

    xqc_engine_wakeup_once(engine);

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

void *
xqc_conn_get_ssl(xqc_connection_t *conn)
{
    if (conn->tls) {
        return xqc_tls_get_ssl(conn->tls);
    }

    return NULL;
}

/* cleanup connection and wait for draining */
void
xqc_conn_shutdown(xqc_connection_t *conn)
{
    xqc_path_ctx_t     *path;
    xqc_list_head_t    *pos, *next;
    xqc_send_ctl_t     *send_ctl;
    xqc_usec_t          now;

    now = xqc_monotonic_timestamp();
    xqc_usec_t pto = xqc_conn_get_max_pto(conn);
    if (!xqc_timer_is_set(&conn->conn_timer_manager, XQC_TIMER_CONN_DRAINING)) {
        xqc_timer_set(&conn->conn_timer_manager, XQC_TIMER_CONN_DRAINING, now, 3 * pto);
    }

    xqc_send_queue_drop_packets(conn);

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        for (int i = 0; i <= XQC_TIMER_LOSS_DETECTION; i++) {
            xqc_timer_unset(&path->path_send_ctl->path_timer_manager, i);
        }
    }
}


xqc_int_t
xqc_conn_immediate_close(xqc_connection_t *conn)
{
    int ret;

    if (conn->conn_state >= XQC_CONN_STATE_DRAINING) {
        return XQC_OK;
    }

    if (!(conn->conn_flag & XQC_CONN_FLAG_INIT_RECVD)
       && conn->conn_type == XQC_CONN_TYPE_SERVER)
    {
        conn->conn_state = XQC_CONN_STATE_CLOSED;
        xqc_log_event(conn->log, CON_CONNECTION_STATE_UPDATED, conn);
        xqc_conn_log(conn, XQC_LOG_ERROR, "|server cannot send CONNECTION_CLOSE before initial pkt received|");
        return XQC_OK;
    }

    if (conn->conn_state < XQC_CONN_STATE_CLOSING) {
        xqc_conn_shutdown(conn);

        /* convert state to CLOSING */
        xqc_log(conn->log, XQC_LOG_INFO, "|state to closing|state:%s|flags:%s",
                xqc_conn_state_2_str(conn->conn_state),
                xqc_conn_flag_2_str(conn, conn->conn_flag));
        conn->conn_state = XQC_CONN_STATE_CLOSING;
        xqc_log_event(conn->log, CON_CONNECTION_STATE_UPDATED, conn);
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
    unsigned char buf[XQC_PACKET_OUT_BUF_CAP];
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
    xqc_engine_remove_wakeup_queue(c->engine, c);
    xqc_engine_add_active_queue(c->engine, c);

    c->conn_flag &= ~XQC_CONN_FLAG_VERSION_NEGOTIATION;
    return XQC_OK;
}

void 
xqc_conn_continue_send_by_conn(xqc_connection_t *conn)
{
    if (!conn) {
        return;
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|conn:%p|", conn);

    xqc_engine_remove_wakeup_queue(conn->engine, conn);
    xqc_engine_add_active_queue(conn->engine, conn);

    xqc_engine_conn_logic(conn->engine, conn);
}

int
xqc_conn_continue_send(xqc_engine_t *engine, const xqc_cid_t *cid)
{
    xqc_connection_t *conn = xqc_engine_conns_hash_find(engine, cid, 's');
    if (!conn) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|can not find connection|cid:%s",
                xqc_scid_str(engine, cid));
        return -XQC_ECONN_NFOUND;
    }

    xqc_conn_continue_send_by_conn(conn);
    return XQC_OK;
}

void 
xqc_conn_encode_mp_settings(xqc_connection_t *conn, char *buf, size_t buf_sz)
{
    size_t len = 0;
    uint8_t encode_val = 0;

    if (buf_sz < XQC_MP_SETTINGS_STR_LEN) {
        return;
    }

    if (conn->enable_multipath) {
        encode_val = 1;
    }
    //len: 1
    len = snprintf(buf, buf_sz, "%d", encode_val);

    encode_val = 0;
    if (conn->local_settings.enable_multipath) {
        encode_val = 1;
    }
    //len: 3
    len += snprintf(buf + len, buf_sz - len, "/%d", encode_val);

    encode_val = 0;
    if (conn->remote_settings.enable_multipath) {
        encode_val = 1;
    }
    //len: 5
    len += snprintf(buf + len, buf_sz - len, "/%d", encode_val);

    //len: 9
    encode_val = conn->local_settings.multipath_version;
    len += snprintf(buf + len, buf_sz - len, "/%x", encode_val);

    //len: 13
    encode_val = conn->remote_settings.multipath_version;
    len += snprintf(buf + len, buf_sz - len, "/%x", encode_val);

    buf[len] = 0;
}

void
xqc_conn_info_print(xqc_connection_t *conn, xqc_conn_stats_t *conn_stats)
{
    char *buff = conn_stats->conn_info;
    size_t buff_size = XQC_CONN_INFO_LEN;
    size_t curr_size = 0;
    int ret = 0;
    int i = 0;
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path = NULL;
    xqc_path_info_t path_info;
    char mp_settings[XQC_MP_SETTINGS_STR_LEN] = {0};
    uint32_t sock_err_flag = 0;
    uint32_t init_cwnd = 0;

    xqc_conn_encode_mp_settings(conn, mp_settings, XQC_MP_SETTINGS_STR_LEN);

    init_cwnd = conn->conn_settings.cc_params.customize_on ? conn->conn_settings.cc_params.init_cwnd : 0;

    /* conn info */
    ret = snprintf(buff, buff_size, "%s,%u,%u,%u,%u,%u,%u,"
                   "%u,%u,%u,%u,%u,%u,%u,%"PRIu64",%"PRIu64",%"PRIu64",i%u,"
                   ,
                   mp_settings,
                   conn->create_path_count,
                   conn->validated_path_count,
                   conn->active_path_count,
                   conn->dgram_stats.total_dgram,
                   conn->dgram_stats.hp_dgram,
                   conn->dgram_stats.hp_red_dgram,
                   conn->dgram_stats.hp_red_dgram_mp,
                   conn->dgram_stats.timer_red_dgram,
                   conn->sched_cc_blocked,
                   conn->send_cc_blocked,
                   conn->snd_pkt_stats.conn_sent_pkts,
                   conn->rcv_pkt_stats.conn_rcvd_pkts,
                   conn->rcv_pkt_stats.conn_udp_pkts,
                   conn->stream_stats.send_bytes,
                   conn->stream_stats.reinjected_bytes,
                   conn->stream_stats.recv_bytes,
                   init_cwnd
                   );

    curr_size += ret;

    if (curr_size >= buff_size) {
        goto full;
    }

    /* recv_stats */
    for (i = 0; i < 3; i++) {

        ret = snprintf(buff + curr_size, buff_size - curr_size,
                       "%u,%u,%u,%"PRIx64",%"PRIu64","
                       "%"PRIu64",%d,",
                       (uint32_t)conn->rcv_pkt_stats.pkt_types[i],
                       conn->rcv_pkt_stats.pkt_size[i],
                       conn->rcv_pkt_stats.pkt_udp_size[i],
                       (uint64_t)conn->rcv_pkt_stats.pkt_frames[i],
                       (uint64_t)conn->rcv_pkt_stats.pkt_pn[i],
                       (uint64_t)conn->rcv_pkt_stats.pkt_timestamp[i],
                       conn->rcv_pkt_stats.pkt_err[i]);

        curr_size += ret;

        if (curr_size >= buff_size) {
            goto full;
        }
    }

    /* send_stats */
    for (i = 0; i < 3; i++) {
        ret = snprintf(buff + curr_size, buff_size - curr_size,
                       "%u,%u,%"PRIx64",%"PRIu64","
                       "%"PRIu64",",
                       (uint32_t)conn->snd_pkt_stats.pkt_types[i],
                       conn->snd_pkt_stats.pkt_size[i],
                       (uint64_t)conn->snd_pkt_stats.pkt_frames[i],
                       (uint64_t)conn->snd_pkt_stats.pkt_pn[i],
                       (uint64_t)conn->snd_pkt_stats.pkt_timestamp[i]);

        curr_size += ret;

        if (curr_size >= buff_size) {
            goto full;
        }
    }

    /* path layer 自定义 */
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        xqc_path_record_info(path, &path_info);

        sock_err_flag = (path->path_flag & XQC_PATH_FLAG_SOCKET_ERROR) != 0;

        ret = snprintf(buff + curr_size, buff_size - curr_size, 
                       "%d-%d,%d-%d,%d-%d,%d-%"PRIu64","
                       "%d-%"PRIu64",%d-%"PRIu64","
                       "%d-%"PRIu64",%d-%"PRIu64","
                       "%d-%u,%d-%u,"
                       "%d-%u,%d-%u,"
                       "%d-%u,%d-%u,"
                       "%d-%u,%d-%u,"
                       "%d-%u,%d-%u,",
                       (int)path_info.path_id, path_info.path_state,
                       (int)path_info.path_id, path_info.app_path_status,
                       (int)path_info.path_id, sock_err_flag,
                       (int)path_info.path_id, path_info.path_create_time,
                       (int)path_info.path_id, path_info.path_destroy_time,
                       (int)path_info.path_id, path_info.srtt / 1000,
                       (int)path_info.path_id, path_info.path_bytes_send,
                       (int)path_info.path_id, path_info.path_bytes_recv,
                       (int)path_info.path_id, path_info.pkt_send_cnt,
                       (int)path_info.path_id, path_info.pkt_recv_cnt,
                       (int)path_info.path_id, path_info.loss_cnt,
                       (int)path_info.path_id, path_info.tlp_cnt,
                       (int)path_info.path_id, path_info.dgram_send_cnt,
                       (int)path_info.path_id, path_info.dgram_recv_cnt,
                       (int)path_info.path_id, path_info.red_dgram_send_cnt,
                       (int)path_info.path_id, path_info.red_dgram_recv_cnt,
                       (int)path_info.path_id, path->rebinding_count,
                       (int)path_info.path_id, path->rebinding_valid);

        curr_size += ret;

        if (curr_size >= buff_size) {
            goto full;
        }

    }
full:
    curr_size = xqc_min(curr_size, buff_size);
    for (i = curr_size - 1; i >= 0; i--) {
        if (buff[i] == ',') {
            buff[i] = '\0';
            break;
        }
    }
    buff[buff_size - 1] = '\0';
}

void 
xqc_conn_get_stats_internal(xqc_connection_t *conn, xqc_conn_stats_t *conn_stats)
{
    /* 1. 与路径无关的连接级别埋点 */
    const char         *out_alpn     = NULL;
    size_t              out_alpn_len = 0;

    if (conn->tls) {
        xqc_tls_get_selected_alpn(conn->tls, &out_alpn, &out_alpn_len);
    }

    xqc_memset(conn_stats->alpn, 0, XQC_MAX_ALPN_BUF_LEN);
    if (out_alpn) {
        strncpy(conn_stats->alpn, out_alpn, xqc_min(out_alpn_len, XQC_MAX_ALPN_BUF_LEN));

    } else {
        conn_stats->alpn[0] = '-';
        conn_stats->alpn[1] = '1';
    }

    conn_stats->conn_err = (int)conn->conn_err;
    conn_stats->early_data_flag = XQC_0RTT_NONE;
    conn_stats->enable_multipath = conn->enable_multipath;
    conn_stats->enable_fec = conn->conn_settings.fec_params.fec_encoder_scheme ? 1 : 0;
    conn_stats->spurious_loss_detect_on = conn->conn_settings.spurious_loss_detect_on;
    conn_stats->max_acked_mtu = conn->max_acked_po_size;
    if (conn->conn_flag & XQC_CONN_FLAG_HAS_0RTT) {
        if (conn->conn_flag & XQC_CONN_FLAG_0RTT_OK) {
            conn_stats->early_data_flag = XQC_0RTT_ACCEPT;

        } else if (conn->conn_flag & XQC_CONN_FLAG_0RTT_REJ) {
            conn_stats->early_data_flag = XQC_0RTT_REJECT;
        }
    }

    /* 2. srtt 和 ack_info 使用主路信息 (TODO: 有问题，后续需要修改) */
    if (conn->conn_initial_path
        && conn->conn_initial_path->path_send_ctl
        && conn->conn_initial_path->path_pn_ctl)
    {
        if (conn->conn_initial_path->path_send_ctl->ctl_first_rtt_sample_time == 0) {
            conn_stats->srtt = 0;
            conn_stats->min_rtt = 0;

        } else {
            conn_stats->srtt = conn->conn_initial_path->path_send_ctl->ctl_srtt;
            conn_stats->min_rtt = conn->conn_initial_path->path_send_ctl->ctl_minrtt;
        }
        
        xqc_recv_record_print(conn, &conn->conn_initial_path->path_pn_ctl->ctl_recv_record[XQC_PNS_APP_DATA],
                              conn_stats->ack_info, sizeof(conn_stats->ack_info));
    }

    if (conn->fec_ctl) {
        conn_stats->send_fec_cnt = conn->fec_ctl->fec_send_repair_num_total;
        conn_stats->fec_recover_pkt_cnt = conn->fec_ctl->fec_recover_pkt_cnt;
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

        conn_stats->lost_count           += send_ctl->ctl_lost_count;
        conn_stats->send_count           += send_ctl->ctl_send_count;
        conn_stats->tlp_count            += send_ctl->ctl_tlp_count;
        conn_stats->spurious_loss_count  += send_ctl->ctl_spurious_loss_count;
        conn_stats->recv_count           += send_ctl->ctl_recv_count;
        conn_stats->lost_dgram_count     += send_ctl->ctl_lost_dgram_cnt;
        conn_stats->inflight_bytes       += send_ctl->ctl_bytes_in_flight;
        conn_stats->total_rebind_count   += path->rebinding_count;
        conn_stats->total_rebind_valid   += path->rebinding_valid;
    }

    /* 路径信息 */
    xqc_conn_path_metrics_print(conn, conn_stats);

    /* 自定义信息 */
    xqc_conn_info_print(conn, conn_stats);

    xqc_extern_conn_info_print(conn, conn_stats);
}

xqc_conn_stats_t
xqc_conn_get_stats(xqc_engine_t *engine, const xqc_cid_t *cid)
{
    xqc_connection_t *conn;
    xqc_conn_stats_t conn_stats;
    xqc_memzero(&conn_stats, sizeof(conn_stats));
    for (int i = 0; i < XQC_MAX_PATHS_COUNT; ++i) {
        conn_stats.paths_info[i].path_id = XQC_MAX_UINT64_VALUE;
        conn_stats.paths_info[i].path_app_status = 0;
    }

    conn = xqc_engine_conns_hash_find(engine, cid, 's');
    if (!conn) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|can not find connection|cid:%s",
                xqc_scid_str(engine, cid));
        return conn_stats;
    }

    xqc_conn_get_stats_internal(conn, &conn_stats);
    
    return conn_stats;
}

xqc_conn_qos_stats_t 
xqc_conn_get_qos_stats(xqc_engine_t *engine, const xqc_cid_t *cid)
{
    xqc_connection_t *conn;
    xqc_conn_qos_stats_t qos_stats;
    xqc_memzero(&qos_stats, sizeof(qos_stats));

    conn = xqc_engine_conns_hash_find(engine, cid, 's');
    if (!conn) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|can not find connection|cid:%s",
                xqc_scid_str(engine, cid));
        return qos_stats;
    }

   /* 2. srtt 和 ack_info 使用主路信息 (TODO: 有问题，后续需要修改) */
    if (conn->conn_initial_path
        && conn->conn_initial_path->path_send_ctl
        && conn->conn_initial_path->path_pn_ctl)
    {
        if (conn->conn_initial_path->path_send_ctl->ctl_first_rtt_sample_time == 0) {
            qos_stats.srtt = 0;
            qos_stats.min_rtt = 0;

        } else {
            qos_stats.srtt = conn->conn_initial_path->path_send_ctl->ctl_srtt;
            qos_stats.min_rtt = conn->conn_initial_path->path_send_ctl->ctl_minrtt;
        }
    }

    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path = NULL;
    xqc_send_ctl_t *send_ctl;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (path == NULL) {
            continue;
        }

        send_ctl = path->path_send_ctl;
        if (send_ctl == NULL) {
            continue;
        }

        qos_stats.inflight_bytes += send_ctl->ctl_bytes_in_flight;
    }
    
    return qos_stats;
}


xqc_usec_t
xqc_conn_get_lastest_rtt(xqc_engine_t *engine, const xqc_cid_t *cid)
{
    xqc_connection_t *conn;
    xqc_path_ctx_t *path;

    conn = xqc_engine_conns_hash_find(engine, cid, 's');
    if (!conn) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|can not find connection|cid:%s",
                xqc_scid_str(engine, cid));
        return 0;
    }

    path = conn->conn_initial_path;
    if (!path) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|can not find initial path|cid:%s",
                xqc_scid_str(engine, cid));
        return 0;
    }

    return path->path_send_ctl->ctl_latest_rtt;
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

void 
xqc_conn_resend_0rtt_datagram(xqc_connection_t *conn)
{
    xqc_list_head_t *pos, *next;
    xqc_datagram_0rtt_buffer_t *dgram_buffer;
    struct iovec iov[XQC_MAX_SEND_MSG_ONCE];
    uint64_t dgram_id_list[XQC_MAX_SEND_MSG_ONCE];
    size_t iov_size, sent, sent_bytes;
    int ret;

    iov_size = 0;

    xqc_list_for_each_safe(pos, next, &conn->dgram_0rtt_buffer_list) {
        dgram_buffer = xqc_list_entry(pos, xqc_datagram_0rtt_buffer_t, list);
        iov[iov_size].iov_base = dgram_buffer->iov.iov_base;
        iov[iov_size].iov_len = dgram_buffer->iov.iov_len;
        dgram_id_list[iov_size] = dgram_buffer->dgram_id;
        iov_size++;
        if (iov_size >= XQC_MAX_SEND_MSG_ONCE) {
            ret = xqc_datagram_send_multiple_internal(conn, iov, dgram_id_list, XQC_MAX_SEND_MSG_ONCE, &sent, &sent_bytes, dgram_buffer->qos_level, XQC_TRUE);
            if (ret < 0) {
                xqc_log(conn->log, XQC_LOG_ERROR, "|unable_to_resend_0rtt_pkts_in_1rtt_way|");
                XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
                iov_size = 0;
                break;
            }
            iov_size -= XQC_MAX_SEND_MSG_ONCE;
        }
    }

    if (iov_size > 0) {
        ret = xqc_datagram_send_multiple_internal(conn, iov, dgram_id_list, iov_size, &sent, &sent_bytes, dgram_buffer->qos_level, XQC_TRUE);
        if (ret < 0) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|unbale_to_resend_0rtt_pkts_in_1rtt_way|");
            XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
        }
    }

    xqc_conn_destroy_0rtt_datagram_buffer_list(conn);
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

    xqc_conn_resend_0rtt_datagram(conn);

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

    xqc_conn_destroy_0rtt_datagram_buffer_list(conn);

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
xqc_conn_add_path_cid_sets(xqc_connection_t *conn, uint32_t start, uint32_t end)
{
    if (conn->enable_multipath) {
        uint32_t path_id;
        xqc_int_t ret;
        /* add cid_set_inner for all paths */
        for (path_id = start; path_id <= end; path_id++) {
            ret = xqc_cid_set_add_path(&conn->scid_set, path_id);
            if (ret != XQC_OK) {
                return ret;
            }

            ret = xqc_cid_set_add_path(&conn->dcid_set, path_id);
            if (ret != XQC_OK) {
                return ret;
            }
        }
    }
    return XQC_OK;
}

void 
xqc_conn_try_to_enable_pmtud(xqc_connection_t *conn)
{
    uint64_t pmtud_check_bit = conn->conn_type == XQC_CONN_TYPE_SERVER ? 0x2 : 0x1;
    xqc_usec_t now;
    if (((conn->remote_settings.enable_pmtud & conn->local_settings.enable_pmtud) & pmtud_check_bit) != 0) {
        conn->enable_pmtud = 1;
        now = xqc_monotonic_timestamp();
        if (conn->enable_multipath) {
            xqc_timer_set(&conn->conn_timer_manager, XQC_TIMER_PMTUD_PROBING, now, XQC_PMTUD_START_DELAY * 1000);

        } else {
            xqc_timer_set(&conn->conn_timer_manager, XQC_TIMER_PMTUD_PROBING, now, 1);
        }
    }
}

xqc_int_t  
xqc_conn_try_to_enable_multipath(xqc_connection_t *conn)
{   
    xqc_int_t ret = XQC_OK;
    uint64_t path_id = 0;

    /* determine multipath mode */
    conn->enable_multipath = xqc_conn_enable_multipath(conn);
    conn->conn_settings.multipath_version = xqc_conn_multipath_version_negotiation(conn);
    if (conn->conn_settings.multipath_version == XQC_ERR_MULTIPATH_VERSION) {
        xqc_log(conn->log, XQC_LOG_WARN, "|multipath_version_negotiation err|");
        conn->enable_multipath = 0;
    }

    if (conn->enable_multipath) {
        conn->conn_flag |= XQC_CONN_FLAG_MP_WAIT_MP_READY;
    }

    return xqc_conn_add_path_cid_sets(conn, XQC_INITIAL_PATH_ID + 1, conn->curr_max_path_id);
}

xqc_int_t
xqc_conn_handshake_complete(xqc_connection_t *conn)
{
    xqc_int_t ret;

    xqc_list_head_t *pos, *next;
    xqc_stream_t *stream;
    xqc_multipath_version_t mp_version_ret;

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
        xqc_log_event(conn->log, TRA_DATAGRAMS_RECEIVED, packet_in->buf_size, packet_in->pi_path_id);
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
xqc_conn_buff_1rtt_packet(xqc_connection_t *conn, xqc_packet_out_t *po)
{
    xqc_send_queue_remove_send(&po->po_list);
    xqc_send_queue_insert_buff(&po->po_list, &conn->conn_send_queue->sndq_buff_1rtt_packets);
    if (!(conn->conn_flag & XQC_CONN_FLAG_DCID_OK)) {
        po->po_flag |= XQC_POF_DCID_NOT_DONE;
    }
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

    xqc_list_head_t *pos, *next;
    xqc_gp_timer_t *gp_timer;
    /* gp timer */
    xqc_list_for_each_safe(pos, next, &conn->conn_timer_manager.gp_timer_list) {
        gp_timer = xqc_list_entry(pos, xqc_gp_timer_t, list);
        if (gp_timer->timer_is_set) {
            min_time = xqc_min(min_time, gp_timer->expire_time);
        }
    } 

    xqc_path_ctx_t *path;
    
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
xqc_local_addr_str(xqc_engine_t *engine, const struct sockaddr *local_addr, socklen_t local_addrlen)
{
    if (local_addrlen == 0 || local_addr == NULL) {
        engine->local_addr_str[0] = '\0';
        return engine->local_addr_str;
    }

    struct sockaddr_in *sa_local = (struct sockaddr_in *)local_addr;
    if (sa_local->sin_family == AF_INET) {
        if (inet_ntop(sa_local->sin_family, &sa_local->sin_addr, engine->local_addr_str, local_addrlen) == NULL) {
            engine->local_addr_str[0] = '\0';
        }

    } else {
        if (inet_ntop(sa_local->sin_family, &((struct sockaddr_in6*)sa_local)->sin6_addr,
                      engine->local_addr_str, local_addrlen) == NULL)
        {
            engine->local_addr_str[0] = '\0';
        }
    }

    return engine->local_addr_str;
}


char *
xqc_peer_addr_str(xqc_engine_t *engine, const struct sockaddr *peer_addr, socklen_t peer_addrlen)
{
    if (peer_addrlen == 0 || peer_addr == NULL) {
        engine->peer_addr_str[0] = '\0';
        return engine->peer_addr_str;
    }

    struct sockaddr_in *sa_peer = (struct sockaddr_in *)peer_addr;
    if (sa_peer->sin_family == AF_INET) {
        if (inet_ntop(sa_peer->sin_family, &sa_peer->sin_addr, engine->peer_addr_str, peer_addrlen) == NULL) {
            engine->peer_addr_str[0] = '\0';
        }

    } else {
        if (inet_ntop(sa_peer->sin_family, &((struct sockaddr_in6*)sa_peer)->sin6_addr,
                      engine->peer_addr_str, peer_addrlen) == NULL)
        {
            engine->peer_addr_str[0] = '\0';
        }
    }

    return engine->peer_addr_str;
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
                                      xqc_local_addr_str(conn->engine, (struct sockaddr*)sa_local, conn->local_addrlen),
                                      ntohs(sa_local->sin_port), xqc_scid_str(conn->engine, &conn->scid_set.user_scid),
                                      xqc_peer_addr_str(conn->engine, (struct sockaddr*)sa_peer, conn->peer_addrlen),
                                      ntohs(sa_peer->sin_port), xqc_dcid_str(conn->engine, &conn->dcid_set.current_dcid));
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
                                      xqc_local_addr_str(path->parent_conn->engine, (struct sockaddr*)sa_local, path->local_addrlen),
                                      ntohs(sa_local->sin_port), xqc_scid_str(path->parent_conn->engine, &path->path_scid),
                                      xqc_peer_addr_str(path->parent_conn->engine, (struct sockaddr*)sa_peer, path->peer_addrlen),
                                      ntohs(sa_peer->sin_port), xqc_dcid_str(path->parent_conn->engine, &path->path_dcid));
    }

    return path->addr_str;
}


void
xqc_conn_record_single(xqc_connection_t *c, xqc_packet_in_t *packet_in)
{
    if (!xqc_has_packet_number(&packet_in->pi_pkt)) {
        return;
    }
    xqc_path_ctx_t *path;

    if (c->enable_multipath) {
        path = xqc_conn_find_path_by_path_id(c, packet_in->pi_path_id);

    } else {
        path = c->conn_initial_path;
    }


    if (path == NULL) {
        return;
    }

    /* update path stats */
    if (packet_in->pi_frame_types & (XQC_FRAME_BIT_STREAM | XQC_FRAME_BIT_DATAGRAM)) {
        path->path_send_ctl->ctl_app_bytes_recv += packet_in->buf_size;
    }

    xqc_pn_ctl_t *pn_ctl = xqc_get_pn_ctl(c, path);
    xqc_send_ctl_t *send_ctl = path->path_send_ctl;

    xqc_pkt_range_status range_status;
    int out_of_order = 0;
    xqc_pkt_num_space_t pns = packet_in->pi_pkt.pkt_pns;
    xqc_packet_number_t pkt_num = packet_in->pi_pkt.pkt_num;

    /* only recording the receive timestamp of pkt in app data space */
    if ((c->conn_settings.extended_ack_features & XQC_ACK_EXT_FEATURE_BIT_RECV_TS)
        && pns == XQC_PNS_APP_DATA)
    {
        xqc_recv_timestamps_info_add_pkt(path->recv_ts_info, pkt_num, packet_in->pkt_recv_time);
    }

    range_status = xqc_recv_record_add(&pn_ctl->ctl_recv_record[pns], pkt_num);
    if (range_status == XQC_PKTRANGE_OK) {
        if (XQC_IS_ACK_ELICITING(packet_in->pi_frame_types)) {
            ++send_ctl->ctl_ack_eliciting_pkt[pns];

            if (pkt_num > send_ctl->ctl_largest_received[pns] || send_ctl->ctl_largest_received[pns] == XQC_MAX_UINT64_VALUE) {
                send_ctl->ctl_largest_received[pns] = pkt_num;
                send_ctl->ctl_largest_recv_time[pns] = packet_in->pkt_recv_time;
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

        if (xqc_cid_in_cid_set(&c->dcid_set, &pkt->pkt_scid, XQC_INITIAL_PATH_ID) == NULL) {
            ret = xqc_cid_set_insert_cid(&c->dcid_set, &pkt->pkt_scid, XQC_CID_USED,
                                         c->local_settings.active_connection_id_limit, 
                                         XQC_INITIAL_PATH_ID);
            if (ret != XQC_OK) {
                xqc_log(c->log, XQC_LOG_ERROR,
                        "|xqc_cid_set_insert_cid error|limit:%ui|unused:%i|used:%i|",
                        c->local_settings.active_connection_id_limit,
                        xqc_cid_set_get_unused_cnt(&c->dcid_set, XQC_INITIAL_PATH_ID), 
                        xqc_cid_set_get_used_cnt(&c->dcid_set, XQC_INITIAL_PATH_ID));
                return ret;
            }
        }

        if (XQC_OK != xqc_cid_is_equal(&c->dcid_set.current_dcid, &pkt->pkt_scid)) {
            xqc_log(c->log, XQC_LOG_INFO, "|dcid change|ori:%s|new:%s|", 
                    xqc_dcid_str(c->engine, &c->dcid_set.current_dcid), xqc_scid_str(c->engine, &pkt->pkt_scid));
            xqc_cid_copy(&c->dcid_set.current_dcid, &pkt->pkt_scid);
            xqc_cid_copy(&c->conn_initial_path->path_dcid, &pkt->pkt_scid);
            xqc_datagram_record_mss(c);
        }

        if (xqc_insert_conns_hash(c->engine->conns_hash_dcid, c,
                                  c->dcid_set.current_dcid.cid_buf,
                                  c->dcid_set.current_dcid.cid_len))
        {
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
                && xqc_cid_in_cid_set(&c->scid_set, &c->original_dcid, XQC_INITIAL_PATH_ID) == NULL
                && xqc_cid_in_cid_set(&c->scid_set, &pi->pi_pkt.pkt_dcid, XQC_INITIAL_PATH_ID) != NULL)
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
    if (pi->pi_frame_types & (~(XQC_FRAME_BIT_STREAM|XQC_FRAME_BIT_DATAGRAM|XQC_FRAME_BIT_PADDING|XQC_FRAME_BIT_SID|XQC_FRAME_BIT_REPAIR_SYMBOL))) {
        c->conn_flag |= XQC_CONN_FLAG_NEED_RUN;
    }

    c->conn_last_recv_time = now;

    xqc_log(c->log, XQC_LOG_INFO, "|====>|conn:%p|path:%ui|size:%uz|pkt_type:%s|pkt_num:%ui|frame:%s|recv_time:%ui|dcid:%s|dcid_seq:%ui|",
            c, pi->pi_path_id, pi->buf_size, xqc_pkt_type_2_str(pi->pi_pkt.pkt_type), pi->pi_pkt.pkt_num,
            xqc_frame_type_2_str(c->engine, pi->pi_frame_types), pi->pkt_recv_time,
            xqc_dcid_str(c->engine, &pi->pi_pkt.pkt_dcid), 
            pi->pi_pkt.pkt_dcid.cid_seq_num);
    return ret;
}


uint8_t
xqc_conn_tolerant_error(xqc_int_t ret)
{
    if (-XQC_EVERSION == ret || -XQC_EILLPKT == ret || -XQC_EWAITING == ret
        || -XQC_EIGNORE_PKT == ret || -XQC_EDECRYPT == ret)
    {
        return XQC_TRUE;
    }

    return XQC_FALSE;
}

static inline void
xqc_conn_log_recvd_packet(xqc_connection_t *c, xqc_packet_in_t *pi, 
    size_t udp_size, xqc_int_t err, xqc_usec_t timestamp)
{
    int index = c->rcv_pkt_stats.curr_index;
    c->rcv_pkt_stats.pkt_frames[index] = pi->pi_frame_types;
    c->rcv_pkt_stats.pkt_err[index] = err;
    c->rcv_pkt_stats.pkt_size[index] = pi->pi_pkt.length;
    c->rcv_pkt_stats.pkt_timestamp[index] = xqc_calc_delay(timestamp, 
                                                           c->conn_create_time);
    c->rcv_pkt_stats.pkt_timestamp[index] /= 1000; // ms
    c->rcv_pkt_stats.pkt_udp_size[index] = udp_size;
    c->rcv_pkt_stats.pkt_types[index] = pi->pi_pkt.pkt_type;
    c->rcv_pkt_stats.pkt_pn[index] = pi->pi_pkt.pkt_num;
    c->rcv_pkt_stats.conn_rcvd_pkts++;
    c->rcv_pkt_stats.curr_index = (index + 1) % 3;
}


xqc_int_t
xqc_conn_process_packet(xqc_connection_t *c,
    const unsigned char *packet_in_buf, size_t packet_in_size, 
    xqc_usec_t recv_time)
{
    xqc_int_t ret = XQC_OK;
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

        packet_in->pi_path_id = XQC_UNKNOWN_PATH_ID;

        /* packet_in->pos will update inside */
        ret = xqc_packet_process_single(c, packet_in);

        xqc_conn_log_recvd_packet(c, packet_in, packet_in_size, ret, recv_time);

        if (ret == XQC_OK) {
            ret = xqc_conn_on_pkt_processed(c, packet_in, recv_time);

        } else if (xqc_conn_tolerant_error(ret)) {
            /* ignore the remain bytes */
            xqc_log(c->log, XQC_LOG_INFO, "|ignore err|%d|", ret);
            packet_in->pos = packet_in->last;
            ret = XQC_OK;
            goto end;
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
end:
    return ret;
}


void
xqc_conn_process_packet_recved_path(xqc_connection_t *conn, xqc_cid_t *scid, 
    size_t packet_in_size, xqc_usec_t recv_time)
{
    xqc_path_ctx_t *path = NULL;
    if (conn->enable_multipath) {
        path = xqc_conn_find_path_by_scid(conn, scid);

    } else {
        path = conn->conn_initial_path;
    }
     
    if (path == NULL) {
        xqc_log(conn->log, XQC_LOG_INFO, "|ignore unknown path|scid:%s|", xqc_scid_str(conn->engine, scid));
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
    if (!(conn->conn_flag & XQC_CONN_FLAG_CAN_SEND_1RTT)
        && xqc_tls_is_key_ready(conn->tls, XQC_ENC_LEV_1RTT, XQC_KEY_TYPE_TX_WRITE)) {
        xqc_log(conn->log, XQC_LOG_INFO, "|keys are ready, can send 1rtt now|");
        conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT;
        xqc_datagram_record_mss(conn);
    }

    return XQC_OK;
}

xqc_int_t
xqc_conn_check_handshake_complete(xqc_connection_t *conn)
{
    /* check tx keys after handshake complete */
    xqc_conn_check_tx_key(conn);

    if (!(conn->conn_flag & XQC_CONN_FLAG_HANDSHAKE_COMPLETED)
        && conn->conn_state == XQC_CONN_STATE_ESTABED)
    {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|HANDSHAKE_COMPLETED|conn:%p|", conn);
        xqc_conn_handshake_complete(conn);
        if (conn->app_proto_cbs.conn_cbs.conn_handshake_finished) {
            conn->app_proto_cbs.conn_cbs.conn_handshake_finished(conn, conn->user_data, conn->proto_data);
        }
    }

    return XQC_OK;
}


xqc_int_t
xqc_conn_get_available_path_id(xqc_connection_t *conn, uint64_t *path_id)
{
    if (conn->enable_multipath 
        && conn->conn_settings.multipath_version >= XQC_MULTIPATH_10) 
    {
        /* principle: the next unused path ID has at least one unused DCID and one acked unused SCID */
        xqc_cid_set_inner_t *scid_inner_set = xqc_get_next_unused_path_cid_set(&conn->scid_set);
        if (scid_inner_set) {
            xqc_cid_set_inner_t *dcid_inner_set = xqc_get_path_cid_set(&conn->dcid_set, scid_inner_set->path_id);
            if (dcid_inner_set) {
                if (dcid_inner_set->unused_cnt > 0 && scid_inner_set->acked_unused > 0) {
                    if (path_id) {
                        *path_id = scid_inner_set->path_id;
                    }
                    return XQC_OK;
                }
            }

        }
    }
    
    return -XQC_EMP_NO_AVAIL_PATH_ID;
}

void
xqc_conn_destroy_cids(xqc_connection_t *conn)
{
    xqc_cid_inner_t *cid = NULL;
    xqc_list_head_t *pos, *next;
    xqc_cid_set_inner_t *inner_set = NULL;
    xqc_list_head_t *pos_set, *next_set;

    if (conn->engine->conns_hash) {
        if (xqc_find_conns_hash(conn->engine->conns_hash, conn,
                                conn->original_dcid.cid_buf,
                                conn->original_dcid.cid_len))
        {
            xqc_remove_conns_hash(conn->engine->conns_hash, conn,
                                  conn->original_dcid.cid_buf,
                                  conn->original_dcid.cid_len);
        }
        xqc_list_for_each_safe(pos_set, next_set, &conn->scid_set.cid_set_list) {
            inner_set = xqc_list_entry(pos_set, xqc_cid_set_inner_t, next);

            xqc_list_for_each_safe(pos, next, &inner_set->cid_list) {
                cid = xqc_list_entry(pos, xqc_cid_inner_t, list);
                if (xqc_find_conns_hash(conn->engine->conns_hash, conn,
                                        cid->cid.cid_buf, cid->cid.cid_len))
                {
                    xqc_remove_conns_hash(conn->engine->conns_hash, conn,
                                        cid->cid.cid_buf, cid->cid.cid_len);
                }
            }
        }
    }

    xqc_list_for_each_safe(pos_set, next_set, &conn->dcid_set.cid_set_list) {
        inner_set = xqc_list_entry(pos_set, xqc_cid_set_inner_t, next);
        xqc_list_for_each_safe(pos, next, &inner_set->cid_list) {
            cid = xqc_list_entry(pos, xqc_cid_inner_t, list);
            if (conn->engine->conns_hash_dcid) {
                /* delete relationship from conns_hash_dcid */
                if (xqc_find_conns_hash(conn->engine->conns_hash_dcid, conn,
                                        cid->cid.cid_buf, cid->cid.cid_len))
                {
                    xqc_remove_conns_hash(conn->engine->conns_hash_dcid, conn,
                                        cid->cid.cid_buf, cid->cid.cid_len);
                }

            }
            if (conn->engine->conns_hash_sr_token) {
                /* delete relationship from conns_hash_sr_token */
                if (xqc_find_conns_hash(conn->engine->conns_hash_sr_token, conn,
                                        cid->cid.sr_token,
                                        XQC_STATELESS_RESET_TOKENLEN))
                {
                    xqc_remove_conns_hash(conn->engine->conns_hash_sr_token, conn,
                                        cid->cid.sr_token,
                                        XQC_STATELESS_RESET_TOKENLEN);
                }
            }
        }
    }

    xqc_destroy_cid_set(&conn->scid_set);
    xqc_destroy_cid_set(&conn->dcid_set);
}

xqc_int_t
xqc_conn_try_add_new_conn_id(xqc_connection_t *conn, uint64_t retire_prior_to)
{
    xqc_int_t ret = XQC_OK;
    uint8_t unused_limit = 2;
    xqc_cid_set_inner_t *inner_set;

    if (xqc_conn_is_handshake_confirmed(conn)) {
        if (conn->enable_multipath && conn->conn_settings.multipath_version >= XQC_MULTIPATH_10) 
        {
            /* principle #1 there are two CIDs for the next path ID */
            inner_set = xqc_get_next_unused_path_cid_set(&conn->scid_set);
            while (inner_set 
                   && (inner_set->unused_cnt + inner_set->used_cnt) < conn->remote_settings.active_connection_id_limit
                   && inner_set->unused_cnt < unused_limit) 
            {
                ret = xqc_write_mp_new_conn_id_frame_to_packet(conn, retire_prior_to, inner_set->path_id);
                if (ret != XQC_OK) {
                    xqc_log(conn->log, XQC_LOG_ERROR, 
                            "|xqc_write_mp_new_conn_id_frame_to_packet error|path_id:%ui|", 
                            inner_set->path_id);
                    return ret;
                }
            }

            /* principle #2 there are two CIDs for every in-use path ID */
            xqc_list_head_t *pos, *next;
            xqc_list_for_each_safe(pos, next, &conn->scid_set.cid_set_list) {
                inner_set = xqc_list_entry(pos, xqc_cid_set_inner_t, next);
                if (inner_set->set_state == XQC_CID_SET_USED) {
                    while (inner_set 
                           && (inner_set->unused_cnt + inner_set->used_cnt) < conn->remote_settings.active_connection_id_limit
                           && inner_set->unused_cnt < unused_limit) 
                    {
                        ret = xqc_write_mp_new_conn_id_frame_to_packet(conn, retire_prior_to, inner_set->path_id);
                        if (ret != XQC_OK) {
                            xqc_log(conn->log, XQC_LOG_ERROR, 
                                    "|xqc_write_mp_new_conn_id_frame_to_packet error|path_id:%ui|", 
                                    inner_set->path_id);
                            return ret;
                        }
                    }
                }
            }

        } else {

            inner_set = xqc_get_path_cid_set(&conn->scid_set, XQC_INITIAL_PATH_ID);
            /* origin logic for new connection id */
            while ((inner_set->used_cnt + inner_set->unused_cnt) < conn->remote_settings.active_connection_id_limit
                   && inner_set->unused_cnt < unused_limit)
            {
                ret = xqc_write_new_conn_id_frame_to_packet(conn, retire_prior_to);
                if (ret != XQC_OK) {
                    xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_new_conn_id_frame_to_packet error|");
                    return ret;
                }
            }
        }
    }
    
    return XQC_OK;
}

void 
xqc_conn_ptmud_probing(xqc_connection_t *conn)
{
    if (conn->conn_state >= XQC_CONN_STATE_CLOSING) {
        xqc_log(conn->log, XQC_LOG_INFO, "|conn closing, cannot send PMTUD probing|");
    }
    /* probing can only be sent in 0RTT/1RTT packets */

    xqc_pkt_type_t pkt_type = XQC_PTYPE_SHORT_HEADER;
    int support_0rtt = xqc_conn_is_ready_to_send_early_data(conn);

    if (!(conn->conn_flag & XQC_CONN_FLAG_CAN_SEND_1RTT)) {
        if ((conn->conn_type == XQC_CONN_TYPE_CLIENT) 
            && (conn->conn_state == XQC_CONN_STATE_CLIENT_INITIAL_SENT) 
            && support_0rtt)
        {
            pkt_type = XQC_PTYPE_0RTT;
            conn->conn_flag |= XQC_CONN_FLAG_HAS_0RTT;

        } else {
            return;
        }
    }

    if (pkt_type == XQC_PTYPE_0RTT 
        && conn->zero_rtt_count >= XQC_PACKET_0RTT_MAX_COUNT) 
    {
        return;
    }

    /* generate PING packets */
    if (conn->probing_cnt >= 3) {
        /* if the current MSS has been already probed for 3 times 
         * while the MSS is not updated, we need to shrink the probing size
         */
        conn->max_pkt_out_size = xqc_max(conn->probing_pkt_out_size - 1, conn->pkt_out_size);
        conn->probing_pkt_out_size = xqc_max(conn->pkt_out_size, (conn->max_pkt_out_size + conn->pkt_out_size) >> 1);
        conn->probing_cnt = 0;
    }

    /* stop probing if the range is less than 10B */
    if ((conn->max_pkt_out_size - conn->pkt_out_size) < 10) {
        xqc_log_event(conn->log, CON_MTU_UPDATED, conn, 1);
        conn->conn_flag &= ~XQC_CONN_FLAG_PMTUD_PROBING;
        return;
    }
    xqc_log_event(conn->log, CON_MTU_UPDATED, conn, 0);
    conn->MTU_updated_count ++;
    

    size_t probing_size = conn->probing_pkt_out_size;
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;
    xqc_int_t ret = XQC_OK;
    xqc_usec_t probing_interval = conn->conn_settings.pmtud_probing_interval;

    /* only probing on active paths */
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (path->path_state != XQC_PATH_STATE_ACTIVE) {
            continue;
        }
        ret = xqc_write_pmtud_ping_to_packet(path, probing_size, pkt_type);
        if (ret < 0) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|genrate PMTUD ping packet error|ret:%d|", ret);
        }
    }

    /* set timer: default 500ms, 1000ms, or 2000ms according to probing_cnt */
    xqc_timer_set(&conn->conn_timer_manager, 
                  XQC_TIMER_PMTUD_PROBING, 
                  xqc_monotonic_timestamp(), 
                  probing_interval * (1 << conn->probing_cnt));
    
    conn->probing_cnt++;
    conn->conn_flag &= ~XQC_CONN_FLAG_PMTUD_PROBING;
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

    xqc_cid_inner_t *scid = xqc_cid_set_search_cid(&conn->scid_set, dcid);
    if (scid == NULL) {
        return -XQC_ECONN_CID_NOT_FOUND;
    }

    if (scid->state == XQC_CID_UNUSED) {
        ret = xqc_cid_switch_to_next_state(&conn->scid_set, scid, XQC_CID_USED, scid->cid.path_id);
        if (ret < 0) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_cid_switch_to_next_state error|scid:%s|",
                    xqc_scid_str(conn->engine, &scid->cid));
            return ret;
        }
    }

    return XQC_OK;
}

xqc_int_t
xqc_conn_set_cid_retired_ts(xqc_connection_t *conn, xqc_cid_inner_t *inner_cid)
{
    xqc_int_t ret = XQC_OK;

    ret = xqc_cid_switch_to_next_state(&conn->scid_set, inner_cid, XQC_CID_RETIRED, inner_cid->cid.path_id);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|set cid retired error|");
        return ret;
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, 
            "|retired|cid:%s|seq:%ui|len:%d|", 
            xqc_scid_str(conn->engine, &inner_cid->cid), 
            inner_cid->cid.cid_seq_num,
            inner_cid->cid.cid_len);

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
xqc_conn_update_user_scid(xqc_connection_t *conn)
{
    xqc_cid_inner_t *scid;
    xqc_list_head_t *pos, *next;

    xqc_cid_set_inner_t *inner_set;
    xqc_list_head_t *pos_set, *next_set;

    xqc_list_for_each_safe(pos_set, next_set, &conn->scid_set.cid_set_list) {
        inner_set = xqc_list_entry(pos_set, xqc_cid_set_inner_t, next);

        xqc_list_for_each_safe(pos, next, &inner_set->cid_list) {
            scid = xqc_list_entry(pos, xqc_cid_inner_t, list);

            if (scid->state == XQC_CID_USED
                && xqc_cid_is_equal(&conn->scid_set.user_scid, &scid->cid) != XQC_OK)
            {
                if (conn->transport_cbs.conn_update_cid_notify) {
                    conn->transport_cbs.conn_update_cid_notify(conn, &conn->scid_set.user_scid, &scid->cid,
                                                               xqc_conn_get_user_data(conn));
                }
                
                xqc_cid_copy(&conn->scid_set.user_scid, &scid->cid);
                xqc_datagram_record_mss(conn);
                return XQC_OK;
            }
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
            xqc_frame_type_2_str(conn->engine, new_po->po_frame_types));

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
    xqc_datagram_record_mss(conn);

    /* reset initial keys */
    ret = xqc_tls_reset_initial(conn->tls, conn->version, retry_scid);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|xqc_tls_reset_initial error|retry_scid:%s|ret:%d|",
                xqc_scid_str(conn->engine, retry_scid), ret);
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
    settings->multipath_version = params->multipath_version;
    settings->init_max_path_id = params->init_max_path_id;
    settings->max_datagram_frame_size = params->max_datagram_frame_size;
    settings->close_dgram_redundancy = params->close_dgram_redundancy;
    settings->enable_pmtud = params->enable_pmtud;

#ifdef XQC_ENABLE_FEC
    /*
     * set fec params to remote_settings
     */

    settings->fec_version = params->fec_version;
    if (params->fec_version != XQC_ERR_FEC_VERSION) {

        // if current host enable fec encode, set decoder params of remote settings
        if (conn->conn_settings.enable_encode_fec) {
            settings->enable_decode_fec = params->enable_decode_fec;
            settings->fec_decoder_schemes_num = params->fec_decoder_schemes_num;
            for (xqc_int_t i = 0; i < settings->fec_decoder_schemes_num; i++) {
                settings->fec_decoder_schemes[i] = params->fec_decoder_schemes[i];
            }
        }
        // if current host enable fec decode, set encoder params of remote settings
        if (conn->conn_settings.enable_decode_fec) {
            settings->enable_encode_fec = params->enable_encode_fec;
            settings->fec_max_symbols_num = params->fec_max_symbols_num;
            settings->fec_encoder_schemes_num = params->fec_encoder_schemes_num;
            for (xqc_int_t i = 0; i < settings->fec_encoder_schemes_num; i++) {
                settings->fec_encoder_schemes[i] = params->fec_encoder_schemes[i];
            }
        }
    } else {
        settings->enable_encode_fec = 0;
        settings->enable_decode_fec = 0;
    }
#endif

    settings->extended_ack_features = params->extended_ack_features;
    settings->max_receive_timestamps_per_ack = params->max_receive_timestamps_per_ack;
    settings->receive_timestamps_exponent = params->receive_timestamps_exponent;

    if (conn->conn_type == XQC_CONN_TYPE_SERVER
        && settings->max_udp_payload_size >= XQC_PACKET_OUT_SIZE) {
        conn->pkt_out_size = xqc_min(conn->pkt_out_size, settings->max_udp_payload_size - XQC_PACKET_OUT_EXT_SPACE);
    }

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
    params->multipath_version = settings->multipath_version;
    params->init_max_path_id = settings->init_max_path_id;
    params->max_datagram_frame_size = settings->max_datagram_frame_size;
    params->enable_pmtud = settings->enable_pmtud;

    params->close_dgram_redundancy = settings->close_dgram_redundancy;

#ifdef XQC_ENABLE_FEC
    if (conn->conn_settings.enable_encode_fec) {
        params->enable_encode_fec = settings->enable_encode_fec;
        params->fec_max_symbols_num = settings->fec_max_symbols_num;
        params->fec_encoder_schemes_num = settings->fec_encoder_schemes_num;
        for (xqc_int_t i = 0; i < settings->fec_encoder_schemes_num; i++) {
            params->fec_encoder_schemes[i] = settings->fec_encoder_schemes[i];
        }
    }
    if (conn->conn_settings.enable_decode_fec) {
        params->enable_decode_fec = settings->enable_decode_fec;
        params->fec_decoder_schemes_num = settings->fec_decoder_schemes_num;
        for (xqc_int_t i = 0; i < settings->fec_decoder_schemes_num; i++) {
            params->fec_decoder_schemes[i] = settings->fec_decoder_schemes[i];
        }
    }
    
#endif  
    
    /* set other transport parameters */
    if (conn->conn_type == XQC_CONN_TYPE_SERVER
        && conn->original_dcid.cid_len > 0)
    {
        xqc_cid_set(&params->original_dest_connection_id,
                     conn->original_dcid.cid_buf, conn->original_dcid.cid_len);
        params->original_dest_connection_id_present = 1;

        xqc_gen_reset_token(&conn->original_dcid, 
                            params->stateless_reset_token,
                            XQC_STATELESS_RESET_TOKENLEN, 
                            conn->engine->config->reset_token_key, 
                            conn->engine->config->reset_token_keylen);
        params->stateless_reset_token_present = 1;

        xqc_log(conn->log, XQC_LOG_INFO, "|generate sr_token[%s] for cid[%s]",
                xqc_sr_token_str(conn->engine, params->stateless_reset_token),
                xqc_scid_str(conn->engine, &conn->original_dcid));

    } else {
        params->original_dest_connection_id_present = 0;
    }

    xqc_cid_set(&params->initial_source_connection_id,
                 conn->initial_scid.cid_buf, conn->initial_scid.cid_len);
    params->initial_source_connection_id_present = 1;

    params->retry_source_connection_id.cid_len = 0;
    params->retry_source_connection_id_present = 0;

    params->conn_option_num = settings->conn_option_num;
    xqc_memcpy(params->conn_options, settings->conn_options, 
               sizeof(uint32_t) * settings->conn_option_num);

    params->extended_ack_features = settings->extended_ack_features;
    params->max_receive_timestamps_per_ack = settings->max_receive_timestamps_per_ack;
    params->receive_timestamps_exponent = settings->receive_timestamps_exponent;

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
xqc_update_neg_info(xqc_connection_t *conn, xqc_transport_params_t params)
{
    xqc_trans_settings_t *ls = &conn->local_settings;
    if (!ls->enable_encode_fec) {
        conn->fec_neg_fail_reason |= XQC_LOCAL_NOT_SUPPORT_ENC;
    }
    if (!ls->enable_decode_fec) {
        conn->fec_neg_fail_reason |= XQC_LOCAL_NOT_SUPPORT_DEC;
    }
    if (!params.enable_encode_fec) {
        conn->fec_neg_fail_reason |= XQC_REMOTE_NOT_SUPPORT_ENC;
    }
    if (!params.enable_decode_fec) {
        conn->fec_neg_fail_reason |= XQC_REMOTE_NOT_SUPPORT_DEC;
    }
}

void
xqc_check_fec_trans_param(xqc_connection_t *conn, xqc_transport_params_t params)
{
    if (params.enable_encode_fec) {
        if (params.fec_max_symbols_num > XQC_FEC_MAX_SYMBOL_NUM_PBLOCK) {
            conn->conn_settings.enable_decode_fec = 0;
            conn->local_settings.enable_decode_fec = 0;
            conn->fec_neg_fail_reason |= XQC_REMOTE_PARAM_ERR;
            xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|remote_setting's max_symbol_number is too large to be decoded");
        }
        if (params.fec_max_symbols_num == 0) {
            conn->conn_settings.enable_decode_fec = 0;
            conn->local_settings.enable_decode_fec = 0;
            conn->fec_neg_fail_reason |= XQC_REMOTE_PARAM_ERR;
            xqc_log(conn->log, XQC_LOG_ERROR, "|quic_fec|remote_setting's max_symbol_number is zero");
        }
    }
}

void
xqc_conn_tls_transport_params_cb(const uint8_t *tp, size_t len, void *user_data)
{
    xqc_int_t                ret, re_encode_local_tp_flag = 0;
    xqc_cid_t               *cid;
    xqc_list_head_t         *node, *pos, *next;
    xqc_cid_inner_t         *cid_node;
    xqc_transport_params_t   params;
    xqc_stream_t            *stream;

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

    /* check datagram parameter */
    if (params.max_datagram_frame_size < conn->remote_settings.max_datagram_frame_size) {
        /* 0RTT: remote_settings.max_datagram_frame_size = X */
        /* 1RTT: remote_settings.max_datagram_frame_size = 0 */
        XQC_CONN_ERR(conn, TRA_0RTT_TRANS_PARAMS_ERROR);
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

    xqc_log(conn->log, XQC_LOG_DEBUG, "|1RTT_transport_params|max_datagram_frame_size:%ud|",
            conn->remote_settings.max_datagram_frame_size);

    if ((conn->local_settings.extended_ack_features & XQC_ACK_EXT_FEATURE_BIT_RECV_TS)
            && (conn->remote_settings.extended_ack_features & XQC_ACK_EXT_FEATURE_BIT_RECV_TS)
            && conn->remote_settings.max_receive_timestamps_per_ack > 0)
    {
        conn->conn_settings.extended_ack_features = 2;
        conn->conn_settings.max_receive_timestamps_per_ack =
            conn->remote_settings.max_receive_timestamps_per_ack;
        conn->conn_settings.receive_timestamps_exponent =
            conn->remote_settings.receive_timestamps_exponent;
    }

    /* save no crypto flag */
    if (params.no_crypto == 1) {
        conn->remote_settings.no_crypto = 1;
        conn->local_settings.no_crypto = 1;
        xqc_tls_set_no_crypto(conn->tls);
    }

    /* sr token will only present in server's transport parameter, it means
       client have already confirmed server's cid, associate the sr token with
       server's cid */
    if (params.stateless_reset_token_present) {
        /* it is supposed to be only one existing cid in the dcid set, find the
           first node and copy the sr token to that cid */
        xqc_cid_set_inner_t *inner_set = xqc_get_path_cid_set(&conn->dcid_set, XQC_INITIAL_PATH_ID);
        node = inner_set->cid_list.next;
        if (NULL != node) {
            cid_node = xqc_list_entry(node, xqc_cid_inner_t, list);
            xqc_memcpy(cid_node->cid.sr_token, params.stateless_reset_token,
                       XQC_STATELESS_RESET_TOKENLEN);

            xqc_log(conn->log, XQC_LOG_INFO, "|store sr_token with cid: %s"
                    "|token:%s", xqc_dcid_str(conn->engine, &cid_node->cid),
                    xqc_sr_token_str(conn->engine, params.stateless_reset_token));

            if (xqc_find_conns_hash(conn->engine->conns_hash_sr_token, conn,
                cid_node->cid.sr_token,
                XQC_STATELESS_RESET_TOKENLEN) == NULL) 
            {
                if (xqc_insert_conns_hash(conn->engine->conns_hash_sr_token, conn,
                    cid_node->cid.sr_token,
                    XQC_STATELESS_RESET_TOKENLEN))
                {
                    xqc_log(conn->log, XQC_LOG_ERROR, "|insert sr conn hash error");
                }
            } else {
                xqc_log(conn->log, XQC_LOG_ERROR, "|sr_token conflict:%s", xqc_sr_token_str(conn->engine, cid_node->cid.sr_token));
            }

        } else {
            /* it's weired if sr token present while cid not confirmed */
            xqc_log(conn->log, XQC_LOG_ERROR,
                    "|cid not confirmed while sr token present");
        }
    }

    if (conn->conn_type == XQC_CONN_TYPE_SERVER
        && params.multipath_version != conn->local_settings.multipath_version
        && xqc_conn_is_current_mp_version_supported(params.multipath_version) == XQC_OK)
    {
        conn->local_settings.multipath_version = params.multipath_version;
        re_encode_local_tp_flag = 1;
    }

    ret = xqc_conn_try_to_enable_multipath(conn);
    if(ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, 
                "|enable multipath error|ret:%d|", ret);
        XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
        return;
    }

    /* must be called after xqc_conn_try_to_enable_multipath */
    xqc_conn_try_to_enable_pmtud(conn);

    /* update flow control */
    xqc_conn_update_flow_ctl_settings(conn);

    xqc_list_for_each_safe(pos, next, &conn->conn_all_streams) {
        stream = xqc_list_entry(pos, xqc_stream_t, all_stream_list);
        xqc_stream_update_flow_ctl(stream);
    }

    /** Negotiate on whether send datagram redundancy on 1RTT packet;
     * on XQC_RED_NOT_USE(default): 
     *      No need to negotiate, and whether to send redundancy is 
     *      completely decided by server's config;
     * on XQC_RED_SET_CLOSE:
     *      The client's signal to close datagram redundancy, thus stop 
     *      sending dgram redundancy.
     * 
     */
    if (conn->conn_type == XQC_CONN_TYPE_SERVER
        && params.close_dgram_redundancy != XQC_RED_NOT_USE)
    {
        if (params.close_dgram_redundancy == XQC_RED_SET_CLOSE) {
            conn->local_settings.close_dgram_redundancy = XQC_RED_SET_CLOSE;
            conn->conn_settings.datagram_redundancy = 0;
        }
        re_encode_local_tp_flag = 1;
    }

    if (conn->local_settings.close_dgram_redundancy == XQC_RED_SET_CLOSE) {
        conn->conn_settings.mp_enable_reinjection = 0;
        xqc_log(conn->log, XQC_LOG_DEBUG, "|stop sending datagram redundancy.");
    }


#ifdef XQC_ENABLE_FEC
    xqc_update_neg_info(conn, params);
    if (conn->conn_settings.enable_encode_fec 
        || conn->conn_settings.enable_decode_fec) 
    {
        // update fec settings according to remote params
        xqc_check_fec_trans_param(conn, params);
        ret = xqc_negotiate_fec_schemes(conn, params);
        if (ret == XQC_OK) {
            xqc_on_fec_negotiate_success(conn, params);
        }
        if (conn->conn_type == XQC_CONN_TYPE_SERVER) {
            re_encode_local_tp_flag = 1;
        }
    }
#endif
    // if local_settings needs to be updated, reencode local transport parameters
    if (re_encode_local_tp_flag) {
        uint8_t tp_buf[XQC_MAX_TRANSPORT_PARAM_BUF_LEN] = {0};
        size_t tp_len = 0;

        ret = xqc_conn_encode_local_tp(conn, tp_buf, 
                                    XQC_MAX_TRANSPORT_PARAM_BUF_LEN, &tp_len);
        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR,
                    "|cannot reset local transport parameters while multipath version is different");
            XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
            return;
        }
        
        ret = xqc_tls_update_tp(conn->tls, tp_buf, tp_len);
        if (ret != XQC_OK) {
            xqc_log(conn->log, XQC_LOG_ERROR, "|server tls update transport param error|ret:%d|", ret);
            XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
            return;
        }
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
    dest->init_max_path_id = src->init_max_path_id;
    dest->max_datagram_frame_size = src->max_datagram_frame_size;
    dest->enable_pmtud = src->enable_pmtud;
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
        eng->eng_callback.keylog_cb(&(conn->scid_set.user_scid), line, eng->user_data);
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

xqc_msec_t
xqc_conn_get_queue_fin_timeout(xqc_connection_t *conn)
{
    return conn->conn_settings.fec_conn_queue_rpr_timeout;
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
                        xqc_log(conn->log, XQC_LOG_DEBUG, "|stream enter DATA RECVD|stream_id:%d", stream->stream_id);
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
xqc_conn_update_stream_stats_on_sent(xqc_connection_t *conn, xqc_send_ctl_t *ctl, 
    xqc_packet_out_t *packet_out, xqc_usec_t now)
{
    xqc_stream_id_t stream_id;
    xqc_stream_t *stream[XQC_MAX_STREAM_FRAME_IN_PO] = {0};
    int stream_cnt = 0;
    int i, j;

    if (packet_out->po_frame_types & (XQC_FRAME_BIT_STREAM | XQC_FRAME_BIT_RESET_STREAM)) {
        for (i = 0; i < XQC_MAX_STREAM_FRAME_IN_PO; i++) {
            if (packet_out->po_stream_frames[i].ps_is_used == 0) {
                break;
            }
            stream_id = packet_out->po_stream_frames[i].ps_stream_id;
            stream[stream_cnt] = xqc_find_stream_by_id(stream_id, conn->streams_hash);
            for (j = 0; j < stream_cnt; j++) {
                if (stream[j] == stream[stream_cnt]) {
                    break;
                }
            }

            if (stream[stream_cnt]) {
                if (stream[stream_cnt]->stream_stats.first_snd_time == 0) {
                    stream[stream_cnt]->stream_stats.first_snd_time = now;
                }
                if (packet_out->po_stream_frames[i].ps_has_fin) {
                    stream[stream_cnt]->stream_stats.local_fin_snd_time = now;
                    if (stream[stream_cnt]->stream_stats.local_fst_fin_snd_time == 0) {
                        stream[stream_cnt]->stream_stats.local_fst_fin_snd_time = now;
                    }
                }
                if (packet_out->po_stream_frames[i].ps_is_reset) {
                    stream[stream_cnt]->stream_stats.local_reset_time = now;
                }
                // do not repeatedly count
                if (j == stream_cnt) {
                    if (packet_out->po_sched_cwnd_blk_ts) {
                        stream[stream_cnt]->stream_stats.sched_cwnd_blk_duration += now - packet_out->po_sched_cwnd_blk_ts;
                        stream[stream_cnt]->stream_stats.sched_cwnd_blk_cnt++;
                    }
                    if (packet_out->po_send_cwnd_blk_ts) {
                        stream[stream_cnt]->stream_stats.send_cwnd_blk_duration += now - packet_out->po_send_cwnd_blk_ts;
                        stream[stream_cnt]->stream_stats.send_cwnd_blk_cnt++;
                    }
                    if (packet_out->po_send_pacing_blk_ts) {
                        stream[stream_cnt]->stream_stats.send_pacing_blk_duration += now - packet_out->po_send_pacing_blk_ts;
                        stream[stream_cnt]->stream_stats.send_pacing_blk_cnt++; 
                    }
                    if (packet_out->po_flag & (XQC_POF_TLP | XQC_POF_LOST)) {
                        stream[stream_cnt]->stream_stats.retrans_pkt_cnt++;
                    }
                    stream[stream_cnt]->stream_stats.sent_pkt_cnt++;
                    stream[stream_cnt]->stream_stats.max_pto_backoff = xqc_max(stream[stream_cnt]->stream_stats.max_pto_backoff, ctl->ctl_pto_count);
                    stream_cnt++;
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

uint32_t 
xqc_conn_get_max_pto_backoff(xqc_connection_t *conn, uint8_t available_only)
{
    xqc_path_ctx_t *path = NULL;
    uint32_t max_pto = 0;

    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (path->path_state != XQC_PATH_STATE_ACTIVE) {
            continue;
        }

        if (available_only 
            && path->app_path_status != XQC_APP_PATH_STATUS_AVAILABLE) 
        {
            continue;
        }

        max_pto = xqc_max(path->path_send_ctl->ctl_pto_count, max_pto);
    }

    return max_pto;
}

xqc_usec_t
xqc_conn_get_min_srtt(xqc_connection_t *conn, xqc_bool_t available_only)
{
    xqc_path_ctx_t *path = NULL;
    xqc_usec_t min_srtt = XQC_MAX_UINT64_VALUE;

    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (path->path_state != XQC_PATH_STATE_ACTIVE) {
            continue;
        }

        if (available_only && path->app_path_status != XQC_APP_PATH_STATUS_AVAILABLE) {
            continue;
        }

        min_srtt = xqc_min(path->path_send_ctl->ctl_srtt, min_srtt);
    }

    return min_srtt;
}

xqc_usec_t
xqc_conn_get_max_srtt(xqc_connection_t *conn)
{
    xqc_path_ctx_t *path = NULL;
    xqc_usec_t max_rtt = 0;

    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (path->path_state != XQC_PATH_STATE_ACTIVE) {
            continue;
        }

        max_rtt = xqc_max(path->path_send_ctl->ctl_srtt, max_rtt);
    }

    return max_rtt;
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

xqc_int_t
xqc_conn_send_path_challenge(xqc_connection_t *conn, xqc_path_ctx_t *path)
{
    xqc_int_t           ret = XQC_OK;
    xqc_packet_out_t   *packet_out;
    xqc_usec_t          now;
    ssize_t             sent;


    /* send data */
    if (NULL == conn->transport_cbs.write_socket_ex) {
        xqc_log(conn->log, XQC_LOG_WARN, "|write_socket_ex not registered while sending PATH_CHALLENGE");
        return XQC_ERROR;
    }

    /* generate random data for path challenge, store it to validate path_response */
    ret = xqc_generate_path_challenge_data(conn, path);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_generate_path_challenge_data error|%d|", ret);
        return ret;
    }

    /* write path challenge frame & send immediately */

    packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
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

    packet_out->po_path_flag |= XQC_PATH_SPECIFIED_BY_PCPR;
    packet_out->po_path_id = path->path_id;

    ret = xqc_enc_packet_with_pn(conn, path, packet_out);
    if (ret != XQC_OK) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_enc_packet_with_pn error|%d|", ret);
        goto end;
    }

    /* record the send time of packet */
    now = xqc_monotonic_timestamp();
    packet_out->po_sent_time = now;

    sent = conn->transport_cbs.write_socket_ex(path->path_id, conn->enc_pkt, conn->enc_pkt_len,
                                                       (struct sockaddr *)path->rebinding_addr,
                                                       path->rebinding_addrlen,
                                                       xqc_conn_get_user_data(conn));

    if (sent != conn->enc_pkt_len) {
        xqc_log(conn->log, XQC_LOG_ERROR,
                "|write_socket error|conn:%p|pkt_num:%ui|size:%ud|sent:%z|pkt_type:%s|frame:%s|now:%ui|",
                conn, packet_out->po_pkt.pkt_num, packet_out->po_used_size, sent,
                xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type),
                xqc_frame_type_2_str(conn->engine, packet_out->po_frame_types), now);
        ret = -XQC_ESOCKET;
        goto end;

    } else {
        xqc_log(conn->log, XQC_LOG_INFO,
                "|<==|conn:%p|pkt_num:%ui|size:%ud|sent:%z|pkt_type:%s|frame:%s|inflight:%ud|now:%ui|",
                conn, packet_out->po_pkt.pkt_num, packet_out->po_used_size, sent,
                xqc_pkt_type_2_str(packet_out->po_pkt.pkt_type),
                xqc_frame_type_2_str(conn->engine, packet_out->po_frame_types), path->path_send_ctl->ctl_bytes_in_flight, now);
    }

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

int 
xqc_conn_buff_0rtt_datagram(xqc_connection_t *conn, void *data, 
    size_t data_len, uint64_t dgram_id, xqc_data_qos_level_t qos_level)
{
    xqc_datagram_0rtt_buffer_t *buffer = xqc_datagram_create_0rtt_buffer(data, data_len, dgram_id, qos_level);
    if (buffer == NULL) {
        return -XQC_EMALLOC;
    }
    xqc_list_add_tail(&buffer->list, &conn->dgram_0rtt_buffer_list);
    return XQC_OK;
}

void 
xqc_conn_destroy_0rtt_datagram_buffer_list(xqc_connection_t *conn)
{
    xqc_list_head_t *pos, *next;
    xqc_datagram_0rtt_buffer_t *buffer;
    xqc_list_for_each_safe(pos, next, &conn->dgram_0rtt_buffer_list) {
        buffer = xqc_list_entry(pos, xqc_datagram_0rtt_buffer_t, list);
        xqc_list_del_init(pos);
        xqc_datagram_destroy_0rtt_buffer(buffer);
    }
}

xqc_ping_record_t* 
xqc_conn_create_ping_record(xqc_connection_t *conn)
{
    xqc_ping_record_t *pr = xqc_calloc(1, sizeof(xqc_ping_record_t));
    xqc_init_list_head(&pr->list);
    xqc_list_add_tail(&pr->list, &conn->ping_notification_list);
    return pr;
}

void 
xqc_conn_destroy_ping_record(xqc_ping_record_t *pr)
{
    xqc_list_del_init(&pr->list);
    xqc_free(pr);
}

void 
xqc_conn_destroy_ping_notification_list(xqc_connection_t *conn)
{
    xqc_list_head_t *pos, *next;
    xqc_ping_record_t *pr;
    xqc_list_for_each_safe(pos, next, &conn->ping_notification_list) {
        pr = xqc_list_entry(pos, xqc_ping_record_t, list);
        xqc_conn_destroy_ping_record(pr);
    }
}

xqc_bool_t 
xqc_conn_should_clear_0rtt_ticket(xqc_int_t conn_err)
{
    if (conn_err == TRA_0RTT_TRANS_PARAMS_ERROR) {
        return XQC_TRUE;
    }
    return XQC_FALSE;
}

xqc_conn_settings_t 
xqc_conn_get_conn_settings_template(xqc_conn_settings_type_t settings_type)
{
    xqc_conn_settings_t conn_settings = internal_default_conn_settings;

    if (settings_type == XQC_CONN_SETTINGS_LOW_DELAY) {
        conn_settings.ack_frequency = 1;
        conn_settings.loss_detection_pkt_thresh = 2;
        conn_settings.pto_backoff_factor = 1.5;
    }

    return conn_settings;
}

xqc_gp_timer_id_t 
xqc_conn_register_gp_timer(xqc_connection_t *conn, char *timer_name, xqc_gp_timer_timeout_pt cb, void *user_data)
{
    return xqc_timer_register_gp_timer(&conn->conn_timer_manager, timer_name, cb, user_data);
}

void 
xqc_conn_unregister_gp_timer(xqc_connection_t *conn, xqc_gp_timer_id_t gp_timer_id)
{
    xqc_timer_unregister_gp_timer(&conn->conn_timer_manager, gp_timer_id);
}

xqc_int_t 
xqc_conn_gp_timer_set(xqc_connection_t *conn, xqc_gp_timer_id_t gp_timer_id, 
    xqc_usec_t expire_time)
{
    return xqc_timer_gp_timer_set(&conn->conn_timer_manager, gp_timer_id, expire_time);
}

xqc_int_t 
xqc_conn_gp_timer_unset(xqc_connection_t *conn, xqc_gp_timer_id_t gp_timer_id)
{
    return xqc_timer_gp_timer_unset(&conn->conn_timer_manager, gp_timer_id);
}

xqc_int_t 
xqc_conn_gp_timer_get_info(xqc_connection_t *conn, xqc_gp_timer_id_t gp_timer_id, 
    xqc_bool_t *is_set, xqc_usec_t *expire_time)
{
    return xqc_timer_gp_timer_get_info(&conn->conn_timer_manager, gp_timer_id, is_set, expire_time);
}


/**
 * @brief get public local transport settings.
 */
xqc_conn_public_local_trans_settings_t 
xqc_conn_get_public_local_trans_settings(xqc_connection_t *conn)
{
    xqc_conn_public_local_trans_settings_t settings;
    settings.max_datagram_frame_size = conn->local_settings.max_datagram_frame_size;
    return settings;
}

/**
 * @brief set public local transport settings
 */
void 
xqc_conn_set_public_local_trans_settings(xqc_connection_t *conn, 
    xqc_conn_public_local_trans_settings_t *settings)
{
    if (conn == NULL || settings == NULL) {
        return;
    }

    if (settings->max_datagram_frame_size != conn->local_settings.max_datagram_frame_size) {
        conn->local_settings.max_datagram_frame_size = settings->max_datagram_frame_size;
        conn->conn_settings.max_datagram_frame_size = settings->max_datagram_frame_size;
        conn->conn_flag |= XQC_CONN_FLAG_LOCAL_TP_UPDATED;
    }
}

/**
 * @brief get public remote transport settings.
 */
xqc_conn_public_remote_trans_settings_t 
xqc_conn_get_public_remote_trans_settings(xqc_connection_t *conn)
{
    xqc_conn_public_remote_trans_settings_t settings;
    settings.max_datagram_frame_size = conn->remote_settings.max_datagram_frame_size;
    return settings;
}

/**
 * @brief set public remote transport settings
 */
void 
xqc_conn_set_public_remote_trans_settings(xqc_connection_t *conn, 
    xqc_conn_public_remote_trans_settings_t *settings)
{
    conn->remote_settings.max_datagram_frame_size = settings->max_datagram_frame_size;
}

void
xqc_conn_reset(xqc_connection_t *conn)
{
    xqc_conn_shutdown(conn);

    /* set error code and close message, notify to application */
    conn->conn_state = XQC_CONN_STATE_DRAINING;
    xqc_log_event(conn->log, CON_CONNECTION_STATE_UPDATED, conn);
    conn->conn_err = XQC_ESTATELESS_RESET;
    XQC_CONN_CLOSE_MSG(conn, "stateless reset");
    xqc_conn_closing(conn);
}

xqc_int_t
xqc_conn_handle_stateless_reset(xqc_connection_t *conn,
    const uint8_t *sr_token)
{
    xqc_int_t            ret;
    int                  res;
    xqc_list_head_t     *pos, *next;
    xqc_cid_inner_t     *cid;
    xqc_cid_set_inner_t *inner_set;
    xqc_list_head_t     *pos_set, *next_set;

    if (NULL == conn || NULL == sr_token) {
        return -XQC_EPARAM;
    }

    if (conn->conn_state >= XQC_CONN_STATE_DRAINING) {
        xqc_log(conn->log, XQC_LOG_INFO, "|conn closing, ignore pkt");
        return XQC_OK;
    }

    /* compare received stateless reset token with the ones peer sent */
    xqc_list_for_each_safe(pos_set, next_set, &conn->dcid_set.cid_set_list) {
        inner_set = xqc_list_entry(pos_set, xqc_cid_set_inner_t, next);
        
        xqc_list_for_each_safe(pos, next, &inner_set->cid_list) {
            cid = xqc_list_entry(pos, xqc_cid_inner_t, list);

            res = xqc_memcmp(sr_token, cid->cid.sr_token,
                            XQC_STATELESS_RESET_TOKENLEN);
            if (0 == res) {
                xqc_log(conn->log, XQC_LOG_INFO, "|====>|receive stateless reset"
                        "|cid:%s|sr_token:%s|", 
                        xqc_dcid_str(conn->engine, &cid->cid),
                        xqc_sr_token_str(conn->engine, sr_token));
                xqc_log_event(conn->log, TRA_STATELESS_RESET, conn);

                if (inner_set->set_state < XQC_CID_SET_ABANDONED
                    && cid->state < XQC_CID_RETIRED)
                {
                    /* only responds for non-retired CIDs */
                    /* stateless reset received, close connection */
                    xqc_conn_reset(conn);
                }

                goto end;
            }
        }
    }

    /* sr_token not matched */
    return -XQC_ERROR;

end:
    return XQC_OK;
}


xqc_int_t
xqc_conn_available_paths(xqc_engine_t *engine, const xqc_cid_t *cid)
{
    xqc_int_t available_paths = 0;
    xqc_connection_t *conn = xqc_engine_conns_hash_find(engine, cid, 's');
    if (conn == NULL) {
        /* no connection found */
        return available_paths;
    }

    xqc_path_ctx_t *path;
    xqc_list_head_t *path_pos, *path_next;

    xqc_list_for_each_safe(path_pos, path_next, &conn->conn_paths_list) {
        path = xqc_list_entry(path_pos, xqc_path_ctx_t, path_list);
        if (path->path_state < XQC_PATH_STATE_VALIDATING) {
            continue;
        }
        if (path->path_state == XQC_PATH_STATE_ACTIVE) {
            available_paths++;
        }
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_conn_available_paths|%" PRId32 "|", available_paths);
    return available_paths;
}

#ifdef XQC_COMPAT_GENERATE_SR_PKT

xqc_int_t
xqc_conn_handle_deprecated_stateless_reset(xqc_connection_t *conn,
    const xqc_cid_t *scid)
{
    if (NULL == conn) {
        return -XQC_EPARAM;
    }

    if (conn->conn_state >= XQC_CONN_STATE_DRAINING) {
        xqc_log(conn->log, XQC_LOG_INFO, "|conn closing, ignore pkt");
        return XQC_OK;
    }

    xqc_log(conn->log, XQC_LOG_INFO, "|====>|receive stateless reset"
            "|deprecated|cid:%s", xqc_dcid_str(conn->engine, scid));

    /* reset state of connection */
    xqc_conn_reset(conn);

    return XQC_OK;
}

#endif
