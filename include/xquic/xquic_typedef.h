/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQUIC_TYPEDEF_H_INCLUDED_
#define _XQUIC_TYPEDEF_H_INCLUDED_

#include <stdint.h>
#include <stddef.h>
#include "xqc_errno.h"

#define XQC_EXTERN extern

/* defined UNIX system default */
#ifndef XQC_SYS_WINDOWS
#   define XQC_SYS_UNIX
#endif

#if defined(_WIN32) || defined(WIN32) || defined(XQC_SYS_WIN32)
#  if !defined(XQC_SYS_WIN32)
#  define XQC_SYS_WIN32
#  endif
#endif

#if defined(_WIN64) || defined(WIN64) || defined(XQC_SYS_WIN64)
#  if !defined(XQC_SYS_WIN64)
#  define XQC_SYS_WIN64
#  endif
#endif

#if defined(XQC_SYS_WIN32) || defined(XQC_SYS_WIN64)
#undef XQC_SYS_UNIX
#define XQC_SYS_WINDOWS
#endif

#if defined(__MINGW64__) || defined(__MINGW32__)
#  if !defined(XQC_ON_MINGW)
#  define XQC_ON_MINGW
#  endif
#endif

#if defined(XQC_SYS_WINDOWS) && !defined(XQC_ON_MINGW)
# undef XQC_EXTERN
# define XQC_EXTERN

#ifdef XQC_SYS_WIN64
    typedef __int64 ssize_t;
#elif defined(XQC_SYS_WIN32)
    typedef __int32 ssize_t;
#endif
#endif


/* TODO: there may be problems using -o2 under Android platform */
#if defined(__GNUC__) && !defined(ANDROID)
#   define XQC_UNLIKELY(cond) __builtin_expect(!!(cond), 0)
#   define XQC_LIKELY(cond) __builtin_expect(!!(cond), 1)
#else
#   define XQC_UNLIKELY(cond) cond
#   define XQC_LIKELY(cond) cond
#endif

typedef struct xqc_stream_s                 xqc_stream_t;
typedef struct xqc_connection_s             xqc_connection_t;
typedef struct xqc_conn_settings_s          xqc_conn_settings_t;
typedef struct xqc_engine_s                 xqc_engine_t;
typedef struct xqc_log_callbacks_s          xqc_log_callbacks_t;
typedef struct xqc_transport_callbacks_s    xqc_transport_callbacks_t;
typedef struct xqc_h3_conn_callbacks_s      xqc_h3_conn_callbacks_t;
typedef struct xqc_random_generator_s       xqc_random_generator_t;
typedef struct xqc_client_connection_s      xqc_client_connection_t;
typedef struct xqc_id_hash_table_s          xqc_id_hash_table_t;
typedef struct xqc_str_hash_table_s         xqc_str_hash_table_t;
typedef struct xqc_priority_queue_s         xqc_pq_t;
typedef struct xqc_wakeup_pq_s              xqc_wakeup_pq_t;
typedef struct xqc_log_s                    xqc_log_t;
typedef struct xqc_send_ctl_s               xqc_send_ctl_t;
typedef struct xqc_send_queue_s             xqc_send_queue_t;
typedef struct xqc_pn_ctl_s                 xqc_pn_ctl_t;
typedef struct xqc_packet_s                 xqc_packet_t;
typedef struct xqc_packet_in_s              xqc_packet_in_t;
typedef struct xqc_packet_out_s             xqc_packet_out_t;
typedef struct xqc_stream_frame_s           xqc_stream_frame_t;
typedef struct xqc_h3_request_s             xqc_h3_request_t;
typedef struct xqc_h3_conn_s                xqc_h3_conn_t;
typedef struct xqc_h3_stream_s              xqc_h3_stream_t;
typedef struct xqc_h3_frame_s               xqc_h3_frame_t;
typedef struct xqc_qpack_s                  xqc_qpack_t;
typedef struct xqc_dtable_s                 xqc_dtable_t;
typedef struct xqc_sample_s                 xqc_sample_t;
typedef struct xqc_memory_pool_s            xqc_memory_pool_t;
typedef struct xqc_bbr_info_interface_s     xqc_bbr_info_interface_t;
typedef struct xqc_path_ctx_s               xqc_path_ctx_t;
typedef struct xqc_timer_manager_s          xqc_timer_manager_t;
typedef struct xqc_h3_ext_bytestream_s      xqc_h3_ext_bytestream_t;
typedef struct xqc_ping_record_s            xqc_ping_record_t;
typedef struct xqc_conn_qos_stats_s         xqc_conn_qos_stats_t;

typedef uint64_t        xqc_msec_t; /* store millisecond values */
typedef uint64_t        xqc_usec_t; /* store microsecond values */

typedef uint64_t        xqc_packet_number_t;
typedef uint64_t        xqc_stream_id_t;

typedef int32_t         xqc_int_t;
typedef uint32_t        xqc_uint_t;
typedef intptr_t        xqc_flag_t;
typedef uint8_t         xqc_bool_t;

/* values of xqc_bool_t */
#define XQC_TRUE        1
#define XQC_FALSE       0

/* restrictions of cid length */
#define XQC_MAX_CID_LEN 20
#define XQC_MIN_CID_LEN 4

/* restrictions of key length in lb cid encryption */
#define XQC_LB_CID_KEY_LEN 16

/* length of stateless reset token */
#define XQC_STATELESS_RESET_TOKENLEN    16

typedef struct xqc_cid_s {
    uint8_t             cid_len;
    uint8_t             cid_buf[XQC_MAX_CID_LEN];
    uint64_t            cid_seq_num;
    uint8_t             sr_token[XQC_STATELESS_RESET_TOKENLEN];
} xqc_cid_t;

typedef enum xqc_log_level_s {
    XQC_LOG_REPORT,
    XQC_LOG_FATAL,
    XQC_LOG_ERROR,
    XQC_LOG_WARN,
    XQC_LOG_STATS,
    XQC_LOG_INFO,
    XQC_LOG_DEBUG,
} xqc_log_level_t;

/* qlog Importance level definition */
typedef enum qlog_event_importance_s {
    EVENT_IMPORTANCE_SELECTED,   /* qlog will be emitted selectly */
    EVENT_IMPORTANCE_CORE,
    EVENT_IMPORTANCE_BASE,
    EVENT_IMPORTANCE_EXTRA,
    EVENT_IMPORTANCE_REMOVED,   /* Currently, some events have been removed in the latest qlog draft. But old qvis need them! */
} qlog_event_importance_t;

#define XQC_BBR_RTTVAR_COMPENSATION_ENABLED 0
typedef enum {
    XQC_BBR_FLAG_NONE = 0x00,
#if XQC_BBR_RTTVAR_COMPENSATION_ENABLED
    XQC_BBR_FLAG_RTTVAR_COMPENSATION = 0x01,
#endif
} xqc_bbr_optimization_flag_t;

#define XQC_BBR2_PLUS_ENABLED 0
typedef enum {
    XQC_BBR2_FLAG_NONE = 0x00,
#if XQC_BBR2_PLUS_ENABLED
    XQC_BBR2_FLAG_RTTVAR_COMPENSATION = 0x01,
    XQC_BBR2_FLAG_FAST_CONVERGENCE = 0x2,
#endif
} xqc_bbr2_optimization_flag_t;

#define XQC_EXPORT_PUBLIC_API   __attribute__((visibility("default")))

#ifdef XQC_SYS_WINDOWS
struct iovec {
    void   *iov_base;   /* [XSI] Base address of I/O memory region */
    size_t  iov_len;    /* [XSI] Size of region iov_base points to */
};

#if !(defined __MINGW32__) && !(defined __MINGW64__)
#undef XQC_EXPORT_PUBLIC_API
#define XQC_EXPORT_PUBLIC_API   _declspec(dllexport) 
#endif

#endif



typedef enum {
    XQC_CONN_TYPE_CLIENT,
    XQC_CONN_TYPE_SERVER,
} xqc_conn_type_t;


typedef enum {
    XQC_STREAM_BIDI,
    XQC_STREAM_UNI
} xqc_stream_direction_t;

#define XQC_DEFAULT_HTTP_PRIORITY_URGENCY 3
#define XQC_HIGHEST_HTTP_PRIORITY_URGENCY 0
#define XQC_LOWEST_HTTP_PRIORITY_URGENCY  7

typedef struct xqc_http_priority_s {
    uint8_t                 urgency;
    uint8_t                 incremental;
    uint8_t                 schedule;
    uint8_t                 reinject;
} xqc_h3_priority_t;

/* ALPN definition */
#define XQC_DEFINED_ALPN_H3      "h3"
#define XQC_DEFINED_ALPN_H3_29   "h3-29"
#define XQC_DEFINED_ALPN_H3_EXT  "h3-ext"

/* max alpn buffer length */
#define XQC_MAX_ALPN_BUF_LEN    256

#define XQC_UNKNOWN_PATH_ID ((uint64_t)-1)

typedef enum xqc_conn_settings_type_e {
    XQC_CONN_SETTINGS_DEFAULT,
    XQC_CONN_SETTINGS_LOW_DELAY,
} xqc_conn_settings_type_t;

typedef struct xqc_conn_public_local_trans_settings_s {
    uint16_t max_datagram_frame_size;
    uint8_t  datagram_redundancy;
} xqc_conn_public_local_trans_settings_t;

typedef struct xqc_conn_public_remote_trans_settings_s {
    uint16_t max_datagram_frame_size;
} xqc_conn_public_remote_trans_settings_t;

typedef struct xqc_stream_settings_s {
    uint64_t recv_rate_bytes_per_sec;
} xqc_stream_settings_t;

#define XQC_CO_TAG(a, b, c, d) (uint32_t)((a << 24) + (b << 16) + (c << 8) + d)

typedef enum xqc_conn_option_e {
    XQC_CO_TBBR = XQC_CO_TAG('T', 'B', 'B', 'R'),    // Reduced Buffer Bloat TCP
    XQC_CO_1RTT = XQC_CO_TAG('1', 'R', 'T', 'T'),    // STARTUP in BBR for 1 RTT
    XQC_CO_2RTT = XQC_CO_TAG('2', 'R', 'T', 'T'),    // STARTUP in BBR for 2 RTTs
    XQC_CO_BBR4 = XQC_CO_TAG('B', 'B', 'R', '4'),    // 20 RTT ack aggregation
    XQC_CO_BBR5 = XQC_CO_TAG('B', 'B', 'R', '5'),    // 40 RTT ack aggregation
    XQC_CO_IW03 = XQC_CO_TAG('I', 'W', '0', '3'),    // Force ICWND to 3
    XQC_CO_IW10 = XQC_CO_TAG('I', 'W', '1', '0'),    // Force ICWND to 10
    XQC_CO_IW20 = XQC_CO_TAG('I', 'W', '2', '0'),    // Force ICWND to 20
    XQC_CO_IW50 = XQC_CO_TAG('I', 'W', '5', '0'),    // Force ICWND to 50
    XQC_CO_B2ON = XQC_CO_TAG('B', '2', 'O', 'N'),    // Enable BBRv2
    XQC_CO_COPA = XQC_CO_TAG('C', 'O', 'P', 'A'),    // Enable COPA
    XQC_CO_C2ON = XQC_CO_TAG('C', '2', 'O', 'N'),    // Enable CopaV2
    XQC_CO_QBIC = XQC_CO_TAG('Q', 'B', 'I', 'C'),    // TCP Cubic
    XQC_CO_RENO = XQC_CO_TAG('R', 'E', 'N', 'O'),    // Enable reno
    XQC_CO_SPRI = XQC_CO_TAG('S', 'P', 'R', 'I'),    // enable stream priority by streamid
    XQC_CO_9218 = XQC_CO_TAG('9', '2', '1', '8'),    // enable stream priority by rfc9218
    XQC_CO_D218 = XQC_CO_TAG('D', '2', '1', '8'),    // disable rfc9218
    XQC_CO_DRST = XQC_CO_TAG('D', 'R', 'S', 'T'),    // disable cease sending stream
    XQC_CO_CBBR = XQC_CO_TAG('C', 'B', 'B', 'R'),    // A global option to enable all the following options (Customized BBR)
    XQC_CO_BNLS = XQC_CO_TAG('B', 'N', 'L', 'S'),    // Force BBR not to respond on losses during STARTUP
    XQC_CO_BACG = XQC_CO_TAG('B', 'A', 'C', 'G'),    // Use Adaptive CWND_GAIN in BBR
    XQC_CO_CG03 = XQC_CO_TAG('C', 'G', '0', '3'),    // Use 3 for CWND_GAIN in BBR
    XQC_CO_CG05 = XQC_CO_TAG('C', 'G', '0', '5'),    // Use 5 for CWND_GAIN in BBR
    XQC_CO_CG10 = XQC_CO_TAG('C', 'G', '1', '0'),    // Use 10 for CWND_GAIN in BBR
    XQC_CO_CG20 = XQC_CO_TAG('C', 'G', '2', '0'),    // Use 20 for CWND_GAIN in BBR
    XQC_CO_PG11 = XQC_CO_TAG('P', 'G', '1', '1'),    // Use 1.1 for PACING_GAIN in BBR PROBE_UP
    XQC_CO_PG15 = XQC_CO_TAG('P', 'G', '1', '5'),    // Use 1.5 for PACING_GAIN in BBR PROBE_UP
    XQC_CO_BNLR = XQC_CO_TAG('B', 'N', 'L', 'R'),    // Disable BBR's loss recovery state
    XQC_CO_MW10 = XQC_CO_TAG('M', 'W', '1', '0'),    // Set min CWND to 10
    XQC_CO_MW20 = XQC_CO_TAG('M', 'W', '2', '0'),    // Set min CWND to 20
    XQC_CO_MW32 = XQC_CO_TAG('M', 'W', '3', '2'),    // Set min CWND to 32
    XQC_CO_MW50 = XQC_CO_TAG('M', 'W', '5', '0'),    // Set min CWND to 50
    XQC_CO_WL20 = XQC_CO_TAG('W', 'L', '2', '0'),    // Set BW window length to 20 (RTTs)
    XQC_CO_WL30 = XQC_CO_TAG('W', 'L', '3', '0'),    // Set BW window length to 30 (RTTs)
    XQC_CO_WL40 = XQC_CO_TAG('W', 'L', '4', '0'),    // Set BW window length to 40 (RTTs)
    XQC_CO_WL50 = XQC_CO_TAG('W', 'L', '5', '0'),    // Set BW window length to 50 (RTTs)
    XQC_CO_PR02 = XQC_CO_TAG('P', 'R', '0', '2'),    // Set the target CWND in ProbeRTT to 0.2xBDP
    XQC_CO_PR03 = XQC_CO_TAG('P', 'R', '0', '3'),    // Set the target CWND in ProbeRTT to 0.3xBDP
    XQC_CO_PR04 = XQC_CO_TAG('P', 'R', '0', '4'),    // Set the target CWND in ProbeRTT to 0.4xBDP
    XQC_CO_PR05 = XQC_CO_TAG('P', 'R', '0', '5'),    // Set the target CWND in ProbeRTT to 0.5xBDP
    XQC_CO_PR06 = XQC_CO_TAG('P', 'R', '0', '6'),    // Set the target CWND in ProbeRTT to 0.6xBDP
    XQC_CO_PR07 = XQC_CO_TAG('P', 'R', '0', '7'),    // Set the target CWND in ProbeRTT to 0.7xBDP
    XQC_CO_ENWC = XQC_CO_TAG('E', 'N', 'W', 'C'),    // Enable CWND compensation according to jitter
    XQC_CO_JW10 = XQC_CO_TAG('J', 'W', '1', '0'),    // Set the window length of max jitter filter to 10xRTT (default)
    XQC_CO_JW20 = XQC_CO_TAG('J', 'W', '2', '0'),    // Set the window length of max jitter filter to 20xRTT
    XQC_CO_JW30 = XQC_CO_TAG('J', 'W', '3', '0'),    // Set the window length of max jitter filter to 30xRTT
    XQC_CO_JW40 = XQC_CO_TAG('J', 'W', '4', '0'),    // Set the window length of max jitter filter to 40xRTT
    XQC_CO_JW50 = XQC_CO_TAG('J', 'W', '5', '0'),    // Set the window length of max jitter filter to 50xRTT
    XQC_CO_SL03 = XQC_CO_TAG('S', 'L', '0', '3'),    // Set the STARTUP loss rate threshold to 0.03
    XQC_CO_SL04 = XQC_CO_TAG('S', 'L', '0', '4'),    // Set the STARTUP loss rate threshold to 0.04
    XQC_CO_SL05 = XQC_CO_TAG('S', 'L', '0', '5'),    // Set the STARTUP loss rate threshold to 0.05
    XQC_CO_SL10 = XQC_CO_TAG('S', 'L', '1', '0'),    // Set the STARTUP loss rate threshold to 0.05    
} xqc_conn_option_t;

#endif /*_XQUIC_TYPEDEF_H_INCLUDED_*/
