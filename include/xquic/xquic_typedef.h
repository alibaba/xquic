/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQUIC_TYPEDEF_H_INCLUDED_
#define _XQUIC_TYPEDEF_H_INCLUDED_

#include <stdint.h>
#include <stddef.h>
#include "xqc_errno.h"

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

typedef struct xqc_cid_s {
    uint8_t             cid_len;
    uint8_t             cid_buf[XQC_MAX_CID_LEN];
    uint64_t            cid_seq_num;
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

#ifdef WIN32
struct iovec {
    void   *iov_base;   /* [XSI] Base address of I/O memory region */
    size_t  iov_len;    /* [XSI] Size of region iov_base points to */
};
#endif

#define XQC_EXPORT_PUBLIC_API   __attribute__((visibility("default")))

#endif /*_XQUIC_TYPEDEF_H_INCLUDED_*/
