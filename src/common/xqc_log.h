/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_H_LOG_INCLUDED_
#define _XQC_H_LOG_INCLUDED_

#include <time.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <xquic/xquic.h>
#include "src/common/xqc_config.h"
#include "src/common/xqc_malloc.h"
#include "src/common/xqc_str.h"
#include "src/common/xqc_time.h"

/* max length for log buffer */
#define XQC_MAX_LOG_LEN 2048


#define XQC_LOG_REMOTE_EVENT    0
#define XQC_LOG_LOCAL_EVENT     1

#define XQC_LOG_STREAM_SEND     0
#define XQC_LOG_STREAM_RECV     1

#define XQC_LOG_DECODER_EVENT   0
#define XQC_LOG_ENCODER_EVENT   1

#define XQC_LOG_DTABLE_INSERTED 0
#define XQC_LOG_DTABLE_EVICTED  1

#define XQC_LOG_BLOCK_PREFIX    0
#define XQC_LOG_HEADER_BLOCK    1
#define XQC_LOG_HEADER_FRAME    2

#define XQC_LOG_TIMER_SET       0
#define XQC_LOG_TIMER_EXPIRE    1
#define XQC_LOG_TIMER_CANCEL    2

typedef enum {
    /* connectivity event */
    CON_SERVER_LISTENING,
    CON_CONNECTION_STARTED,
    CON_CONNECTION_CLOSED,
    CON_CONNECTION_ID_UPDATED,
    CON_SPIN_BIM_UPDATED,
    CON_CONNECTION_STATE_UPDATED,

    /* security event */
    SEC_KEY_UPDATED,
    SEC_KEY_RETIRED,

    /* transport event */
    TRA_VERSION_INFORMATION,
    TRA_ALPN_INFORMATION,
    TRA_PARAMETERS_SET,
    TRA_PARAMETERS_RESTORED,
    TRA_PACKET_SENT,
    TRA_PACKET_RECEIVED,
    TRA_PACKET_DROPPED,
    TRA_PACKET_BUFFERED,
    TRA_PACKETS_ACKED,
    TRA_DATAGRAMS_SENT,
    TRA_DATAGRAMS_RECEIVED,
    TRA_DATAGRAM_DROPPED,
    TRA_STREAM_STATE_UPDATED,
    TRA_FRAMES_PROCESSED,
    TRA_DATA_MOVED,

    /* recovery event */
    REC_PARAMETERS_SET,
    REC_METRICS_UPDATED,
    REC_CONGESTION_STATE_UPDATED,
    REC_LOSS_TIMER_UPDATED,
    REC_PACKET_LOST,
    REC_MARKED_FOR_RETRANSMIT,

    /* http event */
    HTTP_PARAMETERS_SET,
    HTTP_PARAMETERS_RESTORED,
    HTTP_STREAM_TYPE_SET,
    HTTP_FRAME_CREATED,
    HTTP_FRAME_PARSED,
    HTTP_PUSH_RESOLVED,
    HTTP_SETTING_PARSED,

    /* qpack event */
    QPACK_STATE_UPDATED,
    QPACK_STREAM_STATE_UPDATED,
    QPACK_DYNAMIC_TABLE_UPDATED,
    QPACK_HEADERS_ENCODED,
    QPACK_HEADERS_DECODED,
    QPACK_INSTRUCTION_CREATED,
    QPACK_INSTRUCTION_PARSED,

    /* generic event */
    GEN_REPORT,
    GEN_FATAL,
    GEN_ERROR,
    GEN_WARN,
    GEN_STATS,
    GEN_INFO,
    GEN_DEBUG,
} xqc_log_type_t;


typedef struct xqc_log_s {
    xqc_log_level_t                 log_level;
    xqc_flag_t                      log_event; /* 1:enable log event, 0:disable log event */
    xqc_flag_t                      log_timestamp; /* 1:add timestamp before log, 0:don't need timestamp */
    xqc_flag_t                      log_level_name; /* 1:add level name before log, 0:don't need level name */
    unsigned char                  *scid;
    xqc_log_callbacks_t            *log_callbacks;
    void                           *user_data;
} xqc_log_t;

static inline xqc_log_t *
xqc_log_init(xqc_log_level_t log_level, xqc_flag_t log_event, xqc_flag_t log_timestamp, xqc_flag_t log_level_name,
    xqc_log_callbacks_t *log_callbacks, void *user_data)
{
    xqc_log_t* log = xqc_malloc(sizeof(xqc_log_t));
    if (log == NULL) {
        return NULL;
    }

    log->log_level = log_level;
    log->user_data = user_data;
    log->scid = NULL;
    log->log_event = log_event;
    log->log_timestamp = log_timestamp;
    log->log_level_name = log_level_name;
    log->log_callbacks = log_callbacks;
    return log;
}

static inline void
xqc_log_release(xqc_log_t* log)
{
    xqc_free(log);
    log = NULL;
}

void
xqc_log_level_set(xqc_log_t *log, xqc_log_level_t level);

xqc_log_level_t
xqc_log_type_2_level(xqc_log_type_t type);

xqc_log_type_t
xqc_log_event_type(xqc_log_level_t level);

const char*
xqc_log_type_str(xqc_log_type_t type);

void
xqc_log_time(char* buf, size_t buf_len);

void
xqc_log_implement(xqc_log_t *log, xqc_log_type_t type, const char *func, const char *fmt, ...);


#ifndef XQC_DISABLE_LOG
    #ifndef XQC_ONLY_ERROR_LOG
    #define xqc_log(log, level, ...) \
    do { \
        if ((log)->log_level >= level) { \
            xqc_log_implement(log, xqc_log_event_type(level), __FUNCTION__, __VA_ARGS__); \
        } \
    } while (0)
    #else
    #define xqc_log(log, level, ...) \
        do { \
            if (XQC_LOG_ERROR >= level) { \
                xqc_log_implement(log, xqc_log_event_type(level), __FUNCTION__, __VA_ARGS__); \
            } \
        } while (0)
    #endif

    #ifdef XQC_ENABLE_EVENT_LOG
    #define xqc_log_event(log, type, ...) \
    do {                                  \
        if ((log)->log_event) {           \
            if ((log)->log_level >= xqc_log_type_2_level(type)) { \
                xqc_log_##type##_callback(log, __FUNCTION__, __VA_ARGS__); \
            }                             \
        }                                 \
    } while (0)
    #else
    #define xqc_log_event(log, type, ...)
    #endif
#else
#define xqc_log(log, level, ...)
#define xqc_log_event(log, type, ...)
#endif

#define xqc_conn_log(conn, level, fmt, ...) \
    xqc_log(conn->log, level, "|%s " fmt, xqc_conn_addr_str(conn), ##__VA_ARGS__ )


#define xqc_log_fatal(log, ...) \
    do {\
        if ((log)->log_level >= XQC_LOG_FATAL) { \
            xqc_log_implement(log, xqc_log_event_type(XQC_LOG_FATAL), __FUNCTION__, __VA_ARGS__); \
        } \
    } while (0)

#define xqc_log_error(log, ...) \
    do {\
        if ((log)->log_level >= XQC_LOG_ERROR) { \
            xqc_log_implement(log, xqc_log_event_type(XQC_LOG_ERROR), __FUNCTION__, __VA_ARGS__); \
        } \
    } while (0)

#define xqc_log_warn(log, ...) \
    do {\
        if ((log)->log_level >= XQC_LOG_WARN) { \
            xqc_log_implement(log, xqc_log_event_type(XQC_LOG_WARN), __FUNCTION__, __VA_ARGS__); \
        } \
    } while (0)

#define xqc_log_info(log, ...) \
    do {\
        if ((log)->log_level >= XQC_LOG_INFO) { \
            xqc_log_implement(log, xqc_log_event_type(XQC_LOG_INFO), __FUNCTION__, __VA_ARGS__); \
        } \
    } while (0)

#define xqc_log_debug(log, ...) \
    do {\
        if ((log)->log_level >= XQC_LOG_DEBUG) { \
            xqc_log_implement(log, xqc_log_event_type(XQC_LOG_DEBUG), __FUNCTION__, __VA_ARGS__); \
        } \
    } while (0)



#endif /*_XQC_H_LOG_INCLUDED_*/
